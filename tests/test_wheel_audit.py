"""Audit inert synthetic wheels without installing or importing their contents."""

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("toolkit_wheel_audit", Path(__file__).resolve().parents[1] / "scripts/audit_wheel.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class WheelAuditTests(unittest.TestCase):
    def check_wheel(self, files, *, tamper=False, digest=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "example-1.0-py3-none-any.whl"
            entries = dict(files)
            entries["example-1.0.dist-info/METADATA"] = b"Name: example\nVersion: 1.0\n"
            rows = []
            for name, data in entries.items():
                value = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                rows.append(f"{name},sha256={value},{len(data)}")
            record = "example-1.0.dist-info/RECORD"
            entries[record] = ("\n".join([*rows, f"{record},,"]) + "\n").encode()
            if tamper:
                entries["example/__init__.py"] = b"changed = True\n"
            with zipfile.ZipFile(path, "w") as archive:
                for name, data in entries.items():
                    archive.writestr(name, data)
            args = [str(path)]
            if digest:
                args += ["--expect-sha256", digest]
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = audit.main(args)
            return status, output.getvalue()

    def test_valid_inert_wheel(self):
        status, output = self.check_wheel({"example/__init__.py": b"version = '1.0'\n"})
        self.assertEqual(status, 0)
        self.assertIn("hard findings: none", output)

    def test_pth_is_hard_finding_and_never_executed(self):
        # This would raise if an auditor imported or executed the payload.
        status, output = self.check_wheel({"example.pth": b"import builtins; raise RuntimeError('must stay inert')\n"})
        self.assertEqual(status, 1)
        self.assertIn("startup hook: example.pth", output)

    def test_sitecustomize_is_hard_finding(self):
        status, output = self.check_wheel({"sitecustomize.py": b"raise RuntimeError('must stay inert')\n"})
        self.assertEqual(status, 1)
        self.assertIn("startup hook: sitecustomize.py", output)

    def test_relocated_usercustomize_is_hard_finding(self):
        status, output = self.check_wheel({"example-1.0.data/purelib/usercustomize.py": b"raise RuntimeError('must stay inert')\n"})
        self.assertEqual(status, 1)
        self.assertIn("startup hook: example-1.0.data/purelib/usercustomize.py", output)

    def test_wrong_expected_digest_fails(self):
        status, output = self.check_wheel({"example/__init__.py": b""}, digest="0" * 64)
        self.assertEqual(status, 1)
        self.assertIn("sha256 does NOT match", output)

    def test_record_mismatch_fails(self):
        status, output = self.check_wheel({"example/__init__.py": b"original = True\n"}, tamper=True)
        self.assertEqual(status, 1)
        self.assertIn("RECORD: hash mismatch", output)

    def test_network_code_is_flagged_without_running_it(self):
        status, output = self.check_wheel({"example/__init__.py": b"import socket\nraise RuntimeError('must stay inert')\n"})
        self.assertEqual(status, 0)  # Pattern hits require human review; not an automatic malware verdict.
        self.assertIn("network access", output)

    def test_binary_in_pure_wheel_fails(self):
        status, output = self.check_wheel({"example/payload.pyd": b"synthetic, not executable"})
        self.assertEqual(status, 1)
        self.assertIn("binary inside a pure-Python wheel", output)

    def test_archive_resource_and_path_guards_precede_member_reads(self):
        for files, limit, expected in [({"example/data": b"X" * 5000}, 4096, "size/expansion-ratio limit"),
                                       ({"../escape.py": b""}, audit.MAX_MEMBER, "unsafe archive path")]:
            with self.subTest(files=list(files)), patch.object(audit, "MAX_MEMBER", limit):
                status, output = self.check_wheel(files)
                self.assertEqual(status, 1)
                self.assertIn(expected, output)

    def test_weak_record_hash_is_rejected_without_crashing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "record.whl"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("example.py", b"x = 1")
                archive.writestr("example.dist-info/RECORD", "example.py,md5=ignored,5\nexample.dist-info/RECORD,,\n")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = audit.main([str(path)])
            self.assertEqual(status, 1)
            self.assertIn("weak hash", output.getvalue())

    def test_destination_report_and_reviewed_baseline_diff(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "example-1.0-py3-none-any.whl"
            old = root / "old.json"
            old.write_text(json.dumps({"schema_version": 1, "members": {}, "destinations": [{"host": "old.example"}], "sha256": "a" * 64}))
            with zipfile.ZipFile(path, "w") as archive:
                source = b"url = 'https://new.example/x?token=private-value'\nraise RuntimeError('must stay inert')"
                archive.writestr("example/code.py", source)
                archive.writestr("example.dist-info/RECORD", "example.dist-info/RECORD,,\n")
            report = root / "new.json"
            with contextlib.redirect_stdout(io.StringIO()):
                audit.main([str(path), "--report", str(report), "--baseline", str(old)])
            result = json.loads(report.read_text())
            self.assertEqual(result["new_hosts"], ["new.example"])
            self.assertIn("example/code.py", result["changed_members"])
            self.assertNotIn("private-value", report.read_text())

    def test_source_comparison_checks_second_top_level_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            for package in ("alpha", "zeta"):
                (source / package).mkdir(parents=True)
                (source / package / "__init__.py").write_bytes(b"version = 1\n")
            path = root / "example.whl"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("alpha/__init__.py", b"version = 1\n")
                archive.writestr("zeta/__init__.py", b"changed = True\n")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                status = audit.main([str(path), "--source", str(source)])
            self.assertEqual(status, 1)
            self.assertIn("source: differs from repository: zeta/__init__.py", output.getvalue())


class ArtifactStringsTests(unittest.TestCase):
    def test_literals_base64_and_utf16_remain_inert_without_network(self):
        import socket
        encoded = base64.b64encode(b"https://encoded.example/collect").decode()
        source = (f'payload = "{encoded}"\nurl = "https://" + "joined.example" + "/x"\n'
                  'raise RuntimeError("must stay inert")').encode()
        review = audit._strings.Review()
        with patch.object(socket, "socket", side_effect=AssertionError("unexpected network")):
            review.member("example/payload.py", source)
            review.member("example/data.bin", "https://wide.example/x".encode("utf-16-le"))
        rows = review.result()["destinations"]
        hosts = {row["host"] for row in rows}
        self.assertTrue({"encoded.example", "joined.example", "wide.example"} <= hosts)
        self.assertTrue(any("base64" in row["transform"] for row in rows if row["host"] == "encoded.example"))
        self.assertTrue(any(row["line"] == 1 for row in rows if row["host"] == "encoded.example"))
        self.assertTrue(any(row["line"] == 2 for row in rows if row["host"] == "joined.example"))

    def test_gzip_bomb_is_limited_and_marked_incomplete(self):
        import gzip
        review = audit._strings.Review()
        payload = base64.b64encode(gzip.compress(b"X" * 100000)).decode()
        review.member("example/payload.py", f'data = "{payload}"'.encode())
        self.assertTrue(review.result()["coverage_issues"])
        self.assertLessEqual(review.result()["decoded_bytes"], audit._strings.MAX_DECODE_TOTAL)

    def test_url_credentials_and_queries_are_redacted(self):
        review = audit._strings.Review()
        review.member("docs/example.txt", b"https://person:private-pass@docs.example/path?key=private-query#private-fragment")
        result = json.dumps(review.result())
        self.assertIn("docs.example", result)
        for secret in ("private-pass", "private-query", "private-fragment"):
            self.assertNotIn(secret, result)

    def test_partial_string_coverage_is_explicit(self):
        review = audit._strings.Review()
        with patch.object(audit._strings, "MAX_STRINGS", 1):
            review.member("data.bin", b"first.example\x00second.example")
        self.assertIn("coverage is incomplete", " ".join(review.result()["coverage_issues"]))
