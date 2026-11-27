"""5F.4 offline save, original-byte retention and failure-injection acceptance."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core import archives, db, evidence, evidence_schema
from app.core.config import Settings, settings
from app.core.evidence_models import Citation, Document, Source
from app.core.models import VendorResult
from app.core.ratelimit import RateLimiter
from app.modules.enrich import base, bulk
from app.modules.extract import fetch, markdown, saved
from tests.test_shared_evidence import document


def metadata(**changes):
    return saved.ReportMetadata(**{"capture_id": "capture-1", "title": "Synthetic Report",
        "publisher": "Synthetic Publisher", "source_published_at": "2026-11-20",
        "observed_at": "2026-11-18", "sensitivity": "public", **changes})


class LocalDb(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        p = patch.object(settings, "data_dir", self.root)
        p.start()
        self.addCleanup(p.stop)
        self.set_setting("archive_enabled", False)
        self.set_setting("archive_root", None)
        self.set_setting("bulk_enrichment_enabled", False)
        db.init_db()

    def set_setting(self, name, value):
        p = patch.object(settings, name, value)
        p.start()
        self.addCleanup(p.stop)

    def enable_archive(self, **changes):
        for name, value in {"archive_enabled": True, "archive_root": self.root / "originals",
                            "archive_response_bytes": 1000, "archive_source_bytes": 2000,
                            "archive_total_bytes": 3000, "archive_retention_seconds": 60, **changes}.items():
            self.set_setting(name, value)

    def save_report(self, text="A source mention of bad[.]example and 8.8.8.8.", **changes):
        return saved.save(markdown.parse_document(text), text.encode(), metadata(**changes), origin="paste")

    def archive_doc(self, raw=b"original bytes", **changes):
        doc = document(**{"capture_key": sha256(raw).hexdigest(), "content_sha256": sha256(raw).hexdigest(),
                          "sensitivity": "public", **changes})
        ident = evidence.record_document(doc)
        return ident


class ReportTests(LocalDb):
    def test_replay_preserves_capture_dates_and_run_changed_input_creates_new_capture(self):
        text = "Observed bad[.]example, not a malicious verdict."
        first = saved.save(markdown.parse_document(text), text.encode(), metadata(), origin="paste",
                           collected_at="2026-11-26T09:00:00-05:00", job_run_id="origin-run")
        replay = saved.save(markdown.parse_document(text), text.encode(), metadata(), origin="paste",
                            collected_at="2026-11-26T20:00:00Z", job_run_id="origin-run")
        self.assertEqual(first, replay)
        result = saved.detail(first)
        self.assertEqual(result["document"]["collected_at"], "2026-11-26T14:00:00.000000+00:00")
        self.assertEqual(result["document"]["source_published_at"], "2026-11-20")
        self.assertEqual(result["observations"][0]["observed_at"], "2026-11-18")
        self.assertEqual(result["observations"][0]["assertion"], "mention")
        self.assertEqual(result["document"]["job_run_id"], "origin-run")
        self.assertNotEqual(self.save_report(text + " Changed."), first)
        self.assertNotEqual(self.save_report(text, title="Correction"), first)
        self.assertNotEqual(self.save_report(text, capture_id="another-acquisition"), first)
        source = evidence.get_source(result["document"]["source_id"])
        self.assertEqual(source.reliability, "F")
        self.assertFalse(source.collection_enabled)

    def test_literal_citation_hops_preserve_manual_resolution_on_replay(self):
        refs = ("https://middle.invalid/report?revision=2#evidence", "Unresolved original report, section 3")
        ident = self.save_report(citations=refs)
        citations = saved.detail(ident)["citations"]
        self.assertEqual([r["target_reference"] for r in citations], list(refs))
        other = evidence.record_document(document(source="other"))
        evidence.resolve_citation(citations[0]["id"], other, "Explicitly matched the saved reference")
        self.assertEqual(self.save_report(citations=refs), ident)
        self.assertEqual(saved.detail(ident)["citations"][0]["target_document_id"], other)

    def test_invalid_metadata_dates_citations_and_credentials_make_no_save(self):
        for changes in ({"title": ""}, {"publisher": ""}, {"source_published_at": None},
                        {"source_published_at": "2026-02-30"}, {"observed_at": "2026-11-26T10:00:00"},
                        {"citations": ("x"*2049,)}, {"source_url": "https://host.invalid/?token=secret"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.save_report(**changes)
        with self.assertRaises(ValueError):
            self.save_report("password=synthetic-secret bad.example")
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_documents").fetchone()[0], 0)

    def test_atomic_rollback_of_report_and_mentions_then_retry(self):
        original = evidence._snapshot
        calls = 0
        def broken(*args):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise RuntimeError("synthetic interruption")
            return original(*args)
        with patch.object(evidence, "_snapshot", broken), self.assertRaises(RuntimeError):
            self.save_report()
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_documents").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_observations").fetchone()[0], 0)
        ident = self.save_report()
        self.assertEqual(len(saved.detail(ident)["observations"]), 2)

    def test_concurrent_duplicate_saves_have_one_complete_manifest(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            ids = list(pool.map(lambda _: self.save_report(), range(4)))
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(len(saved.list_reports()), 1)

    def test_unknown_and_sensitive_reports_keep_mentions_without_excerpts(self):
        for label in ("unknown", "sensitive"):
            ident = self.save_report(sensitivity=label)
            self.assertTrue(saved.detail(ident)["observations"])
            self.assertTrue(all(not o["excerpt"] for o in saved.detail(ident)["observations"]))
            self.assertEqual(archives.get(ident)["state"], "omitted")

    def test_empty_date_can_be_explicitly_unknown_and_file_origin_is_preserved(self):
        text = "bad.example"
        ident = saved.save(markdown.parse_document(text), text.encode(),
                           metadata(source_published_at=None, publication_unknown=True), origin="file")
        self.assertIsNone(saved.detail(ident)["document"]["source_published_at"])
        self.assertEqual(saved.detail(ident)["document"]["collection_method"], "manual_file")

    def test_parser_and_raw_limits_refuse_partial_saves(self):
        with self.assertRaises(ValueError):
            saved.save(markdown.parse_document("x"*2_000_001), b"x", metadata(), origin="paste")
        with self.assertRaises(ValueError):
            saved.save(markdown.parse_document("x"), b"x"*(10*1024**2+1), metadata(), origin="paste")
        with patch.object(saved, "PARSER_VERSION", "new-parser"):
            new = self.save_report()
        self.assertNotEqual(new, self.save_report())

    def test_version2_upgrade_is_atomic_and_can_resume(self):
        with evidence.connect() as conn:
            conn.execute("DROP TABLE evidence_bulk_results")
            conn.execute("DROP TABLE evidence_report_saves")
            conn.execute("DROP TABLE evidence_archives")
            conn.execute("DELETE FROM evidence_schema_versions WHERE version=2")
            conn.commit()
            with patch.object(evidence_schema, "MIGRATIONS", ((1, evidence_schema.VERSION_1), (2, evidence_schema.VERSION_2 + "; INSERT INTO absent VALUES(1);"))):
                with self.assertRaises(Exception):
                    evidence_schema.migrate(conn)
            self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='evidence_archives'").fetchone())
            evidence_schema.migrate(conn)
            self.assertEqual(conn.execute("SELECT max(version) FROM evidence_schema_versions").fetchone()[0], 2)

    def test_save_route_metadata_views_escape_and_cross_site_is_refused(self):
        from app.main import app
        with TestClient(app, base_url="http://127.0.0.1") as client:
            form = {"text": "bad[.]example", "save_report": "true", "capture_id": "form-1",
                    "source_title": "<script>source</script>", "publisher": "Example",
                    "publication_date": "unknown", "sensitivity": "public"}
            response = client.post("/extract", data=form)
            self.assertEqual(response.status_code, 200)
            self.assertIn("View Saved Report", response.text)
            ident = saved.list_reports()[0]["id"]
            detail = client.get(f"/reports/{ident}")
            self.assertIn("&lt;script&gt;source&lt;/script&gt;", detail.text)
            self.assertNotIn("<script>source</script>", detail.text)
            self.assertIn("disabled", detail.text)
            self.assertEqual(client.get("/reports").status_code, 200)
            self.assertEqual(client.post("/extract", data=form, headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
            self.assertEqual(client.post(f"/reports/{ident}/enrich", data={"request_key": "1"}, headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
            self.assertEqual(client.get(f"/reports/{ident}/original").status_code, 404)


class ArchiveTests(LocalDb):
    def test_settings_fail_closed_and_blank_template_values_remain_disabled(self):
        self.assertFalse(Settings(_env_file=None, archive_root="", archive_total_bytes="").archive_enabled)
        for changes in ({}, {"archive_root": "data/originals"}, {"archive_response_bytes": 0},
                        {"archive_response_bytes": -1}, {"archive_total_bytes": float("inf")}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                Settings(_env_file=None, archive_enabled=True, **changes)

    def test_disabled_omission_and_digest_mismatch(self):
        ident = self.archive_doc()
        self.assertEqual(archives.retain(ident, b"original bytes")["reason"], "disabled")
        self.assertFalse((self.root / "originals").exists())
        with self.assertRaises(evidence.EvidenceConflict):
            archives.retain(ident, b"different bytes")

    def test_exact_original_bytes_and_independent_response_source_total_limits(self):
        self.enable_archive(archive_response_bytes=10, archive_source_bytes=12, archive_total_bytes=15)
        a = self.archive_doc(b"12345678")
        self.assertEqual(archives.retain(a, b"12345678")["state"], "stored")
        self.assertEqual(archives.read(a), b"12345678")
        b = self.archive_doc(b"123456")
        self.assertEqual(archives.retain(b, b"123456")["reason"], "source_limit")
        c = self.archive_doc(b"12345678901", source="different")
        self.assertEqual(archives.retain(c, b"12345678901")["reason"], "response_limit")
        d = self.archive_doc(b"abcdefgh", source="different")
        self.assertEqual(archives.retain(d, b"abcdefgh")["reason"], "total_limit")

    def test_unknown_sensitive_tlp_and_credential_like_raw_are_omitted(self):
        self.enable_archive()
        for index, changes in enumerate(({"sensitivity": "unknown"}, {"sensitivity": "sensitive"}, {"tlp": "AMBER"})):
            raw = f"body {index}".encode()
            ident = self.archive_doc(raw, **changes)
            self.assertEqual(archives.retain(ident, raw)["state"], "omitted")
        raw = b"api_key=synthetic-secret"
        ident = self.archive_doc(raw)
        self.assertEqual(archives.retain(ident, raw)["reason"], "credential_pattern")

    def test_expiry_preserves_documents_indicators_citations_and_digest(self):
        self.enable_archive()
        ident = self.save_report(citations=("Original source, section 3",))
        before = saved.detail(ident)
        with patch.object(archives, "now", return_value=datetime.now(timezone.utc)+timedelta(seconds=120)):
            self.assertEqual(archives.get(ident)["state"], "expired")
            archives.reconcile()
            with self.assertRaises(FileNotFoundError):
                archives.read(ident)
        after = saved.detail(ident)
        self.assertEqual(before["observations"], after["observations"])
        self.assertEqual(before["citations"], after["citations"])
        self.assertEqual(before["document"], after["document"])
        self.assertEqual(before["archive"]["sha256"], after["archive"]["sha256"])
        self.assertEqual(self.save_report(citations=("Original source, section 3",)), ident)
        self.assertEqual(archives.get(ident)["state"], "expired")

    def test_interrupted_write_and_rename_recover_without_fabricated_availability(self):
        self.enable_archive()
        ident = self.archive_doc()
        with patch.object(archives.os, "replace", side_effect=OSError("synthetic failure")):
            self.assertEqual(archives.retain(ident, b"original bytes")["state"], "pending")
        archives.reconcile()
        self.assertEqual(archives.get(ident)["state"], "failed")
        self.assertFalse(list((self.root / "originals").glob("*.tmp")))
        second = self.archive_doc(b"second body")
        update = archives._update
        def broken(ident, state, reason):
            if state == "stored":
                raise OSError("crash after rename")
            return update(ident, state, reason)
        with patch.object(archives, "_update", broken):
            self.assertEqual(archives.retain(second, b"second body")["state"], "pending")
        archives.reconcile()
        self.assertEqual(archives.read(second), b"second body")

    def test_restart_reconciliation_detects_corruption_missing_files_and_orphans(self):
        self.enable_archive()
        ident = self.archive_doc()
        row = archives.retain(ident, b"original bytes")
        (settings.archive_root / row["storage_key"]).write_bytes(b"corrupt bytes!")
        orphan = settings.archive_root / ("a"*32 + ".blob")
        orphan.write_bytes(b"orphan")
        safe = settings.archive_root / "operator-note.txt"
        safe.write_text("preserve")
        archives.reconcile(limit=1)
        self.assertEqual(archives.get(ident)["state"], "failed")
        archives.reconcile()
        self.assertFalse(orphan.exists())
        self.assertTrue(safe.exists())
        second = self.archive_doc(b"second")
        row = archives.retain(second, b"second")
        (settings.archive_root / row["storage_key"]).unlink()
        archives.reconcile()
        self.assertEqual(archives.get(second)["reason"], "missing_or_incomplete")

    def test_root_escape_corrupt_generated_key_and_changed_root_are_refused(self):
        self.enable_archive()
        self.set_setting("archive_root", self.root.parent / "outside-archive")
        with self.assertRaises(ValueError):
            archives.retain(self.archive_doc(), b"original bytes")
        self.set_setting("archive_root", self.root / "originals")
        ident = self.archive_doc(b"body")
        archives.retain(ident, b"body")
        self.set_setting("archive_root", self.root / "other-root")
        with self.assertRaises(FileNotFoundError):
            archives.read(ident)
        self.set_setting("archive_root", self.root / "originals")
        with evidence.connect() as conn, conn:
            conn.execute("UPDATE evidence_archives SET storage_key='../escape' WHERE document_id=?", (ident,))
        with self.assertRaises(ValueError):
            archives.read(ident)

    def test_concurrent_writers_cannot_overspend_archive_budget(self):
        self.enable_archive(archive_response_bytes=8, archive_source_bytes=8, archive_total_bytes=8)
        ids = [self.archive_doc(b"12345678", source=f"source{i}") for i in range(4)]
        def write(ident):
            try:
                return archives.retain(ident, b"12345678")["state"]
            except RuntimeError:
                return "busy"
        with ThreadPoolExecutor(max_workers=4) as pool:
            states = list(pool.map(write, ids))
        self.assertEqual(states.count("stored"), 1)
        self.assertEqual(sum(p.stat().st_size for p in settings.archive_root.glob("*.blob")), 8)

    def test_unavailable_storage_is_visible_and_does_not_erase_saved_mentions(self):
        self.enable_archive()
        with patch.object(archives, "_locked", side_effect=OSError("private path must never be logged")):
            ident = self.save_report()
            self.assertEqual(archives.get(ident)["state"], "failed")
            self.assertTrue(saved.detail(ident)["observations"])
            archives.maintenance()
            self.assertEqual(archives.health()["state"], "Failed")

    def test_expired_list_view_and_disabled_storage_maintenance(self):
        self.enable_archive()
        ident = self.save_report()
        with patch.object(archives, "now", return_value=datetime.now(timezone.utc)+timedelta(seconds=120)):
            self.assertEqual(saved.list_reports()[0]["archive_state"], "expired")
            with patch.object(settings, "archive_enabled", False):
                archives.reconcile()
        self.assertEqual(archives.get(ident)["state"], "expired")

    def test_configured_secret_value_is_never_retained_in_provider_attributes(self):
        with patch.object(settings, "virustotal_api_key", "synthetic-secret-value"):
            result = VendorResult(source="synthetic", indicator="8.8.8.8", indicator_type="ip",
                                  summary={"innocent_name": "synthetic-secret-value"}, detection_ratio="synthetic-secret-value")
            self.assertNotIn("synthetic-secret-value", bulk._safe_result(result))


class BulkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        for name, value in (("data_dir", Path(self.directory.name)), ("bulk_enrichment_enabled", True),
                            ("archive_root", None), ("archive_enabled", False)):
            p = patch.object(settings, name, value)
            p.start()
            self.addCleanup(p.stop)
        db.init_db()
        self.service = bulk.Service(asyncio.get_running_loop())
        self.calls = []
        async def acquire(vendor):
            self.calls.append(("quota", vendor, id(asyncio.get_running_loop())))
        self.limiter = patch("app.core.ratelimit.rate_limiter._acquire", side_effect=acquire)
        self.limiter.start()
        self.addCleanup(self.limiter.stop)
        self.addAsyncCleanup(base.aclose)

    def report(self, text="8.8.8.8", **changes):
        return saved.save(markdown.parse_document(text), text.encode(), metadata(**changes), origin="paste")

    def source(self, name, enabled=True):
        evidence.save_source(Source(source_id="enrich." + name, name=name, source_class="publisher",
            access_method="api", terms_status="approved", terms_reviewed_on="2026-11-26",
            terms_reference="synthetic local review", rate_limit_notes="synthetic bounded test",
            collection_enabled=enabled))

    def mock_http(self, callback):
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(callback)))

    async def run_job(self, params, request_key="request-1"):
        ident = await asyncio.to_thread(self.service.enqueue, params, request_key)
        await asyncio.to_thread(self.service.runner.run_next)
        return ident, self.service.runner.get(ident)

    async def test_default_switch_source_review_and_sensitive_report_fail_closed(self):
        ident = self.report()
        params = bulk.Params(document_id=ident, providers=("internetdb",))
        with self.assertRaises(PermissionError):
            self.service.enqueue(params, "request")
        self.source("internetdb")
        with patch.object(settings, "bulk_enrichment_enabled", False), self.assertRaises(PermissionError):
            self.service.enqueue(params, "request")
        for changes in ({"sensitivity": "unknown"}, {"sensitivity": "sensitive"}, {"tlp": "GREEN"}):
            with self.subTest(changes=changes), self.assertRaises(PermissionError):
                self.service.enqueue(bulk.Params(document_id=self.report(**changes), providers=("internetdb",)), "request")

    async def test_shared_loop_client_quota_capture_and_normalized_attributes(self):
        self.source("internetdb")
        loop = id(asyncio.get_running_loop())
        def response(request):
            self.assertEqual(id(asyncio.get_running_loop()), loop)
            self.assertEqual(request.url.host, "internetdb.shodan.io")
            return httpx.Response(200, json={"ports": [443], "hostnames": ["sample.invalid"], "vulns": ["CVE-2026-12345"]})
        self.mock_http(response)
        ident = self.report()
        job_id, job = await self.run_job(bulk.Params(document_id=ident, providers=("internetdb",)))
        self.assertEqual(job["state"], "succeeded")
        self.assertEqual(job["progress_done"], 1)
        self.assertTrue(job["coverage_checkpoint"])
        self.assertEqual(self.calls, [("quota", "internetdb", loop)])
        result = saved.detail(ident)["bulk_results"][0]
        value = json.loads(result["result_json"])
        self.assertEqual(value["summary"]["ports"], [443])
        self.assertNotIn("raw", value)
        capture = evidence.get_document(result["captured_document_id"])
        self.assertEqual(capture["job_run_id"], self.service.runner.runs(job_id)[0]["id"])
        self.assertEqual(evidence.citations_for_document(capture["id"])[0]["target_document_id"], ident)
        self.assertEqual(archives.get(capture["id"])["state"], "omitted")

    async def test_keyless_first_and_known_good_hash_never_calls_keyed_client(self):
        self.source("hashlookup")
        self.source("virustotal")
        text = "a"*64
        self.mock_http(lambda request: httpx.Response(200, json={"hashlookup:trust": 90, "FileName": "Known Binary"}))
        keyed = AsyncMock(side_effect=AssertionError("keyed client must be skipped"))
        with patch.object(bulk.MODULES["virustotal"], "lookup", keyed):
            ident, job = await self.run_job(bulk.Params(document_id=self.report(text), providers=("virustotal", "hashlookup")))
        self.assertEqual(job["state"], "succeeded")
        keyed.assert_not_called()
        self.assertEqual([c[1] for c in self.calls], ["hashlookup"])

    async def test_unselected_keyed_provider_never_runs_and_private_ip_is_local(self):
        self.source("internetdb")
        self.mock_http(lambda request: self.fail("private IP must not be submitted"))
        _, job = await self.run_job(bulk.Params(document_id=self.report("192.168.1.20"), providers=("internetdb",)))
        self.assertEqual(job["state"], "succeeded")
        self.assertFalse(self.calls)
        self.assertEqual(bulk.KEYLESS, ("hashlookup", "internetdb", "rdap", "crtsh"))

    async def test_revocation_after_quota_wait_prevents_http(self):
        self.source("internetdb")
        async def revoke(vendor):
            self.source("internetdb", False)
        self.mock_http(lambda request: self.fail("revoked source contacted"))
        with patch("app.core.ratelimit.rate_limiter._acquire", side_effect=revoke):
            _, job = await self.run_job(bulk.Params(document_id=self.report(), providers=("internetdb",)))
        self.assertEqual(job["error_code"], "source_ineligible")

    async def test_retry_preserves_committed_units_and_resumes_without_progress_regression(self):
        self.source("internetdb")
        calls = []
        def response(request):
            calls.append(request.url.path)
            if len(calls) == 2:
                return httpx.Response(503)
            return httpx.Response(200, json={"ports": [443]})
        self.mock_http(response)
        params = bulk.Params(document_id=self.report("8.8.8.8 and 1.1.1.1"), providers=("internetdb",))
        job_id, job = await self.run_job(params)
        self.assertEqual((job["state"], job["progress_done"]), ("queued", 1))
        with self.service.runner._connect(write=True) as conn:
            conn.execute("UPDATE durable_jobs SET available_at=created_at WHERE id=?", (job_id,))
        restarted = bulk.Service(asyncio.get_running_loop())
        await asyncio.to_thread(restarted.runner.run_next)
        self.assertEqual(restarted.runner.get(job_id)["state"], "succeeded")
        self.assertEqual(len(calls), 3)
        self.assertNotEqual(calls[0], calls[2])

    async def test_429_cooldown_and_daily_quota_survive_restart(self):
        self.source("internetdb")
        calls = []
        def limited(request):
            calls.append(request)
            return httpx.Response(429, headers={"Retry-After": "7200"})
        self.mock_http(limited)
        params = bulk.Params(document_id=self.report(), providers=("internetdb",))
        _, job = await self.run_job(params)
        self.assertEqual(job["error_code"], "rate_limit")
        self.assertGreater(datetime.fromisoformat(job["available_at"]), datetime.fromisoformat(job["last_attempt_at"])+timedelta(seconds=7000))
        self.service = bulk.Service(asyncio.get_running_loop())
        _, second = await self.run_job(params, "different-request")
        self.assertEqual(second["error_code"], "rate_limit")
        self.assertEqual(len(calls), 1)

    async def test_redirect_and_arbitrary_destinations_fail_closed(self):
        self.source("rdap")
        calls = []
        def redirect(request):
            calls.append(request)
            return httpx.Response(302, headers={"Location": "https://attacker.invalid/collect"})
        self.mock_http(redirect)
        _, job = await self.run_job(bulk.Params(document_id=self.report(), providers=("rdap",)))
        self.assertEqual(job["error_code"], "source_ineligible")
        self.assertEqual(len(calls), 1)
        self.assertFalse(bulk.Feed("enrich.internetdb", "Synthetic", lambda: None,
            (bulk.re.compile(bulk.SURFACES["internetdb"]),), 3600, 86400).permits("https://attacker.invalid/8.8.8.8"))

    async def test_cached_result_has_original_query_time_and_no_new_capture(self):
        self.source("internetdb")
        self.mock_http(lambda request: httpx.Response(200, json={"ports": [80]}))
        params = bulk.Params(document_id=self.report(), providers=("internetdb",))
        await self.run_job(params)
        _, job = await self.run_job(params, "cached-request")
        self.assertEqual(job["state"], "succeeded")
        results = saved.detail(params.document_id)["bulk_results"]
        cached = [r for r in results if json.loads(r["result_json"])["cached"]][0]
        self.assertIsNone(cached["captured_document_id"])
        self.assertEqual(len(self.calls), 1)

    async def test_revoked_retry_and_worker_disable_never_contact_provider(self):
        self.source("internetdb")
        self.mock_http(lambda request: httpx.Response(503))
        job_id, job = await self.run_job(bulk.Params(document_id=self.report(), providers=("internetdb",)))
        self.source("internetdb", False)
        with self.service.runner._connect(write=True) as conn:
            conn.execute("UPDATE durable_jobs SET available_at=created_at WHERE id=?", (job_id,))
        self.mock_http(lambda request: self.fail("revoked retry contacted source"))
        await asyncio.to_thread(self.service.runner.run_next)
        self.assertEqual(self.service.runner.get(job_id)["error_code"], "source_ineligible")

    async def test_same_endpoint_equal_bytes_different_inputs_have_distinct_captures(self):
        self.source("threatfox")
        self.mock_http(lambda request: httpx.Response(200, json={"status": "not found"}))
        async def lookup(itype, value):
            await base.fetch_json("POST", "https://threatfox-api.abuse.ch/api/v1/", json={"query": value})
            return VendorResult(source="threatfox", indicator=value, indicator_type=itype)
        report = self.report("8.8.8.8 and 1.1.1.1")
        with patch.object(bulk.MODULES["threatfox"], "lookup", side_effect=lookup):
            _, job = await self.run_job(bulk.Params(document_id=report, providers=("threatfox",)))
        self.assertEqual(job["state"], "succeeded")
        captures = [r["captured_document_id"] for r in saved.detail(report)["bulk_results"]]
        self.assertEqual(len(set(captures)), 2)

    async def test_request_budget_stops_nested_provider_requests(self):
        self.source("internetdb")
        requests = []
        def response(request):
            requests.append(request)
            return httpx.Response(200, json={"ports": []})
        self.mock_http(response)
        async def runaway(itype, value):
            for _ in range(61):
                await base.fetch_json("GET", "https://internetdb.shodan.io/8.8.8.8")
            return VendorResult(source="internetdb", indicator=value, indicator_type=itype)
        with patch.object(bulk.MODULES["internetdb"], "lookup", side_effect=runaway):
            _, job = await self.run_job(bulk.Params(document_id=self.report(), providers=("internetdb",)))
        self.assertEqual(job["state"], "queued")
        self.assertEqual(len(requests), 60)
        self.assertIsNone(job["coverage_checkpoint"])

    async def test_byte_budget_charges_failed_responses_before_next_unit(self):
        self.source("internetdb")
        requests = []
        def response(request):
            requests.append(request)
            return httpx.Response(404)
        self.mock_http(response)
        async def many(itype, value):
            for _ in range(10):
                await base.fetch_json("GET", "https://internetdb.shodan.io/8.8.8.8")
            return VendorResult(source="internetdb", indicator=value, indicator_type=itype)
        with patch.object(bulk.MODULES["internetdb"], "lookup", side_effect=many):
            _, job = await self.run_job(bulk.Params(document_id=self.report(), providers=("internetdb",)))
        self.assertEqual(len(requests), 6)
        self.assertEqual(job["state"], "queued")

    async def test_durable_daily_bound_prevents_http_even_without_manual_limit(self):
        self.source("internetdb")
        stamp = datetime.now(timezone.utc).timestamp()
        with evidence.connect() as conn, conn:
            conn.executemany("INSERT INTO feed_request_usage VALUES ('internetdb',?)", [(stamp,)]*1000)
        self.mock_http(lambda request: self.fail("daily quota exhausted"))
        _, job = await self.run_job(bulk.Params(document_id=self.report(), providers=("internetdb",)))
        self.assertEqual(job["error_code"], "rate_limit")

    async def test_cancellation_after_request_retains_capture_without_saving_unit(self):
        self.source("internetdb")
        ident = self.report()
        params = bulk.Params(document_id=ident, providers=("internetdb",))
        job_id = self.service.enqueue(params, "cancel-me")
        def response(request):
            self.service.runner.cancel(job_id)
            return httpx.Response(200, json={"ports": [80]})
        self.mock_http(response)
        await asyncio.to_thread(self.service.runner.run_next)
        job = self.service.runner.get(job_id)
        self.assertEqual(job["state"], "cancelled")
        self.assertFalse(saved.detail(ident)["bulk_results"])

    async def test_time_budget_and_source_revocation_between_units(self):
        self.source("internetdb")
        calls = []
        def response(request):
            calls.append(request)
            self.source("internetdb", False)
            return httpx.Response(200, json={"ports": [80]})
        self.mock_http(response)
        _, job = await self.run_job(bulk.Params(document_id=self.report("8.8.8.8 and 1.1.1.1"), providers=("internetdb",)))
        self.assertEqual(job["error_code"], "source_ineligible")
        self.assertEqual(len(calls), 1)
        self.source("internetdb")
        parent_init = bulk.BulkScope.__init__
        def elapsed(scope, *args):
            parent_init(scope, *args)
            scope.started -= 121
        self.mock_http(lambda request: self.fail("time budget exhausted"))
        with patch.object(bulk.BulkScope, "__init__", elapsed):
            _, job = await self.run_job(bulk.Params(document_id=self.report(), providers=("internetdb",)), "elapsed")
        self.assertEqual(job["state"], "queued")

    async def test_enrich_all_splits_replays_and_finishes_every_saved_indicator(self):
        self.source("internetdb")
        self.mock_http(lambda request: httpx.Response(200, json={"ports": [80]}))
        ident = self.report(" ".join(f"8.8.8.{i}" for i in range(1, 12)))
        ids = await asyncio.to_thread(self.service.enqueue_all, ident, ("internetdb",), "all-request")
        self.assertEqual(len(ids), 2)
        self.assertEqual(ids, await asyncio.to_thread(self.service.enqueue_all, ident, ("internetdb",), "all-request"))
        for _ in ids:
            await asyncio.to_thread(self.service.runner.run_next)
        self.assertTrue(all(self.service.runner.get(i)["state"] == "succeeded" for i in ids))
        self.assertEqual(len(saved.detail(ident)["bulk_results"]), 11)

    async def test_explicit_public_source_handling_can_retain_exact_provider_bytes(self):
        self.source("internetdb")
        patches = {"archive_enabled": True, "archive_root": Path(self.directory.name) / "originals",
                   "archive_public_sources": ("enrich.internetdb",), "archive_response_bytes": 1000,
                   "archive_source_bytes": 2000, "archive_total_bytes": 3000, "archive_retention_seconds": 60}
        for name, value in patches.items():
            p = patch.object(settings, name, value)
            p.start()
            self.addCleanup(p.stop)
        raw = b'{"ports": [443]}'
        self.mock_http(lambda request: httpx.Response(200, content=raw))
        report = self.report()
        _, job = await self.run_job(bulk.Params(document_id=report, providers=("internetdb",)))
        self.assertEqual(job["state"], "succeeded")
        capture = saved.detail(report)["bulk_results"][0]["captured_document_id"]
        self.assertEqual(archives.read(capture), raw)

    async def test_rdap_fixed_registry_redirect_rechecks_quotas_and_retains_attributes(self):
        self.source("rdap")
        requests = []
        def response(request):
            requests.append(request)
            if request.url.host == "rdap.org":
                return httpx.Response(302, headers={"Location": "https://rdap.verisign.com/com/v1/domain/example.com"})
            return httpx.Response(200, json={"nameservers": [{"ldhName": "ns1.example.invalid"}],
                "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]})
        self.mock_http(response)
        ident = self.report("example.com")
        _, job = await self.run_job(bulk.Params(document_id=ident, providers=("rdap",)))
        self.assertEqual(job["state"], "succeeded")
        self.assertEqual(len(requests), 2)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(json.loads(saved.detail(ident)["bulk_results"][0]["result_json"])["summary"]["nameservers"], ["ns1.example.invalid"])


class FetchCaptureTests(unittest.IsolatedAsyncioTestCase):
    async def test_fetched_entity_bytes_are_retained_before_normalization_without_refetch(self):
        calls = []
        raw = b"<html><article><p>bad[.]example</p></article></html>"
        def response(request):
            calls.append(request)
            return httpx.Response(200, content=raw, headers={"Content-Type": "text/html; charset=utf-8"})
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(response)))
        try:
            doc, kind, error = await fetch.fetch_document("https://publisher.invalid/report")
            self.assertIsNone(error)
            self.assertEqual(doc.original_bytes, raw)
            self.assertIn("bad[.]example", doc.text)
            self.assertEqual(len(calls), 1)
            self.assertIsNotNone(doc.collected_at)
        finally:
            await base.aclose()
