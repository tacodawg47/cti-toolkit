"""
Static audit of a Python wheel before it is installed.

A wheel is a zip file. Installation avoids source build hooks, but files
such as .pth or sitecustomize.py can execute on the next Python startup,
without the package being explicitly imported. This
script answers the checks a person would make by hand, deterministically:

  1. The wheel's SHA-256 matches the digest PyPI publishes (--expect-sha256).
  2. The RECORD manifest inside the wheel matches the files actually in it,
     so nothing was added or altered after the wheel was built.
  3. Nothing that executes outside a normal import: no .pth files (Python
     runs those at interpreter start-up), no compiled binaries in a pure
     Python wheel, no scripts dropped into bin/. Console entry points are
     listed for review.
  4. Every .py file is scanned for the building blocks of a malicious
     payload: process execution, dynamic code (eval/exec/marshal/pickle),
     network access, decoding of embedded blobs, and long encoded string
     literals. These are LEADS for a human to read, not verdicts: a PDF
     library legitimately uses zlib, a CLI legitimately uses subprocess.
  5. With --source <dir>, every top-level package or module is compared with
     the project's own source archive from GitHub. A file
     that is in the wheel but not in the repository is the signature of a
     tampered build (the 2024 xz-utils backdoor lived in a release tarball
     that did not match the repository).

  6. Bound archive size/expansion, strings and common decoding. Report
     destination candidates with source locations, decoded origin and an
     optional previously reviewed baseline. Never contact them or run code.

Exit status is 1 when a hard check fails or bounded coverage is incomplete.
Pattern hits (4) are printed for review and do not change the exit status
unless --strict is given.

Usage (use a trusted interpreter; -I ignores local import paths and -S
disables site initialization, including installed .pth startup hooks):

    python -I -S scripts/audit_wheel.py path/to/pkg-1.0-py3-none-any.whl \
        --expect-sha256 <digest from PyPI> --source path/to/extracted/repo

Standard library only, on purpose: an audit tool must not need the thing
it audits.
"""

import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
import re
import stat
import sys
import time
import zipfile
from pathlib import Path, PurePosixPath

# Patterns worth a human look, with a one-line reason each. Kept broad on
# purpose; the output says where, the reader decides.
PATTERNS: list[tuple[str, str]] = [
    (r"\bsubprocess\b|\bos\.system\b|\bos\.popen\b|\bos\.exec[lv]p?e?\b|\bos\.spawn",
     "runs external processes"),
    # re.compile builds a regex, not code, so it is excluded from the compile() check.
    (r"\beval\s*\(|\bexec\s*\(|(?<!re\.)\bcompile\s*\(", "evaluates code built at runtime"),
    (r"\b__import__\s*\(|\bimportlib\.import_module\b", "imports a module by name at runtime"),
    (r"\bmarshal\.loads\b|\bpickle\.loads?\b|\bpickle\.Unpickler\b", "deserialises code or objects"),
    (r"\bbase64\.(b64|b32|b16|a85|b85)decode\b|\bcodecs\.decode\(.*rot.?13", "decodes an embedded blob"),
    (r"\bsocket\b|\burllib\.request\b|\bhttp\.client\b|\brequests\b|\bhttpx\b|\baiohttp\b|\bftplib\b|\bsmtplib\b",
     "network access"),
    (r"\bctypes\b|\bcffi\b", "calls native code"),
    (r"\bos\.environ\b|\bgetenv\s*\(", "reads environment variables (where secrets live)"),
    (r"\.ssh\b|\.aws\b|\.gnupg\b|\.netrc\b|id_rsa|\.docker/config", "touches credential files"),
    (r"\bchr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(", "builds strings character by character (obfuscation)"),
    (r"(?:\\x[0-9a-fA-F]{2}){8,}", "long hex-escaped string"),
    (r"['\"][A-Za-z0-9+/=]{200,}['\"]", "long base64-looking string literal"),
    (r"\bgetattr\s*\(\s*(?:builtins|__builtins__)", "indirect access to built-ins (obfuscation)"),
]
_COMPILED = [(re.compile(p), why) for p, why in PATTERNS]

PURE_WHEEL_BINARIES = (".so", ".pyd", ".dll", ".dylib", ".exe")
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_MEMBERS = 10000
MAX_SECONDS = 30

# Resolve our reviewed sibling by exact path, including under python -I -S.
# Nothing from the archive is added to sys.path or imported.
_spec = importlib.util.spec_from_file_location("toolkit_artifact_strings", Path(__file__).with_name("artifact_strings.py"))
_strings = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_strings)


class BoundedZip(zipfile.ZipFile):
    def __init__(self, path):
        super().__init__(path)
        self.deadline = time.monotonic() + MAX_SECONDS

    def read(self, name, pwd=None):
        if time.monotonic() > self.deadline:
            raise ValueError("archive processing time limit reached")
        info = self.getinfo(name) if isinstance(name, str) else name
        with self.open(info, pwd=pwd) as stream:
            data = stream.read(MAX_MEMBER + 1)
        if len(data) > MAX_MEMBER:
            raise ValueError("archive member expanded beyond limit")
        return data


def archive_problems(zf):
    problems, seen = [], set()
    entries = zf.infolist()
    if len(entries) > MAX_MEMBERS:
        return ["archive member-count limit exceeded"]
    if sum(info.file_size for info in entries) > MAX_EXPANDED:
        problems.append("archive expanded-size limit exceeded")
    for info in entries:
        path = PurePosixPath(info.filename)
        if (not path.parts or path.is_absolute() or ".." in path.parts
                or any(character in info.filename for character in '\\:*?"<>|[]')):
            problems.append(f"unsafe archive path: {info.filename}")
        if info.filename in seen:
            problems.append(f"duplicate archive member: {info.filename}")
        seen.add(info.filename)
        if stat.S_ISLNK(info.external_attr >> 16):
            problems.append(f"archive symlink: {info.filename}")
        if info.flag_bits & 1:
            problems.append(f"encrypted archive member: {info.filename}")
        if info.file_size > MAX_MEMBER or info.file_size > max(1, info.compress_size) * 1000:
            problems.append(f"archive member size/expansion-ratio limit exceeded: {info.filename}")
        if info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
            problems.append(f"unsupported archive compression: {info.filename}")
    return problems


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def record_entries(zf: zipfile.ZipFile, dist_info: str) -> dict[str, tuple[str, str] | None]:
    """Parse RECORD: path -> (algorithm, urlsafe-b64 digest) or None for RECORD itself."""
    out: dict[str, tuple[str, str] | None] = {}
    text = zf.read(f"{dist_info}/RECORD").decode("utf-8")
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        if len(row) != 3:
            raise ValueError("invalid RECORD row")
        path, digest, _size = row
        if path in out:
            raise ValueError("duplicate RECORD path")
        if digest:
            algo, _, value = digest.partition("=")
            out[path] = (algo, value)
        else:
            out[path] = None
    return out


def check_record(zf: zipfile.ZipFile, dist_info: str, problems: list[str]) -> None:
    rec = record_entries(zf, dist_info)
    names = [n for n in zf.namelist() if not n.endswith("/")]
    for name in names:
        entry = rec.get(name, "missing")
        if entry == "missing":
            problems.append(f"RECORD: file not listed: {name}")
            continue
        if entry is None:
            if name != f"{dist_info}/RECORD":
                problems.append(f"RECORD: unhashed member: {name}")
            continue
        algo, want = entry
        if algo not in {"sha256", "sha384", "sha512"}:
            problems.append(f"RECORD: unsupported or weak hash: {name}")
            continue
        data = zf.read(name)
        got = base64.urlsafe_b64encode(hashlib.new(algo, data).digest()).rstrip(b"=").decode()
        if got != want:
            problems.append(f"RECORD: hash mismatch for {name}")
    for path in rec:
        if path not in names:
            problems.append(f"RECORD: listed but absent from the wheel: {path}")


def scan_python(name: str, data: bytes, hits: list[str]) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        hits.append(f"{name}: not valid UTF-8 (unusual for a .py file)")
        return
    for lineno, line in enumerate(text.splitlines(), 1):
        for rx, why in _COMPILED:
            if rx.search(line):
                hits.append(f"{name}:{lineno}: {why}: {_strings.redact(line.strip())[:120]}")
                break                    # one report per line is enough


def compare_with_source(zf: zipfile.ZipFile, package: str, source: Path, problems: list[str]) -> int:
    """Compare the wheel's <package>/ tree with the same tree in the source
    archive. Returns the number of files compared."""
    candidates = []
    for number, path in enumerate(source.rglob(f"{package}/__init__.py")):
        if time.monotonic() > zf.deadline or number >= MAX_MEMBERS:
            raise ValueError("source search resource limit reached")
        if not path.is_symlink() and path.resolve().is_relative_to(source.resolve()):
            candidates.append(path.parent)
    if not candidates:
        candidates = [p for p in (source / package, source / "src" / package)
                      if p.is_dir() and not p.is_symlink() and p.resolve().is_relative_to(source.resolve())]
    if not candidates:
        problems.append(f"source: no directory named {package} with __init__.py under {source}")
        return 0
    src_pkg = min(candidates, key=lambda p: len(p.parts))     # shallowest match
    src_files = {}
    for path in src_pkg.rglob("*"):
        if time.monotonic() > zf.deadline:
            raise ValueError("source comparison time limit reached")
        if path.is_file() and "__pycache__" not in path.parts:
            if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
                problems.append(f"source: symlink or escaped path: {path.relative_to(source)}")
            elif path.stat().st_size > MAX_MEMBER:
                problems.append(f"source: file exceeds comparison limit: {path.relative_to(source)}")
            else:
                src_files[path.relative_to(src_pkg).as_posix()] = sha256_file(path)
    wheel_files = {}
    for name in zf.namelist():
        if name.startswith(f"{package}/") and not name.endswith("/"):
            wheel_files[name[len(package) + 1:]] = sha256_bytes(zf.read(name))
    for rel, digest in sorted(wheel_files.items()):
        if rel not in src_files:
            problems.append(f"source: in wheel but NOT in repository: {package}/{rel}")
        elif src_files[rel] != digest:
            problems.append(f"source: differs from repository: {package}/{rel}")
    for rel in sorted(set(src_files) - set(wheel_files)):
        if rel.endswith(".py"):
            print(f"  note: in repository but not in wheel (normal for tests/dev files): {package}/{rel}")
    return len(wheel_files)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("wheel", type=Path)
    ap.add_argument("--expect-sha256", help="digest PyPI lists for this file")
    ap.add_argument("--source", type=Path, help="extracted source archive (GitHub tag) to compare against")
    ap.add_argument("--strict", action="store_true", help="pattern hits also fail the run")
    ap.add_argument("--report", type=Path, help="write a local JSON strings/destination review report")
    ap.add_argument("--baseline", type=Path, help="previously reviewed JSON report; highlight new hosts and changed members")
    args = ap.parse_args(argv)

    if args.report and (args.report.suffix.lower() != ".json" or args.report.exists()
                        or args.report.resolve() == args.wheel.resolve()
                        or args.baseline and args.report.resolve() == args.baseline.resolve()):
        ap.error("use a new .json report path; never overwrite an artifact or prior review")

    problems: list[str] = []
    hits: list[str] = []
    strings = _strings.Review()

    if args.wheel.stat().st_size > MAX_ARCHIVE:
        print("HARD FINDINGS: archive input-size limit exceeded")
        return 1

    print(f"wheel: {json.dumps(args.wheel.name)} ({args.wheel.stat().st_size:,} bytes)")
    digest = sha256_file(args.wheel)
    print(f"sha256: {digest}")
    if args.expect_sha256:
        if digest.lower() == args.expect_sha256.lower():
            print("  matches the expected digest")
        else:
            problems.append("sha256 does NOT match the expected digest")

    try:
        return _audit(args, problems, hits, strings, digest)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, RuntimeError) as exc:
        # Do not interpolate arbitrary exception strings from untrusted input.
        print(f"HARD FINDINGS: audit incomplete ({type(exc).__name__}); do not approve this artifact")
        return 1


def _audit(args, problems, hits, strings, digest):
    with BoundedZip(args.wheel) as zf:
        unsafe = archive_problems(zf)
        if unsafe:
            for problem in unsafe:
                print("HARD FINDINGS: " + json.dumps(problem, ensure_ascii=True))
            return 1
        names = [n for n in zf.namelist() if not n.endswith("/")]
        dist_infos = sorted({PurePosixPath(n).parts[0] for n in names if ".dist-info/" in n})
        if len(dist_infos) != 1:
            problems.append(f"expected one .dist-info directory, found {dist_infos}")
            dist_info = dist_infos[0] if dist_infos else ""
        else:
            dist_info = dist_infos[0]
        top_level = sorted({PurePosixPath(n).parts[0] for n in names
                            if not PurePosixPath(n).parts[0].endswith((".dist-info", ".data"))})
        print(f"files: {len(names)}; top-level: {json.dumps(top_level)}; metadata: {json.dumps(dist_info)}")

        if dist_info:
            check_record(zf, dist_info, problems)
            if f"{dist_info}/entry_points.txt" in names:
                print("entry points (review):")
                for line in zf.read(f"{dist_info}/entry_points.txt").decode().splitlines():
                    if line.strip():
                        print("  " + json.dumps(_strings.redact(line), ensure_ascii=True))

        pure = args.wheel.name.endswith("-py3-none-any.whl") or "-none-any.whl" in args.wheel.name
        for name in names:
            low = name.lower()
            if low.endswith(".pth"):
                problems.append(f"startup hook: {name} (.pth files run when the interpreter starts)")
            if PurePosixPath(low).name in {"sitecustomize.py", "usercustomize.py"}:
                problems.append(f"startup hook: {name} (site initialization can import this automatically)")
            if pure and low.endswith(PURE_WHEEL_BINARIES):
                problems.append(f"binary inside a pure-Python wheel: {name}")
            if ".data/scripts/" in name:
                problems.append(f"script installed to bin/: {name}")
            data = zf.read(name)
            strings.member(name, data)
            if low.endswith(".py"):
                scan_python(name, data, hits)

        if args.source:
            if not args.source.is_dir():
                problems.append(f"source: {args.source} is not a directory")
            elif top_level:
                n = 0
                for package in top_level:
                    if any(name.startswith(package + "/") for name in names):
                        n += compare_with_source(zf, package, args.source, problems)
                    else:
                        candidates = [args.source / package, args.source / "src" / package]
                        original = next((path for path in candidates if path.is_file() and not path.is_symlink()
                                         and path.resolve().is_relative_to(args.source.resolve())), None)
                        if original is None or original.stat().st_size > MAX_MEMBER:
                            problems.append(f"source: top-level file not compared: {package}")
                        elif sha256_file(original) != sha256_bytes(zf.read(package)):
                            problems.append(f"source: differs from repository: {package}")
                        else:
                            n += 1
                print(f"source comparison: {n} wheel files checked against {args.source}")
        if time.monotonic() > zf.deadline:
            problems.append("archive processing time limit reached; coverage is incomplete")

    report = strings.result()
    report.update(artifact=args.wheel.name, sha256=digest, pattern_hits=hits)
    report["new_hosts"] = sorted({row["host"] for row in report["destinations"]})
    report["changed_members"] = sorted(report["members"])
    report["removed_hosts"], report["removed_members"] = [], []
    if args.baseline:
        if args.baseline.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("baseline report too large")
        baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
        if baseline.get("schema_version") != 1 or not isinstance(baseline.get("members"), dict):
            raise ValueError("unsupported baseline report")
        old_hosts = {row["host"] for row in baseline.get("destinations", [])}
        report["removed_hosts"] = sorted(old_hosts - set(report["new_hosts"]))
        report["removed_members"] = sorted(set(baseline["members"]) - set(report["members"]))
        report["new_hosts"] = sorted(set(report["new_hosts"]) - old_hosts)
        report["changed_members"] = sorted(name for name, value in report["members"].items()
                                           if baseline["members"].get(name) != value)
        report["baseline_sha256"] = baseline.get("sha256")
    problems.extend(report["coverage_issues"])
    report["hard_findings"] = list(problems)
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    print(f"strings examined: {report['strings_examined']}; destination candidates: {len(report['destinations'])}")
    for host in sorted({row["host"] for row in report["destinations"]}):
        print("  " + json.dumps(host) + (" [new/unbaselined]" if host in report["new_hosts"] else " [previously listed]"))
    print("Destinations are review leads, not observed connections. No network lookup performed.")

    print()
    if hits:
        print(f"pattern hits for review ({len(hits)}):")
        for h in hits:
            print("  " + json.dumps(h, ensure_ascii=True))
    else:
        print("pattern hits for review: none")
    print()
    if problems:
        print(f"HARD FINDINGS ({len(problems)}):")
        for p in problems:
            print("  " + json.dumps(p, ensure_ascii=True))
        return 1
    print("hard findings: none")
    return 1 if (args.strict and hits) else 0


if __name__ == "__main__":
    sys.exit(main())
