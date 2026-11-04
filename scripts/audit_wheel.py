"""
Static audit of a Python wheel before it is installed.

A wheel is a zip file. Installing one copies files into site-packages and
runs no code, so the question is what those files DO once imported. This
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
  5. With --source <dir>, the wheel's package is compared file by file with
     the package in the project's own source archive from GitHub. A file
     that is in the wheel but not in the repository is the signature of a
     tampered build (the 2024 xz-utils backdoor lived in a release tarball
     that did not match the repository).

Exit status is 1 when a hard check (1, 2, 3, or 5) fails, 0 otherwise.
Pattern hits (4) are printed for review and do not change the exit status
unless --strict is given.

Usage (run with -I so nothing in the current directory is importable):

    python -I scripts/audit_wheel.py path/to/pkg-1.0-py3-none-any.whl \
        --expect-sha256 <digest from PyPI> --source path/to/extracted/repo

Standard library only, on purpose: an audit tool must not need the thing
it audits.
"""

import argparse
import base64
import hashlib
import re
import sys
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
    for line in text.splitlines():
        if not line.strip():
            continue
        path, digest, _size = line.rsplit(",", 2)
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
            continue                     # RECORD lists itself without a hash
        algo, want = entry
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
                hits.append(f"{name}:{lineno}: {why}: {line.strip()[:120]}")
                break                    # one report per line is enough


def compare_with_source(zf: zipfile.ZipFile, package: str, source: Path, problems: list[str]) -> int:
    """Compare the wheel's <package>/ tree with the same tree in the source
    archive. Returns the number of files compared."""
    candidates = [p.parent for p in source.rglob(f"{package}/__init__.py")]
    if not candidates:
        problems.append(f"source: no directory named {package} with __init__.py under {source}")
        return 0
    src_pkg = min(candidates, key=lambda p: len(p.parts))     # shallowest match
    src_files = {str(p.relative_to(src_pkg).as_posix()): sha256_file(p)
                 for p in src_pkg.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
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
    args = ap.parse_args(argv)

    problems: list[str] = []
    hits: list[str] = []

    print(f"wheel: {args.wheel.name} ({args.wheel.stat().st_size:,} bytes)")
    digest = sha256_file(args.wheel)
    print(f"sha256: {digest}")
    if args.expect_sha256:
        if digest.lower() == args.expect_sha256.lower():
            print("  matches the expected digest")
        else:
            problems.append("sha256 does NOT match the expected digest")

    with zipfile.ZipFile(args.wheel) as zf:
        names = [n for n in zf.namelist() if not n.endswith("/")]
        dist_infos = sorted({PurePosixPath(n).parts[0] for n in names if ".dist-info/" in n})
        if len(dist_infos) != 1:
            problems.append(f"expected one .dist-info directory, found {dist_infos}")
            dist_info = dist_infos[0] if dist_infos else ""
        else:
            dist_info = dist_infos[0]
        top_level = sorted({PurePosixPath(n).parts[0] for n in names
                            if not PurePosixPath(n).parts[0].endswith((".dist-info", ".data"))})
        print(f"files: {len(names)}; top-level: {', '.join(top_level)}; metadata: {dist_info}")

        if dist_info:
            check_record(zf, dist_info, problems)
            if f"{dist_info}/entry_points.txt" in names:
                print("entry points (review):")
                for line in zf.read(f"{dist_info}/entry_points.txt").decode().splitlines():
                    if line.strip():
                        print(f"  {line}")

        pure = args.wheel.name.endswith("-py3-none-any.whl") or "-none-any.whl" in args.wheel.name
        for name in names:
            low = name.lower()
            if low.endswith(".pth"):
                problems.append(f"startup hook: {name} (.pth files run when the interpreter starts)")
            if pure and low.endswith(PURE_WHEEL_BINARIES):
                problems.append(f"binary inside a pure-Python wheel: {name}")
            if ".data/scripts/" in name:
                problems.append(f"script installed to bin/: {name}")
            if low.endswith(".py"):
                scan_python(name, zf.read(name), hits)

        if args.source:
            if not args.source.is_dir():
                problems.append(f"source: {args.source} is not a directory")
            elif top_level:
                n = compare_with_source(zf, top_level[0], args.source, problems)
                print(f"source comparison: {n} wheel files checked against {args.source}")

    print()
    if hits:
        print(f"pattern hits for review ({len(hits)}):")
        for h in hits:
            print(f"  {h}")
    else:
        print("pattern hits for review: none")
    print()
    if problems:
        print(f"HARD FINDINGS ({len(problems)}):")
        for p in problems:
            print(f"  {p}")
        return 1
    print("hard findings: none")
    return 1 if (args.strict and hits) else 0


if __name__ == "__main__":
    sys.exit(main())
