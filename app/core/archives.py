"""Private bounded entity-byte archives. Metadata survives file expiry.

No download, decompression, rendering, execution or external export lives here.
An OS-held lock serializes file/metadata reconciliation with all writers.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from itertools import islice
import os
from pathlib import Path
import re
from uuid import uuid4

from . import evidence
from .config import settings
from .job_lock import executor_lock

_maintenance = {"state": "Not Started", "last_attempt": None, "last_success": None}


def now():
    return datetime.now(timezone.utc)


def secret_material(raw: bytes) -> bool:
    # A guard against common accidental credentials, not a universal classifier.
    for name in type(settings).model_fields:
        if name.endswith(("_api_key", "_auth_key")) or name in ("github_token", "github_exposure_token"):
            key = getattr(settings, name)
            if key and key.encode() in raw:
                return True
    return bool(re.search(rb"(?i)(?:authorization\s*[:=]|-----BEGIN [A-Z ]*PRIVATE KEY|"
                          rb"(?:api[_-]?key|password|access[_-]?token|client[_-]?secret)"
                          rb"[\s\"']*[:=][\s\"']*[^\s\"',}]{4,}|https?://[^\s/]+:[^\s/]+@)", raw))


def _root():
    root = settings.archive_root
    limits = (settings.archive_response_bytes, settings.archive_source_bytes,
              settings.archive_total_bytes, settings.archive_retention_seconds)
    if root is None or any(type(v) is not int or v <= 0 for v in limits):
        raise ValueError("Explicit finite archive limits and root are required")
    if not limits[0] <= limits[1] <= limits[2] or limits[0] > 64*1024**2 or limits[3] > 366*86400:
        raise ValueError("Invalid archive limits")
    root = Path(root).absolute()
    # Keep bodies under ignored runtime data. An external DATA_DIR is an
    # operator configuration choice; source text never chooses this location.
    base = settings.data_dir.resolve()
    if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction()) for p in (root, *root.parents)):
        raise ValueError("Archive roots cannot use symlinks")
    root = root.resolve()
    if root == base or not root.is_relative_to(base):
        raise ValueError("Archive root must be a private subdirectory of DATA_DIR")
    return root


@contextmanager
def _locked():
    root = _root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with executor_lock(root / "archive") as acquired:
        if not acquired:
            raise RuntimeError("Archive maintenance is busy")
        yield root


def _path(root, key):
    if not isinstance(key, str) or not re.fullmatch(r"[a-f0-9]{32}\.blob", key):
        raise ValueError("Invalid generated archive key")
    path = root / key
    if path.is_symlink() or path.with_suffix(".tmp").is_symlink():
        raise ValueError("Archive files cannot use symlinks")
    return path


def _entries(root):
    entries = list(islice(root.iterdir(), 20001))
    if len(entries) > 20000:
        raise ValueError("Archive directory exceeds its maintenance entry limit")
    return entries


def get(document_id):
    with evidence.connect() as conn:
        row = conn.execute("SELECT * FROM evidence_archives WHERE document_id=?", (document_id,)).fetchone()
    result = dict(row) if row else None
    if result and result["state"] in ("stored", "pending") and result["expires_at"] <= now().isoformat(timespec="microseconds"):
        result.update(state="expired", reason="retention_elapsed")
    return result


def _update(document_id, state, reason):
    with evidence.connect() as conn, conn:
        conn.execute("UPDATE evidence_archives SET state=?,reason=? WHERE document_id=?", (state, reason, document_id))


def _valid(path, row):
    if not path.is_file() or path.stat().st_size != row["byte_count"]:
        return False
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest() == row["sha256"]


def _reconcile_row(root, row, stamp, verify=True):
    if row["root_token"] != sha256(str(root).encode()).hexdigest():
        return  # Different configured root: never claim its files were deleted.
    path = _path(root, row["storage_key"])
    temp = path.with_suffix(".tmp")
    if row["expires_at"] <= stamp or row["state"] in ("expired", "failed"):
        path.unlink(missing_ok=True)
        temp.unlink(missing_ok=True)
        if row["state"] != "failed":
            _update(row["document_id"], "expired", "retention_elapsed")
    elif (_valid(path, row) if verify or row["state"] == "pending" else
          path.is_file() and path.stat().st_size == row["byte_count"]):
        temp.unlink(missing_ok=True)
        _update(row["document_id"], "stored", "retained")
    else:
        path.unlink(missing_ok=True)
        temp.unlink(missing_ok=True)
        _update(row["document_id"], "failed", "missing_or_incomplete")


def reconcile(*, after=0, file_after="", limit=200, verify=True):
    """One bounded restart/retention page. Repeat cursors to finish maintenance.

    Works while storage is disabled if its explicit root/limits are retained.
    Missing/corrupt files lose availability; no evidence history is deleted.
    """
    if type(limit) is not int or not 1 <= limit <= 200 or type(after) is not int or after < 0:
        raise ValueError("Use bounded reconciliation pages")
    with _locked() as root:
        with evidence.connect() as conn:
            rows = [dict(r) for r in conn.execute("""SELECT * FROM evidence_archives
                WHERE storage_key IS NOT NULL AND document_id>? ORDER BY document_id LIMIT ?""", (after, limit))]
        processed, verified_bytes = [], 0
        for row in rows:
            if verified_bytes >= 64*1024**2:
                break
            _reconcile_row(root, row, now().isoformat(timespec="microseconds"), verify)
            verified_bytes += row["byte_count"] if verify or row["state"] == "pending" else 0
            processed.append(row)
        # Only generated blob/tmp files are candidates. Never remove lock files
        # or arbitrary operator files. Known failed/expired leftovers are retried.
        files = sorted(p.name for p in _entries(root) if p.name > file_after
                       and re.fullmatch(r"[a-f0-9]{32}\.(?:blob|tmp)", p.name))[:limit]
        with evidence.connect() as conn:
            for name in files:
                key = name.rsplit(".", 1)[0] + ".blob"
                row = conn.execute("SELECT state FROM evidence_archives WHERE storage_key=?", (key,)).fetchone()
                path = _path(root, key) if name.endswith(".blob") else _path(root, key).with_suffix(".tmp")
                if row is None or row[0] in ("failed", "expired"):
                    path.unlink(missing_ok=True)
        return {"after": processed[-1]["document_id"] if processed else after,
                "file_after": files[-1] if files else file_after,
                "more": len(rows) == limit or len(processed) < len(rows) or len(files) == limit}


def retain(document_id, raw: bytes, *, media_type="application/octet-stream", representation="entity_bytes"):
    try:
        return _retain(document_id, raw, media_type=media_type, representation=representation)
    except (OSError, RuntimeError):
        # Metadata/normalization remain usable if local file IO fails. Do not
        # overwrite a concurrent writer's pending reservation or log OS paths.
        doc = evidence.get_document(document_id)
        if not isinstance(raw, bytes) or doc is None or doc["content_sha256"] != sha256(raw).hexdigest():
            raise
        with evidence.connect() as conn, conn:
            conn.execute("""INSERT OR IGNORE INTO evidence_archives
                (document_id,state,reason,sha256,byte_count,media_type,representation)
                VALUES (?,'failed','storage_unavailable',?,?,?,?)""",
                (document_id, sha256(raw).hexdigest(), len(raw), media_type[:128], representation[:64]))
        return get(document_id)


def _retain(document_id, raw: bytes, *, media_type, representation):
    if not isinstance(raw, bytes) or len(raw) > 64*1024**2:
        raise ValueError("Archive input must be bounded bytes")
    doc = evidence.get_document(document_id)
    if doc is None:
        raise KeyError(document_id)
    digest = sha256(raw).hexdigest()
    if doc["content_sha256"] != digest:
        raise evidence.EvidenceConflict("Original bytes do not match capture digest")
    existing = get(document_id)
    if existing:
        if existing["sha256"] != digest or existing["byte_count"] != len(raw):
            raise evidence.EvidenceConflict("Archive identity differs")
        return existing  # Expired/omitted originals are never silently resurrected.
    reason = ("disabled" if not settings.archive_enabled else
              "handling_required" if doc["sensitivity"] != "public" else
              "restricted_tlp" if doc["tlp"] not in (None, "CLEAR") else
              "credential_pattern" if secret_material(raw) else None)
    if reason:
        with evidence.connect() as conn, conn:
            conn.execute("""INSERT OR IGNORE INTO evidence_archives
                (document_id,state,reason,sha256,byte_count,media_type,representation)
                VALUES (?,'omitted',?,?,?,?,?)""", (document_id, reason, digest, len(raw), media_type[:128], representation[:64]))
        return get(document_id)
    with _locked() as root:
        existing = get(document_id)
        if existing:
            return existing
        # Reconcile pending work before reserving capacity. Every pending row
        # reserves bytes, including a writer that died before creating its file.
        with evidence.connect() as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            total = conn.execute("SELECT COALESCE(sum(byte_count),0) FROM evidence_archives WHERE state IN ('pending','stored')").fetchone()[0]
            # Count actual bytes too: a crash can leave an orphan or a failed
            # deletion. These bytes still consume physical capacity.
            entries = _entries(root)
            disk_total = sum(p.lstat().st_size for p in entries
                             if re.fullmatch(r"[a-f0-9]{32}\.(?:blob|tmp)", p.name))
            source = conn.execute("""SELECT COALESCE(sum(a.byte_count),0) FROM evidence_archives a
                JOIN evidence_documents d ON d.id=a.document_id WHERE d.source_id=? AND a.state IN ('pending','stored')""", (doc["source_id"],)).fetchone()[0]
            reason = ("response_limit" if len(raw) > settings.archive_response_bytes else
                      "file_count_limit" if len(entries) >= 10000 else
                      "source_limit" if source + len(raw) > settings.archive_source_bytes else
                      "total_limit" if max(total, disk_total) + len(raw) > settings.archive_total_bytes else None)
            key = uuid4().hex + ".blob" if reason is None else None
            expiry = (now() + timedelta(seconds=settings.archive_retention_seconds)).isoformat(timespec="microseconds")
            conn.execute("""INSERT INTO evidence_archives VALUES (?,?,?,?,?,?,?,?,?,?)""",
                         (document_id, "omitted" if reason else "pending", reason or "writing", digest, len(raw),
                          media_type[:128], representation[:64], key, sha256(str(root).encode()).hexdigest(), expiry))
        if reason:
            return get(document_id)
        path = _path(root, key)
        temp = path.with_suffix(".tmp")
        try:
            with temp.open("xb") as handle:
                if os.name != "nt":
                    os.chmod(temp, 0o600)
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
            _update(document_id, "stored", "retained")
        except OSError:
            # Pending metadata is deliberately recoverable on the next pass.
            # A completed atomic rename can still be recovered as stored.
            return get(document_id)
        return get(document_id)


def read(document_id):
    """Local service API only. No route renders or downloads hostile originals."""
    with _locked() as root:
        row = get(document_id)
        if row is None or row["storage_key"] is None:
            raise FileNotFoundError("Original is unavailable")
        _reconcile_row(root, row, now().isoformat(timespec="microseconds"))
        row = get(document_id)
        if row["state"] != "stored" or row["root_token"] != sha256(str(root).encode()).hexdigest():
            raise FileNotFoundError("Original is unavailable")
        return _path(root, row["storage_key"]).read_bytes()


async def serve(stopped):
    """Local-only bounded expiry/recovery pages. Never performs collection."""
    import asyncio
    cursor = {"after": 0, "file_after": ""}
    while not stopped.is_set():
        result = await asyncio.to_thread(maintenance, **cursor, verify=False)
        cursor = {"after": result["after"], "file_after": result["file_after"]} if result["more"] else {"after": 0, "file_after": ""}
        try:
            await asyncio.wait_for(stopped.wait(), timeout=1 if result["more"] else 30)
        except TimeoutError:
            pass


def maintenance(**options):
    _maintenance["last_attempt"] = now().isoformat()
    try:
        result = reconcile(**options)
    except (OSError, RuntimeError, ValueError):
        _maintenance["state"] = "Failed"
        return {"after": options.get("after", 0), "file_after": options.get("file_after", ""), "more": False}
    _maintenance.update(state="Incomplete" if result["more"] else "Current",
                        last_success=now().isoformat())
    return result


def health():
    return {**_maintenance, "state": _maintenance["state"] if settings.archive_root is not None else "Off",
            "storage_enabled": settings.archive_enabled}
