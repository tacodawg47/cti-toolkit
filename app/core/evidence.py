"""Shared metadata access. Inputs are passive evidence, never action instructions.

Writes are short transactions on their own connections. A caller must supply
stable capture/observation/citation keys to replay interrupted imports. Reusing
a key with different content raises EvidenceConflict rather than losing history.
An unresolved citation replay also preserves a later explicit resolution.
"""

from contextlib import contextmanager
from collections.abc import Iterator
import sqlite3

from . import db
from .evidence_models import Citation, Document, Metadata, Observation, Source, SourceLink


class EvidenceConflict(ValueError):
    """A stable identity was reused with different metadata."""


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    # Legacy module connections keep their existing FK behavior. Every corpus
    # connection enforces its own references, including tests and future jobs.
    with db.connect() as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        yield conn


def _row(row) -> dict | None:
    return dict(row) if row is not None else None


def save_source(source: Source) -> None:
    """Explicitly replace current registry metadata; preserve the stable identity.

    This is a local record of a decision, not permission for network traffic.
    Documents do not run this function based on their embedded content.
    """
    values = source.model_dump()
    columns = ", ".join(values)
    updates = ", ".join(f"{name}=excluded.{name}" for name in values if name != "source_id")
    with connect() as conn, conn:
        conn.execute(f"INSERT INTO evidence_sources ({columns}) VALUES ({', '.join('?' for _ in values)}) "
                     f"ON CONFLICT(source_id) DO UPDATE SET {updates}", tuple(values.values()))


def _ensure_source(conn: sqlite3.Connection, source_id: str) -> None:
    conn.execute("INSERT INTO evidence_sources(source_id, name) VALUES (?, ?) ON CONFLICT(source_id) DO NOTHING",
                 (source_id, source_id))


def get_source(source_id: str) -> Source | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM evidence_sources WHERE source_id=?", (source_id,)).fetchone()
        return Source(**dict(row)) if row else None


def require_collection(source_id: str, access_method: str, *, connection: sqlite3.Connection | None = None) -> Source:
    """Recheck each bounded unit/retry, optionally in the runner's transaction."""
    if connection is None:
        source = get_source(source_id)
    else:
        row = connection.execute("SELECT * FROM evidence_sources WHERE source_id=?", (source_id,)).fetchone()
        source = Source(**dict(row)) if row else None
    if source is None or not source.eligible or source.access_method != access_method:
        raise PermissionError("Source is not eligible for this collection method")
    return source


def _page(limit: int, offset: int) -> tuple[int, int]:
    if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or offset < 0:
        raise ValueError("Use a limit of 1 to 200 and a nonnegative offset")
    return limit, offset


def list_sources(*, limit: int = 100, offset: int = 0) -> list[Source]:
    with connect() as conn:
        return [Source(**dict(row)) for row in conn.execute(
            "SELECT * FROM evidence_sources ORDER BY source_id LIMIT ? OFFSET ?", _page(limit, offset))]


def _snapshot(conn: sqlite3.Connection, table: str, model: Metadata, keys: tuple[str, ...]) -> int:
    # table and keys are internal constants, never input strings.
    if not conn.in_transaction:
        conn.execute("BEGIN IMMEDIATE")
    values = model.model_dump()
    where = " AND ".join(f"{key}=?" for key in keys)
    row = conn.execute(f"SELECT * FROM {table} WHERE {where}", tuple(values[key] for key in keys)).fetchone()
    if row:
        if any(row[name] != value for name, value in values.items()):
            raise EvidenceConflict("Identity already exists with different metadata; use a new capture/key")
        return row["id"]
    cursor = conn.execute(f"INSERT INTO {table} ({', '.join(values)}) VALUES ({', '.join('?' for _ in values)})",
                          tuple(values.values()))
    return cursor.lastrowid


def record_document(document: Document) -> int:
    """Record one immutable capture/revision, auto-registering unknown sources as F.

    Recording an existing capture is allowed for disabled sources. It performs
    no collection and makes no claim that collection was approved at the time.
    """
    with connect() as conn, conn:
        _ensure_source(conn, document.source_id)
        return _snapshot(conn, "evidence_documents", document, ("source_id", "external_id", "capture_key"))


def get_document(document_id: int) -> dict | None:
    with connect() as conn:
        return _row(conn.execute("SELECT * FROM evidence_documents WHERE id=?", (document_id,)).fetchone())


def record_observation(observation: Observation) -> int:
    with connect() as conn, conn:
        ident = _snapshot(conn, "evidence_observations", observation, ("document_id", "observation_key"))
        from .alerts import match_observation

        match_observation(conn, ident)
        return ident


def observations_for_subject(subject_type: str, subject_value: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
    """Return separate source assertions; a mention does not establish maliciousness."""
    with connect() as conn:
        return [dict(row) for row in conn.execute("""SELECT o.*, d.source_id, d.source_url,
            d.source_published_at, d.collected_at, d.capture_key, d.source_revision, d.job_run_id
            FROM evidence_observations o JOIN evidence_documents d ON d.id=o.document_id
            WHERE o.subject_type=? AND o.subject_value=? ORDER BY o.id LIMIT ? OFFSET ?""",
            (subject_type, subject_value, *_page(limit, offset)))]


def record_citation(citation: Citation) -> int:
    with connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM evidence_citations WHERE document_id=? AND citation_key=?",
                           (citation.document_id, citation.citation_key)).fetchone()
        if row and row["target_document_id"] is not None and citation.target_document_id is None:
            # Replaying the original unresolved input must not undo a manually
            # resolved hop or force a duplicate edge after interrupted import.
            values = citation.model_dump(exclude={"target_document_id", "resolution_note"})
            if any(row[name] != value for name, value in values.items()):
                raise EvidenceConflict("Citation identity already has different evidence")
            return row["id"]
        return _snapshot(conn, "evidence_citations", citation, ("document_id", "citation_key"))


def resolve_citation(citation_id: int, target_document_id: int, note: str) -> None:
    """Explicitly resolve one hop, retaining its original reference and excerpt."""
    with connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM evidence_citations WHERE id=?", (citation_id,)).fetchone()
        if row is None:
            raise KeyError(citation_id)
        values = {key: row[key] for key in Citation.model_fields}
        resolved = Citation(**{**values, "target_document_id": target_document_id, "resolution_note": note})
        if row["target_document_id"] is not None and (
                row["target_document_id"] != resolved.target_document_id or row["resolution_note"] != resolved.resolution_note):
            raise EvidenceConflict("Citation already resolved; record a separate correction edge")
        conn.execute("UPDATE evidence_citations SET target_document_id=?, resolution_note=? WHERE id=?",
                     (resolved.target_document_id, resolved.resolution_note, citation_id))


def citations_for_document(document_id: int, *, incoming: bool = False, limit: int = 100, offset: int = 0) -> list[dict]:
    column = "target_document_id" if incoming else "document_id"
    with connect() as conn:
        return [dict(row) for row in conn.execute(
            f"SELECT * FROM evidence_citations WHERE {column}=? ORDER BY id LIMIT ? OFFSET ?",
            (document_id, *_page(limit, offset)))]


def record_source_link(link: SourceLink) -> int:
    with connect() as conn, conn:
        return _snapshot(conn, "evidence_source_links", link,
                         ("source_id", "upstream_source_id", "relationship", "scope"))


def links_for_source(source_id: str, *, limit: int = 100, offset: int = 0) -> list[dict]:
    with connect() as conn:
        return [dict(row) for row in conn.execute(
            "SELECT * FROM evidence_source_links WHERE source_id=? ORDER BY id LIMIT ? OFFSET ?",
            (source_id, *_page(limit, offset)))]
