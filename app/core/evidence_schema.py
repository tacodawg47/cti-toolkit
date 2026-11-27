"""Additive, transactional shared-corpus migrations, independent of module schemas."""

import sqlite3


# Do not use PRAGMA user_version: other packages own their migrations too.
# No legacy rows are reinterpreted or copied. Their dates have different meanings.
VERSION_1 = """
CREATE TABLE evidence_sources (
    source_id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    homepage TEXT,
    source_class TEXT NOT NULL DEFAULT 'unknown'
        CHECK (source_class IN ('unknown','publisher','aggregator','legitimate_platform','criminal_operated','local')),
    access_method TEXT NOT NULL DEFAULT 'unknown'
        CHECK (access_method IN ('unknown','api','feed','public_page','manual')),
    reliability TEXT NOT NULL DEFAULT 'F' CHECK (reliability IN ('A','B','C','D','E','F')),
    terms_status TEXT NOT NULL DEFAULT 'unreviewed'
        CHECK (terms_status IN ('unreviewed','approved','restricted','denied')),
    terms_reviewed_on TEXT,
    terms_reference TEXT,
    collection_enabled INTEGER NOT NULL DEFAULT 0 CHECK (collection_enabled IN (0,1)),
    rate_limit_notes TEXT,
    license_name TEXT,
    license_reference TEXT,
    license_recorded_on TEXT,
    review_notes TEXT NOT NULL DEFAULT '',
    CHECK (terms_status='unreviewed' OR
        (length(trim(terms_reviewed_on))>0 AND length(trim(terms_reference))>0
         AND terms_reviewed_on IS NOT NULL AND terms_reference IS NOT NULL)),
    CHECK (license_name IS NULL OR
        (license_reference IS NOT NULL AND license_recorded_on IS NOT NULL)),
    CHECK (collection_enabled=0 OR
        (terms_status='approved' AND source_class<>'unknown' AND access_method<>'unknown'
         AND rate_limit_notes IS NOT NULL AND length(trim(rate_limit_notes))>0))
);
CREATE TABLE evidence_documents (
    id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
    external_id TEXT NOT NULL,
    capture_key TEXT NOT NULL,
    source_revision TEXT,
    title TEXT NOT NULL,
    publisher TEXT,
    source_url TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('report','post','paste','file','api_response','feed')),
    collection_method TEXT NOT NULL
        CHECK (collection_method IN ('api','feed','public_page','manual_paste','manual_file','local_import')),
    source_published_at TEXT,
    source_modified_at TEXT,
    collected_at TEXT NOT NULL,
    content_sha256 TEXT,
    sensitivity TEXT NOT NULL DEFAULT 'unknown' CHECK (sensitivity IN ('unknown','public','sensitive')),
    tlp TEXT CHECK (tlp IN ('CLEAR','GREEN','AMBER','AMBER+STRICT','RED')),
    job_run_id TEXT,
    UNIQUE (source_id, external_id, capture_key)
);
CREATE INDEX evidence_documents_job ON evidence_documents(job_run_id) WHERE job_run_id IS NOT NULL;
CREATE TABLE evidence_observations (
    id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES evidence_documents(id),
    observation_key TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_value TEXT NOT NULL,
    assertion TEXT NOT NULL DEFAULT 'mention' CHECK (assertion IN ('mention','reported','direct_observation')),
    observed_at TEXT,
    first_seen TEXT,
    last_seen TEXT,
    excerpt TEXT NOT NULL DEFAULT '',
    locator TEXT NOT NULL DEFAULT '',
    UNIQUE (document_id, observation_key)
);
CREATE INDEX evidence_observations_subject ON evidence_observations(subject_type, subject_value, id);
CREATE TABLE evidence_citations (
    id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES evidence_documents(id),
    citation_key TEXT NOT NULL,
    target_reference TEXT NOT NULL,
    target_document_id INTEGER REFERENCES evidence_documents(id),
    relationship TEXT NOT NULL CHECK (relationship IN ('cites','derived_from','republishes')),
    excerpt TEXT NOT NULL DEFAULT '',
    locator TEXT NOT NULL DEFAULT '',
    resolution_note TEXT NOT NULL DEFAULT '',
    UNIQUE (document_id, citation_key),
    CHECK (target_document_id IS NULL OR
        (target_document_id<>document_id AND length(trim(resolution_note))>0))
);
CREATE INDEX evidence_citations_target ON evidence_citations(target_document_id);
CREATE TABLE evidence_source_links (
    id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
    upstream_source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
    relationship TEXT NOT NULL CHECK (relationship IN ('derived_from','republishes')),
    scope TEXT NOT NULL,
    evidence_reference TEXT NOT NULL,
    recorded_on TEXT NOT NULL,
    UNIQUE (source_id, upstream_source_id, relationship, scope),
    CHECK (source_id<>upstream_source_id)
);
"""

VERSION_2 = """
CREATE TABLE evidence_archives (
    document_id INTEGER PRIMARY KEY REFERENCES evidence_documents(id),
    state TEXT NOT NULL CHECK(state IN ('pending','stored','omitted','expired','failed')),
    reason TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_count INTEGER NOT NULL CHECK(byte_count>=0),
    media_type TEXT NOT NULL,
    representation TEXT NOT NULL,
    storage_key TEXT,
    root_token TEXT,
    expires_at TEXT
);
CREATE INDEX evidence_archive_expiry ON evidence_archives(state,expires_at);
CREATE TABLE evidence_report_saves (
    save_key TEXT PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES evidence_documents(id),
    manifest_sha256 TEXT NOT NULL,
    complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)),
    indicator_count INTEGER NOT NULL,
    parser_version TEXT NOT NULL
);
CREATE TABLE evidence_bulk_results (
    job_id TEXT NOT NULL REFERENCES durable_jobs(id),
    unit_key TEXT NOT NULL,
    document_id INTEGER NOT NULL REFERENCES evidence_documents(id),
    subject_type TEXT NOT NULL,
    subject_value TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT NOT NULL,
    captured_document_id INTEGER REFERENCES evidence_documents(id),
    PRIMARY KEY(job_id,unit_key)
);
"""

MIGRATIONS = ((1, VERSION_1), (2, VERSION_2))


def migrate(conn: sqlite3.Connection) -> None:
    """Run before other initialization writes; caller owns the connection.

    Explicit BEGIN keeps DDL, reference metadata and version marking atomic.
    executescript would implicitly commit, so execute each static statement.
    BEGIN IMMEDIATE serializes simultaneous initializers before version reads.
    """
    if conn.in_transaction:
        raise RuntimeError("Evidence migration requires a connection outside a transaction")
    conn.execute("PRAGMA foreign_keys=ON")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS evidence_schema_versions (
            version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)""")
        applied = {row[0] for row in conn.execute("SELECT version FROM evidence_schema_versions")}
        known = {version for version, _ in MIGRATIONS}
        if not applied.issubset(known):
            raise RuntimeError("Database has a newer evidence schema; use matching application code")
        for version, script in MIGRATIONS:
            if version in applied:
                continue
            for statement in script.split(";"):
                if statement.strip():
                    conn.execute(statement)
            if version == 1:
                # One existing provider, as historical metadata only. Research is
                # not a current terms decision and never enables collection.
                conn.execute("""INSERT INTO evidence_sources
                    (source_id, name, homepage, source_class, access_method,
                     license_name, license_reference, license_recorded_on, review_notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                    "rvm", "Ransomware Vulnerability Matrix",
                    "https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix",
                    "aggregator", "feed", "CC BY 4.0",
                    "docs/research/2026-11-11-sources/bushido-ransomware-apt.md",
                    "2026-11-11",
                    "Historical license finding from saved research, not reverified. "
                    "Terms eligibility and rate limits remain unreviewed. Existing rvm feed is unchanged.",
                ))
            conn.execute("INSERT INTO evidence_schema_versions(version, applied_at) VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))", (version,))
