"""Independent additive ledger. Nothing here enables a source or schedule."""

VERSION_1 = """
CREATE TABLE evidence_ransomware_batches (
    document_id INTEGER PRIMARY KEY REFERENCES evidence_documents(id),
    job_id TEXT NOT NULL REFERENCES durable_jobs(id),
    payload TEXT NOT NULL,
    next_row INTEGER NOT NULL DEFAULT 0,
    row_count INTEGER NOT NULL CHECK(row_count BETWEEN 1 AND 100)
);
CREATE TABLE evidence_ransomware_claims (
    id INTEGER PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES evidence_sources(source_id),
    external_key TEXT NOT NULL,
    UNIQUE(source_id,external_key)
);
CREATE TABLE evidence_ransomware_captures (
    claim_id INTEGER NOT NULL REFERENCES evidence_ransomware_claims(id),
    document_id INTEGER NOT NULL REFERENCES evidence_documents(id),
    row_number INTEGER NOT NULL,
    metadata TEXT NOT NULL,
    PRIMARY KEY(claim_id,document_id)
);
CREATE TABLE evidence_ransomware_subjects (
    observation_id INTEGER PRIMARY KEY REFERENCES evidence_observations(id),
    claim_id INTEGER NOT NULL REFERENCES evidence_ransomware_claims(id)
);
CREATE INDEX evidence_ransomware_capture_document ON evidence_ransomware_captures(document_id);
"""
MIGRATIONS = ((1, VERSION_1),)


def migrate(conn):
    if conn.in_transaction:
        raise RuntimeError("Ransomware migration requires its own transaction")
    conn.execute("PRAGMA foreign_keys=ON")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS evidence_ransomware_versions(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        applied = {r[0] for r in conn.execute("SELECT version FROM evidence_ransomware_versions")}
        if not applied.issubset({v for v, _ in MIGRATIONS}):
            raise RuntimeError("Database has a newer ransomware schema")
        for version, script in MIGRATIONS:
            if version not in applied:
                for statement in script.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute("INSERT INTO evidence_ransomware_versions VALUES (?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))", (version,))
