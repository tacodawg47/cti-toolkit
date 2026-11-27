"""Independent additive ledger. No source or selector is authorized here."""

VERSION_1 = """
CREATE TABLE breach_permissions (
    id INTEGER PRIMARY KEY,
    selector_id INTEGER NOT NULL REFERENCES evidence_selectors(id),
    approved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    authority_reference TEXT NOT NULL,
    consent_reference TEXT NOT NULL,
    purpose TEXT NOT NULL,
    revoked_at TEXT
);
CREATE UNIQUE INDEX breach_permission_active ON breach_permissions(selector_id) WHERE revoked_at IS NULL;
CREATE TABLE breach_suppressions (
    email_value TEXT PRIMARY KEY,
    suppressed_at TEXT NOT NULL
);
CREATE TABLE breach_units (
    job_id TEXT NOT NULL REFERENCES durable_jobs(id),
    permission_id INTEGER NOT NULL REFERENCES breach_permissions(id),
    document_id INTEGER REFERENCES evidence_documents(id),
    payload TEXT,
    status INTEGER,
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0,1)),
    attempted_at TEXT,
    PRIMARY KEY(job_id,permission_id),
    UNIQUE(document_id)
);
CREATE TABLE breach_associations (
    observation_id INTEGER PRIMARY KEY REFERENCES evidence_observations(id),
    permission_id INTEGER NOT NULL REFERENCES breach_permissions(id),
    breach_name TEXT NOT NULL,
    metadata TEXT NOT NULL
);
"""
MIGRATIONS = ((1, VERSION_1),)


def migrate(conn):
    if conn.in_transaction:
        raise RuntimeError("Breach migration requires its own transaction")
    conn.execute("PRAGMA foreign_keys=ON")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS breach_versions(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        applied = {row[0] for row in conn.execute("SELECT version FROM breach_versions")}
        if not applied.issubset({v for v, _ in MIGRATIONS}):
            raise RuntimeError("Database has a newer breach schema")
        for version, script in MIGRATIONS:
            if version not in applied:
                for statement in script.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute("INSERT INTO breach_versions VALUES (?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))", (version,))
