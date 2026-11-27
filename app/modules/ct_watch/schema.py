"""Independent additive CT consumer migration. No permission or enabling."""

VERSION_1 = """
CREATE TABLE ct_permissions (
    id INTEGER PRIMARY KEY,
    selector_id INTEGER NOT NULL REFERENCES evidence_selectors(id),
    approved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    authority_reference TEXT NOT NULL,
    purpose TEXT NOT NULL,
    pattern_version TEXT NOT NULL,
    pattern_sha256 TEXT NOT NULL,
    matcher_version TEXT NOT NULL,
    revoked_at TEXT
);
CREATE UNIQUE INDEX ct_active_permission ON ct_permissions(selector_id) WHERE revoked_at IS NULL;
CREATE TABLE ct_suppressions (selector_id INTEGER PRIMARY KEY REFERENCES evidence_selectors(id), suppressed_at TEXT NOT NULL);
CREATE TABLE ct_plans (job_id TEXT PRIMARY KEY REFERENCES durable_jobs(id));
CREATE TABLE ct_units (
    job_id TEXT NOT NULL REFERENCES durable_jobs(id),
    permission_id INTEGER NOT NULL REFERENCES ct_permissions(id),
    document_id INTEGER UNIQUE REFERENCES evidence_documents(id),
    payload TEXT,
    attempted_at TEXT,
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0,1)),
    PRIMARY KEY(job_id,permission_id)
);
CREATE TABLE ct_candidates (
    observation_id INTEGER PRIMARY KEY REFERENCES evidence_observations(id),
    permission_id INTEGER NOT NULL REFERENCES ct_permissions(id),
    metadata TEXT NOT NULL,
    match_metadata TEXT NOT NULL
);
"""
MIGRATIONS = ((1, VERSION_1),)


def migrate(conn):
    if conn.in_transaction:
        raise RuntimeError("CT migration requires its own transaction")
    conn.execute("PRAGMA foreign_keys=ON")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS ct_versions(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        applied = {row[0] for row in conn.execute("SELECT version FROM ct_versions")}
        if not applied.issubset({version for version, _ in MIGRATIONS}):
            raise RuntimeError("Database has a newer CT schema")
        for version, script in MIGRATIONS:
            if version not in applied:
                for statement in script.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute("INSERT INTO ct_versions VALUES (?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))", (version,))
