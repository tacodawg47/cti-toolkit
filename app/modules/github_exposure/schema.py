"""Independent additive migration. No source approval or collection switch."""

VERSION_1 = """
CREATE TABLE github_exposure_permissions (
    id INTEGER PRIMARY KEY,
    selector_id INTEGER NOT NULL REFERENCES evidence_selectors(id),
    selector_type TEXT NOT NULL,
    selector_value TEXT NOT NULL,
    query TEXT NOT NULL,
    query_version TEXT NOT NULL,
    api_version TEXT NOT NULL,
    credential_sha256 TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    authority_reference TEXT NOT NULL,
    purpose TEXT NOT NULL,
    revoked_at TEXT
);
CREATE UNIQUE INDEX github_exposure_active ON github_exposure_permissions(selector_id) WHERE revoked_at IS NULL;
CREATE TABLE github_exposure_suppressions (selector_id INTEGER PRIMARY KEY REFERENCES evidence_selectors(id), suppressed_at TEXT NOT NULL);
CREATE TABLE github_exposure_plans (job_id TEXT PRIMARY KEY REFERENCES durable_jobs(id));
CREATE TABLE github_exposure_units (
    job_id TEXT NOT NULL REFERENCES durable_jobs(id),
    permission_id INTEGER NOT NULL REFERENCES github_exposure_permissions(id),
    attempted_at TEXT,
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0,1)),
    window_complete INTEGER NOT NULL DEFAULT 0 CHECK(window_complete IN (0,1)),
    PRIMARY KEY(job_id,permission_id)
);
CREATE TABLE github_exposure_pages (
    job_id TEXT NOT NULL,
    permission_id INTEGER NOT NULL,
    page INTEGER NOT NULL CHECK(page IN (1,2)),
    document_id INTEGER UNIQUE REFERENCES evidence_documents(id),
    payload TEXT,
    completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0,1)),
    PRIMARY KEY(job_id,permission_id,page),
    FOREIGN KEY(job_id,permission_id) REFERENCES github_exposure_units(job_id,permission_id)
);
CREATE TABLE github_exposure_leads (
    observation_id INTEGER PRIMARY KEY REFERENCES evidence_observations(id),
    permission_id INTEGER NOT NULL REFERENCES github_exposure_permissions(id),
    metadata TEXT NOT NULL
);
"""
MIGRATIONS = ((1, VERSION_1),)


def migrate(conn):
    if conn.in_transaction:
        raise RuntimeError("GitHub exposure migration requires its own transaction")
    conn.execute("PRAGMA foreign_keys=ON")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS github_exposure_versions(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        applied = {row[0] for row in conn.execute("SELECT version FROM github_exposure_versions")}
        if not applied.issubset({version for version, _ in MIGRATIONS}):
            raise RuntimeError("Database has a newer GitHub exposure schema")
        for version, script in MIGRATIONS:
            if version not in applied:
                for statement in script.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute("INSERT INTO github_exposure_versions VALUES (?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))", (version,))
