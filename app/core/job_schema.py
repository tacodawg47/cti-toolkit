"""Additive job schema. No job is registered, queued or executed by migration."""

import sqlite3


VERSION_1 = """
CREATE TABLE durable_jobs (
    id TEXT PRIMARY KEY NOT NULL,
    task TEXT NOT NULL,
    task_version TEXT NOT NULL,
    work_key TEXT NOT NULL,
    params TEXT NOT NULL,
    source_id TEXT REFERENCES evidence_sources(source_id),
    access_method TEXT,
    max_attempts INTEGER NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    retry_seconds INTEGER NOT NULL CHECK (retry_seconds BETWEEN 1 AND 86400),
    state TEXT NOT NULL CHECK (state IN ('queued','running','succeeded','failed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0,1)),
    created_at TEXT NOT NULL,
    available_at TEXT NOT NULL,
    last_attempt_at TEXT,
    last_retrieval_at TEXT,
    coverage_checkpoint TEXT,
    coverage_completed_at TEXT,
    completed_at TEXT,
    progress_done INTEGER NOT NULL DEFAULT 0 CHECK (progress_done >= 0),
    progress_total INTEGER CHECK (progress_total >= progress_done),
    checkpoint TEXT NOT NULL DEFAULT '{}',
    error_code TEXT,
    UNIQUE(task, work_key)
);
CREATE INDEX durable_jobs_pending ON durable_jobs(state, available_at, created_at);
CREATE TABLE durable_job_runs (
    id TEXT PRIMARY KEY NOT NULL,
    job_id TEXT NOT NULL REFERENCES durable_jobs(id),
    attempt INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('running','succeeded','failed','interrupted','cancelled')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    error_code TEXT,
    UNIQUE(job_id, attempt)
);
CREATE UNIQUE INDEX durable_job_one_run ON durable_job_runs(job_id) WHERE state='running';
CREATE TABLE durable_job_documents (
    job_id TEXT NOT NULL REFERENCES durable_jobs(id),
    slot TEXT NOT NULL,
    document TEXT NOT NULL,
    PRIMARY KEY(job_id, slot)
);
"""

MIGRATIONS = ((1, VERSION_1),)


def migrate(conn: sqlite3.Connection) -> None:
    if conn.in_transaction:
        raise RuntimeError("Job migration requires a connection outside a transaction")
    conn.execute("PRAGMA foreign_keys=ON")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS job_schema_versions (
            version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)""")
        applied = {row[0] for row in conn.execute("SELECT version FROM job_schema_versions")}
        if not applied.issubset({version for version, _ in MIGRATIONS}):
            raise RuntimeError("Database has a newer job schema; use matching application code")
        for version, script in MIGRATIONS:
            if version not in applied:
                for statement in script.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute("INSERT INTO job_schema_versions VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                             (version,))
