"""Additive scheduling metadata. No source is enabled by migration."""

import sqlite3


VERSION_1 = """
        CREATE TABLE feed_schedules (
            feed TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
            generation INTEGER NOT NULL DEFAULT 0,
            due_at TEXT NOT NULL,
            active_job TEXT,
            last_retrieval_at TEXT,
            coverage_at TEXT,
            coverage TEXT,
            last_error TEXT
        );
        CREATE TABLE feed_request_usage (
            bucket TEXT NOT NULL,
            requested_at REAL NOT NULL
        );
        CREATE INDEX feed_request_usage_time
            ON feed_request_usage(bucket, requested_at);
        CREATE TABLE feed_cooldowns (
            bucket TEXT PRIMARY KEY,
            until_at REAL NOT NULL
        );
        CREATE TABLE feed_capture_progress (
            job_id TEXT NOT NULL REFERENCES durable_jobs(id),
            document_id INTEGER NOT NULL REFERENCES evidence_documents(id),
            validated_at TEXT,
            ingested_at TEXT,
            PRIMARY KEY(job_id, document_id)
        );
"""

MIGRATIONS = ((1, VERSION_1),)


def migrate(conn: sqlite3.Connection):
    if conn.in_transaction:
        raise RuntimeError("Feed migration requires a connection outside a transaction")
    conn.execute("PRAGMA foreign_keys=ON")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS feed_schema_versions(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
        applied = {row[0] for row in conn.execute("SELECT version FROM feed_schema_versions")}
        if not applied.issubset({version for version, _ in MIGRATIONS}):
            raise RuntimeError("Database has a newer feed schema")
        for version, script in MIGRATIONS:
            if version not in applied:
                for statement in script.split(";"):
                    if statement.strip():
                        conn.execute(statement)
                conn.execute("INSERT INTO feed_schema_versions VALUES (?,strftime('%Y-%m-%dT%H:%M:%fZ','now'))", (version,))
