"""Additive local inbox schema. Evidence and review history are never cascaded."""

import sqlite3


VERSION_1 = """
CREATE TABLE evidence_selectors (
    id INTEGER PRIMARY KEY,
    subject_type TEXT NOT NULL,
    mode TEXT NOT NULL CHECK(mode IN ('exact','domain_tree','network')),
    value TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at TEXT NOT NULL,
    scanned_through INTEGER NOT NULL DEFAULT 0,
    UNIQUE(subject_type,mode,value)
);
CREATE TABLE evidence_alerts (
    id INTEGER PRIMARY KEY,
    selector_id INTEGER NOT NULL REFERENCES evidence_selectors(id),
    observation_id INTEGER NOT NULL REFERENCES evidence_observations(id),
    matched_at TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'new' CHECK(state IN ('new','reviewed','dismissed')),
    revision INTEGER NOT NULL DEFAULT 0,
    UNIQUE(selector_id,observation_id)
);
CREATE INDEX evidence_alerts_state ON evidence_alerts(state,id);
CREATE TABLE evidence_alert_reviews (
    alert_id INTEGER NOT NULL REFERENCES evidence_alerts(id),
    revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('new','reviewed','dismissed')),
    reviewed_at TEXT NOT NULL,
    PRIMARY KEY(alert_id,revision)
);
"""

MIGRATIONS = ((1, VERSION_1),)


def migrate(conn: sqlite3.Connection) -> None:
    if conn.in_transaction:
        raise RuntimeError("Inbox migration requires its own transaction")
    conn.execute("PRAGMA foreign_keys=ON")
    with conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""CREATE TABLE IF NOT EXISTS evidence_alert_schema_versions (
            version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)""")
        applied = {r[0] for r in conn.execute("SELECT version FROM evidence_alert_schema_versions")}
        if not applied.issubset({v for v, _ in MIGRATIONS}):
            raise RuntimeError("Database has a newer inbox schema")
        for version, script in MIGRATIONS:
            if version in applied:
                continue
            for statement in script.split(";"):
                if statement.strip():
                    conn.execute(statement)
            conn.execute("INSERT INTO evidence_alert_schema_versions VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))", (version,))
