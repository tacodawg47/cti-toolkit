"""
SQLite access.

Each operation opens a short-lived connection via the `connect()` context
manager. For a local single-user app this is simple and avoids cross-thread
connection-sharing problems. WAL mode (set once in `init_db`) keeps reads and
writes from blocking each other.

Note: these calls do blocking SQLite I/O on the event loop. That is fine for a
single-user local app; do not copy this pattern into the scheduler without
moving the work off the loop (e.g. asyncio.to_thread).
"""

import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
from datetime import datetime, timezone

from .config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    vendor     TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (vendor, key)
);

CREATE TABLE IF NOT EXISTS quota_usage (
    vendor TEXT NOT NULL,
    day    TEXT NOT NULL,
    count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (vendor, day)
);
"""


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    # timeout=5 so a rare concurrent write waits briefly instead of raising
    # "database is locked".
    conn = sqlite3.connect(settings.db_path, timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    # Make sure the data directory exists, then create the schema. WAL is a
    # persistent property of the database file, so it only needs setting once.
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.executescript(SCHEMA)
        # Drop expired cache rows so the table doesn't grow without bound.
        conn.execute("DELETE FROM cache WHERE expires_at < ?",
                     (datetime.now(timezone.utc).isoformat(),))
        conn.commit()
