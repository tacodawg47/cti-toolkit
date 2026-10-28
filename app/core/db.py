"""
SQLite access.

Each operation opens a short-lived connection via the `connect()` context
manager. For a local single-user app this is simple and avoids cross-thread
connection-sharing problems with the ASGI threadpool. WAL mode keeps reads
and writes from blocking each other.
"""

import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator

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
    conn = sqlite3.connect(settings.db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        conn.commit()
