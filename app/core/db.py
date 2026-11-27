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
import time
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


def _enable_wal(conn: sqlite3.Connection) -> None:
    # SQLite's journal-mode transition can return BUSY immediately on a fresh
    # file even with busy_timeout set. Bound this startup-only race explicitly.
    deadline = time.monotonic() + 5
    while True:
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            return
        except sqlite3.OperationalError as exc:
            if (getattr(exc, "sqlite_errorcode", None) not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
                    or time.monotonic() >= deadline):
                raise
            time.sleep(0.05)


def init_db() -> None:
    # Make sure the data directory exists, then create the schema. WAL is a
    # persistent property of the database file, so it only needs setting once.
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    with connect() as conn:
        _enable_wal(conn)
        conn.executescript(SCHEMA)
        from .evidence_schema import migrate

        migrate(conn)
        from .job_schema import migrate as migrate_jobs

        migrate_jobs(conn)
        from .feed_schema import migrate as migrate_feeds

        migrate_feeds(conn)
        from .alert_schema import migrate as migrate_alerts

        migrate_alerts(conn)
        from ..modules.ransomware.schema import migrate as migrate_ransomware

        migrate_ransomware(conn)
        from ..modules.breaches.schema import migrate as migrate_breaches

        migrate_breaches(conn)
        from ..modules.ct_watch.schema import migrate as migrate_ct

        migrate_ct(conn)
        from ..modules.github_exposure.schema import migrate as migrate_github_exposure

        migrate_github_exposure(conn)
        # Drop expired cache rows so the table doesn't grow without bound.
        conn.execute("DELETE FROM cache WHERE expires_at < ?",
                     (datetime.now(timezone.utc).isoformat(),))
        conn.commit()
