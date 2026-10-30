"""
Result cache backed by SQLite.

A lookup result is stored under (vendor, key) with an expiry timestamp.
Repeated lookups of the same indicator inside the TTL return the stored value
and spend no API quota. Expired rows are ignored on read and purged in bulk by
db.init_db() at startup.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import connect


def _now() -> datetime:
    return datetime.now(timezone.utc)


def get(vendor: str, key: str) -> Any | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT value, expires_at FROM cache WHERE vendor=? AND key=?",
            (vendor, key),
        ).fetchone()
    if row is None:
        return None
    if datetime.fromisoformat(row["expires_at"]) < _now():
        return None
    return json.loads(row["value"])


def put(vendor: str, key: str, value: Any, ttl_seconds: int) -> None:
    """Store (vendor, key) -> value for ttl_seconds. (Named `put`, not `set`,
    to avoid shadowing the builtin inside this module.)"""
    now = _now()
    expires = now + timedelta(seconds=ttl_seconds)
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cache(vendor, key, value, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (vendor, key, json.dumps(value), now.isoformat(), expires.isoformat()),
        )
        conn.commit()
