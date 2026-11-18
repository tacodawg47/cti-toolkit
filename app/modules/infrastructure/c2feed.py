"""Local snapshots of C2IntelFeeds CSVs from the publisher."""

import asyncio
import csv
import io
import ipaddress
from datetime import datetime, timezone

from ...core.db import connect
from ...core.indicators import DOMAIN_PATTERN
from ..vulnerability_intelligence.http import fetch_bytes

REPO = "https://github.com/drb-ra/C2IntelFeeds"
DASHBOARD = "https://drb-ra.github.io/c2intel-web/"
LICENSE = "https://creativecommons.org/licenses/by-nc-sa/4.0/"
RAW = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds"
SOURCES = {
    "ip": ("C2 IPs", "ip", "IPC2s.csv"),
    "domain": ("Filtered C2 Domains", "domain", "domainC2s-filter-abused.csv"),
    "unverified": ("Unverified C2 IPs", "ip", "unverified/IPC2s.csv"),
}
PAGE_SIZE = 25
_LIMIT = 8 * 1024 * 1024
_REFRESH_LOCK = asyncio.Lock()


def init_schema() -> None:
    with connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS c2_feed_rows (
                feed TEXT NOT NULL,
                indicator TEXT NOT NULL,
                label TEXT NOT NULL,
                PRIMARY KEY (feed, indicator, label)
            );
            CREATE TABLE IF NOT EXISTS c2_feed_status (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                fetched_at TEXT,
                error TEXT
            );
        """)


def parse(body: bytes, key: str) -> set[tuple[str, str, str]]:
    """Return validated indicator and label pairs, preserving tier by feed."""
    _, kind, _ = SOURCES[key]
    reader = csv.reader(io.StringIO(body.decode("utf-8-sig"), newline=""), strict=True)
    header = next(reader, [])
    if [column.strip().casefold() for column in header] != [f"#{kind}", "ioc"]:
        raise ValueError("unexpected CSV header")
    rows = set()
    for row in reader:
        if not row or not any(field.strip() for field in row):
            continue
        if len(row) != 2:
            raise ValueError("unexpected CSV row")
        value, label = (field.strip() for field in row)
        if kind == "ip":
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not ip.is_global or ip.is_multicast or getattr(ip, "scope_id", None):
                continue
            value = str(ip)
        else:
            value = value.rstrip(".").lower()
            if (not DOMAIN_PATTERN.fullmatch(value) or value.rsplit(".", 1)[-1].isdigit()
                    or value.endswith((".local", ".localhost"))):
                continue
        rows.add((key, value, label[:240]))
    return rows


async def refresh() -> None:
    """Replace all three feed snapshots together after successful validation."""
    async with _REFRESH_LOCK:
        rows = set()
        for key, (label, _, path) in SOURCES.items():
            status, body, err = await fetch_bytes(f"{RAW}/{path}", max_bytes=_LIMIT, follow_redirects=False)
            if not err and status != 200:
                err = f"HTTP {status}"
            if not err:
                try:
                    rows.update(parse(body, key))
                except (ValueError, csv.Error):
                    err = "invalid CSV"
            if err:
                with connect() as conn, conn:
                    conn.execute("""INSERT INTO c2_feed_status (singleton, error) VALUES (1, ?)
                                    ON CONFLICT(singleton) DO UPDATE SET error=excluded.error""",
                                 (f"{label}: {err}",))
                return
        fetched = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with connect() as conn, conn:
            conn.execute("DELETE FROM c2_feed_rows")
            conn.executemany("INSERT INTO c2_feed_rows (feed, indicator, label) VALUES (?, ?, ?)", rows)
            conn.execute("""INSERT INTO c2_feed_status (singleton, fetched_at) VALUES (1, ?)
                            ON CONFLICT(singleton) DO UPDATE SET fetched_at=excluded.fetched_at, error=NULL""",
                         (fetched,))


def page(query: str, scope: str, number: int) -> dict:
    feeds = tuple(SOURCES) if scope == "all" else ("ip", "domain") if scope == "verified" else ("unverified",)
    query = query.casefold()
    where = f"""WHERE feed IN ({','.join('?' for _ in feeds)})
                AND (? = '' OR instr(indicator, ?) > 0 OR instr(lower(label), ?) > 0)"""
    params = (*feeds, query, query, query)
    with connect() as conn:
        conn.execute("BEGIN")
        status = conn.execute("SELECT fetched_at, error FROM c2_feed_status WHERE singleton=1").fetchone()
        total = conn.execute(f"SELECT COUNT(*) FROM c2_feed_rows {where}", params).fetchone()[0]
        last = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        number = min(number, last)
        rows = conn.execute(f"""SELECT feed, indicator, label FROM c2_feed_rows {where}
                               ORDER BY feed='unverified', feed, indicator, label LIMIT ? OFFSET ?""",
                            (*params, PAGE_SIZE, (number - 1) * PAGE_SIZE)).fetchall()
    return {"status": dict(status) if status else {}, "rows": rows, "total": total, "number": number, "last": last}
