"""
Per-vendor rate limiting.

Two limits per vendor:
  - rpm: requests per minute, enforced with an in-memory sliding window.
  - rpd: requests per day, tracked in SQLite so it survives restarts.

`acquire(vendor)` blocks (async) until a per-minute slot is free, raising
QuotaExceeded if the daily cap is already spent. Holding the per-vendor lock
across the wait serializes that vendor's calls, which is exactly the spacing
the free tiers need.
"""

import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from .db import connect

# Known vendor limits. More vendors are added as their modules land.
LIMITS: dict[str, dict[str, int]] = {
    "virustotal": {"rpm": 4, "rpd": 500},
}


class QuotaExceeded(Exception):
    """Raised when a vendor's daily quota is exhausted."""


class RateLimiter:
    def __init__(self) -> None:
        self._minute: dict[str, deque[float]] = defaultdict(deque)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def _day_count(self, vendor: str) -> int:
        with connect() as conn:
            row = conn.execute(
                "SELECT count FROM quota_usage WHERE vendor=? AND day=?",
                (vendor, self._today()),
            ).fetchone()
        return row["count"] if row else 0

    def _bump_day(self, vendor: str) -> None:
        with connect() as conn:
            conn.execute(
                "INSERT INTO quota_usage(vendor, day, count) VALUES (?, ?, 1) "
                "ON CONFLICT(vendor, day) DO UPDATE SET count = count + 1",
                (vendor, self._today()),
            )
            conn.commit()

    def usage(self, vendor: str) -> dict[str, int | None]:
        limits = LIMITS.get(vendor, {})
        return {
            "day": self._day_count(vendor),
            "rpd": limits.get("rpd"),
            "rpm": limits.get("rpm"),
        }

    async def acquire(self, vendor: str) -> None:
        limits = LIMITS.get(vendor)
        if not limits:
            return  # no configured limit for this vendor

        async with self._locks[vendor]:
            if self._day_count(vendor) >= limits["rpd"]:
                raise QuotaExceeded(
                    f"{vendor} daily quota of {limits['rpd']} reached; try tomorrow"
                )

            window = self._minute[vendor]
            now = time.monotonic()
            while window and now - window[0] >= 60:
                window.popleft()

            if len(window) >= limits["rpm"]:
                wait = 60 - (now - window[0])
                if wait > 0:
                    await asyncio.sleep(wait)
                now = time.monotonic()
                while window and now - window[0] >= 60:
                    window.popleft()

            window.append(time.monotonic())
            self._bump_day(vendor)


rate_limiter = RateLimiter()
