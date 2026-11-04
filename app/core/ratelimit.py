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

from .config import settings
from .db import connect

# Known vendor limits. A vendor may set rpm (requests per minute), rpd
# (requests per day), both, or neither. A vendor with no entry here is not
# rate limited by us. Values reflect free-tier caps; adjust as plans change.
LIMITS: dict[str, dict[str, int]] = {
    "virustotal": {"rpm": 4, "rpd": 500},
    "abuseipdb": {"rpd": 1000},          # free tier: 1000 checks/day, no per-minute cap
    "shodan": {"rpm": 60},               # roughly one request per second; also credit-limited (not tracked here)
    "urlscan": {"rpm": 60, "rpd": 1000},
    "greynoise": {"rpd": 10},            # community endpoint, approximate and conservative; raise if needed
    # OTX and the abuse.ch suite have no strict published free cap, but a soft
    # per-minute limit keeps bulk use polite and lets the health page count them.
    "otx": {"rpm": 30},
    "threatfox": {"rpm": 30},
    "malwarebazaar": {"rpm": 30},
    "urlhaus": {"rpm": 30},
    # Keyless sources. No published hard caps; these are courtesy limits
    # (InternetDB asks for about one request per second).
    "internetdb": {"rpm": 60},
    "hashlookup": {"rpm": 60},
    "rdap": {"rpm": 30},
    "yaraify": {"rpm": 30},              # abuse.ch, same soft limit as the rest of the suite
    "crtsh": {"rpm": 10},                # crt.sh is a slow shared service; go easy on it
    # Phase 2, vulnerability intelligence. NVD publishes 5 requests per 30 s
    # without a key and 50 with one; GitHub search is 10 a minute without a
    # token and 30 with one. Both expressed per minute, on the safe side.
    "nvd": {"rpm": 50 if settings.nvd_api_key else 5},
    "github": {"rpm": 30 if settings.github_token else 10},
    # ransomware.live PRO publishes no cap ("fair use", data cached 30 min on
    # their side) but answers bursts with 429s (seen at ~2/s on 2026-11-04).
    # One a second is tolerated; the sweep also backs off on a 429.
    "ransomwarelive": {"rpm": 60},
    "vulnlookup": {"rpm": 30},            # CIRCL's public instance, keyless; courtesy limit
    "euvd": {"rpm": 60},                  # ENISA's public API, keyless; courtesy limit
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

        rpm = limits.get("rpm")
        rpd = limits.get("rpd")

        async with self._locks[vendor]:
            if rpd is not None and self._day_count(vendor) >= rpd:
                raise QuotaExceeded(
                    f"{vendor} daily quota of {rpd} reached; try tomorrow"
                )

            if rpm is not None:
                window = self._minute[vendor]
                now = time.monotonic()
                while window and now - window[0] >= 60:
                    window.popleft()

                # Wait until the window has a free slot, re-pruning after each
                # sleep. A loop (not one sleep) is needed because asyncio.sleep
                # can return a hair early, leaving the window full; that would
                # let one extra call through within the minute and trip a 429.
                while len(window) >= rpm:
                    wait = 60 - (now - window[0])
                    await asyncio.sleep(max(0.05, wait))
                    now = time.monotonic()
                    while window and now - window[0] >= 60:
                        window.popleft()

                window.append(time.monotonic())

            # Track daily usage for any capped vendor, even one with only an
            # rpm cap, so the health page can show how many calls ran today.
            self._bump_day(vendor)


rate_limiter = RateLimiter()
