"""Durable due-work planning and an async bridge onto the app event loop."""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import re
from urllib.parse import urlsplit

from . import feed_scope
from .config import settings
from .evidence import require_collection
from .jobs import Failure, Result, Retry, Runner, Task


@dataclass(frozen=True)
class Feed:
    key: str
    label: str
    refresh: object
    destinations: tuple  # compiled FULL URL patterns, supplied in trusted code
    cadence: int
    stale: int
    requests: int = 24
    bytes: int = 192 * 1024 * 1024
    seconds: int = 240
    rpm: int = 30
    rpd: int = 1000
    vendor: str | None = None
    method: str = "feed"
    prerequisite: object = lambda: ""
    coverage: object = lambda: {"scope": "current_snapshot"}
    allow_empty: bool = False
    bucket_name: str | None = None
    response_bytes: int = 64 * 1024 * 1024
    redirects: int = 0
    legacy_status: object = lambda: None
    raw_allowed: bool = True

    def __post_init__(self):
        limits = ((self.cadence, 60, 30*86400), (self.stale, self.cadence+1, 90*86400),
                  (self.requests, 1, 60), (self.bytes, 1, 1024**3), (self.seconds, 1, 600),
                  (self.rpm, 1, 1000), (self.rpd, 1, 100000),
                  (self.response_bytes, 1, 64*1024**2), (self.redirects, 0, 3))
        if any(type(value) is not int or not low <= value <= high for value, low, high in limits):
            raise ValueError("Feed policies require finite positive integer bounds")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", self.key) or not self.destinations:
            raise ValueError("Register a known source and explicit destination patterns")
        if self.method not in ("api", "feed", "public_page") or not callable(self.refresh):
            raise ValueError("Register an explicit feed callable and method")

    @property
    def source(self):
        return self.key

    @property
    def bucket(self):
        return self.bucket_name or self.vendor or self.key

    def permits(self, url):
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and parsed.username is None and parsed.password is None
                and parsed.port in (None, 443) and not parsed.fragment
                and any(pattern.fullmatch(url) for pattern in self.destinations))


class Scheduler:
    def __init__(self, feeds, loop, *, database=None, clock=None):
        if database is not None and database.resolve() != settings.db_path.resolve():
            raise ValueError("Feed stores use the configured local database")
        self.feeds = {feed.key: feed for feed in feeds}
        if len(self.feeds) != len(feeds):
            raise ValueError("Duplicate feed registration")
        self.loop = loop
        self.runner = Runner([Task("feed." + feed.key, self._handler(feed), source_id=feed.source,
                                   access_method=feed.method, max_attempts=3, retry_seconds=300)
                              for feed in feeds], database=database, clock=clock)

    def initialize(self):
        now = self.runner._stamp(self.runner._now())
        with self.runner._connect(write=True) as conn:
            conn.executemany("INSERT OR IGNORE INTO feed_schedules(feed,due_at) VALUES (?, ?)",
                             [(key, now) for key in self.feeds])

    def configure(self, key, *, enabled):
        """Trusted local operation AFTER direct approval and registry review.

        This does not edit source reviews or infer permission from registry text.
        No web endpoint enables schedules. Cadences/budgets come from code.
        """
        if type(enabled) is not bool:
            raise ValueError("Use an explicit boolean")
        feed = self.feeds[key]
        if enabled:
            require_collection(feed.source, feed.method)
            reason = feed.prerequisite()
            if reason:
                raise ValueError(reason)
        with self.runner._connect(write=True) as conn:
            conn.execute("UPDATE feed_schedules SET enabled=? WHERE feed=?", (enabled, key))

    def _handler(self, feed):
        def run(context, params):
            # .result() is deliberately NOT timed out: cancelling a wait cannot
            # stop parsing/SQLite threads. Keep the runner lock until they finish.
            if self.loop.is_closed() or not self.loop.is_running():
                raise RuntimeError("Feed bridge requires the application event loop")
            return asyncio.run_coroutine_threadsafe(self._execute(context, feed), self.loop).result()
        return run

    async def _execute(self, context, feed):
        scope = feed_scope.Scope(context, feed)
        token = feed_scope.current.set(scope)
        try:
            await scope.check()
            result = await feed.refresh()
            await scope.drain()
            await scope.check()
            entries = (result or {}).get("entries")
            primary = scope.statuses.get(feed.key)
            if entries is None and primary:
                entries = primary[0]
            errors = any(status[2] for status in scope.statuses.values())
            if not result or not result.get("ok") or result.get("failed") or errors:
                raise Retry(Failure.INVALID_RESPONSE)
            complete = result.get("complete", True)
            coverage = await asyncio.to_thread(feed.coverage)
            if coverage is None:
                complete = False
            if not scope.captures and not result.get("unchanged"):
                raise Retry(Failure.INVALID_RESPONSE)
            if not feed.allow_empty and (not isinstance(entries, int) or entries <= 0):
                raise Retry(Failure.INVALID_RESPONSE)
            # A trusted parser's successful return follows committed ingestion.
            # Partial-capable adapters also mark individual validated units early.
            if complete:
                await scope.validated(ingested=True)
                await asyncio.to_thread(self._publish, scope.statuses)
            return Result(coverage=coverage if complete else None)
        except ValueError:
            raise Retry(Failure.INVALID_RESPONSE) from None
        except feed_scope.BudgetReached:
            # A bounded pass is incomplete, not provider success. Source-owned
            # queues/windows retain unfinished work for the next scheduled pass.
            return Result()
        finally:
            await scope.drain()
            feed_scope.current.reset(token)

    def _publish(self, statuses):
        # Scope still exists in this thread, so use direct SQL rather than the
        # legacy status helper (which intentionally stages scheduled updates).
        now = self.runner._stamp(self.runner._now())
        with self.runner._connect(write=True) as conn:
            for name, (entries, version, error) in statuses.items():
                if not error:
                    conn.execute("""INSERT INTO feed_status(feed,fetched_at,entries,version,error) VALUES (?,?,?,?,NULL)
                        ON CONFLICT(feed) DO UPDATE SET fetched_at=excluded.fetched_at,entries=excluded.entries,
                        version=excluded.version,error=NULL""", (name, now, entries, (version or "")[:2048]))

    def plan(self):
        """One active bounded pass per feed. No burst of missed timer ticks."""
        now = self.runner._now()
        for feed in self.feeds.values():
            with self.runner._connect(write=True) as conn:
                row = conn.execute("SELECT * FROM feed_schedules WHERE feed=?", (feed.key,)).fetchone()
                if row is None:
                    continue
                job = conn.execute("SELECT * FROM durable_jobs WHERE id=?", (row["active_job"],)).fetchone()
                if job and job["state"] not in ("queued", "running"):
                    coverage = job["coverage_checkpoint"]
                    conn.execute("""UPDATE feed_schedules SET active_job=NULL,generation=generation+1,
                        due_at=?,coverage_at=CASE WHEN ? IS NOT NULL THEN ? ELSE coverage_at END,
                        coverage=COALESCE(?,coverage),last_error=? WHERE feed=? AND active_job=?""",
                                 (self.runner._stamp(now + timedelta(seconds=feed.cadence)), coverage,
                                  job["coverage_completed_at"], coverage,
                                  job["error_code"] or ("incomplete" if not coverage else None), feed.key, job["id"]))
                    continue
                if job or not row["enabled"] or row["due_at"] > self.runner._stamp(now):
                    continue
                generation = row["generation"]
            try:
                if feed.prerequisite():
                    continue
                ident = self.runner.enqueue("feed." + feed.key, f"scheduled.{feed.key}.{generation}")
            except PermissionError:
                continue
            # A crash before this update reuses the same generation/work key.
            with self.runner._connect(write=True) as conn:
                conn.execute("UPDATE feed_schedules SET active_job=? WHERE feed=? AND generation=? AND active_job IS NULL",
                             (ident, feed.key, generation))

    def step(self):
        self.plan()
        self.runner.run_next(registered_only=True)
        self.plan()

    async def serve(self, stopped):
        while not stopped.is_set():
            await asyncio.to_thread(self.step)
            try:
                await asyncio.wait_for(stopped.wait(), timeout=30)
            except TimeoutError:
                pass


def health(feeds, *, database=None, clock=None):
    """Read-only health, including legacy data. Never polls a provider."""
    runner = Runner([], database=database, clock=clock)
    now = runner._now()
    result = []
    with runner._connect() as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        schedules = {row["feed"]: dict(row) for row in conn.execute("SELECT * FROM feed_schedules")} if "feed_schedules" in tables else {}
        legacy = {row["feed"]: dict(row) for row in conn.execute("SELECT * FROM feed_status")} if "feed_status" in tables else {}
        for feed in feeds:
            row = schedules.get(feed.key, {})
            job = conn.execute("SELECT * FROM durable_jobs WHERE id=?", (row.get("active_job"),)).fetchone() if "durable_jobs" in tables else None
            latest = conn.execute("SELECT * FROM durable_jobs WHERE task=? ORDER BY created_at DESC,id DESC LIMIT 1",
                                  ("feed." + feed.key,)).fetchone() if "durable_jobs" in tables else None
            old = feed.legacy_status() or legacy.get(feed.key, {})
            retrieved = row.get("last_retrieval_at") or old.get("fetched_at")
            last_good = old.get("fetched_at")
            age = max(0, int((now - datetime.fromisoformat(last_good)).total_seconds())) if last_good else None
            states = []
            if not retrieved:
                states.append("Never Loaded")
            if age is not None and age >= feed.stale:
                states.append("Stale")
            error = (latest["error_code"] if latest else None) or row.get("last_error")
            if error or old.get("error"):
                states.append("Failed" if error != "incomplete" else "Incomplete")
            if not row.get("coverage_at") or (job and not job["coverage_completed_at"]):
                if "Incomplete" not in states:
                    states.append("Incomplete")
            coverage = json.loads(row["coverage"]) if row.get("coverage") else {}
            if coverage.get("scope") in ("modified_window", "daily_scores", "delta_since_explicit_snapshot") and coverage.get("through"):
                through = datetime.fromisoformat(coverage["through"])
                lag = (now - through).total_seconds()
                if lag > feed.cadence and "Incomplete" not in states:
                    states.append("Incomplete")
                if lag >= feed.stale and "Stale" not in states:
                    states.append("Stale")
            if not states:
                states.append("Current")
            try:
                if "evidence_sources" not in tables:
                    raise PermissionError("Source registry is not initialized")
                require_collection(feed.source, feed.method, connection=conn)
                eligibility = feed.prerequisite() or "Eligible"
            except PermissionError:
                eligibility = "Source Review / Enabling Required"
            result.append({"key": feed.key, "label": feed.label, "states": states,
                           "enabled": bool(row.get("enabled")), "eligibility": eligibility,
                           "cadence": feed.cadence, "stale_after": feed.stale,
                           "age_seconds": age, "last_retrieval": retrieved,
                           "last_good_at": last_good,
                           "last_attempt": latest["last_attempt_at"] if latest else None,
                           "coverage_at": row.get("coverage_at"), "coverage": row.get("coverage"),
                           "error": error or ("legacy_failure" if old.get("error") else None),
                           "execution": job["state"] if job else None, "due_at": row.get("due_at")})
    return result
