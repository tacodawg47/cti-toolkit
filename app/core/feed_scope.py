"""Request-local scheduled feed safeguards. Manual calls retain their contracts.

The worker submits a coroutine to the application's ONE existing event loop.
Context variables propagate to parsing/SQLite threads without changing globals.
Only trusted adapters install a scope; publisher text cannot create one.
"""

import asyncio
from contextvars import ContextVar
from datetime import timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
import math
import time
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from . import evidence
from .evidence_models import Document
from .jobs import Failure, Retry

current = ContextVar("scheduled_feed", default=None)


class BudgetReached(Exception):
    """A bounded pass ended. Committed units remain resumable."""


class Scope:
    def __init__(self, context, feed):
        self.context, self.feed = context, feed
        self.started = time.monotonic()
        self.requests = self.charged = 0
        self.statuses = {}
        self.captures = {}
        self.lock = asyncio.Lock()
        self.tasks = set()

    def status(self, name, entries, version, error):
        # Do not let partial legacy functions briefly renew a green success.
        # These statuses are published only after the adapter verifies completion.
        self.statuses[name] = (entries, version, bool(error))

    async def check(self):
        await asyncio.to_thread(self.check_sync)

    def check_sync(self):
        self.context.check()
        with self.context._runner._connect() as conn:
            row = conn.execute("SELECT enabled FROM feed_schedules WHERE feed=?", (self.feed.key,)).fetchone()
        if not row or not row[0] or self.feed.prerequisite():
            raise PermissionError("Scheduled source is no longer configured/enabled")
        if time.monotonic() - self.started >= self.feed.seconds:
            raise BudgetReached()

    async def reserve(self, url, allowance):
        self.tasks.add(asyncio.current_task())
        await self.check()
        if not self.feed.permits(url):
            raise PermissionError("Destination is outside the registered feed surface")
        # Reserve the FULL per-response allowance before every request. Refund
        # only successful bounded bodies. Failed/truncated bodies stay charged.
        async with self.lock:
            if self.requests >= self.feed.requests or self.charged + allowance > self.feed.bytes:
                raise BudgetReached()
            self.requests += 1
            self.charged += allowance
        await self.quota()
        if self.feed.vendor:
            from .ratelimit import QuotaExceeded, rate_limiter
            try:
                await rate_limiter._acquire(self.feed.vendor)
            except QuotaExceeded:
                raise Retry(Failure.RATE_LIMIT, after_seconds=86400) from None
        await self.check()  # a wait/quota reservation never carries approval forward

    async def drain(self):
        # Legacy gather() may propagate one exception while sibling units are
        # still finishing. Keep the runner lock until ALL of those units end.
        tasks = [task for task in self.tasks if task is not asyncio.current_task()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def quota(self):
        def acquire():
            runner = self.context._runner
            now = runner._now().timestamp()
            bucket = self.feed.bucket
            with runner._connect(write=True) as conn:
                row = conn.execute("SELECT until_at FROM feed_cooldowns WHERE bucket=?", (bucket,)).fetchone()
                if row and row[0] > now:
                    raise Retry(Failure.RATE_LIMIT, after_seconds=min(31536000, math.ceil(row[0] - now)))
                conn.execute("DELETE FROM feed_request_usage WHERE requested_at<=?", (now - 86400,))
                day = conn.execute("SELECT count(*) FROM feed_request_usage WHERE bucket=?", (bucket,)).fetchone()[0]
                rows = conn.execute("SELECT requested_at FROM feed_request_usage WHERE bucket=? AND requested_at>? ORDER BY requested_at",
                                    (bucket, now - 60)).fetchall()
                if day >= self.feed.rpd:
                    raise Retry(Failure.RATE_LIMIT, after_seconds=86400)
                if len(rows) >= self.feed.rpm:
                    raise Retry(Failure.RATE_LIMIT, after_seconds=max(1, math.ceil(rows[0][0] + 60 - now)))
                conn.execute("INSERT INTO feed_request_usage VALUES (?, ?)", (bucket, now))
        await asyncio.to_thread(acquire)

    async def limited(self, header):
        # Persist a shared provider cooldown. Never log headers, URLs or bodies.
        now = self.context._runner._now()
        delay = 300
        if header and len(header) <= 128:
            try:
                delay = int(header) if header.isascii() and header.isdigit() else math.ceil(
                    (parsedate_to_datetime(header).astimezone(timezone.utc) - now).total_seconds())
            except (ValueError, TypeError, OverflowError):
                pass
        delay = max(300, min(31536000, delay))
        def save():
            with self.context._runner._connect(write=True) as conn:
                conn.execute("INSERT INTO feed_cooldowns VALUES (?, ?) ON CONFLICT(bucket) DO UPDATE SET until_at=MAX(until_at,excluded.until_at)",
                             (self.feed.bucket, now.timestamp() + delay))
        await asyncio.to_thread(save)
        raise Retry(Failure.RATE_LIMIT, after_seconds=delay)

    async def capture(self, url, raw, allowance):
        await self.check()
        digest = sha256(raw).hexdigest()
        parts = urlsplit(url)
        # Query values (including tokens) never enter evidence/job metadata.
        safe_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        identity = sha256((safe_url + ":" + digest).encode()).hexdigest()
        slot = "response." + identity
        def save():
            doc = self.context.document(slot, lambda: Document(
                source_id=self.feed.source, external_id=safe_url, capture_key=uuid4().hex,
                title=self.feed.label, source_url=safe_url, kind="feed",
                collection_method=self.feed.method, content_sha256=digest,
                collected_at=self.context._runner._stamp(self.context._runner._now())))
            # Saved metadata can only be replayed for this exact original input.
            if doc.content_sha256 != digest:
                raise ValueError("Replay digest differs")
            ident = evidence.record_document(doc)
            with self.context._runner._connect(write=True) as conn:
                conn.execute("INSERT OR IGNORE INTO feed_capture_progress(job_id,document_id) VALUES (?, ?)",
                             (self.context.check()["id"], ident))
            return ident
        ident = await asyncio.to_thread(save)
        async with self.lock:
            self.charged -= allowance - len(raw)
            self.captures.setdefault(digest, set()).add(ident)

    async def validated(self, raw=None, *, ingested=False, only_validated=False):
        await self.check()
        digest = sha256(raw).hexdigest() if raw is not None else None
        ids = list(self.captures[digest]) if digest in self.captures else [ident for group in self.captures.values() for ident in group] if raw is None else []
        if not ids:
            return
        async with self.lock:
            def save():
                job = self.context.check()
                if only_validated:
                    with self.context._runner._connect() as conn:
                        saved = {row[0] for row in conn.execute("SELECT document_id FROM feed_capture_progress WHERE job_id=? AND validated_at IS NOT NULL", (job["id"],))}
                    selected = [ident for ident in ids if ident in saved]
                else:
                    selected = ids
                if not selected:
                    return
                self.context.retrieved()
                now = self.context._runner._stamp(self.context._runner._now())
                with self.context._runner._connect(write=True) as conn:
                    conn.executemany("UPDATE feed_capture_progress SET validated_at=COALESCE(validated_at,?), ingested_at=CASE WHEN ? THEN COALESCE(ingested_at,?) ELSE ingested_at END WHERE job_id=? AND document_id=?",
                                     [(now, ingested, now, job["id"], ident) for ident in selected])
                    conn.execute("UPDATE feed_schedules SET last_retrieval_at=? WHERE feed=?", (now, self.feed.key))
                    count = conn.execute("SELECT count(*) FROM feed_capture_progress WHERE job_id=? AND ingested_at IS NOT NULL", (job["id"],)).fetchone()[0]
                self.context.progress(count, checkpoint={"captures_ingested": count})
            await asyncio.to_thread(save)


async def validated(raw=None, *, ingested=False, only_validated=False):
    scope = current.get()
    if scope is not None:
        await scope.validated(raw, ingested=ingested, only_validated=only_validated)


async def fetch(url, *, max_bytes, headers=None, links=None, method="GET", params=None, data=None, json_body=None, _hops=0):
    """Scheduled transport: fixed surface, no implicit redirects or hidden retry."""
    from ..modules.enrich import base
    import httpx

    scope = current.get()
    max_bytes = min(max_bytes, scope.feed.response_bytes)
    await scope.reserve(url, max_bytes)
    try:
        remaining = max(0.001, scope.feed.seconds - (time.monotonic() - scope.started))
        async with asyncio.timeout(min(120, remaining)):
            async with base.get_client().stream(method, url, headers=headers, params=params, data=data,
                                                json=json_body, follow_redirects=False) as response:
                if response.status_code == 429:
                    await scope.limited(response.headers.get("Retry-After"))
                if response.status_code in (301, 302, 303, 307, 308) and scope.feed.redirects:
                    location = response.headers.get("location", "")
                    # Only the CVE delta adapter permits bounded redirects to
                    # fixed official release-asset host/path patterns. No auth
                    # headers or request payloads are forwarded to another host.
                    from urllib.parse import urljoin
                    target = urljoin(url, location)
                    if _hops >= scope.feed.redirects or not scope.feed.permits(target):
                        raise PermissionError("Unregistered feed redirect")
                    return await fetch(target, max_bytes=max_bytes, links=links, _hops=_hops+1)
                if response.status_code != 200:
                    return response.status_code, None, None
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > max_bytes:
                        return 200, None, "Scheduled response exceeded its byte budget"
                    chunks.append(chunk)
                raw = b"".join(chunks)
                if links is not None:
                    links.update(response.links)
        await scope.capture(url, raw, max_bytes)
        return 200, raw, None
    except (TimeoutError, httpx.HTTPError, httpx.InvalidURL):
        raise Retry(Failure.TRANSIENT) from None
