"""One fixed passive hosts API. No DNS, certificate bodies or target requests."""

import asyncio
from hashlib import sha256
import json
import math
import re
import time

import httpx

from ...core import feed_scope
from ...core.config import settings
from ...core.feed_scheduler import Feed
from ...core.jobs import Failure, Retry
from ..enrich import base
from . import models, store

KEY = "subdomain_inventory"
API = models.API


async def cooldown(scope, headers, *, failed=False):
    """Use only bounded quota headers, never retain provider error bodies."""
    now = scope.context._runner._now().timestamp()
    attempt = scope.context.check()["attempts"]
    delay = 300 * 2 ** (attempt - 1) if failed else 0
    retry = headers.get("retry-after", "")
    if len(retry) <= 12 and retry.isascii() and retry.isdigit():
        delay = max(delay, int(retry))
    # No reset timestamp is documented for this endpoint. Conservatively
    # pause to the next UTC month/hour/day when its remaining count is zero.
    from datetime import datetime, timezone
    current = datetime.fromtimestamp(now, timezone.utc)
    if headers.get("x-ratelimit-remaining") == "0":
        year, month = (current.year + 1, 1) if current.month == 12 else (current.year, current.month + 1)
        delay = max(delay, math.ceil(datetime(year, month, 1, tzinfo=timezone.utc).timestamp() - now) + 1)
    if headers.get("x-hourly-remaining") == "0":
        delay = max(delay, 3600 - int(now) % 3600 + 1)
    if headers.get("x-daily-remaining") == "0":
        delay = max(delay, 86400 - int(now) % 86400 + 1)
    if not delay:
        return
    delay = max(300, min(31536000, delay))
    def save():
        with scope.context._runner._connect(write=True) as conn:
            conn.execute("INSERT INTO feed_cooldowns VALUES (?,?) ON CONFLICT(bucket) DO UPDATE SET until_at=MAX(until_at,excluded.until_at)",
                         (scope.feed.bucket, now + delay))
    await asyncio.to_thread(save)
    if failed:
        raise Retry(Failure.RATE_LIMIT, after_seconds=delay)


async def fetch(scope, page):
    permission = await asyncio.to_thread(store.check, scope, page["permission_id"])
    url = models.query(permission["selector_value"])
    params = {}
    if page["page"] == 2:
        first = (await asyncio.to_thread(store.pages, page))[0]
        prior = models.Page.model_validate_json(first["payload"])
        if not first["completed"] or not prior.has_next:
            raise PermissionError("Pagination needs its committed original page")
        params["after"] = models.cursor(prior.next_cursor)
    await scope.reserve(url, models.MAX_BYTES)
    await asyncio.to_thread(store.check, scope, page["permission_id"])
    await asyncio.to_thread(store.attempted, scope, page)
    headers = {"Accept": "application/json",
               "Accept-Encoding": "identity",
               "User-Agent": "CTI-Toolkit/3A.5 (authorized passive inventory)",
               "Authorization": "Bearer " + settings.ctlogs_api_key}
    try:
        remaining = max(0.001, scope.feed.seconds - (time.monotonic() - scope.started))
        async with asyncio.timeout(min(30, remaining)):
            async with base.get_client().stream("GET", url, params=params, headers=headers, follow_redirects=False) as response:
                # Documented busy/quota failures back off without probing access.
                if response.status_code in (429, 503):
                    await cooldown(scope, response.headers, failed=True)
                if response.status_code in (400, 401, 403, 404, 410, 422):
                    raise PermissionError("CTLogs search query, version or access refused")
                if response.status_code != 200:
                    raise Retry(Failure.TRANSIENT if response.status_code >= 500 else Failure.INVALID_RESPONSE)
                if response.headers.get("content-type", "").split(";", 1)[0].lower().strip() != "application/json":
                    raise Retry(Failure.INVALID_RESPONSE)
                if response.headers.get("content-encoding", "identity").lower().strip() != "identity":
                    raise Retry(Failure.INVALID_RESPONSE)
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    await asyncio.to_thread(store.check, scope, page["permission_id"])
                    size += len(chunk)
                    if size > models.MAX_BYTES:
                        raise Retry(Failure.INVALID_RESPONSE)
                    chunks.append(chunk)
                raw = b"".join(chunks)
                # No Link URL, contents URL, redirect, or returned host is used.
                quota_headers = {key: response.headers.get(key, "") for key in
                                 ("retry-after", "x-ratelimit-remaining", "x-hourly-remaining", "x-daily-remaining")}
        await asyncio.to_thread(store.check, scope, page["permission_id"])
        value = await asyncio.to_thread(models.parse, raw, permission["selector_value"])
        await asyncio.to_thread(store.check, scope, page["permission_id"])
        # Persist successful quota exhaustion before a recoverable page exists.
        # A stage/ingestion crash must not discard the response's cooldown.
        await cooldown(scope, quota_headers)
        identity = sha256(json.dumps([permission["id"], url, params, models.QUERY_VERSION, models.API_VERSION], sort_keys=True).encode()).hexdigest()
        scope.capture_kind = "api_response"
        document_id = await scope.capture(API, raw, models.MAX_BYTES, request_identity=identity,
                                          media_type="application/json", sensitive=True)
        await scope.validated(raw)
        await asyncio.to_thread(store.stage, scope, page, document_id, value)
    except (TimeoutError, httpx.HTTPError, httpx.InvalidURL):
        raise Retry(Failure.TRANSIENT) from None


async def refresh():
    scope = feed_scope.current.get()
    if scope is None or scope.feed.key != KEY:
        raise PermissionError("CTLogs collection requires its registered durable scope")
    scope.unit_progress = True
    units = await asyncio.to_thread(store.plan, scope)
    if not units:
        return {"ok": True, "entries": 0, "unchanged": True, "complete": False}
    done = sum(unit["completed"] for unit in units)
    await asyncio.to_thread(scope.context.progress, done, total=len(units), checkpoint={"inventory_domains_ingested": done})
    complete = True
    for unit in units:
        await asyncio.to_thread(store.check, scope, unit["permission_id"])
        if unit["completed"]:
            complete = complete and bool(unit["window_complete"])
            continue
        pages = await asyncio.to_thread(store.pages, unit)
        for page in pages:
            await asyncio.to_thread(store.check, scope, unit["permission_id"])
            if page["page"] == 2:
                first = (await asyncio.to_thread(store.pages, unit))[0]
                if not models.Page.model_validate_json(first["payload"]).has_next:
                    break
            if page["completed"]:
                continue
            if page["document_id"] is None:
                await fetch(scope, page)
                page = (await asyncio.to_thread(store.pages, unit))[page["page"] - 1]
            await asyncio.to_thread(store.ingest, scope, page)
        window = await asyncio.to_thread(store.finish, scope, unit)
        complete = complete and window
        done += 1
        await asyncio.to_thread(scope.context.progress, done, checkpoint={"inventory_domains_ingested": done})
    await scope.check()
    scope.status(KEY, done, "Bounded CT Inventory Windows; DNS And Ownership Unverified", None)
    return {"ok": True, "entries": done, "unchanged": not bool(scope.captures), "complete": complete}


def catalog():
    return [Feed(KEY, "CTLogs Passive Subdomain Inventory", refresh, (re.compile(re.escape(API) + r"/[a-z0-9.-]{3,253}"),),
        cadence=86400, stale=2*86400, requests=20, bytes=20*models.MAX_BYTES, seconds=120,
        response_bytes=models.MAX_BYTES, rpm=20, rpd=48, bucket_name="ctlogs_hosts",
        method="api", raw_allowed=False, allow_empty=True, prerequisite=models.prerequisite,
        coverage=lambda: {"scope": "at_most_two_100_name_pages_per_domain", "history": "certificates_valid_or_expired_within_90_days",
            "dns_ownership": "unverified", "query_version": models.QUERY_VERSION,
            "per_selector_health": "/subdomains"})]
