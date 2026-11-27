"""API-only code-search references. No repository, blob, README or secret fetch."""

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

KEY = "github_exposure"
API = "https://api.github.com/search/code"


async def cooldown(scope, headers, *, failed=False):
    """Use only bounded quota headers, never retain provider error bodies."""
    now = scope.context._runner._now().timestamp()
    attempt = scope.context.check()["attempts"]
    delay = 300 * 2 ** (attempt - 1) if failed else 0
    retry = headers.get("retry-after", "")
    if len(retry) <= 12 and retry.isascii() and retry.isdigit():
        delay = max(delay, int(retry))
    reset = headers.get("x-ratelimit-reset", "")
    if headers.get("x-ratelimit-remaining") == "0":
        delay = max(delay, 300)
        if len(reset) <= 12 and reset.isascii() and reset.isdigit():
            delay = max(delay, math.ceil(int(reset) - now) + 1)
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
    params = {"q": permission["query"], "per_page": models.PER_PAGE, "page": page["page"]}
    await scope.reserve(API, models.MAX_BYTES)
    await asyncio.to_thread(store.check, scope, page["permission_id"])
    await asyncio.to_thread(store.attempted, scope, page)
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": models.API_VERSION,
               "Accept-Encoding": "identity",
               "User-Agent": "CTI-Toolkit/3A.4 (authorized public-code metadata leads)",
               "Authorization": "Bearer " + settings.github_exposure_token}
    try:
        remaining = max(0.001, scope.feed.seconds - (time.monotonic() - scope.started))
        async with asyncio.timeout(min(30, remaining)):
            async with base.get_client().stream("GET", API, params=params, headers=headers, follow_redirects=False) as response:
                # A 403 may be a secondary limit without quota headers. Back off
                # conservatively and finitely; never probe account permissions.
                if response.status_code in (403, 429):
                    await cooldown(scope, response.headers, failed=True)
                if response.status_code in (400, 401, 404, 410, 422):
                    raise PermissionError("GitHub search query, version or access refused")
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
                                 ("retry-after", "x-ratelimit-remaining", "x-ratelimit-reset")}
        await asyncio.to_thread(store.check, scope, page["permission_id"])
        value = await asyncio.to_thread(models.parse, raw)
        await asyncio.to_thread(store.check, scope, page["permission_id"])
        identity = sha256(json.dumps([permission["id"], params, models.QUERY_VERSION, models.API_VERSION], sort_keys=True).encode()).hexdigest()
        scope.capture_kind = "api_response"
        document_id = await scope.capture(API, raw, models.MAX_BYTES, request_identity=identity,
                                          media_type="application/json", sensitive=True)
        await scope.validated(raw)
        await asyncio.to_thread(store.stage, scope, page, document_id, value)
        # Keep successful input before an exhausted response budget pauses the
        # next request. Its original capture remains usable after restart.
        await cooldown(scope, quota_headers)
    except (TimeoutError, httpx.HTTPError, httpx.InvalidURL):
        raise Retry(Failure.TRANSIENT) from None


async def refresh():
    scope = feed_scope.current.get()
    if scope is None or scope.feed.key != KEY:
        raise PermissionError("GitHub collection requires its registered durable scope")
    scope.unit_progress = True
    units = await asyncio.to_thread(store.plan, scope)
    if not units:
        return {"ok": True, "entries": 0, "unchanged": True, "complete": False}
    done = sum(unit["completed"] for unit in units)
    await asyncio.to_thread(scope.context.progress, done, total=len(units), checkpoint={"github_queries_ingested": done})
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
                if models.Page.model_validate_json(first["payload"]).total_count <= models.PER_PAGE:
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
        await asyncio.to_thread(scope.context.progress, done, checkpoint={"github_queries_ingested": done})
    await scope.check()
    scope.status(KEY, done, "Bounded Public-Code Query Windows; Exact Content And Exposure Unverified", None)
    return {"ok": True, "entries": done, "unchanged": not bool(scope.captures), "complete": complete}


def catalog():
    return [Feed(KEY, "GitHub Public-Code Search Leads", refresh, (re.compile(re.escape(API)),),
        cadence=86400, stale=2*86400, requests=20, bytes=20*models.MAX_BYTES, seconds=120,
        response_bytes=models.MAX_BYTES, rpm=8, rpd=48, vendor="github", bucket_name="github",
        method="api", raw_allowed=False, allow_empty=True, prerequisite=models.prerequisite,
        coverage=lambda: {"scope": "at_most_two_50_item_pages_per_query", "history": "not_assessed",
            "exact_content_match": "unverified", "query_version": models.QUERY_VERSION,
            "per_selector_health": "/github-exposure"})]
