"""One indexed search API; no host lookups, DNS, scans or target requests."""

import asyncio
from hashlib import sha256
import json
import re
import time

import httpx

from ...core import feed_scope
from ...core.config import settings
from ...core.feed_scheduler import Feed
from ...core.jobs import Failure, Retry
from ..enrich import base
from . import models, store

KEY = "cloud_exposure"
API = models.API


async def fetch(scope, page):
    permission = await asyncio.to_thread(store.check, scope, page["permission_id"])
    params = {"key": settings.shodan_api_key, "query": permission["query"],
              "page": page["page"], "minify": "true", "fields": models.FIELDS}
    await scope.reserve(API, models.MAX_BYTES)
    delay = await asyncio.to_thread(store.reserve_search, scope, page)
    if delay:
        await asyncio.sleep(delay)
    await asyncio.to_thread(store.check, scope, page["permission_id"])
    await asyncio.to_thread(store.attempted, scope, page)
    headers = {"Accept": "application/json", "Accept-Encoding": "identity",
               "User-Agent": "CTI-Toolkit/3A.6 (authorized indexed metadata)"}
    try:
        remaining = max(0.001, scope.feed.seconds - (time.monotonic() - scope.started))
        async with asyncio.timeout(min(30, remaining)):
            async with base.get_client().stream("GET", API, params=params, headers=headers, follow_redirects=False) as response:
                if response.status_code in (429, 503):
                    # Saved before any body parsing/staging, including on restart.
                    await scope.limited(response.headers.get("retry-after"))
                if response.status_code in (400, 401, 402, 403, 404, 410, 422):
                    raise PermissionError("Shodan search query or access refused")
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
        await asyncio.to_thread(store.check, scope, page["permission_id"])
        value = await asyncio.to_thread(models.parse, raw, permission["selector_value"])
        await asyncio.to_thread(store.check, scope, page["permission_id"])
        # Bind endpoint/query/projection/page without retaining the credential.
        identity = sha256(json.dumps([permission["id"], permission["query"], page["page"],
            models.FIELDS, models.QUERY_VERSION, models.API_VERSION], sort_keys=True).encode()).hexdigest()
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
        raise PermissionError("Shodan cloud metadata needs its registered durable scope")
    scope.unit_progress = True
    units = await asyncio.to_thread(store.plan, scope)
    if not units:
        return {"ok": True, "entries": 0, "unchanged": True, "complete": False}
    done = sum(unit["completed"] for unit in units)
    await asyncio.to_thread(scope.context.progress, done, total=len(units), checkpoint={"cloud_domains_ingested": done})
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
                if models.Page.model_validate_json(first["payload"]).total <= models.PER_PAGE:
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
        await asyncio.to_thread(scope.context.progress, done, checkpoint={"cloud_domains_ingested": done})
    await scope.check()
    scope.status(KEY, done, "Bounded Shodan Metadata Windows; Ownership And Exposure Unverified", None)
    return {"ok": True, "entries": done, "unchanged": not bool(scope.captures), "complete": complete}


def catalog():
    return [Feed(KEY, "Shodan Indexed Cloud Metadata", refresh, (re.compile(re.escape(API)),),
        cadence=86400, stale=2*86400, requests=20, bytes=20*models.MAX_BYTES, seconds=120,
        response_bytes=models.MAX_BYTES, rpm=20, rpd=48, bucket_name="shodan_cloud_search",
        method="api", raw_allowed=False, allow_empty=True, prerequisite=models.prerequisite,
        coverage=lambda: {"scope": "at_most_two_100_service_pages_per_domain", "history": "provider_30_day_index",
            "ownership_exposure": "unverified", "query_version": models.QUERY_VERSION,
            "per_selector_health": "/cloud-exposure"})]
