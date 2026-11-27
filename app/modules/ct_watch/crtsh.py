"""Provisional disabled crt.sh consumer. Hosted-service review stays unapproved.

Original client code; no GPL service implementation imports or copied code.
"""

import asyncio
from hashlib import sha256
import json
import re
import time

import httpx

from ...core import feed_scope
from ...core.feed_scheduler import Feed
from ...core.jobs import Failure, Retry
from ..enrich import base
from . import matching, models, store

KEY = "crtsh_watch"
BASE = "https://crt.sh/"


async def fetch(scope, unit):
    permission = await asyncio.to_thread(store.check, scope, unit["permission_id"])
    params = {"q": "%"+permission["value"]+"%", "output": "json", "exclude": "expired"}
    await scope.reserve(BASE, models.MAX_BYTES)
    await asyncio.to_thread(store.check, scope, unit["permission_id"])
    await asyncio.to_thread(store.attempted, scope, unit["permission_id"])
    try:
        remaining = max(0.001, scope.feed.seconds-(time.monotonic()-scope.started))
        async with asyncio.timeout(min(30, remaining)):
            async with base.get_client().stream("GET", BASE, params=params,
                    headers={"Accept": "application/json", "User-Agent": "CTI-Toolkit/3A.3 (bounded authorized CT watch)"},
                    follow_redirects=False) as response:
                if response.status_code == 429:
                    await scope.limited(response.headers.get("Retry-After"))
                if response.status_code in (400, 401, 403):
                    raise PermissionError("CT service refused query or access")
                if response.status_code != 200:
                    raise Retry(Failure.TRANSIENT if response.status_code >= 500 else Failure.INVALID_RESPONSE)
                if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise Retry(Failure.INVALID_RESPONSE)
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > models.MAX_BYTES:
                        raise Retry(Failure.INVALID_RESPONSE)
                    chunks.append(chunk)
                raw = b"".join(chunks)
        await asyncio.to_thread(store.check, scope, unit["permission_id"])
        rows = await asyncio.to_thread(models.parse, raw)
        await asyncio.to_thread(store.check, scope, unit["permission_id"])
        if len(json.dumps([row.model_dump() for row in rows]).encode()) > models.MAX_PAYLOAD:
            raise ValueError("Normalized CT response exceeds bounds")
        identity = sha256(json.dumps([permission["id"], params, matching.PATTERN_VERSION], sort_keys=True).encode()).hexdigest()
        scope.capture_kind = "api_response"
        document_id = await scope.capture(BASE, raw, models.MAX_BYTES, request_identity=identity,
                                          media_type="application/json", sensitive=True)
        await scope.validated(raw)
        await asyncio.to_thread(store.stage, scope, unit, document_id, rows)
    except (TimeoutError, httpx.HTTPError, httpx.InvalidURL):
        raise Retry(Failure.TRANSIENT) from None


async def refresh():
    scope = feed_scope.current.get()
    if scope is None or scope.feed.key != KEY:
        raise PermissionError("CT collection requires its registered durable scope")
    units = await asyncio.to_thread(store.plan, scope)
    if not units:
        return {"ok": True, "entries": 0, "unchanged": True, "complete": False}
    done = sum(unit["completed"] for unit in units)
    await asyncio.to_thread(scope.context.progress, done, total=len(units), checkpoint={"ct_queries_ingested": done})
    for unit in units:
        await asyncio.to_thread(store.check, scope, unit["permission_id"])
        if unit["completed"]:
            continue
        if unit["document_id"] is None:
            await fetch(scope, unit)
            unit = next(row for row in await asyncio.to_thread(store.plan, scope) if row["permission_id"] == unit["permission_id"])
        await asyncio.to_thread(store.ingest, scope, unit)
    await scope.check()
    await asyncio.to_thread(scope.context.progress, len(units), total=len(units), checkpoint={"ct_queries_ingested": len(units)})
    scope.status(KEY, len(units), "Bounded Unexpired CT Query Snapshots; Coverage And Continuity Unassessed", None)
    return {"ok": True, "entries": len(units), "unchanged": not bool(scope.captures)}


def catalog():
    return [Feed(KEY, "Provisional crt.sh Candidate Names", refresh, (re.compile(re.escape(BASE)),),
        cadence=86400, stale=2*86400, requests=10, bytes=10*models.MAX_BYTES, seconds=120,
        response_bytes=models.MAX_BYTES, rpm=2, rpd=48, vendor="crtsh", method="api", raw_allowed=False,
        allow_empty=True, coverage=lambda: {"scope": "bounded_unexpired_query_snapshots", "history": "not_assessed",
            "provider_completeness": "unverified", "pattern_version": matching.PATTERN_VERSION, "per_seed_health": "/ct-watches"})]
