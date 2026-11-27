"""Original API adapter, written from RansomLook's public API documentation.

Data attribution: RansomLook, CC BY 4.0, https://www.ransomlook.io/about.
No upstream service code is imported. This registration grants no activation.
"""

import asyncio
from hashlib import sha256
import re
import json

from ...core import feed_scope
from ...core.feed_scheduler import Feed
from ...core.jobs import Failure, Retry
from . import store
from .models import Claim, parse_recent

KEY = "ransomlook_recent"
URL = "https://www.ransomlook.io/api/recent/100"


async def drain(scope):
    batch = await asyncio.to_thread(store.pending, scope)
    if batch:
        claims = [Claim(**row) for row in json.loads(batch["payload"])]
        for index in range(batch["next_row"], batch["row_count"]):
            await scope.check()
            await asyncio.to_thread(store.ingest_row, scope, batch, index, claims[index])
        await asyncio.to_thread(store.finish_batch, scope, batch)
    return batch


async def refresh():
    scope = feed_scope.current.get()
    if scope is None or scope.feed.key != KEY:
        raise PermissionError("Victim collection requires its registered durable scope")
    # Finish saved normalized input before any new HTTP. Raw availability and
    # moving upstream snapshots cannot erase a captured unfinished claim.
    await drain(scope)
    if await asyncio.to_thread(store.pending, scope):
        return {"ok": True, "unchanged": True, "complete": False}
    status, raw, error = await feed_scope.fetch(URL, max_bytes=2*1024**2, headers={"Accept": "application/json"})
    if status != 200 or error:
        raise Retry(Failure.INVALID_RESPONSE)
    claims = await asyncio.to_thread(parse_recent, raw)
    await feed_scope.validated(raw)
    document_id = next(iter(scope.captures[sha256(raw).hexdigest()]))
    await scope.check()
    await asyncio.to_thread(store.stage, scope, document_id, claims)
    await drain(scope)
    await scope.check()
    if await asyncio.to_thread(store.pending, scope):
        return {"ok": True, "entries": len(claims), "complete": False}
    await feed_scope.validated(raw, ingested=True)
    scope.status(KEY, len(claims), "Latest 100 Posts Only; History And Gaps Not Assessed", None)
    return {"ok": True, "entries": len(claims)}


def catalog():
    return [Feed(KEY, "RansomLook Recent Victim Claims", refresh, (re.compile(re.escape(URL)),),
        cadence=3600, stale=6*3600, requests=1, bytes=2*1024**2, seconds=60,
        response_bytes=2*1024**2, rpm=1, rpd=24, vendor="ransomlook", method="api", raw_allowed=False,
        coverage=lambda: {"scope": "latest_100_posts_only", "historical_coverage": "not_assessed",
                          "continuity": "not_assessed", "sector_country": "not_supplied"})]
