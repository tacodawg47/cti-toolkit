"""Original HIBP API consumer. No SDK, source records or third-party code.

Attribution: Have I Been Pwned, https://haveibeenpwned.com/, CC BY 4.0.
Direct-email search transmits personal data. Registration grants no approval.
"""

import asyncio
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
import time
from urllib.parse import quote

import httpx

from ...core import feed_scope
from ...core.config import settings
from ...core.evidence_models import instant
from ...core.feed_scheduler import Feed
from ...core.jobs import Failure, Retry
from ..enrich import base
from . import models, store

KEY = "hibp_email"
BASE = "https://haveibeenpwned.com/api/v3/breachedAccount"


def prerequisite():
    try:
        until = datetime.fromisoformat(instant(settings.hibp_subscription_until))
    except (ValueError, TypeError):
        return "Review HIBP paid direct-email entitlement and expiry"
    if until <= datetime.now(timezone.utc) or not re.fullmatch(r"[a-fA-F0-9]{32}", settings.hibp_api_key):
        return "Configure a current reviewed HIBP paid direct-email entitlement"
    return ""


async def fetch(scope, unit):
    permission = await asyncio.to_thread(store.check, scope, unit["permission_id"])
    # URL-encode the WHOLE selector, including +, slash, percent and @. No
    # response field can choose a destination or a subsequent lookup.
    url = BASE + "/" + quote(permission["value"].lower(), safe="")
    await scope.reserve(url, models.MAX_BYTES)
    await asyncio.to_thread(store.check, scope, unit["permission_id"])
    await asyncio.to_thread(store.attempted, scope, unit["permission_id"])
    try:
        remaining = max(0.001, scope.feed.seconds - (time.monotonic()-scope.started))
        async with asyncio.timeout(min(30, remaining)):
            async with base.get_client().stream("GET", url, params={"truncateResponse": "false"},
                    headers={"hibp-api-key": settings.hibp_api_key, "User-Agent": "CTI-Toolkit/3A.2 (local authorized email monitoring)",
                             "Accept": "application/json"}, follow_redirects=False) as response:
                if response.status_code == 429:
                    await scope.limited(response.headers.get("Retry-After"))
                if response.status_code in (401, 403, 400):
                    raise PermissionError("HIBP rejected entitlement or request")
                if response.status_code not in (200, 404):
                    raise Retry(Failure.TRANSIENT if response.status_code >= 500 else Failure.INVALID_RESPONSE)
                chunks, size = [], 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > models.MAX_BYTES:
                        raise Retry(Failure.INVALID_RESPONSE)
                    chunks.append(chunk)
                raw = b"".join(chunks)
                status = response.status_code
                if status == 200 and response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise Retry(Failure.INVALID_RESPONSE)
        await asyncio.to_thread(store.check, scope, unit["permission_id"])
        breaches = await asyncio.to_thread(models.parse, raw, status)
        await asyncio.to_thread(store.check, scope, unit["permission_id"])
        # Retain neither the email URL nor headers in capture/job metadata.
        # Explicitly label the request path as redacted, not a literal full URL.
        identity = sha256(json.dumps([permission["selector_id"], permission["value"].lower(), status]).encode()).hexdigest()
        document_id = await scope.capture(BASE, raw, models.MAX_BYTES, request_identity=identity,
                            media_type="application/json" if status == 200 else "application/octet-stream", sensitive=True)
        await scope.validated(raw)
        await asyncio.to_thread(store.stage, scope, unit, document_id, status, breaches)
    except (TimeoutError, httpx.HTTPError, httpx.InvalidURL):
        raise Retry(Failure.TRANSIENT) from None


async def refresh():
    scope = feed_scope.current.get()
    if scope is None or scope.feed.key != KEY:
        raise PermissionError("Breach lookup requires its registered durable scope")
    units = await asyncio.to_thread(store.plan, scope)
    if not units:
        return {"ok": True, "unchanged": True, "complete": False}
    completed = sum(unit["completed"] for unit in units)
    await asyncio.to_thread(scope.context.progress, completed, total=len(units), checkpoint={"lookups_ingested": completed})
    for unit in units:
        await asyncio.to_thread(store.check, scope, unit["permission_id"])
        if unit["completed"]:
            continue
        if unit["document_id"] is None:
            await fetch(scope, unit)
            unit = next(u for u in await asyncio.to_thread(store.plan, scope) if u["permission_id"] == unit["permission_id"])
        await asyncio.to_thread(store.ingest, scope, unit)
    await scope.check()
    await asyncio.to_thread(scope.context.progress, len(units), total=len(units), checkpoint={"lookups_ingested": len(units)})
    scope.status(KEY, len(units), "Approved Email Snapshot Only; No Public Result Is Not A Clean Verdict", None)
    return {"ok": True, "entries": len(units), "unchanged": not bool(scope.captures)}


def catalog():
    return [Feed(KEY, "Have I Been Pwned Email Associations", refresh,
        (re.compile(re.escape(BASE)+r"/[A-Za-z0-9_.~%+-]+"),),
        cadence=86400, stale=2*86400, requests=10, bytes=10*models.MAX_BYTES, seconds=120,
        response_bytes=models.MAX_BYTES, rpm=10, rpd=240, vendor="hibp", method="api", raw_allowed=False,
        prerequisite=prerequisite, coverage=lambda: {"scope": "approved_email_snapshots_only",
            "history": "not_assessed", "sensitive_retired_opted_out": "not_returned", "per_address_health": "/breaches"})]
