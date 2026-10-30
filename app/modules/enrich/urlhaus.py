"""
abuse.ch URLhaus client (async). URLs and hosts (domain or IP).

URLhaus tracks URLs used for malware distribution. A URL is looked up on the
/url/ endpoint; a domain or IP is looked up as a host on the /host/ endpoint.
A hit verdicts malicious. Requires the abuse.ch Auth-Key.
Docs: https://urlhaus-api.abuse.ch/
"""

import httpx

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from .base import vendor_result

API_BASE = "https://urlhaus-api.abuse.ch/v1"
VENDOR = "urlhaus"
CACHE_TTL = 6 * 3600
NOT_FOUND_TTL = 3600


def _summarise_url(body: dict) -> dict:
    status = body.get("query_status")
    if status == "ok":
        summary = {
            "threat": body.get("threat"),
            "url_status": body.get("url_status"),       # online / offline
            "date_added": body.get("date_added"),
            "tags": body.get("tags"),
            "blacklists": body.get("blacklists"),
        }
        return {"verdict": "malicious", "ratio": "listed", "summary": summary}
    if status == "no_results":
        return {"verdict": "unknown", "ratio": None,
                "summary": {"note": "not listed in URLhaus"}}
    # invalid_url / invalid_host etc. mean our input or request was malformed,
    # not that the indicator is clean. Surface it as an error, not "not listed".
    return {"verdict": "error", "ratio": None, "summary": {},
            "error": f"URLhaus: {status}"}


def _summarise_host(body: dict) -> dict:
    status = body.get("query_status")
    if status == "ok":
        urls = body.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        summary = {
            "urls_total": len(urls),
            "urls_online": online,
            "first_seen": body.get("firstseen"),
            "blacklists": body.get("blacklists"),
        }
        return {"verdict": "malicious", "ratio": f"{len(urls)} malware URL(s)", "summary": summary}
    if status == "no_results":
        return {"verdict": "unknown", "ratio": None,
                "summary": {"note": "not listed in URLhaus"}}
    return {"verdict": "error", "ratio": None, "summary": {},
            "error": f"URLhaus: {status}"}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype not in ("url", "domain", "ip"):
        return vendor_result(VENDOR, itype, value, error=f"URLhaus does not handle type: {itype}")
    if not settings.abusech_auth_key:
        return vendor_result(VENDOR, itype, value, error="no abuse.ch Auth-Key configured")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return vendor_result(VENDOR, itype, value, error=str(exc))

    if itype == "url":
        endpoint, field = f"{API_BASE}/url/", "url"
    else:
        endpoint, field = f"{API_BASE}/host/", "host"

    headers = {"Auth-Key": settings.abusech_auth_key, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(endpoint, headers=headers, data={field: value})
    except httpx.HTTPError as exc:
        return vendor_result(VENDOR, itype, value, verdict="error", error=f"request failed: {type(exc).__name__}")

    if resp.status_code == 401:
        return vendor_result(VENDOR, itype, value, error="abuse.ch rejected the Auth-Key (401)")
    if resp.status_code >= 400:
        return vendor_result(VENDOR, itype, value, verdict="error",
                             error=f"HTTP {resp.status_code} from URLhaus")

    body = resp.json() or {}
    parsed = _summarise_url(body) if itype == "url" else _summarise_host(body)
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
        error=parsed.get("error"),
    )
    # Don't cache error responses (likely transient or an input problem).
    if parsed["verdict"] != "error":
        ttl = CACHE_TTL if parsed["verdict"] == "malicious" else NOT_FOUND_TTL
        cache.set(VENDOR, cache_key, result.model_dump(), ttl)
    return result
