"""
urlscan.io client (async). URLs and domains.

This client only SEARCHES existing public scans; it never submits a new scan.
Submitting would send the indicator to urlscan to be fetched and, for a public
scan, published, which is an outward action we do not take automatically.

The search tells us whether a URL or domain has been scanned before, how many
times, and the latest scan's basic facts. It is informational, so the verdict
stays "unknown"; deeper verdict data would need a follow-up fetch of each
result. An API key raises the rate limit but is not required.
Docs: https://urlscan.io/docs/api/
"""

import httpx

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from .base import vendor_result

API_URL = "https://urlscan.io/api/v1/search/"
VENDOR = "urlscan"
CACHE_TTL = 3 * 3600
NOT_FOUND_TTL = 3600


def _query_for(itype: str, value: str) -> str:
    if itype == "domain":
        return f'domain:"{value}"'
    return f'page.url:"{value}"'       # url


def _summarise(body: dict) -> dict:
    results = body.get("results") or []
    total = body.get("total") or len(results)
    if not results:
        return {"verdict": "unknown", "ratio": None,
                "summary": {"note": "no existing scans on urlscan"}}

    top = results[0]
    page = top.get("page") or {}
    task = top.get("task") or {}
    summary = {
        "scans_found": total,
        "latest_scan": task.get("time"),
        "page_domain": page.get("domain"),
        "page_ip": page.get("ip"),
        "page_server": page.get("server"),
        "country": page.get("country"),
        "result": top.get("result"),
    }
    return {"verdict": "unknown", "ratio": f"{total} scan(s)", "summary": summary}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype not in ("url", "domain"):
        return vendor_result(VENDOR, itype, value, error=f"urlscan does not handle type: {itype}")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return vendor_result(VENDOR, itype, value, error=str(exc))

    headers = {"Accept": "application/json"}
    if settings.urlscan_api_key:
        headers["API-Key"] = settings.urlscan_api_key
    params = {"q": _query_for(itype, value), "size": 5}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(API_URL, headers=headers, params=params)
    except httpx.HTTPError as exc:
        return vendor_result(VENDOR, itype, value, verdict="error", error=f"request failed: {exc}")

    if resp.status_code == 401:
        return vendor_result(VENDOR, itype, value, error="urlscan rejected the API key (401)")
    if resp.status_code == 429:
        return vendor_result(VENDOR, itype, value, error="rate limited by urlscan (429)")
    if resp.status_code >= 400:
        return vendor_result(VENDOR, itype, value, verdict="error",
                             error=f"HTTP {resp.status_code} from urlscan")

    parsed = _summarise(resp.json() or {})
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
    )
    ttl = CACHE_TTL if parsed["ratio"] else NOT_FOUND_TTL
    cache.set(VENDOR, cache_key, result.model_dump(), ttl)
    return result
