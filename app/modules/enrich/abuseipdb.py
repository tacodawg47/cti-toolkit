"""
AbuseIPDB API v2 client (async). IP address reputation and abuse reports.

Docs: https://docs.abuseipdb.com/ . The free plan allows 1000 checks per day.
Only the /check endpoint is used: given an IP, it returns an abuse confidence
score (0-100) and recent report counts.
"""

import httpx

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from .base import vendor_result

API_URL = "https://api.abuseipdb.com/api/v2/check"
VENDOR = "abuseipdb"
CACHE_TTL = 6 * 3600       # found results: 6 hours
NOT_FOUND_TTL = 3600       # clean / unreported: 1 hour
MAX_AGE_DAYS = 90          # only count reports from the last 90 days


def _summarise(data: dict) -> dict:
    """Turn the AbuseIPDB `data` object into a verdict and a summary."""
    score = data.get("abuseConfidenceScore") or 0
    reports = data.get("totalReports") or 0

    if score >= 75:
        verdict = "malicious"
    elif score >= 25:
        verdict = "suspicious"
    elif data.get("isWhitelisted") or reports == 0:
        verdict = "clean"
    else:
        verdict = "unknown"

    summary = {
        "abuse_confidence": f"{score}%",
        "total_reports": reports,
        "distinct_reporters": data.get("numDistinctUsers"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "last_reported": data.get("lastReportedAt"),
        "whitelisted": data.get("isWhitelisted"),
    }
    return {"verdict": verdict, "ratio": f"{score}% confidence", "summary": summary}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype != "ip":
        return vendor_result(VENDOR, itype, value, error="AbuseIPDB handles IP addresses only")
    if not settings.abuseipdb_api_key:
        return vendor_result(VENDOR, itype, value, error="no API key configured")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return vendor_result(VENDOR, itype, value, error=str(exc))

    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": value, "maxAgeInDays": MAX_AGE_DAYS}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(API_URL, headers=headers, params=params)
    except httpx.HTTPError as exc:
        return vendor_result(VENDOR, itype, value, verdict="error", error=f"request failed: {type(exc).__name__}")

    if resp.status_code == 401:
        return vendor_result(VENDOR, itype, value, error="AbuseIPDB rejected the API key (401)")
    if resp.status_code == 429:
        return vendor_result(VENDOR, itype, value, error="rate limited by AbuseIPDB (429)")
    if resp.status_code >= 400:
        return vendor_result(VENDOR, itype, value, verdict="error",
                             error=f"HTTP {resp.status_code} from AbuseIPDB")

    data = (resp.json() or {}).get("data") or {}
    parsed = _summarise(data)
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
        raw={"data": data},
    )
    ttl = CACHE_TTL if parsed["verdict"] in ("malicious", "suspicious") else NOT_FOUND_TTL
    cache.set(VENDOR, cache_key, result.model_dump(), ttl)
    return result
