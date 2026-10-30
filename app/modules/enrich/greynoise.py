"""
GreyNoise Community API client (async). Keyless, for IP addresses.

The community endpoint (https://api.greynoise.io/v3/community/<ip>) says
whether an IP is known internet background noise (mass scanners) and gives a
benign / malicious / unknown classification. It is heavily rate limited, so
results are cached and the daily cap in ratelimit.py is deliberately low.

If a GreyNoise API key is configured it is sent for a higher limit, but the
community endpoint works without one.
"""

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from . import base
from .base import vendor_result

API_BASE = "https://api.greynoise.io/v3/community"
VENDOR = "greynoise"
CACHE_TTL = 6 * 3600
NOT_FOUND_TTL = 3600

# GreyNoise classification -> our verdict vocabulary.
_CLASS_TO_VERDICT = {"malicious": "malicious", "benign": "clean"}


def _summarise(data: dict) -> dict:
    classification = data.get("classification")
    verdict = _CLASS_TO_VERDICT.get(classification, "unknown")
    summary = {
        "classification": classification,
        "noise": data.get("noise"),
        "riot": data.get("riot"),         # part of a known benign service (RIOT)
        "name": data.get("name"),         # actor / provider name
        "last_seen": data.get("last_seen"),
        "link": data.get("link"),
    }
    return {"verdict": verdict, "summary": summary}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype != "ip":
        return base.failed(VENDOR, itype, value, "GreyNoise handles IP addresses only")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return base.quota(VENDOR, itype, value, str(exc))

    headers = {"Accept": "application/json"}
    if settings.greynoise_api_key:
        headers["key"] = settings.greynoise_api_key
    status, body, err = await base.fetch_json("GET", f"{API_BASE}/{value}", headers=headers)
    if err:
        return base.failed(VENDOR, itype, value, err)

    # 404 means "not observed" — a normal answer, not an error.
    if status == 404:
        result = vendor_result(VENDOR, itype, value,
                               summary={"note": "not observed by GreyNoise"})
        cache.put(VENDOR, cache_key, result.model_dump(), NOT_FOUND_TTL)
        return result
    if status == 429:
        return base.quota(VENDOR, itype, value, "rate limited by GreyNoise (429)")
    if status != 200:
        return base.failed(VENDOR, itype, value, f"HTTP {status} from GreyNoise")

    parsed = _summarise(body or {})
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        summary=parsed["summary"],
    )
    ttl = CACHE_TTL if parsed["verdict"] != "unknown" else NOT_FOUND_TTL
    cache.put(VENDOR, cache_key, result.model_dump(), ttl)
    return result
