"""
VirusTotal API v3 client (async).

The path-building (`_path_for`, `_url_id`) and the verdict heuristic
(`_summarise`) are ported from the MIT-licensed cti-skills plugin by Liberty91
(tools/clis/virustotal.py), adapted here to httpx + async and the toolkit's
VendorResult / cache / rate-limiter.
"""

import base64

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from . import base

API_BASE = "https://www.virustotal.com/api/v3"
VENDOR = "virustotal"
CACHE_TTL = 6 * 3600       # found results: 6 hours
NOT_FOUND_TTL = 3600       # "not in VT": 1 hour

# The stats that represent an actual engine opinion. VT also reports timeout,
# type-unsupported, confirmed-timeout and failure; those are not opinions, so
# they must not inflate the detection-ratio denominator.
_ENGINE_STATS = ("harmless", "malicious", "suspicious", "undetected")


def _url_id(url: str) -> str:
    """VT v3 URL identifier: unpadded base64url of the URL."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


def _path_for(itype: str, value: str) -> str:
    if itype == "ip":
        return f"/ip_addresses/{value}"
    if itype == "domain":
        return f"/domains/{value}"
    if itype == "hash":
        return f"/files/{value}"
    if itype == "url":
        return f"/urls/{_url_id(value)}"
    raise ValueError(f"VirusTotal does not handle type: {itype}")


def _summarise(obj: dict) -> dict:
    attrs = (obj.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(stats.get(k, 0) for k in _ENGINE_STATS)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if malicious >= 5:
        verdict = "malicious"
    elif malicious >= 1 or suspicious >= 2:
        verdict = "suspicious"
    elif total >= 10:
        verdict = "clean"
    else:
        verdict = "unknown"

    summary = {
        "community_score": attrs.get("reputation"),
        "tags": attrs.get("tags"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "popular_threat_label": (
            attrs.get("popular_threat_classification") or {}
        ).get("suggested_threat_label"),
        "registrar": attrs.get("registrar"),
    }
    ratio = f"{malicious}/{total}" if total else None
    return {"verdict": verdict, "ratio": ratio, "summary": summary}


async def lookup(itype: str, value: str) -> VendorResult:
    if not settings.virustotal_api_key:
        return base.not_configured(VENDOR, itype, value, "no API key configured")

    try:
        path = _path_for(itype, value)
    except ValueError as exc:
        return base.failed(VENDOR, itype, value, str(exc))

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return base.quota(VENDOR, itype, value, str(exc))

    headers = {"x-apikey": settings.virustotal_api_key, "Accept": "application/json"}
    status, body, err = await base.fetch_json("GET", f"{API_BASE}{path}", headers=headers)
    if err:
        return base.failed(VENDOR, itype, value, err)

    if status == 404:
        result = base.vendor_result(VENDOR, itype, value, summary={"note": "not found in VirusTotal"})
        cache.put(VENDOR, cache_key, result.model_dump(), NOT_FOUND_TTL)
        return result
    if status == 401:
        return base.failed(VENDOR, itype, value, "VirusTotal rejected the API key (401)")
    if status == 429:
        return base.quota(VENDOR, itype, value, "rate limited by VirusTotal (429)")
    if status != 200:
        return base.failed(VENDOR, itype, value, f"HTTP {status} from VirusTotal")

    parsed = _summarise(body or {})
    result = base.vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
    )
    cache.put(VENDOR, cache_key, result.model_dump(), CACHE_TTL)
    return result
