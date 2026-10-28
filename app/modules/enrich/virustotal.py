"""
VirusTotal API v3 client (async).

The path-building (`_path_for`, `_url_id`) and the verdict heuristic
(`_summarise`) are ported from the MIT-licensed cti-skills plugin by Liberty91
(tools/clis/virustotal.py), adapted here to httpx + async and the toolkit's
VendorResult / cache / rate-limiter.
"""

import base64

import httpx

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter

API_BASE = "https://www.virustotal.com/api/v3"
VENDOR = "virustotal"
CACHE_TTL = 6 * 3600       # found results: 6 hours
NOT_FOUND_TTL = 3600       # "not in VT": 1 hour


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
    total = sum(v for v in stats.values() if isinstance(v, int))
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
    return {"verdict": verdict, "ratio": ratio, "summary": summary, "attributes": attrs}


def _result(value: str, itype: str, **kw) -> VendorResult:
    return VendorResult(source=VENDOR, indicator=value, indicator_type=itype, **kw)


async def lookup(itype: str, value: str) -> VendorResult:
    if not settings.virustotal_api_key:
        return _result(value, itype, error="no API key configured")

    try:
        path = _path_for(itype, value)
    except ValueError as exc:
        return _result(value, itype, error=str(exc))

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return _result(value, itype, error=str(exc))

    headers = {"x-apikey": settings.virustotal_api_key, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{API_BASE}{path}", headers=headers)
    except httpx.HTTPError as exc:
        return _result(value, itype, verdict="error", error=f"request failed: {exc}")

    if resp.status_code == 404:
        result = _result(value, itype, summary={"note": "not found in VirusTotal"})
        cache.set(VENDOR, cache_key, result.model_dump(), NOT_FOUND_TTL)
        return result
    if resp.status_code == 429:
        return _result(value, itype, error="rate limited by VirusTotal (429)")
    if resp.status_code == 401:
        return _result(value, itype, error="VirusTotal rejected the API key (401)")
    if resp.status_code >= 400:
        return _result(value, itype, verdict="error",
                       error=f"HTTP {resp.status_code} from VirusTotal")

    parsed = _summarise(resp.json())
    result = _result(
        value, itype,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
        raw={"attributes": parsed["attributes"]},
    )
    cache.set(VENDOR, cache_key, result.model_dump(), CACHE_TTL)
    return result
