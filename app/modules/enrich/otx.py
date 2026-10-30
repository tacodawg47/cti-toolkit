"""
AlienVault OTX (Open Threat Exchange) client (async).

OTX is community threat intelligence organised into "pulses". For an
indicator, the /general section reports how many pulses reference it. Presence
in pulses is a lead, not proof: plenty of benign indicators (example.com, big
CDNs) appear in dozens of pulses, so pulse count alone can never separate a
benign indicator from a malicious one. Pulses therefore cap the verdict at
"suspicious", never "malicious"; OTX's own whitelist / false-positive lists
override that to "clean" when present. Confirmation comes from the other vendors.

Docs: https://otx.alienvault.com/api
"""

import ipaddress
from urllib.parse import quote

import httpx

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from .base import vendor_result

API_BASE = "https://otx.alienvault.com/api/v1/indicators"
VENDOR = "otx"
CACHE_TTL = 6 * 3600
NOT_FOUND_TTL = 3600


def _path(itype: str, value: str) -> str:
    """Build the /general path for an indicator. May raise ValueError."""
    if itype == "ip":
        kind = "IPv6" if ipaddress.ip_address(value).version == 6 else "IPv4"
        return f"/{kind}/{value}/general"
    if itype == "domain":
        return f"/domain/{value}/general"
    if itype == "hash":
        return f"/file/{value}/general"
    if itype == "url":
        return f"/url/{quote(value, safe='')}/general"
    raise ValueError(f"OTX does not handle type: {itype}")


def _summarise(obj: dict) -> dict:
    pulse_info = obj.get("pulse_info") or {}
    count = pulse_info.get("count") or 0
    names = [p.get("name") for p in (pulse_info.get("pulses") or [])][:5]

    # OTX's own validation / false-positive lists are the robust signal. Benign
    # infrastructure (8.8.8.8, big CDNs) sits in many pulses, so pulse count
    # alone cries wolf; if OTX has whitelisted the indicator or accepted a
    # false-positive report, call it clean regardless of pulse count.
    validation = obj.get("validation") or []
    false_positive = obj.get("false_positive") or []
    fp_accepted = any((fp or {}).get("assessment") == "accepted" for fp in false_positive)

    if validation or fp_accepted:
        verdict = "clean"
    elif count >= 1:
        verdict = "suspicious"      # a lead, never proof on its own
    else:
        verdict = "unknown"

    summary = {
        "pulse_count": count,
        "pulses": names,
        "validation": [v.get("name") for v in validation] or None,
        "reputation": obj.get("reputation"),
        "country": obj.get("country_name"),
        "asn": obj.get("asn"),
    }
    return {"verdict": verdict, "ratio": f"{count} pulses", "summary": summary}


async def lookup(itype: str, value: str) -> VendorResult:
    if not settings.otx_api_key:
        return vendor_result(VENDOR, itype, value, error="no API key configured")

    try:
        path = _path(itype, value)
    except ValueError as exc:
        return vendor_result(VENDOR, itype, value, error=str(exc))

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return vendor_result(VENDOR, itype, value, error=str(exc))

    headers = {"X-OTX-API-KEY": settings.otx_api_key, "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{API_BASE}{path}", headers=headers)
    except httpx.HTTPError as exc:
        return vendor_result(VENDOR, itype, value, verdict="error", error=f"request failed: {type(exc).__name__}")

    if resp.status_code == 404:
        result = vendor_result(VENDOR, itype, value, summary={"note": "not found in OTX"})
        cache.set(VENDOR, cache_key, result.model_dump(), NOT_FOUND_TTL)
        return result
    if resp.status_code in (401, 403):
        return vendor_result(VENDOR, itype, value, error="OTX rejected the API key")
    if resp.status_code == 429:
        return vendor_result(VENDOR, itype, value, error="rate limited by OTX (429)")
    if resp.status_code >= 400:
        return vendor_result(VENDOR, itype, value, verdict="error",
                             error=f"HTTP {resp.status_code} from OTX")

    parsed = _summarise(resp.json() or {})
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
        raw=parsed["summary"],
    )
    ttl = CACHE_TTL if parsed["verdict"] != "unknown" else NOT_FOUND_TTL
    cache.set(VENDOR, cache_key, result.model_dump(), ttl)
    return result
