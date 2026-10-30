"""
abuse.ch ThreatFox client (async).

ThreatFox is a database of indicators tied to malware and botnet C2. A hit is
a strong malicious signal (the database is curated), so a match verdicts
malicious; no match verdicts unknown (absence from ThreatFox does not prove an
indicator is clean).

Handles ip, domain, url, and hash via the search_ioc query. Requires the
abuse.ch Auth-Key. Docs: https://threatfox.abuse.ch/api/
"""

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from . import base
from .base import vendor_result

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
VENDOR = "threatfox"
CACHE_TTL = 6 * 3600
NOT_FOUND_TTL = 3600


def _summarise(body: dict) -> dict:
    """Interpret a ThreatFox response body (already JSON-decoded)."""
    status = body.get("query_status")
    rows = body.get("data") or []

    if status == "ok" and rows:
        first = rows[0]
        summary = {
            "malware": first.get("malware_printable") or first.get("malware"),
            "threat_type": first.get("threat_type"),
            "confidence": first.get("confidence_level"),
            "first_seen": first.get("first_seen"),
            "tags": first.get("tags"),
            "matches": len(rows),
        }
        return {"verdict": "malicious", "ratio": f"{len(rows)} match(es)", "summary": summary}

    if status in (None, "illegal_search_term", "illegal_search_type"):
        return {"verdict": "error", "ratio": None,
                "summary": {"note": f"ThreatFox could not search: {status}"}, "error": status}

    return {"verdict": "unknown", "ratio": None, "summary": {"note": "not listed in ThreatFox"}}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype not in ("ip", "domain", "url", "hash"):
        return base.failed(VENDOR, itype, value, f"ThreatFox does not handle type: {itype}")
    if not settings.abusech_auth_key:
        return base.not_configured(VENDOR, itype, value, "no abuse.ch Auth-Key configured")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return base.quota(VENDOR, itype, value, str(exc))

    headers = {"Auth-Key": settings.abusech_auth_key, "Accept": "application/json"}
    payload = {"query": "search_ioc", "search_term": value}
    status, body, err = await base.fetch_json("POST", API_URL, headers=headers, json=payload)
    if err:
        return base.failed(VENDOR, itype, value, err)
    if status == 401:
        return base.failed(VENDOR, itype, value, "abuse.ch rejected the Auth-Key (401)")
    if status != 200:
        return base.failed(VENDOR, itype, value, f"HTTP {status} from ThreatFox")

    parsed = _summarise(body or {})
    if parsed["verdict"] == "error":
        return base.failed(VENDOR, itype, value, parsed.get("error") or "ThreatFox search failed")

    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
    )
    ttl = CACHE_TTL if parsed["verdict"] == "malicious" else NOT_FOUND_TTL
    cache.put(VENDOR, cache_key, result.model_dump(), ttl)
    return result
