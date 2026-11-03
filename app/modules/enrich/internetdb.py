"""
Shodan InternetDB client (async). IP addresses. Keyless, no credits.

InternetDB (https://internetdb.shodan.io/) is Shodan's free, fast subset: for
an IP it returns open ports, hostnames, CPEs, known CVEs and tags, with no API
key and no query credits. It lacks the banners, certificates and service
details of the keyed host lookup (shodan.py), so both are kept: InternetDB is
the cheap default for every IP, the keyed call is for when you want the
detail.

Like the keyed client, this is recon, not reputation: the verdict stays
"unknown" unless one of Shodan's "this host is bad" tags is present. CVEs are
shown for context and never set the verdict.
"""

from ...core import cache
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from . import base
from .base import vendor_result
from .shodan import _BAD_TAGS

API_BASE = "https://internetdb.shodan.io"
VENDOR = "internetdb"
CACHE_TTL = 6 * 3600
NOT_FOUND_TTL = 3600


def _summarise(data: dict) -> dict:
    tags = data.get("tags") or []
    vulns = list(data.get("vulns") or [])
    if any(t in _BAD_TAGS for t in tags):
        verdict, confidence = "suspicious", 0.4     # recon tag, a medium-weak lead
    else:
        verdict, confidence = "unknown", 0.0
    summary = {
        "ports": data.get("ports"),
        "hostnames": data.get("hostnames"),
        "cpes": (data.get("cpes") or [])[:10] or None,
        "tags": tags or None,
        "vulns": vulns[:10] or None,
    }
    ratio = f"{len(vulns)} known CVE(s)" if vulns else None
    return {"verdict": verdict, "confidence": confidence, "ratio": ratio, "summary": summary}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype != "ip":
        return base.failed(VENDOR, itype, value, "InternetDB handles IP addresses only")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return base.quota(VENDOR, itype, value, str(exc))

    status, body, err = await base.fetch_json(
        "GET", f"{API_BASE}/{value}", headers={"Accept": "application/json"}
    )
    if err:
        return base.failed(VENDOR, itype, value, err)

    # 404 means "no information": a normal answer, not an error.
    if status == 404:
        result = vendor_result(VENDOR, itype, value,
                               summary={"note": "no information in InternetDB"})
        cache.put(VENDOR, cache_key, result.model_dump(), NOT_FOUND_TTL)
        return result
    if status == 429:
        return base.quota(VENDOR, itype, value, "rate limited by InternetDB (429)")
    if status != 200:
        return base.failed(VENDOR, itype, value, f"HTTP {status} from InternetDB")

    parsed = _summarise(body or {})
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        confidence=parsed["confidence"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
    )
    cache.put(VENDOR, cache_key, result.model_dump(), CACHE_TTL)
    return result
