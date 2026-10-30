"""
Shodan client (async). IP host information.

Shodan is a recon source, not a reputation source: it reports open ports,
services, and known CVEs for an IP, not a malicious/clean judgement. So the
verdict stays "unknown" unless Shodan's own tags (malware, c2, ...) flag the
host as bad, in which case it is nudged to "suspicious". CVEs are shown for
context but do not set the verdict. The real value is the summary (ports, org,
vulns).

Note: Shodan host lookups also consume query credits on your plan, which this
toolkit does not track; the rpm cap just paces requests. Docs:
https://developer.shodan.io/
"""

import httpx

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from .base import vendor_result

API_BASE = "https://api.shodan.io"
VENDOR = "shodan"
CACHE_TTL = 6 * 3600
NOT_FOUND_TTL = 3600
ACCOUNT_TTL = 300          # api-info balance: refresh every 5 minutes

# Shodan tags that suggest the host itself is bad, not just exposed.
_BAD_TAGS = {"malware", "compromised", "honeypot", "c2"}


def _summarise(data: dict) -> dict:
    tags = data.get("tags") or []
    vulns = list(data.get("vulns") or [])

    # Only Shodan's own "this host is bad" tags move the verdict. CVEs are NOT
    # a verdict signal: Shodan infers them from banner versions and most
    # internet hosts carry at least one, so counting them would flag almost
    # everything as suspicious. The CVE count is shown in the summary instead.
    if any(t in _BAD_TAGS for t in tags):
        verdict = "suspicious"
    else:
        verdict = "unknown"

    summary = {
        "org": data.get("org"),
        "isp": data.get("isp"),
        "os": data.get("os"),
        "country": data.get("country_name"),
        "ports": data.get("ports"),
        "hostnames": data.get("hostnames"),
        "tags": tags or None,
        "vulns": vulns[:10] or None,
        "last_update": data.get("last_update"),
    }
    ratio = f"{len(vulns)} known CVE(s)" if vulns else None
    return {"verdict": verdict, "ratio": ratio, "summary": summary}


async def account_info() -> dict | None:
    """
    Read the live credit balance from Shodan's api-info endpoint.

    Credits are a server-side balance (reset on Shodan's monthly cycle, also
    spent by the website and any other tool on the same key), so we read the
    authoritative number rather than count locally. api-info itself costs no
    credits. Returns None if no key is set, or a dict with the balance (or an
    `error` key if the call fails). Cached for ACCOUNT_TTL to avoid a call on
    every page load.
    """
    if not settings.shodan_api_key:
        return None

    hit = cache.get(VENDOR, "api-info")
    if hit is not None:
        return hit

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{API_BASE}/api-info",
                                    params={"key": settings.shodan_api_key})
    except httpx.HTTPError as exc:
        return {"error": f"request failed: {type(exc).__name__}"}

    if resp.status_code == 401:
        return {"error": "Shodan rejected the API key (401)"}
    if resp.status_code >= 400:
        return {"error": f"HTTP {resp.status_code} from Shodan"}

    data = resp.json() or {}
    info = {
        "plan": data.get("plan"),
        "query_credits": data.get("query_credits"),
        "scan_credits": data.get("scan_credits"),
        "monitored_ips": data.get("monitored_ips"),
        "unlocked": data.get("unlocked"),
    }
    cache.set(VENDOR, "api-info", info, ACCOUNT_TTL)   # cache only on success
    return info


async def lookup(itype: str, value: str) -> VendorResult:
    if itype != "ip":
        return vendor_result(VENDOR, itype, value, error="Shodan handles IP addresses only")
    if not settings.shodan_api_key:
        return vendor_result(VENDOR, itype, value, error="no API key configured")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return vendor_result(VENDOR, itype, value, error=str(exc))

    params = {"key": settings.shodan_api_key}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"{API_BASE}/shodan/host/{value}", params=params)
    except httpx.HTTPError as exc:
        return vendor_result(VENDOR, itype, value, verdict="error", error=f"request failed: {type(exc).__name__}")

    if resp.status_code == 404:
        result = vendor_result(VENDOR, itype, value,
                               summary={"note": "no information in Shodan"})
        cache.set(VENDOR, cache_key, result.model_dump(), NOT_FOUND_TTL)
        return result
    if resp.status_code == 401:
        return vendor_result(VENDOR, itype, value, error="Shodan rejected the API key (401)")
    if resp.status_code == 403:
        return vendor_result(VENDOR, itype, value, error="Shodan access denied (403): plan may not allow host lookups")
    if resp.status_code == 429:
        return vendor_result(VENDOR, itype, value, error="rate limited by Shodan (429)")
    if resp.status_code >= 400:
        return vendor_result(VENDOR, itype, value, verdict="error",
                             error=f"HTTP {resp.status_code} from Shodan")

    parsed = _summarise(resp.json() or {})
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
        raw=parsed["summary"],
    )
    cache.set(VENDOR, cache_key, result.model_dump(), CACHE_TTL)
    return result
