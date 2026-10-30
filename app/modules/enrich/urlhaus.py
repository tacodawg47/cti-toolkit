"""
abuse.ch URLhaus client (async). URLs, hosts (domain or IP), and file hashes.

URLhaus tracks URLs used for malware distribution. A URL is looked up on the
/url/ endpoint; a domain or IP is looked up as a host on the /host/ endpoint;
a file hash is looked up as a payload on the /payload/ endpoint (MD5 or SHA256
only). A hit verdicts malicious. Requires the abuse.ch Auth-Key.
Docs: https://urlhaus-api.abuse.ch/
"""

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from . import base
from .base import vendor_result

API_BASE = "https://urlhaus-api.abuse.ch/v1"
VENDOR = "urlhaus"
CACHE_TTL = 6 * 3600
NOT_FOUND_TTL = 3600


def _not_listed() -> dict:
    return {"verdict": "unknown", "ratio": None, "summary": {"note": "not listed in URLhaus"}}


def _error(status: str) -> dict:
    # invalid_url / invalid_host etc. mean our input or request was malformed,
    # not that the indicator is clean. Surface it as an error, not "not listed".
    return {"verdict": "error", "ratio": None, "summary": {}, "error": f"URLhaus: {status}"}


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
        return _not_listed()
    return _error(status)


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
        return _not_listed()
    return _error(status)


def _summarise_payload(body: dict) -> dict:
    status = body.get("query_status")
    if status == "ok":
        summary = {
            "signature": body.get("signature"),
            "file_type": body.get("file_type"),
            "url_count": body.get("url_count"),
            "first_seen": body.get("firstseen"),
            "sha256": body.get("sha256_hash"),
        }
        return {"verdict": "malicious", "ratio": "known payload", "summary": summary}
    if status in ("no_results", "ok_without_results"):
        return _not_listed()
    return _error(status)


def _request_for(itype: str, value: str):
    """Return (endpoint, form_data, summariser) for the indicator, or None if
    this client cannot query it (e.g. a SHA1 hash, which /payload/ doesn't take)."""
    if itype == "url":
        return f"{API_BASE}/url/", {"url": value}, _summarise_url
    if itype in ("domain", "ip"):
        return f"{API_BASE}/host/", {"host": value}, _summarise_host
    if itype == "hash":
        h = value.lower()
        if len(h) == 32:
            return f"{API_BASE}/payload/", {"md5_hash": h}, _summarise_payload
        if len(h) == 64:
            return f"{API_BASE}/payload/", {"sha256_hash": h}, _summarise_payload
        return None     # SHA1: URLhaus payload lookup supports MD5/SHA256 only
    return None


async def lookup(itype: str, value: str) -> VendorResult:
    req = _request_for(itype, value)
    if req is None:
        if itype == "hash":
            return vendor_result(VENDOR, itype, value,
                                 summary={"note": "URLhaus payload lookup supports MD5/SHA256 only"})
        return base.failed(VENDOR, itype, value, f"URLhaus does not handle type: {itype}")
    if not settings.abusech_auth_key:
        return base.not_configured(VENDOR, itype, value, "no abuse.ch Auth-Key configured")

    endpoint, form, summarise = req

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return base.quota(VENDOR, itype, value, str(exc))

    headers = {"Auth-Key": settings.abusech_auth_key, "Accept": "application/json"}
    status, body, err = await base.fetch_json("POST", endpoint, headers=headers, data=form)
    if err:
        return base.failed(VENDOR, itype, value, err)
    if status == 401:
        return base.failed(VENDOR, itype, value, "abuse.ch rejected the Auth-Key (401)")
    if status != 200:
        return base.failed(VENDOR, itype, value, f"HTTP {status} from URLhaus")

    parsed = summarise(body or {})
    if parsed["verdict"] == "error":
        # invalid_url / invalid_host etc. Same shape as the other abuse.ch
        # clients: status "error" so the UI shows the message, and not cached.
        return base.failed(VENDOR, itype, value, parsed.get("error") or "URLhaus lookup failed")

    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
    )
    ttl = CACHE_TTL if parsed["verdict"] == "malicious" else NOT_FOUND_TTL
    cache.put(VENDOR, cache_key, result.model_dump(), ttl)
    return result
