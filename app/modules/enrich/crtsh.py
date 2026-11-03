"""
crt.sh client (async). Domains only. Keyless.

crt.sh is a search engine over Certificate Transparency logs: every publicly
trusted TLS certificate ever issued for a name. For a domain it tells you how
many certificates exist, which names they cover (which reveals subdomains),
who issued them, and when. That is context, not reputation, so the verdict is
always "unknown"; the summary is the value, and the names list is the seed for
Phase 6 pivoting.

Only unexpired certificates are requested (exclude=expired) to keep responses
small; crt.sh is a free, best-effort service that is often slow or returns
5xx, which simply shows as UNAVAILABLE. Docs: https://crt.sh/
"""

from ...core import cache
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from . import base
from .base import vendor_result

API_URL = "https://crt.sh/"
VENDOR = "crtsh"
CACHE_TTL = 12 * 3600
NOT_FOUND_TTL = 3600
MAX_NAMES = 15
MAX_ISSUERS = 5


def _params(domain: str) -> dict:
    # A plain identity search on crt.sh matches the name itself and its
    # subdomains, so "example.com" also finds www.example.com certificates.
    return {"q": domain, "output": "json", "exclude": "expired"}


def _summarise(rows: list) -> dict:
    rows = [r for r in rows if isinstance(r, dict)]
    if not rows:
        return {"verdict": "unknown", "ratio": None,
                "summary": {"note": "no unexpired certificates in CT logs"}}

    names: dict[str, None] = {}          # insertion-ordered set
    issuers: dict[str, None] = {}
    for r in rows:
        for n in (r.get("name_value") or "").split("\n"):
            n = n.strip().lower()
            if n:
                names.setdefault(n, None)
        if r.get("issuer_name"):
            issuers.setdefault(r["issuer_name"], None)

    not_before = sorted(r.get("not_before") for r in rows if r.get("not_before"))
    summary = {
        "certificates": len(rows),
        "names": list(names)[:MAX_NAMES],
        "names_total": len(names),
        "issuers": list(issuers)[:MAX_ISSUERS],
        "oldest_not_before": not_before[0] if not_before else None,
        "newest_not_before": not_before[-1] if not_before else None,
    }
    return {"verdict": "unknown", "ratio": f"{len(rows)} cert(s)", "summary": summary}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype != "domain":
        return base.failed(VENDOR, itype, value, "crt.sh handles domains only")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return base.quota(VENDOR, itype, value, str(exc))

    status, body, err = await base.fetch_json(
        "GET", API_URL, params=_params(value),
        headers={"Accept": "application/json"}, expect="list",
    )
    if err:
        return base.failed(VENDOR, itype, value, err)
    if status == 429:
        return base.quota(VENDOR, itype, value, "rate limited by crt.sh (429)")
    if status != 200:
        return base.failed(VENDOR, itype, value, f"HTTP {status} from crt.sh")

    parsed = _summarise(body or [])
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
    )
    ttl = CACHE_TTL if parsed["ratio"] else NOT_FOUND_TTL
    cache.put(VENDOR, cache_key, result.model_dump(), ttl)
    return result
