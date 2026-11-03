"""
CIRCL hashlookup client (async). File hashes only. Keyless.

hashlookup.circl.lu is a database of KNOWN-GOOD files: hashes from NSRL,
Debian, Ubuntu, Microsoft, Apple and other vendor catalogues. It answers the
opposite question from VirusTotal: not "is this bad?" but "is this a file we
already know is legitimate?". A hit is therefore "clean" and carries the file
name and the catalogue it came from; a miss says nothing (plenty of good files
are not catalogued) and is "unknown".

The registry uses a hit as an allowlist gate: a known-good file is not sent to
the quota-costing vendors at all. Docs: https://hashlookup.circl.lu/
"""

from ...core import cache
from ...core.indicators import hash_kind
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from . import base
from .base import vendor_result

API_BASE = "https://hashlookup.circl.lu/lookup"
VENDOR = "hashlookup"
CACHE_TTL = 24 * 3600      # catalogue facts are stable; cache a day
NOT_FOUND_TTL = 6 * 3600

# hashlookup's own 0-100 trust score; 50 is its neutral default. Below this we
# still report the match but do not call the file clean.
MIN_TRUST = 50


def _summarise(body: dict) -> dict:
    """Interpret a hashlookup record (HTTP 200 body)."""
    trust = body.get("hashlookup:trust")
    known_malicious = body.get("KnownMalicious")
    source = body.get("source") or body.get("db")

    if known_malicious:
        verdict = "malicious"
    elif trust is None or trust >= MIN_TRUST:
        verdict = "clean"
    else:
        verdict = "unknown"

    summary = {
        "file_name": body.get("FileName"),
        "source": source,
        "trust": trust,
        "file_size": body.get("FileSize"),
        "mimetype": body.get("mimetype"),
        "known_malicious": known_malicious,
        "sha256": body.get("SHA-256"),
    }
    ratio = f"trust {trust}/100" if trust is not None else "known file"
    return {"verdict": verdict, "ratio": ratio, "summary": summary}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype != "hash":
        return base.failed(VENDOR, itype, value, "hashlookup handles file hashes only")
    kind = hash_kind(value)
    if kind is None:
        return base.failed(VENDOR, itype, value, "not an MD5, SHA1 or SHA256 hash")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return base.quota(VENDOR, itype, value, str(exc))

    headers = {"Accept": "application/json"}
    status, body, err = await base.fetch_json(
        "GET", f"{API_BASE}/{kind}/{value}", headers=headers
    )
    if err:
        return base.failed(VENDOR, itype, value, err)

    # 404 means "not a catalogued file": a normal answer, not an error.
    if status == 404:
        result = vendor_result(VENDOR, itype, value,
                               summary={"note": "not a known-good file in hashlookup"})
        cache.put(VENDOR, cache_key, result.model_dump(), NOT_FOUND_TTL)
        return result
    if status == 429:
        return base.quota(VENDOR, itype, value, "rate limited by hashlookup (429)")
    if status != 200:
        return base.failed(VENDOR, itype, value, f"HTTP {status} from hashlookup")

    parsed = _summarise(body or {})
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
    )
    cache.put(VENDOR, cache_key, result.model_dump(), CACHE_TTL)
    return result
