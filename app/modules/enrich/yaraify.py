"""
abuse.ch YARAify client (async). File hashes only.

YARAify scans uploaded files against public YARA rules (YARAhub) and ClamAV,
so a record means someone submitted the file and here is what matched. The
verdict follows the strength of the match:

- ClamAV detection -> malicious (a named AV signature).
- Only YARA matches -> suspicious (YARAhub rules are community rules and some
  are generic, e.g. "contains a PE overlay").
- Scanned, nothing matched -> unknown.
- No record -> unknown (absence from YARAify proves nothing).

Requires the abuse.ch Auth-Key. Docs: https://yaraify.abuse.ch/api/
"""

from ...core import cache
from ...core.config import settings
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from . import base
from .base import vendor_result

API_URL = "https://yaraify-api.abuse.ch/api/v1/"
VENDOR = "yaraify"
CACHE_TTL = 24 * 3600      # scan results are stable; cache a day
NOT_FOUND_TTL = 3600

_ERROR_STATUSES = {None, "illegal_hash", "illegal_search_term", "unknown_query", "no_api_key"}


def _rule_names(task: dict) -> list[str]:
    """YARA rule names from a task's static scan and from any unpacked files."""
    names = [m.get("rule_name") for m in task.get("static_results") or []]
    for unpacked in task.get("unpack_results") or []:
        names += [m.get("rule_name") for m in unpacked.get("unpacked_yara_matches") or []]
    return [n for n in names if n]


def _summarise(body: dict) -> dict:
    status = body.get("query_status")
    data = body.get("data") or {}

    if status == "ok" and data:
        meta = data.get("metadata") or {}
        tasks = data.get("tasks") or []
        clamav: list[str] = []
        yara: list[str] = []
        for t in tasks:
            clamav += [c for c in (t.get("clamav_results") or []) if c]
            yara += _rule_names(t)
        clamav = sorted(set(clamav))
        yara = sorted(set(yara))

        if clamav:
            verdict = "malicious"
        elif yara:
            verdict = "suspicious"
        else:
            verdict = "unknown"

        summary = {
            "file_name": next((t.get("file_name") for t in tasks if t.get("file_name")), None),
            "file_size": meta.get("file_size"),
            "mime_type": meta.get("file_type_mime"),
            "first_seen": meta.get("first_seen"),
            "last_seen": meta.get("last_seen"),
            "sightings": meta.get("sightings"),
            "clamav": clamav or None,
            "yara_rules": yara[:10] or None,
            "scans": len(tasks),
            "sha256": meta.get("sha256_hash"),
        }
        ratio = f"{len(clamav)} AV / {len(yara)} YARA match(es)"
        return {"verdict": verdict, "ratio": ratio, "summary": summary}

    if status in _ERROR_STATUSES:
        return {"verdict": "error", "ratio": None, "summary": {}, "error": f"YARAify: {status}"}

    # no_results (and any other "nothing here" wording abuse.ch may use).
    return {"verdict": "unknown", "ratio": None,
            "summary": {"note": f"not found in YARAify ({status})"}}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype != "hash":
        return base.failed(VENDOR, itype, value, "YARAify handles file hashes only")
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
    payload = {"query": "lookup_hash", "search_term": value}
    status, body, err = await base.fetch_json("POST", API_URL, headers=headers, json=payload)
    if err:
        return base.failed(VENDOR, itype, value, err)
    if status == 401:
        return base.failed(VENDOR, itype, value, "abuse.ch rejected the Auth-Key (401)")
    if status != 200:
        return base.failed(VENDOR, itype, value, f"HTTP {status} from YARAify")

    parsed = _summarise(body or {})
    if parsed["verdict"] == "error":
        return base.failed(VENDOR, itype, value, parsed.get("error") or "YARAify lookup failed")

    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
    )
    ttl = CACHE_TTL if parsed["verdict"] != "unknown" else NOT_FOUND_TTL
    cache.put(VENDOR, cache_key, result.model_dump(), ttl)
    return result
