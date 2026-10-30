"""
Vendor registry and fan-out.

Maps each indicator type to the vendor clients that can look it up, and runs
them concurrently. Each client returns a VendorResult and never raises in
normal use; `enrich_all` still guards against an unexpected crash so one bad
client cannot take down the whole response.
"""

import asyncio
import ipaddress

from ...core.models import VendorResult
from . import (
    abuseipdb,
    greynoise,
    malwarebazaar,
    otx,
    shodan,
    threatfox,
    urlhaus,
    urlscan,
    virustotal,
)

# Which vendor modules apply to each indicator type. Order here is the order
# results are shown. Each module exposes VENDOR and async lookup(itype, value).
VENDORS_BY_TYPE: dict[str, list] = {
    "ip": [virustotal, abuseipdb, greynoise, otx, threatfox, urlhaus, shodan],
    "domain": [virustotal, otx, threatfox, urlhaus, urlscan],
    "url": [virustotal, otx, threatfox, urlhaus, urlscan],
    "hash": [virustotal, otx, threatfox, malwarebazaar, urlhaus],
}

# Highest-to-lowest severity, for the aggregate worst-of line.
_SEVERITY = {"malicious": 3, "suspicious": 2, "clean": 1, "unknown": 0}


def vendors_for(itype: str) -> list:
    return VENDORS_BY_TYPE.get(itype, [])


def aggregate_verdict(results: list[VendorResult]) -> dict | None:
    """Worst verdict across vendors that actually answered, and who said it.

    Lets the analyst read one line instead of scanning every card. Vendors that
    are not configured, quota-limited, or errored are ignored.
    """
    best_sev = -1
    best_verdict = None
    sources: list[str] = []
    for r in results:
        if r.status != "ok":
            continue
        sev = _SEVERITY.get(r.verdict, 0)
        if sev > best_sev:
            best_sev, best_verdict, sources = sev, r.verdict, [r.source]
        elif sev == best_sev:
            sources.append(r.source)
    if best_verdict is None:
        return None
    return {"verdict": best_verdict, "sources": sources}


def _non_global_ip_note(value: str) -> VendorResult | None:
    """Return one informational result for a private/reserved IP, else None."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.is_global:
        return None
    kind = ("loopback" if ip.is_loopback else
            "link-local" if ip.is_link_local else
            "multicast" if ip.is_multicast else
            "private" if ip.is_private else
            "reserved")
    return VendorResult(
        source="(local)", indicator=value, indicator_type="ip",
        verdict="unknown",
        summary={"note": f"{kind} address — not sent to external vendors"},
    )


async def enrich_all(itype: str, value: str) -> list[VendorResult]:
    """Run every applicable vendor concurrently and collect their results."""
    mods = vendors_for(itype)
    if not mods:
        return []

    # Don't fan private / reserved / loopback IPs out to external vendors: the
    # answer is meaningless and it wastes quota (GreyNoise is ~10 lookups/day).
    if itype == "ip":
        gate = _non_global_ip_note(value)
        if gate is not None:
            return [gate]

    results = await asyncio.gather(
        *(m.lookup(itype, value) for m in mods),
        return_exceptions=True,
    )

    out: list[VendorResult] = []
    for mod, res in zip(mods, results):
        if isinstance(res, BaseException):
            out.append(VendorResult(
                source=mod.VENDOR, indicator=value, indicator_type=itype,
                verdict="error", error=f"client crashed: {type(res).__name__}",
            ))
        else:
            out.append(res)
    return out
