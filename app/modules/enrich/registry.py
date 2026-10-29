"""
Vendor registry and fan-out.

Maps each indicator type to the vendor clients that can look it up, and runs
them concurrently. Each client returns a VendorResult and never raises in
normal use; `enrich_all` still guards against an unexpected crash so one bad
client cannot take down the whole response.
"""

import asyncio

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
    "hash": [virustotal, otx, threatfox, malwarebazaar],
}


def vendors_for(itype: str) -> list:
    return VENDORS_BY_TYPE.get(itype, [])


async def enrich_all(itype: str, value: str) -> list[VendorResult]:
    """Run every applicable vendor concurrently and collect their results."""
    mods = vendors_for(itype)
    if not mods:
        return []

    results = await asyncio.gather(
        *(m.lookup(itype, value) for m in mods),
        return_exceptions=True,
    )

    out: list[VendorResult] = []
    for mod, res in zip(mods, results):
        if isinstance(res, BaseException):
            out.append(VendorResult(
                source=mod.VENDOR, indicator=value, indicator_type=itype,
                verdict="error", error=f"client crashed: {res}",
            ))
        else:
            out.append(res)
    return out
