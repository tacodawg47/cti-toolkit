"""
Vendor registry and fan-out.

Maps each indicator type to the vendor clients that can look it up, and runs
them concurrently. Each client returns a VendorResult and never raises in
normal use; `enrich_all` still guards against an unexpected crash so one bad
client cannot take down the whole response.
"""

import asyncio
import ipaddress
from urllib.parse import urlsplit

from ...core.allowlist import allowlist
from ...core.models import VendorResult
from . import (
    abuseipdb,
    crtsh,
    greynoise,
    hashlookup,
    internetdb,
    malwarebazaar,
    otx,
    rdap,
    shodan,
    threatfox,
    urlhaus,
    urlscan,
    virustotal,
    yaraify,
)

# Which vendor modules apply to each indicator type. Order here is the order
# results are shown. Each module exposes VENDOR and async lookup(itype, value).
# Keyless sources (internetdb, rdap, hashlookup, crtsh) sit alongside the
# keyed ones.
VENDORS_BY_TYPE: dict[str, list] = {
    "ip": [virustotal, abuseipdb, greynoise, otx, threatfox, urlhaus, internetdb, shodan, rdap],
    "domain": [virustotal, otx, threatfox, urlhaus, urlscan, rdap, crtsh],
    "url": [virustotal, otx, threatfox, urlhaus, urlscan],
    "hash": [virustotal, otx, threatfox, malwarebazaar, urlhaus, yaraify],
}

# Runs BEFORE the hash fan-out. If CIRCL hashlookup says the file is a known
# catalogued good file (an OS or vendor binary), the quota-costing vendors are
# skipped: the answer would be "clean" anyway, and this is the allowlist gate
# from the roadmap. A miss just adds the hashlookup card to the normal fan-out.
HASH_GATE = hashlookup

# Source name of the informational card we return instead of fanning out
# (private / reserved IPs). It is not a vendor answer, so the aggregate line
# ignores it rather than scoring it.
LOCAL_SOURCE = "(local)"

# A verdict as a number on a -1 (clean) .. +1 (malicious) axis. "unknown" and
# "error" are not here on purpose: they abstain instead of voting.
_VOTE = {"malicious": 1.0, "suspicious": 0.5, "clean": -1.0}

# Risk score (0-10) thresholds for the Overall label. Between CLEAN and
# SUSPICIOUS the evidence genuinely conflicts, and the line says so.
MALICIOUS_AT = 7.5
SUSPICIOUS_AT = 5.5
CLEAN_AT = 3.0


def vendors_for(itype: str) -> list:
    return VENDORS_BY_TYPE.get(itype, [])


def aggregate_verdict(results: list[VendorResult]) -> dict | None:
    """One Overall line from many cards: a confidence-weighted risk score.

    Each vendor that gave a real opinion votes malicious (+1), suspicious
    (+0.5) or clean (-1); "unknown", errors, quota and not-configured cards
    abstain. Each vote is weighted by the vendor's own `confidence`, so one
    VirusTotal engine out of 92 (0.3) cannot outvote an OTX whitelist entry
    (0.9), while a ThreatFox C2 hit (1.0) is never diluted by a crowd of
    "unknown". The weighted mean, -1..+1, is shown as 0..10:

        risk = (sum(confidence * vote) / sum(confidence) + 1) * 5

    Returns None when nobody voted, else a dict with the score, the label,
    the voters grouped by verdict, and how many cards abstained.
    """
    weighted = 0.0
    weight = 0.0
    by_verdict: dict[str, list[str]] = {"malicious": [], "suspicious": [], "clean": []}
    abstained = 0
    for r in results:
        if r.source == LOCAL_SOURCE:
            continue
        vote = _VOTE.get(r.verdict)
        if r.status != "ok" or vote is None or r.confidence <= 0:
            abstained += 1
            continue
        weighted += r.confidence * vote
        weight += r.confidence
        by_verdict[r.verdict].append(r.source)

    if weight == 0:
        return None

    score = round((weighted / weight + 1) * 5, 1)
    if score >= MALICIOUS_AT:
        label = "malicious"
    elif score >= SUSPICIOUS_AT:
        label = "suspicious"
    elif score <= CLEAN_AT:
        label = "clean"
    else:
        label = "inconclusive"
    return {
        "score": score,
        "label": label,
        "malicious": by_verdict["malicious"],
        "suspicious": by_verdict["suspicious"],
        "clean": by_verdict["clean"],
        "abstained": abstained,
    }


def _local_note(itype: str, value: str, note: str) -> VendorResult:
    """An informational card from the toolkit itself (not a vendor answer)."""
    return VendorResult(
        source=LOCAL_SOURCE, indicator=value, indicator_type=itype,
        verdict="unknown", summary={"note": note},
    )


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
    return _local_note("ip", value, f"{kind} address — not sent to external vendors")


def _host_of(itype: str, value: str) -> str | None:
    """The hostname an allowlist check applies to: the domain itself, or the
    host part of a URL. None for other types."""
    if itype == "domain":
        return value
    if itype == "url":
        try:
            return urlsplit(value).hostname
        except ValueError:
            return None
    return None


def _tranco_note(itype: str, value: str) -> VendorResult | None:
    """One informational result if the host is in the loaded Tranco top list."""
    host = _host_of(itype, value)
    if not host:
        return None
    rank = allowlist.rank(host)
    if rank is None:
        return None
    return _local_note(
        itype, value,
        f"{host} is #{rank} in the Tranco top {allowlist.top_n:,} — vendors skipped "
        "to save quota (tick \"query anyway\" to override)",
    )


async def enrich_all(itype: str, value: str, force: bool = False) -> list[VendorResult]:
    """Run every applicable vendor concurrently and collect their results.

    `force=True` bypasses the two allowlist gates (Tranco, CIRCL hashlookup)
    and queries every vendor anyway. The private-IP gate is never bypassed:
    nobody outside can say anything useful about 192.168.1.1.
    """
    mods = vendors_for(itype)
    if not mods:
        return []

    # Don't fan private / reserved / loopback IPs out to external vendors: the
    # answer is meaningless and it wastes quota (GreyNoise is ~10 lookups/day).
    if itype == "ip":
        gate = _non_global_ip_note(value)
        if gate is not None:
            return [gate]

    # Popular-site gate for domains and URLs (Tranco, if the list is loaded).
    if not force:
        gate = _tranco_note(itype, value)
        if gate is not None:
            return [gate]

    # Known-good file gate for hashes (see HASH_GATE above). Its card is shown
    # first either way.
    lead: list[VendorResult] = []
    if itype == "hash":
        try:
            known = await HASH_GATE.lookup(itype, value)
        except Exception as exc:          # same guard as the fan-out below
            known = VendorResult(
                source=HASH_GATE.VENDOR, indicator=value, indicator_type=itype,
                status="error", verdict="error",
                error=f"client crashed: {type(exc).__name__}",
            )
        lead.append(known)
        if known.status == "ok" and known.verdict == "clean" and not force:
            lead.append(_local_note(
                itype, value,
                "known-good file per CIRCL hashlookup — other vendors skipped to save "
                "quota (tick \"query anyway\" to override)",
            ))
            return lead

    results = await asyncio.gather(
        *(m.lookup(itype, value) for m in mods),
        return_exceptions=True,
    )

    out: list[VendorResult] = list(lead)
    for mod, res in zip(mods, results):
        if isinstance(res, BaseException):
            out.append(VendorResult(
                source=mod.VENDOR, indicator=value, indicator_type=itype,
                status="error", verdict="error",
                error=f"client crashed: {type(res).__name__}",
            ))
        else:
            out.append(res)
    return out
