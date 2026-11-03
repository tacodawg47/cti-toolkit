"""
RDAP client (async). Domains and IP addresses. Keyless.

RDAP is the official, structured replacement for WHOIS. For a domain it gives
the registrar, registration / expiry dates, nameservers and status; for an IP
it gives the allocating registry, the netblock and the abuse contact. None of
that is a reputation judgement, so the verdict is "unknown", with one
exception: a domain registered within the last NEW_DOMAIN_DAYS is nudged to
"suspicious", because very new domains are a cheap, strong phishing signal.

We query the rdap.org bootstrap service, which answers with a redirect to the
registry that actually holds the record (Verisign for .com, ARIN for a North
American IP, and so on), so this client follows redirects. Docs:
https://about.rdap.org/
"""

from datetime import datetime, timezone

from ...core import cache
from ...core.models import VendorResult
from ...core.ratelimit import QuotaExceeded, rate_limiter
from . import base
from .base import vendor_result

API_BASE = "https://rdap.org"
VENDOR = "rdap"
CACHE_TTL = 24 * 3600      # registration data changes slowly; cache a day
NOT_FOUND_TTL = 3600
NEW_DOMAIN_DAYS = 30


def _vcard_field(entity: dict, name: str) -> str | None:
    """Pull one field (e.g. "fn", "email") out of an RDAP entity's vCard.

    RDAP stores contact details as jCard: ["vcard", [[name, params, type,
    value], ...]]. We only ever need the first value of a named field.
    """
    card = entity.get("vcardArray") or []
    if len(card) < 2:
        return None
    for prop in card[1]:
        if len(prop) >= 4 and prop[0] == name:
            return prop[3] if isinstance(prop[3], str) else None
    return None


def _entities_with_role(body: dict, role: str) -> list[dict]:
    """All entities (including nested ones) that carry the given role."""
    found: list[dict] = []

    def walk(entities):
        for e in entities or []:
            if role in (e.get("roles") or []):
                found.append(e)
            walk(e.get("entities"))

    walk(body.get("entities"))
    return found


def _event_date(body: dict, action: str) -> str | None:
    for ev in body.get("events") or []:
        if ev.get("eventAction") == action:
            return ev.get("eventDate")
    return None


def _days_since(iso: str | None, now: datetime | None = None) -> int | None:
    if not iso:
        return None
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return (now - t).days


def _summarise_domain(body: dict, now: datetime | None = None) -> dict:
    registered = _event_date(body, "registration")
    age_days = _days_since(registered, now)
    registrars = _entities_with_role(body, "registrar")

    if age_days is not None and age_days < NEW_DOMAIN_DAYS:
        verdict, confidence = "suspicious", 0.4     # a cheap lead, not proof
    else:
        verdict, confidence = "unknown", 0.0

    summary = {
        "registered": registered,
        "age_days": age_days,
        "expires": _event_date(body, "expiration"),
        "last_changed": _event_date(body, "last changed"),
        "registrar": _vcard_field(registrars[0], "fn") if registrars else None,
        "nameservers": [ns.get("ldhName") for ns in body.get("nameservers") or []] or None,
        "status": body.get("status") or None,
    }
    ratio = f"registered {age_days} day(s) ago" if age_days is not None else None
    return {"verdict": verdict, "confidence": confidence, "ratio": ratio, "summary": summary}


def _summarise_ip(body: dict) -> dict:
    abuse = _entities_with_role(body, "abuse")
    summary = {
        "netblock": f"{body.get('startAddress')} - {body.get('endAddress')}"
                    if body.get("startAddress") else None,
        "net_name": body.get("name"),
        "handle": body.get("handle"),
        "type": body.get("type"),
        "country": body.get("country"),
        "abuse_contact": _vcard_field(abuse[0], "email") if abuse else None,
        "registry": body.get("port43"),      # the WHOIS host, which names the RIR
    }
    return {"verdict": "unknown", "confidence": 0.0, "ratio": None, "summary": summary}


async def lookup(itype: str, value: str) -> VendorResult:
    if itype == "domain":
        path, summarise = f"/domain/{value}", _summarise_domain
    elif itype == "ip":
        path, summarise = f"/ip/{value}", _summarise_ip
    else:
        return base.failed(VENDOR, itype, value, f"RDAP does not handle type: {itype}")

    cache_key = f"{itype}:{value}"
    hit = cache.get(VENDOR, cache_key)
    if hit is not None:
        return VendorResult(**{**hit, "cached": True})

    try:
        await rate_limiter.acquire(VENDOR)
    except QuotaExceeded as exc:
        return base.quota(VENDOR, itype, value, str(exc))

    headers = {"Accept": "application/rdap+json, application/json"}
    status, body, err = await base.fetch_json(
        "GET", f"{API_BASE}{path}", headers=headers, follow_redirects=True
    )
    if err:
        return base.failed(VENDOR, itype, value, err)

    # 404: no record (unregistered domain, or a TLD / range with no RDAP server).
    if status == 404:
        result = vendor_result(VENDOR, itype, value,
                               summary={"note": "no RDAP record (unregistered, or no RDAP server for it)"})
        cache.put(VENDOR, cache_key, result.model_dump(), NOT_FOUND_TTL)
        return result
    if status == 429:
        return base.quota(VENDOR, itype, value, "rate limited by RDAP (429)")
    if status != 200:
        return base.failed(VENDOR, itype, value, f"HTTP {status} from RDAP")

    parsed = summarise(body or {})
    result = vendor_result(
        VENDOR, itype, value,
        verdict=parsed["verdict"],
        confidence=parsed["confidence"],
        detection_ratio=parsed["ratio"],
        summary=parsed["summary"],
    )
    cache.put(VENDOR, cache_key, result.model_dump(), CACHE_TTL)
    return result
