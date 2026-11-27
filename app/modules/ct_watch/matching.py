"""Pure exact matching. No suffix database, fuzzy matching or network calls."""

import ipaddress
from hashlib import sha256
import json
from pathlib import Path

import idna

PATTERNS = json.loads(Path(__file__).with_name("patterns-v1.json").read_text(encoding="utf-8"))
PATTERN_VERSION = PATTERNS["version"]
PATTERN_SHA256 = sha256(json.dumps(PATTERNS, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
MATCHER_VERSION = "1"


def hostname(value, *, wildcard=False, label=False):
    """Canonical IDNA2008 spelling, keeping wildcard scope explicit.

    Do not refang, strip URLs/ports, repair whitespace or map confusables.
    A wildcard asserts a pattern; it never establishes its base or a live host.
    """
    if not isinstance(value, str) or not 1 <= len(value) <= 254 or value != value.strip():
        raise ValueError("Use a bounded DNS name")
    if any(dot in value for dot in ("\u3002", "\uff0e", "\uff61")):
        raise ValueError("Use literal ASCII label separators")
    star = value.startswith("*.")
    if star:
        if not wildcard:
            raise ValueError("A seed cannot contain a wildcard")
        value = value[2:]
    value = value.removesuffix(".").lower()
    if value.endswith("."):
        raise ValueError("Empty DNS label")
    try:
        ascii_name = idna.encode(value, uts46=False, std3_rules=True).decode("ascii")
        ipaddress.ip_address(ascii_name)
    except idna.IDNAError as exc:
        raise ValueError("Invalid IDN or DNS name") from exc
    except ValueError:
        pass
    else:
        raise ValueError("IP certificates are outside this consumer")
    if len(ascii_name) > 253 or (label and "." in ascii_name) or (not label and "." not in ascii_name):
        raise ValueError("Use an explicit domain or one label as appropriate")
    if label and (len(ascii_name) < 3 or ascii_name.isdigit()):
        raise ValueError("Watch labels require at least three characters")
    return ("*." if star else "") + ascii_name


def seed(value, kind):
    if kind not in ("domain", "organization", "brand"):
        raise ValueError("Use domain, organization or brand")
    # Organization/brand seeds are explicit DNS tokens, never inferred from a
    # legal entity name or from a domain's apparent registrable component.
    return hostname(value, label=kind != "domain")


def contains_sequence(parts, wanted):
    return any(parts[i:i+len(wanted)] == wanted for i in range(len(parts)-len(wanted)+1))


def match(value, kind, candidate):
    value = seed(value, kind)
    candidate = hostname(candidate, wildcard=True)
    labels = candidate.removeprefix("*.").split(".")
    # Punycode's xn-- prefix is an encoding, not hyphen-separated brand text.
    tokens = {part for item in labels if not item.startswith("xn--") for part in item.split("-")}
    reasons = []
    if kind == "domain":
        wanted = value.split(".")
        if contains_sequence(labels, wanted):
            reasons.append("exact-domain")
    elif value in labels:
        reasons.append("exact-label")
    elif not value.startswith("xn--"):
        wanted = value.split("-")
        for item in labels:
            if not item.startswith("xn--") and contains_sequence(item.split("-"), wanted):
                reasons.append("hyphen-token")
                break
    if not reasons:
        return None
    themes = sorted(group["name"] for group in PATTERNS["groups"] if tokens.intersection(group["tokens"]))
    return {"rules": reasons, "themes": themes, "pattern_version": PATTERN_VERSION,
            "pattern_sha256": PATTERN_SHA256, "matcher_version": MATCHER_VERSION,
            "wildcard": candidate.startswith("*.")}
