"""
Indicator handling: refang untrusted input and detect its type.

"Defanging" is the analyst habit of writing indicators so they are not
clickable or auto-linked, e.g. hxxp://evil[.]com. We refang on input (turn it
back into a real value) before detecting and looking it up.
"""

import ipaddress
import re

HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

# A reasonably strict domain matcher: labels of a-z/0-9/hyphen, at least one dot.
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def refang(value: str) -> str:
    s = value.strip()
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    s = s.replace("[:]", ":")
    s = re.sub(r"h(xx|XX)p", "http", s)
    s = s.replace("[@]", "@").replace("(@)", "@")
    s = s.replace("[://]", "://")
    return s


def hash_kind(value: str) -> str | None:
    for kind, pattern in HASH_PATTERNS.items():
        if pattern.match(value):
            return kind
    return None


def detect_type(value: str) -> str:
    """Return one of: hash, ip, url, domain, unknown. Expects a refanged value."""
    if hash_kind(value):
        return "hash"
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if value.lower().startswith(("http://", "https://")):
        return "url"
    if DOMAIN_PATTERN.match(value):
        return "domain"
    return "unknown"
