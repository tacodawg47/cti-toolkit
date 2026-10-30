"""
Indicator handling: refang untrusted input, normalise it, and detect its type.

"Defanging" is the analyst habit of writing indicators so they are not
clickable or auto-linked, e.g. hxxp://evil[.]com or evil[dot]com. We refang on
input (turn it back into a real value), normalise it (strip wrappers, drop a
port, lowercase where case is irrelevant), and then detect the type before
looking it up.
"""

import ipaddress
import re

MAX_INDICATOR_LEN = 2048       # reject anything longer with a friendly message

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

# Literal defang substitutions applied after the regex ones below.
_REPLACEMENTS = (
    ("[.]", "."), ("(.)", "."), ("{.}", "."), ("\\.", "."),
    ("[:]", ":"), ("[://]", "://"), ("[/]", "/"),
    ("[@]", "@"), ("(@)", "@"), ("[at]", "@"),
)


def refang(value: str) -> str:
    """Turn defanged input back into a real indicator."""
    s = value.strip().strip("'\"<>`")
    # Scheme obfuscation: hxxp/hXXp -> http, fxp -> ftp. Only at the very
    # start of the input and only when a scheme separator follows ("://",
    # "[:]//" or "[://]"), so that legitimate indicators containing those
    # letters (fxp-trading.com, /fxp/report, shxxp.example.com) are untouched.
    s = re.sub(r"^h[xX]{2}p(?=s?(://|\[:\]|\[://\]))", "http", s)
    s = re.sub(r"^f[xX]p(?=(://|\[:\]|\[://\]))", "ftp", s)
    # Bracketed or spelled-out "dot": [dot] (dot) {dot} and "evil dot com".
    s = re.sub(r"[\[\(\{]\s*\.?\s*dot\s*\.?\s*[\]\)\}]", ".", s, flags=re.IGNORECASE)
    s = re.sub(r"(?<=\w)\s+dot\s+(?=\w)", ".", s, flags=re.IGNORECASE)
    for a, b in _REPLACEMENTS:
        s = s.replace(a, b)
    return s


def normalise(raw: str) -> str:
    """Refang, then tidy: drop a trailing dot and an IPv4 :port suffix."""
    s = refang(raw).rstrip(".")
    # "1.2.3.4:443" -> "1.2.3.4" (a bare host:port, not a URL). The port is not
    # part of the indicator we look up.
    if ":" in s and "://" not in s:
        host, _, port = s.rpartition(":")
        if port.isdigit():
            try:
                ipaddress.ip_address(host)
                s = host
            except ValueError:
                pass
    return s


def canonical(itype: str, value: str) -> str:
    """Lowercase where case carries no meaning, so the cache stores one entry.

    Hashes (hex) and domains (DNS is case-insensitive) are lowercased; URLs are
    left as-is because their paths are case-sensitive.
    """
    if itype in ("hash", "domain"):
        return value.lower()
    return value


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
    # The final label of a domain (the TLD) is never all digits; this keeps
    # "1.2.3" from being mistaken for a domain.
    if DOMAIN_PATTERN.match(value) and not value.rsplit(".", 1)[-1].isdigit():
        return "domain"
    return "unknown"
