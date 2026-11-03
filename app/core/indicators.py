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
from urllib.parse import urlsplit, urlunsplit

import idna

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


def _is_host(value: str) -> bool:
    """True if value is an IP address or a domain name (no port, no scheme)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(DOMAIN_PATTERN.match(value)) and not value.rsplit(".", 1)[-1].isdigit()


def _strip_port(s: str) -> str:
    """Drop a :port suffix from a bare host, leaving URLs and plain IPv6 alone.

    "1.2.3.4:443" -> "1.2.3.4", "evil.com:8443" -> "evil.com", and the
    bracketed IPv6 form "[2001:db8::1]:443" -> "2001:db8::1". A plain IPv6
    address like "2001:db8::1" also contains colons but is not host:port, so it
    is only changed if what is left after the last colon is a valid port and
    what is before it is a valid host (which a truncated IPv6 never is).
    """
    if "://" in s or ":" not in s:
        return s
    host, _, port = s.rpartition(":")
    if not (port.isdigit() and 0 < int(port) <= 65535):
        return s
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host if _is_host(host) else s


def _punycode_host(host: str) -> str:
    """Convert an internationalised host name to its ASCII (punycode) form.

    DNS only carries ASCII, so "münchen.de" is really "xn--mnchen-3ya.de", and
    a homograph like "gооgle.com" (Cyrillic o's) becomes "xn--ggle-55da.com",
    which both exposes the trick and lets every vendor look it up. ASCII input
    is returned unchanged; anything idna cannot encode is returned unchanged
    too, and detect_type will then call it unknown.
    """
    if host.isascii():
        return host
    try:
        return idna.encode(host, uts46=True).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        return host


def _punycode(s: str) -> str:
    """Apply _punycode_host to a bare host, or to the host part of a URL."""
    if s.isascii():
        return s
    if "://" not in s:
        return _punycode_host(s)
    try:
        parts = urlsplit(s)
    except ValueError:
        return s
    host = parts.hostname
    if not host or host.isascii():
        return s
    ascii_host = _punycode_host(host)
    # Rebuild netloc keeping any user:pass@ and :port exactly as they were.
    userinfo, _, hostport = parts.netloc.rpartition("@")
    port = f":{parts.port}" if parts.port else ""
    netloc = (userinfo + "@" if userinfo else "") + ascii_host + port
    return urlunsplit(parts._replace(netloc=netloc))


def normalise(raw: str) -> str:
    """Refang, then tidy: drop a trailing dot and a :port suffix on a bare host,
    and put any non-ASCII host name into punycode.

    C2 reports and ThreatFox entries are often written as host:port; the port is
    not part of the indicator we look up, so it is dropped here (the UI shows
    the cleaned value so the analyst can see what was looked up).
    """
    return _punycode(_strip_port(refang(raw).rstrip(".")))


def canonical(itype: str, value: str) -> str:
    """One spelling per indicator, so the cache stores one entry.

    Hashes (hex) and domains (DNS is case-insensitive) are lowercased. IPs are
    rewritten in Python's compressed form, so "2001:DB8::1", "2001:db8:0::1"
    and "2001:0db8::0001" all become "2001:db8::1" (IPv4 is unchanged). URLs
    are left as-is because their paths are case-sensitive.
    """
    if itype in ("hash", "domain"):
        return value.lower()
    if itype == "ip":
        return str(ipaddress.ip_address(value))
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
    # _is_host also rejects an all-digit final label (the TLD is never all
    # digits), which keeps "1.2.3" from being mistaken for a domain.
    if _is_host(value):
        return "domain"
    return "unknown"
