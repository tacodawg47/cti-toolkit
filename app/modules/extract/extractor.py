"""
Find indicators in a block of text.

How it works, in two passes:

1. `refang_text` turns every defanged spelling in the WHOLE document back
   into its real form (hxxps://evil[.]com -> https://evil.com), using the same
   substitutions as app.core.indicators.refang but applied document-wide
   rather than to one value. Working on refanged text means one plain pattern
   per indicator type, instead of a defang-aware pattern for every bracket
   style an author might invent.
2. One regular expression per type runs over the refanged text. Every hit is
   validated (an IPv4 candidate must parse, a domain's last label must not be
   a file extension, a URL must have a host), put into its canonical spelling
   via app.core.indicators.canonical, and de-duplicated with a count.

An indicator is marked `defanged` when its canonical spelling never appears
in the original text, i.e. the author only ever wrote it in a defanged form.
That is usually the strongest hint that the author meant it as an IOC rather
than as a reference link.

Known limits, on purpose:
- A version number like "1.2.3.4" is indistinguishable from an IPv4 address
  by shape; it is extracted and the analyst discards it.
- Domains are validated by shape and a file-extension denylist, not against
  the IANA TLD list, so an unusual filename can slip through as a domain.
- Registry keys, file paths, mutexes and wallet addresses are not extracted.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from ...core.allowlist import allowlist
from ...core.indicators import canonical, hash_kind

# Longer inputs are cut here before extraction. Vendor reports are tens of
# kilobytes; two million characters is a generous cap that keeps a stray
# upload from pinning the CPU in regex work.
MAX_TEXT_CHARS = 2_000_000

# Display order on the results page.
TYPE_ORDER = ("ip", "domain", "url", "hash", "email", "cve")


class Extracted(BaseModel):
    type: str                       # ip | domain | url | hash | email | cve
    value: str                      # refanged, canonical spelling
    count: int = 1                  # occurrences in the text (any spelling)
    defanged: bool = False          # never seen in plain form
    note: str | None = None         # "md5", "private", "host of a URL", ...
    popular_rank: int | None = None  # Tranco rank when the host is a top site


class Extraction(BaseModel):
    items: list[Extracted] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)   # per type
    chars: int = 0                  # characters examined
    truncated: bool = False         # input was cut at MAX_TEXT_CHARS

    def by_type(self, itype: str) -> list[Extracted]:
        return [i for i in self.items if i.type == itype]


# --- pass 1: refang the whole document -------------------------------------

# Scheme obfuscation anywhere in the text, but only when a scheme separator
# follows, so "shxxp.example.com" or a word like "fxp-trading" is untouched.
_HXXP = re.compile(r"\bhxxp(?=s?(?:://|\[:\]|\[://\]))", re.IGNORECASE)
_FXP = re.compile(r"\bfxp(?=(?:://|\[:\]|\[://\]))", re.IGNORECASE)
# Bracketed or spelled-out dots: [dot] (dot) {dot} and "evil dot com".
_DOT_BRACKETED = re.compile(r"[\[\(\{]\s*\.?\s*dot\s*\.?\s*[\]\)\}]", re.IGNORECASE)
_DOT_SPACED = re.compile(r"(?<=\w)\s+dot\s+(?=\w)", re.IGNORECASE)
# Same literal substitutions as indicators.refang, plus the "(at)" family.
_REPLACEMENTS = (
    ("[.]", "."), ("(.)", "."), ("{.}", "."), ("\\.", "."),
    ("[:]", ":"), ("[://]", "://"), ("[/]", "/"),
    ("[@]", "@"), ("(@)", "@"), ("{@}", "@"),
    ("[at]", "@"), ("(at)", "@"), ("{at}", "@"),
)


def refang_text(text: str) -> str:
    """Undo every defanging convention we know, across a whole document."""
    s = _HXXP.sub("http", text)
    s = _FXP.sub("ftp", s)
    s = _DOT_BRACKETED.sub(".", s)
    s = _DOT_SPACED.sub(".", s)
    for a, b in _REPLACEMENTS:
        s = s.replace(a, b)
    return s


# --- pass 2: patterns over the refanged text --------------------------------

# A URL: scheme, then everything up to whitespace or a quote/angle bracket.
# Trailing punctuation that belongs to the sentence is trimmed afterwards.
_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`]+", re.IGNORECASE)

# user@host.tld. The host part is validated like a domain below.
_EMAIL = re.compile(r"\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,63}\b", re.IGNORECASE)

# IPv4 by shape (each octet checked by ipaddress afterwards). A trailing
# sentence dot is allowed ("...at 1.2.3.4.") but a fifth octet is not.
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)")

# IPv6 is hard to describe exactly in a regex (the "::" compression has
# many legal placements), so this only finds candidates: runs of hex digits
# and colons that are not glued to other word characters. ipaddress then
# decides. Times ("12:30:45") and MAC addresses fail that check.
_IPV6 = re.compile(r"(?<![\w:.])[0-9a-f:]{3,39}(?![\w:])", re.IGNORECASE)

# Domain: dotted labels, last label alphabetic (or punycode). The lookbehind
# keeps the match from starting in the middle of a longer host, after an "@"
# (email hosts are listed with the email) or after "/" (URL hosts are added
# separately from the URL itself, see _add_url_host).
_DOMAIN = re.compile(
    r"(?<![\w.@/-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})(?![\w-])",
    re.IGNORECASE,
)

# A run of exactly 32, 40 or 64 hex characters, not part of a longer run.
_HASH = re.compile(r"(?<![a-f0-9])(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![a-f0-9])",
                   re.IGNORECASE)

_CVE = re.compile(r"(?<![\w-])cve-\d{4}-\d{4,7}(?!\d)", re.IGNORECASE)

# Last labels that are file extensions, not top-level domains. A match whose
# final label is here is a filename ("payload.exe"), not a domain. Most of
# these are not real TLDs at all; the few that are (sh, py, pl, md, rs) are
# real but appear in threat reports as file extensions almost every time,
# so they are excluded too and noted in the runbook.
_FILE_EXTENSIONS = frozenset("""
exe dll sys scr pif cpl msi msp cab jar war class apk ipa dmg pkg deb rpm
elf bin dat tmp bak old log txt rtf doc docx dot dotm docm xls xlsx xlsm
ppt pptx pps ppsx pdf odt ods odp csv tsv json xml yml yaml toml ini cfg
conf html htm xhtml js mjs css ps1 psm1 vbs vbe wsf hta bat cmd lnk url
reg py pl sh rs md jpg jpeg png gif bmp svg ico webp tif tiff mp3 mp4 avi
mov wav zipx rar 7z gz tgz bz2 xz tar iso img vhd vhdx vmdk ova ovf
pyc pyd so dylib lib obj dex odex eml msg ics vcf pst ost db sqlite
""".split())


def _is_filename(host: str) -> bool:
    return host.rsplit(".", 1)[-1].lower() in _FILE_EXTENSIONS


def _trim_url(url: str) -> str:
    """Drop sentence punctuation that the greedy URL pattern swallowed.

    "(see https://evil.com/a)." -> "https://evil.com/a". A closing bracket is
    only dropped when it has no opening partner inside the URL, so
    "https://en.wikipedia.org/wiki/Foo_(bar)" survives.
    """
    pairs = {")": "(", "]": "[", "}": "{"}
    while url:
        last = url[-1]
        if last in ".,;:!?'\"":
            url = url[:-1]
        elif last in pairs and url.count(pairs[last]) < url.count(last):
            url = url[:-1]
        else:
            break
    return url


# RFC 5737 / RFC 3849 ranges reserved for documentation. Sanitised reports
# use them in place of real addresses, so they deserve their own tag rather
# than "private".
_DOCUMENTATION = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def _ip_note(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if ip.is_global:
        return None
    if any(ip in net for net in _DOCUMENTATION):
        return "documentation"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_private:
        return "private"
    return "reserved"


class _Collector:
    """Accumulates hits, de-duplicating on (type, canonical value)."""

    def __init__(self, original_lower: str) -> None:
        self._orig = original_lower
        self._seen: dict[tuple[str, str], Extracted] = {}
        self._pos: dict[tuple[str, str], int] = {}     # first position seen

    def add(self, itype: str, value: str, raw: str, pos: int,
            note: str | None = None, popular_rank: int | None = None) -> None:
        """Record one hit. `raw` is the text as matched in the refanged
        document; if that exact spelling is absent from the original, the
        author only wrote it defanged. `pos` is where the match starts, so
        the results page can list each type in text order even though the
        type passes run one after another."""
        key = (itype, value)
        hit = self._seen.get(key)
        if hit is not None:
            hit.count += 1
            if hit.defanged and raw.lower() in self._orig:
                hit.defanged = False
            self._pos[key] = min(self._pos[key], pos)
            return
        self._seen[key] = Extracted(
            type=itype, value=value, note=note, popular_rank=popular_rank,
            defanged=raw.lower() not in self._orig,
        )
        self._pos[key] = pos

    def items(self) -> list[Extracted]:
        order = {t: i for i, t in enumerate(TYPE_ORDER)}
        return sorted(self._seen.values(),
                      key=lambda e: (order.get(e.type, 99), self._pos[(e.type, e.value)]))


def _add_host(col: _Collector, host: str, pos: int, note: str | None) -> None:
    """Add a URL's host as an ip or domain entry."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if _is_filename(host) or not _DOMAIN.fullmatch(host):
            return
        domain = canonical("domain", host)
        col.add("domain", domain, host, pos, note=note, popular_rank=allowlist.rank(domain))
        return
    col.add("ip", str(ip), host, pos, note=_ip_note(ip) or note)


def extract(text: str) -> Extraction:
    """Extract every indicator from `text`. Never raises on odd input."""
    truncated = len(text) > MAX_TEXT_CHARS
    if truncated:
        text = text[:MAX_TEXT_CHARS]
    refanged = refang_text(text)
    col = _Collector(text.lower())

    for m in _CVE.finditer(refanged):
        col.add("cve", canonical("cve", m.group(0)), m.group(0), m.start())

    for m in _HASH.finditer(refanged):
        value = canonical("hash", m.group(0))
        col.add("hash", value, m.group(0), m.start(), note=hash_kind(value))

    for m in _URL.finditer(refanged):
        url = _trim_url(m.group(0))
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if not host:
            continue
        col.add("url", url, url, m.start(), popular_rank=allowlist.rank(host))
        _add_host(col, host, m.start(), note="host of a URL")

    for m in _EMAIL.finditer(refanged):
        email = m.group(0).lower()
        if _is_filename(email.rsplit("@", 1)[1]):
            continue
        col.add("email", email, m.group(0), m.start())

    for m in _IPV4.finditer(refanged):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue                     # an octet over 255: not an address
        col.add("ip", str(ip), m.group(0), m.start(), note=_ip_note(ip))

    for m in _IPV6.finditer(refanged):
        cand = m.group(0)
        if cand.count(":") < 2 or not any(c.isalnum() for c in cand):
            continue
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if ip.version != 6:
            continue
        col.add("ip", str(ip), cand, m.start(), note=_ip_note(ip))

    for m in _DOMAIN.finditer(refanged):
        host = m.group(0)
        if _is_filename(host):
            continue
        domain = canonical("domain", host)
        col.add("domain", domain, host, m.start(), popular_rank=allowlist.rank(domain))

    items = col.items()
    counts: dict[str, int] = {}
    for item in items:
        counts[item.type] = counts.get(item.type, 0) + 1
    return Extraction(items=items, counts=counts, chars=len(text), truncated=truncated)


def plain_list(items: list[Extracted]) -> str:
    """One value per line, for copy-paste into another tool."""
    return "\n".join(i.value for i in items)
