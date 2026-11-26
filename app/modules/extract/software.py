"""Explicit extension references in report prose, with no provider requests.

Do not guess from bare hashes, dotted names, AMO slugs or moz-extension
runtime UUIDs. Those shapes do not establish a stable extension identity.
"""

import re
from urllib.parse import parse_qs, urlencode, urlsplit

MAX_REFERENCES = 200
_CHROME_ID = r"[a-p]{32}"
_VSCODE_ID = r"[a-z0-9][a-z0-9_-]{0,127}\.[a-z0-9][a-z0-9_-]{0,127}"
_FIREFOX_ID = (r"\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}"
               r"|[a-z0-9._-]{0,79}@[a-z0-9_-][a-z0-9._-]{0,78}")
_SEPARATOR = r"[ \t]*[:=|][ \t`\"']*(?:\r?\n[ \t`\"']*)?"
_LABELS = (
    ("Chrome", re.compile(r"\b(?:Chrome|Chromium)\s+Extension\s+ID" + _SEPARATOR + r"(?P<id>" + _CHROME_ID + r")(?![\w-])", re.I)),
    ("VS Code", re.compile(r"\bVS\s*Code\s+Extension\s+ID" + _SEPARATOR + r"(?P<id>" + _VSCODE_ID + r")(?![\w.-])", re.I)),
    ("Firefox", re.compile(r"\bFirefox\s+(?:Add-on|Addon|Extension)\s+ID" + _SEPARATOR + r"(?P<id>" + _FIREFOX_ID + r")(?![\w@.+-])", re.I)),
)
_URL = re.compile(r"\b(?:https://|chrome-extension://)[^\s<>\"'`]{1,4096}", re.I)


def _listing(ecosystem: str, identifier: str) -> str | None:
    if ecosystem == "Chrome":
        return "https://chromewebstore.google.com/detail/" + identifier
    if ecosystem == "VS Code":
        return "https://marketplace.visualstudio.com/items?" + urlencode({"itemName": identifier})
    return None


def _url_identity(value: str) -> tuple[str, str] | None:
    try:
        parts = urlsplit(value)
        if parts.username or parts.password or parts.port not in (None, 443):
            return None
        host = (parts.hostname or "").lower()
        if parts.scheme.lower() == "chrome-extension":
            return ("Chrome", host) if re.fullmatch(_CHROME_ID, host) else None
        if parts.scheme.lower() != "https":
            return None
        path = parts.path.rstrip("/")
        prefix = {"chromewebstore.google.com": "/detail/", "chrome.google.com": "/webstore/detail/"}.get(host)
        if prefix and path.startswith(prefix):
            tail = path[len(prefix):].split("/")
            if len(tail) in (1, 2) and all(tail) and re.fullmatch(_CHROME_ID, tail[-1], re.I):
                return "Chrome", tail[-1].lower()
        if host == "marketplace.visualstudio.com" and path == "/items":
            ids = parse_qs(parts.query, max_num_fields=32).get("itemName", [])
            if len(ids) == 1 and re.fullmatch(_VSCODE_ID, ids[0], re.I):
                return "VS Code", ids[0]
    except ValueError:
        pass
    return None


def references(text: str, linked: list[dict] | None = None) -> tuple[list[dict], str, bool]:
    """Return typed references and text with recognized IDs/URLs masked.

    Keep line breaks for downstream row context. Mask even after the display
    cap, so excess IDs cannot spill into the file-hash or email results.
    """
    found: dict[tuple[str, str], dict] = {}
    spans = []
    limited = False

    def add(ecosystem: str, identifier: str, context: str, evidence: str) -> None:
        nonlocal limited
        if ecosystem == "Chrome":
            identifier = identifier.lower()
        key = (ecosystem, identifier)
        if key in found:
            found[key]["count"] += 1
        elif len(found) < MAX_REFERENCES:
            found[key] = {"ecosystem": ecosystem, "identifier": identifier,
                          "context": context[:500], "evidence": evidence,
                          "listing": _listing(ecosystem, identifier), "count": 1}
        else:
            limited = True

    for ecosystem, pattern in _LABELS:
        for match in pattern.finditer(text):
            if ecosystem == "Firefox" and len(match["id"]) > 80:
                continue
            start = text.rfind("\n", max(0, match.start() - 200), match.start()) + 1
            start = max(start, match.start() - 200)
            end = text.find("\n", match.end(), match.end() + 250)
            context = text[start:end if end != -1 else match.end() + 250].strip()
            add(ecosystem, match["id"], context, "Explicit ID Label")
            spans.append(match.span("id"))

    for match in _URL.finditer(text):
        value = match[0].rstrip(".,;:!?)]}")
        identity = _url_identity(value)
        if identity:
            # Never retain query tokens, user information or URL fragments.
            before = text[max(0, match.start() - 150):match.start()].rsplit("\n", 1)[-1]
            after = text[match.end():match.end() + 150].split("\n", 1)[0]
            context = before + (_listing(*identity) or "") + after
            add(*identity, context.strip(), "Extension URL")
            spans.append(match.span())
    for item in (linked or [])[:100]:
        value = str(item.get("value", ""))
        if len(value) <= 4096 and (identity := _url_identity(value)):
            add(*identity, str(item.get("reason", "Linked report reference")), "Linked Extension URL")

    masked = list(text)
    for start, end in spans:
        for index in range(start, end):
            if masked[index] not in "\r\n":
                masked[index] = " "
    return list(found.values()), "".join(masked), limited
