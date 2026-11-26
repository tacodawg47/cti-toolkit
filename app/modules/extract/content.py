"""Separate passive report evidence from code samples and image references."""

import re
import ipaddress
from urllib.parse import urlsplit

from .layouts import Node, StructureParser

_HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
_IMAGE = re.compile(r"\.(?:png|jpe?g|gif|webp|svg)(?:[?#].*)?$", re.I)
_COMMAND = re.compile(r"^(?:/\S+/(?:nmap|curl|wget|python\S*|bash|sh)|nmap|curl|wget|esxcli|powershell(?:\.exe)?|cmd(?:\.exe)?\s+/c|bash|python[23]?|certutil)(?:\s|$)", re.I)


def kind(text: str, label: str = "") -> str:
    lower = text.lower()
    hint = label.lower()
    if re.search(r"\b(?:private\s+|global\s+)?rule\s+[\w]+\s*(?::[^\n{]+)?\s*\{", text):
        return "YARA"
    if re.search(r"(?m)^\s*logsource\s*:", text) and re.search(r"(?m)^\s*detection\s*:", text):
        return "Sigma"
    if _COMMAND.search(text.strip()):
        return "Command Line"
    if "kql" in hint or re.search(r"\b(?:DeviceProcessEvents|DeviceNetworkEvents|SecurityEvent|SigninLogs)\s*\|", text):
        return "KQL"
    if "splunk" in hint or re.search(r"\bindex\s*=", text):
        return "SPL"
    if "cql" in hint or "#event_simplename" in lower:
        return "CQL"
    return "Code Sample"


def image_url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if host == "localhost" or host.endswith((".localhost", ".local")) or not host:
            return False
        try:
            if not ipaddress.ip_address(host).is_global:
                return False
        except ValueError:
            pass
        return (parsed.scheme == "https" and parsed.username is None
                and not re.search(r"(?:token|secret|api.?key|password)", parsed.query, re.I)
                and bool(_IMAGE.search(value)))
    except ValueError:
        return False


def _artifact(document, text: str, label: str):
    text = text.strip()
    if not text or len(document.artifacts) >= 50:
        return
    item = {"kind": kind(text, label), "label": label[:200], "text": text[:30000], "truncated": len(text) > 30000}
    if not any(row["text"] == item["text"] for row in document.artifacts):
        document.artifacts.append(item)


def enrich_html(document, source: str):
    parser = StructureParser()
    parser.feed(source)
    parser.close()
    candidates = []

    def locate(node):
        if node.tag == "article":
            candidates.append(node)
        for child in node.children:
            if isinstance(child, Node):
                locate(child)
    locate(parser.root)
    root = max(candidates, key=lambda node: len(node.raw()), default=parser.root)
    if len(root.raw().strip()) < 1000:
        root = parser.root
    pieces = []
    heading = ""

    def walk(node):
        nonlocal heading
        if isinstance(node, str):
            pieces.append(node)
            return
        if node.tag in {"nav", "header", "footer"}:
            return
        if node.tag in _HEADINGS:
            heading = node.text()
        if node.tag == "img":
            url = node.attrs.get("src") or ""
            if image_url(url) and len(document.images) < 30 and not any(row["url"] == url for row in document.images):
                document.images.append({"url": url, "caption": node.attrs.get("alt") or heading})
            return
        if node.tag == "a":
            href = node.attrs.get("href") or ""
            # A linked citation is context, not automatically an IOC.
            if href.startswith("https://") and href not in node.raw():
                from urllib.parse import parse_qsl, urlunsplit
                try:
                    parsed = urlsplit(href)
                except ValueError:
                    return
                sensitive = parsed.username is not None or any(re.search(r"token|secret|api.?key|password", key, re.I)
                                                              for key, _ in parse_qsl(parsed.query))
                if parsed.hostname and not sensitive and len(document.references) < 100:
                    reference = {"value": urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment)),
                                 "reason": node.text()[:160] or "Report Reference"}
                    if reference not in document.references:
                        document.references.append(reference)
        if node.tag == "table" and kind(node.raw(), heading) != "Code Sample":
            _artifact(document, node.raw(), heading)
            pieces.append("\n")
            return
        if node.tag == "pre" or node.tag == "code" and ("\n" in node.raw() or kind(node.raw()) != "Code Sample"):
            text = node.raw()
            category = kind(text, heading + " " + str(node.attrs.get("class") or ""))
            ioc_list = any(word in heading.lower() for word in ("hash", "indicator", "ioc")) and category == "Code Sample"
            if not ioc_list:
                _artifact(document, text, heading)
                pieces.append("\n")
                return
        block = node.tag in {"p", "div", "section", "li", "tr", "td", "th", "br", "pre"} | _HEADINGS
        if block:
            pieces.append("\n")
        for child in node.children:
            walk(child)
        if block:
            pieces.append("\n")
    walk(root)
    document.indicator_text = "".join(pieces)[:2_000_000]
    if not document.indicator_text.strip() and not document.artifacts:
        document.indicator_text = None
    # Commands may be plain table cells, without a pre/code element.
    for table in document.tables:
        for row in table.rows:
            for cell in row:
                if _COMMAND.search(cell.strip()):
                    _artifact(document, cell, table.caption or "Report Table")


def prepare_text(document):
    if document.indicator_text is not None:
        return
    text = document.text
    pieces, code = [], []
    fence = ""
    heading = ""
    rule_depth = 0
    rule = []
    rule_opened = False
    for line in text.splitlines():
        marker = re.match(r"^\s*(```+|~~~+)(.*)$", line)
        if marker:
            if fence and marker[1][0] == fence[0] and len(marker[1]) >= len(fence) and not marker[2].strip():
                value = "\n".join(code)
                if any(word in heading.lower() for word in ("hash", "indicator", "ioc")) and kind(value, heading) == "Code Sample":
                    pieces.append(value)
                else:
                    _artifact(document, value, heading)
                fence, code = "", []
            elif not fence:
                fence = marker[1]
            else:
                code.append(line)
            continue
        if fence:
            code.append(line)
            continue
        if rule or re.match(r"\s*(?:(?:private|global)\s+)?rule\s+\w+", line):
            rule.append(line)
            structural = re.sub(r'"(?:\\.|[^"\\])*"|//.*$', '', line)
            rule_opened = rule_opened or "{" in structural
            rule_depth += structural.count("{") - structural.count("}")
            if rule_opened and rule_depth <= 0:
                _artifact(document, "\n".join(rule), heading)
                rule, rule_opened = [], False
            continue
        if line.startswith("#") or line.strip().endswith(":") and len(line) < 160:
            heading = line.lstrip("# ")
        if _COMMAND.search(line.strip()):
            _artifact(document, line, heading)
            continue
        for match in re.finditer(r"https://[^\s<>\"')]+", line):
            url = match[0]
            if image_url(url):
                if len(document.images) < 30 and not any(item["url"] == url for item in document.images):
                    document.images.append({"url": url, "caption": heading or "Report Image"})
                line = line.replace(url, " ")
        pieces.append(line)
    if code:
        _artifact(document, "\n".join(code), heading)
    if rule:
        _artifact(document, "\n".join(rule), heading)
    document.indicator_text = "\n".join(pieces)


def attach_context(result, document):
    from . import extractor
    wanted = {(item.type, item.value): item for item in result.items}
    for table in document.tables:
        label = table.caption
        if kind("\n".join(" ".join(row) for row in table.rows)) != "Code Sample":
            continue
        for row in table.rows:
            text = " | ".join(cell for cell in row if cell).strip()
            if not text:
                continue
            found = extractor.extract(text)
            if not found.items and len(text) < 160:
                label = " | ".join(value for value in (table.caption, text) if value)
            for token in found.items:
                item = wanted.get((token.type, token.value))
                if item is not None:
                    context = " | ".join(value for value in (label, text) if value)[:1500]
                    if context not in item.context and len(item.context) < 3:
                        item.context.append(context)
