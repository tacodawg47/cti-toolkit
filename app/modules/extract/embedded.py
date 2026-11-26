"""Read declarative Next.js article models as JSON. Never execute scripts."""

import json
import re
from html import escape
from html.parser import HTMLParser

_PUSH = re.compile(r"self\.__next_f\.push\(")
_REF = re.compile(r"^\$(?:L)?([0-9a-f]+)$")
_HASH = re.compile(r"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])", re.I)
_TAGS = {"article", "section", "div", "span", "p", "br", "pre", "code", "a", "img", "figure", "figcaption",
         "table", "caption", "thead", "tbody", "tr", "td", "th", "ul", "ol", "li", "strong", "b", "em",
         "h1", "h2", "h3", "h4", "h5", "h6"}


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inside = False
        self.values = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.inside = True

    def handle_endtag(self, tag):
        if tag == "script":
            self.inside = False

    def handle_data(self, data):
        if self.inside and len(self.values) < 1000:
            self.values.append(data)


def article(source: str) -> str | None:
    if "self.__next_f.push(" not in source or len(source) > 5_000_000:
        return None
    parser = _Scripts()
    parser.feed(source)
    chunks = []
    for script in parser.values:
        for match in _PUSH.finditer(script):
            try:
                value, _ = json.JSONDecoder().raw_decode(script[match.end():])
            except (ValueError, RecursionError):
                continue
            if isinstance(value, list) and len(value) == 2 and value[0] == 1 and isinstance(value[1], str):
                chunks.append(value[1])
    stream = "".join(chunks)
    if len(stream) > 2_000_000:
        return None
    records = {}
    for line in stream.splitlines()[:10000]:
        key, separator, payload = line.partition(":")
        if separator and re.fullmatch(r"[0-9a-f]+", key):
            try:
                records[key] = json.loads(payload)
            except (ValueError, RecursionError):
                continue

    def render(node, refs=frozenset(), depth=0, budget=None):
        if depth > 64 or budget[0] <= 0:
            return ""
        budget[0] -= 1
        if isinstance(node, str):
            reference = _REF.fullmatch(node)
            if reference:
                key = reference[1]
                return render(records.get(key), refs | {key}, depth + 1, budget) if key not in refs else ""
            return "" if node.startswith("$") else escape(node)
        if not isinstance(node, list):
            return ""
        if len(node) >= 4 and node[0] == "$" and isinstance(node[3], dict):
            tag, properties = node[1], node[3]
            if not isinstance(tag, str) or tag not in _TAGS:
                return render(properties.get("children"), refs, depth + 1, budget)
            attrs = ""
            for key in ("href", "src", "alt", "className"):
                value = properties.get(key)
                if isinstance(value, str) and not value.startswith("$"):
                    attrs += " " + ("class" if key == "className" else key) + '="' + escape(value[:2048], quote=True) + '"'
            body = render(properties.get("children"), refs, depth + 1, budget)
            return f"<{tag}{attrs}>{body}</{tag}>"
        return "".join(render(part, refs, depth + 1, budget) for part in node)

    best, score = "", (0, 0)
    total_budget = [200000]
    for node in records.values():
        if total_budget[0] <= 0:
            break
        if not isinstance(node, list):
            continue
        value = render(node, budget=total_budget)
        if len(value) > 2_000_000:
            continue
        rank = (len(set(_HASH.findall(value))), value.count("<p"))
        if rank > score:
            best, score = value, rank
    # Require substantial hash overlap before replacing a partially streamed
    # report. This is not a general arbitrary-JavaScript/JSON text extractor.
    overlap = set(_HASH.findall(best)) & set(_HASH.findall(source))
    return best if score[0] >= 10 and len(overlap) >= 5 else None
