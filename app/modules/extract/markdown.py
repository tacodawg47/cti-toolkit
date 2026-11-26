"""Read Markdown tables and explicit ATT&CK list entries as report evidence."""

import re

from .attack import ids
from .extractor import MAX_TEXT_CHARS
from .html import Document, Table

_HEADING = re.compile(r"^ {0,3}#{1,6}[ \t]+(.+)$")
_LIST = re.compile(r"^( {0,3})(?:[-+*]|[0-9]{1,9}[.)])[ \t]+(.+)$")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_DIVIDER = re.compile(r":?-{3,}:?")
_PIPE_TOKEN = re.compile(r"\\\||`+|\|")
_PROCEDURE = re.compile(r"\s+[-–—]\s+")


def _cells(line: str) -> list[str]:
    """Split unescaped pipes outside inline code, with optional outer pipes."""
    if "|" not in line or line.startswith(("    ", "\t")):
        return []
    text = line.strip()
    cells = []
    start = 0
    code_ticks = ""
    for token in _PIPE_TOKEN.finditer(text):
        value = token[0]
        if value.startswith("`"):
            if not code_ticks or code_ticks == value:
                code_ticks = "" if code_ticks else value
        elif value == "|" and not code_ticks:
            cells.append(text[start:token.start()].strip())
            start = token.end()
    if not cells:
        return []
    cells.append(text[start:].strip())
    if not cells[0] and text.startswith("|"):
        cells.pop(0)
    if cells and not cells[-1] and text.endswith("|"):
        cells.pop()
    return [cell.replace(r"\|", "|")[:4000] for cell in cells[:32]]


def _list_row(content: str) -> list[str] | None:
    parts = _cells(content)
    if len(parts) != 2:
        parts = _PROCEDURE.split(content, maxsplit=1)
    if len(parts) != 2:
        return None
    label, procedure = parts
    matches = ids(label)
    first = label.lstrip(" *`_[(").upper()
    if not matches or not matches[0].startswith("T") or not first.startswith(matches[0][:5]):
        return None
    return [" ".join(dict.fromkeys(ident for ident in matches if ident.startswith("T"))), procedure.strip()]


def parse_document(text: str) -> Document:
    """Keep the original input and recover only explicitly structured procedures."""
    lines = text[:MAX_TEXT_CHARS].splitlines()
    tables = []
    prose = []
    heading = ""
    fence = ""
    i = 0
    while i < len(lines) and len(tables) < 200:
        line = lines[i]
        i += 1
        marker = _FENCE.match(line)
        if marker:
            token = marker[1]
            if not fence:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence) and not marker[2].strip():
                fence = ""
            continue
        if fence:
            continue
        title = _HEADING.match(line)
        if title:
            heading = title[1].strip(" #")[:300]
            if any(ident.startswith("T") for ident in ids(heading)):
                body = []
                following = i
                while following < len(lines) and len(body) < 40:
                    candidate = lines[following]
                    if _HEADING.match(candidate) or _LIST.match(candidate) or _FENCE.match(candidate) or _cells(candidate):
                        break
                    body.append(candidate)
                    following += 1
                paragraph = " ".join(part.strip() for part in body if part.strip())[:4000]
                if paragraph:
                    tables.append(Table(heading, [["ID", "Use"], [heading, paragraph]], "Markdown Heading Block"))
                    i = following
            continue
        header = _cells(line)
        divider = _cells(lines[i]) if len(header) >= 2 and i < len(lines) else []
        if len(header) == len(divider) and divider and all(_DIVIDER.fullmatch(cell) for cell in divider):
            rows = [header]
            i += 1
            while i < len(lines) and len(rows) < 2000:
                row = _cells(lines[i])
                if not row or _LIST.match(lines[i]):
                    break
                rows.append(row[:len(header)])
                i += 1
            tables.append(Table(heading, rows, "Markdown Table"))
            continue
        item = _LIST.match(line)
        row = _list_row(item[2]) if item else None
        if row:
            indent = " " * (len(item[1]) + 2)
            while i < len(lines) and lines[i].startswith(indent) and lines[i].strip():
                if _LIST.match(lines[i]) or _FENCE.match(lines[i].lstrip()):
                    break
                row[1] += " " + lines[i].strip()
                i += 1
                if len(row[1]) >= 4000:
                    break
            row[1] = row[1][:4000].strip()
            if row[1]:
                tables.append(Table(heading, [["ID", "Use"], row], "Markdown List"))
                continue
        prose.append(line)
    return Document(text, tables, prose=prose, format="Markdown")
