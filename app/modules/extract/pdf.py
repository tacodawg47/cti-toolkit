"""
PDF to plain text via pypdf.

pypdf is an optional dependency: the import happens inside the function, so
the rest of the extraction module works without it and the page explains
what to install. Text extraction from PDFs is best-effort by nature (a
scanned PDF has no text layer at all); the caller shows the character count
so the analyst can tell an empty result from a failed one.
"""

import io
import re

from .html import Document

MAX_PAGES = 500
_HASH_LINE = re.compile(r"^\s*([a-fA-F0-9]{4,64})(?:[ \t]+(.*))?\s*$")
_HASH_KIND = re.compile(r"\b(SHA[ -]?256|SHA[ -]?1|MD5)\b", re.I)
_PAGE_FURNITURE = re.compile(r"^(?:page\s+)?[0-9]{1,4}(?:\s*(?:of|/)\s*[0-9]{1,4})?$", re.I)


def hash_document(text: str) -> Document:
    """Repair wrapped digest rows while keeping nearby source context."""
    lines = text.splitlines()
    output = []
    context = {}
    target = None
    headings = []
    i = 0
    while i < len(lines):
        line = lines[i]
        kind = _HASH_KIND.findall(line)
        if kind and not _HASH_LINE.match(line):
            lengths = {{"sha256": 64, "sha1": 40, "md5": 32}[value.lower().replace("-", "").replace(" ", "")]
                       for value in kind}
            target = next(iter(lengths)) if len(lengths) == 1 else None
        match = _HASH_LINE.match(line)
        if not match:
            if line.strip() and len(line.strip()) < 180 and not _PAGE_FURNITURE.fullmatch(line.strip()):
                headings = [*headings[-2:], line.strip()]
            output.append(line)
            i += 1
            continue
        chunks = [match[1]]
        end = i + 1
        note = (match[2] or "").strip()
        candidates = []
        for following in range(i + 1, min(i + 7, len(lines))):
            next_line = lines[following]
            if not next_line.strip() or _PAGE_FURNITURE.fullmatch(next_line.strip()):
                continue
            if next_line.strip() in headings and _HASH_KIND.search(next_line):
                continue
            fragment = _HASH_LINE.match(next_line)
            if not fragment or len("".join(chunks)) + len(fragment[1]) > (target or 64):
                break
            chunks.append(fragment[1])
            total = sum(map(len, chunks))
            if fragment[2]:
                note = fragment[2].strip()
            if total in ((target,) if target else (32, 40, 64)):
                ambiguous = target is None and all(len(chunk) in (32, 40, 64) for chunk in chunks)
                if not ambiguous:
                    candidates.append(("".join(chunks), following + 1, note))
            if total == (target or 64):
                break
        if candidates:
            value, end, note = candidates[-1]
            output.append(value + (" " + note if note else ""))
            evidence = f"Rejoined PDF lines {i + 1}-{end}"
        else:
            value = match[1]
            output.append(line)
            evidence = f"PDF line {i + 1}"
        if len(value) in (32, 40, 64):
            details = " · ".join(part for part in (evidence, *headings, note) if part)
            context.setdefault(value.lower(), []).append(details)
        i = end
    return Document("\n".join(output), hash_context=context)


def pdf_text(data: bytes) -> tuple[str | None, str | None]:
    """Return (text, None) on success or (None, error message) on failure."""
    try:
        from pypdf import PdfReader
    except ImportError:
        return None, ("PDF support needs the pypdf package; see "
                      "docs/runbooks/ioc-extraction.md for the install command")
    try:
        reader = PdfReader(io.BytesIO(data))
        if reader.is_encrypted:
            # Many "encrypted" PDFs only restrict printing and open with an
            # empty user password. Anything else is reported, not guessed.
            if not reader.decrypt(""):
                return None, "the PDF is password-protected"
        parts: list[str] = []
        for i, page in enumerate(reader.pages):
            if i >= MAX_PAGES:
                parts.append(f"\n[stopped after {MAX_PAGES} pages]\n")
                break
            parts.append(page.extract_text() or "")
    except Exception as exc:      # pypdf raises many types; none is actionable here
        return None, f"could not read the PDF: {type(exc).__name__}"
    return "\n".join(parts), None


def pdf_document(data: bytes) -> tuple[Document | None, str | None]:
    text, error = pdf_text(data)
    return (None, error) if error else (hash_document(text or ""), None)
