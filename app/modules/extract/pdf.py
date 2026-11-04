"""
PDF to plain text via pypdf.

pypdf is an optional dependency: the import happens inside the function, so
the rest of the extraction module works without it and the page explains
what to install. Text extraction from PDFs is best-effort by nature (a
scanned PDF has no text layer at all); the caller shows the character count
so the analyst can tell an empty result from a failed one.
"""

import io

MAX_PAGES = 500


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
