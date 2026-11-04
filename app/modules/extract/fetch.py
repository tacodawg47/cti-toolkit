"""
Download a report page for extraction.

Meant for vendor blog posts and advisories, so the rules are strict and
simple:
  - HTTPS only, before and after redirects (redirects are followed because
    blogs move; a redirect that lands on plain HTTP is refused).
  - Public hosts only: a loopback, private or link-local address, or a
    "localhost" name, is refused. This toolkit runs on the analyst's own
    machine, and a pasted link must not become a way to read local services.
  - Body capped at the same 5 MB as the vendor clients, with the same total
    wall-clock timeout, on the same shared HTTP client.
  - The response is turned into text by content type: HTML through the
    stdlib parser, PDF through pypdf, anything else decoded as text.

It is NOT a safe way to look at a suspected malicious URL: that is what the
urlscan card in enrichment is for. The page says so next to the box.
"""

import asyncio
import ipaddress
from urllib.parse import urlsplit

import httpx

from ..enrich import base
from .html import html_to_text
from .pdf import pdf_text


def _refusal(url: str) -> str | None:
    """Why a URL must not be fetched, or None if it may be."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "that is not a valid URL"
    if parts.scheme.lower() != "https":
        return "only https:// URLs are fetched"
    host = parts.hostname
    if not host:
        return "the URL has no host"
    if host == "localhost" or host.endswith((".localhost", ".local")):
        return "local hosts are not fetched"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None                      # a name: fine
    if not ip.is_global:
        return "private, loopback and reserved addresses are not fetched"
    return None


async def fetch_text(url: str) -> tuple[str | None, str | None, str | None]:
    """Fetch `url` and return (text, kind, error) where kind is html, pdf or
    text. Exactly one of text and error is None."""
    reason = _refusal(url)
    if reason:
        return None, None, reason

    client = base.get_client()
    try:
        async with asyncio.timeout(base.TOTAL_TIMEOUT):
            async with client.stream("GET", url, follow_redirects=True,
                                     headers={"Accept": "text/html, application/pdf, text/plain"}) as resp:
                if resp.url.scheme != "https":
                    return None, None, "the page redirected to a non-HTTPS address (refused)"
                if resp.status_code != 200:
                    return None, None, f"HTTP {resp.status_code} from the site"
                chunks: list[bytes] = []
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > base.MAX_BODY_BYTES:
                        return None, None, (
                            f"page too large (over {base.MAX_BODY_BYTES // (1024 * 1024)} MB)"
                        )
                    chunks.append(chunk)
                raw = b"".join(chunks)
                ctype = resp.headers.get("content-type", "").lower()
                encoding = resp.charset_encoding or "utf-8"
    except TimeoutError:
        return None, None, f"fetch took longer than {base.TOTAL_TIMEOUT:.0f}s"
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        # Never interpolate the exception: it can carry the full URL.
        return None, None, f"fetch failed: {type(exc).__name__}"

    if ctype.startswith("application/pdf") or raw[:5] == b"%PDF-":
        text, err = pdf_text(raw)
        return (None, None, err) if err else (text, "pdf", None)
    decoded = raw.decode(encoding, errors="replace")
    if "html" in ctype or decoded.lstrip()[:15].lower().startswith(("<!doctype html", "<html")):
        return html_to_text(decoded), "html", None
    return decoded, "text", None
