"""
Shared helpers for vendor clients.

- `vendor_result` / `not_configured` / `quota` / `failed` build a VendorResult
  with the common fields filled in, so each client stays short and the status
  values stay consistent.
- `fetch_json` performs one HTTP request on a shared, pooled AsyncClient and
  returns (status_code, parsed_json | None, error | None). It treats only a
  200-with-JSON as success and turns transport errors and non-JSON bodies into
  a clear message instead of letting `.json()` raise deep inside a client. Each
  client still maps specific codes (401/404/429/...) to its own wording.

The shared client is created once in the app lifespan (see app.main) so every
vendor shares a connection pool and sends one User-Agent. Tests may inject
their own client with `set_client` (e.g. an httpx.MockTransport client).
"""

import asyncio
import json as _json
from typing import Any

import httpx

from ... import __version__
from ...core.models import VendorResult

USER_AGENT = f"cti-toolkit/{__version__}"
DEFAULT_TIMEOUT = 20.0          # httpx per-phase limit: connect, each read, write
TOTAL_TIMEOUT = 30.0            # wall-clock cap for one whole request, body included
MAX_BODY_BYTES = 5 * 1024 * 1024    # stop reading a vendor body past 5 MB

_client: httpx.AsyncClient | None = None


def new_client() -> httpx.AsyncClient:
    """Create a client configured the way every vendor call should use."""
    return httpx.AsyncClient(
        timeout=DEFAULT_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    )


def set_client(client: httpx.AsyncClient | None) -> None:
    """Install the shared client (called from the app lifespan, or from tests)."""
    global _client
    _client = client


def get_client() -> httpx.AsyncClient:
    """Return the shared client, lazily creating a default one if none is set."""
    global _client
    if _client is None:
        _client = new_client()
    return _client


async def aclose() -> None:
    """Close and forget the shared client (called on app shutdown)."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def vendor_result(vendor: str, itype: str, value: str, **kw) -> VendorResult:
    """Build a VendorResult with the common fields filled in."""
    return VendorResult(source=vendor, indicator=value, indicator_type=itype, **kw)


def not_configured(vendor: str, itype: str, value: str, message: str) -> VendorResult:
    return vendor_result(vendor, itype, value, status="not_configured", error=message)


def quota(vendor: str, itype: str, value: str, message: str) -> VendorResult:
    return vendor_result(vendor, itype, value, status="quota", error=message)


def failed(vendor: str, itype: str, value: str, message: str) -> VendorResult:
    return vendor_result(vendor, itype, value, status="error", verdict="error", error=message)


async def fetch_json(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    params: dict | None = None,
    data: dict | None = None,
    json: dict | None = None,
    follow_redirects: bool = False,
    expect: str = "object",
) -> tuple[int | None, Any | None, str | None]:
    """
    Make one request on the shared client.

    `follow_redirects` is off by default: a redirect from a vendor API is
    unexpected and is reported as its 3xx code. RDAP is the exception: the
    rdap.org bootstrap answers with a redirect to the right registry, so that
    client passes follow_redirects=True.

    `expect` is the JSON shape the caller can handle: "object" (a dict, which
    is what every vendor API returns) or "list" (crt.sh returns a JSON array).
    Anything else is turned into an error here rather than crashing inside
    the client when it calls `.get()` on the body.

    Three protections apply to every call, because a slow or oversized answer
    from a free public service must not hang the page or eat memory:
      - the body is streamed and abandoned past MAX_BODY_BYTES;
      - the whole request is capped at TOTAL_TIMEOUT seconds of wall-clock
        time (httpx's own timeout is per read, so a trickle could run on);
      - the final URL must be HTTPS, so a redirect can never downgrade the
        indicator under investigation to cleartext.

    Returns (status_code, body, error):
      - transport error -> (None, None, "request failed: <ExceptionType>")
      - non-200         -> (status_code, None, None)   # caller maps the code
      - 200 + bad JSON  -> (200, None, "vendor returned a non-JSON response")
      - 200 + JSON of the wrong shape
                        -> (200, None, "vendor returned unexpected JSON")
      - 200 + JSON      -> (200, body, None)
    """
    client = get_client()
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT):
            async with client.stream(
                method, url, headers=headers, params=params, data=data, json=json,
                follow_redirects=follow_redirects,
            ) as resp:
                if resp.url.scheme != "https":
                    return None, None, "vendor URL is not HTTPS (refused)"
                if resp.status_code != 200:
                    return resp.status_code, None, None
                chunks: list[bytes] = []
                size = 0
                async for chunk in resp.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_BODY_BYTES:
                        return 200, None, (
                            f"vendor response too large (over {MAX_BODY_BYTES // (1024 * 1024)} MB)"
                        )
                    chunks.append(chunk)
                raw = b"".join(chunks)
    except TimeoutError:
        return None, None, f"request failed: total time over {TOTAL_TIMEOUT:.0f}s"
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        # InvalidURL is not an HTTPError, so it is listed on its own. Never
        # interpolate the exception itself: an httpx error can carry the full
        # URL, and some vendors (Shodan) put the API key in the URL.
        return None, None, f"request failed: {type(exc).__name__}"

    try:
        body = _json.loads(raw)
    except ValueError:
        return 200, None, "vendor returned a non-JSON response"
    wanted = list if expect == "list" else dict
    if not isinstance(body, wanted):
        return 200, None, f"vendor returned unexpected JSON (not a JSON {expect})"
    return 200, body, None
