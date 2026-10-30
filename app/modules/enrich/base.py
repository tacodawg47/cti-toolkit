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

from typing import Any

import httpx

from ...core.models import VendorResult

USER_AGENT = "cti-toolkit/0.1.0"
DEFAULT_TIMEOUT = 20.0          # seconds per request; a hung vendor fails here

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
) -> tuple[int | None, Any | None, str | None]:
    """
    Make one request on the shared client.

    Returns (status_code, body, error):
      - transport error -> (None, None, "request failed: <ExceptionType>")
      - non-200         -> (status_code, None, None)   # caller maps the code
      - 200 + bad JSON  -> (200, None, "vendor returned a non-JSON response")
      - 200 + JSON      -> (200, body, None)
    """
    client = get_client()
    try:
        resp = await client.request(
            method, url, headers=headers, params=params, data=data, json=json
        )
    except httpx.HTTPError as exc:
        # Never interpolate the exception itself: an httpx error can carry the
        # full URL, and some vendors (Shodan) put the API key in the URL.
        return None, None, f"request failed: {type(exc).__name__}"
    if resp.status_code != 200:
        return resp.status_code, None, None
    try:
        body = resp.json()
    except ValueError:
        return 200, None, "vendor returned a non-JSON response"
    return 200, body, None
