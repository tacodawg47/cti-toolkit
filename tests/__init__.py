"""
Test package. Importing it makes the vendor clients OFFLINE for the whole run.

The shared HTTP client is created lazily by app.modules.enrich.base.new_client.
Here that factory is replaced with one whose transport refuses every request,
so a test that forgets to install an httpx.MockTransport fails loudly with
"network disabled in tests" instead of quietly calling a real vendor and
spending quota. Tests that need HTTP install their own mock via base.set_client.
"""

import httpx

from app.modules.enrich import base


def _offline_client() -> httpx.AsyncClient:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network disabled in tests")

    return httpx.AsyncClient(transport=httpx.MockTransport(refuse))


base.new_client = _offline_client
