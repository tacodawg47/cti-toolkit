"""
Small helpers shared by every route module.

Kept in core so a module's router (e.g. vulnerability intelligence) can use
them without importing app.main, which would be circular: main imports the
routers.
"""

from fastapi import HTTPException, Request


def reject_cross_site(request: Request) -> None:
    """Refuse a form post that came from another website.

    Modern browsers tag every request with Sec-Fetch-Site. A form on another
    site posting here arrives as "cross-site"; reject it so a page you happen
    to have open cannot spend your API quota or edit your watchlist. Requests
    without the header (curl, older clients, our tests) are allowed.
    """
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(status_code=403, detail="cross-site requests are not allowed")
