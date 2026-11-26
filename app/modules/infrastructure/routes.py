"""Local C2 feed browser."""

from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from ...core.indicators import refang
from ...core.templating import templates
from ...core.web import reject_cross_site
from ...core.feed_scheduler import health as feed_health
from . import c2feed

router = APIRouter(prefix="/infrastructure")


@router.get("", response_class=HTMLResponse)
def index(request: Request, q: str = "", scope: str = "verified", page: int = Query(1, ge=1)):
    from ..vulnerability_intelligence.scheduled import catalog
    if scope not in ("verified", "unverified", "all"):
        scope = "verified"
    q = q[:256]
    data = c2feed.page(refang(q), scope, page)

    def page_url(number: int) -> str:
        return router.prefix + "?" + urlencode({"q": q, "scope": scope, "page": number})

    return templates.TemplateResponse(request, "infrastructure.html", {
        "q": q, "scope": scope, **data, "page_url": page_url, "sources": c2feed.SOURCES,
        "repository": c2feed.REPO, "dashboard": c2feed.DASHBOARD, "license_url": c2feed.LICENSE,
        "source_health": feed_health([feed for feed in catalog() if feed.key == "c2intel"]),
    })


@router.post("/refresh-c2")
async def refresh(request: Request):
    reject_cross_site(request)
    await c2feed.refresh()
    return RedirectResponse(router.prefix, status_code=303)
