"""Local views only. Watch configuration/review uses the existing inbox."""

from fastapi import APIRouter, HTTPException, Query, Request

from ...core.feed_scheduler import health
from ...core.templating import templates
from . import ransomlook, store

router = APIRouter()


@router.get("/ransomware")
def index(request: Request, before: int | None = Query(None, gt=0)):
    return templates.TemplateResponse(request, "ransomware.html", {"rows": store.claims(before=before),
        "source_health": health(ransomlook.catalog())})


@router.get("/ransomware/claims/{ident}")
def detail(request: Request, ident: int, before: int | None = Query(None, gt=0)):
    value = store.detail(ident, before=before)
    if value is None:
        raise HTTPException(404, "Claim not found")
    return templates.TemplateResponse(request, "ransomware.html", {**value, "source_health": health(ransomlook.catalog())})
