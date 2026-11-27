"""Passive CT views. No GET or web form dispatches collection."""

from fastapi import APIRouter, HTTPException, Query, Request

from ...core.feed_scheduler import health
from ...core.templating import templates
from . import crtsh, matching, store

router = APIRouter()


@router.get("/ct-watches")
def index(request: Request):
    return templates.TemplateResponse(request, "ct_watches.html", {
        "watches": store.watches(), "source_health": health(crtsh.catalog()), "patterns": matching.PATTERNS})


@router.get("/ct-watches/captures/{document_id}")
def capture(request: Request, document_id: int, offset: int = Query(0, ge=0)):
    result = store.capture(document_id, offset=offset)
    if result is None:
        raise HTTPException(404, "CT capture not found")
    return templates.TemplateResponse(request, "ct_watches.html", {**result, "source_health": health(crtsh.catalog())})


@router.get("/ct-watches/watches/{selector_id}")
def history(request: Request, selector_id: int, before: int | None = Query(None, gt=0)):
    return templates.TemplateResponse(request, "ct_watches.html", {
        "history": store.history(selector_id, before=before), "selector_id": selector_id, "source_health": health(crtsh.catalog())})
