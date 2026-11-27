"""Passive local views. No GET or web form authorizes provider submissions."""

from fastapi import APIRouter, HTTPException, Query, Request

from ...core.feed_scheduler import health
from ...core.templating import templates
from . import hibp, store

router = APIRouter()


@router.get("/breaches")
def index(request: Request):
    return templates.TemplateResponse(request, "breaches.html", {"watches": store.watches(), "source_health": health(hibp.catalog())})


@router.get("/breaches/captures/{document_id}")
def capture(request: Request, document_id: int):
    value = store.capture(document_id)
    if value is None:
        raise HTTPException(404, "Lookup capture not found")
    return templates.TemplateResponse(request, "breaches.html", {**value, "source_health": health(hibp.catalog())})


@router.get("/breaches/watches/{selector_id}")
def history(request: Request, selector_id: int, before: int | None = Query(None, gt=0)):
    return templates.TemplateResponse(request, "breaches.html", {
        "history": store.history(selector_id, before=before), "selector_id": selector_id, "source_health": health(hibp.catalog())})
