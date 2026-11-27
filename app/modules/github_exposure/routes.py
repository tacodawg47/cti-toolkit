"""Passive metadata and freshness views. No collection or submission forms."""

from fastapi import APIRouter, HTTPException, Query, Request

from ...core.feed_scheduler import health
from ...core.templating import templates
from . import github, store

router = APIRouter()


@router.get("/github-exposure")
def index(request: Request):
    return templates.TemplateResponse(request, "github_exposure.html", {
        "watches": store.watches(), "source_health": health(github.catalog())})


@router.get("/github-exposure/captures/{document_id}")
def capture(request: Request, document_id: int):
    result = store.capture(document_id)
    if result is None:
        raise HTTPException(404, "GitHub search capture not found")
    return templates.TemplateResponse(request, "github_exposure.html", {**result, "source_health": health(github.catalog())})


@router.get("/github-exposure/watches/{selector_id}")
def history(request: Request, selector_id: int, before: int | None = Query(None, gt=0)):
    return templates.TemplateResponse(request, "github_exposure.html", {
        "history": store.history(selector_id, before=before), "selector_id": selector_id, "source_health": health(github.catalog())})
