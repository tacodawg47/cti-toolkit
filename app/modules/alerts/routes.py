"""Read-only GETs and guarded local configuration/review actions."""

from fastapi import APIRouter, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from ...core import alerts, evidence
from ...core.feed_scheduler import health
from ...core.templating import templates
from ...core.web import reject_cross_site
from ...core.feed_catalog import catalog
from ..ransomware import store as ransomware_store

router = APIRouter()


@router.get("/alerts")
def inbox(request: Request, state: str = "", before: int | None = Query(None, gt=0)):
    try:
        rows = alerts.inbox(state=state or None, before=before)
    except ValueError:
        raise HTTPException(422, "Invalid alert filter") from None
    return templates.TemplateResponse(request, "alerts.html", {"rows": rows, "state": state,
        "selectors": alerts.selectors(), "types": alerts.TYPES, "source_health": health(catalog())})


@router.get("/alerts/{ident}")
def detail(request: Request, ident: int, citation_offset: int = Query(0, ge=0), review_offset: int = Query(0, ge=0)):
    value = alerts.detail(ident, citation_offset=citation_offset, review_offset=review_offset)
    if value is None:
        raise HTTPException(404, "Alert not found")
    feeds = [feed for feed in catalog() if feed.source == value["document"]["source_id"]]
    value["ransomware_claim_id"] = ransomware_store.for_observation(value["observation"]["id"])
    value["source_health"] = health(feeds) if feeds else []
    return templates.TemplateResponse(request, "alerts.html", value)


@router.post("/alert-selectors")
def add_selector(request: Request, subject_type: str = Form(...), mode: str = Form("exact"),
                 value: str = Form(...), authorized: bool = Form(False)):
    reject_cross_site(request)
    if not authorized:
        raise HTTPException(422, "Confirm authority to monitor this selector locally")
    try:
        alerts.add_selector(alerts.Selector(subject_type=subject_type, mode=mode, value=value))
    except ValueError:
        raise HTTPException(422, "Use a valid bounded typed selector; capacity is 100") from None
    return RedirectResponse("/alerts", status_code=303)


@router.post("/alert-selectors/{ident}/enabled")
def enabled(request: Request, ident: int, enabled: bool = Form(...)):
    reject_cross_site(request)
    try:
        alerts.set_enabled(ident, enabled)
    except KeyError:
        raise HTTPException(404, "Selector not found") from None
    return RedirectResponse("/alerts", status_code=303)


@router.post("/alert-selectors/{ident}/scan")
def scan(request: Request, ident: int):
    reject_cross_site(request)
    try:
        alerts.scan_page(ident)
    except KeyError:
        raise HTTPException(404, "Selector not found") from None
    except PermissionError:
        raise HTTPException(403, "Enable this local selector before matching") from None
    return RedirectResponse("/alerts", status_code=303)


@router.post("/alerts/{ident}/review")
def review(request: Request, ident: int, state: str = Form(...), revision: int = Form(...)):
    reject_cross_site(request)
    try:
        alerts.review(ident, state, revision)
    except evidence.EvidenceConflict:
        raise HTTPException(409, "Review changed; reload this alert") from None
    except KeyError:
        raise HTTPException(404, "Alert not found") from None
    except ValueError:
        raise HTTPException(422, "Invalid review state or revision") from None
    return RedirectResponse(f"/alerts/{ident}", status_code=303)
