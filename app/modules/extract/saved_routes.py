"""Local escaped metadata views. Originals have no serving/export route."""

import asyncio
from uuid import uuid4

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse

from ...core.config import settings
from ...core.templating import templates
from ...core.web import reject_cross_site
from ..enrich import bulk
from . import saved

router = APIRouter()


@router.get("/reports")
def reports(request: Request):
    return templates.TemplateResponse(request, "saved_reports.html", {"reports": saved.list_reports()})


@router.get("/reports/{ident}")
def report(request: Request, ident: int):
    value = saved.detail(ident)
    if value is None:
        raise HTTPException(404, "Saved report not found")
    return templates.TemplateResponse(request, "saved_reports.html", {**value, "keyless": bulk.KEYLESS,
        "keyed": bulk.KEYED, "request_key": uuid4().hex, "bulk_enabled": settings.bulk_enrichment_enabled})


@router.post("/reports/{ident}/enrich")
async def enrich_report(request: Request, ident: int, request_key: str = Form(...),
                        providers: list[str] = Form([]), offset: int = Form(0), count: int = Form(10)):
    reject_cross_site(request)
    if not 1 <= len(request_key) <= 128:
        raise HTTPException(422, "Invalid request identity")
    try:
        service = request.app.state.bulk_enrichment
        params = bulk.Params(document_id=ident, providers=tuple(providers), offset=offset, count=count)
        job = await asyncio.to_thread(service.enqueue, params, request_key)
    except PermissionError:
        raise HTTPException(403, "Bulk worker and each selected provider need explicit enabling and review; report must be public and unrestricted") from None
    except ValueError:
        raise HTTPException(422, "Choose a bounded indicator batch and registered providers") from None
    return RedirectResponse(f"/report-jobs/{job}", status_code=303)


@router.get("/report-jobs/{job_id}")
def job_status(request: Request, job_id: str):
    job = request.app.state.bulk_enrichment.runner.get(job_id)
    if job is None or job["task"] != "reports.enrich":
        raise HTTPException(404, "Report job not found")
    return templates.TemplateResponse(request, "saved_reports.html", {"job": job})


@router.post("/reports/{ident}/enrich-all")
async def enrich_all_reports(request: Request, ident: int, request_key: str = Form(...), providers: list[str] = Form([])):
    reject_cross_site(request)
    if not 1 <= len(request_key) <= 128:
        raise HTTPException(422, "Invalid request identity")
    try:
        await asyncio.to_thread(request.app.state.bulk_enrichment.enqueue_all, ident, tuple(providers), request_key)
    except PermissionError:
        raise HTTPException(403, "Worker, selected provider reviews and public report handling are required") from None
    except ValueError:
        raise HTTPException(422, "Choose applicable registered providers and a saved bounded report") from None
    return RedirectResponse(f"/reports/{ident}", status_code=303)


@router.post("/report-jobs/{job_id}/cancel")
def cancel_job(request: Request, job_id: str):
    reject_cross_site(request)
    runner = request.app.state.bulk_enrichment.runner
    job = runner.get(job_id)
    if job is None or job["task"] != "reports.enrich":
        raise HTTPException(404, "Report job not found")
    runner.cancel(job_id)
    return RedirectResponse(f"/report-jobs/{job_id}", status_code=303)
