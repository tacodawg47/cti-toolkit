"""
FastAPI application: search page, enrichment route, health page.

Bound to 127.0.0.1 by run.py. On startup the lifespan handler creates the
database schema and opens the one shared HTTP client that every vendor module
reuses; on shutdown it closes that client.
"""

import asyncio
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .core import db
from .core.feed_scheduler import Scheduler, health as feed_health
from .core.allowlist import allowlist
from .core.config import PROJECT_ROOT, settings
from .core.indicators import MAX_INDICATOR_LEN, canonical, detect_type, normalise
from .core.ratelimit import LIMITS, rate_limiter
from .core.templating import templates
from .core.web import reject_cross_site
from .modules.enrich import base, registry, shodan
from .modules.enrich.bulk import Service as BulkService
from .modules.extract import saved, saved_routes
from .modules.alerts import routes as alert_routes
from .modules.ransomware import routes as ransomware_routes
from .modules.breaches import routes as breach_routes
from .modules.ct_watch import routes as ct_watch_routes
from .modules.github_exposure import routes as github_exposure_routes
from .modules.extract import atlas, attack, attack_catalog, content, decode, extractor, markdown, tlds
from .modules.extract import fetch as extract_fetch
from .modules.extract import pdf as extract_pdf
from .modules.extract.html import Document, parse_document
from .modules.infrastructure import c2feed, routes as infra_routes
from .modules.vulnerability_intelligence import routes as vulnintel_routes
from .modules.vulnerability_intelligence import service as vulnintel_service
from .modules.vulnerability_intelligence import store as vulnintel_store
from .core.feed_catalog import catalog as feed_catalog

BASE_DIR = Path(__file__).resolve().parent

# An uploaded file larger than this is refused before it is read in full.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _display_path(p) -> str:
    """A path for the health page: relative to the project when it is inside
    it, so the page never shows the user's home directory or username."""
    if p is None:
        return "—"
    p = Path(p)
    try:
        return str(p.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(p)


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    vulnintel_store.init_schema()    # module tables live beside the core ones
    c2feed.init_schema()
    vulnintel_service.seed_aliases()  # shipped nicknames, added once, never overwritten
    allowlist.load()                 # Tranco top list, if data/tranco.csv exists
    base.set_client(base.new_client())
    scheduler = Scheduler(feed_catalog(), asyncio.get_running_loop())
    await asyncio.to_thread(scheduler.initialize)
    stopped = asyncio.Event()
    worker = asyncio.create_task(scheduler.serve(stopped)) if settings.scheduled_feeds_enabled else None
    app.state.feed_scheduler = scheduler
    bulk = BulkService(asyncio.get_running_loop())
    app.state.bulk_enrichment = bulk
    bulk_worker = asyncio.create_task(bulk.serve(stopped)) if settings.bulk_enrichment_enabled else None
    from .core import archives
    if settings.archive_root is not None:
        # One bounded page; the runbook describes continuing large maintenance.
        await asyncio.to_thread(archives.maintenance)
    archive_worker = asyncio.create_task(archives.serve(stopped)) if settings.archive_root is not None else None
    try:
        yield
    finally:
        stopped.set()
        if worker is not None:
            # No cancellation of a worker thread, active HTTP or committed saves.
            await worker
        if bulk_worker is not None:
            await bulk_worker
        if archive_worker is not None:
            await archive_worker
        await base.aclose()


app = FastAPI(title="CTI Toolkit", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None)

# Local-only hardening. Only accept requests whose Host header is a loopback
# name; this defeats DNS-rebinding, where a page you visit points a hostname it
# controls at 127.0.0.1 to reach this app as if it were same-origin.
def _allowed_hosts(configured_host: str) -> list[str]:
    """Loopback names the browser may use in the Host header.

    Starlette keeps the square brackets on IPv6 literals, so "::1" must be
    listed as "[::1]". The configured host is included too (bracketed if it is
    IPv6), so config.py's validator and this list can never disagree.
    """
    hosts = ["127.0.0.1", "localhost", "[::1]"]
    h = configured_host if ":" not in configured_host else f"[{configured_host}]"
    if h not in hosts:
        hosts.append(h)
    return hosts


app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts(settings.host))

static_dir = BASE_DIR / "static"
# check_dir=False so a missing (empty, git-ignored) static dir doesn't crash
# startup; it just 404s static requests until there is something to serve.
app.mount("/static", StaticFiles(directory=str(static_dir), check_dir=False), name="static")
app.include_router(vulnintel_routes.router)
app.include_router(infra_routes.router)
app.include_router(saved_routes.router)
app.include_router(alert_routes.router)
app.include_router(ransomware_routes.router)
app.include_router(breach_routes.router)
app.include_router(ct_watch_routes.router)
app.include_router(github_exposure_routes.router)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@app.post("/enrich", response_class=HTMLResponse)
async def enrich(request: Request, indicator: str = Form(...), force: bool = Form(False)):
    # `force` is the "query anyway" checkbox: a browser sends "on" when it is
    # ticked and nothing at all when it is not, which FastAPI turns into a bool.
    reject_cross_site(request)
    raw = indicator.strip()
    if len(raw) > MAX_INDICATOR_LEN:
        return templates.TemplateResponse(
            request, "index.html",
            {"indicator": raw[:80] + "…", "itype": "unknown", "too_long": True},
        )
    value = normalise(raw)
    itype = detect_type(value)
    value = canonical(itype, value)
    results = await registry.enrich_all(itype, value, force=force)
    aggregate = registry.aggregate_verdict(results)
    return templates.TemplateResponse(
        request, "index.html",
        {"indicator": indicator, "value": value, "itype": itype, "force": force,
         "results": results, "aggregate": aggregate},
    )


@app.get("/extract", response_class=HTMLResponse)
def extract_page(request: Request):
    return _extraction_page(request, {})


@app.get("/extract/decoder", response_class=HTMLResponse)
def decoder_page(request: Request):
    return _extraction_page(request, {"extract_tab": "decoder"})


def _extraction_page(request: Request, context: dict, document: Document | None = None, *, status_code: int = 200):
    catalog = attack_catalog.load()
    context.update(catalog_version=catalog.get("version"), decode_modes=decode.MODES)
    context.setdefault("capture_id", uuid4().hex)
    if document is not None:
        content.prepare_text(document)
        context["result"] = extractor.extract(document.indicator_text or "", report_mode=True,
                                               report_references=document.references)
        context["result"].references.extend(document.references)
        content.attach_context(context["result"], document)
        for item in context["result"].by_type("hash"):
            item.context.extend(document.hash_context.get(item.value, []))
        document.text = document.text[:extractor.MAX_TEXT_CHARS]
        context["attack_findings"] = attack.extract(document, catalog)
        context["atlas_findings"] = atlas.extract(document)
        context["attack_layout_limited"] = document.layout_limited
        context["plain_list"] = extractor.plain_list
        context["type_order"] = extractor.TYPE_ORDER
        context.update(artifacts=document.artifacts, images=document.images, recovered=document.recovered, document_format=document.format)
        context["text"], context["url"] = "", ""
    return templates.TemplateResponse(request, "extract.html", context, status_code=status_code)


@app.post("/extract/decode", response_class=HTMLResponse)
async def decode_text(request: Request, encoded: str = Form(""), mode: str = Form("base64")):
    reject_cross_site(request)
    context = {"encoded": encoded[:decode.MAX_INPUT], "decode_mode": mode, "extract_tab": "decoder"}
    try:
        decoded = decode.decode(encoded, mode)
    except ValueError as exc:
        context["error"] = str(exc)
        return _extraction_page(request, context)
    context.update(decoded=decoded, source=f"Local decoding ({decode.MODES[mode]})")
    return _extraction_page(request, context, markdown.parse_document(decoded))


@app.post("/extract/refresh-attack")
async def refresh_attack(request: Request):
    reject_cross_site(request)
    error = await attack_catalog.refresh()
    if not error:
        error = await tlds.refresh()
    if error:
        return _extraction_page(request, {"error": error}, status_code=502)
    return RedirectResponse("/extract", status_code=303)


@app.post("/extract", response_class=HTMLResponse)
async def extract(
    request: Request,
    text: str = Form(""),
    url: str = Form(""),
    file: UploadFile | None = File(None),
    save_report: bool = Form(False),
    capture_id: str = Form(""),
    source_title: str = Form(""),
    publisher: str = Form(""),
    publication_date: str = Form(""),
    observed_at: str = Form(""),
    source_modified_at: str = Form(""),
    provenance_url: str = Form(""),
    sensitivity: str = Form("unknown"),
    tlp: str = Form(""),
    citations: str = Form(""),
):
    """Extract IOCs from whichever input was given: a file, a URL, or text.

    The three inputs are checked in that order so a form with a stale
    textarea and a freshly chosen file does what the analyst meant.
    """
    reject_cross_site(request)
    ctx: dict = {"text": text, "url": url}
    document: Document | None = None
    metadata = None
    if save_report:
        try:
            metadata = saved.ReportMetadata(capture_id=capture_id, title=source_title, publisher=publisher,
                source_url=(provenance_url or (url if not (file and file.filename) else "")).strip() or None,
                source_published_at=None if publication_date.strip().lower() == "unknown" else publication_date.strip() or None,
                publication_unknown=publication_date.strip().lower() == "unknown",
                observed_at=observed_at.strip() or None, sensitivity=sensitivity, tlp=tlp or None,
                source_modified_at=source_modified_at.strip() or None,
                citations=tuple(line.strip() for line in citations.splitlines() if line.strip()))
        except ValueError:
            ctx["error"] = "Saving requires a capture ID, title, publisher, publication date (or unknown), valid dates and credential-free references."
            return _extraction_page(request, ctx, status_code=422)
    raw, origin, media_type = None, "paste", "text/plain"

    if file is not None and file.filename:
        # Read one byte past the cap: if we get it, the file is too big, and
        # we have not pulled the rest of it into memory.
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        raw, origin = data, "file"
        if len(data) > MAX_UPLOAD_BYTES:
            ctx["error"] = f"file too large (over {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)"
        elif data[:5] == b"%PDF-" or (file.filename.lower().endswith(".pdf")):
            document, err = extract_pdf.pdf_document(data)
            if err:
                ctx["error"] = err
            ctx["source"] = f"PDF {file.filename}"
        else:
            body = data.decode("utf-8-sig", errors="replace")
            if file.filename.lower().endswith((".htm", ".html")):
                document = parse_document(body)
            else:
                document = markdown.parse_document(body)
            ctx["source"] = f"file {file.filename}"
    elif url.strip():
        origin = "report"
        document, kind, err = await extract_fetch.fetch_document(url.strip())
        if err:
            ctx["error"] = err
        ctx["source"] = f"{kind or 'page'} at {url.strip()}"
        if document is not None:
            raw, media_type = document.original_bytes, document.media_type
    elif text.strip():
        document = markdown.parse_document(text)
        raw = text.encode("utf-8")
        ctx["source"] = "pasted text"
    else:
        ctx["error"] = "Paste some text, enter a URL, or choose a file."

    if metadata is not None and document is not None and not ctx.get("error"):
        try:
            ctx["saved_report_id"] = await asyncio.to_thread(saved.save, document, raw, metadata, origin=origin,
                collected_at=document.collected_at, media_type=media_type)
        except ValueError:
            ctx["error"] = "Report was not saved. Check input size, source metadata, citation bounds and credential-like content."
    return _extraction_page(request, ctx, document)


@app.get("/health", response_class=HTMLResponse)
async def health(request: Request):
    from .core.archives import health as archive_health
    keys = {
        "virustotal": bool(settings.virustotal_api_key),
        "abuseipdb": bool(settings.abuseipdb_api_key),
        "otx": bool(settings.otx_api_key),
        "shodan": bool(settings.shodan_api_key),
        "urlscan": bool(settings.urlscan_api_key),
        "abusech": bool(settings.abusech_auth_key),
        "greynoise": bool(settings.greynoise_api_key),
        "nvd (optional)": bool(settings.nvd_api_key),
        "github (optional)": bool(settings.github_token),
        "ransomwarelive": bool(settings.ransomwarelive_api_key),
        "vulncheck (optional)": bool(settings.vulncheck_api_key),
    }
    versions = {}
    for pkg in ("fastapi", "httpx", "pydantic", "uvicorn", "jinja2", "pypdf"):
        try:
            versions[pkg] = version(pkg)
        except PackageNotFoundError:
            versions[pkg] = "n/a"
    # Derive the quota table straight from the limiter's config, so adding a
    # vendor there is the only edit needed.
    quotas = {v: rate_limiter.usage(v) for v in sorted(LIMITS)}
    tranco = allowlist.status()
    tranco["path"] = _display_path(tranco["path"])
    return templates.TemplateResponse(
        request, "health.html",
        {"keys": keys, "versions": versions, "quotas": quotas,
         "shodan_account": await shodan.account_info(),
         "tranco": tranco,
         "source_health": await asyncio.to_thread(feed_health, feed_catalog()),
         "scheduled_feeds_enabled": settings.scheduled_feeds_enabled,
         "archive_health": archive_health(),
         "bind": f"{settings.host}:{settings.port}",
         "data_dir": _display_path(settings.data_dir)},
    )
