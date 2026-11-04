"""
FastAPI application: search page, enrichment route, health page.

Bound to 127.0.0.1 by run.py. On startup the lifespan handler creates the
database schema and opens the one shared HTTP client that every vendor module
reuses; on shutdown it closes that client.
"""

from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .core import db
from .core.allowlist import allowlist
from .core.config import PROJECT_ROOT, settings
from .core.indicators import MAX_INDICATOR_LEN, canonical, detect_type, normalise
from .core.ratelimit import LIMITS, rate_limiter
from .core.templating import templates
from .core.web import reject_cross_site
from .modules.enrich import base, registry, shodan
from .modules.extract import extractor
from .modules.extract import fetch as extract_fetch
from .modules.extract import pdf as extract_pdf
from .modules.vulnerability_intelligence import routes as vulnintel_routes
from .modules.vulnerability_intelligence import service as vulnintel_service
from .modules.vulnerability_intelligence import store as vulnintel_store

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
    vulnintel_service.seed_aliases()  # shipped nicknames, added once, never overwritten
    allowlist.load()                 # Tranco top list, if data/tranco.csv exists
    base.set_client(base.new_client())
    try:
        yield
    finally:
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
    return templates.TemplateResponse(request, "extract.html", {})


@app.post("/extract", response_class=HTMLResponse)
async def extract(
    request: Request,
    text: str = Form(""),
    url: str = Form(""),
    file: UploadFile | None = File(None),
):
    """Extract IOCs from whichever input was given: a file, a URL, or text.

    The three inputs are checked in that order so a form with a stale
    textarea and a freshly chosen file does what the analyst meant.
    """
    reject_cross_site(request)
    ctx: dict = {"text": text, "url": url}
    body: str | None = None

    if file is not None and file.filename:
        # Read one byte past the cap: if we get it, the file is too big, and
        # we have not pulled the rest of it into memory.
        data = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            ctx["error"] = f"file too large (over {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)"
        elif data[:5] == b"%PDF-" or (file.filename.lower().endswith(".pdf")):
            body, err = extract_pdf.pdf_text(data)
            if err:
                ctx["error"] = err
            ctx["source"] = f"PDF {file.filename}"
        else:
            body = data.decode("utf-8", errors="replace")
            ctx["source"] = f"file {file.filename}"
    elif url.strip():
        body, kind, err = await extract_fetch.fetch_text(url.strip())
        if err:
            ctx["error"] = err
        ctx["source"] = f"{kind or 'page'} at {url.strip()}"
    elif text.strip():
        body = text
        ctx["source"] = "pasted text"
    else:
        ctx["error"] = "Paste some text, enter a URL, or choose a file."

    if body is not None:
        ctx["result"] = extractor.extract(body)
        ctx["plain_list"] = extractor.plain_list
        ctx["type_order"] = extractor.TYPE_ORDER
    return templates.TemplateResponse(request, "extract.html", ctx)


@app.get("/health", response_class=HTMLResponse)
async def health(request: Request):
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
         "bind": f"{settings.host}:{settings.port}",
         "data_dir": _display_path(settings.data_dir)},
    )
