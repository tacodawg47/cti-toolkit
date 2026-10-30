"""
FastAPI application: search page, enrichment route, health page.

Bound to 127.0.0.1 by run.py. On startup the lifespan handler creates the
database schema and opens the one shared HTTP client that every vendor module
reuses; on shutdown it closes that client.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .core import db
from .core.config import settings
from .core.indicators import MAX_INDICATOR_LEN, canonical, detect_type, normalise
from .core.ratelimit import LIMITS, rate_limiter
from .modules.enrich import base, registry, shodan

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def _fmt(v):
    """Render a summary value: lists as 'a, b', dicts as 'k: v, ...', else as-is."""
    if isinstance(v, dict):
        return ", ".join(f"{k}: {val}" for k, val in v.items())
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return v


def _ago(iso: str) -> str:
    """Turn an ISO timestamp into a short relative age like '2h ago'."""
    try:
        t = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return ""
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    secs = (datetime.now(timezone.utc) - t).total_seconds()
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


templates.env.filters["fmt"] = _fmt
templates.env.filters["ago"] = _ago


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
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
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

static_dir = BASE_DIR / "static"
# check_dir=False so a missing (empty, git-ignored) static dir doesn't crash
# startup; it just 404s static requests until there is something to serve.
app.mount("/static", StaticFiles(directory=str(static_dir), check_dir=False), name="static")


def _reject_cross_site(request: Request) -> None:
    # Modern browsers tag every request with Sec-Fetch-Site. A form on another
    # website posting here arrives as "cross-site"; reject it so a page you
    # happen to have open cannot spend your API quota on indicators it chooses.
    # Requests without the header (curl, older clients, our tests) are allowed.
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(status_code=403, detail="cross-site requests are not allowed")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@app.post("/enrich", response_class=HTMLResponse)
async def enrich(request: Request, indicator: str = Form(...)):
    _reject_cross_site(request)
    raw = indicator.strip()
    if len(raw) > MAX_INDICATOR_LEN:
        return templates.TemplateResponse(
            request, "index.html",
            {"indicator": raw[:80] + "…", "itype": "unknown", "too_long": True},
        )
    value = normalise(raw)
    itype = detect_type(value)
    value = canonical(itype, value)
    results = await registry.enrich_all(itype, value)
    aggregate = registry.aggregate_verdict(results)
    return templates.TemplateResponse(
        request, "index.html",
        {"indicator": indicator, "value": value, "itype": itype,
         "results": results, "aggregate": aggregate},
    )


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
    }
    versions = {}
    for pkg in ("fastapi", "httpx", "pydantic", "uvicorn", "jinja2"):
        try:
            versions[pkg] = version(pkg)
        except PackageNotFoundError:
            versions[pkg] = "n/a"
    # Derive the quota table straight from the limiter's config, so adding a
    # vendor there is the only edit needed.
    quotas = {v: rate_limiter.usage(v) for v in sorted(LIMITS)}
    return templates.TemplateResponse(
        request, "health.html",
        {"keys": keys, "versions": versions, "quotas": quotas,
         "shodan_account": await shodan.account_info(),
         "bind": f"{settings.host}:{settings.port}",
         "data_dir": str(settings.data_dir)},
    )
