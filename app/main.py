"""
FastAPI application: search page, enrichment route, health page.

Bound to 127.0.0.1 by run.py. The database schema is created on startup via
the lifespan handler.
"""

from contextlib import asynccontextmanager
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
from .core.indicators import detect_type, refang
from .core.ratelimit import rate_limiter
from .modules.enrich import registry, shodan

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="CTI Toolkit", version=__version__, lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None)

# Local-only hardening. Only accept requests whose Host header is a loopback
# name; this defeats DNS-rebinding, where a page you visit points a hostname it
# controls at 127.0.0.1 to reach this app as if it were same-origin.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


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
    value = refang(indicator)
    itype = detect_type(value)
    results = await registry.enrich_all(itype, value)
    return templates.TemplateResponse(
        request, "index.html",
        {"indicator": indicator, "value": value, "itype": itype, "results": results},
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
    # Daily usage for the vendors that carry a tracked cap.
    quotas = {
        v: rate_limiter.usage(v)
        for v in ("virustotal", "abuseipdb", "shodan", "urlscan", "greynoise")
    }
    return templates.TemplateResponse(
        request, "health.html",
        {"keys": keys, "versions": versions, "quotas": quotas,
         "shodan_account": await shodan.account_info(),
         "bind": f"{settings.host}:{settings.port}",
         "data_dir": str(settings.data_dir)},
    )
