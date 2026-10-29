"""
FastAPI application: search page, enrichment route, health page.

Bound to 127.0.0.1 by run.py. The database schema is created on startup via
the lifespan handler.
"""

from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__
from .core import db
from .core.config import settings
from .core.indicators import detect_type, refang
from .core.ratelimit import rate_limiter
from .modules.enrich import registry

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    yield


app = FastAPI(title="CTI Toolkit", version=__version__, lifespan=lifespan,
              docs_url="/api/docs", redoc_url=None)

static_dir = BASE_DIR / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {})


@app.post("/enrich", response_class=HTMLResponse)
async def enrich(request: Request, indicator: str = Form(...)):
    value = refang(indicator)
    itype = detect_type(value)
    results = await registry.enrich_all(itype, value)
    return templates.TemplateResponse(
        request, "index.html",
        {"indicator": indicator, "value": value, "itype": itype, "results": results},
    )


@app.get("/health", response_class=HTMLResponse)
def health(request: Request):
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
        {"keys": keys, "versions": versions,
         "quotas": quotas, "settings": settings},
    )
