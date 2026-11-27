"""Explicit bounded saved-report lookup jobs on the existing application loop."""

import asyncio
import json
import re
import time
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field

from ...core import archives, evidence, feed_scope
from ...core.config import settings
from ...core.evidence_models import Citation, Observation
from ...core.feed_scheduler import Feed
from ...core.indicators import canonical, detect_type
from ...core.jobs import Failure, Result, Retry, Runner, Task
from ...core.ratelimit import LIMITS
from ..extract import saved
from . import registry

KEYLESS = ("hashlookup", "internetdb", "rdap", "crtsh")
MODULES = {m.VENDOR: m for mods in registry.VENDORS_BY_TYPE.values() for m in mods}
MODULES["hashlookup"] = registry.HASH_GATE
KEYED = tuple(sorted(set(MODULES) - set(KEYLESS)))

# Explicit provider surfaces, never arbitrary report URLs. RDAP bootstrap
# redirects are restricted to the finite proposed registry routes below.
SURFACES = {
    "hashlookup": r"https://hashlookup\.circl\.lu/lookup/(?:md5|sha1|sha256)/[a-f0-9]+",
    "internetdb": r"https://internetdb\.shodan\.io/[a-fA-F0-9:.]+",
    "rdap": r"https://rdap\.org/(?:domain|ip)/[a-zA-Z0-9.:\-]+",
    "crtsh": r"https://crt\.sh/",
    "virustotal": r"https://www\.virustotal\.com/api/v3/(?:domains|ip_addresses|files|urls)/[a-zA-Z0-9_.:\-]+",
    "abuseipdb": r"https://api\.abuseipdb\.com/api/v2/check",
    "otx": r"https://otx\.alienvault\.com/api/v1/indicators/(?:IPv4|IPv6|domain|file|url)/[a-zA-Z0-9_.:%\-]+/general",
    "shodan": r"https://api\.shodan\.io/shodan/host/[a-fA-F0-9:.]+",
    "greynoise": r"https://api\.greynoise\.io/v3/community/[a-fA-F0-9:.]+",
    "urlscan": r"https://urlscan\.io/api/v1/search/",
    "threatfox": r"https://threatfox-api\.abuse\.ch/api/v1/",
    "urlhaus": r"https://urlhaus-api\.abuse\.ch/v1/(?:url|host|payload)/",
    "malwarebazaar": r"https://mb-api\.abuse\.ch/api/v1/",
    "yaraify": r"https://yaraify-api\.abuse\.ch/api/v1/",
}

# Proposed finite RDAP bootstrap routes. Enabling enrich.rdap requires review
# of this whole listed surface. Unknown registries remain refused, not fetched.
RDAP_REDIRECTS = (
    r"https://rdap\.verisign\.com/(?:com|net)/v1/domain/[a-z0-9.\-]+",
    r"https://rdap\.publicinterestregistry\.org/rdap/domain/[a-z0-9.\-]+",
    r"https://rdap\.arin\.net/registry/ip/[a-fA-F0-9:.]+",
    r"https://rdap\.db\.ripe\.net/ip/[a-fA-F0-9:.]+",
    r"https://rdap\.apnic\.net/ip/[a-fA-F0-9:.]+",
    r"https://rdap\.lacnic\.net/rdap/ip/[a-fA-F0-9:.]+",
    r"https://rdap\.afrinic\.net/rdap/ip/[a-fA-F0-9:.]+",
)


class Params(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    document_id: int = Field(gt=0)
    offset: int = Field(default=0, ge=0, le=1999)
    count: int = Field(default=10, ge=1, le=10)
    providers: tuple[str, ...] = Field(min_length=1, max_length=14)


class BulkScope(feed_scope.Scope):
    def __init__(self, context, provider, budget):
        limits = LIMITS.get(provider, {})
        destinations = (SURFACES[provider],) + (RDAP_REDIRECTS if provider == "rdap" else ())
        feed = Feed("enrich." + provider, "IOC Lookup: " + provider, lambda: None,
                    tuple(re.compile(p) for p in destinations), 3600, 86400,
                    requests=60, bytes=32*1024**2, seconds=120,
                    rpm=limits.get("rpm", 10), rpd=limits.get("rpd", 1000),
                    vendor=provider, method="api", response_bytes=5*1024**2,
                    redirects=3 if provider == "rdap" else 0)
        super().__init__(context, feed)
        self.budget = budget
        self.started = budget["started"]
        self.capture_kind = "api_response"

    def check_sync(self):
        self.context.check()
        if not settings.bulk_enrichment_enabled:
            raise PermissionError("Bulk worker disabled")
        evidence.require_collection(self.feed.source, "api")
        if time.monotonic() - self.started >= self.feed.seconds:
            raise feed_scope.BudgetReached()

    async def reserve(self, url, allowance):
        await self.check()
        if self.budget["requests"] >= 60 or self.budget["bytes"] + allowance > 32*1024**2:
            raise feed_scope.BudgetReached()
        self.budget["requests"] += 1
        self.budget["bytes"] += allowance  # failures retain the full charge
        await super().reserve(url, allowance)

    async def capture(self, url, raw, allowance, *, request_identity="", media_type="application/octet-stream"):
        await super().capture(url, raw, allowance, request_identity=request_identity, media_type=media_type)
        self.budget["bytes"] -= allowance - len(raw)


def _plan(params):
    if len(set(params.providers)) != len(params.providers) or any(p not in MODULES for p in params.providers):
        raise ValueError("Select registered providers once each")
    report = saved.detail(params.document_id)
    if report is None:
        raise ValueError("Save the report first")
    doc = report["document"]
    if doc["sensitivity"] != "public" or doc["tlp"] not in (None, "CLEAR"):
        raise PermissionError("External bulk lookups require a public unrestricted report")
    indicators = [o for o in report["observations"] if o["subject_type"] in ("ip", "domain", "hash", "url")]
    selected = indicators[params.offset:params.offset + params.count]
    if not selected:
        raise ValueError("No indicators in this bounded selection")
    units = []
    for provider in sorted(params.providers, key=lambda p: (p not in KEYLESS, KEYLESS.index(p) if p in KEYLESS else p)):
        for obs in selected:
            itype, value = obs["subject_type"], obs["subject_value"]
            if detect_type(value) != itype or canonical(itype, value) != value:
                raise ValueError("Saved subject is not a canonical lookup indicator")
            if provider != "hashlookup" and MODULES[provider] not in registry.vendors_for(itype):
                continue
            if provider == "hashlookup" and itype != "hash":
                continue
            if archives.secret_material(value.encode()):
                raise PermissionError("Credential-like indicators cannot be submitted")
            if itype == "url":
                parsed = urlsplit(value)
                if parsed.username or any(k in parsed.query.lower() for k in ("token", "secret", "password", "key=")):
                    raise PermissionError("Sensitive URL cannot be submitted")
            units.append((provider, itype, value, saved.digest_json([provider, itype, value])))
    if not units:
        raise ValueError("No applicable providers selected")
    return units


def _safe_result(result):
    # Persist the useful normalized composite, never arbitrary raw JSON/errors.
    value = result.model_dump(exclude={"raw", "error"})
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode()) > 32768 or archives.secret_material(encoded.encode()):
        value["summary"] = {"note": "Provider attributes omitted by local handling limits"}
        value["detection_ratio"] = None
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if archives.secret_material(encoded.encode()):
            raise ValueError("Normalized result contains credential-like metadata")
    return encoded


class Service:
    def __init__(self, loop, *, clock=None):
        self.loop = loop
        self.runner = Runner([Task("reports.enrich", self._handler, params_type=Params,
                                   max_attempts=3, retry_seconds=300)], clock=clock)

    def enqueue(self, params: Params, request_key: str):
        if not settings.bulk_enrichment_enabled:
            raise PermissionError("Enable the bulk worker after approval")
        units = _plan(params)
        for provider in {u[0] for u in units}:
            evidence.require_collection("enrich." + provider, "api")
        work = saved.digest_json([params.model_dump(mode="json"), request_key])
        return self.runner.enqueue("reports.enrich", work, params.model_dump())

    def _handler(self, context, params):
        if not self.loop.is_running():
            raise RuntimeError("Bulk work requires the application loop")
        return asyncio.run_coroutine_threadsafe(self._execute(context, params), self.loop).result()

    def enqueue_all(self, document_id, providers, request_key):
        report = saved.detail(document_id)
        if report is None:
            raise ValueError("Save the report first")
        count = sum(o["subject_type"] in ("ip", "domain", "url", "hash") for o in report["observations"])
        if not count:
            raise ValueError("No enrichable indicators")
        # Validate every bounded selection before creating any work. A repeat
        # uses the same scope keys and resumes partially created batches.
        batches = [Params(document_id=document_id, providers=providers, offset=offset, count=min(10, count-offset))
                   for offset in range(0, count, 10)]
        for params in batches:
            _plan(params)
        return [self.enqueue(params, request_key) for params in batches]

    async def _execute(self, context, params):
        units = await asyncio.to_thread(_plan, params)
        job = await asyncio.to_thread(context.check)
        budget = {"started": time.monotonic(), "requests": 0, "bytes": 0}
        for index, (provider, itype, value, unit_key) in enumerate(units):
            await asyncio.to_thread(context.check)
            previous, known = await asyncio.to_thread(self._prior, job["id"], unit_key, value)
            if not previous:
                scope = BulkScope(context, provider, budget)
                token = feed_scope.current.set(scope)
                try:
                    await scope.check()
                    note = (registry._non_global_ip_note(value) if itype == "ip" else None) or registry._tranco_note(itype, value)
                    if known and json.loads(known)["verdict"] == "clean" and provider != "hashlookup":
                        note = registry._local_note(itype, value, "Known-good file; further providers skipped")
                    async with asyncio.timeout(max(0.001, 120 - (time.monotonic() - budget["started"]))):
                        result = note or await MODULES[provider].lookup(itype, value)
                    await scope.check()
                    if result.status == "quota":
                        raise Retry(Failure.RATE_LIMIT, after_seconds=300)
                    if result.status == "error":
                        raise Retry(Failure.TRANSIENT)
                    captures = [ident for group in scope.captures.values() for ident in group]
                    captured = captures[-1] if captures and not result.cached and result.status == "ok" else None
                    if captured:
                        await asyncio.to_thread(context.retrieved)
                    await asyncio.to_thread(self._save_result, context, params.document_id, provider, itype,
                                            value, unit_key, _safe_result(result), captured)
                except (feed_scope.BudgetReached, TimeoutError):
                    raise Retry(Failure.TRANSIENT) from None
                finally:
                    await scope.drain()
                    feed_scope.current.reset(token)
            if index+1 > job["progress_done"]:
                await asyncio.to_thread(context.progress, index+1, total=len(units), checkpoint={"units_saved": index+1})
        return Result(coverage={"document_id": params.document_id, "offset": params.offset,
                                "count": params.count, "units": len(units)})

    @staticmethod
    def _prior(job_id, unit_key, value):
        with evidence.connect() as conn:
            previous = conn.execute("SELECT 1 FROM evidence_bulk_results WHERE job_id=? AND unit_key=?", (job_id, unit_key)).fetchone()
            known = conn.execute("""SELECT result_json FROM evidence_bulk_results WHERE job_id=?
                AND provider='hashlookup' AND subject_type='hash' AND subject_value=?""", (job_id, value)).fetchone()
        return bool(previous), known[0] if known else None

    @staticmethod
    def _save_result(context, document_id, provider, itype, value, unit_key, encoded, captured):
        job = context.check()
        evidence.require_collection("enrich." + provider, "api")
        if captured:
            evidence.record_observation(Observation(document_id=captured, observation_key=unit_key,
                                                    subject_type=itype, subject_value=value, assertion="reported"))
            evidence.record_citation(Citation(document_id=captured, citation_key="requested-from-report",
                target_reference=f"local report {document_id}", target_document_id=document_id,
                relationship="derived_from", resolution_note="Lookup selected from this saved report's mention"))
        with evidence.connect() as conn, conn:
            conn.execute("INSERT OR IGNORE INTO evidence_bulk_results VALUES (?,?,?,?,?,?,?,?,?)",
                         (job["id"], unit_key, document_id, itype, value, provider,
                          json.loads(encoded)["status"], encoded, captured))

    async def serve(self, stopped):
        while not stopped.is_set():
            if settings.bulk_enrichment_enabled:
                await asyncio.to_thread(self.runner.run_next, registered_only=True)
            try:
                await asyncio.wait_for(stopped.wait(), timeout=2)
            except TimeoutError:
                pass
