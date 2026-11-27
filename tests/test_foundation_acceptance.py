"""Cross-feature 5F.5 acceptance. All providers are synthetic MockTransport.

The synthetic adapter deliberately crashes between evidence and progress and
reuses the existing scoped transport, runner, archive and observation APIs.
It is not a new production feed integration or a terms/activation decision.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from app.core import alerts, archives, db, evidence, feed_scope
from app.core.config import settings
from app.core.evidence_models import Citation, Observation, Source
from app.core.feed_scheduler import Feed, Scheduler, health
from app.modules.enrich import base
from app.modules.vulnerability_intelligence import store
from app.modules.vulnerability_intelligence.http import fetch_bytes

URL = "https://foundation.invalid/report"
BODY = {"indicator": "bad.example", "published": "2026-11-20", "observed": "2026-11-18"}


class Interrupted(BaseException):
    pass


class FoundationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name, value in {"data_dir": self.root, "scheduled_feeds_enabled": False,
                            "bulk_enrichment_enabled": False, "archive_enabled": False, "archive_root": None}.items():
            self.setting(name, value)
        db.init_db()
        store.init_schema()
        self.now = datetime(2026, 11, 26, 17, tzinfo=timezone.utc)
        self.requests = []
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.dispatch))
        base.set_client(self.client)
        self.addAsyncCleanup(self.client.aclose)
        self.addCleanup(base.set_client, None)
        self.status = 200
        self.crash = False
        self.after_response = lambda: None
        self.selector = alerts.add_selector(alerts.Selector(subject_type="domain", value="bad.example"))
        self.feed = Feed("foundation", "Synthetic Foundation", self.refresh,
                         (re.compile(re.escape(URL)),), cadence=3600, stale=7200, requests=2)
        evidence.save_source(Source(source_id=self.feed.source, name=self.feed.label, source_class="publisher",
            access_method="feed", terms_status="approved", terms_reviewed_on="2026-11-26",
            terms_reference="Synthetic test only", rate_limit_notes="Synthetic finite bounds", collection_enabled=True))

    def setting(self, name, value):
        override = patch.object(settings, name, value)
        override.start()
        self.addCleanup(override.stop)

    def dispatch(self, request):
        self.requests.append(str(request.url))
        if self.status == 0:
            raise httpx.ConnectError("Synthetic offline startup")
        return httpx.Response(self.status, json=BODY, headers={"Retry-After": "600"})

    async def refresh(self):
        status, raw, error = await fetch_bytes(URL, max_bytes=1024)
        if status != 200 or error:
            return {"ok": False}
        scope = feed_scope.current.get()
        data = json.loads(raw)
        self.after_response()
        await scope.check()  # Current eligibility and cancellation at ingestion boundary.
        document = next(iter(scope.captures[sha256(raw).hexdigest()]))
        # Source dates are explicit assertions, not derived from local capture time.
        await asyncio.to_thread(evidence.record_observation, Observation(document_id=document,
            observation_key="reported-domain", subject_type="domain", subject_value=data["indicator"],
            assertion="reported", observed_at=data["observed"], locator="synthetic report row"))
        await asyncio.to_thread(evidence.record_citation, Citation(document_id=document, citation_key="literal",
            target_reference="https://primary.invalid/report?edition=2#claim"))
        if self.crash:
            self.crash = False
            raise Interrupted()
        await feed_scope.validated(raw, ingested=True)
        store.set_feed_status(self.feed.key, entries=1, version=data["published"])
        return {"ok": True, "entries": 1}

    def scheduler(self):
        result = Scheduler([self.feed], asyncio.get_running_loop(), clock=lambda: self.now)
        result.initialize()
        result.configure(self.feed.key, enabled=True)
        return result

    async def step(self, scheduler):
        await asyncio.to_thread(scheduler.step)

    def latest(self, scheduler):
        with scheduler.runner._connect() as conn:
            return dict(conn.execute("SELECT * FROM durable_jobs ORDER BY created_at DESC,id DESC LIMIT 1").fetchone())

    def state(self):
        return health([self.feed], clock=lambda: self.now)[0]

    async def test_interrupted_capture_alert_progress_and_origin_survive_restart(self):
        scheduler = self.scheduler()
        self.crash = True
        with self.assertRaises(Interrupted):
            await self.step(scheduler)
        first_job = self.latest(scheduler)
        first_alert = alerts.inbox()[0]
        first_detail = alerts.detail(first_alert["id"])
        self.assertEqual(first_job["progress_done"], 0)
        self.assertIsNone(first_job["coverage_checkpoint"])
        alerts.review(first_alert["id"], "reviewed", 0)
        scheduler = self.scheduler()
        await self.step(scheduler)  # Recovery persists delay, no request.
        self.assertEqual(len(self.requests), 1)
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        job = self.latest(scheduler)
        self.assertEqual(job["id"], first_job["id"])
        self.assertEqual((job["attempts"], job["progress_done"], job["state"]), (2, 1, "succeeded"))
        self.assertEqual(len(alerts.inbox()), 1)
        value = alerts.detail(first_alert["id"])
        self.assertEqual(value["alert"]["state"], "reviewed")
        self.assertEqual(value["document"], first_detail["document"])
        self.assertEqual(value["observation"]["observed_at"], "2026-11-18")
        self.assertIsNone(value["document"]["source_published_at"])  # Not copied from transport or version.
        self.assertEqual(value["citations"][0]["target_reference"], "https://primary.invalid/report?edition=2#claim")
        runs = scheduler.runner.runs(job["id"])
        self.assertEqual([r["state"] for r in runs], ["interrupted", "succeeded"])
        self.assertEqual(value["document"]["job_run_id"], runs[0]["id"])
        self.assertEqual(value["execution"]["state"], "interrupted")
        self.assertEqual(value["execution"]["job_state"], "succeeded")

    async def test_failed_refresh_old_data_and_staleness_render_at_consumers_without_http(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        good = self.state()
        self.now += timedelta(hours=3)
        self.status = 503
        await self.step(scheduler)
        state = self.state()
        self.assertIn("Stale", state["states"])
        self.assertIn("Failed", state["states"])
        self.assertIn("Incomplete", state["states"])
        self.assertEqual(state["last_good_at"], good["last_good_at"])
        self.assertEqual(state["coverage_at"], good["coverage_at"])
        self.assertEqual(len(alerts.inbox()), 1)
        count = len(self.requests)
        from app.main import app
        from app.modules.alerts import routes as alert_routes
        from app.modules.vulnerability_intelligence import routes as vuln_routes, scheduled
        panel = [state]
        def pages():
            with patch.object(alert_routes, "health", return_value=panel), patch.object(vuln_routes, "feed_health", return_value=panel), \
                 patch.object(scheduled, "catalog", return_value=[self.feed]), \
                 patch("app.modules.infrastructure.routes.feed_health", return_value=panel), \
                 patch("app.main.feed_health", return_value=panel), TestClient(app, base_url="http://127.0.0.1") as client:
                for path in ("/alerts", "/health", "/vulnerability-intelligence", "/vulnerability-intelligence/feeds",
                             "/vulnerability-intelligence/vendor-updates", "/vulnerability-intelligence/views/known-exploited",
                             "/vulnerability-intelligence/supply-chain", "/infrastructure"):
                    result = client.get(path)
                    self.assertEqual(result.status_code, 200, path)
                    for text in ("Source Freshness and Coverage", "Stale", "Failed", "Incomplete", good["last_good_at"]):
                        self.assertIn(text, result.text, path)
        await asyncio.to_thread(pages)
        self.assertEqual(len(self.requests), count)

    async def test_offline_first_start_then_recovery_keeps_never_loaded_honest(self):
        scheduler = self.scheduler()
        self.status = 0
        await self.step(scheduler)
        self.assertIn("Never Loaded", self.state()["states"])
        self.assertIsNone(self.state()["last_good_at"])
        self.assertEqual(alerts.inbox(), [])
        self.now += timedelta(minutes=6)
        self.status = 200
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.state()["states"], ["Current"])
        self.assertEqual(len(alerts.inbox()), 1)

    async def test_429_cooldown_persists_and_cancelled_retry_never_resets_history(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.now += timedelta(hours=2)
        self.status = 429
        await self.step(scheduler)
        job = self.latest(scheduler)
        count = len(self.requests)
        scheduler = self.scheduler()
        self.now += timedelta(minutes=5)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), count)
        self.assertEqual(len(alerts.inbox()), 1)
        scheduler.runner.cancel(job["id"])
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.assertEqual(scheduler.runner.get(job["id"])["state"], "cancelled")
        self.assertEqual(len(self.requests), count)
        self.assertEqual(len(alerts.inbox()), 1)

    async def test_cancellation_and_source_revocation_between_capture_and_ingestion(self):
        scheduler = self.scheduler()
        self.after_response = lambda: scheduler.runner.cancel(self.latest(scheduler)["id"])
        await self.step(scheduler)
        job = self.latest(scheduler)
        self.assertEqual(job["state"], "cancelled")
        self.assertEqual(alerts.inbox(), [])
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_documents").fetchone()[0], 1)
        self.now += timedelta(hours=2)
        def revoke():
            source = evidence.get_source(self.feed.source)
            evidence.save_source(source.model_copy(update={"collection_enabled": False}))
        self.after_response = revoke
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")
        self.assertEqual(alerts.inbox(), [])

    async def test_downtime_and_daily_quota_keep_prior_alert_and_coverage(self):
        from dataclasses import replace
        self.feed = replace(self.feed, rpd=1)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.now += timedelta(hours=4)
        scheduler = self.scheduler()
        await self.step(scheduler)
        job = self.latest(scheduler)
        self.assertEqual(job["error_code"], "rate_limit")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(len(alerts.inbox()), 1)
        self.assertIn("Stale", self.state()["states"])
        # A full day of downtime creates one pass, without replaying missed ticks.
        self.now += timedelta(days=1, minutes=1)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.latest(scheduler)["id"], job["id"])
        self.assertEqual(len(alerts.inbox()), 2)  # New acquisition, separate assertion.

    async def test_archive_reconciliation_after_restart_preserves_evidence_and_review(self):
        for name, value in {"archive_enabled": True, "archive_root": self.root / "originals",
                            "archive_response_bytes": 1024, "archive_source_bytes": 2048,
                            "archive_total_bytes": 4096, "archive_retention_seconds": 60,
                            "archive_public_sources": [self.feed.source]}.items():
            self.setting(name, value)
        scheduler = self.scheduler()
        await self.step(scheduler)
        ident = alerts.inbox()[0]["id"]
        alerts.review(ident, "dismissed", 0)
        value = alerts.detail(ident)
        self.assertEqual(value["archive"]["state"], "stored")
        (self.root / "originals" / value["archive"]["storage_key"]).unlink()
        db.init_db()
        archives.reconcile(verify=True)
        after = alerts.detail(ident)
        self.assertEqual(after["archive"]["state"], "failed")
        self.assertEqual(after["document"], value["document"])
        self.assertEqual(after["citations"], value["citations"])
        self.assertEqual(after["alert"]["state"], "dismissed")
        self.assertEqual(len(self.requests), 1)
