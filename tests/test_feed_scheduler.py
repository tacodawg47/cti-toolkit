"""Offline acceptance for schedules, bridge, quotas, captures and recovery."""

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import io
from pathlib import Path
import re
import sqlite3
import tempfile
import threading
import unittest
import zipfile
from unittest.mock import patch

import httpx

from app.core import db, evidence, feed_schema, feed_scope
from app.core.config import settings
from app.core.evidence_models import Source
from app.core.feed_scheduler import Feed, Scheduler, health
from app.core.jobs import Result, Runner, Task
from app.modules.enrich import base
from app.modules.vulnerability_intelligence import scheduled, store, vendor_notices
from app.modules.vulnerability_intelligence.feeds import kev, nvd_recent, vendors
from app.modules.vulnerability_intelligence.feeds import cvelist, epss
from app.modules.vulnerability_intelligence.http import fetch_bytes

URL = "https://synthetic.invalid/feed"
CATALOG = {"catalogVersion": "2026.11.26", "vulnerabilities": [{
    "cveID": "CVE-2026-12345", "vendorProject": "Synthetic", "product": "Gateway",
    "vulnerabilityName": "Example", "dateAdded": "2026-11-25"}]}


class SimulatedCrash(BaseException):
    pass


class FeedTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.override = patch.object(settings, "data_dir", Path(self.directory.name))
        self.override.start()
        db.init_db()
        store.init_schema()
        self.now = datetime(2026, 11, 26, 17, tzinfo=timezone.utc)
        self.requests = []
        self.clients = []

    async def asyncTearDown(self):
        for client in self.clients:
            await client.aclose()
        base.set_client(None)
        self.override.stop()
        self.directory.cleanup()

    def transport(self, handler):
        def dispatch(request):
            self.requests.append(str(request.url))
            return handler(request)
        client = httpx.AsyncClient(transport=httpx.MockTransport(dispatch))
        self.clients.append(client)
        base.set_client(client)

    def feed(self, refresh=None, **kw):
        async def run():
            status, raw, error = await fetch_bytes(URL, max_bytes=1024)
            if status != 200 or error:
                return {"ok": False}
            data = json.loads(raw)
            if not data.get("entries"):
                return {"ok": False}
            await feed_scope.validated(raw)
            store.set_sync("synthetic_ingested", "yes")
            await feed_scope.validated(raw, ingested=True)
            store.set_feed_status("synthetic", entries=data["entries"], version="test")
            return {"ok": True, "entries": data["entries"]}
        return Feed("synthetic", "Synthetic Feed", refresh or run,
                    (re.compile(re.escape(URL)),), cadence=3600, stale=7200, **kw)

    def source(self, feed, enabled=True):
        source = Source(source_id=feed.source, name=feed.label, source_class="publisher",
                        access_method=feed.method, terms_status="approved", terms_reviewed_on="2026-11-26",
                        terms_reference="Synthetic offline review", rate_limit_notes="Synthetic finite bounds",
                        collection_enabled=enabled)
        evidence.save_source(source)
        return source

    def scheduler(self, feed, *, enable=True):
        scheduler = Scheduler([feed], asyncio.get_running_loop(), clock=lambda: self.now)
        scheduler.initialize()
        if enable:
            self.source(feed)
            scheduler.configure(feed.key, enabled=True)
        return scheduler

    async def step(self, scheduler):
        await asyncio.to_thread(scheduler.step)

    def latest(self, scheduler, key):
        with scheduler.runner._connect() as conn:
            return dict(conn.execute("SELECT * FROM durable_jobs WHERE task=? ORDER BY created_at DESC,id DESC LIMIT 1",
                                     ("feed." + key,)).fetchone())

    def state(self, feed):
        return health([feed], clock=lambda: self.now)[0]

    async def test_default_off_and_review_is_not_schedule_approval(self):
        feed = self.feed()
        scheduler = self.scheduler(feed, enable=False)
        self.source(feed)
        await self.step(scheduler)
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM durable_jobs").fetchone()[0], 0)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.state(feed)["states"], ["Never Loaded", "Incomplete"])
        self.source(feed, enabled=False)
        with self.assertRaises(PermissionError):
            scheduler.configure(feed.key, enabled=True)

    async def test_success_distinct_work_run_capture_and_no_page_poll(self):
        feed = self.feed()
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 2}))
        await self.step(scheduler)
        job = self.latest(scheduler, feed.key)
        self.assertEqual(job["state"], "succeeded")
        self.assertEqual(job["progress_done"], 1)
        self.assertEqual(self.state(feed)["states"], ["Current"])
        with db.connect() as conn:
            doc = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
        run = scheduler.runner.runs(job["id"])[0]
        self.assertEqual(doc["job_run_id"], run["id"])
        self.assertNotEqual(job["id"], run["id"])
        self.assertTrue(doc["content_sha256"])
        self.assertNotEqual(doc["capture_key"], run["id"])
        await self.step(scheduler)
        self.state(feed)
        self.assertEqual(len(self.requests), 1)

    async def test_failed_refresh_retains_last_good_and_coverage_then_recovers(self):
        feed = self.feed()
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 2}))
        await self.step(scheduler)
        before = self.state(feed)
        self.now += timedelta(hours=5)
        self.transport(lambda r: httpx.Response(503))
        await self.step(scheduler)
        state = self.state(feed)
        self.assertIn("Stale", state["states"])
        self.assertIn("Failed", state["states"])
        self.assertEqual(state["coverage_at"], before["coverage_at"])
        self.assertEqual(state["last_retrieval"], before["last_retrieval"])
        self.assertEqual(store.feed_status()[feed.key]["fetched_at"], before["last_retrieval"])
        self.now += timedelta(minutes=6)
        self.transport(lambda r: httpx.Response(200, json={"entries": 3}))
        await self.step(scheduler)
        self.assertEqual(self.state(feed)["states"], ["Current"])

    async def test_429_retry_after_survives_scheduler_restart(self):
        feed = self.feed()
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(429, headers={"Retry-After": "7200"}))
        await self.step(scheduler)
        job = self.latest(scheduler, feed.key)
        self.assertEqual(job["error_code"], "rate_limit")
        self.assertEqual(job["attempts"], 1)
        scheduler = self.scheduler(feed)
        self.now += timedelta(hours=1)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        self.now += timedelta(hours=1)
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler, feed.key)["attempts"], 2)
        self.assertEqual(len(scheduler.runner.runs(job["id"])), 2)
        self.assertEqual(self.state(feed)["states"], ["Current"])

    async def test_downtime_creates_one_due_pass_and_preserves_identity(self):
        feed = self.feed()
        scheduler = self.scheduler(feed)
        await asyncio.to_thread(scheduler.plan)
        ident = self.latest(scheduler, feed.key)["id"]
        self.now += timedelta(days=90)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler, feed.key)["id"], ident)
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM durable_jobs").fetchone()[0], 1)

    async def test_revoked_before_dispatch_and_retry_never_reaches_transport(self):
        feed = self.feed()
        scheduler = self.scheduler(feed)
        scheduler.plan()
        self.source(feed, enabled=False)
        self.transport(lambda r: self.fail("Revoked work reached provider"))
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler, feed.key)["error_code"], "source_ineligible")
        self.assertEqual(self.requests, [])

    async def test_revocation_between_units_stops_next_request(self):
        feed = None
        async def run():
            status, raw, error = await fetch_bytes(URL, max_bytes=1024)
            await feed_scope.validated(raw, ingested=True)
            self.source(feed, enabled=False)
            await fetch_bytes(URL, max_bytes=1024)
            self.fail("Revoked second unit ran")
        feed = self.feed(run)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler, feed.key)["error_code"], "source_ineligible")
        self.assertEqual(self.latest(scheduler, feed.key)["progress_done"], 1)

    async def test_schedule_disable_between_units_is_also_enforced(self):
        scheduler = None
        async def run():
            _, raw, _ = await fetch_bytes(URL, max_bytes=1024)
            await feed_scope.validated(raw, ingested=True)
            scheduler.configure("synthetic", enabled=False)
            await fetch_bytes(URL, max_bytes=1024)
        feed = self.feed(run)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler, feed.key)["state"], "failed")

    async def test_request_budget_leaves_incomplete_checkpoint(self):
        async def run():
            for _ in range(2):
                _, raw, _ = await fetch_bytes(URL, max_bytes=1024)
                await feed_scope.validated(raw, ingested=True)
            return {"ok": True, "entries": 1}
        feed = self.feed(run, requests=1)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        await self.step(scheduler)
        job = self.latest(scheduler, feed.key)
        self.assertEqual(job["progress_done"], 1)
        self.assertIsNone(job["coverage_checkpoint"])
        self.assertIn("Incomplete", self.state(feed)["states"])
        self.assertEqual(len(self.requests), 1)

    async def test_oversized_failure_cannot_renew_success(self):
        feed = self.feed(response_bytes=10)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, content=b"x" * 11))
        await self.step(scheduler)
        self.assertIsNone(self.latest(scheduler, feed.key)["last_retrieval_at"])
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_documents").fetchone()[0], 0)

    async def test_quota_persists_across_new_scheduler_instances(self):
        async def run():
            for _ in range(2):
                await fetch_bytes(URL, max_bytes=1024)
            return {"ok": True, "entries": 1}
        feed = self.feed(run, rpm=1)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        scheduler = self.scheduler(feed)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler, feed.key)["error_code"], "rate_limit")

    async def test_content_and_redirect_cannot_choose_another_destination(self):
        async def run():
            _, raw, _ = await fetch_bytes(URL, max_bytes=1024)
            await fetch_bytes(json.loads(raw)["next"], max_bytes=1024)
        feed = self.feed(run)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"next": "https://untrusted.invalid/secret"}))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler, feed.key)["state"], "failed")

    async def test_real_kev_adapter_keeps_rows_on_empty_malformed_and_outage(self):
        feed = next(feed for feed in scheduled.catalog() if feed.key == "cisa_kev")
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json=CATALOG))
        await self.step(scheduler)
        self.assertEqual(store.kev_count(), 1)
        first = self.state(feed)["coverage_at"]
        self.now += timedelta(days=2)
        self.transport(lambda r: httpx.Response(200, json={"vulnerabilities": []}))
        await self.step(scheduler)
        self.assertEqual(store.kev_count(), 1)
        self.assertEqual(self.state(feed)["coverage_at"], first)
        self.assertIn("Failed", self.state(feed)["states"])

    async def test_nvd_pagination_429_and_verified_capture_replay(self):
        feed = next(feed for feed in scheduled.catalog() if feed.key == "nvd_recent")
        feed = replace(feed, vendor=None, rpm=30)
        scheduler = self.scheduler(feed)
        fail_second = True
        def provider(request):
            offset = int(request.url.params["startIndex"])
            if offset and fail_second:
                return httpx.Response(429, headers={"Retry-After": "600"})
            return httpx.Response(200, json={"totalResults": 2, "startIndex": offset,
                "vulnerabilities": [{"cve": {"id": f"CVE-2026-{12345+offset}", "descriptions": []}}]})
        self.transport(provider)
        with patch.object(nvd_recent, "PAGE", 1):
            await self.step(scheduler)
            job = self.latest(scheduler, feed.key)
            self.assertTrue(store.get_sync(nvd_recent.PENDING))
            self.assertIsNone(store.get_sync(nvd_recent.COMPLETED))
            self.assertEqual(job["progress_done"], 1)
            with db.connect() as conn:
                original = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
            fail_second = False
            self.now += timedelta(minutes=11)
            scheduler = self.scheduler(feed)
            await self.step(scheduler)
        final = self.latest(scheduler, feed.key)
        self.assertEqual(final["id"], job["id"])
        self.assertEqual(final["attempts"], 2)
        self.assertEqual(final["progress_done"], 2)
        self.assertTrue(store.get_sync(nvd_recent.COMPLETED))
        with db.connect() as conn:
            documents = [dict(row) for row in conn.execute("SELECT * FROM evidence_documents ORDER BY id")]
        self.assertEqual(len(documents), 2)
        self.assertEqual(documents[0], original)
        self.assertNotEqual(documents[1]["job_run_id"], original["job_run_id"])

    async def test_interrupted_execution_recovers_after_restart_without_losing_progress(self):
        crashed = False
        async def run():
            nonlocal crashed
            _, raw, _ = await fetch_bytes(URL, max_bytes=1024)
            await feed_scope.validated(raw, ingested=True)
            if not crashed:
                crashed = True
                raise SimulatedCrash()
            return {"ok": True, "entries": 1}
        feed = self.feed(run)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        with self.assertRaises(SimulatedCrash):
            await self.step(scheduler)
        original = self.latest(scheduler, feed.key)
        scheduler = self.scheduler(feed)
        await self.step(scheduler)  # Recover and persist retry delay, no request.
        self.assertEqual(len(self.requests), 1)
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler, feed.key)["progress_done"], 1)
        self.assertEqual([run["state"] for run in scheduler.runner.runs(original["id"])], ["interrupted", "succeeded"])

    async def test_registered_only_worker_does_not_fail_other_modules_jobs(self):
        feed = self.feed()
        scheduler = self.scheduler(feed, enable=False)
        runner = Runner([Task("unrelated", lambda c, p: Result())], clock=lambda: self.now)
        job = runner.enqueue("unrelated", "first")
        await self.step(scheduler)
        self.assertEqual(runner.get(job)["state"], "queued")

    async def test_vendor_partial_queue_resumes_without_replacing_saved_index(self):
        from tests.test_vendor_notices import document
        feed = next(feed for feed in scheduled.catalog() if feed.key == "vendor_redhat")
        feed = replace(feed, requests=2)
        scheduler = self.scheduler(feed)
        def provider(request):
            if request.url.path.endswith("changes.csv"):
                return httpx.Response(200, content=(
                    "2026/rhsa-2026_12345.json,2026-11-26T08:00:00Z\n"
                    "2026/rhsa-2026_12346.json,2026-11-26T08:00:00Z\n").encode())
            ident = "RHSA-2026:" + request.url.path.rsplit("_", 1)[1].removesuffix(".json")
            return httpx.Response(200, json=document(ident))
        self.transport(provider)
        await self.step(scheduler)
        progress = vendor_notices.import_progress("redhat")
        self.assertEqual((progress["pending"], progress["done"]), (1, 1))
        first = self.latest(scheduler, feed.key)
        self.assertIsNone(first["coverage_checkpoint"])
        self.assertEqual(first["progress_done"], 2)  # validated index and one advisory
        first_index = progress["index_checked"]
        self.now += timedelta(hours=7)
        scheduler = self.scheduler(feed)
        await self.step(scheduler)
        progress = vendor_notices.import_progress("redhat")
        self.assertEqual((progress["pending"], progress["done"]), (0, 2))
        self.assertEqual(progress["index_checked"], first_index)
        self.assertEqual(sum(url.endswith("changes.csv") for url in self.requests), 1)
        self.assertIsNotNone(self.state(feed)["coverage_at"])

    async def test_same_loop_client_and_provider_quota_are_shared_with_manual_calls(self):
        from app.core.ratelimit import rate_limiter
        loops, threads, acquired = [], [], []
        async def acquire(vendor):
            loops.append(asyncio.get_running_loop())
            threads.append(threading.get_ident())
            acquired.append(vendor)
        feed = self.feed(vendor="synthetic-provider")
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        loop, thread = asyncio.get_running_loop(), threading.get_ident()
        with patch.object(rate_limiter, "_acquire", acquire):
            await rate_limiter.acquire("synthetic-provider")
            await self.step(scheduler)
            self.now += timedelta(hours=2)
            await self.step(scheduler)
        self.assertEqual(acquired, ["synthetic-provider"] * 3)
        self.assertTrue(all(value is loop for value in loops))
        self.assertEqual(threads, [thread] * 3)

    async def test_shutdown_waits_for_active_saves_and_has_no_detached_work(self):
        began, release, stopped = asyncio.Event(), asyncio.Event(), asyncio.Event()
        async def run():
            _, raw, _ = await fetch_bytes(URL, max_bytes=1024)
            began.set()
            await release.wait()
            await feed_scope.validated(raw, ingested=True)
            return {"ok": True, "entries": 1}
        feed = self.feed(run)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        worker = asyncio.create_task(scheduler.serve(stopped))
        await asyncio.wait_for(began.wait(), 10)
        stopped.set()
        await asyncio.sleep(0)
        self.assertFalse(worker.done())
        release.set()
        await asyncio.wait_for(worker, 10)
        self.assertEqual(self.latest(scheduler, feed.key)["state"], "succeeded")

    async def test_failed_sibling_is_drained_before_runner_releases_ownership(self):
        completed = False
        async def unit(fail):
            nonlocal completed
            _, raw, _ = await fetch_bytes(URL, max_bytes=1024)
            if fail:
                raise ValueError("Synthetic parser failure")
            await asyncio.sleep(0.05)
            await feed_scope.validated(raw, ingested=True)
            completed = True
        async def run():
            await asyncio.gather(unit(True), unit(False))
        feed = self.feed(run)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        await self.step(scheduler)
        self.assertTrue(completed)
        self.assertEqual(self.latest(scheduler, feed.key)["state"], "queued")
        self.assertEqual(self.latest(scheduler, feed.key)["progress_done"], 1)

    async def test_time_and_full_allowance_byte_budgets_prevent_next_unit(self):
        async def run():
            await fetch_bytes(URL, max_bytes=1024)
            await fetch_bytes(URL, max_bytes=1024)
            return {"ok": True, "entries": 1}
        feed = self.feed(run, bytes=1024)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(500))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertIn("Incomplete", self.state(feed)["states"])
        # The guard checks elapsed time at work boundaries, even if the event
        # loop itself was not cancelled while a committed save was finishing.
        feed = replace(feed, key="other", seconds=1)
        scheduler = self.scheduler(feed)
        init = feed_scope.Scope.__init__
        def expired(scope, context, definition):
            init(scope, context, definition)
            scope.started -= 20
        with patch.object(feed_scope.Scope, "__init__", expired):
            await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)

    async def test_provider_daily_quota_is_a_bounded_durable_retry(self):
        from app.core.ratelimit import QuotaExceeded, rate_limiter
        feed = self.feed(vendor="synthetic-provider")
        scheduler = self.scheduler(feed)
        async def exhausted(vendor):
            raise QuotaExceeded("Synthetic daily cap")
        self.transport(lambda r: self.fail("Quota exhaustion reached HTTP"))
        with patch.object(rate_limiter, "_acquire", exhausted):
            await self.step(scheduler)
        job = self.latest(scheduler, feed.key)
        self.assertEqual(job["error_code"], "rate_limit")
        self.assertEqual(datetime.fromisoformat(job["available_at"]), self.now + timedelta(days=1))

    async def test_changed_response_uses_new_capture_without_reinterpreting_original(self):
        first = True
        async def run():
            nonlocal first
            _, raw, _ = await fetch_bytes(URL, max_bytes=1024)
            await feed_scope.validated(raw, ingested=True)
            if first:
                first = False
                raise ValueError("Crash after ingestion")
            return {"ok": True, "entries": 1}
        feed = self.feed(run)
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        await self.step(scheduler)
        with db.connect() as conn:
            original = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
        self.now += timedelta(minutes=6)
        self.transport(lambda r: httpx.Response(200, json={"entries": 2}))
        await self.step(scheduler)
        with db.connect() as conn:
            docs = [dict(row) for row in conn.execute("SELECT * FROM evidence_documents ORDER BY id")]
        self.assertEqual(docs[0], original)
        self.assertEqual(len(docs), 2)
        self.assertNotEqual(docs[0]["content_sha256"], docs[1]["content_sha256"])

    async def test_fresh_retrieval_of_old_nvd_window_keeps_gap_visible(self):
        feed = self.feed(coverage=lambda: {"scope": "modified_window", "through": (self.now-timedelta(days=30)).isoformat()})
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, json={"entries": 1}))
        await self.step(scheduler)
        self.assertIn("Stale", self.state(feed)["states"])
        self.assertIn("Incomplete", self.state(feed)["states"])

    async def test_c2_atomic_snapshot_rejects_empty_without_deleting_prior_rows(self):
        from app.modules.infrastructure import c2feed
        c2feed.init_schema()
        feed = next(feed for feed in scheduled.catalog() if feed.key == "c2intel")
        scheduler = self.scheduler(feed)
        def provider(request):
            domain = "domain" in request.url.path
            return httpx.Response(200, content=("#domain,ioc\nexample.invalid,Example\n" if domain else "#ip,ioc\n8.8.8.8,Example\n").encode())
        self.transport(provider)
        await self.step(scheduler)
        before = c2feed.page("", "all", 1)
        self.assertEqual(before["total"], 3)
        self.now += timedelta(hours=7)
        self.transport(lambda r: httpx.Response(200, content=b"#ip,ioc\n"))
        await self.step(scheduler)
        self.assertEqual(c2feed.page("", "all", 1)["total"], before["total"])
        self.assertEqual(self.state(feed)["last_good_at"], before["status"]["fetched_at"])

    async def test_cve_delta_validation_failure_retains_exact_source_checkpoint(self):
        store.set_sync(cvelist.SYNC_KEY, "2026-11-26 midnight")
        feed = next(feed for feed in scheduled.catalog() if feed.key == "cvelist")
        scheduler = self.scheduler(feed)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("CVE-2026-12345.json", b'{"cveMetadata": null}')
        self.transport(lambda r: httpx.Response(200, content=output.getvalue()))
        with patch.object(cvelist, "_today", return_value=self.now.date()):
            await self.step(scheduler)
        self.assertEqual(store.get_sync(cvelist.SYNC_KEY), "2026-11-26 midnight")
        self.assertIsNone(self.latest(scheduler, feed.key)["coverage_checkpoint"])
        self.assertIsNone(self.latest(scheduler, feed.key)["last_retrieval_at"])

    async def test_cve_initial_reload_gate_never_invokes_manual_full_load(self):
        feed = next(feed for feed in scheduled.catalog() if feed.key == "cvelist")
        scheduler = self.scheduler(feed, enable=False)
        self.source(feed)
        with self.assertRaisesRegex(ValueError, "Initial Load"):
            scheduler.configure(feed.key, enabled=True)
        self.transport(lambda r: self.fail("Initial load reached provider"))
        await self.step(scheduler)
        self.assertEqual(self.requests, [])

    async def test_cve_official_redirect_is_bounded_and_other_hosts_are_refused(self):
        async def run():
            status, raw, error = await fetch_bytes(URL, max_bytes=1024)
            return {"ok": status == 200, "entries": 1}
        feed = replace(self.feed(run, redirects=1), destinations=(re.compile(re.escape(URL)), re.compile(r"https://assets\.invalid/fixed")))
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(302, headers={"location": "https://untrusted.invalid/steal"}))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler, feed.key)["state"], "failed")
        self.now += timedelta(hours=2)
        self.transport(lambda r: httpx.Response(302, headers={"location": "https://assets.invalid/fixed"}) if r.url.host == "synthetic.invalid" else httpx.Response(200, json={"entries": 1}))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 3)
        self.assertEqual(self.latest(scheduler, feed.key)["state"], "succeeded")

    async def test_daily_score_date_is_preserved_and_old_score_snapshot_stays_stale(self):
        from tests.test_vulnintel import epss_gz
        feed = next(feed for feed in scheduled.catalog() if feed.key == "epss")
        scheduler = self.scheduler(feed)
        self.transport(lambda r: httpx.Response(200, content=epss_gz([("CVE-2026-12345", "0.1", "0.5")], "2026-11-01T12:00:00Z")))
        await self.step(scheduler)
        self.assertIn("Stale", self.state(feed)["states"])
        self.assertIn("2026-11-01", self.state(feed)["coverage"])

    async def test_freshness_states_render_at_consuming_pages_and_health(self):
        from fastapi.testclient import TestClient
        from app.main import app
        def pages():
            with patch.object(settings, "scheduled_feeds_enabled", False), TestClient(app, base_url="http://127.0.0.1") as client:
                for path in ("/health", "/vulnerability-intelligence", "/vulnerability-intelligence/feeds",
                             "/vulnerability-intelligence/vendor-updates", "/vulnerability-intelligence/views/known-exploited", "/infrastructure"):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200, path)
                    self.assertIn("Source Freshness and Coverage", response.text)
                    self.assertIn("Never Loaded", response.text)
                    self.assertIn("Incomplete", response.text)
                    self.assertIn("Last-Good Snapshot Age", response.text)
        await asyncio.to_thread(pages)


class MigrationTests(unittest.TestCase):
    def test_transactional_migration_rollback_and_future_version_refusal(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        with patch.object(feed_schema, "MIGRATIONS", ((1, feed_schema.VERSION_1 + "; INSERT INTO absent VALUES(1);"),)):
            with self.assertRaises(sqlite3.OperationalError):
                feed_schema.migrate(conn)
        self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='feed_schedules'").fetchone())
        feed_schema.migrate(conn)
        feed_schema.migrate(conn)
        conn.execute("INSERT INTO feed_schema_versions VALUES (99,'synthetic')")
        conn.commit()
        with self.assertRaises(RuntimeError):
            feed_schema.migrate(conn)

    def test_catalog_has_individual_cadences_and_excludes_initial_reload_destinations(self):
        feeds = scheduled.catalog()
        self.assertEqual(len(feeds), 31)
        self.assertEqual(len({feed.key for feed in feeds}), len(feeds))
        self.assertGreater(len({feed.cadence for feed in feeds}), 3)
        for feed in feeds:
            self.assertGreater(feed.stale, feed.cadence)
            self.assertFalse(feed.permits("https://untrusted.invalid/execute"))
        cve = next(feed for feed in feeds if feed.key == "cvelist")
        self.assertFalse(cve.permits("https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-11-26_0000Z/2026-11-26_all_CVEs_at_midnight.zip.zip"))
