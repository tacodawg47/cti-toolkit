"""3A.5 acceptance: temporary databases and synthetic HTTP only."""
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import httpx
from fastapi.testclient import TestClient
from app.core import alerts, db, evidence, feed_scope
from app.core.config import settings
from app.core.evidence_models import Source
from app.core.feed_scheduler import Scheduler
from app.modules.enrich import base
from app.modules.subdomains import ctlogs, models, schema, store
from app.modules.vulnerability_intelligence import store as vulnerability_store


def item(name="a.example.invalid", **changes):
    return {"host": name, "certs": 2, "first_seen": "2025-02-01T00:00:00Z",
        "last_seen": "2026-01-01T01:00:00+01:00", "last_not_after": "2027-01-01T00:00:00Z", **changes}


def body(items=None, **changes):
    return {"hosts": [item()] if items is None else items, "has_next": False,
        "next_cursor": "", "history_window_days": 90, **changes}


class Crash(BaseException):
    pass


class ModelTests(unittest.TestCase):
    def test_exact_boundaries_wildcards_and_injection(self):
        self.assertEqual(models.selector("EXAMPLE.invalid."), "example.invalid")
        self.assertEqual(models.selector("bücher.invalid"), "xn--bcher-kva.invalid")
        for name in ("example.invalid", "a.example.invalid", "a.b.example.invalid", "*.example.invalid", "*.a.example.invalid"):
            self.assertTrue(models.within(name, "example.invalid"))
        for name in ("badexample.invalid", "example.invalid.attacker.invalid", "a.other.invalid"):
            self.assertFalse(models.within(name, "example.invalid"))
            with self.assertRaises(ValueError):
                models.parse(json.dumps(body([item(name)])).encode(), "example.invalid")
        for seed in ("*.example.invalid", "https://example.invalid", "example.invalid:443", "a..invalid", "127.0.0.1", "example.invalid?x=y", "a。invalid", " example.invalid"):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                models.selector(seed)
        with self.assertRaises(ValueError):
            alerts.Selector(subject_type="subdomain_domain", mode="domain_tree", value="example.invalid")

    def test_literal_fields_unknown_dates_minimization_and_shapes(self):
        value = models.parse(json.dumps(body([item("*.EXAMPLE.invalid.", ignored="discard")])).encode(), "example.invalid")
        self.assertEqual(value.leads[0].host, "*.EXAMPLE.invalid.")
        self.assertEqual(value.leads[0].canonical, "*.example.invalid")
        self.assertEqual(value.leads[0].last_seen, item()["last_seen"])
        self.assertNotIn("ignored", value.model_dump_json())
        self.assertIsNone(models.Lead(host="a.example.invalid", certs=1).first_seen)
        for rows in ([], None):
            self.assertEqual(models.parse(json.dumps(body(hosts=rows)).encode(), "example.invalid").leads, ())
        for change in ({"hosts": "x"}, {"has_next": 1}, {"history_window_days": 365}, {"has_next": True}, {"next_cursor": "dangling"}, {"hosts": [item(certs=True)]}, {"hosts": [item(first_seen="2026-01-01")]}, {"hosts": [item(first_seen="2030-01-01T00:00:00Z")]}, {"hosts": [item("*.*.example.invalid")]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                models.parse(json.dumps(body(**change)).encode(), "example.invalid")
        for raw in (b'{"hosts":[],"hosts":[]}', json.dumps(body([item()]*101)).encode()):
            with self.assertRaises(ValueError):
                models.parse(raw, "example.invalid")

    def test_cursor_bounds_and_partial_flags(self):
        for token in ("https://evil.invalid/", "x\ny", "x"*2049, "x&key=bad"):
            with self.assertRaises(ValueError):
                models.parse(json.dumps(body(has_next=True, next_cursor=token)).encode(), "example.invalid")
        self.assertTrue(models.parse(json.dumps(body(truncated=True)).encode(), "example.invalid").partial)


class ConsumerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for key, value in {"data_dir": self.root, "archive_enabled": False, "archive_root": None,
                "scheduled_feeds_enabled": False, "bulk_enrichment_enabled": False,
                "ctlogs_api_key": "synthetic-inventory-key", "ctlogs_access_tier": "free_noncommercial"}.items():
            self.override(settings, key, value)
        db.init_db()
        vulnerability_store.init_schema()
        self.now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        self.responses = {1: body()}
        self.status, self.media, self.raw, self.headers = 200, "application/json", None, {}
        self.requests = []
        self.after_response = lambda: None
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.dispatch))
        base.set_client(self.client)
        self.addAsyncCleanup(self.client.aclose)
        self.addCleanup(base.set_client, None)
        self.feed = ctlogs.catalog()[0]
        self.source = Source(source_id=ctlogs.KEY, name="Synthetic CT inventory", source_class="legitimate_platform", access_method="api",
            terms_status="approved", terms_reviewed_on="2026-11-27", terms_reference="Synthetic fixture only",
            rate_limit_notes="Synthetic limits only", collection_enabled=True)
        evidence.save_source(self.source)
        self.selector = alerts.add_selector(alerts.Selector(subject_type="subdomain_domain", value="example.invalid"))
        self.permission = self.approve(self.selector)

    def override(self, obj, key, value):
        patched = patch.object(obj, key, value)
        patched.start()
        self.addCleanup(patched.stop)

    def approve(self, ident):
        return store.approve(ident, authority_reference="synthetic-use-and-domain-authority", purpose="synthetic monitoring", expires_at="2029-01-01T00:00:00Z")

    def dispatch(self, request):
        self.assertEqual(request.url.host, "api.ctlogs.dev")
        self.assertEqual(request.method, "GET")
        self.assertTrue(request.url.path.startswith("/v1/hosts/"))
        self.assertEqual(request.headers["authorization"], "Bearer synthetic-inventory-key")
        self.assertEqual(request.headers["accept"], "application/json")
        self.assertEqual(set(request.url.params), {"after"} if "after" in request.url.params else set())
        if "after" in request.url.params:
            self.assertEqual(request.url.params["after"], "opaque_2==")
        self.requests.append(request)
        self.after_response()
        if self.status == 0:
            raise httpx.ConnectError("private synthetic error")
        page = 2 if "after" in request.url.params else 1
        raw = self.raw if self.raw is not None else json.dumps(self.responses[page]).encode()
        return httpx.Response(self.status, content=raw, headers={"Content-Type": self.media,
            "Location": "https://evil.invalid/", "Link": '<https://evil.invalid/>; rel="next"', **self.headers})

    def scheduler(self, feed=None, *, enabled=True):
        scheduler = Scheduler([feed or self.feed], asyncio.get_running_loop(), clock=lambda: self.now)
        scheduler.initialize()
        if enabled:
            scheduler.configure(ctlogs.KEY, enabled=True)
        return scheduler

    async def step(self, scheduler):
        await asyncio.to_thread(scheduler.step)

    def latest(self, scheduler):
        with scheduler.runner._connect() as conn:
            return dict(conn.execute("SELECT * FROM durable_jobs ORDER BY created_at DESC,id DESC LIMIT 1").fetchone())

    def count(self, table):
        with evidence.connect() as conn:
            return conn.execute("SELECT count(*) FROM "+table).fetchone()[0]

    def watch(self):
        return store.watches(self.now)[0]

    def two_pages(self):
        self.responses = {1: body([item("*.example.invalid"), item("a.example.invalid")], has_next=True, next_cursor="opaque_2=="), 2: body([item("b.example.invalid")])}

    async def restart(self, scheduler):
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
    async def test_atomic_rollback_staged_recovery_preserves_original_capture(self):
        scheduler = self.scheduler()
        with patch.object(alerts, "match_observation", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        self.assertEqual(self.count("subdomain_inventory_leads"), 0)
        self.assertEqual(self.count("evidence_alerts"), 0)
        with evidence.connect() as conn:
            original = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
        self.responses[1] = body([item("b.example.invalid")])
        await self.restart(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        result = store.capture(original["id"])
        self.assertEqual(result["document"]["job_run_id"], original["job_run_id"])
        self.assertEqual(self.watch()["last_good"], original["collected_at"])
        self.assertEqual(result["leads"][0]["lead"]["host"], item()["host"])


    async def test_crash_after_ingestion_before_finish_repairs_progress_and_reviews(self):
        scheduler = self.scheduler()
        with patch.object(store, "finish", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "reviewed", 0)
        await self.restart(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler)["progress_done"], 1)
        self.assertEqual(alerts.detail(first["id"])["alert"]["revision"], 1)


    async def test_crash_before_stage_refetches_same_bytes_under_original_capture(self):
        scheduler = self.scheduler()
        with patch.object(store, "stage", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        with evidence.connect() as conn:
            original = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
        await self.restart(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.count("evidence_documents"), 1)
        self.assertEqual(evidence.get_document(original["id"]), original)


    async def test_revoked_response_or_staged_input_never_uses_replacement_permission(self):
        scheduler = self.scheduler()
        with patch.object(store, "ingest", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        store.revoke(self.permission)
        replacement = self.approve(self.selector)
        await self.restart(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("subdomain_inventory_leads"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT permission_id FROM subdomain_inventory_units").fetchone()[0], self.permission)
        self.assertNotEqual(replacement, self.permission)


    async def test_response_revocation_refuses_capture(self):
        self.after_response = lambda: store.revoke(self.permission)
        await self.step(self.scheduler())
        self.assertEqual(self.count("evidence_documents"), 0)


    async def test_empty_plan_does_not_gain_later_permissions_same_job(self):
        store.revoke(self.permission)
        scheduler = self.scheduler()
        original = store.plan
        def stop(scope):
            original(scope)
            raise Crash()
        with patch.object(store, "plan", stop), self.assertRaises(Crash):
            await self.step(scheduler)
        self.approve(self.selector)
        await self.restart(scheduler)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.count("subdomain_inventory_units"), 0)


    async def test_second_page_rechecks_selector(self):
        self.two_pages()
        original = store.ingest
        def disable(scope, page):
            original(scope, page)
            alerts.set_enabled(self.selector, False)
        with patch.object(store, "ingest", disable):
            await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("subdomain_inventory_leads"), 2)


    async def test_source_and_schedule_disable_after_response_stop_capture(self):
        scheduler = self.scheduler()
        self.after_response = lambda: scheduler.configure(ctlogs.KEY, enabled=False)
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)
        scheduler.configure(ctlogs.KEY, enabled=True)
        self.now += timedelta(days=1, seconds=1)
        self.after_response = lambda: evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)


    async def test_cancellation_mid_request_is_terminal(self):
        scheduler = self.scheduler()
        self.after_response = lambda: scheduler.runner.cancel(self.latest(scheduler)["id"])
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "cancelled")
        self.assertEqual(self.count("subdomain_inventory_leads"), 0)


    async def test_durable_daily_quota_and_byte_budget_prevent_transport(self):
        scheduler = self.scheduler(replace(self.feed, rpd=1))
        with evidence.connect() as conn, conn:
            conn.execute("INSERT INTO feed_request_usage VALUES ('ctlogs_hosts',?)", (self.now.timestamp(),))
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.latest(scheduler)["error_code"], "rate_limit")
        self.now += timedelta(days=2)
        await self.step(self.scheduler(replace(self.feed, bytes=1)))
        self.assertEqual(self.requests, [])


    async def test_request_budget_retains_first_page_incomplete(self):
        self.two_pages()
        scheduler = self.scheduler(replace(self.feed, requests=1))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("subdomain_inventory_leads"), 2)
        self.assertTrue(self.watch()["incomplete"])
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])


    async def test_empty_success_then_failed_stale_keeps_prior_age(self):
        self.responses[1] = body([])
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.watch()["state"], "Current")
        good = self.watch()["last_good"]
        self.status = 0
        self.now += timedelta(days=3)
        await self.step(scheduler)
        self.assertEqual(self.watch()["state"], "Stale")
        self.assertEqual(self.watch()["last_good"], good)
        self.assertTrue(self.watch()["incomplete"])


    async def test_downtime_plans_one_pass_and_no_unapproved_source(self):
        self.now += timedelta(days=60)
        scheduler = self.scheduler()
        await self.step(scheduler)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        evidence.save_source(Source(source_id=ctlogs.KEY, name="Unreviewed"))
        with self.assertRaises(PermissionError):
            scheduler.configure(ctlogs.KEY, enabled=True)


    async def test_eligibility_at_ingestion_row_boundary_rolls_back_all_matches(self):
        self.responses[1] = body([item(), item("b.example.invalid")])
        original = store.check
        def guarded(scope, permission_id, *, connection=None):
            if connection is not None and connection.execute("SELECT 1 FROM subdomain_inventory_leads LIMIT 1").fetchone():
                raise PermissionError("Synthetic eligibility loss after first row")
            return original(scope, permission_id, connection=connection)
        with patch.object(store, "check", guarded):
            await self.step(self.scheduler())
        self.assertEqual(self.count("subdomain_inventory_leads"), 0)
        self.assertEqual(self.count("evidence_observations"), 0)
        self.assertEqual(self.count("evidence_alerts"), 0)
        self.assertEqual(self.count("evidence_citations"), 0)
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT completed FROM subdomain_inventory_pages WHERE page=1").fetchone()[0], 0)


    async def test_staged_input_cannot_be_replaced_and_checks_original_capture_scope(self):
        scheduler = self.scheduler()
        original = store.stage
        def conflicting(scope, page, document_id, value):
            original(scope, page, document_id, value)
            different = models.parse(json.dumps(body([item("b.example.invalid")])).encode(), "example.invalid")
            with self.assertRaises(evidence.EvidenceConflict):
                original(scope, page, document_id, different)
        with patch.object(store, "stage", conflicting):
            await self.step(scheduler)
        self.assertEqual(self.watch()["state"], "Current")
        self.assertEqual(store.capture(self.watch()["document_id"])["leads"][0]["lead"]["host"], item()["host"])


    async def test_three_attempts_exhaust_transient_retry_budget(self):
        scheduler = self.scheduler()
        self.status = 503
        for _ in range(3):
            await self.step(scheduler)
            self.now += timedelta(minutes=21)
        self.assertEqual(len(self.requests), 3)
        self.assertEqual(self.latest(scheduler)["state"], "failed")
        self.assertEqual(self.latest(scheduler)["attempts"], 3)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 3)


    async def test_cancelled_staging_is_not_adopted_by_another_daily_scope(self):
        scheduler = self.scheduler()
        original = store.stage
        def cancel(scope, page, document_id, value):
            original(scope, page, document_id, value)
            scheduler.runner.cancel(page["job_id"])
        with patch.object(store, "stage", cancel):
            await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "cancelled")
        self.assertEqual(self.count("subdomain_inventory_leads"), 0)
        self.responses[1] = body([item("b.example.invalid")])
        self.now += timedelta(days=1, seconds=1)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.count("subdomain_inventory_leads"), 1)
        self.assertEqual(store.capture(self.watch()["document_id"])["leads"][0]["lead"]["host"], item("b.example.invalid")["host"])


    async def test_api_version_change_refuses_original_permission(self):
        with patch.object(models, "API_VERSION", "future-version"):
            await self.step(self.scheduler())
        self.assertEqual(self.requests, [])


    async def test_rolling_minute_quota_stops_before_transport(self):
        scheduler = self.scheduler(replace(self.feed, rpm=1))
        with evidence.connect() as conn, conn:
            conn.execute("INSERT INTO feed_request_usage VALUES ('ctlogs_hosts',?)", (self.now.timestamp(),))
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.latest(scheduler)["error_code"], "rate_limit")


    async def test_compressed_response_refused_and_normalized_limit_before_capture(self):
        self.headers = {"Content-Encoding": "br"}
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)
        self.headers = {}
        self.now += timedelta(days=1, seconds=1)
        with patch.object(models, "MAX_PAYLOAD", 1):
            await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)


    async def test_defaults_surface_and_literal_provenance(self):
        from app.core.feed_catalog import catalog
        scheduler = Scheduler(catalog(), asyncio.get_running_loop())
        scheduler.initialize()
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*),sum(enabled) FROM feed_schedules").fetchone()[:], (36, 0))
        for url in ("https://api.ctlogs.dev/v1/cert/x", "https://api.ctlogs.dev/v1/hosts/example.invalid?after=x", "https://evil.invalid/v1/hosts/example.invalid"):
            self.assertFalse(self.feed.permits(url))
        with self.assertRaises(PermissionError):
            await ctlogs.refresh()
        self.responses[1] = body([item("example.invalid"), item("*.EXAMPLE.invalid.")])
        with patch.object(settings, "archive_enabled", True), patch.object(settings, "archive_public_sources", [ctlogs.KEY]):
            await self.step(self.scheduler())
        result = store.capture(self.watch()["document_id"])
        self.assertEqual(result["document"]["source_url"], models.API)
        self.assertEqual(result["archive"]["state"], "omitted")
        self.assertIsNone(result["document"]["source_published_at"])
        self.assertEqual(result["leads"][1]["lead"]["host"], "*.EXAMPLE.invalid.")
        self.assertEqual(result["leads"][1]["lead"]["last_seen"], item()["last_seen"])
        self.assertEqual([r["target_reference"] for r in result["citations"]], ["example.invalid", "*.EXAMPLE.invalid."])
        self.assertTrue(all(r["local_first_capture"] == result["document"]["collected_at"] for r in result["leads"]))
        with evidence.connect() as conn:
            for row in conn.execute("SELECT * FROM evidence_observations"):
                self.assertEqual(row["subject_type"], "subdomain_domain")
                self.assertIsNone(row["first_seen"])
                self.assertIsNone(row["observed_at"])

    async def test_two_page_termination_and_partial_drift_without_renewal(self):
        self.two_pages()
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 2)
        self.assertEqual(self.watch()["state"], "Current")
        self.assertIsNotNone(self.latest(scheduler)["coverage_checkpoint"])
        good = self.watch()["last_good"]
        for problem in ("duplicate", "order", "partial", "third_page", "cycle"):
            self.now += timedelta(days=1, seconds=1)
            self.two_pages()
            if problem == "duplicate":
                self.responses[2]["hosts"] = [item()]
            elif problem == "order":
                self.responses[2]["hosts"] = [item("0.example.invalid")]
            elif problem == "partial":
                self.responses[2]["truncated"] = True
            else:
                self.responses[2].update(has_next=True, next_cursor="opaque_2==" if problem == "cycle" else "third")
            await self.step(scheduler)
            self.assertTrue(self.watch()["incomplete"])
            self.assertEqual(self.watch()["last_good"], good)
            self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])
        self.assertEqual(len(self.requests), 12)

    async def test_review_dedup_and_local_first_capture_distinct_from_provider_dates(self):
        self.responses[1] = body([item("example.invalid"), item("*.example.invalid")])
        scheduler = self.scheduler()
        await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "reviewed", 0)
        original = store.capture(self.watch()["document_id"])["leads"][0]["local_first_capture"]
        self.now += timedelta(days=1, seconds=1)
        self.responses[1]["hosts"][0]["certs"] = 3
        await self.step(scheduler)
        self.assertEqual(self.count("subdomain_inventory_leads"), 4)
        self.assertEqual(len(alerts.inbox()), 2)
        self.assertEqual(alerts.detail(first["id"])["alert"]["revision"], 1)
        self.assertEqual(store.capture(self.watch()["document_id"])["leads"][0]["local_first_capture"], original)
        generic = alerts.add_selector(alerts.Selector(subject_type="domain", value="example.invalid"))
        alerts.scan_page(generic)
        self.assertEqual(len(alerts.inbox()), 2)

    async def test_interrupted_pagination_uses_original_cursor_and_oldest_capture(self):
        self.two_pages()
        scheduler = self.scheduler()
        original = ctlogs.fetch
        async def stop_second(scope, page):
            if page["page"] == 2:
                raise Crash()
            await original(scope, page)
        with patch.object(ctlogs, "fetch", stop_second), self.assertRaises(Crash):
            await self.step(scheduler)
        first_good = self.now.isoformat(timespec="microseconds")
        self.responses[1]["next_cursor"] = "changed"
        await self.restart(self.scheduler())
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.watch()["last_good"], first_good)

    async def test_changed_access_versions_expiry_disable_and_suppression(self):
        scheduler = self.scheduler()
        for obj, key, value in ((settings, "ctlogs_api_key", "changed"), (settings, "ctlogs_access_tier", "paid"),
                (models, "QUERY_VERSION", "future")):
            with patch.object(obj, key, value):
                await self.step(scheduler)
            self.now += timedelta(days=1, seconds=1)
        alerts.set_enabled(self.selector, False)
        await self.step(scheduler)
        alerts.set_enabled(self.selector, True)
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        await self.step(scheduler)
        store.suppress(self.selector)
        with self.assertRaises(PermissionError):
            self.approve(self.selector)
        self.assertEqual(self.requests, [])

    async def test_quota_boundary_eligibility(self):
        scheduler = self.scheduler()
        original = feed_scope.Scope.quota
        async def quota(scope):
            await original(scope)
            store.revoke(self.permission)
        with patch.object(feed_scope.Scope, "quota", quota):
            await self.step(scheduler)
        self.assertEqual(self.requests, [])

    async def test_success_quota_headers_and_persistent_busy_backoff(self):
        self.two_pages()
        self.headers = {"X-Hourly-Remaining": "0"}
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("subdomain_inventory_leads"), 2)
        self.headers = {}
        self.now += timedelta(hours=2)
        await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.watch()["state"], "Current")
        for header, lower in (("X-RateLimit-Remaining", 27*86400), ("X-Daily-Remaining", 86000)):
            self.now = datetime(2027, 3 if header.startswith("X-Rate") else 5, 1, tzinfo=timezone.utc)
            self.responses = {1: body()}
            self.headers = {header: "0"}
            await self.step(scheduler)
            with evidence.connect() as conn:
                self.assertGreater(conn.execute("SELECT until_at FROM feed_cooldowns").fetchone()[0] - self.now.timestamp(), lower)
        self.now += timedelta(days=40)
        self.status, self.headers = 429, {"Retry-After": "900"}
        await self.step(scheduler)
        before = len(self.requests)
        await self.step(self.scheduler())
        self.assertEqual(len(self.requests), before)

    async def test_invalid_size_media_access_redirect_and_scope(self):
        scheduler = self.scheduler()
        for status, raw, media in ((200, b"{", "application/json"),
                (200, b"x"*(models.MAX_BYTES+1), "application/json"), (302, b"", "application/json"),
                (200, b"{}", "text/html"), (403, b"private", "application/json"), (401, b"private", "application/json"),
                (422, b"private", "application/json"),
                (200, json.dumps(body([item("example.invalid.attacker.invalid")])).encode(), "application/json")):
            self.status, self.raw, self.media = status, raw, media
            await self.step(scheduler)
            self.assertEqual(self.count("evidence_documents"), 0)
            self.now += timedelta(days=2)

    async def test_stream_timeout_and_soft_deadline_before_transport(self):
        class Slow(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"{"
                await asyncio.sleep(1.1)
                yield b"}"
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request: httpx.Response(200, stream=Slow(), headers={"Content-Type": "application/json"}))) as client:
            base.set_client(client)
            scheduler = self.scheduler(replace(self.feed, seconds=1))
            await self.step(scheduler)
        base.set_client(self.client)
        self.assertEqual(self.count("evidence_documents"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "transient")
        self.now += timedelta(days=2)
        async def delayed(scope):
            await asyncio.sleep(1.01)
        with patch.object(feed_scope.Scope, "quota", delayed):
            await self.step(scheduler)
        self.assertEqual(self.requests, [])

    async def test_access_prerequisite_capacity_and_independent_domain_freshness(self):
        for key, value in (("ctlogs_api_key", ""), ("ctlogs_access_tier", ""), ("ctlogs_access_tier", "unknown")):
            with patch.object(settings, key, value), self.assertRaises(ValueError):
                self.scheduler()
        second = alerts.add_selector(alerts.Selector(subject_type="subdomain_domain", value="a.example.invalid"))
        self.approve(second)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 2)
        self.assertEqual(self.latest(scheduler)["progress_done"], 2)
        self.assertEqual(len(alerts.inbox()), 2)
        old = store.watches(self.now)[1]["last_good"]
        alerts.set_enabled(second, False)
        self.now += timedelta(days=3)
        await self.step(scheduler)
        watches = store.watches(self.now)
        self.assertEqual(watches[0]["state"], "Current")
        self.assertEqual(watches[1]["state"], "Stale")
        self.assertEqual(watches[1]["last_good"], old)
        for index in range(8):
            self.approve(alerts.add_selector(alerts.Selector(subject_type="subdomain_domain", value=f"corp{index}.invalid")))
        with self.assertRaises(ValueError):
            self.approve(alerts.add_selector(alerts.Selector(subject_type="subdomain_domain", value="excess.invalid")))
        with self.assertRaises(ValueError):
            self.approve(alerts.add_selector(alerts.Selector(subject_type="domain", value="example.invalid")))

    async def test_passive_views_unknown_dates_and_local_catchup(self):
        self.responses[1] = body([{"host": "a.example.invalid", "certs": 1}])
        await self.step(self.scheduler())
        ident = self.watch()["document_id"]
        from app.main import app
        with TestClient(app, base_url="http://127.0.0.1") as client:
            for url in ("/subdomains", f"/subdomains/captures/{ident}", f"/subdomains/watches/{self.selector}", f"/alerts/{alerts.inbox()[0]['id']}"):
                self.assertEqual(client.get(url).status_code, 200)
            text = client.get(f"/subdomains/captures/{ident}").text
            self.assertIn("Published: Unknown", text)
            self.assertIn("Literal Provider Names and Dates", text)
            self.assertIn("Local First Capture", text)
            self.assertNotIn('href="https://a.example.invalid', text)
        self.assertEqual(len(self.requests), 1)
        with evidence.connect() as conn, conn:
            conn.execute("DELETE FROM evidence_alert_events")
            conn.execute("DELETE FROM evidence_alerts")
        alerts.scan_page(self.selector)
        self.assertEqual(len(alerts.inbox()), 1)
        self.assertEqual(len(self.requests), 1)

    async def test_success_cooldown_survives_crash_after_staging(self):
        self.two_pages()
        self.headers = {"X-Hourly-Remaining": "0"}
        scheduler = self.scheduler()
        original = store.stage
        def stop(scope, page, document_id, value):
            original(scope, page, document_id, value)
            raise Crash()
        with patch.object(store, "stage", stop), self.assertRaises(Crash):
            await self.step(scheduler)
        self.headers = {}
        await self.restart(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("subdomain_inventory_leads"), 2)
        self.assertEqual(self.latest(scheduler)["error_code"], "rate_limit")

    async def test_nonempty_plan_never_adopts_later_domain(self):
        scheduler = self.scheduler()
        original = store.plan
        def stop(scope):
            original(scope)
            raise Crash()
        with patch.object(store, "plan", stop), self.assertRaises(Crash):
            await self.step(scheduler)
        second = alerts.add_selector(alerts.Selector(subject_type="subdomain_domain", value="a.example.invalid"))
        self.approve(second)
        await self.restart(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("subdomain_inventory_units"), 1)
        self.assertEqual(self.count("subdomain_inventory_pages"), 2)

    async def test_changed_bytes_after_pre_stage_crash_need_new_capture(self):
        scheduler = self.scheduler()
        with patch.object(store, "stage", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        with evidence.connect() as conn:
            original = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
        self.responses[1] = body([item("b.example.invalid")])
        await self.restart(self.scheduler())
        self.assertEqual(self.count("evidence_documents"), 2)
        self.assertEqual(evidence.get_document(original["id"]), original)
        self.assertNotEqual(self.watch()["document_id"], original["id"])
        self.assertEqual(store.capture(self.watch()["document_id"])["leads"][0]["lead"]["host"], "b.example.invalid")

class MigrationTests(unittest.TestCase):
    def test_atomic_migration_rollback_retry_and_newer_version_refused(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE evidence_selectors(id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE durable_jobs(id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE evidence_documents(id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TABLE evidence_observations(id INTEGER PRIMARY KEY)")
        with patch.object(schema, "MIGRATIONS", ((1, schema.VERSION_1+"; INVALID SQL"),)):
            with self.assertRaises(sqlite3.OperationalError):
                schema.migrate(conn)
        self.assertFalse(conn.execute("SELECT 1 FROM sqlite_master WHERE name='subdomain_inventory_permissions'").fetchone())
        schema.migrate(conn)
        schema.migrate(conn)
        self.assertEqual(conn.execute("SELECT count(*) FROM subdomain_inventory_versions").fetchone()[0], 1)
        conn.execute("INSERT INTO subdomain_inventory_versions VALUES (99,'future')")
        conn.commit()
        with self.assertRaises(RuntimeError):
            schema.migrate(conn)
