"""3A.2 acceptance: synthetic HTTP and temporary databases exclusively."""

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

from app.core import alerts, archives, db, evidence, feed_scope, ratelimit
from app.core.config import settings
from app.core.evidence_models import Source
from app.core.feed_scheduler import Scheduler, health
from app.modules.breaches import hibp, models, schema, store
from app.modules.enrich import base
from app.modules.vulnerability_intelligence import store as vulnerability_store


def breach(name="SyntheticBreach", **changes):
    return {"Name": name, "Title": "Synthetic Service", "BreachDate": "2020-01-01",
            "AddedDate": "2026-01-02T03:04:05Z", "ModifiedDate": "2026-02-02T03:04:05Z",
            "IsVerified": False, "IsFabricated": True, "IsSpamList": True,
            "IsMalware": False, "IsStealerLog": False,
            "DisclosureUrl": "https://publisher.invalid/report?edition=2#literal", **changes}


class Crash(BaseException):
    pass


class BreachTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for key, value in {"data_dir": self.root, "archive_enabled": False, "archive_root": None,
                "scheduled_feeds_enabled": False, "bulk_enrichment_enabled": False,
                "hibp_api_key": "a"*32, "hibp_subscription_until": "2030-01-01T00:00:00Z"}.items():
            self.override(settings, key, value)
        db.init_db()
        vulnerability_store.init_schema()
        self.now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        self.rows, self.status, self.raw = [breach()], 200, None
        self.requests = []
        self.after_response = lambda: None
        self.media = "application/json"
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.dispatch))
        base.set_client(self.client)
        self.addAsyncCleanup(self.client.aclose)
        self.addCleanup(base.set_client, None)
        self.limiter = ratelimit.RateLimiter()
        self.override(ratelimit, "rate_limiter", self.limiter)
        self.feed = hibp.catalog()[0]
        self.source = Source(source_id=hibp.KEY, name="Synthetic HIBP Review", source_class="aggregator", access_method="api",
            terms_status="approved", terms_reviewed_on="2026-11-27", terms_reference="Synthetic fixture only",
            rate_limit_notes="Synthetic limits only", collection_enabled=True)
        evidence.save_source(self.source)
        self.selector = alerts.add_selector(alerts.Selector(subject_type="email", value="Test+watch@example.invalid"))
        self.permission = self.approve(self.selector)

    def approve(self, selector):
        return store.approve(selector, authority_reference="synthetic-authority", consent_reference="synthetic-consent",
                             purpose="synthetic defensive monitoring", expires_at="2029-01-01T00:00:00Z")

    def override(self, obj, key, value):
        item = patch.object(obj, key, value)
        item.start()
        self.addCleanup(item.stop)

    def dispatch(self, request):
        self.assertEqual(request.url.host, "haveibeenpwned.com")
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.url.params["truncateResponse"], "false")
        self.assertEqual(request.headers["hibp-api-key"], settings.hibp_api_key)
        self.assertIn("CTI-Toolkit", request.headers["user-agent"])
        self.requests.append(request)
        self.after_response()
        if self.status == 0:
            raise httpx.ConnectError("synthetic offline with secret text")
        return httpx.Response(self.status, content=self.raw if self.raw is not None else b"" if self.status == 404 else json.dumps(self.rows).encode(),
                              headers={"Content-Type": self.media, "Retry-After": "600", "Location": "https://untrusted.invalid/"})

    def scheduler(self, feed=None, enabled=True):
        scheduler = Scheduler([feed or self.feed], asyncio.get_running_loop(), clock=lambda: self.now)
        scheduler.initialize()
        if enabled:
            scheduler.configure(hibp.KEY, enabled=True)
        return scheduler

    async def step(self, scheduler):
        self.limiter._minute["hibp"].clear()
        await asyncio.to_thread(scheduler.step)

    def latest(self, scheduler):
        with scheduler.runner._connect() as conn:
            return dict(conn.execute("SELECT * FROM durable_jobs ORDER BY created_at DESC,id DESC LIMIT 1").fetchone())

    def count(self, table):
        with evidence.connect() as conn:
            return conn.execute("SELECT count(*) FROM "+table).fetchone()[0]

    def watch(self):
        return store.watches(self.now)[0]

    async def test_disabled_defaults_unscoped_fixed_destinations_and_no_implicit_authority(self):
        from app.core.feed_catalog import catalog
        scheduler = Scheduler(catalog(), asyncio.get_running_loop())
        scheduler.initialize()
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*),sum(enabled) FROM feed_schedules").fetchone()[:], (33, 0))
        with self.assertRaises(PermissionError):
            await hibp.refresh()
        for url in (hibp.BASE, hibp.BASE+"/x?truncateResponse=false", hibp.BASE+"/x/other", hibp.BASE.replace("https", "http")+"/x", "https://evil.invalid/x"):
            self.assertFalse(self.feed.permits(url))
        store.revoke(self.permission)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])

    async def test_real_adapter_claims_distinct_dates_literal_hops_and_shared_quota(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "succeeded")
        self.assertEqual(len(self.requests), 1)
        self.assertIn(b"test%2Bwatch%40example.invalid", self.requests[0].url.raw_path)
        detail = alerts.detail(alerts.inbox()[0]["id"])
        self.assertEqual(detail["observation"]["subject_value"], "Test+watch@example.invalid")
        self.assertEqual(detail["observation"]["assertion"], "reported")
        for name in ("observed_at", "first_seen", "last_seen"):
            self.assertIsNone(detail["observation"][name])
        self.assertIsNone(detail["document"]["source_published_at"])
        self.assertEqual(detail["document"]["sensitivity"], "sensitive")
        capture = store.capture(detail["document"]["id"])
        self.assertEqual(capture["associations"][0]["breach"]["breach_date"], "2020-01-01")
        self.assertFalse(capture["associations"][0]["breach"]["verified"])
        self.assertEqual(capture["citations"][0]["target_reference"], breach()["DisclosureUrl"])
        self.assertIsNone(capture["citations"][0]["target_document_id"])
        self.assertEqual(self.limiter.usage("hibp")["day"], 1)
        self.assertEqual(self.watch()["state"], "Current")

    async def test_repeat_capture_and_late_catchup_keep_review_and_claim_dedup(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "dismissed", 0)
        self.now += timedelta(days=1, seconds=1)
        self.rows[0]["ModifiedDate"] = "2026-03-02T03:04:05Z"
        await self.step(scheduler)
        alerts.scan_page(self.selector)
        self.assertEqual(self.count("breach_associations"), 2)
        self.assertEqual(len(alerts.inbox()), 1)
        self.assertEqual(alerts.inbox()[0]["revision"], 1)
        self.assertEqual(alerts.inbox()[0]["state"], "dismissed")
        self.assertEqual(len(store.history(self.selector)), 2)

    async def test_no_public_result_is_recorded_without_negative_or_deleted_claim(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.now += timedelta(days=1, seconds=1)
        self.status = 404
        await self.step(scheduler)
        self.assertTrue(self.watch()["no_result"])
        self.assertEqual(self.watch()["state"], "Current")
        self.assertEqual(self.count("breach_associations"), 1)
        self.assertEqual(len(alerts.inbox()), 1)
        self.assertEqual(self.latest(scheduler)["state"], "succeeded")

    async def test_200_empty_and_malformed_404_do_not_renew_good(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        original = self.watch()["last_good"]
        for status, raw in ((200, b"[]"), (404, b"not an empty no-result")):
            self.now += timedelta(days=3)
            self.status, self.raw = status, raw
            await self.step(scheduler)
            self.assertEqual(self.watch()["last_good"], original)
            self.assertEqual(self.watch()["state"], "Stale")
            self.assertTrue(self.watch()["incomplete"])

    async def test_allowlist_minimization_forced_raw_omission_and_private_request_metadata(self):
        self.override(settings, "archive_enabled", True)
        self.override(settings, "archive_public_sources", (hibp.KEY,))
        self.rows[0].update({"Password": "synthetic-password-not-retained", "Description": "synthetic-private-description", "ApiToken": "synthetic-auth-secret"})
        scheduler = self.scheduler()
        await self.step(scheduler)
        with evidence.connect() as conn:
            for table in ("durable_jobs", "durable_job_runs", "durable_job_documents", "evidence_documents", "breach_units", "breach_associations"):
                values = repr([tuple(r) for r in conn.execute("SELECT * FROM "+table)])
                for secret in ("synthetic-password-not-retained", "synthetic-private-description", "synthetic-auth-secret", "test%2Bwatch", "a"*32):
                    self.assertNotIn(secret, values)
        doc = evidence.get_document(self.watch()["document_id"])
        self.assertEqual(doc["source_url"], hibp.BASE)
        self.assertEqual(archives.get(doc["id"])["state"], "omitted")
        self.assertEqual(archives.get(doc["id"])["reason"], "handling_required")

    async def test_retained_metadata_with_credential_pattern_refused(self):
        self.rows[0]["DisclosureUrl"] = "https://x.invalid/?password=synthetic-secret"
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["error_code"], "invalid_response")
        self.assertEqual(self.count("breach_associations"), 0)
        self.assertEqual(self.count("evidence_documents"), 0)

    async def test_atomic_ingestion_rolls_back_alert_claim_and_completion(self):
        scheduler = self.scheduler()
        with patch.object(alerts, "match_observation", side_effect=RuntimeError("synthetic failure")):
            await self.step(scheduler)
        self.assertEqual(self.count("breach_associations"), 0)
        self.assertEqual(self.count("evidence_observations"), 0)
        self.assertEqual(self.count("evidence_alerts"), 0)
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT completed FROM breach_units").fetchone()[0], 0)
            self.assertIsNotNone(conn.execute("SELECT payload FROM breach_units").fetchone()[0])

    async def test_interrupted_staged_recovery_uses_original_input_origin_and_review(self):
        scheduler = self.scheduler()
        original_ingest = store.ingest
        def fail_after_commit(scope, unit):
            original_ingest(scope, unit)
            raise Crash()
        with patch.object(store, "ingest", fail_after_commit):
            with self.assertRaises(Crash):
                await self.step(scheduler)
        original = alerts.detail(alerts.inbox()[0]["id"])
        alerts.review(original["alert"]["id"], "reviewed", 0)
        self.rows = [breach("ChangedUpstream")]
        self.now += timedelta(minutes=11)
        scheduler = self.scheduler()
        await self.step(scheduler)  # recover interruption and persist backoff
        self.now += timedelta(minutes=11)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler)["state"], "succeeded")
        replay = alerts.detail(original["alert"]["id"])
        self.assertEqual(replay["document"], original["document"])
        self.assertEqual(replay["alert"]["revision"], 1)
        self.assertEqual(replay["execution"]["state"], "interrupted")
        self.assertEqual(replay["execution"]["job_state"], "succeeded")

    async def test_crash_before_ingestion_then_changed_response_uses_saved_payload(self):
        scheduler = self.scheduler()
        with patch.object(store, "ingest", side_effect=Crash):
            with self.assertRaises(Crash):
                await self.step(scheduler)
        self.rows = [breach("ChangedUpstream")]
        self.now += timedelta(minutes=11)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.now += timedelta(minutes=11)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.watch()["breaches"][0]["name"], "SyntheticBreach")

    async def test_source_revocation_after_response_prevents_capture_and_ingestion(self):
        self.after_response = lambda: evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)
        self.assertEqual(self.count("evidence_observations"), 0)

    async def test_selector_permission_revocation_after_response_stops_capture(self):
        self.after_response = lambda: store.revoke(self.permission)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)
        self.assertEqual(self.latest(scheduler)["state"], "failed")

    async def test_after_quota_wait_permission_and_source_rechecked(self):
        async def acquire(vendor):
            store.revoke(self.permission)
        self.override(self.limiter, "_acquire", acquire)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.requests, [])

    async def test_permission_rechecked_at_atomic_ingestion_boundary(self):
        original = store.ingest
        def revoked(scope, unit):
            store.revoke(self.permission)
            original(scope, unit)
        scheduler = self.scheduler()
        with patch.object(store, "ingest", revoked):
            await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 1)
        self.assertEqual(self.count("evidence_observations"), 0)
        self.assertIsNone(self.watch()["last_good"])

    async def test_revoked_permission_or_source_before_retry_sends_no_more_requests(self):
        self.status = 503
        scheduler = self.scheduler()
        await self.step(scheduler)
        store.revoke(self.permission)
        self.now += timedelta(minutes=11)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler)["state"], "failed")

    async def test_revoked_interrupted_resumption_does_not_reuse_new_permission(self):
        scheduler = self.scheduler()
        with patch.object(store, "ingest", side_effect=Crash):
            with self.assertRaises(Crash):
                await self.step(scheduler)
        store.revoke(self.permission)
        self.approve(self.selector)
        self.now += timedelta(minutes=11)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.now += timedelta(minutes=11)
        await self.step(scheduler)
        self.assertEqual(self.count("breach_associations"), 0)
        self.assertEqual(len(self.requests), 1)

    async def test_cancelled_work_retains_staging_and_never_reenqueues(self):
        scheduler = self.scheduler()
        with patch.object(store, "ingest", side_effect=Crash):
            with self.assertRaises(Crash):
                await self.step(scheduler)
        job = self.latest(scheduler)
        scheduler.runner.cancel(job["id"])
        self.now += timedelta(minutes=11)
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "cancelled")
        self.assertEqual(scheduler.runner.enqueue("feed."+hibp.KEY, job["work_key"]), job["id"])
        self.assertEqual(self.count("breach_associations"), 0)
        self.assertEqual(self.count("breach_units"), 1)

    async def test_429_durable_cooldown_and_daily_quota_survive_restart(self):
        self.status = 429
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.now += timedelta(minutes=5)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.now += timedelta(minutes=6)
        self.status = 200
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "succeeded")
        self.assertEqual(len(self.requests), 2)

    async def test_durable_request_and_byte_bounds_before_transport(self):
        selector = alerts.add_selector(alerts.Selector(subject_type="email", value="second@example.invalid"))
        self.approve(selector)
        for feed in (replace(self.feed, requests=1), replace(self.feed, bytes=models.MAX_BYTES-1)):
            scheduler = self.scheduler(feed)
            await self.step(scheduler)
            self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])
            self.now += timedelta(days=1, seconds=1)
        self.assertEqual(len(self.requests), 1)

    async def test_two_equal_body_queries_have_distinct_captures_and_audit(self):
        selector = alerts.add_selector(alerts.Selector(subject_type="email", value="second@example.invalid"))
        self.approve(selector)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 2)
        self.assertEqual(self.count("breach_associations"), 2)
        self.assertEqual(len(self.requests), 2)
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM breach_units WHERE attempted_at IS NOT NULL AND completed=1").fetchone()[0], 2)

    async def test_failure_after_good_and_offline_restart_preserve_freshness(self):
        scheduler = self.scheduler()
        self.status = 0
        await self.step(scheduler)
        self.assertEqual(self.watch()["state"], "Never Loaded")
        self.now += timedelta(days=3)
        self.status = 200
        scheduler = self.scheduler()
        await self.step(scheduler)
        good = self.watch()["last_good"]
        self.assertEqual(self.watch()["state"], "Current")
        self.assertEqual(self.count("durable_jobs"), 1)
        self.now += timedelta(days=3)
        self.status = 503
        await self.step(scheduler)
        self.assertEqual(self.watch()["last_good"], good)
        self.assertEqual(self.watch()["state"], "Stale")
        self.assertTrue(self.watch()["incomplete"])
        self.assertIn("Failed", health([self.feed], clock=lambda: self.now)[0]["states"])

    async def test_expiry_disabled_selector_subscription_and_missing_key_fail_closed(self):
        scheduler = self.scheduler()
        alerts.set_enabled(self.selector, False)
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        alerts.set_enabled(self.selector, True)
        for key, value in (("hibp_api_key", ""), ("hibp_subscription_until", "2020-01-01T00:00:00Z")):
            with patch.object(settings, key, value):
                with self.assertRaises(ValueError):
                    scheduler.configure(hibp.KEY, enabled=True)
        self.now = datetime(2029, 1, 2, tzinfo=timezone.utc)
        await self.step(scheduler)
        self.assertEqual(self.requests, [])

    async def test_local_pages_passive_escaped_and_attributed(self):
        self.rows[0]["Title"] = "<script>synthetic()</script>"
        scheduler = self.scheduler()
        await self.step(scheduler)
        from app.main import app
        before = len(self.requests)
        client = TestClient(app, base_url="http://127.0.0.1")
        for url in ("/breaches", f"/breaches/watches/{self.selector}", f"/breaches/captures/{self.watch()['document_id']}", "/alerts", f"/alerts/{alerts.inbox()[0]['id']}"):
            response = client.get(url)
            self.assertEqual(response.status_code, 200)
            self.assertIn("Have I Been Pwned", response.text)
            self.assertNotIn("<script>synthetic()", response.text)
            self.assertIn('href="https://haveibeenpwned.com/"', response.text)
        self.assertEqual(client.get("/breaches/captures/9999").status_code, 404)
        self.assertEqual(len(self.requests), before)

    async def test_actual_response_size_media_redirect_and_auth_failures(self):
        scheduler = self.scheduler()
        for status, raw, media in ((200, b"x"*(models.MAX_BYTES+1), "application/json"),
                                   (200, b"[]", "text/html"), (302, b"", "text/plain"),
                                   (401, b"provider-secret-error", "text/plain"), (403, b"", "text/plain")):
            self.status, self.raw, self.media = status, raw, media
            await self.step(scheduler)
            self.assertEqual(self.count("evidence_documents"), 0)
            self.assertEqual(self.count("breach_associations"), 0)
            self.assertNotIn("provider-secret-error", repr(self.latest(scheduler)))
            # Exhaust a retrying logical pass, then let the next cadence plan.
            job = self.latest(scheduler)
            if job["state"] == "queued":
                scheduler.runner.cancel(job["id"])
                await self.step(scheduler)
            self.now += timedelta(days=1, seconds=1)
        self.assertEqual(len(self.requests), 5)

    async def test_real_stream_timeout_and_soft_elapsed_budget(self):
        class Slow(httpx.AsyncByteStream):
            async def __aiter__(self):
                await asyncio.sleep(2)
                yield b"[]"
        async def dispatch(request):
            return httpx.Response(200, stream=Slow(), headers={"Content-Type": "application/json"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(dispatch)) as client:
            base.set_client(client)
            scheduler = self.scheduler(replace(self.feed, seconds=1))
            await self.step(scheduler)
            self.assertEqual(self.latest(scheduler)["error_code"], "transient")
        base.set_client(self.client)
        self.now += timedelta(minutes=11)
        self.after_response = lambda: setattr(feed_scope.current.get(), "started", 0)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])
        self.assertEqual(self.count("evidence_documents"), 0)

    async def test_durable_daily_and_minute_quota_before_transport(self):
        for feed in (replace(self.feed, rpd=1), replace(self.feed, rpm=1)):
            self.now += timedelta(days=1, seconds=1)
            with evidence.connect() as conn, conn:
                conn.execute("INSERT INTO feed_request_usage VALUES (?,?)", (self.feed.bucket, self.now.timestamp()))
            scheduler = self.scheduler(feed)
            await self.step(scheduler)
            self.assertEqual(self.latest(scheduler)["error_code"], "rate_limit")
        self.assertEqual(self.requests, [])

    async def test_source_revoked_before_retry_and_staged_resumption(self):
        scheduler = self.scheduler()
        self.status = 503
        await self.step(scheduler)
        evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        self.now += timedelta(minutes=11)
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")
        self.assertEqual(len(self.requests), 1)

    async def test_schedule_disable_between_units_and_per_address_health(self):
        selector = alerts.add_selector(alerts.Selector(subject_type="email", value="second@example.invalid"))
        self.approve(selector)
        scheduler = self.scheduler()
        original = store.ingest
        def disable(scope, unit):
            original(scope, unit)
            scheduler.configure(hibp.KEY, enabled=False)
        with patch.object(store, "ingest", disable):
            await self.step(scheduler)
        watches = store.watches(self.now)
        self.assertEqual(watches[0]["state"], "Current")
        self.assertEqual(watches[1]["state"], "Never Loaded")
        self.assertIsNone(watches[0]["error"])
        self.assertTrue(watches[1]["incomplete"])
        self.assertEqual(len(self.requests), 1)

    async def test_running_cancellation_after_response_stops_next_unit(self):
        scheduler = self.scheduler()
        self.after_response = lambda: scheduler.runner.cancel(self.latest(scheduler)["id"])
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "cancelled")
        self.assertEqual(self.count("evidence_documents"), 0)

    async def test_suppression_is_case_insensitive_blocks_reapproval_and_resume(self):
        store.suppress(self.selector)
        selector = alerts.add_selector(alerts.Selector(subject_type="email", value="test+watch@example.invalid"))
        with self.assertRaises(PermissionError):
            self.approve(selector)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertFalse(self.watch()["authorized"])

    async def test_explicit_consent_references_and_ten_watch_capacity(self):
        with self.assertRaises(ValueError):
            store.approve(self.selector, authority_reference="authority", consent_reference="", purpose="monitor",
                          expires_at="2029-01-01T00:00:00Z")
        domain = alerts.add_selector(alerts.Selector(subject_type="domain", value="example.invalid"))
        with self.assertRaises(ValueError):
            self.approve(domain)
        for index in range(10):
            selector = alerts.add_selector(alerts.Selector(subject_type="email", value=f"watch{index}@example.invalid"))
            if index == 9:
                with self.assertRaises(ValueError):
                    self.approve(selector)
            else:
                self.approve(selector)
        self.assertEqual(self.count("breach_permissions"), 10)

    async def test_expired_metadata_only_original_preserves_claims_and_reviews(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        alert = alerts.inbox()[0]
        alerts.review(alert["id"], "reviewed", 0)
        ident = self.watch()["document_id"]
        with evidence.connect() as conn, conn:
            conn.execute("UPDATE evidence_archives SET state='expired',reason='synthetic_expiry' WHERE document_id=?", (ident,))
        self.assertEqual(store.capture(ident)["archive"]["state"], "expired")
        self.assertEqual(len(store.capture(ident)["citations"]), 1)
        self.assertEqual(alerts.detail(alert["id"])["alert"]["revision"], 1)

    async def test_restart_after_commit_before_progress_repairs_progress_without_request(self):
        from app.core.jobs import Context
        original = Context.progress
        def progress(context, done, **kwargs):
            if done == 1:
                raise Crash()
            return original(context, done, **kwargs)
        scheduler = self.scheduler()
        with patch.object(Context, "progress", progress):
            with self.assertRaises(Crash):
                await self.step(scheduler)
        self.assertEqual(len(alerts.inbox()), 1)
        self.now += timedelta(minutes=11)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.now += timedelta(minutes=11)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler)["progress_done"], 1)
        self.assertEqual(self.latest(scheduler)["progress_total"], 1)


class ParserAndSchemaTests(unittest.TestCase):
    def test_unknown_dates_remain_unknown_and_source_text_does_not_create_fields(self):
        item = models.parse(json.dumps([breach(BreachDate=None, AddedDate=None, ModifiedDate=None, password="discard")]).encode(), 200)[0]
        self.assertIsNone(item.breach_date)
        self.assertIsNone(item.added_date)
        self.assertNotIn("password", item.model_dump())
        item = models.parse(json.dumps([breach(AddedDate="2026-01-02T03:04+01:00", Attribution="Synthetic source credit")]).encode(), 200)[0]
        self.assertEqual(item.added_date, "2026-01-02T03:04+01:00")
        self.assertEqual(item.attribution, "Synthetic source credit")

    def test_malformed_duplicate_oversized_and_typed_fields_refused(self):
        for rows in ({}, [], [breach()]*2, [breach()]*101, [breach(IsVerified="true")], [breach(Name="../unsafe")],
                     [breach(AddedDate="2026-01-01T00:00:00")], [breach(BreachDate="2026-01-01T00:00:00Z")]):
            with self.assertRaises(ValueError):
                models.parse(json.dumps(rows).encode(), 200)
        with self.assertRaises(ValueError):
            models.parse(b"x"*(models.MAX_BYTES+1), 200)

    def test_additive_migration_repeat_rollback_and_newer_version_refusal(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        # Referenced tables need not exist to create FKs in SQLite.
        conn.execute("CREATE TABLE legacy(value TEXT)")
        conn.execute("INSERT INTO legacy VALUES ('retained')")
        conn.commit()
        original = schema.MIGRATIONS
        with patch.object(schema, "MIGRATIONS", ((1, schema.VERSION_1+";INVALID SQL"),)):
            with self.assertRaises(sqlite3.OperationalError):
                schema.migrate(conn)
        self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='breach_permissions'").fetchone())
        schema.migrate(conn)
        schema.migrate(conn)
        self.assertEqual(conn.execute("SELECT value FROM legacy").fetchone()[0], "retained")
        conn.execute("INSERT INTO breach_versions VALUES (999,'future')")
        conn.commit()
        with self.assertRaises(RuntimeError):
            schema.migrate(conn)
