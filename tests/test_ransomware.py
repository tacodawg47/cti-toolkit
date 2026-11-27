"""3A.1 acceptance. Temporary stores and synthetic MockTransport only."""

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
from app.core.evidence_models import Citation, Source
from app.core.feed_scheduler import Scheduler, health
from app.modules.enrich import base
from app.modules.ransomware import models, ransomlook, schema, store
from app.modules.vulnerability_intelligence import store as vulnerability_store


def post(title="Example Industries", group="synthetic-group", **changes):
    return {"post_title": title, "group_name": group, "discovered": "2026-11-20T12:00:00Z",
            "website": "example.invalid", "link": "http://actor.invalid/post?edition=2#claim", **changes}


class Crash(BaseException):
    pass


class RansomwareTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name, value in {"data_dir": self.root, "scheduled_feeds_enabled": False,
                            "archive_enabled": False, "archive_root": None, "bulk_enrichment_enabled": False}.items():
            self.override(settings, name, value)
        db.init_db()
        vulnerability_store.init_schema()
        self.now = datetime(2026, 11, 26, 17, tzinfo=timezone.utc)
        self.requests = []
        self.rows = [post()]
        self.status = 200
        self.raw = None
        self.after_response = lambda: None
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.dispatch))
        base.set_client(self.client)
        self.addAsyncCleanup(self.client.aclose)
        self.addCleanup(base.set_client, None)
        self.limiter = ratelimit.RateLimiter()
        self.override(ratelimit, "rate_limiter", self.limiter)
        self.feed = ransomlook.catalog()[0]
        self.source = Source(source_id=self.feed.source, name="Synthetic RansomLook Review",
            source_class="aggregator", access_method="api", terms_status="approved",
            terms_reviewed_on="2026-11-26", terms_reference="Synthetic fixtures only; no live approval",
            rate_limit_notes="Synthetic 1/minute, 24/day", collection_enabled=True)
        evidence.save_source(self.source)
        self.selector = alerts.add_selector(alerts.Selector(subject_type="organization", value="example industries"))

    def override(self, obj, name, value):
        item = patch.object(obj, name, value)
        item.start()
        self.addCleanup(item.stop)

    def dispatch(self, request):
        self.assertEqual(str(request.url), ransomlook.URL)
        self.assertEqual(request.method, "GET")
        self.assertNotIn("x-api-key", request.headers)
        self.requests.append(str(request.url))
        if self.status == 0:
            raise httpx.ConnectError("Synthetic offline")
        self.after_response()
        return httpx.Response(self.status, content=self.raw if self.raw is not None else json.dumps(self.rows).encode(),
                              headers={"Content-Type": "application/json", "Retry-After": "600", "Location": "https://actor.invalid/"})

    def scheduler(self, feed=None, *, enabled=True):
        result = Scheduler([feed or self.feed], asyncio.get_running_loop(), clock=lambda: self.now)
        result.initialize()
        if enabled:
            result.configure(self.feed.key, enabled=True)
        return result

    async def step(self, scheduler):
        # Our test clock advances hours between retrievals. Clear only this
        # in-memory test limiter window to model that elapsed wall time.
        self.limiter._minute["ransomlook"].clear()
        await asyncio.to_thread(scheduler.step)

    def latest(self, scheduler):
        with scheduler.runner._connect() as conn:
            return dict(conn.execute("SELECT * FROM durable_jobs ORDER BY created_at DESC,id DESC LIMIT 1").fetchone())

    def state(self):
        return health([self.feed], clock=lambda: self.now)[0]

    def count(self, table):
        with evidence.connect() as conn:
            return conn.execute("SELECT count(*) FROM "+table).fetchone()[0]

    async def test_default_disabled_fixed_surface_and_unscoped_calls_refused(self):
        from app.core.feed_catalog import catalog
        feeds = catalog()
        self.assertEqual(len(feeds), 36)
        scheduler = Scheduler(feeds, asyncio.get_running_loop())
        scheduler.initialize()
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT sum(enabled) FROM feed_schedules").fetchone()[0], 0)
        for url in (ransomlook.URL+"?number=999", "https://actor.invalid/", ransomlook.URL.replace("https:", "http:")):
            self.assertFalse(self.feed.permits(url))
        with self.assertRaises(PermissionError):
            await ransomlook.refresh()
        evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        with self.assertRaises(PermissionError):
            self.scheduler()
        self.assertEqual(self.requests, [])

    async def test_real_adapter_captures_claim_dates_citation_and_shared_limiter(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        job = self.latest(scheduler)
        self.assertEqual((job["state"], job["progress_done"]), ("succeeded", 1))
        detail = alerts.detail(alerts.inbox()[0]["id"])
        self.assertEqual(detail["observation"]["assertion"], "reported")
        self.assertTrue(detail["observation"]["observed_at"].startswith("2026-11-20T12:00"))
        self.assertIsNone(detail["document"]["source_published_at"])
        self.assertIsNone(detail["observation"]["first_seen"])
        self.assertEqual(detail["citations"][0]["target_reference"], post()["link"])
        self.assertIsNone(detail["citations"][0]["target_document_id"])
        self.assertEqual(self.limiter.usage("ransomlook")["day"], 1)
        self.assertEqual(self.state()["states"], ["Current"])
        self.assertEqual(json.loads(self.state()["coverage"])["scope"], "latest_100_posts_only")
        self.assertEqual(len(self.requests), 1)

    async def test_repeated_snapshots_keep_captures_and_original_review(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "dismissed", 0)
        self.now += timedelta(hours=2)
        self.rows[0]["description"] = "Ignored extra metadata changes the original response digest"
        await self.step(scheduler)
        self.assertEqual(len(alerts.inbox()), 1)
        self.assertEqual(self.count("evidence_observations"), 2)
        self.assertEqual(self.count("evidence_documents"), 2)
        self.assertEqual(store.claims()[0]["captures"], 2)
        self.assertEqual(alerts.detail(first["id"])["alert"]["state"], "dismissed")
        self.assertEqual(len(alerts.detail(first["id"])["reviews"]), 1)
        self.assertEqual(len(store.detail(store.claims()[0]["id"])["captures"]), 2)

    async def test_same_names_from_different_groups_remain_distinct_claims(self):
        self.rows.append(post(group="other-group"))
        await self.step(self.scheduler())
        self.assertEqual(len(alerts.inbox()), 2)
        self.assertEqual(len(store.claims()), 2)

    async def test_late_paged_catchup_deduplicates_repeated_claims(self):
        alerts.set_enabled(self.selector, False)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.now += timedelta(hours=2)
        await self.step(scheduler)
        self.assertEqual(alerts.inbox(), [])
        alerts.set_enabled(self.selector, True)
        self.assertTrue(alerts.scan_page(self.selector, limit=1)["more"])
        alerts.scan_page(self.selector, limit=1)
        self.assertEqual(len(alerts.inbox()), 1)
        alerts.review(alerts.inbox()[0]["id"], "reviewed", 0)
        alerts.scan_page(self.selector)
        self.assertEqual(alerts.inbox()[0]["state"], "reviewed")

    async def test_unknown_classifications_are_not_inferred_from_titles_websites_or_extra_fields(self):
        alerts.add_selector(alerts.Selector(subject_type="country", value="US"))
        alerts.add_selector(alerts.Selector(subject_type="sector", value="Manufacturing"))
        self.rows = [post("Manufacturing US", website="example.us", sector="Manufacturing", country="US")]
        await self.step(self.scheduler())
        self.assertEqual(alerts.inbox(), [])
        claim = store.claims()[0]["claim"]
        self.assertIsNone(claim["sector"])
        self.assertIsNone(claim["country"])

    async def test_explicit_structured_fixture_sector_country_flow_through_shared_inbox(self):
        alerts.add_selector(alerts.Selector(subject_type="country", value="us"))
        alerts.add_selector(alerts.Selector(subject_type="sector", value="manufacturing"))
        explicit = models.Claim(group="synthetic", organization="Example Industries", country="US", sector="Manufacturing")
        scheduler = self.scheduler()
        # A normalized fixture, not a claim that RansomLook supplies these fields.
        with patch.object(ransomlook, "parse_recent", return_value=[explicit]):
            await self.step(scheduler)
            self.assertEqual({a["subject_type"] for a in alerts.inbox()}, {"organization", "sector", "country"})
            for alert in alerts.inbox():
                alerts.review(alert["id"], "reviewed", 0)
            self.now += timedelta(hours=2)
            await self.step(scheduler)
        self.assertEqual(len(alerts.inbox()), 3)
        self.assertTrue(all(a["state"] == "reviewed" for a in alerts.inbox()))

    async def test_failure_after_good_retains_history_dates_and_stale_coverage(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        previous = self.state()
        self.now += timedelta(hours=7)
        self.status = 503
        await self.step(scheduler)
        state = self.state()
        self.assertTrue({"Stale", "Failed", "Incomplete"}.issubset(state["states"]))
        self.assertEqual(state["last_good_at"], previous["last_good_at"])
        self.assertEqual(state["coverage_at"], previous["coverage_at"])
        self.assertEqual(len(alerts.inbox()), 1)

    async def test_offline_first_attempt_and_restart_recover_without_catchup_burst(self):
        self.status = 0
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertIn("Never Loaded", self.state()["states"])
        self.now += timedelta(days=2)
        self.status = 200
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.count("durable_jobs"), 1)
        self.assertEqual(self.state()["states"], ["Current"])
        self.assertIn("not_assessed", self.state()["coverage"])

    async def test_429_cooldown_survives_restart_and_cancelled_work_never_resets(self):
        self.status = 429
        scheduler = self.scheduler()
        await self.step(scheduler)
        job = self.latest(scheduler)
        self.now += timedelta(minutes=5)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        scheduler.runner.cancel(job["id"])
        self.assertEqual(scheduler.runner.enqueue("feed."+self.feed.key, job["work_key"]), job["id"])
        self.assertEqual(scheduler.runner.get(job["id"])["state"], "cancelled")

    async def test_durable_daily_and_shared_limiter_daily_limits_prevent_http(self):
        scheduler = self.scheduler()
        with evidence.connect() as conn, conn:
            conn.executemany("INSERT INTO feed_request_usage VALUES (?,?)", [(self.feed.bucket, self.now.timestamp()-120)]*24)
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        with evidence.connect() as conn, conn:
            conn.execute("DELETE FROM feed_request_usage")
            conn.execute("INSERT INTO quota_usage VALUES (?,?,24)", ("ransomlook", self.limiter._today()))
        self.now += timedelta(days=1, minutes=1)
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.latest(scheduler)["error_code"], "rate_limit")

    async def test_source_revoked_after_response_stops_capture_and_ingestion(self):
        self.after_response = lambda: evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")
        self.assertEqual(store.claims(), [])
        self.assertEqual(self.count("evidence_documents"), 0)

    async def test_revocation_after_quota_wait_prevents_http(self):
        async def revoke(vendor):
            self.assertEqual(vendor, "ransomlook")
            evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        scheduler = self.scheduler()
        with patch.object(self.limiter, "_acquire", revoke):
            await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")

    async def test_cancel_between_rows_retains_atomic_first_row_and_staged_input(self):
        self.rows.append(post("Second Organization"))
        original = store.ingest_row
        def cancel(scope, batch, index, claim):
            original(scope, batch, index, claim)
            scope.context._runner.cancel(scope.context.check()["id"])
        scheduler = self.scheduler()
        with patch.object(store, "ingest_row", cancel):
            await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "cancelled")
        self.assertEqual(len(store.claims()), 1)
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT next_row FROM evidence_ransomware_batches").fetchone()[0], 1)
        self.now += timedelta(hours=2)
        self.status = 503
        await self.step(self.scheduler())
        self.assertEqual(len(store.claims()), 1)  # Cancelled queue was not resurrected.

    async def test_eligibility_is_rechecked_before_backoff_retry(self):
        scheduler = self.scheduler()
        self.status = 429
        await self.step(scheduler)
        evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        self.now += timedelta(minutes=11)
        await self.step(self.scheduler(enabled=False))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")

    async def test_revoke_after_capture_retains_capture_without_advancing_ingestion(self):
        original = ransomlook.parse_recent
        def revoke(raw):
            claims = original(raw)
            evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
            return claims
        scheduler = self.scheduler()
        with patch.object(ransomlook, "parse_recent", revoke):
            await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 1)
        self.assertEqual(store.claims(), [])
        self.assertIsNone(self.state()["last_good_at"])
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])

    async def test_revoked_source_cannot_resume_interrupted_normalized_input(self):
        original = store.stage
        def crash(scope, document_id, claims):
            original(scope, document_id, claims)
            raise Crash()
        scheduler = self.scheduler()
        with patch.object(store, "stage", crash), self.assertRaises(Crash):
            await self.step(scheduler)
        evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        restarted = self.scheduler(enabled=False)
        await self.step(restarted)
        self.now += timedelta(minutes=6)
        await self.step(restarted)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("evidence_ransomware_batches"), 1)
        self.assertEqual(store.claims(), [])
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")

    async def test_schedule_disabled_between_ingestion_units_stops_remaining_rows(self):
        self.rows.append(post("Second Organization"))
        original = store.ingest_row
        scheduler = self.scheduler()
        def disable(scope, batch, index, claim):
            original(scope, batch, index, claim)
            scheduler.configure(self.feed.key, enabled=False)
        with patch.object(store, "ingest_row", disable):
            await self.step(scheduler)
        self.assertEqual(len(store.claims()), 1)
        self.assertEqual(len(self.requests), 1)
        self.assertIsNone(self.state()["last_good_at"])

    async def test_crash_then_changed_response_recovers_original_rows_and_review_without_raw(self):
        self.rows.append(post("Second Organization"))
        original = store.ingest_row
        def crash(scope, batch, index, claim):
            original(scope, batch, index, claim)
            raise Crash()
        scheduler = self.scheduler()
        with patch.object(store, "ingest_row", crash), self.assertRaises(Crash):
            await self.step(scheduler)
        first = alerts.inbox()[0]
        original_detail = alerts.detail(first["id"])
        alerts.review(first["id"], "reviewed", 0)
        self.assertEqual(original_detail["archive"]["state"], "omitted")
        scheduler = self.scheduler()
        await self.step(scheduler)  # Recover interrupted state and save backoff.
        self.now += timedelta(minutes=6)
        self.rows = [post("New Snapshot Organization")]
        await self.step(scheduler)
        self.assertEqual(len(store.claims()), 3)
        value = alerts.detail(first["id"])
        self.assertEqual(value["alert"]["state"], "reviewed")
        self.assertEqual(value["document"], original_detail["document"])
        self.assertEqual(value["execution"]["state"], "interrupted")
        self.assertEqual(value["execution"]["job_state"], "succeeded")
        self.assertEqual(self.latest(scheduler)["progress_done"], 2)

    async def test_row_failure_rolls_back_capture_association_alert_and_cursor(self):
        scheduler = self.scheduler()
        with patch.object(alerts, "match_observation", side_effect=RuntimeError("Synthetic transaction failure")):
            await self.step(scheduler)
        self.assertEqual(store.claims(), [])
        self.assertEqual(self.count("evidence_observations"), 0)
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT next_row FROM evidence_ransomware_batches").fetchone()[0], 0)
        self.now += timedelta(hours=2)
        await self.step(self.scheduler())  # Later scope drains retained failed batch.
        self.assertEqual(len(store.claims()), 1)
        self.assertEqual(len(alerts.inbox()), 1)

    async def test_source_revoked_between_rows_and_on_resumption(self):
        self.rows.append(post("Second Organization"))
        original = store.ingest_row
        def revoke(scope, batch, index, claim):
            original(scope, batch, index, claim)
            evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        scheduler = self.scheduler()
        with patch.object(store, "ingest_row", revoke):
            await self.step(scheduler)
        self.assertEqual(len(store.claims()), 1)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")
        self.now += timedelta(hours=2)
        await self.step(self.scheduler(enabled=False))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(len(store.claims()), 1)

    async def test_empty_malformed_oversized_and_redirect_responses_never_renew_good(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        good = self.state()["last_good_at"]
        for raw, status in ((b"[]", 200), (b"{}", 200), (b"broken", 200),
                            (json.dumps([post()]*101).encode(), 200), (b"x"*(2*1024**2+1), 200), (b"", 302)):
            with self.subTest(status=status, length=len(raw)):
                self.now += timedelta(hours=2)
                self.raw, self.status = raw, status
                await self.step(scheduler)
                # Finish this bounded logical pass before trying another case.
                active = self.latest(scheduler)
                scheduler.runner.cancel(active["id"])
                scheduler.plan()
                self.assertEqual(self.state()["last_good_at"], good)
                self.assertEqual(len(store.claims()), 1)
        self.assertEqual(len(self.requests), 7)

    async def test_elapsed_budget_stops_before_http_and_leaves_incomplete(self):
        original = feed_scope.Scope.check_sync
        def expire(scope):
            scope.started -= 61
            return original(scope)
        scheduler = self.scheduler()
        with patch.object(feed_scope.Scope, "check_sync", expire):
            await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertIn("Incomplete", self.state()["states"])
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])

    async def test_request_and_charged_byte_budgets_prevent_extra_http(self):
        original = ransomlook.refresh
        async def extra_request():
            await original()
            await feed_scope.fetch(ransomlook.URL, max_bytes=2*1024**2)
        scheduler = self.scheduler(replace(self.feed, refresh=extra_request))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])
        self.now += timedelta(hours=2)
        await self.step(self.scheduler(replace(self.feed, bytes=1024)))
        self.assertEqual(len(self.requests), 1)

    async def test_streaming_request_obeys_finite_wall_timeout(self):
        class SlowStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                await asyncio.sleep(2)
                yield b"[]"
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=SlowStream())))
        self.addAsyncCleanup(client.aclose)
        base.set_client(client)
        scheduler = self.scheduler(replace(self.feed, seconds=1))
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["error_code"], "transient")
        self.assertEqual(store.claims(), [])
        self.assertIsNone(self.state()["last_good_at"])

    async def test_raw_policy_omits_even_when_generic_archive_is_enabled(self):
        self.override(settings, "archive_public_sources", [self.feed.source])
        await self.step(self.scheduler())
        value = alerts.detail(alerts.inbox()[0]["id"])
        self.assertEqual(value["document"]["sensitivity"], "unknown")
        self.assertEqual(value["archive"]["state"], "omitted")

    async def test_raw_expiry_during_interruption_preserves_queue_citations_and_reviews(self):
        for name, value in {"archive_enabled": True, "archive_root": self.root/"originals",
            "archive_response_bytes": 4096, "archive_source_bytes": 8192, "archive_total_bytes": 16384,
            "archive_retention_seconds": 60, "archive_public_sources": [self.feed.source]}.items():
            self.override(settings, name, value)
        # Synthetic metadata-only response explicitly opts into archival for
        # this test. The production adapter always forces raw omission.
        feed = replace(self.feed, raw_allowed=True)
        original = store.ingest_row
        def crash(scope, batch, index, claim):
            original(scope, batch, index, claim)
            raise Crash()
        scheduler = self.scheduler(feed)
        with patch.object(store, "ingest_row", crash), self.assertRaises(Crash):
            await self.step(scheduler)
        alert = alerts.inbox()[0]
        alerts.review(alert["id"], "dismissed", 0)
        value = alerts.detail(alert["id"])
        self.assertEqual(value["archive"]["state"], "stored")
        with patch.object(archives, "now", return_value=archives.now()+timedelta(minutes=2)):
            archives.maintenance()
            self.assertEqual(alerts.detail(alert["id"])["archive"]["state"], "expired")
        await self.step(self.scheduler(feed))
        self.now += timedelta(minutes=6)
        await self.step(self.scheduler(feed))
        self.assertEqual(alerts.detail(alert["id"])["alert"]["state"], "dismissed")
        self.assertEqual(alerts.detail(alert["id"])["citations"], value["citations"])

    async def test_local_pages_escape_text_show_failure_and_never_poll(self):
        self.rows = [post('<script>alert(1)</script>')]
        await self.step(self.scheduler())
        self.now += timedelta(hours=7)
        self.status = 503
        await self.step(self.scheduler())
        from app.main import app
        from app.modules.ransomware import routes
        count = len(self.requests)
        ident = store.claims()[0]["id"]
        def pages():
            with patch.object(routes, "health", return_value=[self.state()]), TestClient(app, base_url="http://127.0.0.1") as client:
                for path in ("/ransomware", f"/ransomware/claims/{ident}"):
                    result = client.get(path)
                    self.assertEqual(result.status_code, 200)
                    self.assertIn("&lt;script&gt;", result.text)
                    self.assertNotIn("<script>alert(1)</script>", result.text)
                    self.assertIn("Stale", result.text)
                    self.assertIn("Failed", result.text)
                self.assertEqual(client.get("/ransomware/claims/999").status_code, 404)
                self.assertEqual(client.get("/ransomware?before=0").status_code, 422)
                response = client.post("/alert-selectors", data={"subject_type": "country", "value": "US", "authorized": "true"}, headers={"Sec-Fetch-Site": "cross-site"})
                self.assertEqual(response.status_code, 403)
        await asyncio.to_thread(pages)
        self.assertEqual(len(self.requests), count)


class ContractTests(unittest.TestCase):
    def test_exact_watch_semantics_have_no_substrings_aliases_or_cross_type_matches(self):
        cases = [("organization", "  Ｅxample   Industries ", "example industries", True),
                 ("organization", "Example", "Example Industries", False),
                 ("organization", "Example, Inc.", "Example Inc", False),
                 ("sector", " MANUFACTURING ", "Manufacturing", True),
                 ("sector", "health", "healthcare", False), ("country", "us", "US", True),
                 ("country", "US", "United States", False)]
        for kind, value, observed, expected in cases:
            selector = alerts.Selector(subject_type=kind, value=value).model_dump()
            self.assertEqual(alerts.matches(selector, {"subject_type": kind, "subject_value": observed}), expected)
            self.assertFalse(alerts.matches(selector, {"subject_type": "domain", "subject_value": observed}))
        for value in ("USA", "United States", "U1", ""):
            with self.assertRaises(ValueError):
                alerts.Selector(subject_type="country", value=value)

    def test_normalized_structured_country_sector_contract_and_literal_naive_dates(self):
        claim = models.Claim(group="synthetic", organization="Example", sector=" Manufacturing ", country="us",
                             discovered_literal="2026-11-20T12:00:00")
        self.assertEqual(claim.subjects(), [("organization", "Example"), ("sector", "manufacturing"), ("country", "US")])
        self.assertIsNone(claim.discovered_at)
        self.assertEqual(claim.discovered_literal, "2026-11-20T12:00:00")
        parsed = models.parse_recent(json.dumps([post(source="base64 html", screen="base64 image", description="ignored")]).encode())
        self.assertNotIn("base64", parsed[0].model_dump_json())
        literal = models.Claim(group="test", organization=" Example ", reference=" literal hop ")
        self.assertEqual(literal.reference, " literal hop ")
        self.assertNotEqual(literal.key, literal.model_copy(update={"organization": "Example"}).key)
        for rows in ([post(discovered="not a date")], [post(), post()], [post(post_title=None)], [{"posts": []}]):
            with self.assertRaises(ValueError):
                models.parse_recent(json.dumps(rows).encode())

    def test_independent_schema_rolls_back_and_refuses_newer_versions(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        with patch.object(schema, "MIGRATIONS", ((1, schema.VERSION_1+"; INSERT INTO absent VALUES(1);"),)):
            with self.assertRaises(sqlite3.OperationalError):
                schema.migrate(conn)
        self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='evidence_ransomware_batches'").fetchone())
        schema.migrate(conn)
        schema.migrate(conn)
        conn.execute("INSERT INTO evidence_ransomware_versions VALUES(99,'future')")
        conn.commit()
        with self.assertRaisesRegex(RuntimeError, "newer ransomware"):
            schema.migrate(conn)
