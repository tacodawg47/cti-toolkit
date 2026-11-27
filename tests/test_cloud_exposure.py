"""3A.6 acceptance. Synthetic HTTP and temporary databases only."""
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
from app.modules.cloud_exposure import models, schema, shodan, store
from app.modules.vulnerability_intelligence import store as vulnerability_store


def item(number=1, **changes):
    return {"ip_str": f"192.0.2.{number}", "port": 443, "transport": "tcp",
        "hostnames": ["a.example.invalid"], "domains": ["example.invalid"],
        "org": "Synthetic IP Manager", "isp": "Synthetic ISP", "asn": "AS64500",
        "product": "Synthetic Service", "version": "1.0", "timestamp": "2026-11-01T00:00:00.123456",
        "cloud": {"provider": "Synthetic Cloud", "region": "region-1", "service": "HOSTING"}, **changes}


def body(items=None, **changes):
    items = [item()] if items is None else items
    return {"matches": items, "total": len(items), **changes}


class Crash(BaseException):
    pass


class ModelTests(unittest.TestCase):
    def parse(self, value):
        return models.parse(json.dumps(value).encode(), "example.invalid")

    def test_exact_domain_label_boundaries_and_no_query_injection(self):
        self.assertEqual(models.query("EXAMPLE.invalid."), 'hostname:"example.invalid"')
        self.assertEqual(models.selector("bücher.invalid"), "xn--bcher-kva.invalid")
        for host in ("example.invalid", "a.example.invalid", "a.b.example.invalid", "EXAMPLE.invalid."):
            self.assertEqual(len(self.parse(body([item(hostnames=[host])])).leads), 1)
        for host in ("badexample.invalid", "example.invalid.evil.invalid", "other.invalid"):
            self.assertEqual(self.parse(body([item(hostnames=[host])])).leads, ())
        for seed in ('example.invalid" OR net:0.0.0.0/0', "*.example.invalid", "https://example.invalid", "127.0.0.1", " example.invalid", "example.invalid:443", "a。invalid"):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                models.query(seed)
        with self.assertRaises(ValueError):
            alerts.Selector(subject_type="cloud_domain", value="example.invalid", mode="domain_tree")

    def test_explicit_cloud_and_returned_hostname_required(self):
        page = self.parse(body([item(cloud=None), item(2, hostnames=[], domains=["example.invalid"]), item(3)]))
        self.assertEqual(page.returned_count, 3)
        self.assertEqual(page.leads[0].row_position, 2)
        self.assertEqual(len(page.leads), 1)
        self.assertEqual(len(page.service_keys), 3)

    def test_literal_metadata_dates_and_unknowns(self):
        value = self.parse(body([item(hostnames=["A.EXAMPLE.invalid."], org=" <b>IP Manager</b> ", timestamp=None, ignored="discard")]))
        self.assertEqual(value.leads[0].hostnames, ("A.EXAMPLE.invalid.",))
        self.assertEqual(value.leads[0].org, " <b>IP Manager</b> ")
        self.assertIsNone(value.leads[0].timestamp)
        self.assertNotIn("ignored", value.model_dump_json())
        self.assertEqual(models.provider_time(item()["timestamp"]), "2026-11-01T00:00:00.123456+00:00")
        self.assertEqual(models.provider_time("2026-11-01T01:00:00+01:00"), "2026-11-01T00:00:00.000000+00:00")
        for value in ("2026-11-01", "yesterday", "2026-13-01T00:00:00", "2026-11-01T00:00:00.1234567"):
            with self.assertRaises(ValueError):
                models.provider_time(value)

    def test_strict_shapes_minimization_and_content_projection_refusal(self):
        for change in ({"port": True}, {"ip_str": "example.invalid"}, {"transport": "TCP"}, {"hostnames": "a.example.invalid"},
                {"hostnames": ["*.example.invalid"]}, {"cloud": {}}, {"org": "x"*257}, {"hostnames": ["a.example.invalid"]*33},
                {"data": "body"}, {"http": {}}, {"ssl": {}}, {"opts": {}}, {"_shodan": {}}, {"org": "line\nbreak"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.parse(body([item(**change)]))
        for value in ({"matches": None, "total": 0}, {"matches": [], "total": True}, body([item()]*101), body(total=0), body(partial=1), body(error="refused")):
            with self.assertRaises(ValueError):
                self.parse(value)
        for raw in (b'{"matches":[],"matches":[],"total":0}', b"x"*(models.MAX_BYTES+1)):
            with self.assertRaises(ValueError):
                models.parse(raw, "example.invalid")

    def test_service_identity_ignores_revision_and_literal_ipv6_spelling(self):
        first = self.parse(body([item(ip_str="2001:db8::1")])).leads[0]
        second = self.parse(body([item(ip_str="2001:0db8:0:0:0:0:0:1", product="changed", timestamp=None)])).leads[0]
        self.assertEqual(first.event, second.event)
        self.assertNotEqual(first.ip_str, second.ip_str)

    def test_normalized_payload_bound_and_nested_field_minimization(self):
        row = item(cloud={"provider": "Literal Cloud", "unexpected": "discard"})
        self.assertNotIn("unexpected", self.parse(body([row])).model_dump_json())
        self.assertTrue(self.parse(body([item(metadata={"truncated": ["timestamp"]})])).partial)
        self.assertNotIn("metadata", self.parse(body([row])).model_dump_json())
        with self.assertRaises(ValueError):
            self.parse(body([item(metadata={"truncated": "timestamp"})]))
        with patch.object(models, "MAX_PAYLOAD", 100), self.assertRaises(ValueError):
            self.parse(body([row]))


class ConsumerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for key, value in {"data_dir": self.root, "archive_enabled": False, "archive_root": None,
                "scheduled_feeds_enabled": False, "bulk_enrichment_enabled": False,
                "shodan_api_key": "synthetic-cloud-key", "shodan_cloud_access_reviewed": True,
                "shodan_cloud_access_tier": "membership", "shodan_cloud_monthly_credits": 20}.items():
            self.override(settings, key, value)
        db.init_db()
        vulnerability_store.init_schema()
        self.now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        self.responses = {1: body()}
        self.status, self.media, self.raw, self.headers = 200, "application/json", None, {}
        self.requests = []
        self.allowed_queries = {'hostname:"example.invalid"'}
        self.after_response = lambda: None
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.dispatch))
        base.set_client(self.client)
        self.addAsyncCleanup(self.client.aclose)
        self.addCleanup(base.set_client, None)
        self.feed = shodan.catalog()[0]
        self.source = Source(source_id=shodan.KEY, name="Synthetic cloud search", source_class="legitimate_platform", access_method="api",
            terms_status="approved", terms_reviewed_on="2026-11-27", terms_reference="Synthetic fixture only",
            rate_limit_notes="Synthetic limits only", collection_enabled=True)
        evidence.save_source(self.source)
        self.selector = alerts.add_selector(alerts.Selector(subject_type="cloud_domain", value="example.invalid"))
        self.permission = self.approve(self.selector)

    def override(self, obj, key, value):
        patched = patch.object(obj, key, value)
        patched.start()
        self.addCleanup(patched.stop)

    def approve(self, ident):
        return store.approve(ident, authority_reference="synthetic-terms-access-and-domain-authority", purpose="synthetic monitoring", expires_at="2029-01-01T00:00:00Z")

    def dispatch(self, request):
        self.assertEqual(str(request.url).split("?")[0], models.API)
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.url.params["key"], "synthetic-cloud-key")
        self.assertIn(request.url.params["query"], self.allowed_queries)
        self.assertEqual(request.url.params["fields"], models.FIELDS)
        self.assertEqual(request.url.params["minify"], "true")
        self.assertEqual(set(request.url.params), {"key", "query", "page", "fields", "minify"})
        self.requests.append(request)
        self.now += timedelta(seconds=2)  # A progressing synthetic provider clock.
        self.after_response()
        if self.status == 0:
            raise httpx.ConnectError("private synthetic error")
        page = int(request.url.params["page"])
        raw = self.raw if self.raw is not None else json.dumps(self.responses[page]).encode()
        return httpx.Response(self.status, content=raw, headers={"Content-Type": self.media,
            "Location": "https://evil.invalid/", "Link": '<https://evil.invalid/>; rel="next"', **self.headers})

    def scheduler(self, feed=None, *, enabled=True):
        scheduler = Scheduler([feed or self.feed], asyncio.get_running_loop(), clock=lambda: self.now)
        scheduler.initialize()
        if enabled:
            scheduler.configure(shodan.KEY, enabled=True)
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

    def credits(self):
        with evidence.connect() as conn:
            row = conn.execute("SELECT reserved FROM cloud_exposure_credit_usage WHERE month=?", (self.now.strftime("%Y-%m"),)).fetchone()
            return row[0] if row else 0

    def two_pages(self, *, total=101):
        self.responses = {1: body([item(i) for i in range(1, 101)], total=total), 2: body([item(101)], total=total)}

    async def restart(self, scheduler):
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.now += timedelta(minutes=6)
        await self.step(scheduler)

    async def test_37_schedules_default_off_and_fixed_surface(self):
        from app.core.feed_catalog import catalog
        scheduler = Scheduler(catalog(), asyncio.get_running_loop(), clock=lambda: self.now)
        scheduler.initialize()
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*),sum(enabled) FROM feed_schedules").fetchone()[:], (37, 0))
        self.assertFalse(settings.scheduled_feeds_enabled)
        self.assertFalse(settings.bulk_enrichment_enabled)
        self.assertFalse(settings.archive_enabled)
        self.assertFalse(self.feed.raw_allowed)
        self.assertEqual(self.feed.requests, 20)
        self.assertEqual(self.feed.bytes, 40*1024**2)
        self.assertEqual(self.feed.seconds, 120)
        for url in (models.API+"?query=bad", "https://evil.invalid/", models.API+"/", "https://api.shodan.io/api-info", "https://api.shodan.io/dns/resolve"):
            self.assertFalse(self.feed.permits(url))
        with self.assertRaises(PermissionError):
            await shodan.refresh()

    async def test_access_attestation_and_tier_do_not_follow_existing_key(self):
        scheduler = self.scheduler(enabled=False)
        for key, value in (("shodan_cloud_access_reviewed", False), ("shodan_cloud_access_tier", "free"), ("shodan_api_key", "")):
            with patch.object(settings, key, value), self.assertRaises(ValueError):
                scheduler.configure(shodan.KEY, enabled=True)
        self.assertEqual(self.requests, [])

    async def test_local_matching_never_grants_submission(self):
        store.revoke(self.permission)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertIsNone(self.latest(scheduler)["coverage_completed_at"])

    async def test_success_provenance_dates_raw_omission_and_separate_typed_matching(self):
        alerts.add_selector(alerts.Selector(subject_type="domain", value="example.invalid"))
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.watch()["state"], "Current")
        self.assertEqual(self.count("evidence_alerts"), 1)
        row = alerts.inbox()[0]
        detail = alerts.detail(row["id"])
        self.assertEqual(detail["observation"]["subject_type"], "cloud_domain")
        self.assertEqual(detail["observation"]["observed_at"], models.provider_time(item()["timestamp"]))
        result = store.capture(row["document_id"])
        self.assertEqual(result["archive"]["state"], "omitted")
        self.assertIsNone(result["document"]["source_published_at"])
        self.assertIsNone(result["document"]["source_modified_at"])
        self.assertEqual(result["citations"][0]["target_reference"], "192.0.2.1")
        self.assertIsNone(result["citations"][0]["target_document_id"])
        self.assertEqual(result["leads"][0]["local_first_capture"], result["document"]["collected_at"])
        self.assertNotIn("synthetic-cloud-key", json.dumps(result["document"]))
        self.assertNotIn("example.invalid", json.dumps(result["document"]))

    async def test_stable_reviews_across_changed_products_dates_and_captures(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "dismissed", 0)
        self.responses[1] = body([item(timestamp=None, product="Changed", cloud={"provider": "Changed Cloud"})])
        self.now += timedelta(days=1, seconds=1)
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 2)
        self.assertEqual(self.count("cloud_exposure_leads"), 2)
        self.assertEqual(self.count("evidence_alerts"), 1)
        self.assertEqual(alerts.detail(first["id"])["alert"]["state"], "dismissed")

    async def test_atomic_rollback_and_staged_restart_preserve_original_capture(self):
        scheduler = self.scheduler()
        with patch.object(alerts, "match_observation", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        self.assertEqual(self.count("cloud_exposure_leads"), 0)
        self.assertEqual(self.count("evidence_observations"), 0)
        self.assertEqual(self.count("evidence_citations"), 0)
        with evidence.connect() as conn:
            original = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
        self.responses[1] = body([item(2)])
        await self.restart(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(evidence.get_document(original["id"]), original)
        self.assertEqual(self.watch()["last_good"], original["collected_at"])

    async def test_crash_after_ingestion_repairs_progress_and_retains_review(self):
        scheduler = self.scheduler()
        with patch.object(store, "finish", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "reviewed", 0)
        await self.restart(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(scheduler)["progress_done"], 1)
        self.assertEqual(alerts.detail(first["id"])["alert"]["revision"], 1)

    async def test_pre_stage_crash_refetches_identical_bytes_into_original_capture(self):
        scheduler = self.scheduler()
        with patch.object(store, "stage", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        await self.restart(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.count("evidence_documents"), 1)
        self.assertEqual(self.credits(), 2)

    async def test_changed_refetch_bytes_get_a_new_capture(self):
        scheduler = self.scheduler()
        with patch.object(store, "stage", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        self.responses[1] = body([item(2)])
        await self.restart(scheduler)
        self.assertEqual(self.count("evidence_documents"), 2)
        self.assertEqual(store.capture(alerts.inbox()[0]["document_id"])["leads"][0]["lead"]["ip_str"], "192.0.2.2")

    async def test_two_pages_skip_committed_page_on_restart(self):
        self.two_pages()
        scheduler = self.scheduler()
        original = shodan.fetch
        async def stop_second(scope, page):
            if page["page"] == 2:
                raise Crash()
            await original(scope, page)
        with patch.object(shodan, "fetch", side_effect=stop_second), self.assertRaises(Crash):
            await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "reviewed", 0)
        await self.restart(self.scheduler())
        self.assertEqual([r.url.params["page"] for r in self.requests], ["1", "2"])
        self.assertEqual(self.latest(scheduler)["progress_done"], 1)
        self.assertEqual(self.watch()["state"], "Current")
        self.assertEqual(alerts.detail(first["id"])["alert"]["state"], "reviewed")

    async def test_duplicate_short_drifting_and_over_cap_windows_stay_incomplete(self):
        scheduler = self.scheduler()
        cases = [body([item(), item()]), body(total=2), body(partial=True)]
        for value in cases:
            self.responses = {1: value}
            await self.step(scheduler)
            self.assertTrue(self.watch()["incomplete"])
            self.assertIsNone(self.watch()["last_good"])
            self.now += timedelta(days=1)
        self.two_pages(total=201)
        await self.step(scheduler)
        self.assertTrue(self.watch()["incomplete"])
        self.assertEqual(len(self.requests), 5)
        self.now += timedelta(days=1)
        self.two_pages()
        self.responses[2]["total"] = 102
        await self.step(scheduler)
        self.assertIsNone(self.watch()["last_good"])

    async def test_empty_and_noncloud_windows_do_not_claim_absence(self):
        self.responses = {1: body([])}
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.watch()["state"], "Current")
        self.assertEqual(self.count("evidence_alerts"), 0)
        self.now += timedelta(days=1)
        self.responses = {1: body([item(cloud=None), item(2, hostnames=["other.invalid"])])}
        await self.step(scheduler)
        self.assertEqual(self.watch()["state"], "Current")
        self.assertEqual(self.count("cloud_exposure_leads"), 0)

    async def test_failure_after_success_preserves_age_and_stale_visibility(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        good = self.watch()["last_good"]
        self.status = 500
        self.now += timedelta(days=3)
        await self.step(scheduler)
        self.assertEqual(self.watch()["last_good"], good)
        self.assertEqual(self.watch()["state"], "Stale")
        self.assertTrue(self.watch()["incomplete"])
        self.assertIsNotNone(self.watch()["error"])

    async def test_authority_loss_during_response_stops_all_ingestion(self):
        self.after_response = lambda: store.revoke(self.permission)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.count("cloud_exposure_leads"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")

    async def test_expiry_suppression_and_version_changes_refuse_frozen_plan(self):
        scheduler = self.scheduler()
        with patch.object(shodan, "fetch", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        for change in (patch.object(models, "API_VERSION", "changed"), patch.object(models, "QUERY_VERSION", "changed"),
                patch.object(settings, "shodan_api_key", "changed"), patch.object(settings, "shodan_cloud_access_tier", "freelancer"),
                patch.object(settings, "shodan_cloud_monthly_credits", 30)):
            with change, evidence.connect() as conn, self.assertRaises(PermissionError):
                store.eligible(conn, self.permission, self.now)
        with evidence.connect() as conn, self.assertRaises(PermissionError):
            store.eligible(conn, self.permission, datetime(2030, 1, 1, tzinfo=timezone.utc))
        store.suppress(self.selector)
        await self.restart(scheduler)
        self.assertEqual(self.requests, [])

    async def test_reapproval_cannot_replace_staged_authority(self):
        scheduler = self.scheduler()
        with patch.object(store, "ingest", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        store.revoke(self.permission)
        replacement = self.approve(self.selector)
        self.assertNotEqual(replacement, self.permission)
        await self.restart(scheduler)
        self.assertEqual(self.count("cloud_exposure_leads"), 0)
        self.assertEqual(len(self.requests), 1)

    async def test_cancelled_scope_is_never_adopted_by_next_daily_scope(self):
        scheduler = self.scheduler()
        self.after_response = lambda: scheduler.runner.cancel(self.latest(scheduler)["id"])
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "cancelled")
        self.after_response = lambda: None
        self.now += timedelta(days=1)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.count("cloud_exposure_units"), 2)

    async def test_source_and_selector_disable_during_staged_recovery(self):
        scheduler = self.scheduler()
        with patch.object(store, "ingest", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        alerts.set_enabled(self.selector, False)
        await self.restart(scheduler)
        self.assertEqual(self.count("cloud_exposure_leads"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")

    async def test_every_row_rechecks_authority_and_rolls_back_page(self):
        self.responses[1] = body([item(), item(2)])
        scheduler = self.scheduler()
        original = alerts.match_observation
        def stop(conn, ident):
            original(conn, ident)
            conn.execute("UPDATE evidence_selectors SET enabled=0 WHERE id=?", (self.selector,))
        with patch.object(alerts, "match_observation", side_effect=stop):
            await self.step(scheduler)
        self.assertEqual(self.count("evidence_alerts"), 0)
        self.assertEqual(self.count("cloud_exposure_leads"), 0)

    async def test_429_cooldown_survives_scheduler_restart(self):
        self.status = 429
        self.headers = {"Retry-After": "1200"}
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.credits(), 1)
        self.now += timedelta(minutes=6)
        await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        with evidence.connect() as conn:
            self.assertGreater(conn.execute("SELECT until_at FROM feed_cooldowns").fetchone()[0], self.now.timestamp())

    async def test_monthly_credits_survive_crashes_and_other_scopes_without_refund(self):
        self.override(settings, "shodan_cloud_monthly_credits", 1)
        store.revoke(self.permission)
        self.permission = self.approve(self.selector)
        scheduler = self.scheduler()
        self.status = 500
        await self.step(scheduler)
        self.status = 200
        await self.restart(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.credits(), 1)
        self.now = datetime(2027, 2, 1, 0, 0, 2, tzinfo=timezone.utc)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)

    async def test_durable_daily_quota_and_request_byte_time_bounds(self):
        self.two_pages()
        scheduler = self.scheduler(replace(self.feed, requests=1))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertTrue(self.watch()["incomplete"])
        self.now += timedelta(days=1)
        scheduler = self.scheduler(replace(self.feed, bytes=models.MAX_BYTES-1))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.now += timedelta(days=1)
        scheduler = self.scheduler(replace(self.feed, rpd=1))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertTrue(self.watch()["incomplete"])

    async def test_pacing_is_durable_and_rechecks_after_wait(self):
        scheduler = self.scheduler()
        original = store.reserve_search
        def reserve(scope, page):
            delay = original(scope, page)
            with evidence.connect() as conn:
                self.assertIsNotNone(conn.execute("SELECT * FROM cloud_exposure_pacing").fetchone())
            store.revoke(self.permission)
            return delay
        with patch.object(store, "reserve_search", side_effect=reserve):
            await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.credits(), 1)

    async def test_transport_errors_are_fixed_codes_and_attempts_finite(self):
        self.status = 0
        scheduler = self.scheduler()
        await self.step(scheduler)
        await self.restart(scheduler)
        self.now += timedelta(minutes=11)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 3)
        self.assertEqual(self.latest(scheduler)["state"], "failed")
        self.assertEqual(self.latest(scheduler)["error_code"], "transient")
        self.assertNotIn("private", json.dumps(self.latest(scheduler)))

    async def test_redirect_media_encoding_oversize_and_access_fail_closed(self):
        scheduler = self.scheduler()
        for status, media, raw, headers in ((302, "application/json", None, {}), (200, "text/html", None, {}),
                (200, "application/json", b"x"*(models.MAX_BYTES+1), {}), (200, "application/json", None, {"Content-Encoding": "gzip"}),
                (403, "application/json", None, {})):
            self.status, self.media, self.raw, self.headers = status, media, raw, headers
            await self.step(scheduler)
            self.assertEqual(self.count("cloud_exposure_leads"), 0)
            self.assertIsNone(self.watch()["last_good"])
            self.now += timedelta(days=1)

    async def test_immutable_empty_plan_and_ten_domain_bound(self):
        store.revoke(self.permission)
        scheduler = self.scheduler()
        original = store.plan
        def interrupted(scope):
            original(scope)
            raise Crash()
        with patch.object(store, "plan", side_effect=interrupted), self.assertRaises(Crash):
            await self.step(scheduler)
        self.approve(self.selector)
        await self.restart(scheduler)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.count("cloud_exposure_units"), 0)
        for i in range(9):
            self.approve(alerts.add_selector(alerts.Selector(subject_type="cloud_domain", value=f"corp{i}.invalid")))
        with self.assertRaises(ValueError):
            self.approve(alerts.add_selector(alerts.Selector(subject_type="cloud_domain", value="excess.invalid")))

    async def test_passive_routes_escape_literals_and_link_reviews_without_requests(self):
        self.responses[1] = body([item(org="<script>bad()</script>")])
        scheduler = self.scheduler()
        await self.step(scheduler)
        row = alerts.inbox()[0]
        from app.main import app
        with TestClient(app, base_url="http://127.0.0.1") as client:
            for url in ("/cloud-exposure", f"/cloud-exposure/captures/{row['document_id']}", f"/cloud-exposure/watches/{self.selector}", f"/alerts/{row['id']}"):
                response = client.get(url)
                self.assertEqual(response.status_code, 200)
            response = client.get(f"/cloud-exposure/captures/{row['document_id']}")
            self.assertIn("&lt;script&gt;", response.text)
            self.assertNotIn("<script>bad()", response.text)
            self.assertNotIn('href="https://192.0.2.1', response.text)
            self.assertIn("Index ingestion/update dates are unknown", response.text)
            self.assertIn("Shodan owns", response.text)
            self.assertEqual(client.get("/cloud-exposure/captures/999999").status_code, 404)
        self.assertEqual(len(self.requests), 1)

    async def test_stream_wall_timeout_and_soft_deadline_stop_new_work(self):
        class Slow(httpx.AsyncByteStream):
            async def __aiter__(self):
                await asyncio.sleep(2)
                yield json.dumps(body()).encode()
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, stream=Slow(), headers={"Content-Type": "application/json"}))) as client:
            base.set_client(client)
            scheduler = self.scheduler(replace(self.feed, seconds=1))
            await self.step(scheduler)
        base.set_client(self.client)
        self.assertEqual(self.latest(scheduler)["error_code"], "transient")
        self.assertEqual(self.count("evidence_documents"), 0)
        self.now += timedelta(days=2)
        reserve = feed_scope.Scope.reserve
        async def expired(scope, url, allowance):
            scope.started -= 121
            await reserve(scope, url, allowance)
        with patch.object(feed_scope.Scope, "reserve", new=expired):
            await self.step(self.scheduler())
        self.assertEqual(self.requests, [])

    async def test_authority_rechecked_after_durable_quota_wait(self):
        async def revoked(scope):
            store.revoke(self.permission)
        with patch.object(feed_scope.Scope, "quota", new=revoked):
            await self.step(self.scheduler())
        self.assertEqual(self.requests, [])
        self.assertEqual(self.credits(), 0)

    async def test_schedule_disable_during_stream_refuses_response(self):
        scheduler = self.scheduler()
        self.after_response = lambda: scheduler.configure(shodan.KEY, enabled=False)
        await self.step(scheduler)
        self.assertEqual(self.count("cloud_exposure_leads"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")

    async def test_source_revoked_before_retry_never_ingests_staged_input(self):
        scheduler = self.scheduler()
        with patch.object(store, "ingest", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        await self.restart(scheduler)
        self.assertEqual(self.count("cloud_exposure_leads"), 0)
        self.assertEqual(len(self.requests), 1)

    async def test_nonempty_plan_does_not_adopt_new_domain_permission(self):
        scheduler = self.scheduler()
        with patch.object(shodan, "fetch", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        second = alerts.add_selector(alerts.Selector(subject_type="cloud_domain", value="another.invalid"))
        self.approve(second)
        await self.restart(scheduler)
        self.assertEqual(self.count("cloud_exposure_units"), 1)
        self.assertEqual(self.count("cloud_exposure_pages"), 2)
        self.assertEqual(len(self.requests), 1)

    async def test_per_domain_freshness_is_not_a_global_success(self):
        second = alerts.add_selector(alerts.Selector(subject_type="cloud_domain", value="a.example.invalid"))
        self.approve(second)
        self.allowed_queries.add('hostname:"a.example.invalid"')
        dispatch = self.dispatch
        def mixed(req):
            response = dispatch(req)
            return httpx.Response(500) if req.url.params["query"] == 'hostname:"a.example.invalid"' else response
        async with httpx.AsyncClient(transport=httpx.MockTransport(mixed)) as client:
            base.set_client(client)
            await self.step(self.scheduler())
        base.set_client(self.client)
        watches = store.watches(self.now)
        self.assertEqual(watches[0]["state"], "Current")
        self.assertEqual(watches[1]["state"], "Never Loaded")
        self.assertTrue(watches[1]["incomplete"])

    async def test_503_http_date_cooldown_persists_without_staging(self):
        self.status = 503
        self.headers = {"Retry-After": "Fri, 01 Jan 2027 01:00:00 GMT"}
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)
        self.now += timedelta(minutes=20)
        await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 1)

    async def test_unknown_provider_date_stays_unknown_in_evidence(self):
        self.responses[1] = body([item(timestamp=None)])
        await self.step(self.scheduler())
        row = alerts.inbox()[0]
        detail = alerts.detail(row["id"])
        self.assertIsNone(detail["observation"]["observed_at"])
        self.assertIsNone(detail["observation"]["first_seen"])
        self.assertIsNone(detail["observation"]["last_seen"])
        self.assertIsNone(store.capture(row["document_id"])["leads"][0]["lead"]["timestamp"])
        self.now += timedelta(days=1)
        self.responses[1] = body([item(metadata={"truncated": ["timestamp"]})])
        await self.step(self.scheduler())
        self.assertTrue(self.watch()["incomplete"])

    async def test_minute_reservations_survive_restart(self):
        self.two_pages()
        scheduler = self.scheduler(replace(self.feed, rpm=1))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM feed_request_usage").fetchone()[0], 1)
        self.now += timedelta(minutes=6)
        await self.step(self.scheduler(replace(self.feed, rpm=1)))
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.watch()["state"], "Current")

    async def test_pacing_slot_survives_restart_and_backwards_clock(self):
        await self.step(self.scheduler())
        with evidence.connect() as conn, conn:
            conn.execute("UPDATE cloud_exposure_pacing SET reserved_at=?", (self.now.timestamp()+10*86400,))
        self.now += timedelta(days=1)
        await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.credits(), 1)

    async def test_duplicate_across_pages_is_incomplete_but_retains_leads(self):
        self.two_pages()
        self.responses[2] = body([item(1)], total=101)
        await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 2)
        self.assertIsNone(self.watch()["last_good"])
        self.assertEqual(self.count("cloud_exposure_leads"), 101)
        self.assertEqual(self.count("evidence_alerts"), 100)

    async def test_staged_input_cannot_be_replaced(self):
        stage = store.stage
        def conflict(scope, page, document, value):
            stage(scope, page, document, value)
            changed = value.model_copy(update={"total": 999})
            with self.assertRaises(evidence.EvidenceConflict):
                stage(scope, page, document, changed)
        with patch.object(store, "stage", side_effect=conflict):
            await self.step(self.scheduler())
        self.assertEqual(self.watch()["state"], "Current")

    async def test_capture_review_links_stay_with_the_exact_domain_selector(self):
        second = alerts.add_selector(alerts.Selector(subject_type="cloud_domain", value="a.example.invalid"))
        self.approve(second)
        self.allowed_queries.add('hostname:"a.example.invalid"')
        await self.step(self.scheduler())
        self.assertEqual(self.count("evidence_alerts"), 2)
        for selector in (self.selector, second):
            document = store.history(selector)[0]["document_id"]
            captured = store.capture(document)
            self.assertEqual([a["selector_id"] for a in captured["leads"][0]["alerts"]], [selector])


class MigrationTests(unittest.TestCase):
    def test_additive_idempotent_and_rejects_newer_version(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        for statement in ("CREATE TABLE evidence_selectors(id INTEGER PRIMARY KEY)", "CREATE TABLE durable_jobs(id TEXT PRIMARY KEY)",
                "CREATE TABLE evidence_documents(id INTEGER PRIMARY KEY)", "CREATE TABLE evidence_observations(id INTEGER PRIMARY KEY)",
                "CREATE TABLE legacy(value TEXT)", "INSERT INTO legacy VALUES ('preserved')"):
            conn.execute(statement)
        conn.commit()
        schema.migrate(conn)
        schema.migrate(conn)
        self.assertEqual(conn.execute("SELECT value FROM legacy").fetchone()[0], "preserved")
        self.assertEqual(conn.execute("SELECT count(*) FROM cloud_exposure_versions").fetchone()[0], 1)
        conn.execute("INSERT INTO cloud_exposure_versions VALUES (99,'future')")
        conn.commit()
        with self.assertRaises(RuntimeError):
            schema.migrate(conn)
