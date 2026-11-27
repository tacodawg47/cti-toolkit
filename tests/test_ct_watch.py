"""3A.3 exact matcher acceptance. Synthetic names only, no provider calls."""

import unittest
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
from unittest.mock import patch

import httpx
from fastapi.testclient import TestClient

from app.core import alerts, archives, db, evidence, ratelimit
from app.core.config import settings
from app.core.evidence_models import Source
from app.core.feed_scheduler import Scheduler
from app.modules.ct_watch import crtsh, matching, models, schema, store
from app.modules.enrich import base
from app.modules.vulnerability_intelligence import store as vulnerability_store


class MatchingTests(unittest.TestCase):
    def test_exact_labels_and_hyphen_boundaries_at_any_depth(self):
        for name in ("anycorp.sso-reset.invalid", "sso.anycorp.invalid", "legal-anycorp.invalid",
                     "nested.anycorp-login.example.invalid", "anycorp.legal"):
            with self.subTest(name=name):
                self.assertIsNotNone(matching.match("anycorp", "brand", name))
        for name in ("notanycorp.invalid", "anycorporation.invalid", "anycorp2.invalid", "xn--anycorp-9jg.invalid"):
            with self.subTest(name=name):
                # Invalid punycode is refused rather than treated as brand text.
                try:
                    result = matching.match("anycorp", "brand", name)
                except ValueError:
                    continue
                self.assertIsNone(result)

    def test_domain_is_complete_label_sequence_without_derived_brand(self):
        for name in ("example.invalid", "login.example.invalid", "example.invalid.other.invalid"):
            self.assertIsNotNone(matching.match("example.invalid", "domain", name))
        for name in ("notexample.invalid", "example.invalidx", "example-login.invalid", "example.other.invalid"):
            self.assertIsNone(matching.match("example.invalid", "domain", name))

    def test_idna_roundtrip_case_root_dot_and_confusables(self):
        self.assertEqual(matching.hostname("BÜCHER.invalid."), "xn--bcher-kva.invalid")
        self.assertIsNotNone(matching.match("bücher", "organization", "xn--bcher-kva.login.invalid"))
        self.assertIsNone(matching.match("apple", "brand", "аррӏе.invalid"))
        self.assertNotEqual(matching.hostname("faß.invalid"), matching.hostname("fass.invalid"))

    def test_wildcard_stays_a_pattern_and_does_not_expand(self):
        match = matching.match("anycorp", "brand", "*.anycorp-login.invalid")
        self.assertTrue(match["wildcard"])
        self.assertEqual(matching.hostname("*.Anycorp.invalid", wildcard=True), "*.anycorp.invalid")
        with self.assertRaises(ValueError):
            matching.seed("*.anycorp.invalid", "domain")

    def test_invalid_names_are_not_repaired_into_queries(self):
        for name in ("https://example.invalid/", "user@example.invalid", "x..invalid", "x.*.invalid", "x_invalid",
                     "a.invalid:443", " example.invalid", "example[.]invalid", "127.0.0.1", "com", "a"*64+".invalid",
                     "a。invalid", "a.invalid\n", "x.invalid.."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                matching.hostname(name, wildcard=True)
        for token in ("a", "42", "any corp", "%anycorp%", "anycorp.invalid"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                matching.seed(token, "brand")

    def test_theme_tags_do_not_expand_matching(self):
        self.assertIsNone(matching.match("anycorp", "brand", "okta-passkey-reset.invalid"))
        result = matching.match("anycorp", "brand", "anycorp.sso-reset.invalid")
        self.assertEqual(result["rules"], ["exact-label"])
        self.assertEqual(result["themes"], ["Auth Flow", "Enrollment and Recovery"])
        self.assertEqual(result["pattern_version"], "2026-11-27.1")

    def test_explicit_hyphenated_seed_has_component_boundaries(self):
        self.assertIsNotNone(matching.match("any-corp", "organization", "legal-any-corp-login.invalid"))
        self.assertIsNone(matching.match("any-corp", "organization", "legal-any-corporation.invalid"))

    def test_patterns_have_explicit_source_basis_and_finite_tokens(self):
        data = matching.PATTERNS
        self.assertEqual(data["reviewed_on"], "2026-11-27")
        self.assertEqual(len(data["rules"]), 4)
        for group in data["groups"]:
            self.assertTrue(group["basis"])
            self.assertTrue(all(key in data["sources"] for key in group["references"]))
            self.assertTrue(all(matching.seed(token, "brand") == token for token in group["tokens"] if len(token) >= 3))


def certificate(**changes):
    return {"id": 123, "name_value": "anycorp.sso-reset.invalid\n*.anycorp-login.invalid\nunrelated.invalid",
            "entry_timestamp": "2026-11-01T01:02:03.123", "not_before": "2026-10-30T00:00:00",
            "not_after": "2027-01-30T00:00:00", **changes}


class Crash(BaseException):
    pass


class ConsumerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for key, value in {"data_dir": self.root, "archive_enabled": False, "archive_root": None,
                           "scheduled_feeds_enabled": False, "bulk_enrichment_enabled": False}.items():
            self.override(settings, key, value)
        db.init_db()
        vulnerability_store.init_schema()
        self.now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        self.rows, self.raw, self.status, self.media = [certificate()], None, 200, "application/json"
        self.requests = []
        self.after_response = lambda: None
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.dispatch))
        base.set_client(self.client)
        self.addAsyncCleanup(self.client.aclose)
        self.addCleanup(base.set_client, None)
        self.limiter = ratelimit.RateLimiter()
        self.override(ratelimit, "rate_limiter", self.limiter)
        self.feed = crtsh.catalog()[0]
        self.source = Source(source_id=crtsh.KEY, name="Synthetic CT Source", source_class="aggregator", access_method="api",
            terms_status="approved", terms_reviewed_on="2026-11-27", terms_reference="Synthetic fixture only",
            rate_limit_notes="Synthetic limits only", collection_enabled=True)
        evidence.save_source(self.source)
        self.selector = alerts.add_selector(alerts.Selector(subject_type="ct_brand", value="anycorp"))
        self.permission = self.approve(self.selector)

    def override(self, obj, key, value):
        item = patch.object(obj, key, value)
        item.start()
        self.addCleanup(item.stop)

    def approve(self, selector):
        return store.approve(selector, authority_reference="synthetic-authority", purpose="synthetic defensive monitoring",
                             expires_at="2029-01-01T00:00:00Z")

    def dispatch(self, request):
        self.assertEqual(request.url.host, "crt.sh")
        self.assertEqual(request.url.path, "/")
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.url.params["output"], "json")
        self.assertEqual(request.url.params["exclude"], "expired")
        self.assertNotIn("authorization", request.headers)
        self.requests.append(request)
        self.after_response()
        if self.status == 0:
            raise httpx.ConnectError("synthetic private error must not be logged")
        return httpx.Response(self.status, content=self.raw if self.raw is not None else json.dumps(self.rows).encode(),
            headers={"Content-Type": self.media, "Retry-After": "600", "Location": "https://untrusted.invalid/"})

    def scheduler(self, feed=None, *, enabled=True):
        scheduler = Scheduler([feed or self.feed], asyncio.get_running_loop(), clock=lambda: self.now)
        scheduler.initialize()
        if enabled:
            scheduler.configure(crtsh.KEY, enabled=True)
        return scheduler

    async def step(self, scheduler):
        self.limiter._minute["crtsh"].clear()
        await asyncio.to_thread(scheduler.step)

    def latest(self, scheduler):
        with scheduler.runner._connect() as conn:
            return dict(conn.execute("SELECT * FROM durable_jobs ORDER BY created_at DESC,id DESC LIMIT 1").fetchone())

    def count(self, table):
        with evidence.connect() as conn:
            return conn.execute("SELECT count(*) FROM "+table).fetchone()[0]

    def watch(self):
        return store.watches(self.now)[0]

    async def test_37_schedules_default_off_unscoped_and_fixed_surface(self):
        from app.core.feed_catalog import catalog
        scheduler = Scheduler(catalog(), asyncio.get_running_loop())
        scheduler.initialize()
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*),sum(enabled) FROM feed_schedules").fetchone()[:], (37, 0))
        self.assertFalse(settings.scheduled_feeds_enabled)
        for url in ("http://crt.sh/", "https://crt.sh/?q=x", "https://crt.sh/other", "https://crt.sh.evil.invalid/"):
            self.assertFalse(self.feed.permits(url))
        with self.assertRaises(PermissionError):
            await crtsh.refresh()
        store.revoke(self.permission)
        await self.step(self.scheduler())
        self.assertEqual(self.requests, [])

    async def test_adapter_literal_dates_provenance_wildcards_and_local_inbox(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "succeeded")
        self.assertEqual(self.requests[0].url.params["q"], "%anycorp%")
        self.assertEqual(self.count("ct_candidates"), 2)
        self.assertEqual(len(alerts.inbox()), 2)
        detail = alerts.detail(alerts.inbox()[0]["id"])
        self.assertEqual(detail["observation"]["subject_type"], "ct_hostname")
        for name in ("observed_at", "first_seen", "last_seen"):
            self.assertIsNone(detail["observation"][name])
        self.assertIsNone(detail["document"]["source_published_at"])
        self.assertIsNone(detail["document"]["source_modified_at"])
        self.assertEqual(detail["document"]["sensitivity"], "sensitive")
        self.assertEqual(detail["document"]["source_url"], "https://crt.sh/")
        self.assertIn("Constructed", detail["citations"][0]["locator"])
        self.assertIsNone(detail["citations"][0]["target_document_id"])
        result = store.capture(self.watch()["document_id"])
        self.assertEqual(result["candidates"][0]["candidate"]["entry_timestamp"], certificate()["entry_timestamp"])
        self.assertEqual(self.limiter.usage("crtsh")["day"], 1)
        self.assertEqual(self.watch()["state"], "Current")

    async def test_same_hostname_new_cert_retains_review_and_late_catchup(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "dismissed", 0)
        self.rows[0]["id"] += 1
        self.now += timedelta(days=1, seconds=1)
        await self.step(scheduler)
        alerts.scan_page(self.selector)
        self.assertEqual(self.count("ct_candidates"), 4)
        self.assertEqual(len(alerts.inbox()), 2)
        self.assertEqual(alerts.detail(first["id"])["alert"]["state"], "dismissed")
        self.assertEqual(len(store.history(self.selector)), 2)
        late = alerts.add_selector(alerts.Selector(subject_type="ct_organization", value="anycorp"))
        alerts.scan_page(late)
        self.assertEqual(len(alerts.inbox()), 4)

    async def test_raw_omission_minimized_fields_and_request_query_not_saved(self):
        self.override(settings, "archive_enabled", True)
        self.override(settings, "archive_public_sources", (crtsh.KEY,))
        self.rows[0].update({"password": "synthetic-discard-me", "issuer_name": "synthetic-discard-issuer"})
        await self.step(self.scheduler())
        result = store.capture(self.watch()["document_id"])
        self.assertEqual(result["archive"]["state"], "omitted")
        with evidence.connect() as conn:
            for table in ("ct_units", "ct_candidates", "evidence_documents", "durable_job_documents", "durable_job_runs"):
                text = repr([tuple(row) for row in conn.execute("SELECT * FROM "+table)])
                for value in ("synthetic-discard-me", "synthetic-discard-issuer", "%anycorp%"):
                    self.assertNotIn(value, text)

    async def test_atomic_failure_rolls_back_matches_and_staged_recovery_is_original(self):
        scheduler = self.scheduler()
        with patch.object(alerts, "match_observation", side_effect=Crash()):
            with self.assertRaises(Crash):
                await self.step(scheduler)
        self.assertEqual(self.count("ct_candidates"), 0)
        self.assertEqual(self.count("evidence_alerts"), 0)
        with evidence.connect() as conn:
            original = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
            self.assertEqual(conn.execute("SELECT completed FROM ct_units").fetchone()[0], 0)
        self.rows = [certificate(id=999, name_value="anycorp.changed.invalid")]
        self.now += timedelta(minutes=6)
        restarted = self.scheduler()
        await self.step(restarted)  # Recover interruption and persist retry delay.
        self.now += timedelta(minutes=6)
        await self.step(restarted)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.latest(restarted)["state"], "succeeded")
        self.assertEqual(self.watch()["last_good"], original["collected_at"])
        self.assertEqual(store.capture(original["id"])["document"]["job_run_id"], original["job_run_id"])

    async def test_crash_after_commit_repairs_progress_without_request_or_review_reset(self):
        scheduler = self.scheduler()
        original_ingest = store.ingest
        def crash(scope, unit):
            original_ingest(scope, unit)
            raise Crash()
        with patch.object(store, "ingest", crash), self.assertRaises(Crash):
            await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "reviewed", 0)
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "succeeded")
        self.assertEqual(self.latest(scheduler)["progress_done"], 1)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(alerts.detail(first["id"])["alert"]["revision"], 1)

    async def test_revocation_after_response_and_renewal_cannot_replace_queued_permission(self):
        scheduler = self.scheduler()
        self.after_response = lambda: store.revoke(self.permission)
        await self.step(scheduler)
        self.assertEqual(self.count("ct_candidates"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")
        replacement = self.approve(self.selector)
        self.assertNotEqual(replacement, self.permission)
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT permission_id FROM ct_units").fetchone()[0], self.permission)

    async def test_disabled_selector_is_not_queried(self):
        alerts.set_enabled(self.selector, False)
        await self.step(self.scheduler())
        self.assertEqual(self.requests, [])

    async def test_expired_permission_is_not_queried(self):
        self.now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        await self.step(self.scheduler())
        self.assertEqual(self.requests, [])

    async def test_suppressed_seed_is_not_reapproved_or_queried(self):
        store.suppress(self.selector)
        with self.assertRaises(PermissionError):
            self.approve(self.selector)
        await self.step(self.scheduler())
        self.assertEqual(self.requests, [])

    async def test_changed_pattern_version_does_not_reinterpret_authority(self):
        self.override(matching, "PATTERN_VERSION", "future")
        await self.step(self.scheduler())
        self.assertEqual(self.requests, [])

    async def test_changed_pattern_content_same_version_refuses_old_authority(self):
        self.override(matching, "PATTERN_SHA256", "0"*64)
        await self.step(self.scheduler())
        self.assertEqual(self.requests, [])

    async def test_current_terms_are_not_approved_by_provisional_adapter(self):
        evidence.save_source(Source(source_id=crtsh.KEY, name="Unreviewed provisional source"))
        scheduler = self.scheduler(enabled=False)
        with self.assertRaises(PermissionError):
            scheduler.configure(crtsh.KEY, enabled=True)
        await self.step(scheduler)
        self.assertEqual(self.requests, [])

    async def test_revoked_staged_input_does_not_resume_under_new_permission(self):
        scheduler = self.scheduler()
        with patch.object(store, "ingest", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        store.revoke(self.permission)
        self.approve(self.selector)
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("ct_candidates"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")

    async def test_eligibility_failure_inside_atomic_ingestion_rolls_back_every_row(self):
        scheduler = self.scheduler()
        original_check = store.check
        rows_checked = 0
        def guarded(scope, permission_id, *, connection=None):
            nonlocal rows_checked
            if connection is not None:
                # Attempt, stage, ingest entry, then each candidate row.
                rows_checked += 1
                if rows_checked == 5:
                    raise PermissionError("synthetic revocation at ingestion boundary")
            return original_check(scope, permission_id, connection=connection)
        with patch.object(store, "check", guarded):
            await self.step(scheduler)
        self.assertEqual(self.count("ct_candidates"), 0)
        self.assertEqual(self.count("evidence_alerts"), 0)
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT completed FROM ct_units").fetchone()[0], 0)

    async def test_stream_wallclock_timeout_does_not_capture_partial_input(self):
        class SlowBody(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"["
                await asyncio.sleep(1.1)
                yield b"]"
        def dispatch(request):
            self.requests.append(request)
            return httpx.Response(200, stream=SlowBody(), headers={"Content-Type": "application/json"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(dispatch)) as client:
            base.set_client(client)
            scheduler = self.scheduler(replace(self.feed, seconds=1))
            await self.step(scheduler)
        base.set_client(self.client)
        self.assertEqual(self.count("evidence_documents"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "transient")

    async def test_normalized_payload_cap_refuses_before_capture(self):
        long_name = ".".join(["a"*50]*4+["anycorp", "invalid"])
        self.rows = [certificate(id=index+1, name_value="\n".join([long_name]*50)) for index in range(20)]
        # Distinct literal root-dot variants are still bounded, while repeating
        # per certificate leaves enough normalized data to exceed 512 KiB.
        for row in self.rows:
            row["name_value"] = "\n".join(f"n{index}."+long_name for index in range(50))
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["error_code"], "invalid_response")
        self.assertEqual(self.count("evidence_documents"), 0)

    async def test_downtime_plans_one_pass_and_domains_use_explicit_full_seed(self):
        store.revoke(self.permission)
        selector = alerts.add_selector(alerts.Selector(subject_type="ct_domain", value="example.invalid"))
        self.approve(selector)
        self.rows = [certificate(name_value="example.invalid.evil.invalid\nnotexample.invalid")]
        self.now += timedelta(days=60)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0].url.params["q"], "%example.invalid%")
        self.assertEqual(self.count("ct_candidates"), 1)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)

    async def test_same_input_same_job_replays_immutable_capture_identity(self):
        scheduler = self.scheduler()
        with patch.object(store, "stage", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        with evidence.connect() as conn:
            before = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.now += timedelta(minutes=6)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.count("evidence_documents"), 1)
        after = evidence.get_document(before["id"])
        for key in ("capture_key", "collected_at", "content_sha256", "job_run_id"):
            self.assertEqual(after[key], before[key])

    async def test_schedule_disabled_during_response_refuses_capture(self):
        scheduler = self.scheduler()
        self.after_response = lambda: scheduler.configure(crtsh.KEY, enabled=False)
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)
        self.assertEqual(self.count("ct_candidates"), 0)

    async def test_source_revoked_during_response_refuses_capture(self):
        self.after_response = lambda: evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        await self.step(self.scheduler())
        self.assertEqual(self.count("evidence_documents"), 0)

    async def test_permission_revoked_after_quota_wait(self):
        scheduler = self.scheduler()
        async def wait(_vendor):
            store.revoke(self.permission)
        with patch.object(self.limiter, "_acquire", wait):
            await self.step(scheduler)
        self.assertEqual(self.requests, [])

    async def test_cancellation_during_request_refuses_ingestion(self):
        scheduler = self.scheduler()
        def cancel():
            scheduler.runner.cancel(self.latest(scheduler)["id"])
        self.after_response = cancel
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "cancelled")
        self.assertEqual(self.count("ct_candidates"), 0)

    async def test_429_persists_cooldown_across_scheduler_restart(self):
        self.status = 429
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["error_code"], "rate_limit")
        self.now += timedelta(seconds=301)
        await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        with evidence.connect() as conn:
            self.assertGreater(conn.execute("SELECT until_at FROM feed_cooldowns WHERE bucket='crtsh'").fetchone()[0], self.now.timestamp())

    async def test_durable_daily_quota_prevents_request(self):
        scheduler = self.scheduler(replace(self.feed, rpd=1))
        with scheduler.runner._connect(write=True) as conn:
            conn.execute("INSERT INTO feed_request_usage VALUES ('crtsh',?)", (self.now.timestamp(),))
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.latest(scheduler)["error_code"], "rate_limit")

    async def test_request_and_byte_budgets_end_incomplete_without_false_success(self):
        second = alerts.add_selector(alerts.Selector(subject_type="ct_brand", value="othercorp"))
        self.approve(second)
        scheduler = self.scheduler(replace(self.feed, requests=1))
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])
        self.assertFalse(self.watch()["incomplete"])
        self.assertTrue(store.watches(self.now)[1]["incomplete"])

    async def test_no_request_when_response_allowance_exceeds_attempt_bytes(self):
        scheduler = self.scheduler(replace(self.feed, bytes=1))
        await self.step(scheduler)
        self.assertEqual(self.requests, [])
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])

    async def test_soft_elapsed_limit_before_transport(self):
        scheduler = self.scheduler(replace(self.feed, seconds=1))
        async def wait(_vendor):
            await asyncio.sleep(1.02)
        with patch.object(self.limiter, "_acquire", wait):
            await self.step(scheduler)
        self.assertEqual(self.requests, [])

    async def test_malformed_oversized_redirect_nonjson_and_404_fail_closed(self):
        scheduler = self.scheduler()
        for status, raw, media in ((200, b"{", "application/json"), (200, b"x"*(models.MAX_BYTES+1), "application/json"),
                                   (302, b"", "application/json"), (404, b"", "application/json"), (200, b"[]", "text/html")):
            self.status, self.raw, self.media = status, raw, media
            self.now += timedelta(days=1, seconds=1)
            await self.step(scheduler)
            self.assertEqual(self.count("ct_candidates"), 0)
            self.assertEqual(self.watch()["state"], "Never Loaded")
        self.assertTrue(all(request.url.host == "crt.sh" for request in self.requests))

    async def test_empty_snapshot_and_failure_preserve_earlier_claim_and_age(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        first_good = self.watch()["last_good"]
        self.rows = []
        self.now += timedelta(days=1, seconds=1)
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "succeeded")
        self.assertEqual(self.count("ct_candidates"), 2)
        self.assertEqual(len(alerts.inbox()), 2)
        empty_good = self.watch()["last_good"]
        self.assertNotEqual(empty_good, first_good)
        self.now += timedelta(days=3)
        self.status = 0
        await self.step(scheduler)
        self.assertEqual(self.watch()["last_good"], empty_good)
        self.assertEqual(self.watch()["state"], "Stale")
        self.assertTrue(self.watch()["incomplete"])

    async def test_passive_escaped_pages_capture_provenance_and_review_links(self):
        await self.step(self.scheduler())
        from app.main import app
        client = TestClient(app, base_url="http://127.0.0.1")
        before = len(self.requests)
        doc = self.watch()["document_id"]
        for path in ("/ct-watches", f"/ct-watches/captures/{doc}", f"/ct-watches/watches/{self.selector}",
                     f"/alerts/{alerts.inbox()[0]['id']}"):
            response = client.get(path)
            self.assertEqual(response.status_code, 200, response.text[:400])
            self.assertIn("registration time", response.text)
        self.assertEqual(len(self.requests), before)
        self.assertEqual(client.get("/ct-watches/captures/99999").status_code, 404)
        self.assertEqual(client.get("/ct-watches/captures/1?offset=-1").status_code, 422)

    async def test_seed_capacity_and_no_implicit_approval_from_local_watch(self):
        for index in range(9):
            self.approve(alerts.add_selector(alerts.Selector(subject_type="ct_organization", value=f"synthetic{index}")))
        extra = alerts.add_selector(alerts.Selector(subject_type="ct_domain", value="example.invalid"))
        with self.assertRaises(ValueError):
            self.approve(extra)
        self.assertEqual(self.count("ct_permissions"), 10)


class ParserTests(unittest.TestCase):
    def test_fields_unknown_dates_literal_offsets_duplicates_and_minimization(self):
        row = certificate(entry_timestamp=None, not_before="2026-01-01T01:02:03+01:00", not_after=None, password="drop")
        result = models.parse(json.dumps([row, row]).encode())
        self.assertEqual(len(result), 3)
        self.assertIsNone(result[0].entry_timestamp)
        self.assertEqual(result[0].not_before, "2026-01-01T01:02:03+01:00")
        self.assertNotIn("password", result[0].model_dump())

    def test_invalid_shapes_names_dates_and_bounds_refused(self):
        for rows in ({}, [certificate()]*201, [certificate(id=True)], [certificate(name_value="x@invalid")],
                     [certificate(name_value="x.invalid\n"*51)], [certificate(entry_timestamp="yesterday")],
                     [certificate(), certificate(not_before=None)]):
            with self.subTest(rows=str(rows)[:80]), self.assertRaises(ValueError):
                models.parse(json.dumps(rows).encode())
        self.assertEqual(models.parse(b"[]"), [])


class MigrationTests(unittest.TestCase):
    def test_additive_migration_rollback_retry_and_newer_version_refusal(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.execute("CREATE TABLE legacy(id INTEGER)")
        connection.execute("INSERT INTO legacy VALUES(9)")
        connection.execute("PRAGMA user_version=7")
        connection.commit()
        with patch.object(schema, "MIGRATIONS", ((1, schema.VERSION_1+";invalid sql"),)), self.assertRaises(sqlite3.Error):
            schema.migrate(connection)
        self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='ct_units'").fetchone())
        schema.migrate(connection)
        schema.migrate(connection)
        self.assertEqual(connection.execute("SELECT * FROM legacy").fetchone()[0], 9)
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 7)
        connection.execute("INSERT INTO ct_versions VALUES(999,'future')")
        connection.commit()
        with self.assertRaisesRegex(RuntimeError, "newer CT"):
            schema.migrate(connection)
