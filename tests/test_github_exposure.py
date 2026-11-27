"""3A.4 acceptance. Temporary databases, synthetic HTTP, no provider traffic."""

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

from app.core import alerts, db, evidence, ratelimit
from app.core.config import settings
from app.core.evidence_models import Source
from app.core.feed_scheduler import Scheduler
from app.modules.enrich import base
from app.modules.github_exposure import github, models, schema, store
from app.modules.vulnerability_intelligence import store as vulnerability_store


def item(index=1, **changes):
    return {"repository": {"id": 123, "full_name": "anycorp/project", "private": False},
            "path": f"docs/reference{index}.txt", "sha": "a" * 40,
            "html_url": f"https://github.com/anycorp/project/blob/" + "b" * 40 + f"/docs/reference{index}.txt", **changes}


def body(items=None, **changes):
    items = [item()] if items is None else items
    return {"total_count": len(items), "incomplete_results": False, "items": items, **changes}


class Crash(BaseException):
    pass


class ModelTests(unittest.TestCase):
    def test_exact_query_and_no_operator_or_alias_expansion(self):
        self.assertEqual(models.query("Any Corp", "github_organization"), '"any corp" in:file')
        self.assertEqual(models.query("BÜCHER.invalid.", "github_domain"), '"xn--bcher-kva.invalid" in:file')
        for value in ('corp" OR x', "org:corp", "corp*", "Corp OR Other", "corp\n", "ab", "  anycorp", "corp/other"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                models.query(value, "github_organization")
        for value in ("*.example.invalid", "https://example.invalid", "user@example.invalid", "x。invalid", "127.0.0.1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                models.query(value, "github_domain")
        with self.assertRaises(ValueError):
            alerts.Selector(subject_type="github_domain", mode="domain_tree", value="example.invalid")

    def test_only_metadata_fields_and_strict_page_shape(self):
        value = item(description="discard narrative", name="discard name", git_url="https://untrusted.invalid/")
        value["repository"].update(created_at="2020-01-01", owner={"email": "nobody@example.invalid"})
        parsed = models.parse(json.dumps(body([value])).encode())
        self.assertEqual(set(parsed.leads[0].model_dump()), {"repository_id", "repository", "path", "blob_sha", "html_url"})
        for invalid in ([], {}, body(total_count=True), body(incomplete_results="false"), body(items=[item()] * 51), body(total_count=0)):
            with self.subTest(invalid=str(invalid)[:40]), self.assertRaises(ValueError):
                models.parse(json.dumps(invalid).encode())
        with self.assertRaises(ValueError):
            models.parse(b'{"items":[],"total_count":0,"total_count":1,"incomplete_results":false}')

    def test_private_content_secret_and_malformed_reference_refused(self):
        for changes in ({"repository": {"id": 1, "full_name": "anycorp/project", "private": True}},
                        {"repository": {"id": 1, "full_name": "anycorp/project"}},
                        {"text_matches": []}, {"content": "must not retain"},
                        {"html_url": "https://untrusted.invalid/file"}, {"path": "../escape"},
                        {"path": "a\nfile"}, {"sha": "no"}, {"html_url": item()["html_url"]+"?token=secret"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                models.parse(json.dumps(body([item(**changes)])).encode())

    def test_duplicate_equal_dedupes_conflict_refused(self):
        parsed = models.parse(json.dumps(body([item(), item()])).encode())
        self.assertEqual(len(parsed.leads), 1)
        self.assertEqual(parsed.returned_count, 2)
        with self.assertRaises(ValueError):
            models.parse(json.dumps(body([item(), item(sha="c" * 40)])).encode())


class ConsumerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for key, value in {"data_dir": self.root, "archive_enabled": False, "archive_root": None,
                           "scheduled_feeds_enabled": False, "bulk_enrichment_enabled": False,
                           "github_exposure_token": "synthetic-public-only-token", "github_exposure_public_only": True}.items():
            self.override(settings, key, value)
        db.init_db()
        vulnerability_store.init_schema()
        self.now = datetime(2027, 1, 1, tzinfo=timezone.utc)
        self.responses = {1: body()}
        self.status, self.media, self.raw = 200, "application/json", None
        self.headers = {}
        self.requests = []
        self.after_response = lambda: None
        self.client = httpx.AsyncClient(transport=httpx.MockTransport(self.dispatch))
        base.set_client(self.client)
        self.addAsyncCleanup(self.client.aclose)
        self.addCleanup(base.set_client, None)
        self.limiter = ratelimit.RateLimiter()
        self.override(ratelimit, "rate_limiter", self.limiter)
        self.feed = github.catalog()[0]
        self.source = Source(source_id=github.KEY, name="Synthetic Code Search", source_class="legitimate_platform", access_method="api",
            terms_status="approved", terms_reviewed_on="2026-11-27", terms_reference="Synthetic fixture only",
            rate_limit_notes="Synthetic limits only", collection_enabled=True)
        evidence.save_source(self.source)
        self.selector = alerts.add_selector(alerts.Selector(subject_type="github_domain", value="example.invalid"))
        self.permission = self.approve(self.selector)

    def override(self, obj, key, value):
        patched = patch.object(obj, key, value)
        patched.start()
        self.addCleanup(patched.stop)

    def approve(self, selector):
        return store.approve(selector, authority_reference="synthetic-authority-and-public-access", purpose="synthetic defensive monitoring",
                             expires_at="2029-01-01T00:00:00Z")

    def dispatch(self, request):
        self.assertEqual(request.url.host, "api.github.com")
        self.assertEqual(request.url.path, "/search/code")
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.headers["accept"], "application/vnd.github+json")
        self.assertEqual(request.headers["x-github-api-version"], models.API_VERSION)
        self.assertEqual(request.headers["authorization"], "Bearer synthetic-public-only-token")
        self.assertEqual(request.url.params["per_page"], "50")
        self.assertIn(request.url.params["page"], ("1", "2"))
        self.requests.append(request)
        self.after_response()
        if self.status == 0:
            raise httpx.ConnectError("synthetic private error must not be logged")
        raw = self.raw if self.raw is not None else json.dumps(self.responses[int(request.url.params["page"])]).encode()
        return httpx.Response(self.status, content=raw, headers={"Content-Type": self.media,
            "Location": "https://untrusted.invalid/", "Link": '<https://untrusted.invalid/?page=999>; rel="next"', **self.headers})

    def scheduler(self, feed=None, *, enabled=True):
        scheduler = Scheduler([feed or self.feed], asyncio.get_running_loop(), clock=lambda: self.now)
        scheduler.initialize()
        if enabled:
            scheduler.configure(github.KEY, enabled=True)
        return scheduler

    async def step(self, scheduler):
        self.limiter._minute["github"].clear()
        await asyncio.to_thread(scheduler.step)

    def latest(self, scheduler):
        with scheduler.runner._connect() as conn:
            return dict(conn.execute("SELECT * FROM durable_jobs ORDER BY created_at DESC,id DESC LIMIT 1").fetchone())

    def count(self, table):
        with evidence.connect() as conn:
            return conn.execute("SELECT count(*) FROM "+table).fetchone()[0]

    def watch(self):
        return store.watches(self.now)[0]

    def two_pages(self, total=51):
        self.responses = {1: body([item(i) for i in range(50)], total_count=total),
                          2: body([item(50)], total_count=total)}

    async def restart(self, scheduler):
        self.now += timedelta(minutes=6)
        await self.step(scheduler)  # Detect interrupted attempt, persist backoff.
        self.now += timedelta(minutes=6)
        await self.step(scheduler)

    async def test_35_schedules_off_fixed_surface_and_unscoped_refusal(self):
        from app.core.feed_catalog import catalog
        scheduler = Scheduler(catalog(), asyncio.get_running_loop())
        scheduler.initialize()
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*),sum(enabled) FROM feed_schedules").fetchone()[:], (35, 0))
        for url in ("https://api.github.com/repos/x/y", "https://api.github.com/search/code?q=x", "http://api.github.com/search/code", "https://evil.invalid/search/code"):
            self.assertFalse(self.feed.permits(url))
        with self.assertRaises(PermissionError):
            await github.refresh()
        self.assertFalse(settings.scheduled_feeds_enabled)
        self.assertFalse(type(settings).model_fields["github_exposure_public_only"].default)

    async def test_one_page_literal_provenance_unknown_dates_and_query_attribution(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "succeeded")
        self.assertEqual(self.requests[0].url.params["q"], '"example.invalid" in:file')
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(len(alerts.inbox()), 1)
        detail = alerts.detail(alerts.inbox()[0]["id"])
        self.assertEqual(detail["observation"]["subject_value"], "example.invalid")
        self.assertIn("exact content unverified", detail["observation"]["locator"])
        for name in ("observed_at", "first_seen", "last_seen"):
            self.assertIsNone(detail["observation"][name])
        for name in ("source_published_at", "source_modified_at", "source_revision"):
            self.assertIsNone(detail["document"][name])
        self.assertEqual(detail["document"]["source_url"], github.API)
        self.assertEqual(detail["document"]["sensitivity"], "sensitive")
        self.assertEqual(detail["citations"][0]["target_reference"], item()["html_url"])
        self.assertIsNone(detail["citations"][0]["target_document_id"])
        self.assertEqual(self.watch()["state"], "Current")
        self.assertEqual(self.limiter.usage("github")["day"], 1)

    async def test_two_fixed_pages_and_bounded_truncation_not_green(self):
        self.two_pages(total=2000)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.count("github_exposure_leads"), 51)
        self.assertEqual(self.watch()["state"], "Never Loaded")
        self.assertTrue(self.watch()["incomplete"])
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])

    async def test_consistent_two_page_window_has_distinct_captures(self):
        self.two_pages()
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 2)
        self.assertEqual(self.count("github_exposure_leads"), 51)
        self.assertEqual(self.watch()["state"], "Current")
        self.assertIsNotNone(self.latest(scheduler)["coverage_checkpoint"])
        self.assertEqual([request.url.params["page"] for request in self.requests], ["1", "2"])

    async def test_incomplete_drift_duplicate_and_short_pages_retain_leads_without_renewal(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        good = self.watch()["last_good"]
        for problem in ("provider", "drift", "duplicate", "short"):
            self.now += timedelta(days=1, seconds=1)
            self.two_pages()
            if problem == "provider":
                self.responses[1]["incomplete_results"] = True
            elif problem == "drift":
                self.responses[2]["total_count"] = 52
            elif problem == "duplicate":
                self.responses[2]["items"] = [item(1)]
            else:
                self.responses[2]["items"] = []
            await self.step(scheduler)
            self.assertTrue(self.watch()["incomplete"])
            self.assertEqual(self.watch()["last_good"], good)
        self.assertEqual(self.watch()["state"], "Stale")

    async def test_raw_forced_omitted_unknown_metadata_and_query_not_in_capture_logs(self):
        self.override(settings, "archive_enabled", True)
        self.override(settings, "archive_public_sources", (github.KEY,))
        self.responses[1]["items"][0].update(password="synthetic-discard-secret", description="synthetic-discard-description")
        await self.step(self.scheduler())
        result = store.capture(self.watch()["document_id"])
        self.assertEqual(result["archive"]["state"], "omitted")
        with evidence.connect() as conn:
            for table in ("github_exposure_pages", "github_exposure_leads", "evidence_documents", "durable_job_documents", "durable_job_runs"):
                text = repr([tuple(row) for row in conn.execute("SELECT * FROM "+table)])
                for value in ("synthetic-discard-secret", "synthetic-discard-description", '"example.invalid" in:file', settings.github_exposure_token):
                    self.assertNotIn(value, text)

    async def test_dedup_new_revision_retains_reviews_and_different_queries_do_not_merge_captures(self):
        scheduler = self.scheduler()
        await self.step(scheduler)
        first = alerts.inbox()[0]
        alerts.review(first["id"], "dismissed", 0)
        self.responses[1] = body([item(sha="c"*40)])
        self.now += timedelta(days=1, seconds=1)
        await self.step(scheduler)
        alerts.scan_page(self.selector)
        self.assertEqual(len(alerts.inbox()), 1)
        self.assertEqual(alerts.detail(first["id"])["alert"]["state"], "dismissed")
        self.assertEqual(self.count("github_exposure_leads"), 2)
        other = alerts.add_selector(alerts.Selector(subject_type="github_organization", value="anycorp"))
        alerts.scan_page(other)
        self.assertEqual(len(alerts.inbox()), 1)  # No inferred org attribution.
        self.approve(other)
        self.now += timedelta(days=1, seconds=1)
        await self.step(scheduler)
        self.assertEqual(len(alerts.inbox()), 2)
        self.assertEqual(self.count("evidence_documents"), 4)

    async def test_atomic_rollback_staged_recovery_preserves_original_capture(self):
        scheduler = self.scheduler()
        with patch.object(alerts, "match_observation", side_effect=Crash()), self.assertRaises(Crash):
            await self.step(scheduler)
        self.assertEqual(self.count("github_exposure_leads"), 0)
        self.assertEqual(self.count("evidence_alerts"), 0)
        with evidence.connect() as conn:
            original = dict(conn.execute("SELECT * FROM evidence_documents").fetchone())
        self.responses[1] = body([item(2)])
        await self.restart(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        result = store.capture(original["id"])
        self.assertEqual(result["document"]["job_run_id"], original["job_run_id"])
        self.assertEqual(self.watch()["last_good"], original["collected_at"])
        self.assertEqual(result["leads"][0]["lead"]["path"], item()["path"])

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

    async def test_interrupted_pagination_never_refetches_committed_page(self):
        self.two_pages()
        scheduler = self.scheduler()
        original = github.fetch
        async def stop_second(scope, page):
            if page["page"] == 2:
                raise Crash()
            return await original(scope, page)
        with patch.object(github, "fetch", stop_second), self.assertRaises(Crash):
            await self.step(scheduler)
        first_good = self.now.isoformat(timespec="microseconds")
        await self.restart(self.scheduler())
        self.assertEqual([request.url.params["page"] for request in self.requests], ["1", "2"])
        self.assertEqual(self.watch()["last_good"], first_good)

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
        self.assertEqual(self.count("github_exposure_leads"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "source_ineligible")
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT permission_id FROM github_exposure_units").fetchone()[0], self.permission)
        self.assertNotEqual(replacement, self.permission)

    async def test_response_revocation_refuses_capture(self):
        self.after_response = lambda: store.revoke(self.permission)
        await self.step(self.scheduler())
        self.assertEqual(self.count("evidence_documents"), 0)

    async def test_query_version_token_change_disable_expiry_and_suppression_stop_new_work(self):
        scheduler = self.scheduler()
        for key, value in (("github_exposure_token", "changed-token"), ("github_exposure_public_only", False)):
            with patch.object(settings, key, value):
                if key == "github_exposure_public_only":
                    with self.assertRaises(ValueError):
                        scheduler.configure(github.KEY, enabled=True)
                # Already enabled work also refuses changed prerequisites/authority.
                await self.step(scheduler)
            self.now += timedelta(days=1, seconds=1)
        with patch.object(models, "QUERY_VERSION", "changed-version"):
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
        self.assertEqual(self.count("github_exposure_units"), 0)

    async def test_quota_wait_revocation_and_second_page_disable_refuse_next_request(self):
        scheduler = self.scheduler()
        async def wait(_vendor):
            store.revoke(self.permission)
        with patch.object(self.limiter, "_acquire", wait):
            await self.step(scheduler)
        self.assertEqual(self.requests, [])

    async def test_second_page_rechecks_selector(self):
        self.two_pages()
        original = store.ingest
        def disable(scope, page):
            original(scope, page)
            alerts.set_enabled(self.selector, False)
        with patch.object(store, "ingest", disable):
            await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("github_exposure_leads"), 50)

    async def test_source_and_schedule_disable_after_response_stop_capture(self):
        scheduler = self.scheduler()
        self.after_response = lambda: scheduler.configure(github.KEY, enabled=False)
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)
        scheduler.configure(github.KEY, enabled=True)
        self.now += timedelta(days=1, seconds=1)
        self.after_response = lambda: evidence.save_source(self.source.model_copy(update={"collection_enabled": False}))
        await self.step(scheduler)
        self.assertEqual(self.count("evidence_documents"), 0)

    async def test_cancellation_mid_request_is_terminal(self):
        scheduler = self.scheduler()
        self.after_response = lambda: scheduler.runner.cancel(self.latest(scheduler)["id"])
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "cancelled")
        self.assertEqual(self.count("github_exposure_leads"), 0)

    async def test_403_429_and_success_remaining_zero_persist_cooldown(self):
        scheduler = self.scheduler()
        self.status = 403
        self.headers = {"Retry-After": "900", "X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(self.now.timestamp())+1800)}
        await self.step(scheduler)
        self.now += timedelta(seconds=601)
        await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 1)
        self.now += timedelta(seconds=1201)
        self.status = 429
        self.headers = {"Retry-After": "1200"}
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.latest(scheduler)["error_code"], "rate_limit")

    async def test_success_zero_remaining_stages_before_next_page_pause(self):
        self.two_pages()
        self.headers = {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": str(int(self.now.timestamp())+900)}
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("github_exposure_leads"), 50)
        self.headers = {}
        self.now += timedelta(seconds=901)
        await self.step(self.scheduler())
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.watch()["state"], "Current")

    async def test_durable_daily_quota_and_byte_budget_prevent_transport(self):
        scheduler = self.scheduler(replace(self.feed, rpd=1))
        with evidence.connect() as conn, conn:
            conn.execute("INSERT INTO feed_request_usage VALUES ('github',?)", (self.now.timestamp(),))
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
        self.assertEqual(self.count("github_exposure_leads"), 50)
        self.assertTrue(self.watch()["incomplete"])
        self.assertIsNone(self.latest(scheduler)["coverage_checkpoint"])

    async def test_stream_timeout_and_soft_elapsed_limit(self):
        class SlowBody(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"{"
                await asyncio.sleep(1.1)
                yield b"}"
        def slow(request):
            self.requests.append(request)
            return httpx.Response(200, stream=SlowBody(), headers={"Content-Type": "application/json"})
        async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as client:
            base.set_client(client)
            scheduler = self.scheduler(replace(self.feed, seconds=1))
            await self.step(scheduler)
        base.set_client(self.client)
        self.assertEqual(self.count("evidence_documents"), 0)
        self.assertEqual(self.latest(scheduler)["error_code"], "transient")
        self.now += timedelta(days=1, seconds=1)
        async def wait(_vendor):
            await asyncio.sleep(1.01)
        with patch.object(self.limiter, "_acquire", wait):
            await self.step(scheduler)
        self.assertEqual(len(self.requests), 1)

    async def test_invalid_oversized_nonjson_redirect_private_and_access_fail_closed(self):
        scheduler = self.scheduler()
        for status, raw, media in ((200, b"{", "application/json"), (200, b"x"*(models.MAX_BYTES+1), "application/json"),
                                  (302, b"", "application/json"), (200, b"{}", "text/html"),
                                  (401, b"private error", "application/json"), (422, b"private query", "application/json"),
                                  (200, json.dumps(body([item(repository={"id": 1, "full_name": "x/y", "private": True})])).encode(), "application/json")):
            self.status, self.raw, self.media = status, raw, media
            self.now += timedelta(days=1, seconds=1)
            await self.step(scheduler)
            self.assertEqual(self.count("github_exposure_leads"), 0)
            self.assertEqual(self.watch()["state"], "Never Loaded")
        self.assertEqual(self.count("evidence_documents"), 0)

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
        evidence.save_source(Source(source_id=github.KEY, name="Unreviewed"))
        with self.assertRaises(PermissionError):
            scheduler.configure(github.KEY, enabled=True)

    async def test_capacity_references_and_only_exact_github_selectors_approved(self):
        for index in range(9):
            self.approve(alerts.add_selector(alerts.Selector(subject_type="github_organization", value=f"corp{index}")))
        with self.assertRaises(ValueError):
            self.approve(alerts.add_selector(alerts.Selector(subject_type="github_organization", value="excesscorp")))
        with self.assertRaises(ValueError):
            self.approve(alerts.add_selector(alerts.Selector(subject_type="domain", value="example.invalid")))
        with self.assertRaises(ValueError):
            store.approve(self.selector, authority_reference="x"*257, purpose="defensive", expires_at="2029-01-01T00:00:00Z")

    async def test_multiple_selector_windows_have_independent_progress_and_captures(self):
        second = alerts.add_selector(alerts.Selector(subject_type="github_organization", value="anycorp"))
        self.approve(second)
        scheduler = self.scheduler()
        await self.step(scheduler)
        self.assertEqual(self.latest(scheduler)["state"], "succeeded")
        self.assertEqual(self.latest(scheduler)["progress_done"], 2)
        self.assertEqual(self.count("evidence_documents"), 2)
        self.assertEqual(len(alerts.inbox()), 2)
        self.assertIsNotNone(self.latest(scheduler)["coverage_checkpoint"])

    async def test_plan_is_frozen_before_permissions_added_on_resumption(self):
        scheduler = self.scheduler()
        original = store.plan
        def stop(scope):
            original(scope)
            raise Crash()
        with patch.object(store, "plan", stop), self.assertRaises(Crash):
            await self.step(scheduler)
        second = alerts.add_selector(alerts.Selector(subject_type="github_organization", value="anycorp"))
        self.approve(second)
        await self.restart(scheduler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.count("github_exposure_units"), 1)
        self.assertEqual(self.count("github_exposure_pages"), 2)

    async def test_eligibility_at_ingestion_row_boundary_rolls_back_all_matches(self):
        self.responses[1] = body([item(), item(2)])
        original = store.check
        def guarded(scope, permission_id, *, connection=None):
            if connection is not None and connection.execute("SELECT 1 FROM github_exposure_leads LIMIT 1").fetchone():
                raise PermissionError("Synthetic eligibility loss after first row")
            return original(scope, permission_id, connection=connection)
        with patch.object(store, "check", guarded):
            await self.step(self.scheduler())
        self.assertEqual(self.count("github_exposure_leads"), 0)
        self.assertEqual(self.count("evidence_observations"), 0)
        self.assertEqual(self.count("evidence_alerts"), 0)
        self.assertEqual(self.count("evidence_citations"), 0)
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT completed FROM github_exposure_pages WHERE page=1").fetchone()[0], 0)

    async def test_staged_input_cannot_be_replaced_and_checks_original_capture_scope(self):
        scheduler = self.scheduler()
        original = store.stage
        def conflicting(scope, page, document_id, value):
            original(scope, page, document_id, value)
            different = models.parse(json.dumps(body([item(2)])).encode())
            with self.assertRaises(evidence.EvidenceConflict):
                original(scope, page, document_id, different)
        with patch.object(store, "stage", conflicting):
            await self.step(scheduler)
        self.assertEqual(self.watch()["state"], "Current")
        self.assertEqual(store.capture(self.watch()["document_id"])["leads"][0]["lead"]["path"], item()["path"])

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
        self.assertEqual(self.count("github_exposure_leads"), 0)
        self.responses[1] = body([item(2)])
        self.now += timedelta(days=1, seconds=1)
        await self.step(scheduler)
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.count("github_exposure_leads"), 1)
        self.assertEqual(store.capture(self.watch()["document_id"])["leads"][0]["lead"]["path"], item(2)["path"])

    async def test_api_version_change_refuses_original_permission(self):
        with patch.object(models, "API_VERSION", "future-version"):
            await self.step(self.scheduler())
        self.assertEqual(self.requests, [])

    async def test_rolling_minute_quota_stops_before_transport(self):
        scheduler = self.scheduler(replace(self.feed, rpm=1))
        with evidence.connect() as conn, conn:
            conn.execute("INSERT INTO feed_request_usage VALUES ('github',?)", (self.now.timestamp(),))
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

    async def test_passive_pages_have_unknown_dates_coverage_and_inbox_links(self):
        await self.step(self.scheduler())
        from app.main import app
        ident = self.watch()["document_id"]
        with TestClient(app, base_url="http://127.0.0.1") as client:
            for url in ("/github-exposure", f"/github-exposure/captures/{ident}",
                        f"/github-exposure/watches/{self.selector}", f"/alerts/{alerts.inbox()[0]['id']}"):
                response = client.get(url)
                self.assertEqual(response.status_code, 200, url)
            text = client.get(f"/github-exposure/captures/{ident}").text
            self.assertIn("Published: Unknown", text)
            self.assertIn("Literal Provider References", text)
            self.assertNotIn('href="https://github.com/anycorp/', text)
        self.assertEqual(len(self.requests), 1)


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
        self.assertFalse(conn.execute("SELECT 1 FROM sqlite_master WHERE name='github_exposure_permissions'").fetchone())
        schema.migrate(conn)
        schema.migrate(conn)
        self.assertEqual(conn.execute("SELECT count(*) FROM github_exposure_versions").fetchone()[0], 1)
        conn.execute("INSERT INTO github_exposure_versions VALUES (99,'future')")
        conn.commit()
        with self.assertRaises(RuntimeError):
            schema.migrate(conn)
