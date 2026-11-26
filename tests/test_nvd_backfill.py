"""Resumable targeted NVD repair, entirely offline in temporary databases."""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.core.db import connect
from app.main import app
from app.modules.vulnerability_intelligence import metadata, store
from app.modules.vulnerability_intelligence.sources import nvd
from tests.test_vulnintel import TempDbMixin


def seed(number, **fields):
    cve = f"CVE-2026-{40000 + number}"
    store.save_ssvc(cve, {"exploitation": "active", "timestamp": "2026-11-20"})
    if fields:
        store.save_cve({"cve_id": cve, **fields})
    return cve


def record(cve, complete=True):
    return {"status": "ok", "cve": {"cve_id": cve, "description": "Synthetic NVD metadata.",
        "cvss_score": 6.1 if complete else None, "cwe": "CWE-601" if complete else None,
        "products": [{"vendor": "Example", "product": "Gateway"}] if complete else []}, "error": None}


def state(cve):
    with connect() as conn:
        return dict(conn.execute("SELECT * FROM nvd_backfill_queue WHERE cve_id=?", (cve,)).fetchone())


class BackfillTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def test_source_rejects_wrong_identity_malformed_empty_and_maps_rate_limit(self):
        for status, body, expected in ((200, {}, "error"),
                (200, {"vulnerabilities": [{"cve": {"id": "CVE-2026-49999"}}]}, "error"),
                (200, {"vulnerabilities": [], "totalResults": 1}, "error"), (429, None, "quota")):
            with patch.object(nvd.rate_limiter, "acquire", new=AsyncMock()), \
                 patch.object(nvd.base, "fetch_json", new=AsyncMock(return_value=(status, body, None))):
                self.assertEqual((await nvd.fetch("CVE-2026-40001", keyless=True))["status"], expected)

    async def test_selection_priority_and_rejected_exclusion(self):
        product = seed(1, cvss_score=6.1, cwe="CWE-601")
        score = seed(2, cwe="CWE-601", products=[{"vendor": "Example", "product": "Gateway"}])
        cwe = seed(3, cvss_score=6.1, products=[{"vendor": "Example", "product": "Gateway"}])
        seed(4, status="Rejected")
        seed(5, cvss_score=6.1, cwe="CWE-601", products=[{"vendor": "Example", "product": "Gateway"}])
        store.save_cve({"cve_id": "CVE-2026-49999"})  # not reported exploited
        self.assertEqual([(row["cve_id"], row["priority"]) for row in metadata.candidates()],
                         [(product, 0), (score, 1), (cwe, 2)])

    async def test_batch_limit_resume_and_unknown_fields_do_not_loop(self):
        cves = [seed(number) for number in range(1, 7)]
        async def fetch(cve, **kwargs):
            self.assertTrue(kwargs["keyless"])
            return record(cve, complete=cve in cves[:2])
        with patch.object(nvd, "fetch", new=AsyncMock(side_effect=fetch)) as fetcher:
            result = await metadata.run(5)
            self.assertEqual((result["attempted"], result["retrieved"]), (5, 5))
            self.assertEqual(metadata.page()["pending"], 1)
            await metadata.run(5)
            await metadata.run(5)
            self.assertEqual(fetcher.await_count, 6)
        self.assertEqual(state(cves[2])["state"], "retrieved")
        self.assertGreater(metadata.page()["gaps"], 0)
        self.assertEqual(metadata.page()["pending"], 0)

    async def test_not_found_is_tracked_without_endless_retry(self):
        cve = seed(1)
        with patch.object(nvd, "fetch", new=AsyncMock(return_value={"status": "not_found", "error": "No record"})) as fetch:
            self.assertEqual((await metadata.run())["not_found"], 1)
            await metadata.run()
            fetch.assert_awaited_once()
        self.assertEqual(state(cve)["state"], "not_found")

    async def test_failure_preserves_metadata_and_retry_does_not_block_other_records(self):
        first = seed(1, cvss_score=8.1)
        second = seed(2)
        async def fetch(cve, **kwargs):
            return {"status": "error", "error": "Transport failure"} if cve == first else record(cve)
        with patch.object(nvd, "fetch", new=AsyncMock(side_effect=fetch)):
            await metadata.run()
        self.assertEqual(store.get_cve(first)["cvss_score"], 8.1)
        self.assertEqual(state(first)["state"], "failed")
        self.assertEqual(state(second)["state"], "retrieved")
        with patch.object(nvd, "fetch", new=AsyncMock(return_value=record(first))) as fetcher:
            await metadata.run(retry=True)
            fetcher.assert_awaited_once_with(first, keyless=True)
        self.assertEqual(state(first)["attempts"], 2)

    async def test_quota_or_auth_failure_pauses_without_spending_rest_of_batch(self):
        cves = [seed(number) for number in range(1, 4)]
        for response in ({"status": "quota", "error": "NVD 429"}, {"status": "error", "error": nvd.KEY_404}):
            with patch.object(nvd, "fetch", new=AsyncMock(return_value=response)) as fetch:
                self.assertEqual((await metadata.run(mode="configured"))["status"], "paused")
                fetch.assert_awaited_once()
        self.assertTrue(all(state(cve)["state"] == "pending" for cve in cves))

    async def test_wrong_cve_never_saves_or_completes_target(self):
        target = seed(1)
        with patch.object(nvd, "fetch", new=AsyncMock(return_value=record("CVE-2026-49999"))):
            await metadata.run()
        self.assertEqual(state(target)["state"], "failed")
        self.assertIsNone(store.get_cve("CVE-2026-49999"))

    async def test_time_budget_leaves_request_pending(self):
        target = seed(1)
        async def slow(*args, **kwargs):
            await asyncio.sleep(1)
        with patch.object(metadata, "RUN_SECONDS", 0.01), patch.object(nvd, "fetch", new=AsyncMock(side_effect=slow)):
            self.assertEqual((await metadata.run())["status"], "paused")
        self.assertEqual(state(target)["state"], "pending")
        self.assertEqual(state(target)["attempts"], 1)

    async def test_concurrent_run_does_not_duplicate_requests(self):
        target = seed(1)
        started, release = asyncio.Event(), asyncio.Event()
        async def fetch(*args, **kwargs):
            started.set()
            await release.wait()
            return record(target)
        with patch.object(nvd, "fetch", new=AsyncMock(side_effect=fetch)) as fetcher:
            task = asyncio.create_task(metadata.run())
            await started.wait()
            try:
                self.assertEqual((await metadata.run())["status"], "busy")
            finally:
                release.set()
                await task
            fetcher.assert_awaited_once()

    async def test_recent_feed_repair_reconciles_pending_work_without_fetching_again(self):
        target = seed(1)
        metadata.prepare(metadata.candidates())
        store.save_cve(record(target)["cve"])
        with patch.object(nvd, "fetch", new=AsyncMock()) as fetch:
            await metadata.run()
            fetch.assert_not_awaited()
        self.assertEqual(state(target)["state"], "resolved")

    async def test_interrupted_save_does_not_report_completion_and_releases_lock(self):
        target = seed(1)
        with patch.object(nvd, "fetch", new=AsyncMock(return_value=record(target))), \
             patch.object(store, "save_cve", side_effect=RuntimeError("Synthetic storage failure")):
            with self.assertRaises(RuntimeError):
                await metadata.run()
        self.assertEqual(state(target)["state"], "pending")
        self.assertEqual(json.loads(store.get_sync("nvd_backfill_last_run"))["status"], "interrupted")
        self.assertFalse(metadata._lock.locked())

    async def test_routes_validate_options_cross_site_and_get_is_read_only(self):
        seed(1)
        client = TestClient(app, base_url="http://127.0.0.1")
        path = "/vulnerability-intelligence/metadata"
        page = client.get(path)
        self.assertEqual(page.status_code, 200)
        self.assertIn("Public API Without Key", page.text)
        with connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM nvd_backfill_queue").fetchone()[0], 0)
        for data in ({"limit": "1000"}, {"mode": "https://other.example"}, {"retry": "yes"}):
            self.assertEqual(client.post(path + "/backfill", data=data).status_code, 400)
        self.assertEqual(client.post(path + "/backfill", headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
        with patch.object(metadata, "run", new=AsyncMock()) as run:
            result = client.post(path + "/backfill", data={"limit": "5", "mode": "public"}, follow_redirects=False)
            self.assertEqual(result.status_code, 303)
            run.assert_awaited_once_with(5, mode="public", retry=False)
