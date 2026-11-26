"""NVD-only recovery controls, read-only previews and bounded imports."""

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch
from datetime import datetime
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.modules.vulnerability_intelligence import feeds, store
from app.modules.vulnerability_intelligence.feeds import nvd_recent as source
from tests.test_metadata_coverage import page
from tests.test_vulnintel import TempDbMixin


class RecoveryTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def test_known_dense_window_splits_after_first_page(self):
        with patch.object(source, "PAGE", 1), patch.object(source.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(source, "fetch_bytes", new=AsyncMock(return_value=page(total=20))) as fetch:
            result = await source.refresh(keyless=True, max_pages=6)
        self.assertFalse(result["ok"])
        fetch.assert_awaited_once()
        self.assertIn("6-page allowance", result["error"])
        self.assertTrue(store.get_sync(source.PENDING))
        self.assertIsNone(store.get_sync(source.COMPLETED))

    async def test_short_page_uses_actual_count_instead_of_skipping_records(self):
        with patch.object(source.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(source, "fetch_bytes", new=AsyncMock(side_effect=[page(total=2), page(2,total=2)])) as fetch:
            result = await source.refresh(keyless=True)
        self.assertTrue(result["ok"])
        self.assertEqual([parse_qs(urlsplit(call.args[0]).query)["startIndex"] for call in fetch.call_args_list], [["0"],["1"]])
        self.assertEqual(result["entries"], 2)

    async def test_duplicate_membership_or_changed_total_cannot_complete_window(self):
        for responses in ((page(total=2),page(total=2)), (page(total=2),page(2,total=3))):
            with patch.object(source.rate_limiter, "acquire", new=AsyncMock()), \
                 patch.object(source, "fetch_bytes", new=AsyncMock(side_effect=responses)):
                result = await source.refresh(keyless=True)
            self.assertFalse(result["ok"])
            self.assertIsNone(store.get_sync(source.COMPLETED))
            self.assertTrue(store.get_sync(source.PENDING))

    def test_get_is_read_only_and_post_refreshes_only_nvd(self):
        client = TestClient(app, base_url="http://127.0.0.1")
        prefix = "/vulnerability-intelligence"
        with patch.object(source, "refresh", new=AsyncMock(return_value={"ok": True})) as refresh, \
             patch.object(feeds, "refresh_all", side_effect=AssertionError("Unrelated feeds")):
            response = client.get(prefix + "/feeds")
            self.assertEqual(response.status_code, 200)
            self.assertIn("NVD Recent-Changes Recovery", response.text)
            self.assertIsNone(store.get_sync(source.PENDING))
            refresh.assert_not_awaited()
            self.assertEqual(client.post(prefix + "/refresh-nvd", data={"mode": "other"}).status_code, 400)
            self.assertEqual(client.post(prefix + "/refresh-nvd", headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
            response = client.post(prefix + "/refresh-nvd", follow_redirects=False)
            self.assertEqual(response.status_code, 303)
            refresh.assert_awaited_once_with(keyless=True, max_pages=source.RECOVERY_PAGES)

    async def test_public_mode_omits_key_and_uses_public_limiter(self):
        with patch.object(settings, "nvd_api_key", "synthetic-key"), \
             patch.object(source.rate_limiter, "acquire", new=AsyncMock()) as acquire, \
             patch.object(source, "fetch_bytes", new=AsyncMock(return_value=(200,
                 b'{"totalResults":0,"vulnerabilities":[]}', None))) as fetch:
            result = await source.refresh(keyless=True, max_pages=6)
        self.assertTrue(result["ok"])
        self.assertNotIn("apiKey", fetch.call_args.kwargs["headers"])
        self.assertFalse(fetch.call_args.kwargs["follow_redirects"])
        acquire.assert_awaited_once_with("nvd_keyless")
        self.assertEqual(result["run"]["pages"], 1)
        self.assertEqual(result["run"]["mode"], "public")

    async def test_body_budget_stops_before_extra_request_and_splits(self):
        response = page(total=2001)
        size = len(response[1])
        with patch.object(source, "PAGE_CAP", size), patch.object(source, "BODY_BUDGET", size * 2 - 1), \
             patch.object(source.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(source, "fetch_bytes", new=AsyncMock(return_value=response)) as fetch:
            result = await source.refresh(keyless=True, max_pages=6)
        self.assertFalse(result["ok"])
        fetch.assert_awaited_once()
        self.assertIn("Body budget", result["error"])
        self.assertIsNone(store.get_sync(source.COMPLETED))
        pending = json.loads(store.get_sync(source.PENDING))
        requested_end = datetime.fromisoformat(result["run"]["end"])
        self.assertLess(datetime.fromisoformat(pending["end"]), requested_end)

    async def test_rate_wait_is_in_network_budget_without_moving_checkpoint(self):
        async def wait(*args):
            await asyncio.sleep(1)
        with patch.object(source, "RUN_SECONDS", 0.02), \
             patch.object(source.rate_limiter, "acquire", new=AsyncMock(side_effect=wait)), \
             patch.object(source, "fetch_bytes", new=AsyncMock()) as fetch:
            result = await source.refresh(keyless=True)
        self.assertFalse(result["ok"])
        fetch.assert_not_awaited()
        self.assertIsNone(store.get_sync(source.COMPLETED))
        self.assertTrue(store.get_sync(source.PENDING))

    async def test_storage_interruption_keeps_window_and_releases_lock(self):
        with patch.object(source.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(source, "fetch_bytes", new=AsyncMock(return_value=page(total=1))), \
             patch.object(store, "save_cves_bulk", side_effect=RuntimeError("Synthetic disk failure")):
            with self.assertRaises(RuntimeError):
                await source.refresh()
        self.assertEqual(json.loads(store.get_sync(source.LAST_RUN))["status"], "interrupted")
        self.assertTrue(store.get_sync(source.PENDING))
        self.assertIsNone(store.get_sync(source.COMPLETED))
        self.assertFalse(source._lock.locked())

    async def test_overlapping_import_is_rejected_without_more_requests(self):
        started, release = asyncio.Event(), asyncio.Event()
        async def fetch(*args, **kwargs):
            started.set()
            await release.wait()
            return 200, b'{"totalResults":0,"vulnerabilities":[]}', None
        with patch.object(source.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(source, "fetch_bytes", new=AsyncMock(side_effect=fetch)) as call:
            task = asyncio.create_task(source.refresh())
            await started.wait()
            try:
                self.assertTrue(source.progress()["running"])
                self.assertFalse((await source.refresh())["ok"])
            finally:
                release.set()
                await task
            call.assert_awaited_once()

    async def test_rate_limit_keeps_original_pending_window(self):
        with patch.object(source.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(source, "fetch_bytes", new=AsyncMock(side_effect=[page(total=2001), (429, None, None)])):
            result = await source.refresh(keyless=True)
        self.assertFalse(result["ok"])
        pending = json.loads(store.get_sync(source.PENDING))
        self.assertEqual(pending["end"], result["run"]["end"])
        self.assertIn("429", store.feed_status()[source.FEED]["error"])
