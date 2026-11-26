"""Prevent lost NVD windows and distinguish absent imports from absent facts."""

import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlsplit

from app.core.db import connect
from app.modules.vulnerability_intelligence import store
from app.modules.vulnerability_intelligence.feeds import nvd_recent
from scripts.audit_vulnerability_coverage import snapshot
from tests.test_vulnintel import TempDbMixin


def page(number=1, total=2):
    return 200, json.dumps({"totalResults": total, "vulnerabilities": [
        {"cve": {"id": f"CVE-2026-{10000 + number}"}}]}).encode(), None


class NvdCoverageTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def test_malformed_success_response_cannot_complete_window(self):
        for body in ({}, {"totalResults": 1, "vulnerabilities": [{}]},
                     {"totalResults": 1, "startIndex": 999, "vulnerabilities": [{"cve": {"id": "CVE-2026-12345"}}]}):
            with patch.object(nvd_recent.rate_limiter, "acquire", new=AsyncMock()), \
                 patch.object(nvd_recent, "fetch_bytes", new=AsyncMock(return_value=(200, json.dumps(body).encode(), None))):
                result = await nvd_recent.refresh()
            self.assertFalse(result["ok"])
            self.assertIsNone(store.get_sync(nvd_recent.COMPLETED))
            self.assertTrue(store.get_sync(nvd_recent.PENDING))

    async def test_partial_failure_is_not_success_and_replays_same_window(self):
        with patch.object(nvd_recent, "PAGE", 1), patch.object(nvd_recent.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(nvd_recent, "fetch_bytes", new=AsyncMock(side_effect=[page(), (500, b"", None)])):
            result = await nvd_recent.refresh()
        self.assertFalse(result["ok"])
        self.assertEqual(result["entries"], 1)
        self.assertTrue(store.feed_status()[nvd_recent.FEED]["error"])
        retained = json.loads(store.get_sync(nvd_recent.PENDING))
        self.assertIsNone(store.get_sync(nvd_recent.COMPLETED))
        with patch.object(nvd_recent, "PAGE", 1), patch.object(nvd_recent.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(nvd_recent, "fetch_bytes", new=AsyncMock(side_effect=[page(), page(2)])) as fetch:
            result = await nvd_recent.refresh()
        self.assertTrue(result["ok"])
        params = [parse_qs(urlsplit(call.args[0]).query) for call in fetch.call_args_list]
        self.assertEqual([row["startIndex"] for row in params], [["0"], ["1"]])
        self.assertEqual(params[0]["lastModStartDate"], params[1]["lastModStartDate"])
        self.assertEqual(store.get_sync(nvd_recent.COMPLETED), retained["end"])
        self.assertFalse(store.get_sync(nvd_recent.PENDING))
        self.assertIsNotNone(store.get_cve("CVE-2026-10002"))

    async def test_cap_splits_window_without_advancing_old_checkpoint(self):
        checkpoint = "2020-01-01T00:00:00+00:00"
        store.set_sync(nvd_recent.COMPLETED, checkpoint)
        with patch.object(nvd_recent, "PAGE", 1), patch.object(nvd_recent, "MAX_PAGES", 1), \
             patch.object(nvd_recent.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(nvd_recent, "fetch_bytes", new=AsyncMock(return_value=page())):
            result = await nvd_recent.refresh()
        self.assertFalse(result["ok"])
        self.assertEqual(store.get_sync(nvd_recent.COMPLETED), checkpoint)
        pending = json.loads(store.get_sync(nvd_recent.PENDING))
        self.assertEqual(pending["start"], "2019-12-31T23:00:00+00:00")
        span = datetime.fromisoformat(pending["end"]) - datetime.fromisoformat(pending["start"])
        self.assertEqual(span, timedelta(days=3.5))

    async def test_legacy_partial_and_empty_response_do_not_hide_gap(self):
        store.set_feed_status(nvd_recent.FEED, entries=4000,
            version="4,000 CVEs modified since 2020-01-01 00:47 UTC (6,472 available; partial: ReadTimeout)")
        with patch.object(nvd_recent.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(nvd_recent, "fetch_bytes", new=AsyncMock(return_value=(200,
                 b'{"totalResults": 1, "vulnerabilities": []}', None))):
            result = await nvd_recent.refresh()
        self.assertFalse(result["ok"])
        self.assertIsNone(store.get_sync(nvd_recent.COMPLETED))
        self.assertEqual(json.loads(store.get_sync(nvd_recent.PENDING))["start"], "2020-01-01T00:47:00+00:00")


class CoverageAuditTests(TempDbMixin, unittest.TestCase):
    def test_counts_separate_source_presence_missing_fields_and_uncited_claims(self):
        first, second = "CVE-2026-33001", "CVE-2026-33002"
        store.save_cve({"cve_id": first, "cvss_score": 6.1, "cwe": "CWE-601", "products": [
            {"vendor": "Example", "product": "Gateway"}]})
        store.upsert_epss([(second, 0.1, 0.9)], "2026-11-20")
        store.save_ssvc(first, {"exploitation": "active", "automatable": "no", "technical_impact": "partial", "timestamp": "2026-11-20"})
        store.replace_recent_sightings([(first, "exploitation-claim", "2026-11-20", 1),
                                       (second, "exploitation-claim", "2026-11-20", 1)],
            [(first, "2026-11-20", "Telegram", "", 1), (second, "2026-11-20", "Telegram", "", 1)])
        with connect() as conn:
            before = conn.total_changes
            result = snapshot(conn)
            self.assertEqual(conn.total_changes, before)
        self.assertEqual(result["catalog"], {"total": 2, "missing_nvd": 1, "missing_cvss": 1,
                                           "missing_cwe": 1, "missing_vendor_product": 1})
        self.assertEqual(result["uncited_claims"]["cves"], 2)
        self.assertEqual(result["uncited_claims"]["without_other_exploitation_evidence"], 1)
