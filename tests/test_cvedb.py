"""Synthetic CVEDB comparisons. No provider calls or imported source fixtures."""

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.core import cache
from app.main import app
from app.modules.vulnerability_intelligence import service, store
from app.modules.vulnerability_intelligence.sources import cvedb
from tests.test_vulnintel import TempDbMixin

CVE = "CVE-2026-12345"
NOW = datetime(2026, 11, 24, 12, tzinfo=timezone.utc)


def body(**kw):
    return {"cve_id": CVE, "cvss_v4": None, "cvss_v3": 8.1, "cvss_version": 3,
            "epss": 0.03, "kev": True, **kw}


class CvedbTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def test_only_keyless_fixed_endpoint_and_fresh_cache_reuse(self):
        with patch.object(cvedb.base, "fetch_json", new=AsyncMock(return_value=(200,body(),None))) as fetch, \
             patch.object(cvedb.rate_limiter, "acquire", new=AsyncMock()) as acquire:
            first = await cvedb.lookup(CVE)
            second = await cvedb.lookup(CVE)
        self.assertEqual(first["status"], "ok")
        self.assertEqual(first["fetched_at"], second["fetched_at"])
        fetch.assert_awaited_once_with("GET", cvedb.API+CVE, headers={"Accept":"application/json"})
        acquire.assert_awaited_once_with("cvedb")
        self.assertFalse(first["stale"])
        self.assertTrue(first["has_snapshot"])

    async def test_explicit_refresh_or_stale_snapshot_makes_one_new_request(self):
        with patch.object(cvedb, "_now", return_value=NOW), \
             patch.object(cvedb.base, "fetch_json", new=AsyncMock(return_value=(200,body(),None))), \
             patch.object(cvedb.rate_limiter, "acquire", new=AsyncMock()):
            await cvedb.lookup(CVE)
        with patch.object(cvedb.base, "fetch_json", new=AsyncMock(return_value=(200,body(epss=0.04),None))) as fetch, \
             patch.object(cvedb.rate_limiter, "acquire", new=AsyncMock()), \
             patch.object(cvedb, "_now", return_value=NOW+timedelta(hours=25)):
            self.assertTrue(cvedb.cached(CVE)["stale"])
            updated = await cvedb.lookup(CVE)
            await cvedb.lookup(CVE, force=True)
        self.assertEqual(fetch.await_count, 2)
        self.assertEqual(updated["data"]["epss"], 0.04)

    async def test_failure_retains_success_without_advancing_its_freshness(self):
        with patch.object(cvedb.base, "fetch_json", new=AsyncMock(return_value=(200,body(),None))), \
             patch.object(cvedb.rate_limiter, "acquire", new=AsyncMock()), patch.object(cvedb,"_now",return_value=NOW):
            success = await cvedb.lookup(CVE)
        for code,payload,error in ((429,None,None),(404,None,None),(500,None,None),(None,None,"SECRET provider error"),(200,body(cve_id="CVE-2026-99999"),None)):
            with self.subTest(code=code), patch.object(cvedb,"_now",return_value=NOW+timedelta(days=2)), \
                 patch.object(cvedb.base,"fetch_json",new=AsyncMock(return_value=(code,payload,error))), \
                 patch.object(cvedb.rate_limiter,"acquire",new=AsyncMock()):
                result = await cvedb.lookup(CVE, force=True)
            self.assertEqual(result["fetched_at"],success["fetched_at"])
            self.assertEqual(result["data"],success["data"])
            self.assertTrue(result["stale"])
            self.assertNotEqual(result["attempted_at"],success["attempted_at"])
            self.assertNotIn("SECRET",str(result))

    async def test_simultaneous_same_cve_requests_share_one_result(self):
        async def response(*args, **kwargs):
            await asyncio.sleep(0)
            return 200,body(),None
        with patch.object(cvedb.base,"fetch_json",new=AsyncMock(side_effect=response)) as fetch, \
             patch.object(cvedb.rate_limiter,"acquire",new=AsyncMock()):
            a,b=await asyncio.gather(cvedb.lookup(CVE),cvedb.lookup(CVE))
        self.assertEqual(a["fetched_at"],b["fetched_at"])
        fetch.assert_awaited_once()

    def test_values_identity_and_version_uncertainty_are_preserved(self):
        data=cvedb.summarise(body(cvss_v4=0,epss=0,kev=False),CVE)
        self.assertEqual(data["cvss"],0)
        self.assertEqual(data["cvss_version"],"4.0")
        self.assertIs(data["kev"],False)
        for value in (True,"0.8",-1,1.1,float('nan'),float('inf'),10**400):
            self.assertIsNone(cvedb.summarise(body(epss=value),CVE)["epss"])
        self.assertIsNone(cvedb.summarise(body(kev="false"),CVE)["kev"])
        with self.assertRaises(ValueError):cvedb.summarise(body(cve_id="CVE-2026-99999"),CVE)
        with self.assertRaises(ValueError):cvedb._id("CVE-2026-12345/path?secret=1")
        rep={"cve":{"cvss_score":8.1,"cvss_version":"3.1"},"epss":{"epss":0.04,"score_date":"2026-11-24"}}
        rows=cvedb.comparison(rep,{"data":cvedb.summarise(body(),CVE)},"Exploitation Reported")
        self.assertEqual(rows[0]["note"],"Version Not Aligned")
        self.assertIn("Dates Not Aligned",rows[1]["note"])
        self.assertIn("May Share Upstream",rows[2]["note"])
        rows=cvedb.comparison(rep,{"data":cvedb.summarise(body(cvss_version=3.1,cvss_v3=9.0),CVE)},"No Exploitation Reported")
        self.assertIn("Different Score",rows[0]["note"])
        self.assertEqual(rows[2]["note"],"Source Coverage Not Aligned")

    def test_get_is_local_post_is_guarded_and_crosscheck_does_not_change_triage(self):
        client=TestClient(app,base_url="http://127.0.0.1")
        store.save_cve({"cve_id":CVE,"description":"Synthetic comparison test","cvss_score":8.1,"cvss_version":"3.1"})
        before=asyncio.run(service.report(CVE,local_first=True))
        prefix="/vulnerability-intelligence/cve/"+CVE
        with patch.object(cvedb,"lookup",new=AsyncMock()) as lookup:
            response=client.get(prefix)
            self.assertEqual(response.status_code,200)
            self.assertIn("CVEDB Source Comparison",response.text)
            lookup.assert_not_awaited()
            self.assertEqual(client.post(prefix+"/cvedb",headers={"Sec-Fetch-Site":"cross-site"}).status_code,403)
            self.assertEqual(client.post("/vulnerability-intelligence/cve/invalid/cvedb").status_code,400)
            lookup.assert_not_awaited()
            result=client.post(prefix+"/cvedb",data={"force":"true"},follow_redirects=False)
            self.assertEqual(result.status_code,303)
            lookup.assert_awaited_once_with(CVE,force=True)
        cache.put(cvedb.VENDOR,"v1:"+CVE,{"status":"error","error":"Synthetic failure","data":cvedb.summarise(body(ransomware_campaign='<script>never()</script>'),CVE),"fetched_at":(NOW-timedelta(days=3)).isoformat(),"attempted_at":NOW.isoformat()},cvedb.RETENTION_SECONDS)
        page=client.get(prefix).text
        self.assertIn("Stale: Over 24 Hours Old",page)
        self.assertIn("Showing the previous successful result",page)
        self.assertIn("&lt;script&gt;never()&lt;/script&gt;",page)
        self.assertNotIn('<script>never()',page)
        after=asyncio.run(service.report(CVE,local_first=True))
        for field in ("priority","actions","kev","fix_status"):
            self.assertEqual(before.get(field),after.get(field))
