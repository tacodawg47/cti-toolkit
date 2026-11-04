"""
Tests for the Phase 2 vulnerability intelligence module. Pure logic for the
parsers and the priority matrix; a temporary database for the store; an
httpx mock transport for the sources; FastAPI's test client for the routes.
No network.

Run from the project root:
    .venv/Scripts/python.exe -m unittest tests.test_vulnintel -v
"""

import gzip
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import httpx

from app.core import db
from app.core.config import settings
from app.modules.enrich import base
from app.modules.vulnerability_intelligence import priority, routes, service, store
from app.modules.vulnerability_intelligence.feeds import epss as epss_feed
from app.modules.vulnerability_intelligence.feeds import kev as kev_feed
from app.modules.vulnerability_intelligence.http import gunzip_bounded
from app.modules.vulnerability_intelligence.sources import github, nvd

KEV_DOC = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.11.03",
    "dateReleased": "2026-11-03T20:00:24Z",
    "count": 2,
    "vulnerabilities": [
        {"cveID": "CVE-2023-4966", "vendorProject": "Citrix", "product": "NetScaler ADC and NetScaler Gateway",
         "vulnerabilityName": "Citrix NetScaler Buffer Overflow", "dateAdded": "2023-10-18",
         "shortDescription": "Buffer overflow.", "requiredAction": "Apply updates.", "dueDate": "2023-11-08",
         "knownRansomwareCampaignUse": "Known", "notes": "https://example.test", "cwes": ["CWE-119"]},
        {"cveID": "CVE-2026-118527", "vendorProject": "Ivanti", "product": "Connect Secure",
         "vulnerabilityName": "Ivanti Connect Secure Predictable Identifiers", "dateAdded": "2099-01-01",
         "shortDescription": "Upload.", "requiredAction": "Apply mitigations.", "dueDate": "2099-01-14",
         "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": ["CWE-340"]},
    ],
}

NVD_DOC = {
    "resultsPerPage": 1, "startIndex": 0, "totalResults": 1, "format": "NVD_CVE", "version": "2.0",
    "vulnerabilities": [{"cve": {
        "id": "CVE-2023-4966", "published": "2023-10-10T14:15:10.977", "lastModified": "2026-07-31T04:16:44.230",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": "Sensitive information disclosure."}],
        "metrics": {"cvssMetricV31": [
            {"source": "secure@citrix.com", "type": "Secondary",
             "cvssData": {"version": "3.1", "baseScore": 9.4, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L", "baseSeverity": "CRITICAL"}},
            {"source": "nvd@nist.gov", "type": "Primary",
             "cvssData": {"version": "3.1", "baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "baseSeverity": "HIGH"}},
        ]},
        "weaknesses": [{"source": "secure@citrix.com", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-119"}]},
                       {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]}],
        "references": [
            {"url": "https://support.citrix.com/article/CTX579459", "tags": ["Vendor Advisory", "Patch"]},
            {"url": "https://support.citrix.com/article/CTX579459", "tags": ["Vendor Advisory", "Patch"]},
            {"url": "http://packetstormsecurity.com/files/175323/x.html", "tags": ["Third Party Advisory", "VDB Entry"]},
            {"url": "https://example.test/no-tags", "tags": []},
        ],
        "configurations": [{"nodes": [{"cpeMatch": [
            {"criteria": "cpe:2.3:a:citrix:netscaler_application_delivery_controller:*:*:*:*:fips:*:*:*",
             "vulnerable": True, "versionStartIncluding": "12.1", "versionEndExcluding": "12.1-55.300"},
            {"criteria": "cpe:2.3:a:citrix:netscaler_gateway:13.0:*:*:*:*:*:*:*", "vulnerable": True},
            {"criteria": "cpe:2.3:o:other:thing:*:*:*:*:*:*:*:*", "vulnerable": False},
        ]}]}],
    }}],
}

GITHUB_DOC = {
    "total_count": 2, "incomplete_results": False,
    "items": [
        {"full_name": "someone/CVE-2023-4966", "html_url": "https://github.com/someone/CVE-2023-4966",
         "description": "PoC", "stargazers_count": 12, "created_at": "2023-10-25T00:00:00Z",
         "pushed_at": "2023-11-01T00:00:00Z", "fork": False, "archived": False, "owner": {"login": "someone"}},
        {"full_name": "other/scanner", "html_url": "https://github.com/other/scanner", "description": None,
         "stargazers_count": 0, "created_at": "2024-01-01T00:00:00Z", "pushed_at": "2024-01-01T00:00:00Z",
         "fork": True, "archived": True, "owner": {"login": "other"}},
    ],
}


def epss_gz(rows: list[tuple[str, str, str]], score_date: str = "2026-11-03T12:00:27Z") -> bytes:
    text = f"#model_version:v2026.06.15,score_date:{score_date}\ncve,epss,percentile\n"
    text += "\n".join(",".join(r) for r in rows) + "\n"
    return gzip.compress(text.encode())


class TempDbMixin:
    """Point the app at a temporary database with the module schema."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = settings.data_dir
        settings.data_dir = Path(self._tmp)
        db.init_db()
        store.init_schema()

    def tearDown(self):
        settings.data_dir = self._orig_dir
        shutil.rmtree(self._tmp, ignore_errors=True)


class PriorityTests(unittest.TestCase):
    def _p(self, **kw):
        args = dict(kev_sources=[], ransomware=False, epss=None, cvss=None, poc_count=0, watchlist_hits=[])
        args.update(kw)
        return priority.compute(**args)

    def test_kev_is_p1_whatever_the_cvss(self):
        p = self._p(kev_sources=["cisa"], cvss=3.1)
        self.assertEqual(p.level, "P1")
        self.assertIn("on a known-exploited list: CISA KEV", p.reasons)

    def test_high_epss_is_p2(self):
        self.assertEqual(self._p(epss=0.6).level, "P2")
        self.assertEqual(self._p(epss=0.95).level, "P2")

    def test_poc_and_watchlist_is_p2_poc_alone_is_p3(self):
        self.assertEqual(self._p(poc_count=3, watchlist_hits=["Citrix"]).level, "P2")
        self.assertEqual(self._p(poc_count=3).level, "P3")

    def test_high_cvss_with_moderate_epss_is_p3(self):
        self.assertEqual(self._p(cvss=8.8, epss=0.2).level, "P3")

    def test_p4_cases(self):
        self.assertEqual(self._p(cvss=7.5).level, "P4")
        self.assertEqual(self._p(epss=0.15).level, "P4")
        self.assertEqual(self._p(watchlist_hits=["x"]).level, "P4")

    def test_p5_and_no_data(self):
        p = self._p()
        self.assertEqual(p.level, "P5")
        self.assertIn("no scoring data yet", p.reasons)
        self.assertEqual(self._p(cvss=4.0, epss=0.01).level, "P5")

    def test_reasons_mention_ransomware_and_missing_fix(self):
        p = self._p(kev_sources=["cisa"], ransomware=True, fix_status="none")
        self.assertIn("known ransomware campaign use", p.reasons)
        self.assertTrue(any(r.startswith("no patch or vendor advisory") for r in p.reasons))
        p = self._p(kev_sources=["cisa"], fix_status="advisory")
        self.assertFalse(any(r.startswith("no patch") for r in p.reasons))


class KevParseTests(unittest.TestCase):
    def test_parse(self):
        rows, version = kev_feed.parse(json.dumps(KEV_DOC).encode())
        self.assertEqual(version, "2026.11.03")
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2023-4966", "CVE-2026-118527"])
        self.assertEqual(rows[0]["ransomware"], 1)
        self.assertEqual(rows[1]["ransomware"], 0)
        self.assertEqual(rows[0]["cwes"], ["CWE-119"])

    def test_bad_shape_raises(self):
        with self.assertRaises(ValueError):
            kev_feed.parse(b'{"nope": []}')
        with self.assertRaises(ValueError):
            kev_feed.parse(b"[]")


class EpssParseTests(unittest.TestCase):
    def test_parse(self):
        rows, date, model = epss_feed.parse(epss_gz([("CVE-1999-0001", "0.04753", "0.91894"),
                                                     ("cve-2023-4966", "0.99999", "0.99997"),
                                                     ("junk", "x", "y")]))
        self.assertEqual(date, "2026-11-03T12:00:27Z")
        self.assertEqual(model, "v2026.06.15")
        self.assertEqual(rows, [("CVE-1999-0001", 0.04753, 0.91894), ("CVE-2023-4966", 0.99999, 0.99997)])

    def test_bad_header_raises(self):
        with self.assertRaises(ValueError):
            epss_feed.parse(gzip.compress(b"#x\nfoo,bar\n1,2\n"))

    def test_gunzip_bound(self):
        with self.assertRaises(ValueError):
            gunzip_bounded(gzip.compress(b"a" * 5000), limit=1000)
        self.assertEqual(gunzip_bounded(gzip.compress(b"abc")), b"abc")


class NvdSummariseTests(unittest.TestCase):
    def test_summarise(self):
        cve = nvd.summarise(NVD_DOC)
        self.assertEqual(cve["cve_id"], "CVE-2023-4966")
        self.assertEqual(cve["description"], "Sensitive information disclosure.")
        self.assertEqual(cve["cvss_score"], 7.5)             # NVD's Primary wins over the vendor's
        self.assertEqual(cve["cvss_severity"], "HIGH")
        self.assertEqual(cve["cvss_version"], "3.1")
        self.assertEqual(cve["cwe"], "CWE-119")               # the only real CWE, even though Secondary
        self.assertTrue(cve["patch_available"])
        self.assertEqual(len(cve["products"]), 2)             # the non-vulnerable CPE is dropped
        self.assertEqual(cve["products"][0]["vendor"], "citrix")
        self.assertEqual(cve["products"][0]["end_excl"], "12.1-55.300")

    def test_empty_is_none(self):
        self.assertIsNone(nvd.summarise({"vulnerabilities": []}))
        self.assertIsNone(nvd.summarise({}))


class GithubSummariseTests(unittest.TestCase):
    def test_summarise(self):
        s = github.summarise(GITHUB_DOC)
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["repos"][0]["stars"], 12)
        self.assertEqual(s["repos"][0]["created"], "2023-10-25")
        self.assertTrue(s["repos"][1]["archived"])
        self.assertEqual(s["repos"][1]["description"], "")


class RouteHelperTests(unittest.TestCase):
    def test_group_references_dedupes_and_groups(self):
        cve = nvd.summarise(NVD_DOC)
        groups = dict(routes.group_references(cve["references"]))
        self.assertEqual(len(groups["Vendor advisory"]), 1)   # duplicate URL collapsed
        self.assertEqual(len(groups["Third-party analysis"]), 1)
        self.assertEqual(len(groups["Other"]), 1)

    def test_version_range(self):
        self.assertEqual(routes.version_range({"start_incl": "12.1", "end_excl": "12.1-55.300"}),
                         ">= 12.1 and < 12.1-55.300")
        self.assertEqual(routes.version_range({"criteria": "cpe:2.3:a:v:p:13.0:*:*:*:*:*:*:*"}), "13.0")
        self.assertEqual(routes.version_range({"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*"}), "all versions")


class StoreTests(TempDbMixin, unittest.TestCase):
    def test_kev_upsert_and_queries(self):
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        self.assertEqual(store.upsert_kev(rows, "cisa"), 2)
        store.upsert_kev(rows, "cisa")                     # idempotent
        self.assertEqual(store.kev_count(), 2)
        k = store.get_kev("CVE-2023-4966")
        self.assertEqual(k[0]["vendor"], "Citrix")
        self.assertEqual(k[0]["cwes"], ["CWE-119"])
        recent = store.recent_kev(7)
        self.assertEqual([r["cve_id"] for r in recent], ["CVE-2026-118527"])   # dated 2099, "recent"
        self.assertEqual(recent[0]["sources"], "cisa")

    def test_epss_prev_tracking_and_risers(self):
        store.upsert_epss([("CVE-2023-4966", 0.2, 0.5), ("CVE-2020-0001", 0.5, 0.9)], "2026-11-01")
        self.assertIsNone(store.get_epss("CVE-2023-4966")["prev_epss"])
        store.upsert_epss([("CVE-2023-4966", 0.9, 0.99), ("CVE-2020-0001", 0.5, 0.9)], "2026-11-02")
        e = store.get_epss("CVE-2023-4966")
        self.assertEqual((e["epss"], e["prev_epss"], e["prev_date"]), (0.9, 0.2, "2026-11-01"))
        self.assertIsNone(store.get_epss("CVE-2020-0001")["prev_epss"])   # unchanged: no movement
        risers = store.epss_risers()
        self.assertEqual([r["cve_id"] for r in risers], ["CVE-2023-4966"])
        self.assertAlmostEqual(risers[0]["delta"], 0.7)
        self.assertEqual(store.epss_count(), 2)

    def test_feed_status_keeps_last_good_on_error(self):
        store.set_feed_status("cisa_kev", entries=5, version="v1")
        store.set_feed_status("cisa_kev", error="boom")
        s = store.feed_status()["cisa_kev"]
        self.assertEqual((s["entries"], s["version"], s["error"]), (5, "v1", "boom"))
        store.set_feed_status("cisa_kev", entries=6, version="v2")
        self.assertIsNone(store.feed_status()["cisa_kev"]["error"])

    def test_cve_save_and_products(self):
        cve = nvd.summarise(NVD_DOC)
        store.save_cve(cve)
        got = store.get_cve("CVE-2023-4966")
        self.assertEqual(got["cvss_score"], 7.5)
        self.assertTrue(got["patch_available"])
        self.assertEqual(len(got["references"]), 4)
        self.assertEqual(len(got["products"]), 2)
        self.assertTrue(nvd.is_fresh(got))
        self.assertFalse(nvd.is_fresh(None))
        self.assertFalse(nvd.is_fresh({"fetched_at": "2000-01-01T00:00:00+00:00"}))

    def test_watchlist_matching(self):
        store.add_watchlist("Citrix", "NetScaler", "edge")
        store.add_watchlist("Ivanti")
        self.assertEqual(len(store.list_watchlist()), 2)
        self.assertEqual([h["vendor"] for h in store.watchlist_matches("citrix", "netscaler_application_delivery_controller")], ["Citrix"])
        self.assertEqual([h["vendor"] for h in store.watchlist_matches("Citrix", "NetScaler ADC and NetScaler Gateway")], ["Citrix"])
        self.assertEqual(store.watchlist_matches("Citrix", "XenApp"), [])            # product differs
        self.assertEqual([h["vendor"] for h in store.watchlist_matches("Ivanti", "Connect Secure")], ["Ivanti"])
        self.assertEqual(store.watchlist_matches("Fortinet", "FortiOS"), [])
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        store.upsert_kev(rows, "cisa")
        stack = store.stack_kev()
        self.assertEqual([r["cve_id"] for r in stack], ["CVE-2026-118527", "CVE-2023-4966"])
        self.assertEqual(stack[1]["matched"], ["Citrix NetScaler"])
        entry = store.list_watchlist()[1]
        store.delete_watchlist(entry["id"])
        self.assertEqual(len(store.list_watchlist()), 1)

    def test_aliases(self):
        self.assertGreater(service.seed_aliases(), 10)
        self.assertEqual(service.seed_aliases(), 0)                                   # idempotent
        self.assertEqual(store.resolve_alias("citrixbleed"), ["CVE-2023-4966"])
        self.assertEqual(store.resolve_alias("Citrix Bleed"), ["CVE-2023-4966"])
        self.assertEqual(store.resolve_alias("proxy-shell"), ["CVE-2021-31207", "CVE-2021-34473", "CVE-2021-34523"])
        self.assertEqual(store.resolve_alias("nothing"), [])
        store.add_alias("MyBug", "cve-2024-0001")
        self.assertEqual(store.resolve_alias("mybug"), ["CVE-2024-0001"])
        store.delete_alias("mybug", "CVE-2024-0001")
        self.assertEqual(store.resolve_alias("mybug"), [])


def _transport(nvd_body=NVD_DOC, github_body=GITHUB_DOC, nvd_status=200, github_status=200):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "services.nvd.nist.gov":
            return httpx.Response(nvd_status, json=nvd_body)
        if req.url.host == "api.github.com":
            return httpx.Response(github_status, json=github_body)
        raise AssertionError(f"unexpected host {req.url.host}")
    return httpx.MockTransport(handler)


class ServiceTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    async def test_report_assembles_everything(self):
        base.set_client(httpx.AsyncClient(transport=_transport()))
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        store.upsert_kev(rows, "cisa")
        store.upsert_epss([("CVE-2023-4966", 0.99, 0.999)], "2026-11-03")
        store.add_watchlist("Citrix")
        rep = await service.report("CVE-2023-4966")
        self.assertEqual(rep["priority"].level, "P1")
        self.assertEqual(rep["cve"]["cvss_score"], 7.5)
        self.assertFalse(rep["nvd"]["cached"])
        self.assertEqual(rep["github"]["total"], 2)
        self.assertEqual(rep["watchlist_hits"], ["Citrix"])
        self.assertEqual(rep["fix_status"], "patch")
        # second call: NVD comes from the store, GitHub from the cache
        rep2 = await service.report("CVE-2023-4966")
        self.assertTrue(rep2["nvd"]["cached"])
        self.assertTrue(rep2["github"]["cached"])

    async def test_nvd_failure_keeps_stored_copy(self):
        base.set_client(httpx.AsyncClient(transport=_transport()))
        await service.report("CVE-2023-4966")
        base.set_client(httpx.AsyncClient(transport=_transport(nvd_status=503)))
        rep = await service.report("CVE-2023-4966", force=True)
        self.assertEqual(rep["nvd"]["status"], "error")
        self.assertTrue(rep["nvd"].get("stale"))
        self.assertEqual(rep["cve"]["cvss_score"], 7.5)

    async def test_unknown_cve(self):
        base.set_client(httpx.AsyncClient(transport=_transport(nvd_body={"vulnerabilities": []},
                                                                github_body={"total_count": 0, "items": []})))
        rep = await service.report("CVE-2099-9999")
        self.assertEqual(rep["nvd"]["status"], "not_found")
        self.assertIsNone(rep["cve"])
        self.assertEqual(rep["priority"].level, "P5")

    async def test_github_quota_and_feed_errors(self):
        base.set_client(httpx.AsyncClient(transport=_transport(github_status=403)))
        gh = await github.search("CVE-2023-4966")
        self.assertEqual(gh["status"], "quota")
        # A feed that 500s records the error without raising.
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))))
        res = await kev_feed.refresh()
        self.assertFalse(res["ok"])
        self.assertIn("500", store.feed_status()["cisa_kev"]["error"])

    async def test_feeds_refresh_end_to_end(self):
        def handler(req):
            if "cisa.gov" in req.url.host:
                return httpx.Response(200, json=KEV_DOC)
            if "empiricalsecurity" in req.url.host:
                return httpx.Response(200, content=epss_gz([("CVE-2023-4966", "0.99", "0.999")]))
            raise AssertionError(req.url.host)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        from app.modules.vulnerability_intelligence import feeds
        results = await feeds.refresh_all()
        self.assertTrue(all(r["ok"] for r in results), results)
        self.assertEqual(store.kev_count(), 2)
        self.assertEqual(store.epss_count(), 1)
        self.assertEqual(store.feed_status()["cisa_kev"]["version"], "2026.11.03")


class RouteTests(TempDbMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app, base_url="http://127.0.0.1")
        base.set_client(httpx.AsyncClient(transport=_transport()))
        service.seed_aliases()

    def tearDown(self):
        import asyncio
        asyncio.run(base.aclose())
        super().tearDown()

    def test_dashboard_empty(self):
        r = self.client.get("/vulnerability-intelligence")
        self.assertEqual(r.status_code, 200)
        self.assertIn("not loaded", r.text)
        self.assertIn("watchlist is empty", r.text)

    def test_search_redirects_for_cve_and_alias(self):
        r = self.client.get("/vulnerability-intelligence/search", params={"q": "cve-2023-4966"}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertTrue(r.headers["location"].endswith("/cve/CVE-2023-4966"))
        r = self.client.get("/vulnerability-intelligence/search", params={"q": "log4shell"}, follow_redirects=False)
        self.assertTrue(r.headers["location"].endswith("/cve/CVE-2021-44228"))
        r = self.client.get("/vulnerability-intelligence/search", params={"q": "proxyshell"})
        self.assertIn("refers to 3 CVEs", r.text)
        r = self.client.get("/vulnerability-intelligence/search", params={"q": "zzz"})
        self.assertIn("No CVE ID and no known nickname", r.text)

    def test_cve_page(self):
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        store.upsert_kev(rows, "cisa")
        r = self.client.get("/vulnerability-intelligence/cve/CVE-2023-4966")
        self.assertEqual(r.status_code, 200)
        for needle in ("P1 Emergency", "Sensitive information disclosure.", "7.5", "CWE-119",
                       "Known exploited", "someone/CVE-2023-4966", "Vendor advisory", "12.1-55.300",
                       "patch tagged in NVD"):
            self.assertIn(needle, r.text)
        r = self.client.get("/vulnerability-intelligence/cve/not-a-cve")
        self.assertIn("not a CVE identifier", r.text)

    def test_exploits_tab(self):
        r = self.client.get("/vulnerability-intelligence/exploits", params={"cve": "CVE-2023-4966"})
        self.assertIn("someone/CVE-2023-4966", r.text)
        r = self.client.get("/vulnerability-intelligence/exploits", params={"cve": "bogus"})
        self.assertIn("not a CVE identifier", r.text)

    def test_watchlist_and_alias_forms(self):
        r = self.client.post("/vulnerability-intelligence/watchlist/add",
                             data={"vendor": "Fortinet", "product": "FortiOS"}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        r = self.client.get("/vulnerability-intelligence/watchlist")
        self.assertIn("Fortinet", r.text)
        entry = store.list_watchlist()[0]
        self.client.post("/vulnerability-intelligence/watchlist/delete", data={"entry_id": entry["id"]})
        self.assertEqual(store.list_watchlist(), [])
        r = self.client.post("/vulnerability-intelligence/watchlist/add", data={"vendor": "  "}, follow_redirects=False)
        self.assertIn("vendor+is+required", r.headers["location"])
        self.client.post("/vulnerability-intelligence/aliases/add", data={"alias": "TestBug", "cve_id": "cve-2024-1234"})
        self.assertEqual(store.resolve_alias("testbug"), ["CVE-2024-1234"])
        r = self.client.post("/vulnerability-intelligence/aliases/add", data={"alias": "x", "cve_id": "nope"}, follow_redirects=False)
        self.assertIn("valid+CVE+ID", r.headers["location"])

    def test_cross_site_posts_rejected(self):
        for path, data in (("/vulnerability-intelligence/refresh", {}),
                           ("/vulnerability-intelligence/watchlist/add", {"vendor": "x"}),
                           ("/vulnerability-intelligence/aliases/add", {"alias": "x", "cve_id": "CVE-2024-1"})):
            r = self.client.post(path, data=data, headers={"sec-fetch-site": "cross-site"})
            self.assertEqual(r.status_code, 403, path)

    def test_enrich_and_extract_link_to_cve_page(self):
        r = self.client.post("/enrich", data={"indicator": "CVE-2023-4966"})
        self.assertIn("/vulnerability-intelligence/cve/CVE-2023-4966", r.text)
        r = self.client.post("/extract", data={"text": "see CVE-2024-3400"})
        self.assertIn("/vulnerability-intelligence/cve/CVE-2024-3400", r.text)


if __name__ == "__main__":
    unittest.main()
