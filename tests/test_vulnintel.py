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
from app.modules.vulnerability_intelligence import brief, hotness, priority, routes, service, store
from app.modules.vulnerability_intelligence.feeds import chatter as chatter_feed
from app.modules.vulnerability_intelligence.feeds import epss as epss_feed
from app.modules.vulnerability_intelligence.feeds import euvd as euvd_feed
from app.modules.vulnerability_intelligence.feeds import kev as kev_feed
from app.modules.vulnerability_intelligence.feeds import exploitdb as edb_feed
from app.modules.vulnerability_intelligence.feeds import metasploit as msf_feed
from app.modules.vulnerability_intelligence.feeds import nuclei as nuclei_feed
from app.modules.vulnerability_intelligence.feeds import poc as poc_feed
from app.modules.vulnerability_intelligence.feeds import ransomwarelive as rl_feed
from app.modules.vulnerability_intelligence.http import gunzip_bounded
from app.modules.vulnerability_intelligence.sources import github, nvd, vulnlookup

SIGHTINGS_DOC = {
    "metadata": {"count": 3, "page": 1, "per_page": 1000},
    "data": [
        {"type": "exploited", "source": "https://dl.shadowserver.org/x/y", "creation_timestamp": "2024-01-05T00:00:00Z", "vulnerability": "CVE-2023-4966"},
        {"type": "exploited", "source": "https://dl.shadowserver.org/x/z", "creation_timestamp": "2024-02-01T00:00:00Z", "vulnerability": "CVE-2023-4966"},
        {"type": "published-proof-of-concept", "source": "https://github.com/x/y", "creation_timestamp": "2023-10-25T00:00:00Z", "vulnerability": "CVE-2023-4966"},
    ],
}

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
        # The per-minute windows live in memory and would otherwise carry
        # over between tests, making the GitHub mock sleep for real.
        from app.core.ratelimit import rate_limiter
        rate_limiter._minute.clear()

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
        self.assertEqual(store.watchlist_matches(None, None), [])            # empty never matches
        self.assertEqual(store.watchlist_matches("", "NetScaler ADC"), [])   # vendor entry needs a vendor
        self.assertEqual([h["vendor"] for h in store.watchlist_matches("Ivanti", None)], ["Ivanti"])
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


def _transport(nvd_body=NVD_DOC, github_body=GITHUB_DOC, nvd_status=200, github_status=200,
               sightings_body=None):
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "services.nvd.nist.gov":
            return httpx.Response(nvd_status, json=nvd_body)
        if req.url.host == "api.github.com":
            return httpx.Response(github_status, json=github_body)
        if req.url.host == "vulnerability.circl.lu":
            return httpx.Response(200, json=sightings_body if sightings_body is not None
                                  else {"metadata": {"count": 0}, "data": []})
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
            if req.url.host == "api.github.com":
                return httpx.Response(200, json={"total_count": 0, "items": []})
            if req.url.host == "gitlab.com":
                return httpx.Response(200, content=EDB_CSV)
            if req.url.host == "raw.githubusercontent.com" and "metasploit" in req.url.path:
                return httpx.Response(200, json=MSF_DOC)
            if req.url.host == "raw.githubusercontent.com" and "nuclei" in req.url.path:
                return httpx.Response(200, content=NUCLEI_NDJSON)
            if req.url.host == "euvdservices.enisa.europa.eu":
                return httpx.Response(200, json={"items": EUVD_ITEMS})
            if req.url.host == "vulnerability.circl.lu":
                return httpx.Response(200, json={"metadata": {"count": 0}, "data": []})
            raise AssertionError(req.url.host)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        from app.modules.vulnerability_intelligence import feeds
        results = await feeds.refresh_all()
        failed = [r for r in results if not r["ok"] and r["feed"] != "vulnlookup_recent"]
        self.assertEqual(failed, [], results)                # chatter may be empty: no sightings in the mock
        self.assertEqual(store.kev_count(), 4)                # 2 CISA + 2 EUVD (one overlaps by CVE? no: distinct)
        self.assertEqual(store.epss_count(), 1)
        self.assertEqual(store.feed_status()["cisa_kev"]["version"], "2026.11.03")
        self.assertEqual(store.exploit_counts(), {"exploitdb": 1, "metasploit": 1, "nuclei": 1})


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
                           ("/vulnerability-intelligence/refresh-ransomware", {}),
                           ("/vulnerability-intelligence/watchlist/add", {"vendor": "x"}),
                           ("/vulnerability-intelligence/aliases/add", {"alias": "x", "cve_id": "CVE-2024-1"})):
            r = self.client.post(path, data=data, headers={"sec-fetch-site": "cross-site"})
            self.assertEqual(r.status_code, 403, path)

    def test_enrich_and_extract_link_to_cve_page(self):
        r = self.client.post("/enrich", data={"indicator": "CVE-2023-4966"})
        self.assertIn("/vulnerability-intelligence/cve/CVE-2023-4966", r.text)
        r = self.client.post("/extract", data={"text": "see CVE-2024-3400"})
        self.assertIn("/vulnerability-intelligence/cve/CVE-2024-3400", r.text)


EDB_CSV = (
    b"id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases,screenshot_url,application_url,source_url\n"
    b"51600,exploits/multiple/webapps/51600.py,Citrix Bleed - Session Token Leak,2099-01-03,x,webapps,multiple,,2099-01-03,2099-01-03,1,CVE-2023-4966;OSVDB-1,,,,,\n"
    b"19049,exploits/bsd/dos/19049.txt,BSDI tcpmux crash,1998-04-07,y,dos,bsd,,1998-04-07,,0,OSVDB-82889,,,,,\n"
)
MSF_DOC = {
    "exploit_linux/http/citrix_bleed": {
        "name": "Citrix ADC (NetScaler) Bleed Scanner", "fullname": "auxiliary/gather/citrix_netscaler_adc_bleed",
        "type": "auxiliary", "rank": 300, "disclosure_date": "2023-10-10",
        "references": ["CVE-2023-4966", "URL-https://example.test"], "path": "/modules/auxiliary/gather/citrix_netscaler_adc_bleed.rb",
        "platform": "Linux,Unix,Windows,Other",
    },
    "post_no_cve": {"name": "x", "fullname": "post/x", "type": "post", "references": ["URL-https://x"]},
}
NUCLEI_NDJSON = (
    b'{"ID":"CVE-2023-4966","Info":{"Name":"Citrix Bleed","Severity":"high","Classification":{"CVSSScore":"9.4"}},"file_path":"http/cves/2023/CVE-2023-4966.yaml"}\n'
    b'not json\n'
    b'{"ID":"GHSA-xxxx","Info":{"Name":"not a cve"},"file_path":"x"}\n'
)


EUVD_ITEMS = [
    {"id": "EUVD-2026-114575", "description": "WordPress Core RCE during upgrade.", "datePublished": "Oct 31, 2026, 5:33:07 AM",
     "baseScore": 8.1, "baseScoreVersion": "3.1", "baseScoreVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "references": "https://a.example\nhttps://b.example\n", "aliases": "GHSA-p6jj-qrp3-7m4g\nCVE-2026-119977\n",
     "assigner": "Wordfence", "epss": 0.6, "exploitedSince": "Nov 3, 2026, 12:00:00 AM",
     "enisaIdVendor": [{"id": "x", "vendor": {"name": "WordPress Foundation"}}]},
    {"id": "EUVD-2015-5432", "description": "BIND TKEY.", "aliases": "GHSA-4622-vjcx-p39j\nCVE-2015-5477\n",
     "exploitedSince": "Oct 8, 2026, 12:00:00 AM", "baseScore": 7.5,
     "enisaIdVendor": [{"id": "y", "vendor": {"name": "n/a"}}],
     "enisaIdProduct": [{"id": "z", "product": {"name": "n/a", "vendor": {"name": "n/a"}}, "product_version": "n/a"}]},
    {"id": "EUVD-2026-1", "description": "no cve alias", "aliases": "GHSA-only\n"},
]

CVE5_RECORD = {"containers": {"cna": {"providerMetadata": {"shortName": "amir1376"}, "metrics": [
    {"cvssV4_0": {"version": "4.0", "baseScore": 8.7, "baseSeverity": "HIGH", "vectorString": "CVSS:4.0/AV:N"}},
    {"cvssV3_1": {"version": "3.1", "baseScore": 8.8, "baseSeverity": "HIGH", "vectorString": "CVSS:3.1/AV:N"}},
]}}}


def gh_repo(name: str, created: str, stars: int = 0) -> dict:
    return {"full_name": f"user/{name}", "html_url": f"https://github.com/user/{name}", "description": "poc",
            "stargazers_count": stars, "created_at": f"{created}T00:00:00Z", "pushed_at": f"{created}T00:00:00Z",
            "fork": False, "archived": False, "owner": {"login": "user"}}


class PocFeedParseTests(unittest.TestCase):
    def test_cve_from_name(self):
        self.assertEqual(poc_feed.cve_from_name("CVE-2024-3400-poc"), "CVE-2024-3400")
        self.assertEqual(poc_feed.cve_from_name("cve_2023_4966_exploit"), "CVE-2023-4966")
        self.assertEqual(poc_feed.cve_from_name("Exploit-for-cve2021-44228"), "CVE-2021-44228")
        self.assertIsNone(poc_feed.cve_from_name("cve-scanner"))
        self.assertIsNone(poc_feed.cve_from_name("awesome-cves"))

    def test_parse_items_keeps_only_cve_named(self):
        rows = poc_feed.parse_items([gh_repo("CVE-2024-3400-poc", "2026-11-01", 5), gh_repo("cve-tools", "2026-11-01")])
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2024-3400"])
        self.assertEqual(rows[0]["created"], "2026-11-01")


class RansomwareLiveParseTests(unittest.TestCase):
    def test_cves_in_any_shape(self):
        self.assertEqual(rl_feed.cves_in(["CVE-2023-4966", "cve-2024-3400"]), {"CVE-2023-4966", "CVE-2024-3400"})
        self.assertEqual(rl_feed.cves_in([{"cve": "CVE-2021-44228", "cvss": 10.0}]), {"CVE-2021-44228"})
        self.assertEqual(rl_feed.cves_in(None), set())
        self.assertEqual(rl_feed.cves_in("none here"), set())

    def test_group_names(self):
        self.assertEqual(rl_feed.group_names([{"name": "lockbit3"}, {"nope": 1}, "x"]), ["lockbit3"])
        self.assertEqual(rl_feed.group_names({"client": "x", "count": 2,
                                              "groups": [{"group": "clop", "victims": 9}, {"group": "8base"}]}),
                         ["clop", "8base"])
        self.assertEqual(rl_feed.group_names({"name": "x"}), [])


class PriorityExploitedByTests(unittest.TestCase):
    def test_ransomware_group_exploitation_is_p1(self):
        p = priority.compute(kev_sources=[], ransomware=False, epss=0.01, cvss=5.0, poc_count=0,
                             watchlist_hits=[], exploited_by=["lockbit3", "clop"])
        self.assertEqual(p.level, "P1")
        self.assertTrue(any("lockbit3, clop" in r for r in p.reasons))


class PocStoreTests(TempDbMixin, unittest.TestCase):
    def test_poc_repos_and_recent(self):
        rows = poc_feed.parse_items([gh_repo("CVE-2024-3400-poc", "2099-01-02", 3),
                                     gh_repo("CVE-2024-3400-scan", "2099-01-01", 9),
                                     gh_repo("CVE-2023-4966-exploit", "2000-01-01")])
        self.assertEqual(store.upsert_poc_repos(rows), 3)
        first_seen = store.poc_repos_for("CVE-2024-3400")[0]["first_seen"]
        rows[0]["stars"] = 10
        store.upsert_poc_repos(rows[:1])                      # update keeps first_seen
        again = store.poc_repos_for("CVE-2024-3400")
        self.assertEqual(again[0]["stars"], 10)
        self.assertEqual(again[0]["first_seen"], first_seen)
        recent = store.recent_poc(7)
        self.assertEqual([(r["cve_id"], r["repos"], r["max_stars"]) for r in recent], [("CVE-2024-3400", 2, 10)])
        # stack_only: nothing matches until the watchlist and KEV/NVD know the vendor
        self.assertEqual(store.recent_poc(7, stack_only=True), [])
        store.add_watchlist("Palo Alto")
        store.upsert_kev([{"cve_id": "CVE-2024-3400", "vendor": "Palo Alto Networks", "product": "PAN-OS",
                           "name": "x", "date_added": "2024-04-12", "due_date": None, "ransomware": 0,
                           "description": "", "required_action": "", "notes": "", "cwes": []}], "cisa")
        hit = store.recent_poc(7, stack_only=True)
        self.assertEqual(hit[0]["matched"], ["Palo Alto"])
        self.assertTrue(hit[0]["kev"])

    def test_ransomware_pairs(self):
        store.upsert_ransomware_cves([("CVE-2023-4966", "lockbit3"), ("CVE-2023-4966", "medusa"), ("CVE-2023-4966", "lockbit3")])
        self.assertEqual(store.ransomware_groups_for("CVE-2023-4966"), ["lockbit3", "medusa"])
        self.assertEqual(store.ransomware_cve_count(), 1)


class PocAndRansomwareFeedTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    async def test_poc_feed_pages_until_short_page(self):
        calls = []

        def handler(req):
            calls.append(dict(req.url.params))
            page = int(req.url.params.get("page", "1"))
            items = [gh_repo(f"CVE-2026-{1000 + i}-poc", "2099-01-01") for i in range(100)] if page == 1 \
                else [gh_repo("CVE-2026-9999-x", "2099-01-01"), gh_repo("not-a-cve", "2099-01-01")]
            return httpx.Response(200, json={"total_count": 102, "items": items})
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await poc_feed.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["entries"], 101)
        self.assertEqual(len(calls), 2)
        self.assertIn("created:>=", calls[0]["q"])
        self.assertEqual(store.feed_status()["github_poc"]["entries"], 101)

    async def test_poc_feed_rate_limit_keeps_partial(self):
        def handler(req):
            page = int(req.url.params.get("page", "1"))
            if page == 1:
                return httpx.Response(200, json={"items": [gh_repo(f"CVE-2026-{1000 + i}-p", "2099-01-01") for i in range(100)]})
            return httpx.Response(403, json={"message": "rate limit"})
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await poc_feed.refresh()
        self.assertTrue(res["ok"])
        self.assertIn("partial", res["version"])

    async def test_ransomware_feed_without_key(self):
        from unittest.mock import patch
        with patch.object(settings, "ransomwarelive_api_key", ""):
            res = await rl_feed.refresh()
        self.assertFalse(res["ok"])
        self.assertIn("no API key", res["error"])

    async def test_ransomware_feed_reads_profiles(self):
        from unittest.mock import patch
        seen_headers = {}

        def handler(req):
            seen_headers.update(req.headers)
            if req.url.path == "/groups":
                return httpx.Response(200, json={"client": "t", "count": 2, "groups": [
                    {"group": "lockbit3", "victims": 1, "vulnerabilities": [{"CVE": "CVE-2023-4966", "CVSS": 7.5}]},
                    {"group": "clop", "victims": 2}]})
            if req.url.path == "/groups/clop":
                return httpx.Response(200, json={"group": "clop", "vulnerabilities": [
                    {"Vendor": "Progress", "Product": "MOVEit Transfer", "CVE": "CVE-2023-34362", "CVSS": 9.8}]})
            raise AssertionError(req.url.path)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        with patch.object(settings, "ransomwarelive_api_key", "test-key"):
            res = await rl_feed.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["entries"], 2)
        self.assertEqual(seen_headers.get("x-api-key"), "test-key")
        self.assertEqual(store.ransomware_groups_for("CVE-2023-34362"), ["clop"])
        self.assertEqual(store.ransomware_groups_for("CVE-2023-4966"), ["lockbit3"])


class ExploitIndexParseTests(unittest.TestCase):
    def test_exploitdb(self):
        rows = edb_feed.parse(EDB_CSV)
        self.assertEqual(len(rows), 1)                        # the OSVDB-only row is skipped
        r = rows[0]
        self.assertEqual((r["ref"], r["cve_id"], r["date"], r["kind"], r["verified"]),
                         ("51600", "CVE-2023-4966", "2099-01-03", "webapps", 1))
        self.assertEqual(r["url"], "https://www.exploit-db.com/exploits/51600")
        with self.assertRaises(ValueError):
            edb_feed.parse(b"a,b,c\n1,2,3\n")

    def test_metasploit(self):
        rows = msf_feed.parse(json.dumps(MSF_DOC).encode())
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["ref"], r["cve_id"], r["kind"], r["date"]),
                         ("auxiliary/gather/citrix_netscaler_adc_bleed", "CVE-2023-4966", "auxiliary", "2023-10-10"))
        self.assertTrue(r["url"].endswith("/modules/auxiliary/gather/citrix_netscaler_adc_bleed.rb"))
        self.assertEqual(r["platform"], "Linux, Unix, Windows")
        with self.assertRaises(ValueError):
            msf_feed.parse(b"[]")

    def test_nuclei(self):
        rows = nuclei_feed.parse(NUCLEI_NDJSON)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cve_id"], "CVE-2023-4966")
        self.assertEqual(rows[0]["kind"], "high")
        self.assertTrue(rows[0]["url"].endswith("http/cves/2023/CVE-2023-4966.yaml"))
        with self.assertRaises(ValueError):
            nuclei_feed.parse(b"\n")


class VulnLookupTests(unittest.TestCase):
    def test_summarise(self):
        s = vulnlookup.summarise(SIGHTINGS_DOC)
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["by_type"], {"exploited": 2, "published-proof-of-concept": 1})
        self.assertEqual(s["first"]["exploited"], "2024-01-05")
        self.assertEqual(s["last"]["exploited"], "2024-02-01")
        self.assertEqual(s["sources"]["exploited"], ["dl.shadowserver.org"])
        self.assertEqual(vulnlookup.summarise({})["total"], 0)

    def test_source_names(self):
        f = vulnlookup._source_name
        self.assertEqual(f("https://dl.shadowserver.org/x/y"), "dl.shadowserver.org")
        self.assertEqual(f("Telegram/sCKB5hmV3mImlXWuLfcoIwNbw20CqZSk"), "Telegram")
        self.assertEqual(f("MISP/2385d0ea-bf42-4e43-bed3-86cc42bd3bf3"), "MISP")
        self.assertEqual(f("The Shadowserver (honeypot/exploited-vulnerabilities) - (2024-01-01)"), "The Shadowserver")
        self.assertEqual(f(""), "")


class PriorityExploitTiersTests(unittest.TestCase):
    def _p(self, **kw):
        args = dict(kev_sources=[], ransomware=False, epss=None, cvss=None, poc_count=0, watchlist_hits=[])
        args.update(kw)
        return priority.compute(**args)

    def test_sightings_are_p1(self):
        p = self._p(exploitation_sightings=2, sightings_latest="2024-02-01")
        self.assertEqual(p.level, "P1")
        self.assertTrue(any("2 exploitation sightings" in r and "2024-02-01" in r for r in p.reasons))

    def test_metasploit_is_p2(self):
        p = self._p(weaponised=["exploit/x"], cvss=5.0)
        self.assertEqual(p.level, "P2")
        self.assertTrue(any(r.startswith("weaponised: 1 Metasploit module") for r in p.reasons))

    def test_exploit_entries_count_as_poc(self):
        self.assertEqual(self._p(poc_count=1).level, "P3")


class ExploitStoreTests(TempDbMixin, unittest.TestCase):
    def test_exploits_for_and_recent_merge(self):
        store.upsert_exploits("exploitdb", edb_feed.parse(EDB_CSV))
        store.upsert_exploits("metasploit", msf_feed.parse(json.dumps(MSF_DOC).encode()))
        store.upsert_exploits("nuclei", nuclei_feed.parse(NUCLEI_NDJSON))
        got = store.exploits_for("CVE-2023-4966")
        self.assertEqual(sorted(got), ["exploitdb", "metasploit", "nuclei"])
        self.assertEqual(store.exploit_counts(), {"exploitdb": 1, "metasploit": 1, "nuclei": 1})
        # recent: the EDB entry is dated 2099 so it is "recent"; MSF/Nuclei show as flags
        rows = store.recent_poc(7)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["cve_id"], r["repos"], r["edb"], bool(r["msf"]), bool(r["nuclei"])),
                         ("CVE-2023-4966", 0, 1, True, True))
        # a GitHub repo for the same CVE merges into the same row
        store.upsert_poc_repos(poc_feed.parse_items([gh_repo("CVE-2023-4966-poc", "2099-01-05", 4)]))
        r = store.recent_poc(7)[0]
        self.assertEqual((r["repos"], r["edb"], r["newest"], r["max_stars"]), (1, 1, "2099-01-05", 4))


class EuvdTests(unittest.TestCase):
    def test_parse_date(self):
        self.assertEqual(euvd_feed.parse_date("Oct 8, 2026, 12:00:00 AM"), "2026-10-08")
        self.assertEqual(euvd_feed.parse_date("Nov 3, 2026, 12:00:00 AM"), "2026-11-03")
        self.assertEqual(euvd_feed.parse_date("2026-11-03T10:00:00"), "2026-11-03")
        self.assertIsNone(euvd_feed.parse_date(None))
        self.assertIsNone(euvd_feed.parse_date("garbage"))

    def test_parse_items(self):
        rows = euvd_feed.parse_items(EUVD_ITEMS)
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2026-119977", "CVE-2015-5477"])
        wp = rows[0]
        self.assertEqual((wp["vendor"], wp["product"], wp["date_added"], wp["score"], wp["epss"]),
                         ("WordPress Foundation", None, "2026-11-03", 8.1, 0.6))
        self.assertTrue(wp["notes"].startswith("EUVD EUVD-2026-114575"))
        bind = rows[1]
        self.assertIsNone(bind["vendor"])                  # "n/a" becomes None
        self.assertEqual(bind["name"], "BIND TKEY.")


class HotnessAndBriefTests(unittest.TestCase):
    def test_heat_weights(self):
        from datetime import date
        today = date(2026, 11, 4)
        top = hotness.compute(kev=True, ransomware=True, epss=1.0, cvss=10.0, kev_added="2026-11-01",
                              msf=True, poc=True, chatter=50, today=today)
        self.assertEqual(top.score, 133.0)
        self.assertIn("listed 3d ago", top.parts)
        old = hotness.compute(kev=True, ransomware=False, epss=0.1, cvss=7.5, kev_added="2020-01-01",
                              msf=False, poc=False, chatter=0, today=today)
        self.assertEqual(old.score, 35.5)                     # 40 + 3 + 7.5 - 15 (over a year old)
        self.assertIn("listed 6y ago", old.parts)
        log4shell = hotness.compute(kev=True, ransomware=True, epss=1.0, cvss=10.0, kev_added="2021-12-10",
                                    msf=True, poc=True, chatter=0, today=today)
        fresh = hotness.compute(kev=True, ransomware=False, epss=0.5, cvss=9.0, kev_added="2026-11-02",
                                msf=False, poc=False, chatter=0, today=today)
        self.assertGreater(fresh.score, log4shell.score)      # "right now" beats "famous"
        poc_only = hotness.compute(kev=False, ransomware=False, epss=None, cvss=None, kev_added=None,
                                   msf=False, poc=True, chatter=4, today=today)
        self.assertEqual(poc_only.score, 7.0)
        self.assertEqual(hotness.compute(kev=False, ransomware=False, epss=None, cvss=None, kev_added=None,
                                         msf=False, poc=False, chatter=0).score, 0.0)

    def test_brief_text(self):
        rows = [{"cve_id": "CVE-2024-3400", "vendor": "Palo Alto Networks", "product": "PAN-OS", "cvss": 10.0,
                 "epss": 0.999, "kev": True, "ransomware": True, "msf": True, "poc": True, "due_date": "2024-04-19"},
                {"cve_id": "CVE-2026-1", "vendor": None, "product": None, "cvss": None, "epss": None,
                 "kev": False, "ransomware": False, "msf": False, "poc": True, "due_date": None}]
        text = brief.render(rows, counts={"kev": 1767})
        self.assertIn("1,767 known-exploited CVEs tracked", text)
        self.assertIn("- CVE-2024-3400 | Palo Alto Networks PAN-OS | CVSS 10.0 | EPSS 100% | EXPLOITED RANSOMWARE METASPLOIT | CISA due 2024-04-19", text)
        self.assertIn("- CVE-2026-1 | vendor unknown | CVSS n/a | EPSS n/a | POC", text)
        self.assertNotIn("watchlist", text)


class ChatterTests(unittest.TestCase):
    def test_aggregate_recent(self):
        from datetime import datetime, timedelta, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        old = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
        data = [
            {"vulnerability": "CVE-2026-1", "type": "seen", "creation_timestamp": f"{today}T01:00:00"},
            {"vulnerability": "cve-2026-1", "type": "seen", "creation_timestamp": f"{today}T02:00:00"},
            {"vulnerability": "CVE-2026-1", "type": "exploited", "creation_timestamp": f"{today}T03:00:00"},
            {"vulnerability": "CVE-2026-2", "type": "seen", "creation_timestamp": f"{old}T03:00:00"},
            {"vulnerability": "GHSA-x", "type": "seen", "creation_timestamp": f"{today}T03:00:00"},
        ]
        rows = sorted(vulnlookup.aggregate_recent(data))
        self.assertEqual(rows, [("CVE-2026-1", "exploited", today, 1), ("CVE-2026-1", "seen", today, 2)])

    def test_cvss_from_record(self):
        c = vulnlookup.cvss_from_record(CVE5_RECORD)
        self.assertEqual((c["cvss_score"], c["cvss_version"], c["cvss_source"]), (8.7, "4.0", "cna:amir1376"))
        self.assertIsNone(vulnlookup.cvss_from_record({}))


class HottestStoreTests(TempDbMixin, unittest.TestCase):
    def test_migration_is_idempotent_and_adds_columns(self):
        store.init_schema()                                   # second run: duplicate-column errors swallowed
        store.upsert_kev(euvd_feed.parse_items(EUVD_ITEMS), "euvd")
        k = store.get_kev("CVE-2026-119977")[0]
        self.assertEqual((k["source"], k["score"], k["epss"]), ("euvd", 8.1, 0.6))

    def test_hottest_ranks_and_uses_euvd_fallbacks(self):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        store.upsert_kev(rows, "cisa")                        # CVE-2023-4966 (ransomware), CVE-2026-118527 (added 2099)
        store.upsert_kev(euvd_feed.parse_items(EUVD_ITEMS), "euvd")   # CVE-2026-119977 with score 8.1, epss 0.6
        store.upsert_epss([("CVE-2023-4966", 0.99, 0.999)], today)
        store.upsert_exploits("metasploit", msf_feed.parse(json.dumps(MSF_DOC).encode()))
        store.replace_recent_sightings([("CVE-2026-119977", "seen", today, 7), ("CVE-2026-9", "seen", today, 1)])
        self.assertEqual(store.chatter(2), {"CVE-2026-119977": 7, "CVE-2026-9": 1})
        top = service.hottest(10)
        ids = [r["cve_id"] for r in top]
        # The two exploited CVEs lead; which is first depends on how recently
        # the EUVD one was listed (the recency bonus decays), so assert the pair.
        self.assertEqual(set(ids[:2]), {"CVE-2023-4966", "CVE-2026-119977"})
        citrix = next(r for r in top if r["cve_id"] == "CVE-2023-4966")
        self.assertEqual(citrix["heat"], 69.7)                 # 40 + 10 ransomware + 29.7 EPSS + 5 MSF - 15 (listed 2023)
        self.assertTrue(all(h >= 0 for h in (r["heat"] for r in top)))
        self.assertEqual(ids, sorted(ids, key=lambda i: (-next(r["heat"] for r in top if r["cve_id"] == i), i)))
        wp = next(r for r in top if r["cve_id"] == "CVE-2026-119977")
        self.assertEqual((wp["cvss"], wp["epss"], wp["chatter"]), (8.1, 0.6, 7))   # EUVD fallbacks + chatter
        self.assertIn("7 sightings/48h", wp["parts"])
        nine = next(r for r in top if r["cve_id"] == "CVE-2026-9")      # chatter only, still listed
        self.assertEqual(nine["heat"], 1.0)
        text = service.dashboard_brief(top, {"kev": store.kev_count()})
        self.assertIn("CVE-2023-4966", text)


class EuvdAndChatterFeedTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    async def test_euvd_feed_pages_until_short_page(self):
        pages = []

        def handler(req):
            pages.append(req.url.params.get("page"))
            return httpx.Response(200, json={"items": EUVD_ITEMS})      # 3 items < 100: one page
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await euvd_feed.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["entries"], 2)
        self.assertEqual(pages, ["0"])
        self.assertEqual(store.get_kev("CVE-2015-5477")[0]["date_added"], "2026-10-08")

    async def test_euvd_feed_error(self):
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(503))))
        res = await euvd_feed.refresh()
        self.assertFalse(res["ok"])
        self.assertIn("503", store.feed_status()["euvd"]["error"])

    async def test_chatter_feed(self):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        def handler(req):
            page = req.url.params.get("page")
            self.assertTrue(req.url.params.get("date_from", "").startswith("20"))   # server-side window
            if page == "1":
                return httpx.Response(200, json={"metadata": {"count": 2}, "data": [
                    {"vulnerability": "CVE-2026-5", "type": "seen", "creation_timestamp": f"{today}T01:00:00"},
                    {"vulnerability": "CVE-2026-5", "type": "seen", "creation_timestamp": "2000-01-01T00:00:00"},
                ]})
            raise AssertionError("should stop after the first (short) page")
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await chatter_feed.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual(store.chatter(2), {"CVE-2026-5": 1})
        self.assertEqual(res["version"], "last 48 hours")

    async def test_chatter_skips_oversized_page(self):
        from datetime import datetime, timezone
        from app.modules.vulnerability_intelligence.sources import vulnlookup as vl
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        def handler(req):
            page = req.url.params.get("page")
            if page == "1":
                return httpx.Response(200, content=b"x" * (vl.RECENT_PAGE_CAP + 1))      # one giant page
            if page == "2":
                return httpx.Response(200, json={"metadata": {"count": 1}, "data": [
                    {"vulnerability": "CVE-2026-6", "type": "seen", "creation_timestamp": f"{today}T01:00:00"},
                    {"vulnerability": "CVE-2026-6", "type": "seen", "creation_timestamp": "2000-01-01T00:00:00"},
                ]})
            raise AssertionError(page)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await chatter_feed.refresh()
        self.assertTrue(res["ok"], res)
        self.assertIn("1 oversized page skipped", res["version"])
        self.assertEqual(store.chatter(2), {"CVE-2026-6": 1})

    async def test_cvss_fallback_in_report(self):
        def handler(req):
            if req.url.host == "services.nvd.nist.gov":
                return httpx.Response(200, json={"vulnerabilities": []})
            if req.url.host == "api.github.com":
                return httpx.Response(200, json={"total_count": 0, "items": []})
            if req.url.host == "vulnerability.circl.lu" and "/api/vulnerability/" in req.url.path:
                return httpx.Response(200, json=CVE5_RECORD)
            if req.url.host == "vulnerability.circl.lu":
                return httpx.Response(200, json={"metadata": {"count": 0}, "data": []})
            raise AssertionError(req.url)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        rep = await service.report("CVE-2026-121451")
        self.assertEqual(rep["nvd"]["status"], "not_found")
        self.assertEqual(rep["cvss_fallback"]["cvss_score"], 8.7)
        self.assertIn("CVE record", rep["cvss_fallback"]["source"])
        self.assertIn("CVSS 8.7", rep["priority"].reasons)
        # EUVD score wins over the record when present
        store.upsert_kev(euvd_feed.parse_items(EUVD_ITEMS), "euvd")
        rep = await service.report("CVE-2026-119977")
        self.assertEqual(rep["cvss_fallback"]["source"], "ENISA EUVD")
        self.assertEqual(rep["priority"].level, "P1")


class PocRouteTests(TempDbMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app, base_url="http://127.0.0.1")
        base.set_client(httpx.AsyncClient(transport=_transport()))

    def tearDown(self):
        import asyncio
        asyncio.run(base.aclose())
        super().tearDown()

    def test_dashboard_and_exploits_show_recent_poc(self):
        store.upsert_poc_repos(poc_feed.parse_items([gh_repo("CVE-2024-3400-poc", "2099-01-02", 3)]))
        store.set_feed_status("github_poc", entries=1, version="test")
        r = self.client.get("/vulnerability-intelligence")
        self.assertIn("New exploit code", r.text)
        self.assertIn("/cve/CVE-2024-3400", r.text)
        self.assertIn("Hottest right now", r.text)
        self.assertIn("text brief", r.text)
        self.assertIn("- CVE-2024-3400 |", r.text)          # the brief lists it (PoC this week)
        r = self.client.get("/vulnerability-intelligence?hot=100")
        self.assertIn("show 10", r.text)
        r = self.client.get("/vulnerability-intelligence?poc=stack")
        self.assertIn("No new exploit code for anything on the watchlist", r.text)
        r = self.client.get("/vulnerability-intelligence/exploits")
        self.assertIn("Recently published exploit code", r.text)
        self.assertIn("/cve/CVE-2024-3400", r.text)

    def test_cve_page_shows_ransomware_groups(self):
        store.upsert_ransomware_cves([("CVE-2023-4966", "lockbit3")])
        r = self.client.get("/vulnerability-intelligence/cve/CVE-2023-4966")
        self.assertIn("Ransomware groups known to exploit it", r.text)
        self.assertIn("lockbit3", r.text)
        self.assertIn("P1 Emergency", r.text)

    def test_cve_page_shows_exploit_indexes_and_sightings(self):
        base.set_client(httpx.AsyncClient(transport=_transport(sightings_body=SIGHTINGS_DOC)))
        store.upsert_exploits("metasploit", msf_feed.parse(json.dumps(MSF_DOC).encode()))
        store.upsert_exploits("exploitdb", edb_feed.parse(EDB_CSV))
        r = self.client.get("/vulnerability-intelligence/cve/CVE-2023-4966")
        for needle in ("weaponised", "citrix_netscaler_adc_bleed", "Exploit-DB", "51600",
                       "Exploitation sightings", "dl.shadowserver.org", "2 exploitation sightings", "P1 Emergency"):
            self.assertIn(needle, r.text)
        r = self.client.get("/vulnerability-intelligence/exploits", params={"cve": "CVE-2023-4966"})
        self.assertIn("Metasploit modules", r.text)
        self.assertIn("51600", r.text)


if __name__ == "__main__":
    unittest.main()
