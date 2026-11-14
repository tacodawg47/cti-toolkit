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
from app.modules.vulnerability_intelligence import brief, charts, hotness, priority, routes, service, store, tables
from app.modules.vulnerability_intelligence.feeds import chatter as chatter_feed
from app.modules.vulnerability_intelligence.feeds import nvd_recent
from app.modules.vulnerability_intelligence.feeds import epss as epss_feed
from app.modules.vulnerability_intelligence.feeds import euvd as euvd_feed
from app.modules.vulnerability_intelligence.feeds import kev as kev_feed
from app.modules.vulnerability_intelligence.feeds import exploitdb as edb_feed
from app.modules.vulnerability_intelligence.feeds import metasploit as msf_feed
from app.modules.vulnerability_intelligence.feeds import nuclei as nuclei_feed
from app.modules.vulnerability_intelligence.feeds import poc as poc_feed
from app.modules.vulnerability_intelligence.feeds import vulncheck_kev as vc_feed
from app.modules.vulnerability_intelligence.feeds import ransomwarelive as rl_feed
from app.modules.vulnerability_intelligence.http import gunzip_bounded
from app.modules.vulnerability_intelligence.sources import github, nvd, vulnlookup
from app.modules.vulnerability_intelligence.sources import otx as otx_cve

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
        # Tests never use the operator's real keys: a feed that needs a token
        # is tested by setting a fake one explicitly.
        self._orig_vc = settings.vulncheck_api_key
        settings.vulncheck_api_key = ""
        self._orig_otx = settings.otx_api_key
        settings.otx_api_key = ""

    def tearDown(self):
        settings.data_dir = self._orig_dir
        settings.vulncheck_api_key = self._orig_vc
        settings.otx_api_key = self._orig_otx
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
        self.assertEqual(p.level, "N/A")
        self.assertIn("insufficient evidence to assign a priority", p.reasons)
        self.assertEqual(self._p(cvss=4.0, epss=0.01).level, "P5")

    def test_reasons_mention_ransomware(self):
        p = self._p(kev_sources=["cisa"], ransomware=True)
        self.assertIn("known ransomware campaign use", p.reasons)


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

    def test_claim_requires_matching_cve_and_nearby_keyword(self):
        cve = "CVE-2024-3400"
        self.assertTrue(github.claim(cve, "someone/CVE_2024_3400-proof-of-concept"))
        self.assertTrue(github.claim(cve, "someone/research", "Exploit code for CVE-2024-3400"))
        self.assertIsNone(github.claim(cve, "someone/CVE-2024-34000-poc"))
        self.assertIsNone(github.claim(cve, "someone/research", readme=f"{cve}\nUnrelated PoC"))


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
        self.assertEqual(rep["priority"].level, "N/A")

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
            if req.url.host == "services.nvd.nist.gov":
                return httpx.Response(200, json={**NVD_DOC, "totalResults": 1})
            if req.url.host == "docs.google.com":                    # Project Zero: one year tab with rows
                return httpx.Response(200, text=GP0_CSV if req.url.params.get("sheet") == "2026" else GP0_INTRO)
            if req.url.host == "raw.githubusercontent.com" and "Ransomware-Vulnerability-Matrix" in req.url.path:
                return httpx.Response(200, text=RVM_EDGE)
            raise AssertionError(req.url.host)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        from app.modules.vulnerability_intelligence import feeds
        results = await feeds.refresh_all()
        failed = [r for r in results if not r["ok"] and r["feed"] != "vulnlookup_recent"]
        self.assertEqual(failed, [], results)                # chatter may be empty: no sightings in the mock
        self.assertEqual(store.kev_count(), 6)                # 2 CISA + 2 EUVD + 2 Project Zero, all distinct
        self.assertEqual(store.epss_count(), 1)
        self.assertEqual(store.feed_status()["cisa_kev"]["version"], "2026.11.03")
        self.assertEqual(store.exploit_counts(), {"exploitdb": 1, "metasploit": 1, "nuclei": 1})
        self.assertEqual(store.get_cve("CVE-2023-4966")["cvss_score"], 7.5)     # via the NVD recent feed
        self.assertTrue(store.feed_status()["nvd_recent"]["version"].startswith("1 CVEs modified since"))


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
        self.assertIn("No feeds loaded yet", r.text)
        self.assertIn("The watchlist is empty", r.text)
        r = self.client.get("/vulnerability-intelligence/feeds")
        self.assertEqual(r.status_code, 200)
        self.assertIn("not loaded", r.text)
        self.assertIn("Refresh feeds", r.text)
        # the refresh buttons live on the Feeds tab only
        self.assertNotIn('action="/vulnerability-intelligence/refresh"', self.client.get("/vulnerability-intelligence").text)

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
                       '<a href="#references">Patch Reference</a>',
                       '<p class="cvetitle">Citrix NetScaler Buffer Overflow</p>',   # CISA's name as the title
                       "<li>On a known-exploited list"):                          # bullets start with a capital
            self.assertIn(needle, r.text)
        # CVSS and EPSS sit in the key figures, not in the bullet list
        bullets = r.text.split("<li>On a known-exploited list")[1].split("</ul>")[0]
        self.assertNotIn("CVSS 7.5", bullets)
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
        self.assertIn("enter+a+vendor+or+product", r.headers["location"])
        self.client.post("/vulnerability-intelligence/watchlist/add", data={"product": "FortiOS"})
        self.assertEqual([(e["vendor"], e["product"]) for e in store.list_watchlist()], [("", "FortiOS")])
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
        self.assertEqual([(r["cve_id"], r["repos"], r["max_stars"]) for r in recent], [("CVE-2024-3400", 1, 10)])
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

    async def test_github_readme_claim_is_distinct_from_repository_mention(self):
        from base64 import b64encode
        cve = "CVE-2024-3400"
        checked = []

        def handler(req):
            if req.url.path == "/search/repositories":
                items = [gh_repo(f"{cve}-report", "2024-04-12"), gh_repo("notes", "2024-04-12")]
                for item in items:
                    item["description"] = "Research notes"
                return httpx.Response(200, json={"total_count": 2, "items": items})
            checked.append(req.url.path)
            if req.url.path == "/repos/user/notes/readme":
                encoded = b64encode(f"# Proof of concept for {cve}".encode()).decode()
                return httpx.Response(200, json={"encoding": "base64", "content": encoded})
            return httpx.Response(404)

        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        result = await github.search(cve)
        self.assertEqual(set(checked), {f"/repos/user/{cve}-report/readme", "/repos/user/notes/readme"})
        self.assertIsNone(result["repos"][0]["claim"])
        self.assertTrue(result["repos"][1]["claim"].startswith("README mentions"))
        self.assertTrue((await github.search(cve))["cached"])

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

    async def test_ransomware_feed_reads_profiles_and_skips_unchanged(self):
        from unittest.mock import patch
        seen_headers = {}
        detail_calls = []
        victims = {"clop": 2}

        def handler(req):
            seen_headers.update(req.headers)
            if req.url.path == "/groups":
                return httpx.Response(200, json={"client": "t", "count": 3, "groups": [
                    {"group": "lockbit3", "victims": 1, "vulnerabilities": [{"CVE": "CVE-2023-4966", "CVSS": 7.5}]},
                    {"group": "clop", "victims": victims["clop"]},
                    {"group": "0day syndicate", "victims": 0}]})
            detail_calls.append(req.url.path)
            if req.url.path == "/groups/clop":
                return httpx.Response(200, json={"group": "clop", "vulnerabilities": [
                    {"Vendor": "Progress", "Product": "MOVEit Transfer", "CVE": "CVE-2023-34362", "CVSS": 9.8}]})
            if req.url.path == "/groups/0day syndicate":                   # httpx decodes the path here
                self.assertEqual(req.url.raw_path, b"/groups/0day%20syndicate")   # but the wire is encoded
                return httpx.Response(200, json={"group": "0day syndicate", "vulnerabilities": []})
            raise AssertionError(req.url.path)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        with patch.object(settings, "ransomwarelive_api_key", "test-key"):
            res = await rl_feed.refresh()
            self.assertTrue(res["ok"], res)
            self.assertEqual(res["read"], 2)
            self.assertEqual(seen_headers.get("x-api-key"), "test-key")
            self.assertEqual(store.ransomware_groups_for("CVE-2023-34362"), ["clop"])
            self.assertEqual(store.ransomware_groups_for("CVE-2023-4966"), ["lockbit3"])
            # second run: nothing changed, so no profile is re-read
            detail_calls.clear()
            res = await rl_feed.refresh()
            self.assertEqual((res["read"], detail_calls), (0, []))
            # a changed victim count triggers one re-read
            victims["clop"] = 3
            res = await rl_feed.refresh()
            self.assertEqual((res["read"], detail_calls), (1, ["/groups/clop"]))

    async def test_ransomware_feed_retries_on_429(self):
        from unittest.mock import patch
        calls = {"n": 0}

        def handler(req):
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429)
            return httpx.Response(200, json={"groups": [{"group": "x", "victims": 1, "vulnerabilities": ["CVE-2024-1111"]}]})
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        sleeps = []

        async def fake_sleep(s):
            sleeps.append(s)
        with patch.object(settings, "ransomwarelive_api_key", "k"), patch("asyncio.sleep", fake_sleep):
            res = await rl_feed.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual(sleeps, [rl_feed.RETRY_WAIT])
        self.assertEqual(store.ransomware_groups_for("CVE-2024-1111"), ["x"])


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
                         ("CVE-2023-4966", 0, 1, False, True))
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
        self.assertIn("- CVE-2024-3400 | Palo Alto Networks PAN-OS | CVSS 10.0 | EPSS 100% | EXPLOITED RANSOMWARE METASPLOIT", text)
        self.assertNotIn("CISA due", text)
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
        self.assertEqual(citrix["heat"], 64.7)                 # auxiliary module adds no exploit weight
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


class NvdRecentTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    def test_window(self):
        from datetime import datetime, timezone
        now = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
        start, end = nvd_recent.window(None, now)
        self.assertEqual((end - start).days, 7)
        start, _ = nvd_recent.window({"fetched_at": "2026-11-03T10:00:00+00:00", "error": None}, now)
        self.assertEqual(start.isoformat(), "2026-11-03T09:00:00+00:00")         # one hour of overlap
        start, _ = nvd_recent.window({"fetched_at": "2026-11-03T10:00:00+00:00", "error": "boom"}, now)
        self.assertEqual((end - start).days, 7)                                    # a failed run does not move it
        start, _ = nvd_recent.window({"fetched_at": "2025-01-01T00:00:00+00:00", "error": None}, now)
        self.assertEqual((end - start).days, 120)                                  # NVD's cap

    def test_parse_page(self):
        items, total = nvd_recent.parse_page({**NVD_DOC, "totalResults": 42})
        self.assertEqual((len(items), total, items[0]["cve_id"]), (1, 42, "CVE-2023-4966"))

    async def test_refresh_pages_and_saves(self):
        pages = []

        def handler(req):
            idx = int(req.url.params.get("startIndex", "0"))
            pages.append(idx)
            self.assertIn("lastModStartDate", dict(req.url.params))
            doc = {"resultsPerPage": 2000, "totalResults": 2001, "vulnerabilities": NVD_DOC["vulnerabilities"]}
            if idx == 2000:
                doc["vulnerabilities"] = [{"cve": {**NVD_DOC["vulnerabilities"][0]["cve"], "id": "CVE-2026-999999"}}]
            return httpx.Response(200, json=doc)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await nvd_recent.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual((res["entries"], pages), (2, [0, 2000]))
        self.assertIsNotNone(store.get_cve("CVE-2026-999999"))
        self.assertEqual(len(store.get_cve("CVE-2026-999999")["products"]), 2)

    async def test_refresh_error_keeps_status(self):
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403))))
        res = await nvd_recent.refresh()
        self.assertFalse(res["ok"])
        self.assertIn("403", store.feed_status()["nvd_recent"]["error"])


class DashboardDataTests(TempDbMixin, unittest.TestCase):
    def test_bulk_save_and_stack_new(self):
        cve = nvd.summarise(NVD_DOC)
        from datetime import datetime, timezone
        cve["published"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00")
        other = {**cve, "cve_id": "CVE-2026-424242", "products": [{"vendor": "fortinet", "product": "fortios"}]}
        self.assertEqual(store.save_cves_bulk([cve, other]), 2)
        self.assertEqual(store.stack_new_cves(), [])                              # empty watchlist
        store.add_watchlist("Citrix")
        rows = store.stack_new_cves(7)
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2023-4966"])
        self.assertEqual(rows[0]["matched"], ["Citrix"])
        self.assertFalse(rows[0]["kev"])
        self.assertIn("citrix netscaler gateway", rows[0]["products"])

    def test_kev_monthly_and_vendors(self):
        from datetime import datetime, timezone
        ym = datetime.now(timezone.utc).strftime("%Y-%m")
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        rows[0]["date_added"] = f"{ym}-02"                     # Citrix, ransomware, this month
        rows[1]["date_added"] = f"{ym}-03"                     # Ivanti, this month
        store.upsert_kev(rows, "cisa")
        monthly = store.kev_monthly(12)
        self.assertEqual(len(monthly), 12)
        self.assertEqual(monthly[-1], {"month": ym, "total": 2, "ransomware": 1})
        self.assertEqual(monthly[0]["total"], 0)
        vendors = store.kev_top_vendors(12, 10)
        self.assertEqual([(v["vendor"], v["total"], v["ransomware"]) for v in vendors],
                         [("Citrix", 1, 1), ("Ivanti", 1, 0)])

    def test_ransomware_group_table(self):
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        store.upsert_kev(rows, "cisa")
        store.upsert_ransomware_cves([("CVE-2023-4966", "lockbit"), ("CVE-2026-118527", "lockbit"),
                                      ("CVE-2026-118527", "clop")])
        store.mark_ransomware_group("lockbit", 1200)
        table = store.ransomware_group_table()
        self.assertEqual([(g["grp"], len(g["cves"]), g["victims"]) for g in table], [("lockbit", 2, 1200), ("clop", 1, None)])
        self.assertEqual(table[0]["cves"][0]["vendor"], "Ivanti")
        this_year = store.ransomware_group_table(year=2026)
        # same CVE count, so the group with more victims comes first
        self.assertEqual([(g["grp"], [c["cve_id"] for c in g["cves"]]) for g in this_year],
                         [("lockbit", ["CVE-2026-118527"]), ("clop", ["CVE-2026-118527"])])
        self.assertEqual(len(store.ransomware_group_table(year=2026, limit=1)), 1)


class TableHelperTests(unittest.TestCase):
    def _rows(self):
        return [
            {"cve_id": "CVE-2026-1", "vendor": "Ivanti", "product": "A", "date": "2026-11-01", "cvss": 9.0, "epss": 0.9,
             "kev": True, "ransomware": False, "code": {"msf": True, "edb": False, "nuclei": False, "gh": False}},
            {"cve_id": "CVE-2026-2", "vendor": "Citrix", "product": "B", "date": "2026-10-01", "cvss": None, "epss": 0.2,
             "kev": False, "ransomware": True, "code": {"msf": False, "edb": True, "nuclei": False, "gh": False}},
            {"cve_id": "CVE-2026-3", "vendor": None, "product": None, "date": None, "cvss": 5.0, "epss": None,
             "kev": False, "ransomware": False, "code": {"msf": False, "edb": False, "nuclei": False, "gh": False}},
        ]

    def test_parse(self):
        from starlette.datastructures import QueryParams
        f = tables.Filters.parse(QueryParams("x_vendor=Ivanti&x_tag=exploited&x_tag=bogus&x_epss=0.5&x_since=30&x_sort=cvss&x_dir=asc&x_page=3"), "x")
        self.assertEqual((f.vendors, f.tags, f.epss, f.since, f.sort, f.desc, f.page), (["Ivanti"], ["exploited"], 0.5, 30, "cvss", False, 3))
        self.assertTrue(f.active)
        f = tables.Filters.parse(QueryParams("x_epss=0.3&x_since=5&x_sort=nope&x_page=-2"), "x", "date")
        self.assertEqual((f.epss, f.since, f.sort, f.desc, f.page), (None, None, "date", True, 1))
        self.assertFalse(f.active)
        # several vendors at once; blanks dropped, duplicates folded
        f = tables.Filters.parse(QueryParams("x_vendor=Ivanti&x_vendor=Citrix&x_vendor=&x_vendor=Citrix"), "x")
        self.assertEqual(f.vendors, ["Citrix", "Ivanti"])
        # a default window applies until the URL says otherwise; "all" means any time
        f = tables.Filters.parse(QueryParams(""), "x", default_since=7)
        self.assertEqual((f.since, f.active), (7, False))
        f = tables.Filters.parse(QueryParams("x_since=all"), "x", default_since=7)
        self.assertEqual((f.since, f.active), (None, True))
        f = tables.Filters.parse(QueryParams("x_since=30"), "x", default_since=7)
        self.assertEqual((f.since, f.active), (30, True))

    def test_apply_filters_and_sorts(self):
        rows = self._rows()
        f = tables.Filters(vendors=["ivanti"])
        self.assertEqual([r["cve_id"] for r in tables.apply(rows, f)], ["CVE-2026-1"])
        f = tables.Filters(vendors=["Ivanti", "Citrix"], tags=["ransomware"])        # vendors OR'd, tags AND'd
        self.assertEqual([r["cve_id"] for r in tables.apply(rows, f)], ["CVE-2026-2"])
        f = tables.Filters(tags=["code"])
        self.assertEqual([r["cve_id"] for r in tables.apply(rows, f)], ["CVE-2026-1", "CVE-2026-2"])
        f = tables.Filters(tags=["weaponised", "exploited"])
        self.assertEqual([r["cve_id"] for r in tables.apply(rows, f)], ["CVE-2026-1"])
        f = tables.Filters(epss=0.5)
        self.assertEqual([r["cve_id"] for r in tables.apply(rows, f)], ["CVE-2026-1"])
        f = tables.Filters(since=30)
        self.assertEqual([r["cve_id"] for r in tables.apply(rows, f, since_day="2026-10-15")], ["CVE-2026-1"])
        f = tables.Filters(sort="cvss", desc=True)
        self.assertEqual([r["cve_id"] for r in tables.apply(rows, f)], ["CVE-2026-1", "CVE-2026-3", "CVE-2026-2"])   # None last
        f = tables.Filters(sort="vendor", desc=False)
        self.assertEqual([r["cve_id"] for r in tables.apply(rows, f)], ["CVE-2026-2", "CVE-2026-1", "CVE-2026-3"])
        self.assertEqual(tables.vendor_options(rows), ["Citrix", "Ivanti"])

    def test_paginate_and_fix(self):
        rows = [{"n": i} for i in range(23)]
        p = tables.paginate(rows, 3)
        self.assertEqual((p["page"], p["pages"], p["start"], p["end"], [r["n"] for r in p["rows"]]), (3, 3, 21, 23, [20, 21, 22]))
        self.assertEqual(tables.paginate(rows, 99)["page"], 3)
        self.assertEqual(tables.paginate([], 1)["start"], 0)
        self.assertEqual(tables.fix_status(1, "[]"), "patch")
        self.assertEqual(tables.fix_status(0, '[{"tags": ["Vendor Advisory"]}]'), "advisory")
        self.assertEqual(tables.fix_status(0, "[]"), "none")
        self.assertIsNone(tables.fix_status(None, None))


class ChartTests(unittest.TestCase):
    def test_monthly_bars(self):
        svg = charts.monthly_bars([{"month": "2026-10", "total": 10, "ransomware": 4},
                                   {"month": "2026-11", "total": 0, "ransomware": 0}])
        self.assertTrue(svg.startswith("<svg"))
        self.assertIn('fill="#f87171"', svg)                       # ransomware share drawn
        self.assertIn("2026-10: 10 listed, 4 ransomware", svg)
        self.assertEqual(charts.monthly_bars([]), "")

    def test_hbars_escape(self):
        svg = charts.hbars([{"vendor": "A <b>&", "total": 3, "ransomware": 1}])
        self.assertIn("A &lt;b&gt;&amp;", svg)
        self.assertNotIn("<b>", svg)

    def test_sparkline(self):
        self.assertEqual(charts.sparkline([0, 0, 0]), "")
        svg = charts.sparkline([1, 3, 2], ["d1", "d2", "d3"])
        self.assertIn("<polyline", svg)
        self.assertIn("6 over 3 days, peak 3, d1 to d3", svg)
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).date().isoformat()
        values, labels = vulnlookup.daily_series({today: 4}, 5)
        self.assertEqual((values[-1], len(labels), labels[-1]), (4, 5, today))


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
        self.assertNotIn("<h3>New exploit code", r.text)          # on the Exploit Code tab
        self.assertIn("New exploit reports or claimed PoCs in the last 7 days for <strong>1</strong> CVE", r.text)
        self.assertNotIn("Hottest right now", r.text)             # parked 2026-11-11
        self.assertNotIn("Ask your AI.", r.text)
        self.assertIn("CVEs Exploited by Ransomware Groups", r.text)
        self.assertIn("Data sourced from", r.text)
        self.assertIn("<h3>Newly Exploited</h3>", r.text)
        # the exploited table has no "exploited" tick box; others keep theirs
        self.assertNotIn('name="kev_tag" value="exploited"', r.text)
        self.assertIn('name="kev_tag" value="code"', r.text)
        self.assertIn("Public Exploit Code", r.text)
        # the filter form returns to its table and submits on change
        self.assertIn('action="/vulnerability-intelligence#t-kev"', r.text)
        self.assertIn("this.requestSubmit()", r.text)
        r = self.client.get("/vulnerability-intelligence/exploits")
        self.assertIn("Recent Exploit Reports and Claimed PoCs", r.text)
        self.assertIn('>Exploits &amp; Detection</a>', r.text)
        self.assertIn("/cve/CVE-2024-3400", r.text)
        self.assertIn('<span class="badge">Claimed PoC (GitHub)</span>', r.text)
        self.assertNotIn("Exploit code available?", r.text)
        self.assertIn('name="poc_tag" value="code"', r.text)
        self.assertIn('name="poc_sort"', r.text)                  # the sort dropdown
        self.assertIn('poc_sort=cvss&amp;poc_dir=desc#t-poc"', r.text)   # header sort links return to the table
        # the vendor filter keeps the row for a non-matching vendor out
        r = self.client.get("/vulnerability-intelligence/exploits?poc_vendor=Nobody")
        self.assertIn("No recent exploit reports or claimed PoCs match.", r.text)
        self.assertIn("0 of 1 rows", r.text)
        r = self.client.get("/vulnerability-intelligence/exploits?poc_sort=heat")
        self.assertIn("Why it's hot", r.text)

    def test_dashboard_charts_and_groups(self):
        from datetime import datetime, timezone
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        rows[0]["date_added"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        store.upsert_kev(rows, "cisa")
        store.upsert_ransomware_cves([("CVE-2026-118527", "clop"), ("CVE-2019-0001", "clop")]
                                     + [(f"CVE-2025-{1000 + i}", "akira") for i in range(7)])
        r = self.client.get("/vulnerability-intelligence")
        self.assertIn("Newly Exploited CVEs per Month", r.text)
        self.assertIn("Most-Exploited Vendors, Last 12 Months", r.text)
        self.assertIn("<svg", r.text)
        self.assertIn("Citrix", r.text)                        # vendor chart label
        self.assertIn("clop", r.text)
        self.assertIn("CVE-2026-118527", r.text)
        self.assertIn("CVE-2019-0001", r.text)                 # all years, no year switch
        self.assertIn("Victims (all time)", r.text)
        self.assertIn("of which known ransomware use", r.text)   # chart legend
        self.assertIn("show 2 more", r.text)                   # akira: 5 shown, 2 behind "show more"

    def test_tables_filter_sort_and_page(self):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        rows = []
        for i in range(12):
            rows.append({"cve_id": f"CVE-2026-{10000 + i}", "vendor": "Ivanti" if i % 2 else "Citrix",
                         "product": f"P{i}", "name": "x", "date_added": today, "due_date": None,
                         "ransomware": 1 if i == 3 else 0, "description": "", "required_action": "",
                         "notes": "", "cwes": []})
        store.upsert_kev(rows, "cisa")
        store.upsert_epss([(f"CVE-2026-{10000 + i}", 0.05 * i, 0.5) for i in range(12)], today)
        store.upsert_exploits("metasploit", [{"ref": "m", "cve_id": "CVE-2026-10003", "title": "t", "url": None,
                                              "date": None, "kind": "exploit", "platform": None, "verified": 1}])
        store.upsert_kev([{**rows[0], "cve_id": "CVE-2020-9999", "date_added": "2020-01-01"}], "cisa")   # old listing
        r = self.client.get("/vulnerability-intelligence")
        self.assertIn("rows 1–10 of 12", r.text)                 # newly exploited: the last 7 days by default
        self.assertIn("12 of 13 rows", r.text)
        self.assertIn("next 10", r.text)
        self.assertNotIn(">clear</a>", r.text.split("Newly Exploited")[1].split("</form>")[0])   # default window is not a filter
        r = self.client.get("/vulnerability-intelligence?kev_page=2")
        self.assertIn("rows 11–12 of 12", r.text)
        r = self.client.get("/vulnerability-intelligence?kev_since=all&kev_page=2")
        self.assertIn("rows 11–13 of 13", r.text)               # any time brings the 2020 listing in
        self.assertIn("CVE-2020-9999", r.text)
        r = self.client.get("/vulnerability-intelligence?kev_vendor=Ivanti&kev_tag=ransomware&kev_tag=weaponised")
        self.assertIn("1 of 13 rows", r.text)
        self.assertIn("CVE-2026-10003", r.text)
        r = self.client.get("/vulnerability-intelligence?kev_vendor=Ivanti&kev_vendor=Citrix")
        self.assertIn("vendor: 2 selected", r.text)
        self.assertIn("12 of 13 rows", r.text)
        r = self.client.get("/vulnerability-intelligence?kev_epss=0.5")
        self.assertIn("2 of 13 rows", r.text)                    # 0.50 and 0.55
        r = self.client.get("/vulnerability-intelligence?kev_sort=epss&kev_dir=asc")
        body = r.text.split("Newly Exploited</h3>")[1]
        self.assertLess(body.index("CVE-2026-10000"), body.index("CVE-2026-10001"))

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
        for needle in ("auxiliary", "citrix_netscaler_adc_bleed", "Exploit-DB", "51600",
                       "Exploitation sightings", "dl.shadowserver.org", "2 exploitation sightings", "P1 Emergency"):
            self.assertIn(needle, r.text)
        r = self.client.get("/vulnerability-intelligence/exploits", params={"cve": "CVE-2023-4966"})
        self.assertIn("Metasploit Modules", r.text)
        self.assertIn("51600", r.text)


if __name__ == "__main__":
    unittest.main()


VC_ITEM = {
    "vendorProject": "Linux", "product": "Kernel", "vulnerabilityName": "Linux Kernel Info Leak",
    "shortDescription": "Leak.", "required_action": "Apply updates.", "knownRansomwareCampaignUse": "Known",
    "cve": ["CVE-2026-99999"], "cwes": ["CWE-200"],
    "vulncheck_xdb": [{"xdb_id": "d78be1b0f067", "xdb_url": "https://vulncheck.com/xdb/d78be1b0f067",
                       "date_added": "2099-01-01T06:21:55Z", "exploit_type": "info-leak",
                       "clone_ssh_url": "git@github.com:someone/CVE-2026-99999.git"}],
    "vulncheck_reported_exploitation": [
        {"url": "https://access.redhat.com/security/cve/cve-2026-99999", "date_added": "2026-10-19T00:00:00Z"},
        {"url": "javascript:alert(1)", "date_added": "2026-10-19T00:00:00Z"}],
    "reported_exploited_by_vulncheck_canaries": True,
    "date_added": "2026-10-19T00:00:00Z", "_timestamp": "2026-10-20T00:00:00Z",
}


class VulnCheckKevTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    def test_parse_page(self):
        kev, xdb, cursor = vc_feed.parse_page({"_meta": {"next_cursor": "abc"}, "data": [VC_ITEM, {"cve": ["junk"]}]})
        self.assertEqual(cursor, "abc")
        self.assertEqual(len(kev), 1)
        row = kev[0]
        self.assertEqual((row["cve_id"], row["date_added"], row["ransomware"]), ("CVE-2026-99999", "2026-10-19", 1))
        self.assertEqual([c["url"] for c in row["citations"]], ["https://access.redhat.com/security/cve/cve-2026-99999"])
        self.assertIn("canaries", row["notes"])
        self.assertEqual(xdb[0]["title"], "someone/CVE-2026-99999")
        self.assertEqual((xdb[0]["kind"], xdb[0]["date"]), ("info-leak", "2099-01-01"))
        with self.assertRaises(ValueError):
            vc_feed.parse_page({"error": True})

    async def test_skipped_without_token(self):
        res = await vc_feed.refresh()
        self.assertTrue(res["ok"])
        self.assertIn("skipped", res["version"])

    async def test_refresh_follows_cursor_and_stores(self):
        seen = []

        def handler(req):
            self.assertEqual(req.url.host, "api.vulncheck.com")
            self.assertEqual(req.headers["authorization"], "Bearer test-token")
            seen.append(dict(req.url.params))
            if "cursor" not in req.url.params:
                return httpx.Response(200, json={"_meta": {"next_cursor": "page2"}, "data": [VC_ITEM]})
            other = {**VC_ITEM, "cve": ["CVE-2023-4966"], "vulncheck_xdb": [], "knownRansomwareCampaignUse": "Unknown"}
            return httpx.Response(200, json={"_meta": {}, "data": [other]})

        settings.vulncheck_api_key = "test-token"
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await vc_feed.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["entries"], 2)
        self.assertIn("start_cursor", seen[0])
        self.assertEqual(seen[1]["cursor"], "page2")
        kev = store.get_kev("CVE-2026-99999")
        self.assertEqual(kev[0]["source"], "vulncheck")
        self.assertEqual(kev[0]["citations"][0]["date"], "2026-10-19")
        self.assertEqual(store.exploit_counts(), {"xdb": 1})
        self.assertTrue(store.flags_for(["CVE-2026-99999"])["CVE-2026-99999"]["code"]["xdb"])
        # XDB entries count as new exploit code by the date XDB added them
        self.assertEqual([r["cve_id"] for r in store.recent_poc(30)], ["CVE-2026-99999"])
        self.assertEqual(priority.KEV_NAMES["vulncheck"], "VulnCheck KEV")

    async def test_bad_token_is_reported(self):
        settings.vulncheck_api_key = "wrong"
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(401))))
        res = await vc_feed.refresh()
        self.assertFalse(res["ok"])
        self.assertIn("401", store.feed_status()["vulncheck_kev"]["error"])


class CvssFilterTests(unittest.TestCase):
    def test_cvss_filter(self):
        f = tables.Filters.parse({"t_cvss": "7.0"}, "t")
        self.assertEqual(f.cvss, 7.0)
        self.assertTrue(f.active)
        rows = [{"cve_id": "A", "cvss": 9.8}, {"cve_id": "B", "cvss": 5.0}, {"cve_id": "C", "cvss": None}]
        self.assertEqual([r["cve_id"] for r in tables.apply(rows, f)], ["A"])
        self.assertIsNone(tables.Filters.parse({"t_cvss": "6.5"}, "t").cvss)     # only the offered bands


class NvdKeyRejectedTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def test_404_with_a_key_names_the_key(self):
        orig = settings.nvd_api_key
        settings.nvd_api_key = "revoked"
        try:
            base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(
                lambda r: httpx.Response(404, headers={"message": "Invalid apiKey."}))))
            res = await nvd.fetch("CVE-2024-3400")
            self.assertEqual(res["status"], "error")
            self.assertIn("NVD_API_KEY", res["error"])
            out = await nvd_recent.refresh()
            self.assertFalse(out["ok"])
            self.assertIn("NVD_API_KEY", store.feed_status()["nvd_recent"]["error"])
        finally:
            settings.nvd_api_key = orig


CVE5_WITH_SSVC = {"containers": {
    "cna": {"providerMetadata": {"shortName": "palo_alto"}, "problemTypes": [{"descriptions": [{"cweId": "CWE-77"}]}]},
    "adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [
        {"other": {"type": "ssvc", "content": {"id": "CVE-2024-3400", "role": "CISA Coordinator",
                   "options": [{"Exploitation": "active"}, {"Automatable": "yes"}, {"Technical Impact": "total"}],
                   "version": "2.0.3", "timestamp": "2024-04-17T04:00:13.543064Z"}}},
        {"other": {"type": "kev", "content": {"dateAdded": "2024-04-12"}}},
        {"cvssV3_1": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}},
    ]}]}}

OTX_CVE_DOC = {"pulse_info": {"count": 3, "pulses": [
    {"id": "aaa", "name": "Old pulse", "created": "2024-04-13T00:00:00", "modified": "2024-04-13T00:00:00",
     "author": {"username": "someone"}, "tags": ["pan-os"], "adversary": "UTA0218",
     "malware_families": [{"display_name": "UPSTYLE"}], "attack_ids": [{"id": "T1190"}]},
    {"id": "bbb", "name": "New pulse", "created": "2026-11-01T00:00:00", "modified": "2026-11-03T00:00:00",
     "author": {"username": "AlienVault"}, "tags": [], "adversary": "", "malware_families": [], "attack_ids": []},
    {"name": "no id, skipped"},
]}}


class SsvcTests(unittest.TestCase):
    def test_ssvc_and_cwe_from_record(self):
        s = vulnlookup.ssvc_from_record(CVE5_WITH_SSVC)
        self.assertEqual((s["exploitation"], s["automatable"], s["technical_impact"]), ("active", "yes", "total"))
        self.assertEqual(s["timestamp"], "2024-04-17")
        self.assertIsNone(vulnlookup.ssvc_from_record(CVE5_RECORD))     # CNA only, no CISA-ADP
        self.assertIsNone(vulnlookup.ssvc_from_record({}))
        self.assertEqual(vulnlookup.cwe_from_record(CVE5_WITH_SSVC), "CWE-77")
        self.assertEqual(vulnlookup.cvss_from_record(CVE5_WITH_SSVC)["cvss_score"], 10.0)   # from CISA-ADP

    def test_priority_uses_ssvc_only_to_raise(self):
        base_args = dict(kev_sources=[], ransomware=False, epss=None, cvss=None, poc_count=0, watchlist_hits=[])
        active = priority.compute(**base_args, ssvc={"exploitation": "active", "timestamp": "2026-11-01"})
        self.assertEqual(active.level, "P1")
        self.assertIn("CISA SSVC as of 2026-11-01: Exploitation active", active.reasons)
        self.assertEqual(priority.compute(**base_args, ssvc={"exploitation": "poc"}).level, "P3")
        severe = {"exploitation": "none", "automatable": "yes", "technical_impact": "total"}
        self.assertEqual(priority.compute(**base_args, ssvc=severe).level, "P4")
        # a stale "none" never lowers what other evidence set
        kev = priority.compute(**{**base_args, "kev_sources": ["cisa"]}, ssvc={"exploitation": "none"})
        self.assertEqual(kev.level, "P1")
        self.assertEqual(priority.compute(**base_args).level, "N/A")


class OtxCveTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    def test_summarise_newest_first(self):
        o = otx_cve.summarise(OTX_CVE_DOC)
        self.assertEqual(o["count"], 3)
        self.assertEqual([p["name"] for p in o["pulses"]], ["New pulse", "Old pulse"])
        self.assertEqual(o["pulses"][1]["malware"], ["UPSTYLE"])
        self.assertEqual(o["pulses"][1]["attack_ids"], 1)
        self.assertEqual(o["pulses"][0]["url"], "https://otx.alienvault.com/pulse/bbb")
        self.assertEqual(o["authors"], 2)

    def test_daily_series_folded_per_author(self):
        daily = [{"id": f"d{i}", "name": f"Actively_Exploited_Kev | Nov {i}, 2026", "created": f"2026-11-{i:02d}T00:00:00",
                  "modified": f"2026-11-{i:02d}T00:00:00", "author": {"username": "bot"}} for i in range(1, 8)]
        clone = {"id": "c1", "name": "Actively_Exploited_Kev | Nov 3, 2026", "created": "2026-11-03T00:00:00",
                 "modified": "2026-11-03T00:00:00", "author": {"username": "someone-else"}}
        o = otx_cve.summarise({"pulse_info": {"count": 8, "pulses": daily + [clone]}})
        self.assertEqual(o["series"], 2)                       # one per author
        first = o["pulses"][0]
        self.assertEqual((first["id"], first["repeats"], first["oldest"]), ("d7", 7, "2026-11-01"))
        self.assertEqual(o["pulses"][1]["repeats"], 1)
        self.assertNotEqual(otx_cve.series_key("a", "Ivanti exploitation wave"),
                            otx_cve.series_key("a", "Citrix exploitation wave"))

    async def test_pulses_not_configured_without_key(self):
        self.assertEqual((await otx_cve.pulses("CVE-2024-3400"))["status"], "not_configured")

    async def test_pulses_fetch_and_cache(self):
        calls = []

        def handler(req):
            calls.append(req.url.path)
            self.assertEqual(req.headers["x-otx-api-key"], "test-otx")
            return httpx.Response(200, json=OTX_CVE_DOC)

        settings.otx_api_key = "test-otx"
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        first = await otx_cve.pulses("cve-2024-3400")
        self.assertEqual(first["status"], "ok")
        self.assertEqual(calls, ["/api/v1/indicators/cve/CVE-2024-3400/general"])
        second = await otx_cve.pulses("CVE-2024-3400")
        self.assertTrue(second["cached"])
        self.assertEqual(len(calls), 1)

    async def test_report_with_ssvc_and_otx(self):
        def handler(req):
            if req.url.host == "services.nvd.nist.gov":
                return httpx.Response(200, json={"vulnerabilities": []})
            if req.url.host == "api.github.com":
                return httpx.Response(200, json={"total_count": 0, "items": []})
            if req.url.host == "vulnerability.circl.lu" and "/api/vulnerability/" in req.url.path:
                return httpx.Response(200, json=CVE5_WITH_SSVC)
            if req.url.host == "vulnerability.circl.lu":
                return httpx.Response(200, json={"metadata": {"count": 0}, "data": []})
            if req.url.host == "otx.alienvault.com":
                return httpx.Response(200, json=OTX_CVE_DOC)
            raise AssertionError(req.url)

        settings.otx_api_key = "test-otx"
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        rep = await service.report("CVE-2024-3400")
        self.assertEqual(rep["priority"].level, "P1")              # SSVC active, nothing else
        self.assertEqual(rep["ssvc"]["exploitation"], "active")
        self.assertEqual(store.get_ssvc("CVE-2024-3400")["automatable"], "yes")
        self.assertEqual(rep["otx"]["count"], 3)
        self.assertEqual(rep["cwe_fallback"], "CWE-77")
        self.assertEqual(rep["cvss_fallback"]["cvss_score"], 10.0)


class SsvcOtxPageTests(TempDbMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app, base_url="http://127.0.0.1")

        def handler(req):
            if req.url.host == "vulnerability.circl.lu" and "/api/vulnerability/" in req.url.path:
                return httpx.Response(200, json=CVE5_WITH_SSVC)
            if req.url.host == "vulnerability.circl.lu":
                return httpx.Response(200, json={"metadata": {"count": 0}, "data": []})
            if req.url.host == "otx.alienvault.com":
                return httpx.Response(200, json=OTX_CVE_DOC)
            if req.url.host == "services.nvd.nist.gov":
                return httpx.Response(200, json=NVD_DOC)
            if req.url.host == "api.github.com":
                return httpx.Response(200, json={"total_count": 0, "items": []})
            raise AssertionError(req.url)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    def tearDown(self):
        import asyncio
        asyncio.run(base.aclose())
        super().tearDown()

    def test_page_shows_ssvc_and_pulses(self):
        settings.otx_api_key = "test-otx"
        r = self.client.get("/vulnerability-intelligence/cve/CVE-2023-4966")
        self.assertEqual(r.status_code, 200)
        self.assertIn("CISA SSVC", r.text)
        self.assertIn('<span class="verdict-malicious">active</span>', r.text)
        self.assertIn("2024-04-17", r.text)
        self.assertIn("OTX pulses", r.text)
        self.assertIn("https://otx.alienvault.com/pulse/bbb", r.text)
        self.assertIn("UPSTYLE", r.text)
        self.assertIn("Context, not evidence", r.text)

    def test_page_without_otx_key(self):
        r = self.client.get("/vulnerability-intelligence/cve/CVE-2023-4966")
        self.assertIn("Add OTX_API_KEY to .env", r.text)


CIRCL_KEV_ITEMS = [
    {"vulnerability": {"vulnId": "CVE-2026-0001"}, "gcve": {"origin_uuid": "c8fb6bf1-f81f-4cb8-95b1-eadbb3b54ee8"},
     "status": {"exploited": True, "status_reason": "confirmed"},
     "timestamps": {"first_seen_at": "2026-11-08T00:00:00+00:00"},
     "evidence": [{"source": "shadowserver", "details": {"feed": "Shadowserver honeypot"}}],
     "scope": {"notes": "Affected: Fortinet"}, "characteristics": {"remote_code_execution": True}},
    {"vulnerability": {"vulnId": "CVE-2026-0002"}, "gcve": {"origin_uuid": "405284c2-e461-4670-8979-7fd2c9755a60"},
     "status": {"exploited": True, "status_reason": "confirmed"}, "timestamps": {"first_seen_at": "2026-11-01T00:00:00Z"},
     "evidence": []},                                                     # CISA via CIRCL: skipped
    {"vulnerability": {"vulnId": "CVE-2026-0003"}, "gcve": {"origin_uuid": "1a89b78e-f703-45f3-bb86-59eb712668bd"},
     "status": {"exploited": True, "status_reason": "confirmed"}, "timestamps": {"asserted_at": "2026-11-09T00:00:00Z"},
     "evidence": []},                                                     # CIRCL's own
    {"vulnerability": {"vulnId": "CVE-2026-0004"}, "gcve": {"origin_uuid": "x"},
     "status": {"exploited": True, "status_reason": "suspected"}, "timestamps": {}, "evidence": []},   # suspected: skipped
    {"vulnerability": {"vulnId": "not-a-cve"}, "status": {"exploited": True, "status_reason": "confirmed"}},
]


class CirclKevTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    def test_parse_items(self):
        from app.modules.vulnerability_intelligence.feeds import circl_kev
        out = circl_kev.parse_items(CIRCL_KEV_ITEMS)
        self.assertEqual(sorted(out), ["circl", "shadowserver"])
        row = out["shadowserver"][0]
        self.assertEqual((row["cve_id"], row["date_added"]), ("CVE-2026-0001", "2026-11-08"))
        self.assertTrue(row["notes"].startswith("Remote code execution."))
        self.assertEqual(out["circl"][0]["date_added"], "2026-11-09")
        self.assertIn("shadowserver", priority.KEV_NAMES)

    async def test_refresh_pages_and_stores(self):
        from app.modules.vulnerability_intelligence.feeds import circl_kev

        def handler(req):
            self.assertEqual(req.url.path, "/api/kev/")
            return httpx.Response(200, json={"metadata": {"count": 5}, "data": CIRCL_KEV_ITEMS})
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await circl_kev.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["entries"], 2)
        self.assertEqual([k["source"] for k in store.get_kev("CVE-2026-0001")], ["shadowserver"])
        self.assertEqual(store.get_kev("CVE-2026-0002"), [])


class ViewTests(TempDbMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())          # CVE-2023-4966 (Citrix), CVE-2026-118527 (Ivanti)
        store.upsert_kev(rows, "cisa")
        store.upsert_kev([{**rows[0], "date_added": "2023-10-10"}], "shadowserver")   # earlier listing elsewhere
        store.upsert_exploits("metasploit", [{"ref": "exploit/x", "cve_id": "CVE-2023-4966", "title": "t", "url": None,
                                             "date": None, "kind": "exploit", "platform": None, "verified": 0}])
        store.upsert_exploits("nuclei", [{"ref": "cves/2025/CVE-2025-1111.yaml", "cve_id": "CVE-2025-1111", "title": "t",
                                          "url": None, "date": None, "kind": "high", "platform": None, "verified": 0}])
        store.upsert_poc_repos(poc_feed.parse_items([gh_repo("CVE-2025-2222-poc", "2026-11-01", 3)]))
        store.upsert_epss([("CVE-2025-1111", 0.6, 0.9), ("CVE-2025-2222", 0.2, 0.8)], "2026-11-10")

    def test_exploited_view(self):
        from app.modules.vulnerability_intelligence import views
        rows = {r["cve_id"]: r for r in views.BY_SLUG["exploited"].rows()}
        self.assertEqual(set(rows), {"CVE-2023-4966", "CVE-2026-118527"})
        citrix = rows["CVE-2023-4966"]
        self.assertEqual(citrix["sources"], ["cisa", "shadowserver"])
        self.assertEqual(citrix["date"], "2023-10-10")                   # earliest listing = first seen exploited
        self.assertTrue(citrix["ransomware"])
        self.assertEqual(citrix["maturity"], "Exploit Module")
        self.assertEqual(views.BY_SLUG["exploited"].count(), 2)

    def test_code_not_exploited_view(self):
        from app.modules.vulnerability_intelligence import views
        v = views.BY_SLUG["code"]
        rows = {r["cve_id"]: r for r in v.rows()}
        self.assertEqual(set(rows), {"CVE-2025-2222"})   # Nuclei-only and already exploited CVEs stay out
        self.assertEqual(rows["CVE-2025-2222"]["maturity"], "Claimed PoC")
        self.assertEqual(rows["CVE-2025-2222"]["date"], "2026-11-01")
        self.assertEqual(v.count(), 1)

    def test_watchlist_view(self):
        from app.modules.vulnerability_intelligence import views
        self.assertEqual(views.BY_SLUG["watchlist"].rows(), [])
        store.add_watchlist("Ivanti")
        rows = views.BY_SLUG["watchlist"].rows()
        self.assertEqual([r["cve_id"] for r in rows], ["CVE-2026-118527"])
        self.assertEqual(rows[0]["matched"], ["Ivanti"])


class ViewRouteTests(ViewTests):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from app.main import app
        self.client = TestClient(app, base_url="http://127.0.0.1")

    def test_views_pages(self):
        r = self.client.get("/vulnerability-intelligence/views")
        self.assertIn("Exploit Leads Without Reported Exploitation", r.text)
        r = self.client.get("/vulnerability-intelligence/views/code")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Exploit Evidence", r.text)
        self.assertIn(">Claimed PoC</a>", r.text)
        self.assertIn("CVE-2025-2222", r.text)
        self.assertNotIn("CVE-2025-1111", r.text)
        r = self.client.get("/vulnerability-intelligence/views/exploited?v_tag=ransomware")
        self.assertIn("CVE-2023-4966", r.text)
        self.assertNotIn("CVE-2026-118527</code>", r.text)
        self.assertIn("No view named", self.client.get("/vulnerability-intelligence/views/nope").text)

    def test_dashboard_counters(self):
        r = self.client.get("/vulnerability-intelligence")
        self.assertIn('href="/vulnerability-intelligence/views/exploited" class="viewcount"><strong>2</strong> Known Exploited', r.text)
        self.assertIn('href="/vulnerability-intelligence/views/all" class="viewcount"><strong>4</strong> All Vulnerabilities', r.text)

    def test_watchlist_filter_on_both_views(self):
        from app.modules.vulnerability_intelligence.feeds import cvelist

        cve_id = "CVE-2026-12400"
        store.save_cve_records([cvelist.parse_record(cve5(cve_id, vendor="Acme", product="Connect Secure"))])
        store.add_watchlist("", "Connect Secure")
        dashboard = self.client.get("/vulnerability-intelligence").text
        self.assertIn('/views/all?v_tag=watchlist', dashboard)
        self.assertIn('/views/exploited?v_tag=watchlist', dashboard)
        for slug in ("all", "exploited"):
            result = self.client.get(f"/vulnerability-intelligence/views/{slug}?v_tag=watchlist")
            self.assertEqual(result.status_code, 200)
            self.assertIn('value="watchlist" checked> Watchlist', result.text)
            self.assertIn("Product Match", result.text)
            self.assertIn("CVE-2026-118527", result.text)
            self.assertNotIn("CVE-2023-4966", result.text)
            self.assertEqual(cve_id in result.text, slug == "all")

    def test_catalog_pages_filtered_results_and_can_be_pinned(self):
        from app.modules.vulnerability_intelligence.feeds import cvelist

        store.save_cve_records([
            cvelist.parse_record(cve5(f"CVE-2026-{7000 + i}", vendor="Acme",
                                      published=f"2026-11-{i + 1:02d}T00:00:00Z")) for i in range(12)
        ] + [cvelist.parse_record(cve5("CVE-2026-7999", vendor="Acme", state="REJECTED"))])
        store.upsert_epss([("CVE-2026-7999", 0.9, 0.9)], "2026-11-10")
        url = "/vulnerability-intelligence/views/all"
        result = self.client.get(url, params={"v_vendor_query": "ACME", "v_page": "999"})
        self.assertIn("12 of 16 rows", result.text)
        self.assertIn("rows 11–12 of 12", result.text)
        self.assertLess(result.text.index("CVE-2026-7001"), result.text.index("CVE-2026-7000"))
        self.assertNotIn("CVE-2026-7011", result.text)
        self.assertNotIn("CVE-2026-7999", result.text)
        result = self.client.get(url, params={"v_tag": ["exploited", "code"], "v_vendor_query": "citrix"})
        self.assertIn("1 of 16 rows", result.text)
        self.assertIn("CVE-2023-4966", result.text)
        self.assertNotIn("CVE-2026-118527", result.text)
        self.client.post("/vulnerability-intelligence/views/pins", data={"pinned": "all"})
        dashboard = self.client.get("/vulnerability-intelligence").text
        preview = dashboard.split('id="t-pin-all"', 1)[1].split("</table>", 1)[0]
        self.assertEqual(preview.count('<td class="cvecell">'), 5)
        self.assertIn("CVE-2026-7011", preview)
        self.assertNotIn("CVE-2026-7006", preview)

    def test_dashboard_pins_show_first_five_and_survive_schema_init(self):
        store.upsert_epss([(f"CVE-2026-{6000 + i}", (i + 1) / 10, 0.9) for i in range(7)], "2026-11-10")
        response = self.client.post("/vulnerability-intelligence/views/pins",
                                    data={"pinned": ["likely", "watchlist"]}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/vulnerability-intelligence#pinned-views")
        store.init_schema()
        self.assertEqual(store.dashboard_view_pins(), {"likely", "watchlist"})
        dashboard = self.client.get("/vulnerability-intelligence").text
        pinned = dashboard.split('<section id="pinned-views"', 1)[1].split("</section>", 1)[0]
        self.assertIn('id="t-pin-watchlist"', pinned)
        self.assertIn("No CVEs in this view yet.", pinned)
        self.assertIn('href="/vulnerability-intelligence/views/likely"', pinned)
        self.assertEqual(pinned.count("<td class=\"cvecell\">"), 5)
        self.assertIn("CVE-2026-6006", pinned)
        self.assertNotIn("CVE-2026-6000", pinned)
        self.assertNotIn('name="pin-likely_tag"', pinned)
        self.client.post("/vulnerability-intelligence/views/pins", data={})
        self.assertFalse(store.dashboard_view_pins())
        self.assertNotIn('id="t-pin-likely"', self.client.get("/vulnerability-intelligence").text)

    def test_invalid_pin_submissions_keep_saved_selection(self):
        url = "/vulnerability-intelligence/views/pins"
        store.save_dashboard_view_pins({"ransomware"})
        response = self.client.post(url, data={"pinned": ["exploited", "watchlist", "code", "likely", "ransomware"]})
        self.assertIn("Choose up to 4 views.", response.text)
        response = self.client.post(url, data={"pinned": "missing"})
        self.assertIn("Choose only views shown on this page.", response.text)
        response = self.client.post(url, data={"pinned": "code"}, headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(store.dashboard_view_pins(), {"ransomware"})


class FirstSeenTests(TempDbMixin, unittest.TestCase):
    def test_old_cve_reported_again_is_not_new(self):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        old = [r for r in rows if r["cve_id"] == "CVE-2023-4966"]           # CISA listed 2023-10-18
        store.upsert_kev(old, "cisa")
        store.upsert_kev([{**old[0], "date_added": today}], "shadowserver")  # a honeypot saw it today
        self.assertEqual(store.recent_kev(7), [])                            # not "newly exploited"
        hot = {r["cve_id"]: r for r in service.hottest(10)}["CVE-2023-4966"]
        self.assertEqual(hot["first_exploited"], "2023-10-18")
        self.assertTrue(any(p.startswith("listed ") and p.endswith("y ago") for p in hot["parts"]), hot["parts"])


class ActionAndReviewTests(TempDbMixin, unittest.TestCase):
    def setUp(self):
        super().setUp()
        from fastapi.testclient import TestClient
        from app.main import app

        self.client = TestClient(app, base_url="http://127.0.0.1")
        self.prefix = "/vulnerability-intelligence"

    def test_non_microsoft_actions_and_watchlist_scope(self):
        from app.modules.vulnerability_intelligence.feeds import cvelist

        cve_id = "CVE-2026-12001"
        record = cve5(cve_id)
        record["containers"]["cna"]["workarounds"] = [{"lang": "en", "value": "Disable the widget endpoint."}]
        store.save_cve_records([cvelist.parse_record(record)])
        store.save_cve({"cve_id": cve_id, "patch_available": True, "references": [
            {"url": "https://example.test/update", "tags": ["Patch"]},
            {"url": "https://github.com/example/widget-exploit", "tags": ["Exploit"]},
        ]})
        store.add_watchlist("Acme", "Widget")
        url = self.prefix + "/views/all"
        body = self.client.get(url).text
        for label in ("Patch", "Mitigate", "Hunt"):
            self.assertIn(f">{label}</span>", body)
        self.assertNotIn(">Investigate Applicability</span>", body)
        filtered = self.client.get(url, params={"v_tag": "watchlist"}).text
        self.assertIn(">Investigate Applicability</span>", filtered)

        record["containers"]["cna"]["references"] = [{"url": "https://example.test/cna-fix", "tags": ["patch"]}]
        store.save_cve_records([cvelist.parse_record(record)])
        store.save_cve({"cve_id": cve_id})
        self.assertIn("CNA Patch Reference", self.client.get(url).text)

    def test_advisory_only_keeps_patch_unknown_and_detection_is_not_exploit_code(self):
        cve_id = "CVE-2026-12002"
        store.save_cve({"cve_id": cve_id, "references": [
            {"url": "https://example.test/advisory", "tags": ["Vendor Advisory"]},
            {"url": "https://example.test/workaround", "tags": ["Mitigation"]},
        ]})
        store.upsert_exploits("nuclei", [{"ref": "test", "cve_id": cve_id, "title": "Test", "url": None,
                                          "date": None, "kind": "high", "platform": None, "verified": 0}])
        body = self.client.get(self.prefix + "/views/all").text
        self.assertIn("Unknown · Advisory", body)
        for label in ("Mitigate", "Monitor"):
            self.assertIn(f">{label}</span>", body)
        for label in ("Patch", "Hunt"):
            self.assertNotIn(f">{label}</span>", body)

    def test_review_tracks_material_changes_and_preserves_later_arrivals(self):
        from app.modules.vulnerability_intelligence import review
        from app.modules.vulnerability_intelligence.feeds import cvelist

        cve_id = "CVE-2026-12003"
        store.save_cve_records([cvelist.parse_record(cve5(cve_id))])
        response = self.client.post(self.prefix + "/watchlist/add", data={"vendor": "Acme"})
        self.assertEqual(response.status_code, 200)
        watch = review.page()["rows"][0]
        self.assertEqual((watch["kind"], watch["detail"]), ("watch", "Acme"))
        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        store.upsert_kev(rows[:1], "cisa")
        store.save_cve({"cve_id": cve_id, "patch_available": True, "references": [
            {"url": "https://example.test/patch", "tags": ["Patch"]},
        ]})
        store.upsert_exploits("exploitdb", [{"ref": "100", "cve_id": cve_id, "title": "Test", "url": None,
                                             "date": None, "kind": "webapps", "platform": None, "verified": 1}])
        review.capture()
        url = self.prefix + "/review"
        body = self.client.get(url).text
        for label in ("Product Match", "Patch Evidence", "Exploitation Reported", "Public Exploit Code"):
            self.assertIn(label, body)
        self.assertEqual(review.page()["total"], 4)
        last_seen = review.page()["latest"]
        self.client.post(url + "/mark", data={"event_id": watch["id"]})
        store.upsert_kev(rows[1:], "cisa")
        review.capture(cve_id="CVE-2026-118527")
        review.capture()
        self.assertEqual(review.page()["total"], 4)
        denied = self.client.post(url + "/mark", data={"event_id": last_seen, "through": True},
                                  headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(denied.status_code, 403)
        self.client.post(url + "/mark", data={"event_id": last_seen, "through": True})
        self.assertEqual([r["cve_id"] for r in review.page()["rows"]], ["CVE-2026-118527"])
        store.init_schema()
        self.assertEqual(review.page(history=True)["total"], 5)
        self.assertIn("Reviewed", self.client.get(url, params={"history": True}).text)
        self.assertIn("Since Last Review", self.client.get(self.prefix).text)

    def test_review_baselines_an_existing_database_and_expires_old_events(self):
        from app.modules.vulnerability_intelligence import review

        rows, _ = kev_feed.parse(json.dumps(KEV_DOC).encode())
        store.upsert_kev(rows[:1], "cisa")
        with db.connect() as conn, conn:
            conn.execute("DELETE FROM sync_state WHERE name='vuln_review_initialized'")
        review.capture()
        self.assertEqual(review.page(history=True)["total"], 0)
        store.upsert_kev(rows[1:], "cisa")
        review.capture()
        self.assertEqual(review.page(history=True)["total"], 1)
        with db.connect() as conn, conn:
            conn.execute("UPDATE vuln_review_events SET observed_at='2000-01-01'")
        review.capture()
        self.assertEqual(review.page(history=True)["total"], 0)
        with db.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM vuln_review_events").fetchone()[0], 0)


class MicrosoftAdvisoryTests(TempDbMixin, unittest.TestCase):
    def test_refresh_retries_missing_advisories_and_feeds_the_views(self):
        import asyncio
        from unittest.mock import patch

        from fastapi.testclient import TestClient

        from app.main import app
        from app.modules.vulnerability_intelligence.feeds import msrc

        ids = [f"CVE-2026-{9010 + i}" for i in range(4)]
        paths = {cve: f"2026/msrc_{cve.lower()}.json" for cve in ids}

        def advisory(cve, released, severity, exploited="No", cna="Microsoft"):
            return {"document": {"tracking": {"initial_release_date": released,
                                              "current_release_date": "2026-11-13T08:00:00Z"}},
                    "product_tree": {"branches": [{"category": "product_name", "name": "Windows Widget",
                                                  "product": {"product_id": "1", "name": "Windows Widget"}}]},
                    "vulnerabilities": [{"cve": cve, "title": f"{cna} Widget Vulnerability",
                                         "notes": [{"title": "Assigning CNA", "text": cna}],
                                         "product_status": {"known_affected": ["1"]},
                                         "scores": [{"cvss_v3": {"baseScore": 7.0, "baseSeverity": severity}}],
                                         "threats": [{"category": "exploit_status", "details":
                                                      f"Publicly Disclosed:Yes;Exploited:{exploited};"
                                                      "Latest Software Release:Exploitation More Likely"}],
                                         "remediations": [{"category": "vendor_fix", "product_ids": ["1"],
                                                           "details": "10.0.9:Security Update:https://support.microsoft.com/help/1234",
                                                           "url": "https://support.microsoft.com/help/1234"}]}]}

        docs = {paths[ids[0]]: advisory(ids[0], "2026-11-10", "HIGH", "Yes"),
                paths[ids[1]]: advisory(ids[1], "2026-11-10", "MEDIUM"),
                paths[ids[2]]: advisory(ids[2], "2026-11-10", "HIGH", cna="Chromium"),
                paths[ids[3]]: advisory(ids[3], "2026-11-12", "HIGH")}
        docs[paths[ids[0]]]["vulnerabilities"][0]["remediations"].append(
            {"category": "workaround", "details": "Disable the affected component", "product_ids": ["1"]})
        calls = []
        fail = {paths[ids[1]]}

        def handle(req):
            path = req.url.path.removeprefix("/csaf/advisories/")
            if path == "changes.csv":
                content = "".join(f'"{name}","2026-11-13T08:00:00Z"\n' for name in docs)
                return httpx.Response(200, content=content)
            calls.append(path)
            return httpx.Response(503) if path in fail else httpx.Response(200, json=docs[path])

        store.set_sync(msrc.SYNC_KEY, "2026-10-01")

        async def load():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
                with patch.object(base, "get_client", return_value=client):
                    self.assertFalse((await msrc.refresh())["ok"])
                    self.assertIn("1 Microsoft advisories failed", store.feed_status()[msrc.FEED]["error"])
                    fail.clear()
                    calls.clear()
                    self.assertEqual((await msrc.refresh())["entries"], 4)
                    self.assertEqual(calls, [paths[ids[1]]])
                    self.assertIsNone(store.feed_status()[msrc.FEED]["error"])

        asyncio.run(load())
        self.assertEqual(store.get_kev(ids[0])[0]["date_added"], "2026-11-13")
        client = TestClient(app, base_url="http://127.0.0.1")
        url = "/vulnerability-intelligence/views/patch-tuesday"
        triage = client.get(url)
        self.assertEqual(triage.status_code, 200)
        self.assertIn(ids[0], triage.text)
        self.assertIn("Windows Widget", triage.text)
        self.assertIn("10.0.9", triage.text)
        for label in ("Patch", "Mitigate", "Hunt"):
            self.assertIn(f">{label}</span>", triage.text)
        self.assertNotIn(ids[1], triage.text)
        self.assertIn(ids[1], client.get(url, params={"v_focus": "all"}).text)
        self.assertIn(ids[2], client.get(url, params={"v_cycle": "also"}).text)
        self.assertIn(ids[3], client.get(url, params={"v_cycle": "out-of-band"}).text)
        known = client.get("/vulnerability-intelligence/views/exploited")
        self.assertIn(ids[0], known.text)
        self.assertIn("Microsoft Reported Exploitation</span>", known.text)
        catalog = client.get("/vulnerability-intelligence/views/all")
        self.assertIn(ids[3], catalog.text)
        self.assertIn(f'/cve/{ids[3]}#microsoft-advisory">Microsoft Fix</a>', catalog.text)
        store.add_watchlist("", "Windows Widget")
        watched = client.get("/vulnerability-intelligence/views/all?v_tag=watchlist")
        self.assertIn(ids[3], watched.text)
        self.assertIn("Product Match", watched.text)
        denied = client.post("/vulnerability-intelligence/refresh-msrc", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(denied.status_code, 403)


def cve5(cve_id, vendor="Acme", product="Widget", published="2026-11-10T00:00:00Z", ssvc=None, state="PUBLISHED"):
    rec = {"dataType": "CVE_RECORD", "cveMetadata": {"cveId": cve_id, "state": state, "assignerShortName": "acme",
                                                     "datePublished": published, "dateUpdated": published},
           "containers": {"cna": {"title": "Widget overflow", "affected": [{"vendor": vendor, "product": product},
                                                                          {"vendor": "n/a", "product": "n/a"}],
                                  "descriptions": [{"lang": "en", "value": "A   buffer overflow."}],
                                  "problemTypes": [{"descriptions": [{"cweId": "CWE-787"}]}],
                                  "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": 9.1, "baseSeverity": "CRITICAL",
                                                            "vectorString": "CVSS:3.1/AV:N"}}]}}}
    if ssvc:
        rec["containers"]["adp"] = [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": [
            {"other": {"type": "ssvc", "content": {"options": [{"Exploitation": ssvc}, {"Automatable": "yes"},
                                                              {"Technical Impact": "total"}],
                                                  "timestamp": "2026-11-09T00:00:00Z"}}}]}]
    return rec


def zip_of(records: dict, folder: str = "cves/2026/1xxx") -> bytes:
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, rec in records.items():
            zf.writestr(f"{folder}/{name}.json", json.dumps(rec))
        zf.writestr("cves/deltaLog.json", "[]")                        # non-CVE files are ignored
    return buf.getvalue()


class CveListTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    def test_parse_record(self):
        from app.modules.vulnerability_intelligence.feeds import cvelist
        row = cvelist.parse_record(cve5("CVE-2026-1001", ssvc="active"))
        self.assertEqual(row["products"], [("Acme", "Widget", "")])          # "n/a" pairs dropped
        self.assertEqual((row["published"], row["cvss_score"], row["cwe"]), ("2026-11-10", 9.1, "CWE-787"))
        self.assertEqual(row["description"], "A buffer overflow.")
        self.assertEqual(row["ssvc"]["exploitation"], "active")
        self.assertIsNone(cvelist.parse_record({"nope": 1}))

    async def test_full_load_then_deltas(self):
        import io
        import zipfile
        from datetime import datetime, timedelta, timezone
        from app.modules.vulnerability_intelligence.feeds import cvelist
        today = datetime.now(timezone.utc).date()
        yesterday = today - timedelta(days=1)
        inner = zip_of({"CVE-2026-1001": cve5("CVE-2026-1001"), "CVE-2026-1002": cve5("CVE-2026-1002", ssvc="active")})
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("cves.zip", inner)
        delta = zip_of({"CVE-2026-1003": cve5("CVE-2026-1003", vendor="Ivanti", product="Connect Secure")}, "deltaCves")
        seen = []

        def handler(req):
            path = req.url.path
            seen.append(path.rsplit("/", 1)[-1])
            if path.endswith(f"{yesterday.isoformat()}_all_CVEs_at_midnight.zip.zip"):
                return httpx.Response(200, content=outer.getvalue())
            if "all_CVEs_at_midnight" in path:
                return httpx.Response(404)                              # today's snapshot not out yet
            if path.endswith(f"{yesterday.isoformat()}_delta_CVEs_at_end_of_day.zip"):
                return httpx.Response(200, content=delta)
            if f"{today.isoformat()}_delta_CVEs_at_" in path:
                return httpx.Response(200, content=zip_of({}, "deltaCves"))
            return httpx.Response(404)

        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        self.assertIn("not loaded yet", (await cvelist.refresh())["version"])
        res = await cvelist.full_load()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["entries"], 2)
        self.assertIn(f"{yesterday.isoformat()}_delta_CVEs_at_end_of_day.zip", seen)   # the gap day applied
        self.assertTrue(store.get_sync(cvelist.SYNC_KEY).startswith(today.isoformat()))
        self.assertFalse((settings.data_dir / "cvelist").exists())                      # downloads removed
        self.assertEqual(store.get_ssvc("CVE-2026-1002")["exploitation"], "active")

        from app.modules.vulnerability_intelligence import views
        exploited = {r["cve_id"]: r for r in views.BY_SLUG["exploited"].rows()}
        self.assertEqual(exploited["CVE-2026-1002"]["sources"], ["ssvc"])               # SSVC active counts
        self.assertEqual(exploited["CVE-2026-1002"]["date"], "2026-11-09")
        self.assertEqual(exploited["CVE-2026-1002"]["vendor"], "Acme")                 # from the CVE record
        self.assertEqual(exploited["CVE-2026-1002"]["cvss"], 9.1)
        store.add_watchlist("Ivanti")
        self.assertEqual([r["cve_id"] for r in views.BY_SLUG["watchlist"].rows()], ["CVE-2026-1003"])

    async def test_too_far_behind_asks_for_reload(self):
        from datetime import datetime, timedelta, timezone
        from app.modules.vulnerability_intelligence.feeds import cvelist
        old = datetime.now(timezone.utc).date() - timedelta(days=30)
        store.set_sync(cvelist.SYNC_KEY, f"{old.isoformat()} midnight")
        res = await cvelist.refresh()
        self.assertFalse(res["ok"])
        self.assertIn("load the CVE List again", res["error"])


class MoreViewTests(ViewTests):
    """Views 5, 6, 9, 11 and 12, on top of ViewTests' fixture: Citrix
    CVE-2023-4966 (CISA 2023-10-18 with ransomware, Shadowserver 2023-10-10),
    Ivanti CVE-2026-118527 (CISA 2099-01-01), CVE-2025-1111 (Nuclei, EPSS
    0.6) and CVE-2025-2222 (GitHub PoC, EPSS 0.2)."""

    def _record(self, cve_id, published, cvss=None, state="PUBLISHED"):
        from app.core.db import connect
        with connect() as conn:
            conn.execute("INSERT OR REPLACE INTO cve_records (cve_id, state, published, cvss_score) VALUES (?, ?, ?, ?)",
                         (cve_id, state, published, cvss))
            conn.commit()

    def _ids(self, slug):
        from app.modules.vulnerability_intelligence import views
        v = views.BY_SLUG[slug]
        rows = {r["cve_id"]: r for r in v.rows()}
        self.assertEqual(v.count(), len(rows))           # the counter and the page agree
        return rows

    def test_new_and_severe(self):
        from datetime import datetime, timedelta, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%dT10:00:00")
        old = (datetime.now(timezone.utc) - timedelta(days=20)).strftime("%Y-%m-%dT10:00:00")
        self._record("CVE-2026-50001", today, 9.8)                       # critical: in
        self._record("CVE-2026-50002", today, 5.0)                       # SSVC automatable + total: in
        store.save_ssvc("CVE-2026-50002", {"exploitation": "none", "automatable": "yes",
                                           "technical_impact": "total", "timestamp": today[:10]})
        self._record("CVE-2026-50003", today, 5.0)                       # medium: out
        self._record("CVE-2026-50004", old, 9.8)                         # too old: out
        self._record("CVE-2026-50005", today, 9.8, state="REJECTED")     # rejected: out
        rows = self._ids("new-severe")
        self.assertEqual(set(rows), {"CVE-2026-50001", "CVE-2026-50002"})
        self.assertEqual(rows["CVE-2026-50001"]["date"], today[:10])
        self.assertEqual(rows["CVE-2026-50001"]["cvss"], 9.8)

    def test_likely_next(self):
        store.upsert_epss([("CVE-2023-4966", 0.97, 0.99), ("CVE-2024-0009", 0.05, 0.9)], "2026-11-10")
        rows = self._ids("likely")
        # EPSS 0.6 and 0.2 are in; the exploited Citrix CVE and EPSS 0.05 are not.
        self.assertEqual(set(rows), {"CVE-2025-1111", "CVE-2025-2222"})

    def test_ransomware_linked(self):
        store.upsert_ransomware_cves([("CVE-2025-2222", "akira"), ("CVE-2023-4966", "lockbit")])
        rows = self._ids("ransomware")
        self.assertEqual(set(rows), {"CVE-2023-4966", "CVE-2025-2222"})
        self.assertEqual(rows["CVE-2025-2222"]["ransomware_groups"], ["akira"])
        self.assertTrue(rows["CVE-2025-2222"]["ransomware"])            # a group link alone sets the flag
        self.assertEqual(rows["CVE-2023-4966"]["date"], "2023-10-10")   # first seen exploited

    def test_possible_zero_days(self):
        self._record("CVE-2023-4966", "2023-10-10T14:15:00")            # first listed the same day: in
        self._record("CVE-2026-118527", "2026-01-01T00:00:00")          # listed in 2099: out
        self._record("CVE-2025-1111", "2026-11-08T09:00:00")            # SSVC active the day after: out
        store.save_ssvc("CVE-2025-1111", {"exploitation": "active", "automatable": "no",
                                          "technical_impact": "partial", "timestamp": "2026-11-09"})
        self._record("CVE-2025-2222", "2026-11-01T09:00:00")            # not exploited: out
        rows = self._ids("zero-day")
        self.assertEqual(set(rows), {"CVE-2023-4966"})
        self.assertEqual(rows["CVE-2023-4966"]["zero_day"], "Possible Zero-Day")

    def test_exploitation_sightings(self):
        from app.core.db import connect
        with connect() as conn:
            conn.executemany("INSERT INTO sightings_recent (cve_id, type, day, n) VALUES (?, ?, ?, ?)",
                             [("CVE-2025-1111", "exploited", "2026-11-09", 1),
                              ("CVE-2025-1111", "exploited", "2026-11-10", 2),
                              ("CVE-2025-2222", "seen", "2026-11-10", 5)])
            conn.commit()
        rows = self._ids("sightings")
        self.assertEqual(set(rows), {"CVE-2025-1111"})                  # "seen" is not "exploited"
        self.assertEqual(rows["CVE-2025-1111"]["date"], "2026-11-10")
        self.assertEqual(rows["CVE-2025-1111"]["sightings"], 3)

    def test_pages_render(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.modules.vulnerability_intelligence import views
        client = TestClient(app, base_url="http://127.0.0.1")
        store.upsert_ransomware_cves([("CVE-2025-2222", "akira")])
        listing = client.get("/vulnerability-intelligence/views").text
        for v in views.VIEWS:
            self.assertIn(v.title, listing)
            r = client.get(f"/vulnerability-intelligence/views/{v.slug}")
            self.assertEqual(r.status_code, 200, v.slug)
        r = client.get("/vulnerability-intelligence/views/ransomware")
        self.assertIn('title="known ransomware use: akira"', r.text)


class SsvcActiveIsExploitedTests(ViewTests):
    def test_ssvc_active_cve_is_not_in_the_code_view(self):
        from app.modules.vulnerability_intelligence import views
        # CVE-2025-1111 has a Nuclei template and is on no list; CISA now assesses it as actively exploited.
        store.save_ssvc("CVE-2025-1111", {"exploitation": "active", "automatable": "yes",
                                          "technical_impact": "total", "timestamp": "2026-11-09"})
        code = {r["cve_id"] for r in views.BY_SLUG["code"].rows()}
        self.assertEqual(code, {"CVE-2025-2222"})
        self.assertEqual(views.BY_SLUG["code"].count(), 1)
        exploited = {r["cve_id"]: r for r in views.BY_SLUG["exploited"].rows()}
        self.assertEqual(exploited["CVE-2025-1111"]["sources"], ["ssvc"])
        self.assertEqual(views.BY_SLUG["exploited"].count(), 3)


RVM_EDGE = """## Network Edge Devices
- VPNs, firewalls

### `Fortinet`
| Product | CVE(s) | Ransomware Group(s) | Source(s) |
|---|---|---|---|
| FortiOS | CVE-2018-13379 | Conti, LockBit, Ghost/Cring | [cisa.gov](https://www.cisa.gov/a) / [tenable.com](https://www.tenable.com/b) |
| FortiOS | CVE-2019-5591 | Nemesis Kitten+ | [secureworks.com](https://www.secureworks.com/c) |
"""
RVM_MS = """## Microsoft Products

### `Windows`
| Product | CVE(s) | Ransomware Group(s) | Source(s) |
|---|---|---|---|
| Print Spooler | CVE-2021-1675 and CVE-2021-34527 ("PrintNightmare") | *Prophet Spider, Vice Society, CosmicBeetle* | [x.test](https://x.test/1) |
| PaperCut | CVE-2023\N{REPLACEMENT CHARACTER}27350 & CVE-2023\N{EN DASH}27351 | Black Basta, BlackBasta | [y.test](https://y.test/2) |
"""


class RvmParseTests(unittest.TestCase):
    def test_parse_cells_markers_and_separators(self):
        from app.modules.vulnerability_intelligence.feeds import rvm
        rows = {(r["cve_id"], r["grp"]): r for r in rvm.parse({"NetworkEdge": RVM_EDGE, "Microsoft": RVM_MS})}
        conti = rows[("CVE-2018-13379", "Conti")]
        self.assertEqual((conti["category"], conti["vendor"], conti["product"], conti["role"]),
                         ("Network Edge Devices", "Fortinet", "FortiOS", "gang"))
        self.assertEqual([s["url"] for s in conti["sources"]], ["https://www.cisa.gov/a", "https://www.tenable.com/b"])
        self.assertIn(("CVE-2018-13379", "Ghost/Cring"), rows)               # "/" is part of a name, not a separator
        self.assertEqual(rows[("CVE-2019-5591", "Nemesis Kitten")]["role"], "state")
        # "and" between CVEs, a nickname, and each marker:
        self.assertEqual(rows[("CVE-2021-1675", "Prophet Spider")]["role"], "broker")
        self.assertEqual(rows[("CVE-2021-34527", "CosmicBeetle")]["role"], "affiliate")
        self.assertEqual(rows[("CVE-2021-34527", "Vice Society")]["vendor"], "Windows")
        # A broken dash still yields the CVE; two spellings of one group become one.
        self.assertIn(("CVE-2023-27350", "Black Basta"), rows)
        self.assertIn(("CVE-2023-27351", "Black Basta"), rows)
        self.assertNotIn(("CVE-2023-27350", "BlackBasta"), rows)

    def test_empty_matrix_is_an_error(self):
        from app.modules.vulnerability_intelligence.feeds import rvm
        with self.assertRaises(ValueError):
            rvm.parse({"x": "## Nothing here\n"})


class RvmFeedTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    async def test_refresh_replaces_rows_and_keeps_first_seen(self):
        from app.modules.vulnerability_intelligence.feeds import rvm
        files = {"NetworkEdge": RVM_EDGE, "Microsoft": RVM_MS}

        def handler(req):
            name = req.url.path.rsplit("/", 1)[-1].removesuffix(".md")
            return httpx.Response(200, text=files.get(name, "## Empty\n"))
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await rvm.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["entries"], 6)                              # distinct CVEs
        first = {r["grp"]: r["first_seen"] for r in store.rvm_for("CVE-2018-13379")}
        files["NetworkEdge"] = RVM_EDGE.replace("Conti, ", "")           # the matrix drops one pair
        res = await rvm.refresh()
        again = {r["grp"]: r["first_seen"] for r in store.rvm_for("CVE-2018-13379")}
        self.assertEqual(set(again), {"LockBit", "Ghost/Cring"})
        self.assertEqual(again["LockBit"], first["LockBit"])

    async def test_refresh_error(self):
        from app.modules.vulnerability_intelligence.feeds import rvm
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))))
        res = await rvm.refresh()
        self.assertFalse(res["ok"])
        self.assertIn("404", store.feed_status()["rvm"]["error"])


GP0_CSV = (
    '"CVE","Vendor","Product","Type","Description","Date Discovered","Date Patched","Advisory",'
    '"Analysis URL","Root Cause Analysis","Reported By"\n'
    '"CVE-2026-20805","Microsoft","Windows","Information Disclosure","DWM disclosure","???","2026-01-13",'
    '"https://msrc.example/CVE-2026-20805","???","","MSTIC"\n'
    '"CVE-2025-1111","Google","Chrome","Memory Corruption","V8 type confusion","2025-03-01","2025-03-05",'
    '"https://chrome.example/1","https://analysis.example/1","","TAG"\n'
    '"CVE-????","Acme","Thing","?","no CVE yet","???","???","","","",""\n'
)
GP0_INTRO = '"0day ""In the Wild"""\n"Last updated: 2023-04-20"\n'


class Gp0Tests(unittest.TestCase):
    def test_parse(self):
        from app.modules.vulnerability_intelligence.feeds import gp0
        rows = {r["cve_id"]: r for r in gp0.parse(GP0_CSV.encode())}
        self.assertEqual(set(rows), {"CVE-2026-20805", "CVE-2025-1111"})     # the row without a CVE is skipped
        dwm = rows["CVE-2026-20805"]
        self.assertEqual(dwm["date_added"], "2026-01-13")                    # no discovery date: the patch date
        self.assertEqual([c["url"] for c in dwm["citations"]], ["https://msrc.example/CVE-2026-20805"])
        self.assertIn("reported by MSTIC", dwm["notes"])
        self.assertEqual(rows["CVE-2025-1111"]["date_added"], "2025-03-01")  # discovery date when known
        self.assertEqual(len(rows["CVE-2025-1111"]["citations"]), 2)

    def test_intro_tab_is_not_a_year(self):
        from app.modules.vulnerability_intelligence.feeds import gp0
        self.assertIsNone(gp0.parse(GP0_INTRO.encode()))


class Gp0FeedAndViewTests(ViewTests, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    async def test_feed_loads_years_and_feeds_the_zero_day_view(self):
        from app.modules.vulnerability_intelligence import views
        from app.modules.vulnerability_intelligence.feeds import gp0
        asked = []

        def handler(req):
            year = req.url.params.get("sheet")
            asked.append(year)
            return httpx.Response(200, text=GP0_CSV if year == "2026" else GP0_INTRO)
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        res = await gp0.refresh()
        self.assertTrue(res["ok"], res)
        self.assertEqual(asked[0], "2014")
        kev = {k["source"]: k for k in store.get_kev("CVE-2026-20805")}
        self.assertEqual(kev["gp0"]["date_added"], "2026-01-13")
        # Listed by Project Zero: a zero-day even with no publication date stored.
        zero = {r["cve_id"]: r for r in views.BY_SLUG["zero-day"].rows()}
        self.assertIn("CVE-2026-20805", zero)
        self.assertEqual(zero["CVE-2026-20805"]["sources"], ["gp0"])
        self.assertEqual(views.BY_SLUG["zero-day"].count(), len(zero))
        self.assertEqual(priority.KEV_NAMES["gp0"], "Project Zero 0-day")


class RvmViewAndPageTests(ViewTests):
    def test_view_nine_and_cve_page(self):
        from fastapi.testclient import TestClient
        from app.main import app
        from app.modules.vulnerability_intelligence import views
        from app.modules.vulnerability_intelligence.feeds import rvm
        store.replace_rvm(rvm.parse({"NetworkEdge": RVM_EDGE}))
        rows = {r["cve_id"]: r for r in views.BY_SLUG["ransomware"].rows()}
        self.assertIn("CVE-2019-5591", rows)                                  # matrix only
        self.assertEqual(rows["CVE-2019-5591"]["ransomware_groups"], ["Nemesis Kitten"])
        self.assertTrue(rows["CVE-2019-5591"]["ransomware"])
        self.assertEqual(views.BY_SLUG["ransomware"].count(), len(rows))
        pri = priority.compute(kev_sources=[], ransomware=False, epss=None, cvss=None, poc_count=0,
                               watchlist_hits=[], matrix_groups=["Conti"])
        self.assertEqual(pri.level, "P1")
        self.assertTrue(any("Ransomware Vulnerability Matrix: Conti" in r for r in pri.reasons))
        import asyncio
        base.set_client(httpx.AsyncClient(transport=_transport()))       # the page's live lookups, mocked
        client = TestClient(app, base_url="http://127.0.0.1")
        page = client.get("/vulnerability-intelligence/cve/CVE-2019-5591")
        asyncio.run(base.aclose())
        self.assertEqual(page.status_code, 200)
        self.assertIn("Ransomware Vulnerability Matrix", page.text)
        self.assertIn("suspected state-sponsored", page.text)
        self.assertIn("https://www.secureworks.com/c", page.text)
