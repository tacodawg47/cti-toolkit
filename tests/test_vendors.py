"""
Tests for the pure helpers in the vendor clients: verdict heuristics and path
building. No network calls, no database, no API keys.

Run from the project root:
    .venv/Scripts/python.exe -m unittest discover -s tests -t . -v
"""

import shutil
import tempfile
import unittest
from pathlib import Path

import httpx
from pydantic import ValidationError

from app.core import db, indicators
from app.core.config import Settings, settings
from app.core.models import VendorResult
from app.modules.enrich import (
    abuseipdb,
    base,
    greynoise,
    malwarebazaar,
    otx,
    registry,
    shodan,
    threatfox,
    urlhaus,
    urlscan,
    virustotal,
)


class AbuseIPDBTests(unittest.TestCase):
    def test_high_score_is_malicious(self):
        self.assertEqual(abuseipdb._summarise({"abuseConfidenceScore": 90})["verdict"], "malicious")

    def test_mid_score_is_suspicious(self):
        self.assertEqual(abuseipdb._summarise({"abuseConfidenceScore": 40, "totalReports": 3})["verdict"], "suspicious")

    def test_zero_reports_is_clean(self):
        self.assertEqual(abuseipdb._summarise({"abuseConfidenceScore": 0, "totalReports": 0})["verdict"], "clean")

    def test_whitelisted_is_clean(self):
        self.assertEqual(abuseipdb._summarise({"abuseConfidenceScore": 10, "isWhitelisted": True})["verdict"], "clean")

    def test_low_score_with_reports_is_unknown(self):
        self.assertEqual(abuseipdb._summarise({"abuseConfidenceScore": 10, "totalReports": 2})["verdict"], "unknown")


class GreyNoiseTests(unittest.TestCase):
    def test_classification_maps_to_verdict(self):
        self.assertEqual(greynoise._summarise({"classification": "malicious"})["verdict"], "malicious")
        self.assertEqual(greynoise._summarise({"classification": "benign"})["verdict"], "clean")
        self.assertEqual(greynoise._summarise({"classification": "unknown"})["verdict"], "unknown")
        self.assertEqual(greynoise._summarise({})["verdict"], "unknown")


class OtxPathTests(unittest.TestCase):
    def test_ipv4_and_ipv6(self):
        self.assertEqual(otx._path("ip", "8.8.8.8"), "/IPv4/8.8.8.8/general")
        self.assertEqual(otx._path("ip", "2001:4860:4860::8888"), "/IPv6/2001:4860:4860::8888/general")

    def test_domain_hash_url(self):
        self.assertEqual(otx._path("domain", "example.com"), "/domain/example.com/general")
        self.assertEqual(otx._path("hash", "abc123"), "/file/abc123/general")
        self.assertTrue(otx._path("url", "http://x.com/a b").startswith("/url/"))
        self.assertNotIn(" ", otx._path("url", "http://x.com/a b"))  # URL-encoded

    def test_unknown_type_raises(self):
        with self.assertRaises(ValueError):
            otx._path("email", "a@b.com")


class OtxSummariseTests(unittest.TestCase):
    def test_pulse_thresholds(self):
        # Capped at suspicious: pulse count never asserts malicious on its own.
        self.assertEqual(otx._summarise({"pulse_info": {"count": 0}})["verdict"], "unknown")
        self.assertEqual(otx._summarise({"pulse_info": {"count": 3}})["verdict"], "suspicious")
        self.assertEqual(otx._summarise({"pulse_info": {"count": 25}})["verdict"], "suspicious")

    def test_empty_object(self):
        self.assertEqual(otx._summarise({})["verdict"], "unknown")

    def test_whitelisted_is_clean_despite_pulses(self):
        obj = {"pulse_info": {"count": 10}, "validation": [{"name": "Whitelisted IP"}]}
        self.assertEqual(otx._summarise(obj)["verdict"], "clean")

    def test_accepted_false_positive_is_clean(self):
        obj = {"pulse_info": {"count": 5}, "false_positive": [{"assessment": "accepted"}]}
        self.assertEqual(otx._summarise(obj)["verdict"], "clean")


class ThreatFoxTests(unittest.TestCase):
    def test_hit_is_malicious(self):
        body = {"query_status": "ok", "data": [{"malware_printable": "Cobalt Strike", "threat_type": "botnet_cc"}]}
        parsed = threatfox._summarise(body)
        self.assertEqual(parsed["verdict"], "malicious")
        self.assertEqual(parsed["summary"]["malware"], "Cobalt Strike")

    def test_no_result_is_unknown(self):
        self.assertEqual(threatfox._summarise({"query_status": "no_result"})["verdict"], "unknown")

    def test_illegal_term_is_error(self):
        self.assertEqual(threatfox._summarise({"query_status": "illegal_search_term"})["verdict"], "error")


class MalwareBazaarTests(unittest.TestCase):
    def test_hit_is_malicious(self):
        body = {"query_status": "ok", "data": [{"signature": "Emotet", "file_type": "exe"}]}
        parsed = malwarebazaar._summarise(body)
        self.assertEqual(parsed["verdict"], "malicious")
        self.assertEqual(parsed["summary"]["family"], "Emotet")

    def test_not_found_is_unknown(self):
        self.assertEqual(malwarebazaar._summarise({"query_status": "hash_not_found"})["verdict"], "unknown")

    def test_illegal_hash_is_error(self):
        self.assertEqual(malwarebazaar._summarise({"query_status": "illegal_hash"})["verdict"], "error")


class UrlhausTests(unittest.TestCase):
    def test_url_hit_is_malicious(self):
        parsed = urlhaus._summarise_url({"query_status": "ok", "threat": "malware_download", "url_status": "online"})
        self.assertEqual(parsed["verdict"], "malicious")
        self.assertEqual(parsed["summary"]["threat"], "malware_download")

    def test_url_miss_is_unknown(self):
        self.assertEqual(urlhaus._summarise_url({"query_status": "no_results"})["verdict"], "unknown")

    def test_host_hit_counts_urls(self):
        body = {"query_status": "ok", "urls": [{"url_status": "online"}, {"url_status": "offline"}]}
        parsed = urlhaus._summarise_host(body)
        self.assertEqual(parsed["verdict"], "malicious")
        self.assertEqual(parsed["summary"]["urls_total"], 2)
        self.assertEqual(parsed["summary"]["urls_online"], 1)

    def test_host_miss_is_unknown(self):
        self.assertEqual(urlhaus._summarise_host({"query_status": "no_results"})["verdict"], "unknown")

    def test_url_invalid_is_error(self):
        self.assertEqual(urlhaus._summarise_url({"query_status": "invalid_url"})["verdict"], "error")

    def test_host_invalid_is_error(self):
        self.assertEqual(urlhaus._summarise_host({"query_status": "invalid_host"})["verdict"], "error")


class ShodanTests(unittest.TestCase):
    def test_bad_tag_is_suspicious(self):
        self.assertEqual(shodan._summarise({"tags": ["malware"]})["verdict"], "suspicious")

    def test_vulns_alone_are_not_a_verdict(self):
        # CVEs are informational now, not a verdict signal (M8).
        parsed = shodan._summarise({"vulns": ["CVE-2021-1234"], "ports": [80]})
        self.assertEqual(parsed["verdict"], "unknown")
        self.assertEqual(parsed["ratio"], "1 known CVE(s)")

    def test_plain_host_is_unknown(self):
        self.assertEqual(shodan._summarise({"ports": [443], "org": "Example"})["verdict"], "unknown")


class UrlscanTests(unittest.TestCase):
    def test_query_building(self):
        self.assertEqual(urlscan._query_for("domain", "example.com"), 'domain:"example.com"')
        self.assertTrue(urlscan._query_for("url", "http://x.com").startswith("page.url:"))

    def test_results_summarised(self):
        body = {"total": 2, "results": [{"page": {"domain": "x.com", "ip": "1.1.1.1"}, "task": {"time": "t"}}]}
        parsed = urlscan._summarise(body)
        self.assertEqual(parsed["verdict"], "unknown")
        self.assertEqual(parsed["ratio"], "2 scan(s)")
        self.assertEqual(parsed["summary"]["page_domain"], "x.com")

    def test_no_results(self):
        parsed = urlscan._summarise({"total": 0, "results": []})
        self.assertIsNone(parsed["ratio"])

    def test_query_escapes_quotes(self):
        q = urlscan._query_for("url", 'http://x.com/"a')
        self.assertIn('\\"', q)


class ConfigHostTests(unittest.TestCase):
    def test_loopback_allowed(self):
        self.assertEqual(Settings(host="127.0.0.1").host, "127.0.0.1")
        self.assertEqual(Settings(host="localhost").host, "localhost")
        self.assertEqual(Settings(host="::1").host, "::1")

    def test_non_loopback_rejected(self):
        with self.assertRaises(ValidationError):
            Settings(host="0.0.0.0")


class RegistryGateTests(unittest.IsolatedAsyncioTestCase):
    async def test_private_ip_not_fanned_out(self):
        res = await registry.enrich_all("ip", "192.168.1.1")
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].source, "(local)")
        self.assertIn("private", res[0].summary["note"])

    async def test_loopback_ip_gated(self):
        res = await registry.enrich_all("ip", "127.0.0.1")
        self.assertEqual(len(res), 1)
        self.assertTrue(res[0].summary["note"].startswith("loopback"))


class IndicatorsTests(unittest.TestCase):
    def test_refang_variants(self):
        self.assertEqual(indicators.refang("hxxp://evil[.]com"), "http://evil.com")
        self.assertEqual(indicators.refang("hxxps[:]//evil[.]com"), "https://evil.com")
        self.assertEqual(indicators.refang("hXXp[://]evil[.]com"), "http://evil.com")
        self.assertEqual(indicators.refang("fxp://evil[.]com"), "ftp://evil.com")
        self.assertEqual(indicators.refang("evil[dot]com"), "evil.com")
        self.assertEqual(indicators.refang("evil(dot)com"), "evil.com")
        self.assertEqual(indicators.refang("evil dot com"), "evil.com")
        self.assertEqual(indicators.refang("<evil[.]com>"), "evil.com")

    def test_scheme_refang_does_not_rewrite_legit_values(self):
        # "fxp"/"hxxp" only count as a defanged scheme at the start of the
        # input and when a scheme separator follows (N2 in the verification).
        for s in ("fxp-trading.com", "http://example.com/fxp/report",
                  "shxxp.example.com", "hxxp.example.com", "fxp"):
            self.assertEqual(indicators.refang(s), s)

    def test_normalise_ip_port_and_trailing_dot(self):
        self.assertEqual(indicators.normalise("1.2.3.4:443"), "1.2.3.4")
        self.assertEqual(indicators.normalise("example.com."), "example.com")
        self.assertEqual(indicators.normalise("8.8.8.8"), "8.8.8.8")

    def test_canonical_lowercases_hash_and_domain_not_url(self):
        self.assertEqual(indicators.canonical("hash", "ABCdef"), "abcdef")
        self.assertEqual(indicators.canonical("domain", "Example.COM"), "example.com")
        self.assertEqual(indicators.canonical("url", "http://X.com/AbC"), "http://X.com/AbC")

    def test_numeric_label_is_not_a_domain(self):
        self.assertEqual(indicators.detect_type("1.2.3"), "unknown")
        self.assertEqual(indicators.detect_type("example.com"), "domain")

    def test_detect_basic_types(self):
        self.assertEqual(indicators.detect_type("8.8.8.8"), "ip")
        self.assertEqual(indicators.detect_type("a" * 64), "hash")
        self.assertEqual(indicators.detect_type("http://x.com"), "url")


class VirustotalDenominatorTests(unittest.TestCase):
    def test_denominator_excludes_non_engine_stats(self):
        obj = {"data": {"attributes": {"last_analysis_stats": {
            "harmless": 60, "malicious": 0, "suspicious": 0, "undetected": 10,
            "timeout": 5, "type-unsupported": 20, "failure": 3}}}}
        parsed = virustotal._summarise(obj)
        self.assertEqual(parsed["ratio"], "0/70")      # 60 + 0 + 0 + 10 only
        self.assertEqual(parsed["verdict"], "clean")


class RegistryCrashTests(unittest.IsolatedAsyncioTestCase):
    """A client that raises must become an error card, not an 'ok' result."""

    class _Boom:
        VENDOR = "boom"

        @staticmethod
        async def lookup(itype, value):
            raise RuntimeError("simulated crash")

    class _Fine:
        VENDOR = "fine"

        @staticmethod
        async def lookup(itype, value):
            return VendorResult(source="fine", indicator=value, indicator_type=itype,
                                verdict="clean")

    def setUp(self):
        self._orig = dict(registry.VENDORS_BY_TYPE)
        registry.VENDORS_BY_TYPE["hash"] = [self._Boom, self._Fine]

    def tearDown(self):
        registry.VENDORS_BY_TYPE.clear()
        registry.VENDORS_BY_TYPE.update(self._orig)

    async def test_crash_is_error_status_and_others_survive(self):
        res = await registry.enrich_all("hash", "a" * 64)
        self.assertEqual([r.source for r in res], ["boom", "fine"])
        self.assertEqual(res[0].status, "error")
        self.assertEqual(res[0].verdict, "error")
        self.assertIn("RuntimeError", res[0].error)
        self.assertEqual(res[1].verdict, "clean")

    async def test_crash_never_reaches_aggregate(self):
        res = await registry.enrich_all("hash", "a" * 64)
        agg = registry.aggregate_verdict(res)
        self.assertEqual(agg, {"verdict": "clean", "sources": ["fine"]})


class AllowedHostsTests(unittest.TestCase):
    def test_ipv6_loopback_is_bracketed_and_allowed(self):
        from app.main import _allowed_hosts
        self.assertIn("[::1]", _allowed_hosts("127.0.0.1"))
        self.assertIn("[::1]", _allowed_hosts("::1"))
        self.assertIn("localhost", _allowed_hosts("localhost"))
        # No duplicates when the configured host is already a default.
        self.assertEqual(len(_allowed_hosts("::1")), 3)


class AggregateTests(unittest.TestCase):
    @staticmethod
    def _r(source, verdict, status="ok"):
        return VendorResult(source=source, indicator="x", indicator_type="ip",
                            verdict=verdict, status=status)

    def test_error_verdict_with_ok_status_is_ignored(self):
        # Second guard (N1): even a mislabelled result never becomes "Overall: ERROR".
        agg = registry.aggregate_verdict([self._r("x", "error"), self._r("vt", "unknown")])
        self.assertEqual(agg, {"verdict": "unknown", "sources": ["vt"]})

    def test_worst_of_names_its_sources(self):
        agg = registry.aggregate_verdict([
            self._r("vt", "malicious"),
            self._r("otx", "suspicious"),
            self._r("ab", "unknown"),
            self._r("gn", "clean", status="error"),     # ignored (not ok)
        ])
        self.assertEqual(agg["verdict"], "malicious")
        self.assertEqual(agg["sources"], ["vt"])

    def test_none_when_nobody_answered(self):
        self.assertIsNone(registry.aggregate_verdict([
            self._r("vt", "unknown", status="error"),
            self._r("otx", "unknown", status="not_configured"),
        ]))


class FetchJsonTests(unittest.IsolatedAsyncioTestCase):
    def _install(self, handler):
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    async def asyncTearDown(self):
        await base.aclose()

    async def test_200_json(self):
        self._install(lambda req: httpx.Response(200, json={"ok": True}))
        self.assertEqual(await base.fetch_json("GET", "https://x/"), (200, {"ok": True}, None))

    async def test_non_200_passes_code_through(self):
        self._install(lambda req: httpx.Response(404, json={}))
        status, body, err = await base.fetch_json("GET", "https://x/")
        self.assertEqual((status, body, err), (404, None, None))

    async def test_200_non_json_is_clear_error(self):
        self._install(lambda req: httpx.Response(200, text="<html>maintenance</html>"))
        status, body, err = await base.fetch_json("GET", "https://x/")
        self.assertEqual(status, 200)
        self.assertIsNone(body)
        self.assertIn("non-JSON", err)

    async def test_transport_error_is_typed(self):
        def boom(req):
            raise httpx.ConnectError("down")
        self._install(boom)
        status, body, err = await base.fetch_json("GET", "https://x/")
        self.assertIsNone(status)
        self.assertTrue(err.startswith("request failed:"))


class AbuseIPDBBranchTests(unittest.IsolatedAsyncioTestCase):
    """End-to-end client paths (get_json + status + cache round-trip), offline."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = settings.data_dir
        self._orig_key = settings.abuseipdb_api_key
        settings.data_dir = Path(self._tmp)
        settings.abuseipdb_api_key = "test-key"
        db.init_db()

    async def asyncTearDown(self):
        await base.aclose()
        settings.data_dir = self._orig_dir
        settings.abuseipdb_api_key = self._orig_key
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _install(self, handler):
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    async def test_401_sets_error_status(self):
        self._install(lambda req: httpx.Response(401, json={}))
        res = await abuseipdb.lookup("ip", "8.8.8.8")
        self.assertEqual(res.status, "error")
        self.assertIn("401", res.error)

    async def test_200_success_then_cache_hit(self):
        self._install(lambda req: httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 90, "totalReports": 5}}))
        res = await abuseipdb.lookup("ip", "9.9.9.9")
        self.assertEqual(res.status, "ok")
        self.assertEqual(res.verdict, "malicious")
        self.assertFalse(res.cached)
        res2 = await abuseipdb.lookup("ip", "9.9.9.9")
        self.assertTrue(res2.cached)

    async def test_non_json_body_is_clear_error(self):
        self._install(lambda req: httpx.Response(200, text="<html>nope</html>"))
        res = await abuseipdb.lookup("ip", "1.1.1.1")
        self.assertEqual(res.status, "error")
        self.assertIn("non-JSON", res.error)


class UrlhausBranchTests(unittest.IsolatedAsyncioTestCase):
    """invalid_url from URLhaus must surface as status 'error' with its message."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = settings.data_dir
        self._orig_key = settings.abusech_auth_key
        settings.data_dir = Path(self._tmp)
        settings.abusech_auth_key = "test-key"
        db.init_db()

    async def asyncTearDown(self):
        await base.aclose()
        settings.data_dir = self._orig_dir
        settings.abusech_auth_key = self._orig_key
        shutil.rmtree(self._tmp, ignore_errors=True)

    async def test_invalid_url_is_error_status_and_not_cached(self):
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(
            lambda req: httpx.Response(200, json={"query_status": "invalid_url"}))))
        res = await urlhaus.lookup("url", "http://x.com/")
        self.assertEqual(res.status, "error")
        self.assertEqual(res.verdict, "error")
        self.assertIn("invalid_url", res.error)
        self.assertFalse(res.cached)
        res2 = await urlhaus.lookup("url", "http://x.com/")
        self.assertFalse(res2.cached)       # errors are never cached


class UrlhausPayloadTests(unittest.TestCase):
    def test_md5_and_sha256_route_to_payload(self):
        self.assertIsNotNone(urlhaus._request_for("hash", "a" * 32))
        self.assertIsNotNone(urlhaus._request_for("hash", "a" * 64))

    def test_sha1_is_unsupported(self):
        self.assertIsNone(urlhaus._request_for("hash", "a" * 40))

    def test_payload_hit_is_malicious(self):
        parsed = urlhaus._summarise_payload({"query_status": "ok", "signature": "Emotet", "url_count": 3})
        self.assertEqual(parsed["verdict"], "malicious")


if __name__ == "__main__":
    unittest.main()
