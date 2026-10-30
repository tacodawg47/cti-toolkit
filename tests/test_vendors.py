"""
Tests for the pure helpers in the vendor clients: verdict heuristics and path
building. No network calls, no database, no API keys.

Run from the project root:
    .venv/Scripts/python.exe -m unittest discover -s tests -t . -v
"""

import unittest

from pydantic import ValidationError

from app.core.config import Settings
from app.modules.enrich import (
    abuseipdb,
    greynoise,
    malwarebazaar,
    otx,
    registry,
    shodan,
    threatfox,
    urlhaus,
    urlscan,
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


if __name__ == "__main__":
    unittest.main()
