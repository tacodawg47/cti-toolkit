"""
Tests for the pure helpers in the vendor clients: verdict heuristics and path
building. No network calls, no database, no API keys.

Run from the project root:
    .venv/Scripts/python.exe -m unittest discover -s tests -t . -v
"""

import asyncio
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import httpx
from pydantic import ValidationError

from app.core import allowlist as allowlist_mod
from app.core import db, indicators, ratelimit
from app.core.config import Settings, settings
from app.core.models import VendorResult
from app.modules.enrich import (
    abuseipdb,
    base,
    crtsh,
    greynoise,
    hashlookup,
    internetdb,
    malwarebazaar,
    otx,
    rdap,
    registry,
    shodan,
    threatfox,
    urlhaus,
    urlscan,
    virustotal,
    yaraify,
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


class HashlookupTests(unittest.TestCase):
    def test_known_file_is_clean(self):
        body = {"FileName": "notepad.exe", "source": "NSRL", "hashlookup:trust": 80}
        parsed = hashlookup._summarise(body)
        self.assertEqual(parsed["verdict"], "clean")
        self.assertEqual(parsed["summary"]["file_name"], "notepad.exe")
        self.assertEqual(parsed["ratio"], "trust 80/100")

    def test_no_trust_field_is_unknown_not_clean(self):
        # L2: no score means no quality signal, so it must not gate the fan-out.
        parsed = hashlookup._summarise({"FileName": "x"})
        self.assertEqual(parsed["verdict"], "unknown")
        self.assertIn("no trust score", parsed["summary"]["note"])

    def test_non_numeric_trust_is_unknown(self):
        self.assertEqual(hashlookup._summarise({"hashlookup:trust": "high"})["verdict"], "unknown")

    def test_low_trust_is_unknown(self):
        self.assertEqual(hashlookup._summarise({"hashlookup:trust": 10})["verdict"], "unknown")

    def test_known_malicious_flag_wins(self):
        body = {"hashlookup:trust": 90, "KnownMalicious": "some-source"}
        self.assertEqual(hashlookup._summarise(body)["verdict"], "malicious")


class InternetDBTests(unittest.TestCase):
    def test_bad_tag_is_suspicious(self):
        self.assertEqual(internetdb._summarise({"tags": ["c2"]})["verdict"], "suspicious")

    def test_ports_and_vulns_are_informational(self):
        parsed = internetdb._summarise({"ports": [22, 443], "vulns": ["CVE-2024-1"], "tags": ["cloud"]})
        self.assertEqual(parsed["verdict"], "unknown")
        self.assertEqual(parsed["ratio"], "1 known CVE(s)")
        self.assertEqual(parsed["summary"]["ports"], [22, 443])


class RdapTests(unittest.TestCase):
    NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)

    @staticmethod
    def _domain(registered: str) -> dict:
        return {
            "events": [
                {"eventAction": "registration", "eventDate": registered},
                {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
            ],
            "status": ["client transfer prohibited"],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}, {"ldhName": "NS2.EXAMPLE.NET"}],
            "entities": [{
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                         ["fn", {}, "text", "Example Registrar, Inc."]]],
            }],
        }

    def test_new_domain_is_suspicious(self):
        parsed = rdap._summarise_domain(self._domain("2026-10-28T12:00:00Z"), now=self.NOW)
        self.assertEqual(parsed["verdict"], "suspicious")
        self.assertEqual(parsed["summary"]["age_days"], 4)
        self.assertEqual(parsed["ratio"], "registered 4 day(s) ago")

    def test_old_domain_is_unknown_with_details(self):
        parsed = rdap._summarise_domain(self._domain("1995-08-14T04:00:00Z"), now=self.NOW)
        self.assertEqual(parsed["verdict"], "unknown")
        self.assertEqual(parsed["summary"]["registrar"], "Example Registrar, Inc.")
        self.assertEqual(parsed["summary"]["nameservers"], ["NS1.EXAMPLE.NET", "NS2.EXAMPLE.NET"])
        self.assertEqual(parsed["summary"]["expires"], "2027-01-01T00:00:00Z")

    def test_missing_events_is_unknown(self):
        parsed = rdap._summarise_domain({}, now=self.NOW)
        self.assertEqual(parsed["verdict"], "unknown")
        self.assertIsNone(parsed["summary"]["age_days"])

    def test_ip_abuse_contact_found_when_nested(self):
        body = {
            "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "name": "GOGL",
            "handle": "NET-8-8-8-0-1", "type": "DIRECT ALLOCATION", "country": "US",
            "port43": "whois.arin.net",
            "entities": [{
                "roles": ["registrant"],
                "entities": [{
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"],
                                             ["email", {}, "text", "abuse@example.net"]]],
                }],
            }],
        }
        parsed = rdap._summarise_ip(body)
        self.assertEqual(parsed["verdict"], "unknown")
        self.assertEqual(parsed["summary"]["abuse_contact"], "abuse@example.net")
        self.assertEqual(parsed["summary"]["netblock"], "8.8.8.0 - 8.8.8.255")
        self.assertEqual(parsed["summary"]["registry"], "whois.arin.net")


class YaraifyTests(unittest.TestCase):
    @staticmethod
    def _hit(clamav=(), static=(), unpacked=()):
        return {"query_status": "ok", "data": {
            "metadata": {"file_size": 1234, "file_type_mime": "application/x-dosexec",
                         "first_seen": "2026-01-01", "sightings": 3, "sha256_hash": "ab"},
            "tasks": [{
                "file_name": "dropper.exe",
                "clamav_results": list(clamav),
                "static_results": [{"rule_name": r} for r in static],
                "unpack_results": [{"unpacked_yara_matches": [{"rule_name": r} for r in unpacked]}],
            }],
        }}

    def test_clamav_hit_is_malicious(self):
        parsed = yaraify._summarise(self._hit(clamav=["Win.Trojan.Agent-123"], static=["x"]))
        self.assertEqual(parsed["verdict"], "malicious")
        self.assertEqual(parsed["summary"]["clamav"], ["Win.Trojan.Agent-123"])
        self.assertEqual(parsed["summary"]["file_name"], "dropper.exe")
        self.assertEqual(parsed["ratio"], "1 AV / 1 YARA match(es)")

    def test_yara_only_is_suspicious_and_includes_unpacked_matches(self):
        parsed = yaraify._summarise(self._hit(static=["pe_overlay"], unpacked=["cobalt_strike"]))
        self.assertEqual(parsed["verdict"], "suspicious")
        self.assertEqual(parsed["summary"]["yara_rules"], ["cobalt_strike", "pe_overlay"])

    def test_scanned_with_no_matches_is_unknown(self):
        self.assertEqual(yaraify._summarise(self._hit())["verdict"], "unknown")

    def test_no_results_is_unknown_and_illegal_is_error(self):
        self.assertEqual(yaraify._summarise({"query_status": "no_results"})["verdict"], "unknown")
        self.assertEqual(yaraify._summarise({"query_status": "illegal_hash"})["verdict"], "error")
        self.assertEqual(yaraify._summarise({})["verdict"], "error")

    def test_data_of_wrong_shape_is_error_not_crash(self):
        self.assertEqual(yaraify._summarise({"query_status": "ok", "data": [1]})["verdict"], "error")


class CrtshTests(unittest.TestCase):
    ROWS = [
        {"issuer_name": "C=US, O=Let's Encrypt, CN=R11", "name_value": "example.com\nwww.example.com",
         "not_before": "2026-09-01T00:00:00", "not_after": "2026-12-01T00:00:00"},
        {"issuer_name": "C=US, O=Let's Encrypt, CN=R11", "name_value": "mail.example.com",
         "not_before": "2026-10-15T00:00:00", "not_after": "2027-01-15T00:00:00"},
        {"issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
         "name_value": "WWW.EXAMPLE.COM", "not_before": "2025-03-01T00:00:00"},
    ]

    def test_names_issuers_and_dates(self):
        parsed = crtsh._summarise(self.ROWS)
        self.assertEqual(parsed["verdict"], "unknown")
        self.assertEqual(parsed["ratio"], "3 cert(s)")
        s = parsed["summary"]
        self.assertEqual(s["names"], ["example.com", "www.example.com", "mail.example.com"])
        self.assertEqual(s["names_total"], 3)
        self.assertEqual(len(s["issuers"]), 2)
        self.assertEqual(s["oldest_not_before"], "2025-03-01T00:00:00")
        self.assertEqual(s["newest_not_before"], "2026-10-15T00:00:00")

    def test_empty_list_is_unknown_with_note(self):
        parsed = crtsh._summarise([])
        self.assertIsNone(parsed["ratio"])
        self.assertIn("no unexpired certificates", parsed["summary"]["note"])

    def test_params_request_json_without_expired(self):
        p = crtsh._params("example.com")
        self.assertEqual(p["q"], "example.com")
        self.assertEqual(p["output"], "json")
        self.assertEqual(p["exclude"], "expired")


class AllowlistTests(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.csv = self._tmp / "tranco.csv"
        self.csv.write_text("1,google.com\n2,youtube.com\n3,github.io\n4,example.com\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_load_respects_top_n_and_matches_exact_or_www(self):
        al = allowlist_mod.Allowlist()
        self.assertEqual(al.load(self.csv, top_n=3), 3)
        self.assertTrue(al.loaded)
        self.assertEqual(al.rank("google.com"), 1)
        self.assertEqual(al.rank("WWW.Google.com."), 1)
        self.assertIsNone(al.rank("example.com"))          # row 4, beyond top_n

    def test_subdomains_of_popular_hosts_are_not_allowlisted(self):
        al = allowlist_mod.Allowlist()
        al.load(self.csv, top_n=10)
        self.assertEqual(al.rank("github.io"), 3)
        self.assertIsNone(al.rank("evil.github.io"))
        self.assertIsNone(al.rank("accounts.google.com"))

    def test_missing_file_means_gate_off(self):
        al = allowlist_mod.Allowlist()
        self.assertEqual(al.load(self._tmp / "nope.csv", top_n=10), 0)
        self.assertFalse(al.loaded)
        self.assertIsNone(al.rank("google.com"))
        self.assertFalse(al.status()["loaded"])
        self.assertIsNone(al.status()["error"])

    def test_unreadable_file_does_not_raise(self):
        # L3: load() runs at startup, so a bad file must report, not crash.
        bad = self._tmp / "bad.csv"
        bad.write_bytes(b"1,caf\xe9.com\n")          # Latin-1 byte, not UTF-8
        al = allowlist_mod.Allowlist()
        self.assertEqual(al.load(bad, top_n=10), 0)
        self.assertFalse(al.loaded)
        self.assertIn("UnicodeDecodeError", al.status()["error"])


class RegistryTrancoGateTests(unittest.IsolatedAsyncioTestCase):
    class _Fine:
        VENDOR = "fine"

        @staticmethod
        async def lookup(itype, value):
            return VendorResult(source="fine", indicator=value, indicator_type=itype,
                                verdict="clean")

    def setUp(self):
        self._orig = dict(registry.VENDORS_BY_TYPE)
        registry.VENDORS_BY_TYPE["domain"] = [self._Fine]
        registry.VENDORS_BY_TYPE["url"] = [self._Fine]
        self._tmp = Path(tempfile.mkdtemp())
        csv_path = self._tmp / "tranco.csv"
        csv_path.write_text("1,google.com\n", encoding="utf-8")
        allowlist_mod.allowlist.load(csv_path, top_n=10)

    def tearDown(self):
        registry.VENDORS_BY_TYPE.clear()
        registry.VENDORS_BY_TYPE.update(self._orig)
        allowlist_mod.allowlist.load(self._tmp / "nope.csv", top_n=10)   # unload
        shutil.rmtree(self._tmp, ignore_errors=True)

    async def test_popular_domain_is_gated(self):
        res = await registry.enrich_all("domain", "google.com")
        self.assertEqual([r.source for r in res], [registry.LOCAL_SOURCE])
        self.assertIn("#1", res[0].summary["note"])
        self.assertIsNone(registry.aggregate_verdict(res))

    async def test_url_on_popular_host_is_gated_but_subdomain_is_not(self):
        res = await registry.enrich_all("url", "https://www.google.com/search?q=x")
        self.assertEqual([r.source for r in res], [registry.LOCAL_SOURCE])
        res = await registry.enrich_all("url", "https://sites.google.com/view/phish")
        self.assertEqual([r.source for r in res], ["fine"])

    async def test_force_bypasses_the_gate(self):
        res = await registry.enrich_all("domain", "google.com", force=True)
        self.assertEqual([r.source for r in res], ["fine"])

    async def test_unpopular_domain_runs_normally(self):
        res = await registry.enrich_all("domain", "evil.test")
        self.assertEqual([r.source for r in res], ["fine"])


class RegistryHashGateTests(unittest.IsolatedAsyncioTestCase):
    """A CIRCL hashlookup hit must stop the fan-out; a miss must not."""

    class _Fine:
        VENDOR = "fine"

        @staticmethod
        async def lookup(itype, value):
            return VendorResult(source="fine", indicator=value, indicator_type=itype,
                                verdict="clean")

    def setUp(self):
        self._orig = dict(registry.VENDORS_BY_TYPE)
        registry.VENDORS_BY_TYPE["hash"] = [self._Fine]

    def tearDown(self):
        registry.VENDORS_BY_TYPE.clear()
        registry.VENDORS_BY_TYPE.update(self._orig)

    @staticmethod
    def _gate(verdict, status="ok"):
        async def fake(itype, value):
            return VendorResult(source="hashlookup", indicator=value, indicator_type=itype,
                                verdict=verdict, status=status)
        return fake

    async def test_known_good_skips_other_vendors(self):
        with patch.object(hashlookup, "lookup", self._gate("clean")):
            res = await registry.enrich_all("hash", "a" * 64)
        self.assertEqual([r.source for r in res], ["hashlookup", registry.LOCAL_SOURCE])
        self.assertIn("skipped", res[1].summary["note"])
        self.assertEqual(registry.aggregate_verdict(res), {"verdict": "clean", "sources": ["hashlookup"]})

    async def test_miss_runs_fan_out_with_gate_card_first(self):
        with patch.object(hashlookup, "lookup", self._gate("unknown")):
            res = await registry.enrich_all("hash", "a" * 64)
        self.assertEqual([r.source for r in res], ["hashlookup", "fine"])

    async def test_gate_error_does_not_skip_fan_out(self):
        with patch.object(hashlookup, "lookup", self._gate("error", status="error")):
            res = await registry.enrich_all("hash", "a" * 64)
        self.assertEqual([r.source for r in res], ["hashlookup", "fine"])

    async def test_force_runs_fan_out_even_for_known_good(self):
        with patch.object(hashlookup, "lookup", self._gate("clean")):
            res = await registry.enrich_all("hash", "a" * 64, force=True)
        self.assertEqual([r.source for r in res], ["hashlookup", "fine"])


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

    async def test_gate_card_is_not_aggregated(self):
        # The "(local)" card is information, not a vendor verdict, so there is
        # no "Overall: UNKNOWN (worst of (local))" line.
        res = await registry.enrich_all("ip", "10.0.0.1")
        self.assertIsNone(registry.aggregate_verdict(res))


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

    def test_normalise_domain_port_and_bracketed_ipv6(self):
        self.assertEqual(indicators.normalise("evil.com:8443"), "evil.com")
        self.assertEqual(indicators.normalise("c2.evil[.]com[:]4444"), "c2.evil.com")
        self.assertEqual(indicators.normalise("[2001:db8::1]:443"), "2001:db8::1")
        self.assertEqual(indicators.detect_type(indicators.normalise("evil.com:8443")), "domain")

    def test_idn_and_homograph_hosts_become_punycode(self):
        # M1: analysts paste the Unicode form; DNS and every vendor need ASCII.
        self.assertEqual(indicators.normalise("münchen.de"), "xn--mnchen-3ya.de")
        homograph = indicators.normalise("gооgle.com")     # Cyrillic o's
        self.assertTrue(homograph.startswith("xn--"))
        self.assertEqual(indicators.detect_type(homograph), "domain")
        self.assertEqual(indicators.normalise("https://münchen.de:8443/pfad?q=ü"),
                         "https://xn--mnchen-3ya.de:8443/pfad?q=ü")
        self.assertEqual(indicators.normalise("münchen[.]de"), "xn--mnchen-3ya.de")

    def test_ascii_and_already_punycode_unchanged(self):
        self.assertEqual(indicators.normalise("xn--mnchen-3ya.de"), "xn--mnchen-3ya.de")
        self.assertEqual(indicators.normalise("example.com"), "example.com")
        self.assertEqual(indicators.normalise("https://user@example.com/x"), "https://user@example.com/x")

    def test_normalise_leaves_non_host_port_alone(self):
        # Plain IPv6 has colons but is not host:port.
        self.assertEqual(indicators.normalise("2001:db8::1"), "2001:db8::1")
        # URLs keep their port.
        self.assertEqual(indicators.normalise("http://evil.com:8080/x"), "http://evil.com:8080/x")
        # Out-of-range or non-numeric "port" is not a port.
        self.assertEqual(indicators.normalise("evil.com:99999"), "evil.com:99999")
        self.assertEqual(indicators.normalise("evil.com:abc"), "evil.com:abc")

    def test_canonical_lowercases_hash_and_domain_not_url(self):
        self.assertEqual(indicators.canonical("hash", "ABCdef"), "abcdef")
        self.assertEqual(indicators.canonical("domain", "Example.COM"), "example.com")
        self.assertEqual(indicators.canonical("url", "http://X.com/AbC"), "http://X.com/AbC")

    def test_canonical_compresses_ipv6_and_keeps_ipv4(self):
        for spelling in ("2001:DB8::1", "2001:db8:0::1", "2001:0db8:0000:0000:0000:0000:0000:0001"):
            self.assertEqual(indicators.canonical("ip", spelling), "2001:db8::1")
        self.assertEqual(indicators.canonical("ip", "8.8.8.8"), "8.8.8.8")

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

    # "url" type: no gate runs before the fan-out, so only the fakes are called.
    def setUp(self):
        self._orig = dict(registry.VENDORS_BY_TYPE)
        registry.VENDORS_BY_TYPE["url"] = [self._Boom, self._Fine]

    def tearDown(self):
        registry.VENDORS_BY_TYPE.clear()
        registry.VENDORS_BY_TYPE.update(self._orig)

    async def test_crash_is_error_status_and_others_survive(self):
        res = await registry.enrich_all("url", "http://x.test/")
        self.assertEqual([r.source for r in res], ["boom", "fine"])
        self.assertEqual(res[0].status, "error")
        self.assertEqual(res[0].verdict, "error")
        self.assertIn("RuntimeError", res[0].error)
        self.assertEqual(res[1].verdict, "clean")

    async def test_crash_never_reaches_aggregate(self):
        res = await registry.enrich_all("url", "http://x.test/")
        agg = registry.aggregate_verdict(res)
        self.assertEqual(agg, {"verdict": "clean", "sources": ["fine"]})


class DisplayPathTests(unittest.TestCase):
    def test_paths_inside_project_are_relative(self):
        # L5: the health page must not show the user's home directory.
        from app.core.config import PROJECT_ROOT
        from app.main import _display_path
        self.assertEqual(_display_path(PROJECT_ROOT / "data" / "tranco.csv"), str(Path("data") / "tranco.csv"))
        self.assertEqual(_display_path(None), "—")
        outside = Path(tempfile.gettempdir()) / "elsewhere"
        self.assertEqual(_display_path(outside), str(outside))


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

    async def test_200_non_object_json_is_clear_error(self):
        # A JSON list/string/number would crash the caller's `.get()`.
        for payload in ([1, 2], "text", 42):
            self._install(lambda req, p=payload: httpx.Response(200, json=p))
            status, body, err = await base.fetch_json("GET", "https://x/")
            self.assertEqual(status, 200)
            self.assertIsNone(body)
            self.assertIn("unexpected JSON", err)

    async def test_oversized_body_is_abandoned(self):
        # M2: stop reading past the cap instead of loading it all into memory.
        big = b"[" + b"1," * (base.MAX_BODY_BYTES // 2) + b"1]"
        self._install(lambda req: httpx.Response(200, content=big,
                                                 headers={"content-type": "application/json"}))
        status, body, err = await base.fetch_json("GET", "https://x/", expect="list")
        self.assertEqual(status, 200)
        self.assertIsNone(body)
        self.assertIn("too large", err)

    async def test_total_timeout_caps_a_slow_trickle(self):
        # M2: httpx's timeout is per read; a slow stream must still end.
        async def slow(req):
            await asyncio.sleep(0.5)
            return httpx.Response(200, json={})
        self._install(slow)
        with patch.object(base, "TOTAL_TIMEOUT", 0.05):
            status, body, err = await base.fetch_json("GET", "https://x/")
        self.assertIsNone(status)
        self.assertIn("total time", err)

    async def test_non_https_final_url_is_refused(self):
        # L1: a redirect must never downgrade the indicator to cleartext.
        def handler(req):
            if req.url.scheme == "https":
                return httpx.Response(302, headers={"location": "http://registry/record"})
            return httpx.Response(200, json={"leaked": True})
        self._install(handler)
        status, body, err = await base.fetch_json("GET", "https://bootstrap/x", follow_redirects=True)
        self.assertIsNone(body)
        self.assertIn("not HTTPS", err)
        status, body, err = await base.fetch_json("GET", "http://plain/x")
        self.assertIn("not HTTPS", err)

    async def test_expect_list_accepts_arrays_and_rejects_objects(self):
        self._install(lambda req: httpx.Response(200, json=[{"a": 1}]))
        status, body, err = await base.fetch_json("GET", "https://x/", expect="list")
        self.assertEqual((status, body, err), (200, [{"a": 1}], None))
        self._install(lambda req: httpx.Response(200, json={"a": 1}))
        status, body, err = await base.fetch_json("GET", "https://x/", expect="list")
        self.assertIsNone(body)
        self.assertIn("not a JSON list", err)

    async def test_redirects_followed_only_when_asked(self):
        def handler(req):
            if req.url.host == "bootstrap":
                return httpx.Response(302, headers={"location": "https://registry/record"})
            return httpx.Response(200, json={"from": "registry"})
        self._install(handler)
        status, body, _ = await base.fetch_json("GET", "https://bootstrap/x", follow_redirects=True)
        self.assertEqual((status, body), (200, {"from": "registry"}))
        status, body, _ = await base.fetch_json("GET", "https://bootstrap/x")
        self.assertEqual((status, body), (302, None))

    async def test_invalid_url_is_typed_error_not_crash(self):
        # httpx.InvalidURL is not an HTTPError; a NUL byte in the URL raises it.
        self._install(lambda req: httpx.Response(200, json={}))
        status, body, err = await base.fetch_json("GET", "http://x\x00y/")
        self.assertIsNone(status)
        self.assertEqual(err, "request failed: InvalidURL")


class RateLimiterLoopTests(unittest.IsolatedAsyncioTestCase):
    """The per-minute window waits in a loop and re-prunes after each sleep.

    Uses a fake clock and a fake sleep so the test takes no real time. The
    first fake sleep returns 1 ms early, which is the case that let one extra
    call through before the loop existed (M3).
    """

    VENDOR = "_test_rpm2"

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_dir = settings.data_dir
        settings.data_dir = Path(self._tmp)
        db.init_db()
        ratelimit.LIMITS[self.VENDOR] = {"rpm": 2}

    def tearDown(self):
        del ratelimit.LIMITS[self.VENDOR]
        settings.data_dir = self._orig_dir
        shutil.rmtree(self._tmp, ignore_errors=True)

    async def test_third_call_waits_and_reprunes(self):
        clock = [1000.0]
        sleeps: list[float] = []

        async def fake_sleep(seconds):
            sleeps.append(seconds)
            # First wake-up is a hair early; later ones are exact.
            clock[0] += seconds - 0.001 if len(sleeps) == 1 else seconds

        rl = ratelimit.RateLimiter()
        with patch.object(ratelimit.time, "monotonic", lambda: clock[0]), \
             patch.object(ratelimit.asyncio, "sleep", fake_sleep):
            await rl.acquire(self.VENDOR)          # t=1000
            clock[0] += 1
            await rl.acquire(self.VENDOR)          # t=1001, window full
            self.assertEqual(sleeps, [])
            await rl.acquire(self.VENDOR)          # must wait for t>=1060

        # Slept ~59 s, woke 1 ms early with the window still full, slept the
        # 50 ms floor, then got the slot. Never more than rpm entries.
        self.assertEqual(len(sleeps), 2)
        self.assertAlmostEqual(sleeps[0], 59.0)
        self.assertEqual(sleeps[1], 0.05)
        self.assertEqual(len(rl._minute[self.VENDOR]), 2)
        self.assertEqual(rl.usage(self.VENDOR)["day"], 3)


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
