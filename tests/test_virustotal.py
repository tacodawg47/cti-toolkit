"""
Tests for the VirusTotal client's pure helpers: URL id, path building, and
the verdict heuristic. No network calls.

Run from the project root:
    .venv/Scripts/python.exe -m unittest discover -s tests -t . -v
"""

import unittest

from app.modules.enrich import virustotal as vt


def _obj(malicious=0, suspicious=0, harmless=0, undetected=0, **attrs):
    stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
    }
    return {"data": {"attributes": {"last_analysis_stats": stats, **attrs}}}


class UrlIdTests(unittest.TestCase):
    def test_unpadded_base64url(self):
        # VT v3 uses unpadded base64url of the URL.
        self.assertEqual(vt._url_id("http://example.com"), "aHR0cDovL2V4YW1wbGUuY29t")
        self.assertNotIn("=", vt._url_id("https://a.very/long/url?with=padding"))


class PathForTests(unittest.TestCase):
    def test_each_type(self):
        self.assertEqual(vt._path_for("ip", "8.8.8.8"), "/ip_addresses/8.8.8.8")
        self.assertEqual(vt._path_for("domain", "example.com"), "/domains/example.com")
        self.assertEqual(vt._path_for("hash", "abc123"), "/files/abc123")
        self.assertTrue(vt._path_for("url", "http://x.com").startswith("/urls/"))

    def test_unknown_type_raises(self):
        with self.assertRaises(ValueError):
            vt._path_for("email", "a@b.com")


class SummariseTests(unittest.TestCase):
    def test_malicious(self):
        self.assertEqual(vt._summarise(_obj(malicious=5, harmless=80))["verdict"], "malicious")

    def test_suspicious_from_one_malicious(self):
        self.assertEqual(vt._summarise(_obj(malicious=1, harmless=80))["verdict"], "suspicious")

    def test_suspicious_from_two_suspicious(self):
        self.assertEqual(vt._summarise(_obj(suspicious=2, harmless=80))["verdict"], "suspicious")

    def test_clean_when_many_engines_no_detections(self):
        self.assertEqual(vt._summarise(_obj(harmless=90))["verdict"], "clean")

    def test_unknown_when_few_engines(self):
        self.assertEqual(vt._summarise(_obj(harmless=3))["verdict"], "unknown")

    def test_unknown_on_empty(self):
        self.assertEqual(vt._summarise({})["verdict"], "unknown")

    def test_detection_ratio(self):
        self.assertEqual(vt._summarise(_obj(malicious=5, harmless=85))["ratio"], "5/90")
        self.assertIsNone(vt._summarise({})["ratio"])

    def test_summary_carries_context_fields(self):
        parsed = vt._summarise(_obj(harmless=90, as_owner="Google LLC", country="US"))
        self.assertEqual(parsed["summary"]["as_owner"], "Google LLC")
        self.assertEqual(parsed["summary"]["country"], "US")


if __name__ == "__main__":
    unittest.main()
