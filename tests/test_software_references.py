"""Synthetic report extension IDs and isolated manual CVE refresh controls."""

import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app
from app.modules.extract import content, extractor, html, software
from app.modules.vulnerability_intelligence import feeds
from app.modules.vulnerability_intelligence.feeds import cvelist
from tests.test_vulnintel import TempDbMixin

CHROME = "abcd" * 8  # Also valid hex: must not become an MD5 in report mode.


class SoftwareReferenceTests(unittest.TestCase):
    def test_explicit_labels_keep_namespaces_and_avoid_ioc_misclassification(self):
        text = (f"Chrome Extension ID: {CHROME}\n"
                "VS Code Extension ID: example.publisher-tool\n"
                "Firefox Add-on ID: addon@example.test\n"
                "Firefox Extension ID: {12345678-1234-1234-1234-123456789abc}\n"
                "Firefox Addon ID: @example-addon\n"
                "C2: evil[.]example")
        result = extractor.extract(text, report_mode=True)
        self.assertEqual(len(result.extensions), 5)
        self.assertEqual([i.type for i in result.items], ["domain"])
        self.assertEqual(result.items[0].value, "evil.example")
        self.assertIn("Chrome Extension ID:", result.extensions[0]["context"])
        self.assertIsNone(result.extensions[2]["listing"])
        self.assertIn(CHROME, [i.value for i in extractor.extract(CHROME).by_type("hash")])
        self.assertEqual(extractor.extract(f"Chrome Extension ID:\n{CHROME}", report_mode=True).extensions[0]["identifier"], CHROME)
        self.assertFalse(extractor.extract("Firefox Add-on ID: " + "a" * 70 + "@" + "b" * 30, report_mode=True).extensions)

    def test_store_urls_local_chrome_uri_and_hidden_link_targets(self):
        text = (f"Reported campaign extension: https://chromewebstore.google.com/detail/sample/{CHROME}?token=SECRET#fragment\n"
                f"https://chrome.google.com/webstore/detail/{CHROME}\n"
                f"chrome-extension://{CHROME}/script.js\n"
                "https://marketplace.visualstudio.com/items?itemName=example.tool&tracking=1")
        result = extractor.extract(text, report_mode=True)
        self.assertEqual(len(result.extensions), 2)
        self.assertEqual(result.extensions[0]["count"], 3)
        self.assertFalse(result.items)
        self.assertNotIn("SECRET", str(result.extensions))
        self.assertIn("Reported campaign extension:", result.extensions[0]["context"])
        doc = html.parse_document(f'<p>Research</p><a href="https://chromewebstore.google.com/detail/{CHROME}">Reported extension</a>')
        content.prepare_text(doc)
        linked = extractor.extract(doc.indicator_text, report_mode=True, report_references=doc.references)
        self.assertEqual(linked.extensions[0]["identifier"], CHROME)
        self.assertEqual(linked.extensions[0]["context"], "Reported extension")

    def test_unqualified_strings_runtime_ids_and_spoofed_stores_are_not_classified(self):
        text = (f"{CHROME}\nrequest.getparameter\nexample.tool\n"
                "https://addons.mozilla.org/firefox/addon/example-slug/\n"
                "moz-extension://12345678-1234-1234-1234-123456789abc/page.html\n"
                f"https://chromewebstore.google.com.attacker.example/detail/{CHROME}\n"
                f"https://user@chromewebstore.google.com/detail/{CHROME}\n"
                f"https://chromewebstore.google.com:444/detail/{CHROME}\n"
                "https://marketplace.visualstudio.com/items?itemName=a.tool&itemName=b.tool")
        self.assertFalse(extractor.extract(text, report_mode=True).extensions)
        self.assertFalse(extractor.extract(f"Chrome Extension ID: {CHROME}q", report_mode=True).extensions)

    def test_rules_stay_excluded_and_capped_ids_do_not_leak_as_hashes(self):
        doc = html.parse_document(f'<pre>rule Sample {{ strings: $a = "Chrome Extension ID: {CHROME}" condition: $a }}</pre>')
        content.prepare_text(doc)
        self.assertFalse(extractor.extract(doc.indicator_text, report_mode=True).extensions)
        with patch.object(software, "MAX_REFERENCES", 1):
            result = extractor.extract(f"Chrome Extension ID: {CHROME}\nChrome Extension ID: {'a' * 32}", report_mode=True)
        self.assertEqual(len(result.extensions), 1)
        self.assertTrue(result.extensions_limited)
        self.assertFalse(result.by_type("hash"))

    def test_ui_is_passive_escaped_and_has_copy_controls(self):
        client = TestClient(app, base_url="http://127.0.0.1")
        with patch("httpx.AsyncClient.send", side_effect=AssertionError("No provider requests")):
            response = client.post("/extract", data={"text": f"Chrome Extension ID: {CHROME} <script>bad()</script>"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Software Extension References (1)", response.text)
        self.assertNotIn("nothing that looks like an indicator", response.text)
        self.assertIn('data-copy-target="plain-extensions"', response.text)
        self.assertIn(f'data-copy-value="{CHROME}"', response.text)
        self.assertIn("&lt;script&gt;bad()&lt;/script&gt;", response.text)
        self.assertNotIn("<script>bad()", response.text)
        self.assertNotIn('name="indicator"', response.text)


class ManualCveRefreshTests(TempDbMixin, unittest.TestCase):
    def test_read_only_get_and_isolated_guarded_post(self):
        client = TestClient(app, base_url="http://127.0.0.1")
        prefix = "/vulnerability-intelligence"
        with patch.object(cvelist, "refresh", new=AsyncMock(return_value={"ok": True})) as refresh, \
             patch.object(feeds, "refresh_all", side_effect=AssertionError("Unrelated feeds")), \
             patch.object(feeds, "load_cvelist", side_effect=AssertionError("Large full snapshot")):
            response = client.get(prefix + "/feeds")
            self.assertIn("Fetch New CVE Records", response.text)
            refresh.assert_not_awaited()
            self.assertEqual(client.get(prefix + "/refresh-cvelist").status_code, 405)
            self.assertEqual(client.post(prefix + "/refresh-cvelist", headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
            refresh.assert_not_awaited()
            response = client.post(prefix + "/refresh-cvelist", follow_redirects=False)
            self.assertEqual(response.status_code, 303)
            self.assertEqual(response.headers["location"], prefix + "/feeds#cvelist-refresh")
            refresh.assert_awaited_once_with()
