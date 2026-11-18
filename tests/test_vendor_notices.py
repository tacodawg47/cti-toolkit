"""Vendor notice parsing, provenance, incremental refresh and analyst views."""

import copy
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.modules.vulnerability_intelligence import review, service, store, tables, vendor_notices, views
from app.modules.vulnerability_intelligence.feeds import vendors
from tests.test_vulnintel import TempDbMixin

CVE = "CVE-2026-12345"
STAMP = "2026-11-17T08:00:00Z"


def document(ident="RHSA-2026:12345"):
    return {
        "document": {"title": "Example Product Fix", "tracking": {"id": ident, "status": "final",
            "initial_release_date": STAMP, "current_release_date": STAMP}},
        "product_tree": {"branches": [{"category": "vendor", "name": "Example Vendor", "branches": [
            {"category": "product_name", "name": "Example Product", "product": {"product_id": "p1", "name": "Example 1.0"}}]}]},
        "vulnerabilities": [{"cve": CVE, "product_status": {"known_affected": ["p1"]},
            "scores": [{"cvss_v3": {"baseScore": 8.1}}], "remediations": [
                {"category": "vendor_fix", "product_ids": ["p1"], "details": "Update to 1.1"},
                {"category": "workaround", "product_ids": ["p1"], "details": "Disable the feature"}]}],
    }


def parsed(doc=None):
    return vendors.parse_csaf(json.dumps(doc or document()).encode(), "redhat",
                               "https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_12345.json",
                               "rhsa-2026_12345")


class VendorParserTests(unittest.TestCase):
    def test_csaf_identity_scope_and_draft(self):
        evidence = parsed()["cves"][CVE]
        self.assertTrue(evidence["patch"])
        self.assertTrue(evidence["mitigation"])
        self.assertEqual(evidence["remediations"][0]["products"], ["Example 1.0"])
        self.assertEqual(evidence["matches"], [("Example Vendor", "Example Product")])
        for source, ident, expected in (("fortinet", "FG-IR-26-123", "FG-IR-26-123"),
                                       ("suse", "SUSE-SU-2026:123-1", "suse-su-2026_123-1")):
            self.assertIn(CVE, vendors.parse_csaf(json.dumps(document(ident)).encode(), source,
                                                 vendors.SOURCES[source], expected)["cves"])
        changed = document()
        changed["document"]["tracking"]["id"] = "WRONG"
        with self.assertRaises(ValueError):
            parsed(changed)
        changed = document()
        changed["vulnerabilities"][0]["product_status"] = {}
        for fix in changed["vulnerabilities"][0]["remediations"]:
            fix["product_ids"] = ["unknown"]
        self.assertFalse(parsed(changed)["cves"][CVE]["patch"])
        changed["document"]["tracking"]["status"] = "draft"
        self.assertEqual(parsed(changed)["cves"], {})
        fortinet = document("FG-IR-26-123")
        fortinet["document"]["tracking"]["initial_release_date"] = "2026-11-17T00:00:00"
        fortinet["document"]["tracking"]["current_release_date"] = "2026-11-17T00:00:00"
        row = vendors.parse_csaf(json.dumps(fortinet).encode(), "fortinet", vendors.SOURCES["fortinet"], "FG-IR-26-123")
        self.assertEqual(row["published"], "2026-11-17")

    def test_cisco_chrome_and_fortinet_feeds(self):
        rss = f'<rss><channel><item><title>Fix {CVE}</title><link>https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/test</link><description>Update available</description><pubDate>Tue, 17 Nov 2026 08:00:00 GMT</pubDate></item></channel></rss>'
        rows, pending = vendors.parse_rss(rss.encode(), "cisco")
        self.assertFalse(rows[0]["cves"][CVE]["patch"])
        self.assertEqual(pending, [])
        naive = rss.replace('Tue, 17 Nov 2026 08:00:00 GMT', '2026-11-17 08:00:00.0')
        self.assertEqual(vendors.parse_rss(naive.encode(), "cisco")[0][0]["published"], "2026-11-17")
        atom = f'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Stable Update</title><link rel="alternate" href="https://chromereleases.googleblog.com/2026/11/update.html"/><published>{STAMP}</published><content>{CVE}</content></entry></feed>'
        self.assertIn(CVE, vendors.parse_rss(atom.encode(), "chrome")[0][0]["cves"])
        fortinet = rss.replace('<rss>', '<rss xmlns:csaf="https://fortiguard.fortinet.com/rss/ns/csaf">').replace(
            'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/test',
            'https://www.fortiguard.com/psirt/FG-IR-26-123').replace('</item>',
            '<csaf:link>https://filestore.fortinet.com/fortiguard/psirt/csaf_fg-ir-26-123.json</csaf:link></item>')
        rows, pending = vendors.parse_rss(fortinet.encode(), "fortinet")
        self.assertEqual(rows, [])
        self.assertEqual(pending[0][0], "FG-IR-26-123")
        with self.assertRaises(ValueError):
            vendors.parse_rss(rss.replace('sec.cloudapps.cisco.com', 'untrusted.invalid').encode(), "cisco")
        with self.assertRaises(ValueError):
            vendors.parse_rss(b'<!DOCTYPE rss><rss/>', "cisco")

    def test_paloalto_scoped_fix_and_non_cve_notice(self):
        row = {"ID": CVE, "title": "Example", "version": ["PAN-OS 11.1"], "affected": ["<11.1.2"],
               "fixed": [">=11.1.2"], "product": ["PAN-OS"], "baseScore": 9.1, "date": STAMP, "updated": STAMP}
        self.assertTrue(vendors.parse_paloalto(json.dumps([row]).encode())[0]["cves"][CVE]["patch"])
        row["fixed"] = ["None"]
        self.assertFalse(vendors.parse_paloalto(json.dumps([row]).encode())[0]["cves"][CVE]["patch"])
        row["ID"] = "PAN-SA-2026-12345"
        self.assertEqual(vendors.parse_paloalto(json.dumps([row]).encode())[0]["cves"], {})

    def test_suse_invalid_utf8_is_visible_and_not_reinterpreted(self):
        doc = document("openSUSE-SU-2026:123-1")
        body = json.dumps(doc).encode().replace(b"Example Product Fix", b"Example \xd7 Product Fix")
        row = vendors.parse_csaf(body, "suse", vendors.SOURCES["suse"], "opensuse-su-2026_123-1")
        self.assertIn("\ufffd", row["title"])
        self.assertIn("invalid UTF-8", row["cves"][CVE]["source_warning"])


class VendorStoreTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def test_catalog_detail_watchlist_and_review_share_evidence(self):
        review.capture()
        vendor_notices.save(parsed())
        review.capture()
        self.assertTrue(any(event["kind"] == "patch" for event in review.page()["rows"]))
        row = views._rows("SELECT ? AS cve_id", (CVE,))[0]
        self.assertEqual(row["fix"], "vendor_patch")
        self.assertEqual(row["cvss"], 8.1)
        catalog = views.catalog_page(tables.Filters.parse({}, "v", default_sort="date"), {})
        self.assertIn(CVE, [row["cve_id"] for row in catalog["rows"]])
        hits = views.watchlist_hits([{"id": 1, "vendor": "Example Vendor", "product": "Example Product"}])
        self.assertIn(CVE, hits)
        with patch("httpx.AsyncClient.send", side_effect=AssertionError("Unexpected network")):
            rep = await service.report(CVE, local_first=True)
        self.assertEqual(rep["fix_status"], "vendor_patch")
        self.assertEqual(rep["cvss_fallback"]["cvss_score"], 8.1)
        self.assertEqual({action["label"] for action in rep["actions"]}, {"Patch", "Mitigate"})
        client = TestClient(app, base_url="http://127.0.0.1")
        response = client.get("/vulnerability-intelligence/vendor-updates?vendor_source=redhat")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Example Product Fix", response.text)
        response = client.get(f"/vulnerability-intelligence/cve/{CVE}")
        self.assertEqual(response.status_code, 200)
        self.assertIn('href="#vendor-advisories">Vendor Fix', response.text)
        self.assertIn("Update to 1.1", response.text)

    async def test_revisions_remove_stale_evidence_and_ignore_older(self):
        row = parsed()
        vendor_notices.save(row)
        old = copy.deepcopy(row)
        old["updated"] = "2020-01-01"
        old["cves"] = {}
        vendor_notices.save(old)
        self.assertEqual(len(vendor_notices.for_cve(CVE)), 1)
        row["cves"] = {}
        vendor_notices.save(row)
        self.assertEqual(vendor_notices.for_cve(CVE), [])

    async def test_chrome_repeated_filenames_preserve_distinct_months(self):
        atom = f'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Stable</title><link rel="alternate" href="https://chromereleases.googleblog.com/2026/11/update.html"/><published>{STAMP}</published><content>{CVE}</content></entry></feed>'
        november = vendors.parse_rss(atom.encode(), "chrome")[0][0]
        legacy = {**november, "advisory_id": "update.html"}
        vendor_notices.save(legacy)
        vendor_notices.save(november)
        october = vendors.parse_rss(atom.replace('/11/', '/10/').encode(), "chrome")[0][0]
        vendor_notices.save(october)
        self.assertEqual(len(vendor_notices.saved("chrome")), 2)
        self.assertEqual(len(vendor_notices.for_cve(CVE)), 2)

    async def test_bounded_csaf_refresh_resumes_and_retries_errors(self):
        now = datetime.now(timezone.utc).isoformat()
        csv = f'"2026/rhsa-2026_12345.json","{now}"\n"2026/rhsa-2026_12346.json","{now}"'
        calls = []
        failed = False

        async def fetch(url, **kwargs):
            calls.append(url)
            if url.endswith("changes.csv"):
                return 200, csv.encode(), None
            if failed:
                return 503, b"", None
            ident = "RHSA-2026:" + url.rsplit("_", 1)[-1].removesuffix(".json")
            return 200, json.dumps(document(ident)).encode(), None

        with patch.object(vendors, "fetch_bytes", side_effect=fetch), patch.object(vendors, "BATCH_LIMIT", 1):
            self.assertTrue((await vendors.refresh("redhat"))["ok"])
            self.assertIn("1 additional", store.feed_status()["vendor_redhat"]["version"])
            failed = True
            self.assertFalse((await vendors.refresh("redhat"))["ok"])
            self.assertEqual(len(vendor_notices.saved("redhat")), 1)
            failed = False
            self.assertTrue((await vendors.refresh("redhat"))["ok"])
            self.assertEqual(len(vendor_notices.saved("redhat")), 2)
            calls.clear()
            await vendors.refresh("redhat")
            self.assertEqual(len(calls), 1)

    async def test_fortinet_unchanged_revision_skips_csaf_download(self):
        rss = b'''<rss xmlns:csaf="https://fortiguard.fortinet.com/rss/ns/csaf"><channel><item>
          <title>Example</title><link>https://fortiguard.fortinet.com/psirt/FG-IR-26-123</link>
          <description>Revised on 2026-11-17 00:00:00</description>
          <pubDate>Tue, 10 Nov 2026 00:00:00 -0700</pubDate>
          <csaf:link>https://filestore.fortinet.com/fortiguard/psirt/csaf_example_fg-ir-26-123.json</csaf:link>
          </item></channel></rss>'''
        downloads = []

        async def fetch(url, **kwargs):
            if url.endswith('.xml'):
                return 200, rss, None
            downloads.append(url)
            return 200, json.dumps(document('FG-IR-26-123')).encode(), None

        with patch.object(vendors, "fetch_bytes", side_effect=fetch):
            self.assertTrue((await vendors.refresh('fortinet'))['ok'])
            self.assertTrue((await vendors.refresh('fortinet'))['ok'])
            self.assertEqual(len(downloads), 1)
