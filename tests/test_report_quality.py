"""Regressions for the operator's publisher reports and CVE evidence gaps.

All report fixtures are synthetic. Downloaded publisher content stays local.
"""

import json
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.modules.extract import atlas, content, extractor, html, markdown
from app.modules.vulnerability_intelligence import evidence, service, store, vendor_notices, views
from app.modules.vulnerability_intelligence.feeds import msrc
from app.modules.vulnerability_intelligence.sources import nvd, vulnlookup
from tests.test_vulnintel import TempDbMixin


def extract_document(document):
    content.prepare_text(document)
    result = extractor.extract(document.indicator_text, report_mode=True)
    content.attach_context(result, document)
    return result


class ReportQualityTests(unittest.TestCase):
    def test_streamed_json_recovers_hashes_without_executing_scripts(self):
        hashes = [f"{number:064x}" for number in range(1, 14)]
        model = ["$", "article", None, {"children": [
            ["$", "p", None, {"children": value}] for value in hashes]}]
        stream = "a:" + json.dumps(model) + "\n"
        script = "self.__next_f.push(" + json.dumps([1, stream]) + ");throw new Error('never execute');"
        source = "<p>" + hashes[0] + "</p><script>" + script + "</script>"
        doc = html.parse_document(source)
        self.assertTrue(doc.recovered)
        self.assertEqual(set(i.value for i in extract_document(doc).by_type("hash")), set(hashes))
        complete = "".join("<p>" + value + "</p>" for value in hashes) + source
        self.assertFalse(html.parse_document(complete).recovered)

    def test_known_suffixes_references_and_defanged_hosting_indicators(self):
        result = extractor.extract(
            "img.src data.mdb request.getparameter github.com golang.org urlscan.io "
            "https://github.com/org/project https://urlscan.io/result/abc "
            "hxxps://github[.]com/actor/payload evil[.]com a.read(buffer)", report_mode=True)
        self.assertEqual([i.value for i in result.by_type("domain")], ["github.com", "evil.com"])
        self.assertIn("https://github.com/actor/payload", [i.value for i in result.by_type("url")])
        self.assertEqual(len(result.references), 2)

    def test_rules_queries_and_commands_are_inert_and_not_iocs(self):
        source = '''<h2>YARA</h2><pre>rule Sample {
 strings: $a = "https://hooks.slack.com/services/SECRET"
 condition: $a
}</pre><h2>Sigma</h2><pre>title: Test
logsource:
  product: windows
detection:
  selection:
    CommandLine: https://rule.example/path
  condition: selection</pre><h2>KQL</h2><pre>DeviceProcessEvents | where FileName == "curl.exe"</pre>
<pre>nmap -sS 192.0.2.1</pre><p><code>rule Inline { strings: $a = "https://inline-rule.example/path" condition: $a }</code></p><p>C2: evil[.]com</p>'''
        doc = html.parse_document(source)
        result = extract_document(doc)
        self.assertEqual({i.value for i in result.items}, {"evil.com"})
        self.assertEqual({item["kind"] for item in doc.artifacts}, {"YARA", "Sigma", "KQL", "Command Line"})

    def test_plain_yara_and_images_are_separated(self):
        doc = markdown.parse_document('''YARA:
rule sample
{
 strings:
  $a = "https://hooks.slack.com/services/SECRET"
 condition: $a
}
https://images.example/diagram.png
evil[.]com''')
        result = extract_document(doc)
        self.assertEqual([i.value for i in result.items], ["evil.com"])
        self.assertEqual(doc.artifacts[0]["kind"], "YARA")
        self.assertEqual(len(doc.images), 1)
        for value in ("https://127.0.0.1/a.png", "https://localhost/a.png", "https://images.example/a.png?token=secret"):
            self.assertFalse(content.image_url(value))

    def test_table_context_links_and_atlas_are_separate(self):
        digest = "ab" * 32
        doc = html.parse_document(f'''<h2>Favicon Hashes</h2><table><tr><td>Console:</td></tr>
<tr><td> {digest} </td></tr></table><table><tr><td>192.0.2.10</td><td>Observed proxy</td></tr></table>
<p>AML.T0051: a source assertion.</p><a href="https://github.com/example/research">Original research</a>''')
        result = extract_document(doc)
        self.assertIn("Console:", result.by_type("hash")[0].context[0])
        self.assertEqual(result.by_type("hash")[0].value, digest)
        self.assertIn("Observed proxy", result.by_type("ip")[0].context[0])
        self.assertFalse(result.by_type("url"))
        self.assertEqual(doc.references[0]["value"], "https://github.com/example/research")
        self.assertEqual(atlas.extract(doc)[0]["id"], "AML.T0051")

    def test_success_clears_inputs_and_exposes_copy_controls_and_decoder_tab(self):
        client = TestClient(app, base_url="http://127.0.0.1")
        with patch("httpx.AsyncClient.send", side_effect=AssertionError("Network")):
            response = client.post("/extract", data={"text": "UNIQUE_INPUT evil[.]com"})
            self.assertEqual(response.status_code, 200)
            form = response.text.split('action="/extract"', 1)[1].split("</form>", 1)[0]
            self.assertNotIn("UNIQUE_INPUT", form)
            self.assertIn('data-copy-target="plain-domain"', response.text)
            decoder = client.get("/extract/decoder").text
            self.assertIn('action="/extract/decode"', decoder)
            self.assertNotIn('name="url"', decoder)
            command = client.post("/extract", data={"text": "nmap -sS 192.0.2.1"}).text
            self.assertIn("Command Line", command)
            self.assertNotIn("Candidate Behavior Mappings", command)
            self.assertNotIn("T1046", command)


class MetadataQualityTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def test_nvd_version_fallback_and_general_manual_load(self):
        cve = "CVE-2018-12345"
        body = {"vulnerabilities": [{"cve": {"id": cve,
            "descriptions": [{"lang": "en", "value": "Example learning platform."}],
            "metrics": {"cvssMetricV40": [{"cvssData": {}}], "cvssMetricV31": [
                {"type": "Primary", "cvssData": {"baseScore": 6.1, "version": "3.1", "baseSeverity": "MEDIUM"}}]},
            "weaknesses": [{"type": "Primary", "description": [{"value": "CWE-601"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:example:learning_platform:*:*:*:*:*:*:*:*", "vulnerable": True}]}]}]}}]}
        parsed = nvd.summarise(body)
        self.assertEqual((parsed["cvss_score"], parsed["cvss_version"], parsed["cwe"]), (6.1, "3.1", "CWE-601"))
        client = TestClient(app, base_url="http://127.0.0.1")
        with patch.object(nvd, "fetch", new=AsyncMock(return_value={"status": "ok", "cve": parsed})) as fetch:
            response = client.post(f"/vulnerability-intelligence/cve/{cve}/load-nvd", data={"keyless": "1"}, follow_redirects=False)
            self.assertEqual(response.status_code, 303)
            fetch.assert_awaited_once_with(cve, keyless=True)
            self.assertEqual(store.get_cve(cve)["cvss_score"], 6.1)
            row = views._rows("SELECT ? AS cve_id", (cve,))[0]
            self.assertEqual((row["vendor"], row["product"]), ("example", "learning platform"))
            blocked = client.post(f"/vulnerability-intelligence/cve/{cve}/load-nvd", headers={"Sec-Fetch-Site": "cross-site"})
            self.assertEqual(blocked.status_code, 403)

    async def test_keyless_call_uses_own_limit_and_omits_key(self):
        with patch.object(settings, "nvd_api_key", "synthetic-key"), \
             patch.object(nvd.rate_limiter, "acquire", new=AsyncMock()) as acquire, \
             patch.object(nvd.base, "fetch_json", new=AsyncMock(return_value=(200, {}, None))) as fetch:
            await nvd.fetch("CVE-2026-12345", keyless=True)
            acquire.assert_awaited_once_with("nvd_keyless")
            self.assertNotIn("apiKey", fetch.call_args.kwargs["headers"])

    async def test_uncited_claim_never_promotes_but_cited_report_does(self):
        cve = "CVE-2026-34567"
        day = store._since(0)
        store.save_cve({"cve_id": cve, "published": day})
        store.replace_recent_sightings([(cve, "exploited", day, 1)], [(cve, day, "Telegram", "", 1)])
        result = vulnlookup.summarise({"data": [{"vulnerability": cve, "type": "exploited", "source": "Telegram", "creation_timestamp": day}]})
        self.assertEqual(result["by_type"], {"exploitation-claim": 1})
        self.assertNotIn(cve, views.exploited_ids())
        self.assertNotIn(cve, {r["cve_id"] for r in views._zero_days()})
        self.assertFalse(views._rows("SELECT ? AS cve_id", (cve,))[0]["exploited_sighting"])
        rep = await service.report(cve, local_first=True)
        self.assertNotIn("Hunt", {action["label"] for action in rep["actions"]})
        store.replace_recent_sightings([(cve, "exploited", day, 1)], [(cve, day, "Researcher", "https://research.example/report", 1)])
        self.assertIn(cve, views.exploited_ids())
        self.assertTrue(views._rows("SELECT ? AS cve_id", (cve,))[0]["exploited_sighting"])

    async def test_mismatched_sighting_response_is_rejected(self):
        with patch.object(vulnlookup.base, "fetch_json", new=AsyncMock(return_value=(200, {"data": [
                {"vulnerability": "CVE-2026-99999", "type": "exploited", "source": "https://research.example/report"}]}, None))):
            result = await vulnlookup.sightings("CVE-2026-12345", force=True)
            self.assertEqual(result["status"], "error")
            self.assertFalse(vulnlookup.cached_sightings("CVE-2026-12345"))

    async def test_microsoft_catalog_filter_and_refresh_share_existing_store(self):
        cve = "CVE-2026-45678"
        row = {"cve_id": cve, "title": "Example Windows Fix", "url": "https://msrc.microsoft.com/update-guide/vulnerability/" + cve,
               "released": "2026-11-10", "revised": "2026-11-11", "cycle": "scheduled", "products": ["Windows"], "exploited": False}
        msrc._save(row, row["revised"])
        page = vendor_notices.page(1, "microsoft", "2026-11", {cve})
        self.assertEqual(page["rows"][0]["title"], row["title"])
        self.assertEqual(page["rows"][0]["cves"], [cve])
        self.assertEqual(vendor_notices.page(1, "microsoft", "2026-11", set())["rows"], [])
        client = TestClient(app, base_url="http://127.0.0.1")
        self.assertIn("Microsoft Security Response Center", client.get("/vulnerability-intelligence/vendor-updates").text)
        with patch.object(msrc, "refresh", new=AsyncMock()) as refresh:
            response = client.post("/vulnerability-intelligence/refresh-vendors/microsoft", follow_redirects=False)
            self.assertEqual(response.status_code, 303)
            refresh.assert_awaited_once()
