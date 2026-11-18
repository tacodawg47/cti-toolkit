"""Monthly Microsoft coverage, source precedence, and scoped remediation."""

import copy
import json
import unittest

import httpx

from app.modules.enrich import base
from app.modules.vulnerability_intelligence import routes, store
from app.modules.vulnerability_intelligence.feeds import msrc, msrc_cvrf
from tests.test_vulnintel import TempDbMixin


def monthly_document() -> dict:
    return {
        "DocumentTracking": {"Identification": {"ID": {"Value": "2026-Nov"}},
                             "CurrentReleaseDate": "2026-11-17T08:00:00"},
        "ProductTree": {"Branch": [{"Items": [
            {"ProductID": "1", "Value": "Example Server"},
            {"ProductID": "2", "Value": "Example Client"},
            {"ProductID": "3", "Value": "azl3 python on Azure Linux 3.0"},
        ]}]},
        "Vulnerability": [{
            "CVE": "CVE-2026-10001", "Title": {"Value": "Example Server"},
            "RevisionHistory": [{"Date": "2026-11-17T08:00:00"}, {"Date": "2026-11-10T08:00:00"}],
            "Notes": [{"Title": "Customer Action Required", "Value": "Yes"}],
            "ProductStatuses": [{"Type": 3, "ProductID": ["1", "2"]}, {"Type": 4, "ProductID": ["3"]}],
            "Threats": [
                {"Type": 0, "Description": {"Value": "Remote Code Execution"}},
                {"Type": 3, "Description": {"Value": "Important"}},
                {"Type": 1, "Description": {"Value": "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:N/A"}},
            ],
            "CVSSScoreSets": [{"BaseScore": 9.9}],
            "Remediations": [
                {"Type": 2, "Description": {"Value": "Security Update"}, "URL": "https://support.microsoft.com/fix",
                 "ProductID": ["1"], "FixedBuild": "1.2"},
                {"Type": 2, "Description": {"Value": "Release Notes"}, "URL": "", "ProductID": ["2"], "FixedBuild": ""},
                {"Type": 0, "Description": {"Value": "<p>Disable <strong>this</strong> feature.</p>"},
                 "ProductID": ["2"]},
            ],
        }],
    }


class MonthlyMicrosoftTests(TempDbMixin, unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await base.aclose()

    async def test_fallback_refresh_and_detail_preserve_source_scope_and_updates(self):
        document = monthly_document()
        cve = document["Vulnerability"][0]["CVE"]
        calls = []
        updated = "2026-11-17T08:00:00Z"
        broken = False
        index_failure = True

        def handler(request):
            calls.append(str(request.url))
            self.assertNotIn("authorization", request.headers)
            if request.url.path.endswith("/changes.csv"):
                if index_failure:
                    return httpx.Response(502)
                return httpx.Response(200, text='"2026/msrc_cve-2026-99999.json","2026-09-01T08:00:00Z"')
            if request.url.path.endswith("/updates"):
                return httpx.Response(200, json={"value": [{
                    "ID": "2026-Nov", "InitialReleaseDate": "2026-11-10T08:00:00Z",
                    "CurrentReleaseDate": updated, "CvrfUrl": "https://untrusted.invalid/ignored",
                }]})
            self.assertEqual(str(request.url), f"{msrc_cvrf.API}/cvrf/2026-Nov")
            return httpx.Response(200, json={"invalid": True} if broken else document)

        store.set_sync(msrc.SYNC_KEY, "2026-10-03")
        base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        self.assertFalse((await msrc.refresh())["ok"])
        self.assertIsNone(store.feed_status()[msrc_cvrf.FEED]["error"])
        saved = msrc.get_advisory(cve)
        self.assertEqual(saved["released"], "2026-11-10")
        self.assertEqual(saved["products"], ["Example Client", "Example Server"])
        self.assertEqual(saved["fixes"][0]["products"], ["Example Server"])
        self.assertEqual(saved["fixes"][1]["products"], ["Example Client"])
        self.assertEqual(saved["fixes"][1]["label"], "Disable this feature.")
        self.assertEqual(saved["customer_action"], "Yes")
        self.assertEqual(store.get_kev(cve)[0]["date_added"], "2026-11-17")
        self.assertEqual(routes._patch_release({"v_month": "2026-11"})["rows"][0]["cve_id"], cve)
        index_failure = False
        self.assertTrue((await msrc.refresh())["ok"])
        self.assertEqual(sum(url.endswith("/cvrf/2026-Nov") for url in calls), 1)

        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app, base_url="http://127.0.0.1")
        detail = client.get(f"/vulnerability-intelligence/cve/{cve}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("Microsoft Monthly CVRF", detail.text)
        self.assertIn("Disable this feature.", detail.text)
        self.assertIn(">Patch</strong>", detail.text)
        self.assertIn(">Mitigate</strong>", detail.text)
        self.assertIn(">Hunt</strong>", detail.text)

        updated = "2026-11-18T08:00:00Z"
        broken = True
        self.assertFalse((await msrc_cvrf.refresh("2026-10-03"))["ok"])
        self.assertEqual(msrc.get_advisory(cve), saved)
        self.assertEqual(store.get_sync("msrc_cvrf_2026-Nov"), "2026-11-17T08:00:00+00:00")
        broken = False
        document["DocumentTracking"]["CurrentReleaseDate"] = updated
        document["Vulnerability"][0]["Threats"][-1]["Description"]["Value"] = "Exploited:No"
        self.assertTrue((await msrc_cvrf.refresh("2026-10-03"))["ok"])
        self.assertEqual(store.get_kev(cve), [])
        self.assertEqual(msrc.get_advisory(cve)["exploited"], "No")

    def test_csaf_supersedes_fallback_and_withdrawal_preserves_csaf(self):
        document = monthly_document()
        rows, changed = msrc_cvrf.parse_month(json.dumps(document).encode(), "2026-Nov")
        fallback = rows[0]
        cve = fallback["cve_id"]
        msrc_cvrf._save_month(rows, changed, "2026-Nov")
        csaf = {key: value for key, value in fallback.items()
                if key not in ("format", "source_url", "source_revised", "document_id")}
        csaf["title"], csaf["exploited"] = "Per-CVE advisory", "No"
        # Per-CVE and monthly document clocks can differ.
        msrc._save(csaf, "2026-11-10T08:00:00+00:00")
        self.assertEqual(msrc.get_advisory(cve)["title"], "Per-CVE advisory")
        msrc_cvrf._save_month(rows, "2026-11-18T08:00:00+00:00", "2026-Nov")
        self.assertEqual(msrc.get_advisory(cve)["title"], "Per-CVE advisory")
        self.assertEqual(store.get_kev(cve), [])
        extra = copy.deepcopy(fallback)
        extra["cve_id"] = "CVE-2026-10002"
        msrc_cvrf._save_month([fallback, extra], "2026-11-19T08:00:00+00:00", "2026-Nov")
        msrc_cvrf._save_month([fallback], "2026-11-20T08:00:00+00:00", "2026-Nov")
        self.assertIsNone(msrc.get_advisory(extra["cve_id"]))
        self.assertEqual(store.get_kev(extra["cve_id"]), [])
        self.assertEqual(msrc.get_advisory(cve)["title"], "Per-CVE advisory")

    def test_third_party_group_and_placeholder_do_not_imply_patch(self):
        document = monthly_document()
        row = document["Vulnerability"][0]
        row["ProductStatuses"] = [{"Type": 3, "ProductID": ["3"]}]
        row["Remediations"] = [row["Remediations"][1]]
        document["Vulnerability"].append({"CVE": "ADV260001"})
        parsed, _ = msrc_cvrf.parse_month(json.dumps(document).encode(), "2026-Nov")
        self.assertEqual(parsed[0]["cycle"], "also")
        self.assertFalse(parsed[0]["vendor_fix"])
        self.assertEqual(parsed[0]["fixes"], [])
        with self.assertRaises(ValueError):
            msrc_cvrf.parse_month(json.dumps(document).encode(), "2026-Oct")
