"""Explicit no-fix scope, mixed targets and source corrections."""

import json
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.core.db import connect
from app.main import app
from app.modules.vulnerability_intelligence import advisory_reload, review, service, store, unfixed, vendor_notices, views
from app.modules.vulnerability_intelligence.feeds import ot
from tests.test_vendor_notices import CVE, document, parsed
from tests.test_vulnintel import TempDbMixin, ot_document
from tests.test_vulnerability_evidence import action_labels, shared_row


def mixed_doc():
    doc=document()
    doc["product_tree"]["full_product_names"]=[{"product_id":"p2","name":"Example Fixed 2.0"}]
    doc["product_tree"]["product_groups"]=[{"group_id":"old","product_ids":["p1"]}]
    vuln=doc["vulnerabilities"][0]
    vuln["product_status"]={"known_affected":["p1"],"fixed":["p2"]}
    vuln["remediations"]=[
        {"category":"no_fix_planned","details":"Legacy release has no planned fix.","group_ids":["old"]},
        {"category":"workaround","details":"Disable legacy feature.","product_ids":["p1"]},
        {"category":"workaround","details":"Other release only.","product_ids":["p2"]},
        {"category":"vendor_fix","details":"Use fixed release.","product_ids":["p2"]},
    ]
    return doc


class ScopeTests(unittest.TestCase):
    def test_raw_product_ids_scope_and_overlapping_workarounds(self):
        proof=parsed(mixed_doc())["cves"][CVE]
        self.assertEqual(proof["unfixed"][0]["product_ids"],["p1"])
        self.assertEqual(proof["unfixed"][0]["products"],["Example 1.0"])
        self.assertEqual(proof["fixed_count"],1)
        self.assertEqual([m["details"] for m in proof["unfixed"][0]["mitigations"]],["Disable legacy feature."])
        self.assertTrue(proof["patch"])

    def test_unscoped_unknown_and_excluded_targets_never_qualify(self):
        for category in ("none_available","no_fix_planned"):
            for scope in ({},{"group_ids":["unknown"]},{"product_ids":["missing"]},{"product_ids":["p1","missing"]}):
                doc=mixed_doc();item=doc["vulnerabilities"][0]["remediations"][0]
                item.clear();item.update(category=category,details="No fix",**scope)
                self.assertFalse(parsed(doc)["cves"][CVE]["unfixed"])
        for status in ("fixed","first_fixed","known_not_affected","under_investigation","recommended"):
            doc=mixed_doc();doc["vulnerabilities"][0]["product_status"][status]=["p1"]
            self.assertFalse(parsed(doc)["cves"][CVE]["unfixed"])
        doc=mixed_doc();doc["vulnerabilities"][0]["product_status"]={}
        self.assertFalse(parsed(doc)["cves"][CVE]["unfixed"])

    def test_duplicate_cve_entries_are_checked_together_and_names_do_not_imply_ids(self):
        doc=mixed_doc()
        doc["vulnerabilities"].append({"cve":CVE,"product_status":{"fixed":["p1"]}})
        self.assertFalse(parsed(doc)["cves"][CVE]["unfixed"])
        doc=mixed_doc()
        doc["product_tree"]["full_product_names"][0]["name"]="Example 1.0"
        # Same display name is not the same product ID. p1 remains affected.
        self.assertEqual(parsed(doc)["cves"][CVE]["unfixed"][0]["product_ids"],["p1"])

    def test_missing_or_unscoped_patch_is_not_a_no_fix_statement(self):
        doc=mixed_doc();doc["vulnerabilities"][0]["remediations"]=[]
        self.assertFalse(parsed(doc)["cves"][CVE]["unfixed"])
        doc=mixed_doc();doc["vulnerabilities"][0]["remediations"][-1].pop("product_ids")
        self.assertFalse(parsed(doc)["cves"][CVE]["unfixed"])


class UnfixedIntegrationTests(TempDbMixin,unittest.IsolatedAsyncioTestCase):
    async def test_vendor_only_shared_view_detail_actions_and_review(self):
        store.save_ssvc(CVE,{"exploitation":"active","timestamp":"2026-11-17"})
        review.capture()
        before={r["slug"]:r["count"] for r in views.counts()}
        vendor_notices.save(parsed(mixed_doc()))
        review.capture()
        rep=await service.report(CVE,local_first=True)
        self.assertEqual(len(rep["unfixed_sources"]),1)
        self.assertEqual(action_labels(rep),{"Patch","Mitigate","Hunt"})
        row=shared_row(CVE)
        self.assertEqual(action_labels(row),action_labels(rep))
        self.assertEqual({r["cve_id"] for r in views.BY_SLUG["unfixed"].rows()},{CVE})
        self.assertEqual({r["slug"]:r["count"] for r in views.counts()}["unfixed"],before["unfixed"]+1)
        self.assertTrue(any(r["kind"]=="unfixed" for r in review.page()["rows"]))
        client=TestClient(app,base_url="http://127.0.0.1")
        for url in (f"/vulnerability-intelligence/cve/{CVE}","/vulnerability-intelligence/views/unfixed"):
            page=client.get(url)
            self.assertEqual(page.status_code,200)
            self.assertIn("No Fix Planned",page.text)
            self.assertIn("Example 1.0",page.text)
            self.assertIn("Disable legacy feature.",page.text)
            self.assertIn("also lists fixed targets",page.text)
        page=client.get(f"/vulnerability-intelligence/cve/{CVE}").text
        self.assertIn("Stored Source Data",page)
        self.assertIn("No-Fix Sources",page)
        self.assertIn("not complete original provider responses",page)

    async def test_ot_source_and_nonexploited_no_fix_are_distinct(self):
        path="2026/icsa-26-324-01.json"
        doc=ot_document(path,[CVE])
        doc["vulnerabilities"][0]["remediations"].append({"category":"none_available","product_ids":["p1"],"details":"No fix for the older controller."})
        doc["vulnerabilities"][0]["remediations"]=[m for m in doc["vulnerabilities"][0]["remediations"] if m["category"]!="vendor_fix"]
        parsed_ot=ot.parse_advisory(json.dumps(doc).encode(),path)
        with connect() as conn,conn:ot._save(conn,parsed_ot,parsed_ot["revised"])
        self.assertTrue(unfixed.sources_for([CVE])[CVE])
        self.assertEqual(views.BY_SLUG["unfixed"].rows(),[])
        store.save_ssvc(CVE,{"exploitation":"active","timestamp":"2026-11-17"})
        self.assertEqual(views.BY_SLUG["unfixed"].count(),1)
        row=views.BY_SLUG["unfixed"].rows()[0]
        self.assertEqual(row["unfixed_sources"][0]["source"],"cisa")
        self.assertEqual(row["unfixed_sources"][0]["unfixed"][0]["products"],["Example Controller before 2.1"])

    async def test_newer_correction_removes_its_scope_and_does_not_restore_from_old_copy(self):
        store.save_ssvc(CVE,{"exploitation":"active","timestamp":"2026-11-17"})
        original=parsed(mixed_doc());vendor_notices.save(original)
        self.assertEqual(views.BY_SLUG["unfixed"].count(),1)
        doc=mixed_doc();doc["document"]["tracking"]["current_release_date"]="2026-11-18T08:00:00Z"
        doc["vulnerabilities"][0]["product_status"]["fixed"].append("p1")
        vendor_notices.save(parsed(doc))
        self.assertEqual(views.BY_SLUG["unfixed"].count(),0)
        vendor_notices.save(original)
        self.assertEqual(views.BY_SLUG["unfixed"].count(),0)

    async def test_legacy_normalization_does_not_create_inferred_no_fix_scope(self):
        row=parsed(mixed_doc());proof=row["cves"][CVE]
        for key in ("unfixed","unfixed_schema","fixed_count"):proof.pop(key)
        vendor_notices.save(row)
        store.save_ssvc(CVE,{"exploitation":"active","timestamp":"2026-11-17"})
        self.assertEqual(views.BY_SLUG["unfixed"].count(),0)

    async def test_one_legacy_vendor_advisory_can_be_reloaded_without_feed_refresh(self):
        row=parsed(mixed_doc());row["advisory_id"]="2026/rhsa-2026_12345.json"
        for key in ("unfixed","unfixed_schema","fixed_count"):row["cves"][CVE].pop(key)
        vendor_notices.save(row)
        store.save_ssvc(CVE,{"exploitation":"active","timestamp":"2026-11-17"})
        self.assertEqual(len(advisory_reload.candidates(CVE)),1)
        client=TestClient(app,base_url="http://127.0.0.1")
        url=f"/vulnerability-intelligence/cve/{CVE}/advisory-scope"
        fields={"origin":"vendor","source":"redhat","reference":row["advisory_id"]}
        with patch.object(advisory_reload,"fetch_bytes",new=AsyncMock(return_value=(200,json.dumps(mixed_doc()).encode(),None))) as fetch:
            self.assertEqual(client.post(url,data=fields,headers={"Sec-Fetch-Site":"cross-site"}).status_code,403)
            bad={**fields,"reference":"../private.json"}
            self.assertEqual(client.post(url,data=bad).status_code,400)
            fetch.assert_not_awaited()
            self.assertEqual(client.post(url,data=fields,follow_redirects=False).status_code,303)
            fetch.assert_awaited_once()
            self.assertEqual(fetch.call_args.args[0],"https://security.access.redhat.com/data/csaf/v2/advisories/2026/rhsa-2026_12345.json")
            self.assertFalse(fetch.call_args.kwargs["follow_redirects"])
        self.assertEqual(advisory_reload.candidates(CVE),[])
        self.assertEqual(views.BY_SLUG["unfixed"].count(),1)

    async def test_legacy_ot_reimport_uses_equal_index_and_failure_preserves_old_evidence(self):
        path="2026/icsa-26-324-01.json"
        doc=ot_document(path,[CVE])
        doc["vulnerabilities"][0]["remediations"]=[{"category":"no_fix_planned","product_ids":["p1"],"details":"No planned fix"}]
        current=ot.parse_advisory(json.dumps(doc).encode(),path)
        legacy=json.loads(json.dumps(current))
        for key in ("unfixed","unfixed_schema","fixed_count"):legacy["cves"][CVE].pop(key)
        with connect() as conn,conn:ot._save(conn,legacy,legacy["revised"])
        with patch.object(advisory_reload,"fetch_bytes",new=AsyncMock(return_value=(503,None,"SYNTHETIC_SECRET"))):
            result=await advisory_reload.reload(CVE,"ot","cisa",path)
        self.assertFalse(result["ok"])
        self.assertNotIn("SYNTHETIC_SECRET",str(result))
        self.assertEqual(len(advisory_reload.candidates(CVE)),1)
        with patch.object(advisory_reload,"fetch_bytes",new=AsyncMock(return_value=(200,json.dumps(doc).encode(),None))):
            result=await advisory_reload.reload(CVE,"ot","cisa",path)
        self.assertTrue(result["ok"])
        self.assertEqual(advisory_reload.candidates(CVE),[])
        self.assertTrue(unfixed.sources_for([CVE])[CVE])
