"""Grouped dashboard changes preserve the full queue and explicit review scope."""

import unittest
from datetime import datetime,timedelta,timezone

from fastapi.testclient import TestClient

from app.core.db import connect
from app.main import app
from app.modules.vulnerability_intelligence import review
from tests.test_vulnintel import TempDbMixin

CVE="CVE-2026-41001"
OTHER="CVE-2026-41002"


class ReviewDigestTests(TempDbMixin,unittest.TestCase):
    def add(self,cve,kind="patch",days=0,reviewed=None):
        with connect() as conn,conn:
            return conn.execute("""INSERT INTO vuln_review_events(cve_id,kind,source,detail,observed_at,reviewed_at)
                VALUES (?,?,'Example','Synthetic evidence',?,?)""",
                (cve,kind,(datetime.now(timezone.utc)-timedelta(days=days)).isoformat(),reviewed)).lastrowid

    def test_recent_events_group_by_cve_without_losing_or_acknowledging_any(self):
        self.add(CVE);self.add(CVE,"exploited");self.add(OTHER,days=8)
        self.add("CVE-2026-41003",reviewed="2026-11-20")
        rows=review.recent_summary()
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["cve_id"],CVE)
        self.assertEqual(rows[0]["changes"],2)
        self.assertEqual(set(rows[0]["kinds"]),{"patch","exploited"})
        self.assertEqual(review.page()["total"],3)
        self.assertEqual(review.page(history=True)["total"],4)

    def test_summary_is_bounded_and_orders_by_latest_evidence(self):
        for number in range(10):self.add(f"CVE-2026-{42000+number}")
        self.add("CVE-2026-42001","code")
        rows=review.recent_summary()
        self.assertEqual(len(rows),5)
        self.assertEqual(rows[0]["cve_id"],"CVE-2026-42001")
        self.assertEqual(review.page()["total"],11)

    def test_filtered_review_marks_only_the_selected_cve_and_get_does_not_mark(self):
        self.add(CVE);self.add(OTHER);latest=self.add(CVE,"mitigation")
        client=TestClient(app,base_url="http://127.0.0.1")
        page=client.get(f"/vulnerability-intelligence/review?cve={CVE}")
        self.assertEqual(page.status_code,200)
        self.assertIn("Mark This CVE Reviewed",page.text)
        self.assertNotIn(OTHER,page.text)
        self.assertEqual(review.page()["total"],3)
        route="/vulnerability-intelligence/review/mark"
        fields={"event_id":latest,"through":"true","cve":CVE}
        self.assertEqual(client.post(route,data=fields,headers={"Sec-Fetch-Site":"cross-site"}).status_code,403)
        result=client.post(route,data=fields,follow_redirects=False)
        self.assertEqual(result.status_code,303)
        self.assertEqual(result.headers["location"],f"/vulnerability-intelligence/review?cve={CVE}")
        self.assertEqual(review.page(cve_id=CVE)["total"],0)
        self.assertEqual(review.page(cve_id=OTHER)["total"],1)
        self.assertEqual(review.page(history=True,cve_id=CVE)["total"],2)
        self.assertEqual(client.get('/vulnerability-intelligence/review?cve=invalid').status_code,400)

    def test_dashboard_is_a_digest_without_global_backlog_count_or_mark_all_action(self):
        self.add(CVE);self.add(CVE,"code");self.add(OTHER,days=10)
        page=TestClient(app,base_url="http://127.0.0.1").get('/vulnerability-intelligence')
        self.assertEqual(page.status_code,200)
        panel=page.text.split('id="since-last-review"',1)[1].split('</section>',1)[0]
        self.assertIn("Review This CVE",panel)
        self.assertIn("2 evidence changes",panel)
        self.assertNotIn("Mark All Reviewed",panel)
        self.assertNotIn("All Unreviewed Changes (",panel)
        self.assertEqual(review.page()["total"],3)
