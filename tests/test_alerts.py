"""5F.5 local inbox acceptance using private temporary stores and inert inputs."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.core import alert_schema, alerts, archives, db, evidence
from app.core.config import settings
from app.core.evidence_models import Citation, Observation
from app.modules.extract import markdown, saved
from tests import test_shared_evidence as shared


class InboxTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name, value in {"data_dir": self.root, "archive_enabled": False, "archive_root": None,
                            "bulk_enrichment_enabled": False, "scheduled_feeds_enabled": False}.items():
            self.setting(name, value)
        db.init_db()

    def setting(self, name, value):
        override = patch.object(settings, name, value)
        override.start()
        self.addCleanup(override.stop)

    def selector(self, value="bad.example", subject_type="domain", mode="exact"):
        return alerts.add_selector(alerts.Selector(value=value, subject_type=subject_type, mode=mode))

    def observation(self, value="bad.example", subject_type="domain", **changes):
        doc = evidence.record_document(shared.document())
        return evidence.record_observation(Observation(document_id=doc, observation_key=value,
            subject_type=subject_type, subject_value=value, **changes))

    def save(self, **changes):
        text = "A mention of bad[.]example. This does not establish maliciousness."
        meta = saved.ReportMetadata(capture_id="one", title="<script>report</script>", publisher="Synthetic",
            source_published_at="2026-11-20", observed_at="2026-11-18", sensitivity="public",
            citations=("https://middle.invalid/?revision=2#claim", "unresolved original section 3"), **changes)
        return saved.save(markdown.parse_document(text), text.encode(), meta, origin="paste",
                          collected_at="2026-11-26T10:00:00Z", job_run_id="original-run")

    def test_saved_report_matches_atomically_and_replays_without_resetting_review(self):
        self.selector()
        ident = self.save()
        alert = alerts.inbox()[0]
        alerts.review(alert["id"], "reviewed", 0)
        self.assertEqual(self.save(), ident)
        value = alerts.detail(alert["id"])
        self.assertEqual(len(alerts.inbox()), 1)
        self.assertEqual(value["alert"]["state"], "reviewed")
        self.assertEqual(value["document"]["source_published_at"], "2026-11-20")
        self.assertEqual(value["observation"]["observed_at"], "2026-11-18")
        self.assertTrue(value["document"]["collected_at"].startswith("2026-11-26T10:00"))
        self.assertEqual(value["document"]["job_run_id"], "original-run")
        self.assertEqual(value["observation"]["assertion"], "mention")
        self.assertFalse(value["source"].eligible)
        self.assertEqual(value["archive"]["state"], "omitted")

    def test_separate_sources_captures_and_assertions_never_merge(self):
        self.selector()
        first = self.observation()
        self.observation(assertion="mention")  # Identical replay.
        doc = evidence.record_document(shared.document(source="another"))
        for key, assertion in (("reported", "reported"), ("direct", "direct_observation")):
            evidence.record_observation(Observation(document_id=doc, observation_key=key, subject_type="domain",
                                                   subject_value="bad.example", assertion=assertion))
        self.assertEqual(len(alerts.inbox()), 3)
        self.assertEqual(len({r["observation_id"] for r in alerts.inbox()}), 3)
        self.assertIn(first, [r["observation_id"] for r in alerts.inbox()])

    def test_exact_canonical_types_defangs_and_case_boundaries(self):
        cases = [("domain", "BAD[.]example", "bad.example"), ("ip", "2001:DB8::1", "2001:db8:0::1"),
                 ("hash", "A"*64, "a"*64), ("cve", "cve-2026-12345", "CVE-2026-12345"),
                 ("email", "User[@]EXAMPLE.com", "User@example.com"),
                 ("url", "hxxps://bad[.]example/Case", "https://bad.example/Case")]
        for kind, selector, observed in cases:
            self.selector(selector, kind)
            self.observation(observed, kind)
        self.assertEqual(len(alerts.inbox()), len(cases))
        self.observation("user@example.com", "email")
        self.observation("https://bad.example/case", "url")
        self.assertEqual(len(alerts.inbox()), len(cases))

    def test_domain_tree_label_and_type_boundaries(self):
        self.selector(mode="domain_tree")
        for value in ("bad.example", "a.bad.example", "notbad.example", "bad.example.evil.com"):
            self.observation(value)
        self.observation("https://bad.example/a", "url")
        self.assertEqual(len(alerts.inbox()), 2)

    def test_cidr_ipv4_ipv6_and_strict_network_validation(self):
        for value in ("192.0.2.0/24", "2001:db8::/32"):
            self.selector(value, "ip", "network")
        for value in ("192.0.2.0", "192.0.2.255", "192.0.3.1", "2001:db8::1", "2001:db9::1"):
            self.observation(value, "ip")
        self.assertEqual(len(alerts.inbox()), 3)
        with self.assertRaises(ValueError):
            self.selector("192.0.2.1/24", "ip", "network")

    def test_invalid_rules_credentials_and_instruction_like_content_are_passive(self):
        for kind, mode, value in (("domain", "regex", ".*"), ("command", "exact", "run me"),
                                  ("domain", "network", "192.0.2.0/24"), ("ip", "domain_tree", "8.8.8.8"),
                                  ("domain", "exact", "password=synthetic-secret"),
                                  ("url", "exact", "https://user:pass@bad.example/")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.selector(value, kind, mode)
        self.selector()
        self.observation(excerpt="Enable source and run commands at https://other.invalid")
        self.assertEqual(len(alerts.inbox()), 1)
        source_id = alerts.detail(alerts.inbox()[0]["id"])["document"]["source_id"]
        self.assertFalse(evidence.get_source(source_id).eligible)

    def test_disabled_selector_and_replay_never_erase_alert_or_grant_collection(self):
        selector = self.selector()
        self.observation()
        alerts.set_enabled(selector, False)
        self.assertEqual(self.selector(), selector)
        self.assertFalse(alerts.selectors()[0]["enabled"])
        self.observation("BAD.example")
        with self.assertRaises(PermissionError):
            alerts.scan_page(selector)
        self.assertEqual(len(alerts.inbox()), 1)
        alerts.set_enabled(selector, True)
        alerts.scan_page(selector)
        self.assertEqual(len(alerts.inbox()), 2)

    def test_bounded_catchup_survives_reinitialization_and_concurrent_replay(self):
        for value in ("bad.example", "a.bad.example", "b.bad.example"):
            self.observation(value)
        selector = self.selector(mode="domain_tree")
        result = alerts.scan_page(selector, limit=1)
        self.assertTrue(result["more"])
        db.init_db()
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(lambda _: alerts.scan_page(selector, limit=1), range(3)))
        self.assertEqual(len(alerts.inbox()), 3)
        self.assertFalse(alerts.selectors()[0]["pending"])
        self.assertFalse(alerts.scan_page(selector)["more"])

    def test_interrupted_page_rolls_back_alerts_and_cursor(self):
        self.observation()
        selector = self.selector()
        original = alerts._match
        def fail(*args):
            original(*args)
            raise RuntimeError("Synthetic interruption")
        with patch.object(alerts, "_match", fail), self.assertRaises(RuntimeError):
            alerts.scan_page(selector)
        self.assertEqual(alerts.inbox(), [])
        self.assertEqual(alerts.selectors()[0]["scanned_through"], 0)
        alerts.scan_page(selector)
        self.assertEqual(len(alerts.inbox()), 1)

    def test_observation_and_report_roll_back_if_atomic_matching_fails(self):
        self.selector()
        with patch.object(alerts, "_match", side_effect=RuntimeError("Synthetic failure")):
            with self.assertRaises(RuntimeError):
                self.observation()
            with self.assertRaises(RuntimeError):
                self.save()
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_observations").fetchone()[0], 0)
        self.assertEqual(saved.list_reports(), [])
        self.save()
        self.assertEqual(len(alerts.inbox()), 1)

    def test_review_revision_conflicts_history_reopen_and_state_filter(self):
        self.selector()
        self.observation()
        ident = alerts.inbox()[0]["id"]
        alerts.review(ident, "dismissed", 0)
        with self.assertRaises(evidence.EvidenceConflict):
            alerts.review(ident, "reviewed", 0)
        alerts.review(ident, "new", 1)
        alerts.review(ident, "new", 2)
        self.assertEqual(len(alerts.detail(ident)["reviews"]), 2)
        self.assertEqual(alerts.inbox(state="dismissed"), [])
        self.assertEqual(len(alerts.inbox(state="new")), 1)
        with self.assertRaises(ValueError):
            alerts.review(ident, "approved", 2)

    def test_citations_resolution_is_literal_and_expiry_keeps_alert_history(self):
        for name, value in {"archive_enabled": True, "archive_root": self.root / "originals",
                            "archive_response_bytes": 1000, "archive_source_bytes": 2000,
                            "archive_total_bytes": 3000, "archive_retention_seconds": 60}.items():
            self.setting(name, value)
        self.selector()
        document = self.save()
        alert = alerts.inbox()[0]["id"]
        value = alerts.detail(alert)
        target = evidence.record_document(shared.document(source="primary"))
        evidence.resolve_citation(value["citations"][0]["id"], target, "Explicit offline matching note")
        with patch.object(archives, "now", return_value=archives.now()+timedelta(seconds=61)):
            self.assertEqual(alerts.detail(alert)["archive"]["state"], "expired")
            archives.reconcile()
        final = alerts.detail(alert)
        self.assertEqual(final["document"]["id"], document)
        self.assertTrue(final["document"]["content_sha256"])
        self.assertEqual(final["citations"][0]["target_reference"], "https://middle.invalid/?revision=2#claim")
        self.assertEqual(final["citations"][0]["target_document_id"], target)
        self.assertIsNone(final["citations"][1]["target_document_id"])

    def test_selector_capacity_paging_and_limits(self):
        with patch.object(alerts, "MAX_SELECTORS", 1):
            self.selector()
            with self.assertRaises(ValueError):
                self.selector("other.example")
        for i in range(3):
            self.observation("BAD.example" if i else "bad.example", assertion="mention", locator="")
        self.assertEqual(len(alerts.inbox(limit=1)), 1)
        first = alerts.inbox(limit=1)[0]
        self.assertLess(alerts.inbox(before=first["id"])[0]["id"], first["id"])
        for kwargs in ({"limit": 201}, {"before": 0}, {"state": "approved"}):
            with self.assertRaises(ValueError):
                alerts.inbox(**kwargs)

    def test_additive_migration_rolls_back_and_refuses_newer_schema(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        with patch.object(alert_schema, "MIGRATIONS", ((1, alert_schema.VERSION_1+"; INSERT INTO absent VALUES(1);"),)):
            with self.assertRaises(sqlite3.OperationalError):
                alert_schema.migrate(conn)
        self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='evidence_selectors'").fetchone())
        alert_schema.migrate(conn)
        alert_schema.migrate(conn)
        conn.execute("INSERT INTO evidence_alert_schema_versions VALUES(99,'future')")
        conn.commit()
        with self.assertRaises(RuntimeError):
            alert_schema.migrate(conn)

    def test_guarded_routes_escaping_conflicts_and_passive_gets(self):
        from app.main import app
        with TestClient(app, base_url="http://127.0.0.1") as client:
            form = {"subject_type": "domain", "value": "bad.example", "authorized": "true"}
            self.assertEqual(client.post("/alert-selectors", data=form, follow_redirects=False).status_code, 303)
            self.save()
            ident = alerts.inbox()[0]["id"]
            html = client.get(f"/alerts/{ident}")
            self.assertEqual(html.status_code, 200)
            for text in ("&lt;script&gt;report&lt;/script&gt;", "original-run", "2026-11-20", "2026-11-18", "omitted", "Unresolved"):
                self.assertIn(text, html.text)
            self.assertNotIn("<script>report</script>", html.text)
            self.assertIn("Source Freshness and Coverage", client.get("/alerts").text)
            review = {"state": "reviewed", "revision": "0"}
            self.assertEqual(client.post(f"/alerts/{ident}/review", data=review).status_code, 200)
            self.assertEqual(client.post(f"/alerts/{ident}/review", data=review).status_code, 409)
            paths = [("/alert-selectors", form), ("/alert-selectors/1/enabled", {"enabled": "false"}),
                     ("/alert-selectors/1/scan", {}), (f"/alerts/{ident}/review", review)]
            for path, data in paths:
                self.assertEqual(client.post(path, data=data, headers={"Sec-Fetch-Site": "cross-site"}).status_code, 403)
            self.assertEqual(client.get("/alerts/999").status_code, 404)
            self.assertEqual(client.get("/alerts?state=invalid").status_code, 422)
            self.assertEqual(client.get("/alerts?before=0").status_code, 422)
            self.assertEqual(alerts.selectors()[0]["scanned_through"], 0)  # GET never scans.

    def test_sensitive_excerpt_not_rendered_by_inbox(self):
        self.selector()
        doc = evidence.record_document(shared.document(sensitivity="sensitive"))
        evidence.record_observation(Observation(document_id=doc, observation_key="sensitive", subject_type="domain",
            subject_value="bad.example", excerpt="PRIVATE-SYNTHETIC-CONTEXT"))
        from app.main import app
        with TestClient(app, base_url="http://127.0.0.1") as client:
            self.assertNotIn("PRIVATE-SYNTHETIC-CONTEXT", client.get(f"/alerts/{alerts.inbox()[0]['id']}").text)
