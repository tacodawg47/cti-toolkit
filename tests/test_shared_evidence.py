"""Offline migration, provenance and compatibility acceptance for subphase 5F.1."""

from concurrent.futures import ThreadPoolExecutor
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from app.core import db, evidence, evidence_schema
from app.core.config import settings
from app.core.evidence_models import Citation, Document, Observation, Source, SourceLink


def document(source="publisher", **changes):
    return Document(**{
        "source_id": source, "external_id": "advisory-1", "capture_key": "capture-1",
        "title": "Synthetic Advisory", "publisher": "Synthetic Publisher",
        "source_url": "https://publisher.invalid/advisory-1",
        "collection_method": "local_import", "source_published_at": "2026-11-20",
        "collected_at": "2026-11-26T10:00:00-05:00", **changes,
    })


def observation(document_id, **changes):
    return Observation(**{
        "document_id": document_id, "observation_key": "row-1",
        "subject_type": "domain", "subject_value": "example.invalid",
        "excerpt": "This domain was mentioned as a benign example.", "locator": "paragraph 3",
        **changes,
    })


class EvidenceDbTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.override = patch.object(settings, "data_dir", Path(self.directory.name))
        self.override.start()
        self.addCleanup(self.override.stop)

    def init(self):
        db.init_db()

    def test_empty_database_migrates_and_initialization_is_repeatable(self):
        self.init()
        with evidence.connect() as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertTrue({"evidence_sources", "evidence_documents", "evidence_observations",
                             "evidence_citations", "evidence_source_links"}.issubset(tables))
            self.assertEqual(conn.execute("SELECT version FROM evidence_schema_versions").fetchall()[0][0], 1)
        source = evidence.get_source("rvm")
        self.assertEqual((source.license_name, source.license_recorded_on), ("CC BY 4.0", "2026-11-11"))
        self.assertEqual((source.terms_status, source.terms_reviewed_on, source.reliability), ("unreviewed", None, "F"))
        self.assertFalse(source.eligible)
        evidence.save_source(Source(**{**source.model_dump(), "review_notes": "Local later review"}))
        self.init()
        self.assertEqual(evidence.get_source("rvm").review_notes, "Local later review")
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_schema_versions").fetchone()[0], 1)

    def test_existing_phase2_database_keeps_rows_views_and_user_version(self):
        from app.modules.vulnerability_intelligence import store, views
        from app.modules.infrastructure import c2feed

        # Build an old database without the new initializer. Capture every legacy
        # table and view, including existing review history and cache content.
        with db.connect() as conn:
            conn.executescript(db.SCHEMA)
            conn.execute("PRAGMA user_version=23")
            conn.execute("INSERT INTO cache VALUES ('synthetic','key','{}','2026-11-20','2999-01-01')")
            conn.execute("INSERT INTO quota_usage VALUES ('synthetic','2026-11-26',2)")
            conn.commit()
        store.init_schema()
        c2feed.init_schema()
        store.upsert_kev([{"cve_id": "CVE-2026-12345", "date_added": "2026-11-20",
            "vendor": "Synthetic", "product": "Gateway", "name": "Synthetic Vulnerability",
            "due_date": None, "ransomware": 0, "description": "Synthetic test record",
            "required_action": "Apply update", "notes": ""}], "cisa")
        store.set_feed_status("cisa", entries=1, version="synthetic")

        def snapshot():
            with db.connect() as conn:
                names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'evidence_%'")]
                rows = {name: sorted(map(tuple, conn.execute(f'SELECT * FROM "{name}"')), key=repr) for name in names}
                schema = [tuple(row) for row in conn.execute("SELECT name,sql FROM sqlite_master WHERE type='view' ORDER BY name")]
                return rows, schema

        before = snapshot()
        membership = views.exploited_ids()
        self.init()
        self.init()
        self.assertEqual(snapshot(), before)
        self.assertEqual(views.exploited_ids(), membership)
        with db.connect() as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 23)
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_documents").fetchone()[0], 0)
        # Normal module initialization still works after core migration.
        store.init_schema()
        c2feed.init_schema()
        self.assertEqual(views.exploited_ids(), membership)

    def test_interrupted_migration_rolls_back_ddl_seed_and_version_and_can_retry(self):
        broken = evidence_schema.VERSION_1 + "; INSERT INTO absent_table VALUES (1);"
        with db.connect() as conn:
            with patch.object(evidence_schema, "MIGRATIONS", ((1, broken),)):
                with self.assertRaises(sqlite3.OperationalError):
                    evidence_schema.migrate(conn)
            names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertNotIn("evidence_sources", names)
            self.assertNotIn("evidence_schema_versions", names)
            evidence_schema.migrate(conn)
        self.assertIsNotNone(evidence.get_source("rvm"))

    def test_newer_schema_fails_closed_without_applying_old_migrations(self):
        self.init()
        with db.connect() as conn, conn:
            conn.execute("INSERT INTO evidence_schema_versions VALUES (99, 'future')")
        with self.assertRaisesRegex(RuntimeError, "newer evidence schema"):
            self.init()
        self.assertIsNotNone(evidence.get_source("rvm"))

    def test_simultaneous_initializers_serialize(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: db.init_db(), range(2)))
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_schema_versions").fetchone()[0], 1)

    def test_unknown_source_is_unrated_disabled_and_does_not_overwrite_review(self):
        self.init()
        ident = evidence.record_document(document())
        source = evidence.get_source("publisher")
        self.assertEqual((source.reliability, source.terms_status, source.source_class), ("F", "unreviewed", "unknown"))
        self.assertIsNone(source.license_name)
        with self.assertRaises(PermissionError):
            evidence.require_collection("publisher", "api")
        approved = Source(**{**source.model_dump(), "name": "Reviewed Synthetic Publisher",
            "source_class": "publisher", "access_method": "api", "terms_status": "approved",
            "terms_reviewed_on": "2026-11-26", "terms_reference": "Synthetic operator review",
            "rate_limit_notes": "Synthetic limit: one request per minute", "collection_enabled": True})
        evidence.save_source(approved)
        self.assertEqual(evidence.record_document(document()), ident)
        self.assertEqual(evidence.require_collection("publisher", "api"), approved)
        with self.assertRaises(PermissionError):
            evidence.require_collection("publisher", "public_page")
        with self.assertRaises(PermissionError):
            evidence.require_collection("absent", "api")
        evidence.save_source(Source(**{**approved.model_dump(), "collection_enabled": False}))
        with self.assertRaises(PermissionError):
            evidence.require_collection("publisher", "api")

    def test_source_decisions_and_license_findings_need_their_own_evidence(self):
        for changes in ({"collection_enabled": True}, {"terms_status": "approved"},
                        {"terms_status": "denied"}, {"license_name": "MIT"},
                        {"terms_reviewed_on": "2026-02-30"}, {"reliability": "high"}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                Source(source_id="synthetic", name="Synthetic", **changes)
        source = Source(source_id="synthetic", name="Synthetic", license_name="MIT",
                        license_recorded_on="2026-11-26", license_reference="Synthetic license review")
        self.assertFalse(source.eligible)

    def test_sql_cannot_enable_an_unreviewed_source(self):
        self.init()
        with evidence.connect() as conn, conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE evidence_sources SET collection_enabled=1 WHERE source_id='rvm'")
        self.assertFalse(evidence.get_source("rvm").eligible)

    def test_dates_remain_distinct_and_unknowns_are_not_filled(self):
        self.init()
        ident = evidence.record_document(document(source_published_at="2026-11-21T01:00:00+02:00"))
        evidence.record_observation(observation(ident, observed_at="2026-10-01",
            first_seen="2026-09-01", last_seen="2026-10-02"))
        row = evidence.observations_for_subject("domain", "example.invalid")[0]
        self.assertEqual(row["collected_at"], "2026-11-26T15:00:00.000000+00:00")
        self.assertEqual(row["source_published_at"], "2026-11-20T23:00:00.000000+00:00")
        self.assertEqual((row["observed_at"], row["first_seen"], row["last_seen"]),
                         ("2026-10-01", "2026-09-01", "2026-10-02"))
        second = evidence.record_document(document(capture_key="capture-2", source_published_at=None))
        evidence.record_observation(observation(second))
        row = evidence.observations_for_subject("domain", "example.invalid")[1]
        self.assertTrue(all(row[key] is None for key in ("source_published_at", "observed_at", "first_seen", "last_seen")))
        self.assertEqual(row["assertion"], "mention")

    def test_bad_dates_naive_collection_and_reversed_intervals_are_rejected(self):
        for stamp in ("2026-02-30", "2026-11-26 10:00:00", "2026-11-26T10:00:00",
                      "2026-11-26T10:00:00+01:99", "0001-01-01T00:00:00+01:00", "", "unknown"):
            with self.subTest(stamp=stamp), self.assertRaises(ValidationError):
                observation(1, observed_at=stamp)
        for stamp in ("2026-11-26", "2026-11-26T10:00:00"):
            with self.subTest(stamp=stamp), self.assertRaises(ValidationError):
                document(collected_at=stamp)
        with self.assertRaises(ValidationError):
            observation(1, first_seen="2026-11-22", last_seen="2026-11-21")
        # Same-day mixed precision does not imply a false reversed interval.
        observation(1, first_seen="2026-11-21T12:00:00Z", last_seen="2026-11-21")

    def test_replays_are_idempotent_and_corrections_keep_prior_captures(self):
        self.init()
        doc = document()
        ident = evidence.record_document(doc)
        obs = observation(ident)
        obs_id = evidence.record_observation(obs)
        self.assertEqual(evidence.record_document(doc), ident)
        self.assertEqual(evidence.record_observation(obs), obs_id)
        with self.assertRaises(evidence.EvidenceConflict):
            evidence.record_document(document(title="Changed content under same revision"))
        with self.assertRaises(evidence.EvidenceConflict):
            evidence.record_observation(observation(ident, assertion="reported"))
        corrected = evidence.record_document(document(capture_key="capture-2", title="Correction"))
        evidence.record_observation(observation(corrected, excerpt="The source corrected its earlier statement."))
        self.assertEqual(len(evidence.observations_for_subject("domain", "example.invalid")), 2)
        self.assertEqual(evidence.get_document(ident)["title"], doc.title)

    def test_concurrent_replay_returns_the_same_document_and_observation(self):
        self.init()
        with ThreadPoolExecutor(max_workers=3) as pool:
            ids = list(pool.map(lambda _: evidence.record_document(document()), range(3)))
            observations = list(pool.map(lambda _: evidence.record_observation(observation(ids[0])), range(3)))
        self.assertEqual(len(set(ids)), 1)
        self.assertEqual(len(set(observations)), 1)

    def test_source_assertions_do_not_merge_or_gain_an_exploitation_verdict(self):
        self.init()
        for source in ("config", "honeypot", "feed", "scan"):
            ident = evidence.record_document(document(source))
            evidence.record_observation(observation(ident))
        rows = evidence.observations_for_subject("domain", "example.invalid")
        self.assertEqual({row["source_id"] for row in rows}, {"config", "honeypot", "feed", "scan"})
        self.assertEqual({row["assertion"] for row in rows}, {"mention"})
        self.assertEqual(len(rows), 4)

    def test_citation_chain_retains_unresolved_hop_and_reverse_relationships(self):
        self.init()
        primary = evidence.record_document(document("primary"))
        secondary = evidence.record_document(document("secondary"))
        tertiary = evidence.record_document(document("tertiary"))
        citation = Citation(document_id=secondary, citation_key="reference-1",
            target_reference="https://primary.invalid/original", excerpt="See original report", locator="footnote 1")
        ident = evidence.record_citation(citation)
        self.assertEqual(evidence.record_citation(citation), ident)
        self.assertIsNone(evidence.citations_for_document(secondary)[0]["target_document_id"])
        evidence.resolve_citation(ident, primary, "Manually matched the cited report")
        evidence.resolve_citation(ident, primary, "Manually matched the cited report")
        self.assertEqual(evidence.record_citation(citation), ident)
        edge = evidence.citations_for_document(primary, incoming=True)[0]
        self.assertEqual((edge["target_reference"], edge["excerpt"], edge["locator"]),
                         (citation.target_reference, citation.excerpt, citation.locator))
        evidence.record_citation(Citation(document_id=tertiary, citation_key="reference-1",
            target_reference="secondary advisory", target_document_id=secondary,
            relationship="republishes", resolution_note="Explicit republication notice"))
        self.assertEqual(evidence.citations_for_document(tertiary)[0]["target_document_id"], secondary)
        with self.assertRaises(evidence.EvidenceConflict):
            evidence.resolve_citation(ident, tertiary, "Different target")
        with self.assertRaises(ValidationError):
            evidence.resolve_citation(ident, secondary, "Self target")

    def test_source_lineage_is_scoped_and_does_not_authorize_collection(self):
        self.init()
        for source in ("upstream", "aggregator"):
            evidence.save_source(Source(source_id=source, name=source))
        link = SourceLink(source_id="aggregator", upstream_source_id="upstream", relationship="republishes",
                          scope="TTP matrix only", evidence_reference="Synthetic saved research", recorded_on="2026-11-26")
        ident = evidence.record_source_link(link)
        self.assertEqual(evidence.record_source_link(link), ident)
        self.assertEqual(evidence.links_for_source("aggregator")[0]["scope"], "TTP matrix only")
        self.assertFalse(evidence.get_source("aggregator").eligible)
        with self.assertRaises(ValidationError):
            SourceLink(**{**link.model_dump(), "upstream_source_id": "aggregator"})

    def test_foreign_keys_and_failed_resolution_preserve_existing_evidence(self):
        self.init()
        ident = evidence.record_document(document())
        with self.assertRaises(sqlite3.IntegrityError):
            evidence.record_observation(observation(999))
        citation = evidence.record_citation(Citation(document_id=ident, citation_key="ref", target_reference="unknown report"))
        with self.assertRaises(sqlite3.IntegrityError):
            evidence.resolve_citation(citation, 999, "Missing capture")
        self.assertIsNone(evidence.citations_for_document(ident)[0]["target_document_id"])
        with evidence.connect() as conn, conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM evidence_sources WHERE source_id='publisher'")
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM evidence_documents WHERE id=?", (ident,))
            self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_bounded_reads_excerpts_and_job_identity_contract(self):
        self.init()
        ident = evidence.record_document(document(job_run_id="run-123", source_revision="upstream-etag-1",
                                                  sensitivity="sensitive", tlp="AMBER+STRICT"))
        evidence.record_observation(observation(ident, excerpt="<script>untrusted instruction</script>"))
        row = evidence.observations_for_subject("domain", "example.invalid")[0]
        self.assertEqual(row["job_run_id"], "run-123")
        self.assertEqual(row["source_revision"], "upstream-etag-1")
        self.assertIn("<script>", row["excerpt"])  # stored as text, never executed/rendered here
        self.assertEqual(evidence.get_document(ident)["sensitivity"], "sensitive")
        for limit in (0, 201, True, "10"):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                evidence.list_sources(limit=limit)
        self.assertEqual(evidence.observations_for_subject("domain", "example.invalid", offset=1), [])
        with self.assertRaises(ValidationError):
            observation(ident, excerpt="x" * 4097)
        with self.assertRaises(ValidationError):
            document(archive_path="unreviewed arbitrary path")

    def test_app_lifespan_uses_new_schema_with_existing_pages_offline(self):
        from fastapi.testclient import TestClient
        from app.main import app

        with TestClient(app, base_url="http://127.0.0.1") as client:
            for path in ("/", "/health", "/extract", "/vulnerability-intelligence",
                         "/vulnerability-intelligence/feeds", "/infrastructure"):
                with self.subTest(path=path):
                    self.assertEqual(client.get(path).status_code, 200)
        self.assertIsNotNone(evidence.get_source("rvm"))
        with evidence.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_documents").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
