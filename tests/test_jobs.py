"""Offline durable-runner acceptance. All jobs and databases are synthetic."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core import db, evidence, job_schema
from app.core.config import settings
from app.core.evidence_models import Citation, Document, Observation, Source
from app.core.jobs import Failure, LostExecution, Result, Retry, Runner, Task


def _process_crash(database, instant):
    """Real abrupt death releases the OS lock while leaving the committed claim."""
    def crash(context, params):
        context.progress(1, total=2, checkpoint={"next": 1})
        os._exit(17)

    runner = Runner([Task("crash", crash)], database=Path(database),
                    clock=lambda: datetime.fromisoformat(instant))
    runner.run_next()


def _process_hold(database, ready, release):
    def hold(context, params):
        ready.set()
        if not release.wait(15):
            raise RuntimeError("Synthetic worker timeout")
        return Result()

    Runner([Task("hold", hold)], database=Path(database)).run_next()


class Parameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    page: int = Field(ge=0, le=10)


class JobTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        override = patch.object(settings, "data_dir", Path(directory.name))
        override.start()
        self.addCleanup(override.stop)
        db.init_db()
        self.now = datetime(2026, 11, 26, 16, tzinfo=timezone.utc)

    def runner(self, handler=lambda c, p: Result(), **policy):
        return Runner([Task("test", handler, **policy)], clock=lambda: self.now)

    def advance(self, seconds=86400):
        self.now += timedelta(seconds=seconds)

    def source(self, enabled=True):
        source = Source(source_id="synthetic", name="Synthetic", source_class="publisher",
                        access_method="api", terms_status="approved", terms_reviewed_on="2026-11-26",
                        terms_reference="Synthetic local review", rate_limit_notes="One bounded synthetic unit",
                        collection_enabled=enabled)
        evidence.save_source(source)
        return source

    def test_registration_and_parameters_fail_closed(self):
        runner = self.runner(params_type=Parameters)
        with self.assertRaises(KeyError):
            runner.enqueue("os.system", "work")
        for params in ({"page": -1}, {"page": "1"}, {"page": 1, "command": "anything"}):
            with self.subTest(params=params), self.assertRaises(ValidationError):
                runner.enqueue("test", "work", params)
        job = runner.enqueue("test", "work", {"page": 1})
        self.assertEqual(json.loads(runner.get(job)["params"]), {"page": 1})
        self.assertIsNotNone(runner.run_next())
        self.assertEqual(runner.get(job)["state"], "succeeded")

    def test_invalid_policy_and_bounded_metadata(self):
        for policy in ({"max_attempts": 0}, {"max_attempts": 11}, {"retry_seconds": 0},
                       {"retry_seconds": True}, {"source_id": "synthetic"}, {"access_method": "api"}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                self.runner(**policy)
        with self.assertRaises(ValueError):
            Runner([Task("same", lambda c, p: Result()), Task("same", lambda c, p: Result())])
        for key in ("", "../path", "x" * 257):
            with self.assertRaises(ValueError):
                self.runner().enqueue("test", key)
        with self.assertRaises(ValueError):
            self.runner().enqueue("test", "valid", {"unexpected": "x"})

    def test_enqueue_race_and_repeated_execution_are_idempotent(self):
        calls = []
        runner = self.runner(lambda c, p: calls.append(c.run_id) or Result())
        with ThreadPoolExecutor(max_workers=6) as pool:
            identities = list(pool.map(lambda _: runner.enqueue("test", "same"), range(12)))
        self.assertEqual(len(set(identities)), 1)
        with ThreadPoolExecutor(max_workers=6) as pool:
            executions = list(pool.map(lambda _: runner.run_next(), range(12)))
        self.assertEqual(len([run for run in executions if run]), 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(runner.enqueue("test", "same"), identities[0])
        self.assertIsNone(runner.run_next())
        self.assertEqual(runner.get(identities[0])["attempts"], 1)

    def test_identity_conflicts_and_terminal_work_are_not_reset(self):
        runner = self.runner(params_type=Parameters)
        job = runner.enqueue("test", "revision-1", {"page": 1})
        with self.assertRaises(evidence.EvidenceConflict):
            runner.enqueue("test", "revision-1", {"page": 2})
        changed = self.runner(params_type=Parameters, version="2")
        with self.assertRaises(evidence.EvidenceConflict):
            changed.enqueue("test", "revision-1", {"page": 1})
        runner.cancel(job)
        self.assertEqual(runner.enqueue("test", "revision-1", {"page": 1}), job)
        self.assertEqual(runner.get(job)["state"], "cancelled")
        self.assertNotEqual(runner.enqueue("test", "revision-2", {"page": 1}), job)

    def test_removed_or_changed_registration_cannot_dispatch_saved_work(self):
        for tasks in ([], [Task("test", lambda c, p: self.fail("Changed handler ran"), version="2")]):
            runner = self.runner()
            job = runner.enqueue("test", "case-" + str(len(tasks)))
            new = Runner(tasks, clock=lambda: self.now)
            run = new.run_next()
            self.assertEqual(new.get(job)["state"], "failed")
            self.assertEqual(new.get(job)["error_code"], "task_unavailable")
            self.assertEqual(new.runs(job)[0]["id"], run)
            self.assertIsNone(new.run_next())

    def test_retry_bounds_backoff_and_distinct_execution_ids(self):
        def retry(context, params):
            raise Retry(Failure.RATE_LIMIT)

        runner = self.runner(retry, max_attempts=3, retry_seconds=2)
        job = runner.enqueue("test", "retry")
        first = runner.run_next()
        self.assertIsNone(runner.run_next())
        self.advance(2)
        second = self.runner(retry, max_attempts=3, retry_seconds=2).run_next()
        self.advance(3)
        self.assertIsNone(runner.run_next())
        self.advance(1)
        third = runner.run_next()
        self.assertEqual(len({first, second, third}), 3)
        self.assertEqual(runner.get(job)["state"], "failed")
        self.assertEqual(runner.get(job)["attempts"], 3)
        self.assertEqual([r["attempt"] for r in runner.runs(job)], [1, 2, 3])
        self.assertIsNone(runner.get(job)["last_retrieval_at"])
        self.assertIsNone(runner.get(job)["coverage_checkpoint"])
        self.advance()
        self.assertIsNone(runner.run_next())

    def test_unexpected_exceptions_do_not_retry_or_persist_private_text(self):
        def fail(context, params):
            raise RuntimeError("synthetic-secret source content")

        runner = self.runner(fail)
        job = runner.enqueue("test", "failure")
        runner.run_next()
        self.assertEqual(runner.get(job)["error_code"], "handler_error")
        self.assertEqual(runner.get(job)["attempts"], 1)
        self.assertNotIn("synthetic-secret", repr(runner.get(job)) + repr(runner.runs(job)))
        self.assertIsNone(runner.run_next())

    def test_cancel_queued_and_backing_off_work(self):
        runner = self.runner(lambda c, p: (_ for _ in ()).throw(Retry()))
        queued = runner.enqueue("test", "queued")
        self.assertTrue(runner.cancel(queued))
        self.assertFalse(runner.cancel(queued))
        self.assertEqual(runner.runs(queued), [])
        retrying = runner.enqueue("test", "retrying")
        runner.run_next()
        self.assertTrue(runner.cancel(retrying))
        self.advance()
        self.assertIsNone(runner.run_next())
        self.assertEqual(runner.get(retrying)["state"], "cancelled")

    def test_cancel_running_at_boundary_and_on_return(self):
        for boundary in (True, False):
            entered, release = threading.Event(), threading.Event()
            called = []

            def handler(context, params):
                entered.set()
                if not release.wait(5):
                    raise RuntimeError("Synthetic timeout")
                if boundary:
                    context.check()
                called.append("returned")
                return Result(coverage={"end": 2})

            runner = self.runner(handler)
            job = runner.enqueue("test", "cancel-" + str(boundary))
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(runner.run_next)
                try:
                    self.assertTrue(entered.wait(5))
                    self.assertTrue(runner.cancel(job))
                finally:
                    release.set()
                future.result(5)
            self.assertEqual(runner.get(job)["state"], "cancelled")
            self.assertEqual(runner.runs(job)[0]["state"], "cancelled")
            self.assertIsNone(runner.get(job)["coverage_checkpoint"])
            self.assertEqual(called, [] if boundary else ["returned"])

    def test_stalled_handler_cannot_be_reclaimed_by_second_runner(self):
        entered, release = threading.Event(), threading.Event()

        def handler(context, params):
            entered.set()
            release.wait(5)
            return Result()

        runner = self.runner(handler)
        job = runner.enqueue("test", "held")
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(runner.run_next)
            try:
                self.assertTrue(entered.wait(5))
                self.advance(864000)
                self.assertIsNone(self.runner().run_next())
                self.assertEqual(runner.get(job)["state"], "running")
                self.assertEqual(len(runner.runs(job)), 1)
            finally:
                release.set()
            future.result(5)
        self.assertEqual(runner.get(job)["state"], "succeeded")

    def test_real_process_crash_recovery_preserves_progress_and_attempt_budget(self):
        def resume(context, params):
            saved = context.check()
            self.assertEqual(json.loads(saved["checkpoint"]), {"next": 1})
            self.assertEqual(saved["progress_done"], 1)
            context.progress(2, total=2, checkpoint={"next": 2})
            return Result(coverage={"end": 2})

        runner = Runner([Task("crash", resume)], clock=lambda: self.now)
        job = runner.enqueue("crash", "page-window")
        child = multiprocessing.get_context("spawn").Process(
            target=_process_crash, args=(str(settings.db_path), self.now.isoformat()))
        child.start()
        child.join(15)
        if child.is_alive():
            child.terminate()
            child.join(5)
            self.fail("Synthetic crash process timed out")
        self.assertEqual(child.exitcode, 17)
        self.assertEqual(runner.get(job)["state"], "running")
        self.assertIsNone(runner.run_next())  # recovery persists bounded backoff
        self.assertEqual(runner.runs(job)[0]["state"], "interrupted")
        self.advance(30)
        runner.run_next()
        self.assertEqual(runner.get(job)["state"], "succeeded")
        self.assertEqual(runner.get(job)["attempts"], 2)
        self.assertEqual(json.loads(runner.get(job)["coverage_checkpoint"]), {"end": 2})

    def test_independent_process_cannot_claim_live_execution(self):
        runner = Runner([Task("hold", lambda c, p: self.fail("Duplicate handler"))])
        job = runner.enqueue("hold", "one")
        process_context = multiprocessing.get_context("spawn")
        ready, release = process_context.Event(), process_context.Event()
        child = process_context.Process(target=_process_hold, args=(str(settings.db_path), ready, release))
        child.start()
        try:
            self.assertTrue(ready.wait(10))
            self.assertIsNone(runner.run_next())
            self.assertEqual(runner.get(job)["attempts"], 1)
        finally:
            release.set()
            child.join(15)
            if child.is_alive():
                child.terminate()
                child.join(5)
        self.assertEqual(child.exitcode, 0)
        self.assertEqual(runner.get(job)["state"], "succeeded")

    def test_repeated_interruption_exhausts_attempts_and_cancelled_recovery_wins(self):
        def crash(context, params):
            raise KeyboardInterrupt()

        runner = self.runner(crash, max_attempts=2, retry_seconds=1)
        job = runner.enqueue("test", "crash-loop")
        for attempt in (1, 2):
            with self.assertRaises(KeyboardInterrupt):
                runner.run_next()
            self.assertIsNone(runner.run_next())
            self.advance(1)
        self.assertEqual(runner.get(job)["state"], "failed")
        self.assertEqual([r["state"] for r in runner.runs(job)], ["interrupted", "interrupted"])
        job = runner.enqueue("test", "cancel-interrupted")
        with self.assertRaises(KeyboardInterrupt):
            runner.run_next()
        runner.cancel(job)
        self.assertIsNone(runner.run_next())
        self.assertEqual(runner.get(job)["state"], "cancelled")

    def test_source_gate_before_enqueue_claim_each_unit_and_retry(self):
        def handler(context, params):
            context.progress(1, checkpoint={"saved": True})
            evidence.save_source(self.source(False))
            context.check()
            self.fail("Revoked source continued")

        runner = self.runner(handler, source_id="synthetic", access_method="api")
        with self.assertRaises(PermissionError):
            runner.enqueue("test", "unknown")
        self.source()
        job = runner.enqueue("test", "revoked-between-units")
        runner.run_next()
        self.assertEqual(runner.get(job)["error_code"], "source_ineligible")
        self.assertEqual(runner.get(job)["progress_done"], 1)
        self.source()
        job = runner.enqueue("test", "revoked-in-queue")
        self.source(False)
        runner.run_next()
        self.assertEqual(runner.get(job)["error_code"], "source_ineligible")
        self.source()
        retry = self.runner(lambda c, p: (_ for _ in ()).throw(Retry()), source_id="synthetic", access_method="api")
        job = retry.enqueue("test", "revoked-before-retry")
        retry.run_next()
        self.source(False)
        self.advance(30)
        retry.run_next()
        self.assertEqual(retry.get(job)["error_code"], "source_ineligible")
        self.assertEqual(retry.get(job)["attempts"], 2)

    def test_successful_retrieval_survives_failure_without_claiming_coverage(self):
        def partial(context, params):
            if context.check()["attempts"] == 1:
                context.retrieved()
                context.progress(1, total=2, checkpoint={"next": 1})
            raise Retry(Failure.INVALID_RESPONSE)

        runner = self.runner(partial, max_attempts=2)
        job = runner.enqueue("test", "partial")
        runner.run_next()
        first = runner.get(job)
        self.advance(30)
        runner.run_next()
        failed = runner.get(job)
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(failed["last_retrieval_at"], first["last_retrieval_at"])
        self.assertNotEqual(failed["last_attempt_at"], first["last_attempt_at"])
        self.assertIsNone(failed["coverage_checkpoint"])
        self.assertIsNone(failed["coverage_completed_at"])
        self.assertEqual(json.loads(failed["checkpoint"]), {"next": 1})

    def test_success_without_coverage_and_unfinished_coverage_guard(self):
        def handler(context, params):
            context.progress(1, total=2, checkpoint={"next": 1})
            return Result(coverage={"end": 2})

        runner = self.runner(handler)
        job = runner.enqueue("test", "unfinished")
        runner.run_next()
        self.assertEqual(runner.get(job)["state"], "failed")
        self.assertIsNone(runner.get(job)["coverage_checkpoint"])
        runner = self.runner()
        job = runner.enqueue("test", "no-coverage-assertion")
        runner.run_next()
        self.assertEqual(runner.get(job)["state"], "succeeded")
        self.assertIsNone(runner.get(job)["last_retrieval_at"])
        self.assertIsNone(runner.get(job)["coverage_checkpoint"])

    def test_evidence_replay_after_crash_between_writes_uses_original_capture_run(self):
        ids, documents, contexts = [], [], []

        def handler(context, params):
            contexts.append(context)
            saved = context.document("capture-1", lambda: Document(
                source_id="synthetic", external_id="advisory", capture_key="stable-capture",
                title="Synthetic", collection_method="local_import", collected_at=self.now.isoformat()))
            documents.append(saved)
            ident = evidence.record_document(saved)
            ids.append(ident)
            if len(ids) == 1:
                raise KeyboardInterrupt()
            evidence.record_observation(Observation(document_id=ident, observation_key="mention-1",
                                                    subject_type="domain", subject_value="example.invalid"))
            evidence.record_citation(Citation(document_id=ident, citation_key="citation-1",
                                             target_reference="Unresolved synthetic citation"))
            context.progress(1, total=1, checkpoint={"done": True})
            return Result(coverage={"capture": "stable-capture"})

        runner = self.runner(handler)
        job = runner.enqueue("test", "capture")
        with self.assertRaises(KeyboardInterrupt):
            runner.run_next()
        runner.run_next()
        self.advance(30)
        runner.run_next()
        self.assertEqual(ids[0], ids[1])
        self.assertEqual(documents[0], documents[1])
        runs = runner.runs(job)
        self.assertNotEqual(runs[0]["id"], runs[1]["id"])
        self.assertEqual(documents[1].job_run_id, runs[0]["id"])
        self.assertEqual(len(evidence.observations_for_subject("domain", "example.invalid")), 1)
        self.assertEqual(len(evidence.citations_for_document(ids[0])), 1)
        with self.assertRaises(LostExecution):
            contexts[0].progress(2, checkpoint={})
        self.assertEqual(runner.get(job)["state"], "succeeded")

    def test_progress_and_capture_budgets_fail_closed(self):
        for action in (lambda c: c.progress(1, checkpoint={"x": "x" * 8192}),
                       lambda c: c.progress(True, checkpoint={}),
                       lambda c: c.progress(1, total=0, checkpoint={}),
                       lambda c: c.progress(1, checkpoint={"n": float("nan")}),
                       lambda c: c.document("../source-path", lambda: None)):
            runner = self.runner(lambda c, p: action(c) or Result())
            job = runner.enqueue("test", "budget-" + str(id(action)))
            runner.run_next()
            self.assertEqual(runner.get(job)["state"], "failed")
            self.assertEqual(runner.get(job)["progress_done"], 0)

    def test_progress_replay_cannot_erase_total_or_skip_backwards(self):
        def handler(context, params):
            context.progress(1, total=2, checkpoint={"next": 1})
            context.progress(1, checkpoint={"next": 1})
            self.assertEqual(context.check()["progress_total"], 2)
            for done, total in ((0, 2), (3, None), (1, 3)):
                with self.assertRaises(ValueError):
                    context.progress(done, total=total, checkpoint={})
            context.progress(2, checkpoint={"next": 2})
            return Result(coverage={"end": 2})

        runner = self.runner(handler)
        job = runner.enqueue("test", "fixed-scope")
        runner.run_next()
        self.assertEqual(runner.get(job)["state"], "succeeded")
        self.assertEqual(runner.get(job)["progress_total"], 2)

    def test_source_revocation_is_checked_on_restart_recovery(self):
        def crash(context, params):
            raise KeyboardInterrupt()

        self.source()
        runner = self.runner(crash, source_id="synthetic", access_method="api")
        job = runner.enqueue("test", "restart-source")
        with self.assertRaises(KeyboardInterrupt):
            runner.run_next()
        self.source(False)
        resumed = self.runner(lambda c, p: self.fail("Revoked source ran"), source_id="synthetic", access_method="api")
        resumed.run_next()
        self.advance(30)
        resumed.run_next()
        self.assertEqual(resumed.get(job)["error_code"], "source_ineligible")
        self.assertEqual([r["state"] for r in resumed.runs(job)], ["interrupted", "failed"])

    def test_completed_coverage_is_retained_when_new_work_fails(self):
        successful = self.runner(lambda c, p: c.retrieved() or Result(coverage={"end": 1}))
        old = successful.enqueue("test", "window-1")
        successful.run_next()
        saved = successful.get(old)
        self.advance()
        failed = self.runner(lambda c, p: (_ for _ in ()).throw(Retry()), max_attempts=1)
        newer = failed.enqueue("test", "window-2")
        failed.run_next()
        self.assertEqual(failed.get(newer)["state"], "failed")
        self.assertIsNone(failed.get(newer)["coverage_checkpoint"])
        self.assertEqual(successful.get(old), saved)

    def test_startup_wal_retry_handles_busy_only_and_has_a_deadline(self):
        from unittest.mock import Mock

        busy = sqlite3.OperationalError("Synthetic busy")
        busy.sqlite_errorcode = sqlite3.SQLITE_BUSY
        connection = Mock()
        connection.execute.side_effect = [busy, None]
        with patch.object(db.time, "sleep") as sleep:
            db._enable_wal(connection)
        sleep.assert_called_once_with(0.05)
        connection.execute.side_effect = busy
        with patch.object(db.time, "monotonic", side_effect=[0, 6]), self.assertRaises(sqlite3.OperationalError):
            db._enable_wal(connection)
        connection.execute.side_effect = sqlite3.OperationalError("Synthetic non-lock error")
        with self.assertRaises(sqlite3.OperationalError):
            db._enable_wal(connection)

    def test_foreign_keys_and_unique_active_run(self):
        runner = self.runner()
        job = runner.enqueue("test", "constraint")
        with evidence.connect() as conn, conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO durable_job_runs VALUES ('bad','missing',1,'running','now',NULL,NULL)")
            conn.execute("INSERT INTO durable_job_runs VALUES ('one',?,1,'running','now',NULL,NULL)", (job,))
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("INSERT INTO durable_job_runs VALUES ('two',?,2,'running','now',NULL,NULL)", (job,))

    def test_migration_is_atomic_repeatable_and_rejects_newer_schema(self):
        with db.connect() as conn, conn:
            conn.execute("DROP TABLE durable_job_documents")
            conn.execute("DROP TABLE durable_job_runs")
            conn.execute("DROP TABLE durable_jobs")
            conn.execute("DROP TABLE job_schema_versions")
        with db.connect() as conn:
            broken = job_schema.VERSION_1 + "; INSERT INTO missing_table VALUES (1);"
            with patch.object(job_schema, "MIGRATIONS", ((1, broken),)):
                with self.assertRaises(sqlite3.OperationalError):
                    job_schema.migrate(conn)
            self.assertIsNone(conn.execute("SELECT name FROM sqlite_master WHERE name='durable_jobs'").fetchone())
            job_schema.migrate(conn)
            job_schema.migrate(conn)
            with conn:
                conn.execute("INSERT INTO job_schema_versions VALUES (99,'future')")
            with self.assertRaisesRegex(RuntimeError, "newer job schema"):
                job_schema.migrate(conn)


if __name__ == "__main__":
    unittest.main()
