"""Opt-in durable runner for trusted, bounded synchronous application handlers.

No built-in tasks, scheduler, HTTP client, dynamic imports or startup worker.
Call run_next() in a worker thread. It executes at most one job and never
sleeps for backoff. One OS-held executor lock per local database prevents a
live/stalled handler being reclaimed merely because a lease expired.
"""

from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import inspect
import re
import sqlite3
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from .config import settings
from .evidence import EvidenceConflict, require_collection
from .evidence_models import Document
from .job_lock import executor_lock


class EmptyParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Failure(str, Enum):
    TRANSIENT = "transient"
    RATE_LIMIT = "rate_limit"
    INVALID_RESPONSE = "invalid_response"


class Retry(Exception):
    """Only these fixed codes are persisted. Exception/source text is not logged."""

    def __init__(self, code: Failure = Failure.TRANSIENT, *, after_seconds: int = 0):
        self.code = Failure(code)
        _integer(after_seconds, 0, 31536000)
        self.after_seconds = after_seconds
        super().__init__(self.code.value)


class Cancelled(Exception):
    """Cancellation observed at a cooperative work boundary."""


class LostExecution(RuntimeError):
    """This context no longer owns a running execution."""


@dataclass(frozen=True)
class Result:
    # A completed execution alone does not assert complete source coverage.
    coverage: dict | None = None


@dataclass(frozen=True)
class Task:
    name: str
    handler: Callable
    version: str = "1"
    params_type: type[BaseModel] = EmptyParams
    source_id: str | None = None
    access_method: str | None = None
    max_attempts: int = 3
    retry_seconds: int = 30

    def __post_init__(self):
        _key(self.name, 128)
        _key(self.version, 64)
        if (not callable(self.handler) or inspect.iscoroutinefunction(self.handler)
                or inspect.isasyncgenfunction(self.handler) or not isinstance(self.params_type, type)
                or not issubclass(self.params_type, BaseModel)):
            raise ValueError("Register a callable and an explicit parameter model")
        _integer(self.max_attempts, 1, 10)
        _integer(self.retry_seconds, 1, 86400)
        if (self.source_id is None) != (self.access_method is None):
            raise ValueError("Source and method must be registered together")
        if self.source_id is not None:
            _key(self.source_id, 128)
            if self.access_method not in {"api", "feed", "public_page", "manual"}:
                raise ValueError("Unknown source access method")

    def policy(self):
        return (self.version, self.source_id, self.access_method, self.max_attempts, self.retry_seconds)


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Integer outside permitted bounds")


def _key(value, limit=256):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]*", value) or len(value) > limit:
        raise ValueError("Use a bounded application-generated identity")
    return value


def _json(value, limit=8192):
    if not isinstance(value, dict):
        raise ValueError("Checkpoint/parameters must be a JSON object")
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(text.encode("utf-8")) > limit:
        raise ValueError("Job metadata exceeds its byte budget")
    return text


class Runner:
    def __init__(self, tasks: list[Task], *, database: Path | None = None,
                 clock: Callable[[], datetime] | None = None):
        self.database = (database or settings.db_path).resolve()
        self._tasks = {task.name: task for task in tasks}
        if len(self._tasks) != len(tasks):
            raise ValueError("Task names must be unique")
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self):
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Runner clock requires an aware timestamp")
        return now.astimezone(timezone.utc)

    @staticmethod
    def _stamp(now):
        return now.isoformat(timespec="microseconds")

    @contextmanager
    def _connect(self, *, write=False):
        # Each operation owns its connection, including cancellation from a
        # second thread. No transaction spans a handler or provider request.
        conn = sqlite3.connect(self.database, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            with conn:
                if write:
                    conn.execute("BEGIN IMMEDIATE")
                yield conn
        finally:
            conn.close()

    def get(self, job_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM durable_jobs WHERE id=?", (job_id,)).fetchone()
            return dict(row) if row else None

    def runs(self, job_id: str) -> list[dict]:
        with self._connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM durable_job_runs WHERE job_id=? ORDER BY attempt", (job_id,))]

    def enqueue(self, task_name: str, work_key: str, params: Mapping | None = None) -> str:
        """Trusted callers supply logical scope/revision keys, never report instructions.

        The same task/work_key always returns the same job, even after success,
        cancellation or exhausted retries. A new scope requires a new key.
        """
        task = self._tasks[task_name]  # unknown work fails closed
        _key(work_key)
        values = task.params_type.model_validate(dict(params or {}), strict=True)
        encoded = _json(values.model_dump(mode="json"))
        now = self._stamp(self._now())
        with self._connect(write=True) as conn:
            row = conn.execute("SELECT * FROM durable_jobs WHERE task=? AND work_key=?",
                               (task_name, work_key)).fetchone()
            if row:
                if row["params"] != encoded or self._policy(row) != task.policy():
                    raise EvidenceConflict("Logical work identity already has different parameters/policy")
                return row["id"]
            self._eligible(conn, task.source_id, task.access_method)
            ident = uuid4().hex
            conn.execute("""INSERT INTO durable_jobs
                (id, task, task_version, work_key, params, source_id, access_method,
                 max_attempts, retry_seconds, state, created_at, available_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)""",
                         (ident, task_name, task.version, work_key, encoded,
                          task.source_id, task.access_method, task.max_attempts, task.retry_seconds, now, now))
            return ident

    @staticmethod
    def _policy(row):
        return tuple(row[key] for key in ("task_version", "source_id", "access_method", "max_attempts", "retry_seconds"))

    @staticmethod
    def _eligible(conn, source_id, method):
        if source_id is None:
            return
        require_collection(source_id, method, connection=conn)

    def cancel(self, job_id: str) -> bool:
        now = self._stamp(self._now())
        with self._connect(write=True) as conn:
            changed = conn.execute("""UPDATE durable_jobs SET cancel_requested=1,
                state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END,
                completed_at=CASE WHEN state='queued' THEN ? ELSE completed_at END
                WHERE id=? AND state IN ('queued','running')""", (now, job_id))
            return bool(changed.rowcount)

    def _owned(self, conn, run_id, *, allow_cancel=False):
        row = conn.execute("""SELECT j.* FROM durable_jobs j JOIN durable_job_runs r ON r.job_id=j.id
            WHERE r.id=? AND r.state='running' AND j.state='running'""", (run_id,)).fetchone()
        if not row:
            raise LostExecution("Execution is no longer running")
        if row["cancel_requested"] and not allow_cancel:
            raise Cancelled()
        return row

    def _finish(self, conn, run_id, outcome, code=None, coverage=None, after_seconds=0):
        row = self._owned(conn, run_id, allow_cancel=True)
        now = self._now()
        stamp = self._stamp(now)
        if row["cancel_requested"] or outcome == "cancelled":
            state, outcome, code = "cancelled", "cancelled", None
        elif outcome == "succeeded":
            state = "succeeded"
        elif outcome in {"failed", "interrupted"}:
            state = "queued" if row["attempts"] < row["max_attempts"] else "failed"
        else:
            raise ValueError("Invalid execution outcome")
        conn.execute("UPDATE durable_job_runs SET state=?, finished_at=?, error_code=? WHERE id=?",
                     (outcome, stamp, code, run_id))
        delay = max(after_seconds, min(86400, row["retry_seconds"] * 2 ** (row["attempts"] - 1)))
        conn.execute("""UPDATE durable_jobs SET state=?, error_code=?, available_at=?, completed_at=?,
            coverage_checkpoint=CASE WHEN ? THEN ? ELSE coverage_checkpoint END,
            coverage_completed_at=CASE WHEN ? THEN ? ELSE coverage_completed_at END WHERE id=?""",
                     (state, code, self._stamp(now + timedelta(seconds=delay)) if state == "queued" else stamp,
                      None if state == "queued" else stamp,
                      state == "succeeded" and coverage is not None, coverage,
                      state == "succeeded" and coverage is not None, stamp, row["id"]))

    def _recover(self, conn):
        # Only called while holding the process lock. A live runner, including
        # one stalled on IO, cannot lose ownership through a clock timeout.
        for row in conn.execute("SELECT id FROM durable_job_runs WHERE state='running'").fetchall():
            self._finish(conn, row["id"], "interrupted", "interrupted")

    def run_next(self, *, registered_only=False) -> str | None:
        """Recover abandoned executions, then claim at most one due job.

        None means busy/no due work. An unhandled BaseException leaves its run
        interrupted for recovery. Ordinary exceptions fail closed without
        saving their text; only explicit Retry requests consume retry policy.
        """
        with executor_lock(self.database) as acquired:
            if not acquired:
                return None
            with self._connect(write=True) as conn:
                self._recover(conn)
                selection = ""
                values = [self._stamp(self._now())]
                if registered_only:
                    selection = " AND task IN (" + ",".join("?" for _ in self._tasks) + ")"
                    values.extend(self._tasks)
                row = conn.execute("SELECT * FROM durable_jobs WHERE state='queued' AND available_at<=?" + selection +
                                   " ORDER BY available_at, created_at, id LIMIT 1", values).fetchone()
                if row is None:
                    return None
                run_id = uuid4().hex
                now = self._stamp(self._now())
                conn.execute("""UPDATE durable_jobs SET state='running', attempts=attempts+1,
                    last_attempt_at=?, error_code=NULL WHERE id=?""", (now, row["id"]))
                conn.execute("INSERT INTO durable_job_runs(id,job_id,attempt,state,started_at) VALUES (?,?,?,'running',?)",
                             (run_id, row["id"], row["attempts"] + 1, now))
            context = Context(self, run_id)
            try:
                task = self._tasks.get(row["task"])
                if task is None or task.policy() != self._policy(row):
                    self._terminal(run_id, "task_unavailable")
                    return run_id
                params = task.params_type.model_validate_json(row["params"], strict=True)
                context.check()
                result = task.handler(context, params)
                if not isinstance(result, Result):
                    raise TypeError("Handlers must return Result")
                coverage = _json(result.coverage) if result.coverage is not None else None
                context.check()
                with self._connect(write=True) as conn:
                    owned = self._owned(conn, run_id)
                    if coverage is not None and owned["progress_total"] is not None and owned["progress_done"] != owned["progress_total"]:
                        raise ValueError("Coverage cannot complete unfinished progress")
                    self._finish(conn, run_id, "succeeded", coverage=coverage)
            except Cancelled:
                with self._connect(write=True) as conn:
                    self._finish(conn, run_id, "cancelled")
            except Retry as exc:
                with self._connect(write=True) as conn:
                    self._finish(conn, run_id, "failed", exc.code.value, after_seconds=exc.after_seconds)
            except PermissionError:
                self._terminal(run_id, "source_ineligible")
            except Exception:
                self._terminal(run_id, "handler_error")
            return run_id

    def _terminal(self, run_id, code):
        with self._connect(write=True) as conn:
            row = self._owned(conn, run_id, allow_cancel=True)
            # Non-retryable failure does not spend fake attempts to exhaust a budget.
            stamp = self._stamp(self._now())
            state = "cancelled" if row["cancel_requested"] else "failed"
            code = None if state == "cancelled" else code
            conn.execute("UPDATE durable_job_runs SET state=?, finished_at=?, error_code=? WHERE id=?",
                         (state, stamp, code, run_id))
            conn.execute("UPDATE durable_jobs SET state=?, completed_at=?, error_code=? WHERE id=?",
                         (state, stamp, code, row["id"]))


class Context:
    """Valid only during its handler invocation. Do not spawn detached work."""

    def __init__(self, runner: Runner, run_id: str):
        self._runner = runner
        self.run_id = run_id

    def check(self) -> dict:
        """Check ownership, cancellation and current source eligibility per unit."""
        with self._runner._connect() as conn:
            row = self._runner._owned(conn, self.run_id)
            self._runner._eligible(conn, row["source_id"], row["access_method"])
            return dict(row)

    def progress(self, done: int, *, total: int | None = None, checkpoint: dict):
        _integer(done, 0, 2**63 - 1)
        if total is not None:
            _integer(total, done, 2**63 - 1)
        encoded = _json(checkpoint)
        self.check()
        with self._runner._connect(write=True) as conn:
            row = self._runner._owned(conn, self.run_id)
            if done < row["progress_done"]:
                raise ValueError("Committed progress cannot move backwards")
            if row["progress_total"] is not None:
                if total is not None and total != row["progress_total"]:
                    raise ValueError("Logical work cannot change its established total")
                total = row["progress_total"]
                _integer(done, 0, total)
            conn.execute("UPDATE durable_jobs SET progress_done=?, progress_total=?, checkpoint=? WHERE id=?",
                         (done, total, encoded, row["id"]))

    def retrieved(self):
        """Adapter calls only after a validated retrieval, never on an attempt."""
        self.check()
        with self._runner._connect(write=True) as conn:
            row = self._runner._owned(conn, self.run_id)
            conn.execute("UPDATE durable_jobs SET last_retrieval_at=? WHERE id=?",
                         (self._runner._stamp(self._runner._now()), row["id"]))

    def document(self, slot: str, prepare: Callable[[], Document]) -> Document:
        """Persist capture metadata BEFORE ingestion. Replay its original run/time.

        The trusted factory runs only for a new slot. Use a different slot for
        changed input; it must not fetch/execute anything or store raw bodies.
        Call evidence.record_document() with the returned immutable snapshot.
        """
        _key(slot)
        self.check()
        with self._runner._connect(write=True) as conn:
            job = self._runner._owned(conn, self.run_id)
            row = conn.execute("SELECT document FROM durable_job_documents WHERE job_id=? AND slot=?",
                               (job["id"], slot)).fetchone()
            if row:
                return Document.model_validate_json(row["document"])
            count = conn.execute("SELECT count(*) FROM durable_job_documents WHERE job_id=?", (job["id"],)).fetchone()[0]
            if count >= 200:
                raise ValueError("Split work into jobs of at most 200 captures")
            document = prepare()
            if not isinstance(document, Document):
                raise TypeError("Prepare must return validated Document metadata")
            document = Document(**{**document.model_dump(), "job_run_id": self.run_id})
            if job["source_id"] and document.source_id != job["source_id"]:
                raise ValueError("Document source differs from registered work")
            conn.execute("INSERT INTO durable_job_documents VALUES (?, ?, ?)",
                         (job["id"], slot, _json(document.model_dump(), 32768)))
            return document
