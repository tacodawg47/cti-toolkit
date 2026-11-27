# Durable Job Runner

Update 2026-11-27, 3A.6: [Indexed Cloud Leads](cloud-exposure.md) freezes
exact permissions and two search-page slots per domain. Original normalized
staging and atomic inbox ingestion recover without refetching. Durable
consumer-local monthly credit reservations and one-second request slots
survive restart; query/access changes invalidate queued authority. No new loop.


Update 2026-11-27, 3A.5: [Passive Subdomain Inventory](subdomain-inventory.md)
freezes exact-domain permissions and two page slots. It reuses logical-unit
progress, original staged input and atomic inbox ingestion. Successful quota
cooldowns persist before recoverable staging. No new worker or loop.

Update 2026-11-27: [GitHub Public-Code Leads](github-exposure.md) freezes
exact permission IDs and two page slots per selector. Token/API/query-version
changes invalidate old authority. Original staged input and committed pages
survive restart. Its explicit Scope.unit_progress option tracks logical
queries independently of captured-response counts; other feeds keep the
default capture-count behavior. No extra worker or loop is introduced.

Update 2026-11-27: [CT Lookalike Watches](ct-lookalike-watches.md) snapshots
immutable submission permissions, including pattern content/version and
matcher version. Bounded normalized input resumes under the original capture
and execution. Completed units repair progress without another request.
This adds no separate worker and grants no source eligibility.

Update 2026-11-26: [Alert Inbox](alert-inbox.md) displays the originating
capture execution separately from its logical job's current state. Foundation
integration tests crash after alert creation and before ingestion progress,
then verify restart replay retains the original run and review state.

Update 2026-11-26: [Saved Reports and Archives](saved-reports-and-archives.md)
registers explicit opt-in saved-report bulk jobs using the same app-loop
bridge, provider quotas and OS execution lock. Committed units resume without
moving progress backwards. Its worker and all provider reviews default off.

Update 2026-11-26: 5F.3 adds opt-in production feed registrations and a
durable scheduler. See [Scheduled Feeds](scheduled-feeds.md). The original
5F.2 scope and contracts below remain historical. `Retry` now accepts an
optional bounded `after_seconds` to honor persisted provider cooldowns.
`run_next(registered_only=True)` limits a worker to its registered tasks.
The feed worker submits coroutines to the existing app loop and drains
active saves before shutdown. All schedules and its worker default off.

Written 2026-11-26. Subphase 5F.2. No new dependency. This is an opt-in core
API with no registered production tasks, startup worker, scheduler or routes.
Normal approved startup adds its tables through `db.init_db()`. Tests use
temporary databases. The live database has not been migrated in this pass.

## Existing Patterns and Compatibility

The vendor changed-window queue, NVD pending/completed windows and metadata
backfill queue retain their current ownership. They have separate coverage
semantics and are not backfilled into generic jobs. Existing refresh routes
and in-memory async locks remain unchanged. Shared database access opens a
short-lived connection per operation. The new runner uses that same pattern
with foreign keys and serialized write transactions. No transaction spans
a handler or provider request, except the metadata-only document factory
described below, which must never perform IO.

The existing vendor limiter uses async locks and an in-memory minute window
plus SQLite daily counts. It is not a thread-safe, multi-loop quota service.
Do not call it through a new event loop per synchronous job. 5F.3 must choose
and test one compatible async bridge or source-specific durable quota adapter
before wrapping existing feeds. Descriptive registry notes do not spend or
enforce quota. No rate limit is bypassed or newly applied by this subphase.

Concurrent fresh-file initialization exposed SQLite returning BUSY on the
WAL transition despite the connection timeout. Core startup now retries only
BUSY/LOCKED for that transition, with a five-second retry deadline and 50 ms
poll interval. Each SQLite call still has its existing five-second timeout.
Other errors propagate. Migration versions have their own atomic ledgers;
legacy `user_version`, rows and views are preserved.

## Register and Invoke Trusted Work

`app/core/jobs.py` supplies `Task`, `Runner`, `Context`, `Result`, `Retry`
and fixed `Failure` codes. Supply a list of explicitly constructed tasks to
`Runner`. No registry entries, source documents, import strings or serialized
callables are executed. Unknown task names fail closed. Source and method,
handler, parameter model, version and retry policy come from trusted code.
Parameter models should forbid extra fields and bound each accepted value.

The following shows the API for a local metadata-only handler. It is a
design example, not a command to run against the live database:

```python
import asyncio
import json
from app.core.jobs import Result, Runner, Task

def local_work(context, params):
    saved = context.check()
    checkpoint = json.loads(saved["checkpoint"])
    if not checkpoint.get("done"):
        # Commit all intended idempotent writes before advancing progress.
        context.progress(1, total=1, checkpoint={"done": True})
    return Result(coverage={"local_batch": "example-1"})

runner = Runner([Task("local-example", local_work)])
# These calls change the configured database. Obtain required approval first.
job_id = runner.enqueue("local-example", "example-1")
# Inside an async application, use its worker pool:
run_id = await asyncio.to_thread(runner.run_next)
```

Call `run_next()` in a worker thread, including future scheduler dispatch.
It claims at most one due job and returns its execution ID. `None` means
another executor holds the lock or no job is due. It never waits for retry
backoff. Scheduling/polling and UI wiring belong to 5F.3 and later consumers.
Call `enqueue`, `get`, `runs` and `cancel` off the async loop too.

Handlers must be synchronous, bounded and cooperative. Before **each**
bounded provider request or write unit, call `context.check()`. It checks
current ownership, cancellation and the 5F.1 `require_collection()` gate.
The runner checks at invocation and on successful return as well. Source
eligibility can be revoked after enqueue, during a job or before a retry.
Omitting source metadata is for local work only, never an escape for collection.

Every source handler must have fixed destinations or a validated, reviewed
destination policy in code. Source content cannot choose a task, callable,
command, filesystem path, destination, credential, approval or retry policy.
Validated remote pagination may supply passive cursors only inside that fixed
policy. Registration and source eligibility do not grant operator permission
for external transfers. No production handler or provider traffic was enabled.

## Identities and Checkpoints

| Identity or Field | Meaning |
|---|---|
| `(task, work_key)` | Unique logical work, such as an explicitly selected source/window/revision. Caller generates a bounded key. |
| `durable_jobs.id` | Stable local job ID. Duplicate enqueues return this ID, including terminal work. Conflicting parameters/policy raise `EvidenceConflict`. |
| `durable_job_runs.id` | New execution ID for each attempt, including interrupted attempts. |
| `task_version` and saved policy | Refuse dispatch if registration is absent or its version/source/method/retry policy changed. Bump the version when parameter or handler semantics change. |
| `last_attempt_at` | Latest execution claim, including one that fails before retrieval. |
| `last_retrieval_at` | Set only by `context.retrieved()` after an adapter validates retrieval. Preserved through later failures. |
| `progress_done`, `progress_total`, `checkpoint` | Committed ingestion progress. Counts never go backwards. A known total cannot be erased or changed for that logical scope. |
| `coverage_checkpoint`, `coverage_completed_at` | Set only on successful return with explicit `Result(coverage=...)`. A known total must be finished. |

Execution success without an explicit coverage checkpoint does not assert
complete source coverage or even a network retrieval. These fields describe
one job, not global source health. 5F.3 must preserve prior completed windows,
reconcile them by source, and expose incomplete/stale/failure states. New work
uses a new scope key. Re-enqueue never resets cancellation or retry exhaustion.
No arbitrary reset/retry button is provided in this API.

## Recovery, Claims and Cancellation

SQLite `BEGIN IMMEDIATE` serializes enqueues and claims. Unique constraints
reject duplicate logical work and multiple running attempts for one job.
A process-held OS file lock protects the entire `run_next()` invocation,
including the handler. It uses `msvcrt` on Windows and `flock` on Linux.
The lock file is `<database>.runner.lock`, resolved beside the database.
Do not delete, replace or clean it while any executor might exist.

One runner executes at a time per local database. A stalled handler retains
the lock, so another runner cannot execute overlapping work after a lease
timeout. Process death releases the OS lock. The next `run_next()` recovers
committed running attempts as interrupted, then saves backoff or terminal
failure according to the original attempt budget. It preserves progress,
capture metadata and retrieval/coverage checkpoints. There is no automatic
startup invocation until a later consumer explicitly starts dispatch.

This deliberately trades throughput for simple duplicate-execution control.
Use one canonical database path on a local filesystem. Network filesystems,
hard-link aliases, distributed workers and hostile local processes are outside
the contract. The lock is not an authorization or security boundary. Handlers
must not spawn detached threads, subprocess work or callbacks that survive
their invocation. Cancellation of an asyncio wait does not stop its thread:
request job cancellation and await the bounded handler's completion.

`runner.cancel(job_id)` immediately cancels queued/backoff work. Running work
sets a durable request observed at the next `check()` and on return. It does
not forcibly terminate a thread, retract an in-flight request or roll back
already committed evidence. Cancelled interrupted work is not retried.
Source request/body/time limits and quota waits must therefore be finite.

Only `Retry(Failure.TRANSIENT/RATE_LIMIT/INVALID_RESPONSE)` requests another
attempt. Other exceptions are terminal `handler_error`; revoked eligibility
is terminal `source_ineligible`; missing/changed registration is terminal
`task_unavailable`. Exception messages, provider bodies, keys and URLs are
never copied into job errors. Interpret fixed codes in future UI text.

The total attempt cap is 1 to 10, including first execution and interruptions.
The base retry delay is 1 to 86,400 seconds. Exponential delays double after
each failed/interrupted attempt and cap at 86,400 seconds. They persist in
`available_at` and are checked using aware UTC timestamps. Clock changes can
delay or accelerate when a retry becomes due; they cannot release an active
execution lock. Typed provider-specific Retry-After/quota policy is 5F.3 work.

## Evidence Replay and Bounds

Call `context.document(slot, prepare)` **before** `evidence.record_document()`.
The metadata-only trusted factory returns a validated `Document`. The runner
saves it with the current execution ID. A replay returns that same snapshot
without rerunning the factory, preserving its original capture key,
collection time, source revision, digest and `job_run_id`. The document's
run association identifies the originating capture attempt, not the attempt
that eventually finished all ingestion. Source jobs enforce matching source.
Existing opaque legacy document run IDs are not retroactively reinterpreted
or foreign-keyed. New snapshots identify a real run, retained in the job store.

Choose observation/citation keys deterministically from the saved capture and
trusted parser's row identity, before writing. Replay document, observation
and citation writes after a crash; each commits independently in 5F.1.
Advance progress only after all intended writes commit. Conflicting evidence
must still raise `EvidenceConflict`. A changed upstream response needs a new
capture/slot and validated revision or original-byte digest. Never ingest a
fresh response under an old snapshot just because its slot already exists.
The runner does not archive response bodies or validate source completeness.
Adapters must preserve or verify the replay input; archives belong to 5F.4.

Parameters, progress and coverage objects each have an 8,192-byte encoded
JSON limit. Identity keys have length/character limits. Document metadata is
at most 32,768 bytes per slot and 200 slots per logical job. Split larger work
into explicitly bounded jobs. Raw bodies, secrets and unrestricted excerpts
do not belong in parameters, checkpoints or document factories. There is no
job-history pruning yet. New metadata is finite per job; future retention must
preserve evidence associations rather than deleting referenced runs silently.

## Repeatable Offline Acceptance

From the project root, using the already installed environment:

```bash
# Windows: runner, shared migration/replay compatibility, then all tests
.venv/Scripts/python.exe -B -m unittest tests.test_jobs tests.test_shared_evidence -v
.venv/Scripts/python.exe -B -m unittest discover -s tests -t .

# Linux equivalents
.venv/bin/python -B -m unittest tests.test_jobs tests.test_shared_evidence -v
.venv/bin/python -B -m unittest discover -s tests -t .
```

Tests include temporary databases, thread races, a spawned process killed by
its own synthetic `os._exit`, and an independent live competing process.
Their synchronization waits are bounded and cleanup terminates only test
children if needed. Existing HTTP refusal applies. No install, live migration,
app restart or provider refresh is part of these commands. The Windows venv
launcher required execution outside the managed sandbox launcher restriction;
no environment repair or package change was needed. Linux execution remains
unverified in this Windows pass.

Git checkpoint commands, each requiring approval, are in
[Session Handoff](session-handoff.md). The exact proposed 5F.2 paths and message
are in [Checkpoint Files](../review/2026-11-26-5f2-checkpoint-files.md).

## Approved Read-Only Checkpoint Inspection

The operator approved this inspection on 2026-11-26. It confirmed main at
6341acc, an empty index, .githooks configured and no tracked whitespace errors.
Future sessions still need their own authorization. None of these commands
stages files or contacts a remote:

```bash
git status --short
git diff --stat
git diff --check
git diff --cached --name-only
git log -1 --format="%h %s"
git branch --show-current
git config --get core.hooksPath
git diff -- .gitignore AGENTS.md CLAUDE.md ROADMAP.md app/core/db.py app/core/evidence.py docs/handoff.md docs/journal.md docs/runbooks/shared-evidence.md docs/runbooks/testing.md tests/test_shared_evidence.py
```

Read the seven new proposed files directly too; ordinary `git diff` omits
untracked content. Exclude the separate Feedly rules and local Claude settings.
Git's inaccessible global-ignore warning and LF/CRLF notices did not change
configuration or block inspection. The operator subsequently directly
instructed commit and push in this chat. The updated 19-path checkpoint
manifest records the exact commands and authorization; the closing chat
message records their actual result. No new code changed after acceptance.
