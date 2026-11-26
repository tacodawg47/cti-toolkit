# Current Session Handoff

Updated: 2026-11-26.

**Ended: Subphase 5F.2 Complete.** Opt-in durable runner supports trusted
registration, distinct logical work and execution identities, progress,
bounded retries, cancellation, restart recovery and duplicate-execution
control. See [Closeout](review/2026-11-26-5f2-closeout.md) and
[Durable Jobs](runbooks/durable-jobs.md) for handler contracts and limits.

Acceptance: 24 new runner tests and 18 shared-evidence tests passed. Final
offline suite ran 553 tests in 71.144 seconds: 552 passed and one existing
skip. Real Windows process-crash and competing-process tests passed. Six
existing startup/page checks returned 200 on a temporary database. No live
database migration, restart, source enabling, provider traffic or dependency
change. Linux execution was not performed. V1 freshness remains outstanding.

Checkpoint: the operator confirms 5F.1 commit `6341acc`, `Add shared evidence
model and source registry`, was pushed to `origin/main` and verified. Do not
repeat it. Approved read-only Git inspection confirmed main at 6341acc,
an empty index and .githooks configured. Changes match the proposal and
tracked whitespace checks passed. The operator then directly instructed commit
and push and requested an explicit on-screen handover rule. Both checkpoint
actions are authorized. This handoff is prepared for execution; the closing
chat message records the actual commit and push result. Do not infer a pending
checkpoint from this pre-commit note without reconciling that result.
The exact 19-path proposal and message `Add durable job runner` are in
[Checkpoint Files](review/2026-11-26-5f2-checkpoint-files.md). Reconcile the
current operator message and closing chat result before deciding what remains.
Saved notes never grant Git permission.

The handover prompt must also be printed directly in the final response, in
a fenced text block. See the updated session-handoff runbook and paired rules.

Preserve/exclude `feedly-review-rules.md`, `.claude/settings.local.json`,
the unrelated untracked `prototypes/` directory,
secrets, runtime data and conversation exports. Source metadata remains
disabled by default. Existing manual feeds/queues/async limits are unchanged.
Runner execution is serial per canonical local database path. No startup
dispatcher or production task exists. Handlers must use cooperative checks,
finite source budgets and verified replay input. 5F.3 must bridge async feed
clients/quotas explicitly; do not create a fresh event loop per job around
the shared async limiter. Follow [Session Handoff](runbooks/session-handoff.md).

## Next-Chat Prompt

```text
Continue the CTI Toolkit at C:\Users\Robert\Projects\cti-toolkit.
Implement only 5F.3: Scheduled Feed Refresh and Source Health.

Follow AGENTS.md and its required reading order. Read focused ROADMAP.md
foundation sections, newest Research notes in docs/journal.md, docs/handoff.md,
docs/review/2026-11-26-5f2-closeout.md, docs/runbooks/durable-jobs.md,
shared-evidence.md, session-handoff.md and v1-data-freshness.md.

5F.2 is complete: final offline suite ran 553 tests, 552 passed and one
existing skip, including 24 runner tests. The live database has not been
migrated or restarted for 5F.1/5F.2. 5F.1 commit 6341acc was pushed to
origin/main and verified, as confirmed by the operator. Reconcile the latest
operator message/closing checkpoint result before deciding whether 5F.2 Git
work remains. Every Git inspection, commit and push needs current-chat
approval; commit and push are separately approved. Preserve unrelated Feedly
rules/local Claude settings and exclude secrets, runtime data and exports.

Inspect the runner, existing source-specific queues, async clients and quotas
before integrating feeds. Register permitted source work in trusted code.
Design/test a compatible async bridge or durable quota adapter; the shared
async limiter must not be reused across fresh event loops per job. Keep
requests, time, bytes and retries bounded. Check source eligibility before
each bounded unit/retry and preserve logical work/run/capture identities.
Source content cannot choose callables, commands, destinations or approvals.

Implement explicit source-specific schedules and health for existing reviewed,
configured feeds using the runner. Preserve separate last attempt, validated
retrieval and complete-coverage checkpoints; retain prior good data. Surface
never-loaded, stale, failed and incomplete states where analysts consume it.
Test downtime/restart gap recovery, 429/quota handling, provider failures,
partial pagination and success without skipping unfinished windows. Keep
large historical reloads behind their existing explicit action. Review terms,
cadence and quotas before enabling any source; registry notes and old manual
routes do not confer new collection permission. Do not initiate provider
traffic or migrate/restart the live app without direct approval.

Done when meaningful offline scheduler/health/recovery and compatibility tests
pass and design limits/repeatable commands are documented. Saved reports and
archives are 5F.4; alerts 5F.5. Collectors and AI remain outside this pass.
New dependencies, installs, external transfers and other system changes follow
AGENTS.md approval rules. Routine project edits/offline tests need no prompt.

Work through this one subphase, then stop. State Subphase 5F.3 Complete only
if acceptance passes. Write a dated closeout, update journal, roadmap, paired
status summaries and handoff, and paste a ready-to-use 5F.4 prompt directly in
the final response. Prepare exact commit files/message for individual approval
and request push approval separately after the commit. If incomplete, record
actual status and provide a resume prompt rather than claiming completion.
```
