# Subphase 5F.5 Checkpoint Proposal

Date: 2026-11-26. Implementation and offline acceptance complete. Read-only
Git inspection was approved. The operator individually approved this exact
26-path scope and message. Commit execution is prepared; push is not approved.

Proposed message: `Add local alert inbox and accept foundation integration`

## Exact 26 Paths

```text
AGENTS.md
CLAUDE.md
ROADMAP.md
app/core/alert_schema.py
app/core/alerts.py
app/core/db.py
app/core/evidence.py
app/main.py
app/modules/alerts/__init__.py
app/modules/alerts/routes.py
app/modules/extract/saved.py
app/templates/alerts.html
app/templates/base.html
docs/handoff.md
docs/journal.md
docs/review/2026-11-26-5f5-checkpoint-files.md
docs/review/2026-11-26-5f5-closeout.md
docs/runbooks/alert-inbox.md
docs/runbooks/durable-jobs.md
docs/runbooks/saved-reports-and-archives.md
docs/runbooks/scheduled-feeds.md
docs/runbooks/shared-evidence.md
docs/runbooks/testing.md
docs/runbooks/v1-data-freshness.md
tests/test_alerts.py
tests/test_foundation_acceptance.py
```

## Shared-File Scope

Stage ROADMAP.md from HEAD plus only its foundation session status, 5F.5
table row, next-subphase paragraph and new 5F.5 design paragraph. All other
working-tree roadmap changes stay out, including the unrelated whitespace.

Stage docs/journal.md from HEAD plus only the new dated Subphase 5F.5 entry
at the top of Research notes. Preserve all independent existing entries.

Stage docs/handoff.md from HEAD plus only the new current 5F.5 header and
next-chat fenced prompt. Exclude its independently added Parked Phase 9
Prototype section and OSINT research prose. Leave both in the working file.

Local prepared shared-document snapshots under ignored data/5f5-checkpoint/
are derived from the inspected HEAD plus exactly those edits. They are
staging inputs, never files to commit. Rebuild/review if documents or HEAD
change. Approval is required before writing Git objects or updating its index.

The other 23 paths are proposed in full. Inspect every diff and new file;
ordinary git diff omits untracked contents. The accepted full suite ran
650 tests: 649 passed, one existing skip in 138.479 seconds. Grouped
foundation acceptance passed all 139 in 61.754 seconds.

## Exclusions and Permission

Exclude .claude/settings.local.json, feedly-review-rules.md, prototypes/,
actor-profile prototype review/runbook, OSINT tools research,
docs/runbooks/untrusted-repository-review.md, all independent shared blocks,
keys, runtime data and conversation exports. No git add . or blanket staging.
Current HEAD and local origin/main are the 5F.4 commit c5cdae9; no remote
contact occurred in this chat. An empty index was inspected before proposal.

Obtain individual approval for this exact list/scope/message before staging
or committing. Then verify exact staged membership, shared-file diffs and
whitespace, stopping on unexpected content. Obtain separate approval before
any push. Read-only approval is not commit or remote-transfer permission.
See [Session Handoff](../runbooks/session-handoff.md).
