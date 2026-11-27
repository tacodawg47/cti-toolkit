# Subphase 3A.1 Checkpoint Proposal

Prepared: 2026-11-26. Read-only inspection approved and completed 2026-11-27.
Main/local origin/main are a947eb0 with an empty index. No remote contact or
Git mutation occurred during inspection. The operator subsequently approved
this exact individual staging/commit proposal. Execution is prepared; push
approval remains pending. This manifest excludes unrelated working-tree changes.

Proposed message: `Add API-only ransomware victim tracking and local watches`

## Exact 33 Paths

```text
AGENTS.md
CLAUDE.md
ROADMAP.md
app/core/alert_schema.py
app/core/alerts.py
app/core/db.py
app/core/feed_catalog.py
app/core/feed_scheduler.py
app/core/feed_scope.py
app/core/ratelimit.py
app/main.py
app/modules/alerts/routes.py
app/modules/ransomware/__init__.py
app/modules/ransomware/models.py
app/modules/ransomware/ransomlook.py
app/modules/ransomware/routes.py
app/modules/ransomware/schema.py
app/modules/ransomware/store.py
app/templates/alerts.html
app/templates/base.html
app/templates/ransomware.html
docs/handoff.md
docs/journal.md
docs/research/2026-11-26-ransomware-api-review.md
docs/review/2026-11-26-3a1-checkpoint-files.md
docs/review/2026-11-26-3a1-closeout.md
docs/runbooks/alert-inbox.md
docs/runbooks/ransomware-victims.md
docs/runbooks/scheduled-feeds.md
docs/runbooks/shared-evidence.md
docs/runbooks/testing.md
docs/runbooks/v1-data-freshness.md
tests/test_ransomware.py
```

## Selective Scope

The new ransomware package, template, composed feed catalog, tests, runbook,
source review and dated closeout/checkpoint files belong to this subphase.
Existing code changes extend typed watches and optional stable-event alert
deduplication, add additive migrations, force raw omission for this API and
compose the source into existing startup/health/inbox consumers.

Stage only the new 3A.1 current-status text in AGENTS.md and CLAUDE.md.
Keep their other current working rules unchanged. In ROADMAP.md select only
the Phase 3 source wording, 3A.1 scope/status and foundation next-step update.
In docs/journal.md select only the new dated 3A.1 implementation and checkpoint
Research notes entries.
In docs/handoff.md select only the current 3A.1 header and resumption prompt.
Keep the independent prototype, OSINT and detection research blocks in the
working files and outside this checkpoint.

Runbook changes are the new ransomware runbook, new top update paragraphs
in alert-inbox/shared-evidence/scheduled-feeds/v1-data-freshness, and the
testing summary/new test row. Verify all other named-file diffs after approved
inspection. Do not blindly stage a named file if it contains unrelated work.
Build selective snapshots from the approved inspected HEAD if needed; that
Git work itself requires authorization. No such snapshots were made here.

## Exclusions and Prior Checkpoint

Preserve Feedly rules, local Claude settings, prototypes/ and their review/
runbook, OSINT tools research, untrusted-repository-review additions,
detection tools research/catalog-review additions and every independent
shared-doc edit. Exclude keys, runtime data and conversation exports.
Do not use blanket staging, stash, reset or discard to obtain a clean tree.

The operator reports the individually approved 5F.5 commit and separately
approved push completed at a947eb0c83f0f5260c1c1844e64d1b8402ffb332,
with matching local/remote hashes and an empty index afterward. Saved notes
precede that execution. Do not repeat the checkpoint. Approved local
inspection confirmed HEAD/local origin/main at that hash, an empty index
and the selective diff scope. The live remote was not contacted. Focused
tracked whitespace passed. Preserve the unrelated roadmap trailing whitespace
and all independent changes outside the checkpoint.

## Approval Sequence

Current-chat read-only inspection was approved and completed. The operator
then individually approved this exact list, selective blocks and message.
Any new chat still needs its own approval. A commit request does not
authorize push. Verify the resulting commit and destination before asking
for separate push approval. Stop on unexpected content or hook/test failure.
See [Session Handoff](../runbooks/session-handoff.md).
