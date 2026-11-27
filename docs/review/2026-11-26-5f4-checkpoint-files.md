# 5F.4 Checkpoint Proposal

Date: 2026-11-26. The operator individually approved this exact 28-path
proposal and message in this chat. Execution is prepared. Push is separate.

Proposed message: `Add saved reports and bounded original archives`

Exactly 28 paths:

```text
.env.example
AGENTS.md
CLAUDE.md
ROADMAP.md
app/core/archives.py
app/core/config.py
app/core/evidence_schema.py
app/core/feed_scope.py
app/main.py
app/modules/enrich/bulk.py
app/modules/extract/fetch.py
app/modules/extract/html.py
app/modules/extract/saved.py
app/modules/extract/saved_routes.py
app/templates/extract.html
app/templates/health.html
app/templates/saved_reports.html
docs/handoff.md
docs/journal.md
docs/review/2026-11-26-5f4-closeout.md
docs/review/2026-11-26-5f4-checkpoint-files.md
docs/runbooks/durable-jobs.md
docs/runbooks/saved-reports-and-archives.md
docs/runbooks/scheduled-feeds.md
docs/runbooks/shared-evidence.md
docs/runbooks/testing.md
tests/test_saved_reports.py
tests/test_shared_evidence.py
```

Shared-file staging is limited to 5F.4:

- ROADMAP.md: foundation session status, 5F.4 delivery row, next-chat pointer
  and the new 5F.4 design paragraph.
- docs/journal.md: only the new Subphase 5F.4 Complete research entry.
- docs/handoff.md: the new 5F.4 summary/checkpoint and next-chat prompt.

Preserve all unrelated work in the working tree. Exclude prototype files and
their roadmap/journal/handoff blocks, review and runbook; OSINT tools research,
its roadmap/journal/handoff additions and untrusted-repository-review runbook;
Feedly rules and local Claude settings. Exclude keys, runtime data, local
checkpoint scratch files and conversation exports. No broad `git add .`.
Prepare shared index content from HEAD plus only the named changes, review
it and verify exact staged path membership before committing. Do not amend
to add this containing commit's own future hash.

Acceptance: 627-test full run, 626 passed and one existing skip; subsequent
42-test focused acceptance passed after the last credential guard refinement.
No live activation, source traffic, migration or restart. See the closeout.
