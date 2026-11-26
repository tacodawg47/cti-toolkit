# Subphase 5F.1 Checkpoint Proposal

Date: 2026-11-26. Proposed message:
`Add shared evidence model and source registry`.

Read-only Git inspection was approved in this chat. It found main at
8df28b0, `Complete Phase 2 and document subphase handoffs`, with an empty
index. The operator reports that checkpoint was already pushed and verified
in the previous chat. Do not repeat it. No remote contact was needed here.

The exact proposed 5F.1 checkpoint is these 14 paths, including this manifest:

```text
AGENTS.md
CLAUDE.md
ROADMAP.md
app/core/db.py
app/core/evidence.py
app/core/evidence_models.py
app/core/evidence_schema.py
docs/handoff.md
docs/journal.md
docs/review/2026-11-26-5f1-checkpoint-files.md
docs/review/2026-11-26-5f1-closeout.md
docs/runbooks/shared-evidence.md
docs/runbooks/testing.md
tests/test_shared_evidence.py
```

Exclude `.claude/settings.local.json`, `feedly-review-rules.md`, `.env`,
runtime data and conversation exports. The two unrelated local files were
not edited. Do not use `git add .`.

The operator explicitly approved both the named commit and its push in this
chat on 2026-11-26. This record is prepared for those operations. Inspection
approval alone did not authorize them. Record the actual resulting commit
and push in the closing message; do not amend to chase a self-referential ID.
The verified destination is the existing origin/main on the project's GitHub
repository, with the transcript guard configured through .githooks.
