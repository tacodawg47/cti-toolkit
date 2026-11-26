# 5F.3 Checkpoint Proposal

Date: 2026-11-26. Subphase 5F.3 Complete.

Final acceptance: 585 offline tests in 92.493 seconds, 584 passed and one
existing skip. No live migration, app restart, source enabling or provider
traffic. Read-only Git inspection confirmed main at eff4b41, an empty index
and .githooks configured. Tracked whitespace checks passed.

Proposed message: `Add scheduled feed refresh and source health`.

The operator individually approved this exact commit proposal in the current
chat. Execution is prepared below; separate push approval remains pending.
This manifest grants no future permission. See the closing chat result for
actual execution; do not repeat a completed checkpoint from prepared notes.

## Exact 58 Paths

For ROADMAP.md, docs/journal.md and docs/handoff.md, stage **only 5F.3
content**. Their separate actor-prototype additions stay in the working tree,
unstaged. The remaining listed paths are staged in full. No other path is
included. Preserve/exclude the prototype tree and its closeout/runbook,
Feedly rules, local Claude settings, secrets, runtime data and exports.

```text
.env.example
AGENTS.md
CLAUDE.md
ROADMAP.md
app/core/config.py
app/core/db.py
app/core/feed_scheduler.py
app/core/feed_schema.py
app/core/feed_scope.py
app/core/jobs.py
app/core/ratelimit.py
app/main.py
app/modules/enrich/base.py
app/modules/infrastructure/c2feed.py
app/modules/infrastructure/routes.py
app/modules/vulnerability_intelligence/feeds/chatter.py
app/modules/vulnerability_intelligence/feeds/circl_kev.py
app/modules/vulnerability_intelligence/feeds/cvelist.py
app/modules/vulnerability_intelligence/feeds/cvemon.py
app/modules/vulnerability_intelligence/feeds/cwe.py
app/modules/vulnerability_intelligence/feeds/epss.py
app/modules/vulnerability_intelligence/feeds/euvd.py
app/modules/vulnerability_intelligence/feeds/exploitdb.py
app/modules/vulnerability_intelligence/feeds/gp0.py
app/modules/vulnerability_intelligence/feeds/kev.py
app/modules/vulnerability_intelligence/feeds/metasploit.py
app/modules/vulnerability_intelligence/feeds/msrc.py
app/modules/vulnerability_intelligence/feeds/msrc_cvrf.py
app/modules/vulnerability_intelligence/feeds/nuclei.py
app/modules/vulnerability_intelligence/feeds/nvd_recent.py
app/modules/vulnerability_intelligence/feeds/ot.py
app/modules/vulnerability_intelligence/feeds/poc.py
app/modules/vulnerability_intelligence/feeds/ransomwarelive.py
app/modules/vulnerability_intelligence/feeds/redhat.py
app/modules/vulnerability_intelligence/feeds/rvm.py
app/modules/vulnerability_intelligence/feeds/supply.py
app/modules/vulnerability_intelligence/feeds/vendors.py
app/modules/vulnerability_intelligence/feeds/vulncheck_kev.py
app/modules/vulnerability_intelligence/http.py
app/modules/vulnerability_intelligence/routes.py
app/modules/vulnerability_intelligence/scheduled.py
app/modules/vulnerability_intelligence/store.py
app/templates/health.html
app/templates/infrastructure.html
app/templates/source_health.html
app/templates/vulnintel/layout.html
docs/handoff.md
docs/journal.md
docs/review/2026-11-26-5f3-checkpoint-files.md
docs/review/2026-11-26-5f3-closeout.md
docs/runbooks/durable-jobs.md
docs/runbooks/scheduled-feeds.md
docs/runbooks/shared-evidence.md
docs/runbooks/testing.md
docs/runbooks/v1-data-freshness.md
docs/runbooks/vulnerability-intelligence.md
tests/test_feed_scheduler.py
tests/test_shared_evidence.py
```

## Shared Document Staging

The prototype additions are identified by these existing sections:

- ROADMAP.md: Phase 9 prototype bullets from `- Starting code:` through the
  prototype HANDOFF reference, before the original threat-actor-profile bullet.
- docs/journal.md: the entry headed `2026-11-26: Validated and Parked the
  Actor Profiles Prototype`, up to the next dated research entry.
- docs/handoff.md: `Parked Phase 9 Prototype`, up to `Next-Chat Prompt`.

Prepare index-only snapshots that omit those three additions while retaining
all 5F.3 edits. Hash and stage those snapshots for their original paths only
after approval. Do not rewrite the working files, stash, reset or discard the
prototype work. Before commit, verify exact staged membership, whitespace,
the three shared diffs and absence of prototype sections from staged blobs.
Repeatable commands and the approval boundary are in
[Scheduled Feeds](../runbooks/scheduled-feeds.md).
