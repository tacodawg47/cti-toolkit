# Subphase 3A.2 Checkpoint Files

Prepared: 2026-11-27. This is the exact authored scope, not Git approval.
Approved local read-only inspection is complete. Main/HEAD/local origin/main
match d34a37d68aa120b58ee3d18822ccf5ebcc54b31c and the index is empty. No
remote contact or Git mutation occurred during inspection. The operator then
directly approved this exact commit proposal and explicitly authorized its
push on 2026-11-27. Execution is prepared; the closing message records the
actual commit/hash/push result. This grants no other chat permission.

Proposed message: `Add bounded HIBP watched-email breach lookups`.

## Exact Paths

34 paths. Tracked diffs and independent shared blocks were reviewed.
Do not stage a whole path if inspection reveals unrelated changes inside it.

```text
.env.example
AGENTS.md
CLAUDE.md
ROADMAP.md
app/core/config.py
app/core/db.py
app/core/feed_catalog.py
app/core/feed_scope.py
app/core/ratelimit.py
app/main.py
app/modules/alerts/routes.py
app/modules/breaches/__init__.py
app/modules/breaches/hibp.py
app/modules/breaches/models.py
app/modules/breaches/routes.py
app/modules/breaches/schema.py
app/modules/breaches/store.py
app/templates/alerts.html
app/templates/base.html
app/templates/breaches.html
docs/handoff.md
docs/journal.md
docs/research/2026-11-27-breach-api-review.md
docs/review/2026-11-26-3a1-closeout.md
docs/review/2026-11-27-3a2-checkpoint-files.md
docs/review/2026-11-27-3a2-closeout.md
docs/runbooks/breach-lookups.md
docs/runbooks/ransomware-victims.md
docs/runbooks/scheduled-feeds.md
docs/runbooks/testing.md
docs/runbooks/v1-data-freshness.md
tests/test_breaches.py
tests/test_ransomware.py
tests/test_shared_evidence.py
```

## Shared Blocks and Exclusions

- ROADMAP.md: last-updated date; the supplied actual 3A.1 checkpoint result;
  the new 3A.2 scope/status block; the foundation continuation paragraph.
  Preserve all independent research/prototype/phase additions.
- docs/journal.md: only the new dated 3A.2 closeout/reconciliation and approved
  inspection entries under
  Research notes. Preserve all historical and independent entries.
- docs/handoff.md: the current 3A.2 header and final checkpoint-resumption
  prompt. Preserve independent prototype, OSINT and detection blocks in the
  working file; exclude those independent blocks from this checkpoint.
- AGENTS.md and CLAUDE.md: paired current status only. No unrelated rules.
- Existing code/tests/runbooks: only the exact breach integration, migration,
  limiter/settings, passive pages, 33-registration expectation and actual
  legacy-table snapshot correction described in the closeout.
- 3A.1 closeout/runbook: the new supplied-result reconciliation note only.
  Preserve the historical approved commands; never execute them again.

Exclude unrelated Feedly rules, local Claude settings, prototypes/ and their
review/runbook, OSINT tools/untrusted-repository-review and detection/catalog
research additions, independent shared-file edits, keys, runtime data,
archives and conversation exports. No blanket staging, reset, discard or stash.

## Required Review and Approvals

Read-only inspection was directly approved and completed. Commands used:

```bash
git status --short
git diff --stat
git diff --cached --name-only
git branch --show-current
git rev-parse HEAD refs/remotes/origin/main
git log -1 --format="%H %s"
git diff --check
git diff -- <the exact authored paths above>
```

The last line is a description of the path-scoped review, not a command to
copy with angle brackets. Review new/untracked files directly too. No remote
contact is needed for this inspection. Do not display credential-bearing
configuration or local secrets.

If shared files contain independent edits, prepare selective staging inputs
only after reviewing the approved HEAD/current diff. Do not overwrite the
working files. Keep any scratch inputs under ignored data/; never commit
those copies. Earlier checkpoint snapshots are historical, not reusable here.

Prepared three local `.snapshot` inputs under ignored `data/3a2-checkpoint/`.
Their bases were reconstructed from the approved current diffs, verifying
every hunk against the current text, then adding only the blocks above.
Independent working text remains untouched. Scope checks confirm that the
new OSINT/detection/prototype blocks and unrelated roadmap whitespace are
absent from these inputs. The journal includes both 3A.2 entries. Handoff
includes only its current header and final full prompt. These are staging
inputs, never commit targets. See the runbook for the gated commands.

After inspection, show the final exact list/selective scope and message for
individual commit approval. Verify staged membership, whitespace and scope,
then commit without bypassing hooks. Obtain separate push approval after
showing the actual commit and verified intended destination. Do not force
push or amend merely to include a commit's own hash in its saved handoff.

See [Session Handoff](../runbooks/session-handoff.md). Update this record and
the handoff with the actual closing result, without implying new permission.
