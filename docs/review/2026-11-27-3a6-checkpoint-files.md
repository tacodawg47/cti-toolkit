# 3A.6 Authored Scope Inventory

Date: 2026-11-27. The operator approved local read-only Git inspection.
Main, HEAD/local origin/main at 5cbcc426f3e16fc254258be12f60de8a3302678d and
an empty index were confirmed; no remote was contacted. This inventory
identifies the exact authored paths/blocks for selective checkpoint review.
No staging, commit or push is approved. Preserve all unrelated working text.
Show final reviewed selective copies/diffs and message for individual commit
approval. Obtain push approval separately.

Candidate message after review: `Add bounded indexed cloud metadata leads`.

Selective copies are prepared under ignored data/3a6-checkpoint/source/.
The 37-path list and SHA-256 identities are in paths.json and digests.json;
review.patch compares the 25 tracked selective copies with HEAD. Twelve new
feature files are reviewed directly. The helper reads HEAD and copies source
only; it writes no index or Git objects. Final acceptance/document updates
must be refreshed into these copies before seeking commit approval.

## New Feature Files

```text
app/modules/cloud_exposure/__init__.py
app/modules/cloud_exposure/models.py
app/modules/cloud_exposure/routes.py
app/modules/cloud_exposure/schema.py
app/modules/cloud_exposure/shodan.py
app/modules/cloud_exposure/store.py
app/templates/cloud_exposure.html
tests/test_cloud_exposure.py
docs/research/2026-11-27-cloud-exposure-api-review.md
docs/review/2026-11-27-3a6-closeout.md
docs/review/2026-11-27-3a6-checkpoint-files.md
docs/runbooks/cloud-exposure.md
```

## Existing Paths, Only Named Blocks

| Path | This Subphase's Selective Block |
|---|---|
| `.env.example` | Three Shodan cloud search review/tier/credit settings and comments. Blank credentials only. |
| `AGENTS.md`, `CLAUDE.md` | Paired current-status summary only. Preserve independent rules and notes. |
| `ROADMAP.md` | 3A.6 design/closeout, next 3A.7 public catalogue scope and supplied 3A.5 completed-checkpoint reconciliation only. Preserve independent research/prototype/parking-lot content. |
| `app/core/alerts.py` | cloud_domain type, canonicalization and exact-only selector validation. |
| `app/core/config.py` | Three default-off/blank/bounded Shodan cloud settings. |
| `app/core/db.py` | Additive cloud schema migration call. |
| `app/core/feed_catalog.py` | One cloud consumer catalog import/composition. |
| `app/main.py` | Cloud routes import/registration. |
| `app/modules/alerts/routes.py` | Cloud capture link identity. |
| `app/templates/alerts.html` | Cloud capture/selector explanatory text. |
| `app/templates/base.html` | Cloud Leads navigation link. |
| `tests/test_breaches.py` | Composed catalog count 36 to 37 only. |
| `tests/test_ct_watch.py` | Composed count and test name 36 to 37 only. |
| `tests/test_github_exposure.py` | Composed count and test name 36 to 37 only. |
| `tests/test_ransomware.py` | Composed catalog count 36 to 37 only. |
| `tests/test_subdomains.py` | Composed catalog count 36 to 37 only. |
| `docs/handoff.md` | Current 3A.6 boundary, actual supplied completed checkpoints, pending new checkpoint and full next bounded prompt. Preserve independent research/prototype revisit blocks. |
| `docs/journal.md` | New dated 3A.6 Research notes entry, including supplied 3A.5 completion. Preserve detailed history and independent notes. |
| `docs/runbooks/alert-inbox.md` | New top 3A.6 update only. |
| `docs/runbooks/durable-jobs.md` | New top 3A.6 update only. |
| `docs/runbooks/scheduled-feeds.md` | New top 3A.6 update only. |
| `docs/runbooks/shared-evidence.md` | New top 3A.6 update only. |
| `docs/runbooks/testing.md` | Current 3A.6 acceptance paragraph and new test inventory row only. |
| `docs/runbooks/v1-data-freshness.md` | New top 3A.6 update only. |

Total authored scope: 37 paths, including 12 new paths and 25 existing
selective paths. Do not blanket-stage these shared files. Any existing
independent content in them requires a selective copy/block review.

## Exclusions and Previous Checkpoints

No .env, API keys, runtime databases, private captures, conversation exports,
local settings, Feedly work, prototypes, independent OSINT/untrusted-repository
reviews, detection/catalog research, reconciliation or handoff-rule edits.
No source enabling or live database operation belongs in this checkpoint.

Operator-supplied 3A.1 through 3A.5 checkpoints are already committed/pushed.
Latest supplied 3A.5: 5cbcc426f3e16fc254258be12f60de8a3302678d, matching
local HEAD/local origin/main/live remote main and empty index on 2026-11-27.
That supersedes prepared/pending notes. Approved inspection verified the
local hashes and empty index only; matching live remote main is supplied
by the operator and was not rechecked.
Never repeat a completed checkpoint or infer future Git approval from notes.
