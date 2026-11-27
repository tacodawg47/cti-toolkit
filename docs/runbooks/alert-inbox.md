# Alert Inbox and Foundation Acceptance

Update 2026-11-26: [Ransomware Victim Claims](ransomware-victims.md) adds
exact organization/sector/country selectors and an optional stable source-claim
deduplication key. All immutable observations/captures survive; repeat victim
sightings retain the first alert and review. Generic evidence keeps the
per-observation semantics below. No watch enables provider collection.

Written 2026-11-26. Subphase 5F.5. Local metadata only, no new dependency.
The live database has not been migrated or the application restarted in this
chat. These features become available after a separately approved normal
startup. No source, schedule, network worker or raw storage was enabled.

## Use the Inbox

1. Open `/alerts`. Source Freshness and Coverage uses the same read-only
   health calculation as the consuming feed pages. Opening the inbox does
   not refresh a provider, scan old observations or queue work.
2. Expand Add Local Selector. Confirm ownership or authority to monitor.
   Choose an exact typed value, domain tree or IP network. This confirmation
   applies only to local matching. It never approves collection or submission.
3. New observations saved through the shared API and report saver match
   enabled selectors in the same transaction. A failed match write rolls back
   the observation/report rather than silently losing its alert.
4. For older observations, press Match Saved Page. Each POST checks at most
   200 observations for that selector. Repeat while Catch-Up says Pending.
   The cursor and alerts commit together. A crash can safely replay the page.
   Previously matched observations may be checked again without duplicates.
5. Open an alert. Read its source assertion, separate dates, literal citation
   hops, capture identity, original availability and originating execution.
   New, Reviewed and Dismissed are workflow states, not credibility ratings.
   Save Review retains dated history. Another tab's conflicting review returns
   409; reload before changing it. Reopening to New is supported.
6. Disable a selector to stop new matching. Existing alerts/reviews remain.
   Adding an identical definition does not re-enable it. On explicit re-enable,
   Match Saved Page also includes observations obtained while disabled.

## Matching and Deduplication

Definitions are immutable. There are at most 100 definitions, including
disabled ones. Values have at most 2,048 characters. Changed definitions
create another selector; no deletion/reset route is supplied. This finite
foundation limit can be revisited with Phase 3 watchlist lifecycle work.

| Mode | Meaning |
|---|---|
| Exact | Same typed canonical domain, IP, hash, URL, email or CVE. Uses existing refang/normalization. |
| Domain Tree | The named domain and its subdomains, separated by a DNS label boundary. Domain observations only. |
| Network | An IP observation inside a strict canonical IPv4/IPv6 CIDR. Network host bits must be zero. |

Domain/hash case, compressed IP spelling and CVE case use shared indicator
rules. Exact URLs retain case, including paths, under the existing URL
normalization contract. Email domains normalize; local parts preserve case.
An email/domain inside a URL is not an implicit cross-type match. Report
extraction can supply its own separate host/domain observations. No regex,
substring, arbitrary code or remote selector expansion is accepted. Brand,
identity and other Phase 3 family rules remain later work. Generic evidence
with unsupported or invalid typed values remains stored but does not match.

Uniqueness is `(selector_id, observation_id)`. Replaying an immutable
observation cannot duplicate an alert or reset its review. Separate sources,
captures and source assertions retain separate alerts even for equal values.
They are not automatically independent evidence. Matching time is local
processing time, never the publication, observation or collection date.

The inbox shows 50 alerts per page, newest local ID first, with state filters
and an older-page cursor. Detail pages show up to 100 citation hops and 100
reviews, with continuation links. Source references are escaped passive text;
the inbox never follows them. Original bodies have no render/download route.
Non-public or restricted-TLP excerpts are suppressed. Private metadata is
still visible in this local single-operator app; labels are not access control.

## Provenance, Recovery and Availability

`app/core/alert_schema.py` has its own additive transactional version ledger.
It references existing observations and never changes their dates or source
assertions. `app/core/alerts.py` owns local matching and review transactions;
`app/modules/alerts/routes.py` owns guarded local forms. SQL uses parameters.
Neither selector rows nor evidence can select a callable, job registration,
command, destination, credential or collection decision.

An originating execution can remain Interrupted while its logical job later
succeeds. The alert shows both facts without rewriting capture identity.
Manual/legacy opaque execution IDs remain visible without inventing a run.
Alert details show capture age and relevant registered source freshness. A
source without a schedule has no scheduled freshness assessment. An immutable
report capture is not a claim about that source's current contents.

Archive availability comes from the shared archive metadata, including
immediate expiry. Missing/corrupt files become Failed after bounded existing
reconciliation. No inbox GET performs filesystem reconciliation. Expired,
omitted or failed bodies never delete observations, citations, alerts or
reviews. Digests establish byte identity, not authenticity. No history pruning,
privacy deletion, encrypted quarantine or automatic historical scan worker
is added. Catch-up is explicit; incremental matches need no separate worker.

## Repeat the Offline Acceptance

From the project root, use the already installed environment:

```bash
# Windows: new inbox and cross-feature checks
.venv/Scripts/python.exe -B -m unittest tests.test_alerts tests.test_foundation_acceptance -q
# Full foundation, including real process-death recovery and existing budgets
.venv/Scripts/python.exe -B -m unittest tests.test_alerts tests.test_foundation_acceptance tests.test_saved_reports tests.test_feed_scheduler tests.test_jobs tests.test_shared_evidence -q
# Full compatibility
.venv/Scripts/python.exe -B -m unittest discover -s tests -t . -q

# Linux equivalents
.venv/bin/python -B -m unittest tests.test_alerts tests.test_foundation_acceptance -q
.venv/bin/python -B -m unittest discover -s tests -t . -q
```

Tests use temporary databases and blocked/mock HTTP. The Windows venv
launcher needs the established execution path outside the managed launcher
restriction. No interpreter, package or security setting is changed.

New failure injection covers interruption between capture/alert and progress,
restart replay with retained review/origin, failed refresh after success,
offline first startup, 429 cooldown across scheduler instances, cancellation,
revocation between capture and ingestion, downtime, daily quota and archive
reconciliation. The renderer test passes the real calculated failure state
through the existing panels on eight consuming pages. Existing foundation
tests also cover real process death/exclusion, source-owned pagination/window
recovery, malformed/empty/oversized bodies, request/byte/time bounds, quota
waits, retained checkpoints, interrupted archive writes and expiry cleanup.

Mocks establish application invariants under controlled failures. They do
not establish current provider terms, live endpoint schemas, real quota
headers, data completeness, long-running cadence, OS downtime behavior on a
deployed instance, Linux execution or native-browser visual acceptance.
Before daily v1 use, approve and perform named source reviews, live additive
migration/restart and bounded live refresh/recovery acceptance, recording
sizes, time, lag and actual results. See [V1 Freshness](v1-data-freshness.md).
No large historical reload is required by this subphase.

Git inspection, commit and push each require current-chat approval. The
subphase manifest and proposed message are in the dated checkpoint file.
Preserve unrelated working-tree and shared-document edits. See
[Session Handoff](session-handoff.md).

## Approved Read-Only Checkpoint Inspection

The operator approved read-only inspection in this chat on 2026-11-26.
These commands confirmed main, an empty index, and HEAD/local origin/main
at c5cdae9ec0cd378b1d4fc90bfdaf912490958bb6. They contacted no remote:

```bash
git status --short
git diff --stat
git diff --cached --name-only
git rev-parse HEAD refs/remotes/origin/main
git branch --show-current
git diff --check
git diff -- app/core/db.py app/core/evidence.py app/main.py app/modules/extract/saved.py app/templates/base.html ROADMAP.md docs/journal.md docs/handoff.md
git show HEAD:ROADMAP.md
git show HEAD:docs/journal.md
git show HEAD:docs/handoff.md
```

The whole-working-tree whitespace check found trailing spaces in an
unrelated roadmap addition. Leave that independent edit out of this commit;
the focused 5F.5 tracked-file check passed. Global-ignore permission warnings
and LF/CRLF notices did not change settings or block inspection. Three local
staging snapshots under ignored data/5f5-checkpoint/ start from inspected
HEAD plus only the new foundation/handoff/journal blocks. All independent
working text remains. Never commit those runtime snapshots. The exact 26-path
proposal and shared-file scope are in
[Checkpoint Files](../review/2026-11-26-5f5-checkpoint-files.md).

This approval covers no staging, commit or push. Obtain each required direct
approval before the corresponding operation; saved commands are a record.

## Individually Approved 5F.5 Commit

The operator subsequently approved the exact 26-path proposal and message
in this chat. The shared snapshots preserve all unrelated working text.
These commands record that individual approval, not permission for a push
or another chat. Stop on any error or unexpected staged content:

```powershell
$checkpointText = Get-Content 'docs/review/2026-11-26-5f5-checkpoint-files.md' -Raw
$checkpointBlock = [regex]::Match($checkpointText, '(?s)```text\r?\n(.*?)\r?\n```')
$checkpointPaths = @($checkpointBlock.Groups[1].Value -split '\r?\n')
if ($checkpointPaths.Count -ne 26) { throw 'Unexpected manifest' }
if (@(git diff --cached --name-only).Count) { throw 'Unexpected staged work' }
$checkpointShared = @('ROADMAP.md', 'docs/journal.md', 'docs/handoff.md')
$checkpointWhole = @($checkpointPaths | Where-Object { $_ -notin $checkpointShared })
git add -- @checkpointWhole
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
foreach ($checkpointPath in $checkpointShared) {
    $checkpointSnapshot = Join-Path 'data/5f5-checkpoint' (($checkpointPath -replace '/', '_') + '.snapshot')
    $checkpointBlob = git hash-object -w --path=$checkpointPath -- $checkpointSnapshot
    if ($LASTEXITCODE -ne 0) { throw 'Snapshot failed' }
    git update-index --add --cacheinfo "100644,$checkpointBlob,$checkpointPath"
    if ($LASTEXITCODE -ne 0) { throw 'Index update failed' }
}
$checkpointStaged = @(git diff --cached --name-only)
if (Compare-Object ($checkpointPaths | Sort-Object) ($checkpointStaged | Sort-Object)) {
    throw 'Staged paths differ from approved manifest'
}
git diff --cached --check
git diff --cached --stat
git diff --cached -- ROADMAP.md docs/journal.md docs/handoff.md
# Inspect the shared diffs and confirm unrelated additions are absent.
git commit -m 'Add local alert inbox and accept foundation integration'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git log -1 --format="%h %s"
git status --short
```

Obtain separate push approval after verifying the resulting commit and
intended remote/branch. Prepared notes precede actual execution; reconcile
the closing chat result before repeating this checkpoint.
