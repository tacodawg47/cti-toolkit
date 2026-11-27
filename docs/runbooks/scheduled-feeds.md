# Scheduled Feed Refresh and Source Health
Update 2026-11-27: [GitHub Public-Code Leads](github-exposure.md) adds one
disabled daily API schedule, bringing the composed catalog to 35. All
schedules, workers, bulk and raw storage default off. Exact submission
authority and reviewed public-only access are separate gates. Two fixed
pages per query, finite body/request/time bounds and persistent GitHub
cooldowns apply. Truncated/provider-incomplete windows do not renew success.

Update 2026-11-27: [CT Lookalike Watches](ct-lookalike-watches.md) adds one
provisional disabled daily crtsh_watch schedule. The composed catalog is 34;
all schedules and the worker default off. Source terms remain unapproved.
Exact seed submission permissions and per-seed freshness remain separate
from a global pass. Existing manual crt.sh enrichment is unchanged.

Update 2026-11-27: [HIBP Watched Email Lookups](breach-lookups.md) adds one
disabled daily API consumer for up to ten separately approved email watches.
The composed catalog is now 33; all schedules and the worker default off.
Per-address capture age remains separate from global pass completion.

Update 2026-11-26: [Ransomware Victim Claims](ransomware-victims.md) adds one
disabled API snapshot schedule. `app.core.feed_catalog.catalog` composes it
with the existing 31 vulnerability/infrastructure surfaces for app startup,
Health and the inbox. The original module catalog remains 31. All 32
schedules and the worker default off. Source review and live acceptance are
separate. No existing source registration or cadence changed.

Update 2026-11-26: [Alert Inbox](alert-inbox.md) reuses this read-only source
health panel. Foundation integration tests connect mocked scoped retrievals,
observation alerts, progress/recovery, persistent cooldowns and archive
availability. The source/worker activation gates below still apply.

Update 2026-11-26: [Saved Reports and Archives](saved-reports-and-archives.md)
adds optional bounded retention at the existing capture boundary. Unknown
source handling omits raw bodies. Request identity now hashes method,
endpoint and query/payload inputs, keeping equal responses to different
queries separate without persisting query tokens. Original run/time metadata
remain immutable on replay. No source, schedule or worker was enabled.

Written 2026-11-26. Subphase 5F.3. All schedules and the worker default to
disabled. This file documents code and repeatable procedures. It does not
approve a source, a transfer, a migration or a restart.

## Design

`app/core/feed_schema.py` adds versioned transactional tables alongside the
runner and shared evidence. It preserves legacy tables, views and
`user_version`. `feed_schedules` stores due work, the active job, generation,
validated retrieval and complete coverage. Request reservations and provider
cooldowns survive restart. Capture progress records validated and ingested
units separately from execution attempts.

`app/modules/vulnerability_intelligence/scheduled.py` registers 31 explicit
surfaces, including the existing infrastructure C2 snapshots. Registry text,
feed contents and database values never supply a callable or destination
pattern. The Microsoft monthly feed runs under the Microsoft registration.
OSV and GitHub supply-chain collection have separate approvals and schedules.

APScheduler is not installed. This slice uses a stdlib asyncio timer, checked
every 30 seconds, with durable due work in SQLite. It adds no dependency.
`Scheduler.step()` plans due work, dispatches at most one registered task,
then reconciles its outcome. A restart or missed timer tick creates one
outstanding pass per feed, rather than a burst for every missed interval.
An interrupted active job retains its work ID, attempts and saved progress.
An enqueue interrupted before schedule linkage reuses its generation key.
Future modules' queued tasks are not claimed by this feed worker.

The synchronous runner executes in a worker thread. Its handler submits the
feed coroutine to the existing application loop with
`asyncio.run_coroutine_threadsafe()`. The shared HTTP client, feed locks and
provider limiter stay on that loop. No new event loop is created per job.
SQLite operations introduced by the scheduler run in threads. Existing
manual feed/store contracts retain their established ownership.

Shutdown signals the timer and waits for active requests, sibling tasks and
save threads before closing the shared client. A wait timeout is not used to
pretend a thread stopped. Legacy concurrent batches are drained even when
one sibling fails. Requests have wall-clock limits; cooperative elapsed-time
checks stop new units. Parsing and a committed SQLite save can finish after
the soft pass deadline. This is not an OS sandbox or forced thread kill.

## Proposed Cadences

These are conservative local proposals over already implemented adapters.
They are not a fresh upstream terms review. Before enabling any source,
review its own full documentation, exact surface, cost, credentials and
limits. Tighten the trusted policy if its current allowance requires it.

| Source / Schedule Key | Cadence | Stale After |
|---|---|---|
| CISA KEV, `cisa_kev` | 6 hours | 36 hours |
| EPSS, `epss` | 24 hours | 48 hours |
| Trending Attention, `cvemon_trending` | 1 hour | 6 hours |
| MITRE CWE, `cwe` | 7 days | 30 days |
| Exploit-DB, `exploitdb` | 24 hours | 3 days |
| Metasploit, `metasploit` | 24 hours | 3 days |
| Nuclei CVE index, `nuclei` | 24 hours | 3 days |
| Project Zero, `gp0` | 24 hours | 3 days |
| Ransomware Vulnerability Matrix, `rvm` | 24 hours | 3 days |
| NVD public recent changes, `nvd_recent` | 1 hour | 12 hours |
| EUVD, `euvd` | 6 hours | 36 hours |
| CIRCL KEV, `circl_kev` | 6 hours | 36 hours |
| VulnCheck KEV, `vulncheck_kev` | 6 hours | 36 hours |
| GitHub repository leads, `github_poc` | 6 hours | 36 hours |
| Recent sightings, `vulnlookup_recent` | 1 hour | 6 hours |
| CVE Program deltas, `cvelist` | 1 hour | 12 hours |
| Microsoft CSAF and CVRF, `msrc` | 6 hours | 36 hours |
| Red Hat VEX, `redhat_vex` | 24 hours | 3 days |
| ransomware.live groups, `ransomwarelive` | 24 hours | 3 days |
| Fortinet, `vendor_fortinet` | 6 hours | 36 hours |
| Palo Alto, `vendor_paloalto` | 6 hours | 36 hours |
| Cisco, `vendor_cisco` | 6 hours | 36 hours |
| Red Hat, `vendor_redhat` | 6 hours | 36 hours |
| SUSE, `vendor_suse` | 6 hours | 36 hours |
| Chrome, `vendor_chrome` | 6 hours | 36 hours |
| CISA OT, `cisa_ot` | 6 hours | 36 hours |
| Siemens, `siemens_ot` | 6 hours | 36 hours |
| Schneider Electric, `schneider_ot` | 6 hours | 36 hours |
| C2IntelFeeds, `c2intel` | 6 hours | 24 hours |
| OSV supply chain, `supply_osv` | 6 hours | 36 hours |
| GitHub supply chain, `supply_github` | 6 hours | 36 hours |

Use the trusted catalog for exact keys and policy values. The health panel
shows cadence and stale threshold beside each source.

## Bounds and Quotas

Every pass defaults to 24 requests, 192 MiB charged bytes and a soft
240-second deadline. A response is limited to the smaller of the existing
adapter cap and 64 MiB. Source overrides in the catalog are finite:

- NVD: 6 pages, its existing 64 MiB page allowance and 192 MiB body budget.
  Its existing window splitter can end the pass earlier.
- Project Zero: 32 requests and 256 MiB. RVM: 16 requests and 256 MiB.
- Publisher notices: 24 requests and 256 MiB. Existing vendor imports also
  enforce their 60-second and 128 MiB bounds.
- Microsoft, VEX, OT, OSV and group profiles: at most 40 requests. The first
  four use 256 MiB; group profiles retain the 192 MiB default.
- CVE deltas: 32 requests, 256 MiB, 32 MiB per response and at most two
  explicit redirects per download. Only fixed release and official asset
  host/path patterns are allowed. Auth headers are not forwarded. Scheduled
  delta expansion is at most 256 MiB and 10,000 archive members. Invalid or
  oversized records retain the exact delta checkpoint.
- C2 snapshots: 3 requests, 32 MiB total, with the existing 8 MiB file caps.

Reserve a full response allowance before starting each request. Refund only
the unused part of a complete bounded response. Error, truncated and redirect
responses retain their allowance. There is no request outside the source's
fixed registered surface. Other feeds do not follow redirects automatically.

Scheduled requests have a durable rolling 60-second cap of 30 and a rolling
24-hour cap of 1,000 by default. NVD uses 5 per minute. Registered adapters
also acquire the existing provider limiter at the actual transport boundary.
Existing feed calls before that boundary do not double-spend quota.
Provider buckets are shared between related scheduled surfaces. Red Hat VEX
and notices share a courtesy bucket. Public NVD calls share the existing
keyless allowance when no key is configured.

The existing limiter still owns manual in-memory minute windows and durable
UTC daily counts. The new rolling ledger bounds scheduled traffic; it is
not a new cross-process quota service for manual routes. Use one app process.
Account changes and provider caps still need operator review.

There are three total runner attempts per pass, including interruptions.
Backoff starts at 300 seconds and doubles. A 429 records a provider cooldown
and honors numeric or HTTP-date Retry-After. The local minimum is 300 seconds;
the defensive maximum is one year. Invalid hints use 300 seconds. No tight
retry loop follows a 429. Daily quota exhaustion waits one day. After the
pass ends, a later cadence may create a new bounded pass over remaining
source work. It never resets the earlier job's attempt history.

## Recovery and Evidence

Recheck registry eligibility, schedule enabling, credentials/initial-load
prerequisites and budgets before every request, retry and resumed execution.
Recheck after quota waits and at ingestion boundaries. Disabling collection
or the schedule stops the next cooperative unit. In-flight responses cannot
be retracted.

Capture metadata is persisted before ingestion. Slots bind a fixed endpoint
and original-body digest. Query values and auth headers are omitted. Replaying
the same bytes under that logical job retains the original capture key,
collection time and originating run ID. Changed bytes create a new capture.
The completing execution has its own run ID. No original bodies are archived
in 5F.3. These digests describe bytes returned by the existing HTTP decoder,
not transport-compressed wire bytes. No indicator observations are fabricated
from bulk-feed rows in this slice.

NVD retains its pending window and advances only a fully validated walk.
Dense windows split without discarding an old watermark. Red Hat/SUSE drain
the saved queue before fetching a newer index; failures remain retryable and
the exact revision completes only after its save. Other advisory adapters
compare saved revisions against fixed indexes. GitHub supply-chain overlap
starts from the last complete refresh, so a failed pagination walk does not
skip an unfinished interval. Snapshot/paginated indexes can replay from the
start. They do not claim immutable upstream snapshots or all history.

Large initial loads stay manual: CVE List snapshots/reloads, the CISA OT
archive and OSV Actions archive are not scheduled. CVE gaps beyond the
existing supported delta horizon require the explicit reload. NVD metadata
backfills and arbitrary URL/advisory reloads are not scheduled. Rolling
sightings cover only their existing 48-hour window, not missing older history.
If finite pass limits cannot complete a source window, health stays
incomplete. Adjusting budgets or doing a large recovery needs its own review.

Attempt, validated retrieval, committed capture progress, complete coverage
and last-good snapshot age are separate. Scheduled legacy status updates are
staged until the adapter confirms completion. Partial walks never briefly
publish a green successful refresh. Prior good data and completed coverage
survive later failures. Health also checks NVD, CVE and EPSS coverage dates,
so fetching an old window or old daily scores does not conceal a gap.

Health and every vulnerability page show Never Loaded, Stale, Failed and
Incomplete states. Infrastructure shows C2 source health beside its results.
Ordinary page rendering does not dispatch scheduled collection. Existing
explicit detail lookup/manual route behavior remains compatible.

## Repeatable Offline Acceptance

Run from the project root. These use temporary databases and mock HTTP.
No live migration, source enabling, restart or transfer is part of testing.

```bash
# Windows
.venv/Scripts/python.exe -B -m unittest tests.test_feed_scheduler -v
.venv/Scripts/python.exe -B -m unittest tests.test_jobs tests.test_shared_evidence -v
.venv/Scripts/python.exe -B -m unittest discover -s tests -t . -q

# Linux
.venv/bin/python -B -m unittest tests.test_feed_scheduler -v
.venv/bin/python -B -m unittest tests.test_jobs tests.test_shared_evidence -v
.venv/bin/python -B -m unittest discover -s tests -t . -q
```

## Activation After Separate Approval

No activation was performed for this subphase. First obtain direct approval
for the named source's exact collection scope, quota/cadence policy, live
migration and restart. Review source terms and create its explicit `Source`
entry through the shared-evidence API. Never copy approval from registry
notes, a feed response or these examples.

After an approved live migration, open the existing interpreter from the
project root (`.venv/Scripts/python.exe -B` on Windows or
`.venv/bin/python -B` on Linux). These Python lines configure one already
approved source; they do not fetch it or approve its review metadata:

```python
import asyncio
from app.core.feed_scheduler import Scheduler
from app.modules.vulnerability_intelligence.scheduled import catalog
setup_loop = asyncio.new_event_loop()
scheduler = Scheduler(catalog(), setup_loop)
scheduler.initialize()
scheduler.configure("cisa_kev", enabled=True)
setup_loop.close()
```

Use `enabled=False` to stop that schedule. Replace the example source only
with the individually reviewed, approved key. The setup loop does no feed
execution. Runtime feed jobs use the application's existing loop.

Separately enable `SCHEDULED_FEEDS_ENABLED=true` in the local ignored `.env`
and perform the approved normal app restart. The app startup initializes
schema and starts the opt-in timer. Do not start a second app process. Check
Health, source data and actual bounded live results before v1 daily use.
Turning the worker switch off requires the normal approved restart; a source
or per-source schedule can be revoked between units without restarting.

## Approved Read-Only Git Inspection

After approval on 2026-11-26, these confirmed `main` at `eff4b41`, an empty
index and the intended code changes. No remote contact occurred.

```bash
git status --short
git diff --stat
git diff --check
git diff --cached --name-only
git branch --show-current
git log -1 --format="%h %s"
git diff -- ROADMAP.md docs/handoff.md docs/journal.md
```

The three shared documents also contain separate actor-prototype edits.
Preserve those in the working tree and stage only 5F.3 content from those
files. Prototype files, Feedly rules, local settings, runtime data, secrets
and exports are excluded. Commit/push commands require their own approvals.

## Exact Checkpoint Commands After Commit Approval

The prepared snapshots below are ordinary document copies under ignored
`data/5f3-checkpoint/`. They omit only the prototype blocks named in the
manifest, leaving the real working files unchanged. Rebuild them from the
latest working text if any shared document changes. Stop if a named block
is missing, duplicated, or contains new work outside the reviewed scope.

```powershell
$checkpointSpecs = @(
    @('ROADMAP.md', '(?ms)^- Starting code: prototypes/actor_profiles_prototype/.*?(?=^- Threat actor profiles \(their own module)'),
    @('docs/journal.md', '(?ms)^### 2026-11-26: Validated and Parked the Actor Profiles Prototype\r?\n.*?(?=^### )'),
    @('docs/handoff.md', '(?ms)^## Parked Phase 9 Prototype\r?\n.*?(?=^## Next-Chat Prompt)')
)
$checkpointScratch = Join-Path (Get-Location).Path 'data/5f3-checkpoint'
[System.IO.Directory]::CreateDirectory($checkpointScratch) | Out-Null
foreach ($checkpointSpec in $checkpointSpecs) {
    $checkpointOriginal = [System.IO.File]::ReadAllText((Join-Path (Get-Location).Path $checkpointSpec[0]))
    $checkpointPattern = [regex]::new($checkpointSpec[1])
    if ($checkpointPattern.Matches($checkpointOriginal).Count -ne 1) { throw 'Shared section changed' }
    $checkpointContent = $checkpointPattern.Replace($checkpointOriginal, '')
    if (-not $checkpointContent.Contains('5F.3 Complete')) { throw '5F.3 closeout missing' }
    $checkpointSnapshot = Join-Path $checkpointScratch (($checkpointSpec[0] -replace '/', '_') + '.snapshot')
    [System.IO.File]::WriteAllText($checkpointSnapshot, $checkpointContent, [System.Text.UTF8Encoding]::new($false))
}
```

After the individually approved exact manifest/message, stage the other 55
paths normally and use the three prepared blobs for the shared documents.
This writes the Git index; do not run it under read-only approval alone.

```powershell
$checkpointManifest = Get-Content 'docs/review/2026-11-26-5f3-checkpoint-files.md' -Raw
$checkpointBlock = [regex]::Match($checkpointManifest, '(?s)```text\r?\n(.*?)\r?\n```')
if (-not $checkpointBlock.Success) { throw 'Exact manifest missing' }
$checkpointPaths = @($checkpointBlock.Groups[1].Value -split '\r?\n')
if ($checkpointPaths.Count -ne 58) { throw 'Unexpected path count' }
$checkpointShared = @('ROADMAP.md', 'docs/journal.md', 'docs/handoff.md')
$checkpointWhole = @($checkpointPaths | Where-Object { $_ -notin $checkpointShared })
git add -- @checkpointWhole
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
foreach ($checkpointPath in $checkpointShared) {
    $checkpointSnapshot = Join-Path 'data/5f3-checkpoint' (($checkpointPath -replace '/', '_') + '.snapshot')
    $checkpointBlob = git hash-object -w --path=$checkpointPath -- $checkpointSnapshot
    if ($LASTEXITCODE -ne 0) { throw 'Blob creation failed' }
    git update-index --add --cacheinfo "100644,$checkpointBlob,$checkpointPath"
    if ($LASTEXITCODE -ne 0) { throw 'Shared staging failed' }
}
$checkpointStaged = @(git diff --cached --name-only)
if ($LASTEXITCODE -ne 0) { throw 'Staged inspection failed' }
if (Compare-Object ($checkpointPaths | Sort-Object) ($checkpointStaged | Sort-Object)) {
    throw 'Staged paths differ from the approved manifest'
}
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Whitespace check failed' }
git diff --cached --stat
git diff --cached -- ROADMAP.md docs/journal.md docs/handoff.md
# Review these diffs and confirm the prototype additions are absent.
git commit -m 'Add scheduled feed refresh and source health'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git log -1 --format="%h %s"
git status --short
```

After the resulting commit is shown, obtain separate push approval. Verify
the destination without displaying embedded credentials. For the verified
`origin/main` destination, do not force push:

```powershell
git push origin main
if ($LASTEXITCODE -ne 0) { throw 'Push failed' }
git rev-parse HEAD refs/remotes/origin/main
git ls-remote --exit-code origin refs/heads/main
git status --short
```

The local and live remote hashes must agree. Report the actual result in the
closing message. Prepared checkpoint notes cannot contain their own future
commit ID; do not amend repeatedly to chase that self-reference.
