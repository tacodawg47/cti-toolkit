# Ransomware Victim Claims and Watches

Written 2026-11-26. Subphase 3A.1. API-only implementation, offline acceptance.
No live migration/restart or source enabling has occurred. No dependency added.
Source review: [Current API Review](../research/2026-11-26-ransomware-api-review.md).

## Read and Review Locally

After a separately approved startup, open `/ransomware`. The page lists 50
saved claims with Older Claims paging. A claim page lists 50 immutable
captures at a time, including literal references, discovery dates, original
availability and originating/current job states. No GET collects data,
scans old observations, resolves references or runs archive maintenance.
Actor references and victim websites are passive escaped text.

Use `/alerts` to add watches after confirming authority to monitor locally.
Each definition is an independent match, so several watches operate as OR,
not a combined organization/sector/country filter. Existing 100-definition
capacity, enable/disable, paged catch-up and revision-checked review apply.

| Watch | Exact Semantics |
|---|---|
| Organization | Exact post title after Unicode NFKC, case folding and whitespace collapse. Punctuation remains significant. No substring, fuzzy name, corporate alias, URL-host or domain expansion. A title may differ from an organization's formal name. |
| Sector | Exact normalized explicit structured source label. No taxonomy crosswalk, description mining or inferred classification. |
| Country | Explicit two-letter ASCII source code, normalized to uppercase. No country-name aliases, geography inference or code-to-country verification service. |

RansomLook's documented Post schema supplies neither sector nor country.
Those watches are supported by the normalized contract and synthetic
integration fixtures, but this adapter creates no such observations. It
ignores undocumented extra fields. Missing fields remain unknown.

## Claims, Captures and Reviews

Source claim identity is source plus case-insensitive group plus the literal
exact post title, including whitespace. This follows RansomLook's documented
post lookup identity. A title rename creates another claim. Different groups
remain different claims. There is no automatic entity-resolution judgment.

Every capture has separate immutable reported observations and citation
edges. The inbox's optional stable event key deduplicates by watch, source
claim and subject type. Existing generic evidence still deduplicates by
observation. Repeat snapshots retain the original alert, review revisions
and originating capture. Claim history links subsequent captures. Disabling
and re-adding an identical watch never resets or re-enables it.

Discovery stays in its own literal field. Date-only and aware instants can
also be normalized as source observation dates. Naive values stay literal
with no invented timezone. Publication, modification, first/last seen and
attack dates remain unknown when absent. Collection time and execution
identity come from the captured response, never from source text. Citation
hops remain literal, unresolved unless explicitly resolved locally.

## Bounds and Recovery

The trusted `ransomlook_recent` registration allows exactly one HTTPS endpoint,
one request, 2 MiB response/charged bytes and 60 seconds for new work per
attempt. No redirect or pagination expansion. Each snapshot has 1 to 100
validated rows; empty/malformed/duplicate/oversized input does not renew good
status. Normalized staged input is capped at 1 MiB. Each attempt drains at
most one old batch before fetching and one received batch afterward, at most
200 rows total. The runner allows three attempts with durable backoff.

The shared app loop, client and limiter remain the HTTP owners. The durable
ledger enforces 1/minute and 24/day; the existing limiter applies those local
bounds too. A 429 persists cooldown and honors bounded Retry-After. Registry
eligibility, schedule state, cancellation and elapsed budget are rechecked
at requests, after quota waits, at each row and inside write transactions.
An in-flight request cannot be retracted; new work stops cooperatively.

Validated normalized batches persist independently of raw bodies. Claim,
capture association, observations, citations, alerts and the row cursor
commit atomically. Resume saved input before retrieving a changed snapshot.
Failed terminal batches can drain under a later eligible pass; cancelled
queues are retained but excluded from automatic resumption. A future newly
authorized snapshot may legitimately include those source claims again.
Retrieval, committed ingestion, attempts and scoped coverage stay separate.
The interrupted originating run stays visible even when the job later succeeds.

Raw storage is forced off for this adapter even if the generic archive
configuration names this source as public. Encoded source HTML, screenshots,
descriptions and unknown extra fields are discarded. Capture digests and
availability metadata remain. Synthetic metadata-only archive fixtures verify
that expiry preserves queues, citations and reviews. No raw serving route.
There is no history pruning or privacy-deletion implementation in this slice.

## Freshness and Operational Limits

Cadence is one hour and stale threshold six hours. These are local proposals,
not provider guarantees. Current means a validated, ingested recent snapshot.
Coverage says latest 100 posts only; historical completeness and continuity
are not assessed. Posts lost between snapshots or during downtime may be
missing. Restart creates one due pass, not a burst of missed intervals.
Failure preserves the last good capture age and coverage. Never Loaded,
Stale, Failed and Incomplete stay visible on consuming pages.

The composed catalog has 32 schedules; the existing vulnerability catalog
retains its 31. All schedules, feed worker, bulk work and generic raw storage
default off. This does not establish v1 operational readiness. Linux and
native-browser visual acceptance remain unperformed. Before live acceptance,
approve the exact source review/eligibility, migration, restart and a small
bounded refresh/recovery test. Measure real response size, schema, elapsed
time, freshness lag, quota behavior and restart outcome. No historical reload.

## Repeat Offline Acceptance

Run from the repository root with the installed environment. All databases
are temporary; HTTP uses MockTransport or the existing network-refusal guard.

```bash
# Windows: focused, grouped, full compatibility
.venv/Scripts/python.exe -B -m unittest tests.test_ransomware -q
.venv/Scripts/python.exe -B -m unittest tests.test_ransomware tests.test_alerts tests.test_foundation_acceptance tests.test_saved_reports tests.test_feed_scheduler tests.test_jobs tests.test_shared_evidence -q
.venv/Scripts/python.exe -B -m unittest discover -s tests -t . -q
# Linux equivalents
.venv/bin/python -B -m unittest tests.test_ransomware -q
.venv/bin/python -B -m unittest discover -s tests -t . -q
```

The Windows venv launcher has the established managed-launch restriction.
Authorized tests ran through the existing execution path outside that
restriction, with no interpreter, package or security-setting changes.
Activation procedures remain in [Scheduled Feeds](scheduled-feeds.md).
For this source, use `app.core.feed_catalog.catalog` and `ransomlook_recent`
after direct approval and a real registry review. No example grants approval.
Git inspection, commit and push each require current-chat authorization;
see [Session Handoff](session-handoff.md).

## Approved Read-Only Checkpoint Inspection

Approved in this chat and completed 2026-11-27. These are a record, not future
permission. Main/local origin/main matched a947eb0 and the index was empty.
No remote was contacted. Global-ignore permission and LF/CRLF notices were
nonfatal. Whole-tree whitespace identified an unrelated roadmap addition;
focused tracked 3A.1 whitespace passed. Preserve unrelated changes outside
the selective checkpoint.

```bash
git status --short
git diff --stat
git diff --cached --name-only
git branch --show-current
git rev-parse HEAD refs/remotes/origin/main
git log -1 --format="%H %s"
git diff --check
git diff -- ROADMAP.md docs/journal.md docs/handoff.md
```

Review the other named tracked diffs and new files too. The exact paths and
shared-block scope are in
[Checkpoint Files](../review/2026-11-26-3a1-checkpoint-files.md). The proposed
message is Add API-only ransomware victim tracking and local watches.
Individual commit approval and separate push approval remain required.

## Individually Approved 3A.1 Commit

The operator individually approved the exact 33-path/selective-block proposal
on 2026-11-27. These commands record that approval, not future permission or
a push authorization. Stop on unexpected HEAD, staged paths or diff content.
Prepare the three ignored staging inputs from inspected HEAD plus only 3A.1:

```powershell
$checkpointExpected = 'a947eb0c83f0f5260c1c1844e64d1b8402ffb332'
$checkpointHead = git rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $checkpointHead -ne $checkpointExpected) { throw 'HEAD changed' }
if (@(git diff --cached --name-only).Count) { throw 'Unexpected staged work' }
$checkpointLF = [string][char]10
$checkpointCR = [string][char]13
$checkpointShared = @('ROADMAP.md', 'docs/journal.md', 'docs/handoff.md')
$checkpointBase = @{}
$checkpointCurrent = @{}
foreach ($checkpointPath in $checkpointShared) {
    $checkpointLines = @(git show "HEAD:$checkpointPath")
    if ($LASTEXITCODE -ne 0) { throw 'HEAD document read failed' }
    $checkpointBase[$checkpointPath] = ($checkpointLines -join $checkpointLF) + $checkpointLF
    $checkpointCurrent[$checkpointPath] = [IO.File]::ReadAllText((Join-Path (Get-Location).Path $checkpointPath)).Replace($checkpointCR+$checkpointLF, $checkpointLF)
}
function Select-CheckpointBlock($textValue, $markerStart, $markerEnd) {
    $startAt = $textValue.IndexOf($markerStart, [StringComparison]::Ordinal)
    $endAt = $textValue.IndexOf($markerEnd, $startAt + $markerStart.Length, [StringComparison]::Ordinal)
    if ($startAt -lt 0 -or $endAt -lt 0) { throw 'Checkpoint marker missing' }
    return $textValue.Substring($startAt, $endAt-$startAt)
}
$checkpointSnapshot = @{}
$checkpointRoadBase = $checkpointBase['ROADMAP.md']
$checkpointRoadCurrent = $checkpointCurrent['ROADMAP.md']
$checkpointOldScope = Select-CheckpointBlock $checkpointRoadBase '**Ransomware and leak-site tracking**' '**Breach and credential-leak monitoring**'
$checkpointNewScope = Select-CheckpointBlock $checkpointRoadCurrent '**Ransomware and leak-site tracking**' '**Breach and credential-leak monitoring**'
$checkpointOldNext = Select-CheckpointBlock $checkpointRoadBase 'The next chat starts Phase 3 slice A' '5F.5 design, decided'
$checkpointNewNext = Select-CheckpointBlock $checkpointRoadCurrent 'Approved read-only inspection on 2026-11-27 confirmed' '5F.5 design, decided'
$checkpointSnapshot['ROADMAP.md'] = $checkpointRoadBase.Replace($checkpointOldScope,$checkpointNewScope).Replace($checkpointOldNext,$checkpointNewNext)
$checkpointResearch = '## Research notes' + $checkpointLF + $checkpointLF
$checkpointNotes = Select-CheckpointBlock $checkpointCurrent['docs/journal.md'] '### 2026-11-27: Inspected the Pending 3A.1 Checkpoint After Approval' '### 2026-11-26: Detection and Utility Catalog Review Complete'
$checkpointSnapshot['docs/journal.md'] = $checkpointBase['docs/journal.md'].Replace($checkpointResearch, $checkpointResearch+$checkpointNotes)
$checkpointHandoff = $checkpointCurrent['docs/handoff.md']
$checkpointHeader = Select-CheckpointBlock $checkpointHandoff '# Current Session Handoff' '## Parked Phase 9 Prototype'
$checkpointFence = ([string][char]96)*3
$checkpointPrompts = [regex]::Matches($checkpointHandoff, '(?s)'+$checkpointFence+'text\r?\n(.*?)\r?\n'+$checkpointFence)
if ($checkpointPrompts.Count -lt 1) { throw 'Handoff prompt missing' }
$checkpointSnapshot['docs/handoff.md'] = $checkpointHeader + '## Next-Chat Prompt' + $checkpointLF+$checkpointLF + $checkpointPrompts[$checkpointPrompts.Count-1].Value + $checkpointLF
$checkpointProject = [IO.Path]::GetFullPath((Get-Location).Path)
$checkpointRoot = [IO.Path]::GetFullPath((Join-Path $checkpointProject 'data/3a1-checkpoint'))
if (-not $checkpointRoot.StartsWith($checkpointProject+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Snapshot path outside project' }
New-Item -ItemType Directory -Path $checkpointRoot -Force | Out-Null
foreach ($checkpointPath in $checkpointShared) {
    $checkpointName = $checkpointPath.Replace('/','_')
    [IO.File]::WriteAllText((Join-Path $checkpointRoot ($checkpointName+'.base')), $checkpointBase[$checkpointPath], [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $checkpointRoot ($checkpointName+'.snapshot')), $checkpointSnapshot[$checkpointPath], [Text.UTF8Encoding]::new($false))
}
'Prepared three selective snapshots; index unchanged.'
```

Review each `.base` versus `.snapshot` with `git diff --no-index --` before
staging. Exit 1 means that expected differences exist. Only Phase 3 source/
scope/status and the foundation next-step paragraph belong in ROADMAP.md.
Only the two 3A.1 entries belong in the journal. Handoff includes its current
3A.1 header and final prompt, excluding independent prototype/research blocks.
The snapshots are ignored staging inputs, never commit targets.

After reviewing those selective snapshots, stage and inspect the approved
paths. These are the exact commands used for this checkpoint:

```powershell
$checkpointText = Get-Content 'docs/review/2026-11-26-3a1-checkpoint-files.md' -Raw
$checkpointFence = ([string][char]96)*3
$checkpointBlock = [regex]::Match($checkpointText, '(?s)'+$checkpointFence+'text\r?\n(.*?)\r?\n'+$checkpointFence)
$checkpointPaths = @($checkpointBlock.Groups[1].Value -split '\r?\n')
if ($checkpointPaths.Count -ne 33 -or @($checkpointPaths | Sort-Object -Unique).Count -ne 33) { throw 'Unexpected manifest' }
if ((git rev-parse HEAD) -ne 'a947eb0c83f0f5260c1c1844e64d1b8402ffb332') { throw 'HEAD changed' }
if (@(git diff --cached --name-only).Count) { throw 'Unexpected staged work' }
$checkpointShared = @('ROADMAP.md','docs/journal.md','docs/handoff.md')
$checkpointWhole = @($checkpointPaths | Where-Object { $_ -notin $checkpointShared })
git add -- @checkpointWhole
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
foreach ($checkpointPath in $checkpointShared) {
    $checkpointSnapshot = Join-Path 'data/3a1-checkpoint' ($checkpointPath.Replace('/','_')+'.snapshot')
    $checkpointBlob = git hash-object -w --path=$checkpointPath -- $checkpointSnapshot
    if ($LASTEXITCODE -ne 0) { throw 'Snapshot failed' }
    git update-index --add --cacheinfo "100644,$checkpointBlob,$checkpointPath"
    if ($LASTEXITCODE -ne 0) { throw 'Index update failed' }
}
$checkpointStaged = @(git diff --cached --name-only)
if (Compare-Object ($checkpointPaths | Sort-Object) ($checkpointStaged | Sort-Object)) { throw 'Staged paths differ from approved manifest' }
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Staged whitespace failed' }
git diff --cached --stat
git diff --cached -- ROADMAP.md docs/journal.md docs/handoff.md
```

After inspecting the staged scope and whitespace, create the individually
approved commit. Stop if any hook or commit step fails; do not bypass it.

```powershell
git commit -m 'Add API-only ransomware victim tracking and local watches'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git log -1 --format="%H %s"
git status --short
```

Check the resulting commit and intended origin/main destination. Obtain
separate push approval before any push. Record the actual hash and outcome
in the closing message; do not amend a commit to include its own hash.
