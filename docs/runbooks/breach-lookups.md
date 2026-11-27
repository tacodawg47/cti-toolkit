# HIBP Watched Email Lookups

Written 2026-11-27. Subphase 3A.2. API-only implementation and offline
acceptance. Source research: [Current Review](../research/2026-11-27-breach-api-review.md).
No live migration/restart, source enabling, API data request or install.

## Read Results Locally

After a separately approved normal startup, open `/breaches`. It shows at
most ten watched addresses with separate last attempt, last good capture,
stale, failed and incomplete states. Capture history pages show 50 captures
at a time. Capture detail shows immutable provider association claims,
literal dates and references, original availability and originating/current
execution states. Inbox links retain reviews across repeat captures.
Every GET is passive. No form submits email addresses to a provider.

Create an exact email watch through `/alerts` only when authorized for local
monitoring. This does not grant external submission permission. Email local
part case remains significant for local inbox matching. The provider query
lowercases the whole address according to HIBP's case-insensitive contract;
stored observations use the original canonical watch spelling. No aliases,
username expansion, domain enumeration or derived email addresses are queried.

HIBP attribution appears on lookup and associated alert pages. A breach
identifier names a provider claim, not proof of identity or current compromise.
Spam-list, fabricated, unverified, malware and stealer-log flags remain
separate when supplied. Unknown flags/dates remain unknown. Provider breach
date is approximate, AddedDate is addition to HIBP and ModifiedDate is change
in HIBP. None is silently assigned as the observation or collection date.
Minute precision and timezone offsets remain literal. DisclosureUrl stays
an unresolved passive citation; no hop is invented from a name or description.

404 means no publicly disclosable result. Sensitive, retired and opted-out
associations can be missing. It never deletes an earlier association, resets
a review or produces a clean verdict. A 200 with an empty/malformed response
does not renew successful health. History and continuity remain unassessed.

## Submission and Handling Gates

The first delivery permits at most ten distinct local email selector IDs.
Every submission permission needs explicit authority and consent record
references, a defensive purpose and an aware future expiry. These are bounded
local record identifiers, not copies of consent documents or personal details.
Definitions retain approval/revocation history. Reapproval creates another
permission ID; it never replaces the ID saved in queued work.

After direct approval for the named address and live configuration, use the
already installed interpreter from the project root:

```bash
# Windows
.venv/Scripts/python.exe -B
# Linux
.venv/bin/python -B
```

Inside that interpreter, substitute the approved existing selector ID and
real private record references. These operations change the live database;
the agent must obtain direct approval first. They do not fetch data:

```python
from app.modules.breaches import store
permission_id = store.approve(
    selector_id,
    authority_reference=authority_record,
    consent_reference=consent_record,
    purpose=approved_defensive_purpose,
    expires_at=approved_expiry,
)
# Revoke this approval without resetting evidence or reviews:
store.revoke(permission_id)
# Honor suppression for the entire case-insensitive email, including other
# case variants and future approvals. No automatic unsuppress operation:
store.suppress(selector_id)
```

Suppression blocks future breach submissions, including retries/resumption.
It does not delete existing evidence or stop unrelated local corpus matching.
Privacy deletion and encrypted storage require their own policy/work. This
single-operator local app has no new authentication or export route.

Only allowlisted breach metadata enters normalized staging. Passwords,
authentication secrets, descriptions, logos, raw records and unknown fields
are discarded. Common credential patterns in retained metadata are refused.
This guard cannot recognize every possible encoded/contextual secret. Do not
use the module to ingest breach source files. Captures are explicitly sensitive
and raw bodies remain omitted even if generic public archive settings name
the source. Capture digests, literal citations and review history survive
omission/expiry. Headers, error bodies and the email-bearing URL are not
saved in jobs/captures. The saved endpoint is labelled as redacted. Query
audit consists of immutable job/permission units with attempted time, staged
status and completion, linked to originating runs; failures use fixed codes.

## Bounds, Recovery and Freshness

One `hibp_email` registration adds one disabled schedule to the existing 32.
All 33 schedules, the feed worker, bulk and raw storage default off. The
proposed cadence is daily, with a two-day stale threshold. No account purchase,
key configuration, permission, schedule or worker was enabled in this pass.

Each logical pass snapshots at most ten explicit permission IDs. Each attempt
allows ten requests, 1 MiB per response, 10 MiB charged bytes and 120 seconds
for new work. A request has a 30-second wall-clock cap including streaming.
Up to 100 breach associations fit one atomic lookup; larger results fail
visibly rather than truncating. Normalized payload is at most 512 KiB per
lookup. No redirects, extra endpoint, provider-driven pagination or historical
reload. Three total attempts, durable backoff and cooperative cancellation
use the existing runner. Completed units are never requested again by a retry.

The local rolling allowance is 10/minute and 240/day, also applied by the
existing shared-loop limiter. Verify that the paid account permits at least
the configured rate before enabling. Reserve the full response allowance;
successful bounded responses refund unused bytes, failures keep the charge.
429 cooldown persists, honoring bounded Retry-After under the core policy.

Source/schedule/entitlement and selector permission are checked at units,
before requests, after quota waits, after responses/parsing and at atomic
staging/ingestion boundaries. Disabled, expired, revoked or suppressed work
fails closed. An in-flight request cannot be retracted. No revoked permission
can silently resume using a newly granted one.

Staged normalized input survives raw omission and changed upstream data.
On restart, a retry drains its saved lookup before requesting another unit.
All assertions, literal citations, inbox matches and lookup completion commit
atomically. A crash before progress is repaired from committed units. Capture
time and originating run stay unchanged. Failed terminal/cancelled scopes
retain their staged evidence but are not automatically resurrected by a later
daily scope. A later approved pass is a new acquisition, not recovery of that
terminal scope. No job/evidence history pruning is implemented.

Per-address age uses original collection time, including resumed saved input.
A failed pass preserves earlier successful captures. The global source panel
describes the pass; inspect per-address health for the age of actual evidence.
Downtime creates one due pass, not a burst of missed intervals.

## Repeat Offline Acceptance

All databases are temporary and HTTP is MockTransport or the existing refusal
guard. No live database, provider allowance or personal data is used:

```bash
# Windows
.venv/Scripts/python.exe -B -m unittest tests.test_breaches -q
.venv/Scripts/python.exe -B -m unittest tests.test_breaches tests.test_shared_evidence -q
.venv/Scripts/python.exe -B -m unittest discover -s tests -t . -q
# Linux
.venv/bin/python -B -m unittest tests.test_breaches -q
.venv/bin/python -B -m unittest tests.test_breaches tests.test_shared_evidence -q
.venv/bin/python -B -m unittest discover -s tests -t . -q
```

The existing Windows managed-launch restriction required the established
test execution path outside that restriction. No interpreter, package or
security setting was changed. No new dependency was added.

Final focused breach/shared-evidence acceptance: 54 passed in 32.105 seconds,
including all 36 breach cases. Final full compatibility: 717 tests in
180.083 seconds, 716 passed and one existing skip. The intermediate 35-case
breach run passed in 28.061 seconds before the final progress-recovery case.

## Approved Live Acceptance Still Required

Before daily use, review current provider terms and actual paid account
access/RPM/expiry. Obtain direct approval for the exact watched address,
submission, purpose/consent/handling, source review, live migration/restart,
schedule/worker and small measured API acceptance. Put keys only in ignored
`.env`; the blank names are in `.env.example`. Review configuration and
registry using [Shared Evidence](shared-evidence.md) and enable `hibp_email`
through `app.core.feed_catalog.catalog` using [Scheduled Feeds](scheduled-feeds.md).
Never treat examples or account possession as transfer permission.

Measure real schema/body size/time, 404 meaning, quota/cooldown, stale/failure
display and restart recovery. Separately check Linux and native-browser
visual behavior. No live v1 operational acceptance is implied by mocks.
Git inspection, each commit and each push require current-chat approval.

## Approved Local Checkpoint Inspection

The operator approved the read-only checks below on 2026-11-27. They confirmed
main/HEAD/local origin/main at d34a37d and an empty index. No remote was
contacted and no Git mutation occurred. Future chats need new authorization.

```powershell
git status --short
git diff --stat
git diff --cached --name-only
git branch --show-current
git rev-parse HEAD refs/remotes/origin/main
git log -1 --format="%H %s"
git diff --check
$reviewText = Get-Content 'docs/review/2026-11-27-3a2-checkpoint-files.md' -Raw
$reviewBlock = [regex]::Match($reviewText, '(?s)```text\r?\n(.*?)\r?\n```')
$reviewPaths = @($reviewBlock.Groups[1].Value -split '\r?\n')
if ($reviewPaths.Count -ne 34) { throw 'Unexpected manifest' }
git diff -- @reviewPaths
```

Review untracked proposed files directly too. Whole-tree whitespace found the
known unrelated roadmap line. Global-ignore permission and LF/CRLF notices
were nonfatal. Preserve all independent shared-document additions and named
unrelated files. The 34-path manifest requires selective ROADMAP/journal/
handoff blocks. Individual commit approval and separate push remain pending.

## Exact Commit Commands After Individual Approval

The operator individually approved the exact 34-path proposal/message and
explicitly authorized its push on 2026-11-27. The commands record that approval,
not standing permission in another chat. Execution is prepared; use the
closing message for the actual result.
Three reviewed local inputs under ignored `data/3a2-checkpoint/` contain only
the intended shared-document changes. Their bases were recovered from the
approved diffs after verifying each current hunk. The working shared docs
retain all independent content. These commands modify Git; do not execute
them under read-only inspection approval alone:

```powershell
$checkpointText = Get-Content 'docs/review/2026-11-27-3a2-checkpoint-files.md' -Raw
$checkpointBlock = [regex]::Match($checkpointText, '(?s)```text\r?\n(.*?)\r?\n```')
if (-not $checkpointBlock.Success) { throw 'Manifest missing' }
$checkpointPaths = @($checkpointBlock.Groups[1].Value -split '\r?\n')
if ($checkpointPaths.Count -ne 34 -or @($checkpointPaths | Sort-Object -Unique).Count -ne 34) { throw 'Unexpected manifest' }
if ((git rev-parse HEAD) -ne 'd34a37d68aa120b58ee3d18822ccf5ebcc54b31c') { throw 'HEAD changed' }
if (@(git diff --cached --name-only).Count) { throw 'Unexpected staged work' }
$checkpointShared = @('ROADMAP.md','docs/journal.md','docs/handoff.md')
$checkpointWhole = @($checkpointPaths | Where-Object { $_ -notin $checkpointShared })
git add -- @checkpointWhole
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
foreach ($checkpointPath in $checkpointShared) {
    $checkpointSnapshot = Join-Path 'data/3a2-checkpoint' ($checkpointPath.Replace('/','_')+'.snapshot')
    $checkpointBlob = git hash-object -w --path=$checkpointPath -- $checkpointSnapshot
    if ($LASTEXITCODE -ne 0) { throw 'Snapshot failed' }
    git update-index --add --cacheinfo "100644,$checkpointBlob,$checkpointPath"
    if ($LASTEXITCODE -ne 0) { throw 'Selective staging failed' }
}
$checkpointStaged = @(git diff --cached --name-only)
if (Compare-Object ($checkpointPaths | Sort-Object) ($checkpointStaged | Sort-Object)) { throw 'Staged membership differs' }
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Staged whitespace failed' }
git diff --cached --stat
git diff --cached -- ROADMAP.md docs/journal.md docs/handoff.md
# Review these diffs and confirm all independent additions are absent.
git commit -m 'Add bounded HIBP watched-email breach lookups'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git log -1 --format="%H %s"
git status --short
```

Stop on any unexpected HEAD, path, diff, hook or commit failure. Do not bypass
hooks or discard unrelated files. The operator explicitly authorized the push
as well. After checking the actual commit and intended origin/main destination,
use that current-chat approval. No live activation is authorized.

```powershell
git push origin main
if ($LASTEXITCODE -ne 0) { throw 'Push failed' }
git rev-parse HEAD refs/remotes/origin/main
git ls-remote --exit-code origin refs/heads/main
git status --short
git diff --cached --name-only
```

Verify the local/remote hashes match and the index is empty, preserving the
remaining independent working-tree files. Record the actual result in the
closing message. Do not amend the commit to include its own hash.
