# Indexed Cloud Metadata Leads

Written 2026-11-27. Subphase 3A.6. One disabled Shodan search consumer.
See [API Review](../research/2026-11-27-cloud-exposure-api-review.md).
No live source enabling, selector submission, data request or migration/restart.

## Read and Match Locally

After separately approved normal startup, open /cloud-exposure for per-domain
Last Attempt, Last Good Window, Never Loaded, Current, Stale, Failed and
Incomplete state. Daily cadence; stale after two days. Last Good Window
uses the oldest original capture in a consistent terminated bounded search
window. Failed/partial passes preserve prior evidence and its age. History
has 50 captures/page. GETs never submit queries or queue work.

At /alerts add cloud_domain with Exact Typed Value and confirm authority
to monitor locally. Strict IDNA2008, ASCII case and one terminal root dot
canonicalize. No wildcard seeds, aliases, inferred registrable domains,
URLs, IP seeds, fuzzy rules, Boolean syntax or storage-name guessing.
Local selector creation and Match Saved Page grant no external authority.

The fixed query is hostname:"canonical-domain". Locally retain only results
with explicit structured cloud.provider and at least one literal returned
hostname equal to that domain or ending with dot plus domain. domains and
IP manager/ISP text alone never establish a match or cloud attribution.
Other valid rows contribute only bounded service-identity hashes and counts
for window consistency; their metadata is discarded. Original source row
positions survive filtering. No extra search or host lookup follows.

Shodan supplies indexed leads. They do not prove ownership, current
reachability, public exposure, misconfiguration, compromise or maliciousness.
PTR omissions, virtual hosting, stale/reassigned IPs, cloud attribution,
indexing and local limits affect discovery. Empty output is not absence.

## Separate Access and Exact Query Authority

All 37 schedules, workers, bulk and raw storage default off. A source review,
source enabling, schedule enabling, worker switch and expiring exact-query
permission are separate gates. No UI form approves or runs this consumer.

Before live use, approve actual Shodan key/tier, purpose, contractual
automated-use/storage rights, cost, privacy/retention handling and exact
query disclosure. Terms contain an automation restriction alongside the
documented API. No entitlement or contractual resolution is inferred.
Use the existing private SHODAN_API_KEY. SHODAN_CLOUD_ACCESS_REVIEWED defaults
false and SHODAN_CLOUD_ACCESS_TIER blank. Accepted reviewed tier labels:
membership, freelancer, small_business, corporate or enterprise. These are
human records, not account probes. A key configured for enrichment grants
no search approval. No api-info/count/token request is made here.

After direct approval of live database changes and actual disclosure,
start the installed interpreter from project root. These examples document
operator procedures; they grant no approval to an agent:

```bash
# Windows
.venv/Scripts/python.exe -B
# Linux
.venv/bin/python -B
```

Use existing local selector IDs and private approval references:

```python
from app.modules.cloud_exposure import store
permission_id = store.approve(
    selector_id,
    authority_reference=approved_exact_query_and_access_record,
    purpose=approved_defensive_purpose,
    expires_at=approved_aware_future_expiry,
)
store.revoke(permission_id)
store.suppress(selector_id)
```

At most ten distinct domains across permission history. Reapproval gets a
new immutable ID. Permissions bind exact canonical selector/query, local
query/API contract versions, endpoint/projection/page bounds, key digest,
reviewed tier/attestation and monthly credit cap. Any change invalidates old
authority. Suppression stops submission and is not privacy deletion.
Revocation/expiry, selector/source/schedule disabling and cancellation stop
cooperative work at retry, quota/wait, transport, stream, stage and each
ingestion row. In-flight requests cannot be retracted.

## Bounds, Quotas and Recovery

Each job freezes up to ten permission IDs and two page slots each, including
an immutable empty plan. Only fixed GET /shodan/host/search is allowed with
key, query, page, minify=true and the fixed metadata fields projection.
No facets, links, redirects, returned destinations, historical cursor,
anonymous fallback or key rotation. minify alone is insufficient; unexpected
content-bearing fields fail closed. Real nested projection needs measurement.

Each attempt: 20 requests, 40 MiB charged allowance and 120 seconds for new
work. Each response: 2 MiB, identity encoding and 30 seconds including
streaming. Normalized page: 512 KiB, 100 service records, at most 32 hostnames
and 32 domains per record. No silent truncation of literal fields. Three
total attempts, including interruptions. SQL/parsing can finish after a
cooperative deadline; no forced thread/process cutoff is claimed.

Durable rolling limits: 20/minute and 48/day in shodan_cloud_search.
One-second request slots persist across restarts. Waits happen outside SQL
and recheck authority. A backwards clock causing over two seconds of queued
delay produces a bounded durable retry instead of an unbounded sleep.
SHODAN_CLOUD_MONTHLY_CREDITS defaults to 20 (allowed 1 to 1,000). Reserve one
credit per attempted page, including failed/refetched/interrupted requests.
No refunds and no reset on key changes. Exhaustion pauses to the next UTC
month. This is a conservative consumer-local ceiling, not a measured balance
or account-wide service. Existing enrichment/manual/other-app usage remains
outside it and needs coordination before live use.

429/503 persist bounded numeric or HTTP-date Retry-After (300-second minimum,
one-year maximum). Other retriable errors use the existing finite runner
backoff. Access/query errors fail closed. No provider error text, headers,
key, private query or raw body enters job errors/capture request metadata.

Validated normalized input is immutable under original capture/run/digest.
Assertions, literal IP citations, stable Shodan IP/port/transport events,
local matches and page completion commit atomically. A later timestamp,
product or cloud label retains the same alert/review for that selector and
service, while new immutable evidence stays separate. This identity can
conflate reassigned IP services; it never establishes an asset identity.
Capture and inbox views display each captured assertion and its date.

Staged input resumes without transport. Committed pages skip transport.
Finalization repairs without resetting reviews. Before-stage crashes may
refetch identical bytes into the original capture; changed bytes get a new
capture. New daily jobs cannot adopt cancelled/failed scopes. Downtime
creates one due pass, not a missed-day burst. SQL transactions never span IO.

Only equal totals, expected page lengths, distinct service identities and
no provider partial flags renew per-domain success within the 200-row cap.
Short/duplicate/drifting/over-cap windows keep leads and remain incomplete.
Nonempty per-result metadata.truncated lists also keep the window incomplete;
those flags are not silently discarded with unrelated metadata.
Even a consistent termination is not an atomic provider snapshot or proof
of complete indexing. No historical reload or deletion/clean verdict.

## Provenance, Dates and Handling

Only bounded literal IP, port, transport, hostnames, domains, org, isp, asn,
product, version, timestamp and cloud provider/region/service survive for
leads. Row locators retain original page/matches index. IP citations remain
passive unresolved provider values, never constructed target URLs. Visible
Shodan credit and ownership/copyright wording accompanies the results.

timestamp is provider banner acquisition, documented as UTC even when its
literal spelling lacks an offset. observed_at normalizes that explicit
meaning; literal timestamp remains intact. Missing/null dates remain unknown.
Index ingestion/update, publication, modification and first/last observation
dates stay unknown. Local First Capture is our earliest retained acquisition
of this Shodan service, distinct from provider time.

Raw originals are sensitive and forced omitted even with generic archive
settings. Digests identify bytes, not authenticity. No export, encrypted
quarantine, privacy deletion or evidence-history pruning is added.

## Repeat Offline Acceptance

From project root, using only synthetic fixtures and temporary databases.
Importing tests installs the established HTTP refusal guard:

```bash
# Windows
.venv/Scripts/python.exe -B -m unittest tests.test_cloud_exposure tests.test_alerts tests.test_shared_evidence -q
.venv/Scripts/python.exe -B -m unittest discover -s tests -t . -q
# Linux
.venv/bin/python -B -m unittest tests.test_cloud_exposure tests.test_alerts tests.test_shared_evidence -q
.venv/bin/python -B -m unittest discover -s tests -t . -q
```

Windows may require the established external test launcher because the
managed venv launcher cannot start. No interpreter or dependency repair is
part of these commands. Actual acceptance results are in the
[Closeout](../review/2026-11-27-3a6-closeout.md). Linux and native-browser
visual acceptance remain separate.

## Separately Approved Measured Live Acceptance

Resolve actual contractual/API-use/storage rights, key/tier/purpose, cost,
privacy/retention and exact query disclosure first. Separately approve live
migration/restart and source/schedule/worker enabling. Then authorize one
small exact-domain search window and measure projection/envelope/nulls,
literal dates, counts/paging drift, request/body sizes, durations, index lag,
actual credit debits, errors/cooldown, freshness and restart recovery. Do not
probe the targets or substitute another provider. Record unresolved limits.

Git inspection, each selective commit and each push need direct current-chat
approval. The authored scope inventory is not an inspected diff or approval.
See [Session Handoff](session-handoff.md). The operator approved local
read-only inspection for 3A.6. It confirmed
main, HEAD/local origin/main at 5cbcc426f3e16fc254258be12f60de8a3302678d and
an empty index. No remote was contacted. Actual 3A.5 completion therefore
supersedes saved prepared notes. Commands from project root:

```bash
git status --short
git diff --stat
git diff --cached --name-only
git rev-parse HEAD refs/remotes/origin/main
git branch --show-current
git diff --check
git show HEAD:docs/handoff.md
git show HEAD:AGENTS.md
git diff -- .env.example app/core/alerts.py app/core/config.py app/core/db.py app/core/feed_catalog.py app/main.py app/modules/alerts/routes.py app/templates/alerts.html app/templates/base.html tests/test_breaches.py tests/test_ct_watch.py tests/test_github_exposure.py tests/test_ransomware.py tests/test_subdomains.py
git diff -- AGENTS.md CLAUDE.md ROADMAP.md docs/handoff.md docs/journal.md docs/runbooks/shared-evidence.md docs/runbooks/durable-jobs.md docs/runbooks/scheduled-feeds.md docs/runbooks/alert-inbox.md docs/runbooks/v1-data-freshness.md
```

The whole-tree whitespace check found independent roadmap trailing spaces
and extra EOF blank lines introduced by the test-count edit. Corrected only
our extra EOF lines. Preserve the unrelated roadmap text and omit it from
the selective checkpoint. Global-ignore permission and LF/CRLF warnings
changed no configuration. Read new untracked feature files directly too;
ordinary git diff omits them. Commit and push still need separate approvals.

Prepared source copies under ignored data/3a6-checkpoint/ exclude independent
shared-document edits. The local helper reads HEAD, extracts only the five
named shared-document blocks and copies the remaining reviewed paths. It
writes paths.json, digests.json and source copies; it does not stage or
create Git objects. Repeat only within an approved local Git review:

```powershell
& data/3a6-checkpoint/prepare.ps1
git ls-files -- .env.example AGENTS.md CLAUDE.md ROADMAP.md docs/handoff.md docs/journal.md
git diff --no-index --no-ext-diff -- data/3a6-checkpoint/base/ROADMAP.md data/3a6-checkpoint/source/ROADMAP.md
```

Exit 1 from no-index means differences were found; greater than 1 is an
error. The prepared review.patch has all 25 tracked selective diffs, with
12 new feature files reviewed directly. Refresh copies after final doc
edits and verify all 37 digests before any individually approved checkpoint.
The helper remains local and is not committed. Future staging must use only
these approved copies/paths, never whole shared working files by default.

## Selective Commit After Its Individual Approval

The prepared message is Add bounded indexed cloud metadata leads. These
commands are a repeatable procedure, not authorization. Run them only after
the operator directly approves the exact final 37 paths/copy digests and
that message. Stop on an unexpected base, nonempty index, changed copy,
membership mismatch, hook failure or command error. Never bypass the hook:

```powershell
$checkpointPaths = @(Get-Content data/3a6-checkpoint/paths.json -Raw | ConvertFrom-Json)
$checkpointDigests = @(Get-Content data/3a6-checkpoint/digests.json -Raw | ConvertFrom-Json)
if ($checkpointPaths.Count -ne 37 -or $checkpointDigests.Count -ne 37) { throw 'Unexpected scope' }
if ((git rev-parse HEAD) -ne '5cbcc426f3e16fc254258be12f60de8a3302678d') { throw 'Base changed' }
if (@(git diff --cached --name-only).Count) { throw 'Unexpected index content' }
foreach ($checkpointPath in $checkpointPaths) {
    $checkpointCopy = Join-Path data/3a6-checkpoint/source $checkpointPath
    $checkpointExpected = @($checkpointDigests | Where-Object path -eq $checkpointPath)
    if ($checkpointExpected.Count -ne 1 -or (Get-FileHash -LiteralPath $checkpointCopy -Algorithm SHA256).Hash.ToLowerInvariant() -ne $checkpointExpected[0].sha256) { throw 'Reviewed copy changed' }
    $checkpointBlob = git hash-object -w --path=$checkpointPath -- $checkpointCopy
    if ($LASTEXITCODE -ne 0) { throw 'Blob creation failed' }
    git update-index --add --cacheinfo "100644,$checkpointBlob,$checkpointPath"
    if ($LASTEXITCODE -ne 0) { throw 'Selective staging failed' }
}
$checkpointStaged = @(git diff --cached --name-only)
if (Compare-Object ($checkpointPaths | Sort-Object) ($checkpointStaged | Sort-Object)) { throw 'Staged scope differs' }
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Staged whitespace check failed' }
git diff --cached --stat
# Inspect exact staged content against the reviewed selective copies.
git commit -m 'Add bounded indexed cloud metadata leads'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed; inspect without bypassing the hook' }
git log -1 --format="%H %s"
git diff --cached --name-only
```

Show the actual resulting commit and verified intended origin/main destination
before requesting separate push approval. An individually approved push uses
git push origin main, followed by local and live remote hash comparison and
empty-index verification. Never infer that approval from this procedure.
No Git action enables collection, migrates the live database or backs up
ignored runtime data.
