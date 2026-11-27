# Passive Subdomain Inventory

Written 2026-11-27. Subphase 3A.5. One disabled CTLogs API consumer.
See [API Review](../research/2026-11-27-subdomain-api-review.md). No live data
request, selector submission, source approval, install, migration or restart.

## Read and Match Locally

After separately approved startup, open /subdomains for per-domain last
attempt, last good bounded window, Never Loaded, Current, Stale, Failed and
Incomplete state. Daily cadence; stale after two days. Good age uses the
oldest original page capture, including after restart. A failed or partial
pass preserves earlier evidence and age. History has 50 captures per page.
Capture views show literal names, distinct dates, original/current runs and
inbox reviews. All GETs are passive. No form submits or enables collection.

At /alerts create subdomain_domain with Exact Typed Value and confirm local
monitoring authority. Use a full exact owned/authorized domain. Strict
IDNA2008, ASCII case and one terminal root dot canonicalize; no aliases,
URLs, IPs, ports, wildcard seeds, fuzzy or permutation expansion. Local
matching is query attribution to this exact approved inventory domain.
Generic domain, CT lookalike and GitHub selectors keep their existing rules.
An inventory observation is not inferred live DNS or a confirmed asset.

Returned names must equal the approved domain or end in a complete dot-label
boundary. Literal *. patterns remain distinct from their bases and hosts.
No DNS, target probing, page/certificate body fetch or wildcard expansion.
Names do not establish ownership, registration time, a dangling service,
compromise or maliciousness. Empty results do not establish absence.

## Access and Separate Submission Authority

Paging needs a CTLogs key. Before any live use, directly approve the actual
purpose, terms, free non-commercial versus paid entitlement, cost, privacy/
retention handling and exact-domain disclosure. Store CTLOGS_API_KEY privately
in ignored .env and set CTLOGS_ACCESS_TIER to free_noncommercial or paid only
after that review. Both default blank. The tier is a human record, not an
entitlement probe. Business operations need paid access under current terms.
No account, key, subscription or registry eligibility was obtained here.

All 36 schedules, workers, bulk and raw storage default off. The one added
schedule is subdomain_inventory. Registry approval/enabling, schedule/worker
configuration and expiring exact-domain permissions are distinct gates.
Source terms remain unapproved. A key or local selector grants none of them.

After separate live database, access and exact disclosure approval, open the
installed interpreter from project root. These are repeatable operator
commands, not permission for an agent to run them on the live database:

```bash
# Windows
.venv/Scripts/python.exe -B
# Linux
.venv/bin/python -B
```

Use approved existing local selector IDs and private record references:

```python
from app.modules.subdomains import store
permission_id = store.approve(
    selector_id,
    authority_reference=approved_exact_domain_and_access_record,
    purpose=approved_defensive_purpose,
    expires_at=approved_aware_future_expiry,
)
store.revoke(permission_id)
store.suppress(selector_id)
```

At most ten distinct domains across permission history. Reapproval creates
a new ID and never replaces queued authority. Permissions bind canonical
domain, endpoint/query/API versions, key digest and reviewed tier. Revocation,
expiry, suppression, changed key/tier/version, selector/source/schedule
disabling and cancellation stop new work at cooperative boundaries, including
post-quota, streaming, staging and each ingestion row. In-flight traffic
cannot be retracted. Suppression stops submission; it is not privacy deletion.

## Bounds and Recovery

One job freezes up to ten permission IDs and two page slots each, including
an immutable empty plan. Page two uses only the original committed page's
opaque cursor at the same fixed GET /v1/hosts/{domain}. No links, redirects,
other APIs, anonymous fallback, key rotation or quota probes are followed.
Cursor syntax is deliberately conservative; live acceptance must verify it.

Each attempt: 20 requests, 40 MiB charged body allowance, 120 seconds for new
work. Each response: 2 MiB, 30 seconds including streaming, identity encoding
only. Each page: at most 100 names, 256 KiB normalized input. Three attempts.
Local durable rolling limits: 20/minute and 48/day in ctlogs_hosts, sequential
requests. Other apps/manual traffic are not covered. 429/503 save bounded
numeric Retry-After or finite 300/600/1200-second backoff. Successful zero
monthly/hourly/daily remaining headers save cooldown to the next UTC boundary
before a recoverable capture is staged. No reset endpoint is queried.

Validated normalized input is immutable under original capture/run/digest.
Assertions, literal host citations, stable source/name events, local matches
and page completion commit atomically. Staged input resumes without fetching;
committed pages skip transport; finalization repairs without resetting review.
A pre-stage crash can refetch identical bytes into the original capture;
changed bytes need their own capture. Cancelled/failed scopes are never
adopted by a new daily scope. Downtime plans one pass, not a catch-up burst.
Database transactions never span network requests. Parsing/SQL can complete
past a cooperative soft deadline; no forced process/thread stop is claimed.

Terminated, distinct, ordered pages without partial flags renew per-domain
success. A remaining third page, duplicate, out-of-order or partial response
retains evidence but stays incomplete. Even consistent termination cannot
prove provider completeness or detect all between-page drift. Coverage is
only certificates valid now or expired within 90 days and at most 200 names.
No automatic historical reload, negative/deletion verdict or expansion.

## Provenance and Dates

Only literal host, certificate count and provider date fields survive row
normalization. Unknown fields are discarded and sensitive raw forced omitted.
Domain/cursor/headers stay out of capture/job request metadata. Private
permission records retain the exact query. Logs use fixed failure codes.

Provider first_seen/last_seen are earliest/latest certificate validity starts
in this window; last_not_after is the latest certificate expiry. Missing or
null fields stay unknown. They are not SCT logging or registration dates.
Local First Capture is the earliest retained CTLogs acquisition for that
canonical literal name/pattern, separate from provider dates. Generic source
publication/modified/observation/first-seen dates stay unknown. Literal host
citations have source row locators, remain unresolved and never become
invented certificate/log URLs. Visible ctlogs.dev credit is included.
No export, encryption, privacy deletion or evidence pruning is added.

## Repeat Offline Acceptance

Verified 2026-11-27: focused 113 passed in 91.091 seconds plus two final
recovery cases in 2.563 seconds. The final inventory has 38 tests. Full suite:
841 tests in 302.124 seconds, 840 passed and one existing skip.

The existing tests package installs the HTTP refusal guard. Fixtures replace
transport with synthetic responses and use temporary databases only:

```bash
# Windows
.venv/Scripts/python.exe -B -m unittest tests.test_subdomains tests.test_github_exposure tests.test_alerts tests.test_shared_evidence -q
.venv/Scripts/python.exe -B -m unittest discover -s tests -t . -q
# Linux
.venv/bin/python -B -m unittest tests.test_subdomains tests.test_github_exposure tests.test_alerts tests.test_shared_evidence -q
.venv/bin/python -B -m unittest discover -s tests -t . -q
```

Windows required the established external test execution path after the
managed venv launcher failed. No interpreter, dependency or security setting
changed. The dated closeout records actual results and intermediate issues.
Linux execution and native-browser visual acceptance remain unperformed.

## Separately Approved Measured Live Acceptance

Review current terms/access, entitlement, exact authorized disclosure and
handling first. Approve live migration/restart, source eligibility and
schedule/worker configuration separately. Then authorize one small exact
domain request/window and measure actual response schema/nulls/cursor,
request/body sizes, durations, indexing lag, quota headers, cooldown, failure
visibility and restart recovery. Record provider/index and local coverage
gaps. No source activation or transfer approval is implied by this runbook.
Every Git inspection/commit/push retains its separate current-chat approval.

## Individually Authorized Selective Checkpoint

The operator directly approved inspection and commit/push of each reviewed
3A.4/3A.5 checkpoint on 2026-11-27. This 38-path checkpoint follows the actual
3A.4 commit recorded in the handoff. Record a DNS-blocked push separately;
a pending push does not prevent the second authorized local checkpoint.
Keep independent rules, research, prototypes, reconciliation and local
settings out. The 841-test acceptance covers unchanged application code.
Checkpoint documentation edits receive content/diff review.

```powershell
$checkpointPaths = @(Get-Content data/3a45-checkpoint/phase5.json -Raw | ConvertFrom-Json)
$checkpointBase = (Get-Content data/3a45-checkpoint/committed4.txt -Raw).Trim()
if ($checkpointPaths.Count -ne 38 -or (git rev-parse HEAD) -ne $checkpointBase) { throw 'Reviewed scope/base changed' }
if (@(git diff --cached --name-only).Count) { throw 'Unexpected index content' }
foreach ($checkpointPath in $checkpointPaths) {
    $checkpointCopy = Join-Path data/3a45-checkpoint/phase5 $checkpointPath
    $checkpointBlob = git hash-object -w --path=$checkpointPath -- $checkpointCopy
    if ($LASTEXITCODE -ne 0) { throw 'Blob creation failed' }
    git update-index --add --cacheinfo "100644,$checkpointBlob,$checkpointPath"
    if ($LASTEXITCODE -ne 0) { throw 'Selective staging failed' }
}
$checkpointStaged = @(git diff --cached --name-only)
if (Compare-Object ($checkpointPaths | Sort-Object) ($checkpointStaged | Sort-Object)) { throw 'Staged scope differs' }
git diff --cached --check
git diff --cached --stat
# Review exact staged content before using this specific approval.
git commit -m 'Add bounded passive subdomain inventory'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed; inspect, never bypass the hook' }
git log -1 --format="%H %s"
git push origin main
# If push fails, record failure without claiming remote completion.
git rev-parse HEAD refs/remotes/origin/main
git ls-remote --exit-code origin refs/heads/main
git diff --cached --name-only
```

Successful push requires matching hashes and an empty index. Preserve all
independent working edits. Actual results supersede prepared handoff notes.
