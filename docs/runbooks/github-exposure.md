# GitHub Public-Code Exposure Leads
Written 2026-11-27. Subphase 3A.4. Implementation and offline acceptance only.
Source research: [API Review](../research/2026-11-27-github-exposure-api-review.md).
All collection remains off. No live migration, restart or provider request.

## Read Results Locally

After a separately approved startup, open /github-exposure. The page shows
at most ten watched selectors, last attempt, oldest original capture in the
last consistent bounded window, and Current, Stale, Failed or Incomplete
states. Stale means two days old; proposed cadence is daily. Capture pages
show one provider page, its count/partial flags, literal passive references,
originating/current execution and retained inbox reviews. History shows
50 captures with an older-page cursor. All GETs are passive.

Create a local selector at /alerts only for an authorized organization or
domain. Use github_domain or github_organization, Exact Typed Value only.
Domains use strict IDNA2008 spelling; URLs, wildcards, ports and IPs are
refused. Organization values are 3 to 80 plain ASCII letters, numbers,
spaces or hyphens. They name explicit search text, not inferred accounts.
Case normalizes. Quotes, operators, qualifier injection, ambiguous short
names and fuzzy/permutation expansion are refused. No aliases are generated.

The query is the quoted canonical selector followed by in:file. A domain
has at most 200 canonical characters. The legacy API may ignore punctuation
and does not prove an exact content occurrence. Local inbox observations
use dedicated GitHub selector types to attribute a provider result to its
approved query. They never become generic confirmed domain/organization
observations. No code is read to validate the occurrence.

Metadata hits are review leads, not proof of exposure, credential validity,
ownership or maliciousness. Empty results do not establish absence. Search
has default-branch, file-size, fork, activity and other indexing restrictions.
No historical completeness or continuity is claimed.

## Separate Authority and Access

The consumer uses the existing app loop/client/GitHub limiter and one
disabled github_exposure schedule. The composed catalog now has 35 disabled
schedules. Source terms/collection switch, exact query submission permission,
schedule and worker are separate gates. Local selector forms grant none of
these. No web form enables or runs this source.

The existing Phase 2 token is never inherited. After direct access/handling
approval, a human reviews a separate token restricted to public repository
access and records it privately in .env as GITHUB_EXPOSURE_TOKEN. Set
GITHUB_EXPOSURE_PUBLIC_ONLY=true only after that review. Both default unset/
false in the template. The attestation is not automated proof of token scope.
Current endpoint docs contradict themselves on anonymous access and list
fine-grained token support that has not been live-tested here. Never resolve
this by testing credentials without approval or by silently broadening scopes.

Approve source registry eligibility only after resolving the real access,
contractual purpose, privacy/retention and cost conditions. Review each exact
query before sending it. Public indexing does not make private watchlists
non-sensitive. This runbook grants no enabling or transfer permission.

After separate live database and exact selector approval, open the installed
interpreter from project root:

```bash
# Windows
.venv/Scripts/python.exe -B
# Linux
.venv/bin/python -B
```

In that interpreter, substitute approved existing selector IDs and bounded
private record references. These operations change the database and require
direct approval before an agent runs them:

```python
from app.modules.github_exposure import store
permission_id = store.approve(
    selector_id,
    authority_reference=approved_query_and_access_record,
    purpose=approved_defensive_purpose,
    expires_at=approved_aware_future_expiry,
)
store.revoke(permission_id)
store.suppress(selector_id)
```

At most ten distinct selector IDs across permission history. One unrevoked
permission per selector. Reapproval creates a new ID, never replaces queued
authority. Permission binds canonical type/value/query, query version, API
version and token digest. Revocation, expiry, suppression, selector/source/
schedule disablement, changed versions or changed token stop new units,
requests, post-quota waits, stream processing, staging and ingestion at
cooperative boundaries. Renewed authority cannot adopt an old plan. No
unsuppress, export, privacy deletion, encryption or evidence pruning is added.

## Bounds, Provenance and Recovery

One job freezes up to ten permission IDs, including an immutable empty plan.
Each selector has two fixed planned page slots; page 2 is used only when
page 1 reports more than 50 results. No Link or redirect target is followed.
No repository, code, README, blob, profile or secret endpoint can be fetched.
No found secret becomes another query or a tested credential.

Each attempt: 20 requests, 40 MiB charged body allowance and 120 seconds for
new work. Each response: 2 MiB and 30 seconds including streaming. Request
identity encoding and reject compressed bodies to avoid an unbounded decoded
expansion. At most 50 returned items and 256 KiB normalized input per page.
Larger/malformed inputs fail rather than truncate. Only bounded successful
captures refund unused allowance. Parsing and committed SQLite work are
cooperative and can finish past a soft deadline. In-flight requests cannot
be retracted. No network transaction holds a database write lock.

Local rolling caps: 8/minute and 48/day in the shared scheduled GitHub bucket,
in addition to the existing shared-loop provider limiter. These are local
courtesy limits, not a global account quota service for other applications.
403/429 conservatively persist cooldowns, even when a 403 might be access
denial. Honor bounded numeric Retry-After and zero-remaining/reset headers;
otherwise back off 300/600/1200 seconds with three total attempts. Successful
zero-remaining responses stage before the next request pauses. No token
rotation, hidden HTTP retry, rate_limit probe or anonymous fallback.

Normalized page input is immutable under its original document/capture/run.
Assertions, literal citations, local matches and page completion commit in
one transaction. A crash after staging resumes input without a request;
a crash after page commit skips that page. If a crash precedes staging,
newly fetched identical bytes replay the original capture; changed bytes
need their own capture. Final query progress repairs after a crash. Logical
selector progress is independent from response-capture counts, using the
scope's explicit unit_progress option. Existing feeds retain their default.

Stable provider repository-ID/file-path events retain reviews across new
blobs, captures and repository renames. Different query selectors keep
separate alerts and evidence. Catch-up only matches an existing observation's
query attribution; it never infers another organization's involvement.
Terminal failed/cancelled scopes retain staging but another daily job makes
new acquisitions. Downtime creates one due pass, not missed-interval bursts.

All bounded pages must agree on total_count, have no provider incomplete flag,
fit within 100 references, and contain exactly that many distinct file
identities to renew per-selector success. Truncated, short, duplicate or
drifting windows retain leads but stay incomplete. This checks consistency,
not atomic server snapshots or exhaustive indexing. Successful age uses the
oldest original page collection, not completion or resumption time. A global
pass date is not per-selector freshness.

Only repository ID/full name, path, blob SHA and validated literal html_url
are retained. Safe ASCII reference syntax excludes some legitimate results.
Descriptions, dates, profiles, content fields and unknown fields are not
stored. Unexpected content-bearing results are refused. Raw is forced omitted;
captures are sensitive. Common credential guards cannot recognize every
possible secret hidden in a reference. Keep metadata private and ignored.
Queries and headers are absent from capture/job metadata; permission records
retain the exact approved query privately. Logs use fixed failure codes.

Literal html_url citations stay unresolved passive text. No branch, commit
or file date is inferred from a blob SHA or URL. Source publication, modified,
observed and first/last-seen dates remain unknown; local collection and match
times retain their distinct meanings. Body digests identify bytes, not truth.

## Repeat Offline Acceptance

Verified 2026-11-27: focused GitHub/inbox/shared-evidence 77 passed in
51.547 seconds, including 43 GitHub cases. Full compatibility: 803 tests
in 255.655 seconds, 802 passed and one existing skip.

From project root, use the existing environment. Importing tests installs
the HTTP refusal guard; fixtures install only synthetic transports.

```bash
# Windows
.venv/Scripts/python.exe -B -m unittest tests.test_github_exposure tests.test_alerts tests.test_shared_evidence -q
.venv/Scripts/python.exe -B -m unittest discover -s tests -t . -q
# Linux
.venv/bin/python -B -m unittest tests.test_github_exposure tests.test_alerts tests.test_shared_evidence -q
.venv/bin/python -B -m unittest discover -s tests -t . -q
```

Temporary databases only. On this Windows host, the managed launcher could
not start the venv interpreter; the established external test execution path
worked without interpreter, dependency or security-setting changes. See the
dated closeout for measured results and intermediate failures. Linux and
native-browser visual acceptance remain unperformed.

## Separately Approved Measured Live Acceptance

Before daily v1 use, approve the actual source/access/terms scope, public-only
token and exact selector disclosure; handling/removal policy; live migration/
restart; and schedule/worker configuration. Approve one small exact query
and measure schema, request/body sizes, duration, partial/index lag, real
quota headers, cooldown and restart recovery. Keep code/snippets/raw storage
off, never use found secrets, never test their validity and do not expand
into repository or target probing. Record actual measurements and unresolved
coverage. No such approval or provider traffic occurred in 3A.4.

Git inspection, selective commit and push each still require their approvals.
The operator-supplied 3A.3 completion is 749d97351c5158558789afa8a297a461999b9c42,
committed/pushed on 2026-11-27 with matching hashes and an empty index then.
This was reconciled by ordinary documentation edits, without Git commands.
Never infer the current index or working-tree state from that historical result.

## Individually Authorized Selective Checkpoint

On 2026-11-27 the operator directly approved inspection, commit and push of
each reviewed 3A.4/3A.5 checkpoint. Initial main/HEAD/local origin/main was
749d97351c5158558789afa8a297a461999b9c42; the index was empty. Origin is the
existing credential-free GitHub repository, branch main. Independent working
changes and all 3A.5 code are excluded from the 40-path 3A.4 snapshot.
An isolated local copy passed 80 tests in 52.900 seconds, including the 35
schedules. Full 3A.4 acceptance above remains its historical measured run.
Remote inspection encountered an approval-review timeout, then the retry
ran but failed to resolve github.com. No network settings were changed.
Proceed with the individually authorized local commits; record each actual
push result rather than infer that an approved push succeeded.

Repeat the isolated 80-case check with the root venv's absolute path, working
from data/3a45-checkpoint/phase4-test:

```powershell
.venv/Scripts/python.exe -B -m unittest tests.test_github_exposure tests.test_alerts tests.test_shared_evidence tests.test_breaches.BreachTests.test_disabled_defaults_unscoped_fixed_destinations_and_no_implicit_authority tests.test_ct_watch.ConsumerTests.test_34_schedules_default_off_unscoped_and_fixed_surface tests.test_ransomware.RansomwareTests.test_default_disabled_fixed_surface_and_unscoped_calls_refused -q
```

The exact arguments above also work from project root after that selective
checkpoint is checked out. Review inputs below are ignored local copies,
never commit targets. Rebuild/review if HEAD or source changes. Commands
record this authorization and grant no future Git permission:

```powershell
$checkpointPaths = @(Get-Content data/3a45-checkpoint/phase4.json -Raw | ConvertFrom-Json)
if ($checkpointPaths.Count -ne 40) { throw 'Unexpected reviewed manifest' }
if ((git rev-parse HEAD) -ne '749d97351c5158558789afa8a297a461999b9c42') { throw 'HEAD changed' }
if (@(git diff --cached --name-only).Count) { throw 'Unexpected index content' }
foreach ($checkpointPath in $checkpointPaths) {
    $checkpointCopy = Join-Path data/3a45-checkpoint/phase4 $checkpointPath
    $checkpointBlob = git hash-object -w --path=$checkpointPath -- $checkpointCopy
    if ($LASTEXITCODE -ne 0) { throw 'Blob creation failed' }
    git update-index --add --cacheinfo "100644,$checkpointBlob,$checkpointPath"
    if ($LASTEXITCODE -ne 0) { throw 'Selective staging failed' }
}
$checkpointStaged = @(git diff --cached --name-only)
if (Compare-Object ($checkpointPaths | Sort-Object) ($checkpointStaged | Sort-Object)) { throw 'Staged scope differs' }
git diff --cached --check
git diff --cached --stat
# Review the exact staged diff, then use this specific approval.
git commit -m 'Add bounded GitHub public-code exposure leads'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed; inspect, never bypass the hook' }
git log -1 --format="%H %s"
git push origin main
# If push fails, record the failure; never claim remote completion.
git rev-parse HEAD refs/remotes/origin/main
git ls-remote --exit-code origin refs/heads/main
git diff --cached --name-only
```

Successful push requires matching local/live hashes and an empty index.
Preserve unrelated working changes. Actual closing hashes/results supersede
prepared notes; a saved file cannot contain its own containing commit ID.
