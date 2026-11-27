# CT Lookalike Watches


Update 2026-11-27, 3A.5: [Passive Subdomain Inventory](subdomain-inventory.md) is
a separate disabled CTLogs hosts-window consumer for exact authorized domains. It
does not change crt.sh matching, approve crt.sh access or combine indexes. Its
provider validity dates are distinct from CT logging and local capture dates.

Checkpoint update 2026-11-27: the operator confirms the exact 35-path/selective
commit and authorized push completed as 749d97351c5158558789afa8a297a461999b9c42.
Local HEAD/local origin/main/live remote main matched and the index was empty
afterward. Prepared commands below are historical, not steps to repeat.
Reconciled by ordinary documentation edits without Git operations. Independent
reconciliation/handoff-rule edits remain uncommitted. See the 3A.3 closeout.

Written: 2026-11-27. Subphase 3A.3. Provisional crt.sh implementation and
offline acceptance only. The operator expressly permitted this disabled
adapter despite the unresolved current service documentation. That decision
grants no live query, source eligibility, migration, restart or install.
See the dated CT API and pattern reviews under docs/research/.

## Local Use After Approved Startup

Open /ct-watches for per-seed age, last attempt, failure/incomplete states,
pattern version and coverage caveats. Capture and seed-history pages are
paged. Every GET is passive. No form enables collection or submits a query.
The ordinary approved app startup applies the independent additive schema;
no startup or live migration was performed in this delivery.

Use /alerts to add a ct_domain, ct_organization or ct_brand selector, with
Exact Typed Value and local monitoring authority. Domain values are complete
explicit domains. Organization/brand values are explicitly chosen DNS tokens
of at least three characters. No token is inferred from a legal entity name,
an alias, a URL or a registrable domain. Local matching authority is separate
from permission to send that exact token to crt.sh.

## Exact Matching and Evidence

IDNA2008 uses the existing pinned idna package with UTS46 disabled. No
confusable mapping, transliteration or fuzzy/permutation expansion occurs.
Non-ASCII dots, malformed names, URLs, ports, IPs and wildcard seeds are
refused. One terminal root dot and ASCII letter case normalize. Wildcard
candidate patterns retain their star; they never establish an apex or a
specific live hostname.

Complete seed labels and hyphen-component sequences match anywhere in a
hostname. Full-domain seeds match contiguous complete label sequences,
including example.invalid.other.invalid. There is no public-suffix or
ownership inference. Theme tokens only annotate an exact seed match. They
do not generate queries, extra hits, risk scores or malicious verdicts.

Only returned name_value identities are processed. This is not a complete
SAN enumeration. Valid unrelated names are ignored at matching. Missing or
malformed fields and oversized snapshots fail visibly. Equal provider rows
can deduplicate; conflicting content under one certificate ID is refused.
Validity dates and entry timestamps retain literal precision and offsets;
naive dates have no invented timezone. Observation/publication/first-seen
fields stay unknown. CT appearance is not domain registration time, live DNS,
ownership or maliciousness.

Capture/body digest and original execution survive retries. Each query's
normalized input, assertions, citations, inbox matches and completion commit
under explicit recovery rules. A later daily acquisition has a new scope.
Terminal failed/cancelled scopes retain staged input but are not resumed
under another scope. Stable source/hostname inbox events retain reviews even
when another certificate or capture reports the name. Other sources remain
separate. A late local selector can use the existing paged inbox catch-up.

The JSON response supplies a certificate ID, not a citation URL. The local
crt.sh ID reference is explicitly labelled constructed, never represented
as a literal supplied URL or original-log citation. It remains passive and
unresolved. Original source-log provenance is unknown in this surface.

## Submission Authority After Separate Approval

After the exact seed, source review, retention/handling and live database
changes have been approved, open the installed interpreter from project root:

```bash
# Windows
.venv/Scripts/python.exe -B
# Linux
.venv/bin/python -B
```

Use approved existing local selector IDs and bounded private record references:

```python
from app.modules.ct_watch import store
permission_id = store.approve(
    selector_id,
    authority_reference=approved_local_record,
    purpose=approved_defensive_purpose,
    expires_at=approved_aware_expiry,
)
store.revoke(permission_id)  # Stops this immutable permission.
store.suppress(selector_id)  # Stops this seed selector, including future approvals.
```

These change the live database. No example grants approval. There is no
unsuppress or evidence-deletion operation. Revocation/expiry, local selector
disablement, suppression and pattern content/version or matcher changes
stop queries, staging and ingestion at each cooperative boundary. A new
permission never replaces the ID in queued work. Changed patterns need a
new explicit permission after the old one is revoked. There are at most ten
distinct selector IDs across permission history. One active permission per
selector is allowed; expired permissions must be revoked before reapproval.

## Bounds, Recovery and Freshness

One crtsh_watch registration composes with the previous 33. All 34 schedules,
feed worker, bulk and raw storage default off. The source receives no automatic
review approval or collection switch. Use Shared Evidence and Scheduled Feeds
only after a separate real source review; select app.core.feed_catalog.catalog.
No extra worker, event loop, dependency or credential is introduced.

One daily pass snapshots at most ten permission IDs, including an immutable
empty plan. Queries use only the approved seed surrounded by provider search
wildcards, output=json and exclude=expired. This substring discovery request
is filtered by exact local boundaries. No query derives other seeds, fetches
certificates, follows redirects, resolves DNS or opens candidate pages.

Each attempt allows ten requests, 20 MiB charged bytes and 120 seconds for
new work. Each response is at most 2 MiB and 30 seconds including streaming.
Parsing permits 200 certificate rows, 50 names per row and 1,000 processed
names total. Normalized input is at most 512 KiB per query. Larger responses
fail rather than truncate. Three total attempts, durable backoff, 429 cooldowns
and the existing shared-loop crtsh limiter apply. Durable local limits are
2/minute and 48/day. These are conservative local limits, not a verified
current provider allowance. Only complete bounded successful bodies refund
unused byte allowance. In-flight requests cannot be retracted; elapsed and
cancellation checks are cooperative. Atomic SQLite work may finish past a
soft deadline. No network transaction holds a database write lock.

Restart drains saved normalized input before any fresh request for that unit.
A crash after completion repairs progress without changing original collection
time or review history. Freshness uses each seed's original capture, daily
cadence and a two-day stale threshold. Downtime creates one due pass, not a
burst of missed intervals. Global pass success is not per-seed freshness.

Coverage is bounded unexpired query snapshots only. Empty valid JSON records
an empty snapshot, not proof of absence or a clean verdict. Provider truncation,
indexing lag, log coverage, historical completeness and continuity cannot be
verified by this interface. Captures are sensitive; raw responses are forced
omitted even under generic public-source archive settings. Unknown fields,
issuer narratives, email SANs and secret fields are not retained. Query/headers
are omitted from capture request metadata; normalized selector/permission and
attempt records remain private. No export, privacy deletion or encryption is
added. Keep runtime data ignored and local.

## Repeat Offline Acceptance

Run from project root using the installed environment:

```bash
# Windows
.venv/Scripts/python.exe -B -m unittest tests.test_ct_watch tests.test_alerts tests.test_shared_evidence -q
.venv/Scripts/python.exe -B -m unittest discover -s tests -t . -q
# Linux equivalents
.venv/bin/python -B -m unittest tests.test_ct_watch tests.test_alerts tests.test_shared_evidence -q
.venv/bin/python -B -m unittest discover -s tests -t . -q
```

Temporary databases and synthetic/refused HTTP only. The existing Windows
managed-launch restriction required the established external test execution
path; no interpreter, package or security setting changed. See the closeout
for final results and intermediate failures. No live database is initialized
by these tests. Linux and native-browser visual acceptance remain separate.

## Live Acceptance Still Required

Review current crt.sh hosted-service permission, documented restrictions,
real schema and account/access requirements before approving its registry
entry. Review each exact external query and its authority reference, local
handling and expiry. Approve migration/restart, schedule/worker enabling and
a small measured provider/recovery acceptance separately. Record actual
sizes, durations, lag, failures and restart behavior. Do not treat the
provisional adapter approval, old maintainer posts or this runbook as live
permission. No broad historical reload is required.

CTLogs was evaluated as requested. Its documented organization API searches
subject O=, not arbitrary brand tokens in hostnames. Its domain inventory
APIs are later candidates; they are not wired as a fallback. Combining indexes
would disclose seeds twice and is not independent source corroboration.
See the API review for terms, rate-document inconsistency, privacy and limits.
Every Git inspection, individual commit and push still needs direct approval.

## Approved Local Checkpoint Inspection

The operator directly approved read-only local inspection on 2026-11-27.
It confirmed main, HEAD and local origin/main at
3eaf484bcdb803555c5f199c1906b30969dce80f and an empty index. No remote was
contacted and no Git mutation occurred. These are a record, not future
permission. Repeat the commands only after the required direct approval:

```powershell
git status --short
git branch --show-current
git rev-parse HEAD refs/remotes/origin/main
git log -1 --format="%H %s"
git diff --cached --name-only
git diff --stat
git diff --check
$inspectionText = Get-Content 'docs/review/2026-11-27-3a3-checkpoint-files.md' -Raw
$inspectionFence = ([string][char]96)*3
$inspectionBlock = [regex]::Match($inspectionText, '(?s)'+$inspectionFence+'text\r?\n(.*?)\r?\n'+$inspectionFence)
$inspectionPaths = @($inspectionBlock.Groups[1].Value -split '\r?\n')
if ($inspectionPaths.Count -ne 35) { throw 'Unexpected exact manifest' }
git diff --no-ext-diff -- @inspectionPaths
git show HEAD:docs/handoff.md
```

Read new/untracked named files directly too; ordinary Git diff omits them.
Whole-tree whitespace identified only the known unrelated roadmap addition.
Exclude it rather than edit that work. Global-ignore access and LF/CRLF
warnings were nonfatal and changed no setting. Five selective local review
copies under ignored data/3a3-checkpoint/ use inspected HEAD plus only the
named current status, phase scope, journal entries and handoff. The current
status scope includes the completed 3A.2 result needed to replace stale
prepared-execution wording. Independent rules/research/prototypes remain
in the actual working files and outside those copies.

For each of AGENTS.md, CLAUDE.md, ROADMAP.md, docs/journal.md and
docs/handoff.md, compare the prepared .base and .snapshot files. Replace
slashes in the filename with underscores. The first example is:

```powershell
git diff --no-index -- data/3a3-checkpoint/AGENTS.md.base data/3a3-checkpoint/AGENTS.md.snapshot
git diff --no-index --check -- data/3a3-checkpoint/AGENTS.md.base data/3a3-checkpoint/AGENTS.md.snapshot
```

Exit 1 from a normal no-index comparison means expected differences, not
failure. Inspect the exact content; do not reuse snapshots if HEAD or the
shared files change. The copies are ignored review/staging inputs, never
commit targets. No staging, commit or push is authorized by inspection.
Show the final 35 paths, selective blocks and proposed message Add bounded
certificate transparency lookalike watches for individual commit approval.
Obtain separate push approval afterward. No acceptance rerun is needed for
these documentation-only checkpoint updates.

## Individually Approved 3A.3 Commit and Push

The operator directly instructed commit and push on 2026-11-27 after the
exact 35-path/selective-block proposal and message were shown. This records
that specific approval, not standing permission for a future chat. Keep the
five reviewed snapshots synchronized with approved checkpoint-state notes.
Stop on changed HEAD, unexpected staged content, whitespace or hook failure.

```powershell
$checkpointText = Get-Content 'docs/review/2026-11-27-3a3-checkpoint-files.md' -Raw
$checkpointFence = ([string][char]96)*3
$checkpointBlock = [regex]::Match($checkpointText, '(?s)'+$checkpointFence+'text\r?\n(.*?)\r?\n'+$checkpointFence)
if (-not $checkpointBlock.Success) { throw 'Exact manifest missing' }
$checkpointPaths = @($checkpointBlock.Groups[1].Value -split '\r?\n')
if ($checkpointPaths.Count -ne 35 -or @($checkpointPaths | Sort-Object -Unique).Count -ne 35) { throw 'Unexpected manifest' }
if ((git rev-parse HEAD) -ne '3eaf484bcdb803555c5f199c1906b30969dce80f') { throw 'HEAD changed' }
if (@(git diff --cached --name-only).Count) { throw 'Unexpected staged work' }
$checkpointShared = @('AGENTS.md','CLAUDE.md','ROADMAP.md','docs/journal.md','docs/handoff.md')
$checkpointWhole = @($checkpointPaths | Where-Object { $_ -notin $checkpointShared })
git add -- @checkpointWhole
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
foreach ($checkpointPath in $checkpointShared) {
    $checkpointSnapshot = Join-Path 'data/3a3-checkpoint' ($checkpointPath.Replace('/','_')+'.snapshot')
    $checkpointBlob = git hash-object -w --path=$checkpointPath -- $checkpointSnapshot
    if ($LASTEXITCODE -ne 0) { throw 'Blob creation failed' }
    git update-index --add --cacheinfo "100644,$checkpointBlob,$checkpointPath"
    if ($LASTEXITCODE -ne 0) { throw 'Selective staging failed' }
}
$checkpointStaged = @(git diff --cached --name-only)
if (Compare-Object ($checkpointPaths | Sort-Object) ($checkpointStaged | Sort-Object)) { throw 'Staged paths differ' }
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Staged whitespace failed' }
git diff --cached --stat
git diff --cached -- AGENTS.md CLAUDE.md ROADMAP.md docs/journal.md docs/handoff.md
```

Inspect the staged shared-file diffs and confirm every independent block is
absent. Then create the approved commit, retaining the configured hook:

```powershell
git commit -m 'Add bounded certificate transparency lookalike watches'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git log -1 --format="%H %s"
git status --short
```

The same direct message explicitly authorized push. Check the actual commit
and intended origin/main destination before using that approval:

```powershell
git push origin main
if ($LASTEXITCODE -ne 0) { throw 'Push failed' }
git rev-parse HEAD refs/remotes/origin/main
git ls-remote --exit-code origin refs/heads/main
git diff --cached --name-only
git status --short
```

All three hashes must match and the index must be empty. Preserve remaining
independent working-tree changes. Report the actual result in the closing
message; do not amend a commit merely to include its own hash.
