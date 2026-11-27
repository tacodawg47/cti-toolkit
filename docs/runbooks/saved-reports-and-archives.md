# Saved Reports and Original Archives

Update 2026-11-26: [Alert Inbox](alert-inbox.md) matches saved report
observations atomically. Alerts preserve document/citation/run associations
when originals are omitted, expired or fail reconciliation. It adds no raw
serving route, collection permission or automatic historical matching worker.

Written 2026-11-26. Subphase 5F.4. No new dependency. All new network workers,
raw storage and source collection switches default off. Tests use temporary
databases and mocked HTTP. No live migration, restart or enabling was done.

## Save a Report

Open `/extract`. Enter text, a report URL, or a file using the existing input
priority. Open Save Report With Source Metadata. Supply a title/name,
publisher, and publication date. Enter `unknown` if that date is unknown.
Optional fields preserve source modification and observation dates, source
URL, TLP and literal citation references. Select the handling classification.
Press Extract and Save. Extract alone retains its previous behavior.

A URL save uses the bytes from that extraction request. Saving does not fetch
the report again. Files retain their uploaded bytes; a paste uses UTF-8 bytes.
HTTP archives retain the entity bytes delivered by the HTTP client after
transport decoding, not a packet capture or the compressed wire transfer.
The captured record reference retains the final response URL when different
from the supplied provenance URL. Headers, cookies and authentication are
not archived. The original media type is retained where available.

`/reports` shows the latest 100 saves. Each report page shows its provenance,
mentions, unresolved or explicitly resolved citation hops, archive availability
and latest 200 jobs/results. The per-report indicator list is capped at 2,000.
The extraction text cap is 2,000,000 characters; original input is at most
10 MiB. Over-limit saves fail rather than silently claim a complete save.
These are bounded views, not a complete export of historical jobs/results.

Saving does not approve collection. Unknown publisher surfaces get an F,
unreviewed, collection-disabled source entry. Observations are mentions, not
malicious verdicts. Publication, source observation and local collection dates
stay separate. Unknown dates stay null. All source text is escaped.

The document, sightings, citation edges and save manifest commit in one short
SQLite transaction. The form's capture ID, original digest, metadata, parser
version and parsed content determine replay identity. A repeated unchanged
save retains the first capture time and originating run. Changed bytes,
metadata, final response reference or parser output create another capture.
A fresh form records a new acquisition even for equal bytes. Existing manual
citation resolutions survive replay. No citation is fetched or resolved by
guessing. Record multiple literal hops as separate edges; do not infer that
multiple references constitute independent corroboration.

## Handling Rules

Unknown and sensitive report saves retain metadata and indicator mentions
locally, with no context excerpts. They cannot use external bulk enrichment
or raw storage. Restricted TLP content also cannot use those actions. This
slice permits raw storage and external bulk submission only for an explicitly
public report with TLP CLEAR or unspecified. Labels do not encrypt files or
provide account access controls. Sensitive retention/quarantine and privacy
deletion need their separate policy; they are not implemented here.

Report input with common credential patterns, a private-key marker, URL
credentials or a configured API key is refused before saving. Provider raw
bytes with those patterns are omitted; normalized provider attributes that
match are suppressed. This is a guard, not a universal secret detector.
Encoded, novel and contextual secrets can escape it. Public handling must
be chosen after reviewing the material. Do not use this archive for private
runtime data, credentials, conversation exports or breach source files.
Never put raw bytes, source excerpts or provider errors in job logs, commits
or external diagnostics. There is no raw download, render or export route.

## Configure Raw Storage After Approval

Enabling storage, changing the live `.env`, migration and restart require
direct approval. Review the intended local root, response/source/total byte
limits, age, source handling decisions and filesystem access first. Do not
copy example limits as an approved operational policy. Configuration requires
all of these values, with no unlimited/default retention:

```dotenv
ARCHIVE_ENABLED=false
ARCHIVE_ROOT=
ARCHIVE_RESPONSE_BYTES=
ARCHIVE_SOURCE_BYTES=
ARCHIVE_TOTAL_BYTES=
ARCHIVE_RETENTION_SECONDS=
ARCHIVE_PUBLIC_SOURCES=[]
```

The root must be a private subdirectory of the configured ignored DATA_DIR.
It cannot be DATA_DIR itself or traverse a symlink/junction. Source material
never supplies paths. Response <= source <= total. Responses are at most
64 MiB, source/total at most 1 TiB, and age at most 366 days. The writer also
refuses at 10,000 directory entries. Maintenance refuses directories above
20,000 entries. Preserve the ownership/ACL of this private runtime directory;
POSIX new directories/files request 0700/0600. Windows uses account ACLs.
No settings or permissions are changed system-wide.

Feed and bulk response classifications default to unknown. The explicit
`ARCHIVE_PUBLIC_SOURCES` JSON list may name reviewed source IDs, such as
`enrich.internetdb`, only after their response content and retention terms
are approved. This is a handling decision, not collection permission. A
scheduled source still needs its reviewed registry entry, schedule and worker.
Bulk providers still need their API review and the bulk worker. Old captures
retain their original classification on replay. Do not relabel them silently.
The normal one-IOC manual enrichment route does not create archive captures.

The writer reserves capacity before IO. Pending/stored metadata and actual
generated files count against the total, including orphan bytes after a crash.
Generated random `.blob` names have no executable extension or source path.
An exclusive temporary write, flush/fsync and atomic rename precede marking
the original stored. The archive OS lock serializes writers, readers and
maintenance. Lock contention/storage errors record failed availability or
leave an existing pending write recoverable. Normalized evidence stays usable.
Digests establish byte identity, not source authenticity.

States: pending, stored, omitted, expired and failed. Omitted records explain
disabled storage, required handling or capacity/credential restrictions.
Expired and omitted originals are not resurrected by replay. A deliberate
new acquisition needs a new capture. Changing the configured root does not
move/delete originals in the old root; reads refuse its unmatched root token.
Review and maintain the old root explicitly before changing this setting.

## Reconciliation and Expiry

Approved startup verifies one bounded maintenance page. With a configured
root, a local maintenance worker continues pages, checks expiry and missing
files, and retries cleanup independently of the network workers. A page
checks at most 200 metadata rows and 200 generated files; full verification
stops after at least 64 MiB has been considered (one final response can cross
that threshold). Further pages run about one second apart. Completed sweeps
repeat about every 30 seconds. Deadlines are cooperative, not a filesystem
latency guarantee. Health shows maintenance failure, partial progress and the
last successful page. Do not interpret that page timestamp as full coverage.

Pending writes are verified by size/digest. Completed renames can be recovered;
missing/partial/corrupt originals become failed. Generated orphan files are
removed. Arbitrary operator files and lock files are preserved. Expiry removes
only raw files. Document, sightings, citations, original digests and job/run
metadata remain. Read/list availability becomes expired immediately at the
deadline, even before physical cleanup. While the app is stopped, cleanup
waits for startup or explicit maintenance. Failed deletion remains visible
in Health. Disabling raw writes while retaining the root/limits still allows
expiry cleanup; removing the root setting stops automatic cleanup.

For approved local maintenance, open the existing project interpreter:

```bash
# Windows
.venv/Scripts/python.exe -B
# Linux
.venv/bin/python -B
```

Then run bounded pages against the already reviewed configured root:

```python
from app.core import archives
cursor = {"after": 0, "file_after": ""}
while True:
    result = archives.reconcile(**cursor, verify=True)
    if not result["more"]:
        break
    cursor = {"after": result["after"], "file_after": result["file_after"]}
```

This deletes only expired/incomplete/orphan generated originals. Obtain the
required approval before an agent runs it on live data. Do not delete or
replace the archive or database runner lock files while executors may exist.

## Bulk Enrichment After Approval

Use the saved report controls to choose a batch, or Enrich All in Bounded
Batches. All splits are durable and replayable with the same request ID.
Each job has at most 10 indicators and 14 explicit provider choices. Enrich
All creates at most 200 jobs for the save's 2,000-mention limit. Report text
never supplies callables, provider definitions, commands or destination hosts.
Emails and CVEs are not sent through this IOC workflow. Choose providers
applicable to every selected batch; a batch with no applicable provider is
refused before Enrich All starts creating jobs.

Default choices are keyless hashlookup, InternetDB, RDAP and crt.sh. Additional
providers are unchecked and require an explicit choice. GreyNoise and urlscan
are in that group because they can send a configured optional key. Missing
keys produce an explicit not-configured result. The private-IP and Tranco
gates remain. A known-good hashlookup result suppresses later hash providers.
There is no bulk force override. Keyless units run before additional providers
within each batch. A not-found answer is not a clean verdict.

The worker switch `BULK_ENRICHMENT_ENABLED` defaults false. For every selected
provider, the source registry needs an individually reviewed and enabled API
surface named `enrich.<provider>`. Existing manual lookup access does not grant
this permission. Use the shared-evidence review workflow; record actual terms
references/date and bounded rate notes, not placeholders from tests.

Fixed destination patterns are in `app/modules/enrich/bulk.py`. RDAP allows
at most three redirects to the listed Verisign/PIR and five RIR path patterns.
Review that entire proposed surface before enabling enrich.rdap. Unknown
registries, arbitrary redirects and non-HTTPS destinations are refused.
No current upstream terms or endpoint availability were checked in 5F.4.
No credential or request payload is forwarded on a redirect. Each hop spends
quota and rechecks eligibility. These are proposed opt-in policies, not live
source approvals. Later registry additions need review and offline tests.

Each attempt allows at most 60 requests, 5 MiB per response, 32 MiB charged
bytes and 120 seconds for new work, including quota waits. Successful bounded
bodies refund unused response allowance. Errors and redirects keep their full
allowance charged. There are at most three attempts, with durable retry/backoff.
Per-provider rolling minute/day counts and 429 cooldowns survive restart.
The existing manual provider limiter is also acquired on its original app
loop. Absent a stricter existing daily cap, a bulk provider permits at most
1,000 rolling daily reservations. Sources without a minute cap use 10/minute.

The sync runner thread submits to the existing application loop and shared
HTTP client/limiter. There is no event loop per job. Worker shutdown drains
active work before closing the client. Registry eligibility and the worker
switch are rechecked at units, requests, after quota waits and before result
writes, including retries. Cancellation is cooperative. One OS execution lock
serializes feed and bulk jobs using the same local database.

Successful units commit normalized provider attributes and capture/source
relationships before advancing progress. Cached results preserve their query
time and have no new original capture. HTTP 200 captures bind endpoint,
request-input digest and response digest before normalization. Equal bodies
from different queries get separate captures; replay preserves originating
run/time. Non-200 bodies are discarded and have no retained original claim.
No downloaded response can grant approval or direct the next destination.
Failed units retain prior results and retry within limits. Exhausted jobs
remain visibly failed/incomplete. Re-enqueuing a terminal scope does not reset
it; a deliberate new request gets a new logical scope. No job/evidence-history
pruning or live v1 operational acceptance is implied.

## Repeatable Offline Acceptance

From the project root using the existing environment:

```bash
# Windows
.venv/Scripts/python.exe -B -m unittest tests.test_saved_reports -v
.venv/Scripts/python.exe -B -m unittest tests.test_saved_reports tests.test_shared_evidence tests.test_feed_scheduler -q
.venv/Scripts/python.exe -B -m unittest discover -s tests -t . -q
# Linux
.venv/bin/python -B -m unittest tests.test_saved_reports -v
.venv/bin/python -B -m unittest discover -s tests -t . -q
```

Tests never migrate the live database or spend provider quota. The installed
Windows venv launcher needs the established execution path outside its
managed sandbox restriction. This changes no interpreter, package or security
setting. Linux and native-browser visual acceptance remain separate checks.

## Approved Checkpoint Inspection

Read-only checks approved in this chat confirmed 5F.3 at `2491fb3` and matching
local origin/main tracking. This did not contact the remote. Commands used:

```bash
git status --short
git log -4 --format="%h %s"
git branch -vv
git diff --stat
git diff --cached --name-only
git rev-parse HEAD refs/remotes/origin/main
git diff --check
```

These are a record, not future Git permission. Every commit and push still
needs its own approval. Preserve prototype blocks in the three shared docs,
all prototype files, Feedly rules and local Claude settings. Never stage
runtime data, keys or conversation exports. See session-handoff.md.

## Individually Approved 5F.4 Commit

The operator approved the exact 28-path manifest and message on 2026-11-26.
The three shared snapshots are prepared from HEAD plus only the named 5F.4
blocks. This leaves all unrelated working-tree content untouched. The local
snapshots live under ignored `data/5f4-checkpoint/`. These commands document
this approval, not standing permission for another chat or a push:

```powershell
$checkpointText = Get-Content 'docs/review/2026-11-26-5f4-checkpoint-files.md' -Raw
$checkpointMatch = [regex]::Match($checkpointText, '(?s)```text\r?\n(.*?)\r?\n```')
$checkpointPaths = @($checkpointMatch.Groups[1].Value -split '\r?\n')
if ($checkpointPaths.Count -ne 28) { throw 'Unexpected manifest' }
if (@(git diff --cached --name-only).Count) { throw 'Unexpected staged work' }
$checkpointShared = @('ROADMAP.md', 'docs/journal.md', 'docs/handoff.md')
$checkpointWhole = @($checkpointPaths | Where-Object { $_ -notin $checkpointShared })
git add -- @checkpointWhole
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
foreach ($checkpointPath in $checkpointShared) {
    $checkpointSnapshot = Join-Path 'data/5f4-checkpoint' (($checkpointPath -replace '/', '_') + '.snapshot')
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
git commit -m 'Add saved reports and bounded original archives'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git log -1 --format="%h %s"
git status --short
```

Obtain separate push approval after checking the resulting commit and intended
destination. No push was authorized as part of this commit approval.
