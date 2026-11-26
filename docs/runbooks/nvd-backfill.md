# Targeted NVD Metadata Backfill

Written 2026-11-20. Phase 2. No additional dependency.

## Use the App

Open Vulnerability Intelligence, Feeds, then NVD Metadata Backfill.
The page is `/vulnerability-intelligence/metadata`.
Opening it only reads local data. It does not queue downloads or contact NVD.

The first scope is non-rejected Known Exploited CVEs. Product gaps come
first, followed by CVSS, CWE and absent NVD records. Existing CNA, vendor,
Microsoft and catalog fields count as available metadata. This is not
a full-catalog import. Watchlist-specific scope is a separate follow-up.

Choose five or ten records and an API mode, then Continue Backfill.
Public API Without Key is the default. Configured mode uses the existing
NVD_API_KEY if set; the page never accepts or displays a key.
One request is made per selected CVE, without automatic request retries.
Each accepted response body is capped at 5 MiB. Five records allow up to
25 MiB of bodies; ten allow 50 MiB. Network framing and an over-limit read
chunk are not included in those body caps. The run pauses after a 90-second
network budget, including rate-limit waits, then saves local review state.

Only public CVE IDs are queried. No reports, watchlist entries, local files
or private indicators are uploaded. Nothing is executed from the responses.
App binding remains loopback only. The scheduler is not involved.

## Results and Retry

The local queue survives restarts. Each completed lookup is recorded before
the next starts. An interrupted lookup stays pending and may be repeated.
Successful NVD data flows through the existing score, products, remediation,
detail, watchlist and review consumers. The wrong CVE cannot complete a
target's lookup or be saved as a different record.

Retrieved means the source was checked. It does not mean every field was
available. The Recent Results table shows remaining gaps. Retrieved and
not-found records are not automatically fetched again. Regular NVD change
imports can provide later metadata; a selected-CVE load remains available.

A transport or parsing error leaves previous NVD metadata intact and records
a failed item. Other pending work can continue. Retry Failed Records
explicitly requeues those items. A quota/authentication refusal pauses the
batch, leaving remaining items pending. It never silently switches API modes.
Deadline-limited attempts rotate behind unattempted items at the same
priority. Another source filling a pending gap can resolve it without a
duplicate NVD lookup. One in-process batch runs at a time. This assumes the
current single-worker app; a multi-worker deployment needs durable leasing.

## Repeat by Hand

With the local app running, inspect before sending requests:

```powershell
$endpoint = 'http://127.0.0.1:8000/vulnerability-intelligence/metadata'
(Invoke-WebRequest -Uri $endpoint -TimeoutSec 45).StatusCode
```

HTTP 200 is expected. After authorizing the displayed batch:

```powershell
$result = Invoke-WebRequest -Method Post -Uri "$endpoint/backfill" -Body @{limit='5';mode='public'} -TimeoutSec 150
$result.StatusCode
$result.Content.Contains('Last Batch:')
```

Expected: HTTP 200 after the 303 redirect, and True. The raw POST returns
303. A refresh of the result page does not resubmit the POST. To retry
failed records, add `retry='1'` to the body. It never retries successful
unknown fields just because a gap remains.

Cross-platform CLI equivalent for a five-record run, after permission:

```bash
curl -X POST --data "limit=5&mode=public" http://127.0.0.1:8000/vulnerability-intelligence/metadata/backfill
```

Use the existing verified restart procedure in running-the-app.md after
Python changes. Additive queue schema is created at startup. The first
acceptance run used hidden launcher output at `data/nvd-backfill.stdout.log`
and `data/nvd-backfill.stderr.log`, both ignored. Wait for startup completion
before posting.

Compare aggregate coverage without networking:

```powershell
.\.venv\Scripts\python.exe -B -I -S scripts/audit_vulnerability_coverage.py
.\.venv\Scripts\python.exe -B -m unittest tests.test_nvd_backfill -v
```

On Linux use `.venv/bin/python`. The tests use temporary databases and
mocked requests. Queue state is `nvd_backfill_queue`; the last run summary
is `sync_state.nvd_backfill_last_run`. They contain public CVE metadata
and operational status, not keys or downloaded code.
