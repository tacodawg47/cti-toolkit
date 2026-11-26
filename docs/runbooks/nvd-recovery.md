# Recover NVD Recent Changes

Written 2026-11-24. This imports NVD changes independently of other feeds.
It is separate from the per-CVE metadata backfill.

## Inspect Before Downloading

Open Vulnerability Intelligence, Feeds, NVD Recent-Changes Recovery.
GET reads the next date window and completed checkpoint. It makes no NVD
request and does not create pending work. A legacy partial download without
a checkpoint is recovered from its original start date, not its failed
attempt's fetched time. All displayed window boundaries are UTC.

Choose Public API Without Key or Configured NVD Key. Public mode is the
default for this control and omits the configured key. Configured mode
uses the existing NVD key if set. Keys are never entered or shown here.
Continue NVD Recovery runs NVD only. Refresh feeds still runs all feeds.

Each dedicated run allows at most six requests, 64 MiB per response and
192 MiB of charged response bodies, under a 180-second network budget.
Rate-limit waits are included. Parsing, local writes and review capture
can add time after the network budget. Failed/abandoned downloads charge
their full response allowance because their byte count may be unavailable.
Framing, an over-limit read chunk and memory overhead are outside body caps.
Raw response files are not retained; normalized data goes to SQLite.

## Recovery Semantics

The window is saved before requesting pages. Only a complete walk advances
the completed checkpoint. An ordinary HTTP, quota or parse error leaves
the original window pending. Previously saved pages remain useful.
Retries replay from offset zero. They may update existing rows, so records
processed are not a count of new CVEs.

Offsets advance by actual returned record count, not the requested page
size. A duplicate ID/page, inconsistent count or wrong returned offset
blocks completion. This does not make a mutable API an immutable snapshot.
Historical membership may change when NVD revises records later.

If the first page reports more records than the request allowance can cover,
the importer narrows the pending window immediately. It also halves a
window at a page, body or time cap. It never advances the checkpoint to skip
the unprocessed half. Completed coverage then catches up in bounded slices,
with an hour of overlap. Boundaries match the UTC seconds sent to NVD.

One recent-change import runs at a time in the current single-worker app.
A second POST does not duplicate its requests. The Feeds page can be opened
during a run to inspect saved progress. Interrupted runs remain pending and
are labelled interrupted, not complete. No automatic continuation runs.

## Exact Commands

After the app has finished startup, inspect the page:

```powershell
$base = 'http://127.0.0.1:8000/vulnerability-intelligence'
(Invoke-WebRequest -Uri "$base/feeds" -TimeoutSec 45).StatusCode
```

After authorizing NVD recovery, run one bounded window:

```powershell
$result = Invoke-WebRequest -Method Post -Uri "$base/refresh-nvd" -Body @{mode='public'} -TimeoutSec 300
$result.StatusCode
$result.Content.Contains('NVD Recent-Changes Recovery')
```

Expected: 200 after the 303 redirect, and True. A browser reload of the
result GET does not repeat the POST. Use `mode='configured'` only when
intending to use the existing NVD key. No other feed is refreshed.

Cross-platform equivalent:

```bash
curl -X POST --data "mode=public" http://127.0.0.1:8000/vulnerability-intelligence/refresh-nvd
```

Repeat only after checking the result and the next window. A partial result
does not mean the window is complete. Stop on quota/authentication errors
instead of repeatedly issuing requests. No local report or private seed is
submitted; requests contain public date filters and pagination parameters.

The persistent keys are `nvd_recent_pending_window`,
`nvd_recent_completed_end` and `nvd_recent_last_run` in sync_state.
The last-run summary contains requested dates, request and processed-row
counts, budget charges, mode, status and sanitized errors. It contains no key.
Use the standard verified loopback restart procedure after Python changes.

Offline checks and the read-only coverage audit:

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_nvd_recovery tests.test_metadata_coverage tests.test_vulnintel.NvdRecentTests -v
.\.venv\Scripts\python.exe -B -I -S scripts/audit_vulnerability_coverage.py
```

On Linux replace the interpreter with `.venv/bin/python`.
