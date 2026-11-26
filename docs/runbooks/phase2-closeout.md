# Phase 2 Closeout Checks

Written 2026-11-25. This covers the final no-fix, source-data and review UI
changes. The broader module procedure is in
[Vulnerability Intelligence](vulnerability-intelligence.md).

## Run the Offline Checks

From the project root, using the existing reviewed environment:

```powershell
.venv/Scripts/python.exe -B -m unittest tests.test_unfixed tests.test_review_digest tests.test_vulnintel.RedHatVexTests -v
.venv/Scripts/python.exe -B -m unittest discover -s tests -t .
.venv/Scripts/python.exe -B -m tests.phase2_coverage_probe
```

On Linux replace `.venv/Scripts/python.exe` with `.venv/bin/python`.
Tests use temporary databases and mocked HTTP. The probe prints observations;
it is not a replacement for assertions. Its uncited sighting fixture also
contains an Exploit-DB entry: Hunt comes from that entry, while the uncited
sighting does not establish Known Exploited membership.

For a diagnostic invocation without Python startup hooks, this pass used:

```powershell
@'
import sys, unittest
from pathlib import Path
sys.path[:0] = [str(Path.cwd()), str(Path('.venv/Lib/site-packages').resolve())]
suite = unittest.defaultTestLoader.discover('tests', top_level_dir='.')
result = unittest.TextTestRunner(verbosity=1).run(suite)
raise SystemExit(not result.wasSuccessful())
'@ | .venv/Scripts/python.exe -B -I -S
```

This is for the already reviewed project environment. Do not use an unknown
interpreter or add an unfamiliar environment to `sys.path` for artifact review.

## Read No-Fix Evidence

1. Open **Views > Exploited and Unfixed**. Membership requires both tracked
   positive exploitation evidence and an explicit no-fix assertion.
2. Expand the row's no-fix evidence. Open its original advisory and verify
   the named release or target. The CVE detail shows the same evidence under
   **Affected Targets Without a Fix**.
3. Keep target scope in mind. Patch and Mitigate may both appear, and a patch
   for another release does not resolve a listed unfixed target.

Supported sources are existing Red Hat VEX plus the existing vendor and OT
CSAF connectors. New findings require explicit product IDs or group IDs that
fully resolve. They must overlap an affected target and must not conflict
with a fixed, unaffected or under-investigation status. A missing patch link
does not qualify. This is not a complete CSAF conformance validator.

Old normalized advisories do not retain enough identity information to
reconstruct safe no-fix scope. A normal changed-document import populates
the new fields. For a specific older record:

1. Open its CVE detail and expand **Update Advisory Scope**, when present.
2. Select **Fetch This Advisory** beside the relevant stored advisory.
3. Check the dated result and original source before using its findings.

This explicit POST downloads one known stored advisory from its fixed
publisher endpoint. It does not accept arbitrary URLs, follow redirects or
refresh all feeds. The response cap is 64 MiB for SUSE and 32 MiB for other
supported sources. Failed requests or invalid documents preserve the old
evidence. No live per-document reload was performed in this closeout pass;
the request and failure paths were checked with mocked providers.

## Read Stored Source Data

Open a CVE and expand **Stored Source Data**, then the source of interest.
These are the fields retained by this application, including normalized
advisory evidence. They are not complete HTTP response archives. A local
observation date, document revision, publication date and exploitation date
have different meanings. Full original-response archives wait for the
Phase 5 shared evidence store.

## Use Since Last Review

The dashboard shows up to five CVEs with unreviewed changes observed in the
last seven days. A row groups change types, change count, source count and
latest observation date. Source count does not measure independent reports.

**Review This CVE** opens only that CVE's queue. Its checkmarks and **Mark
This CVE Reviewed** affect that CVE only, through the latest ID displayed.
Other CVEs and changes arriving after the page loaded remain unread.
**Review All Changes** opens the full queue; **90-Day History** includes
reviewed records. Opening either page never acknowledges anything.
The existing 90-day retention still applies. The dashboard change does not
reset, delete or automatically review the backlog.

## Check the Running App

Restart only the verified project `run.py` process when loading code changes.
If it is running in your terminal, stop it with Ctrl+C, then start:

```powershell
.venv/Scripts/python.exe -B run.py
```

For a hidden local launch with logs:

```powershell
$projectRoot = (Get-Location).Path
$projectPython = (Resolve-Path '.venv/Scripts/python.exe').Path
Start-Process -FilePath $projectPython -ArgumentList @('-B', 'run.py') -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $projectRoot 'data/phase2-closeout.stdout.log') -RedirectStandardError (Join-Path $projectRoot 'data/phase2-closeout.stderr.log')
Get-NetTCPConnection -LocalPort 8000 -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess
```

Do not start a second copy over an existing listener. Check for
`127.0.0.1:8000`, then use these passive page requests:

```powershell
$base = 'http://127.0.0.1:8000/vulnerability-intelligence'
(Invoke-WebRequest -Uri $base).StatusCode
(Invoke-WebRequest -Uri "$base/views/unfixed").StatusCode
(Invoke-WebRequest -Uri "$base/review?cve=CVE-2018-13257").StatusCode
(Invoke-WebRequest -Uri "$base/cve/CVE-2018-13257").StatusCode
```

The last request assumes that CVE is already loaded locally. Unknown CVE
lookups may use the module's ordinary on-demand sources. This closeout used
the already loaded record and did not submit refresh or review forms.

The local acceptance result is `data/phase2-closeout-acceptance.json`.
Logs and runtime data remain local and git-ignored. Operational freshness
is the next foundation requirement, described in
[V1 Data Freshness](v1-data-freshness.md).
