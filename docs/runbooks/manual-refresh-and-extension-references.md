# Manual Refresh and Software Extension References

Written 2026-11-24. Data freshness is optional maintenance during feature
development. Do not refresh feeds automatically on git commit or push.
This exception applies only during the build. Once v1 is used for real
investigations, freshness, scheduled updates, stale-data visibility and
recovery are operational requirements. See [V1 Data Freshness](v1-data-freshness.md).

The app must be restarted after Python changes. Use the verified hidden
restart procedure in [Running the App](running-the-app.md). This pass used
these ignored log destinations with its final Start-Process command:

```powershell
$root = (Get-Location).Path
$python = (Resolve-Path '.venv/Scripts/python.exe').Path
# Run only after the existing verified listener has been stopped.
Start-Process -FilePath $python -ArgumentList @('-B','run.py') -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root 'data/phase2-features-final.stdout.log') -RedirectStandardError (Join-Path $root 'data/phase2-features-final.stderr.log')
Get-Content data/phase2-features-final.stderr.log -Tail 8
```

Wait for Application startup complete before checking a page. No source
refresh is needed to activate the code changes.

## Fetch CVE Program Changes

1. Open Vulnerability Intelligence, Feeds.
2. Check the CVE List row for its last fetch, sync version and error.
3. Click Fetch New CVE Records to fetch that source's changes only.
4. Read the updated status. No local snapshot, or more than 14 days behind,
   requires the separately labelled Load the CVE List control. The incremental
   button never silently downloads the roughly 660 MB full snapshot.

NVD Recent-Changes Recovery remains a separate bounded control. Refresh feeds
still refreshes its existing set of feeds. No scheduler was added.

With the local app already running, the equivalent optional request is:

```powershell
Invoke-WebRequest -Method Post -Uri 'http://127.0.0.1:8000/vulnerability-intelligence/refresh-cvelist' -TimeoutSec 600
```

Linux:

```bash
curl --fail --request POST http://127.0.0.1:8000/vulnerability-intelligence/refresh-cvelist
```

This contacts the CVE Program's public GitHub release downloads through the
app. It writes local records and review changes. It is not an offline test.

## Extract Extension References

Open Report Extraction at `/extract`. For an offline demonstration, paste:

```text
Chrome Extension ID: abcdefghijklmnopabcdefghijklmnop
Firefox Add-on ID: addon@example.test
VS Code Extension ID: example.sample-extension
```

Click Extract. Software Extension References lists the ecosystem, ID and
source context. Copy individual IDs or the labelled list. No external lookup
occurs. Store links contact the official store only when clicked. Firefox
IDs do not imply a listing slug, so no listing is invented for them.

Recognized Chrome/VS Code store URLs and hidden HTML hrefs are supported.
Bare hashes and bare publisher.name strings are not enough. Firefox runtime
moz-extension UUIDs are excluded. Rule/query blocks remain inert artifacts;
they are not scanned for these prose labels. This first slice does not
monitor extension stores or classify extensions as malicious.

## Repeat Offline Tests

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_software_references tests.test_decode_pdf -v
```

Linux uses `.venv/bin/python`. All fixtures are synthetic. The original
MuddyWater PDF acceptance and remaining ordering limitation are recorded in
`docs/review/2026-11-24-report-extensions-and-pdf.md`.
