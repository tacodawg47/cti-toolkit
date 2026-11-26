# CVEDB Comparison

Written 2026-11-24. Optional comparison for the local non-commercial toolkit.
No API key or Shodan host/search credit is used by this endpoint. Do not
assume this grants commercial usage; review the provider terms first.

## Use

1. Open a CVE page and expand CVEDB Source Comparison near References.
2. Click Fetch CVEDB Comparison. The app sends that CVE ID to CVEDB only.
   It sends no watchlist, file, private notes or configured API keys.
3. Inspect the successful-fetch and last-attempt timestamps. A result over
   24 hours old is labelled stale. Retrieval time is not a source update date.
4. Use Refresh Saved Result to fetch again within the 24-hour reuse window.
   Without that checkbox a recent successful result is reused.

The comparison shows CVSS, EPSS and exploitation flags beside current page
evidence. CVSS versions must align before a score difference is labelled.
CVEDB does not provide an EPSS score date in the reviewed schema, so a
different probability is not presented as a same-day conflict. Aggregate
flags may have different coverage and may share upstream sources. Not Flagged
does not establish that exploitation has never happened.

This source does not change CVE products, exploitation status, priority,
actions, views, or review events. Supplied ransomware text is source context,
not verified attribution. Opening a page never queries CVEDB. Fetch Source
Updates and general feed refresh do not add CVEDB requests.

Successful normalized snapshots and last-attempt status use the existing
ignored SQLite cache with 30-day retention, separate from 24-hour freshness.
Startup purges expired cache rows. No raw response archive is kept. A failed
refresh preserves the prior successful data and date within retention, shows
the failure and records the attempt time. There is no automatic retry.

One HTTPS request, no redirects or credential headers, uses the shared
30-second total timeout and 5 MiB response cap. Ten requests/minute is a
local courtesy limit, not a published provider quota. Concurrent duplicate
requests share a fresh result in the current single-worker app.

## Repeat Offline Checks

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_cvedb -v
```

Linux uses `.venv/bin/python`. Fixtures are synthetic and providers mocked.
No dependency, key or account installation is needed.

With the app running and after choosing to contact the provider, the
equivalent manual POST is:

```powershell
Invoke-WebRequest -Method Post -Uri 'http://127.0.0.1:8000/vulnerability-intelligence/cve/CVE-2024-0204/cvedb' -Body @{force='true'} -TimeoutSec 120
```

Linux:

```bash
curl --fail --request POST --data 'force=true' http://127.0.0.1:8000/vulnerability-intelligence/cve/CVE-2024-0204/cvedb
```

The POST returns a 303 to the CVE page. Existing first-time CVE-page lookups
have their normal behavior; use an already loaded CVE to isolate this manual
check from first-time enrichment. This pass used offline provider tests and
read-only local page checks, without a live CVEDB POST.

Source: [CVEDB usage FAQ](https://cvedb.shodan.io/) and
[published schema](https://cvedb.shodan.io/openapi.json).

## Restart and Check Locally

Use the verified loopback restart procedure in
[Running the App](running-the-app.md) after Python changes. This pass used
the same hidden Start-Process command, with these ignored log destinations:

```powershell
$root = (Get-Location).Path
$python = (Resolve-Path '.venv/Scripts/python.exe').Path
# Only after stopping the verified existing listener.
Start-Process -FilePath $python -ArgumentList @('-B','run.py') -WorkingDirectory $root -WindowStyle Hidden -RedirectStandardOutput (Join-Path $root 'data/phase2-source-scope.stdout.log') -RedirectStandardError (Join-Path $root 'data/phase2-source-scope.stderr.log')
Get-Content data/phase2-source-scope.stderr.log -Tail 6
```

Wait for Application startup complete. Check an already loaded CVE without
requesting a provider refresh:

```powershell
$page = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/vulnerability-intelligence/cve/CVE-2018-13257' -TimeoutSec 60
$page.StatusCode
$page.Content.Contains('CVEDB Source Comparison')
```

Expected: 200 and True. A direct source fetch is the separate POST described
above. Do not confuse an HTTP 200 local UI check with a live-provider test.

For the GET-only module walkthrough, with the app running:

```powershell
$base = 'http://127.0.0.1:8000/vulnerability-intelligence'
$tabs = @('', '/views', '/vendor-updates', '/supply-chain', '/watchlist', '/feeds', '/search', '/exploits')
$slugs = @('all','exploited','watchlist','code','patch-tuesday','new-severe','likely','unfixed','edge','ransomware','ai-stack','zero-day','sightings','ot','trending')
$urls = @($tabs | ForEach-Object { "$base$_" }) + @($slugs | ForEach-Object { "$base/views/$_" }) + @('http://127.0.0.1:8000/extract','http://127.0.0.1:8000/extract/decoder')
foreach ($url in $urls) {
    $response = Invoke-WebRequest -Uri $url -TimeoutSec 60
    Write-Output "$($response.StatusCode) $url"
}
```

Expected: 25 HTTP 200 responses. These pages read local data. Do not append
refresh query parameters or invoke any POST in this walkthrough. Successful
rendering does not establish source freshness or complete historical coverage.
