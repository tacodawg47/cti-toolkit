# Runbook: IOC extraction (phase 2)

Written 2026-11-02.

The Extract IOCs page (`/extract`) pulls indicators out of a block of text, a
fetched web page, or an uploaded PDF, and hands each one to enrichment with a
button. It is the "paste an advisory" half of Phase 2; CVE IDs it finds are
routed to the vulnerability intelligence module.

## What it extracts

Updated 2026-11-24: explicit Chrome, Firefox and VS Code IDs appear under
Software Extension References. Copy IDs and ecosystem-labelled lists, with
manual official store links where the identity supports one. They do not
become file hashes, email addresses or ordinary enrichment inputs. See
[the repeatable feature checks](manual-refresh-and-extension-references.md).
Plural PDF hash headings and standalone detection names are supported.
The original MuddyWater check recovers 105 complete hashes; one out-of-order
cross-page row remains unsupported. See the 2026-11-24 acceptance review.

Updated 2026-11-19: **Report Extraction** and **Decoder Tool** are separate
tabs at `/extract` and `/extract/decoder`. Successful report extraction
clears its text, URL and file inputs. Failed inputs remain for correction.
Individual indicators and plain lists have Copy buttons. Values are trimmed;
the space before the Copy button is outside the indicator value.

Report mode separates linked citations from IOC enrichment. Common plain
reference hosts such as GitHub, Go and urlscan remain full references.
Explicit defanged hosting URLs remain indicator candidates. Domains require
a known delegated or special-use suffix as well as filename filtering.
The ATT&CK catalog refresh also loads IANA's small TLD list into ignored
`data/iana-tlds.txt`; before that, a limited common-suffix fallback applies.
There is no DNS lookup of extracted indicators during this validation.

Recognizable HTML code blocks and pasted fenced code are shown under
**Rules, Queries and Command Lines**. Recognized YARA, Sigma, KQL, SPL and
CQL are labelled; unknown blocks stay Code Sample. Standalone pasted
YARA rules and common command lines are also recognized. Contents are
inert, excluded from ordinary IOC enrichment and never executed, deployed
or certified valid. Plain pasted queries without explicit boundaries may
still need manual selection. Row context preserves adjacent hash/IP labels.

Explicit `AML.T` IDs appear under **ATLAS References**, separately from
ATT&CK. Official ATLAS catalog validation and names remain future work.
Command-to-technique candidate mappings were removed on 2026-11-20.
Only explicitly reported technique IDs are listed. Commands and rules
remain verbatim artifacts. Inferred TTPs wait for optional Phase 11 AI
assist and analyst review. AI output will still require validation.

Image references have an explicit Load Image button. Images are not
automatically requested or enriched. Clicking contacts the image host from
the browser with no referrer. Local IP literals and credential-like query
parameters are refused. This is not a proxy or a guarantee about a named
host's DNS destination. Never use previews for suspected malicious links.

Some Next.js pages stream article models as JSON inside script elements.
The parser can recover bounded declarative native HTML models without
executing JavaScript. It only replaces visible text when it recovers more
hashes. This fixes the checked ReversingLabs report, not all dynamic sites.
Unsupported components, OCR and unrestricted browser rendering remain out
of scope. Inputs, embedded data and recovered content have size/work caps.

Offline regression checks:

```powershell
.\.venv\Scripts\python.exe -B -m unittest tests.test_report_quality tests.test_extract tests.test_decode_pdf tests.test_attack_layouts -v
```

On Linux replace the Python path with `.venv/bin/python`.

Repeat the two original URL checks with the local app running:

```powershell
$endpoint = 'http://127.0.0.1:8000/extract'
$rlUrl = 'https://www.reversinglabs.com/blog/threat-researchers-notebook-detection-strategies-for-artex-and-related-forks'
$rl = Invoke-WebRequest -Method Post -Uri $endpoint -Body @{url=$rlUrl} -TimeoutSec 90
$rl.Content -match '193\s+hashes'
$googleUrl = 'https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere'
$google = Invoke-WebRequest -Method Post -Uri $endpoint -Body @{url=$googleUrl} -TimeoutSec 90
$google.Content -match '11\s+IPs'
([regex]::Matches($google.Content, '<summary>YARA ')).Count
```

Expected on the checked revisions: True, True and 6. These requests fetch
the public reports without executing page scripts or submitting extracted
IOCs to enrichment. Source revisions can change counts. Check the source
before changing expectations. After a restart, wait until startup completes
in the server log before issuing requests against the large local database.

| Type | Pattern | Notes |
|---|---|---|
| IPv4 | four dotted octets, each 0–255 | a version number like `1.2.3.4` has the same shape and is extracted too; private, loopback, reserved and documentation-range (`203.0.113.x`) addresses are tagged and dimmed |
| IPv6 | hex-and-colon candidates validated by Python's `ipaddress` | times (`12:30:45`) and MAC addresses fail validation and are dropped |
| Domain | dotted labels, last label alphabetic or punycode | a last label that is a file extension (`exe`, `dll`, `pdf`, `json`, …) makes it a filename, not a domain; see the list in `extractor.py` |
| URL | `http://`, `https://` or `ftp://` up to the next whitespace | sentence punctuation after the URL is trimmed; the URL's host is also listed as a domain or IP |
| File hash | exactly 32, 40 or 64 hex characters | tagged md5, sha1 or sha256; lowercased |
| Email | `user@host.tld` | the mail host is not listed separately as a domain |
| CVE | `CVE-YYYY-NNNN…` | uppercased |

Every result is de-duplicated with a count and marked **defanged** when the
author only ever wrote it in a defanged form (`hxxp`, `[.]`, `(dot)`, `[at]`,
`evil dot com`). That is usually the strongest hint that the author meant it
as an IOC rather than as a reference link. Hosts in the Tranco top list (if
`data/tranco.csv` is loaded) are tagged with their rank and dimmed, since
enrichment would skip them anyway.

Five real top-level domains (`sh`, `py`, `pl`, `md`, `rs`) are on the
file-extension list on purpose: in threat reports they are file names almost
every time. If you ever need a `.sh` domain extracted, paste it alone into
the enrichment box instead.

## How to use it

1. Open `http://127.0.0.1:8000/extract`.
2. Either paste text into the box, or put a report URL in the URL field, or
   choose a PDF or text file. If more than one is filled in, the file wins,
   then the URL, then the text.
3. Click **Extract**. Results are grouped by type. Click **Enrich** on a row
   to run the Phase 1 vendors on it. Open **plain list** under a group to
   copy the values for another tool.
4. Expand **Report Context** beside an IOC before interpreting it. This is
   up to 280 nearby characters from the extracted text, with indicators
   refanged. It keeps the earliest mention. It is not an exact original-file
   locator, a full quotation or a maliciousness verdict. PDF hash-row context
   remains available separately. Viewing context makes no extra request.

To repeat the local context checks without any provider lookup:

```powershell
.venv/Scripts/python.exe -m unittest tests.test_extract -v
```

For a manual check, paste `Training sample: bad[.]example is not malicious.`
and select **Extract**. The domain's Report Context must preserve the
negative wording and display the refanged name. Pasted markup and commands
remain escaped text. These rendering checks do not test a future AI model's
resistance to prompt injection; that has its own Phase 11 acceptance work.

If the app is stopped, the reviewed Windows background start used for this
pass is below. If port 8000 is occupied, use the verified restart procedure
in [running-the-app.md](running-the-app.md), not a second server.

```powershell
$toolkitPython = (Resolve-Path -LiteralPath '.venv/Scripts/python.exe').Path
$toolkitProcess = Start-Process -FilePath $toolkitPython -ArgumentList @('-B', 'run.py') -WorkingDirectory (Get-Location).Path -WindowStyle Hidden -PassThru -RedirectStandardOutput 'data/report-context.stdout.log' -RedirectStandardError 'data/report-context.stderr.log'
$toolkitProcess.Id
$extractPage = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/extract' -TimeoutSec 20
$contextPage = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/extract' -Method Post -Body @{ text = 'Training sample: bad[.]example is not malicious.' } -TimeoutSec 20
$extractPage.StatusCode
$contextPage.StatusCode
$contextPage.Content.Contains('Report Context')
$contextPage.Content.Contains('Training sample: bad.example is not malicious.')
```

Expect two 200 status codes and two True values. These requests exercise
local extraction only. They do not submit the example to a provider.

The URL fetch is for vendor blogs and advisories. It validates the initial
HTTPS URL and each redirect before requesting it. It refuses embedded
credentials, local names, and private, reserved or multicast address
literals. It stops after five redirects or a 5 MB body. DNS resolution is
handled by the OS. Use enrichment's existing-scan lookup for suspected
malicious URLs.

## Read ATT&CK Evidence

1. Open **Extract IOCs** and select **Load ATT&CK Catalog**. This fetches
   the three public MITRE STIX bundles for Enterprise, Mobile, and ICS
   at v20.1. The toolkit keeps just a compact index in git-ignored
   `data/attack-index.json`. A failed fetch keeps the prior index.
2. Paste a report or upload a Markdown, PDF, or HTML advisory. For HTML,
   uploading `.html` or entering an advisory URL preserves its tables.
   Markdown tables and explicit technique list items work in pastes and
   text uploads. For example, a bullet beginning `T1059.001 PowerShell -
   Ran a script` supplies a procedure to the PowerShell row. A heading
   such as `## Execution` supplies the reported tactic. Fenced examples
   provide no procedure evidence.
3. Open **ATT&CK References**. Technique, software and group IDs show
   the official MITRE name and catalog status when matched. Review
   absent IDs and revoked or deprecated entries. The result lists a
   replacement when MITRE supplies one in the catalog.
4. Expand the table evidence beside a technique to view the report's
   procedure and stated tactic. The excerpt belongs to the report.
   The catalog supplies the official name, domains, and mappings used
   to flag a reported mismatch. Evidence also works for HTML lists, grids,
   pre/br blocks and ID-bearing headings. Markdown headings can supply a
   paragraph. Prose fallback is explicitly labelled, with Low confidence
   for three or more IDs in one sentence. ATLAS IDs are outside this view.
5. PDF procedures require a one-to-one paragraph association. Flattened
   ID columns followed by prose, multiple IDs in one PDF paragraph and
   associations across page boundaries stay as IDs only. No OCR runs.
   A structured-layout limit notice means a smaller section may recover
   more evidence. These labels describe association, not source credibility
   or an independently verified behavior.

For Windows, with the local app running:

```powershell
Invoke-WebRequest -Method POST -Uri 'http://127.0.0.1:8000/extract/refresh-attack'
.\.venv\Scripts\python.exe -B -m unittest tests.test_extract tests.test_attack_layouts tests.test_decode_pdf
```

[MITRE ATT&CK data and attribution](https://attack.mitre.org/resources/attack-data-and-tools/).

For a harmless live check after the normal app restart, save the following
as an HTML file and upload it at `/extract`:

```html
<h2>Execution</h2>
<ul><li>T1059.001 PowerShell - Ran encoded commands.</li>
<li>T1059.003 Windows Command Shell - Launched cmd.exe.</li></ul>
```

With the catalog loaded, each ID should show its own procedure, HTML List,
Source Structure and reported tactic Execution. Removing the procedure
phrases leaves names and IDs without invented behavior. No link, image or
script in an uploaded HTML document is fetched or executed. The synthetic
test file does not establish coverage of all original publisher reports.

### Repeat Original Publisher Acceptance

Checked 2026-11-19: the 12 named survey pages and Recorded Future PDF.
Results and limits are in
[the acceptance review](../review/2026-11-19-publisher-acceptance.md).
The helper downloads only its fixed publisher URL list and never fetches
page assets or executes page code. Raw captures remain in git-ignored data/.
The default operation is offline analysis; --fetch explicitly enables GETs.
The per-file cap is 6 MiB and per-run combined transfer cap is 30 MiB.

From the project root, the exact fetch command is:

```powershell
.venv/Scripts/python.exe -B -I -S -c "import sys, runpy; from pathlib import Path; sys.path[:0] = [str(Path.cwd()), str(Path('.venv/Lib/site-packages').resolve())]; sys.argv = ['check_report_layouts.py', 'data/phase2-acceptance-2026-11-19', '--fetch']; runpy.run_path('scripts/check_report_layouts.py', run_name='__main__')"
```

The original run used a 5 MiB cap. After a HEAD response established the
PDF's 5,895,616-byte size, raised it to 6 MiB and retried only that source:

```powershell
.venv/Scripts/python.exe -B -I -S -c "import sys, runpy; from pathlib import Path; sys.path[:0] = [str(Path.cwd()), str(Path('.venv/Lib/site-packages').resolve())]; sys.argv = ['check_report_layouts.py', 'data/phase2-acceptance-2026-11-19', '--fetch', '--only', 'recordedfuture-pdf']; runpy.run_path('scripts/check_report_layouts.py', run_name='__main__')"
```

We disable Python startup hooks with -I -S, then add only the trusted project
and existing site-packages paths. No downloaded report is imported as code.
Review the fixed URL list before future live runs and use a new dated
capture directory when preserving an earlier snapshot.

Scan only the incoming publisher captures with the approved Defender
process, using an elevated PowerShell. The completed scans used:

```powershell
$defenderExe = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform\CurrentVersion\MpCmdRun.exe'
$defenderSignature = Get-AuthenticodeSignature -LiteralPath $defenderExe
if ($defenderSignature.Status -ne 'Valid' -or $defenderSignature.SignerCertificate.Subject -notmatch 'Microsoft') { throw 'Defender executable signature verification failed.' }
$incomingReports = (Resolve-Path -LiteralPath 'data/phase2-acceptance-2026-11-19/incoming').Path
& $defenderExe -Scan -ScanType 3 -File $incomingReports
$LASTEXITCODE
$reportPdf = (Resolve-Path -LiteralPath 'data/phase2-acceptance-2026-11-19/incoming/recordedfuture-pdf.pdf').Path
& $defenderExe -Scan -ScanType 3 -File $reportPdf
$LASTEXITCODE
```

The directory scan preceded the PDF retry on the original run; scanning the
whole dedicated incoming directory after a fresh fetch covers all files.
Do not substitute Downloads, the project root or a personal folder. Check
the explicit detection output as well as exit status. This process permits
Microsoft cloud analysis for these public project downloads. No global
Defender setting is changed. See [scan semantics](defender-artifact-scan.md).

After scanning, the offline analysis command is:

```powershell
.venv/Scripts/python.exe -B -I -S -c "import sys, runpy; from pathlib import Path; sys.path[:0] = [str(Path.cwd()), str(Path('.venv/Lib/site-packages').resolve())]; sys.argv = ['check_report_layouts.py', 'data/phase2-acceptance-2026-11-19']; runpy.run_path('scripts/check_report_layouts.py', run_name='__main__')"
```

downloads.json records source, size and digest. analysis.json holds the local
findings, evidence kinds and catalog version. Inspect original structures
and representative source-aligned cells, rather than accepting procedure
counts as proof. Labels-only matrices must stay without procedure text.
Source descriptions can be generic; association is not credibility or
independent confirmation of observed behavior. A changed digest/layout
requires renewed acceptance. Do not commit the captures or extracted text.

## PDF support

### Decode Text Locally

Open Extract IOCs, expand **Decode Text**, choose a format, and select
**Decode and Extract**. Formats are plain Base64 to UTF-8, PowerShell
Base64 to UTF-16LE, Base64 with Gzip, zlib or raw Deflate, decimal or
0x-prefixed character codes, and JWT header/payload JSON. Character
codes use comma or space separators. Decoding handles one layer at a
time. Commands remain displayed text. JWT signatures are not validated.
The form makes no source requests and does not save its input.

Input is capped at 1 MB of characters and decoded UTF-8 output at 2 MB.
Compressed streams stop at the output cap, including highly compressed
inputs. Invalid encodings, incomplete streams and concatenated streams
show an error. Source extraction's own text/result limits still apply.

With the local app running, repeat a harmless Base64 check in PowerShell:

```powershell
$sample = 'hxxps://example[.]org/a CVE-2026-12345'
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sample))
$result = Invoke-WebRequest -Method Post -Uri 'http://127.0.0.1:8000/extract/decode' -Body @{mode='base64'; encoded=$encoded}
$result.Content.Contains('https://example.org/a')
.\.venv\Scripts\python.exe -B -m unittest tests.test_decode_pdf -v
```

### Wrapped PDF Hashes

Upload a text-layer PDF or fetch a public report PDF from the existing
URL field. Hash repair rejoins contiguous hex fragments of MD5, SHA-1,
and SHA-256. It skips blank lines, numeric page footers and repeated
hash headings across a short page boundary. Expand **PDF Row Context**
beside a recovered hash to read its text line numbers, recent headings,
detection names and trailing annotations such as `(abused)`.

An explicit SHA256 heading permits joining two 32-character fragments.
Without that heading, two complete MD5-sized rows remain separate.
Other unrelated text stops a join. This is text repair, not OCR or a
general reconstruction of multi-column tables. Check source context
before using repaired hashes. The offline tests build a real PDF in
memory; the original MuddyWater report is not a checked-in fixture.

On Linux run `.venv/bin/python -B -m unittest tests.test_decode_pdf -v`.

PDF text extraction uses `pypdf` (BSD-3-Clause, maintained by the py-pdf
organisation, pure Python, no required dependencies), pinned in
`requirements.in` since 2026-11-03 after the checks in
`vetting-a-dependency.md`. The import is still optional in the code: without
it the page works for text and URLs, and a PDF upload shows a message
pointing here. If you ever rebuild the environment, these are the steps:

```bash
# 1. add the name to requirements.in, then regenerate the hash-locked file
.venv/Scripts/python.exe -m piptools compile --generate-hashes --output-file=requirements.txt requirements.in
```

```bash
# 2. install wheels only, hashes required
.venv/Scripts/python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.txt
```

```bash
# 3. audit
.venv-tools/Scripts/python.exe -m pip_audit -r requirements.txt
```

(On Linux the paths are `.venv/bin/python` and `.venv-tools/bin/python`.)

A scanned PDF has no text layer, so extraction returns nothing; the page
shows the character count so you can tell "nothing found" from "nothing to
read". Password-protected PDFs are reported, not guessed.

## Where the code lives

| File | Does |
|---|---|
| `app/core/indicators.py` | the CVE indicator type (`detect_type` now returns `cve`) |
| `app/modules/extract/extractor.py` | document-wide refang, one pattern per type, validation, de-duplication |
| `app/modules/extract/html.py` | Visible text and HTML table cells with the standard-library parser |
| `app/modules/extract/attack.py` | ATT&CK identifier and procedure extraction |
| `app/modules/extract/markdown.py` | Structured Markdown tables and explicit technique lists |
| `app/modules/extract/attack_catalog.py` | MITRE STIX parsing and local catalog refresh |
| `app/modules/extract/fetch.py` | the HTTPS-only, public-host-only page download |
| `app/modules/extract/pdf.py` | pypdf wrapper with a page cap |
| `app/templates/extract.html` | the page |
| `tests/test_extract.py` | offline tests for all of the above, including the route |

## Why not a library

The roadmap originally named `iocextract`. It is GPL-2.0 and was last
released in 2023; a GPL dependency would push the whole project toward GPL
before a license has even been chosen. `ioc-finder` is LGPL-3.0 and active,
but adds `pyparsing` for the same result. The in-house version reuses the
refang code Phase 1 already had and keeps the dependency count at zero for
text input.
