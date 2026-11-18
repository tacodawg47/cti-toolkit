# Runbook: IOC extraction (phase 2)

Written 2026-11-02.

The Extract IOCs page (`/extract`) pulls indicators out of a block of text, a
fetched web page, or an uploaded PDF, and hands each one to enrichment with a
button. It is the "paste an advisory" half of Phase 2; CVE IDs it finds are
routed to the vulnerability intelligence module.

## What it extracts

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
   to flag a reported mismatch. Unstructured text and PDFs show IDs
   without attached procedure text. ATLAS IDs are outside this view.

For Windows, with the local app running:

```powershell
Invoke-WebRequest -Method POST -Uri 'http://127.0.0.1:8000/extract/refresh-attack'
.\.venv\Scripts\python.exe -B -m unittest tests.test_extract
```

[MITRE ATT&CK data and attribution](https://attack.mitre.org/resources/attack-data-and-tools/).

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
