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

The URL fetch is for vendor blogs and advisories. It only fetches `https://`
addresses on public hosts, follows redirects but refuses one that lands on
plain HTTP, and stops reading past 5 MB. It is not a sandbox: a suspected
malicious URL belongs in the enrichment box, where urlscan's existing public
scans are searched instead of the page being fetched.

## PDF support

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
| `app/modules/extract/html.py` | HTML to text with the standard-library parser (scripts and styles skipped) |
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
