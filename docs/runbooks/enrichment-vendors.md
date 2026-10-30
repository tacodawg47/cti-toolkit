# Runbook: IOC enrichment vendors (phase 1)

Written 2026-10-29.

Phase 1 enrichment now fans out across multiple vendors. You type one
indicator; the app detects its type and queries every vendor that supports
that type at the same time, then shows each vendor's verdict and summary.

## Which vendors run for which type

| Indicator | Vendors queried |
|---|---|
| IP address | VirusTotal, AbuseIPDB, GreyNoise, OTX, ThreatFox, URLhaus, Shodan |
| Domain | VirusTotal, OTX, ThreatFox, URLhaus, urlscan |
| URL | VirusTotal, OTX, ThreatFox, URLhaus, urlscan |
| File hash | VirusTotal, OTX, ThreatFox, MalwareBazaar |

GreyNoise uses the keyless community endpoint. The abuse.ch trio (ThreatFox,
MalwareBazaar, URLhaus) all authenticate with the single `ABUSECH_AUTH_KEY`.
urlscan only SEARCHES existing public scans; it never submits a new scan.

## How a vendor client is structured

Each file under `app/modules/enrich/` is one vendor and exposes two things the
rest of the app relies on:

- `VENDOR` — the vendor's short name.
- `async def lookup(itype, value) -> VendorResult` — does the key check, cache
  check, rate-limit wait, HTTP call, and returns a normalized `VendorResult`.

A pure `_summarise(...)` helper turns the vendor's raw JSON into a verdict and
a summary. Those helpers take a plain dict and are what the unit tests check,
so no test needs the network or a key.

`registry.py` maps each type to its vendor list and runs them concurrently
with `asyncio.gather`. If one client were to crash, the registry turns that
into an error result for that vendor so the others still return.

## Verdict meaning per vendor

- VirusTotal: malicious/suspicious/clean from engine detections.
- AbuseIPDB: abuse confidence score (>=75 malicious, >=25 suspicious).
- GreyNoise: benign -> clean, malicious -> malicious, else unknown.
- OTX: pulse count caps the verdict at suspicious (never malicious on its own,
  since benign indicators appear in many pulses). OTX's own whitelist /
  false-positive lists override to clean when present.
- ThreatFox / MalwareBazaar / URLhaus: a hit is malicious (curated lists); a
  miss is unknown, not clean. URLhaus invalid_url/invalid_host answers surface
  as an error (a sign of bad input), not "not listed".
- Shodan: recon, not reputation. Unknown unless Shodan's own bad tags
  (malware, c2, ...) push it to suspicious; CVEs are shown for context but do
  not set the verdict. The value is the port/org/CVE summary.
- urlscan: informational. Shows how many past scans exist; verdict stays
  unknown.

## Rate limits and quota

`app/core/ratelimit.py` holds the caps. A vendor may set requests-per-minute,
requests-per-day, both, or neither:

| Vendor | Per-minute | Per-day |
|---|---|---|
| VirusTotal | 4 | 500 |
| AbuseIPDB | — | 1000 |
| Shodan | 60 | — |
| urlscan | 60 | 1000 |
| GreyNoise | — | 10 (approx, conservative) |
| OTX, abuse.ch | — | — (uncapped here) |

Daily usage per capped vendor is shown on the `/health` page. Results are
cached in SQLite, so repeating a lookup inside its TTL costs no quota.

## Keys

All keys live in `.env` (git-ignored) and are read by `app/core/config.py`.
GreyNoise needs no key. The `/health` page shows only whether each key is
present, never its value.

## Run the tests

The vendor verdict helpers have unit tests (no network, no keys):

```bash
.venv/Scripts/python.exe -m unittest tests.test_vendors -v
```

Or the whole suite:

```bash
.venv/Scripts/python.exe -m unittest discover -s tests -t . -v
```
