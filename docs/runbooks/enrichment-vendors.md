# Runbook: IOC enrichment vendors (phase 1)

Written 2026-10-29. Updated 2026-11-02 (keyless sources added).

Phase 1 enrichment now fans out across multiple vendors. You type one
indicator; the app detects its type and queries every vendor that supports
that type at the same time, then shows each vendor's verdict and summary.
Input is cleaned first: defanged forms are refanged, a `host:port` loses its
port, and hashes/domains/IPs are put in one canonical spelling so the cache
stores one entry per indicator.

## Which vendors run for which type

| Indicator | Vendors queried |
|---|---|
| IP address | VirusTotal, AbuseIPDB, GreyNoise, OTX, ThreatFox, URLhaus, InternetDB, Shodan, RDAP |
| Domain | VirusTotal, OTX, ThreatFox, URLhaus, urlscan, RDAP |
| URL | VirusTotal, OTX, ThreatFox, URLhaus, urlscan |
| File hash | CIRCL hashlookup first (gate), then VirusTotal, OTX, ThreatFox, MalwareBazaar, URLhaus |

Keyless sources: GreyNoise (community endpoint), Shodan InternetDB, RDAP, and
CIRCL hashlookup need no key at all. The abuse.ch trio (ThreatFox,
MalwareBazaar, URLhaus) all authenticate with the single `ABUSECH_AUTH_KEY`.
urlscan only SEARCHES existing public scans; it never submits a new scan.

Two gates run before any vendor is called:

- Private, reserved and loopback IPs are never sent out (one local card
  explains why).
- A file hash is checked against CIRCL hashlookup first. If it is a known
  catalogued good file (an OS or vendor binary from NSRL, Debian, Microsoft,
  etc.), the other vendors are skipped to save quota and a local card says so.
  A miss simply adds the hashlookup card and the normal fan-out runs.

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
into an error result for that vendor so the others still return. It also builds
the "Overall" worst-of line above the cards and skips private/reserved IPs (no
point querying `192.168.x.x`).

`base.py` holds the shared pieces: one pooled `httpx.AsyncClient` (opened once
at startup) and `fetch_json`, which every client uses so a transport error or a
non-JSON response becomes a clear message instead of a crash. A result card
shows NOT CONFIGURED, QUOTA, or UNAVAILABLE (from the result's `status`) when a
vendor could not answer.

## Verdict meaning per vendor

- VirusTotal: malicious/suspicious/clean from engine detections.
- AbuseIPDB: abuse confidence score (>=75 malicious, >=25 suspicious).
- GreyNoise: benign -> clean, malicious -> malicious, else unknown.
- OTX: pulse count caps the verdict at suspicious (never malicious on its own,
  since benign indicators appear in many pulses). OTX's own whitelist /
  false-positive lists override to clean when present.
- ThreatFox / MalwareBazaar / URLhaus: a hit is malicious (curated lists); a
  miss is unknown, not clean. URLhaus also checks file hashes (MD5/SHA256) via
  its payload endpoint. URLhaus invalid_url/invalid_host answers surface as an
  error (a sign of bad input), not "not listed".
- Shodan: recon, not reputation. Unknown unless Shodan's own bad tags
  (malware, c2, ...) push it to suspicious; CVEs are shown for context but do
  not set the verdict. The value is the port/org/CVE summary.
- urlscan: informational. Shows how many past scans exist; verdict stays
  unknown.
- Shodan InternetDB: the free, keyless subset of Shodan (ports, hostnames,
  CPEs, CVEs, tags). Same rule as Shodan: unknown unless a bad tag is present.
  Use it as the everyday IP recon; the keyed Shodan call adds banners and
  certificates when you need them.
- RDAP: the official WHOIS replacement. Domains: registrar, registration and
  expiry dates, nameservers, status; a domain registered in the last 30 days is
  nudged to suspicious (new domains are a cheap phishing signal). IPs: the
  netblock, the registry, and the abuse contact to report to. Otherwise unknown.
  The client follows the rdap.org bootstrap redirect to the right registry.
- CIRCL hashlookup: known-GOOD files. A hit is clean (with file name, source
  catalogue and hashlookup's 0-100 trust score); a miss is unknown, not bad.
  This is the opposite question from every other vendor, which is why it gates
  the hash fan-out.

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
| OTX, ThreatFox, MalwareBazaar, URLhaus | 30 (soft) | — |
| InternetDB, CIRCL hashlookup | 60 (courtesy) | — |
| RDAP | 30 (courtesy) | — |

Daily usage per capped vendor is shown on the `/health` page. Results are
cached in SQLite, so repeating a lookup inside its TTL costs no quota.

## Keys

All keys live in `.env` (git-ignored) and are read by `app/core/config.py`.
GreyNoise, InternetDB, RDAP and CIRCL hashlookup need no key. The `/health`
page shows only whether each key is present, never its value.

## Run the tests

The vendor verdict helpers have unit tests (no network, no keys):

```bash
.venv/Scripts/python.exe -m unittest tests.test_vendors -v
```

Or the whole suite:

```bash
.venv/Scripts/python.exe -m unittest discover -s tests -t . -v
```
