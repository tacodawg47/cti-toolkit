# Runbook: Running the toolkit (phase 1)

Written 2026-10-27. Updated 2026-10-29.

## What phase 1 contains

A local web app with IOC enrichment. You paste a hash, IP, domain, or URL
(defanged input like `evil[.]com`, `evil[dot]com`, or `hxxp://...` is accepted
and cleaned). The app detects the type, queries every vendor that supports that
type at once, and shows an "Overall" worst-of line plus one normalized verdict
card per vendor. A health page shows which API keys are configured, the daily
quota used per tracked vendor, the live Shodan credit balance, and package
versions. See `enrichment-vendors.md` for the vendor list and verdict meanings.

## One-time setup (already done on this machine)

```bash
# From the project folder
py -3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.txt
```

`.env` must exist with the keys you have (at least `VIRUSTOTAL_API_KEY=...`).
Copy `.env.example` to `.env` and fill it in if starting fresh. Every key is
optional: a vendor with no key simply shows NOT CONFIGURED instead of running.

If you clone this repo fresh on another machine, enable the commit guard once:

```bash
git config core.hooksPath .githooks
```

## Start the app

```bash
# Windows
.venv/Scripts/python.exe run.py

# Linux
.venv/bin/python run.py
```

It prints `Uvicorn running on http://127.0.0.1:8000`. Open that address in a
browser. It listens on localhost only, and refuses any request whose Host
header is not a loopback name, so nothing off the machine can reach it. Stop it
with Ctrl+C.

## Use it

- Enrichment page (`/`): paste an indicator, click Enrich.
- Health page (`/health`): keys configured, per-vendor quota used today,
  Shodan credit balance, package versions.

(The interactive API docs are turned off in phase 1 — there is no JSON API yet,
and the docs page would load scripts from a CDN, which a local-only tool avoids.)

## How the pieces fit (for learning)

| File | Job |
|---|---|
| `app/core/config.py` | Load `.env` into a typed settings object (host must be loopback) |
| `app/core/db.py` | Open SQLite connections; create the schema; purge expired cache |
| `app/core/cache.py` | Store/retrieve lookups with a TTL (repeat lookups cost no quota) |
| `app/core/ratelimit.py` | Space calls and track the daily cap per vendor |
| `app/core/models.py` | The normalized `VendorResult` every vendor returns |
| `app/core/indicators.py` | Refang, normalise, and detect hash/ip/domain/url |
| `app/modules/enrich/base.py` | Shared HTTP client + `fetch_json` + result helpers |
| `app/modules/enrich/registry.py` | Fan out to the right vendors; aggregate the verdicts |
| `app/modules/enrich/*.py` | One async client per vendor |
| `app/main.py` | The web routes: `/`, `/enrich`, `/health` |
| `run.py` | Start the server bound to 127.0.0.1 |

## Rate-limit and cache behaviour

- The first lookup of an indicator calls the vendors and increments each one's
  daily counter (visible on the health page).
- A repeat within the TTL is served from the SQLite cache, marked `(cached)`,
  and does not touch any quota.
- When a per-minute cap is full the limiter waits for a slot; when a per-day
  cap is reached that vendor's card shows QUOTA instead of calling the API.
- Private, reserved, and loopback IPs are not sent to any vendor.

## Quick self-test without the browser

```bash
# Start the server in one terminal, then in another:
curl -s -X POST http://127.0.0.1:8000/enrich --data-urlencode "indicator=8.8.8.8"
curl -s http://127.0.0.1:8000/health
```
