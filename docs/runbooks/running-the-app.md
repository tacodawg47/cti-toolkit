# Runbook: Running the toolkit (phase 1)

Written 2026-10-27.

## What phase 1 contains

A local web app with IOC enrichment. You paste a hash, IP, domain, or URL
(defanged input like `evil[.]com` or `hxxp://...` is accepted), it detects the
type, queries VirusTotal, and shows a normalized verdict card. A health page
shows which API keys are configured, the VirusTotal quota used today, and
package versions.

## One-time setup (already done on this machine)

```bash
# From the project folder
py -3.12 -m venv .venv
.venv/Scripts/python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.txt
```

`.env` must exist with at least `VIRUSTOTAL_API_KEY=...`. Copy `.env.example`
to `.env` and fill it in if starting fresh.

## Start the app

```bash
# Windows
.venv/Scripts/python.exe run.py

# Linux
.venv/bin/python run.py
```

It prints `Uvicorn running on http://127.0.0.1:8000`. Open that address in a
browser. It listens on localhost only, so nothing off the machine can reach it.
Stop it with Ctrl+C in the terminal.

## Use it

- Enrichment page (`/`): paste an indicator, click Enrich.
- Health page (`/health`): keys configured, VirusTotal quota today, versions.
- API docs (`/api/docs`): FastAPI's auto-generated interactive API reference.

## How the pieces fit (for learning)

| File | Job |
|---|---|
| `app/core/config.py` | Load `.env` into a typed settings object |
| `app/core/db.py` | Open SQLite connections; create the schema |
| `app/core/cache.py` | Store/retrieve lookups with a TTL (repeat lookups cost no quota) |
| `app/core/ratelimit.py` | Space calls (VirusTotal 4/min) and track the daily cap (500/day) |
| `app/core/models.py` | The normalized `VendorResult` every vendor returns |
| `app/core/indicators.py` | Refang input and detect hash/ip/domain/url |
| `app/modules/enrich/virustotal.py` | Async VirusTotal client (ported from cti-skills) |
| `app/main.py` | The web routes: `/`, `/enrich`, `/health` |
| `run.py` | Start the server bound to 127.0.0.1 |

## Rate-limit and cache behaviour

- The first lookup of an indicator calls VirusTotal and increments the daily
  counter (visible on the health page).
- A repeat within 6 hours is served from the SQLite cache, marked `(cached)`,
  and does not touch the quota.
- A 5th lookup inside one minute waits automatically until a slot frees.
- When 500/day is reached, lookups return an error instead of calling the API.

## Quick self-test without the browser

```bash
# Start the server in one terminal, then in another:
curl -s -X POST http://127.0.0.1:8000/enrich --data-urlencode "indicator=8.8.8.8"
curl -s http://127.0.0.1:8000/health
```
