# CTI Toolkit

Local-only cyber threat intelligence toolkit: many analyst tools under one
web interface. Portfolio project and daily workflow aid.

Read ROADMAP.md first. It holds the phases, stack, decisions log, and open
questions. Work proceeds phase by phase in the order listed there.

## Working agreement

- **Approval before side effects.** Before installing anything, running any
  git or GitHub operation, executing scripts or commands that change the
  system, creating accounts or keys, or sending data to an external service:
  say what will be done and why, then wait for the user's go-ahead. Writing
  and editing code and docs inside the project folder is normal work and
  needs no prompt. Read-only steps (reading files, web research, version
  checks) need no prompt.
- **Human in the loop for commits.** Every commit and push is approved
  individually. Show the files and the proposed message first.
- **Teach as you go.** After each approved action, add a short runbook under
  docs/runbooks/ with the exact commands so the user can repeat it by hand.
  The user wants to learn to do this without AI.
- The user is new to Python, FastAPI, web development, and git. Explain
  choices briefly as you go and keep the code readable over clever.
- Deterministic core. No AI anywhere except the final "assist" phase, and
  that must be optional with a "none" provider as the default.
- The app binds to 127.0.0.1 only.
- Code must run on Linux (primary) and Windows. Use pathlib, no shell-specific
  calls, no hard-coded paths.
- API keys live in .env (git-ignored). Never commit secrets. Never print keys
  or echo them back in chat. Keys on hand (values in .env only): VirusTotal
  (free: 4/min, 500/day, 15.5K/month, non-commercial), AbuseIPDB, OTX, Shodan,
  urlscan, abuse.ch Auth-Key (ThreatFox, MalwareBazaar, URLhaus, YARAify).
  GreyNoise: no key, community endpoint only (about 10 lookups/day).
- Reuse open source tools by wrapping them. The MIT-licensed cti-skills plugin
  (Liberty91) has stdlib Python vendor clients and dark web scripts worth
  porting with attribution.
- Prefer small, testable modules: one package per tool under app/modules/,
  shared code under app/core/.
- Dependencies: few, well known, pinned with hashes, installed wheels-only
  with `--require-hashes --only-binary=:all:`. See the policy in ROADMAP.md.
  Propose any new dependency by name, maintainer, and reason before adding.
- No automated joining of Telegram channels, no engagement with threat
  actors, no purchases, no bypassing of anti-bot protections.

## Stack

Python 3.12, FastAPI, Jinja2, HTMX, SQLite (FTS5), httpx, pydantic,
APScheduler, Cytoscape.js (vendored). pip + venv. Docker in phase 8.

## Current status

Phase 1 not started. Developing on Windows 11 for now (Python 3.12 installed
at the user level; Git with Credential Manager). Linux dual boot is broken by
a kernel panic; switch when Linux-only tooling is needed. Repository:
github.com/tacodawg47/cti-toolkit (private).
