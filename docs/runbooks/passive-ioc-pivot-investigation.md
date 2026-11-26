# Passive IOC Pivot Investigation

2026-11-19. Scope: 162.120.17.69, two hops, at most ten retained candidates per hop. Queried provider APIs only. No connections to suspect infrastructure, scan submissions or malware downloads.

Evidence and repeatable scripts are stored locally under data/investigations/2026-11-19-162.120.17.69, covered by the existing data/ ignore policy. These contain provider evidence, not conversation exports. Do not commit the evidence; AbuseIPDB records can contain individualized tracking links.

Run from the project root in PowerShell, with authorization for the outgoing lookup requests:

```powershell
.venv/Scripts/python.exe data/investigations/2026-11-19-162.120.17.69/lookup_seed.py data/investigations/2026-11-19-162.120.17.69/seed.json
.venv/Scripts/python.exe data/investigations/2026-11-19-162.120.17.69/lookup_pivots.py data/investigations/2026-11-19-162.120.17.69/pivots.json
```

These scripts are case-specific. They load credential values in process from app.core.config and do not print the values. The seed script prints raw provider data, which can include tracking tokens. Keep that output local. They do not retry automatically or fetch subsequent search pages. The pivot script prints at most ten records per query. Shodan totals count service records, not distinct IPs. Broad title-only matches are not retained cluster candidates.

Retained graph: seed -> Mailer-Go title plus HTML hash -267699125 -> 91.92.41.15, 168.222.97.161, 153.75.233.79, 5.22.213.9. This is a template relationship of Moderate confidence, not confirmed common actor ownership. A Shodan HTML hash is a short non-cryptographic fingerprint and shared templates can occur across operators.

Exact RDP certificate search returned the seed only. VirusTotal historical DNS resolved n8n59325.hostkey.in at 2025-11-30, too old to establish current campaign membership. ThreatFox and URLhaus returned no matches. Four OTX pulses include aggregation and copied reporting; do not count them as four independent confirmations.

## 2026-11-20: 185.244.161.72

Read-only lookups were authorized in the chat. Evidence, the report, and
case-specific scripts are in the ignored folder
`data/investigations/2026-11-20-185.244.161.72/`.

Repeat from the project root in PowerShell after authorizing outgoing queries:

```powershell
.venv/Scripts/python.exe data/investigations/2026-11-20-185.244.161.72/lookup_seed.py data/investigations/2026-11-20-185.244.161.72/seed.json
.venv/Scripts/python.exe data/investigations/2026-11-20-185.244.161.72/lookup_pivots.py data/investigations/2026-11-20-185.244.161.72/pivots.json
.venv/Scripts/python.exe data/investigations/2026-11-20-185.244.161.72/check_pattern.py data/investigations/2026-11-20-185.244.161.72/pattern.json
```

The seed script prints statuses only. The follow-up scripts print selected
provider records, never credential values. No downloaded code is executed.
A generic aiohttp 404 hash on port 1050 proved widespread, so all ten sampled
candidates were rejected as campaign links. Exact http.server search returned
zero despite a known matching seed banner; simpler queries recovered the
pattern. No Medium or High confidence adversarial cluster was established.
