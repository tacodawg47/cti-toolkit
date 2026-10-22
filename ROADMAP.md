# CTI Toolkit Roadmap

Last updated: 2026-10-22

A local-only cyber threat intelligence toolkit that puts multiple analyst
tools under one web interface. Built as a daily-use workflow aid and as a
portfolio project.

## Principles

1. **Deterministic core.** Every lookup, match, score, and pivot is rule-based
   and auditable. No AI in the pipeline.
2. **AI is optional and last.** An "assist" layer (summaries, translation,
   TTP extraction) arrives in the final phase, behind a pluggable provider
   (none / Ollama local / Claude Haiku 5.5). The toolkit must work identically
   with no provider configured. Sensitive data (breach hits, credentials,
   employer incidents) never goes to a cloud model.
3. **Local only.** The app binds to 127.0.0.1. No remote access.
4. **Easy wins first.** Phases are ordered by impact divided by effort.
5. **Reuse open source.** Wrap maintained tools rather than rewriting them.
   The MIT-licensed cti-skills plugin (Liberty91) supplies stdlib Python
   clients for VirusTotal, Shodan, Censys, GreyNoise, AbuseIPDB, OTX, urlscan,
   ransomware.live, MISP, OpenCTI, plus dark web scripts and reference lists.
   Port with attribution.
6. **OS-agnostic code.** Developed and run on Linux; must not break on Windows.

## Stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.12 | One language end to end |
| Web | FastAPI + Jinja2 templates + HTMX | Real API plus HTML UI, no JavaScript build toolchain |
| Database | SQLite with FTS5 | Zero setup, full-text search for collected messages |
| HTTP | httpx (async) | Concurrent vendor calls |
| Models | pydantic | Normalized schemas across vendors |
| Jobs | APScheduler in-process + jobs table | Scheduled monitors, long-running scans |
| Graph UI | Cytoscape.js (single vendored file) | Pivot graph rendering |
| Secrets | .env file, never committed | API keys |
| Packaging | pip + venv now; Dockerfile and Compose in phase 8 | Resume portability |

## Phases

### Phase 1: Skeleton and IOC enrichment
- Project layout, config, key vault, SQLite cache with TTL, rate limiter per vendor, job runner, base UI shell.
- Input: hash, IP, domain, URL. Auto-detect type, defang/refang.
- Vendors: VirusTotal, AbuseIPDB, OTX, GreyNoise, Shodan, urlscan, Censys (optional).
- Normalized verdict card per IOC plus raw vendor JSON.
- Bulk paste of many IOCs.
- Keys needed: VT, AbuseIPDB, OTX, GreyNoise, Shodan, urlscan.

### Phase 2: IOC extraction and vulnerability intelligence
- Paste text, a URL, or upload a PDF; extract defanged and plain IOCs with iocextract; one click sends them to enrichment.
- CVE lookup: NVD, CISA KEV, VulnCheck KEV, EPSS, inthewild.io, GreyNoise CVE tags, GitHub proof-of-concept search, ransomware.live group exploited-CVE lists, OTX pulses by CVE.
- Priority score P1 to P5 using the plugin's prioritisation matrix.
- CVE alias table (nickname to CVE, e.g. CitrixBleed to CVE-2023-4966), editable in the UI, seeded from KEV and advisories.

### Phase 3: Ransomware and breach tracking, credential exposure, domain monitoring
- Ransomware and leak tracker: ransomware.live (free PRO tier), breach.house (paid API, account TBD), RansomLook (open source, also covers markets, forums, Telegram).
- Watchlist of organizations, sectors, and countries with alerts on new victims.
- Credential exposure: Have I Been Pwned domain search, Hudson Rock free infostealer API, IntelligenceX free tier, LeakCheck.
- Newly registered domain monitoring: WhoisDS daily NRD files, ICANN CZDS zone files, certstream certificate transparency. dnstwist permutations of org domains, OpenSquat patterns.
  - Scheduled daily run against org domains.
  - Manual run over a selectable window (1, 7, 30 days).
  - Ad hoc search: type any domain or keyword plus a timeframe.

### Phase 4: News and topic search
- Feedly developer API (needs Pro+ or Enterprise; verify) or OPML import into feedparser.
- GDELT and Google Custom Search (date restricted) for time-bounded topic searches.
- Topic watchlists: industry verticals, technologies, CVE identifiers and nicknames from the phase 2 alias table.
- Vulnerability enrichment from news: link articles to CVEs.

### Phase 5: Telegram and dark web monitoring
- Telegram: Telethon read-only monitor, channel catalog seeded from the plugin's 30+ channel list, snowball discovery queue (new links found in collected messages, joined manually per OPSEC), local full-text search over everything collected. Third-party indexers (TGStat, Telemetr, Lyzem) for discovery.
- Onion indexer search: Ahmia, dark.fail, IntelligenceX, ported from the plugin's onion_search.py.
- Forum catalog seeded from the plugin's 35+ forum list (status, mirror, access tier).
- Selector watchlists using the six families from the plugin: brand, identity, email, domain, network, technical artefacts. Ported keyword_match.py logic.
- Optional Tor SOCKS mode for fetching leak-site mirrors.
- Scheduler and alerting (in-app inbox first; email or webhook later).
- OPSEC primer shipped as in-app documentation. No automated channel joining. No active engagement. No purchases.

### Phase 6: Infrastructure pivoting
- Graph model: nodes are indicators, edges are pivots with a confidence label from the plugin's pivot quality table.
- Pivots: passive DNS (VT, OTX), certificate SHA-256 (Shodan, Censys, crt.sh), JARM, favicon hash, HTTP body hash, subdomains, WHOIS registrant and nameserver, ASN neighbors, VT relationship walks for hashes (contacted IPs and domains, dropped files).
- Cytoscape.js graph view, hop-by-hop expansion, pivot chain export.
- Paid data (bulk historical passive DNS, reverse WHOIS) noted as upgrade path; SecurityTrails and Validin free tiers for light use.

### Phase 7: OSINT
- One search box with input-type detection (domain, IP, email, username, organization) showing which tools will run as checkboxes.
- Result tabs by category: infrastructure and DNS, people and identity, breaches, code leaks.
- Wrapped tools: theHarvester, dnstwist, crt.sh, holehe, Maigret, GitHub code search, Shodan org dorks.
- SpiderFoot as the optional deep scan (runs as a server, triggered by API).
- Deterministic identity correlation: username reuse, email and PGP key reuse, crypto wallet reuse, avatar image hashes. No stylometry, no AI.
- Use cases: own attack surface, vendor footprinting, M&A due diligence, executive exposure, threat actor persona research, leaked secrets, attacker infrastructure attribution.

### Phase 8: Exports, detection templating, packaging
- Exports: STIX 2.1, CSV, TXT, PDF.
- Detection templates from IOC sets: YARA, Sigma, SQL, KQL. SPL skipped.
- Dockerfile and Docker Compose (app, Tor, SpiderFoot).
- README with demo, tests, CI.

### Phase 9: Back burner
- MITRE ATT&CK lookup and mapping (plugin has a local dataset).
- Rigor fields: Admiralty source rating, TLP, confidence level.
- Control coverage mapping.
- Report builder.
- IntelOwl as an optional enrichment backend connector.
- MISP and OpenCTI push.

### Phase 10: AI assist (last)
- Provider abstraction: none (default), Ollama, Claude Haiku 5.5 via the official Anthropic SDK.
- Features, each a button beside deterministic results: enrichment summary, article summary, translation of non-English posts, TTP and ATT&CK extraction from reports, feed relevance ranking, report paragraph drafting.
- Sensitive data routed to local model or excluded.
- Cost reference: Haiku 5.5 is $0.10 per million input tokens and $0.50 per million output tokens; about 1,000 enrichment summaries per month costs roughly $0.65.

## Decisions log

- 2026-10-12: App form over CLI. Local web app, not remotely accessible.
- 2026-10-12: Build own enrichment core; IntelOwl optional later. Reason: IntelOwl is heavy and would make the project a thin wrapper.
- 2026-10-12: Skip phone number and social media OSINT for now.
- 2026-10-12: MMFIC-Framework rejected: requires an LLM, AGPL license, 13 stars, bypasses anti-bot protections.
- 2026-10-12: Python end to end (FastAPI + HTMX), not React. Reason: single language, no Node toolchain, user is new to both.
- 2026-10-13: AI only as an optional last-phase layer.
- 2026-10-22: Develop and run on Linux (dual boot) from the start. Code stays OS-agnostic.

## Open questions

- breach.house: does the user have an advanced or enterprise account? API needs one.
- Feedly: does the user's plan include the developer token? Fallback is OPML export.
- Is the Linux machine always on? If so it hosts the monitoring instance.
- GitHub account for the repository (needed for the resume angle and for CI).

## Reference material

- cti-skills plugin (MIT): install in Claude Code on Linux to reuse its API references and scripts. Skills of interest: darkweb-collection, indicator-pivoting, osint-methodology, vulnerability-intelligence, ioc-enrichment-workflow, stix-bundle, sigma-writing, yara-writing, kql-writing, and the lookup-* and *-api skills.
- breach.house API docs: https://breach.house/docs
- Feedly developer token: https://feedly.com/v3/auth/dev
