<!-- REVIEW COPY: Phase 3 and the data-handling policy are removed. The live roadmap is ROADMAP.md. -->

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
- Vendors with keys: VirusTotal, AbuseIPDB, OTX, Shodan, urlscan, abuse.ch
  (ThreatFox IOC search, MalwareBazaar hash lookup, URLhaus URL/host lookup,
  YARAify). Censys optional.
- Vendors with no key: Shodan InternetDB (ports, vulns, tags per IP),
  CIRCL hashlookup (known-good hash filter), RDAP (official WHOIS replacement),
  BGPView (ASN and prefix), ip-api.com (geo, 45/min non-commercial),
  crt.sh (certificates), GreyNoise community endpoint (about 10/day).
- Rate limiting is a first-class feature: per-vendor token bucket (VirusTotal
  is 4/min and 500/day on the free key), a queue that spaces bulk lookups,
  a result cache with per-vendor TTL so repeats cost nothing, and a quota
  meter in the UI. Bulk jobs run in the background with an ETA.
- Normalized verdict card per IOC plus raw vendor JSON.
- Bulk paste of many IOCs.
- Allowlist filter: Tranco top sites and CIRCL hashlookup suppress obvious
  false positives before quota is spent.

### Phase 2: IOC extraction and vulnerability intelligence
- Paste text, a URL, or upload a PDF; extract defanged and plain IOCs with iocextract; one click sends them to enrichment.
- CVE lookup: NVD, CISA KEV, VulnCheck KEV, EPSS, inthewild.io, GreyNoise CVE tags, GitHub proof-of-concept search, ransomware.live group exploited-CVE lists, OTX pulses by CVE.
- Priority score P1 to P5 using the plugin's prioritisation matrix.
- CVE alias table (nickname to CVE, e.g. CitrixBleed to CVE-2023-4966), editable in the UI, seeded from KEV and advisories.

### Phase 3: (omitted from this review copy)

### Phase 4: News and topic search
- Feedly developer API (needs Pro+ or Enterprise; verify) or OPML import into feedparser.
- GDELT and Google Custom Search (date restricted) for time-bounded topic searches.
- Topic watchlists: industry verticals, technologies, CVE identifiers and nicknames from the phase 2 alias table.
- Vulnerability enrichment from news: link articles to CVEs.

### Phase 5: Telegram and dark web monitoring
- Telegram: Telethon read-only monitor, channel catalog seeded from the plugin's 30+ channel list, snowball discovery queue (new links found in collected messages, joined manually per OPSEC), local full-text search over everything collected.
- Telegram without an account: public channels expose a web preview at
  t.me/s/<channel> that can be read with plain HTTP. Use it to preview a
  channel before joining and as a low-cost poller for channels not yet joined.
- Telegram discovery: Lyzem, TelegramDB, TGStat, Telemetr, and a Google
  Custom Search over site:t.me. SocialLinks' similar-channels tool for
  snowballing. (Source: The-Osint-Toolbox/Telegram-OSINT list.)
- Excluded: Telegram "lookup bots" (Telelog, Sherlock-style phone lookups,
  leak bots). Unknown operators, breach-derived personal data, and every
  query leaks your selectors to a third party.
- Onion indexer search: Ahmia, dark.fail, IntelligenceX, ported from the plugin's onion_search.py.
- Forum catalog seeded from the plugin's 35+ forum list (status, mirror, access tier).
- Selector watchlists using the six families from the plugin: brand, identity, email, domain, network, technical artefacts. Ported keyword_match.py logic.
- Optional Tor SOCKS mode for fetching leak-site mirrors.
- Scheduler and alerting (in-app inbox first; email or webhook later).
- OPSEC primer shipped as in-app documentation. No automated channel joining. No active engagement. No purchases.

### Phase 6: Infrastructure pivoting
- Graph model: nodes are indicators, edges are pivots with a confidence label from the plugin's pivot quality table.
- Pivots: passive DNS (VT, OTX), certificate SHA-256 (Shodan, Censys, crt.sh), JARM, favicon hash, HTTP body hash, subdomains, WHOIS registrant and nameserver, ASN neighbors, VT relationship walks for hashes (contacted IPs and domains, dropped files).
- Advanced fingerprint pivots (added 2026-10-28, confirmed worth doing):
  - JARM: active TLS server fingerprint. Pivot via Shodan `ssl.jarm:"<hash>"`
    to find hosts (often the same C2 family) presenting the same TLS stack.
    Strong for unusual JARMs, weak for default-config tools, so label
    confidence per the pivot quality table.
  - JA3 / JA3S and the JA4+ suite (JA4, JA4S, JA4H, JA4X, JA4T): TLS and HTTP
    fingerprints. JA4+ is the modern, more robust successor; prefer it where a
    source exposes it. Strong for custom clients, weak for OS-default stacks.
  - Favicon hash (mmh3): pivot via Shodan `http.favicon.hash:<n>` to find
    hosts serving the same favicon (phishing kits, panels, C2 UIs).
  - HTTP response body / HTML content hash and page-title pivots (urlscan,
    Shodan) to cluster templated infrastructure.
  - Tracking-ID pivots: Google Analytics / GA4 / AdSense / Facebook Pixel IDs
    embedded in page source (urlscan, publicwww) tie sites to one operator.
  - SSH host key fingerprint and HTTP header hash (HHHash) via Shodan.
  - Each pivot carries a confidence and a false-positive note; the graph never
    presents a weak pivot (same registrar, same /24, shared CDN) as strong.
- Cytoscape.js graph view, hop-by-hop expansion, pivot chain export.
- Local resolution-history store (added 2026-10-29): a SQLite table
  (indicator, resolved_to, first_seen, last_seen, source) that records every
  domain->IP and IP->host resolution the toolkit performs, building a
  first-party passive-DNS history of the indicators the operator actually
  looks at. Free, private, no quota. Complements provider pDNS (breadth) with
  continuity and change detection on our own watchlist. Honest limit: it only
  knows what we have looked at and has no history before we started.
- Reviewing and visualizing the stored data (this is a web app, so review
  happens in the UI, not by reading SQLite by hand):
  - pDNS / history page: a search box (domain -> its resolution history; IP ->
    domains seen resolving there) rendering a results table plus a simple
    first_seen/last_seen timeline.
  - Changes feed: the scheduler (Phase 5) re-resolves watchlist domains and
    logs a change event when a watchlisted indicator resolves to something
    new. Shown as a reverse-chronological feed/in-app inbox.
  - Pivot graph: Cytoscape.js renders domain<->IP<->domain relationships from
    this store, so the history feeds the graph directly.
  - Dashboard home: tiles for watchlist size, changes in the last 24h/7d,
    recent enrichments, and API quota usage.
- Change-detection noise control (important, or the changes feed is useless):
  only alert on WATCHLIST indicators, not every lookup; suppress expected
  rotation from large CDN/hosting ASNs (Cloudflare, Akamai, Fastly, etc.) via
  an allowlist; alert on MEANINGFUL change (new ASN, new country, new hosting
  provider) rather than every IP tick inside the same provider; collapse and
  de-duplicate. Operator can tune the suppression list.
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
- System health page (added 2026-10-27): installed package versions versus
  latest on PyPI (PyPI JSON API), pip-audit findings, versions of wrapped
  tools (Maigret, dnstwist, theHarvester, SpiderFoot) versus their latest
  releases, vendored JavaScript versions, and the age of each data feed
  (NRD files, KEV, EPSS). Read-only: it reports, the operator decides.
- Isolation ladder for third-party code: app venv (our own code and
  mainstream packages) -> separate venv per wrapped tool -> container
  (phase 8) -> VirtualBox VM for unfamiliar or untrusted sources. A container
  is a convenience and reproducibility boundary; a VM is the security
  boundary.

### Phase 9: Back burner
- MITRE ATT&CK lookup and mapping (plugin has a local dataset).
- Rigor fields: Admiralty source rating, TLP, confidence level.
- Control coverage mapping.
- Report builder.
- IntelOwl as an optional enrichment backend connector.
- MISP and OpenCTI push.

### Phase 10: Documentation and runbooks
- Documentation is written as we go: every approved action produces a runbook
  under docs/runbooks/ (exact commands, why, how to repeat by hand), and every
  module gets a docs page when its phase closes.
- This phase consolidates: user guide per tool, analyst workflow runbooks
  (triage an IOC, investigate a domain, respond to a ransomware victim alert,
  weekly vulnerability review), operations runbook (start, stop, backup,
  rotate keys), and a contributor guide.

### Phase 11: AI assist (last)
- Provider abstraction: none (default), Ollama, Claude Haiku 5.5 via the official Anthropic SDK.
- Features, each a button beside deterministic results: enrichment summary, article summary, translation of non-English posts, TTP and ATT&CK extraction from reports, feed relevance ranking, report paragraph drafting.
- Sensitive data routed to local model or excluded.
- Cost reference: Haiku 5.5 is $0.10 per million input tokens and $0.50 per million output tokens; about 1,000 enrichment summaries per month costs roughly $0.65.

## Parking lot (revisit after the final phase)

Added 2026-10-29. Ideas we were unsure about or deferred on purpose, parked
here so they do not block progress. Once the core phases are complete, review
this list and decide what to pull into active work. Keeps the project moving.

- Real-time certstream listener (self-hosted certstream-server-go, bound to
  127.0.0.1): continuous CT firehose to catch issuance the moment it happens,
  as an upgrade to the crt.sh scheduled/ad-hoc sweep. Client-only or
  localhost-bound, so no inbound exposure; store only matches, never the
  firehose.
- MISP and/or OpenCTI integration as an optional downstream TIP: push curated
  finished IOCs out for long-term correlation and sharing. Toolkit core stays
  on local SQLite and never depends on a TIP server being up. (Also tracked in
  Phase 9.)
- Additional dashboards beyond the Phase 6 pivot/pDNS views and the Phase 8
  health page: a ransomware-victim dashboard, a DNS/passive-DNS dashboard, an
  enrichment-lookup dashboard, vulnerability dashboards and an overview home. Decide scope and which
  data each surfaces when we get here.
- Findomain and any dropped enumeration tools: revisit only if Subfinder
  coverage proves thin.
- VirusTotal monthly quota tracking (~15,500/month): deliberately NOT tracked
  (decided 2026-10-29). VT does not expose a live balance the way Shodan's
  api-info does, so it would need a local monthly counter. Add only if heavy
  use makes the monthly cap a real risk. Minute and daily caps are enforced.

## Data handling policy (omitted from this review copy)

## Dependency and supply-chain policy

Adopted 2026-10-27. Details and commands in docs/runbooks/dependency-policy.md.

1. Few dependencies, from well-known maintainers, copied by exact name from
   PyPI to avoid typosquats.
2. Every version pinned and hash-locked in requirements.txt; installs use
   `--require-hashes` so a swapped package fails to install.
3. Wheels only (`--only-binary=:all:`) so no package runs build code at
   install time.
4. No upgrades without reading the changelog; prefer versions at least a
   week old (lets the ecosystem catch a hijacked release).
5. `pip-audit` before each commit that changes dependencies; Dependabot
   alerts enabled on the GitHub repository.
6. Third-party OSINT tools (theHarvester, Maigret, dnstwist, SpiderFoot) run
   in their own venvs or containers, never in the app's venv, and ideally in
   a VM when the source is less established.
7. Vendored JavaScript (Cytoscape.js, HTMX) downloaded from official releases
   with the SHA-256 recorded in docs/.

## Decisions log

- 2026-10-12: App form over CLI. Local web app, not remotely accessible.
- 2026-10-12: Build own enrichment core; IntelOwl optional later. Reason: IntelOwl is heavy and would make the project a thin wrapper.
- 2026-10-12: Skip phone number and social media OSINT for now.
- 2026-10-12: MMFIC-Framework rejected: requires an LLM, AGPL license, 13 stars, bypasses anti-bot protections.
- 2026-10-12: Python end to end (FastAPI + HTMX), not React. Reason: single language, no Node toolchain, user is new to both.
- 2026-10-13: AI only as an optional last-phase layer.
- 2026-10-22: Develop and run on Linux (dual boot) from the start. Code stays OS-agnostic.
- 2026-10-22 (later): Linux dual boot hit a kernel panic after an upgrade
  ("Unable to mount root fs on unknown-block(0,0)"). Development continues on
  Windows until Linux is required (Tor, SpiderFoot, always-on monitoring).
  Options then: boot the previous kernel from the GRUB advanced menu,
  reinstall the partition, or install WSL2 inside Windows instead.
- 2026-10-22: Repository is private at github.com/tacodawg47/cti-toolkit.
- 2026-10-23: Approval-first workflow. Claude asks before any install, git or
  GitHub operation, script execution, or external call, and writes a runbook
  afterwards. Commits are approved one by one.
- 2026-10-23: abuse.ch suite and several keyless sources added to phase 1.
  GreyNoise demoted to a best-effort source because free keys are no longer
  issued to consumer email domains.
- 2026-10-23: Documentation phase inserted before the AI phase.

## Additional free sources to consider (by phase)

- Phase 1: Pulsedive (free key), Google Safe Browsing (free key), PhishTank
  and OpenPhish (free feeds), Hybrid Analysis (free key, sandbox reports),
  MalShare (free key), Malpedia (free account, malware family context),
  ipinfo.io (free key, 50K/month), Team Cymru IP-to-ASN.
- Phase 2: NVD API key (free, raises rate limit), Vulners (free tier),
  AttackerKB (free key), Nuclei templates as an exploit-availability signal.
- Phase 3: SecurityTrails (free, 50/month), WhoisXML (free, 500/month),
  Validin (free tier), ransomwatch archive.
- Phase 6: Validin and SecurityTrails for passive DNS, crt.sh for cert pivots.

## Open questions

- breach.house: does the user have an advanced or enterprise account? API needs one.
- Feedly: does the user's plan include the developer token? Fallback is OPML export.
- Is the Linux machine always on? If so it hosts the monitoring instance.
- Resolved 2026-10-22: GitHub repository created (private).
- GreyNoise: live with the 10/day community endpoint, or obtain a key later
  through a non-consumer email domain.

## Reference material

- cti-skills plugin (MIT): install in Claude Code on Linux to reuse its API references and scripts. Skills of interest: darkweb-collection, indicator-pivoting, osint-methodology, vulnerability-intelligence, ioc-enrichment-workflow, stix-bundle, sigma-writing, yara-writing, kql-writing, and the lookup-* and *-api skills.
- breach.house API docs: https://breach.house/docs
- Feedly developer token: https://feedly.com/v3/auth/dev
