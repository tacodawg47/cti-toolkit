# CTI Toolkit Roadmap

Last updated: 2026-11-02

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

Design settled 2026-11-02: one phase, two packages. They share only the
CVE indicator type (added to app/core/indicators.py) and the "send to"
buttons between them. Extraction is pure text processing with no keys, no
cache and no database; vulnerability intelligence is vendor clients plus a
local store, built on the Phase 1 HTTP client, cache and rate limiter.

**IOC extraction** (`app/modules/extract/`)
- Paste text, give a URL, or upload a PDF; extract defanged and plain IOCs
  (IPv4/IPv6, domains, URLs, MD5/SHA-1/SHA-256, email addresses, CVE IDs),
  de-duplicated with counts, each marked defanged or plain and flagged when it
  is a private IP or in the Tranco top list. One click sends an IOC to
  enrichment and a CVE to vulnerability intelligence.
- Written in-house on top of app/core/indicators.py. iocextract (named here
  originally) is GPL-2.0, last released in 2023, and pulls in the `regex`
  package; shipping it would push the whole project toward GPL-2.0. ioc-finder
  is LGPL-3.0 but adds pyparsing for the same result. Our own patterns keep
  the dependency count at zero for text and one for PDFs (pypdf, BSD-3,
  pure Python, no required dependencies).
- URL fetching is for vendor reports and advisories: HTTPS only, public
  hosts only, body capped. It is not a sandbox; a suspected malicious URL
  goes to urlscan through enrichment, never here.

**Vulnerability intelligence** (`app/modules/vulnerability_intelligence/`)

One module page at `/vulnerability-intelligence` with four tabs (a server-
rendered sub-navigation, no JavaScript needed), all reading one local store:
a `vulnerabilities` table in SQLite filled from bulk feeds, plus per-CVE
lookups made on demand and cached. Tab design agreed 2026-11-03; features
borrowed from cve.feedly.com, VulnCheck KEV and XDB, cvedetails.com and
AttackerKB are marked with the source they come from.

1. **Dashboard** (default tab). Sections, each a query over the table:
   - *Your stack*: new or updated vulnerabilities whose vendor/product (KEV
     fields, NVD CPE) match the technology watchlist, newest first, with
     KEV, EPSS and exploit-available badges. The reason the watchlist exists.
   - *Newly known-exploited*: additions to CISA KEV and VulnCheck KEV in the
     last 7 / 30 days, with the ransomware-use flag and, from VulnCheck, the
     citation of the exploitation report (VulnCheck KEV lists more CVEs than
     CISA and cites its evidence; needs the free VulnCheck token).
   - *Trending*: EPSS risers since the last refresh (cve.feedly.com's
     "trending" idea, driven by EPSS now and by news mentions once Phase 4
     links articles to CVEs).
   - *Feed status*: age of each bulk feed and a "Refresh feeds" button.
     Manual refresh in Phase 2; scheduled refresh waits for the Phase 5
     scheduler (same parking-lot pattern as bulk paste).
2. **Search**. A CVE ID or nickname (alias table) opens the detail page, the
   cve.feedly.com-style "one page per CVE" view:
   - Header: ID, aliases, description, published and last-modified dates,
     CVSS vector and score, CWE, and the P1 to P5 priority with the reasons
     behind it (the plugin's prioritisation matrix: KEV, EPSS, exploit
     availability, ransomware use, watchlist match).
   - Affected products with version ranges from the NVD CPE configuration
     (cvedetails.com's product table).
   - References grouped by NVD's own tags: vendor advisory, patch, exploit,
     third-party analysis (cvedetails.com's categorised references).
   - Exploitation evidence: CISA KEV dates and due date, VulnCheck KEV
     citations, inthewild.io sightings, GreyNoise tags, ransomware.live
     groups known to exploit it, OTX pulses mentioning it.
   - Community assessment: AttackerKB attacker-value and exploitability
     ratings with the analyst write-ups (needs a free AttackerKB key; drop-in
     slot, skipped when absent).
   - Exploit availability panel: the Exploits tab's result for this CVE.
   - Raw JSON per source, as the enrichment cards have.
   - Slow per-CVE sources (NVD, GitHub, OTX, AttackerKB) are fetched when
     the page opens and cached with a TTL; the bulk-fed facts render
     instantly from the table.
3. **Exploits**. Enter a CVE; the tab queries GitHub code/repository search,
   inthewild.io, VulnCheck XDB (its index of exploit code across GitHub and
   elsewhere, with the exploit type) and the Nuclei template index, and
   lists what exists with repository, author, stars, created date and last
   push. Links only, never a download: fake "PoC" repositories carrying
   malware aimed at researchers are a known lure, so the tab says so and
   shows age and star count as the analyst's first filter. GitHub keyless
   limit is 10 searches a minute, so results are cached with a TTL and the
   search is never run across the whole feed.
4. **Watchlist**. Manage the technology watchlist (vendor, product, optional
   version pattern; matched case-insensitively against KEV
   vendorProject/product and NVD CPE vendor:product) and the CVE alias table
   (nickname to CVE, seeded from KEV and advisories). Both editable in the
   UI; the watchlist lives in the git-ignored data folder because it may
   describe the operator's own stack. It is a filter and a highlight, not a
   gate: the full feed stays one tab away.

Bulk feeds (downloaded whole into the table): CISA KEV JSON, EPSS daily
CSV, inthewild.io exploited list, VulnCheck KEV (token). Per-CVE lookups
(on demand, cached): NVD, GitHub search, OTX, GreyNoise, ransomware.live,
AttackerKB, VulnCheck XDB. Keys needed: VulnCheck and AttackerKB are free
accounts the operator creates when wanted; an NVD key only raises the rate
limit. Previdian was considered as a third KEV source and dropped
(2026-11-03): it is a paid product.

Progress 2026-11-03: first build committed with the four tabs, the CISA KEV
and EPSS feeds, NVD and GitHub lookups, the priority matrix, the watchlist
and the alias table (docs/runbooks/vulnerability-intelligence.md). Second
build the same day: a "New exploit code" table (GitHub search for CVE-named
repositories created in the last 7 days, run on every refresh and meant to
run at least daily once scheduled, with a your-stack-only toggle, on the
Dashboard and the Exploits tab) and ransomware.live PRO group profiles (the CVEs each
group exploits; shown on the detail page and counted as in-the-wild
exploitation for P1). inthewild.io dropped: API down, RSS and database
frozen since January 2025; replaced by Vulnerability-Lookup (CIRCL)
sightings, keyless, with exploited / published-PoC / seen types. Third
build: the Exploit-DB, Metasploit and Nuclei indexes as bulk feeds into an
`exploits` table; Exploit-DB joins GitHub in the "New exploit code" table,
Metasploit sets P2 as the weaponised tier, Nuclei is a badge. Sources
considered and not used: cve.now (an aggregator of sources already pulled
directly; keep as a fallback), Senserva's tracker (an HTML page, not a
feed). Still to wire: VulnCheck KEV and XDB, OTX pulses by CVE, AttackerKB,
and an NVD recent-changes feed so "Your stack" also shows new CVEs not yet
in KEV.

Ideas taken from Senserva's non-Microsoft CVE tracker (reviewed 2026-11-04;
its data is CISA KEV ranked by EPSS with NVD/CIRCL CVSS, VulnCheck KEV and
ENISA EUVD flags, and vendor advisory links, all of which we pull or can pull
first-hand). Built the same day:
- ENISA EUVD (EU vulnerability database, keyless API) as a feed: a second
  government "exploited" list, into the kev table as source euvd, with
  ENISA's CVSS and EPSS kept.
- CVSS fallback: ENISA's score, else the CNA's score from the CVE record on
  Vulnerability-Lookup, so a fresh CVE is never "not scored".
- "Hottest right now": a deterministic heat score (weights in the runbook)
  over exploited status, ransomware use, EPSS, CVSS, recency, exploit code
  and 48-hour sightings; top 10 / 100 on the Dashboard with the reasons.
  Chatter comes from Vulnerability-Lookup's sightings (Bluesky, Telegram,
  MISP, Shadowserver, PoC notes). X/Twitter is not a source: no free API
  and scraping breaks its terms. Phase 4 news mentions and Phase 5
  Telegram collection will add to the same chatter table.
- Text brief: rendered under the hottest list on every load, one line per
  CVE plus a source preamble and a triage ask, for a report, a ticket or
  whatever LLM the operator chooses. Built from the ranked list only, which
  never uses the watchlist, so it reveals nothing about the operator's
  stack; no model runs inside the app (Phase 11).
Still open from that review: CSV / JSON / RSS exports (Phase 8) and the
per-vendor history and monthly chart (dashboards parking-lot item).

**Supply chain tab** (decided 2026-11-04, fifth tab of this module, to
build next): "is a library, package or repository I depend on vulnerable
or compromised?", the question GitHub Advisory Database and OSV answer
with package-level affected versions per ecosystem (npm, PyPI, Maven, Go,
crates, RubyGems, NuGet...). Three parts:
- A packages watchlist (ecosystem, name, optional version) checked against
  the keyless OSV batch query API on refresh, which is what pip-audit
  already does for this project's own dependencies; results link to the
  advisory and to the CVE detail page when one exists.
- A lockfile / manifest upload (requirements.txt, package-lock.json,
  go.sum, Cargo.lock...) checked the same way, cve.now's lockfile checker
  idea, for the operator's own projects.
- Malicious and compromised package reports: the OpenSSF malicious-packages
  repository (OSV-format records, keyless) as the feed, plus public
  reporting on hijacked packages and repositories (Socket, Phylum,
  StepSecurity, Sonatype, ReversingLabs blogs) through the Phase 4 news
  feed with a "supply chain" keyword category; the operator will name
  specific sources. Shown newest first with ecosystem and package name.
Nothing here needs a key. Record also that GHSA/OSV add little as a CVE
feed for the other tabs: nearly every entry that matters there already
has a CVE in NVD.

Open gaps noted 2026-11-04 from the live dashboard:
- Many CVEs show no vendor, product or CVSS: those fields come from KEV,
  EUVD or NVD, and NVD is fetched per CVE only when a page is opened. Fix:
  an NVD recent-changes feed (lastModStartDate over the last 7 days, pages
  of 2,000) run with the other feeds, so every recently published or
  modified CVE has its NVD record locally; the free NVD key makes it ten
  times faster. Also fills "Your stack" with new CVEs not yet in KEV.
- Charts: the module is tables only. Add small inline SVG charts rendered
  server-side (no JavaScript library needed): KEV additions per month with
  the ransomware share, most-exploited vendors over 12 months, heat bars
  in the hottest table, and a sparkline of sightings per day on the detail
  page. Senserva and cve.feedly.com use this to make the page readable at a
  glance. Belongs with the dashboards parking-lot item; do a first pass
  before Phase 2 closes.
- Ingest everything, surface selectively (decided): KEV ignores CVSS and
  many exploited CVEs are medium severity, EPSS is needed for every CVE a
  page can open, and the exploit indexes are small. Filtering happens on
  the dashboard (heat, exploitation, exploit code), not at ingest.

Three cheap signals to add once the detail page exists (agreed 2026-11-03):
- Patch available: NVD tags references as "Patch" or "Vendor Advisory";
  show a badge and the link, so "exploited and unpatched" stands out.
- Score disagreement: highlight a CVE whose EPSS is high while its CVSS is
  low (or the reverse). Those are the ones a CVSS-only triage misses.
- Deadlines: CISA's KEV due date shown as a countdown on the dashboard and
  the detail page; it is a federal deadline, but a useful urgency proxy.

### Phase 3: Ransomware and breach tracking, credential exposure, domain monitoring
- Ransomware and leak tracker: ransomware.live (free PRO tier), breach.house (paid API, account TBD), RansomLook (open source, also covers markets, forums, Telegram).
- Watchlist of organizations, sectors, and countries with alerts on new victims.
- Credential exposure: Have I Been Pwned domain search, Hudson Rock free infostealer API, IntelligenceX free tier, LeakCheck.
- Identity lookup (username or email as the seed), added 2026-10-27 after a
  work task showed the need. Free building blocks:
  - Username enumeration across sites: WhatsMyName data file (open source
    JSON used by whatsmyname.app), Maigret (3000+ sites, pulls profile
    details and avatars), Sherlock as a cross-check.
  - Email to services: holehe (which sites have an account for this email,
    without alerting the owner).
  - Breach association: HIBP (email in, breach names out), LeakCheck public
    API (username or email in, breach sources and field types out, no
    values), Hudson Rock free API (search by username, email, domain),
    IntelligenceX free tier (document previews), psbdmp (paste search).
  - Email discovery from public artefacts: GitHub commit emails via the
    .patch trick, Gravatar profile JSON, PGP keyserver search, Keybase,
    historical WHOIS, GHunt-style Google account checks.
  - Result view: services found, avatars, breach sources, candidate emails
    with the evidence for each, and a confidence note.
  - Free tier limit: free APIs return which breach and which field types, not
    the plaintext email-to-username pair. A paid vendor key (DeHashed,
    Intelligence X) drops into the adapter slot to fill that gap.
- Local breach index (username <-> email correlation), added 2026-10-27.
  A personal research index over breach compilations the operator has
  lawfully obtained from public sources, for legitimate OSINT/CTI casework.
  - Scope: this is a personal analyst tool, not a public lookup service and
    not for targeting private individuals outside legitimate casework.
  - Acquisition is out of band and the operator's responsibility: download
    and first-touch happen in an isolated VM, never on the host (mirrors the
    darkweb-collection posture where the skill provides the matcher and the
    analyst does the collection off-host). The toolkit ingests from a local
    quarantine path; it does not fetch dumps itself.
  - Minimize at ingest: parse combolist (email:pass, user:pass), CSV, JSON,
    and SQL-dump formats; store username, email, and source only. Drop
    passwords (optional: keep a present/absent flag and hash type, never the
    value).
  - Provenance per record: source name, date added, file SHA-256, record
    count. Every answer cites its source dump.
  - Malware hygiene: hash each file and optionally check VirusTotal before
    opening; open only in the VM.
  - Governance: suppression/deletion list to honor removal requests; local
    query audit log; optional encryption at rest for the store (external
    drive). Store never leaves the machine; never committed to git.
  - Storage: SQLite with indexes (and FTS where useful). Start with a couple
    of major compilations, measure, then decide on scale.
  - Search: username -> associated emails and the reverse, with source
    attribution and a confidence note.
- Newly registered domain monitoring: WhoisDS daily NRD files, ICANN CZDS zone files, certstream certificate transparency. dnstwist permutations of org domains, OpenSquat patterns.
  - Scheduled daily run against org domains.
  - Manual run over a selectable window (1, 7, 30 days).
  - Ad hoc search: type any domain or keyword plus a timeframe.
  - Impersonation watch (added 2026-10-29): prioritize lookalikes of IAM and
    MFA vendors (Okta, Duo, Ping, Microsoft/Entra, Google, Auth0, 1Password,
    Yubico) and the auth-flow nouns attackers register for vishing landing
    pages (mfa, otp, 2fa, sso, vpn, passkey, reset, verify, helpdesk, support,
    login, portal plus the victim org name). Patterns modeled on Scattered
    Spider / 0ktapus-style IAM phishing kits; refresh the keyword and pattern
    list from current threat reporting rather than hardcoding once.
  - Brand-as-subdomain-label pattern (important): actors often put the victim
    name to the LEFT of their own registered domain, e.g.
    mycompany.itpasskey.com or mycompany.sso-reset.com. mycompany is just a
    subdomain label on an attacker-owned apex, so a dnstwist run on
    mycompany.com will never see it. Catch it by matching the auth-noun /
    pattern list against the registered name AND against any label in the
    hostname, wherever the brand token or auth noun appears.
  - Matching layers: exact keyword/brand in the cert SAN, hostname label, or
    registered domain; fuzzy match (dnstwist permutation set, Levenshtein
    distance, homoglyph/IDN and bitsquat detection); combined brand+auth-noun
    heuristics (e.g. okta + reset). Score and rank candidates; this is a lead
    generator, operator triages.
  - Keyword/pattern list is a version-controlled file curated from current
    security-vendor reporting on IAM-impersonation and vishing campaigns.
    Curation can be research- or LLM-assisted OFFLINE (a web search to find
    patterns dnstwist/the base list miss), but the runtime matching stays
    deterministic. An in-tool LLM refresh of the list is a Phase 11 (optional,
    "none" default) feature, never in the core matching path.
    FIRST TASK when this phase begins: generate this keyword/pattern list
    (brand tokens for IAM/MFA vendors + auth nouns + known vishing patterns)
    from current reporting, before building the matcher.
  - Certificate transparency: crt.sh is the primary source and fits the
    desired cadence (scheduled sweep every 6-24h over the watchlist patterns,
    plus an ad-hoc "search this domain/keyword" box) because it is a queryable
    CT database with JSON output. certstream is a LIVE firehose, not a
    queryable API, so it only catches certs issued while a listener is
    connected; treat a self-hosted certstream-server-go listener as an
    OPTIONAL real-time add-on later, not the first build. Wildcard limitation
    still applies: a *.brand.tld cert in CT reveals only the apex, never the
    subdomains, so supplement with passive DNS and on-demand enumeration.
  - Subdomain enumeration (on-demand per investigation, not continuous mass
    scanning). Chosen set, picked for coverage with low overlap:
    - Subfinder (passive, fast) as the default aggregator, runs automatically
      when the module is used. Do NOT give it our VirusTotal key: VT free is
      500/day shared with IOC lookups, and Subfinder already aggregates many
      keyless sources (crt.sh and others), so it does not need VT. Feed it the
      generous keys (OTX, and SecurityTrails free tier if added), withhold the
      scarce VT one.
    - VirusTotal passive DNS / subdomains: reached in the pivoting module
      on-demand per investigation, NOT wired into Subfinder, so it never
      silently spends the daily VT budget.
    - Amass (optional "deep" mode, passive+active) and BBOT (aggressive,
      recursive): both opt-in, OFF by default, operator-triggered only, each
      behind a prominent warning that it is aggressive and can get the
      operator rate-limited or blocked, run in the VM. Never automatic.
    - Findomain dropped: passive like Subfinder, so it adds overlap not reach.
      Revisit only if coverage proves thin.
    Results are normalized and de-duplicated into a hostname set so lists do
    not balloon with duplicates. Subfinder/Amass/BBOT external binaries, not
    pip wheels, so they get a separate supply-chain path (pinned release,
    checksum, run in the VM when a mode does active probing). There is no
    single global DNS zone to query; AXFR is almost always blocked. Realistic
    sources are CT, passive DNS, ICANN CZDS zone files (second-level
    registrations, free but per-TLD approval), and active brute/permutation
    tooling run per-target.
  - Module UX: one search box, not a wall of separate tools. Type a domain or
    keyword once; the module fans out to the safe passive tools automatically
    and shows one merged, de-duplicated, source-attributed result set.
    Aggressive/quota-spending tools (Amass, BBOT) appear as opt-in toggles
    with warnings. Mirrors the Phase 7 OSINT "one box, checkboxes for which
    tools run" pattern so the app stays consistent module to module.

### Phase 4: News and topic search
- Own RSS/report aggregator instead of Feedly (dropped 2026-11-03 — operator
  unhappy with it). Build on open-source libraries (feedparser for RSS/Atom,
  trafilatura or readability for article text), or wrap an existing
  open-source reader. No paid service, no vendor lock-in, runs local.
- Sources: a curated list of vendor / research / CERT feeds. Use the site's
  RSS/Atom where it publishes one; fall back to an HTML scrape with a
  per-source extractor where it does not.
- Google dorking / Custom Search (date-restricted) and GDELT for keyword and
  time-bounded topic monitoring beyond the fixed feed list, to catch reporting
  that is not in a subscribed feed.
- Keyword monitoring and highlighting (the one Feedly feature worth keeping):
  match a keyword list against every collected article and flag/boost the ones
  that hit, so relevant reporting surfaces instead of scrolling the whole feed.
  Deterministic matching; the keyword list is config-driven and can reuse the
  Phase 5 topical-category lists where it makes sense.
- Preselectable keyword chips at the top of the feed: a row of preset keyword
  filters so a reader jumps straight to the topic they care about, plus a
  free-text search box over already-collected articles (search the local
  store, no live fetch per query). This is the piece that makes the feed
  usable as a public "shop window" if it is ever opened up (see the
  public-deployment parking-lot item) — it is read-only and spends no keys.
- Newsletter ingestion (the other Feedly feature worth copying): generate a
  random alias on our own domain, subscribe to vendor newsletters/report
  mailers with it, and ingest the received mail as feed items — no real
  contact address handed out. Receiving does NOT need a self-run mail server:
  point the domain's MX at a free inbound router (Cloudflare Email Routing, or
  the open-source ForwardEmail.net) with a catch-all that forwards or webhooks
  into the app. Cost is basically just the domain (~$10-15/yr); inbound routing
  is free. Keep it INBOUND-ONLY (we never send), which sidesteps the
  open-relay / outbound-spam liability, and keep alias generation behind auth /
  personal — not a public "make me an email" button, which invites abuse.
  Treat every received message as untrusted (no auto-opening attachments/links).
- Topic watchlists: industry verticals, technologies, CVE identifiers and nicknames from the phase 2 alias table.
- Vulnerability enrichment from news: link articles to CVEs.
- AI threat landscape tracking (added 2026-11-03). Not a standalone module —
  there is no deterministic indicator to look up, so it is a curated
  tracking/reading concern that reuses this phase's keyword mechanism. Two
  framings, both as keyword categories (same config-driven, deterministic
  matching as the Phase 5 topical categories):
  - AI as weapon: threat actors USING AI to augment operations — LLM-assisted
    phishing/BEC, deepfake fraud (ties to the Phase 5 "deepfake/KYC" category),
    malware/exploit code generation, influence operations.
  - AI as target: attacks AGAINST AI systems — prompt injection, jailbreaks,
    model and AI-supply-chain exploitation, data/secret exfiltration via agents
    and tools.
  - Presentation: a dedicated "AI Threat Landscape" tab that is a saved
    filtered VIEW over the existing article corpus, not a new data pipeline —
    cheap to build, strong portfolio signal.
  - Curated seed sources (frameworks/trackers, not blind scrape targets): MITRE
    ATLAS (adversarial threat landscape for AI systems — the ATT&CK analogue),
    OWASP Top 10 for LLM Applications, the AI Incident Database, and vendor
    threat reports on malicious AI use (OpenAI / Anthropic / Google /
    Microsoft). ATLAS + OWASP feed the "AI as target" angle; vendor reports
    feed "AI as weapon".
  - Note: this also tracks the attack surface of our own future "assist" phase
    — dogfooding awareness of a capability we will add.

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
- Topical keyword categories (separate from the selector watchlists above):
  thematic lists that flag a post by its subject, not by a selector you own.
  Each category is a named list in a version-controlled config file; matching
  is deterministic word/substring matching at runtime, and the lists are
  curated offline (same rule as the Phase 4 vishing list — any LLM help with
  wording happens offline, never in the running app). Adding a category or a
  keyword is one edit to that file, no code change. Seed categories (to grow
  over time):
  - Fraud: deepfake, KYC.
  - Vulnerability: zero day / 0day, exploit.
  - Industry targeting: Defense, DIB (Defense Industrial Base).
  Design notes: a match tags the post with its category (a post can hit
  several) and is a lead, not a verdict. Very broad terms (e.g. "Defense")
  will be noisy, so support requiring two terms to co-occur, or scoping a
  category to certain channels/forums, to cut false positives. Any sensitive
  entries (your own org, program, or product names) live in the git-ignored
  config location, the same way the selector watchlist is kept out of source.
- On-demand search/scrape, not just the static corpus (operator wants this):
  type a term (domain, email, CVE, handle) and scrape the configured
  Telegram/onion sources live for it, returning fresh hits. Built for
  authenticated/self use. A PUBLIC version is a liability trap: returning
  darkweb/breach hits for an arbitrary third party's email or domain discloses
  personal data about someone who did not consent — the same reason the
  Telegram "lookup bots" are excluded above and the data policy keeps the
  corpus local. If a public self-check is ever wanted, gate it behind proof of
  ownership (verify the domain/email belongs to the requester, HIBP-style),
  never an open arbitrary-term lookup. Pinned for the public-deployment brainstorm.
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
- Username-search integration approach (decided 2026-11-03, applies to the
  Maigret / WhatsMyName references here and in Phase 3). The value of these
  tools is the TECHNIQUE and the SITE LIST (per-site "does this username
  exist" rules: profile URL pattern + a match/no-match test), not the package.
  Decision: build our OWN async checker and our OWN curated site list from
  scratch. A list of sites and existence-detection rules is largely factual,
  so we seed our list with the sites we actually care about and look at
  Maigret / WhatsMyName / Sherlock only for ideas, crediting them as
  inspiration. This sidesteps the licensing of any one project's data file:
  - Preferred: own checker (httpx, already pooled), own list, deterministic,
    matches the "few, pinned, wheels-only" policy.
  - Escape hatch if full breadth is ever wanted fast: wrap the installed CLI
    as an optional subprocess tool (own venv per the isolation ladder) and
    parse its JSON report — its heavy async tree stays out of our import graph.
  License note: do NOT take Maigret as a `pip` dependency, and do not copy any
  specific project's data file verbatim without first checking that file's
  license (MIT/BSD/Apache = fine with attribution; GPL/AGPL = avoid). Building
  our own list avoids the question.
  OPSEC (refined 2026-11-03): username enumeration fires requests at many
  third-party sites from the host IP, so:
  - Keep these OSINT/OPSEC tools behind auth (see the public-deployment
    parking-lot item).
  - Reduce blocks by behaving like a polite client, NOT by evading controls:
    cap concurrency per host and add small delays (bursting is the main
    block-trigger, and it is a knob we control); send an honest, normal
    User-Agent rather than a scraper default; honor each site's own signals
    (back off on HTTP 429 per Retry-After, prefer a site's real
    existence-check endpoint over scraping its HTML); cache and dedup (already
    done); and prune sites that block every time — a curated ~200-site list
    that works beats 3,000 where half challenge you.
  - When a CAPTCHA or WAF blocks a lookup, mark that site blocked/unknown, log
    it, and surface it in the results so the operator sees what was skipped.
  - This is exactly what the mainstream tools (Maigret, Sherlock, holehe) do:
    they handle a block by skipping it, they do NOT defeat it. So we get full
    parity without any bypass. The one excluded bucket is ACTIVE evasion
    (CAPTCHA-solving services, residential-proxy rotation to dodge rate
    limits, humanization to beat detection) — the line between "a lookup tool"
    and "abuse infrastructure", and where the "no bypassing anti-bot
    protections" rule bites. Handling a block is fine; breaking one is not.
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
  enrichment-lookup dashboard, and an overview home. Decide scope and which
  data each surfaces when we get here.
- AI threat landscape dashboard (added 2026-11-03). A visual dashboard over
  the Phase 4 "AI threat landscape" corpus (the two framings: AI as weapon /
  AI as target), not just the filtered list view — e.g. volume-over-time of
  AI-abuse reporting, breakdown by technique (MITRE ATLAS tactic, OWASP LLM
  Top 10 category), top targeted AI tools/vendors, and a recent-incidents
  feed. Good public "shop window" candidate since it is read-only and
  aggregate. Look for existing trackers/visualizations to pull inspiration and
  possibly data from, beyond the seed sources already listed in Phase 4 (MITRE
  ATLAS, OWASP LLM Top 10, AI Incident Database, vendor reports) — operator to
  research specific dashboards later.
- Findomain and any dropped enumeration tools: revisit only if Subfinder
  coverage proves thin.
- VirusTotal monthly quota tracking (~15,500/month): deliberately NOT tracked
  (decided 2026-10-29). VT does not expose a live balance the way Shodan's
  api-info does, so it would need a local monthly counter. Add only if heavy
  use makes the monthly cap a real risk. Minute and daily caps are enforced.
- Phase 1 enrichment expansion (parked 2026-10-29, operator did not want to
  create accounts yet): wire the additional free IOC sources listed under
  "Additional free sources to consider" once their free keys exist. Each is a
  drop-in vendor module. Note: Team Cymru IP-to-ASN adds little over the ASN /
  AS-owner that VirusTotal and AbuseIPDB already return for an IP, so it is
  not worth adding for Phase 1; its exact BGP prefix is more useful in Phase 6
  pivoting (ASN / CIDR-neighbor pivots).
- Censys (parked 2026-11-02): listed as "optional" in Phase 1 and not built.
  It needs an account and API key, and for single-IP enrichment it largely
  duplicates what Shodan InternetDB (free, keyless) and the keyed Shodan
  host lookup already return (ports, services, certificates). Its real value
  is in Phase 6 pivoting: certificate SHA-256 and JARM searches across hosts,
  where Censys often covers hosts Shodan misses. Decide then whether to add
  it; the client is a drop-in vendor module and the cti-skills plugin has a
  stdlib Censys client to port with attribution.
- Phase 1 items that wait for the Phase 5 scheduler (parked 2026-11-02): bulk
  paste of many IOCs with a background job and ETA, and the generic job
  runner. Everything else in the Phase 1 list is built, except BGPView and
  ip-api.com, which were dropped (2026-11-02): both only duplicate the ASN,
  ISP and country data VirusTotal, AbuseIPDB, Shodan and RDAP already return,
  and ip-api's free tier is HTTP-only, which would send the IP under
  investigation in cleartext.
- Public deployment / hosting (parked 2026-11-03): if this is ever turned from
  a local-only tool into a reachable website, design the security posture
  before exposing it. Open questions to work through then, with first-cut
  notes so future-me has a starting point:
  - Login-only vs fully public: default to authenticated (even a single
    account, or basic auth at a reverse proxy). The app spends metered API
    keys and exposes `/health` (key presence, versions), so an open instance
    lets anyone burn your quota and fingerprint the stack.
  - "Not storing sensitive data" is not the whole risk. Even with nothing
    sensitive stored, an exposed instance still risks: quota/credit theft
    (every open lookup spends your keys), being used as an SSRF/proxy to fetch
    attacker-chosen URLs through your host, resource exhaustion / DoS, and info
    leak via `/health` and error pages. And the `.env` keys themselves ARE
    sensitive and sit on the host.
  - Is the host PC at risk? It is one process, but a code-exec bug in the app
    or a dependency runs as your user on your machine. Shrink the blast radius:
    run it in a container / VM / dedicated low-privilege user, never as admin,
    and keep it off the machine that holds the breach corpus and other keys.
  - Protection to design: authentication + per-account rate limits; only drop
    the 127.0.0.1 bind behind a TLS reverse proxy (Caddy/nginx) with
    TrustedHost kept strict; gate or trim `/health`; keep an egress allowlist
    so the fetcher can only reach known vendor APIs (anti-SSRF); keep the
    existing Sec-Fetch-Site / TrustedHost guards and add a CSP; secrets from
    the environment, never baked into an image.
  - Detection: structured access + audit logging (who looked up what, when),
    alerts on quota spikes and auth failures, proxy-level blocking
    (fail2ban-style) for abusive IPs, and a way to see it (the health page or a
    small access-log view). Decide up front what "someone is abusing this"
    looks like and how you would notice.
  - Which modules public vs gated (auth is per route, not all-or-nothing):
    leave the no-key, read-only pieces open as a shop window — the news/RSS
    feed with its keyword search (Phase 4), the IOC extraction page (pure local
    parsing), and a landing/architecture page. Gate everything that spends
    keys, hits metered APIs, or reveals what you are investigating: enrichment,
    infrastructure pivoting, the OSINT module, and any dashboard built on that
    data. Keeping only the no-quota parts open does gut the enrichment demo (it
    is hollow without the keyed vendors), so the gated parts get a demo path
    instead of public exposure (next point).
  - Demoing the gated parts to employers: a read-only GUEST account (tight rate
    limits, a throwaway/low-quota key or canned sample responses, no access to
    the Telegram/dark-web corpus) is a normal, non-suspicious way to show a
    gated app — and demonstrating auth/RBAC is itself a plus for a security
    role. Pair it with short screen-recordings / GIFs in the README for parts
    you would rather not run live. A live screenshare is also fine and exposes
    nothing.
  - Telegram / dark-web monitoring stays private, full stop: the data-handling
    policy says the collected corpus never leaves the machine (it can hold
    breach-derived and personal data and it exposes your selectors). Do NOT put
    a public search box over the real corpus. To show this module, use
    synthetic/sample data or screenshare only.
  - SIEM / WAF if it is ever hosted: put a free WAF in front — Coraza or
    ModSecurity with the OWASP Core Rule Set at the reverse proxy, or
    Cloudflare's free-tier WAF if fronted by Cloudflare — to block common web
    attacks and rate-limit. Ship the app's access/audit logs to a SIEM such as
    Wazuh (free, open source; its agent can also watch the host for
    file-integrity and process anomalies) and alert on auth failures, quota
    spikes, and WAF blocks. WAF is the "prevent" half, Wazuh the "detect" half.
  - Open-vs-gated brainstorm (revisit once the core project is done — several
    gated modules might safely open with the right design):
    - OSINT: possibly public, but your host becomes the ORIGIN of the recon
      (theHarvester / dnstwist / holehe / Maigret hit third parties from your
      IP), so rate-limit hard, prefer passive lookups, and weigh the
      open-recon-proxy abuse/liability. (Operator has specific public OSINT
      sites in mind to compare against.)
    - Dashboards: aggregate / non-sensitive ones likely public; anything over
      investigation or corpus data stays gated.
    - Enrichment without enterprise quotas: a public tier served only from the
      free/keyless sources (GreyNoise community, InternetDB, RDAP, crt.sh,
      CIRCL, abuse.ch) with aggressive caching; for the metered vendors (VT,
      AbuseIPDB, Shodan) require the visitor's OWN key (BYO-key). Still
      rate-limited, and may still be abuse-prone — decide then.
  - Accounts for a demo: BYO-key in user settings (per-account, encrypted) is
    the clean, ethical path — their keys, their quota. Minting extra free-tier
    vendor accounts to hand shared keys to visitors likely breaks those
    vendors' ToS (no multi-account / no third-party use), so avoid it; any
    single demo key must serve cached-only results with tiny limits. Don't name
    the demo account "guest" (obvious target) — use a non-descriptive name. Add
    MFA (TOTP, e.g. pyotp) on all real accounts. Record a short GIF/Loom
    walkthrough in the README for the parts not run live.
  Revisit as its own hardening phase before any non-localhost deployment;
  deliberately out of scope while the tool stays local-only (127.0.0.1).
- Security testing of the app itself (part of the ops/hardening collection; run
  in CI or against a staging instance, never inside the app), parked 2026-11-03:
  - Dependencies: pip-audit (already in the dependency policy) plus GitHub
    Dependabot alerts for vulnerable/compromised packages — formalise in CI.
  - SAST (scan our own code): Bandit (Python, free) and/or Semgrep (free tier).
  - DAST (scan the running app): OWASP ZAP (free, the right tool for a web app)
    or Nuclei templates. For this project ZAP beats Qualys Community Edition,
    which is more host/infra-oriented and heavier.
  - Host/network (only if hosted): OpenVAS/Greenbone Community or Nessus
    Essentials; pairs with the Wazuh agent on the host.
  Not overkill for a security portfolio — security-testing your own tool is a
  selling point. Keep it out of the app runtime.
- GreyNoise API key (parked 2026-11-03): GreyNoise no longer issues free
  keys to consumer email domains, and a paid business plan is not worth it
  for this toolkit. Revisit once the operator owns a domain with inbound
  mail (the Phase 4 newsletter-alias item provides exactly that): sign up
  with an address on that domain and drop the key into the existing
  GreyNoise vendor module. Until then the 10/day community endpoint stands.
- GreyNoise Project Swarm (parked 2026-11-03, operator interested): deploy
  GreyNoise's sensor (a managed honeypot) on a cheap VPS with a public IP,
  never on the home network, and read what hits it through their API
  (sessions, payloads, PCAP; comparison against their global grid). It is a
  data SOURCE for this toolkit, not something to rebuild: (1) an enrichment
  card "seen on my sensors" per IP, a first-party signal like the local
  resolution-history store; (2) a dashboard of top attacking IPs and payloads
  in the last 24h with one-click pivot into enrichment; (3) sensor payloads
  that carry a CVE (exploit attempts) become first-party "exploited in the
  wild against my IP space" sightings on the vulnerability detail page.
  Wazuh is a different layer (host and app log detection); the sensor can
  ship its logs there too, but the value here is GreyNoise's analysis and
  the API. Needs a GreyNoise account and the sensor terms checked first.
  Pricing as published 2026-11-03: a one-time $1 identity verification, no
  subscription, no contract.
  OPSEC AND PERSONAL SECURITY, non-negotiable when this is picked up:
  - Run the sensor on a cheap VPS and NEVER on the home network. A honeypot
    invites traffic by design; attackers who probe it will keep probing the
    IP, and anything on the same network is in the blast radius.
  - The VPS is disposable: nothing personal on it, no reused passwords, SSH
    keys only, a separate key pair from everything else, and no route from
    it back to the home network or to this toolkit's host.
  - The sensor's public IP is not tied to the operator's name: register the
    VPS with the same pseudonymous alias and domain used for the newsletter
    and GreyNoise accounts, not a personal email.
  - Read sensor data through the GreyNoise API only; never pull raw PCAP or
    payloads onto the home machine except into the isolated VM, and treat
    every payload as hostile input (the same rule as breach data).
  - Keep the toolkit integration read-only: it fetches sensor results, it
    never manages or reconfigures the sensor from the home host.

## Data handling policy (breach and leak data)

Adopted 2026-10-27.

- Purpose limit: breach/leak data is used for legitimate OSINT/CTI casework
  (personal and professional), not a public service, not arbitrary targeting
  of private individuals.
- Lawful public sources only. No unauthorized access, no purchase of stolen
  data, no criminal-market engagement to acquire it.
- Acquisition and first-touch happen off-host in a VM. The toolkit ingests
  from a local quarantine path and never fetches dumps itself.
- Minimize: keep username, email, and provenance; drop passwords by default.
- The store lives on local/external disk, is git-ignored, may be encrypted
  at rest, and never leaves the machine.
- Keep a query audit log and a suppression list (honor deletion requests).
- Jurisdiction note: if the corpus includes EU/UK residents, the operator is
  a data controller; "legitimate interest for security research" is the basis
  and carries security + data-subject-request obligations.

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
- 2026-11-02: Phase 2 stays one phase but is built as two packages,
  `extract` and `vulnerability_intelligence`, because the code shares almost
  nothing (text processing versus vendor clients and a local store) while
  the analyst workflow joins them (paste an advisory, enrich the IOCs, look
  up the CVEs). CVE lookups get their own registry and card rather than
  being bolted onto the enrichment verdict: "is it malicious?" and "how
  urgently do we patch?" are different questions with different outputs.
- 2026-11-02: The IOC extractor is written in-house; no GPL dependency
  (iocextract is GPL-2.0). The project itself has no LICENSE file yet; one
  must be chosen before the repository goes public (MIT would match the
  cti-skills code ported with attribution).
- 2026-11-02: Vulnerability intelligence is search plus feed over one local
  table, with a technology watchlist as a filter, not a gate. Bulk feed files
  (KEV, EPSS, inthewild) are downloaded whole; per-CVE APIs (NVD, GitHub,
  OTX, GreyNoise) are queried on demand from the detail page.
- 2026-11-03: Vulnerability intelligence laid out as four tabs (Dashboard,
  Search, Exploits, Watchlist); see the Phase 2 section.
- 2026-11-03: ransomware.live PRO key obtained. Its terms (fair use, no
  relaying other users' queries, no re-serving the data, no cloning their
  dashboard) fit a local single-user toolkit; the group sweep runs at most
  daily. A Phase 3 ransomware tracker on the same key stays within the
  terms as long as it is local and has its own look.
- 2026-11-03: inthewild.io dropped as a source (dormant since January 2025).
- 2026-11-03: API keys that had been pasted into chat sessions were rotated
  in .env, except VirusTotal, which cannot be rotated without a new account
  and was kept (free key, non-commercial, no financial exposure). Rule going
  forward: keys go straight into .env, never into chat.
- 2026-11-03: pypdf 6.21.4 added for PDF text extraction after a full vet
  (docs/runbooks/vetting-a-dependency.md): PyPI provenance names the
  py-pdf/pypdf publish workflow, every packaged file matches the GitHub tag,
  no startup hooks or binaries, no known vulnerabilities. Installed at six
  days old, one day inside the one-week rule, by operator decision: the
  6.21.x line is security hardening for hostile PDFs, which is exactly the
  input this toolkit feeds it. The only process execution in the package is
  an optional external JBIG2 image decoder that is off unless configured.

## Additional free sources to consider (by phase)

Phase 1 shipped (2026-10-29) with only the vendors whose keys were already in
.env (VirusTotal, AbuseIPDB, OTX, Shodan, urlscan, abuse.ch, keyless
GreyNoise). The sources below were deferred only because each needs a new free
account/key the operator must create; wiring one is now a drop-in vendor
module. Planned "Phase 1 enrichment expansion", in rough priority order:
Team Cymru IP-to-ASN (keyless, can add anytime), ipinfo.io, Pulsedive, Google
Safe Browsing, Hybrid Analysis, MalShare. PhishTank/OpenPhish are feeds (local
feed-match module, not the vendor pattern). Malpedia last (vetted account).

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
- Feedly: RESOLVED 2026-11-03 — dropped (operator unhappy with it). Phase 4
  builds its own open-source RSS/report aggregator with keyword highlighting
  and dorking instead.
- Is the Linux machine always on? If so it hosts the monitoring instance.
- Resolved 2026-10-22: GitHub repository created (private).
- GreyNoise: live with the 10/day community endpoint, or obtain a key later
  through a non-consumer email domain.

## Reference material

- cti-skills plugin (MIT): install in Claude Code on Linux to reuse its API references and scripts. Skills of interest: darkweb-collection, indicator-pivoting, osint-methodology, vulnerability-intelligence, ioc-enrichment-workflow, stix-bundle, sigma-writing, yara-writing, kql-writing, and the lookup-* and *-api skills.
- breach.house API docs: https://breach.house/docs
- Feedly developer token: https://feedly.com/v3/auth/dev
