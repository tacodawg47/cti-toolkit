# CTI Toolkit Roadmap

Last updated: 2026-11-10 (v3, with the 2026-11-06, 2026-11-09 and 2026-11-10 review rounds)

A local-only cyber threat intelligence toolkit that puts multiple analyst
tools under one web interface. Built as a daily-use workflow aid and as a
portfolio project.

## Conventions for this document

- The roadmap holds scope, phase order, and decisions with a one-line reason.
  Its job is to move the project phase to phase and confirm each phase
  delivers what it sets out to deliver.
- Troubleshooting records, mistakes, one-off policy exceptions, build
  narrative, and personal commentary do not belong here; they live in
  docs/journal.md. Working rules for the AI assistant live in CLAUDE.md.
- Instructions are recorded as plain directives: "Include X", "Exclude X".
- Wording stays project-specific. "Operator" means the analyst using the tool
  and appears only where a feature has a user-facing role.

## Principles

1. **Deterministic core.** Every lookup, match, score, and pivot is rule-based
   and auditable. No AI in the pipeline.
2. **AI is optional and last.** An "assist" layer (summaries, translation,
   TTP extraction) arrives in the final phase, behind a pluggable provider
   (none / Ollama local / Claude Haiku 5.5). The toolkit must work identically
   with no provider configured. Sensitive data (breach hits, credentials,
   internal incident data) never goes to a cloud model.
3. **Local only.** The app binds to 127.0.0.1. No remote access.
4. **Easy wins first.** Work is ordered by impact divided by effort. Phase
   numbers are labels; the Build order section gives the sequence.
5. **Reuse open source.** Wrap maintained tools rather than rewriting them.
   The MIT-licensed cti-skills plugin (Liberty91) supplies stdlib Python
   clients for VirusTotal, Shodan, Censys, GreyNoise, AbuseIPDB, OTX, urlscan,
   ransomware.live, MISP, OpenCTI, plus dark web scripts and reference lists.
   Port with attribution. Check each project's license before porting code or
   data (MIT/BSD/Apache: fine with attribution; GPL/AGPL: do not copy).
6. **OS-agnostic code.** The app runs on Linux and Windows. Container
   workloads (the Phase 5 collectors and sidecars) need Linux or WSL2.
7. **API before scraping.** Use a vendor API or feed where one exists and its
   terms allow the use. Scrape only where none does. No scraping of
   ransomware.live or any other site that offers an API.
8. **Scraping policy.** Collection from sources without a usable API goes
   through the Phase 5 scraping layer. Every source has an entry in the source
   registry and does not run until that entry records its class and a terms
   review:
   - Criminal-operated sources (ransomware leak sites, cybercrime forums and
     markets, actor-run mirrors): browser automation, challenge handling, and
     Tor or proxy egress are in scope.
   - Legitimate platforms that sometimes host malicious content (paste sites,
     document-sharing sites, code hosts, social platforms): the platform's
     API, logged-out public pages, and search-engine alerts only. No challenge
     bypass and no use that breaks the platform's terms.

   No impersonation accounts: nothing poses as a real person or organisation.
   Research personas (pseudonymous, read-only accounts the analyst creates by
   hand for OPSEC) are allowed. The toolkit never creates accounts, posts,
   vouches, pays, or engages with actors.
9. **Monitoring versus investigation.** Phase 3 (digital risk protection)
   watches seeds the operator owns or is authorised to monitor and raises
   alerts. Phase 7 (OSINT) answers on-demand questions about any seed. Both
   read one shared local corpus.

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
| Browser automation | Playwright (Python) | JavaScript-heavy pages and session capture (Phase 5) |
| Challenge handling | FlareSolverr or a compatible solver (sidecar container, chosen by test) | Cloudflare and DDoS-Guard challenges on criminal-operated sources (Phase 5) |
| Egress | Tor for onion services; a VPS or per-source proxy for clearnet criminal sources | Keeps the home IP off criminal infrastructure (Phase 5) |
| Fuzzy matching | rapidfuzz (candidate) | Handle correlation; SQLite has no built-in Levenshtein (Phase 7) |
| Secrets | .env file, never committed | API keys |
| Packaging | pip + venv now; sidecar containers from Phase 5; Dockerfile and Compose in Phase 8 | Portability and reproducible installs |


## Phases

### Build order

Phase numbers are stable labels used in cross-references. They are not the
build sequence. Build in this order:

1. Phase 1 (complete).
2. Phase 2: finish "Still to wire" and the Supply chain tab.
3. Phase 5 foundation slice: scheduler, job runner, alert inbox, and the
   shared corpus with its source registry (app/core). Unblocks Phase 1 bulk
   paste, Phase 2 scheduled refresh, and every alert.
4. Phase 3, slice A (API-only): ransomware victim tracking and watchlist
   alerts, vendor breach lookups, lookalike-domain and subdomain monitoring,
   GitHub secret leaks. Needs only step 3.
5. Phase 9, threat actor profiles seed slice: structured sources only.
6. Phase 4: news and topic search.
7. Phase 5 collectors and scraping layer. Needs a container host (WSL2 or
   Linux).
8. Phase 7, first slice: identity lookup and the username checker.
9. Phase 3, slice B: hits from collected sources (paste, forum, Telegram,
   marketplace), page similarity, and social handle monitoring. Needs steps 7
   and 8.
10. Phase 6, the rest of Phase 7, then Phases 8 to 11.

### Phase 1: Skeleton and IOC enrichment
- Project layout, config, key vault, SQLite cache with TTL, rate limiter per vendor, job runner, base UI shell.
- Input: hash, IP, domain, URL. Auto-detect type, defang/refang.
- Vendors with keys: VirusTotal, AbuseIPDB, OTX, Shodan, urlscan, abuse.ch
  (ThreatFox IOC search, MalwareBazaar hash lookup, URLhaus URL/host lookup,
  YARAify). Censys optional.
- Vendors with no key: Shodan InternetDB (ports, vulns, tags per IP),
  CIRCL hashlookup (known-good hash filter), RDAP (official WHOIS replacement),
  crt.sh (certificates), GreyNoise community endpoint (about 10/day). BGPView and ip-api.com were
  dropped (see the parking lot).
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
buttons between them. Extraction is pure text processing with no keys and no
cache (saving results to the shared corpus is planned, see below);
vulnerability intelligence is vendor clients plus a
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
- Include (2026-11-06): a saved extraction is a document record in the shared
  corpus that carries its source. A fetched URL records itself; pasted text
  and uploaded files require a source field (title or name, publisher, date,
  optional TLP) before they are saved. Each extracted indicator is stored as
  a sighting linked to that document, so any indicator can answer "which
  report did this come from, and when?".
- Include (2026-11-06): "Enrich all" sends a document's indicators to
  enrichment through the job queue (keyless sources first, keyed vendors on
  request) and stores the composite attributes (ASN, registrar, nameservers,
  WHOIS dates, certificate and SAN, JARM, hosting, file metadata) for Phase 6
  pivoting. Needs the Phase 5 foundation slice.
- Include (2026-11-06): ATT&CK technique, software, and group IDs (T1059.001,
  S0154, G0016) as extracted types, named from a local ATT&CK dataset, plus
  actor-name matches against the Phase 9 alias table. This gives a
  deterministic technique list for any report that carries a TTP table.
  Reports that describe behaviour only in prose wait for Phase 11.
- Include (2026-11-06): the "Use" column too. CISA joint advisories and the
  current AR/MAR template render ATT&CK as real HTML tables, one per
  tactic, header `Technique Title | ID | Use`, tactic in the `<caption>`
  ("Table 5. Defense Evasion"), technique IDs in links to
  attack.mitre.org/versions/vNN/techniques/T####/###, stable since at least
  2023 (checked AA25-203A, AA26-097A, AR26-113A). Some Word-pasted
  advisories use `Tactic | ID | Technique | Procedure` with `&nbsp;` in the
  headers. Microsoft's blog uses a tactic heading followed by a bullet list
  "T1190 Name | procedure"; Google Cloud posts have no table. So the
  extractor is table-aware: for any table or list block whose rows contain a
  technique ID, it captures the whole row as a TTP record (tactic from the
  caption or heading, ID, name, and the remaining cells as "use"), after
  normalising header text (strip tags, nbsp, case). A document with no such
  block yields IDs only, labelled "no procedure text". CISA STIX bundles are
  not a shortcut: the FIRESTARTER bundle has no attack-pattern objects and
  AA25-203A's carry the ID only in the object name.
- Include (2026-11-09): column roles come from the cell contents, never
  from the header text. A survey of 69 reports from 40 publishers
  (2024-2026) found 17 different names for the procedure column
  (Description, Evidence, Observed Behavior, Annotation, Use, Procedure,
  Example, Notes, Summary, Observed Activity, Code behavior, Where it
  appears, Threat Actor Action, and more), three publishers whose headers
  are simply wrong (a "Tactic" column holding technique names, a
  "Technique" column holding IDs), one table with no header at all, and
  one in Korean. Rules:
  - A block is a candidate when it holds two or more valid technique IDs:
    a table (65% of the sample), a grid of sibling `div`s (Recorded
    Future), list items, `pre` lines, or `br`-split paragraphs (13%), a
    heading that carries an ID with paragraphs under it (4%).
  - In a table: the ID column is the one where most cells contain an ID;
    the tactic column is the one whose values are tactic names or TA IDs
    from the local dataset; the name column is the one whose values match
    the dataset's name for that row's ID; the procedure column is the
    remaining column with the longest average text. The header synonym
    list only breaks ties. No column left over means "IDs and names only"
    (36% of the sample).
  - ID and name sharing a cell (`T1059.001 PowerShell`, `Name (ID)`,
    `Parent::Sub [ID]`, with a hyphen, en dash, em dash, or colon) are
    split by matching the dataset name, because technique names contain
    colons themselves. A separate sub-technique column never occurs.
  - Tactic is carried forward from an expanded `rowspan`, the last
    non-blank tactic cell, a full-width separator row, the table caption,
    or the nearest bold paragraph or heading above the block.
  - Several IDs in one cell give one record per ID sharing the row's text,
    flagged "shared procedure". When the stated tactic is not one the
    dataset lists for the technique, the stated one is kept and flagged.
  - Prose fallback: an ID outside any block takes the sentence it sits in
    as its procedure, flagged as such and marked low confidence when the
    sentence holds three or more IDs.
  - Tactic names come from the local ATT&CK dataset with aliases, not a
    fixed list of 14: ATT&CK v19 and v20 split Defense Evasion into
    Stealth and Defense Impairment, and 2026 reports use both vocabularies.
  - MITRE ATLAS IDs (`AML.T0040`) are a separate type and must not match
    the ICS pattern `T0xxx`. Every ID is validated against the Enterprise,
    ICS, and Mobile datasets; deprecated IDs are kept and flagged.
  - Parsing must tolerate an unclosed `thead`, header cells that are bold
    `td`s, stray markdown asterisks, non-breaking spaces, a byte-order
    mark, and a decoy table with a "Technique" header and no IDs.
  - PDFs: IDs and names reliably; procedure text only when the plain-text
    paragraphs line up one-to-one with the IDs, otherwise "IDs and names
    only". A STIX file beside the report (NCSC-UK malware analysis
    reports carry the procedure in each attack-pattern's description) is
    preferred to the PDF.
  - Out of reach without OCR or a model, and labelled so: matrices
    published as images, PDFs with no text layer, tables that exist only
    in a page's JavaScript payload, and reports with no IDs at all (in
    this sample CrowdStrike, Proofpoint, Volexity, Check Point, CERT-UA,
    CERT-FR).
  - Offline test fixtures: twelve saved pages, one per layout (ESET, Talos,
    Intel 471, Fortinet, Group-IB with and without header, Microsoft,
    Recorded Future HTML and PDF, DFIR Report, Picus, Zscaler ATLAS,
    Genians Korean); URLs in docs/journal.md.

**Vulnerability intelligence** (`app/modules/vulnerability_intelligence/`)

One module page at `/vulnerability-intelligence` with five tabs (Dashboard,
Search, Exploits, Watchlist, Feeds; a server-rendered sub-navigation, no
JavaScript needed), all reading one local store:
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
   - *Feed status*: a one-line status. The feed table and the refresh
     buttons are on the Feeds tab. Manual refresh in Phase 2; scheduled
     refresh waits for the Phase 5 foundation slice (same pattern as bulk
     paste).
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
     citations, Vulnerability-Lookup (CIRCL) sightings, GreyNoise tags,
     ransomware.live
     groups known to exploit it, OTX pulses mentioning it.
   - Community assessment: dropped 2026-11-09. It relied on AttackerKB,
     whose public platform and API Rapid7 retired on 2026-08-18.
   - Exploit availability panel: the Exploits tab's result for this CVE.
   - Raw JSON per source, as the enrichment cards have.
   - Slow per-CVE sources (NVD, GitHub, OTX) are fetched when
     the page opens and cached with a TTL; the bulk-fed facts render
     instantly from the table.
3. **Exploits**. Enter a CVE; the tab queries GitHub code/repository search,
   the Exploit-DB, Metasploit, and Nuclei indexes, and (once wired) VulnCheck
   XDB (its index of exploit code across GitHub and elsewhere, with the
   exploit type), and
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
5. **Feeds**. The status and age of each bulk feed, with refresh buttons.

Bulk feeds (downloaded whole into the table): CISA KEV JSON, EPSS daily
CSV, ENISA EUVD, NVD recent changes, the Exploit-DB, Metasploit, and Nuclei
indexes, and VulnCheck KEV (token; not yet wired). Per-CVE lookups (on
demand, cached): NVD, GitHub search, Vulnerability-Lookup sightings,
ransomware.live, and, not yet wired, OTX, GreyNoise, and VulnCheck XDB.
Keys needed: VulnCheck is a free account created when wanted; an NVD key
only raises the rate limit. Previdian was considered as a third KEV source and dropped
(2026-11-03): it is a paid product.

**Built so far** (build narrative is in docs/journal.md)
- Tabs: Dashboard, Search (one detail page per CVE with the P1 to P5
  priority and its reasons), Exploits, Watchlist (technology watchlist and
  CVE alias table), and Feeds (feed status and refresh buttons).
- Bulk feeds: CISA KEV, EPSS, ENISA EUVD (a second government "exploited"
  list, stored as source euvd with ENISA's CVSS and EPSS kept), NVD recent
  changes (everything modified since the last run, so recent CVEs carry vendor,
  product, and CVSS, and "Your stack" shows CVEs for watched products before
  they reach KEV), and the Exploit-DB, Metasploit, and Nuclei indexes (an
  `exploits` table).
- Per-CVE lookups, cached: NVD, GitHub, ransomware.live PRO group profiles
  (the CVEs each group exploits), and Vulnerability-Lookup (CIRCL) sightings
  (keyless; exploited / published-PoC / seen types).
- Scoring: the priority matrix (KEV, EPSS, exploit availability, ransomware
  use, watchlist match; Metasploit sets P2 as the weaponised tier; group
  exploitation from ransomware.live counts as in-the-wild for P1; Nuclei is a
  badge). CVSS fallback: ENISA's score, else the CNA's score from the CVE
  record on Vulnerability-Lookup, so a fresh CVE is never "not scored". A
  deterministic heat score drives "Hottest right now" (weights in the runbook).
- Dashboard sections: Your stack; Newly known-exploited; Trending (EPSS
  risers); Hottest right now (top 10 / 100 with reasons); New exploit code
  (GitHub search for CVE-named repositories created in the last 7 days, plus
  Exploit-DB, with a your-stack-only toggle); ransomware groups and the CVEs
  they exploit (this year by default; data in data/cti.db, never re-served);
  server-rendered SVG charts (known-exploited CVEs per month with the
  ransomware share, most-exploited vendors over 12 months, heat bars, and a
  sightings-per-day sparkline on the detail page); feed status. Every CVE table
  shares one renderer with server-side filters, sorting, and paging.
- Text brief: rendered under the hottest list, one line per CVE plus a source
  preamble and a triage ask, for a report, a ticket, or an external LLM. It is
  built from the ranked list only (never the watchlist), so it reveals nothing
  about the stack; no model runs inside the app.
- Design decision: ingest everything, surface selectively. KEV ignores CVSS,
  many exploited CVEs are medium severity, EPSS is needed for every CVE a page
  can open, and the exploit indexes are small. Filtering happens on the
  dashboard (heat, exploitation, exploit code), not at ingest.
- Sources considered and not used: X/Twitter (no free API; scraping breaks its
  terms), Previdian (paid), cve.now (aggregates sources already pulled
  directly; fallback only), Senserva's tracker (an HTML page, not a feed),
  inthewild.io (API down; RSS and database frozen since January 2025).

**Still to wire**
- VulnCheck KEV and XDB (key slot VULNCHECK_API_KEY exists; needs the free
  community token) and OTX pulses by CVE. AttackerKB is dropped: Rapid7
  retired the public platform and API on 2026-08-18.
- Include (2026-11-09): views. The dashboard's stacked sections become
  named views over the one `vulnerabilities` table, each a saved filter
  with its own URL, a counter on the dashboard, and the shared table
  renderer (filter bar, sort, pager). A view is a rule, not a second
  table in the database, so a CVE can sit in several and its badges show
  which. The dashboard keeps the counters, the charts, and the top rows of
  the three or four views the operator pins. Views and their membership
  rules, in build order:
  1. Exploited: in CISA KEV, VulnCheck KEV, the EUVD exploited list, any
     catalogue in Vulnerability-Lookup's `/api/kev` (it aggregates CIRCL,
     CISA, ENISA, Shadowserver and others), Microsoft `Exploited:Yes`, or
     CISA SSVC Exploitation = active. One badge per source and the
     earliest date as "first seen exploited".
  2. Watchlist: matches the technology watchlist (built), with the other
     views shown as badges.
  3. Exploit code, not yet exploited: not in view 1 and has a Metasploit
     module, Nuclei template, Exploit-DB entry, VulnCheck XDB entry,
     GitHub PoC, or SSVC Exploitation = poc. A maturity column (module,
     template, proof of concept).
  4. Patch Tuesday (Microsoft): MSRC's per-CVE CSAF files, driven from
     `msrc.microsoft.com/csaf/advisories/changes.csv` (keyless; the
     monthly CVRF document is over 10 MB). Membership: initial release on
     the second Tuesday of the month, excluding Azure Linux ("Mariner")
     and Chromium-assigned entries, which go under an "also released"
     filter; any other date is out-of-band. Columns: CVE, title,
     component, impact, severity, CVSS, publicly disclosed, exploited,
     exploitability assessment, customer action required, KB or fixed
     build. Sub-filters: exploited, publicly disclosed, "Exploitation
     More Likely", critical. October 2026 carried about 1,400 CVEs, so
     the view opens on the sub-filters, not the full list. Default
     filter for Microsoft rows (operator's rule, 2026-11-10; to refine in
     the working session): show only high or critical severity, or
     exploit code available, or exploited. Everything is still ingested
     (the "ingest everything, surface selectively" decision stands); the
     rest sits behind a "show all" toggle. Two things to check against
     real data then: most Microsoft CVEs score 7.0 or higher, so "high"
     alone may keep most of the list, and "publicly disclosed" and
     "Exploitation More Likely" are worth adding to the default because
     they are Microsoft's own early-warning flags. Other vendors'
     cycles join as tagged rows where a keyless feed exists: Fortinet
     PSIRT RSS, Palo Alto's JSON API, Cisco, Red Hat, and SUSE CSAF,
     Chrome release notes, CISA's CSAF feeds.
  5. New and severe: published in the last 7 days with CVSS 9.0 or
     higher, or SSVC Automatable = yes with Technical Impact = total.
  6. Likely next: not in view 1 and EPSS at or above 0.10, or in the top
     5 percent, or risen by 0.10 in 7 days, or Microsoft "Exploitation
     More Likely". Absorbs today's Trending section.
  7. Exploited and unfixed: in view 1 and no vendor fix (vendor CSAF
     remediation of `none_available` or `no_fix_planned`, no OSV fixed
     version, or the affected release is end-of-life per the
     endoflife.date API, MIT).
  8. Edge and perimeter: vendor and product on a hand-kept list of
     firewalls, VPNs, gateways, file-transfer and remote-access products
     (no official public list exists), seeded from the Ransomware
     Vulnerability Matrix categories.
  9. Ransomware-linked: KEV ransomware flag, a ransomware.live group
     link, or a Ransomware Vulnerability Matrix row (CC BY 4.0).
  10. AI and ML stack: a CVE or advisory whose package is on an
      `ai_packages` list (PyPI, npm, crates), whose vendor and product is
      on an `ai_products` list, or whose CVE record carries CWE-1427
      (prompt injection; read from the CVE record, since NVD and GHSA
      searches by that CWE return nothing). Keyword matches ("prompt
      injection", "MCP server", "LLM") go to a "needs review" filter and
      are never auto-included. The reason a row matched is stored and
      shown. Lists are config files seeded from confirmed advisories
      (langflow, litellm, mlflow, flowise, mcp-remote, the MCP SDKs and
      Inspector, torch, langchain-core, Cursor, and so on) and the Valyu
      2026 AI-tooling dataset (CC BY 4.0) as a one-off seed.
  11. Probable zero-days: in view 1 and exploited at first publication
      (Microsoft Exploited:Yes at revision 1, KEV added within a day of
      publication, Chrome's "exists in the wild" wording, EUVD
      exploited-since on or before publication). Labelled "probable".
  12. Seen in honeypots: Vulnerability-Lookup sightings of type exploited
      from Shadowserver in the last 7 days (already ingested).
  13. OT, ICS, and medical: CVEs in CISA's CSAF OT feed (ICSA, ICSMA)
      and the Siemens and Schneider CSAF feeds.
  14. Trending attention: in Intruder's cvemon trending RSS or in the
      top sighting counts over 24 hours. Attention, not exploitation.
  Malicious packages stay a separate table on the Supply chain tab (no
  CVE). Shodan's CVEDB (keyless, non-commercial; KEV, EPSS, ransomware
  flag, CPEs in one call) is a cross-check source, fetched at runtime.
  None of the views needs a new key or dependency; CSAF, RSS, Atom, and
  CSV parse with the standard library. Known dead ends, checked
  2026-11-09: the SANS ISC Patch Tuesday API ("no longer supported"),
  patchtuesdaydashboard.com (gone), KEVIntel (now Previdian, paid API),
  huntr (no feed), Project Zero's in-the-wild sheet (freshness
  unconfirmed).
- Include (2026-11-06): CISA SSVC from Vulnrichment (CC0). The CVE records
  already fetched from Vulnerability-Lookup carry it in the CISA-ADP
  container, so no new source is needed. Store Exploitation (none / poc /
  active), Automatable (no / yes), and Technical Impact (partial / total)
  with their timestamp. Show them as their own labelled signal and as a named
  priority reason; do not blend them into a number. A stale "none" never
  lowers a priority set by other evidence. Use CISA's CVSS and CWE as a
  labelled fallback when the CNA and NVD give none. The full SSVC outcome
  (Track / Track* / Attend / Act) needs two organisation-specific inputs;
  derive mission prevalence from the technology watchlist and make the
  well-being impact a setting.
- The Supply chain tab (below).
- Scheduled feed refresh (waits for the Phase 5 scheduler).
- Include: an alert when new exploit code appears for a CVE matching the
  technology watchlist (P1 alert; needs the Phase 5 alert inbox). Exploit
  repositories stay links only and unverified; age and star count remain the
  first filter.
- Include: a social chatter collector for open Infosec Mastodon instances
  (such as infosec.exchange) and Bluesky, feeding the existing chatter table
  with rolling 48-hour CVE mention counts for the heat score.
  Vulnerability-Lookup sightings already cover Bluesky among other sources, so
  this adds direct polling and Mastodon. Phase 4 news mentions and Phase 5
  Telegram collection feed the same table.
- CSV / JSON / RSS exports (Phase 8), a per-vendor history and monthly chart
  (dashboards parking-lot item), and collapsible dashboard sections (needs a
  small script to remember state, with HTMX).
- Include (2026-11-06): verdict lines. Every CVE detail page gets a short
  "first steps" block of one to three sentences, each produced by a fixed
  rule from the record's own fields and naming the field that fired
  ("Treat as emergency remediation: on CISA KEV since 2026-10-13";
  "Exploit code exists in 15 public repositories; that is capability, not
  observed use"; "No fix reference in NVD yet: restrict exposure"). Rules
  live in one table and the "how the score works" page lists every rule in
  plain words. The same pattern applies to the Phase 1 enrichment verdict
  ("blocklisted by URLhaus; AbuseIPDB 98% from 40 reporters: block"), the
  Phase 3 alert ("new lookalike registered 2 days ago, MX set: watch for
  phishing"), and Phase 6 pivots ("single feature class, shared hosting:
  Weak, do not export"). No prose is generated; a line is a template with
  values filled in.
- Include (2026-11-06): a "signals disagree" strip on the detail page and
  as a dashboard filter: KEV, EPSS, CVSS, and SSVC side by side, with the
  score-disagreement rule (below) highlighted when they pull apart.

**Supply chain tab** (decided 2026-11-04, sixth tab of this module, to
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
  feed with a "supply chain" keyword category; specific sources to be
  named. Shown newest first with ecosystem and package name.
- Open Source Malware (opensourcemalware.com, OSM Security; checked
  2026-11-06): a database of malicious packages, container images, and
  repositories plus the domains, IPs, and wallets tied to them. No binary
  samples and no hash lookups. Free endpoints (`check-malicious`,
  `query-latest`) with a token from GitHub sign-in; terms allow
  non-commercial internal use and local storage but not redistribution, so
  it is a runtime lookup here, never vendored. The bulk feed and STIX
  export are paid.
Nothing here needs a key except the OSM token. Record also that GHSA/OSV add little as a CVE
feed for the other tabs: nearly every entry that matters there already
has a CVE in NVD.

Three cheap signals (agreed 2026-11-03):
- Patch available (built): the Fix column and the detail page show whether
  NVD tags a reference as "Patch" or "Vendor Advisory", so "exploited and
  unpatched" stands out.
- Score disagreement (not built): highlight a CVE whose EPSS is high while
  its CVSS is low (or the reverse). Those are the ones a CVSS-only triage
  misses.
- Deadlines (built on the detail page): CISA's KEV due date, a federal
  deadline that is a useful urgency proxy. It was dropped from the Dashboard
  on 2026-11-04.

### Phase 3: Digital risk protection

Organization-centric monitoring. Seeds are things the operator owns or is
authorised to monitor (organization domains, brand names, watched email
addresses, executives who have consented). Results arrive as scheduled alerts.
This phase consumes the Phase 5 collection layer and scheduler. On-demand
questions about arbitrary people or selectors belong to Phase 7 (OSINT). Both
phases read one shared local corpus and share the vendor clients below.

Built in two slices (see Build order). Slice A needs only the Phase 5
foundation slice and vendor APIs: ransomware and leak-site tracking, the
vendor breach sources, GitHub secret leaks, exposed cloud assets, and the
domain and subdomain monitoring. Slice B needs the Phase 5 collectors and the
Phase 7 username checker: hits from collected sources, page similarity, and
fake-profile monitoring.

**Ransomware and leak-site tracking**
- Sources: ransomware.live (free PRO tier; use its API, never site scraping),
  RansomLook (GPL-3.0, actively maintained; self-host it as a separate
  service and read its API to cover leak sites, markets, forums, and
  Telegram; never import its code), breach.house (paid API, account TBD).
- Watchlist of organizations, sectors, and countries with alerts on new
  victims.

**Breach and credential-leak monitoring** (for the watched domains and email
addresses)
- Vendor sources: Have I Been Pwned domain search, Hudson Rock free infostealer
  API, IntelligenceX free tier, LeakCheck. These clients are shared with the
  Phase 7 identity lookup.
- Collected sources (through Phase 5): paste sites, hacking forums, Telegram
  channels, and underground marketplaces. Marketplaces are covered through
  public-facing pages and aggregator data only: no purchases, no engagement, no
  posting. Paste and document-sharing sites (Pastebin, Scribd, and similar)
  are legitimate platforms under Principle 8: use their API or search-engine
  alerts for watched selectors, never a challenge bypass. Routes as checked
  on 2026-11-06:
  - Pastebin: no site search since 2020; the scraping API needs PRO and PRO
    is sold out; `/archive` (50 newest pastes) and `/u/<username>` (a user's
    public pastes) are plain HTML, allowed by robots.txt, and the ToS
    limits scraping to bona fide researchers and archivists. The operator
    is a security researcher (stated 2026-11-09), so a researcher-mode
    poller is in scope as a source-picker option: off until ticked, with
    the ToS clause shown; `/archive` every 30-60 minutes (one observation
    on 2026-11-09 showed entries one to nineteen days old, so faster
    polling gains nothing; re-check), then the paste page itself, whose
    HTML carries the full text, never `/raw/` (robots.txt disallows it);
    `/u/<username>` for watched handles; back off on any 403 or 429.
    psbdmp no longer resolves. GitHub public gists
    (`/gists/public?since=`) and GitLab public snippets
    (`/snippets/public?created_after=`) are the two paste feeds with a
    real listing API.
  - Scribd, SlideShare, Issuu: `/search` is disallowed by robots.txt and
    Scribd's ToS bans bots; there is no API. Scribd publishes document
    sitemaps, so search engines index uploads within about half an hour
    (Cyjax, 2025). What is indexable differs by site (HTML checked
    2026-11-09): a Scribd document page carries only the title, the
    uploader's description, and an "AI-enhanced" title and description
    written from the document's extracted text; the body loads separately.
    SlideShare pages carry the full slide transcript. Issuu pages carry
    only the uploader's description. Detection route: standing
    `"<selector>" site:scribd.com` queries through Google Alerts (free,
    RSS) and the Brave Search API, run daily, diffed against seen URLs.
    Uploader handles are indexed too, so the same route covers username
    search.
  - Honest limit, logo-only documents: a scanned document on Scribd has no
    text layer (two scanned uploads checked; Scribd does not appear to
    OCR), so its AI description never names the organisation, and no free
    search route finds a document by an image inside it (Bing's visual
    search API is retired, Google's is closing, Brave's image search takes
    text queries only). Commercial vendors that alert on a logo crawl the
    sites and run logo recognition on page images; that is out of reach
    here without crawling Scribd against its terms. What the toolkit does
    instead: (1) a wider selector set per organisation, because a document
    that shows a logo usually also carries letterhead text: legal entity
    names and former names, registration and tax numbers, street
    addresses and switchboard numbers, e-mail and intranet domains,
    footer strings ("Proprietary and Confidential - <Org>"),
    classification labels, document-control and form numbers, project and
    product codenames, slogans, executive names; (2) logo matching as a
    confirmation step on a candidate the search already returned or the
    analyst opened: compare the page-1 preview image, or images extracted
    from a supplied PDF with pypdf, against the operator's reference logos
    with a perceptual hash (ImageHash, BSD-2; needs Pillow, numpy, scipy:
    dependency to be proposed when built), labelled "logo match on page 1
    only"; (3) manual reverse image search links (Google Lens, Yandex,
    TinEye) on the review page.
  - Revisit (operator's question, 2026-11-10: "if the vendor crawls and
    runs logo recognition, why can't we?"). Nothing technical stops it.
    Scribd publishes its document sitemaps for crawlers, each document
    page exposes a page-1 preview image, and a perceptual hash or
    feature match against reference logos is ordinary code. What stops
    it today is policy and scale: Scribd's terms ban automated access
    with no research exception (unlike Pastebin's), Principle 8 treats
    it as a legitimate platform, vendors presumably hold a licence or
    accept that risk as a business, and scanning every new upload means
    fetching a very large number of pages and images. Options to weigh
    then: stay text-only; read the sitemaps only (the URL slug carries
    the title, which is still text); or an opt-in mode that fetches
    preview images only for new documents whose title or uploader passes
    a loose text pre-filter. Do now: the wider selector set and the
    confirmation-step matcher.
  - Intelligence X free key (50 selector searches a day, non-commercial)
    adds a "pastes" bucket that search engines never index.
- Paste-hosted C2 and dead-drop monitoring (added 2026-11-09; ATT&CK
  T1102.001). Malware families routinely keep the C2 address or the next
  stage on a text site: AsyncRAT and XWorm have a "Pastebin" field in
  their builder, DCRat, njRAT, PrivateLoader, SilentCryptoMiner and DPRK
  npm packages used Pastebin, TA558 and XWorm used paste.ee, Molerats
  used JustPaste.it, Vidar and Lumma use Steam and Telegram profiles,
  Gamaredon uses telegra.ph. Most of these pastes are unlisted, so an
  archive poller never sees them; the sandboxes and abuse.ch do, because
  they read the URL out of the sample's config. Design, feeds first:
  - A paste-host list held as data (pastebin.com, paste.ee, paste.tc,
    rentry.co, justpaste.it, telegra.ph, graph.org, teletype.in,
    steamcommunity.com, t.me, gist and raw GitHub hosts, JSON-storage
    sites), seeded from the cases above, lolc2, and the LOTS entries.
  - URLhaus recent dump filtered by host locally, and the URLhaus `host`
    query; ThreatFox `search_ioc` per host daily. Both use the abuse.ch
    key already on hand. The key sits in the URLhaus dump URL, so that URL
    is never logged.
  - On demand for a hash under investigation: VirusTotal `contacted_urls`
    and urlscan `page.domain:<host>`.
  - A dead-drop record links the paste URL, the family, the sample, the
    resolved C2 values with first and last seen, and the paste's status
    (live, removed), and feeds the Phase 6 grid as a sample-to-
    infrastructure pivot.
  - Content classifier for any paste text the toolkit holds (from a feed
    hit, the researcher-mode poller, or gists and snippets), written
    in-house: resolver shapes (a whole paste under about 200 bytes that is
    `host:port[:port]`, `HOST:<ip>`, a lone Base64 domain, or
    marker-delimited values), Base64 PE headers (`TVqQAAMAAAAEAAAA` and
    variants, and the same reversed), gzip `H4sI`, hex `4D5A9000`, decimal
    `77,90`, encoded PowerShell, credential-list shapes, private-key
    headers, API-key formats. dumpmon and Scavenger term lists (MIT) may
    be ported with attribution; PasteHunter (GPL-3.0) and pystemon
    (AGPL-3.0) are ideas only. Config parsers (rat_king_parser,
    CAPE-parsers, both MIT) are candidates for the isolated worker, never
    the web app.
  - The toolkit fetches paste text only; it never downloads a decoded
    payload.
  - Revisit when this is built (operator's note, 2026-11-10): several
    IPs and domains on VirusTotal carried community comments linking to
    Pastebin pages described as C2, so people are tracking these as they
    appear. Likely explanation: researchers and sandbox bots post what
    they pull from sample configs, and some run archive pollers. To
    check then: whether the VirusTotal free API returns comments for a
    file, IP, or domain (the `comments` relationship), and if so mine
    them for paste URLs on every indicator already being enriched, at no
    extra design cost; which accounts post such comments and whether
    they publish a feed; and how many live paste URLs URLhaus and
    ThreatFox actually hold. "Most are unlisted" above is an inference
    from the cases reviewed, not a measurement.
  Paste sites are a low-yield venue now; most leak distribution has moved
  to Telegram and forums.
- Repeat-leak detection for watched own-organisation selectors: store a keyed
  hash (HMAC with a local secret) of a leaked credential so a repeat of a known
  leak can be told from a new one. Never store the value, and never test a
  credential against a live service.
- GitHub secret and credential leaks for watched domains and organization
  names. CVE and exploit content on GitHub stays in Phase 2.
- Exposed public cloud assets tied to the organization, found through search
  indexes (Shodan, Censys, GrayhatWarfare-style indexes). No guessing of
  storage names.
- Selector watchlists using the six families from the plugin: brand, identity,
  email, domain, network, technical artefacts. Ported keyword_match.py logic.
  Sensitive entries (own org, program, or product names) live in the
  git-ignored config location.
- The corpus is local, git-ignored, and never made public. Every hit cites its
  source, and a new hit on a watched selector raises an alert.

**Brand monitoring**
- Lookalike domains (typosquatting, homoglyph/IDN, IAM and MFA vendor
  impersonation): the domain monitoring detail below.
- Subdomain monitoring: new subdomains under lookalike domains and under the
  organization's own domains (shadow and dangling hosts). The same enumerator
  is exposed as an on-demand search in Phase 7.
- Page similarity for candidate domains: compare a candidate's page (DOM
  structure hash, favicon hash, screenshot hash) with the organization's real
  login page to rank lookalikes. Tests use a clearly fictional fixture
  ("AnyCorp Login"). No page imitating a real organization is built.
- Fake social profiles and handle impersonation, staged: (1) existence checks
  for brand and executive names across platforms with the Phase 7 username
  checker; (2) search-engine dorks such as site:linkedin.com/in "<org>",
  delivered as alert feeds and as one-click manual-review links (the Google
  Custom Search JSON API closes on 2027-01-01, so it is not used); (3) every
  platform with a usable API (candidates: Bluesky, Mastodon, Reddit, GitHub,
  YouTube, Telegram public previews; confirm each when built); (4) logged-out
  public pages only where a platform's terms permit it. LinkedIn has no
  public search API, so it stays at stage 2 with manual review. No
  impersonation accounts. Executive monitoring requires the person's consent.
- Noise control for handle and profile hits: an exclusion list of known
  legitimate accounts, per-platform ignore rules, a minimum similarity score,
  and "reviewed, not a threat" suppression so a dismissed hit does not alert
  again. A hit is a lead for the analyst, not a verdict.

**Domain monitoring detail**
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
  - Subdomain monitoring: run the passive enumeration below on a schedule
    against flagged lookalike domains and the organization's own domains, and
    alert on new hostnames. The aggressive tools stay opt-in and manual.
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
- Own RSS/report aggregator instead of Feedly (dropped 2026-11-03). Build on open-source libraries (feedparser for RSS/Atom,
  trafilatura or readability for article text), or wrap an existing
  open-source reader. No paid service, no vendor lock-in, runs local.
- Sources: a curated list of vendor / research / CERT feeds. Use the site's
  RSS/Atom where it publishes one; fall back to an HTML scrape with a
  per-source extractor where it does not.
- Keyword and time-bounded topic monitoring beyond the fixed feed list, to
  catch reporting that is not in a subscribed feed: the GDELT DOC 2.0 API,
  Google News RSS search URLs (unofficial; test before relying on them), and
  standing alerts delivered as RSS (Google Alerts, Talkwalker Alerts), all
  ingested like any other feed. Alerts are created by hand. The Google Custom
  Search JSON API is not used (closed to new customers; ends 2027-01-01).
- Dork launcher: build the search URL for a saved dork (site:, quoted
  phrases, date range) and open it in the browser. Deterministic, free, and
  no terms exposure. The Brave Search API (decided 2026-11-06) automates the
  low-volume remainder: about 1,000 free queries a month, 50 a second, card
  on file; no scraped-Google resellers (Serper, SerpApi) and no scraping of
  Google ourselves. Brave's terms (§3(b)(i), 2026-09-01) forbid storing,
  caching, or building a database of results beyond "transient storage
  required for operation", so the toolkit shows result links for the
  session and drops them on the next refresh. A result the analyst saves
  keeps only the URL, the time, and the analyst's own note: never Brave's
  title, snippet, or ranking, and never a log of results on disk. A seen-URL
  diff for alerts stores URLs only.
- Keyword monitoring and highlighting (the one Feedly feature worth keeping):
  match a keyword list against every collected article and flag/boost the ones
  that hit, so relevant reporting surfaces instead of scrolling the whole feed.
  Deterministic matching; the keyword list is config-driven and can reuse the
  Phase 5 topical-category lists where it makes sense.
- Preselectable keyword chips at the top of the feed: a row of preset keyword
  filters so a reader jumps straight to the topic they care about, plus a
  free-text search box over already-collected articles (search the local
  store, no live fetch per query). This is the piece that makes the feed
  usable as a public read-only view if it is ever opened up (see the
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
    cheap to build.
  - Curated seed sources (frameworks/trackers, not blind scrape targets): MITRE
    ATLAS (adversarial threat landscape for AI systems — the ATT&CK analogue),
    OWASP Top 10 for LLM Applications, the AI Incident Database, and vendor
    threat reports on malicious AI use (OpenAI / Anthropic / Google /
    Microsoft). ATLAS + OWASP feed the "AI as target" angle; vendor reports
    feed "AI as weapon".
  - Note: this also tracks the attack surface of our own future "assist" phase
    — dogfooding awareness of a capability we will add.

### Phase 5: Collection infrastructure (collectors, scraping layer, scheduler, alerting)

Shared plumbing for the monitoring and investigation phases. Phase 3 consumes
the collectors and selector matching, Phase 2 consumes the topical categories
for zero-day and exploit chatter, Phase 7 consumes the on-demand search. The
scheduler and alert inbox are a foundation slice built before the Phase 3
scheduled alerts; Phases 1, 2, 3, and 6 all wait on it. Phase numbers stay as
they are.

**Foundation slice: scheduler and alerting**
- APScheduler in-process with the jobs table and generic job runner. Unblocks
  Phase 1 bulk paste (background job with ETA), Phase 2 scheduled feed
  refresh, Phase 3 scheduled alerts, and the Phase 6 changes feed.
- In-app alert inbox first; email or webhook later.
- Shared corpus (app/core): documents (reports, posts, pastes, leak entries)
  with their source and provenance, indicator sightings that link an
  indicator to the document it came from, and the selector matcher. Phases 2,
  3, 4, 5, and 7 write to it or read from it; no single phase owns its
  schema.
- Source registry: one entry per source with its class (Principle 8), access
  method, rate limits, terms-review status and date, and a default
  reliability rating (the Admiralty A to F scale, Phase 9). A source without
  a reviewed entry does not run. A document that arrives from a source not
  in the registry (a dork hit, a pasted URL) is stored under an automatic
  "F: unrated, review" entry; the analyst promotes it or leaves it.
- Later slice, alert-triggered playbooks: a high-priority event opens an HTMX
  remediation checklist and writes to an immutable local audit log.

**Scraping layer** (for sources without a usable API)
- Rule: Principles 7 and 8. A source runs only with a reviewed source-registry
  entry. No impersonation accounts, no posting, no purchases.
- Isolation: collectors run in a separate worker inside a container or VM,
  never in the web app process. The worker writes to an ingest path and the
  app reads from it. A browser that renders hostile pages sits at the
  container or VM rung of the isolation ladder (Phase 8).
- Access methods, added in this order and only when a named source needs the
  next one: plain HTTP (httpx), Tor SOCKS for onion services, Playwright for
  JavaScript-heavy pages, human-in-the-loop session capture, then a challenge
  solver.
- Egress: an onion service is reached inside the Tor network, so no exit node
  is involved and exit-node blocking does not apply. Prefer a source's onion
  address where it has one. Clearnet criminal sources go out through a VPS or
  a per-source proxy so the home IP never touches them. Proxy rotation is not
  built until volume requires it. Scrapoxy was dropped (2026-11-06:
  discontinued, proprietary licence).
- Challenge handling: a local fork of FlareSolverr (MIT) as a sidecar
  container, for Cloudflare and DDoS-Guard browser challenges on
  criminal-operated sources only. Its CAPTCHA solvers do not work, so a
  CAPTCHA goes to the human-in-the-loop slice. Test per source. Upstream
  state on 2026-11-06: one active maintainer, 49 open PRs, and an unanswered
  hardening batch, so the fork carries about 150-200 lines that are already
  written in open PRs: bind to 127.0.0.1 and require a bearer token (PR
  1792), redact cookies and proxy credentials from logs (PR 1783, issue
  1753), publish the compose port on 127.0.0.1 (issue 1754), dismiss page
  alerts (PR 1807, the v3.5.2 regression), and `apt-get upgrade` in the
  Dockerfile so the unpinned Chromium picks up fixes (issue 1813). Fork from
  master, not the v3.5.2 tag, because the proxy-extension injection fix
  (GHSA-c52x-qhrp-8qqp) is only on master. Byparr (GPL-3.0, so a separate
  service only) is the fallback behind the same /v1 call. Checked and not
  usable: simple-cloudflare-solver (no licence, so no code may be copied)
  and scrappey_proxy (dormant, needs a paid third-party API). Writing our
  own solver is not planned: the hard part is the weekly Cloudflare
  cat-and-mouse, not the code, and the fork is where upstream's fixes land.
- Excluded: commercial scraping APIs and proxy aggregators (ScrapeOps,
  Scrappey), because they see target URLs, page content, and session cookies.
  Free public proxy lists are excluded on measured risk (NDSS 2018: 38% of
  65,000 open proxies modified content; MADWeb 2024: 640,000 listed
  proxies, a third ever alive, 42,000 on MikroTik routers, 17,000
  manipulating content): a collector cannot trust what came back, and the
  listed hosts are largely other people's compromised routers.
- Egress ladder for clearnet criminal sources (decided 2026-11-09,
  replacing "never residential"). Move down a rung only when the rung
  above has failed for a named source with a correct client (real
  browser, human pacing, cookies), and write the reason in the source
  registry:
  1. A published feed that already covers the need (ransomware.live,
     RansomLook).
  2. Tor to the source's onion address.
  3. The operator's own VPS over WireGuard or `ssh -D`, with the
     destination allow-list and request log enforced in the collector
     itself. No proxy daemon is needed for one analyst; Squid (GPL,
     actively maintained, a long advisory record) only if a separate
     enforcement point is wanted later, bound to the tunnel interface.
     CCProxy (Windows, proprietary, old overflow CVEs) is not used.
  4. A second VPS on a different provider or country.
  5. A commercial VPN exit with audited no-logs claims (Mullvad, Proton).
  6. A dedicated ISP ("static residential") address from a named vendor
     that verifies its customers: an address announced by a consumer ISP
     but hosted on a server, so no end user's device is involved. About
     $2-5 per address per month.
  7. A connection in the operator's own name (a second line or a SIM
     modem), kept apart from the home network. Never someone else's home.
  8. A peer-to-peer residential pool: last resort, per source, recorded.
     Public pages only, no logins, HTTPS only, minimal volume, standard
     proxy mode (never an "unblocker" or scraping-API product, which
     terminates TLS at the vendor). Why it is last and not a routine
     fallback: "user consent" is the vendor's assertion and cannot be
     checked, because pools overlap through resale (Google, 2026; half of
     tested pools share upstream sources, Proxyway 2026); the vendor logs
     every destination domain and may report at its discretion; a
     stranger's home address ends up in a criminal site's logs; and a
     third to a half of these exits are flagged as proxies anyway.
     Vendors reviewed 2026-11-09: Decodo (ex-Smartproxy; Lithuanian
     entity, ISO 27001, customer verification, names no source apps, its
     terms bar collecting data behind a login) is the most defensible;
     DataImpulse second (sources through the TraffMonetizer app, which
     has been found installed on compromised servers); NodeMaven last
     (white-labelled pool, no sourcing disclosure, no known customer
     verification).
  This is the operator's purchase and account, never the toolkit's.
- Revisit when Phase 5 collectors are built (operator's questions of
  2026-11-10 with first-pass answers; nothing here is decided):
  - Hard requirement from the operator: nothing in the egress path may
    degrade the integrity of collected data or of an investigation.
    First-pass rule: content integrity holds when the collector speaks
    HTTPS end to end through the proxy (a CONNECT tunnel; the proxy and
    the exit device see the hostname, not the content) with certificate
    checking on, or reaches an onion address over Tor. It does not hold
    for a plain-HTTP source through any third-party hop, nor for an
    "unblocker" product that terminates TLS. So every stored document
    records its egress route and whether the fetch was end-to-end
    encrypted, and a plain-HTTP source is flagged "content unverified".
  - "How can a residential address be flagged as a proxy?" Detection
    firms classify by behaviour, not by who owns the address: they buy
    access to the pools and record the exit addresses, fingerprint the
    proxy software and SDKs, and look for mismatches (many users and
    countries behind one home address, a server-style network stack
    arriving from a consumer line). "Residential" describes the owner;
    "proxy" describes the use. Both can be true.
  - "Is an ISP address a VPS with a residential IP?" Close: it is a proxy
    endpoint in a data centre whose address block belongs to a consumer
    ISP. You get a fixed address, not a machine to log in to. IP
    databases label some of them as hosting, so test before relying on
    one.
  - Vendors named by the operator: Decodo, DataImpulse, NodeMaven (see
    the ladder above); IPRoyal (pool sourced from vetted partners, not
    its own app; customers verified; and it blocks "crime and stolen-data
    sites", "dark-web gateways", and "malware downloads" by default,
    with access on a reviewed request, so a collector's targets are
    blocked until the operator explains the use: a point in its favour
    for ethics and a hurdle for this use).
  - Squid: proxy server software for the operator's own VPS, not a
    source of addresses (see rung 3).
  - Octo Browser and Dolphin Anty: anti-detect browsers sold for
    multi-accounting (ad accounts, bonus hunting, ticketing). They spoof
    device fingerprints and keep many browser profiles, usually synced
    to the vendor's cloud. First-pass view: not needed and a poor fit.
    The collector uses one consistent browser profile per research
    persona inside its own container (Playwright with a persistent
    profile), which is what a real returning visitor looks like;
    randomised fingerprints help people running hundreds of accounts,
    not one read-only reader. Closed-source browsers that hold a
    persona's session cookies on a vendor's servers are a risk to the
    integrity requirement above.
  - Octoparse (and Kraven Security's guide to it): a commercial no-code
    scraper with a desktop app and cloud runs. The guide builds an IOC
    extractor from regular expressions over a report page, which the
    Phase 2 extractor already does locally. Idea worth keeping: a small
    per-source extraction recipe (start URL, the block to read, clean-up
    steps) held as data so a new source needs no code. Not for criminal
    sources: cloud runs would send the targets to a third party.
- If rotation is ever needed: gost (MIT) or mubeng (Apache-2.0) in front of
  paid proxies. Tor gives a fresh circuit per connection for onion sources,
  so they need no rotator.
- Human-in-the-loop session capture: the analyst completes login
  and any CAPTCHA once in a local web VNC viewport; Playwright stores the
  session cookies and background workers reuse the session until it expires.
  Session files are credentials: git-ignored, optionally encrypted.
- Optional Tor SOCKS mode for onion sources and leak-site mirrors.
- Docker is introduced here for the sidecars; full Compose packaging stays in
  Phase 8.
- Research-persona logins are created by hand, are read-only, and are stored
  like session files. A forum that demands payment, posting, or vouching for
  access is out of scope.
- Automated CAPTCHA solver APIs (CapSolver, NopeCHA): parking lot.

**Collectors**
- Telegram: Telethon read-only monitor, channel catalog seeded from the plugin's 30+ channel list, snowball discovery queue (new links found in collected messages, joined manually per OPSEC), local full-text search over everything collected.
- Telegram without an account: public channels expose a web preview at
  t.me/s/<channel> that can be read with plain HTTP. Use it to preview a
  channel before joining and as a low-cost poller for channels not yet joined.
- Telegram discovery: Lyzem, TgDB (telegramdb.org, now tgdb.org), TGStat,
  Telemetr, and a Google Custom Search Engine over t.me used in the browser
  (Telegago). SocialLinks' similar-channels tool for snowballing. (Source:
  The-Osint-Toolbox/Telegram-OSINT list.)
- Onion search engines (Torch, Ahmia, and the 16-engine list in robin):
  queried over Tor from the collector worker; results are leads into the
  forum and leak-site catalogs, never auto-collected.
- Excluded: Telegram "lookup bots" (Telelog, Sherlock-style phone lookups,
  leak bots). Unknown operators, breach-derived personal data, and every
  query leaks your selectors to a third party.
- Onion indexer search: Ahmia, dark.fail, IntelligenceX, ported from the plugin's onion_search.py.
- Forum catalog seeded from the plugin's 35+ forum list (status, mirror, access tier).
- Directory seeding: read fastfire/deepdarkCTI (a curated directory of deep
  and dark web CTI sources) to seed the forum, leak-site, and Telegram
  catalogs. Treat every listed URL as hostile input. Its license is GPL-3.0, so
  read the list at runtime and do not copy its data into the repository.
- Topical keyword categories (separate from the Phase 3 selector watchlists):
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
  Routing: the Vulnerability category feeds the Phase 2 chatter table; Fraud
  and Industry targeting feed the Phase 4 keyword mechanism and Phase 3 alerts.
- Selector watchlists live in Phase 3; on-demand search across collected
  sources lives in Phase 7.
- OPSEC primer shipped as in-app documentation. No automated channel joining.
  No active engagement. No purchases.

**Candidate sources and reference projects** (licence and last push checked
on GitHub 2026-11-06; no tool was run. "No licence" means ideas only, no
code may be copied.)
- fastfire/deepdarkCTI: GPL-3.0, active (see directory seeding above).
- apurvsinghgautam/robin: MIT, active; LLM-driven dark web OSINT tool. Its
  search layer imports nothing LLM-related and queries 16 onion search
  engines over Tor (requests and BeautifulSoup). Port the engine list and
  the technique onto httpx. Its LLM workflow is a Phase 11 candidate, with a
  local model only.
- brunosergi/darkweb-forums-tracker: no licence, last push 2025-07; built on
  n8n, Playwright, and LLM agents. Ideas only (session handling,
  deduplication).
- shadsidd/DarkWeb-Monitoring: no licence, last push 2025-04; small Python
  org-mention monitor. Read 2026-11-06: it never sends the query and its
  match cannot succeed. One idea kept: a per-source reachability panel.
- osintph/darkweb-observatory: no licence (ideas only; no code copied),
  3 commits (2026-03); onion uptime monitor with indicator extraction.
  Adopted for the source monitor (decided 2026-11-06):
  - Target record: name, URL, category (forum, leak site, marketplace,
    search, index), risk, deep-scan flag, source of the entry, and the
    upstream list's claimed status next to our observed status.
  - Status vocabulary per check: UP, UP (blocked), UP (rate-limited),
    HTTP <code>, DOWN, with latency; a rolling window of checks gives
    uptime and a sparkline.
  - Change detection: a content baseline per target, hashed after stripping
    timestamps and tokens (the original hashes raw HTML and so fires on every
    poll), with a change-event list per target and a stored previous copy so
    a change can be diffed. SHA-256, not MD5.
  - Alert taxonomy: down, recovery, change, new indicator, uptime below
    threshold; per-(type, target) cooldown; new-indicator alerts only on
    first sighting.
  - Seed-list ingestion from community lists (alecmuffett/real-world-onion-
    sites, fastfire/deepdarkCTI) with caching, dedupe, and provenance; mirror
    sets are modelled as one target with several addresses, not deduped
    away.
  - On-demand single-URL scan from the UI, and an ops rule: all outbound
    through Tor, dashboard never served from the collector host.
  - Not taken: page titles and server headers rendered unescaped (stored
    XSS into the analyst's dashboard); JSON state files rewritten from
    worker threads; deep-scan harvesting of e-mail addresses from markets.
  Wallet, onion-string, and hash extraction is written in-house on
  app/core/indicators.py.
- The-Osint-Toolbox/Telegram-OSINT (maintained, last push 2026-05) and
  0xSojalSec/Telegram-OSINT (a copy of ItIsMeCall911/Awesome-Telegram-OSINT):
  link lists used as discovery aids. Reviewed link by link on 2026-11-06
  (107 links: 50 live, 19 dead, 38 unverifiable by fetch, mostly VK threads,
  bots, and sites behind bot checks). The two lists share about 19 links.
  Of the 71 directory entries, all but TGStat, Telemetr, and TgDB are
  consumer channel catalogues, ad marketplaces, or adult "leak" catalogues
  with no threat-channel value.
- Taken from that review:
  - Forward and mention graph: pull the source channel out of forwarded
    messages and @mentions already collected and feed it to the discovery
    queue. Public channels expose both in the t.me/s preview, so the crawl
    needs no account and is not bound by the membership cap. Renders as a
    channel network (the 2021 "Tracing forwards and mentions" method).
  - Channel state in the catalog: live, renamed, banned, or dead, and whether
    the channel needs membership or can use the t.me/s poller. A Telegram
    account can be a member of about 500 channels and groups, so the
    research account's memberships are a budget spent on channels with no
    public preview.
  - Bot-token pivot: a Telegram bot token or chat ID found in malware or a
    phishing kit is extracted and stored as an indicator, and matched
    across samples, kits, and scanned pages (the same token on two kits
    links them). The toolkit does not call the Bot API with a found token:
    using someone else's credential is a legal grey area even for
    read-only calls (revised 2026-11-09).
  - Third-party post search (TGStat, Telemetr, TgDB): off by default,
    because keywords go to the operator and the useful tiers are paid.
  - Persona pivots by hand: creationdatebot (account age) and SangMata
    (username history) are bots run by unknown operators; use them from a
    research account only, never with own-organisation selectors.
  - Telethon: the GitHub repository was archived on 2026-02-21; upstream is
    https://codeberg.org/Lonami/Telethon (confirmed 2026-11-06). Pin from
    PyPI with hashes as usual and watch the Codeberg home for releases.

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
- Sources reviewed 2026-11-06 (free tiers as published that day):
  - mnemonic passive DNS: keyless, 10 a minute, 1,000 a day. First pDNS
    source to wire.
  - Validin community: 10 queries a day, 50 a month, with hash pivots (JARM,
    favicon, certificate, body). Manual, cached pivot; never spent by a
    background job.
  - Censys Platform: 100 credits a month, lookups only (search is paid).
    Host and certificate lookup by value.
  - Silent Push community: 100-250 requests a month, evaluation terms. Used
    by hand through a query-template link, not integrated.
  - Whoxy: no free tier; reverse WHOIS at about $10 per 1,000 queries. The
    one purchase worth considering: registrant and e-mail pivots across all
    domains, and WHOIS history, which RDAP (current record only, mostly
    redacted) cannot give. Optional vendor module.
  - Spur: no free API. Not integrated; ipapi.is (1,000 a day) gives
    VPN/proxy/datacenter/Tor flags, and AbuseIPDB already returns `isTor`
    and a usage type (data centre, ISP, and so on) for every IP.
  - Local gates, no key: the Tor exit list (check.torproject.org), Spamhaus
    DROP, and the OFAC sanctioned digital-currency addresses (SDN XML; the
    0xB10C parser is MIT and rebuilt nightly).
  - Query-template links for tools we cannot call: for each indicator type,
    a table of pre-filled deep links into Validin, Censys, Silent Push,
    Shodan, urlscan, and the chain explorers ("pivot by certificate",
    "hosts with this JARM", "reverse WHOIS on this e-mail"). Deterministic
    and free; the Phase 11 assistant may later rank them from the tool docs.
- Interface decision (2026-11-09): table first, graph second. The primary
  view of any indicator is a pivot grid: one row per attribute of the seed
  (certificate fingerprint, serial, subject, JARM, favicon hash, body hash,
  header hash, title, SSH key, nameserver set, registrar, creation time,
  MX, TXT, tracker IDs, URL paths, ASN), each with how many other entities
  share that value, first and last seen, the feature class, and a
  suppression badge. Rows inside a rarity band are highlighted and the rest
  are greyed. Published bands used as defaults: 2-119 hosts for host
  attributes (Censys CensEye), up to 500 domains for registration
  attributes (DomainTools guided pivots), under 5,000 domains for a
  nameserver provider (Silent Push). Reasoning: every commercial pivoting
  tool that publishes its design leads with counts per attribute, and the
  graph-first tools all ship features to fight the "hairball"; no
  published user study compares the two. The graph is kept for what it is
  good at: the investigation trail (where the case started and how each
  member was admitted) and the cluster picture for a report.
  - Tick-to-combine: tick any rows to build a conjunction ("same registrar
    AND same NS set AND created within 5 minutes") and see the count for
    the combination, with NOT for exclusions. Single attributes are weak;
    the conjunction is the pivot (urlscan Pro's pivot panel, Pivot Atlas
    "combine multiple pivots").
  - Timeline strip under the grid: first-seen to last-seen bars per
    candidate, because overlap in time is what a table hides.
  - Saved pivots carry a first-used date, a last-yield date, and a
    time-to-live, since content pivots (favicon, title, CSS hash) decay in
    weeks while certificate, DNS, and registration pivots last (Validin's
    re-tests of its own published pivots).
- Pivot catalogue (2026-11-09), modelled on Pivot Atlas (gopivot.ing,
  Amitai Cohen; no licence, so structure and ideas only): a typed map of
  artifact -> pivot -> artifact, held as data, that drives the grid and
  the query-template links. Artifact types: domain, IP address (client or
  server role, static or dynamic), TLS certificate, sample, URL, user
  agent, e-mail address, GitHub user, wallet, Telegram token or handle,
  onion address. Each pivot entry names its source and target type, its
  feature class, the fingerprint kind (lossless such as a SHA-256, lossy
  such as JARM or a header hash, fuzzy such as ssdeep or TLSH), the free
  route if one exists, the paid route as a deep link, the known
  false-pivot traps, and an example. Seeded from Pivot Atlas, the
  practitioner write-ups reviewed on 2026-11-09 (Embee Research, Validin,
  Silent Push playbook, Censys, Hunt.io, Netlas, urlscan, Kraven,
  BushidoToken), and the cti-skills pivot table.
  - Free-route pivots to build first, in order of signal per quota: match
    against a local default-signature library (zero quota); certificate
    fingerprint, serial, and subject or issuer quirks from one host
    lookup, pivoted only when self-signed or unusual; time-windowed passive
    DNS co-hosting with a count guard (mnemonic); urlscan resource `hash:`
    and `filename:`; Shodan property hashes (`http.html_hash`,
    `http.headers_hash`, `http.favicon.hash`, `http.robots_hash`); SSH host
    key; the registration tuple (registrar, NS set, creation time within
    five minutes) as a scoring check on candidates; hard-coded SAN names
    with issuer and validity window; nameserver pair for small providers;
    tracker IDs; URL path regex and redirect target; sample to
    infrastructure through abuse.ch before VirusTotal; JARM and JA3S only
    as one term of a conjunction.
  - Default-signature library (local data): known framework defaults such
    as the Cobalt Strike certificate serial 146473198, certificate subjects
    like "AsyncRAT Server", published JARM, JA4X, favicon, body, and header
    hashes per C2 framework and phishing kit. Sources: thehappydinoa/
    awesome-censys-queries (CC0), the query dictionary in the archived
    montysecurity/C2-Tracker (no licence: facts re-keyed, not copied), the
    nuclei C2 templates, SSLBL, C2IntelFeeds (CC BY-NC-SA: fetched at
    runtime, not shipped), and phish-report/IOK kit rules (ODbL). A match
    says "this is tool X with default settings", which identifies the tool
    and not the operator, and the grid says so.
  - Suppression and rejection lists (local data), checked before any pivot
    is offered: MISP warninglists (CC0: sinkholes, parking domains and
    parking nameservers, dynamic DNS, Cloudflare, AWS, GCP, Azure, Fastly,
    Akamai, URL shorteners, disposable e-mail, VPN, Tor exits), the cloud
    providers' own range feeds, the Public Suffix List private section and
    a dynamic-DNS list so a pivot stays on the actor's subdomain and never
    on a shared apex, Spamhaus DROP and ASN-DROP, and a local denylist of
    empty and stock-page hashes. Each trap has a deterministic test: CDN or
    reverse-proxy IP (range lists: reverse-IP pivots disabled, content
    pivots kept); shared hosting (distinct-domain count over the window);
    parking and sinkholes (lists); default content hashes (denylist plus
    count); generic certificates (pivot on a fingerprint only if
    self-signed or the SAN count is small, and check the certificate names
    the host); TLS-stack collisions (no single-attribute JARM pivot);
    recycled IPs (require overlapping intervals, flag a Server-header or
    certificate change between observations); registrar-default
    nameservers and privacy services (count threshold demotes to
    corroboration); shared libraries and brand favicons (suppress resource
    hashes also seen on Tranco-top sites).
  - "Prior art" step: before any pivot, the seed is searched in the local
    corpus, the actor profiles, and the default-signature library, and the
    grid opens with what is already known.
  - Outcome ladder on every case (Pivot Atlas "impact"): monitor (saved
    pivots re-run on a schedule and alert on new members), detect (export
    to the Phase 8 templates), hunt (low-confidence members go to a hunt
    list, never a blocklist), block (time-limited for IPs), share (STIX or
    MISP export with the limitations block). Attribution is a separate,
    optional step handled by the Phase 9 evidence gate.
  - Naming (open, 2026-11-10): the phase stays "Infrastructure pivoting"
    in this document. Proposed name in the app: "Infrastructure Hunting",
    with sub-tabs Pivot (the grid for one indicator), Hunts (saved pivots
    that re-run on a schedule), Cases, and Signatures (the default-
    signature library). "Pivot" names one step; "hunting" names the job.
    The operator decides.
  - From Kraven Security's "C2 Hunting 101" (reviewed 2026-11-10):
    - Header template builder: take a host's response headers, blank the
      volatile values (Date, Content-Length, ETag, cookies), and offer
      "widen" and "narrow" steps (drop a version number so `PHP/8.1.17`
      becomes `PHP/`; add an exclusion with NOT; add the JARM as a second
      term) with the result count after each step.
    - Hunt quality score: for a saved hunt, the share of returned hosts
      that are already known bad in the corpus, ThreatFox, or VirusTotal.
      A hunt that returns 40 hosts of which 30 are known C2 is a good
      net; one that returns 4,000 with 3 known is noise. Shown beside
      every saved hunt and tracked over time.
    - Seed suitability check before any host pivot: static rather than
      dynamic address, few domains resolving to it, recent resolutions.
    - Saved hunts run daily where the source allows it (Shodan search by
      API needs the paid membership already on hand) and alert on hosts
      not seen before.
    - Markers for an absent pivot: an HTML hash of 0 means the host
      served no HTML.
  - Recorded but not built: netflow and traffic pivots (no free source),
    active probing of hosts (out of scope for a passive tool), and calling
    a found Telegram bot token against the Bot API (extract and correlate
    only; replaces the "candidate" wording in Phase 5).
- Workflow and page design, taken from the 1200km field manual's bounded
  cluster method (2026-11-06; the manual names no tools, its structure is
  what we use):
  - Seed record: indicator, source, source type, confidence in the source,
    first and last seen in the source, note.
  - Time window on the case: start, end, rationale, and a maximum age for
    pivots; every edge carries first seen and last seen, and a pivot outside
    the window is rejected by default.
  - Pivot results table: one row per candidate entity with a column per
    feature class (passive DNS, certificate, WHOIS, ASN, URL path, favicon,
    malware config) showing whether that class corroborates it, a link
    strength 0-100, and in or out of the cluster. Strength is computed from
    relevance to the seed, recency, uniqueness (a shared CDN IP or a
    100-domain certificate is weak), observed co-occurrence, and data
    quality; a single feature class never exceeds Weak, and Moderate or
    Strong needs two independent classes overlapping in time.
  - Rejected neighbours stay on the page with their reason (outside window,
    shared hosting, different certificate, CDN pattern, no corroboration),
    drawn as dashed edges in the graph; a pivot log records accepted,
    rejected, and pending with reason, time, and expiry.
  - Fan-out guard: an IP shared by hundreds of domains or an ASN is never
    auto-expanded; the analyst opens it on purpose.
  - Cluster summary block: entities in cluster, total considered, time
    window, primary infrastructure, cluster confidence with rationale, and a
    "next collection to improve confidence" list.
  - Limitations block on every case, written by the analyst, with
    "proves / does not prove / would strengthen" prompts.
  - Export gating: only entities at Moderate or above reach a hunt package
    (domains, IPs and ASNs, certificates and hashes, URL paths, keywords,
    limitations); weak pivots never reach a blocklist export.
- Cases (decided 2026-11-06; the name replaces "investigations"): a case has
  an objective, a time window, stop rules, members (indicators, documents,
  actors), the pivot log, notes, and a status. Built in this phase with the
  graph. An indicator in an open case is pinned: it never decays and never
  retires.
- Indicator retention (decided 2026-11-06): nothing is deleted. Every
  indicator keeps its sightings, composite attributes (registrar,
  certificate, JARM, ASN, nameservers) and history forever, because the
  composite parts outlive the IP. A relevance score decays with time since
  the last sighting, with a half-life per type (IPs fast, domains slower,
  hashes and certificates never), and a new sighting resets it. Below a
  threshold an indicator is excluded from alerts and blocklist exports and
  shown as "dormant", but it still matches in search and still enriches.

### Phase 7: OSINT

On-demand investigation of any seed (username, email, domain, organization,
handle): "what is linked to this?" Phase 3 watches seeds continuously; this
phase answers questions now. Both read the same local corpus.

Build order: identity lookup is the first slice of this phase. The username
checker built for it also serves Phase 3 brand-handle checks.

- Identity lookup (username or email as the seed), added 2026-10-27. Free building blocks:
  - Username enumeration across sites: WhatsMyName data file (open source
    JSON used by whatsmyname.app), Maigret (3000+ sites, pulls profile
    details and avatars), Sherlock as a cross-check.
  - Email to services: holehe (which sites have an account for this email,
    without alerting the owner).
  - Breach association: HIBP (email in, breach names out), LeakCheck public
    API (username or email in, breach sources and field types out, no
    values), Hudson Rock free API (search by username, email, domain),
    IntelligenceX free tier (document previews; psbdmp is dead as of
    2026-11-06, its "pastes" bucket replaces it).
  - Email discovery from public artefacts: GitHub commit emails via the
    .patch trick, Gravatar profile JSON, PGP keyserver search, Keybase,
    historical WHOIS, GHunt-style Google account checks. Hunter.io (decided
    2026-11-06; free plan, 50 credits a month, API included, domain search
    capped at 10 results) for the operator's own domains: which addresses
    and address pattern are public. Apollo.io is not used: its terms limit
    use to sales and recruiting and free search returns no addresses.
  - Persona vetting (added 2026-11-06; for impersonation and DPRK IT-worker
    style profiles): a checklist page that joins what the toolkit can
    check deterministically (handle age and reuse across sites, e-mail and
    PGP reuse, GitHub account age and commit history, breach footprint,
    avatar hash reuse) with manual-review links (reverse image search,
    profile pages opened by hand). Output is a vetting record with the
    evidence, not a verdict.
  - Result view: services found, avatars, breach sources, candidate emails
    with the evidence for each, and a confidence note.
  - Free tier limit: free APIs return which breach and which field types, not
    the plaintext email-to-username pair. A paid vendor key (DeHashed,
    Intelligence X) drops into the adapter slot to fill that gap.
  - Shared with Phase 3: breach association uses the same vendor clients and
    local corpus as Phase 3 credential monitoring. Phase 3 asks "any new hits
    for the selectors I watch?" on a schedule; this phase asks "what is linked
    to this seed?" on demand.
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
    value). For watched own-organisation selectors only, a keyed hash
    supports the Phase 3 repeat-leak detection.
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
- One search box with input-type detection (domain, IP, email, username, organization) showing which tools will run as checkboxes.
- Source picker (agreed in principle 2026-11-09, details when built): every
  search and every scheduled watch shows its sources as a checklist the
  operator can untick, grouped by kind (keyless, keyed with remaining
  quota shown, third-party that sees the query, opt-in researcher-mode
  sources). The choice is remembered per search type. Nothing that sends a
  selector to a third party runs unless its box is ticked.
- Result tabs by category: infrastructure and DNS, people and identity, breaches, code leaks.
- Wrapped tools: theHarvester, dnstwist, crt.sh, holehe, Maigret, GitHub code search, Shodan org dorks. GitHub username and code search live here; CVE and exploit content on GitHub stays in Phase 2, and secret leaks for watched selectors stay in Phase 3. All three share one GitHub client.
- SpiderFoot as the optional deep scan (runs as a server, triggered by API).
- Subdomain enumeration as an ad hoc search: the same enumerator as the Phase 3 subdomain monitoring (Subfinder passive by default; Amass and BBOT opt-in).
- Deterministic identity correlation: username reuse, email and PGP key reuse, crypto wallet reuse, avatar image hashes. No stylometry, no AI.
- Fuzzy handle correlation: soft-match fluid threat actor handles (for example IntelBroker versus intel_broker_) across ingested forum posts using edit-distance scoring. SQLite has no built-in Levenshtein function, so use a vetted library (rapidfuzz is the candidate) under the dependency policy.
- On-demand search/scrape, not just the static corpus (planned):
  type a term (domain, email, CVE, handle) and scrape the configured
  Telegram/onion sources live for it, returning fresh hits. Built for
  authenticated/self use. A PUBLIC version is a liability trap: returning
  darkweb/breach hits for an arbitrary third party's email or domain discloses
  personal data about someone who did not consent — the same reason the
  Telegram "lookup bots" are excluded above and the data policy keeps the
  corpus local. If a public self-check is ever wanted, gate it behind proof of
  ownership (verify the domain/email belongs to the requester, HIBP-style),
  never an open arbitrary-term lookup. Pinned for the public-deployment brainstorm.
- Threat actor profiles moved to Phase 9 as their own module (2026-11-06). The fuzzy handle correlation above feeds a profile's known handles.
- Username-search integration approach (decided 2026-11-03, applies to the
  Maigret / WhatsMyName references in this phase). The value of these
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
  - Reduce blocks by behaving like a polite client first: cap concurrency per
    host and add small delays (bursting is the main block-trigger, and it is a
    knob we control); send an honest, normal User-Agent rather than a scraper
    default; honor each site's own signals (back off on HTTP 429 per
    Retry-After, prefer a site's real existence-check endpoint over scraping its
    HTML); cache and dedup (already done); and prune sites that block every
    time — a curated ~200-site list that works beats 3,000 where half
    challenge you.
  - When a site challenges a lookup, mark it blocked/unknown, log it, and
    surface it in the results so the operator sees what was skipped. These are
    legitimate platforms, so Principle 8 rules out a challenge bypass.


### Phase 8: Exports, detection templating, packaging
- Exports: STIX 2.1, CSV, TXT, PDF.
- Detection templates from IOC sets: YARA, Sigma, SQL, KQL. SPL skipped.
- Living-off-the-land datasets as local enrichment and profile context
  (decided 2026-11-06; lolol.farm lists 37 projects, licences checked):
  - Wire first: LOLRMM (Apache-2.0; `rmm_domains.csv`, certificates JSON,
    pushed daily) as a domain and certificate gate for RMM abuse; LOLDrivers
    (Apache-2.0; `drivers.json` with hashes and signer data) in the hash
    lookup; lolcerts (Apache-2.0, stale since 2024; leaked and malicious
    code-signing certificates) against MalwareBazaar's `code_sign` data;
    LOT Tunnels (GPL-3.0; `domains.csv` of tunnelling services); LOLBAS
    (GPL-3.0; `lolbas.json` with ATT&CK IDs) for technique context.
  - Fetch at runtime into the git-ignored data directory and cite the
    source; GPL-3.0 datasets (LOLBAS, GTFOBins, HijackLibs, LOOBins, LOFL,
    LOLESXi, LOT Tunnels, lolbins-cti-driven) are never vendored. The
    unlicensed ones (LOLC2, LOLAD, LOLAPI, Living Off The Hardware) are
    runtime-only too. LOTS, FileSec, and MalAPI have no repository or
    export (HTML only; not integrated). RogueApps has been withdrawn.
  - Dashboard detections and profiles also draw on Sigma (DRL 1.1, actor
    tags), Atomic Red Team, MITRE CAR, and Splunk security_content's
    actor-named analytic stories (Apache-2.0).
- Dockerfile and Docker Compose (app, collector worker, Tor, SpiderFoot, and the Phase 5 challenge-solver sidecar).
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

### Phase 9: Threat actor profiles, ATT&CK, and rigor
- Threat actor profiles (their own module, decided 2026-11-06): one page per
  actor or group that reconciles vendor aliases and joins what the toolkit
  already knows about it.
  - Seed slice (see Build order), structured sources only: MITRE ATT&CK
    groups, software, and techniques from a local dataset; an alias table
    that records the source of every alias claim; the ransomware group
    list; and the Phase 2 group-to-CVE links.
  - Later slices attach Phase 3 victims, Phase 4 reporting, Phase 5 chatter
    and handles, and public detection rules, as each corpus comes to exist.
  - Sources (checked 2026-11-06):
    - Backbone: MISP galaxy `threat-actor.json` (CC0 or BSD-2, 1,118
      entries, updated weekly or faster; last change 2026-11-02 added three
      2026 actors). Each entry has `synonyms`, `refs`, country, and
      `related` links to the ATT&CK intrusion set and to the Microsoft
      cluster. Its `name-attribution` field records which vendor uses which
      name (`"Octo Tempest:<Microsoft uuid>"`, resolved through
      `producer.json`): the only permissively licensed, machine-readable
      vendor crosswalk found. Coverage is partial, so the alias table takes
      it as one claim source among several.
    - Alongside it: `microsoft-activity-group.json` (179 Microsoft names,
      linked back to threat-actor entries; Microsoft's own mapping JSON is
      CC BY 4.0 but does not say which vendor owns an "other name") and the
      MITRE ATT&CK groups STIX (182 groups).
    - Ransomware groups: RansomLook (data CC BY 4.0, keyless `/api/groups`,
      `/api/group/<name>` with leak-site status and posts, `/api/actor`)
      is the group list. ransomware.live's v2 `/v2/groups` is keyless but
      its terms define group listings as "the Data": "Source:
      Ransomware.live" linked wherever shown, 30-minute cache minimum,
      personal use, no re-export. We take group names and aliases from
      RansomLook and MISP first; where ransomware.live PRO data is shown
      (Phase 2 group-to-CVE, victims) the templates carry the linked
      attribution. MISP's `ransomware.json` mixes families with RansomLook
      imported groups and has no field telling them apart.
    - Reference, not data: ETDA Threat Group Cards and Malpedia (both
      CC BY-NC-SA) and Sophos CTU profiles (no stated data licence) are
      the richest per-vendor alias crosswalks. The profile page links out
      to each; nothing from them is stored or shipped. HiP (0xjet/hip,
      MIT, 17 vendor taxonomies) is a candidate claim source to evaluate.
  - Aliases are stored as claims, "source X says A is also called B", and
    are never hard-merged transitively. Clusters: an actor profile is
    created when an authoritative source (MISP galaxy entry, ATT&CK group)
    defines one; aliases claimed by two independent sources attach
    automatically; a single-source claim shows as "reported alias" until
    the analyst confirms or rejects it; the analyst can split a cluster.
    Example of why: SOCRadar's free profile for Lazarus (read 2026-11-06)
    folds Andariel, Citrine, Diamond, Moonstone, and Sapphire Sleet into one
    actor, lists Qilin as its malware, and attaches 286 CVEs. Of the 1,118
    galaxy entries, the list page shows by default only those with
    activity in the last three years or an ATT&CK ID; the rest exist as
    stubs reachable by search.
  - Technique lists come from structured sources and from the Phase 2
    technique-ID and TTP-table extraction, each row carrying its source
    document. The analyst can add a technique by hand with its source.
    Extraction from prose waits for Phase 11.
  - List page: counters first, then a table with a search box and filters
    on targeting (sector, region), motivation, type (state, crime,
    hacktivist, ransomware), and last activity.
  - Profile page (layout agreed 2026-11-06), top to bottom, then tabs:
    - Header: primary name, aliases with the claiming source on hover,
      type, origin, first and last seen, motivation descriptors.
    - Targeting: sectors and regions, from structured sources and from the
      victim records; then a short description paragraph (analyst-written
      or quoted with its source).
    - Tabs: Capability (malware, tools, techniques with their procedures,
      CVEs exploited, with the operator's stack matches highlighted);
      Infrastructure (hosting providers and ASNs used, registrars,
      certificate issuers, JARM and favicon fingerprints, TLDs, naming
      patterns: aggregated metadata from sightings rather than a raw IOC
      list; live indicators appear only while they are not dormant);
      Victims (sectors and regions, and named victims from reporting and
      leak sites, each with source); Defend (public Sigma, YARA, and
      Splunk rules tagged to the actor, ATT&CK mitigations for its
      techniques, and the Navigator layer export); Reporting (every
      document in the corpus that mentions the actor, from feeds or added
      by hand, newest first, with a "add this report" form that requires
      a source).
    - Rigor on every claim: source, date, and the source's reliability
      letter from the registry.
  - From Kraven Security's "Threat Profiling 101" (reviewed 2026-11-10):
    - Header fields added: archetype (nation-state, cybercriminal,
      hacktivist, insider), motivation, intent, and capability, the last
      three as short analyst-set ratings with a reason.
    - Proximity tag per actor, set by the operator: direct (seen against
      the operator's own organisation), industry (seen against the
      sector), opportunistic (victim-agnostic, such as ransomware
      affiliates and infostealers). The list page filters on it.
    - Priority set: the operator pins the handful of actors that matter
      most (the article's "10-20 down to 3-5"). A "my threat landscape"
      page aggregates across the pinned set: most common techniques,
      shared initial-access methods, shared tools and infrastructure
      habits, and the detection-coverage gaps that several actors have
      in common. This is the page that turns profiles into priorities.
    - Strategic context tab: an analyst-written PESTLE table (political,
      economic, social, technological, legal, environmental factors that
      could change the actor's behaviour) and a short activity timeline.
      Free text with sources; nothing generated.
    - Supporting elements on the Defend tab: the intelligence
      requirements the profile answers and the data sources needed to
      detect the actor, beside the rules already planned.
    - Upkeep: a "last reviewed" date and review interval per profile, and
      the change note already required on edits.
    - Export in the shape of MITRE's CTI Blueprints threat actor profile.
    - Threat profiling (who is out there) is kept apart from threat
      modelling (how they would get into this environment); the second
      is the control-coverage item below.
  - From AdversaryGraph and its public "Threat Matrix" page
    (anpa1200/adversarygraph, licence "personal use only", so ideas only;
    reviewed 2026-11-10). Most of what the public page does is already
    planned here (ATT&CK lookup, actor pivots, group overlap, coverage
    leads, Navigator export). Taken from it:
    - Technique page layout: description, then ATT&CK's own detection
      strategies and analytics with their log sources and data
      components, then mapped groups, then the matrix with the technique
      highlighted.
    - An in-app matrix view (zoom, expand sub-techniques, layer export)
      with tabs for Enterprise, Mobile, ICS, and ATLAS, so a layer can be
      read without leaving for the Navigator site.
    - Dataset provenance line on every ATT&CK-derived page: dataset
      version and the SHA-256 of the bundle in use.
    - A stated boundary on each page: what it does not do.
    - Evidence-to-detection chain as a view on a case: evidence, claim,
      behaviour, technique, required telemetry, detection candidate,
      rule, validation, result, analyst decision, with each link marked
      proven or inferred. It fits the evidence classes and the coverage
      gap already planned.
    - Not taken: its AI mapping, RAG, attack simulation, scanner, and
      SIEM forwarding, which are outside this toolkit's scope.
  - Behaviour pivoting (added 2026-11-09): comparing an intrusion, a
    report, or a case with known actors, and actors with each other. Built
    so that a number is never read as attribution. MITRE's own guidance is
    that activity should not be attributed on techniques alone, and a 2025
    study of ATT&CK v15 found a mean pairwise overlap between group
    technique profiles of about 0.07, only a third of groups with any
    group-specific technique, and about two thirds with no specific
    behaviour at all once tools and CVEs are added.
    - Guard-rails first (these ship before any comparison feature):
      - Commodity and shared-tool stop-list, three tiers: commodity or
        open source (Mimikatz, Cobalt Strike, RMM tools, LOLBins: counts
        for nothing in same-actor scoring), shared within an ecosystem
        (counts only toward an "ecosystem" hypothesis), exclusive as far
        as known. Each entry has a source, a valid-from date (a tool that
        leaked or was sold stops counting from that date), and a review
        date. Seeded from ATT&CK tool objects with high group counts,
        LOLBAS, LOLRMM, and the Ransomware Tool Matrix "most used" list.
      - Evidence classes and the attribution gate: every evidence item on
        a case belongs to one class (technique or procedure, tooling,
        malware code, infrastructure, victimology, timing, artefact
        metadata, persona, external vendor assessment). "Likely the same
        actor" needs two independent classes; "very likely" needs three
        including one that is hard to forge; technique overlap alone
        never suffices; two vendor reports that cite each other count as
        one source. Any number of matching indicators of one kind is
        still one class.
      - Profile-quality badge wherever a profile is compared: number of
        source reports and publishers, date range, share of techniques
        with a single citation, share of tools on the stop-list.
      - Forgeability label per artefact type (trivially forgeable,
        forgeable with effort, hard to forge) with consistency checks
        where they exist (the Olympic Destroyer Rich header was caught
        because it contradicted the real build environment).
    - Comparison features, each deterministic:
      - Rarity-weighted technique overlap: weight each technique by how
        few reference profiles use it, report weighted containment (share
        of the observed set found in the profile) beside weighted
        Jaccard, give half credit for a parent-only match, and suppress
        the score when the observed set has fewer than 8 techniques or
        the overlap fewer than 5. Shown with a fixed caveat panel:
        MITRE's caution, each candidate's profile size, and the share of
        the score that comes from common techniques. Campaign objects are
        preferred to multi-year group profiles as the comparison unit.
      - "What would tell A from B": the techniques, tools, and CVEs one
        candidate has and the other lacks, ordered by rarity and filtered
        to things there is a detection for, each with its cited procedure
        sentence. This is the list an incident responder can act on.
      - Procedure-level matching: command lines and artefact strings from
        reports and case notes are normalised (paths, hosts, and GUIDs
        replaced by placeholders) and matched against stored procedures
        per actor and against Atomic Red Team and LOLBAS examples; a
        command identical to a public example is flagged as low value for
        attribution and still useful as detection content.
      - Tool-stack overlap matrix after the stop-list; shared-CVE
        timeline (who used a CVE, and whether before or after public
        exploit code); victimology heatmap with a base-rate column so
        opportunistic targeting shows as such; "first seen using"
        timeline and yearly drift per actor.
      - Technique co-occurrence ("what else to look for"): pair counts
        and lift from the CTID Technique Inference Engine dataset (6,236
        reports, Apache-2.0), labelled as corpus co-occurrence and not
        prediction; no model is trained or run.
      - Sequence comparison: longest common ordered run of techniques
        between two cases or Attack Flow examples (41 flows, Apache-2.0),
        since an ordered run is more specific than a set.
      - Artefact-fingerprint registry across the operator's own cases:
        imphash, Rich header hash, PDB path tokens, compile time, icon
        hash, mutex and pipe names, LNK machine ID and volume serial,
        Office document part hashes, signer certificate, each exact-match
        with its forgeability label and a "builder default" list (a
        builder fingerprint links to the builder, not the operator).
      - Ransomware lineage panel: shingled text match of a ransom note or
        negotiation chat against ThreatLabz ransomware_notes and
        Casualtek/Ransomchats (both MIT), exact match on contact IDs and
        wallets, with the standing caveat that code and templates are
        sold, leaked, and copied.
      - Hypotheses board: an analysis-of-competing-hypotheses matrix per
        case, with "unrelated actor using shared tooling" and "deliberate
        imitation" always present, evidence that fits every hypothesis
        greyed out as non-diagnostic, ranking by weighted inconsistency,
        and a view of which single item would change the ranking if wrong.
      - Estimative-language builder: likelihood from the seven ICD 203
        terms, confidence as a separate field with its basis, assumptions
        stored as records, a "what changed and why" note on every edit,
        and a check that no sentence carries both a likelihood and a
        confidence. Template rendering, no model.
    - Outputs for defenders: detection-coverage gap per actor (actor
      techniques joined to Sigma, Splunk, and ATT&CK detection strategies
      by tag; Navigator layer export) and a hunting package per actor
      (non-commodity tools with their LOLRMM and LOLBAS artefacts,
      procedure idioms, tagged rules, CVEs, current ThreatFox indicators
      with their age), each item with provenance and licence.
    - Datasets, in ingestion order: ATT&CK STIX 2.1 (groups, software,
      campaigns, and the procedure sentence on each "uses" relationship);
      MISP galaxy (including the Tidal, sector, and country clusters);
      the TIE dataset; Ransomware Tool Matrix and Ransomware Vulnerability
      Matrix (CC BY 4.0); Sigma; Atomic Red Team indexes (MIT; parsed,
      never executed); LOLBAS and LOLRMM; the Attack Flow corpus;
      Microsoft's mapping JSON; ThreatLabz notes and Ransomchats.
      Repositories with no licence (Russian APT Tool Matrix, EternalLiberty,
      APTnotes, the report archives) are linked, not copied.
    - Build order inside this block: stop-list, evidence classes, and
      quality badge; then overlap, discriminators, tool matrix, and
      coverage gap; then procedures, CVE timeline, drift, and hunting
      package; then case threads, sequences, hypotheses board, and
      co-occurrence; then the registry, lineage panel, and language
      builder.
- MITRE ATT&CK lookup and mapping (plugin has a local dataset). Pulled
  forward with the seed slice.
- Rigor fields: Admiralty source rating, TLP, confidence level. The default
  source reliability lives in the Phase 5 source registry from the start.
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
- Report-to-profile extraction (added 2026-11-06): the analyst gives a
  report (a URL through the Phase 2 fetcher, or pasted text, or a RAGFlow
  document if that is wired) and a required source attribution; the model
  proposes entries for the profile sections (aliases, techniques with
  procedures, malware, CVEs, infrastructure metadata, victims) as a diff
  against the current profile. Nothing is written until the analyst accepts
  each line; every accepted line carries the report as its source. The
  deterministic extractor (IDs, TTP tables) runs first and the model only
  fills what it missed, so prose-only reports are the model's job and
  table reports stay deterministic.
- Query suggestions for restrictive tools (added 2026-11-06): given a
  case's current entities and the documentation of tools we cannot call
  freely (Validin, Censys, Silent Push), the model recommends the next
  manual queries; the Phase 6 query-template links are the deterministic
  version and come first.
- Chatter sentiment and "mood" for the weekly brief: only here; the
  deterministic brief uses reply counts and poster reputation.
- MCP (Model Context Protocol) servers, reviewed 2026-11-10 from Kraven
  Security's survey: the four it lists (MCP-ThreatIntel, fastmcp-
  threatintel, and unofficial VirusTotal and MISP servers) mostly wrap
  enrichment sources this toolkit already calls natively, so none is
  needed. Direction for this phase instead: expose the toolkit's own
  local corpus as a read-only MCP server (search indicators, documents,
  actors, cases; no write tools, bound to 127.0.0.1) so a local model
  can query what the operator has already collected and vetted.
  Third-party MCP servers are code with access to keys and data and get
  the full dependency vetting; a trojanised MCP server delivering an
  infostealer was reported in 2026. On "confidence-scored attribution"
  from indicators and TTPs (fastmcp-threatintel; code not inspected): a
  model's score is not evidence. If such a feature is ever added it sits
  behind the Phase 9 evidence gate, shows which evidence classes it
  used, and can never raise a likelihood term the gate would not allow.
- Sensitive data routed to local model or excluded. Dark-web and Telegram
  text, case contents, and own-organisation selectors never leave the
  machine: local model only.
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
  feed. Public read-only candidate since it is read-only and
  aggregate. Look for existing trackers/visualizations to pull inspiration and
  possibly data from, beyond the seed sources already listed in Phase 4 (MITRE
  ATLAS, OWASP LLM Top 10, AI Incident Database, vendor reports) — specific dashboards to be
  researched later.
- Findomain and any dropped enumeration tools: revisit only if Subfinder
  coverage proves thin.
- VirusTotal monthly quota tracking (~15,500/month): deliberately NOT tracked
  (decided 2026-10-29). VT does not expose a live balance the way Shodan's
  api-info does, so it would need a local monthly counter. Add only if heavy
  use makes the monthly cap a real risk. Minute and daily caps are enforced.
- Phase 1 enrichment expansion (parked 2026-10-29; needs new free
  accounts): wire the additional free IOC sources listed under
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
- Public deployment / hosting (parked 2026-11-03): design the security
  posture before any non-localhost exposure; deliberately out of scope while
  the tool stays local (127.0.0.1). Summary of the first-cut design:
  authenticated by default (MFA/TOTP on real accounts), TLS reverse proxy with
  strict TrustedHost, gated or trimmed `/health`, egress allowlist against
  SSRF, CSP, per-account rate limits, container/VM/low-privilege isolation,
  structured audit logging with Wazuh and a free WAF (Coraza or ModSecurity
  with the OWASP CRS, or Cloudflare). Open versus gated: the no-key read-only
  pieces (news feed with keyword search, IOC extraction page, landing page)
  may be public; anything that spends keys or reveals investigations stays
  gated; the Telegram/dark-web corpus is never public (synthetic data or
  screenshare only). Demo path for gated modules: a read-only demo account
  with a non-descriptive name, cached or canned responses, BYO-key in user
  settings, and README recordings. Full notes are in docs/journal.md.
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
  Keep it out of the app runtime.
- Automated CAPTCHA solving (parked 2026-11-04): hook a solver API (CapSolver
  or NopeCHA) into the Playwright layer to automate puzzle CAPTCHAs on
  criminal-operated sources. The Phase 5 human-in-the-loop session capture
  comes first.
- Research write-ups and a weekly chatter brief (parked 2026-11-06): a module
  for research notes and blog-style write-ups drawn from the toolkit's own
  data (for example first-party sensor data). First candidate: a weekly brief
  of dark-web and Telegram chatter (malware advertised, targeting,
  vulnerabilities discussed, hacktivist activity). The toolkit assembles the
  evidence deterministically (top category hits, most-mentioned CVEs, new
  malware-for-sale posts, each with its citation) and the analyst writes the
  prose. Scope agreed 2026-11-06: malware and exploit code advertised or
  sold, hacktivist group chatter and claims on Telegram, vulnerabilities
  discussed, targeting; per post the deterministic proxies for attention
  are reply count, view count where the platform shows it, and the
  poster's standing (account age, post count, reputation where the forum
  shows one). Source display rule for anything published: the forum name
  for dark-web sources and the word "Telegram" for Telegram sources, never
  the post link or channel handle; the full citation stays local for the
  analyst's own review. Sentiment waits for Phase 11.
- Review list for the operator (added 2026-11-09). Things built or planned
  on a first cut that the operator wants to revisit by hand once the core
  phases are done:
  - Verdict lines (Phase 2 and the other modules): read the rule table and
    the wording on real results and give feedback.
  - Telegram: the links and tools that could not be checked automatically
    (VK threads, subreddits, bots, sites behind bot checks; the list is in
    docs/journal.md) and anything the collector cannot reach without a
    joined account.
  - Chatter brief: everything beyond the deterministic first cut
    (sentiment, mood, per-forum reputation scales, which forums and
    channels count).
  - Source picker defaults: which sources are ticked by default for each
    kind of search (see Phase 7).
  - Proxies, anti-detect browsers, and scraping tools: the operator's
    questions and the first-pass answers are recorded under the Phase 5
    egress ladder ("Revisit when Phase 5 collectors are built").
  - Paste-hosted C2: how others spot it (VirusTotal community comments
    with paste links) and whether to mine those comments (Phase 3).
  - Logo detection on document-sharing sites: whether to crawl at all
    (Phase 3).
  - Analysis VM and OSINT distro choice (Tsurugi, REMnux, plain Ubuntu):
    decide when WSL2 is set up.
  - Vulnerability views: the operator is not yet sure about the layout;
    review after the first three views exist. Microsoft default filter
    (Phase 2).
  - Module name for Phase 6 (see the naming note there).
- AI for TTP extraction (parked 2026-11-10): a model is a good fit for the
  cases the deterministic extractor labels as out of reach (prose-only
  reports, image matrices after OCR, one procedure shared by several IDs,
  PDFs whose columns will not line up) and for proposing a procedure
  sentence where a report gives IDs and names only. Same rules as the
  Phase 11 report-to-profile feature: local model, proposals shown as a
  diff, nothing saved until accepted, the deterministic result kept
  beside it.
- AI pivot advisor (parked 2026-11-10): given a case's grid (attributes,
  share counts, what has been tried, what was rejected and why), a model
  recommends the next pivots and conjunctions worth trying and which tool
  fits each one (which engine indexes that attribute, which free quota is
  left), with its reason. Advisory only: it never runs a pivot, never
  admits a member to a cluster, and its suggestions are logged as
  suggestions. The deterministic version ships first: the rarity band,
  the per-pivot free-route and paid-route table, and remaining quota
  shown per source.
- Local model driving web search (parked 2026-11-06): a RAGFlow or local
  model workflow that issues Google queries and reads the results. Parked
  because a model issuing Google queries is still scraping Google under
  Google's terms; revisit if a compliant search API with storage rights is
  on hand, or run it against Brave within its transient-use terms.
- Blockchain explorers for ClickFix and EtherHiding tracking (parked
  2026-11-06 until a case needs it): the Etherscan V2 API (one free key,
  3 calls a second, 100,000 a day; source and ABI endpoints on every chain,
  transaction history only on free-tier chains, and BNB Smart Chain, where
  most EtherHiding lives, is not one) plus plain JSON-RPC `eth_call` and
  `eth_getCode` against public nodes (bsc-dataseed.binance.org,
  polygon-rpc.com), which is how the loaders themselves read the payload
  and needs no key. Decode the ABI string, Base64 and gzip deterministically
  and never evaluate it. Blockmage/ether_unhide (Apache-2.0) is the
  reference implementation. Bitcoin: mempool.space REST (keyless). Monero
  addresses are not traceable by design.
- GreyNoise API key (parked 2026-11-03): GreyNoise no longer issues free
  keys to consumer email domains, and a paid business plan is not worth it
  for this toolkit. Revisit once the operator owns a domain with inbound
  mail (the Phase 4 newsletter-alias item provides exactly that): sign up
  with an address on that domain and drop the key into the existing
  GreyNoise vendor module. Until then the 10/day community endpoint stands.
- GreyNoise Project Swarm (parked 2026-11-03): deploy
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
  - Register the VPS and the sensor account under an alias and domain that
    are not linked to a personal identity. Do not use a personal email.
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
  One exception: for watched own-organisation selectors, a keyed hash (HMAC
  with a local secret) may be kept to tell a repeat leak from a new one. No
  password value is stored, and no credential is tested against a live
  service.
- Accounts: no impersonation accounts. Research-persona logins are created
  by hand, are read-only, and are stored as credentials.
- The store lives on local/external disk, is git-ignored, may be encrypted
  at rest, and never leaves the machine.
- Keep a query audit log and a suppression list (honor deletion requests).
- Phase 3 seeds are limited to selectors the operator owns or is authorised
  to monitor; executive or employee monitoring requires consent. Arbitrary
  seeds are Phase 7 queries that stay local and authenticated.
- Phase 3 and Phase 7 read one shared local corpus under this one policy.
- Scraping session files (cookies, tokens) are credentials: stored in the
  git-ignored data folder, optionally encrypted, never committed.
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
8. Browser and sidecar tooling (Playwright browser binaries, the challenge
   solver) follows the external-binary path: pinned release, checksum,
   container, and a VM when the target source is untrusted.

## Decisions log

- 2026-10-12: App form over CLI. Local web app, not remotely accessible.
- 2026-10-12: Build own enrichment core; IntelOwl optional later. Reason: IntelOwl is heavy and would make the project a thin wrapper.
- 2026-10-12: Skip phone number OSINT for now. Social media monitoring is
  in scope from 2026-11-04 for brand and executive impersonation (Phase 3).
- 2026-10-12: MMFIC-Framework rejected: requires an LLM, AGPL license, 13 stars.
- 2026-10-12: Python end to end (FastAPI + HTMX), not React. Reason: single language, no Node toolchain.
- 2026-10-13: AI only as an optional last-phase layer.
- 2026-10-22: Develop and run on Linux (dual boot) from the start. Code stays OS-agnostic.
- 2026-10-22 (later): Development may continue on Windows until Linux is
  required (Tor, SpiderFoot, always-on monitoring).
- 2026-10-22: Repository is private on GitHub.
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
  (KEV, EPSS, and at the time inthewild) are downloaded whole; per-CVE APIs (NVD, GitHub,
  OTX, GreyNoise) are queried on demand from the detail page.
- 2026-11-03: Vulnerability intelligence laid out as four tabs (Dashboard,
  Search, Exploits, Watchlist); see the Phase 2 section. A Feeds tab was
  added on 2026-11-04.
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
  no startup hooks or binaries, no known vulnerabilities. The 6.21.x
  line is security hardening for hostile PDFs, which is exactly the input
  this toolkit feeds it. The only process execution in the package is
  an optional external JBIG2 image decoder that is off unless configured.
- 2026-11-04: Phase 3 is retitled Digital risk protection: ransomware and
  leak-site tracking, breach and credential-leak monitoring, brand monitoring,
  and watchlist alerts. Identity lookup and the local breach index move to
  Phase 7 (identity lookup is its first slice). Phase 3 watches seeds the
  operator owns and alerts on new hits; Phase 7 answers on-demand queries on
  any seed; both read one corpus and share vendor clients.
- 2026-11-04: Phase 5 is retitled Collection infrastructure. The scheduler and
  alert inbox are a foundation slice built before Phase 3 alerts. Selector
  watchlists move to Phase 3, on-demand search to Phase 7, and topical
  categories feed Phase 2 chatter and Phase 4. Phase numbers are unchanged.
- 2026-11-04: Scraping policy. Anti-bot handling tools (browser automation,
  challenge solving, proxy routing) are in scope. Each source is reviewed
  against its terms before it is enabled, the toolkit creates no fake profiles,
  and an API is used instead of scraping wherever one exists (no scraping of
  ransomware.live).
- 2026-11-04: GitHub work is split. Secret and credential leaks: Phase 3.
  CVE and exploit content: Phase 2. Username and code search: Phase 7. One
  shared GitHub client.
- 2026-11-04: Subdomain work is split. Monitoring of lookalike and own-org
  domains: Phase 3. The same enumerator as an ad hoc search: Phase 7.
- 2026-11-04: Social media monitoring is staged: handle existence checks and
  dorking first, platform APIs or licensed data next, scraping only where a
  platform's terms permit it.
- 2026-11-04: Threat actor profiles are built last in Phase 7. Alert-triggered
  playbooks are a later slice of Phase 5. The "Local compromise index" idea is
  merged into the Phase 7 local breach index (passwords stay dropped).
- 2026-11-06: Scraping policy refined into two source classes (Principle 8).
  Criminal-operated sources may be collected with browser automation,
  challenge handling, and Tor or proxy egress. Legitimate platforms get
  their API, logged-out public pages, and search-engine alerts only. Reason:
  it keeps reliable collection from leak sites and forums without breaking a
  legitimate site's terms.
- 2026-11-06: "No fake profiles" defined as no impersonation accounts.
  Research personas created by hand for OPSEC are allowed; the toolkit never
  creates accounts, posts, vouches, pays, or engages.
- 2026-11-06: Scrapoxy dropped: its repository says it is discontinued and
  its licence reserves all rights. Proxy rotation is not built until volume
  requires it; egress is Tor for onion services and a VPS or per-source proxy
  for clearnet criminal sources.
- 2026-11-06: The Google Custom Search JSON API is not used (closed to new
  customers, ends 2027-01-01). Dorks run as search-engine alert feeds and as
  manual-review links.
- 2026-11-06: Build order is separate from phase numbers (see Build order).
  Phase 3 is built in two slices: API-only first, collected sources after the
  Phase 5 collectors exist.
- 2026-11-06: Collectors run in a separate worker inside a container or VM,
  never in the web app process.
- 2026-11-06: The shared corpus and the source registry are core components
  (app/core) built with the Phase 5 foundation slice. Extractions are saved
  with a required source, and each indicator is a sighting linked to its
  document.
- 2026-11-06: Password values are never stored. A keyed hash for watched
  own-organisation selectors supports repeat-leak detection.
- 2026-11-06: Threat actor profiles are their own module in Phase 9, with a
  seed slice from structured sources built early. Supersedes the 2026-11-04
  placement in Phase 7.
- 2026-11-06: Candidate repositories checked on GitHub (licence, last push);
  results are in the Phase 5 candidate list.
- 2026-11-06: Brave Search API chosen for low-volume automated dorks;
  results are shown and dropped, never stored (only analyst-saved URLs
  persist). No scraped-Google resellers.
- 2026-11-06: Paste and document-sharing sites are detected through search
  engines (Google Alerts, Brave) and the Intelligence X free tier; the
  Pastebin archive poller is opt-in and off by default because the ToS
  limits it to researchers.
- 2026-11-06: Challenge handling is a local fork of FlareSolverr carrying
  the open hardening PRs; no in-house solver. Free proxy lists and
  residential pools are excluded on evidence; a datacenter proxy or VPS is
  the last resort.
- 2026-11-06: darkweb-observatory's target record, status vocabulary,
  change-detection baseline, alert taxonomy, and seed-list ingestion are
  adopted as the design of the Phase 5 source monitor (ideas only; no
  code, it has no licence).
- 2026-11-06: Phase 6 adopts the bounded-cluster workflow (seed record,
  time window, feature-class corroboration, rejected neighbours, export
  gating) and introduces Cases. Indicators are never deleted; relevance
  decays and a case pins it. mnemonic passive DNS is the first pDNS source;
  Validin and Censys are manual cached lookups; Silent Push, Spur, and
  Whoxy are not integrated (Whoxy is an optional paid module).
- 2026-11-06: The extractor captures TTP tables (tactic, ID, name,
  procedure) from HTML tables and lists, not only bare technique IDs.
- 2026-11-06: Verdict lines: each module's result page carries one to
  three rule-generated sentences that name the field that fired; the rule
  table is published in the app.
- 2026-11-06: Actor profiles use MISP galaxy as the backbone, RansomLook
  (CC BY 4.0) for the ransomware group list, claim-based aliases with
  two-source auto-attachment, and the tabbed layout in Phase 9. ETDA,
  Malpedia, and Sophos profiles are linked, never stored.
- 2026-11-06: Living-off-the-land datasets (LOLRMM, LOLDrivers, lolcerts,
  LOT Tunnels, LOLBAS first) are fetched at runtime; GPL and unlicensed
  ones are never vendored.
- 2026-11-06: Hunter.io for own-domain address discovery; Apollo.io not
  used (terms). Open Source Malware as a runtime lookup on the Supply
  chain tab. VX Underground is linked, never ingested: MalwareBazaar and
  VirusTotal already give hash, metadata, and contacted infrastructure
  without handling live samples.
- 2026-11-06: Telethon's upstream is codeberg.org/Lonami/Telethon.
- 2026-11-09: Phase 6 is table first: a pivot grid with a share count per
  attribute and a rarity band, tick-to-combine conjunctions, a timeline
  strip, and the graph kept for the investigation trail. A typed pivot
  catalogue (after Pivot Atlas), a default-signature library, and
  suppression lists (MISP warninglists first) are local data.
- 2026-11-09: Behaviour pivoting joins Phase 9 with guard-rails first: a
  commodity-tool stop-list, evidence classes with an attribution gate
  (two independent classes for "likely"), and a profile-quality badge.
  Technique overlap is rarity-weighted and always shown with its caveats.
- 2026-11-09: Egress is a ladder (feeds, Tor, own VPS, second VPS, audited
  VPN, ISP address, own line, residential pool last and recorded per
  source). Supersedes "never residential" from 2026-11-06.
- 2026-11-09: Pastebin researcher-mode poller is in scope as an opt-in
  source (the operator is a security researcher; the ToS exception
  applies). Paste-hosted C2 and dead-drop monitoring is added to Phase 3,
  feeds first (URLhaus, ThreatFox).
- 2026-11-09: Logo-only leaked documents cannot be discovered by any free
  legitimate route; the toolkit widens text selectors and offers logo
  matching as a confirmation step on candidates.
- 2026-11-09: Vulnerability dashboard sections become named views (rules
  over one table). AttackerKB dropped (retired 2026-08-18). Microsoft
  Patch Tuesday comes from MSRC's keyless per-CVE CSAF files.
- 2026-11-09: A source picker (tick-list of sources per search and per
  watch) is agreed in principle.
- 2026-11-09: The Telegram bot-token pivot is extract-and-correlate only;
  the toolkit does not call the Bot API with a found token.
- 2026-11-09: Container host: the operator will remove the Linux
  partition and use WSL2 when the Phase 5 collectors are built. Tsurugi
  Linux is not used as a development or container host (forensic distro
  with a custom kernel, refreshed by re-release); REMnux or the Tsurugi
  Lab OVA remain options for the isolated analysis VM.
- 2026-11-10: Tsurugi revisited at the operator's request. Its site
  describes it as a "Digital Forensics, Osint and malware analysis Linux
  Distribution" and it ships an OSINT tool profile, so it is a reasonable
  VM for manual OSINT and for opening hostile files. It is an operating
  system with tools preinstalled, not a tool this app can call, so it
  does not replace anything in the roadmap. Default stays plain Ubuntu
  inside WSL2 for development and containers; the VM choice is made when
  WSL2 is set up.
- 2026-11-10: Parked for the AI phase: model-assisted TTP extraction and
  a pivot advisor. Third-party CTI MCP servers are not adopted; the
  toolkit would expose its own corpus as a read-only MCP server instead.
- 2026-11-10: Taken from Kraven Security's guides and from
  AdversaryGraph's public page (ideas only): header template builder
  and hunt quality score (Phase 6); proximity tags, a pinned priority
  set with a "my threat landscape" page, strategic-context tab,
  technique page layout, in-app matrix, dataset provenance line, and an
  evidence-to-detection view (Phase 9).
- 2026-11-10: Microsoft rows in the Patch Tuesday view default to
  high or critical severity, exploit code, or exploited; to refine
  against real data.

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
  Nuclei templates as an exploit-availability signal, MSRC CSAF (keyless),
  Shodan CVEDB (keyless, non-commercial), endoflife.date (keyless).
- Phase 3: SecurityTrails (free, 50/month), WhoisXML (free, 500/month),
  Validin (free tier), ransomwatch archive.
- Phase 5: Playwright, and the FlareSolverr fork, for the scraping layer.
- Phase 6: mnemonic (keyless), Validin and SecurityTrails for passive DNS,
  crt.sh for cert pivots; Spamhaus DROP, the Tor exit list, OFAC addresses,
  and the LOLRMM/LOT Tunnels domain lists as local gates.

## Open questions

- breach.house: confirm which account tier the API requires.
- Feedly: RESOLVED 2026-11-03 — dropped. Phase 4
  builds its own open-source RSS/report aggregator with keyword highlighting
  and dorking instead.
- Which machine hosts the always-on monitoring instance?
- Which social platforms are in the first brand-monitoring pass?
- Container host for the Phase 5 collectors: RESOLVED 2026-11-09, WSL2 on
  the Windows machine, set up when Phase 5 collectors start (runbook
  then). Still to choose at that point: Docker Engine inside the Ubuntu
  distro, Microsoft's `wslc`, or Docker Desktop.
- Is a VPS enough egress for clearnet criminal sources? Decided per
  source by walking the Phase 5 egress ladder.
- Pastebin `/archive` turnover: one observation showed day-old entries
  at the top. Re-check from a browser before choosing the poll interval.
- Does the VirusTotal free key return `contacted_urls` for a file? The
  API reference says yes and the public-versus-premium page says no.
  Test once with a known sample hash.
- Which search API, if any, backs on-demand dorking: RESOLVED 2026-11-06,
  Brave Search API within its transient-use terms.
- Which challenge solver: RESOLVED 2026-11-06, a hardened FlareSolverr fork.
- Threat actor profiles: RESOLVED 2026-11-06 for layout and sources (Phase
  9); the alias-claim threshold and the Infrastructure tab's aggregation
  rules are refined when the module is built.
- HiP (0xjet/hip) as an alias-claim source: inspect its data format and
  error rate before use.
- GreyNoise: live with the 10/day community endpoint, or obtain a key later
  through a non-consumer email domain.

## Reference material

- cti-skills plugin (MIT): install in Claude Code on Linux to reuse its API references and scripts. Skills of interest: darkweb-collection, indicator-pivoting, osint-methodology, vulnerability-intelligence, ioc-enrichment-workflow, stix-bundle, sigma-writing, yara-writing, kql-writing, and the lookup-* and *-api skills.
- breach.house API docs: https://breach.house/docs
- docs/journal.md: build narrative, troubleshooting, mistakes, policy
  exceptions, and parked design notes that do not belong in this roadmap.
