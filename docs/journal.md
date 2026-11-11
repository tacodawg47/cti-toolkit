# Journal

Everything that helps explain the project but does not belong in ROADMAP.md:
troubleshooting records, one-off policy exceptions, build narrative, and
parked design notes kept in full. ROADMAP.md holds scope, order, and
decisions only. Add new entries at the top of the matching section, dated.

## Troubleshooting

### 2026-10-22: Linux dual boot kernel panic

The Linux dual boot hit a kernel panic after an upgrade ("Unable to mount
root fs on unknown-block(0,0)"). Development continued on Windows.

Options recorded at the time: boot the previous kernel from the GRUB advanced
menu, reinstall the partition, or install WSL2 inside Windows instead.

Note added 2026-11-06: that error usually means the new kernel has no
initramfs. Booting the previous kernel from the GRUB advanced menu and
rebuilding the initramfs for the new kernel (then updating GRUB) normally
fixes it without a reinstall. Not yet tried.

## Policy exceptions

### 2026-11-03: pypdf installed one day inside the one-week rule

pypdf 6.21.4 was installed at six days old, one day inside the dependency
policy's one-week rule, by operator decision: the 6.21.x line is security
hardening for hostile PDFs, which is exactly the input this toolkit feeds it.
The vetting record is in docs/runbooks/vetting-a-dependency.md.

## Build narrative

### Phase 2 progress log (2026-11-03)

~~~text
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
~~~

### Phase 2: ideas taken from the Senserva tracker review (2026-11-04)

~~~text
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
~~~

### Phase 2: built after the live dashboard review (2026-11-04)

~~~text
Built 2026-11-04 after the live dashboard review:
- NVD recent-changes feed (everything modified since the last run, pages
  of 2,000, bulk-saved), so recent CVEs carry vendor, product and CVSS
  without being opened, and "Your stack" shows CVEs published for watched
  products before they reach KEV. The free NVD key makes it ten times
  faster.
- Charts, server-rendered inline SVG, no JavaScript library: known-exploited
  CVEs per month with the ransomware share, most-exploited vendors over 12
  months, heat bars in the hottest table, a sightings-per-day sparkline on
  the detail page. First pass; more belongs with the dashboards parking-lot
  item.
- A "ransomware groups and the CVEs they exploit" table on the Dashboard:
  this year's CVEs by default, all years on request, one CVE per line.
  The data lives in data/cti.db (ransomware_cves, ransomware_groups) and is
  never re-served. Victim counts are all-time until the Phase 3 feed.
- Dashboard workshop (2026-11-04): the feed table and refresh buttons
  moved to a Feeds tab with a one-line status on the Dashboard; every CVE
  table shares one renderer with separate vendor and product columns, Fix
  and Exploit-code columns, dropdown filters (vendor, tags, EPSS, window),
  sortable headers and ten-row paging, all server-side in the URL; CISA due
  dates dropped from the Dashboard (kept on the detail page); chart legend;
  heat defined in one line; "Ask your AI" wording for the text block;
  "show 30 days" labels; Exploits tab sorts newest or hottest. Collapsible
  sections deferred (need a little script to remember state; with HTMX).
- VulnCheck KEV and XDB: key slot added (VULNCHECK_API_KEY); the feed is
  the next source to wire once the community token exists.
- Ingest everything, surface selectively (decided): KEV ignores CVSS and
  many exploited CVEs are medium severity, EPSS is needed for every CVE a
  page can open, and the exploit indexes are small. Filtering happens on
  the dashboard (heat, exploitation, exploit code), not at ingest.
~~~

## Research notes

### 2026-11-10: Kraven guides, AdversaryGraph, proxy and browser products

Pages read in the browser; nothing installed or run.

- Kraven Security, "C2 Hunting 101" (2024-11-29): five steps (known bad
  IP, find the host in Shodan, pick pivot points, search and alert,
  automate). Pivots covered: header text with the date stripped and
  versions shortened, HTML hash, SSH key, certificate hash, JA3S, JARM,
  combined with NOT exclusions. Judges a query by how many returned
  hosts are already known malicious. One sentence says to prefer IPs
  resolving to few domains and the next says "at least 100 domains";
  treated as a typo.
- Kraven, "Threat Profiling 101" (2025-05-05): profile parts are threat
  identification (identifier, aliases, description, archetype,
  motivation, intent, capability, a simple Diamond), operational and
  tactical intelligence, strategic context (PESTLE, timeline), and
  supporting elements (requirements, data sources, detections). Threats
  sorted as direct, industry, opportunistic; narrow 10-20 to 3-5.
- Kraven, "MCP Servers for CTI in 2026" (2026-04-20): MCP-ThreatIntel
  (OTX, AbuseIPDB, GreyNoise, abuse.ch), fastmcp-threatintel
  ("confidence-scored attribution"), unofficial VirusTotal and MISP
  servers; security cases cited: SmartLoader trojanised MCP server
  delivering StealC, RoguePilot prompt injection, AI services as C2
  proxies. The listed servers' code was not inspected.
- Kraven, "Web Scraping using Octoparse" (2024-12-17): builds a regex IOC
  extractor over one report page in a no-code scraper.
- AdversaryGraph (github.com/anpa1200/adversarygraph): v8.1.2 of
  2026-10-20, 35 stars, licence badge "personal use only". Public light
  page at 1200km.com/threat-matrix: ATT&CK 20.0, 178 groups, 706
  techniques, 15 tactics; technique page shows detection strategies and
  analytics with log sources, mapped groups, a zoomable matrix, layer
  export, and a dataset SHA-256 line.
- Octo Browser and Dolphin Anty: both describe themselves as antidetect
  browsers for multi-accounting (ad accounts, bonus hunting, ticketing,
  scraping).
- IPRoyal: residential from $1.75/GB on plans ($7/GB for 1 GB
  pay-as-you-go); pool "comes from our partner network" with identity
  check, business-model review, and evidence of consent required from
  suppliers; restricted targets by default include "Crime and
  stolen-data sites", "Dark-web gateways", "Malware downloads"; access
  on reviewed request. Customer identity verification for unrestricted
  access.
- Tsurugi Linux: site title "Digital Forensics, Osint and malware
  analysis Linux Distribution"; body calls it "Your DFIR Linux
  distribution".

### 2026-11-09: pivoting, behaviour, egress, paste sites, vulnerability views

Web-only research plus two things done locally by research helpers: about
14 read-only page fetches with curl (Scribd, SlideShare, Issuu, and
Pastebin pages, to see the raw HTML) and text extraction from four saved
PDFs. Nothing was installed and no payload was fetched.

**Pivot Atlas (gopivot.ing).** Amitai Cohen's handbook; repo
korniko98/pivot-atlas, no licence, last push 2025-12-09. Structure: one
page per artifact (domain, IP address, sample, TLS certificate, user
agent, GitHub user), each listing its pivots grouped by target artifact,
with an example and "Try it out" query templates such as
`https://app.validin.com/detail?type=ip&find={IP_ADDRESS}#tab=resolutions`
and `https://urlscan.io/search/#page.url%3A%22{PATH}%22`. Other pages:
fingerprints (lossless, lossy, fuzzy; file and certificate hashes, HTML
body hash, JA4+, JARM, HHHash, HASSH, GreyNoise IP similarity), tips
(focus on rarity and use frequency analysis; inclusion and exclusion;
combine pivots; check several databases; search for prior art; document
with exact source), impact (monitoring, detection, hunting, prevention,
collaboration, friction, attribution, cost imposition), and a tool
matrix. Distinctions worth keeping: client versus server and static
versus dynamic IPs; actor-controlled subdomains of shared domains (pivot
on the subdomain, not the apex); victim-side versus attacker-side
tooling. Its own future-plans list names actor behaviour and naming
conventions as pivots not yet covered.

**How tools present pivots.** DomainTools Iris: a grid with one row per
domain and guided pivots that highlight any field shared by 500 or fewer
domains. Censys CensEye: each attribute with the count of hosts sharing
it, rows with 2 to 119 matches highlighted, an allow-list of fields
because not every field pivots well. Validin: count filters, more than
1,000 connections treated as too broad, a timeline view because overlap
in time is not obvious in a table. urlscan Pro: tick indicators to search
for scans sharing all of them. Graph-first tools (VirusTotal Graph,
Maltego, OpenCTI) each add grouping, counts, or commonality lists to
fight clutter. No published user study comparing tables and graphs was
found.

**Pivot durability.** Validin re-tested its own published pivots months
later: DNS, certificate, host-response hash, and registration-time
pivots mostly still worked; favicon, event titles, and CSS class hashes
decayed; plain IPs and simple hashes went inactive quickly.

**False-pivot evidence.** One Cloudflare IP returned about 800 million
domains; SEDO's parking IP appears in two published cases; a generic
nginx 404 body hash matched about 300 domains; Cobalt Strike's JARM also
matched Burp Collaborator and a point-of-sale system; 250,000 routers
shared one SSH host key from a vendor image; a Server header changing on
the same IP marked a change of tenant.

**Behaviour pivoting.** Diamond Model sections 7 to 9 treat a pivot as a
hypothesis test and warn (footnote 21) that clustering fails by
overfitting on a public capability or shared hosting and then compounds.
ATT&CK Design and Philosophy: do not attribute on techniques alone. Saha,
Lindorfer, Caballero (2025, ATT&CK v15.1): mean pairwise Jaccard between
group technique profiles about 0.07, 46% of techniques linked to no
group, 34% of groups with a group-specific technique, about 64% with no
specific behaviour at all. Unit 42's attribution framework (2025) is the
most encodable public method: clusters need two related events,
temporary groups about six months, named actors evidence on all four
Diamond vertices; an IP address defaults to Admiralty credibility 4.
Mimikatz is used by 46 ATT&CK groups. Royal Road (RTF weaponizer) and
the i-Soon leak show tools moving between unrelated groups. Turla used
an Iranian group's infrastructure and implants. Microsoft: one ransomware
affiliate used at least six payloads, so a ransomware "group" profile is
a mixture. ATT&CK v20 (2026-10-13): 227 techniques, 479 sub-techniques,
178 groups, 842 software, 57 campaigns. A pivot on Word RSIDs has no
practitioner source; treat as low weight like document part hashes.

**Egress.** Decodo: UAB Data troops, Vilnius; residential $4/GB
pay-as-you-go, ISP addresses about $3.33 each; resells partner
peer-to-peer pools, names none; logs the target domain; terms bar
"collection of non-public information (i.e: data behind login)".
NodeMaven: NodeMaven FZ LLC, UAE; pool reported as white-labelled; no
known customer verification. DataImpulse: Softoria LLC; $1/GB; sources
through the TraffMonetizer app, which AhnLab found installed on
compromised MS-SQL servers. None was named in Google's IPIDEA report.
Share of residential exits that IPinfo flags as proxies (Proxyway 2026):
Decodo 30% worldwide and 47% in the US, DataImpulse 50% and 52%. Squid
7.8 (2026-10-30), GPL-2.0-or-later; a 2021 audit found 55
vulnerabilities, 35 unfixed at publication in 2023. CCProxy: Windows,
proprietary, overflow CVEs from 2004 and 2008. No measurement of what
leak-site clearnet mirrors block was found. Tsurugi Linux: Lab 26.03
(2026-04-04), rebuilt on Ubuntu 24.04 in 25.11, signed hash file.

**Paste sites as C2.** AsyncRAT's client reads `Settings.Pastebin` and
expects `host:port1:port2`. Cases 2022-2026: LimeRAT, njRAT, XWorm
(paste.tc, paste.ee, Pastebin), DCRat, PrivateLoader (`HOST:<ip>`),
SilentCryptoMiner, DPRK npm packages hiding 31 domains in a Pastebin
essay, Molerats on JustPaste.it, TA558 on paste.ee, Raccoon and Vidar on
Telegram and Steam, Lumma and ACRStealer on Steam and telegra.ph,
Gamaredon on telegra.ph and Teletype. A Pastebin paste page carries the
whole text in HTML. Three spam entries listed as a day old were already
removed.

**Scribd and logos.** A Scribd document page holds the title, the
description, JSON-LD, and an "AI-enhanced title and description"; the
body loads from separate per-page files. Two scanned uploads had no text
beyond the scanner's own watermark, and the AI description was about the
scanner app. SlideShare pages hold the full transcript. ZeroFox, Recorded
Future, and Group-IB describe logo recognition, OCR, and image similarity
on content they crawl; none names Scribd.

**Vulnerability sources.** MSRC: `api.msrc.microsoft.com/cvrf/v3.0/`
needs no key; per-CVE CSAF at `msrc.microsoft.com/csaf/advisories/` with
an exploit-status string such as "Publicly Disclosed:No;Exploited:Yes;
Latest Software Release:Exploitation Detected"; the month document also
holds Edge, Chromium, and Azure Linux entries. October 2026 Patch
Tuesday: about 1,400 CVEs. Vulnerability-Lookup `/api/kev` aggregates
six catalogues. CWE-1427 (prompt injection) is allowed for mapping,
CWE-1426 is discouraged. Langflow has six KEV entries; LiteLLM
CVE-2026-42208 and MLflow CVE-2026-64849 are in KEV. Shodan CVEDB is
keyless and non-commercial. The BSI CSAF lister has 14 providers and
omits Microsoft, Cisco, SUSE, and NCSC-NL, which also publish CSAF.
AttackerKB was retired on 2026-08-18.

**TTP table survey.** 69 report renditions from 40 publishers: 65% real
tables (a third with the header as the first body row, a quarter with a
`thead`), 13% lists or line blocks, 9% prose only, 4% headings with
paragraphs, 4% PDF, 3% div grids, 1% image only. Procedure text sits
beside the ID in 62%; 36% give IDs and names only. Header for the ID
column: "ID" 19 times, "Technique ID" 8. For the procedure column:
Description 6, Evidence 4, Observed Behavior 3, Annotation 2, Use 2,
Procedure 2, Example 2, and a dozen singletons. Mislabelled headers:
Seqrite, Fortinet, Darktrace. Publishers whose posts carried no IDs at
all in every post scanned: CrowdStrike, Proofpoint, Volexity, Bitdefender
Labs, Wiz, Aqua, JPCERT/CC, eSentire, Morphisec, Claroty, SentinelLabs.
Test fixtures, one per layout:
- https://www.welivesecurity.com/en/eset-research/slippynunchucks-hijacks-sogou-input-methods-brand-promotion-mechanism-to-distribute-malware/
- https://blog.talosintelligence.com/ir-trends-q3-2026/
- https://www.intel471.com/blog/openclaw-a-viral-ai-assistant-and-a-magnet-for-infostealer-malware-and-clickfix-trickery
- https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant
- https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/
- https://www.group-ib.com/blog/stray-cat-network-edge/
- https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/
- https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge (and its PDF, assets.recordedfuture.com/insikt-report-pdfs/2026/cta-ru-2026-0827.pdf)
- https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/
- https://www.picussecurity.com/resource/blog/famous-chollima-apt-group-major-activities-ttps-and-simulation
- https://www.zscaler.com/blogs/security-research/inside-global-ai-assisted-hacking-campaign
- https://www.genians.co.kr/blog/threat_intelligence/ai-agent-opencode

Not reached in the survey: ACSC, Trellix, Positive Technologies, Splunk,
WithSecure, Kroll, a 2024-2026 NCSC-UK report. One saved PDF text file
vanished from the scratch folder right after extraction, probably removed
by antivirus because it quoted webshell code; expect that with
indicator-heavy reports.

**Telegram links left for a manual look** (from the 2026-11-06 link
review; none could be checked by fetch): telemetr.io/en/channels and
telegramchannels.me (Cloudflare check); sssoou.com (empty body);
hottg.com, tmbots.info, telegros.ru, yuque.com/telegram/yxg3h6/tm (403);
telegramcatalog.com, telegram-catalog.ru, tg-me.com, telegramindex.com,
telegrambots.info, linkbaza.com, telegram.community, telegram.url.tw (TLS
errors, probably dead); eight VK threads (vk.com/topic-27339681_35246829,
-156599162_36469304, -104630729_33036142, -18200000_33478269,
-42713470_31758284, -34185416_34307947, -42281098_35740699,
-130067045_34430403); reddit.com/r/TelegramChannels, /r/TelegramGroups,
and the r/OSINT thread kvb5jd; smmacc.ru/shop/telegram.html (a shop
selling channels; skip); the Better Programming article "How to get data
from Telegram"; and the bots username_to_id_bot, userinfobot,
creationdatebot, SangMataInfo_bot, MotherSearchBot, LinkCreatorBot
(profiles confirmed, behaviour untested).

**Not confirmed.** Slowik's "Formulating a Robust Pivoting Methodology"
PDF could not be read; his DomainTools composite-objects article was
used. Koczwara's Medium posts, the ja4db site, vendor pricing pages for
FOFA, ZoomEye, Criminal IP, LeakIX and ONYPHE, the EWDCI member list, and
any carrier's SIM terms were not opened.

### 2026-11-06: source and tool review behind the roadmap decisions

Web-only research (nothing installed or run). The roadmap carries the
decisions; the evidence and caveats are here.

**Paste and document sites.** Pastebin: site search removed April 2020;
`/search` 403; scraping API needs PRO and `pastebin.com/pro` says PRO is
"currently sold out"; robots.txt disallows `/raw/` but not `/archive`; ToS
C.6 limits scraping to researchers and archivists. `/archive` serves the 50
newest pastes as plain HTML; `/u/<name>` lists a user's public pastes.
Scribd: `/search?` disallowed in robots.txt, ToS 9.1(a) bans bots, the
search page is a JS shell; ten document sitemaps on sitemaps.scribd.com, so
search engines index uploads (Cyjax 2025 measured about 30 minutes).
SlideShare and Issuu also disallow `/search`; Issuu blocks AwarioBot by
name. PrivateBin-style sites are unmonitorable by design. Every maintained
open-source paste collector either needs PRO (PasteHunter, Watcher) or
scrapes `/archive` (Scavenger, pystemon); SpiderFoot's module uses the
Google CSE API that closes 2027-01-01. HIBP's paste API is e-mail only and
paid. Intelligence X free: 50 selector searches a day on free.intelx.io.

**Brave Search API.** Terms dated 2026-09-01 at
api-dashboard.search.brave.com/terms-of-service. §3(b)(i) forbids
"store, cache, or create a database of Search Results, in whole or in
part" other than "transient storage required for operation"; no caching
window is defined; §13(c)(ii) requires erasing all copies on termination;
§3(b)(xiii) forbids using results to train or evaluate models. Storage
rights exist only on a plan that includes them (not named publicly).
Pricing page: $5 per 1,000 requests, $5 free credit a month, 50 queries a
second, card required.

**CISA TTP tables.** AR26-113A (FIRESTARTER), AA25-203A (Interlock), and
AA26-097A all use real `<table class="tablesaw">` elements with
`<thead>`, header `Technique Title | ID | Use`, one table per tactic with
the tactic in `<caption>` as "Table N. <Tactic>", IDs linked to
attack.mitre.org/versions/vNN/techniques/. AA26-113A (pasted from Word)
uses `Tactic | ID | Technique | Procedure` with `&nbsp;` in the header
cells. Classic MAR-xxxxxxxx reports have no ATT&CK table. CISA STIX
bundles vary: FIRESTARTER's has no attack-pattern objects; Interlock's has
27 but the ID is only in the object name. Microsoft's blog puts IDs in a
bullet list under a tactic heading; Google Cloud posts had no table.

**Telegram link list** (ItIsMeCall911/Awesome-Telegram-OSINT, 107 links):
50 live, 19 dead, 38 unverifiable by fetch (8 VK threads, 3 Reddit, 6
bots, the rest TLS errors or bot checks). In the browser: tgstat.ru and
tgdb.org load; telemetr.io and telegramchannels.me sit behind Cloudflare
checks. The Medium article "Telegram Network Visualization: Tracing
Forwards and Mentions" (2021) builds a channel graph from t.me/s previews
and Gephi without an account. The README has no per-link descriptions.
Two adult "leak" catalogues (all-catalog.ru, telegram-sliv.ru) are in the
list and are excluded. Informer (paulpierre) is the most recently
maintained keyword monitor (Telethon, 500 channels per account).

**FlareSolverr** (2026-11-06): v3.5.2 of 2026-09-12; 55 open issues, 49
open PRs; all 2026 commits by one maintainer; hardening issues 1750-1754
and PRs 1783, 1792, 1807 unanswered. GHSA-c52x-qhrp-8qqp (proxy-extension
JS injection) fixed on master only. Issue 1813: the image ships Chromium
152 with KEV CVEs because the Dockerfile installs Chromium unpinned.

**Free proxies.** Haschek 2015 (79% of live free proxies blocked HTTPS,
17% modified HTML); ProxyTorrent 2017 (under 2% of listed proxies work,
about 10% of those malicious); NDSS 2018 (38% of 65,000 modified
content, 5% maliciously); MADWeb 2024 (640,600 proxies over 30 months,
34.5% ever alive, 16,923 manipulating content, 42,206 on MikroTik
routers); Mi et al. 2019 (237,029 IoT devices in "residential" pools);
Trend Micro 2023 (proxyware exit nodes used for SQLi probing and fraud);
DOJ 911 S5 (19 million IPs, spread by free VPN apps); Lumen AVrecon and
TheMoon/Faceless (SOHO routers); Google IPIDEA 2026 (550 threat groups on
one "consent" pool in a week; SDKs enrolled devices without disclosure).

**WSL2 and Docker.** Docker Desktop on Windows uses WSL2 (default) or
Hyper-V; free for personal use; Windows 11 Pro 23H2 build 22631 is the
exact minimum. WSL2 is a lightweight VM with a real kernel; shell by
default, GUI apps through WSLg; disk is a sparse ext4.vhdx up to 1 TB;
memory defaults to half of RAM (`.wslconfig`); `/mnt/c` and `\\wsl$`
cross-mount; systemd supported (`[boot] systemd=true`). Microsoft now
ships `wslc.exe` (WSL containers, preview 2026-06, no Compose yet). Docker
does not document Engine-inside-WSL but it is common practice. Reclaiming
the Linux partition: set Windows Boot Manager first in UEFI, delete the
Linux partitions in Disk Management, extend C: only if the free space is
adjacent (`Resize-Partition`), remove the leftover firmware entry with
`bcdedit /enum firmware` and `/delete`; have the BitLocker key at hand.

**Actor sources.** MISP galaxy threat-actor.json: 1,118 entries, last
change 2026-11-02, dual CC0 / BSD-2; `meta.name-attribution` holds
"<name>:<producer uuid>" with producer.json naming the vendor; APT29's
entry has "Midnight Blizzard" only through `related` to the
microsoft-activity-group cluster, not in `synonyms`; "Salt Typhoon" is a
synonym of "GhostEmperor". RansomLook: code AGPL-3.0, data CC BY 4.0,
keyless `/api/groups`, `/api/group/<name>`, `/api/actor/<name>`, no stated
rate limit. ransomware.live: `/v2/groups` keyless (419 groups), terms of
2026-08-19 define group listings as the Data (attribution link, 30-minute
cache, personal use on v2, no re-export). Sophos CTU profiles carry
per-vendor aliases but no data licence. SOCRadar's free actor database:
"500+" headline but 1,275 listed; Lazarus profile merges 42 aliases
including Andariel and four Sleet actors, lists Qilin as malware, 286
CVEs, and deprecated technique IDs (T1045, T1444). Its CVE pages are the
better reference: a triage strip (KEV, EPSS, SSVC, CVSS), a "first 24
hours" list built from record fields, "capability, not use" caveats, and
operator search (`has:exploit -has:rule`, `epss:>90 -has:kev`,
`age:<30 has:actor`, `is:overdue has:ransomware`).

**1200km infographics** (read in the browser at 1536x1024): the bounded
cluster workflow is seven steps (seed record, time window, pivot across
sources, score each link 0-100 on relevance, recency, uniqueness,
co-occurrence, context, data quality; reject below 40 or outside the
window or shared infrastructure; build the cluster from entities at 40+
with one corroborating link; write limitations). The example page shows a
pivot table with one column per feature class, a rejected-neighbours
table with reasons, a cluster summary with confidence and rationale, a
"next collection" list, and a hunt enrichment package. The scoring bands
are 81-100 very strong, 61-80 strong, 40-60 moderate, 20-39 weak, 0-19
very weak. The "single IOC" page's infographic is actually the
intelligence-judgments workflow (mislabelled on the site).

**Crypto and LOL datasets.** Etherscan V1 per-chain APIs retired
2025-08-15; V2 free tier 3 calls a second, 100,000 a day, with BNB Smart
Chain and Base not on the free tier (source/ABI endpoints are). EtherHiding
chains: BSC (ClearFake 2023, UNC5142 2025, 2026 testnet variant),
Ethereum (UNC5342), Polygon (SmartLoader/ClickFix 2025-26). lolol.farm:
37 projects; licences by project are in the Phase 8 roadmap text.

## Parked design notes

### Public deployment and hosting (parked 2026-11-03), full text

The roadmap parking lot keeps a short summary. This is the full first-cut
design, to be revisited as its own hardening phase before any non-localhost
deployment.

~~~text
- Public deployment / hosting (parked 2026-11-03): if this is ever turned from
  a local-only tool into a reachable website, design the security posture
  before exposing it. Open questions to work through then, with first-cut
  first-cut notes as a starting point:
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
    leave the no-key, read-only pieces open as a read-only public view — the news/RSS
    feed with its keyword search (Phase 4), the IOC extraction page (pure local
    parsing), and a landing/architecture page. Gate everything that spends
    keys, hits metered APIs, or reveals what you are investigating: enrichment,
    infrastructure pivoting, the OSINT module, and any dashboard built on that
    data. Keeping only the no-quota parts open does gut the enrichment demo (it
    is hollow without the keyed vendors), so the gated parts get a demo path
    instead of public exposure (next point).
  - Demoing the gated parts: a read-only GUEST account (tight rate
    limits, a throwaway/low-quota key or canned sample responses, no access to
    the Telegram/dark-web corpus) is a normal, non-suspicious way to show a
    gated app. Pair it with short screen-recordings / GIFs in the README for parts
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
      open-recon-proxy abuse/liability. (Compare against existing public OSINT
      sites.)
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
~~~

## Roadmap wording removed in v3 (2026-11-04)

For the record, v3 removed these kinds of wording from the roadmap and they
should stay out of it: career and job-hunting framing, first-person and
"operator wants / operator unhappy" commentary, skill-level remarks, the
reference to a work task as the origin of a feature, and to-do notes addressed
to one person. Decisions and their technical reasons stayed.
