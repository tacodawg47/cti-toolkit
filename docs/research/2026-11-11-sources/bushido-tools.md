# BushidoUK resource lists: link-by-link review for the CTI Toolkit

Checked 2026-11-11 with read-only WebFetch. Nothing was downloaded on purpose, cloned,
installed or signed up for. Page content was treated as data. Every row was checked
against ROADMAP.md ("In roadmap?" column) by searching for the item's name and obvious variants.

**Licence rule used throughout:** a repo with no licence is all rights reserved, so the toolkit
may read or fetch it at runtime for local use but may not copy it into the repo. Plain facts
(a CVE-to-group pair, a favicon hash, an alias) can be re-keyed. NC and SA licences mean the
data is fetched at runtime and never shipped.

**Scale:** about 1,000 links in all. Source 1 has 36 sub-lists (972 table rows across the parts
below, including "Home" navigation links and one external README, curated-intel/CTI-fundamentals).
Source 2 has 4 links plus 3 data files. Source 3 has 27 links.

**How to read this file:** Source 1 is split into parts A to H, one per group of sub-lists. Each
part has its tables and then "High-value notes". Every part's "Links not checked" list has been
moved to the appendix at the end. Sources 2 and 3, the top-10 list and the roadmap corrections
come after part H.

**Incidental files.** WebFetch saves PDF responses to disk by itself. Eight PDFs linked from the
lists were saved without being requested (part B: 4, part D: 2, part H: 2). They are in
`<session folder>/tool-results/`.
They are publisher reports and guides (Home Office guide, CrowdStrike, Trend Micro, Lookout,
ialeia, cryptome and two from the Misc list), and none was opened beyond the fetch. The operator
can delete them; I did not delete anything.

---

## Source 1: BushidoUK/Open-source-tools-for-CTI

https://github.com/BushidoUK/Open-source-tools-for-CTI. This is a curated index by BushidoToken
(William Thomas). The README has 35 links to Markdown sub-lists, grouped as Strategic,
Operational, Tactical, Auxiliary and Community. Some README links use the repo's old name,
`Opensource-tools`, which GitHub redirects. One sub-list, `Frameworks.md`, is in the repo but not
linked from the README; part D covers it.

- **Licence:** none, so all rights reserved. The list itself must not be copied; individual
  tools carry their own licences.
- **Maintenance:** 510 commits on branch `master`, last commit 2026-02-08 ("Update
  SecurityNews.md"), not archived. Updates are steady but slow, and many entries are stale (see
  the dead-link notes in each part).
- **In roadmap?** BushidoToken appears once in ROADMAP.md, in Phase 6 (line ~1435). The list
  itself is not cited.

| README section | Sub-list | Covered in |
|---|---|---|
| Strategic | CTI Fundamentals (external: curated-intel/CTI-fundamentals) | Part D |
| Strategic | Adversary Intelligence, Monthly CTI Reports, CTI Reporting | Part D |
| Strategic | Ransomware Intelligence | Part C |
| Operational | Data breaches, Darknet | Part C |
| Operational | Security News, CERTs, Collections | Part E |
| Operational | Vulnerabilities, ICS/OT, Mobile, Threat Hunting | Part B |
| Tactical | IOC Feeds, Network IOC vetting | Part A |
| Tactical | Anti-Phishing, Website Security, Search Engine Tools, OSINT Investigation Tools | Part F |
| Tactical | Malware Analysis Tools | Part G |
| Auxiliary | GitHub Projects, Chrome Extensions, Honeypots | Part G |
| Auxiliary | VPN & Private browsing, Virtual Machines, Secure Email, OPSEC essentials, Certifications, Training | Part H |
| Community | InfoSec Twitter, Podcasts, Conferences, YouTube, Misc | Part H |
| (unlinked) | Frameworks.md | Part D |

## Part A: IOC feeds and IOC vetting (checked 2026-11-11)

Source: BushidoUK/Open-source-tools-for-CTI, branch master, files `IOCs Feeds.md`
and `IOC-vetting.md` (both fetched from raw.githubusercontent.com).
Several sites are JavaScript-only, Cloudflare-gated, or answered 403 to WebFetch;
those cells say so rather than guess. A shared safety-check rate limit hit
mid-run (x.com, misp-project.org, mxtoolbox, spamhaus, botvrij.eu, who.is);
each was retried once as allowed.

### IOCs Feeds.md (25 links: 13 feeds, 10 malware sharing sites, 1 feed management, 1 nav)

| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Automated Alerts of DGA Domains](https://twitter.com/dgafeedalerts) | X account posting Bambenek DGA feed alerts | n/a | Unknown: X returned 402 | None (social posts) | None | no |
| [Data Feeds (Bambenek)](https://osint.bambenekconsulting.com/feeds/) | Bambenek OSINT feeds (DGA domains, C2 IPs) | Commercial licence since 2019; research/non-profit free on request (third-party report) | Unknown: site 403 to fetch | Plain text/CSV feeds historically; MISP lists Bambenek feed as "requires a valid license" | L, Ph5 (licence friction) | no |
| [All Cybercrime IP Feeds (FireHOL)](https://iplists.firehol.org/) | Aggregator/comparison of ~hundreds of public IP blocklists | Tool GPLv2; list data keeps each source's terms; repo shows no licence | Yes: lists regenerated 2026-11-11, daily | Raw `.ipset`/`.netset` files in github.com/firehol/blocklist-ipsets, keyless | H, Ph5 feed-match + Ph6 gate | no |
| [Block Lists (blocklist.de)](http://www.blocklist.de/en/statistics.html) | fail2ban-reported attacker IPs (ssh, mail, apache, bots) | n/a (service); "use at your own risk"; terms page not read | Yes: lists regenerated every 30 min | Keyless TXT lists at lists.blocklist.de/lists/*.txt; getlast.php API; RBL | M, Ph5 feed / Ph1 local gate | no |
| [Botvrij.eu](https://botvrij.eu/data/feed-osint/) | MISP-format OSINT event feed (UUID .json + manifest + hashes.csv) | None stated | Yes: files regenerated 2026-02-03; a MISP default feed | Keyless MISP feed directory | M, Ph5 (MISP feed ingest) | partly (MISP named; not this feed) |
| [CINS Army Sentinel](https://cinsarmy.com/) | Sentinel IPS community bad-IP list | EULA_2017.pdf (not read); cinsscore.com: "use in any way you see fit" | Site stale (2016 posts) but list live | Keyless cinsscore.com/list/ci-badguys.txt (<=15,000 IPs); cinsarmy tarball needs registration token | M, Ph5 feed-match | no |
| [C1fApp](https://www.c1fapp.com/) | Old feed aggregator with search API | Unknown | Unknown: 403; no recent sign of life | Was keyed search API | None | no |
| [Cyber Crime Tracker](https://cybercrime-tracker.net/) | Long-running panel/C2 URL tracker | Unknown | Unknown: timed out twice | Historically all.php text list, keyless | L, Ph5 (if reachable) | no |
| [Green Snow](https://greensnow.co/) | Attacker IP blocklist (scan, SSH, FTP, mail, cPanel) | "All rights reserved; reproduction or republication strictly prohibited" | Yes: updated 2026-11-12 00:15, ~2,800 IPs | Keyless blocklist.greensnow.co/greensnow.txt | M, Ph5 feed-match (local use only, never re-export) | no |
| [Covert.io Threat Intelligence](http://www.covert.io/threat-intelligence/) | Jason Trost's list of ~120 feed URLs and IOC repos | n/a (personal page) | Stale: undated, entries from 2014-2015 | None itself | L, reference only | no |
| [SANS Institute DShield](https://www.dshield.org/reports.html) | SANS ISC honeypot/firewall-log reports | Data CC BY-NC-SA 4.0 | Yes (API live); reports page redirect-looped | Keyless isc.sans.edu/api: ip, intelfeed, threatlist, sources, cloudips | H, Ph1 enrichment + Ph5 feed | no (only the dead ISC Patch Tuesday API, Ph2) |
| [Malc0de Database](https://twitter.com/malc0de) | X account of the old malc0de malware URL DB | n/a | Unknown: X returned 402 | None | None | no |
| [MISP (CIRCL)](https://www.circl.lu/services/misp-malware-information-sharing-platform/) | CIRCL's MISP service page; MISP TIP | MISP software AGPL-3.0 (not shown on page); site content CC BY-SA 3.0 | Yes: CIRCL OSINT feed files dated 2026-11-11 | Keyless CIRCL OSINT MISP feed at circl.lu/doc/misp/feed-osint; community access vetted | H, Ph5 feed ingest + Ph6/Ph8 | yes: MISP warninglists Ph6, galaxy Ph9, push later |
| [VirusTotal](https://www.virustotal.com/gui/home/search) | Multi-AV/URL/IP reputation | n/a (service) | Yes | Keyed v3 API (free 4/min, 500/day) | H, Ph1 (built) | yes, Ph1 built |
| [OTX AlienVault](https://otx.alienvault.com/) | LevelBlue Open Threat Exchange pulses | n/a (service) | Yes (now LevelBlue branding; JS page) | Keyed free API | H, Ph1 (built) | yes, Ph1 built |
| [Any.Run malware trends](https://any.run/malware-trends/) | Family trend tracker with IOCs, sessions | n/a (service) | Yes, "real time" | No public free API; TI/sandbox APIs on paid plans | L, reference + deep link | yes, parking lot (API paid) |
| [Koodous APKs](https://koodous.com/) | Collaborative Android APK analysis | n/a (service) | Yes (c 2015-2026) | Keyed REST API (docs.koodous.com; quotas page not read) | L, parking lot (mobile) | no |
| [BlueLiv community](https://community.blueliv.com/#!/discover) | Blueliv Threat Exchange (Outpost24 since 2021) | n/a | Dead: DNS does not resolve | None | None | no |
| [URLhaus](https://urlhaus.abuse.ch/) | abuse.ch malware URL DB | abuse.ch ToU: not-for-profit free; commercial via Spamhaus | Yes | Auth-Key API (built); ASN/country/TLD CSV/JSON feeds, max once per 10 min | H, Ph1 built; Ph5 bulk | yes, Ph1 built |
| [Malware Bazaar](https://bazaar.abuse.ch/) | abuse.ch malware sample exchange | Same abuse.ch ToU (not-for-profit) | Yes | Auth-Key API (built) + exports | H, Ph1 built; parking lot corpus | yes, Ph1 built |
| [MalShare](https://malshare.com/) | Free malware sample repo | ToS not read | Yes: newest sample 2026-11-11 | Keyed API: getlist (last 24h hashes), details, search, type; getlimit shows quota | M, Ph1 expansion + corpus | yes, Ph1 expansion |
| [Virus Bay](https://beta.virusbay.io/) | Old community malware sharing site | Unknown | Dead: DNS fails (twice) | None | None | no |
| [InQuest Labs](https://labs.inquest.net/) | DFI, RepDB, IOCDB lookups (OPSWAT since 2024) | n/a | Unknown: "socket hang up" twice | Historically keyless/keyed REST API | L, revisit if back | no |
| [via Discord (BushidoToken blog)](https://blog.bushidotoken.net/2021/02/using-discord-server-as-personal-cti.html) | 2021 post: Discord server as CTI dashboard via RSS bots | n/a (blog) | Static 2021 post; TweetShift dead | MonitoRSS, Pingcord, YAGPDB, Reminder-Bot | L, Ph4/Ph5 method reference | no |
| [Home (nav link)](https://github.com/WilliamThomas-sec/Opensource-tools/blob/master/README.md) | Navigation link; resolves to the BushidoUK list README | Not shown | n/a | None | None | n/a |

### IOC-vetting.md (32 links: 24 IP reputation, 8 IP information)

| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [CyberGordon](https://cybergordon.com/) | Web meta-checker querying 30+ engines per observable | n/a; code not open | Last update v0.22.1, 2023-07-30 | Keyless GET /request/<obs>; ~10/min "tolerated" | L, reference (method: fan-out report layout) | no |
| [URLVoid](https://www.urlvoid.com/) | Site reputation vs 30+ blocklists | n/a (service) | Yes (c 2026) | Web only; API via paid APIVoid (30-day trial) | L, deep link only | no |
| [InQuest RepDB](https://labs.inquest.net/repdb) | Aggregated reputation DB lookup | n/a | Unknown: "socket hang up" | Historically API | L | no |
| [ScamAdviser](https://www.scamadviser.com/) | Consumer scam-site trust checker | n/a (service) | Yes | No public API seen; /check-website/?url= | L, Ph3 deep link (brand fraud) | no |
| [OTX pulse create](https://otx.alienvault.com/pulse/create) | OTX pulse builder (bulk IOC indexing) | n/a | Yes (JS page; needs account) | OTX API can create pulses | L, Ph8 export target | yes, OTX Ph1 |
| [VirusTotal search](https://www.virustotal.com/gui/home/search) | Single IOC lookup | n/a | Yes | Keyed v3 API | H, Ph1 built | yes, Ph1 built |
| [Pulsedive](https://pulsedive.com/) | Community TI platform, indicator risk + pivots | n/a; feed/API marked "commercial use" plans | Yes (v6.3.19) | pulsedive.com/api/indicator.php; key optional (keyless works, key raises limits); free limits not shown (JS) | M, Ph1 expansion | yes, Ph1 expansion |
| [IPVoid](https://www.ipvoid.com/) | Free IP tools (blacklist, whois, geo) | n/a | Yes | Web only; API via paid APIVoid | L, deep link | no |
| [AbuseIPDB](https://www.abuseipdb.com/) | IP abuse reports | n/a | Yes (403 to fetch) | Keyed API (built) | H, Ph1 built | yes, Ph1 built |
| [ANY.RUN app](https://app.any.run/) | Interactive sandbox | n/a | Yes (JS page) | API on paid plans | L, parking lot | yes, parking lot |
| [MXToolbox blacklists](https://mxtoolbox.com/blacklists.aspx) | Checks IP/domain vs 100+ DNSBLs | n/a | Yes (c 2004-2026) | Paid MXToolbox API (free tier not seen) | L, deep link | no |
| [Spamhaus check](https://check.spamhaus.org/) | Spamhaus listing lookup | n/a; DROP free for any use with credit | Check page 403; DROP page live | Keyless DROP/ASN-DROP JSON, at most hourly (DQS not checked) | M, Ph6 gate (DROP) | yes, Ph6 (DROP, ASN-DROP) |
| [IPVoid blacklist check](https://www.ipvoid.com/ip-blacklist-check/) | IP vs 80+ DNSBLs, risk score | n/a | Yes | Web only; paid APIVoid | L, deep link | no |
| [Feodo Tracker browse](https://feodotracker.abuse.ch/browse/) | Botnet C2 list (Dridex, QakBot, Emotet...) | CC0 per abuse.ch ToU | Banner: "datasets currently empty"; newest row 2026-03-04 | Keyless /downloads/ipblocklist*.txt/.json/.csv, every 5 min | L now (empty), M if refilled, Ph5/Ph6 | yes, Ph6 (noted empty) |
| [URLhaus browse](https://urlhaus.abuse.ch/browse/) | URLhaus web search (`url:`, `domain:`) | abuse.ch ToU | Yes; now behind a bot check | Use the API instead | H, Ph1 built | yes, Ph1 built |
| [ThreatFox browse](https://threatfox.abuse.ch/browse/) | ThreatFox web search (`ioc:`) | abuse.ch ToU | Yes; behind a bot check | Auth-Key API (built); >6-month IOCs web only | H, Ph1 built | yes, Ph1 built + Ph6 note |
| [GreyNoise](https://www.greynoise.io/) | Internet scanner/noise classification | n/a | Yes | Community endpoint, keyless (built) | H, Ph1 built | yes, Ph1 built |
| [urlscan search](https://urlscan.io/search) | Scan search, ElasticSearch query syntax | n/a | Yes | Keyed search API, per-key quotas | H, Ph1 built; Ph6 pivots | yes, Ph1 built + Ph6 |
| [Triage (tria.ge) search](https://tria.ge/s) | Recorded Future public sandbox reports | n/a | Yes: reports dated 2026-11-11 | /docs/ API; free researcher key (per roadmap) | M, parking lot (report lookup by hash) | yes, parking lot |
| [Kaspersky OpenTIP](https://opentip.kaspersky.com/) | Kaspersky Threat Intelligence Portal | n/a | Live (JS page; content not readable) | API exists (token); limits/terms not readable | M, Ph1 expansion candidate (verify terms) | no |
| [ThreatMiner](https://www.threatminer.org/index.php) | Free TI portal (pDNS, WHOIS, samples, APT reports) | n/a | Down: HTTP 522 twice (Cloudflare origin) | Historically keyless api.threatminer.org/v2, 10/min | L (unreliable), Ph6 if it returns | no |
| [Pulsedive analyze](https://pulsedive.com/analyze) | Pulsedive scan/analyze page | n/a | Yes | Part of Pulsedive API | M, covered by Pulsedive row | yes, Ph1 expansion |
| [MetaDefender (OPSWAT)](https://metadefender.opswat.com/) | Multi-AV file/hash/IP/URL lookup; now metadefender.com | n/a | Yes (JS page; redirect) | Keyed free-tier API exists; limits not readable | M, Ph1 expansion candidate (hash multi-AV) | no |
| [Palo Alto URL filtering](https://urlfiltering.paloaltonetworks.com/query/) | PAN-DB category lookup | n/a | Yes | Web only; no API stated | L, deep link | no |
| [InfoByIP bulk lookup](https://www.infobyip.com/ipbulklookup.php) | Bulk IP/domain geo lookup | n/a | Unknown: 403 | Web only | None (RDAP/ASN already cover it) | no |
| [CentralOps](https://centralops.net/co/) | Domain Dossier, whois, dig, traceroute | n/a | Appears live (frameset) | Web only; paid Hexillion Whois API | L, deep link | no |
| [DomainTools WHOIS](https://whois.domaintools.com/) | WHOIS lookup | n/a | Yes | Paid API | L, deep link | partly (cited for Ph6 pivot bands only) |
| [who.is](https://who.is/) | WHOIS, RDAP, DNS, history | n/a | Yes | "Pro API" with no-card free tier (JSON whois, RDAP, DNS/TLS history); limits not read | M, Ph6 (DNS/TLS history) candidate | no |
| [DNSlytics](https://search.dnslytics.com/) | Reverse IP/NS/MX, domain/IP info | n/a | Unknown: 403 | Paid API historically | L, deep link | no |
| [DNSDumpster](https://dnsdumpster.com/) | HackerTarget subdomain/DNS recon | n/a; no formal terms on API page | Yes | Keyed (free account) api.dnsdumpster.com/domain/{d}, X-API-Key, 1 req/2 s, 50 records | M, Ph3/Ph6 subdomains | no |
| [IPQualityScore](https://www.ipqualityscore.com/) | Fraud/proxy/VPN/Tor IP scoring | n/a | Yes ("All Systems Operational") | Keyed API; "1,000 free lookups" (period not stated) | L, Ph1 (ipapi.is already chosen) | no (Spur/ipapi.is noted Ph6) |
| [CDN Planet](https://www.cdnplanet.com/) | CDN info site with CDN Finder tool | n/a | Yes (c 2011-2025) | Web tool only | L, method reference for CDN trap | no |

### High-value notes

**FireHOL blocklist-ipsets (H, Ph5 feed-match and Ph6 gates).** Use as data,
not as a tool: pull selected raw files from github.com/firehol/blocklist-ipsets
(`<source>.ipset` single IPs, `<source>.netset` CIDRs, `_1d/_7d/_30d` retention
suffixes; regenerated daily). It saves writing one fetcher per feed, and the
iplists site documents each list's source, update rate, and overlap. No repo
licence; README says each list keeps its maintainer's terms, so the source
registry must record each list's own terms; fetch at runtime, never ship.
Keyless, GitHub raw (no rate concern at daily pulls). Good test of "feed
published date is not first-seen".

**SANS ISC / DShield API (H, Ph1 enrichment and Ph5 feeds).** Keyless REST at
`https://isc.sans.edu/api/`: `/ip/{ip}?json` (reports count, attacks targets,
first/last seen, AS, threat-feed hits), `/intelfeed`, `/threatlist/{feed}`,
`/threatcategory/{cat}`, `/sources/...` (top 10,000 sources; "DO NOT USE AS
A BLOCKLIST"), `/cloudips` and `/cloudcidrs` (handy for the Ph6 CDN/cloud
trap). Formats XML default, `?json`, text. No published rate limit; on 429
back off 5 minutes. Data CC BY-NC-SA 4.0: fine for local, non-commercial
use; share-alike matters if exports are ever published. ISC asks for a contact
address in the User-Agent and blocks some default agents: per privacy rules,
the operator decides what goes there (a generic toolkit UA plus the operator's
own address set in .env). A natural drop-in vendor module beside GreyNoise.

**MISP OSINT feeds: CIRCL and Botvrij (H/M, Ph5 ingest, Ph8).** Both are
keyless MISP-format feed directories (`manifest.json` + one JSON per event +
`hashes.csv`): `https://www.circl.lu/doc/misp/feed-osint/` (files dated
2026-11-11) and `https://www.botvrij.eu/data/feed-osint/` (2026-02-03).
Ingest means: read the manifest, fetch new event UUIDs, store attributes as
observations with the event as the document. No licence stated on either; use
locally, do not redistribute. The misp-project.org feed page lists 108 default
feeds (18 MISP, 47 CSV, 43 free text), which is a ready-made catalogue for the
Ph5 source registry. MISP itself is AGPL-3.0 (wrap over HTTP, never import).

**abuse.ch terms (affects built Ph1 modules, and Ph5 bulk pulls).** The
abuse.ch Terms of Use (effective 2025-11-04, updated 2026-10-21) say only
Feodo Tracker, SSLBL, and YARAify are CC0; URLhaus, MalwareBazaar, and
ThreatFox are free for not-for-profit use, commercial use goes through
Spamhaus, and the terms forbid using the data for AI training without
Spamhaus consent (relevant to Ph11: never feed abuse.ch data to an external
LLM by default). Browse pages now sit behind a bot check, so the API is the
only route. URLhaus ASN/country/TLD feeds: no more than once per 10 minutes and
"not intended for blocking". Feodo Tracker: keyless `/downloads/ipblocklist_
recommended.json` and friends every 5 minutes, but the datasets were empty
again on 2026-11-11 (matches the roadmap note).

**Spamhaus DROP (M, Ph6 gate, already planned).** The listed check.spamhaus.org
page returned 403, but the DROP page was read on retry: keyless JSON at
`https://www.spamhaus.org/drop/drop_v4.json`, `drop_v6.json`, `asndrop.json`
(text files to be deprecated). Re-evaluated daily; fetch at most once per hour,
once per day recommended, or the IP may be firewalled. Free for any use; a
product must credit The Spamhaus Project and keep the date and copyright text
with the data.

**Keyless bad-IP lists for a Ph5 feed-match module (M).** blocklist.de
(`https://lists.blocklist.de/lists/{all,ssh,mail,apache,imap,ftp,sip,bots,
strongips,bruteforcelogin}.txt`, one IP per line, gzip-served, regenerated
every 30 min, 48-hour window, "use at your own risk"), CINS
(`https://cinsscore.com/list/ci-badguys.txt`, up to 15,000 IPs, "use in any
way you see fit"), GreenSnow (`https://blocklist.greensnow.co/greensnow.txt`,
~2,800 IPs, "reproduction or republication strictly prohibited": local match
only, never in an export). All are also inside FireHOL, so pick one route, not
both. These answer "seen attacking in the last N days" next to GreyNoise.

**DNSDumpster API (M, Ph3/Ph6).** Free account key in `X-API-Key`,
`GET https://api.dnsdumpster.com/domain/{domain}` returns JSON (a, cname, mx,
ns, txt; each host with ip, asn, asn_name, asn_range, country, ptr). Free:
1 request per 2 seconds, 50 records per domain; banners endpoint is paid.
HackerTarget project; no formal terms on the page. Overlaps Subfinder/crt.sh;
useful as a second subdomain source.

**Pulsedive and MalShare (M, Ph1 expansion, already planned).** Pulsedive:
`https://pulsedive.com/api/indicator.php?indicator=...&key=...`; docs say a
key is optional and raises limits; free-tier numbers were not readable (JS).
MalShare: `https://malshare.com/api.php?api_key=...&action=getlist|details|
search|type|getlimit`; `getlist` gives the last day's hashes (a cheap daily
hash feed for the corpus), `getlimit` reports the daily quota.

**Kaspersky OpenTIP and MetaDefender (M, Ph1 expansion candidates, not in
roadmap).** Both are live, both offer keyed lookup APIs with a free tier, but
the pages are JavaScript-only, so limits and commercial-use terms were not
verified. Worth a manual check by the operator before adding to the
"Additional free sources" list: OpenTIP gives a second vendor verdict on
hashes, IPs, domains, and URLs; MetaDefender gives multi-AV hash results.

**who.is (M, Ph6 candidate).** Advertises a Pro API with a no-card free tier
covering parsed WHOIS, normalised RDAP, and DNS and TLS-certificate history.
History is what RDAP cannot give (roadmap Ph6 notes). Limits and terms not
read (who.is/api returned 404); verify before planning.

(Links not checked: see appendix.)

---

## Part B: Vulnerabilities, ThreatHunting, ICS-OT, Mobile

Source: BushidoUK/Open-source-tools-for-CTI (master), checked 2026-11-11.
Roadmap check: case-insensitive grep of ROADMAP.md (Phase 2 section read in full).
"Rate-limited" means WebFetch's domain safety check refused the fetch; per the brief, one later retry was made and then no more.
X/Twitter: every x.com URL tried returned HTTP 402 (33 tried). After that, the x.com safety check was rate-limited, so the remaining 20 mobile accounts were not tried. Phase 2 already rules out X ("no free API; scraping breaks its terms").

### Vulnerabilities.md (32 links + 1 navigation link)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | US government exploited-CVE catalogue, 1,779 entries | CC0 1.0 (license.txt verified) | Yes, last added 2026-11-10 | JSON/CSV/schema under /sites/default/files/feeds/, keyless | H, Ph2 (built) | yes, Ph2 built |
| [Google Project Zero 0day ITW sheet](https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/view) | Project Zero's tracker of in-the-wild 0-days, one tab per year 2014-2026 | None stated on the sheet; companion repo Apache-2.0 | **Yes**: 2026 tab has 26 rows, latest patched 2026-11-09 | Keyless CSV per tab via `/gviz/tq?tqx=out:csv&sheet=2026` | H, Ph2 view 11 (zero-days) | Listed in Ph2 as a dead end with "freshness unconfirmed". It is fresh, so reconsider |
| [Full Disclosure](https://seclists.org/fulldisclosure/) | Public vulnerability-disclosure mailing list archive (Nmap/SecLists) | n/a (service); no terms shown | Yes, Nov 2026 posts | RSS `seclists.org/rss/fulldisclosure.rss` (15 items, RSS 2.0) | M, Ph2 chatter / Ph4 feed | no |
| [National Vulnerability Database](https://nvd.nist.gov/) | NIST CVE database | n/a (US gov) | Yes | CVE API 2.0 (page did not render to fetcher) | H, Ph2 (built) | yes, Ph2 built |
| [Vulmon Trends](https://vulmon.com/trends) | Vulmon trending CVEs, products, queries | n/a (service) | Yes (2026 CVEs) | No free feed or API seen | L, Ph2 (design idea only) | no |
| [CIRCL CVE feed](https://cvepremium.circl.lu/) | A Vulnerability-Lookup instance (CIRCL), the same software as vulnerability.circl.lu | n/a (service) | Yes, entries 2026-11-11 | Per-CNA and per-GNA Atom/RSS (`/cna-root/CISA/recent.atom`), API, NDJSON dumps | L (duplicate), Ph2 | yes, Ph2 (Vulnerability-Lookup built) |
| [Mitre CVE feed (@CVEnew)](https://twitter.com/CVEnew) | X account posting new CVEs | n/a | Unknown (HTTP 402) | None usable; cvelistV5 covers it | None | yes, ruled out (X), and cvelistV5 is built |
| [Receive Vulnerability Alerts (Vulmon)](https://alerts.vulmon.com/) | Vulmon alert subscriptions | n/a (commercial service) | Yes | API and RSS only on paid plans ($39+/mo); free plan has 2 queries | None (paid; watchlist is built) | no |
| [CVE Details](https://www.cvedetails.com/index.php) | CVE browser with statistics (SecurityScorecard) | n/a (service) | Unknown (HTTP 403 to fetcher) | API page also 403; not verified | L, Ph2 (UI model only) | yes, Ph2 (features borrowed) |
| [AusCERT Security Bulletins](https://www.auscert.org.au/resources/security-bulletins/) | AusCERT ESB bulletins | n/a | Unknown: link 404; /bulletins/ redirects to portal.auscert.org.au | Not seen (portal fetch was rate-limited) | L, Ph4 feed | no |
| [Tencent Threat Notices](https://s.tencent.com/research/bsafe/) | **Dead**: redirects to a Tencent iOA product marketing page | n/a | No (link gone) | None | None | no |
| [CXSECURITY](https://cxsecurity.com/) | One-person Bugtraq-style list of bugs, exploits and dorks, plus a CVE map | n/a; no terms seen | Yes, entries 2026-11-11 | RSS: `/wlb/rss/all/`, `/wlb/rss/exploit/`, `/wlb/rss/vulnerabilities/`, `/cverss/fullmap/` | L-M, Ph2 exploit signal (minor) | no |
| [Exploit Database](https://www.exploit-db.com/) | OffSec public exploit archive plus GHDB | Not stated on page (repo on GitLab) | Yes | RSS `/rss.xml`; GitLab `exploit-database/exploitdb` | H, Ph2 (built) | yes, Ph2 built |
| [Patrowl CVE feeds](https://www.patrowl.io/) | Now a commercial EASM and pentest vendor; no free feed on the page | n/a (commercial) | Company active; PatrowlHears repo (AGPL-3.0) shows (c) 2020-2022 | Paid "CSIRT feeds" in the Pro edition | None | no |
| [OpenCVE feeds](https://www.opencve.io/cve) | Redirects to app.opencve.io: CVE search and alerting, 424,637 CVEs | Cloud service; self-host is BSL ("limitations for commercial use") | Yes, updated 2026-11-11 | API v2 at `/api/v2/docs/` (details did not render); opencve-kb repo, per-year folders (licence not stated) | L, Ph2 (duplicates cvelistV5 + NVD + Vulnrichment) | no |
| [BugBountyHunting](https://www.bugbountyhunting.com/) | Search engine for bug bounty write-ups (@payloadartist) | n/a | Appears live; undated | `?q=` search only, no API | L, Ph4 or Ph7 (link-out) | no |
| [ZDI upcoming advisories](https://www.zerodayinitiative.com/advisories/upcoming/) | TrendAI ZDI: 701 reported-but-undisclosed bugs, plus published advisories | (c) TrendAI, all rights reserved; RSS offered publicly | Yes, 2026-11-11 | RSS `/rss/upcoming/` and `/rss/published/` (CVSS in description; "(0Day)" flag in title) | **H**, Ph2 | no |
| [Security Wizardry Radar](https://www.securitywizardry.com/the-radar-page/alert-details) | CND Ltd dashboard of daily vendor advisories with EPSS and tags | (c) CND Ltd, all rights reserved | Yes, 2026-11-11 | No RSS or API; HTML only; duplicated and mislabelled entries | L | no |
| [Cisco Talos CVE label](https://blog.talosintelligence.com/search/label/CVE) | Old Blogger label URL: **404**. Live instead: talosintelligence.com/vulnerability_reports | n/a | Reports page yes (TALOS-2026-2426, 2026-11-11; 28 open zero-days) | Guessed `.rss` returned 406; no feed confirmed | L-M, Ph2 (zero-day count) / Ph4 | no (Talos only as a Ph2 extraction fixture) |
| [Zero Science Lab 0days](https://www.zeroscience.mk/en/vulnerabilities/) | Link **404**; site live (ZSL advisories, lablog to 2026-10-31) | n/a | Yes | RSS `zeroscience.mk/zslrss.xml` | L, Ph4 feed | no |
| [Wiz Open Cloud Vulnerability DB](https://www.cloudvulndb.org/) | Cloud and CSP issues, many with no CVE (open-cvdb) | Repo CC-BY-4.0 | Stale: last entry 2025-09-17 | RSS `/rss/feed.xml`; YAML in github.com/wiz-sec/open-cvdb | M, Ph2 (cloud tag) / Ph4 | no |
| [@jonasLyk](https://twitter.com/jonasLyk) | X account (Windows LPE researcher) | n/a | Unknown (402) | None | None | X ruled out, Ph2 |
| [@gentilkiwi](https://twitter.com/gentilkiwi) | X account (mimikatz author) | n/a | Unknown (402) | None | None | X ruled out |
| [@ptswarm](https://twitter.com/ptswarm) | X account (Positive Technologies offensive team) | n/a | Unknown (402) | None | None | X ruled out |
| [@testanull](https://twitter.com/testanull) | X account (Exchange/web bug researcher) | n/a | Unknown (402) | None | None | X ruled out |
| [@wugeej](https://twitter.com/wugeej) | X account (researcher) | n/a | Unknown (402) | None | None | X ruled out |
| [@bad_packets](https://twitter.com/bad_packets) | X account (honeypot scanning reports) | n/a | Unknown (402) | None | None | X ruled out |
| [@orange_8361](https://twitter.com/orange_8361) | X account (Orange Tsai, DEVCORE) | n/a | Unknown (402) | None | None | X ruled out |
| [@maxpl0it](https://twitter.com/maxpl0it) | X account (researcher) | n/a | Unknown (402) | None | None | X ruled out |
| [@chompie1337](https://twitter.com/chompie1337) | X account (exploit developer) | n/a | Unknown (402) | None | None | X ruled out |
| [Pwn2Own (X search)](https://twitter.com/search?q=%23pwn2own&src=typed_query&f=live) | Live X search for #pwn2own | n/a | Unknown (402) | None; results surface later as ZDI advisories | None | X ruled out |
| [Tianfu Cup (X search)](https://twitter.com/search?q=Tianfu%20Cup&src=typed_query&f=live) | Live X search for Tianfu Cup | n/a | Unknown (402) | None | None | X ruled out |
| [Home (nav)](https://github.com/BushidoUK/Open-source-tools-for-CTI/blob/master/README.md#index-%E2%84%B9%EF%B8%8F) | Navigation link back to the list's README index | None stated | n/a | n/a | n/a | n/a |

### ThreatHunting.md (10 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Sigma Project](https://github.com/SigmaHQ/sigma) | Generic detection rule corpus, 3,000+ rules | Rules DRL 1.1 | Yes (16,958 commits, 336 open PRs) | Release rule packages; YAML | H, Ph8/Ph9 | yes, Ph8 and Ph9 (DRL 1.1, actor tags) |
| [Detection Rules Feed](https://detection.fyi/) | Browsable index of public detection rules | Not seen | Unknown | Page over 10 MB, not readable; /about/ 404 | M, Ph8/Ph9 (link-out) | no |
| [Detect.fyi](https://detect.fyi/) | Detection-engineering blog publication (Medium) | n/a | Unknown (403) | Medium RSS likely, not verified | L, Ph4 feed | no |
| [Uncoder IO](https://uncoder.io/) | SOC Prime's Sigma/Roota-to-SIEM query translator | Community edition Apache-2.0 (repo UncoderIO/Uncoder_IO) | Active repo (856 commits) | Runs locally in Docker on localhost:4010, offline | M, Ph8 (wrap in its own container) | no |
| [YARA Toolkit](https://yaratoolkit.securitybreak.io/) | Streamlit YARA web app (Thomas Roccia, SecurityBreak) | Not found | Unknown (only "Streamlit" rendered) | None seen | L, Ph8 reference | no |
| [CrowdStrike S.E.A.R.C.H](https://www.crowdstrike.com/blog/successful-threat-hunting-starts-with-search/) | Hunting method: Sense, Enrich, Analyze, Reconstruct, Communicate, Hone (2020-10-08) | n/a | Static article | None | L, Ph9/Ph10 method reference | no |
| [Splunk P.E.A.K](https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html) | PEAK hunting framework, D. Bianco, 2023-04-18 | n/a | Static article | None | M, Ph9 (hunting package structure) | no ("hunting package" in Ph9 is unrelated wording) |
| [UK Home Office Threat Hunting Study](https://hodigital.blog.gov.uk/wp-content/uploads/sites/161/2020/03/Detecting-the-Unknown-A-Guide-to-Threat-Hunting-v2.0.pdf) | "Detecting the Unknown" hunting guide v2.0, 50-page PDF (2020-03) | Not visible (text compressed) | Static | None | L, Ph10 reference | no |
| [BushidoToken Threat Hunting blogs](https://blog.bushidotoken.net/search/label/Threat%20Hunting) | Author's hunting posts (4, 2024-06 to 2025-01); blog active Nov 2026 | n/a | Yes | Blogger feed likely; not verified | M, Ph4 feed | partly (Ransomware Tool Matrix, Ph9) |
| [EDR Telemetry Project](https://github.com/tsale/EDR-Telemetry) | Telemetry-coverage comparison of EDR products and Sysmon | CC BY-NC 4.0 | Active (241 commits, open PRs) | `EDR_telem_windows.json`, `_linux`, `_macOS`, plus ATT&CK mappings; edr-telemetry.com | M, Ph9 (detection gap context) | no |

### ICS-OT.md (51 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [CISA ICS-CERT alerts](https://www.cisa.gov/uscert/ics/alerts) | Old path **404**. Live: cisa.gov/news-events/ics-advisories (4,229; latest ICSA-26-307-01, 2026-11-03) | US gov | Yes | CSAF in github.com/cisagov/CSAF; provider-metadata.json | H, Ph2 view 13 | yes, Ph2 view 13 (CISA CSAF OT feed) |
| [ICS NewsNow Feed](https://www.newsnow.co.uk/h/?search=Industrial+Control+Systems&lang=en&searchheadlines=1) | NewsNow headline search, "Industrial Control Systems" | n/a | **404** for this query | None | L, Ph4 | no |
| [SCADA NewsNow Feed](https://www.newsnow.co.uk/h/?search=scada&lang=en&searchheadlines=1) | NewsNow headline search, "scada" | n/a | Yes (2026-11-09) | HTML only; mostly market PR | L, Ph4 (GDELT covers this) | no |
| [SecurityWeek ICS](https://www.securityweek.com/icsot) | SecurityWeek ICS/OT column | n/a | Unknown (403) | RSS likely, not verified | M, Ph4 feed | no |
| [TheRecord ICS search](https://therecord.media/?s=Industrial+Control+Systems) | Recorded Future News search | n/a | Unknown (403) | Not verified | M, Ph4 feed | no |
| [IndustrialCyber](https://industrialcyber.co/news/) | Industrial cybersecurity news | n/a | Unknown (403) | Not verified | L-M, Ph4 | no |
| [Dragos resources](https://www.dragos.com/resources/) | Dragos reports, webinars, threat group pages | n/a | Yes (2026-11-10) | No RSS seen | M, Ph4 / Ph9 (ICS groups) | no |
| [Kaspersky ICS-CERT reports](https://ics-cert.kaspersky.com/publications/reports/) | ICS threat reports and quarterly landscape | n/a | Yes (2026-11-05) | RSS `ics-cert.kaspersky.com/feed/` | M, Ph4 feed | no |
| [Claroty blog](https://claroty.com/blog/) | Claroty / Team82 OT research | n/a | Yes (undated listing) | Blog RSS not seen; Team82 Disclosure Dashboard RSS `/team82/disclosure-dashboard/feed` (766 CVEs; last 2026-03-12) | L-M, Ph2 view 13 cross-check | no |
| [Red Balloon](https://redballoonsecurity.com/blog/index.html) | Embedded and ICS security blog | n/a | Slow: last post 2025-08-21 | None | L | no |
| [Forescout](https://www.forescout.com/blog/) | Vedere Labs OT/IoT research (OT:ICEFALL and others) | n/a | Yes (2026 posts) | No RSS seen | M, Ph4 | no |
| [Nozomi research reports](https://www.nozominetworks.com/resources/research-reports/) | Link **404**; live at /research-reports and /labs | n/a | Site live | None seen | L-M, Ph4 | no |
| [JSOF](https://www.jsof-tech.com/blog/) | Ripple20 / NAME:WRECK researchers | n/a | Likely defunct (blank page, root and blog) | None | None | no |
| [SCADAfence](https://blog.scadafence.com/) | OT security blog | n/a | Unknown (403); from memory, not checked here: Honeywell acquired SCADAfence in 2023 | None | L | no |
| [Mandiant ICS blogs](https://www.mandiant.com/search?search=OT) | **Dead**: 301 to Google Cloud Mandiant services page | n/a | Link gone | None | L (use Google Threat Intelligence blog in Ph4) | no |
| [Cisco Talos ICS](https://blog.talosintelligence.com/search/label/ICS) | Old Blogger label: **404** | n/a | Link gone | None | L | no |
| [Trend Micro ICS](https://www.trendmicro.com/en_us/common/cse.html#?cludoquery=ICS) | Site search; results load via JavaScript only | n/a | Site live | None | L | no |
| [Cyble ICS](https://blog.cyble.com/?s=ICS) | 301 to cyble.com/blog?s=ICS, which returned 403 | n/a | Unknown | Not verified | L-M, Ph4 | no |
| [IBM Energy & Utility](https://securityintelligence.com/category/energy-utility-industry/) | IBM Security Intelligence category | n/a | Unknown (TLS error in fetcher) | Not verified | L | no |
| [vx-underground ICS/SCADA](https://www.vx-underground.org/ics_scada.html) | ICS malware papers and samples collection | n/a | Not checked (rate-limited twice) | Not checked | L, parking lot (malware corpus) | no |
| [MITRE ATT&CK ICS Techniques](https://attack.mitre.org/techniques/ics/) | ATT&CK for ICS v20.1: 78 techniques, 26 sub-techniques | ATT&CK terms of use | Yes | STIX via mitre-attack repo (not shown on page) | H, Ph2 extraction / Ph9 | yes, Ph2 (ICS dataset) and Ph9 (Navigator ICS tab) |
| [MITRE ATT&CK ICS Mitigations](https://attack.mitre.org/mitigations/ics/) | 53 ICS mitigations, v20.1 | ATT&CK terms | Yes | Same STIX | M, Ph9 | yes (with the ICS dataset) |
| [ICS Cyber Kill Chain (SANS)](https://www.sans.org/white-papers/36297/) | Assante and Lee, 2015 | SANS paper | Static | Free PDF via Egnyte link | L, Ph9 method reference | no |
| [UK NCSC ICS COI](https://www.ncsc.gov.uk/blog-post/strength-of-ics-coi-is-the-team) | NCSC blog post on the ICS community of interest | n/a | Not checked (rate-limited twice) | None expected | L | no |
| [Shodan ICS Safari](https://www.shodan.io/explore/category/industrial-control-systems) | Shodan ICS explore page with per-protocol queries | n/a | Yes | Query list (`port:502`, `port:102`, `port:47808`, `port:44818`, …); `tag:ics` needs an enterprise plan | M, Ph6 (saved query presets on the existing key) | Shodan yes (Ph1); ICS presets no |
| [PIPEDREAM talk](https://www.youtube.com/watch?v=H82sbIwFxt4) | Video on PIPEDREAM ICS malware | n/a | Video page exists | None | L reference | no |
| [Industroyer2 (ESET)](https://www.youtube.com/watch?v=mbCWplL8-ng) | Video with Robert Lipovsky | n/a | Video page exists | None | L reference | no |
| [Baffling Berserk Bear](https://www.youtube.com/watch?v=SX3BBfYP3m8) | Talk on a decade of Berserk Bear CI targeting | n/a | Video page exists | None | L reference | no |
| [Dragos LockerGoga webinar](https://www.youtube.com/watch?v=VziQT5qw9XA) | Dragos webinar | n/a | Video page exists | None | L reference | no |
| [Stateful Protocol Hunting](https://www.youtube.com/watch?v=KTczBtb2ReU) | Gunter and Michaud-Soucy talk | n/a | Video page exists | None | L reference | no |
| [Anatomy of TRITON (SANS)](https://www.youtube.com/watch?v=zorVnE_aL40) | SANS webinar | n/a | Video page exists | None | L reference | no |
| [@5w0rdFish](https://twitter.com/5w0rdFish) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@DragosInc](https://twitter.com/DragosInc) | X account (Dragos) | n/a | Unknown (402) | None | None | X ruled out |
| [@ICSCERT](https://twitter.com/ICSCERT) | X account (old ICS-CERT) | n/a | Unknown (402) | None | None | X ruled out |
| [@ICS_Village](https://twitter.com/ICS_Village) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@SANSICS](https://twitter.com/SANSICS) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@KasperskyICS](https://twitter.com/KasperskyICS) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@RUSCADASEC](https://twitter.com/RUSCADASEC) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@ReverseICS](https://twitter.com/ReverseICS) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@IcsNick](https://twitter.com/IcsNick) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@Kevin_ICS](https://twitter.com/Kevin_ICS) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@ICS_SCADA](https://twitter.com/ICS_SCADA) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@chrissistrunk](https://twitter.com/chrissistrunk) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@jfslowik](https://twitter.com/jfslowik) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@brysonbort](https://twitter.com/brysonbort) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@Marmusha](https://twitter.com/Marmusha) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@shipulin_anton](https://twitter.com/shipulin_anton) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@dudekmar](https://twitter.com/dudekmar) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@mayahustle](https://twitter.com/mayahustle) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@icsk3n](https://twitter.com/icsk3n) | X account | n/a | Unknown (402) | None | None | X ruled out |
| [@JimGilsinn](https://twitter.com/JimGilsinn) | X account | n/a | Unknown (402) | None | None | X ruled out |

### Mobile.md (78 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [ThreatFabric](https://threatfabric.com/blogs.html) | Link **404**; live at threatfabric.com/blogs (fraud and banking malware) | n/a | Site live, undated | No RSS seen | M, Ph4 feed | no |
| [Cleafy Labs](https://www.cleafy.com/labs) | Mobile banking-fraud research | n/a | Yes (2026-09-28) | No RSS seen | M, Ph4 | no |
| [Lookout threat intel](https://www.lookout.com/tag/threat-intelligence) | Lookout mobile threat posts | n/a | Unknown (403) | Not verified | M, Ph4 | no |
| [Zimperium](https://blog.zimperium.com/) | Subdomain **NXDOMAIN**; live at zimperium.com/blog (zLabs, 2026-11-09) | n/a | Yes | No RSS seen | M, Ph4 | no |
| [NowSecure research](https://www.nowsecure.com/blog/category/research-threat-intel/) | Mobile AppSec blog | n/a | Yes (2026-10-30) | WordPress /feed/ likely | L | no |
| [WMC Global](https://www.wmcglobal.com/blog) | Phishing and smishing vendor blog | n/a | Sparse (last 2026-01-21) | None | L | no |
| [APKLab](https://www.apklab.io/) | Avast APK analysis platform | n/a | Unknown (TLS error in fetcher) | Not verified | L | no |
| [Koodous](https://koodous.com/) | Collaborative Android malware platform | n/a (service; ToS linked) | Live ((c) 2015-2026) | API (Apks, Feed, Rulesets) per docs.koodous.com; quotas not read | M, Ph1 (APK hash lookup) / parking lot | no |
| [MalwareBazaar: android](https://bazaar.abuse.ch/browse/tag/android/) | Android-tagged samples | abuse.ch terms | Live (browser check blocked fetcher) | MB API (existing abuse.ch key), query by tag | M, Ph1 (tag query on existing client) | MB yes (Ph1); tag views no |
| [MalwareBazaar: apk](https://bazaar.abuse.ch/browse/tag/apk/) | APK-tagged samples | abuse.ch terms | Live (browser check) | Same | M, Ph1 | same |
| [MalwareBazaar: sms](https://bazaar.abuse.ch/browse/tag/sms/) | SMS-tagged samples | abuse.ch terms | Live (browser check) | Same | L-M, Ph1 | same |
| [VirusTotal: android comments](https://www.virustotal.com/gui/search/android/comments) | VT GUI comment search | VT terms | JavaScript only | Comment search is GUI or premium | L | VT yes (Ph1) |
| [VirusTotal: apk comments](https://www.virustotal.com/gui/search/apk/comments) | Same | VT terms | JavaScript only | Same | L | VT yes |
| [VirusTotal: ios comments](https://www.virustotal.com/gui/search/ios/comments) | Same | VT terms | JavaScript only | Same | L | VT yes |
| [VirusTotal: iphone comments](https://www.virustotal.com/gui/search/iphone/comments) | Same | VT terms | JavaScript only | Same | L | VT yes |
| [CrowdStrike: What is mobile malware](https://www.crowdstrike.com/cybersecurity-101/malware/mobile-malware/) | Explainer (2023-11-02) | n/a | Static | None | L reference | no |
| [Europol mobile malware guide](https://www.europol.europa.eu/operations-services-and-innovation/public-awareness-and-prevention-guides/mobile-malware) | Awareness guide (single-page app, did not render) | n/a | Unknown | None | L | no |
| [Android Banking Trojan Nexus](https://github.com/BushidoUK/Android-Banking-Trojan-Nexus/blob/main/Android.csv) | CSV, 58 Android banker families: AKA, code similarities, actors, source | **No licence** | Stale (last reported Feb-22) | Raw CSV; repo also has 2023 Chrome APK and Korean banking APK CSVs | M, Ph9 (mobile family aliases; facts re-keyed) | no |
| [Corellium GitHub](https://github.com/corellium) | Client libraries for the commercial Corellium virtual-device platform | Clients Apache-2.0; platform commercial | Yes (2026-10) | Needs a paid Corellium account | None (parking lot sandbox, paid) | no |
| [Citizen Lab research](https://citizenlab.ca/category/research/) | Mercenary spyware research | n/a; IOC repo CC BY-NC-SA 4.0 | Yes (2026-10-19) | RSS `citizenlab.ca/feed/`; github.com/citizenlab/malware-indicators (CSV, MISP JSON, STIX, OpenIOC; 22 reports) | M-H, Ph4 feed + Ph9 IOCs | no |
| [Krebs SIM swapping](https://krebsonsecurity.com/category/sim-swapping/) | Krebs category (latest 2026-04-21) | n/a | Yes | RSS `krebsonsecurity.com/feed/` | L-M, Ph4 | no |
| [Cerberus via MDM (Check Point)](https://research.checkpoint.com/2020/mobile-as-attack-vector-using-mdm/) | Report, 2020-04-29, IOC appendix | n/a | Static | IOCs (IP, packages, SHA-256) | L (Ph2 extraction test fixture) | no |
| [Anubis dev arrest (stv24, archived)](https://web.archive.org/web/20210515025455/https://stv24.tv/novosti/izvestnogo-hakera-maza-in-budut-sudit-v-stavropole/) | Wayback copy of a Russian news item | n/a | Archive | None | L | no (fetch tool blocks web.archive.org) |
| [Out-of-band SMS phishing (SANS ISC)](https://isc.sans.edu/forums/diary/Out+of+Band+Phishing+Using+SMS+messages+to+Evade+Network+Detection/27768/) | ISC diary, J. Ullrich, 2021-08-19 | n/a | Static | None | L reference | no |
| [WhatsApp call-forwarding hijack](https://blog.malwarebytes.com/social-engineering/2022/06/whatsapp-accounts-hijacked-by-call-forwarding/) | Malwarebytes, 2022-06-01 (301 to new path) | n/a | Static | None | L reference | no |
| [FluBot takedown (Europol)](https://www.europol.europa.eu/media-press/newsroom/news/takedown-of-sms-based-flubot-spyware-infecting-android-phones) | Europol press release (single-page app, title only) | n/a | Static | None | L reference | no |
| [MoqHao Part 1 (Team Cymru)](https://team-cymru.com/blog/2021/01/20/moqhao-part-1-identifying-phishing-infrastructure/) | Infrastructure pivot write-up (2021) | n/a | Static | None | L, Ph6 method reference | no |
| [MoqHao Part 1.5](https://team-cymru.com/blog/2021/08/11/moqhao-part-1-5-high-level-trends-of-recent-campaigns-targeting-japan/) | **Moved**: lands on the blog index | n/a | Link broken | None | L | no |
| [MoqHao Part 2](https://team-cymru.com/blog/2022/04/07/moqhao-part-2-continued-european-expansion/) | **Moved**: lands on the blog index | n/a | Link broken | None | L | no |
| [PixStealer (Check Point)](https://research.checkpoint.com/2021/pixstealer-a-new-wave-of-android-banking-trojans-abusing-accessibility-services/) | Report, 2021-09-29, IOCs | n/a | Static | IOCs (hashes, packages) | L (fixture) | no |
| [Evil emulator farms (IBM)](https://securityintelligence.com/posts/massive-fraud-operation-evil-mobile-emulator-farms/) | IBM Trusteer report | n/a | Unknown (TLS error in fetcher) | None | L | no |
| [SVR iOS zero-day (The Record)](https://therecord.media/svr-cyberspies-used-ios-zero-day-in-recent-phishing-campaign/) | News, 2021-05-28 | n/a | Static | None | L reference | no |
| [Sandworm Android (Wired)](https://www.wired.com/story/sandworm-android-malware/) | News article | n/a | Not checked (tool blocks wired.com) | None | L | no |
| [Fancy Bear artillery (CrowdStrike PDF)](https://www.crowdstrike.com/wp-content/brochures/FancyBearTracksUkrainianArtillery.pdf) | PDF loads (metadata 2016) | n/a | Static | None | L reference | no |
| [Pre-infected phones, Africa (BBC)](https://www.bbc.co.uk/news/technology-53903436) | News article | n/a | Not checked (tool blocks bbc.co.uk) | None | L | no |
| [Tianfu iPhone hack vs Uyghurs (MIT TR)](https://www.technologyreview.com/2021/05/06/1024621/china-apple-spy-uyghur-hacker-tianfu/) | News, 2021-05-06 | n/a | Static | None | L reference | no |
| [Uyghur mobile APT (Lookout PDF)](https://www.lookout.com/documents/threat-reports/us/lookout-uyghur-malware-tr-us.pdf) | Lookout report PDF | n/a | Unknown (403) | None | L | no |
| [Fake KakaoTalk (McAfee)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/north-korean-defectors-journalists-targeted-using-social-networks-kakaotalk/) | McAfee Labs blog | n/a | Unknown (timeout) | None | L | no |
| [Kimsuky Hdac wallet (X post)](https://twitter.com/vigilantbeluga/status/1315720089316941824) | X post | n/a | Unknown (402) | None | None | X ruled out |
| [Domestic Kitten (Check Point)](https://research.checkpoint.com/2018/domestic-kitten-an-iranian-surveillance-operation/) | Report, 2018-09-07, defanged IOCs | n/a | Static | IOCs | L (defang fixture) | no |
| [Bouncing Golf (Trend Micro)](https://www.trendmicro.com/en_us/research/19/f/mobile-cyberespionage-campaign-bouncing-golf-affects-middle-east.html) | Report, 2019-06-18; IOCs in a separate PDF | n/a | Static | IOC PDF | L | no |
| [MuddyWater Android (Trend PDF)](https://documents.trendmicro.com/assets/white_papers/wp_new_muddywater_findings_uncovered.pdf) | 28-page PDF loads | n/a | Static | None | L | no |
| [StrongPity Android (Trend Micro)](https://www.trendmicro.com/en_us/research/21/g/strongpity-apt-group-deploys-android-malware-for-the-first-time.html) | Report, 2021-07-21 | n/a | Static | None | L | no |
| [Stealth Mango and Tangelo (Lookout PDF)](https://info.lookout.com/rs/051-ESQ-475/images/lookout-stealth-mango-srr-us.pdf) | PDF exists (over 10 MB, too large to read) | n/a | Static | None | L | no |
| [DoNot Firestarter (Talos)](https://blog.talosintelligence.com/2020/10/donot-firestarter.html) | Report, 2020-10-29 | n/a | Static | None | L | no |
| [SideWinder fake VPN (BleepingComputer)](https://www.bleepingcomputer.com/news/security/sidewinder-hackers-plant-fake-android-vpn-app-in-google-play-store/) | News, 2022-06-01 | n/a | Static | None | L | no |
| [Syria COVID lures (Lookout)](https://www.lookout.com/blog/nation-state-mobile-malware-targets-syrians-with-covid-19-lures) | Lookout blog | n/a | Unknown (403) | None | L | no |
| [PhantomLance (Securelist)](https://securelist.com/apt-phantomlance/96772/) | Report, 2020-04-28, IOCs | n/a | Static | IOCs | L (fixture) | no |
| [Operation Bearded Barbie (Cybereason)](https://www.cybereason.com/blog/operation-bearded-barbie-apt-c-23-campaign-targeting-israeli-officials) | **Moved**: 301 to the LevelBlue blog index; article lost | n/a | Link broken | None | L | no |
| [Pegasus Android (Lookout)](https://www.lookout.com/blog/pegasus-android) | Lookout blog | n/a | Unknown (403) | None | L | no |
| [Pegasus technical analysis (Lookout PDF)](https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-technical-analysis.pdf) | PDF loads | n/a | Static | None | L | no |
| [Candiru (Citizen Lab)](https://citizenlab.ca/2021/07/hooking-candiru-another-mercenary-spyware-vendor-comes-into-focus/) | Report, 2021-07-15, IOCs | n/a | Static | IOCs (also in the malware-indicators repo) | L (fixture) | no |
| [Cytrox / Predator (Citizen Lab)](https://citizenlab.ca/2021/12/pegasus-vs-predator-dissidents-doubly-infected-iphone-reveals-cytrox-mercenary-spyware/) | Report, 2021-12-16, IOCs | n/a | Static | IOCs | L (fixture) | no |
| [Circles SS7 (Citizen Lab)](https://citizenlab.ca/2020/12/running-in-circles-uncovering-the-clients-of-cyberespionage-firm-circles/) | Report, 2020-12-01 | n/a | Static | None | L | no |
| [FinSpy Mobile (WikiLeaks)](https://wikileaks.org/spyfiles/docs/gamma/291_remote-monitoring-and-infection-solutions-finspy-mobile.html) | Spy Files listing of a 2011 Gamma brochure | Leaked document | Static | None | L | no |
| [Monokle (Lookout PDF)](https://www.lookout.com/documents/threat-reports/lookout-discovers-monokle-threat-report.pdf) | Lookout report | n/a | Unknown (403) | None | L | no |
| [DarkMatter / Raven (Reuters)](https://www.reuters.com/investigates/special-report/usa-spying-raven/) | Reuters investigation | n/a | Not checked (tool blocks reuters.com) | None | L | no |
| [@apkdetect](https://twitter.com/apkdetect) | X account | n/a | Not checked (x.com rate-limited) | None | None | X ruled out |
| [@ThreatFabric](https://twitter.com/ThreatFabric) | X account | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@ReBensk](https://twitter.com/ReBensk) | X account | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@pr3wtd](https://twitter.com/pr3wtd) | X account | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@U039b](https://twitter.com/U039b) | X account | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@bl4ckh0l3z](https://twitter.com/bl4ckh0l3z) | X account | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@LukasStefanko](https://twitter.com/LukasStefanko) | X account (ESET mobile researcher) | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@m0br3v](https://twitter.com/m0br3v) | X account | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@virqdroid](https://twitter.com/virqdroid) | X account | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@ninoseki](https://twitter.com/ninoseki) | X account | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@_icebre4ker_](https://twitter.com/_icebre4ker_) | X account | n/a | Not checked (rate-limited) | None | None | X ruled out |
| [@midnight_comms](https://twitter.com/midnight_comms) | X account | n/a | Not tried (x.com rate-limited) | None | None | X ruled out |
| [@aazim_here](https://twitter.com/aazim_here) | X account | n/a | Not tried | None | None | X ruled out |
| [@sh1shk0va](https://twitter.com/sh1shk0va) | X account | n/a | Not tried | None | None | X ruled out |
| [@gaur7v](https://twitter.com/gaur7v) | X account | n/a | Not tried | None | None | X ruled out |
| [@0xabc0](https://twitter.com/0xabc0) | X account | n/a | Not tried | None | None | X ruled out |
| [@MrHazum](https://twitter.com/MrHazum) | X account | n/a | Not tried | None | None | X ruled out |
| [@enovella_](https://twitter.com/enovella_) | X account | n/a | Not tried | None | None | X ruled out |
| [@klmitchell212](https://twitter.com/klmitchell212) | X account | n/a | Not tried | None | None | X ruled out |
| [@mem3hack](https://twitter.com/mem3hack) | X account | n/a | Not tried | None | None | X ruled out |
| [@cryptax](https://twitter.com/cryptax) | X account | n/a | Not tried | None | None | X ruled out |

### High-value notes

**Google Project Zero 0day "In the Wild" sheet (H, Ph2): reconsider the dead end**
- ROADMAP Ph2 lists it as a dead end ("Project Zero's in-the-wild sheet (freshness unconfirmed)"). It is fresh. The 2026 tab has 26 rows; the latest is Chrome, patched 2026-11-09, then Windows 2026-10-13 and iOS 2026-09-29. The banner "Last updated: 2023-04-20" is stale and should be ignored.
- Endpoint (keyless, no login): `https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/gviz/tq?tqx=out:csv&sheet=<YEAR>`. Columns: CVE, Vendor, Product, Type, Description, Date Discovered (all "???" in 2026), Date Patched, Advisory, Analysis URL, Root Cause Analysis, Reported By.
- Use: a small bulk feed (one CSV per year, refresh only the current year) as an "exploited" source with its own badge (view 1). It is the strongest evidence for view 11 (Probable zero-days): "Project Zero lists it as an in-the-wild 0-day" turns "probable" into "confirmed by Google". Store it as source `gp0`.
- Licence: no licence is stated on the sheet. Store the facts (CVE, dates, vendor, product) re-keyed and link out for the descriptions. The companion repo googleprojectzero/0days-in-the-wild (Apache-2.0) holds the RCA markdown.

**ZDI published and upcoming RSS (H, Ph2): not in the roadmap**
- `https://www.zerodayinitiative.com/rss/published/` (about 140 items). The title carries the ZDI-YY-NNN ID, vendor, product and bug class, and has a "(0Day)" prefix when ZDI disclosed without a vendor patch. `guid` is the ZDI-CAN ID. The description holds the CVSS score and sometimes the CVE.
- `https://www.zerodayinitiative.com/rss/upcoming/` (701 pending). Each item gives ZDI-CAN ID, vendor, CVSS score and vector, discoverer, reported date and disclosure deadline. There are no product or CVE details.
- Use: (a) "(0Day)" published advisories become a "public, no vendor fix" tag that feeds view 7 (Exploited and unfixed) and the "No fix" verdict line. This is disclosure, not exploitation, so keep it out of view 1. (b) Upcoming gives a per-vendor count of reported but unpatched bugs, which is useful context on the Watchlist tab ("ZDI holds 12 undisclosed reports for this vendor"). (c) Pwn2Own entries arrive here, which covers the two X search links.
- Keyless, no stated rate limit; standard-library XML parsing. The site says "(c) TrendAI, all rights reserved", so store facts and links, not description prose. Refresh daily.

**Full Disclosure RSS (M, Ph2 chatter / Ph4)**
- `https://seclists.org/rss/fulldisclosure.rss` holds the last 15 posts (title, link, description, pubDate). It carries vendor-independent advisories (SEC Consult, for example) that often come before NVD enrichment.
- Use: run the Ph2 CVE extractor over each item to add mention counts to the chatter table and a "disclosed on Full Disclosure" reference on the detail page. Keyless. Reuse the Ph4 reader, so no separate reader is needed.

**Wiz Open Cloud Vulnerability DB (M, Ph2 cloud tag / Ph4)**
- github.com/wiz-sec/open-cvdb is CC-BY-4.0, with YAML per issue (sample at `pages/sample.yaml`), plus RSS at `cloudvulndb.org/rss/feed.xml`. Many entries have no CVE (CSP-side fixes), so they can never reach the CVE table.
- Caution: the last entry is 2025-09-17, about 14 months stale. Use it as a static reference table of cloud issues (attribution required), not as a live feed. Low effort if Ph2 ever gains a cloud view.

**Claroty Team82 disclosure dashboard (L-M, Ph2 view 13)**
- RSS `https://claroty.com/team82/disclosure-dashboard/feed`: 766 OT/IoT CVEs with date, CVE, vendor and product. The last entry is 2026-03-12, so updates are irregular.
- Use only as a cross-check for view 13. CISA ICSA CSAF (already planned) carries most Team82 CVEs with fuller data.

**Citizen Lab (M-H, Ph4 + Ph9)**
- RSS `citizenlab.ca/feed/` for the Ph4 reader (mercenary spyware; latest post 2026-10-19).
- github.com/citizenlab/malware-indicators (CC BY-NC-SA 4.0) provides IOCs per report as CSV, MISP JSON, STIX and OpenIOC, covering 22 reports. Use for local enrichment context ("seen in Citizen Lab report X") and Ph9 spyware profiles. NC-SA means fetch at runtime into the data folder and never vendor it. Low volume, high signal.

**Uncoder IO (M, Ph8)**
- github.com/UncoderIO/Uncoder_IO, community edition Apache-2.0. It translates Sigma (and Roota) into Splunk SPL, Sentinel/Defender KQL, Elastic, QRadar AQL, Chronicle YARA-L, LogScale and others, and runs offline in Docker at localhost:4010.
- Use: wrap it as a separate container in the Ph8 compose file (isolation ladder) rather than writing converters. Note that commercial-edition features are non-commercial only.
- Ph8 currently skips SPL; Uncoder would make it free. Alternative to weigh: pySigma (the Sigma project's own library), which needs a dependency proposal.

**EDR-Telemetry (M, Ph9)**
- github.com/tsale/EDR-Telemetry, CC BY-NC 4.0. `EDR_telem_windows.json`, `EDR_telem_linux.json` and `EDR_telem_macOS.json` give telemetry availability per event type per EDR product, plus ATT&CK mapping files.
- Use: on the Ph9 per-actor detection-gap output, show "can your EDR even see this?" for each technique's telemetry. Fetch at runtime (NC), cite the source.

**Splunk PEAK (M, Ph9 method)**
- Hypothesis, Baseline and Model-assisted hunt types, each through Prepare, Execute and Act. Take the structure for the Ph9 per-actor hunting package. Reference only; no data.

**Shodan ICS explore presets (M, Ph6)**
- Per-protocol queries (`port:502` Modbus, `port:102` S7, `port:20000 source address` DNP3, `port:47808` BACnet, `port:44818` EtherNet/IP, `port:2404 asdu address` IEC-104, and others) as saved query presets on the existing Shodan key. `tag:ics` needs an enterprise plan. Whether filter search works on our key's tier is unconfirmed, so test once.

**Kaspersky ICS-CERT, Dragos, Forescout, Zimperium, Cleafy, ThreatFabric (M, Ph4 feeds)**
- Kaspersky ICS-CERT has RSS at `ics-cert.kaspersky.com/feed/`. The others showed no RSS link and need the per-source HTML extractor in Ph4. Suggested Ph4 categories: "ICS/OT" and "Mobile".

**Android Banking Trojan Nexus (M, Ph9)**
- Raw CSV `raw.githubusercontent.com/BushidoUK/Android-Banking-Trojan-Nexus/main/Android.csv` lists 58 families with AKA, code similarities, associated actors and source link. Last updated Feb 2022, no licence.
- Use: seed the mobile malware alias table with re-keyed facts and a link to the source. The repo also has 2023 CSVs of malicious Chrome APKs and Korean banking APKs.

**MalwareBazaar tag queries (M, Ph1)**
- The android, apk and sms tag pages are behind a browser check for the fetcher, but the existing MB client and abuse.ch key can query by tag (`get_taginfo`, from memory of the API and not re-verified here). That makes a small "recent mobile samples" list cheap to add.

**IOC-bearing reports as Ph2 extraction fixtures (reference)**
- Check Point MDM/Cerberus, PixStealer and Domestic Kitten (defanged `[.]` IOCs), Securelist PhantomLance, and Citizen Lab Candiru and Predator (defanged plus WhatsApp numbers and iOS paths) are good offline test pages for defang handling and IOC tables.

**Dead or duplicate notes for the Ph2 sources list**
- Tencent bsafe is gone (redirects to iOA marketing).
- Patrowl is commercial (PatrowlHears is AGPL-3.0, last activity 2022).
- Vulmon offers API and RSS only on paid plans ($39+/mo).
- cvepremium.circl.lu is the Vulnerability-Lookup already wired.
- OpenCVE's data duplicates cvelistV5, NVD and Vulnrichment, which are already ingested. Self-host is BSL. opencve-kb has no stated licence.
- CXSecurity has exploit RSS but is one-person and overlaps Exploit-DB.
- The Security Wizardry radar is HTML only, all rights reserved, with visible duplicates and mislabelled rows.

(Links not checked: see appendix.)

---

## Part C: RansomwareIntel.md, Darknet.md, Data breaches.md

Checked 2026-11-11 with WebFetch, read-only. Sub-files fetched from
raw.githubusercontent.com (master). No .onion or defanged link was fetched, no
breach search was run for any person, e-mail or domain, nothing was signed up
for or downloaded. Roadmap checks are greps of ROADMAP.md (section quoted).

Total: 65 links (RansomwareIntel 28, Darknet 31 including one duplicate,
Data breaches 6). Each sub-file ends with a "Home" footer link, counted here.

### RansomwareIntel.md (28 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [The Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix) | Tools used per ransomware gang, by category; 17 group profiles, 24 community reports | CC BY 4.0 | Yes, last commit 2026-08-29, 901 commits | Markdown tables + 2 CSVs; raw GitHub | H, Ph9 (stop-list, tool overlap, hunt packages) | Yes, Ph9 (stop-list seed; datasets list) |
| [The Ransomware Vulnerability Matrix](https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix/) | CVEs weaponised by ransomware actors, with group and source per row | CC BY 4.0 | Yes, last commit 2026-08-30, 208 commits | 8 Markdown tables + 12 group profiles; raw GitHub | H, Ph2 view 9 and view 8; Ph9 shared-CVE timeline | Yes, Ph2 views 8 and 9 (Matrix not yet wired); Ph9 datasets |
| [Ransomware Internal Chat/Resource Leaks](https://github.com/BushidoUK/Ransomware-Leaks) | Index of 9 ransomware-gang leaks (chats, playbooks); hosts some copies | None shown | Last commit 2025-11-01, 15 commits | README table; hosts 7z/zip/PDF leak copies | M (reference), Ph9 lineage panel; policy conflict, see notes | No (Ransomchats/ThreatLabz notes are, Ph9) |
| [Ransomware Countermeasure Tracker](https://virtual-routes.org/ransomware-countermeasures-tracker/) | Government actions vs ransomware (arrests, sanctions, takedowns) | None stated (based on Smeets' "Ransom War" dataset) | Yes, newest entry 2026-09-30 | Filterable web table; no export seen | L-M, Ph9 actor timeline (reference link) | No |
| [Historical list of Darknet Data Leak victims](https://drive.google.com/file/d/1MI8Z2tBhmqQ5X8Wf_ozv3dVjz5sJOs-3/view) | DarkTracer .xlsx of leak-site victims 2019-05 to 2021-07 | Not shown | Static, historic | XLSX on Drive; sign-in prompt shown | L, Ph3 historic backfill only | No |
| [Ransomware blog links](https://github.com/thetanz/ransomwatch/blob/main/docs/INDEX.md) | ransomwatch leak-site index (redirects to joshhighet/ransomwatch); ~450 onion rows | Unlicense | Archived 2026-03-03 | posts.json, groups.json in repo | M, Ph3 historic victim backfill (2021-2026) | Yes, "Additional free sources", Ph3: "ransomwatch archive" |
| [ID Ransomware](https://id-ransomware.malwarehunterteam.com/) | Identify family from ransom note / encrypted sample upload; 1191 families | n/a (service), no ToS, FAQ only | Yes, "Updated 11/11/2026" | Upload form; no API | L, Ph9/Ph10 manual link | No |
| [ID Ransomware Blogspot](https://id-ransomware.blogspot.com/) | Amigo-A's Russian-language ransomware family digest with notes and IOCs | n/a (blog) | Yes, newest post 2026-11-04 | Atom feed | L-M, Ph4 feed (new families) | No |
| [No More Ransom](https://www.nomoreransom.org/) | Europol/partners decryptor repository, by family | n/a (service), disclaimer not read | Yes, recent decryptors (Akira, BlackBasta, Lockbit 3.0) | Web list; no API | M, Ph9 "decryptor exists" link per family | No |
| [VirusTotal comments](https://www.virustotal.com/gui/search/ransomware/comments) | VT community comments search for "ransomware" | n/a (service) | JS app, rendered empty | VT API comments (key on hand) | L, Ph3 paste/C2 revisit | Yes, Ph3 revisit note on VT comments |
| [Hatching Triage](https://tria.ge/s?q=tag%3Aransomware) | Recorded Future Triage sandbox listing tagged ransomware | n/a (service) | Live, entries dated 2026-11-11 | Public API /api/v0/; free researcher key (per roadmap) | M, parking lot (sandbox reports by hash) | Yes, parking lot (malware analysis stage 1 and 4) |
| [Malware Bazaar Ransomware Tags](https://bazaar.abuse.ch/browse.php?search=tag%3Aransomware) | MalwareBazaar browse by tag ransomware | n/a (abuse.ch terms) | Live (bot check page served) | MalwareBazaar API (key on hand); tag query not confirmed on page | M, Ph1/Ph9 recent samples per family | Partial: MalwareBazaar built Ph1; tag listing not named |
| [Pulsedive Ransomware news articles](https://pulsedive.com/threat/?tid=437) | Pulsedive threat page for "ransomware" with linked news | n/a (service) | Live, v6.3.19 | API with key; Pro $29/mo; free limits not shown | M, Ph1 expansion (threat context) | Yes, Additional sources Ph1 "Pulsedive (free key)" |
| [AnyRun Ransomware Tags](https://app.any.run/submissions/#tag:ransomware) | ANY.RUN public submissions by tag | n/a (service) | JS app, rendered empty | API on paid plans | L, parking lot | Yes, parking lot ("ANY.RUN's API is on paid plans") |
| [Twitter #Ransomware tags](https://twitter.com/search?q=%23ransomware&src=typed_query&f=live) | X live search for #ransomware | n/a | X/Twitter, not renderable (402) | X API paid | None (manual only) | No |
| [APK Mobile Ransomware](https://koodous.com/apks?search=tag:ransomware) | Koodous Android malware platform, tag search | n/a, ToS at /terms | Live, login form | Docs at docs.koodous.com; account needed | L, parking lot (mobile corpus) | No |
| [Ransomware Overview Spreadsheet](https://docs.google.com/spreadsheets/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/view) | Google Sheet of ~21 ransomware mitigation measures, rated | Not shown | Unknown date | View-only sheet | L, Ph10 docs reference | No |
| Ransomwre groups Wiki (edteebo2w2b...cvkbuqd[.]onion) | Onion ransomware wiki | - | Not checked | - | Not rated | No |
| [Ransomware Cryptocurrency Wallets](https://ransomwhe.re/) | Ransomwhere: crowdsourced ransomware payment addresses and transactions | Data CC BY 4.0 (Zenodo); code MIT | Repo commit 2025-08-29; dataset v1.1.0 (2024) | api.ransomwhe.re/export (all transactions); "Download all data" | M, Ph6 wallet gate/pivot; Ph9 family finance | No (wallet extraction is, Ph5) |
| [Who's been ransomware'd](https://ransom.wiki/) | Ransom.Wiki victim checker | Disclaimer only | Stale: data "upto 03-april-2024" | No API seen | None (superseded by ransomware.live, RansomLook) | No |
| Ransomware leak index (hxxps://darkfeed.io/) | Listed as [offline] in source | - | Not checked (defanged) | - | Not rated | No |
| [CISA Ransomware Newsroom](https://www.cisa.gov/stopransomware/newsroom) | #StopRansomware news, advisories, DOJ/Europol items | US gov public domain | Yes, top item SafePay AA26-293A | HTML; e-mail subscribe only, no RSS shown | M, Ph9 actor sources; Ph4 feed | No by name |
| [CISA Ransomware Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-cisa) | CISA #StopRansomware advisories per family | US gov public domain | Yes, top item Gunra AA26-222A | HTML list; advisories carry STIX/IOC files (not checked) | M, Ph9 actor profile sources; Ph8 IOC import | No by name |
| [FBI Ransomware Alerts](https://www.cisa.gov/stopransomware/official-alerts-statements-fbi) | FBI FLASH/PIN/PSA and joint advisories | US gov public domain | Newest 2025-11-13 (Akira update) | HTML list | L-M, Ph9 actor sources | No |
| [NCSC Ransomware Alerts](https://www.ncsc.gov.uk/search?q=Ransomware&sort=date%2Bdesc&topics=Cyber+attack) | NCSC site search results | Crown copyright (OGL likely, not checked) | Results JS-rendered, empty | NCSC all-feed RSS works (20 items, newest 2026-11-11, none on ransomware) | L, Ph4 feed | Only as NCSC-UK STIX example (Ph2) |
| [Ransom Payment Legality](https://rkovar.github.io/ransomwarelegality/) | Map: is paying ransom legal per country (now isitlegaltopay.com) | No licence seen | Last commit 2023-12-18 | data.yml, merged-data.geojson in repo | L, Ph10 reference link | No |
| [Twitter List (Ransomware researchers)](https://twitter.com/i/lists/1256159047755202560) | X list of ransomware researchers | n/a | X/Twitter, not renderable (402) | - | None (manual) | No |
| [Home](https://github.com/BushidoUK/Open-source-tools-for-CTI/blob/master/README.md) | Parent list README | None shown | Yes, 510 commits | Markdown | Reference only | n/a |

### Darknet.md (31 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Tor browser](https://www.torproject.org/download/) | Tor Project download page (redirects to download.torproject.org) | Open source (licence page not read) | Yes | n/a | L, Ph5 OPSEC doc (operator tool) | Partial: Tor SOCKS egress, Ph5 |
| [Search tools](https://iaca-darkweb-tools.com/) | IACA (NL) dark-web investigation portal: multi-engine search, link directories | n/a (service) | Live; 140/142 tools reachable | No API; its scripts work only over Tor | L-M, Ph5 reference for engine list | No |
| [DarknetDaily](https://darknetdaily.com/) | Darknet news site (per listing) | - | Fetch failed: TLS error, twice | - | Not rated | No |
| [OSINT Tools for the Dark Web](https://github.com/apurvsinghgautam/dark-web-osint-tools) | Curated list, 23 dark-web OSINT tools (search, crawl, scan) | None shown | Yes, last commit 2026-08-07 | Markdown list | M, Ph5 reference (same author as robin) | Robin yes (Ph5); this list no |
| [DarkSearch](https://darksearch.io/) | Former dark-web search engine with API | - | Dead: DNS does not resolve | - | None | No |
| [Identity Management](https://keepass.info/) | KeePass password manager | Open source, OSI certified (GPL-2.0 per project; not shown on page) | Yes, 2.62 on 2026-11-04 | n/a | L, operator OPSEC for persona creds | No |
| [DarknetOnions](https://darknetonions.com/) | "Top darkweb markets" article with market onion links | n/a | Updated 2026-11-06 | No | None (unvetted market links, phishing risk) | No |
| [dark.fail](https://dark.fail/) | Onion uptime directory with PGP-verified URLs | n/a; pseudonymous operator | Updated 2026-11-11; all ~40 sites shown Offline | /mirrors.txt, /pgp.txt; no API | M, Ph5 source-monitor seed and URL verification | Yes, Ph5 "Onion indexer search: Ahmia, dark.fail" |
| [Tor .onion URLs](https://thehiddenwiki.org/) | "The Hidden Wiki" onion link directory | n/a | Stale, newest post 2025-06-30 | No | None (no vetting, card/ID shops listed) | No |
| [DarkWeb24](https://darkweb24.net/) | Parked domain ("may be for sale") | - | Dead/parked | - | None | No |
| [Onion Tree](https://oniontree.org/) | OnionTree onion-service directory | - | Down: connection refused | - | Not rated (down) | No |
| Ransomwre groups Wiki (edteebo2w2b...cvkbuqd[.]onion) | Onion ransomware wiki (same as RansomwareIntel #18) | - | Not checked (onion, defanged) | - | Not rated | No |
| [Crime Forums](https://github.com/misterch0c/CrimeBoards) | List of ~45 blackhat forums/shops (URL, type, private, notes) | None shown | Dead: last commit 2019-03-09 | Markdown table | L, Ph5 forum catalog (historic names only) | No (Ph5 seeds from plugin and deepdarkCTI) |
| Facebook social network (facebookcorewwwi.onion) | Facebook v2 onion | - | Not checked (onion; v2 address, retired by Tor in 2021) | - | Not rated | No |
| DuckDuckGo privacy search (3g2upl4pq6kufc4m.onion) | DuckDuckGo v2 onion | - | Not checked (onion; v2, retired) | - | Not rated | No |
| Protonmail (protonirockerxow.onion) | Proton v2 onion | - | Not checked (onion; v2, retired) | - | Not rated | No |
| The Tor Project official site browser (expyuzz4wqqyqhjn.onion) | Tor Project v2 onion | - | Not checked (onion; v2, retired) | - | Not rated | No |
| Stronghold Paste (nzxj65x32vh2fkhk[.]onion) | Onion paste site | - | Not checked (onion, defanged) | - | Not rated | No |
| BTDigg (btdiggwzoyrwwbiv[.]onion) | BitTorrent DHT search onion | - | Not checked (onion, defanged) | - | Not rated | No |
| Tor Browser Security Guide (dreadytofat...yazubrad.onion/d/OpSec/wiki?id=a306397a) | Dread forum OpSec wiki page | - | Not checked (onion) | - | Not rated | No |
| [Tor reley search](https://metrics.torproject.org/rs.html) | Tor Metrics Relay Search (front end of Onionoo) | Data CC0 | Yes (JS page) | Onionoo JSON API, keyless (known; not shown on page) | M, Ph6 relay details for an IP | Partial: Tor exit list only (Ph6) |
| [Tor Bulk Exit node list](https://check.torproject.org/torbulkexitlist) | Plain list of current Tor exit IPv4s | Tor Metrics data, CC0 | Live | One IP per line, ~1,800-2,000 lines, no header | H, Ph6 local gate; Ph1 flag | Yes, Ph6 "Local gates, no key: the Tor exit list" |
| [Tor scraper](https://github.com/adnane-X-tebbaa/Katana) | Katana-ds: Google dorking tool with Tor support | MIT | Archived 2025-07-02, 4 commits | Python CLI | None (scrapes Google; conflicts with Ph4 rule) | No |
| [Tor crawler](https://github.com/MikeMeliz/TorCrawl.py) | Python crawler for onion/clearnet pages; JSON/SQLite export | GPL-3.0 | Yes, last commit 2026-06-29 | CLI; PyPI `torcrawl` | L, Ph5 ideas only (GPL: no copying) | No |
| [Darknet OSINT](https://github.com/apurvsinghgautam/dark-web-osint-tools) | Duplicate of row 4 | None shown | See row 4 | - | See row 4 | See row 4 |
| [r/Onions](https://www.reddit.com/r/onions/) | Subreddit | n/a | Not checked: fetch tool cannot reach reddit.com | Reddit API (per Ph3 note) | L, Ph4 news via subreddit RSS (unverified) | Reddit only as Ph3 platform API candidate |
| [r/DNMBusts](https://www.reddit.com/r/DNMBusts/) | Subreddit on darknet market arrests | n/a | Not checked: reddit.com blocked for fetch | - | L, Ph4 law-enforcement news | No |
| [r/deepweb](https://www.reddit.com/r/deepweb/) | Subreddit | n/a | Not checked: reddit.com blocked for fetch | - | None-L | No |
| [r/TOR](https://www.reddit.com/r/TOR/) | Subreddit | n/a | Not checked: reddit.com blocked for fetch | - | L | No |
| [r/Darknet](https://www.reddit.com/r/darknet/) | Subreddit | n/a | Not checked: reddit.com blocked for fetch | - | None-L | No |
| [Home](https://github.com/BushidoUK/Open-source-tools-for-CTI/blob/master/README.md) | Parent list README | None shown | Yes | Markdown | Reference only | n/a |

### Data breaches.md (6 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [LeakRadar](https://leakradar.io) | Commercial search over plaintext credentials from stealer logs, combolists, dumps | n/a (service) | Site fetch failed (TLS error, twice); via search: active, docs.leakradar.io, Python wrapper on GitHub | REST API with key; free account (no card); alerts paid; 30 req/s | M-L, Ph3 own-domain only; policy conflict, see notes | No |
| [Have I been pwned?](https://haveibeenpwned.com/) | Breach search and notification; 1,051 breaches | Breach/paste API data CC BY 4.0 with attribution | Live | Keyless: /breaches, /breach/{name}, /latestBreach, /dataClasses, Pwned Passwords; paid key: e-mail, domain, stealer logs; domain must be verified | H, Ph3 domain search; Ph7 breach association; breach catalogue as reference data | Yes, Ph3 vendor sources and Ph7 |
| [Hudson Rock (Free Cybercrime Intelligence Toolset)](https://www.hudsonrock.com/threat-intelligence-cybercrime-tools) | Infostealer intelligence vendor's free tools page | n/a (service) | Page rendered title only; docs (cavalier.hudsonrock.com/docs) 403 | Free API by e-mail, username, domain (per roadmap; not reconfirmed) | H, Ph3 own-domain infostealer hits; Ph7 | Yes, Ph3 vendor sources and Ph7 |
| [Dehashed](https://www.dehashed.com/) | Paid breach search engine (returns credential fields) | n/a (service) | 403 to fetch; not confirmed | Paid API | L-M, Ph7 paid adapter slot only; policy constraints | Yes, Ph7 "A paid vendor key (DeHashed, Intelligence X)" |
| [Data breach news](https://www.databreaches.net/) | DataBreaches.net breach news blog | n/a (blog) | Live; main page 403 to fetch, RSS works, newest 2026-11-11 | RSS 2.0 at /feed/ | M, Ph4 feed (breach and extortion news) | No |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools) | Old account URL; resolves to BushidoUK/Open-source-tools-for-CTI | None shown | Yes, 510 commits | Markdown | Reference only | n/a |

### High-value notes

**Ransomware Vulnerability Matrix (H; Ph2 view 9 and view 8, Ph9).**
- Layout: `Vulnerabilities/` holds 8 Markdown files (NetworkEdge, Microsoft,
  Linux, Applications, Virtualization, FileTransferServers, RMM_Tools,
  Drivers). Each has one table per vendor under an H3 heading, header
  `| Product | CVE(s) | Ransomware Group(s) | Source(s) |`. NetworkEdge.md alone:
  38 rows, 10 vendor tables, 42 distinct CVEs. No CSV or JSON.
- Cell encoding: CVE(s) comma-separated, all `CVE-YYYY-NNNN`; groups comma +
  space; sources separated by " / ". Name markers carry meaning: trailing `*` =
  affiliate, leading `*` = initial access broker, trailing `+` = suspected
  state actor. Parse the marker into a role field, strip it for alias matching
  against RansomLook/MISP names.
- `GroupProfiles/` (12 seen: Akira, BlackBasta, BlackCat, Clop, DragonForce,
  LockBit, PioneerKitten, ProphetSpider, Qilin, RansomHub, TheGentlemen,
  WarLock) uses the same 4-column table plus a `| Date Published | Report |`
  sources table; gives a dated source per group for the Ph9 shared-CVE timeline.
- Ingest: a small parser over raw.githubusercontent.com Markdown, pinned to a
  commit SHA, refreshed weekly (Ph5 scheduler) with a diff. Store each row as a
  claim (cve, group, role, product, vendor, source URLs, matrix commit). CC BY
  4.0 allows copying with attribution and a note of changes, so a parsed
  snapshot may live in the repo. Feeds view 9 (the slot the roadmap left open
  on 2026-11-11), the view 8 edge list seed, and Ph9 profiles.
- ransomware.live/vulns lists 126 CVEs and the Matrix README links it as an
  "integration"; the page does not name its origin, so treat them as two
  sources and dedupe on (CVE, group).

**Ransomware Tool Matrix (H; Ph9).**
- `Tools/*.md`: two columns, `| Tool Name | Threat Group Usage |`, groups comma
  separated, no source links (Exfiltration.md: 34 rows). `MostUsedTools.md`:
  `| Tool Name | Type | Threat Group Usage | MITRE ATT&CK TTPs | Detection Rules |`,
  12 tools (Cobalt Strike 25 groups, Mimikatz 20, PsExec 17, AnyDesk and RClone
  16, AdFind 14...). This is the ready-made seed for the Ph9 commodity stop-list.
- `Tools/AllTools.csv`: one column per category (Discovery, RMM Tools, Defense
  Evasion, Credential Theft, OffSec, Networking, LOLBAS, Exfiltration), 42 rows,
  no group mapping: a category lookup only. Some values defanged ("Catbox[.]moe").
- `GroupProfiles/` (17: Akira, Beast, BianLian, BlackBasta, BlackSuit,
  DragonForce, EvilCorp, INC_Ransom, Interlock, PLAY, ProphetSpider, Qilin,
  SafePay, ScatteredSpider, TheGentlemen, Warlock, Yurei): one 8-category tool
  table plus a dated sources table; no ATT&CK IDs or CVEs. Good for the tool-
  stack overlap matrix and per-actor hunting package.
- `CommunityReports/CR-NNN-FAMILY-DATE.md` (24) and `ThreatIntel/*.md` (CISA,
  DFIR Report, Trend Micro group lists): reference links for profiles.
- `RTM_ThreatHunt_Checklist.csv` (Tool Name, Date of Hunt, Query Used,
  Findings?, Rule Coverage?, Blocked?, Analyst Comment, Course of Action,
  Ticket #): a template worth copying as the column set for a hunt-tracker
  export in the Ph9 hunting package.
- Same parser approach and CC BY 4.0 terms as the vulnerability matrix.

**Ransomware-Leaks (M as reference; Ph9; policy conflict).**
- README table: Date, Threat Actor, Source of Leak, Size of Leak, Reporting,
  Copy of Leak. 9 rows (Medusa, LockBit panel SQL, BlackBasta chats, Dispossessor,
  Trigona, Yanluowang, Conti chats and playbook, Bassterlord manual). The repo
  itself hosts leak archives (Medusa .7z, BlackBasta JSON zip, PDFs); other
  copies point to D4RK-R4BB1T/Criminal-Leaks, DDoSecrets, and an X post.
- No licence: index facts may be re-keyed, files may not be copied.
- Conflict with the Data handling policy: the toolkit "never fetches dumps
  itself" and acquisition happens off-host in a VM. So the toolkit may show the
  index (actor, date, reporting link) on the Ph9 profile, but must not fetch
  `Files/` or the external copies. If the operator wants the chats for the Ph9
  ransomware lineage panel, they acquire them by hand in the VM and drop them
  in the quarantine path; leaked chats also contain victim and personal data,
  so minimisation applies. Last commit 2025-11-01.

**Have I Been Pwned (H; Ph3, Ph7).** Already planned. Confirmed: the breach
catalogue endpoints (`/breaches`, `/breach/{name}`, `/latestBreach`,
`/dataClasses`) need no key and are CC BY 4.0 with a visible link to HIBP, so
the toolkit can hold the breach list as reference data (breach name, date,
data classes) for any phase. E-mail, domain, paste and stealer-log searches
need a paid key; domain search returns 403 unless the domain is verified (DNS
TXT or an e-mail to admin/hostmaster/info/security/webmaster), which matches
the policy rule that Ph3 seeds are domains the operator owns. Pwned Passwords
is keyless but is not needed: the policy drops password values.

**Hudson Rock (H; Ph3, Ph7).** Already planned; the free-tools page rendered
only its title and the API docs returned 403, so endpoints and limits were not
reconfirmed. Re-check when Ph3 slice A is built. Policy: own-domain seeds in
Ph3; arbitrary seeds only as audited Ph7 queries.

**Tor bulk exit list (H; Ph6, Ph1).** Already planned as a Ph6 local gate.
Format confirmed: one IPv4 per line, about 1,800-2,000 lines, no header, CC0.
Cheap to pull hourly and also usable as an enrichment flag on Ph1 IP results.
Tor Relay Search's backend, Onionoo (keyless JSON, CC0), adds relay details
(nickname, flags, first seen) for an IP that is a relay but not an exit; not
in the roadmap, Ph6 candidate.

**Ransomwhere (M; Ph6, Ph9).** Crowdsourced ransomware payment addresses with
family and transactions. `https://api.ransomwhe.re/export` returns all past
transactions; Zenodo dataset `ransomwhere.json` (v1.0.0 4.1 MB; v1.1.0 2024)
is CC BY 4.0, code MIT. Use as a local wallet gate next to the OFAC list: a
wallet extracted by the Ph5 indicator code that matches Ransomwhere gets the
family label. Freshness is unclear (site repo commit 2025-08-29, dataset 2024).

**ransomwatch archive (M; Ph3).** Already in "Additional free sources" (Ph3).
Repo archived 2026-03-03, Unlicense, so `posts.json` and `groups.json` can be
imported once as a historic victim backfill (2021 to early 2026) behind
ransomware.live and RansomLook. groups.json holds onion addresses: treat as
hostile input, never auto-fetched.

**CISA and FBI #StopRansomware pages (M; Ph9, Ph4, Ph8).** Per-family joint
advisories (newest: SafePay AA26-293A, Gunra AA26-222A; FBI list newest
2025-11-13) are the best public, citable source documents for ransomware
actor profiles, and US government works are public domain. No RSS on these
pages (e-mail only), so Ph4 needs an HTML extractor or CISA's general
advisories feed; advisories usually ship STIX/IOC files that Ph8 could import
(not checked here).

**No More Ransom (M; Ph9).** A "decryptor available" link on a family's profile
page (recent: Akira, BlackBasta, Rhysida, Lockbit 3.0, Phobos/8base). No API;
re-key family names by hand or link the decryption-tools page.

**MalwareBazaar tag listing (M; Ph1, Ph9).** The abuse.ch key is already in
.env; a tag or signature query on the MalwareBazaar API gives recent samples
per family for the profile page. The web page served a bot check, so the
endpoint was not confirmed here.

**dark.fail (M; Ph5).** Already planned. Publishes `/mirrors.txt` and a PGP key
with rotation history; useful for checking onion URLs before they enter the
source registry. Operator is pseudonymous; on 2026-11-11 every listed site
showed "Offline", so its status data is not reliable on its own.

**DataBreaches.net (M; Ph4).** Live RSS 2.0 at `/feed/` (newest item
2026-11-11) covering breaches and extortion claims; add to the Ph4 feed list.
The site's HTML returned 403 to the fetcher, so read the feed, not the pages.

**LeakRadar (M-L; Ph3; policy conflict).** Commercial index of plaintext
credentials from stealer logs and combolists (vendor claims 240-280 billion).
API key with a free account; paid alerting. Conflicts to resolve before any
use: it returns password values (the policy drops them at ingest, so the client
must discard them before storage); a paid plan is paying a third party for
stolen-credential access, which sits next to the "no purchase of stolen data"
rule, so it needs an explicit operator decision; seeds limited to own domains
(Ph3) or audited Ph7 queries. Account creation is the operator's, by hand.

**DeHashed (L-M; Ph7).** Already the planned paid adapter. Same constraints as
LeakRadar: drop password and hash fields at ingest, audit log every query, no
arbitrary-person lookups outside casework. Site returned 403; not reconfirmed.

(Links not checked: see appendix.)

---

## Part D: adversary intelligence, CTI fundamentals, reporting, frameworks

Checked 2026-11-11. Sources: the external repo curated-intel/CTI-fundamentals (README),
and four sub-files of BushidoUK/Open-source-tools-for-CTI (branch `master`, no licence,
last push 2026-02-08): `Adversary Intelligence.md`, `Monthly_CTI_Reports.md`,
`CTI_Reporting.md`, and `Frameworks.md`. **Frameworks.md is in the repo root but is not
linked from the BushidoUK README** (confirmed against the README index); covered anyway.

Repo facts: curated-intel/CTI-fundamentals has no licence (`license: null`), 738 stars,
last push 2026-04-25, not archived. Its `Archive/` folder holds 18 mirrored PDFs plus
the CREST MMAT spreadsheets, so many README PDFs have a copy there.

Link count: README 109, Adversary Intelligence 60, Monthly_CTI_Reports 7, CTI_Reporting 4,
Frameworks 11. **Total 191** (many repeats: author Twitter/Wikipedia links and one
spreadsheet appear several times).

Legend: Value = H/M/L/None + phase. "Roadmap" = grep of ROADMAP.md (case-insensitive).
PDF rows marked "PDF, not fetched": WebFetch saves binary PDFs to disk, which the brief
forbids, so the landing page or the Archive copy was checked instead where one exists.

---

### CTI-fundamentals README (109 links)

#### CTI Theory

| # | Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|---|
| 1 | [The US Central Intelligence Agency](https://en.wikipedia.org/wiki/Central_Intelligence_Agency) | Wikipedia author link | CC BY-SA (Wikipedia) | live | none | None | no |
| 2 | [the-intelligence-cycle.html](https://web.archive.org/web/20200508151219/https://www.cia.gov/kids-page/6-12th-grade/who-we-are-what-we-do/the-intelligence-cycle.html) | Archived CIA intelligence-cycle explainer | n/a | archive copy, 2020 | none | L Ph10 | no |
| 3 | [The US Central Intelligence Agency](https://en.wikipedia.org/wiki/Central_Intelligence_Agency) | dup of #1 | - | - | - | None | no |
| 4 | [Tradecraft-Primer-apr09.pdf](https://www.cia.gov/resources/csi/books-monographs/a-tradecraft-primer/) | CIA "A Tradecraft Primer: Structured Analytic Techniques" (2009), landing + PDF | US Gov work | live, static | none | M Ph9 (SAT method) | partly (ACH, ICD 203 in Ph9) |
| 5 | [The US Central Intelligence Agency](https://en.wikipedia.org/wiki/Central_Intelligence_Agency) | dup of #1 | - | - | - | None | no |
| 6 | [Psychology_of_Intelligence_Analysis.pdf](https://www.ialeia.org/docs/Psychology_of_Intelligence_Analysis.pdf) | Heuer, Psychology of Intelligence Analysis (214-page scanned PDF); ACH origin | US Gov work | live | none | M Ph9 (ACH method) | partly (hypotheses board) |
| 7 | [iSIGHT Partners](https://www.linkedin.com/company/isight-partners) | LinkedIn page of defunct vendor | n/a | 403 | none | None | no |
| 8 | [cti-guide.pdf](https://cryptome.org/2015/09/cti-guide.pdf) | iSIGHT CTI guide (2015), image-only PDF | unclear | live | none | L Ph10 | no |
| 9 | [Recorded Future](https://recordedfuture.com) | Vendor homepage | n/a (service) | live | paid only | None | no |
| 10 | [What the 6 Phases of the Threat Intelligence Lifecycle Mean for Your Team](https://web.archive.org/web/20210330021716/https://www.recordedfuture.com/threat-intelligence-lifecycle-phases/) | Archived RF lifecycle blog | n/a | archive copy | none | L Ph10 | no |
| 11 | [SANS](https://www.sans.org/) | Training vendor homepage | n/a | live | none | None | no |
| 12 | [The Industrial Control System Cyber Kill Chain](https://github.com/curated-intel/CTI-fundamentals/blob/main/Archive/SANS%20-%20ICS%20Kill%20Chain%20-%20Whitepaper.pdf) | SANS ICS Kill Chain whitepaper, repo copy (4 MB) | unclear (mirror) | static | none | L Ph9 | no |
| 13 | [Mercyhurst University Institute for Intelligence Studies](https://en.wikipedia.org/wiki/Mercyhurst_University_Institute_for_Intelligence_Studies) | Wikipedia author link | CC BY-SA | live | none | None | no |
| 14 | [analysts_style_manual.pdf](https://ncirc.bja.ojp.gov/sites/g/files/xyckuh326/files/media/document/analysts_style_manual.pdf) | Mercyhurst Analyst's Style Manual; copy in Archive | unclear | PDF, not fetched | none | L Ph9/Ph10 (writing style) | no |
| 15 | [Freddy M](https://no.linkedin.com/in/fmurre?trk=pulse-article_main-author-card) | LinkedIn profile | n/a | HTTP 999 | none | None | no |
| 16 | [intelligence-architecture-map-freddy-m](https://www.linkedin.com/pulse/intelligence-architecture-map-freddy-m/) | Mind map of a CTI function (2021-03-20) | n/a | live | none | L Ph10 | no |
| 17 | [Grace Chi](https://twitter.com/euphoricfall) | X profile | n/a | X 402 | none | None | no |
| 18 | [ctinetworkingreport2022.pdf](https://pulsedive.com/downloads/ctinetworkingreport2022.pdf) | Pulsedive CTI networking survey 2022 | unclear | PDF, not fetched | none | None | no |
| 19 | [Institute for Software Research ... Carnegie Mellon University](https://isri.cmu.edu/) | CMU dept, now redirects to s3d.cmu.edu | n/a | redirect | none | None | no |
| 20 | [CMU-ISR-17-100.pdf](http://reports-archive.adm.cs.cmu.edu/anon/isr2017/CMU-ISR-17-100.pdf) | CMU tech report (2017) on CTI | unclear | PDF, not fetched | none | L | no |
| 21 | [RAND Corporation](https://en.wikipedia.org/wiki/RAND_Corporation) | Wikipedia author link | CC BY-SA | live | none | None | no |
| 22 | [RAND_RRA382-1.pdf](https://www.rand.org/content/dam/rand/pubs/research_reports/RRA300/RRA382-1/RAND_RRA382-1.pdf) | RAND report RRA382-1 (landing 403) | RAND terms | PDF, not fetched | none | L | no |
| 23 | [UK National Anti Fraud Network](https://www.nafn.gov.uk/) | UK public-sector fraud intel service | n/a | live | none | None | no |
| 24 | [Intelligence%20Management%20Training.pdf](https://www.local.gov.uk/sites/default/files/documents/Intelligence%20Management%20Training.pdf) | UK LGA intelligence management training | OGL likely | PDF, not fetched | none | L Ph10 | no |
| 25 | [International Journal of Intelligence and CounterIntelligence](https://www.tandfonline.com/journals/ujic20) | Journal homepage | paywalled | 403 | none | None | no |
| 26 | [Cyber Threat Intelligence: A Product Without a Process?](https://www.tandfonline.com/doi/full/10.1080/08850607.2020.1780062) | Journal article (2020); copy in Archive | publisher copyright | 403 | none | L Ph9 | no |
| 27 | [mxm0z](https://github.com/mxm0z/) | GitHub profile (Ygor Maximo) | n/a | active | none | None | no |
| 28 | [Awesome Intelligence Writing](https://github.com/mxm0z/awesome-intelligence-writing) | Curated list on intel writing | CC-BY-SA-4.0 (badge says CC0) | push 2025-12-04 | none | L Ph9 report builder, Ph10 | no |
| 29 | [threat-intelligence.eu](https://threat-intelligence.eu) | Community hub of standards and methods | CC BY | no date shown | none | L | no |
| 30 | [Standards related to Threat Intelligence](https://threat-intelligence.eu/standards/) | List: MISP formats, IODEF, IDMEF, STIX 1.x/2.0, Sigma, YARA, GENE | CC BY | stale (STIX 2.0 only) | none | L Ph8 | partly (STIX, MISP, Sigma) |
| 31 | [Joe Slowik](https://twitter.com/jfslowik) | X profile | n/a | X 402 | none | None | no |
| 32 | [dragos.com](https://www.dragos.com/wp-content/uploads/Threat-Intelligence-and-the-Limits-of-Malware-Analysis.pdf) | Slowik, limits of malware analysis paper | Dragos copyright | PDF, not fetched | none | L Ph9 | no |
| 33 | [Joe Slowik](https://twitter.com/jfslowik) | dup of #31 | - | - | - | None | no |
| 34 | [domaintools.com](https://www.domaintools.com/resources/blog/analyzing-network-infrastructure-as-composite-objects/) | Slowik 2020-11-18: indicators as composite objects | n/a | live | none | M Ph6 (pivot method) | partly (Ph6 pivots) |
| 35 | [stat.berkeley.edu](https://www.stat.berkeley.edu/~aldous/157/Papers/Tradecraft%20Primer-apr09.pdf) | Mirror of CIA Tradecraft Primer (#4) | US Gov work | PDF, not fetched | none | dup of #4 | no |
| 36 | [Juan Andrés Guerrero-Saade](https://twitter.com/juanandres_gs) | X profile | n/a | X 402 | none | None | no |
| 37 | [Guerrero-Saade-VB2015.pdf](https://media.kaspersky.com/pdf/Guerrero-Saade-VB2015.pdf) | VB2015 paper on attribution/intel ethics | Kaspersky copyright | PDF, not fetched | none | L Ph9 | no |
| 38 | [Juan Andrés Guerrero-Saade](https://twitter.com/juanandres_gs) | dup of #36 | - | - | - | None | no |
| 39 | [VB2018-Guerrero-Saade.pdf](https://www.virusbulletin.com/uploads/pdf/magazine/2018/VB2018-Guerrero-Saade.pdf) | VB2018 paper (landing page 403) | VB copyright | PDF, not fetched | none | L Ph9 | no |
| 40 | [Matt Richard](https://medium.com/@mrichard91/about) | Medium author page | n/a | 403 | none | None | no |
| 41 | [medium.com/@mrichard91](https://medium.com/@mrichard91/common-cyber-threat-intel-biases-9d6f410f5829) | "Common cyber threat intel biases" | n/a | 403 | none | L Ph9 | no |

#### CTI Frameworks

| # | Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|---|
| 42 | [John Boyd](https://en.wikipedia.org/wiki/John_Boyd_(military_strategist)) | Wikipedia author link | CC BY-SA | live | none | None | no |
| 43 | [OODA_Loop.html](https://en.wikipedia.org/wiki/OODA_loop) | OODA loop (observe, orient, decide, act) | CC BY-SA | live | none | L Ph10 | no |
| 44 | [David J. Bianco](https://twitter.com/DavidJBianco) | X profile | n/a | X 402 | none | None | no |
| 45 | [the-pyramid-of-pain.html](https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html) | Pyramid of Pain (2013, hash level added 2014): hash, IP, domain, artifacts, tools, TTPs | n/a | static | none | M Ph1/Ph9 (IOC "pain" tier label) | no |
| 46 | [diamond.pdf](https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf?adlt=strict) | Diamond Model paper (2013); landing page HTTP 500; copy in Archive | unclear | PDF, not fetched | none | M Ph9 (profile attributes) | no (Diamond appears only as an actor name) |
| 47 | [Lockheed Martin](https://en.wikipedia.org/wiki/Lockheed_Martin) | Wikipedia author link | CC BY-SA | live | none | None | no |
| 48 | [Cyber_Kill_Chain.pdf](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/Gaining_the_Advantage_Cyber_Kill_Chain.pdf) | LM "Gaining the Advantage" kill chain guide; still linked from LM page | LM copyright | live (via LM landing) | none | L Ph9 | no |
| 49 | [Lockheed Martin](https://en.wikipedia.org/wiki/Lockheed_Martin) | dup of #47 | - | - | - | None | no |
| 50 | [LM-White-Paper-Intel-Driven-Defense.pdf](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf) | Hutchins et al. intel-driven defense / CoA matrix; linked from LM page | LM copyright | live | none | L Ph9 | no |
| 51 | [attack.mitre.org](https://attack.mitre.org/) | MITRE ATT&CK (content v20.1) | ATT&CK Terms of Use (royalty-free) | active | STIX 2.1 via mitre-attack/attack-stix-data | H Ph2/Ph9 | yes, Ph2 + Ph9 |
| 52 | [mandiant.com](https://web.archive.org/web/20220217155129/https://www.mandiant.com/resources/targeted-attack-lifecycle) | Archived Mandiant targeted attack lifecycle | n/a | archive only (live site redirects to Google Cloud) | none | L | no |
| 53 | [Paul Pols](https://www.linkedin.com/in/paulpols) | LinkedIn profile | n/a | not fetched (LinkedIn 403 pattern) | none | None | no |
| 54 | [unifiedkillchain.com](https://www.unifiedkillchain.com/) | Unified Kill Chain (In, Through, Out), 2021 | GPL v2 (site footer) | static since 2021 | none (PDFs) | L-M Ph9 (TTP summary stages) | no |
| 55 | [verizon.com](https://www.verizon.com/about/news/veris-framework-enables-sharing-security-incident-data-across-globe) | VERIS press release | n/a | 404 dead | none | L Ph8 (VERIS lives on GitHub) | no |
| 56 | [ibm.com](https://www.ibm.com/downloads/cas/A27KQP8R) | IBM download (file, likely X-Force framework paper) | IBM copyright | not fetched (download) | none | None | no |

#### Threat Intelligence Seminal Research

| # | Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|---|
| 57 | [the-dark-visitor-inside-the-world-of-chinese-hackers.pdf](https://github.com/curated-intel/CTI-fundamentals/blob/main/Archive/the-dark-visitor-inside-the-world-of-chinese-hackers.pdf) | "The Dark Visitor" book, repo copy (6 MB) | unclear (mirror) | static | none | L Ph9 | no |
| 58 | [Mandiant](https://www.mandiant.com/) | Redirects to cloud.google.com Mandiant services | n/a | redirect | none | None | no |
| 59 | [mandiant-apt1-report.pdf](https://www.mandiant.com/resources/apt1-exposing-one-of-chinas-cyber-espionage-units) | APT1 report (2013) | Mandiant copyright | dead: redirects to Google Cloud sales page | none | L Ph9 (find via APTnotes) | no |
| 60 | [CrowdStrike](https://www.crowdstrike.com/) | Vendor homepage | n/a | live | none | None | no |
| 61 | [crowdstrike.com](https://www.crowdstrike.com/blog/first-ever-adversary-ranking-in-2019-global-threat-report-highlights-the-importance-of-speed/) | 2019 blog: adversary breakout-time ranking, 1-10-60 | n/a | live (2019) | none | L Ph9 | no |
| 62 | [Trevor Giffen](https://twitter.com/TrevorGiffen) | X profile | n/a | X 402 | none | None | no |
| 63 | [curatedintel.org](https://www.curatedintel.org/2021/10/initial-access-broker-landscape.html) | IAB landscape graphic v1 (2021-10-21) | n/a | static | PNG/SVG on GitHub | L Ph5 | no |
| 64 | [Trevor Giffen](https://twitter.com/TrevorGiffen) | dup of #62 | - | - | - | None | no |
| 65 | [curatedintel.org](https://www.curatedintel.org/2021/03/assessing-state-of-breached-data-search.html) | Breached-data search services compared (2021-03-21) | n/a | stale | none | L Ph3 | partly (HIBP in Ph3) |
| 66 | [William Thomas](https://twitter.com/BushidoToken) | X profile | n/a | X 402 | none | None | no |
| 67 | [curatedintel.org](https://www.curatedintel.org/2022/05/threat-group-naming-schemes-in-cyber.html) | Vendor actor-naming schemes (2022-05-20): Mandiant APT/FIN/UNC, Proofpoint TA, MS elements, etc. | n/a | static (pre-MS 2023 weather names) | none | M Ph9 (naming-pattern rules) | no |
| 68 | [William Thomas](https://twitter.com/BushidoToken) | dup of #66 | - | - | - | None | no |
| 69 | [CTI Lexicon](https://github.com/BushidoUK/CTI-Lexicon/blob/main/Lexicon.md) | CTI glossary; this file path 404s, glossary now in README.md | none | push 2025-11-27 | markdown only | L Ph10 (glossary) | no |
| 70 | [William Thomas](https://twitter.com/BushidoToken) | dup of #66 | - | - | - | None | no |
| 71 | [Curated Intel Threat Actor Profile Guide](https://github.com/curated-intel/Threat-Actor-Profile-Guide) | Actor-profile template guide (PDF + TXT) | none | push 2023-07-15 | none | M Ph9 (profile sections) | no |
| 72 | [Sarah Jones](https://twitter.com/sj94356) | X profile | n/a | X 402 | none | None | no |
| 73 | [securityandtechnology.org](https://securityandtechnology.org/wp-content/uploads/2020/07/summit_archive_1548105619.pdf) | IST summit paper (archive PDF) | unclear | PDF, not fetched | none | L | no |
| 74 | [Anastasios Pingios](https://twitter.com/xorlgr) | X profile | n/a | X 402 | none | None | no |
| 75 | [xorl.wordpress.com](https://github.com/BushidoUK/Open-source-tools-for-CTI/blob/master/Adversary%20Intelligence.md#intelligence-agency-and-security-services-internal-structure) | Anchor into BushidoUK Adversary Intelligence.md (xorl posts) | none | see AI #32-37 | - | see below | - |
| 76 | [RAND Corporation](https://en.wikipedia.org/wiki/RAND_Corporation) | dup of #21 | - | - | - | None | no |
| 77 | [RAND_RR610.pdf](https://www.rand.org/content/dam/rand/pubs/research_reports/RR600/RR610/RAND_RR610.pdf) | RAND RR610 (2014, hacker markets); landing 403 | RAND terms | PDF, not fetched | none | L Ph5 | no |
| 78 | [@Bank_Security](https://twitter.com/Bank_Security) | X profile | n/a | X 402 | none | None | no |
| 79 | [cyber-intelligence-humint-operations](https://bank-security.medium.com/cyber-intelligence-humint-operations-2d3d526e4007) | Medium post on cyber HUMINT | n/a | 403 | none | None (no engagement policy) | no |
| 80 | [MSTIC](https://twitter.com/MsftSecIntel) | X profile | n/a | X 402 | none | None | no |
| 81 | [microsoft.com](https://www.microsoft.com/security/blog/2022/05/09/ransomware-as-a-service-understanding-the-cybercrime-gig-economy-and-how-to-protect-yourself/) | MS RaaS gig-economy post (2022-05-09), DEV-#### naming | n/a | live | none | L Ph9 (affiliate vs operator) | no |
| 82 | [Google Project Zero](https://twitter.com/ProjectZeroBugs) | X profile | n/a | X 402 | none | None | no |
| 83 | [0days "In the Wild"](https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/view) | Project Zero ITW 0-day sheet; tabs 2014-2026; "Last updated 2023-04-20" note | none stated | partial render | Google Sheet | M Ph2 | yes, Ph2 (freshness noted) |
| 84 | [Katie Nickels](https://twitter.com/likethecoins) | X profile | n/a | X 402 | none | None | no |
| 85 | [Legal Documents of Interest to CTI Analysts](https://docs.google.com/spreadsheets/d/12iZfDkc-DtVNXV5ZoOiKKZuNGcsb3yQ0V3DNBQIalSo/htmlview#gid=1677585875) | Sheet of indictments/legal docs; title only rendered | unknown | not renderable | Google Sheet | M Ph9 (attribution evidence) | no |
| 86 | [Intel 471](https://intel471.com) | Vendor homepage | n/a | live | paid only | None | no |
| 87 | [Cybercrime Underground General Intelligence Requirements Handbook (CU-GIRH)](https://intel471.com/resources/cu-girh-download-request) | GIR handbook, download-request page | vendor | live; not downloaded | none | M Ph4/Ph5 (requirements taxonomy) | partly (Ph9 "intelligence requirements") |
| 88 | [InfoStealers by Hudson Rock](https://www.infostealers.com/) | Hudson Rock infostealer hub, telemetry updated 2026-11-11 | n/a (service) | active | RSS feeds (blog, reports); free lookups, no API stated | M Ph4 (feed) | yes, Ph3/Ph7 (Hudson Rock API) |
| 89 | [InfoStealers.com](https://www.infostealers.com) | dup of #88 | - | - | - | - | - |
| 90 | [Scott Small](https://twitter.com/IntelScott) | X profile | n/a | X 402 | none | None | no |
| 91 | [Cyber_Threat_Profiling_Ebook.pdf](https://github.com/curated-intel/CTI-fundamentals/blob/main/Archive/Cyber_Threat_Profiling_Ebook.pdf) | Scott Small threat-profiling ebook, repo copy (15 MB) | unclear (mirror) | static | none | L-M Ph9 | partly (Kraven profiling items) |
| 92 | [crysys.hu](https://static.crysys.hu/publications/files/tedi/ukatemicrysys_territorialdispute.pdf) | CrySyS "Territorial Dispute" (NSA SIG list) paper | academic | PDF, not fetched | none | L Ph9 | no |

#### Running Enterprise Threat Intelligence Programs

| # | Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|---|
| 93 | [CREST](https://www.crest-approved.org/) | Accreditation body homepage | n/a | live | none | None | no |
| 94 | [CREST CTI Maturity Model Assessment Tool (MMAT)](https://github.com/curated-intel/CTI-fundamentals/tree/main/Archive/CREST%20CTI%20Maturity%20Model%20Tool) | 3 xlsx: summary v1.0, intermediate v1.6, detailed v1.2 (2019) | CREST copyright (mirror) | static 2019 | xlsx | L Ph10 | no |
| 95 | [Recorded Future](https://recordedfuture.com) | dup of #9 | - | - | - | None | no |
| 96 | [The Intelligence Handbook: Fourth Edition](https://go.recordedfuture.com/hubfs/ebooks/intelligence-handbook-fourth-edition.pdf) | RF handbook; copy in Archive | RF copyright | PDF, not fetched | none | L Ph10 | no |
| 97 | [Recorded Future](https://recordedfuture.com) | dup of #9 | - | - | - | None | no |
| 98 | [The Intelligence Playbook: Practical Applications Across the Enterprise](https://go.recordedfuture.com/hubfs/The_Intelligence_Playbook_Practical_Applications_Across_the_Enterprise.pdf) | RF playbook; copy in Archive | RF copyright | PDF, not fetched | none | L | no |
| 99 | [CERT-BI](https://cert.bancaditalia.it/) | Bank of Italy CERT homepage | n/a | live | none | None | no |
| 100 | [A service architecture for an enhanced CTI capability](http://ceur-ws.org/Vol-2940/paper37.pdf) | ITASEC 2021 paper (Amato et al.), confirmed in CEUR Vol-2940 index | CEUR (usually CC BY 4.0) | static | none | L | no |
| 101 | [NCSC (UK)](https://www.ncsc.gov.uk/) | UK NCSC homepage | n/a | live | none seen | L Ph4 (source) | no |
| 102 | [Cyber Threat Intelligence in Government: A Guide for Decision Makers & Analysts](https://hodigital.blog.gov.uk/wp-content/uploads/sites/161/2020/03/Cyber-Threat-Intelligence-A-Guide-For-Decision-Makers-and-Analysts-v2.0.pdf) | UK Home Office CTI guide v2.0; copy in Archive | OGL likely | PDF, not fetched | none | L Ph10 | no |
| 103 | [Mandiant](https://www.mandiant.com/) | dup of #58 | - | - | - | None | no |
| 104 | [The Mandiant CTI Analyst Core Competencies Framework](https://www.mandiant.com/sites/default/files/2022-05/cti-analyst-core-competencies-framework-v1.pdf) | Analyst skills framework; copy in Archive (mandiant.com now redirects) | Mandiant copyright | PDF, not fetched | none | L Ph10 | no |
| 105 | [Exploring the opportunities and limitations of current Threat Intelligence Platforms](https://www.enisa.europa.eu/publications/exploring-the-opportunities-and-limitations-of-current-threat-intelligence-platforms/at_download/fullReport) | ENISA TIP report (2018-03-26); landing page checked | ENISA reuse terms | static | none | L | no |
| 106 | [sfakiana](https://github.com/sfakiana/SANS-CTI-Summit-2021) | SANS CTI Summit 2021 TIP talk refs; TIP lists | none | push 2023-11-08 | none | L | no |
| 107 | [Threat Intelligence Platform (TIP) Functional Requirements](https://github.com/sfakiana/SANS-CTI-Summit-2021/blob/main/TIP_Functional_Requirements_v1.0.xlsx) | TIP requirements xlsx (18.7 KB); did not render | none | static | xlsx | L-M Ph8/Ph9 (feature checklist) | no |
| 108 | [Mandiant](https://www.mandiant.com) | dup of #58 | - | - | - | None | no |
| 109 | [Cyber Threat Intelligence Program Maturity Assessment](https://www.mandiant.com/resources/blog/cti-program-maturity-assessment) | Mandiant blog; now redirects to Google Cloud sales page | n/a | dead | none | None | no |

---

### Adversary Intelligence.md (60 links)

| # | Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|---|
| 1 | [My own blog!](https://blog.bushidotoken.net/search/label/Tracking%20Adversaries) | BushidoToken "Tracking Adversaries" posts (latest 2025-04-02) | n/a | active blog | Blogger feed likely (not confirmed) | M Ph4 (feed) | yes, Ph6 (cited as pivot source) |
| 2 | [Mitre Group DB](https://attack.mitre.org/groups/) | ATT&CK Groups, 182 groups, content v20.1 | ATT&CK Terms of Use | active | STIX 2.1 bundles on GitHub | H Ph9 | yes, Ph9 seed |
| 3 | [CrowdStrike Adversary World](https://adversary.crowdstrike.com/) | 301 to crowdstrike.com/adversaries: 66 names (41 eCrime), names only | vendor terms | live | no export | L Ph9 (link-out) | no |
| 4 | [Dell SecureWorks Threat Profiles](https://www.secureworks.com/research/threat-profiles) | 301 to Sophos CTU threat profiles: 181 profiles, aliases with vendor, tools | no stated licence | active | RSS + "Download All Data" (format not shown) | M Ph9 | yes, Ph9 (link only) |
| 5 | [Dragos threat groups](https://www.dragos.com/threat-activity-groups/) | 404; current list at dragos.com/threat-groups/ (26 ICS groups) | vendor | link dead, list live | no export | L Ph9 | no |
| 6 | [ThaiCERT APT encyclopedia](https://www.thaicert.or.th/downloads/files/A_Threat_Actor_Encyclopedia.pdf) | Original 2019 PDF | CC BY-NC-SA | 404 dead | - | None (superseded by ETDA) | yes, Ph9 (ETDA, link only) |
| 7 | [ThaiCERT APT encyclopedia v2.0](https://www.dropbox.com/s/ds0ra0c8odwsv3m/Threat%20Group%20Cards.pdf) | Dropbox copy of v2.0 PDF (2020, "outdated now" per ETDA) | CC BY-NC-SA | stale | PDF | None | yes, Ph9 (ETDA) |
| 8 | [APTs targeting Germany](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage/Analysen-und-Prognosen/Threat-Intelligence/Aktive_APT-Gruppen/aktive-apt-gruppen_node.html) | BSI list: 26 APTs active vs Germany, aliases, WZ sectors; Stand 2026-04-14 | German gov (terms not shown) | active | HTML only | M Ph9 (gov alias + sector claims) | no |
| 9 | [Adversary Monikers](https://github.com/StrangerealIntel/EternalLiberty/blob/main/EternalLiberty.csv) | EternalLiberty: ~848 actors x 100 vendor-name columns, CSV + JSON | none | push 2025-06-05 | raw CSV/JSON | H Ph9 (vendor crosswalk) | yes, Ph9 (linked, not copied) |
| 10 | [The Russian APT Tool Matrix](https://github.com/BushidoUK/Russian-APT-Tool-Matrix) | Tools per Russian APT by category; `Tools/AllToolsRU.csv` | none | push 2025-08-20 | CSV + markdown | M Ph9 | yes, Ph9 (linked) |
| 11 | [Campaign Monitor](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections) | 4.1k-star report archive by year 2006-2024; `index.csv` (Published, SHA-1, Filename, Download URL) | none | push 2024-07-25 | 6.4 GB repo of PDFs | M Ph4/Ph9 (test corpus, index) | yes, Ph9 ("report archives") |
| 12 | [Mapping APT attacks](https://github.com/BushidoUK/Exploring-APT-campaigns) | VT Graph `.mtgl` files per campaign | none | push 2022-06-04 | needs VT Graph | L | no |
| 13 | [Adversary and Malware DB](https://malpedia.caad.fkie.fraunhofer.de/) | Malpedia; inventory updated 2026-11-09 | CC BY-NC-SA (per roadmap) | active | API, account for full data | M Ph1/Ph9 | yes, Ph1 + Ph9 |
| 14 | [Kaspersky APT list](https://apt.securelist.com/) | Kaspersky targeted-attacks logbook; table JS-loaded | vendor | live | no export | L Ph9 | no |
| 15 | [Cyber Operations Tracker](https://www.cfr.org/cyber-operations/) | CFR state-sponsored incidents since 2005 | no terms seen | live | no export; cfr-* fields reach MISP/ETDA | M Ph9 (via MISP fields) | partly (MISP galaxy) |
| 16 | [Threat Actor Map](https://aptmap.netlify.app/) | "APTMAP" title only rendered | unknown | unclear | unknown | L | no |
| 17 | [APT WORLD MAP](https://andreacristaldi.github.io/APTmap/) | APTmap: search by actor, tools, ATT&CK; repo andreacristaldi/APTmap | README says CC BY 4.0 (no LICENSE file; built on NC-SA ETDA data) | push 2026-01-31 | `apt.json` (>10 MB), `apt_rel.json` | L-M Ph9 (UI idea) | no |
| 18 | [APT Groups and Operations](https://docs.google.com/spreadsheets/u/1/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml) | Florian Roth (@cyb3rops) vendor-name crosswalk sheet; pubhtml rendered title only | CC BY 4.0 (README tab) | first release 2015; has MS 2023 renaming tab; no update date | Google Sheet, `_Download` tab | M-H Ph9 (permissive crosswalk) | no |
| 19 | [APT campaigns](https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit#gid=1864660085) | Same sheet; tabs China, Russia, NK, Iran, Israel, NATO, etc. | CC BY 4.0 | as #18 | as #18 | see #18 | no |
| 20 | [Russian APT ecosystem](https://apt-ecosystem.com/russia/map/) | Intezer/Check Point 2019 map; domain now serves casino spam | n/a | compromised/lapsed domain | do not use | None | no |
| 21 | [National Security Archive](https://embed.kumu.io/0b023bf1a971ba32510e86e8f1a38c38#apt-index) | Kumu embed; only "Kumu" title rendered | unknown | unclear | none seen | L | no |
| 22 | [Open Source Tools used by APTs](https://www.intezer.com/ost-map/) | OST map; now lands on Intezer blog index | n/a | dead | none | None | no |
| 23 | [APT Notes part I](https://github.com/1sn0m4d/APTnotes) | Fork of kbandla/APTnotes, 5 stars | none | push 2016-05-20, stale | as upstream | None | partly (APTnotes) |
| 24 | [APT Notes part II](https://github.com/aptnotes/data) | APTnotes data: `APTnotes.json`/CSV (Filename, Title, Source, Link to Box, SHA-1, Date, Year) | none | push 2024-12-16 | JSON/CSV index, PDFs on Box | M Ph4/Ph9 (report index) | yes, Ph9 (linked) |
| 25 | [APT Notes](https://github.com/kbandla/APTnotes) | Original APTnotes, README lists reports 2008-2023-12 | none | push 2024-01-01 | `APTnotes_summary.csv` | L (use aptnotes/data) | yes, Ph9 |
| 26 | [RedDrip7 APT tools](https://github.com/RedDrip7/APT_Digital_Weapon) | Qi-AnXin hashes per APT group (65 groups; hash, type, family, VT first seen, name) | GPL-3.0 | push 2026-02-28 | markdown tables | M Ph9 (hunting package) | no |
| 27 | [RedDrip7 APT map](https://ti.qianxin.com/apt/) | Qi-AnXin APT map | vendor | 403 | unknown | L | no |
| 28 | [Carnegie Endowment for International Peace](https://carnegieendowment.org/specialprojects/protectingfinancialstability/timeline) | ~200 incidents vs financial institutions since 2007; BAE data | Carnegie terms | stale (latest Apr 2022) | no export | L Ph9 | no |
| 29 | [CrowdStrike Yearly GTRs and THRs](https://www.google.co.uk/search?q=site%3Acrowdstrike.com+%22Global+Threat+Report%22%7C%22Nowhere+to+hide%22) | Google dork for CrowdStrike reports | n/a | Google blocks render | dork | L Ph4 (saved dork) | partly (Ph4 dork launcher) |
| 30 | [Mandiant Yearly M-Trends Reports](https://www.google.co.uk/search?q=site%3Amandiant.com+%22M-Trends%22) | Google dork; mandiant.com now redirects | n/a | Google blocks render | dork | L Ph4 | partly (dork launcher) |
| 31 | [Kaspersky GReAT Quarterly APT Trends Reports](https://www.google.co.uk/search?q=site%3Asecurelist.com+%22APT+trends+report%22) | Google dork for Securelist APT trends | n/a | Google blocks render | dork | L Ph4 | partly (dork launcher) |
| 32 | [China](https://xorl.wordpress.com/2021/04/20/chinese-cyber-operations-groups/) | xorl diagram: PRC agencies to APTs, v2.0 2021-06-18 | n/a | stale | image + sources | L-M Ph9 (sponsor field) | no |
| 33 | [USA](https://xorl.wordpress.com/2021/04/18/us-cyber-operations-groups/) | xorl US groups diagram, v2.5 2021-04-29 | n/a | stale | image | L Ph9 | no |
| 34 | [Russia](https://xorl.wordpress.com/2021/04/16/russias-cyber-operations-groups/) | xorl Russia diagram, v7.0 2024-09-06 | n/a | updated 2024 | image | L-M Ph9 | no |
| 35 | [Iran](https://xorl.wordpress.com/2021/05/06/iran-cyber-operations-groups/) | xorl Iran diagram, v2.0 2022-01-13 | n/a | stale | image | L Ph9 | no |
| 36 | [EU](https://xorl.wordpress.com/2021/04/28/eu-cyber-operations-groups/) | xorl EU diagram, v2.0 2021-09-07 | n/a | stale | image | L Ph9 | no |
| 37 | [North Korea](https://xorl.wordpress.com/2021/04/24/north-korea-dprk-cyber-operations-groups/) | xorl DPRK diagram, v2.2 2023-10-10 | n/a | stale | image | L Ph9 | no |
| 38 | [@ShadowChasing1](https://twitter.com/ShadowChasing1) | APT researcher on X | n/a | X 402 | none | L Ph4 (handle list) | no |
| 39 | [@Arkbird_SOLG](https://twitter.com/Arkbird_SOLG) | APT researcher on X | n/a | X 402 | none | L | no |
| 40 | [@cyberwar_15](https://twitter.com/cyberwar_15) | APT researcher on X | n/a | X 402 | none | L | no |
| 41 | [@RedDrip7](https://twitter.com/RedDrip7) | Qi-AnXin RedDrip on X | n/a | X 402 | none | L | no |
| 42 | [@AnonySecAgency](https://twitter.com/AnonySecAgency) | account on X | n/a | X 402 | none | L | no |
| 43 | [@cyber__sloth](https://twitter.com/cyber__sloth) | APT researcher on X | n/a | X 402 | none | L | no |
| 44 | [@blackorbird](https://twitter.com/blackorbird) | APT researcher on X | n/a | X 402 | none | L | no |
| 45 | [@h2jazi](https://twitter.com/h2jazi) | APT researcher on X | n/a | X 402 | none | L | no |
| 46 | [@blackorbird](https://twitter.com/blackorbird) | dup of #44 in source | n/a | X 402 | none | L | no |
| 47 | [@unpacker](https://twitter.com/unpacker) | researcher on X | n/a | X 402 | none | L | no |
| 48 | [@lazarusholic](https://twitter.com/lazarusholic) | DPRK-focused researcher on X | n/a | X 402 | none | L | no |
| 49 | [@Cyber0verload](https://x.com/Cyber0verload) | researcher on X | n/a | X 402 | none | L | no |
| 50 | [@volrant136](https://x.com/volrant136) | researcher on X | n/a | X 402 | none | L | no |
| 51 | [@k3yp0d](https://x.com/k3yp0d) | researcher on X | n/a | X 402 | none | L | no |
| 52 | [@malwrhunterteam](https://x.com/malwrhunterteam) | MalwareHunterTeam on X | n/a | X 402 | none | L | no |
| 53 | [@1ZRR4H](https://x.com/1ZRR4H) | researcher on X | n/a | X 402 | none | L | no |
| 54 | [@JAMESWT_WT](https://x.com/JAMESWT_WT) | researcher on X | n/a | X 402 | none | L | no |
| 55 | [@James_inthe_box](https://x.com/James_inthe_box) | researcher on X | n/a | X 402 | none | L | no |
| 56 | [@TLP_R3D](https://x.com/TLP_R3D) | researcher on X | n/a | X 402 | none | L | no |
| 57 | [@ShanHolo](https://x.com/ShanHolo) | researcher on X | n/a | X 402 | none | L | no |
| 58 | [Are you an APT target?](https://lab52.io/) | Lab52 (S2 Grupo) research blog | n/a | fetch failed twice (socket closed) | unknown | L Ph4 | no |
| 59 | [APT Member Legal Indictments](https://docs.google.com/spreadsheets/d/12iZfDkc-DtVNXV5ZoOiKKZuNGcsb3yQ0V3DNBQIalSo/htmlview#gid=1677585875) | Same sheet as README #85 | unknown | not renderable | Google Sheet | M Ph9 | no |
| 60 | [VX-UNDERGROUND APT samples](https://vx-underground.org/samples/Families/APT/) | vx-underground APT sample/paper tree | n/a | 403 | samples (not fetched) | None (policy) | yes, decisions log: linked, never ingested |

---

### Monthly_CTI_Reports.md (7 links)

| # | Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|---|
| 1 | [RedCanary](https://redcanary.com/blog/page/2/?search=Insights&topic=threat-intelligence) | Red Canary monthly Intelligence Insights; redirects to zscaler.com/blogs (Zscaler bought Red Canary) | n/a | link dead; no Insights on Zscaler page | no RSS seen | L Ph4 | no |
| 2 | [Nextron Systems](https://www.nextron-systems.com/?s=Tales+of+Valhalla) | "Tales of Valhalla" YARA/hunting digest; latest found 2024-03-05 | n/a | stale | WordPress site | L Ph4 | no |
| 3 | [WithSecure](https://www.withsecure.com/en/expertise/research-and-innovation/research/monthly-threat-highlights-report) | Now generic W/Labs listing with "Not Found" notice; no monthly report | n/a | moved/dead | none | L Ph4 (W/Labs blog) | no |
| 4 | [Cyware](https://cyware.com/resources/threat-briefings/monthly-threat-briefing/) | Monthly threat briefing | n/a | 404 dead (briefings index JS-only) | none | None | no |
| 5 | [Rewterz](https://www.rewterz.com/monthly-threat-insights/) | Monthly threat insights | n/a | 404 dead (site has threat-advisories, annual report) | none | L Ph4 | no |
| 6 | [NCC Group](https://www.nccgroup.com/resource-hub/cyber-threat-intelligence-reports/) | NCC monthly Threat Pulse/Intelligence report; latest Q3 2026 review, Aug 2026 monthly | n/a | active | PDF via insights.nccgroup.com (gating unclear) | M Ph4 (ransomware monthly stats) | no |
| 7 | [SentinelOne](https://www.google.co.uk/search?q=site%3Asentinelone.com+intitle%3A%22Cybercrime+Update+%7C%22) | Google dork for SentinelOne "Cybercrime Update" | n/a | Google blocks render | dork | L Ph4 | partly (dork launcher) |

---

### CTI_Reporting.md (4 links)

| # | Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|---|
| 1 | [ThreatNote](https://threatnote.io/) | Former CTI management tool; 308 to morado.io (commercial TI platform) | n/a | dead as listed | none | None | no |
| 2 | [Fabric](https://blackstork.io/fabric/) | BlackStork Fabric: Go CLI, HCL templates to Markdown/HTML/PDF; MISP, OpenCTI, VT plugins. Page 404, repo live | BSL 1.1 (to Apache-2.0 per release) | repo push 2026-11-03 | CLI, plugins | L-M Ph8/Ph9 (method only) | no |
| 3 | [Curated Intel Threat Actor Profile Guide](https://github.com/curated-intel/Threat-Actor-Profile-Guide) | Same as README #71 | none | push 2023-07-15 | PDF/TXT | M Ph9 | no |
| 4 | [The CTI Analyst Challenge](https://github.com/BushidoUK/CTI-Analyst-Challenge) | Junior analyst exercise: PIR report or RFI response, templates | none | push 2024-07-03 | markdown templates | L Ph10 | no |

---

### Frameworks.md (11 links; not linked from the BushidoUK README)

| # | Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|---|
| 1 | [CLOAK](https://github.com/Mickinthemiddle/CLOAK) | ATT&CK-style KB of criminal concealment/OPSEC: 13 tactics, 109 techniques, 1,387 TTPs | GPL-2.0 | push 2026-10-25 | `concealment-data.json` | M Ph5/Ph9 | no |
| 2 | [Insider Threat Matrix](https://insiderthreatmatrix.org/) | Forscie insider-threat framework, 882 objects; repo forscie/insider-threat-matrix | Apache-2.0 (repo) | push 2026-11-09 | `insider-threat-matrix.json` | M Ph9 (insider archetype) | partly (insider archetype only) |
| 3 | [Fraud Neuron (Axur)](https://blog.axur.com/en-us/fraud-neuron-axur-framework) | Fraud modelling framework (2025-04-11), explorer + repo axur/FraudNeuron | none (repo) | repo push 2025-08-29, 4 stars | unclear | L Ph3 | no |
| 4 | [Wiz Threats](https://threats.wiz.io/all-techniques) | Wiz cloud threat landscape: techniques, actors, incidents | not stated | updated 2025-04-03 | RSS + STIX JSON feed (wiz.io/feed/cloud-threats-landscape/stix.json) | M Ph4/Ph9 (cloud actors) | no |
| 5 | [DISARM Framework](https://www.disarm.foundation/framework) | Influence-operations TTP framework (ATT&CK-like) | CC-BY-SA-4.0 | repo push 2026-03-28 | DISARMframeworks repo (generated files) | M Ph4/Ph9 | partly (influence ops as Ph4 keyword) |
| 6 | [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/) | Enterprise matrix v20, 15 tactics | ATT&CK ToU | active | STIX 2.1 | H Ph2/Ph9 | yes |
| 7 | [MITRE ATT&CK Mobile](https://attack.mitre.org/matrices/mobile/) | Mobile matrix v20, 12 tactics | ATT&CK ToU | active | STIX 2.1 | M Ph2/Ph9 | yes (ID validation, matrix tab) |
| 8 | [MITRE ATT&CK ICS](https://attack.mitre.org/matrices/ics/) | ICS matrix v20, 12 tactics | ATT&CK ToU | active | STIX 2.1 | M Ph2/Ph9 | yes |
| 9 | [MITRE ATLAS](https://atlas.mitre.org) | AI-system attack matrix; only title rendered | atlas-data: NOASSERTION | atlas-data push 2026-10-28 | mitre-atlas/atlas-data | M Ph2/Ph4/Ph9 | yes, Ph2 + Ph4 + Ph9 |
| 10 | [MITRE D3FEND](https://d3fend.mitre.org) | Countermeasure knowledge graph v1.6.0, mapped to ATT&CK/ATLAS | MITRE ToU | active | API/OWL not confirmed on page | M Ph9 (Defend tab) | no |
| 11 | [MITRE Engage](https://engage.mitre.org/matrix/) | Adversary engagement/deception matrix | MITRE ToU | 403 | unknown | L | no |

---

### High-value notes

**MITRE ATT&CK (README #51, AI #2, Frameworks #6-8). H, Ph2/Ph9, already planned.**
Live site shows content v20.1, 182 groups, Enterprise 15 tactics. Data: STIX 2.1 bundles
in mitre-attack/attack-stix-data (`enterprise-attack/enterprise-attack.json` always
latest, versioned files beside it, `index.json` collection index). Fetch at runtime into
the data dir, record version and SHA-256 as the roadmap already says. Nothing new to add.

**EternalLiberty (AI #9). H, Ph9 alias table, roadmap lists it as "linked, not copied".**
The richest machine-readable vendor crosswalk in this set: about 848 rows, header
`Threat Actor Official Name, Confidence, Type, Country` then 100 vendor columns
(Mandiant/FireEye, Proofpoint, Kaspersky, CrowdStrike, Microsoft, MITRE, ... Google TAG,
NSFOCUS). Aliases inside a cell are `/`-separated (sometimes ` / `). Confidence is
High/Mid/Low/Unknown. JSON twin `EternalLiberty.json`. Each cell is a vendor-attributed
claim ("Microsoft calls FIN11 Lace Tempest"), which is what MISP lacks. No licence, so
fetch at runtime from raw.githubusercontent.com and store as "source: EternalLiberty"
single-source claims (never vendored, never auto-merged). Last push 2025-06-05, so newer
actors are missing. Keyless, no rate limit beyond GitHub raw.

**APT Groups and Operations sheet, Florian Roth (AI #18-19). M-H, Ph9, not in roadmap.**
The README tab states CC BY 4.0, which makes it a permissively licensed vendor
crosswalk. That contradicts the roadmap note that MISP `name-attribution` is the only
one found. Tabs by origin (China, Russia, North Korea, Iran, Israel, NATO, Middle East,
Others, Unknown) plus `_Download`, `_Taxonomies`, `_Malware`, `_Sources`, and a
"Microsoft 2023 renaming taxonomy" tab. WebFetch could not render the grid, so column
layout and freshness are unconfirmed. It is probably stale beyond 2023. Next step: the
operator opens it in a browser, checks the last-edited date and the `_Download` tab, and
then decides whether a one-off CSV export goes in as a dated claim source (CC BY 4.0
allows storing it with attribution).

**ETDA Threat Group Cards MISP export (AI #6-7 lead here). M, Ph9, roadmap: link only.**
The ThaiCERT PDF links are dead (404) or stale. The live site apt.etda.or.th offers
machine-readable exports: `/cgi-bin/getmisp.cgi?o=g` (actors, about 2.1 MB MISP cluster
JSON) and `?o=t` (tools), plus galaxy header files `/misp/tgc-actors.json` and
`/misp/tgc-tools.json`. Cluster `version` is `20250816`, author "Martijn van der Heide
(ThaiCERT)". Each value has `meta.synonyms`, `country`, `motivation`, `date`,
`attribution-confidence`, `cfr-target-category`, `cfr-suspected-victims`,
`cfr-suspected-state-sponsor`, `refs`, and `related` (`uses`, `overlaps`, `similar`) to
tool UUIDs. The same parser as the MISP galaxy would read it. Licence CC BY-NC-SA 4.0.
The roadmap decision (2026-11-06) is "linked, never stored", and that still holds. If
it is revisited, a runtime fetch for a local non-commercial tool fits NC, and SA matters
only if the data is redistributed. The listing page shows about 450+ groups.

**Sophos CTU threat profiles (AI #4, via the Secureworks redirect). M, Ph9, roadmap: link only.**
181 profiles with Name, Location, Objectives, Aliases (vendor in parentheses), Tools.
The page offers an RSS feed and "Download All Data", but the format and terms were not
visible to WebFetch. Worth one manual check: if the download is CSV/JSON, it is a good
vendor-attributed alias source. Without a stated licence it stays runtime-only.

**BSI "Aktive APT-Gruppen" (AI #8). M, Ph9, not in roadmap.**
A government source: 26 groups (plus 3 under observation: APT30, APT31, Gallium), with
slash-separated aliases, WZ 2008 sectors, and notes. "Stand: 14.04.2026". HTML only.
Use: hand-re-keyed alias and sector claims with source "BSI" (plain facts), and a
"targets Germany" regional tag. A useful independent second source for two-source
alias attachment.

**APTnotes (AI #23-25) and CyberMonitor (AI #11). M, Ph4/Ph9 test corpus, roadmap: linked.**
aptnotes/data: `APTnotes.json`/`APTnotes.csv` with `Filename, Title, Source, Link (Box),
SHA-1, Date (MM/DD/YYYY), Year`. PDFs are on Box, not in git. Last push 2024-12-16. No
licence. CyberMonitor `index.csv` has `Published, SHA-1, Filename, Download URL` (PDFs in
the 6.4 GB repo), last push 2024-07-25, no licence. Use both as a runtime-read index (title,
vendor, date, URL) for the Ph9 Reporting tab and as a parser test set alongside the
already-parked CZLi/apt-reports. Never vendor the PDFs. 1sn0m4d/APTnotes is a stale 2016
fork: skip it.

**RedDrip7 APT_Digital_Weapon (AI #26). M, Ph9 hunting package, not in roadmap.**
GPL-3.0, active (push 2026-02-28), 65 group folders of markdown tables
`Hash (MD5, VT link) | Type | Family | First_Seen | Name`. Use: runtime fetch for "known
hashes attributed by Qi-AnXin" on an actor's Capability tab and as a Phase 1 hash-context
hit ("listed by RedDrip7 under APT-C-xx"). GPL means never vendored. Qi-AnXin uses its
own APT-C-NN names, which become alias claims.

**Threat Actor Profile Guide (README #71, Reporting #3). M, Ph9 method.**
Sections: Foreword, Executive Summary, About (alias table, attribution, type,
sophistication), Targets, Diamond Model attributes (adversary, victim, capability,
infrastructure), TTPs (UKC In/Through/Out summary plus an ATT&CK table of ID,
description, observable, source), References with reliability footnotes. Take the
method: the Diamond block and the "observable" column map onto the planned Ph9 profile
tabs. Add it as a second export shape beside CTI Blueprints. No licence, so do not copy
its text.

**Insider Threat Matrix (Frameworks #2). M, Ph9.** Apache-2.0, single
`insider-threat-matrix.json` (articles, sections, sub-sections, preventions, detections;
prefixes MT/ME/PR/IF/AF), active (2026-11-09), plus a synthetic-insider twin repo. It can be
vendored. It fits the "insider" archetype already in the Ph9 header fields and the
in-app matrix view.

**DISARM (Frameworks #5), Wiz (Frameworks #4), CLOAK (Frameworks #1). M.**
DISARM: CC BY-SA 4.0, master data in DISARMFoundation/DISARMframeworks (push
2026-03-28), so it could be an extra matrix tab and a Ph4 "influence ops" category
(SA applies if redistributed). Wiz: STIX JSON feed at
`wiz.io/feed/cloud-threats-landscape/stix.json` plus RSS. There are no stated terms, so
treat it as runtime-only, for a Ph4 feed and Ph9 cloud-actor context. CLOAK: GPL-2.0
`concealment-data.json`, an ATT&CK-shaped OPSEC taxonomy of criminal concealment (13
tactics, 1,387 TTPs). Runtime-only; useful vocabulary for Ph5 dark-web keyword
categories and Ph9 persona/OPSEC evidence.

**D3FEND (Frameworks #10). M, Ph9 Defend tab, not in roadmap.** KG v1.6.0, maps
countermeasures to ATT&CK, ICS, Mobile, and ATLAS techniques. The page did not confirm
download formats or the API, so check them when Ph9 is built. It is a candidate source for "mitigations
for this actor's techniques" beside ATT&CK mitigations.

**Vendor naming schemes (README #67). M, Ph9 method.** Deterministic name-pattern
rules (Mandiant `APT\d+|FIN\d+|UNC\d+`, Proofpoint `TA\d+`, IBM `ITG\d+|Hive\d+`,
Microsoft elements/`DEV-\d+` then 2023 weather names, Secureworks colour+word,
CrowdStrike animal suffix, Dragos minerals, Symantec insects, RF colour+phonetic) let the
Ph2 extractor flag a probable actor name, and its likely vendor, even before the alias table knows it. Small,
testable, no data dependency.

**NCC Group monthly threat report (Monthly #6). M, Ph4.** The only live monthly series in
that file (August 2026 monthly, Q3 2026 review). PDF via insights.nccgroup.com, and the
gating is unclear. Add the hub page to the Ph4 source list as an HTML-scrape source. The
other six monthly links are dead, moved, or Google dorks.

**Reference only (methods for Ph9 rigor):** CIA Tradecraft Primer (#4) and Heuer
(#6) back the planned hypotheses board and devil's-advocacy items. Pyramid of Pain (#45)
can label every IOC type with its pain tier in Ph1/Ph9 output: a one-line lookup table.
Diamond Model (#46) and the Unified Kill Chain (#54, GPL v2) supply profile structure.

(Links not checked: see appendix.)

---

## Part E: SecurityNews, CERTs, Collections

Checked 2026-11-11 with WebFetch. Feed URLs below were fetched directly and
confirmed to parse as RSS/Atom unless marked "not verified". Total links: 41
(SecurityNews 19, CERTs 6, Collections 16). The "Home" link appears in both
CERTs and Collections and is the same URL, so there are 40 distinct URLs.

### SecurityNews.md (19 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Vendor Blogs & Other Sites](https://start.me/p/rxr5Nm/incident-reports) | start.me bookmark page of incident-report sources | n/a (service) | Unknown (HTTP 403 to fetcher) | None seen; start.me has no public export | M Ph4 (seed list for feed curation, manual) | no |
| [Europol's Investigations](https://www.europol.europa.eu/media-press/newsroom?type=209&type=210&area=336&area=338&area=521) | Europol newsroom, filtered to cybercrime ops (JS app) | n/a (service) | Yes (site live) | RSS `https://www.europol.europa.eu/rss.xml` (all news, 10 items, no pubDate, no cyber filter) | M Ph4 (law-enforcement takedowns; keyword-filter) | no |
| [The Cyber Wire daily briefing](https://thecyberwire.com/newsletters/daily-briefing) | N2K CyberWire daily newsletter archive | n/a (service) | Yes, issue 2026-11-09 | RSS `https://thecyberwire.com/feeds/rss.xml` (podcast feed, 40 items, some broken media URLs); newsletter by email | M Ph4 | no |
| [FBI IC3 Newsletter](https://delivery.fbi.gov/subscribe) | FBI GovDelivery email signup | n/a (service) | Unknown (HTTP 403) | Email only here; use IC3 RSS instead: `https://www.ic3.gov/PSA/RSS` (verified, latest 2026-10-23) and `https://www.ic3.gov/CSA/RSS` (linked, not verified) | H Ph4 via IC3 RSS (signup link itself L) | no |
| [Department of Justice](https://public.govdelivery.com/accounts/USDOJ/subscriber/new) | DOJ GovDelivery email signup | n/a (service) | Yes (form live) | Email; RSS `https://www.justice.gov/news/rss` (all DOJ/USAO press, needs cyber keyword filter) | M Ph4 (indictments, takedowns) | no (newsletter ingestion idea Ph4) |
| [RiskyBiz](https://news.risky.biz/) | Risky Business newsletters (Risky Bulletin, Seriously Risky Biz) | n/a (service) | Yes, 2026-11-11 | RSS `https://news.risky.biz/rss/` (Ghost, full text, ~1.1 MB) | H Ph4 | no |
| [NewsNow Security](https://www.newsnow.co.uk/h/Industry+Sectors/Information+Technology/Security) | Headline aggregator page | n/a (service) | Yes (live) | No public RSS found (`?type=rss` returns HTML); scraping a commercial aggregator: avoid | L Ph4 | no |
| [Full Disclosure](https://seclists.org/fulldisclosure/) | Nmap seclists mailing list archive (vuln advisories) | n/a (list archive) | Yes, post 2026-11-05 | RSS `https://seclists.org/rss/fulldisclosure.rss` (15 items) | H Ph4 + Ph2 (advisories carry CVE IDs) | no |
| [DataBreaches.net](https://www.databreaches.net/news/) | Breach news blog (Dissent Doe) | n/a (service) | Yes, 2026-11-11 (page 403, feed OK) | RSS `https://www.databreaches.net/feed/` (10 items) | H Ph4 + Ph3 (victim/org mentions) | no |
| [Daily Cyber Digest (Silobreaker)](https://www.silobreaker.com/tag/daily-cyber-digest/) | Tag page now lands on Silobreaker product page; digest discontinued | n/a (vendor) | Digest dead; blog live 2026-11-11 | Blog RSS `https://www.silobreaker.com/feed/` (no digest items) | None (digest gone); blog L Ph4 | no |
| [Bleeping Computer](https://www.bleepingcomputer.com/) | Security news site | n/a; "All Rights Reserved" | Yes, 2026-11-11 | RSS `https://www.bleepingcomputer.com/feed/` (15 items) | H Ph4 | no |
| [The Record](https://therecord.media/) | Recorded Future News site | n/a (service) | Yes, 2026-11-11 | RSS `https://therecord.media/feed/` (only 5 items: poll often) | H Ph4 | no |
| [CyberScoop](https://cyberscoop.com/) | Policy and gov-focused security news | n/a (service) | Yes, 2026-11-10 | RSS `https://cyberscoop.com/feed/` (WordPress, 10 items; not linked on page) | M Ph4 | no |
| [The Hacker News](https://thehackernews.com/) | Security news site | n/a (service) | Yes, 2026-11-11 | RSS `https://feeds.feedburner.com/TheHackersNews` (50 items) | H Ph4 | no |
| [The Register](https://www.theregister.com/) | Tech news, Security section | n/a (service) | Yes, 2026-11-11 | Atom `https://www.theregister.com/security/headlines.atom` (302 to api.theregister.com RSS, security tag, 20+ items) | M Ph4 | no |
| [Android Malware Telegram](https://t.me/s/androidMalware) | Public channel "Android Security & Malware", 44.5K subs | n/a | Yes (post #3003, ~Oct/Nov 2026) | t.me/s web preview (HTML, keyless); no RSS | M Ph5 (t.me/s poller) + Ph4 mobile topic | yes, Ph5 t.me/s poller (generic) |
| [cKure InfoSec News](https://telegram.me/s/cKure) | Public channel, 7.3K subs, self-described as AI-bot (n8n) run | n/a | Yes (several posts/hour) | t.me/s preview HTML | L Ph5 (re-posts of mainstream news; noise) | yes, Ph5 t.me/s poller (generic) |
| [News Fusion](https://www.newsfusion.com/cyber-security) | Promo page for a mobile news app | n/a | Likely abandoned (footer (c) 2014) | None | None | no |
| [About:Intel](https://www.aboutintel.com) | Portal; page shows only "AboutIntel / Know what matters" (JS app) | n/a | Unclear (/about 404) | None visible; membership needed per list text | L (unverifiable) | no |

Note: the raw file has 19 links (2 collections, 4 email, 4 RSS, 5 news
sites, 3 app, 1 portal). The first link-listing pass reported "22", which was
a counting error by the fetch model; the raw text was re-read to confirm 19.

### CERTs.md (6 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [US CISA](https://www.us-cert.gov/ncas/alerts) | Old US-CERT URL; 301 to cisa.gov alerts and advisories (5,115 items) | US gov (public domain) | Yes, 2026-11-10 | RSS `https://www.cisa.gov/cybersecurity-advisories/all.xml` (all advisories, ~880 KB); feed index at cisa.gov/subscribe-updates-cisa | H Ph4 + Ph2 (advisory text for TTP extraction) | partly: CISA KEV/CSAF/SSVC Ph2, CISA advisories as extraction input |
| [Australia AusCERT](https://www.auscert.org.au/resources/security-bulletins/) | AusCERT ESB bulletins; old path 404, now portal.auscert.org.au/bulletins/ | n/a (service) | Yes, 2026-11-12 | No RSS seen; full bulletins "Members Only" | L Ph4 (titles only; members-only) | no |
| [Canada CERT (CCCS)](https://cyber.gc.ca/en/alerts-advisories) | Canadian Centre for Cyber Security alerts and advisories | Gov of Canada terms (not checked) | Yes, 2026-11-09 | Atom `https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en` (42+ entries); listing page exceeded 10 MB fetch cap | H Ph4 + Ph2 (vendor advisory roll-ups with CVEs) | no |
| [UK NCSC](https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports?q=&defaultTypes=report&sort=date%2Bdesc&start=0&rows=20) | NCSC threat reports listing (JS) | Likely OGL (not stated on page) | Yes, 2026-11-03 | RSS `https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml` (20 items) | M-H Ph4 + Ph9 | partly: NCSC-UK MAR STIX in Ph2 extraction notes |
| [Hong Kong HKCERT](https://www.hkcert.org/security-bulletin) | HKCERT security bulletins (648 pages), risk levels, "exploited" flags | n/a (copyright page linked) | Yes, 2026-11-11 | RSS `https://www.hkcert.org/getrss/security-bulletin` (20 items, duplicate description tags); news `https://www.hkcert.org/getrss/security-news` (not verified) | M Ph4 + Ph2 (patch-day roll-up, exploited notes) | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Old URL of BushidoUK/Open-source-tools-for-CTI (redirects) | None (no LICENSE) | Yes, last push 2026-02-08 | Markdown lists | Reference only (the source list itself) | n/a |

### Collections.md (16 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Threat Intel Dashboard](https://start.me/p/ELY5By/technical-sources) | start.me bookmark dashboard of technical CTI sources | n/a (service) | Unknown (HTTP 403) | Not machine-readable (no export seen) | M Ph4/Ph7 (manual seed list) | no |
| [OSINT Dashboard](https://start.me/p/wMxOjN/osint) | start.me OSINT bookmark dashboard | n/a (service) | Unknown (HTTP 403) | Not machine-readable | L Ph7 | no |
| [EDR Bypasses](https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/) | Blog post on EDR evasion (S3cur3Th1sSh1t) | Not stated | Static, 2021-01-31 | None | L Ph9 (background reading) | no |
| [Red Team Pentest Guide (TJ-JPT)](https://github.com/tjnull/TJ-JPT) | Joplin pentest note template | GPL-3.0 | Last push 2024-09-04 | .jex / markdown | None (offensive template) | no |
| [SecLists](https://github.com/danielmiessler/SecLists) | Security testing wordlists (passwords, web shells, payloads, patterns) | MIT | Active, push 2026-11-11 | Plain text files | L Ph3/Ph8 (Pattern-Matching lists for leak scanning; AV false positives if vendored) | no |
| [Shodan Queries](https://github.com/jakejarvis/awesome-shodan-queries) | ~75 curated Shodan queries (ICS, network infra, etc.) | CC0-1.0 | Last push 2024-05-27 | Markdown code blocks | M Ph6 (seed the saved-hunt library; CC0 so copyable) | partly: Ph6 saved Shodan hunts |
| [Google Dorks](https://github.com/WilliamThomas-sec/google_dork_list) | Dork list repo | Unknown | Dead: 404 (also 404 under BushidoUK) | n/a | None (gone) | dork launcher Ph4 (generic) |
| [APT Activity (CyberMonitor)](https://github.com/CyberMonitor/APT_CyberCriminal_Campagin_Collections) | Archive of APT/crime report PDFs by year 2006-2024 (6.4 GB) | None (no licence) | Last push 2024-07-25 | `index.csv` (Published, SHA-1, Filename, Download URL); README links to originals | M Ph9 (historical report index; link only) | yes, Ph9 "the report archives are linked, not copied" |
| [OSINT Tools (awesome-osint)](https://github.com/jivoi/awesome-osint) | Large curated OSINT list incl. News and Threat Intel sections | CC BY-SA 4.0 | Active, push 2026-11-08 | Markdown only | M Ph7 (+Ph4 "News" section as feed candidates) | no |
| [CTI & OSINT Resources (Sky analyst)](https://docs.google.com/spreadsheets/d/1klugQqw6POlBtuzon8S0b18-gpsDwX-5OYRrB7TyNEw/htmlview) | Google Sheet; title "AaronCTI's OSINT Resource Collection" | Unknown | Unknown (did not render) | Sheet (CSV export possible in principle; not checked) | L (unverified) | no |
| [TraceLabs OSINT Tools](https://www.tracelabs.org/resources/tools/) | TraceLabs OSINT tools list | n/a | Unknown (HTTP 403) | Unknown | L Ph7 | no |
| [MITRE ATT&CK](https://attack.mitre.org/) | ATT&CK knowledge base, content v20.1 | ATT&CK terms of use (free, trademark notice) | Active | STIX 2.1 `github.com/mitre-attack/attack-stix-data`, TAXII 2.1, Excel per version | H Ph2 + Ph9 | yes, Ph2 extraction and Ph9 dataset |
| [ATT&CK Navigator](https://github.com/mitre-attack/attack-navigator) | Matrix annotation web app (layers JSON) | Apache-2.0 | Active, push 2026-11-11 | Layer JSON format | M Ph9 (export layer format) | yes, Ph9 Navigator layer export |
| [ATT&CK Navigator web app](https://mitre-attack.github.io/attack-navigator/enterprise/) | Hosted Navigator; old path redirects to `/attack-navigator/` | Apache-2.0 | Active | Imports layer JSON | L Ph9 (link target for exported layers) | yes, Ph9 |
| [This Week in OSINT](https://medium.com/week-in-osint) | Sector035's weekly OSINT newsletter on Medium | n/a | Moved off Medium Aug 2020 (feed last item "Week in OSINT has moved!") | RSS `https://medium.com/feed/week-in-osint` (stale) | L Ph7 (new home not checked) | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Same as CERTs Home (BushidoUK/Open-source-tools-for-CTI) | None | push 2026-02-08 | Markdown | Reference only | n/a |

### High-value notes

- **Phase 4 starter feed list (all keyless, verified RSS/Atom 2026-11-11).** Integrate as feedparser sources:
  `https://www.bleepingcomputer.com/feed/`, `https://therecord.media/feed/`,
  `https://feeds.feedburner.com/TheHackersNews`, `https://cyberscoop.com/feed/`,
  `https://www.theregister.com/security/headlines.atom` (302 to an api.theregister.com RSS URL: follow redirects),
  `https://news.risky.biz/rss/`, `https://www.databreaches.net/feed/`,
  `https://seclists.org/rss/fulldisclosure.rss`. All are copyrighted news: store
  title, link, date, and summary for local search; do not republish full text.
  The Record keeps only 5 items, so poll it more often (hourly) or items are missed.
  Risky.biz returns about 1.1 MB of full text: fine for local storage, but use
  conditional GET (ETag/If-Modified-Since).
- **CERT feeds (gov, keyless).** CISA `https://www.cisa.gov/cybersecurity-advisories/all.xml`
  (US public domain; ~880 KB, so conditional GET), CCCS Atom
  `https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en`,
  NCSC UK `https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml`,
  HKCERT `https://www.hkcert.org/getrss/security-bulletin` (malformed: two
  description elements per item; feedparser tolerates it). Use in Ph4 as the
  "CERT" category and in Ph2: CISA advisories feed the existing ATT&CK-table
  extractor; CCCS/HKCERT roll-ups carry CVE IDs and "exploited" notes for the
  Ph2 news-mention signal.
- **IC3 (replaces the FBI email signup).** `https://www.ic3.gov/PSA/RSS` (verified,
  5 items, missing channel description) and `https://www.ic3.gov/CSA/RSS`
  (linked, not fetched). US gov. Ph4 CERT/LE category. DOJ press
  `https://www.justice.gov/news/rss` and Europol `https://www.europol.europa.eu/rss.xml`
  are broad; route them through the Ph4 keyword matcher (ransomware, botnet,
  computer intrusion, cybercrime) before showing. Europol items have no pubDate,
  so record first-seen time instead.
- **Full Disclosure** is also a Ph2 source: advisories (SEC Consult etc.) name
  CVEs before NVD enrichment; link via the CVE regex already in Ph2 extraction.
- **MITRE ATT&CK (already planned).** STIX 2.1 from
  github.com/mitre-attack/attack-stix-data, current content v20.1; Navigator
  (Apache-2.0) defines the layer JSON the Ph9 export should match. Nothing new
  beyond confirming the version.
- **Notable Medium.** CyberMonitor `index.csv` gives a dated, hashed index of
  roughly 1,800 historical APT reports (estimate from file size; rows seen run
to 2015 in the first quarter of the file) (no licence: fetch the CSV at runtime or
  link, do not vendor; repo is 6.4 GB, never clone). awesome-shodan-queries is
  CC0, so its ~75 queries can be re-keyed into the Ph6 saved-hunt library with
  attribution as courtesy. awesome-osint is CC BY-SA 4.0 (share-alike: link or
  re-key facts, do not copy the list into the repo). Telegram
  @androidMalware is a reasonable seed for the Ph5 t.me/s poller's mobile
  category (read-only preview, no join).

(Links not checked: see appendix.)

---

## F: Anti-Phishing, Website Security, Search Engine, OSINT Investigation

Source: BushidoUK/Open-source-tools-for-CTI (master). All links fetched 2026-11-11.
Total links: 137 (28 + 19 + 15 + 75), including 4 "Home" navigation links.
"(known)" in a cell marks a fact from prior knowledge that the fetched page did
not show; verify before relying on it.

### Anti-Phishing Tools (28 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [StalkPhish](https://github.com/t4d/StalkPhish) | Phishing-kit harvester (Python); renamed, points to t4d/StalkPhish-OSS | AGPL-3.0 | Archived 2024-03-11 | CLI; sources urlscan, urlquery, PhishTank, OpenPhish, PhishStats, Phishing.Database | M Ph3 (method + source list; use -OSS, not this) | no |
| [Phishing Catcher (x0rz)](https://github.com/x0rz/phishing_catcher) | certstream listener scoring suspicious cert domains; "working PoC" | GPL-3.0 | Not archived; old (Py2/3), no recent activity seen | CLI script; YAML keyword lists; score_domain() | M Ph3 (scoring method + keyword idea; do not copy GPL code) | partly: certstream add-on Ph3 / parking lot |
| [PhishStats](https://phishstats.info/) | Phishing URL database and feed, updated every 90 min | n/a (service); data licence not stated | Live (c) 2026 | JSON API api.phishstats.info; 50/day anon, 150/day free key | M Ph3/Ph1 feed-match | no |
| [URLscan.io](https://urlscan.io/) | URL sandbox and search | n/a (service) | Live 2026-11-11 | API; key in .env already | H (already built Ph1; Ph3/Ph6 search) | yes, Ph1 built; Ph6 pivots |
| [NormShield](https://services.normshield.com/phishing-domain-search) | Phishing domain search (NormShield became Black Kite) | n/a | DEAD: DNS does not resolve | none | None | no |
| [crt.sh](https://crt.sh/) | CT log search (Sectigo) | n/a (service) | Live (c) 2026 | Web + `?output=json` (known; used by toolkit) | H (built Ph1; Ph3 primary CT source) | yes, Ph1 built; Ph3 primary CT |
| [DNSlytics](https://dnslytics.com/) | Domain/IP/provider research, reverse IP/NS/MX, history | n/a (service) | Live | Premium (paid) API | L Ph6 (manual deep link) | no |
| [StinkyPhish](https://github.com/olihough86/stinkyphish) | Go certstream-style CT monitor for phishing domains | LICENSE file present, type not shown | Archived 2021-03-18 | CLI only | L (superseded) | no |
| [Lumpysoft](https://lumpysoft.com/) | Now a "Google Index Search" (media/ebook open-directory finder) with donation links; not a phishing tool | n/a | Live but repurposed | none | None | no |
| [Checkphish.ai](https://checkphish.ai/) | Bolster CheckPhish URL scanner; 302 to checkphish.bolster.ai (403 to fetcher) | n/a (service) | Live (redirects) | Free API exists per vendor (not confirmed on page) | L Ph3 | no |
| [PhishTank](https://www.phishtank.com/) | Community phishing DB, Cisco Talos | n/a (service) | Live, IDs ~9.55M | data.phishtank.com/data/online-valid.json (.csv/.bz2), hourly; keyless "a few downloads per day"; app-key registration link present | M Ph1/Ph3 feed-match | yes, "Additional free sources" (Ph1 feed) |
| [phishunt.io community](https://phishunt.io/community/) | Community page of phishunt | n/a | 404 (page gone; main site live) | n/a | None | no |
| [Whois DomainTools](http://whois.domaintools.com/) | DomainTools WHOIS lookup | n/a (service) | Live | Paid API (Iris) | L Ph6 (manual deep link) | partly: DomainTools band cited Ph6 |
| [DecentSecurity](https://decentsecurity.com/#/malware-web-and-phishing-investigation/) | Static guide to reporting phishing/malware sites (abuse contacts) | n/a | Live; undated | none | L Ph3 (takedown contacts reference) | no |
| [isitphishing brand-alert](https://isitphishing.org/brand-alert) | Vade "IsItPhishing" brand alert page | n/a | 404 (page gone) | none | None | no |
| [IANA Root-zone Database](https://www.iana.org/domains/root/db) | Authoritative TLD list with type and manager | n/a (public data) | Live | Keyless: data.iana.org/TLD/tlds-alpha-by-domain.txt, data.iana.org/TLD/v1/tlds.json, internic root.zone | M Ph3 (TLD list for typosquat permutations) | no |
| [Browserling](https://www.browserling.com/) | Remote browser in VMs, safe URL viewing | n/a (service) | Live (c) 2026 | Live API (paid); free plan limited | L Ph3 (manual safe-view link) | no |
| [Onyphe](https://www.onyphe.io/) | Internet scan search engine (ASM + CTI); 301 to onyphe.com | n/a (service) | Live (c) 2026, weekly scans | REST JSON API, Export and Bulk APIs; field:value syntax (tag:opendir); free plan not shown | M Ph6 (Shodan/Censys alternative; check free tier first) | no |
| [UK NCSC takedowns](https://www.ncsc.gov.uk/information/report-suspicious-emails) | NCSC guidance: how to report scam email, text, site, ad | n/a (gov) | Live (stats Sep 2026) | none | L Ph3 (report link in takedown workflow) | no |
| [JoulioK/Phishing_Kits](https://github.com/JoulioK/Phishing_Kits) | Repo of phishing kit folders named by domain | No licence | Not archived; dates not shown | Raw kit source in repo | L (contains live kit code; do not ingest) | no |
| [neonprimetime/PhishingKitTracker](https://github.com/neonprimetime/PhishingKitTracker) | CSVs of threat-actor emails found in kits, 2017-10 to 2020-12 | No licence shown | PAUSED 2022-01-11 | Monthly CSVs | L Ph9 (historic actor-email facts, re-key only) | no |
| [cybercdh/phishfinder](https://github.com/cybercdh/phishfinder) | Python: probes phishing URL open dirs, downloads zip/txt/exe | MIT | Archived 2023-03-21; superseded by kitphishr | CLI; reads PhishTank feed | L (superseded) | no |
| [t4d/PhishingKitHunter](https://github.com/t4d/PhishingKitHunter) | Python 3: parses own web logs for referers using brand assets | AGPL-3.0 | Not archived; v0.8.1, old | CLI; CSV out | M Ph3 (method: referer/asset-hotlink detection, own code) | no |
| [marcoramilli/PhishingKitTracker](https://github.com/marcoramilli/PhishingKitTracker) | Daily kit-zip archive (git-lfs) by Marco Ramilli, launched 2020 | n/a | DEAD: repo 404; stale Gitee mirror (2022) | n/a | None | no |
| [cybercdh/kitphishr](https://github.com/cybercdh/kitphishr) | Go: hunts and downloads kit archives from phishing URLs; `analyze` extracts emails, Telegram bot tokens, Discord webhooks | GPLv2 + commercial dual licence | Active (Go 1.25 req.) | CLI; JSONL index; feeds PhishTank, OpenPhish, PhishStats, Phishing.Database, phishunt, TweetFeed | M Ph3/Ph5 (feed list + analyze method; downloads live kits so VM only) | no |
| [phishunt.io](https://phishunt.io/) | Free real-time feed of suspicious phishing/scam sites, enriched | Data CC0 1.0 (ToS s.7) | Live, updated 2026-11-11 22:01 UTC, feeds hourly | Keyless API /api/v1/ (domains, analyze, campaigns), feed.json/csv/txt, STIX 2.1 bundle, OpenAPI; 10 req/s | H Ph3 (feed-match + campaign clusters), Ph1 | no |
| [Guide: hunting for phishing kits](https://loungefly84.medium.com/brand-protection-hunting-for-phishing-kits-34df8740989a) | Medium blog on brand-protection kit hunting | n/a (article) | 403 to fetcher (after a rate-limited first try) | none | L (reference; unread) | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools) | Old repo name; resolves to BushidoUK/Open-source-tools-for-CTI | No licence | List repo | n/a | None (navigation) | n/a |

### Website Security (19 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Mx ToolBox](https://mxtoolbox.com/blacklists.aspx) | Checks an IP/domain against 100+ DNSBLs | n/a (service) | Live (c) 2004-2026 | Paid API product (details not shown) | L Ph1 (manual link; direct DNSBL queries have their own terms) | no |
| [BGP Hurricane Electric](https://bgp.he.net/) | HE BGP toolkit: ASN, prefixes, peers, IX, RPKI, looking glass | n/a (service) | Live, data updated 2026-11-10 | No API or bulk export; no stated automation terms | L Ph6 (manual ASN deep link; Team Cymru/RDAP for data) | no |
| [Qualys SSL test](https://www.ssllabs.com/ssltest/) | SSL Labs server TLS config grader | n/a (service) | Live, report v2.4.3, (c) 2026 | Not shown on page (SSL Labs API exists: v4 needs registered email) | L Ph3 (own-domain TLS hygiene) | no |
| [Cloudflare URL Scanner](https://radar.cloudflare.com/scan) | Cloudflare Radar URL scanner (screenshot, DOM, network, tech) | n/a (service) | 403 to fetcher; known live | Cloudflare API with free account token (not confirmed on page) | M Ph3/Ph6 (urlscan alternative; free account needed) | no (Cloudflare only as CDN/solver) |
| [Gordon (CyberGordon)](https://cybergordon.com/) | Reputation aggregator over 30+ engines for IP/URL/domain/hash/email | n/a (service) | Last announcement v0.22.1, 2023-07-30; ~800 analyses/day | GET /request/<obs>; 10/min tolerated; no key | L (sends IOCs to third party; toolkit does same itself) | no |
| [PulseDive](https://pulsedive.com/) | Community TI platform: enrich IP/URL/domain, explore, feeds | n/a (service) | Live v6.3.19, 2026-11-09 | API, free account key; Pro $29/mo non-commercial | M Ph1 (planned enrichment expansion) | yes, Ph1 expansion / "Additional free sources" |
| [Whois search](https://whois.domaintools.com/) | DomainTools WHOIS (duplicate of Anti-Phishing row) | n/a (service) | Live | Paid API | L Ph6 (deep link) | partly (DomainTools cited Ph6) |
| [VirusTotal](https://www.virustotal.com/gui/home/search) | VT search UI (JS app; only title rendered) | n/a (service) | Live | API; key in .env | H (already built Ph1) | yes, Ph1 built |
| [URLScan](https://urlscan.io/) | Duplicate of Anti-Phishing row | n/a (service) | Live | API; key in .env | H (built Ph1) | yes, Ph1 |
| [DNS Dumpster](https://dnsdumpster.com) | HackerTarget domain recon: hosts, DNS records, map | n/a (service) | Live | API at /developer/ (membership; terms not shown) | L Ph3/Ph7 (Subfinder covers it) | no |
| [Wappalyzer](https://www.wappalyzer.com) | Technographic lookup, now sales-oriented; paid API | n/a (service); old OSS fingerprints moved/closed (not confirmed on page) | Live (page showed errors) | Paid API | L Ph6 (tech fingerprint; use webappanalyzer-style OSS data instead) | no |
| [BuiltWith](https://builtwith.com/) | Technology lookup for websites, incl. history | n/a (service) | Live 2026 | API (keyed; free tier not shown) | L Ph6 (tracker-ID / tech pivots, manual) | no |
| [Exploit-DB](https://www.exploit-db.com) | OffSec public exploit archive + GHDB | n/a; repo on GitLab exploit-database/exploitdb | Live (c) 2026 | RSS /rss.xml; GitLab repo with files_exploits.csv | H (already used Ph2) | yes, Ph2 (Exploit-DB index) |
| [Certificate Stream (crt.sh)](https://crt.sh/) | Labelled "Certificate Stream" but links crt.sh (duplicate) | n/a (service) | Live | JSON output | H (built Ph1; Ph3) | yes, Ph1/Ph3 |
| [FOCA](https://github.com/ElevenPaths/FOCA) | Windows .NET document metadata harvester (Google/Bing/DDG) | GPL-3.0 | Not archived; dates not shown, old | GUI only; needs SQL Server | L Ph7 (method only: doc metadata; Windows-only GUI cannot be wrapped) | no |
| [MS-SQL Server Express (FOCA prerequisite)](https://www.microsoft.com/en-au/sql-server/sql-server-editions-express) | Microsoft marketing page (now SQL Server 2019 page) | Proprietary | Page stale (2022 preview text) | n/a | None (FOCA dependency) | no |
| [NMAP/Zenmap](https://nmap.org/zenmap/) | Official Nmap GUI | Nmap Public Source Licence (NPSL; not OSI) | Live | CLI nmap XML output | L (active scanning; out of passive scope; maybe parking lot own-host checks) | no |
| [OpenVAS](https://www.openvas.org/) | Greenbone OpenVAS vulnerability scanner (Community Edition) | GPL (Greenbone repos; not stated on page) | Live, daily feed | GMP API (self-hosted) | L (parking lot: own-host scanning if hosted) | yes, parking lot ("OpenVAS/Greenbone Community") |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Navigation to list repo | No licence | n/a | n/a | None | n/a |

### Search Engine Tools (15 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Shodan](https://www.shodan.io/) | Internet device search engine, weekly crawl | n/a (service) | Live | API; key in .env; filter syntax in Help Center (ssl.jarm, http.favicon.hash, etc.) | H (built Ph1; Ph6 pivots; Ph3 exposed assets) | yes, Ph1 built, Ph6 pivots |
| [Censys.io](https://censys.io/) | Internet host/cert search; 301 to censys.com | n/a (service) | Live (c) 2026 | Platform API; free = 100 credits/month, lookups only, search paid (per ROADMAP, not re-confirmed on page) | M Ph6 (cert/host lookup by value) | yes, Ph6 + parking lot "Censys (parked 2026-11-02)" |
| [Abuse IP Database](https://www.abuseipdb.com/) | IP abuse reports | n/a (service) | 403 to fetcher; key in .env and working | API; key in .env | H (built Ph1) | yes, Ph1 built |
| [Robtex Domain/IP Lookup (via itools)](http://itools.com/tool/robtex-domain-ip-address-lookup) | itools.com wrapper page for Robtex | n/a | DEAD: connection refused | none | None (use robtex.com directly if wanted) | no |
| [NetCraft (same itools URL)](http://itools.com/tool/robtex-domain-ip-address-lookup) | List error: NetCraft entry points to the Robtex itools URL | n/a | DEAD: connection refused | none | None (Netcraft site report is the real tool) | no |
| [GitHub Code Search](https://github.com/search) | GitHub search UI | n/a (service) | Live; code search needs sign-in | REST /search/code needs token | H Ph7/Ph3/Ph2 (already planned GitHub client) | yes, Ph7 "GitHub code search", Ph3 secret leaks |
| [Yandex Image Translate](https://translate.yandex.com/ocr) | OCR + translate text in images | n/a (service) | Live (transient error shown) | Yandex Cloud Translate/Vision paid API | L Ph4 (manual link for foreign-language screenshots) | no |
| [Binary Edge](https://www.binaryedge.io/) | Internet scan search engine; 301 to Coalition "BinaryEdge Transition FAQ" (404) | n/a | DEAD: shut down after Coalition acquisition | none | None | no |
| [Threat Connect free](https://threatconnect.com/free/) | Old free TC Open community account; now 301 to dataminr.com | n/a | Gone: ThreatConnect absorbed by Dataminr; free page removed | none | None | no |
| [Threat Crowd (by OTX)](https://www.threatcrowd.org/) | Old graph search engine for IOCs (AlienVault) | n/a | DEAD: DNS does not resolve | none (OTX replaces it) | None (OTX already built) | no (OTX yes, Ph1) |
| [Earthcam](https://www.earthcam.com/) | Public live webcam network | n/a (service) | Live | none for OSINT use | L Ph7 (manual geo-verification) | no |
| [Insecam](https://www.insecam.org/) | Directory of unsecured IP cameras streamed without owners' consent | n/a | Expired TLS certificate; status unclear | none | None (ethically and legally unsuitable) | no |
| [Wigle](https://wigle.net/) | Crowdsourced Wi-Fi/cell network map | n/a (service); EULA | Live (c) 2026 | api.wigle.net; account needed; limits not shown | L Ph7 (BSSID/SSID geolocation, manual) | no |
| [Shard Cam](https://www.willpearson.co.uk/interactive/virtualtour/shard-day/) | Static 360 gigapixel panorama from the Shard, London | n/a | Live; static image, not a camera | none | None | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Navigation to list repo | No licence | n/a | n/a | None | n/a |

### OSINT Investigation Tools (75 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [OSINT Search Operators](https://github.com/BushidoUK/OSINT-SearchOperators) | BushidoUK lists: GoogleDorks.csv, ShodanQueriesAppliances.csv, ShodanAdversaryInfa.md | No licence shown | Not archived; 98 commits, dates not shown | CSV/MD files | M Ph3/Ph6 (dork and Shodan query ideas; no licence: re-key facts, fetch at runtime) | no |
| [Image EXIF Data](https://exifdata.com/) | In-browser EXIF viewer/remover (no upload claimed) | n/a (service) | Live (c) 2025 | none | L Ph7 (do it locally with Pillow/exiftool instead) | no |
| [Synapsint](https://www.synapsint.com/) | OSINT engine: domain, IP, ASN, SSL, analytics/AdSense IDs, email, phone, BTC, CVE | n/a (service) | Live; undated | api.php (terms not shown) | L Ph6 (tracker-ID pivot as manual link) | no |
| [Reddit6](https://reddit6.com/#/Stream) | Old Reddit live-stream viewer | n/a | DEAD: DNS does not resolve | none | None | no |
| [Google Alerts](https://www.google.co.uk/alerts) | Google keyword alerts (email or RSS feed delivery, Google account) | n/a (service) | Live | No API; RSS delivery option (known, not on page) | M Ph4 (RSS alert feeds into the aggregator) | no |
| [Warble Alerts](https://warble.co/) | Twitter keyword email alerts | n/a | DEAD: banner says it stopped when Twitter ended free API | none | None | no |
| [VisualPing](https://visualping.io/) | Web page change monitoring with alerts | n/a (service) | Live (c) 2026 | api.visualping.io; free personal plan, limits not shown | L Ph5 (own scheduler + diff does this locally) | no |
| [Webpage Archiver (archive.today)](http://archive.vn/) | archive.today snapshot service | n/a (service) | Not checked (fetch tool refuses this domain) | no official API | L Ph7 (manual link) | no |
| [Barcode Reader](https://online-barcode-reader.inliteresearch.com/) | Inlite ClearImage online barcode reader demo (upload) | n/a (service) | Live (c) 2014-2026 | Paid SDK | L (decode QR locally for quishing instead) | no |
| [OSINT Team](https://osint.team/home) | Mastodon instance for OSINT community | n/a | DEAD: DNS does not resolve | none | None | no |
| [Wen (Wayback) Archive](https://archive.org/web/) | Internet Archive Wayback Machine | n/a (service) | Not checked (rate-limited twice); known live | CDX and availability APIs keyless (known) | M Ph7/Ph6 (historical page and URL lookups) | no |
| [Companies House](https://www.gov.uk/government/organisations/companies-house) | UK company registry org page | OGL (UK gov data, known) | Not checked (rate-limited twice) | Free REST API with key, bulk data products (known) | M Ph7 (company/officer lookups for UK orgs) | no |
| [192.com](https://www.192.com/people/search/) | UK people search (electoral roll etc., paid credits) | n/a (service) | 403 to fetcher | Paid | None (people search; data policy) | no |
| [RocketReach](https://rocketreach.co/) | "Lead Intelligence: Phone and Email Finder" (only title rendered) | n/a (service) | Live (title) | Paid API | None (sales tool; same reasoning as Apollo.io exclusion) | no (Ph7 rejects Apollo.io for similar terms) |
| [Maltego](https://www.paterva.com/downloads.php) | Link-analysis desktop app; 301 to maltego.com/downloads | Proprietary | Live; free plan needs Maltego ID, credits vary by plan | Transforms (credits) | L Ph6/Ph7 (reference for graph UX; not wrappable) | no |
| [Spiderfoot](https://www.spiderfoot.net/) | OSINT automation; site 301 to intel471.com; OSS at smicallef/spiderfoot | MIT (OSS repo) | OSS v4.0, not archived; HX now Intel 471 | Self-hosted web UI + sfcli.py; Python 3.7+ | M Ph7 (optional deep scan, separate process) | yes, Ph7 "SpiderFoot as the optional deep scan", Ph8 |
| [Refseek](https://www.refseek.com/) | Academic search engine | n/a | Live (c) 2025 | none | None | no |
| [WorldCat](https://www.worldcat.org/) | Library catalogue search; 301 to search.worldcat.org | n/a | Live | OCLC APIs (membership) | None | no |
| [Springer Link](https://link.springer.com/) | Scientific publisher portal (303 to Springer login cookie check) | n/a | Live | Springer Nature API (key) | None | no |
| [Bioline](https://www.bioline.org.br/) | Bioscience journal library | n/a | TLS chain broken ("unable to verify first certificate") | none | None | no |
| [RePEc](http://repec.org/) | Economics papers index | n/a | HTTPS handshake failed (site may be HTTP only) | Open data via FTP (known) | None | no |
| [Science.gov](https://www.science.gov/) | US federal science search | n/a (gov) | Live | none shown | None | no |
| [PDF Drive](https://www.pdfdrive.com/) | Free ebook download site (unlicensed copies) | n/a | Live | none | None (copyright risk) | no |
| [BASE](https://www.base-search.net/) | Bielefeld academic search engine | n/a | Live but bot wall (Anubis) blocked fetcher | OAI/HTTP API on request (known) | None | no |
| [WhatsMyName](https://whatsmyname.app/) | Username enumeration web app over WMN data | Data CC BY-SA 4.0 | Site HTTP 464 to fetcher; REPO ARCHIVED 2026-11-09, no longer maintained | wmn-data.json (691 sites; uri_check, e_code/e_string, m_code/m_string) | H Ph7 (site-list facts and detection schema; frozen now) | yes, Ph7 identity lookup |
| [CheckUsernames](https://checkusernames.com/) | Username availability checker | n/a | DOWN: HTTP 522 (Cloudflare origin timeout) | none | None | no |
| [PGP Key Server (key-server.io)](https://pgp.key-server.io/) | Former PGP keyserver | n/a | DEAD: parked, "domain may be for sale" | none | None (use keys.openpgp.org instead) | partly: Ph7 "PGP keyserver search" |
| [Whoxy](https://www.whoxy.com/) | WHOIS API, history, reverse WHOIS, NRD lists | n/a (service) | Live (c) 2026 | Paid: $10/5k lookups, $25/5k history, $50/5k reverse | M Ph6 (optional paid module) | yes, Ph6 "Whoxy: ... optional vendor module" |
| [Maigret](https://github.com/soxoj/maigret) | Username dossier across ~5,900 sites | MIT | Active, 1,755 commits, not archived | CLI + library; JSON/CSV/HTML/PDF/graph out | H Ph7 (escape-hatch subprocess wrap; ideas for own checker) | yes, Ph7 |
| [Holehe](https://github.com/megadose/holehe) | Email -> which of 120+ sites have an account (password-reset probes) | GPL-3.0 | Not archived; 73 open issues | CLI + library (trio/httpx) | M Ph7 (wrap as subprocess only: GPL) | yes, Ph7 wrapped tool |
| [Profil3r](https://github.com/Rog3rSm1th/Profil3r) | Social profile and email permutation finder | n/a | DEAD: repo 404 (still on PyPI per search) | none | None | no |
| [EagleEye](https://github.com/ThoughtfulDev/EagleEye) | Face recognition + reverse image search to find a person's social profiles | WTFPL | Old (Py3.5/3.6, ImageRaider); not archived | Selenium/dlib CLI | None (people-tracking, out of scope) | no |
| [EmailRep](https://emailrep.io/) | Email reputation (Sublime Security) | n/a (service) | HTTP 400 to fetcher; status unconfirmed | API with key (known: free tier on request) | L Ph1/Ph7 | no |
| [Epieos](https://tools.epieos.com/) | Email/phone to Google and other accounts; 301 to epieos.com (403 to fetcher) | n/a (service) | Live (redirects) | Paid API (known) | L Ph7 (manual link) | no |
| [Predicta Search](https://www.predictasearch.com) | Email/phone/name/username across 1,710+ platforms (Predicta Lab, FR) | n/a (service) | Live | Free limited lookups; API on contact | L Ph7 (manual link) | no |
| [OSINT Tool Blog](https://medium.com/@z3roTrust/open-source-intelligence-osint-reconnaissance-75edd7f7dada) | Medium article on OSINT recon tools | n/a (article) | 403 to fetcher | none | L (reference) | no |
| [OSINT techniques (sinwindie)](https://github.com/sinwindie/OSINT) | Bookmarklets and method collections per platform | No licence; README forbids selling/hosting | Not archived; 206 commits | JS bookmarklets | L Ph7 (methods only; do not copy) | no |
| [Intel Techniques OSINT packet 2019](https://inteltechniques.com/JE/OSINT_Packet_2019.pdf) | Bazzell OSINT workbook PDF | (c) author | DEAD: 404 | none | None | no |
| [Privacy Checklist Feb 2019](https://inteltechniques.com/JE/Privacy_Checklists_Feb2019.pdf) | Bazzell privacy checklists PDF | (c) author | DEAD: 404 | none | None | no |
| [OSINT collection (start.me)](https://start.me/p/DPYPMz/the-ultimate-osint-collection) | Bookmark page of OSINT links | n/a | 403 to fetcher | none | L (reference) | no |
| [Aware-Online OSINT tools](https://www.aware-online.com/en/osint-tools/) | Dutch training firm's free OSINT search tools by category | n/a | Live; undated | none | L Ph7 (reference) | no |
| [Bellingcat's OSINT tool set](https://docs.google.com/spreadsheets/d/18rtqh8EG2q1xBo2cLNyhIDuK9jrPGwYr9DI2UncoqJQ/edit#gid=930747607) | Old Bellingcat toolkit sheet; says "not active anymore", moved to bellingcat.gitbook.io/toolkit | n/a | Retired (moved) | none | L Ph7 (use the GitBook toolkit as reference) | no |
| [OSINT for People](https://docs.google.com/spreadsheets/d/1JxBbMt4JvGr--G0Pkl3jP9VDTBunR2uD3_faZXDvhxc/edit#gid=970216593) | "OSINT for Finding People" sheet v0.7 by @cybersecstu | n/a | Readable; undated | none | L (people-finding; reference only) | no |
| [OSINT Framework](https://osintframework.com/) | Tree of free OSINT resources | MIT (lockfale/osint-framework) | Active repo, 912 commits | arf.json (name, type, url, status, pricing, api, opsec flags) | M Ph7 (MIT data: seed for the source picker/manual-link catalogue) | no |
| [OSINT Yoga](https://yoga.osint.ninja/) | YOGA: interactive OSINT pivot graph (WebBreacher); 301 to yoga.myosint.training | Source on GitHub (licence not checked) | Live | none | L Ph6/Ph7 (pivot ideas) | no |
| [Search by Image (Chrome)](https://chrome.google.com/webstore/detail/search-by-image/cnojnbdhbhnkbcieeekonklommdnndci) | Reverse image search extension, 30+ engines (armin.dev) | n/a (extension) | Updated 2026-06-16, v8.5.4, ~300k users | none | L (analyst browser aid; engine URL patterns useful for deep links) | partly: Ph3 manual reverse image links |
| [RevEye (Chrome)](https://chrome.google.com/webstore/detail/reveye-reverse-image-sear/keaaclcjhehbbapnphnmpiklalfhelgf) | Right-click reverse image search (Lens, Bing, Yandex, TinEye) | n/a (extension) | Last update 2024-09-03, ~100k users | none | L (browser aid) | partly: Ph3 manual links |
| [TinEye](https://tineye.com/) | Reverse image search | n/a (service) | 403 to fetcher; known live | Paid API (known) | L Ph3/Ph7 (manual deep link) | yes, Ph3 manual reverse image links |
| [Yandex image search](https://yandex.com/images/) | Image search incl. search-by-image | n/a (service) | Live (c) 2026 | No public API shown | L Ph3/Ph7 (manual deep link) | yes, Ph3 manual links |
| [Bing image search](https://www.bing.com/images/) | Image search with Visual Search | n/a (service) | Live | Bing Search API retired 2025 (known, not on page) | L (manual link) | no |
| [Google Lens](https://lens.google.com/) | Google visual search; 302 to lens.google | n/a (service) | Live | No API | L Ph3/Ph7 (manual deep link) | yes, Ph3 manual links |
| [Pixsy](https://www.pixsy.com/) | Image-theft monitoring and takedown; 500 images free | n/a (service) | Live | No API shown | L Ph3 (logo misuse monitoring, manual) | no |
| [Dupli Checker reverse image](https://www.duplichecker.com/reverse-image-search.php) | Ad-supported SEO-tools site with a reverse image proxy | n/a | 403 to fetcher | none known | None (Lens/Yandex/TinEye links suffice) | no |
| [PimEyes](https://pimeyes.com/en) | Face search engine; free first search, paid plans with alerts | n/a (service) | Live (c) 2026 | No API ("exclusively through this website") | None (face search of people; out of scope) | no |
| [Google Maps](https://www.google.com/maps/) | Maps and Street View | n/a (service) | Live (title only rendered) | Paid Maps Platform APIs | L Ph7 (manual geolocation link) | no |
| [Google Earth](https://earth.google.com/) | Google Earth web (WebAssembly) | n/a (service) | Live | none | L Ph7 (manual) | no |
| [Bing Aerial Maps](https://www.bing.com/maps/aerial) | Bing aerial imagery | n/a (service) | Page rendered only a Bing fragment; status unclear | none | L Ph7 (manual) | no |
| [OpenStreetMap](https://www.openstreetmap.org/) | Open world map | ODbL (known; page links /copyright) | Live | Nominatim/Overpass APIs (known, usage policies) | L Ph7 (geocode a location string, light use) | no |
| [Snap Map](https://map.snapchat.com/) | Public Snap heat map; now 308 to snapchat.com, web map not offered | n/a | Moved into app; web map not confirmed | none | None | no |
| [Liveuamap](https://liveuamap.com/) | Live conflict news map (items dated 2026-11-11) | n/a (service) | Live | /promo/api (paid, details not shown) | L Ph4 (geopolitical context; manual) | no |
| [Flight Radar](https://www.flightradar24.com/) | Flight tracking | n/a (service) | 403 to fetcher; known live | Paid API | None | no |
| [Freedar](https://radar.freedar.uk/VirtualRadar/desktop.html#) | Hobbyist Virtual Radar Server ADS-B map | n/a | 403 to fetcher | none | None | no |
| [ADSB Exchange](https://globe.adsbexchange.com/) | Community ADS-B flight tracking (tar1090) | n/a (service) | Live page; data fetch failed in capture | Paid API (not shown on page) | None | no |
| [Marine Traffic](https://www.marinetraffic.com/) | AIS ship tracking | n/a (service) | 403 to fetcher; known live | Paid API | None | no |
| [Radio.Garden](http://radio.garden/) | Globe of live radio streams | n/a (service) | Live | none | None | no |
| [MeteoBlue webcams](https://www.meteoblue.com/en/weather/webcams/) | Weather webcams (from windy.com), refreshed minutes ago | n/a (service) | Live | Paid weather APIs | None | no |
| [Windy](https://www.windy.com/) | Wind map and forecast (only title rendered) | n/a (service) | Live (title only) | Webcams/point APIs (not shown) | None | no |
| [WalletExplorer](https://www.walletexplorer.com/) | Bitcoin explorer with address clustering and service labels | n/a (service) | Live, block 975345 at 2026-11-10 | JSON API (count up to 1000; terms not shown) | M Ph6/Ph9 (BTC wallet-to-service attribution for ransom/extortion addresses) | partly: parking lot blockchain explorers (mempool.space) |
| [Chainalysis](https://chainalysis.com/) | Commercial blockchain analytics | n/a (service) | Live (news 2026-11-10) | Paid; free sanctions screening API exists (known, not on page) | L Ph1/Ph6 (sanctions check; OFAC SDN list already planned) | partly: OFAC addresses Ph6 gate |
| [Scorechain](https://scorechain.com/) | Commercial blockchain analytics (LU) | n/a (service) | Live (blog 2026-11-03) | "Free sanction screening API" and free wallet checks (limits not shown) | L Ph6 (optional sanctions/risk check) | no |
| [Blockseer](https://blockseer.com/) | Now DMG Blockchain's Bitcoin tracking tool aimed at miners; free access claimed | n/a (service) | Live | none shown | L | no |
| [Elliptic](https://www.elliptic.co/) | Commercial crypto compliance; page offers a free exploit blocklist ("$6.4 billion theft") | n/a (service) | Live | Paid API; free exploit blocklist | L Ph6 (free blocklist as a local gate, check terms) | no |
| [Blockchain.com](https://blockchain.com) | Exchange/wallet with block explorer | n/a (service) | 403 to fetcher; known live | Explorer data API (known, keyless) | L Ph6 (mempool.space already chosen) | no |
| [CheckBitcoinAddress](https://checkbitcoinaddress.com/) | BTC address abuse-report checker | n/a | DEAD: "UNDER CONSTRUCTION" placeholder | none | None (BitcoinAbuse successor is Chainabuse) | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Navigation to list repo | No licence | n/a | n/a | None | n/a |

### High-value notes

**phishunt.io (H, Ph3 feed-match; also Ph1 enrichment)** - best new find in these lists.
- Integrate as a keyless data source. Base `https://phishunt.io/api/v1/`: `domains?format=json|csv|txt` (limit 1000, offset up to 10000), `analyze?url=` (passive, never touches the target), `campaigns`, `campaigns/{key}/export`. Bulk: `/feed.json`, `/feed.csv`, `/feed.txt`, `/stix/bundle.json`, `/openapi.yaml`; also blocklist formats (hosts, RPZ, adblock).
- No key except `analyze/deep` (token, 50/day). Limit 10 req/s per IP (burst 20); asks for a descriptive User-Agent. Feeds refresh hourly.
- Licence: ToS s.7 releases feeds and API responses under CC0 1.0, so data may be stored and redistributed; ToS forbids calling a listed domain "confirmed phishing" just because it is listed, so label hits as "suspicious (phishunt)".
- Fit: daily pull into the Phase 3 feed-match store next to PhishTank/OpenPhish; campaign groups feed Phase 6 clustering; STIX bundle maps to Phase 8.

**PhishTank (M, Ph1/Ph3; already in "Additional free sources")**
- Feed: `https://data.phishtank.com/data/online-valid.json` (also .csv, .bz2/.gz). Keyless downloads are "a few per day"; with an app key, ETag HEAD checks are unlimited. Hourly refresh. Cisco EULA terms; licence for data not stated, so keep local, do not republish.
- Use: one scheduled download per day keyless is enough for local feed-match (Phase 5 scheduler).

**PhishStats (M, Ph3)**
- JSON API at `api.phishstats.info` (docs at /api-docs): 50 requests/day anonymous per IP, 150/day with a free key. DB refreshes every 90 minutes. Data licence not stated: local use only. A second phishing feed beside PhishTank and phishunt.

**crt.sh, urlscan, Shodan, VirusTotal, AbuseIPDB, Exploit-DB, Pulsedive (H/M, already planned)**
- Nothing new: all already built or planned. crt.sh is the Phase 3 primary CT source; Shodan filter syntax (`ssl.jarm`, `http.favicon.hash`, `http.html_hash`) drives Phase 6 pivots; Exploit-DB GitLab index is in Phase 2.

**IANA TLD list (M, Ph3)**
- Fetch `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` (or `/TLD/v1/tlds.json`, with type and manager) on a schedule. Use it as the TLD set for typosquat permutations (dnstwist-style TLD swap) and to validate extracted domains in Phase 2 IOC extraction. Public data, keyless.

**Cloudflare URL Scanner (M, Ph3/Ph6)**
- API: `https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner/v2/...`; needs a free Cloudflare account and a custom token with "URL Scanner: Edit". Bulk submit up to 100 URLs; search endpoint takes Elasticsearch-style queries over public scans. Scans default to Public: always submit as Unlisted for client brands. Price and rate limits not shown on the doc page. A second sandbox when urlscan quota runs out; needs operator approval to create an account.

**WhatsMyName (H, Ph7; already planned) - status change**
- The repo was archived on 2026-11-09 ("no longer maintained"). Data is CC BY-SA 4.0 (share-alike: copying entries into the repo would bind that file to CC BY-SA, so the roadmap's "own list, ideas only" decision still holds). The schema (`uri_check`, `e_code`+`e_string`, `m_code`+`m_string`, `known`, `protection`) is a good model for the toolkit's own site-rule format; it says to require both status and string to match. Expect the 691 entries to rot; Naminter and Blackbird are named downstream users. Update ROADMAP Ph7 to note the archive.

**Maigret (H, Ph7; already planned)**
- MIT, active, ~5,900 sites (default run checks top 500). CLI with `--json ndjson|simple`, also importable. Roadmap already says: subprocess wrap only, own venv, no pip dependency. MIT means its `data.json` site rules may be reused with attribution, unlike WhatsMyName's CC BY-SA.

**Holehe (M, Ph7; already planned)**
- GPL-3.0: wrap as a subprocess in its own venv, never import. Probes password-reset/registration flows on 120+ sites; the README claims it does not alert the target, but this is a claim. Output per module: exists, rate-limited, partial recovery email/phone.

**SpiderFoot (M, Ph7; already planned)**
- spiderfoot.net now redirects to intel471.com (HX is Intel 471's). OSS repo smicallef/spiderfoot: MIT, v4.0, Python 3.7+, web UI via `sf.py -l 127.0.0.1:5001` and `sfcli.py`. The OSS README does not document the REST API (the "fully RESTful API" line refers to HX), so check "triggered by API" in ROADMAP Ph7 against the OSS code before building.

**OSINT Framework (M, Ph7)**
- lockfale/osint-framework, MIT, active. `arf.json` entries carry `name`, `type`, `url` plus optional `status`, `pricing`, `opsec`, `localInstall`, `api`. MIT allows reuse with attribution: a seed for the Ph7 source picker and the Ph6 "query-template links" catalogue (filter `api: true`, `pricing: free`).

**kitphishr / StalkPhish-OSS / PhishingKitHunter (M, Ph3, method)**
- kitphishr (Go, GPLv2 + commercial dual licence, active): its built-in feed list (PhishTank, OpenPhish, PhishStats, Phishing.Database, phishunt, TweetFeed) confirms which free phishing feeds are worth wiring. Its `analyze` step pulls emails, Telegram bot tokens/chat IDs and Discord webhooks from kit source, which matches the Ph6 "kit extracted and stored as indicator" idea. It downloads live kits: VM only, binary run as a subprocess at most.
- StalkPhish-OSS (Python, AGPL-3.0): same pattern, plus urlquery as a source. AGPL: do not copy code.
- PhishingKitHunter (AGPL-3.0): method only. Parse your own web logs for Referer URLs that hot-link the brand's CSS/JS/images; a cheap, deterministic Ph3 brand check to rebuild in own code.

**Phishing Catcher (M, Ph3, method)**
- GPL-3.0 certstream PoC. The useful part is the scoring idea: keyword weights, suspicious TLDs, entropy, hyphen count, and Levenshtein distance to brand terms in a YAML file. Rebuild the scoring in own code for the crt.sh sweep (Ph3 "Matching layers"); do not copy.

**Onyphe (M, Ph6)**
- onyphe.io redirects to onyphe.com. REST JSON API, Export and Bulk APIs, `field:value` queries (`tag:opendir`, `device.class:database`). Free plan not visible on the home page: check pricing before planning. Another Shodan/Censys-class source for Ph6 if a free tier exists.

**BushidoUK/OSINT-SearchOperators (M, Ph3/Ph6)**
- GoogleDorks.csv, ShodanQueriesAppliances.csv, ShodanAdversaryInfa.md. No licence shown: fetch at runtime or re-key individual queries as facts, do not copy files. Useful seed for Shodan adversary-infrastructure queries in the Ph6 default-signature library and for Ph3 dork review links.

**WalletExplorer (M, Ph6/Ph9)**
- Bitcoin explorer that clusters addresses into wallets and labels known services (exchanges, markets); live (block 975345, 2026-11-10). Has a JSON API (count up to 1000); free or not is not stated. Fits the parked blockchain-explorer item: answer "which service received this ransom payment?" Use as a manual link first.

**Whoxy (M, Ph6; already planned as optional paid module)**
- Prices confirmed on 2026-11-11: WHOIS lookup $10 per 5,000, history $25 per 5,000, reverse WHOIS $50 per 5,000. ROADMAP says "about $10 per 1,000" for reverse WHOIS; the page now shows $50 per 5,000, which is the same per-query price.

### Dead, moved, or changed (for the roadmap)
- WhatsMyName archived 2026-11-09 (planned in Ph7).
- spiderfoot.net now redirects to Intel 471; OSS repo still MIT and live.
- BinaryEdge shut down (now redirects to a Coalition transition FAQ that returns 404).
- ThreatConnect free page redirects to dataminr.com; ThreatCrowd domain gone.
- NormShield, Reddit6, osint.team, key-server.io (parked), Warble (Twitter API), checkbitcoinaddress (placeholder), itools Robtex page, marcoramilli/PhishingKitTracker, Profil3r, both Bazzell 2019 PDFs: dead.
- Lumpysoft is now an unrelated "Google Index Search" media finder.
- Bellingcat toolkit sheet retired; it now points to bellingcat.gitbook.io/toolkit.
- PGP: key-server.io parked; Ph7 "PGP keyserver search" should target keys.openpgp.org or another live keyserver.

(Links not checked: see appendix.)

---

## Part G: Malware analysis, Honeypots, GitHub Projects, Chrome Extensions

Checked 2026-11-11 with WebFetch (GitHub facts from api.github.com: licence SPDX, `pushed_at`, archived flag). Source: BushidoUK/Open-source-tools-for-CTI, branch `master`. "In roadmap?" comes from a grep of ROADMAP.md. "SPA" means the page is a JavaScript app and the fetch returned only its title.

Total links: 123 (Malware analysis 71, Honeypots 5, GitHub Projects 24, Chrome Extensions 23). Each count includes the sub-file's "Home" navigation link.

### Malware analysis.md (71 links)

**Malware Analysis Tools**

| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Flare VM](https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html) | 2017 blog post. Redirects to mandiant.com, then to a generic Google Cloud page (the post is gone). Project lives at mandiant/flare-vm | Apache-2.0 (repo) | Repo active, push 2026-10-07, PowerShell, 9.3k stars | None; installer scripts for a Windows RE VM | M, parking lot (build the isolated analysis VM) | No by name ("isolated analysis VM" in parking lot) |
| [VirusTotal](https://www.virustotal.com/gui/home/upload) | VT upload page (SPA) | n/a (service) | Live | API v3, free key 4/min | Already built (Ph1). Uploading publishes the sample: hash lookup only | Yes, Ph1 |
| [App.Any.Run](https://app.any.run/) | Interactive sandbox (SPA). Plans page: free Community tier with unlimited public analyses | n/a (service) | Live | API on paid tiers only (Enterprise, "from 1,500 requests/mo"). Private analyses are paid | L, parking lot stage 1/4 | Yes, parking lot ("ANY.RUN's API is on paid plans") |
| [Passive Total by RISK IQ](https://community.riskiq.com/registration) | RiskIQ community signup | n/a | Dead: ECONNREFUSED. RiskIQ was folded into Microsoft Defender TI, and the standalone MDTI has been retired | None | None | No |
| [Hybrid Analysis](https://www.hybrid-analysis.com/) | CrowdStrike Falcon Sandbox public instance (SPA; docs and FAQ also returned only titles) | n/a (service) | Live | API v2 with a free key (per roadmap; not re-verified here) | H, Ph1 expansion and parking lot stage 1 (report by hash) | Yes, Ph1 expansion and parking lot |
| [IDA](https://www.hex-rays.com/products/ida/) | Hex-Rays disassembler. This URL now returns 404. IDA Free: non-commercial use only, cloud decompiler (x86/x64), no IDAPython | Proprietary; Pro is a paid subscription | Live product | None useful | L, analyst tool inside the VM only | No |
| [Wireshark](https://www.wireshark.org/download.html) | Packet analyser download page, v4.6.9 | GPL-2.0 (well known; the page itself says "free, open-source") | Active | tshark CLI | L, parking lot (read PCAP test captures inside the VM) | No (CTU and PCAP captures are mentioned) |
| [Default Apps](https://ninite.com/) | Ninite bulk Windows app installer | Free for home use, Pro is paid | Active | None | None: clashes with the pinned-hash install policy | No |
| [FakeNet](https://sourceforge.net/projects/fakenet/) | Original FakeNet on SourceForge, beta, "Other License" | Other | Dead: last update 2013-05-29. Replaced by mandiant/flare-fakenet-ng (Apache-2.0, push 2026-10-30, Python) | None | M, parking lot (network simulation in dynamic-analysis VM, use FakeNet-NG) | No |
| [ELF Digest](https://elfdigest.com/) | Title "ELF DIGEST" only (SPA). Purpose not verifiable | Unknown | Unknown (renders a title, not parked) | Unknown | L (unverified) | No |
| [FileScan.io](https://www.filescan.io/scan) | OPSWAT's "Next-Gen Malware Analysis Platform" (SPA). Zeltser still lists it as free | n/a (service) | Live (title loads) | API exists (not verified here) | M, parking lot stage 1 candidate | No |
| [Cuckoo automated analysis](https://cuckoosandbox.org/) | **Domain hijacked**: now Korean sports-betting spam. cuckoosandbox/cuckoo was archived 2021-04-26 ("unmaintained") | Repo NOASSERTION | Dead | None | None (use CAPE or Cuckoo3). Never link this domain | Yes, parking lot names Cuckoo3, not Cuckoo 2 |
| [FireEye Free tools](https://www.fireeye.com/services/freeware.html) | Redirects to fireeye.market, an app catalogue (© 2018-2021) with placeholder IDs | n/a | Stale | None | None (Mandiant tools now live on GitHub: capa, FLOSS) | capa and FLOSS yes, parking lot |
| [Manalyzer](https://manalyzer.org/) | Free online static PE analyser. News dated 2025-10-11 | Service. Source JusticeRage/Manalyze is GPL-3.0 (push 2026-08-29) | Active | Web API "totally unrestricted" (docs.manalyzer.org); no key mentioned | M, parking lot stage 1/2 (JSON report by hash; or run the GPL tool in the worker) | No |
| [Sekoia.fr](https://malware.sekoia.fr/new) | Former Sekoia malware submission page | n/a | Dead: DNS ENOTFOUND | None | None | No |
| [IRIS-H](https://iris-h.services/) | Online document and file forensics UI ("Public User"; last 50 submissions show "No data found") | n/a (service) | Loads, little activity | No API docs seen | L | No |
| [CAPE Sandbox](https://capesandbox.com/analysis/) | Public CAPE instance. 403 to our fetcher. kevoreilly/CAPEv2: push 2026-11-11, Python, 3.7k stars | Repo NOASSERTION (GitHub cannot classify; check LICENSE before reuse) | Very active | REST API on self-hosted instances; config extraction | H, parking lot stage 3 (self-hosted sandbox read through its API) | Yes, parking lot |
| [APK Analysis](https://github.com/ndelphit/apkurlgrep/blob/master/README.md) | apkurlgrep: extracts endpoints from APKs | MIT | Push 2024-05-22, Go, 904 stars | CLI | L, parking lot (mobile; take the string-extraction method) | No |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Mobile app static and dynamic analysis framework | GPL-3.0 | Very active (push 2026-11-11), Python, 22k stars | REST API | M, parking lot (run as a separate service in isolation; never import) | No |
| [Control Panel attribution](https://lp-db.github.io/lp-db/) | LP-DB: login pages of C2 panels and phishing kits. Each entry has a urlscan UUID, tags, and Malpedia ID; blockhash perceptual hash. Site is a Vue SPA | **No licence** (repo lp-db/lp-db) | Stale: push 2023-01-22, 38 stars | `data.json` in repo | M, Ph6 (panel identification) and Ph3 (page-similarity method). Fetch at runtime only | No by name (Ph6 favicon/panel pivots are close) |
| [James_inthe_box's tools](https://pastebin.com/s5whXhXH) | Paste "Tools used in Tweets", 2017-09-30: an analysis tool list | n/a | Stale (2017) | None | L, reference only | No |
| [C&C server communication attribution](https://github.com/silence-is-best/c2db) | c2db: Markdown of known C2 and exfil traffic strings for about 70 families (HTTP, SMTP, hex patterns, some PCAP links) | **No licence** | Stale: push 2023-02-06, 193 stars | Markdown only | M, Ph6 (default-signature library: re-key facts such as URI paths and headers, no copying) | No by name (Ph6 default-signature library) |
| [GreyNoise](https://viz.greynoise.io/) | GreyNoise visualiser. 403 to our fetcher | n/a (service) | Live | Community API (already used) | Already built (Ph1). Swarm parked | Yes, Ph1 and parking lot |
| [Telltale by Kryptos Logic](https://telltale.kryptoslogic.com/) | "The Actionable Breach Intelligence Service". Only a browser-support notice rendered | n/a (service) | Unclear | None seen | L | No |
| [Emerging Threats](https://rules.emergingthreats.net/) | Proofpoint ET rule downloads. ET Open needs no registration: `open/suricata-$ver/emerging.rules.tar.gz`, `version.txt`, plus an `open-nogpl/` directory | Not stated on page (ET Open is a GPL/BSD mix; `open-nogpl` exists) | Active: daily on weekdays | Tarballs; poll `version.txt` | H, parking lot (match honeypot exploit attempts to CVEs via `reference:cve`) and Ph2/Ph8 (detection-coverage signal) | Partly: parking lot says "IDS rules that carry CVE IDs"; ET not named |
| [List of Automated Malware Analysis tools](https://zeltser.com/automated-malware-analysis/) | Zeltser's list of free sandboxes (20), updated 2026-06-30 | n/a | Active | None | M, reference for parking lot stage 1 source list | Partly (Triage, HA named) |

**Malware sharing sites**

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [OTX Alienvault](https://otx.alienvault.com/) | Now "LevelBlue - Open Threat Exchange" (SPA) | n/a (service) | Live | API with free key (in use) | Already built | Yes, Ph1 |
| [Koodous APKs](https://koodous.com/) | Collaborative Android malware platform (© 2015-2026) | n/a (service) | Live | API: Apks, Feed, Rulesets, Notifications; usage-limits page; key terms not seen | L-M, parking lot (mobile samples and YARA notifications) | No |
| [BlueLiv](https://community.blueliv.com/#!/discover) | Blueliv Threat Exchange Network | n/a | Dead: DNS ENOTFOUND | None | None | No |
| [URLhaus](https://urlhaus.abuse.ch/) | abuse.ch/Spamhaus malicious URL DB | Terms page (not read) | Active | API, bulk API, feeds | Already built | Yes, Ph1 |
| [Malware Bazaar](https://bazaar.abuse.ch/) | abuse.ch sample sharing | Terms page (not read) | Active | API, exports | Already built; corpus source | Yes, Ph1 and parking lot |
| [MalShare](https://malshare.com/) | Sample repository. Newest sample 2026-11-11 | n/a (service, ToS) | Active | Free registered `api_key`: `getlist` (24 h hashes), `details`, `hashlookup` (POST), `search`, `getfile`, `getlimit` | M-H, Ph1 expansion (hash lookup) and parking lot (daily hash list) | Yes, Ph1 expansion |
| [Virus Bay](https://beta.virusbay.io/) | Former sample-sharing community | n/a | Dead: DNS does not resolve | None | None | No |
| [InQuest](https://labs.inquest.net/) | InQuest Labs (DFI, IOC DB, REP DB). Fetch got "socket hang up". InQuest was bought by OPSWAT in Aug 2024 | n/a | Uncertain (likely folded into OPSWAT) | Formerly a free API | L until status is confirmed | No |

**YARA**

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [McAfee YARA rules](https://github.com/advanced-threat-research/Yara-Rules) | Trellix ATR rules accompanying its blogs | Apache-2.0 | Slow: push 2025-03-18, 631 stars | .yar files | M, Ph8/Ph9 (rule corpus tagged by family/actor) | No (Ph9 "public detection rules" generic) |
| [InQuest YARA](https://github.com/InQuest/awesome-yara) | Curated list of YARA rule sets, tools, people | CC BY 4.0 | Active: push 2026-06-15, 4.3k stars | List | M, reference for Ph8 rule sources and tooling | No |
| [VirusTotal YARA](https://github.com/VirusTotal/yara) | YARA engine (C). Successor YARA-X (Rust, BSD-3, push 2026-11-11) | BSD-3-Clause | Active: push 2026-10-27, 10k stars | `yara-python` 4.5.4 (Apache-2.0, cp312 wheels for win_amd64 and manylinux, 2025-05-27); `yara-x` 1.23.0 (BSD, abi3 cp39+ wheels win_amd64 and manylinux_2_28, 2026-11-05) | H, Ph8 (compile-check generated rules) and parking lot static analysis | YARA yes (Ph8, parking lot); library not chosen |
| [ReversingLabs YARA](https://github.com/reversinglabs/reversinglabs-yara-rules/tree/develop/yara) | RL's family rules (default branch `develop`) | MIT | Active: push 2025-11-03, 952 stars | .yar files | H, Ph8/Ph9 (MIT: can ship with attribution) | No |
| [THOR Scanner YARA](https://github.com/Neo23x0/signature-base) | Florian Roth's signature-base: YARA rules plus IOC text files | DRL 1.1 (attribution, including in alerts) | Very active: push 2026-11-06, 3k stars | .yar and IOC .txt | H, Ph8/Ph9 (rules) and Ph1/Ph6 (IOC lists as local match data, with credit) | No by name (DRL 1.1 already noted for Sigma) |
| [YARA scan](https://riskmitigation.ch/yara-scan/) | Hosted YARA retro-scan service | n/a | **Discontinued** Sept 2024; API returns 403 `service_shutdown` | None | None (YARAify fills this role) | YARAify yes, Ph1 |

**Decoding & Deobfuscation**

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [ROT13](https://rot13.com/) | ROT-n web tool | n/a | Live | None | None (stdlib `codecs`) | No |
| [BASE64](https://www.base64decode.org/) | Base64 web decoder. 403 to our fetcher | n/a | Presumed live | None | None (stdlib); pasting data to a third party is an OPSEC leak | Ph5 decodes Base64 in-house |
| [CyberChef](https://gchq.github.io/CyberChef/) | GCHQ data-transform web app; runs fully client-side. v11.5.0, build 2026-11-04 | Apache-2.0 | Very active: push 2026-11-07, 36k stars | Static build; recipes in URL | M, Ph2/parking lot (vendor a pinned offline build, or deep-link "open in CyberChef" with a recipe) | No |
| [Dcode](https://www.dcode.fr/) | 900+ cipher and puzzle tools | Results reusable CC-BY; no public API | Live | No API | L | No |
| [Obfuscation technique](https://obfuscator.io/) | JS obfuscator service built on javascript-obfuscator (BSD-2, push 2026-11-11); paid VM obfuscation | Service; lib BSD-2 | Active | None | None (attacker-side); L as a reference for recognising patterns | No |
| [Code beautifier](https://beautifier.io) | js-beautify web UI | MIT (beautifier/js-beautify, push 2026-10-19) | Active | PyPI `jsbeautifier` (MIT, py3 wheel; 2.0.3 latest) | L-M, parking lot (pretty-print JS from phishing kits inside the worker) | No |

**Workshops, Checklists, Tips, Tutorials**

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [malwareunicorn RE101](https://malwareunicorn.org/workshops/re101.html#0) | RE101 Windows malware workshop | n/a | Static, about 2019 | None | L, Ph10 reading list | No |
| [pramos lab article](https://medium.com/@pramos/why-you-need-you-a-malware-analysis-lab-and-how-to-build-it-10048eaa8e9) | Medium article on building a malware lab. 403 to our fetcher | n/a | Unknown | None | L, reference for the parking lot VM | No |
| [t.me/s/androidMalware](https://t.me/s/androidMalware) | "Android Security & Malware" channel, 44.5K subscribers; public web preview works | n/a | Active (msg id about 3003) | Public `t.me/s/` HTML preview (no join needed) | L-M, Ph4/Ph5 (mobile-threat link source via preview) | Telegram collection yes, Ph5; channel no |
| [t.me/s/malwareplayground](https://t.me/s/malwareplayground) | Renders only a contact page; no channel preview | n/a | Unknown | None | None | No |
| [Collection](https://zeltser.com/malware-sample-sources/) | Zeltser's 20 free sample sources (MalwareBazaar, MalShare, Triage, VirusShare, vx-underground, theZoo and more), updated 2025-12-18 | n/a | Active | None | M, parking lot corpus source checklist | Partly (MalwareBazaar, vx-underground) |
| [Free eBook](https://beginners.re/) | Yurichev's *Reverse Engineering for Beginners* | CC BY-SA 4.0 | Static | PDFs | L, Ph10 reading list | No |
| [Forums](https://www.kernelmode.info/) | Former KernelMode.info RE forum | n/a | **Dead/repurposed**: 301 to unrelated xoilactvst.net (not followed) | None | None | No |

**VirusTotal accounts** (all 17 are VT GUI SPA pages: the fetch returned only "VirusTotal". VT API v3 exposes `/api/v3/users/{id}/comments` as a relationship; it needs a key, and free-tier availability is unconfirmed.)

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [CYBERCOM_Malware_Alert](https://www.virustotal.com/en/user/CYBERCOM_Malware_Alert/) | USCYBERCOM VT profile (legacy `/en/user/` URL) | n/a | **404** (old URL format) | `/gui/user/CYBERCOM_Malware_Alert` + API | M as a group (see notes) | No |
| [dnwls0719](https://www.virustotal.com/gui/user/dnwls0719/comments) | VT researcher comments | n/a | SPA, title only | API v3 users/comments | Group M | No |
| [sns_amigo](https://www.virustotal.com/gui/user/sns_amigo/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [jameswt](https://www.virustotal.com/gui/user/jameswt/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [QVMESET](https://www.virustotal.com/gui/user/QVMESET/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [GrujaRS](https://www.virustotal.com/gui/user/GrujaRS/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [khahn](https://www.virustotal.com/gui/user/khahn/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [pcrisk](https://www.virustotal.com/gui/user/pcrisk/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [intezer_analyze](https://www.virustotal.com/gui/user/intezer_analyze/comments) | Intezer bot comments (family attribution) | n/a | SPA, title only | same | Group M | No |
| [Mao_Ware](https://www.virustotal.com/gui/user/Mao_Ware/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [jslowik](https://www.virustotal.com/gui/user/jslowik/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [r7_babd](https://www.virustotal.com/gui/user/r7_babd/comments) | Rapid7 comments | n/a | SPA, title only | same | Group M | No |
| [cryptokitty](https://www.virustotal.com/gui/user/cryptokitty/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [QuoIntelligence](https://www.virustotal.com/gui/user/QuoIntelligence/comments) | QuoIntelligence comments | n/a | SPA, title only | same | Group M | No |
| [siri](https://www.virustotal.com/gui/user/siri/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |
| [SWITCHCERT](https://www.virustotal.com/gui/user/SWITCHCERT/comments) | SWITCH-CERT comments | n/a | SPA, title only | same | Group M | No |
| [patricksvgrapi](https://www.virustotal.com/gui/user/patricksvgrapi/comments) | VT researcher comments | n/a | SPA, title only | same | Group M | No |

**Navigation**

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [Home](https://github.com/BushidoUK/Open-source-tools-for-CTI/blob/master/README.md) | Index README of the source list | None (no licence) | Push 2026-02-08 | n/a | n/a | n/a |

### Honeypots.md (5 links)

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [Modern Honey Network (MHN)](https://github.com/Pwnlandia/mhn) | Central honeypot manager (Flask; deploys Cowrie, Dionaea, Snort and others) | LGPL-2.1 | Stale: push 2024-11-30. Supports Ubuntu 16.04/18.04 and CentOS 6.9; Py3 rewrite partial; Docker "not maintained" | HTTP API, hpfeeds | L (superseded by T-Pot) | No |
| [MHN setup Tutorial](https://www.youtube.com/watch?v=Y2gH5kHetNc) | YouTube "MHN Install & Configuration" | n/a | Channel and date not visible | None | None | No |
| [T-pot Honeypot](https://github.com/dtag-dev-sec/tpotce) | Now telekom-security/tpotce: multi-honeypot platform (31 listed, including cowrie, dionaea, log4pot, citrixhoneypot, ciscoasa, LLM honeypots) plus an Elastic stack | GPL-3.0 (components mixed) | Very active: push 2026-11-08, 9.7k stars | Elasticsearch/Kibana; ships to Telekom community backend **by default** (opt out by removing `ewsposter`) | H, parking lot (own sensors on a VPS) | Yes, parking lot ("T-Pot is the usual candidate") |
| [HoneyDrive by Brute Force Labs](https://bruteforce.gr/honeydrive/) | Honeypot Linux distro OVA (Kippo, Dionaea, Honeyd, Glastopf) | Not stated | Dead: last release July 2014, Xubuntu 12.04 32-bit | None | None | No |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/blob/master/README.md) | Old repo name; resolves to BushidoUK/Open-source-tools-for-CTI | None | Push 2026-02-08 | n/a | n/a | n/a |

### Github Projects.md (24 links)

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [VECTR](https://github.com/securityriskadvisors/VECTR) | Red/blue team test tracking mapped to ATT&CK | Community Edition EULA (not OSS; GitHub shows none) | Active: push 2026-08-14, 1.6k stars | GraphQL API; self-host Ubuntu 22.04 | L-M, Ph9 (take the method: test-result-to-technique coverage) | No |
| [Harpoon](https://github.com/Te-k/harpoon) | CLI wrapping many OSINT/TI APIs | GPL-3.0 (PyPI metadata conflicts: also MIT classifier) | Repo push 2026-09-11; PyPI 0.1.7 wheel from 2022-07-25 (stale release) | CLI, Python lib | M, Ph1/Ph6 (method and plugin list only; GPL, stale PyPI: no dependency) | No |
| [OSweep](https://github.com/ecstatic-nobel/OSweep) | Splunk OSINT dashboard app | MIT | Dead: push 2021-01-26 | Splunk app | L | No |
| [Goog-mail](https://github.com/BushidoUK/Goog-mail) | Script scraping Google results for addresses at a domain | **No licence** | Dead: push 2021-04-06, 7 stars | None | L, Ph7 (Hunter.io already chosen; Google scraping is fragile) | Hunter.io yes, Ph7 |
| [Sherlock](https://github.com/sherlock-project/sherlock) | Username search across sites | MIT | Very active: push 2026-11-11, 110k stars | CLI; site JSON | M, Ph7 (ideas and cross-check; own checker decided) | Yes, Ph7 |
| [Slurp](https://github.com/0xbharath/slurp) | S3 bucket enumerator | GPL-3.0 | Dead: push 2022-08-18 | CLI (Go) | None: roadmap forbids guessing storage names | Ph3 "no guessing of storage names" |
| [Yar](https://github.com/Furduhlutur/yar) | Moved to nielsing/yar: secret hunting in org/user git history | GPL-3.0 | Dead: push 2021-01-03, Go | CLI | L, Ph3 | Ph3 GitHub secret leaks (tool not named) |
| [ComboList Generator](https://github.com/jsoverson/combolist-generator) | Generates combolists | **No licence** | Dead: push 2019-05-10, 10 stars | None | None | No |
| [URL Crazy](https://github.com/urbanadventurer/urlcrazy) | Typo-domain generator and checker | **No licence** detected | Active-ish: push 2025-07-28, Ruby, 702 stars | CLI | L-M, Ph3 (cross-check dnstwist's permutation classes; method only) | dnstwist yes, Ph3; URLCrazy no |
| [Automater](http://www.tekdefense.com/automater/) | TekDefense IP/URL/MD5 OSINT aggregator. Site fails TLS. Repo 1aN0rmus/TekDefense-Automater: MIT, push 2024-08-13 | MIT (repo) | Stale | CLI | L (Ph1 already does this) | No |
| [GitGot](https://github.com/BishopFox/GitGot) | Feedback-driven GitHub secret search | LGPL-3.0 | Stale: push 2024-03-07, 1.6k stars | CLI | M, Ph3 (take method: dismiss-and-learn noise filtering) | Ph3 GitHub leaks yes; tool no |
| [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) | Now RedSiege/EyeWitness: web screenshots, headers, default-credential hints | GPL-3.0 | Active: push 2026-01-05, 5.9k stars | CLI, reports | L-M, Ph3/Ph6 (screenshot method; Playwright planned) | Screenshot hash yes, Ph3; tool no |
| [RED_HAWK](https://github.com/Tuhinshubhra/RED_HAWK) | PHP recon and vulnerability scanner | MIT | Stale: push 2024-07-31 | CLI (PHP) | None (active scanning) | No |
| [Infoga](https://github.com/m4ll0k/Infoga) | Email OSINT tool | n/a | **Dead: repo 404** | None | None | No |
| [KockMail](https://github.com/4w4k3/KnockMail) | Checks whether an email exists via SMTP | BSD-3-Clause | Dead: push 2021-12-31 | CLI | L: SMTP probing touches the target's mail server | No |
| [ReconDog](https://github.com/s0md3v/ReconDog) | Recon wrapper (HackerTarget and others) | Apache-2.0 | Dead: push 2021-01-26 | CLI | L | No |
| [Sn1per](https://github.com/1N3/Sn1per) | Offensive recon, scan, exploit platform; Pro $984/seat/yr | Custom source-available EULA | Active: push 2026-10-27 | CLI, MCP server | None (offensive, licence) | No |
| [Final Recon](https://hakin9.org/final-recon-osint-tool-for-all-in-one-web-reconnaissance/) | Hakin9 article **404**. Tool is thewhiteh4t/FinalRecon: headers, SSL, whois, DNS, crawl, Wayback, dir enum | MIT (repo) | Active: push 2026-10-31, 3k stars | CLI | L-M, Ph7 (method; most of it is planned) | No |
| [Holehe](https://github.com/megadose/holehe) | Email-to-registered-sites checker | GPL-3.0 | Slowing: push 2024-09-10, 15.6k stars | CLI, PyPI | M, Ph7 (wrap CLI in separate venv; site modules rot) | Yes, Ph7 |
| [Git Hound](https://github.com/tillson/git-hound) | GitHub-wide secret search with dorks | MIT | Active: push 2026-02-10, Go | CLI | M, Ph3 (wrap binary or take dork method) | Ph3 GitHub leaks yes; tool no |
| [SubDomainizer](https://github.com/nsonaniya2010/SubDomainizer) | Finds subdomains, cloud URLs, and secrets in a page's JS files | MIT | Active: push 2026-09-14 | CLI | M, Ph3/Ph7 (method: parse page JS for hosts and buckets) | Subdomain enum yes (Subfinder); this no |
| [Get All Urls](https://github.com/lc/gau) | gau: known URLs for a domain from Wayback, Common Crawl, OTX, urlscan | MIT | Active: push 2026-10-12, 5.2k stars | CLI (Go) | M-H, Ph6/Ph7 (take method in httpx: Wayback CDX + CC index + OTX `url_list` + urlscan search) | No (Wayback not in roadmap) |
| [GHunt](https://github.com/mxrch/GHunt) | Google account OSINT; needs a logged-in Google session | AGPL-3.0 | Active: push 2026-04-10, 19.8k stars | CLI | L-M, Ph7 (method only: AGPL and needs session cookies) | Yes, Ph7 ("GHunt-style") |
| [Home](https://github.com/BushidoUK/Opensource-tools/) | Old repo name; resolves to Open-source-tools-for-CTI | None | Push 2026-02-08 | n/a | n/a | n/a |

### Chrome Extensions.md (23 links)

Nothing was installed. Store URLs redirect to chromewebstore.google.com. "Empty listing" means the store served an `empty-title` page, so the extension is no longer listed.

| Name | What it is | Licence | Maintained? | API/data | Value (method as toolkit feature) | In roadmap? |
|---|---|---|---|---|---|---|
| [Shodan](https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap?utm_source=chrome-ntp-icon) | Shows Shodan host data for the current site | Proprietary | v2.0.0, 2025-03-13, 100k users | Shodan | L (Ph1 Shodan and InternetDB already built) | Yes, Ph1 |
| [Sputnik](https://chrome.google.com/webstore/detail/sputnik/manapjdamopgbpimgojkccikaabhmocd?utm_source=chrome-ntp-icon) | Right-click OSINT lookups for IP, domain, hash, URL (about 50 services) | Repo mitchmoser/sputnik NOASSERTION | v1.25, 2026-03-02, 10k users | URL links | M, Ph1 ("open in" link list per IOC type) | No |
| [Mitaka](https://chrome.google.com/webstore/detail/mitaka/bfjbejmeoibbdpfdbmbacmefcbannnbg?utm_source=chrome-ntp-icon) | IOC select, refang, then search or scan on 50+ services | MIT (ninoseki/mitaka) | v2.10.1, 2026-08-27; repo push 2026-10-21 | URL templates in source | H-M, Ph1/Ph2 (pivot-link templates; refang cases for extractor tests) | No |
| [Threat Pinch](https://chrome.google.com/webstore/detail/threatpinch-lookup/ljdgplocfnmnofbhpkjclbefmjoikgke) | ThreatPinch Lookup (IOC hover lookups) | Repo cloudtracer/ThreatPinchLookup: no licence | **Empty listing**; repo push 2018-09 | None | None | No |
| [Treeverse](https://chrome.google.com/webstore/detail/treeverse/aahmjdadniahaicebomlagekkcnlcila) | Was a Twitter thread tree viewer; repo now does Bluesky | MIT (paulgb/treeverse) | **Empty listing**; repo push 2025-03-21 | None | L | No |
| [Distill Web Monitor](https://chrome.google.com/webstore/detail/distill-web-monitor/inlikjemeeknofckkjolnjbpehgadgge?utm_source=chrome-ntp-icon) | Page or feed change monitor with alerts; paid tiers | Proprietary | v4.2.21, 2026-10-17, 400k users | None | M, Ph5/Ph3 (change detection already designed) | Yes, Ph5 source-monitor change detection |
| [Bulk URL Opener](https://chrome.google.com/webstore/detail/bulk-url-opener-extension/hgenngnjgfkdggambccohomebieocekm?utm_source=chrome-ntp-icon) | Opens a list of URLs in tabs | Proprietary | v2.7.0.1, 2026-02-24, 300k users | None | L ("open all pivot links" button) | No |
| [uBlock Origin](https://chrome.google.com/webstore/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm?utm_source=chrome-ntp-icon) | Content blocker | GPL-3.0 (gorhill/uBlock, push 2026-11-10) | **Empty listing** (MV2 removal) | None | None (analyst hygiene) | No |
| [Search by Image](https://chrome.google.com/webstore/detail/search-by-image/cnojnbdhbhnkbcieeekonklommdnndci) | Reverse image search on 30+ engines | Not checked | v8.5.4, 2026-06-16, 300k users | Engine URL list | M, Ph3/Ph7 (manual reverse-image links) | Yes, Ph3 and Ph7 manual reverse-image links |
| [RevEye](https://chrome.google.com/webstore/detail/reveye-reverse-image-sear/keaaclcjhehbbapnphnmpiklalfhelgf) | Reverse image search (Lens, Bing, Yandex, TinEye) | Proprietary | v2.0.0, 2024-09-03, 100k users | None | L-M (same feature as above) | Yes (same) |
| [Imagus](https://chrome.google.com/webstore/detail/imagus/immpkjjlgappgfkkfieppnmlhakdmaab) | Hover image enlarger | n/a | **Empty listing** | None | None | No |
| [GoFullPage](https://chrome.google.com/webstore/detail/gofullpage-full-page-scre/fdpohaocaechififmbbbbbknoalclacl) | Full-page screenshot to PNG/PDF | Proprietary | v8.11, 2026-11-07, 11M users | None | M, Ph3/Ph5 (Playwright `full_page` evidence capture) | Playwright Ph5, screenshot hash Ph3 |
| [Go Back in Time](https://chrome.google.com/webstore/detail/go-back-in-time/hgdahcpipmgehmaaankiglanlgljlakj?utm_source=chrome-ntp-icon) | Wayback/cache link for current page | n/a | **Empty listing** | None | L (a Wayback link per URL is trivial) | No |
| [Stratus Mitre ATT&CK TTPs](https://chrome.google.com/webstore/detail/stratus/jjpceekakjijeamhoeedjfgmhgbefcmp?utm_source=chrome-ntp-icon) | ATT&CK TTP helper | n/a | **Empty listing** | None | None (Ph2 ATT&CK ID extraction covers this) | ATT&CK extraction yes, Ph2/Ph9 |
| [Link Redirect Trace](https://chrome.google.com/webstore/detail/link-redirect-trace/nnpljppamoaalgkieeciijbcccohlpoh) | Redirect-chain and header analyser (SEO) | Proprietary | v1.1.5.27, 2024-06-15, 100k users | None | M, Ph1/Ph6 (show redirect chain from urlscan; never fetch malicious URLs directly) | Ph6 "redirect target" pivot yes |
| [Pulsedive](https://chrome.google.com/webstore/detail/pulsedive-threat-intellig/gdbemlfgncdmmljmkkcemfedbbfgghcp?hl=en) | Highlights and enriches IOCs on any page | Proprietary | v3.0.1, 2024-06-21, 2k users | Pulsedive API | M (via API, not the extension) | Yes, Ph1 expansion |
| [Browserling](https://chrome.google.com/webstore/detail/browserling-cross-browser/chfdigebbepdmeelcfiefkklfldmmgld?hl=en) | Opens the page in a remote cloud browser | Proprietary, freemium | v3.0.5, 2026-11-06, 10k users | None | L (third party sees the URL) | No |
| [RocketReach](https://chrome.google.com/webstore/detail/rocketreach-chrome-extens/oiecklaabeielolbliiddlbokpfnmhba) | Sales prospecting emails and phones | Proprietary, paid | v4.0.15, 2026-08-10, 300k users | Paid API | None (same reasoning as Apollo.io rejection) | No (Apollo rejected, Ph7) |
| [Hunter.io Email Finder](https://chrome.google.com/webstore/detail/hunter-email-finder-exten/hgmhmanijnjhaffoampdlllchpolkdnj) | Domain email search; 50 free credits/month | Proprietary | v3.3.3, 2026-11-11, 700k users | Hunter API | M (via API) | Yes, Ph7 |
| [Privacy Badger](https://chrome.google.com/webstore/detail/privacy-badger/pkehgijcmpdhfbdbbnkijodmdjhbjlgp) | EFF tracker blocker | Open source (EFF) | v2026.9.15.2, 2026-10-09, 1M users | None | None (hygiene) | No |
| [InVID](https://chrome.google.com/webstore/detail/fake-news-debunker-by-inv/mhccpoafgdgbhnjfhkcmgknndkeenfhe) | Video/image verification: keyframes, forensics, reverse search | EU research project | v0.94, 2026-11-02, 100k users | None | L-M, Ph7 persona vetting (manual-review link) | Partly (Ph7 manual-review links) |
| [DumpItBlue+](https://chrome.google.com/webstore/detail/dumpitblue%2B/igmgknoioooacbcpcfgjigbaajpelbfe) | Facebook page dumping helper | Proprietary | v3.2.1, 2025-04-21, 10k users | None | None (Facebook scraping) | No |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Old repo name; resolves to Open-source-tools-for-CTI | None | Push 2026-02-08 | n/a | n/a | n/a |

### High-value notes

- **YARA engine: VirusTotal/yara, yara-python, YARA-X (H, Ph8 and parking lot).** Phase 8 only needs a compiler to prove generated rules are valid; matching samples belongs in the isolated worker.
  - `yara-x` 1.23.0 (2026-11-05, BSD-3, VirusTotal-maintained) ships abi3 wheels for win_amd64 and manylinux_2_28_x86_64, so it fits `--only-binary=:all: --require-hashes`. Its `yara_x.compile(src)` raises on errors.
  - `yara-python` 4.5.4 (Apache-2.0) also has cp312 wheels, but its last release was 2025-05.
  - Proposal: yara-x, used for compile-check only (no scanning in the app process).

- **ReversingLabs YARA rules (H, Ph8/Ph9).** MIT, so it can be fetched at runtime and could even be vendored with attribution. Rules are family-named, which maps to Phase 9 family and actor profiles and to the "Defend" tab. Use the `develop` branch, `yara/` tree.

- **signature-base (H, Ph8/Ph9, and Ph1/Ph6 local match data).** DRL 1.1 requires author attribution on any shared rule and in alerts generated from matches. It is the same licence family as Sigma, which the roadmap already handles. Fetch at runtime into the data directory and never vendor. Besides .yar rules, the repo carries IOC text lists (C2, hash, filename); I did not re-open those files in this pass. They can serve as a zero-quota local gate: "known in signature-base".

- **Emerging Threats Open (H, parking lot sensors, Ph2/Ph8).**
  - Keyless download: `https://rules.emergingthreats.net/open/suricata-<ver>/emerging.rules.tar.gz`. Poll `version.txt` once a day; ET updates on weekdays.
  - Rules carry `reference:cve,YYYY-NNNN`. That gives (a) the CVE matcher the parking lot's "own sensors" plan needs and (b) a Phase 2 "network detection exists" flag per CVE, like the Nuclei signal.
  - Licence is mixed GPL/BSD (an `open-nogpl` set exists): fetch at runtime, never vendor.

- **T-Pot (H, parking lot).** Now telekom-security/tpotce, GPL-3.0, pushed 2026-11-08.
  - Needs 8 GB RAM and a 128 GB SSD for a Sensor, or 16 GB and 256 GB for a Hive. Runs on Debian 13 / Ubuntu 26.04 server images and is tested on cloud.
  - Community data submission is **on by default**: remove the `ewsposter` service in `docker-compose.yml` to opt out. Record this as an OPSEC step in the parking-lot plan.
  - Distributed mode (Hive plus Sensors) matches the multi-VPS idea. The toolkit reads its Elasticsearch read-only.

- **CAPEv2 (H, parking lot stage 3).** Most active open sandbox (pushed today); it does config extraction. Run it as a separate service and read its REST API. GitHub reports licence NOASSERTION, so read LICENSE before reusing any code; API use is fine. The public capesandbox.com instance returned 403 to the fetcher. Cuckoo 2 is archived, and **cuckoosandbox.org is now a gambling spam site**: no links to it anywhere.

- **Mitaka / Sputnik method (H-M, Ph1/Ph2).**
  - Add a deterministic "search on…" link set beside each enrichment result: a table of `{service, ioc_types, url_template}`.
  - Mitaka is MIT, with 50+ services, so its template list can be re-keyed with credit. Sputnik's licence is unclear, so ideas only.
  - Mitaka's refang examples (`[.]`, `[at]`, `hxxp`) make good unit-test cases for the in-house Phase 2 extractor.
  - Links open in the analyst's browser, so the toolkit sends nothing itself.

- **gau method (M-H, Ph6/Ph7).** Historical URLs for a domain from four sources: Wayback CDX API (keyless), Common Crawl index (keyless), OTX `/indicators/domain/{d}/url_list` (key already held), and urlscan search (key held). Implement in httpx rather than wrapping the Go binary. Useful for phishing-kit paths, C2 URL patterns, and exposed files on lookalike domains.

- **MalShare (M-H, Ph1 expansion, already planned).** Free registered key. `/api.php?api_key=…&action=details&hash=` covers lookup, and `action=getlist` gives the last 24 h of hashes for the corpus. Quota via `action=getlimit` (the number is not published). Read `tos.php` before use.

- **LP-DB and c2db (M, Ph6 default-signature library).**
  - Both have no licence, so facts are re-keyed and the data is fetched at runtime only.
  - LP-DB `data.json` maps panel names to urlscan scan UUIDs and Malpedia IDs. Its blockhash perceptual-hash approach matches the Phase 3 page-similarity idea.
  - c2db lists distinctive C2 HTTP paths, headers, and byte markers per family.

- **CyberChef (M).** Apache-2.0, fully client-side. Either vendor a pinned offline build under `static/` (with checksum, like HTMX) or add "open in CyberChef" deep links with a recipe in the URL fragment. Keeps decoding offline, unlike base64decode.org and similar sites.

- **Manalyzer (M, parking lot stage 1/2).** Free, unrestricted web API returning a JSON PE static report by hash (docs.manalyzer.org). The tool is GPL-3.0: run it in the worker as a CLI, never import it.

- **VirusTotal researcher accounts (M, Ph1/parking lot).** VT API v3 `GET /api/v3/users/{id}/comments` could add a "trusted commenters" filter to the VT card: comments on a hash from these 17 accounts (Intezer, SWITCH-CERT, Rapid7, pcrisk and others) shown first. Whether the free public key may read user relationships is unconfirmed; test with one call.

- **Harpoon (M, method only).** GPL-3.0, and the PyPI release is stale (0.1.7, 2022), so not a dependency. Its plugin list is a checklist of TI APIs to compare with the Phase 1 expansion.

(Links not checked: see appendix.)

---

## H-aux: auxiliary sub-lists (VPN, VMs, email, OPSEC, certs, training, Twitter tools, podcasts, conferences, YouTube, Misc)

Checked 2026-11-11 against BushidoUK/Open-source-tools-for-CTI, branch master.
186 links across 11 sub-files. Most are reference only; the toolkit-relevant finds are
in "High-value notes".

General notes:
- The "Home" link at the foot of most files (github.com/WilliamThomas-sec/Opensource-tools/...)
  is the old name of the source repo. It now resolves to BushidoUK/Open-source-tools-for-CTI
  (837 stars, 510 commits, no licence shown on the repo page, so treat it as all rights reserved:
  read it, re-key facts, do not copy text).
- The InfoSecTwitter file is not a list of accounts. It lists Twitter *tools* (10 links), so there
  were no X profile links to skip. X links do appear in Podcasts (1) and Misc (1). Both were
  tried: x.com returns HTTP 402. Recorded as "X/Twitter, not renderable".
- A shared WebFetch domain-safety rate limit hit this run several times. Domains that failed
  twice were not retried by another route (see "Links not checked").
- WebFetch cached two linked PDFs (Misc rows 19 and 20) under the session's tool-results folder
  on its own. I did not open, save, or use them anywhere else.
- Roadmap column: "yes, PhN" means the item, or the same thing under another name, is already in
  ROADMAP.md. Line numbers are from the 2026-11-11 working copy.

### VPN & Private browsing (7 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Proton VPN](https://protonvpn.com/) | Commercial VPN with a free plan (1 device, 10 countries) | n/a (service) | Yes, page updated Apr 2026 | None relevant | L, Ph5 egress option | yes, Ph5 egress ladder rung 5 (Mullvad, Proton) |
| [CyberGhost VPN](https://www.cyberghostvpn.com/) | Paid commercial VPN, no free tier | n/a (service) | Yes | None | None | no |
| [The Onion Router (TOR)](https://www.torproject.org/) | Tor Project home page and Tor Browser | n/a (site); Tor is BSD-3 | Yes | Tor exit list (check.torproject.org) is a separate keyless data source | M, Ph5 onion egress, Ph6 exit-list gate | yes, Ph5 egress + Ph6 local gate |
| [I2P](https://geti2p.net/en/) | Anonymity network. 301 redirect to i2p.net | n/a (site) | Yes, 2.14.1 released 2026-11-04 | None | L, reference only | no |
| [Freenet](https://freenetproject.org/index.html) | Renamed Hyphanet. 301 redirect to hyphanet.org | n/a (site) | Yes, build 1507 on 2026-09-13 | None | None | no |
| [Brave browser](https://brave.com/) | Privacy browser. The site also links the Brave Search API | n/a (service) | Yes | Brave Search API (paid tier with free credits) | M, Ph4 dorking (already decided) | yes, Ph4 Brave Search API (decided 2026-11-06) |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Old name; resolves to the source repo | None shown | Active | n/a | None | n/a |

### VirtualMachine (32 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Kali Linux](https://www.kali.org/downloads/) | Kali download page | n/a (site); distro mixed FOSS | Yes, 2026.3 + weekly 2026-W46 | None | L, reference | no |
| [Kali on Windows](https://www.kali.org/docs/wsl/win-kex/) | Win-KeX GUI desktop for Kali under WSL2 | n/a (docs) | Page updated 2025-06-18 | None | L, Ph5 WSL2 host reference | partly: WSL2 host decided (2026-11-09), Kali not named |
| [Flare VM by FireEye](https://www.fireeye.com/blog/threat-research/2017/07/flare-vm-the-windows-malware.html) | 2017 blog. Redirects via mandiant.com to a Google Cloud services page (post gone). Project now at github.com/mandiant/flare-vm | Repo Apache-2.0 | Repo not archived, 563 commits | None | L, parking lot analysis VM | no (REMnux and Tsurugi named instead) |
| [Commando VM by FireEye](https://www.fireeye.com/blog/threat-research/2019/03/commando-vm-windows-offensive-distribution.html) | 2019 blog, same dead redirect. Offensive Windows distro, github.com/mandiant/commando-vm | Repo Apache-2.0 | Repo not archived | None | None (offensive tooling) | no |
| [TraceLabs OSINT VM](https://www.tracelabs.org/trace-labs-osint-vm/) | Trace Labs Kali-based OSINT VM page | n/a | Unknown: HTTP 403 on page and home page | None | L, Ph7 manual OSINT VM option | no |
| [Parrot OS](https://parrotlinux.org/download.php) | Calls itself an *independent guide*, not the official parrotsec.org. Lists Parrot 7.4 (Oct 2026) | n/a | Yes | None | None. Prefer parrotsec.org if ever needed | no |
| [Black Arch Linux](https://blackarch.org/downloads.html#ova-download) | BlackArch downloads | n/a (site) | Stale media: ISO 2023.05, OVA 2023.04 | None | None | no |
| [TAILs Linux](https://tails.boum.org/) | Old Tails domain. TLS cert mismatch; project moved to tails.net | n/a | tails.net live (2026 fundraiser) | None | L, operator OPSEC reference | no |
| [CSI Linux](https://csilinux.com/) | Forensics, IR, and OSINT distro (VM appliances). Training is sold separately | Says open source; licence not stated | Yes, 2026.4 | None | L, Ph7 manual OSINT VM option | no |
| [SIFT Workstation](https://digital-forensics.sans.org/community/downloads) | Old URL redirects to the SANS DFIR page. SIFT now at sans.org/tools/sift-workstation | Free, FOSS bundle | Page updated 2026-04-24 | None | L, parking lot analysis VM | no |
| [REMnux](https://remnux.org/) | Linux toolkit for malware analysis | Free (mixed FOSS) | Live, ©2026; no release date seen | None | M, parking lot analysis VM | yes, decisions log 2026-11-09/10 and open item "Analysis VM ... (Tsurugi, REMnux)" |
| [Buscador VM](https://inteltechniques.com/buscador/) | IntelTechniques OSINT VM | n/a | Dead: HTTP 404 (discontinued) | None | None | no |
| [WhoNix](https://www.whonix.org/) | Tor-routed OS that runs as VMs | n/a (site); FOSS | Live, ©2026 | None | L, Ph5 isolation reference | no |
| [TAILS](https://tails.boum.org/index.en.html) | Duplicate of the Tails row (same old domain) | n/a | Moved to tails.net | None | L | no |
| [Qubes](https://www.qubes-os.org/) | Xen-compartmentalised OS | n/a (site); GPL | Yes, 4.3.2, news 2026-11-10 | None | L, reference | no |
| [QEMU](https://www.qemu.org/) | Machine emulator and virtualiser | GPL-2.0 (not stated on page) | Yes, 11.1.3 on 2026-10-28 | None | L, parking lot sandbox (CAPE uses KVM/QEMU) | partly: CAPE/KVM in parking lot |
| [OpenBSD](https://www.freebsd.org/) | **Mislabelled:** the link goes to FreeBSD, not OpenBSD | n/a | FreeBSD 15.1 | None | None | no |
| [Virtual Box](https://www.virtualbox.org/) | Oracle VirtualBox hypervisor | GPL-3.0 base (page says "open source") | Yes, 7.2.22 on 2026-10-20 | None | M, Ph8 isolation ladder | yes, Ph8 "VirtualBox VM for unfamiliar or untrusted sources" |
| [Virtual Machines from Microsoft](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/) | Free Edge/Windows test VMs | n/a | Dead: HTTP 404 (retired) | None | None | no |
| [Docker](https://www.docker.com/) | Container platform; Personal plan is $0 | n/a (service); Engine Apache-2.0 | Yes | None | M, Ph5 sidecars, Ph8 Compose | yes, Ph5/Ph8 |
| [Autopsy Sleuth Kit (Forensics)](https://www.sleuthkit.org/autopsy/) | Disk forensics GUI on The Sleuth Kit | Free (Apache-2.0 per its licences page; not read) | ©2003-2026; no version seen | None | L, reference | no |
| [Access Data FTK Imager (Forensics)](https://accessdata.com/product-download/ftk-imager-version-4-3-0) | Redirects to the exterro.com home page, which does not mention FTK Imager | Proprietary freeware | Link dead (product moved to Exterro) | None | None | no |
| [Termux Android Terminal Emulator](https://termux.com/) | termux.com 302 redirects to the Google Play listing. Upstream project is GitHub termux/termux-app | GPL-3.0 (upstream) | Redirect only; Play listing not fetched | None | None | no |
| [ProxMox](https://proxmox.com/en/) | Proxmox VE hypervisor | AGPL-3.0 (upstream; not shown) | Yes, VE 9.2 | REST API (own host) | L, possible always-on monitoring host | no (open question on the host machine) |
| [pfSense (free FireWall)](https://www.pfsense.org/) | Firewall distro | Apache-2.0 (CE; not shown) | No version shown on page | None | None | no |
| [ClamAV (free Anti-Virus)](https://www.clamav.net/) | Open-source AV engine | GPL-2.0 (site content CC BY-ND 2.5) | Yes, 1.5.4 | Signature DBs via freshclam | L, parking lot sample triage | no |
| [TCPdump (free packet analyser)](https://www.tcpdump.org/) | tcpdump/libpcap | BSD-3 | Yes, tcpdump 4.99.7 on 2026-09-21 | None | None | no |
| [Snort (free intrusion detection system)](https://www.snort.org/) | Snort 3 IDS; free Community Ruleset (Oinkcode registration for automated pulls) | GPL-2.0; community rules under their own licence | Yes | Ruleset downloads | L, Ph8 detection templating (Suricata/Snort rule export idea) | no |
| [Security Onion (free log management and monitoring)](https://securityonion.net/) | Redirects to securityonionsolutions.com. Free, open-source NSM/SIEM distro | Free/open (GPL-2.0 upstream; not shown) | Yes, "Security Onion 3 (2026)" | None | L, reference | no |
| [How to setup a Virtual Lab](https://leanpub.com/avatar) | Book: *Building Virtual Machine Labs* (Tony Robinson), $20; 2nd ed. exists | Copyrighted book | 2nd edition available | None | L, Ph10 reference | no |
| [Setting up a Malware RE lab](https://labs.sentinelone.com/building-a-custom-malware-analysis-lab-environment/) | SentinelLabs lab-build article. 301 to sentinelone.com/labs/...; target returned 429 | n/a | Redirect works; article not read | None | L, parking lot reference | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Source repo (old name) | None shown | Active | n/a | None | n/a |

### Secure Email (6 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Protonmail](https://protonmail.com/) | Redirects to proton.me/mail. Encrypted mail, free 1 GB tier | n/a (service) | Yes | None | L, operator research-persona mail | no |
| [CTemplar](https://ctemplar.com/) | Encrypted mail service page, ©2026 | n/a | Site live. Unverified recollection: CTemplar announced a shutdown around 2022, so the current operator may be different. Treat with caution | None | None | no |
| [10 Minute Mail](https://10minutemail.com/) | Disposable inbox | n/a | Unknown: HTTP 403 | None. Its domains belong on a disposable-mail list | L, Ph6 suppression list (disposable e-mail) | partly: Ph6 suppression list mentions "disposable e-mail" |
| [my24h](https://my24h.email) | Disposable mail | n/a | Likely dead: TLS certificate expired | None | None | no |
| [cock.li](https://cock.li) | Long-running free mail host; often seen in ransom notes and criminal sign-ups | n/a | Live ("mostly alive since 2013"); register link present | None. Its domain list is a useful selector/gate fact | L, Ph6 suppression/flag list (free-mail domains seen in ransom notes) | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Source repo (old name) | None shown | Active | n/a | None | n/a |

### OPSEC essentials (17 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [OPSEC 101 Guide](https://github.com/BushidoUK/Operational-Security-101) | BushidoUK OPSEC advice for friends and family | None shown | 16 commits, not archived | None | L, Ph10 reference | no |
| [MFA applications](https://www.microsoft.com/en-us/account/authenticator) | Microsoft Authenticator page | n/a | Live | None | None | no |
| [Safe browsing](https://www.browserling.com/) | Remote browser sandbox; has a Live API (paid) | n/a (service) | Live | Browserling Live API (paid) | L, Ph5 manual remote viewing | no |
| [Malicious URL checker](https://urlscan.io/) | urlscan.io | n/a (service) | Live | API, key (in .env) | Built, Ph1 | yes, Ph1 (built) |
| [Malicious file checker](https://www.virustotal.com/) | VirusTotal | n/a (service) | Live (JS page) | API, key (in .env) | Built, Ph1 | yes, Ph1 (built) |
| [Breach exposer](https://haveibeenpwned.com/) | Have I Been Pwned | Breach metadata CC BY 4.0; Pwned Passwords no licence requirement | Live | Keyless: /breaches, /breach/{name}, /latestBreach, /dataClasses, Pwned Passwords range. Email/domain/stealer-log need a paid key | H, Ph3/Ph7 (keyless breach catalogue) | yes, Ph7 breach association (HIBP) |
| [Password manager](https://keepass.info/) | KeePass | GPL-2.0 (OSI; page says open source) | Yes, 2.62 on 2026-11-04 | None | None | no |
| [Email alerts](https://www.google.co.uk/alerts) | Google Alerts | n/a (service) | Live | RSS delivery is an option inside the alert settings (not stated on the landing page) | M, Ph4 standing alerts (already planned) | yes, Ph4 "standing alerts delivered as RSS (Google Alerts...)" |
| [Twitter alerts](https://warble.co/) | Warble Twitter alerts | n/a | Dead: page says it stopped when Twitter ended free API access | None | None | no (X excluded in Ph2) |
| [Secure email](https://protonmail.com/) | Duplicate of Proton Mail (redirect to proton.me/mail) | n/a | Yes | None | L | no |
| [VPN](https://protonvpn.com/) | Duplicate of Proton VPN | n/a | Yes | None | L, Ph5 | yes, Ph5 egress |
| [VMs](https://www.virtualbox.org/) | Duplicate of VirtualBox | GPL-3.0 | Yes | None | M, Ph8 | yes, Ph8 |
| [Secure messaging & file transfer](https://keybase.io/) | Keybase. Fetched page is labelled "Keybase Staging Server" | n/a | Unclear: ©2026 but staging label | Public user lookup API exists (not confirmed on this page) | L, Ph7 identity pivot | yes, Ph7 (Keybase in the email/identity pivots) |
| [Intruder alerts](http://canarytokens.org/generate) | Thinkst Canarytokens generator (free); the page is a JS app. Source: github.com/thinkst/canarytokens | GPL-3.0 with Thinkst exceptions | Repo active (998 commits, not archived); Docker self-host supported | Self-hosted canarytokens-docker; the hosted service sends alerts by email/webhook | M, Ph3 DRP (self-hosted tripwires) or parking lot | no |
| [So, you want to be a darknet drug lord...](https://pastebin.com/GrV3uYh5) | Old pastebin OPSEC essay, written from a hidden-service operator's view | Unknown (paste) | Paste still live | None | L, Ph10 reading only | no |
| [General Operational Security Resources](https://greysec.net/showthread.php?tid=2859) | GreySec forum thread | n/a | Dead: forum shows a "GreySec V2 Reloaded, COMING SOON" placeholder | None | None | no |
| [Home](https://github.com/BushidoUK/Open-source-tools-for-CTI/blob/master/README.md) | Source repo README | None shown | Active | n/a | None | n/a |

### Certifications (12 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [ARCX CTI 101](https://arcx.io/courses/cyber-threat-intelligence-101) | ARCX intro CTI course | n/a | Unknown: HTTP 403 | None | L, Ph10 reference | no |
| [Mosse MTIA](https://www.mosse-institute.com/certifications/mtia-certified-threat-intelligence-analyst.html) | MCSI intermediate CTI cert, $595 | n/a | Live | None | L | no |
| [GIAC GCTI](https://www.giac.org/certifications/cyber-threat-intelligence-gcti) | GIAC CTI cert (pairs with SANS FOR578) | n/a | Live | None | L, Ph10 reference | no |
| [CREST CPTIA](https://www.crest-approved.org/certification-careers/crest-certifications/crest-practitioner-threat-intelligence-analyst) | CREST entry-level CTI exam | n/a | Live | None | L | no |
| [Mile2 Threat Analyst](https://www.mile2.com/threat-analyst) | Mile2 CTIA course | n/a | Live | None | None | no |
| [EC-Council CTIA](https://www.eccouncil.org/programs/threat-intelligence-training) | EC-Council CTIA program page | n/a | Live | None | None | no |
| [TCM PJOR](https://certifications.tcm-sec.com/pjor/) | Now named PORP (Practical OSINT Research Professional), $399 | n/a | Live | None | L, Ph7 reference | no |
| [CompTIA Security+](https://www.comptia.org/en/certifications/security/) | Security+ (V7 now live) | n/a | Live | None | None | no |
| [Udemy Security+ course](https://www.udemy.com/course/securityplus/?couponCode=MT250908ANEW) | Paid Udemy course with a coupon code in the URL | n/a | Unknown: HTTP 403 | None | None | no |
| [Blue Team Level 1](https://www.securityblue.team/certifications/blue-team-level-1) | Security Blue Team is now Centri (301 to centri.org). BTL1, £399 | n/a | Live under the new domain | None | None | no |
| [Certified Junior Detection Engineer](https://www.securityblue.team/certifications/certified-junior-detection-engineer) | Redirects to Centri; now "Certified Detection Engineering Associate", £399 | n/a | Live (renamed) | None | None | no |
| [TryHackMe SAL1](https://tryhackme.com/certification/security-analyst-level-1) | Entry-level SOC analyst cert, about €301/$349 | n/a | Live | None | None | no |

### Training (9 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [LetsDefend](https://letsdefend.io) | Simulated-SOC training; free Basic tier | n/a | Live | None | L, Ph10 reference | no |
| [TryHackMe](https://tryhackme.com) | Browser-based labs; free tier | n/a | Live | None | L | no |
| [HackTheBox Sherlocks](https://hackthebox.com/blog/htb-sherlocks-dedicated-labs) | Blog post on HTB Sherlocks (DFIR labs) | n/a | Live | None | L | no |
| [BlueTeamLabs](https://blueteamlabs.online) | BTLO challenges; free tier | n/a | Live | None | L | no |
| [The Art of Malware Analysis](https://courses.null-char.com/courses/the-art-of-malware-analysis) | Redirects to ASK Academy; Ahmed Kasmani, $149.99 | n/a | Live (moved) | None | L, parking lot (malware) reference | no |
| [Zero2Auto Malware Analysis](https://courses.zero2auto.com/) | Redirects to courses.0ffset.net; Zero2Automated, £149.99 | n/a | Live (moved) | None | L, parking lot reference | no |
| [Introduction to Malware Binary Triage](https://training.invokere.com/course/imbt) | Invoke RE IMBT (IDA edition), Josh Reynolds | n/a | Live; price on a separate page | None | L, parking lot reference | no |
| [How DNS Works](https://www.nslookup.io/dns-course) | nslookup.io DNS course (JS page; only the title rendered) | n/a | Unknown (title only) | nslookup.io has DNS lookup tools (not checked) | L, Ph10 reference | no |
| [Cybrary](https://cybrary.it) | Training platform; Free Access tier | n/a | Live | None | L | no |

### InfoSecTwitter (10 links)
The file lists Twitter tools, not accounts. X has no free API (roadmap Ph2 excludes X), so all are None.
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Tweetdeck](https://tweetdeck.twitter.com/) | 301 to pro.twitter.com (X Pro, paid). Not followed | n/a | Replaced by X Pro | None | None | no (X excluded, Ph2 line 370) |
| [Geo-Chip](http://www.geochirp.com/) | GeoChirp geo-search for tweets | n/a | Likely dead: empty page | None | None | no |
| [Tweeps-Map](http://tweepsmap.com/) | Now 301 to fedica.com (social media analytics, freemium) | n/a | Rebranded | Paid platform | None | no |
| [Tinfo-Leak](https://tinfoleak.com/) | Twitter user dossier tool | n/a | Stale: ©2015 and template placeholder text; cannot work without the X API | None | None | no |
| [Tweetmap](https://www.omnisci.com/demos/tweetmap) | OmniSci (now HEAVY.AI) tweet-map demo | n/a | Dead: TLS internal error | None | None | no |
| [Twint](https://github.com/twintproject/twint) | Twitter scraper (Python) | MIT | Archived 2023-03-30 | None (broken by X changes) | None | no |
| [TwitWork](https://github.com/atmoner/TwitWork) | Electron Twitter stream monitor | GPL-3.0 | 39 commits; needs the dead free API | None | None | no |
| [Spoonbill](https://spoonbill.io/) | Twitter profile-change tracker | n/a | Not checked: safety-check rate limit twice | Unknown | None (X-dependent) | no |
| [Mention Mapp](https://analytics.mentionmapp.com/modules/free/) | Twitter mention-network visualiser | n/a | Not checked: safety-check rate limit twice | Unknown | None (X-dependent) | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/) | Source repo (old name) | None shown | Active | n/a | None | n/a |

### Podcasts (6 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Darknet Diaries](https://darknetdiaries.com/) | Jack Rhysider's narrative security podcast | n/a | Not checked: safety-check rate limit twice | Podcast RSS (URL not confirmed) | L, Ph4 optional feed | no |
| [Cyber Security Sauna](https://twitter.com/cybersauna?lang=en) | WithSecure (ex F-Secure) podcast; the link is its X account | n/a | X/Twitter, not renderable (301 to x.com) | Podcast RSS not identified | None | no |
| [Malicious Life](https://malicious.life/) | Cybereason history-of-hacking podcast | n/a | Not checked: safety-check rate limit twice | Podcast RSS (URL not confirmed) | L, Ph4 optional feed | no |
| [The Cyber Wire](https://thecyberwire.com/podcasts) | N2K CyberWire podcast network (Daily, Research Saturday, etc.) | n/a | Not checked: safety-check rate limit three times | Per-show RSS (not confirmed) | M, Ph4 news feed (daily briefing is news, not storytelling) | no |
| [Smashing Security](https://www.smashingsecurity.com/episodes) | Cluley/Lee weekly news podcast | n/a | Yes, ep. 491 on 2026-11-05 | RSS: https://www.smashingsecurity.com/rss | L, Ph4 optional feed | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/new/master) | GitHub "new file" URL; shows a sign-in form | n/a | Broken nav link | n/a | None | n/a |

### Conferences (10 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [DEFCON](https://www.defcon.org/) | DEF CON site | n/a | Fetch failed (ECONNRESET). YouTube channel active 2026-11-06 | media.defcon.org talk archive (not checked); YouTube RSS | M, Ph4 talk feed via YouTube RSS | no |
| [Black Hat](https://www.blackhat.com/) | Black Hat site | n/a | Unknown: HTTP 403 | Briefings archive (not checked) | L, Ph10 reference | no |
| [BSides](https://www.securitybsides.org.uk/) | BSides London site (points to bsides.london) | n/a | Last event listed 2024-12-14; stale page | None | L | no |
| [Recorded Future Predict](https://predict.recordedfuture.com/) | RF Predict conference | n/a | Dead: DNS NXDOMAIN | None | None | no |
| [SANS/NCSC CyberThreat](https://cyberthreat.io/) | CyberThreat conference, London | n/a | Yes, next 16-17 Nov 2026 | No recordings archive on page | L | no |
| [Sleuthcon](https://www.sleuthcon.com/) | CTI/investigations con | n/a | Yes, 2026-06-05 edition | YouTube link (videos) | L, Ph4 via YouTube RSS | no |
| [CyberWarCon](https://www.cyberwarcon.com/) | State-actor CTI conference | n/a | Yes, 2026 edition | Site has an "Archive" section (not opened) | M, Ph9 actor reporting reference (talk archive) | no |
| [VirusBulletin](https://www.virusbulletin.com/) | VB conference and paper archive | n/a | Unknown: HTTP 403 | VB papers archive (free; not checked) | M, Ph9/Ph10 reference (papers) | no |
| [Botconf](https://www.botconf.eu/) | Botnet/malware conference | n/a | Yes; 2026 Reims held, 2027 Vannes Apr 27-30 | "Past editions" pages hold talks (not opened) | M, Ph9/Ph10 reference | no |
| [PivotCon](https://pivotcon.org/) | Invite-only CTI con, Málaga 2027 | n/a | Yes | None: talks are not streamed or recorded | None | no |

### Security YouTube channels (43 links)
Method: pages that only rendered a title were checked as reachable. Where the link holds a channel ID
(`/channel/UC...`) or legacy user (`/user/...`), the keyless Atom feed
`https://www.youtube.com/feeds/videos.xml?channel_id=...` or `?user=...` was fetched for the newest upload date.
`/c/` custom URLs cannot be fed without first resolving the channel ID.
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Jim Browning](https://www.youtube.com/c/JimBrowning/videos) | Scam-baiting investigations | n/a (YouTube) | Page loads; date unknown | RSS needs channel ID | L | no |
| [NetworkChuck](https://www.youtube.com/c/NetworkChuck/videos) | Networking/IT education | n/a | Page loads | RSS needs channel ID | None | no |
| [Troy Hunt](https://www.youtube.com/user/troyhuntdotcom) | HIBP creator; weekly update videos | n/a | Yes, RSS newest 2026-11-09 | RSS ?user=troyhuntdotcom | L, Ph4 | no |
| [Grant Collins](https://www.youtube.com/channel/UCTLUi3oc1-a7dS-2-YgEKmA/) | Security career content | n/a | Yes, RSS newest 2026-11-04 | RSS by channel_id | None | no |
| [John Hammond](https://www.youtube.com/c/JohnHammond010/videos) | Malware, CTF, and threat walkthroughs | n/a | Page loads | RSS needs channel ID | L, Ph4 | no |
| [Lukas Stefanko](https://www.youtube.com/channel/UCg08SXtXlfADk4yAODpShfQ) | ESET Android malware researcher | n/a | Page shows footer only; RSS 404 (channel empty or removed) | None | None | no |
| [Malwaretech](https://www.youtube.com/channel/UCLDnEn-TxejaDB8qm2AUhHQ) | Marcus Hutchins | n/a | Yes, RSS newest 2026-10-16 (15 entries) | RSS by channel_id | L, Ph4 | no |
| [Mr Turvey](https://www.youtube.com/c/MrTurvey/videos) | Blue team / Splunk tutorials | n/a | Page loads | RSS needs channel ID | None | no |
| [GrujaRS Ransomware](https://www.youtube.com/c/CyberSecurityGrujaRS/videos) | Ransomware sample demos | n/a | Dead: HTTP 404 (also without /videos) | None | None | no |
| [Danooct1 Malware analysis](https://www.youtube.com/user/danooct1) | Malware demo videos | n/a | Slow: RSS newest 2024-09-06 | RSS ?user=danooct1 | None | no |
| [Michael Gillespie](https://www.youtube.com/user/Demonslay335/videos) | ID Ransomware author | n/a | Inactive: RSS newest 2020-10-24 | RSS ?user=Demonslay335 | None | no |
| [MalwareAnalysisForHedgehogs](https://www.youtube.com/c/MalwareAnalysisForHedgehogs/videos) | Malware RE tutorials (Karsten Hahn) | n/a | Page loads | RSS needs channel ID | L, parking lot reference | no |
| [StudioSec](https://www.youtube.com/c/StudioSec/videos) | Security tutorials | n/a | Page loads | RSS needs channel ID | None | no |
| [AhmedS Kasmani](https://www.youtube.com/channel/UC0vsNncAvJlPh2XGUi5s33Q/videos) | Malware analysis | n/a | Yes, RSS newest 2026-01-20 | RSS by channel_id | L | no |
| [BendoBrown](https://www.youtube.com/c/Bendobrown/videos) | OSINT tutorials (Benjamin Strick) | n/a | Page loads | RSS needs channel ID | L, Ph7 reference | no |
| [SecureNinjaTV](https://www.youtube.com/c/SecureNinjaTV/videos) | Conference interviews | n/a | Page loads | RSS needs channel ID | None | no |
| [Oxdade](https://www.youtube.com/c/0xdade/videos) | Security talks | n/a | Page loads | RSS needs channel ID | None | no |
| [Christiaan008](https://www.youtube.com/c/ChRiStIaAn008/videos) | Security talk aggregator | n/a | Page loads | RSS needs channel ID | None | no |
| [CybersecStu](https://www.youtube.com/channel/UCWJdCqxV2gq0bdERD26dgRQ/videos) | "Stu" | n/a | Inactive: RSS newest 2021-04-14 | RSS by channel_id | None | no |
| [BSides DC](https://www.youtube.com/c/BsidesdcOrg/videos) | Conference talks | n/a | Page loads | RSS needs channel ID | L, Ph4 | no |
| [BSides San Francisco](https://www.youtube.com/c/BSidesSFTV/videos) | Conference talks | n/a | Page loads | RSS needs channel ID | L, Ph4 | no |
| [BSides London](https://www.youtube.com/channel/UCXXNOelGiY_N96a2nfhcaDA/videos) | Conference talks | n/a | Yes, RSS newest 2026-03-02 | RSS by channel_id | L, Ph4 | no |
| [DEFCON Conference talks](https://www.youtube.com/user/DEFCONConference) | DEF CON talks (channel ID UC6Om9kAkl32dWlDSNlDS9Iw) | n/a | Yes, RSS newest 2026-11-06 | RSS ?user=DEFCONConference | M, Ph4 talk feed | no |
| [Red Team Village](https://www.youtube.com/channel/UC8nq3PX9coMiqgKH6fw-VCQ) | DEF CON village talks | n/a | Yes, RSS newest 2026-08-28 | RSS by channel_id | L | no |
| [Blue Team Village](https://www.youtube.com/channel/UCk4dddMFiso_hgt0ViSPNpQ) | DEF CON village talks | n/a | Inactive: RSS newest 2023-10-08 | RSS by channel_id | None | no |
| [ICS Village](https://www.youtube.com/channel/UCI_GT2-OMrsqqglv0JijHhw) | ICS security talks | n/a | Yes, RSS newest 2026-09-03 | RSS by channel_id | L | no |
| [BlackHat](https://www.youtube.com/c/BlackHatOfficialYT) | Black Hat talks | n/a | Page loads | RSS needs channel ID | M, Ph4 talk feed | no |
| [RSA Conference](https://www.youtube.com/c/RSAConference/videos) | Now "RSAC Cybersecurity" | n/a | Page loads | RSS needs channel ID | L | no |
| [SecureSouthWest](https://www.youtube.com/user/SecureSouthWest/videos) | UK regional con | n/a | Inactive: RSS newest 2021-03-17 | RSS ?user= | None | no |
| [CitizenLab](https://www.youtube.com/c/CitizenLabUofT/videos) | Citizen Lab (spyware, digital repression research) | n/a | Page loads | RSS needs channel ID; the blog feed matters more | M, Ph4 (blog feed rather than video) | no |
| [SANS Institute](https://www.youtube.com/user/TheSANSInstitute) | SANS talks, webcasts, CTI Summit | n/a | Yes, RSS newest 2026-11-11 | RSS ?user=TheSANSInstitute | M, Ph4 (CTI Summit talks) | no |
| [SANS Cyber Defense](https://www.youtube.com/c/SANSBlueTeamOps/videos) | SANS blue team | n/a | Page loads | RSS needs channel ID | L | no |
| [SANS Digital Forensics and Incident Response](https://www.youtube.com/c/SANSDigitalForensics/videos) | SANS DFIR | n/a | Page loads | RSS needs channel ID | L | no |
| [CyberNews](https://www.youtube.com/c/CyberNews/videos) | Cybernews outlet | n/a | Page loads | RSS needs channel ID | L | no |
| [BleepingComputer](https://www.youtube.com/c/bleepingcomputer/videos) | BleepingComputer video | n/a | Page loads | RSS needs channel ID; site RSS is the better source | L (site RSS is M, Ph4) | no |
| [Hak5](https://www.youtube.com/user/Hak5Darren) | Hak5 hardware/hacking | n/a | Yes, RSS newest 2026-11-10 | RSS ?user=Hak5Darren | None | no |
| [Trident Talks](https://www.youtube.com/channel/UCz3aSUvKrQyyaN70AcRl2Nw/videos) | Talk series | n/a | Yes, RSS newest 2026-09-28 | RSS by channel_id | L | no |
| [Pen Test Partners](https://www.youtube.com/user/PenTestPartnersLLP) | PTP research videos | n/a | Yes, RSS newest 2026-08-21 | RSS ?user= | L | no |
| [Kaspersky](https://www.youtube.com/c/KasperskyLab/videos) | Kaspersky (GReAT, SAS talks) | n/a | Page loads | RSS needs channel ID | L | no |
| [Microsoft Security](https://www.youtube.com/c/MicrosoftSecurity/videos) | Microsoft Security | n/a | Page loads | RSS needs channel ID | L | no |
| [Bastille](https://www.youtube.com/c/Bastille/videos) | Bastille (RF security) | n/a | Page loads | RSS needs channel ID | None | no |
| [vx-underground](https://www.youtube.com/channel/UC0g-PFeCjWJvBYgCwCWWUzA) | vx-underground | n/a | Inactive: RSS newest 2023-05-07 | RSS by channel_id | None (use their site/archive instead) | no |
| [The Glasshouse Center](https://www.youtube.com/channel/UC1vgdCz3YkBTKlrcXZHfrBA/videos) | Livestream channel | n/a | Inactive: RSS newest 2023-01-20 | RSS by channel_id | None | no |

### Misc (34 links)
| Name | What it is | Licence | Maintained? | API/data | Value (H/M/L/None + phase) | In roadmap? |
|---|---|---|---|---|---|---|
| [Windows Sysinternals](https://docs.microsoft.com/en-us/sysinternals/) | Redirects to learn.microsoft.com; Sysinternals suite incl. Sysmon | Proprietary freeware | Yes, What's New 2026-11-05 | What's New RSS (techcommunity board); live.sysinternals.com | L, Ph8 (Sysmon-based detection context) | no |
| [PowerShell scripts](https://stackify.com/powershell-commands-every-developer-should-know/) | Stackify blog "50+ PowerShell commands" | n/a | Article dated 2023-10-25 | None | None | no |
| [Canary Tokens](http://canarytokens.org/generate#) | Same as the OPSEC Canarytokens row | GPL-3.0 + exceptions (repo) | Active | Self-hostable | M, Ph3 | no |
| [HoneyDoc](https://github.com/jqreator/honeydoc) | Generates decoy documents with fake employee data and a tracking pixel | GPL-3.0 | 14 commits, not archived | None | L, Ph3 tripwire idea | no |
| [Tiny URL](https://tinyurl.com/) | URL shortener (JS page) | n/a | Live (title only) | Paid API exists (not confirmed) | L, Ph6 shortener list (suppress/expand) | partly: Ph6 suppression list mentions "URL shorteners" |
| [Kaspersky Password checker](https://password.kaspersky.com/) | Password strength and leak check | n/a | Live | None | None | no |
| [CTF Training site](https://pwnable.kr/play.php) | pwnable.kr binary-exploitation wargame | n/a | Reachable; page shows only the site name | None | None | no |
| [Sourcing Games](https://www.sourcing.games/) | Recruiter sourcing/OSINT puzzles | n/a | Yes, updated 2026-06-15 | None | L, Ph7 practice | no |
| [Free Diagram Tool](https://app.diagrams.net/) | diagrams.net (draw.io) | Apache-2.0 (upstream jgraph/drawio) | Live | None | L, Ph10 docs diagrams | no |
| [Free Diagram Tool](https://draw.io) | 301 to app.diagrams.net (duplicate) | Apache-2.0 | Live | None | L, Ph10 | no |
| [Learn to Code for Free](https://www.codecademy.com/) | Codecademy; free tier | n/a | Live | None | L, operator learning | no |
| [Visual Studio Code](https://code.visualstudio.com/) | Code editor | MIT (source) | Yes, Oct 2026 posts | None | L | no |
| [NSA Document Generator](http://ternus.github.io/nsaproductgenerator/) | Joke NSA ANT-style codename generator | n/a | Static GitHub Page | None | None | no |
| [Text Magic](https://www.textmagic.com/free-tools/) | 301 to freetools.textmagic.com: ~30 tools incl. phone validator, carrier lookup | n/a | Live | No free API (paid SMS API only) | L, Ph7 manual phone lookup | no |
| [Code presentation](https://carbon.now.sh/) | Carbon: images of source code | MIT (upstream) | Live | None | None | no |
| [RBMK-1000 ICS Simulator](https://www.youtube.com/watch?v=XLmFjCTa-FU) | YouTube tutorial video for a Chernobyl reactor simulator | n/a | Video page loads | None | None | no |
| [Zotero](https://www.zotero.org/) | Reference manager | AGPL-3.0 (upstream; page says open source) | Live | Zotero Web API exists (not on this page) | L, Ph10 citation management | no |
| [SecureDrop](https://securedrop.org/) | Whistleblower submission system; instance directory at /directory/ | AGPL-3.0 (upstream) | Live | Directory (HTML; API not seen) | None | no |
| [Definitive Guide to Cyber Threat Intelligence (iSIGHT, 2015)](https://cryptome.org/2015/09/cti-guide.pdf) | 2015 iSIGHT CTI primer on cryptome | Copyright iSIGHT (mirror) | PDF loads (static, 2015) | None | L, Ph10 reading | no |
| [Analysis of Adversary Campaigns and Intrusion Kill Chains (Lockheed Martin)](https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/Gaining_the_Advantage_Cyber_Kill_Chain.pdf) | Lockheed Martin "Gaining the Advantage" Cyber Kill Chain paper (13 pp, 2015), **not** the 2011 Hutchins et al. paper the label names | Copyright LM | PDF loads | None | L, Ph9/Ph10 (kill-chain phase mapping reference) | no |
| [Hackers' Bazaar (RAND)](https://www.rand.org/pubs/research_reports/RR610.html) | RAND RR610 (2014) cybercrime markets report | RAND copyright (free PDF) | Unknown: HTTP 403 | None | L, Ph10 reading | no |
| [Bandit (Linux Practice)](https://overthewire.org/wargames/bandit/) | OverTheWire beginner SSH wargame | n/a | Live | None | L, operator Linux practice (Ph5 WSL2 prep) | no |
| [PowerShell Training](https://underthewire.tech/) | Under The Wire PowerShell wargames (React app; title only) | n/a | Reachable; content not rendered | None | L | no |
| [OSINT CTF](https://ctf.cybersoc.wales/) | Cyber Wales OSINT CTF | n/a | Dead: DNS NXDOMAIN | None | None | no |
| [OSINT CTF](https://twitter.com/Sector035/status/1211038518635614208?s=20) | Sector035 tweet (2019) about an OSINT CTF | n/a | X/Twitter, not renderable (402 on x.com) | None | None | no |
| [My CTF](https://blog.bushidotoken.net/p/ctf.html) | BushidoToken blog CTF page | n/a | Blog active: newest post 2026-11-04 | Blog Atom: https://blog.bushidotoken.net/feeds/posts/default | M, Ph4 news source (UK cybercrime and CTI blog) | partly: BushidoToken cited in Ph6 (line 1435), blog not in the Ph4 source list |
| [Prezi](https://prezi.com/) | Presentation SaaS | n/a | Live | None | None | no |
| [Issuu](https://issuu.com/) | Document publishing platform | n/a | Live | None | L, Ph3 document-leak dork target (site:issuu.com), like scribd | partly: Ph3 has scribd dorks; issuu not named |
| [GIAC](https://www.giac.org/certification/cyber-threat-intelligence-gcti) | Old-path GCTI page (same as the Certifications row) | n/a | Live | None | L | no |
| [CTIA](https://iclass.eccouncil.org/our-courses/certified-threat-intelligence-analyst-ctia/) | EC-Council iClass CTIA course | n/a | Live | None | None | no |
| [FOR578](https://www.sans.org/cyber-security-courses/cyber-threat-intelligence/) | SANS FOR578 Cyber Threat Intelligence | n/a | Live | None | L, Ph10 reference | no |
| [Why the f@ck was I breached?](https://whythefuckwasibreached.com/) | Joke breach-excuse generator (Reflare) | n/a | Live | None | None | no |
| [Fake Update](https://fakeupdate.net/) | Prank site with fake OS update / BSOD screens | n/a | Live | None | None | no |
| [Home](https://github.com/WilliamThomas-sec/Opensource-tools/blob/master/README.md#index-%E2%84%B9%EF%B8%8F) | Source repo README (old name; resolves) | None shown | Active | n/a | None | n/a |

### High-value notes

**Have I Been Pwned keyless endpoints (H; Ph3 and Ph7; already planned in Ph7)**
- Integrate as a data source. These endpoints need no key: `GET https://haveibeenpwned.com/api/v3/breaches`
  (full breach catalogue as JSON, filterable with `?domain=`), `/breach/{name}`, `/latestBreach`, `/dataClasses`,
  and the Pwned Passwords k-anonymity range API (`api.pwnedpasswords.com/range/{5-hex}`, no rate limit).
- Ph3 use: a daily pull of `/breaches` diffed locally raises an alert when a watched organisation domain
  appears in a new breach. Per-email, per-domain search, and stealer-log endpoints need a paid key and stay out.
- Licence: breach and paste metadata is CC BY 4.0. Show "Source: Have I Been Pwned" with a link wherever it
  is displayed. Pwned Passwords has no attribution requirement. A user-agent header is required.

**YouTube channel RSS as a Ph4 feed type (M; Ph4; not in roadmap as a source)**
- Keyless Atom feed: `https://www.youtube.com/feeds/videos.xml?channel_id=UC...`. `?user=<legacy name>` also
  works (confirmed for troyhuntdotcom, DEFCONConference, TheSANSInstitute, Hak5Darren). Each feed returns the
  latest 15 entries (title, link, published date, description).
- The feeds lack a feed-level `<updated>`, but feedparser (already planned) reads them fine. `/c/` custom
  URLs must first be resolved to a UC... ID once, by hand from the page source, then stored in config.
- Worth adding as conference-talk feeds: DEFCONConference (UC6Om9kAkl32dWlDSNlDS9Iw, active 2026-11-06),
  TheSANSInstitute (CTI Summit talks; active 2026-11-11), Black Hat, BSides London, ICS Village.
  Store only title, URL, and date, matched against the Ph4 keyword lists. No video download.
- Dead or inactive (do not add): GrujaRS (404), Lukas Stefanko (no feed), Blue Team Village (2023),
  vx-underground (2023), Michael Gillespie (2020), CybersecStu (2021), SecureSouthWest (2021), Glasshouse (2023).

**Canarytokens, self-hosted (M; Ph3 DRP or parking lot; not in roadmap)**
- Wrap as a tool: run thinkst/canarytokens-docker (GPL-3.0 with Thinkst exceptions) next to the collectors and
  plant tokens (DNS, URL, document, AWS-key style) in the operator's own assets. Each token trigger posts to a
  webhook, which the Ph5 alert inbox ingests as a "tripwire fired" alert with source IP and user agent.
- Run it as a separate container and talk to it only over its HTTP and webhook interfaces. That avoids copying
  GPL code into the repo. The hosted canarytokens.org is free but sends alert data to Thinkst.
- HoneyDoc (GPL-3.0, small repo) is the same idea for decoy documents. Take the method only.

**BushidoToken blog Atom feed (M; Ph4)**
- `https://blog.bushidotoken.net/feeds/posts/default` (Blogger Atom; newest post 2026-11-04, "UK Cybercrime
  Journal" series). This is the same author as the source list and is good for UK cybercrime and ransomware
  reporting. Add it to the Ph4 curated source list. Blogger also serves `?alt=rss`.

**Podcast and news feeds (L-M; Ph4)**
- Smashing Security RSS confirmed: `https://www.smashingsecurity.com/rss` (ep. 491, 2026-11-05).
- The CyberWire (Daily, Research Saturday) is the one podcast here that works as a news source. Its RSS URL was
  not confirmed (rate limit); check it when the reader is built. Darknet Diaries and Malicious Life are
  storytelling shows and of low value to keyword monitoring.

**Conference talk and paper archives (M; Ph9/Ph10 reference)**
- Botconf (past editions with talks and papers), Virus Bulletin (free conference paper archive), and
  CyberWarCon (archive section) are the CTI-relevant talk archives. Each is a link-out reference from actor
  profiles and docs, not a feed. VB and Black Hat returned 403 to the fetcher, so access was not confirmed.
  PivotCon is never recorded. Predict's domain no longer resolves.

**Disposable and free mail domains (L-M; Ph6 suppression and flag list; partly planned)**
- 10minutemail, my24h, cock.li (and its sister domains) are facts for the Ph6 "disposable e-mail" suppression
  list and for flagging ransom-note contact addresses. Re-key domain names only. Do not copy any list text.

**Reference only, already decided elsewhere**
- Tor (Ph5 onion egress, Ph6 exit-list gate), Proton VPN (Ph5 egress rung), Brave Search API (Ph4),
  Google Alerts RSS (Ph4), VirtualBox (Ph8 isolation), Docker (Ph5/Ph8), REMnux (analysis-VM open item),
  urlscan and VirusTotal (Ph1, built), Keybase (Ph7). FLARE VM (Apache-2.0, github.com/mandiant/flare-vm)
  joins REMnux, Tsurugi, SIFT, and CSI Linux as Windows-side candidates for the analysis-VM decision.
- The Lockheed Martin PDF is the 2015 "Gaining the Advantage" paper, not Hutchins et al. 2011. For Ph9
  kill-chain phase mapping, cite the original paper instead.

(Links not checked: see appendix.)


---

## Source 2: BushidoUK/OSINT-SearchOperators

https://github.com/BushidoUK/OSINT-SearchOperators. This repo is three data files of search
queries with a three-link README.

- **Licence:** none, so all rights reserved. Individual query facts (a favicon hash, a filter
  and value pair) are plain facts and can be re-keyed, credited as a courtesy. The files must not
  be copied in.
- **Maintenance:** 98 commits, branch `main`, 166 stars, not archived. The last commits are
  2026-09-27 and 2026-04 (both to ShodanAdversaryInfa.md); before that, 2023.
- **In roadmap?** The repo is not named in ROADMAP.md. Its content maps onto planned features:
  - Phase 4: the dork launcher (ROADMAP ~line 945).
  - Phase 3: dorks as alert feeds (~836).
  - Phase 6: favicon and JARM pivots (~1325-1335) and the default-signature library (~1449-1555),
    plus saved hunts (~1499-1508).
  - Phase 7: "Shodan org dorks" in the wrapped tools (~1684).
- Part F rated the repo Medium (Ph3/Ph6). I rate it High for Ph6 and Medium for Ph3/Ph4, because
  it fills the planned default-signature library and saved-hunt library directly.

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [ShodanQueriesAppliances.csv](https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanQueriesAppliances.csv) | 45 Shodan queries for exposed services and edge appliances (header `Type,Service,Query`) | none | file stable; repo active 2026-09 | CSV, raw GitHub | M-H, Ph3 own-org exposure, Ph2 view 8 | Shodan org dorks Ph7; edge view Ph2; not the file |
| [ShodanAdversaryInfa.md](https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/ShodanAdversaryInfa.md) | 22 sections, 38 Shodan queries plus 3 cert fingerprints for C2 frameworks, stealer panels and tools | none | yes, updated 2026-09-27 | Markdown | H, Ph6 default-signature library and saved hunts | library planned (other sources named); this file no |
| [GoogleDorks.csv](https://github.com/BushidoUK/OSINT-SearchOperators/blob/main/GoogleDorks.csv) | 42 Google dorks (header `Target,Search Operator`) | none | stable | CSV | M, Ph3 dork review links, Ph4 dork launcher | dork launcher planned; file no |
| [Group-IB: ShadowSyndicate infrastructure](https://www.group-ib.com/blog/new-shadowsyndicate-infrastructure/) (linked from ShodanAdversaryInfa) | Vendor blog, 2026-02-04 (modified 2026-05-26): ShadowSyndicate SSH fingerprints and an IP table of 100+ rows | n/a (vendor blog, rights reserved) | yes | HTML table only, IPs defanged, no download | M, Ph6 seed (SSH-fingerprint pivot), Ph9 ransomware infra | ShadowSyndicate no; SSH host-key pivot yes (Ph6 ~1442) |

### Operator sets that can become query templates

**Shodan: appliances / own-organisation exposure** (ShodanQueriesAppliances.csv, 45 rows).

| Filter | Rows using it | Template shape | Notes |
|---|---|---|---|
| `http.favicon.hash:` | 21 | `http.favicon.hash:{mmh3}` | One hash per product: Elastic, OWA, Outlook, VMware Horizon, Tomcat, Citrix, F5, Fortinet, SonicWall, SolarWinds Orion and Serv-U, Drupal, Joomla, Magento, Jenkins, Meraki, Ubiquiti, Sophos, Ivanti, Google Search Appliance |
| `ssl:"{org}"` | 18 | `ssl:"{org}" port:{n}` / `ssl:"{org}" product:"{p}"` | The `"brand name"` placeholder is the org selector. This is a ready Phase 3 "our exposed services" template set: SSH 22, FTP 21, SMTP 25, VNC 5900, RDP 3389, SMB 445, Docker 2375, Redis 6379, MongoDB, MS-SQL, Elastic, Citrix, Pulse Secure, QNAP |
| `http.title:` | 10 | `http.title:{product}` | exchange, sharepoint, weblogic, tomcat, fortigate, BIG-IP, mariadb, solarwinds, `ID_VC_Welcome` (vCenter) |
| `port:` | 8 | combined with ssl | |
| `product:` | 7 | combined with ssl | |
| `http.component:` | 1 | `http.component:"{tech}"` | Pulse Secure |
| `has_vuln:true` | 1 | `ssl:"{org}" has_vuln:true` | Needs a paid Shodan tier. Check against the key on hand before offering it |

**Shodan: adversary infrastructure** (ShodanAdversaryInfa.md). WebFetch summarised this file and
would not reproduce the query strings, so the operator should read the file in a browser to
re-key the exact values.

- Filters used: `http.favicon.hash`, `ssl`, `ssl.jarm`, `ssl.cert.serial`,
  `ssl.cert.issuer.cn`, `ssl.cert.subject.cn`, `product`, `port`, `http.html`,
  `http.html_hash`, `http.title`, `http.component`, bare banner strings, and `-` negation.
- Targets:
  - C2 frameworks: Metasploit, Cobalt Strike, Covenant, Sliver, Mythic, PoshC2, Brute Ratel,
    Deimos, PANDA.
  - Stealer panels: AcridRain, Misha, Patriot, RAXNET, Titan, Collector, Mystic.
  - Dual-use tools: Hashcat, BurpSuite, PowerSploit, XMRig.
  - Other: Uname web panel, and ShadowSyndicate (cert SHA-1s and SSH fingerprints).
- Template shape for the default-signature library: one record per
  `{family, component, filter, value, source, date_added, strength}`. Mark "weak" for generic
  markers such as a bare `http.html` string, and "strong" for cert serial, JARM plus header
  conjunction, or html_hash. This matches the roadmap's conjunction rule: "JARM and JA3S only
  as one term of a conjunction".
- Overlaps with the sources already named in Ph6 (awesome-censys-queries, C2-Tracker,
  Adversary-Hunter), so de-duplicate on (filter, value).

**Google dorks** (GoogleDorks.csv, 42 rows).

- Operators: `site:` (~25), `ext:` (~28), `inurl:` (~24, including `-inurl:`), `intext:`
  (~15), `intitle:` (~11), `filetype:` (4), `view-source:` (1). Syntax used: `|` OR, `AND`,
  `-` exclude, `+`, `*` wildcard in domains, quoted phrases. No `before:`/`after:`.
- Categories:
  - Exposed files: APK, EXE, BAT, confidential PDF and PPT, logs.
  - Credential leakage: doc, xls, sql, logs, Trello.
  - Cloud storage: S3, Azure Blob, Google Drive, AnonFiles, uFile.
  - Misconfiguration: open directories, config, backups, FTP, robots.txt, test pages, database
    errors.
  - Login and admin panels, including government portals; subdomains; open redirects.
  - Social and contact: Twitter handles, Telegram groups, WhatsApp contacts via Facebook or
    LinkedIn.
  - Collaboration tools: Zoom, Skype, Atlassian.
  - Exposed security reports: Nessus, Joe Sandbox, ANY.RUN, Hybrid Analysis.
- Template shape: `{name, category, engine, template, placeholders}`, where placeholders are
  mainly `{domain}` for `site:` and `{org}`.
- How the toolkit uses them:
  - Phase 3 (own domain): open-directory, exposed-document, cloud-bucket and paste dorks,
    scoped with `site:{own_domain}` or `"{org}"`.
  - Phase 4 dork launcher: build the URL and open it in the browser. No scraping; the Brave
    API is for the low-volume remainder.
- Policy filter: drop or hide the credential-harvesting and contact-harvesting rows (default
  passwords, WhatsApp contacts) unless scoped to the operator's own domain. They fall outside
  DRP of one's own assets.
- Telegram-group dorks fit the Ph5 discovery step (find public channels by keyword). This is
  read-only, with no joining.

**Engines covered:** Shodan and Google only. There is nothing for Censys, FOFA, ZoomEye, Bing,
Yandex or GitHub code search. Part F records which of those engines have free tiers.

---

## Source 3: BushidoUK/Operational-Security-101

https://github.com/BushidoUK/Operational-Security-101. This is a single README of personal OPSEC
advice for non-technical users and for researchers with a higher threat level. It is a copy of a
2020-12-31 BushidoToken blog post.

- **Licence:** none.
- **Maintenance:** 16 commits, last 2024-02-21. Static, not archived.
- **Value to the toolkit:** mainly reference for docs and runbooks (Phase 10) and for the
  operator's own Phase 5 collection OPSEC. A few items are data or tool candidates; see the
  notes after the table.

| Name | What it is | Licence | Maintained? | API/data | Value | In roadmap? |
|---|---|---|---|---|---|---|
| [wikiHow single-name Facebook](https://www.wikihow.com/Make-a-Single-Name-Account-on-Facebook) | How-to article | n/a | not checked (fetch tool cannot reach wikihow.com) | none | None (personal OPSEC) | no |
| [NCSC three random words](https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online/three-random-words) | UK NCSC password guidance | UK gov (OGL not confirmed on page) | reviewed 2021-12-21, v2.0 | none (NCSC report RSS exists, see part E) | L, Ph10 reference | no |
| [10 Minute Mail](https://10minutemail.com/) | Disposable inbox | n/a | HTTP 403 to fetcher | none seen | L, Ph6 disposable-mail suppression list (domain fact only) | disposable e-mail list yes (Ph6); this service no |
| [Have I Been Pwned](https://haveibeenpwned.com) | Breach notification service | breach/paste data CC BY 4.0; Pwned Passwords no terms | live (1,051 breaches) | API v3: `/breaches`, `/breach/{name}`, `/latestBreach`, `/dataClasses` and Pwned Passwords range are keyless; email, domain, paste and stealer-log need a paid key (Core and up) | H, Ph3 + Ph7 | yes (Ph3 vendor sources ~680, Ph7 ~1622) |
| [I Know What You Download](https://iknowwhatyoudownload.com/en/contacts/) | Torrent peer-activity-by-IP database (Antitor) | n/a | live (15.8M torrents) | APIs (Peer, Capture, Content, Torrent, Online) at api.antitor.com; demo key by email, no prices shown | L-M, Ph1 IP context ("torrenting seen", which hints at residential or proxy use); privacy-sensitive | no |
| [Browserling](https://www.browserling.com) | Remote live browsers ("cybersecurity sandboxes") | n/a | live | Live API (paid); free plan, limits not shown | L, manual safe-open of a URL | no |
| [urlscan.io](https://urlscan.io) | URL sandbox | n/a | live | API, keyed | already built (Ph1) | yes, built |
| [VirusTotal](https://www.virustotal.com) | Multi-AV / TI | n/a | live (page renders as a JS shell only) | API v3, keyed | already built (Ph1) | yes, built |
| [Google Alerts](https://www.google.co.uk/alerts) | Web/news mention alerts | n/a | live | delivery to RSS is available (set up by hand) | M, Ph4 standing alerts | yes (Ph4 ~942, Ph3 ~714) |
| [ProtonMail](https://protonmail.com) | Encrypted e-mail; 301 to proton.me/mail | n/a | live, free tier 1 GB | none relevant | L, operator OPSEC (sock-puppet mail) | Proton named for VPN only (Ph5 ~1111) |
| [ProtonVPN](https://protonvpn.com) | VPN; free tier (1 device, 10 countries) | n/a (apps open source) | live, updated Apr 2026 | none | L, Ph5 egress rung | yes (Ph5 ~1111) |
| [Tor Browser](https://www.torproject.org/download) | 302 to download.torproject.org | Tor: BSD-style | live | Tor exit list and Onionoo (see part C) | M, Ph5 onion egress, Ph6 exit gate | yes |
| [VirtualBox](https://www.virtualbox.org) | Hypervisor | GPLv3 (base) | 7.2.22, 2026-10-20 | none | L, Ph8 isolation / analysis VM | yes (~1765) |
| [Signal](https://signal.org) | E2E messenger | AGPL (clients) | live | none | None | no |
| [Keybase](https://keybase.io) | E2E chat and identity proofs (Zoom-owned since 2020) | BSD (client) | page header showed "Keybase Staging Server"; development status unclear | public user lookup API (identity proofs) | L, Ph7 identity pivot | yes (Ph7 ~1628) |
| [Canarytokens](http://canarytokens.org/generate) | Thinkst tripwire tokens | thinkst/canarytokens: GPL-3.0 per part H | hosted page rendered title only; repo active | self-host via Docker; email and webhook alerts | M, Ph3 tripwires into Ph5 alert inbox (self-hosted) | no |
| [WhatsMyName](https://whatsmyname.app) | Username search site over the WebBreacher/WhatsMyName data | data CC BY-SA 4.0 | **repo archived 2026-11-09**, final dataset of 691 sites; site returned HTTP 464 | `wmn-data.json` and schema | H (method) / M (data), Ph7 | yes (Ph7 ~1617). Archive needs noting |
| [DeHashed](https://www.dehashed.com) | Breach search (returns credentials) | n/a | HTTP 403 to fetcher | paid API | L-M, Ph7 paid adapter; policy constraints | yes (Ph7 ~1644) |
| [BleepingComputer](https://www.bleepingcomputer.com) | Security news | n/a (copyright) | live, 2026-11-11 | RSS `/feed/` | M, Ph4 | not named; Ph4 curated feed list planned (~936) |
| [The Record](https://therecord.media) | Security news (Recorded Future News) | n/a | live, 2026-11-10 | RSS `/feed/` (only 5 items, so poll hourly) | M, Ph4 | not named; as above |
| [BBC News Technology](https://www.bbc.co.uk/news/technology) | General tech news | n/a | not checked (fetch tool cannot reach bbc.co.uk) | BBC publishes RSS per section (known, not verified) | L, Ph4 (general, needs keyword filter) | no |
| [Microsoft Authenticator](https://www.microsoft.com/en-us/account/authenticator) | MFA app | n/a | live | none | None | no |
| [KeePass](https://keepass.info/download.html) | Password manager | GPLv2 (known; page did not state) | 2.62 current | none | None (operator hygiene) | no |
| [Digital Defense checklist](https://digital-defense.io/) | Personal security checklist (lissy93/personal-security-checklist) | MIT | active (© 2019-2026, 1,128 commits) | YAML `personal-security-checklist.yml` plus an API | L-M, Ph10 runbook: operator OPSEC checklist (MIT, so it can be vendored with credit) | no |
| [US DoD OPSEC training](https://securityawareness.usalearning.gov/opsec/index.htm) | CDSE OPSEC awareness course | US gov | not checked (TLS certificate chain error) | none | L, Ph10 reference | no |
| [Digital Exhaust Opt-Out Guide](https://www.documentcloud.org/documents/6983419-Digital-Exhaust-Opt-Out-Guide-for-Law-Enforcement) | Data-broker opt-out guide for law enforcement (DocumentCloud) | n/a | HTTP 403 to fetcher | PDF | L, Ph3 executive-protection reference | no |
| [BushidoToken blog post](https://blog.bushidotoken.net/2020/12/operational-security-tips-and-tricks.html) | Source post (2020-12-31); also lists Warble Alerts (dead, see part F) and Telegram | n/a | blog active (Nov 2026) | Blogger Atom feed (part H) | L (post), M (blog feed, Ph4) | no |

Notes on the higher-value Source 3 items:
- **HIBP:** see part C and part H. Integrate the keyless breach catalogue as reference data
  with the CC BY 4.0 credit. Domain search works only for verified own domains, which suits
  Phase 3.
- **WhatsMyName:** update ROADMAP Ph7. The project is archived and frozen at 691 sites. Keep the
  schema as the model for the toolkit's own site-rule format; the CC BY-SA data stays out of the
  repo.
- **Canarytokens, self-hosted:** run it as a separate container. Token triggers post to a
  webhook, and the Ph5 alert inbox ingests them. This is the only item here that adds a new
  capability.
- **Digital Defense checklist:** MIT YAML. It could seed an "operator OPSEC" checklist page in the
  Phase 10 runbooks before any Phase 5 collection work. Low priority.

---

## Top 10 recommendations (ranked)

The ranking weighs value to the phase being built now (Phase 2) first, then cost (keyless and
licence-clean first), then novelty (not already planned).

1. **Ransomware Vulnerability Matrix to Phase 2 view 9 "Ransomware-linked" (and view 8 edge
   devices).**
   - Data: Markdown tables `Product | CVE(s) | Ransomware Group(s) | Source(s)`, CC BY 4.0,
     last commit 2026-08-30.
   - How: write a small parser pinned to a commit SHA, refreshed weekly. Each row becomes a claim
     (cve, group, role from the `*`/`+` markers, product, sources).
   - Licence: CC BY 4.0 allows a parsed snapshot in the repo with attribution.
   - Dedupe against ransomware.live `/vulns` on (CVE, group).
   - This fills the view the roadmap left open. Part C.
2. **Google Project Zero "0day In the Wild" sheet to Phase 2 view 11 (and view 1).**
   - The roadmap marks it a dead end, but it is current: 26 rows in 2026, the latest patched
     2026-11-09.
   - Keyless CSV per year: `.../gviz/tq?tqx=out:csv&sheet=<YEAR>`.
   - No licence, so store re-keyed facts (CVE, vendor, product, dates) and link out. Part B.
3. **ZDI RSS (published and upcoming) to Phase 2.**
   - "(0Day)"-prefixed published advisories become a "public, no vendor fix" tag for view 7.
   - The upcoming feed gives per-vendor counts of unpatched reported bugs for the Watchlist.
   - Keyless, standard-library XML. Store facts only (rights reserved). Part B.
4. **SANS ISC / DShield API to Phase 1 enrichment (and Phase 5 / Phase 6).**
   - Keyless JSON `isc.sans.edu/api/ip/{ip}?json`: reports, targets, first and last seen.
   - `/cloudips` and `/cloudcidrs` serve the Ph6 cloud gate.
   - Data is CC BY-NC-SA. The User-Agent must carry a contact, so the operator decides the value
     and keeps it in .env. Part A.
5. **phishunt.io to the Phase 3 feed-match store.**
   - CC0, keyless, hourly feeds in JSON, CSV, TXT and STIX 2.1, plus campaign clusters.
     10 requests per second.
   - Label hits as "suspicious (phishunt)", as its terms require. Pair it with PhishTank and
     PhishStats. Part F.
6. **BushidoUK OSINT-SearchOperators to Phase 6 default-signature library and saved hunts, and
   Phase 3 own-org exposure templates.**
   - Re-key the facts. The repo has no licence, so do not copy the files.
   - Store as `{family, filter, value, strength}` records and parameterised `ssl:"{org}"`
     templates.
   - The adversary file was updated 2026-09-27. Source 2 above.
7. **Ransomware Tool Matrix to the Phase 9 commodity-tool stop-list and tool-overlap matrix.**
   - CC BY 4.0. `MostUsedTools.md` has group counts, and there are 17 group profiles.
   - `RTM_ThreatHunt_Checklist.csv` gives the column set for a hunt-tracker export. Part C.
8. **Phase 4 starter feed list:** a verified, keyless set of RSS feeds:
   - Security news: BleepingComputer, The Record, The Hacker News, CyberScoop, The Register,
     Risky.Biz, DataBreaches.net, Full Disclosure.
   - Government and CERT: CISA advisories, CCCS, NCSC UK, HKCERT, IC3 PSA.
   - Blogs and research: BushidoToken blog, Citizen Lab, Kaspersky ICS-CERT.
   - Video: YouTube channel Atom feeds for conference talks (DEF CON, SANS).
   - Full Disclosure, CCCS and HKCERT also feed the Ph2 CVE-mention signal. Parts E, B and H.
9. **Keyless bulk IOC feeds for Phase 5 feed-match:**
   - FireHOL blocklist-ipsets: one repo, hundreds of lists, each keeping its own terms.
   - CIRCL and Botvrij MISP OSINT feeds: MISP manifest format, no licence, local use.
   - Spamhaus DROP JSON: hourly at most, with credit.
   - Use one route per list, either FireHOL or direct (blocklist.de, CINS, GreenSnow, where
     GreenSnow allows local use only). Part A.
10. **Phase 9 vendor-alias crosswalk sources:**
    - Florian Roth's APT Groups and Operations sheet: CC BY 4.0, so storable. This contradicts
      the roadmap note that MISP is the only crosswalk. Check freshness by hand.
    - EternalLiberty: about 848 actors by 100 vendor columns, no licence, so runtime and
      single-source claims only.
    - ETDA MISP export (`getmisp.cgi?o=g`): CC BY-NC-SA. The roadmap says "link only"; revisit
      that decision.
    - BSI "Aktive APT-Gruppen": government, re-key by hand.
    - Plus the deterministic vendor naming-scheme regexes for the Ph2 extractor. Part D.

Close behind:
- yara-x 1.23.0 (BSD-3, cp312 wheels for Windows and Linux): Ph8 compile-check dependency
  proposal.
- Emerging Threats Open rules: `reference:cve` gives a Ph2 "network detection exists" flag.
- Citizen Lab malware-indicators (CC BY-NC-SA, runtime only): Ph4 and Ph9.
- Ransomwhere wallet export (CC BY 4.0): Ph6 wallet gate.
- Mitaka's MIT "search on…" URL-template list: Ph1 link-outs and Ph2 refang test cases.
- HIBP keyless breach catalogue: Ph3 daily diff.
- Self-hosted Canarytokens: Ph3, feeding the Ph5 alert inbox.
- Uncoder IO community edition (Apache-2.0, offline Docker): Ph8 Sigma to SPL/KQL.

## Roadmap corrections and status changes found

These are facts the operator may want to record in ROADMAP.md or docs/journal.md. Nothing has been
edited.

- **Phase 2:**
  - The Project Zero in-the-wild sheet is not a dead end: it is current to 2026-11-09.
  - Tencent bsafe is gone.
  - Vulmon offers API and RSS only on paid plans ($39+/month).
  - cvepremium.circl.lu is the Vulnerability-Lookup already wired.
- **Phase 1 and Phase 11:**
  - The abuse.ch terms (updated 2026-10-21) make only Feodo, SSLBL and YARAify CC0.
  - URLhaus, MalwareBazaar and ThreatFox are not-for-profit only, and their data may not be used
    for AI training without Spamhaus consent. Keep abuse.ch data out of any external-LLM prompt by
    default.
  - The abuse.ch browse pages now sit behind a bot check, so the API is the only route.
- **Phase 7:**
  - WhatsMyName was archived on 2026-11-09.
  - spiderfoot.net now redirects to Intel 471. The open-source SpiderFoot (MIT) README documents
    no REST API, so check "triggered by API" before building.
  - key-server.io is parked; point PGP lookups at keys.openpgp.org.
  - Whoxy reverse WHOIS is $50 per 5,000 queries, the same per-query price as the roadmap's
    figure.
- **Phase 6:**
  - BinaryEdge has shut down.
  - ThreatCrowd is gone, and ThreatConnect's free page redirects to Dataminr.
- **Do not link:**
  - cuckoosandbox.org now serves gambling spam; the Cuckoo 2 repo has been archived since 2021.
  - apt-ecosystem.com serves casino spam and should be treated as compromised.
- **Parking lot:**
  - T-Pot sends community data by default; remove `ewsposter` to opt out.
  - T-Pot's home is now telekom-security/tpotce.
- **Data handling policy conflicts to decide:**
  - LeakRadar returns plaintext passwords, and its paid plan sits next to the "no purchase of
    stolen data" rule.
  - Ransomware-Leaks hosts leaked chat archives. Show the index only and never fetch `Files/`.
- **Phase 9:** the Lockheed Martin link in the list is the 2015 "Gaining the Advantage" paper,
  not the 2011 Hutchins et al. original.

---

## Appendix: every link not checked, and why

### Part A: IOC feeds and IOC vetting (checked 2026-11-11)
- https://twitter.com/dgafeedalerts and https://twitter.com/malc0de: redirect
  to x.com, which returned HTTP 402 (X/Twitter, not renderable). Intent: DGA
  feed alerts (Bambenek) and the old malc0de malware URL database account.
- https://osint.bambenekconsulting.com/feeds/: HTTP 403. Status inferred from
  a web search (commercial licence since 2019) and MISP's feed list ("requires
  a valid license").
- https://www.c1fapp.com/: HTTP 403; no current status found by web search.
- https://cybercrime-tracker.net/: timed out twice.
- https://www.dshield.org/reports.html (and isc.sans.edu/reports.html): too
  many redirects; the ISC API page was read instead.
- https://community.blueliv.com/#!/discover: DNS does not resolve (dead).
- https://beta.virusbay.io/: DNS failure twice (dead).
- https://labs.inquest.net/ and https://labs.inquest.net/repdb: "socket hang
  up" twice. InQuest was acquired by OPSWAT in August 2024 (web search); no
  shutdown notice found.
- https://www.threatminer.org/index.php (and /api.php): HTTP 522 twice.
- https://www.abuseipdb.com/, https://check.spamhaus.org/,
  https://www.infobyip.com/ipbulklookup.php, https://search.dnslytics.com/:
  HTTP 403 to WebFetch (sites are up for browsers; content not read).
- JavaScript-only pages, reached but content not readable:
  https://otx.alienvault.com/, https://otx.alienvault.com/pulse/create,
  https://app.any.run/, https://opentip.kaspersky.com/,
  https://metadefender.opswat.com/ (redirects to metadefender.com),
  https://whois.domaintools.com/, https://www.virustotal.com/gui/home/search.
- https://urlhaus.abuse.ch/browse/ and https://threatfox.abuse.ch/browse/:
  reached a bot-verification screen; services known live (built in Ph1).
- Supplementary pages (not list links): botvrij.eu home was rate-limited by
  the shared safety check; who.is/api returned 404 on retry, so the who.is
  free-tier limits were not read. The Spamhaus DROP page was read on retry.

### Part B: Vulnerabilities, ThreatHunting, ICS-OT, Mobile
- **X/Twitter**: 33 x.com URLs returned HTTP 402: @CVEnew; the 9 Vulnerabilities researchers; the 2 contest searches; the 20 ICS researchers; and the Kimsuky status post. The x.com safety check was then rate-limited for the 21 mobile researcher accounts: 11 attempts were refused and 10 were not tried (@midnight_comms through @cryptax). X is already ruled out in ROADMAP Ph2.
- **Rate-limited twice (stopped per brief)**: portal.auscert.org.au/bulletins/ (AusCERT), vx-underground.org/ics_scada.html, ncsc.gov.uk ICS COI post. cyble.com was rate-limited, then returned 403 on retry.
- **Tool-blocked domains**: web.archive.org (Anubis/stv24 snapshot), wired.com (Sandworm), bbc.co.uk (Africa phones), reuters.com (DarkMatter).
- **HTTP 403**: cvedetails.com (and its API docs page), securityweek.com, therecord.media search, industrialcyber.co, blog.scadafence.com, detect.fyi, lookout.com (tag page, Uyghur PDF, Syria blog, Pegasus blog, Monokle PDF).
- **HTTP 404 / dead / moved**: AusCERT original path; Talos `/search/label/CVE` and `/search/label/ICS`; zeroscience.mk/en/vulnerabilities/; cisa.gov/uscert/ics/alerts; NewsNow ICS query; nozominetworks research-reports path; threatfabric.com/blogs.html; blog.zimperium.com (NXDOMAIN); Mandiant search (to a Google Cloud services page); Tencent bsafe (to iOA marketing); Team Cymru MoqHao 1.5 and 2 (to blog index); Cybereason Bearded Barbie (to LevelBlue blog index); jsof-tech.com (blank, likely defunct).
- **TLS or timeout errors**: securityintelligence.com (two links), apklab.io (certificate error), mcafee.com (60 s timeout).
- **Partially read**: nvd.nist.gov (title only; already integrated); detection.fyi (page over 10 MB); Lookout Stealth Mango PDF (over 10 MB, exists); yaratoolkit (Streamlit shell only); uncoder.io (title only, so the repo was used instead); VirusTotal GUI pages (JavaScript only); Europol pages (single-page-app shell); MalwareBazaar tag pages (browser check); YouTube pages (titles resolved; availability not confirmable).
- **Note on files**: WebFetch automatically saved four PDF responses to `<session folder>/tool-results/`: the Home Office guide, CrowdStrike Fancy Bear, Trend MuddyWater and Lookout Pegasus. These were not requested downloads and were not opened beyond the fetch.

### Part C: RansomwareIntel.md, Darknet.md, Data breaches.md
- Ransomwre groups Wiki, `edteebo2w2b...cvkbuqd[.]onion` (in both
  RansomwareIntel and Darknet): onion and defanged.
- Ransomware leak index, `hxxps://darkfeed.io/`: defanged, marked [offline]
  in the source.
- Twitter #Ransomware search and the Twitter researcher list: X/Twitter, not
  renderable (HTTP 402). Intent: live #ransomware search and a curated list of
  ransomware researchers.
- facebookcorewwwi.onion, 3g2upl4pq6kufc4m.onion, protonirockerxow.onion,
  expyuzz4wqqyqhjn.onion: onion addresses (also v2 format, retired by Tor in
  2021, so these addresses no longer work).
- Stronghold Paste `nzxj65x32vh2fkhk[.]onion`, BTDigg `btdiggwzoyrwwbiv[.]onion`:
  onion and defanged.
- Tor Browser Security Guide on Dread (dreadytofat...onion): onion.
- r/Onions, r/DNMBusts, r/deepweb, r/TOR, r/Darknet: the fetch tool refuses
  reddit.com; not retried by another route.
- DarknetDaily (darknetdaily.com and www.): TLS error on both attempts.
- LeakRadar (leakradar.io and www.): TLS error on both attempts; facts above
  come from one web search (Product Hunt, GitHub LeakRadar org, dev.to post).
- Onion Tree (oniontree.org): connection refused.
- DarkSearch (darksearch.io): DNS does not resolve (dead).
- Partially checked: VirusTotal comments and ANY.RUN (JS apps rendered empty);
  Hudson Rock tools page (title only; docs 403); Dehashed (403);
  DataBreaches.net home (403, RSS read instead); MalwareBazaar (bot check page);
  NCSC search (results JS-rendered; NCSC all-feed RSS read instead); DarkTracer
  Google Drive file (title only, sign-in prompt); Pulsedive threat page (no
  threat content rendered).

### Part D: adversary intelligence, CTI fundamentals, reporting, frameworks
- **X/Twitter (38 links, 32 unique handles):** README #17, 31, 33, 36, 38, 44, 62, 64, 66, 68, 70, 72, 74, 78,
  80, 82, 84, 90; Adversary Intelligence #38-57. Each tried once (twitter.com 301s to
  x.com, and x.com returns HTTP 402 to unauthenticated fetches). "X/Twitter, not
  renderable". Intent: follow APT researchers and author accounts. These could seed a Ph4
  handle watchlist if X is ever read.
- **LinkedIn:** README #7 (403 after a rate-limited first try), #15 (HTTP 999), #53 (not
  fetched; same LinkedIn block). #16 (LinkedIn Pulse) loaded.
- **PDFs not fetched** (WebFetch saves binary PDFs to disk, and the brief forbids downloads):
  README #14, 18, 20, 22, 24, 32, 35, 37, 39, 46, 48, 50, 56 (IBM download), 73, 77, 92,
  96, 98, 100, 102, 104, 105 (`at_download`). Where possible the landing page or Archive copy
  was checked instead: #48 and #50 are confirmed linked from LM's live kill-chain page; #100
  is listed in the CEUR Vol-2940 index; #105's ENISA landing page loads; #22, #39, and #77
  landing pages returned 403; #46's landing page returned HTTP 500; #14, #26, #46, #96, #98,
  #102, and #104 have copies in CTI-fundamentals/Archive.
- **PDFs fetched before the binary save was noticed:** README #6 (ialeia, 2 MB) and #8
  (cryptome, 4.8 MB). WebFetch auto-saved them under
  `<session folder>/tool-results/`
  (`webfetch-1794442341346-r71vul.pdf`, `webfetch-1794442341982-x8e1xr.pdf`). They can be
  deleted. No other files were saved.
- **web.archive.org:** README #2, #10, #52. The first try was rate-limited, and the second
  returned "Claude Code is unable to fetch from web.archive.org". Not checked.
- **403 Forbidden:** README #25, #26 (tandfonline), #40, #41, #79 (medium);
  AI #27 (ti.qianxin.com), AI #60 (vx-underground); Frameworks #11 (engage.mitre.org).
- **Failed twice (socket closed):** AI #58 lab52.io.
- **Rendered only a title (JS apps or Google Sheets):** README #83 (partial), #85 / AI #59
  (legal indictments sheet), AI #16 (aptmap.netlify.app), AI #18 pubhtml (the `/edit`
  view did give tabs and licence), AI #21 (kumu embed), Frameworks #9 (ATLAS; repo
  checked via the GitHub API instead).
- **Google search dorks:** AI #29-31, Monthly #7. Google returns its "having trouble"
  page with no results. Recorded as dork intent only.
- **Dead or moved (checked, recorded):** AI #5 (Dragos old URL 404, new list checked), AI #6
  (ThaiCERT 404), AI #20 (apt-ecosystem.com now serves casino spam: treat as compromised,
  do not link), AI #22 (Intezer OST map gone), README #55 (Verizon 404), #59/#109
  (mandiant.com redirects to Google Cloud sales), #69 (Lexicon.md 404, repo live),
  Monthly #1 (Red Canary to Zscaler), #3 (WithSecure), #4 (Cyware 404), #5 (Rewterz 404),
  Reporting #1 (ThreatNote to morado.io), #2 (Fabric page 404, repo live).
- **Not fetched as a file:** README #94 folder listing checked; #107 xlsx GitHub page loaded
  but the spreadsheet did not render. The xlsx files were not downloaded.
- **Not fetched in full:** the APTmap `apt.json` raw file exceeds 10 MB, so its structure
  is unread.

### Part E: SecurityNews, CERTs, Collections
- https://start.me/p/rxr5Nm/incident-reports, https://start.me/p/ELY5By/technical-sources,
  https://start.me/p/wMxOjN/osint: HTTP 403 to the fetcher; content not seen.
- https://delivery.fbi.gov/subscribe: HTTP 403 (IC3 RSS checked as the substitute).
- https://www.tracelabs.org/resources/tools/: HTTP 403.
- https://medium.com/week-in-osint: page HTTP 403; its Medium RSS feed was read instead.
- https://www.databreaches.net/news/: page HTTP 403; its /feed/ was read instead.
- https://docs.google.com/spreadsheets/d/1klugQqw6POlBtuzon8S0b18-gpsDwX-5OYRrB7TyNEw/htmlview:
  only the title rendered; tabs and rows not visible (one try, per brief).
- https://cyber.gc.ca/en/alerts-advisories: first attempt rate-limited by the
  fetch safety check, second attempt exceeded the 10 MB fetch cap; the CCCS
  Atom feed was verified instead.
- https://github.com/WilliamThomas-sec/google_dork_list: 404 (dead; also 404 at
  github.com/BushidoUK/google_dork_list and via the GitHub API).
- https://www.aboutintel.com: fetched, but only a title and tagline rendered
  (JS app); /about returned 404, so purpose and terms are unverified.
- Not fetched by design: none (no .onion, defanged, or X/Twitter links in these files).
- Feed URLs linked but not fetched: https://www.ic3.gov/CSA/RSS,
  https://www.hkcert.org/getrss/security-news.

### F: Anti-Phishing, Website Security, Search Engine, OSINT Investigation
- [http://archive.vn/](http://archive.vn/): the fetch tool refuses this domain ("unable to fetch"); not retried by another route.
- [https://archive.org/web/](https://archive.org/web/): safety check rate-limited on both attempts; stopped as instructed. Row uses prior knowledge.
- [https://www.gov.uk/government/organisations/companies-house](https://www.gov.uk/government/organisations/companies-house): safety check rate-limited on both attempts; stopped. Row uses prior knowledge.
- Fetched but blocked (HTTP 403 or bot wall): checkphish.bolster.ai (redirect target of checkphish.ai), radar.cloudflare.com/scan (used the Cloudflare developer docs instead), abuseipdb.com, epieos.com, medium.com z3roTrust article, loungefly84.medium.com guide (rate-limited first, 403 second), start.me, tineye.com, 192.com, duplichecker.com, flightradar24.com, radar.freedar.uk, marinetraffic.com, blockchain.com, base-search.net (Anubis bot wall).
- Fetched with errors: services.normshield.com, threatcrowd.org, reddit6.com, osint.team (DNS does not resolve); itools.com (connection refused); insecam.org (expired certificate); bioline.org.br (certificate chain error); repec.org (TLS handshake error); whatsmyname.app (HTTP 464; data checked through the GitHub repo); checkusernames.com (HTTP 522); emailrep.io (HTTP 400); phishunt.io/community/ and isitphishing.org/brand-alert (404); Rog3rSm1th/Profil3r and marcoramilli/PhishingKitTracker (404); both inteltechniques.com PDFs (404).
- Rendered only a title or fragment (status partly known): whois.domaintools.com, virustotal.com GUI, google.com/maps, bing.com/maps/aerial, windy.com, rocketreach.co.
- Redirects not followed further: worldcat.org (to search.worldcat.org), link.springer.com (to a Springer login cookie check), map.snapchat.com (to snapchat.com; followed once, web map not offered), binaryedge.io (Coalition FAQ, 404).
- No .onion, defanged, or X/Twitter links were in these four files.

### Part G: Malware analysis, Honeypots, GitHub Projects, Chrome Extensions
All 123 links were attempted. These failed or returned too little to verify:

- Pages that fetched but could not be verified:
  - Passive Total (community.riskiq.com): connection refused. Status taken from a WebSearch, since the site is dead.
  - Sekoia (malware.sekoia.fr): DNS not found.
  - BlueLiv (community.blueliv.com): DNS not found (first attempt was rate-limited).
  - VirusBay (beta.virusbay.io): DNS failure (first attempt was rate-limited).
  - InQuest Labs: socket hang up (first attempt was rate-limited). Status per WebSearch: acquired by OPSWAT in 2024.
  - IDA product URL: 404 (checked the IDA Free page instead).
  - Hakin9 FinalRecon article: 404 (checked the repo instead).
  - Infoga repo: 404.
  - VT `/en/user/CYBERCOM_Malware_Alert/`: 404 (legacy URL).
  - Automater (tekdefense.com): TLS error (checked the repo instead).
  - CAPE public instance, viz.greynoise.io, base64decode.org, Medium (pramos): HTTP 403 to the fetcher.
- Redirects not followed:
  - kernelmode.info: 301 to the unrelated xoilactvst.net. Not followed: repurposed domain.
  - Flare VM blog: chain ends at a generic Google Cloud page. Project checked on GitHub instead.
- Single-page apps that returned only a title (existence confirmed, details not readable):
  - VirusTotal upload and all 16 `/gui/user/` pages.
  - App.Any.Run (the plans page was read instead), Hybrid Analysis (home, API docs and FAQ), FileScan.io, OTX, ELF Digest (second attempt also returned only the title), LP-DB site (the repo README was read instead).
- Chrome Web Store empty listings (detail not readable; extension delisted): ThreatPinch, Treeverse, uBlock Origin, Imagus, Go Back in Time, Stratus.
- Partial content:
  - t.me/s/malwareplayground: no channel preview, contact page only.
  - YouTube MHN tutorial: title only.
  - fireeye.market: loaded after one rate-limited attempt.
- Not opened: abuse.ch terms pages (URLhaus, MalwareBazaar) and MalShare `tos.php`.

### H-aux: auxiliary sub-lists (VPN, VMs, email, OPSEC, certs, training, Twitter tools, podcasts, conferences, YouTube, Misc)
- Darknet Diaries (https://darknetdiaries.com/): WebFetch domain-safety check rate-limited twice. Not retried.
- Malicious Life (https://malicious.life/): safety check rate-limited twice. Not retried.
- The Cyber Wire (https://thecyberwire.com/podcasts): safety check rate-limited three times. Not retried.
- Spoonbill (https://spoonbill.io/): safety check rate-limited twice. Not retried.
- Mention Mapp (https://analytics.mentionmapp.com/modules/free/): safety check rate-limited twice. Not retried.
- Cyber Security Sauna (https://twitter.com/cybersauna?lang=en): X/Twitter, not renderable (301 to x.com, which returns 402).
- Sector035 OSINT CTF tweet (https://twitter.com/Sector035/status/1211038518635614208?s=20): X/Twitter, not renderable (402).
- Tweetdeck (https://tweetdeck.twitter.com/): 301 to pro.twitter.com (X Pro). Not followed because X does not render.
- Fetched but content blocked or failed (recorded in the tables): TraceLabs OSINT VM (403), 10 Minute Mail (403),
  ARCX (403), Udemy (403), Black Hat (403), Virus Bulletin (403), RAND RR610 (403), DEF CON (connection reset),
  SentinelOne lab article (redirect target 429), tails.boum.org (TLS mismatch; tails.net checked instead),
  my24h.email (expired certificate), OmniSci Tweetmap (TLS error), Recorded Future Predict and
  ctf.cybersoc.wales (DNS NXDOMAIN), Microsoft Edge VMs and Buscador (404), GrujaRS YouTube (404).
- Redirects noted but not followed further: termux.com to Google Play; the FireEye blogs to a generic Google
  Cloud Mandiant page (repos checked on GitHub instead).
- No .onion or defanged links appear in these sub-files.

### Sources 2 and 3
- wikiHow single-name Facebook article: the fetch tool cannot reach wikihow.com.
- BBC News Technology: the fetch tool cannot reach bbc.co.uk.
- 10minutemail.com, dehashed.com, DocumentCloud Digital Exhaust guide: HTTP 403 to the fetcher.
- whatsmyname.app: HTTP 464. The underlying GitHub repo was checked instead (archived 2026-11-09).
- securityawareness.usalearning.gov (DoD OPSEC): TLS certificate chain error ("unable to verify the first certificate").
- canarytokens.org/generate and virustotal.com: page rendered a title only (JavaScript app). Covered via the thinkst/canarytokens repo and the built VT module.
- ShodanAdversaryInfa.md: fetched and summarised, but the fetch tool's summariser declined to reproduce the query strings verbatim. Operators and targets are captured; exact values need a manual read in a browser before re-keying.
