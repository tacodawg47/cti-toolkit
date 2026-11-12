# Threat actor TTPs, IP attribution, and actor-profile guide: research notes

Researched 2026-11-11 by read-only web fetch (GitHub API, raw.githubusercontent.com, and the linked pages).
Nothing was cloned, installed, or signed up for. Onion addresses found in the repos were recorded (defanged) and
never visited. Page content was treated as data.

Read before judging: ROADMAP.md Phase 6 (lines 1323-1605: pivot grid, suppression lists, bounded-cluster
workflow, "Attribution is a separate, optional step handled by the Phase 9 evidence gate") and Phase 9
(lines 1769-2017: profile layout agreed 2026-11-06, Kraven additions, behaviour pivoting, evidence classes and
attribution gate, stop-list, datasets), plus the Phase 5 source registry (Admiralty rating, line 1045) and
`app/modules/enrich/rdap.py` (already returns the RDAP abuse contact).

**Headline findings**

1. **crocodyli/ThreatActors-TTPs** is a community, **unlicensed**, mostly **unsourced** set of Markdown profiles
   for 41 ransomware and extortion groups plus a generic "Commands" folder. About 670 ATT&CK table rows; **no row
   cites a source**. It has data-quality defects (deprecated, invalid, and mismatched technique IDs). It is **not a
   seed** for our profiles. Most important: **ransomware.live displays this repo's TTP matrix and background
   text and credits it** (checked on the 8Base and DragonForce group pages). We already show ransomware.live
   PRO group data, so this repo and ransomware.live's TTP section are **one source, not two**.
2. **curated-intel/Attribution-to-IP** is not about attributing infrastructure to threat actors. It is a
   checklist of 18 free and 3 commercial methods for finding the **owner** of an IP address, for victim
   notification and bug bounty work. Its value to us: (a) a clean rule that **owner/hoster is not operator**,
   (b) an IP-type classification step that has to come before any pivot or attribution, and (c) a
   **victim-notification / "compromised third party"** workflow that the roadmap does not have yet.
3. **curated-intel/Threat-Actor-Profile-Guide** is a short (about 6 KB text, 4-page PDF) 2023 template by
   BushidoToken. Our Phase 9 layout already covers more than it does on sourcing and rigor. What we lack from
   it: a dated **executive summary** (What / So what / What now) with a "relevance to us" and a
   "how well we are defended" statement, **audience variants** (leadership vs operations), a
   **Diamond Model card** (including attack vs support infrastructure and targeted systems), an
   **"Observable" column** per technique, an **IN / THROUGH / OUT (Unified Kill Chain)** grouping of techniques,
   **dwell time**, **cyber-enablement (stepping-stone) targeting**, an **attribution diagram**, and a
   **contention footnote**.

---

## 1. crocodyli/ThreatActors-TTPs

### Description

"Threat Actors and Ransomwares, TTPs": one folder per ransomware or extortion group. Each folder holds a narrative
`Readme.md` (history, aliases, operating model, sometimes references) and usually a `<Group>-TTP.md` ATT&CK table.
Newer folders (2026) add `CVEs-<Group>.md` and `Additional-Sources.md`. A `Commands/` folder holds captured Windows
commands. The README describes a "Payload locations" section, but **no such folder exists** in the tree. The README
says the data is meant to feed other projects, naming RANSOMWARE.LIVE. It has done that: ransomware.live group pages
credit "Crocodyli's ThreatActors-TTPs" for the background text and the "TTPs Matrix" (checked on /group/8base and
/group/dragonforce).

### Format

- **156 tree entries** (GitHub API, not truncated): 42 folders, 113 files. Almost all are Markdown, plus one ATT&CK
  Navigator layer (`Cl0p/attack-navigator.json`, 27.5 KB). Total repo size is reported as 177 MB (mostly images held
  as GitHub user-attachments, not in the tree).
- **TTP tables:** Markdown tables `TACTIC | TECHNIQUE | ID | DETAILS`. The DETAILS cell is a one-line procedure
  sentence, sometimes naming tools (PsExec, Rclone, Cobalt Strike, AdFind, Mimikatz) or binaries (vssadmin, wmic,
  bcdedit). There are no full command lines in the TTP tables. The tactic cell is often blank after the first row of
  a group. Some tables have Portuguese headers or are partly in Portuguese. Brain Cipher uses a 3-column table with
  the ID inside the technique cell. CrossLock has an empty ID column.
- **CVE files:** `CVE | Description` or `CVE | Severity | Description`, with no sources.
- **Additional-Sources files** (0apt, CoinbaseCartel, ShinyHunters, Sinobi, Tengu): tables of `Source | Date | Highlight`
  that **name** publishers (Cyble, Mandiant, Bitdefender, Red Piranha, Symantec, SOCRadar, ReliaQuest, Barracuda,
  IBM X-Force, BlackFog, CYFIRMA, BitSight) with a month, but **contain no URLs**.
- **Navigator layer (Cl0p):** ATT&CK v13, Navigator 4.8.2, layer 4.4, enterprise. 142 technique entries, 40 coloured,
  **no scores, no comments, no links, no metadata**.
- **Commands folder (20 files):** `COMMAND | DESCRIPTION` tables of generic ransomware pre-encryption commands
  (net stop for backup, AV, and DB services; vssadmin, wmic, and PowerShell shadow-copy deletion; wbadmin;
  bcdedit safe-mode; wevtutil log clearing; netsh firewall; net user and localgroup; registry; LSASS dump;
  PowerShell download and upload). **No ATT&CK IDs, no sources, and only one is attributed to a group**
  (Indicator-Removal: BlackSuit).

### Actors covered (41 groups)

| Folder | Files | ATT&CK rows (unique IDs) | Sources inside | Notes |
|---|---|---|---|---|
| 0apt | TTP, CVEs, Additional-Sources, Readme | 6 | named only (Cyble, Mandiant, Bitdefender); no URLs | Unsourced "likely Asian APT" origin claim |
| 0mega | TTP, CVEs, readme | 7 | ransomware.live link | CVE file lists none |
| 3AM | TTP, readme | 10 | Symantec named; onion | |
| 8base | TTP, CVEs, Readme | 32 (31) | ransomware.live; DOJ, NPA named | CVE file lists no CVEs |
| ALPHV-BlackCat | 2 TTP tables, Readme | 59 (56) + 37 | none | Tactic IDs (TA0002, TA0008) in ID column; T1059.001 labelled as cmd shell |
| APT73 | readme | none | none | Hosting AS9009 noted; TTPs "pending" |
| Akira | TTP, CVEs, Tools, Readme | 33 (32) | none | Aliases Storm-1567, GOLD SAHARA, PUNK SPIDER given **without source**; 8 CVEs; 36 tools |
| AlphaLocker | TTP, readme | 4 | ransomware.live | |
| BianLian | TTP | 10 | none | no readme |
| BlackBasta | TTP, readme | 41 (38) | none; 2 onions | Aliases Cardinal, Storm-1811, UNC4393 **unsourced** |
| BlackSuit | TTP, readme | 16 (15) | ransomware.live | |
| Brain Cipher | TTP, readme | 5 | Sangfor named | 3-column table |
| Cactus Ransomware | TTP, Readme (14 KB) | 21 | Kroll, SOCRadar, SecurityScorecard, The Hacker News (URLs) | Commands, registry, MSI GUIDs, CVEs |
| Cl0p | 2 TTP tables, Readme, Navigator JSON | 11 + 28 | tweet image only | Table 2 "mapped by carlosadrianosj" |
| CoinbaseCartel | TTP, Additional-Sources, readme | 18 | 7 publishers named, no URLs | Alias "shinysp1d3r" |
| CrossLock | TTP, Readme | 0 (ID column empty) | Medium, Cyble, VT sample (URLs) | |
| Cuba | TTP, Readme | 12 | BlackBerry, Mandiant, Elastic, CISA AA22-335A, IC3, Profero (URLs) | Best-sourced readme |
| DORRRA | TTP, readme | 16 | none | Makop variant |
| Devman's Ransomware | TTP, readme | 18 | VT IP pages, ARIN RDAP, Cogent geofeed, Medium, YouTube | Hunting notes (FOFA, Mythic C2 hosting IPs) |
| DoNex | TTP, readme | 33 (32) | Fortinet | **T1064 (deprecated "Scripting")** |
| DragonForce | TTP, readme | 5 | ransomware.live, Cyble | **T1005.002 does not exist** (labelled "User Execution") |
| FSociety-Flocker | TTP, readme | 1 | none | |
| HsHarada | Readme | none | none | ransom-note image only |
| Hunt-Dharma-Crysis | TTP, readme | 20 (19) | none | |
| Hunters International | TTP, Readme | 6 | BleepingComputer x2, own tweet | |
| KageNoHitobito | TTP, readme | 20 (19) | none | |
| LockBit | 2 TTP tables, Readme | 43 (38 + TA0010) + 23 | none | Table 2 by carlosadrianosj |
| Magaskosh | TTP, Readme | 5 (4) | VT behaviour page | |
| Medusa | TTP, readme | 19 | none | |
| Play | Readme | none (CVEs and tools only) | Trend Micro, Avertium, Symantec, Malpedia (URLs) | |
| RansomHub | TTP, Readme (10 KB) | 8 | Fortinet, Forescout; onion | |
| Rhysida | TTP, README | 32 (28) | Trend Micro, HHS HC3 PDF | |
| Rincrypt | TTP, readme | 16 (12) | PCRisk image credit | Chaos variant |
| SafePay | TTP, Readme | 13 | none | **T1089 (revoked)**; mapped by Sudesh Yalavarthi |
| Shinra | TTP, readme | 34 (33) | none | Proton variant |
| ShinyHunters | TTP, CVEs, Additional-Sources, Readme | 5 | named only | Coalition partners (Scattered Spider, LAPSUS$, UNC5537) unsourced |
| Sinobi | TTP, CVEs, Additional-Sources, Readme | 10 | ReliaQuest, Barracuda, IBM, BlackFog named | Lynx/INC lineage claim |
| Tengu | TTP, CVEs, Additional-Sources, Readme | 10 | Red Piranha, CYFIRMA, BitSight named | |
| Van Helsing Ransomware | Hunting/Daily.md | none | ransomware.live, CYFIRMA, FOFA queries | Leak-site title pivot, 2 IPs |
| Yashma-Ator-Vietnamita | TTP, Readme | 9 (7) | Cisco Talos | T1105 labelled "Input Capture" (it is Ingress Tool Transfer) |

**Totals:** about 670 technique rows across 37 tables for 35 groups. Five groups have no TTP table (APT73, HsHarada,
Play, Van Helsing, and CrossLock in effect). **Per-row citations: zero.** About 12 of 41 readmes carry at least one
reference URL. The rest are unsourced narrative or point only to ransomware.live.

### How TTPs are expressed

- ATT&CK technique IDs, often with sub-techniques, plus a one-line procedure sentence. There are no dates per row,
  no ATT&CK version stated (the only versioned artefact is the Cl0p layer, v13), and no source per row.
- Quality defects found by reading every table: revoked or deprecated IDs (T1064, T1089), a non-existent sub-technique
  (T1005.002), ID and name mismatches (T1105 as Input Capture, T1059.001 described as cmd), tactic IDs in the
  technique column, empty ID columns, duplicated rows, mixed languages.

### Licence and maintenance

- **Licence: none** (GitHub API `license: null`; nothing in the README). This means all rights reserved. It may be read or
  fetched at runtime for local use. It may not be copied into our repo, and not used as test fixtures by copying.
- Created 2023-07-28; 406 commits; **last push 2026-01-29** (a bulk upload of ShinyHunters, Sinobi, Tengu,
  CoinbaseCartel, and 0apt that day). Nothing since, so about 9.5 months idle as of 2026-11-11. 421 stars, 60 forks,
  2 open issues. Single maintainer (crocodyli) with two named table contributors. Renamed from
  `crocodyli/Ransomwares-TTP` (old asset URLs and the old repo URL resolve to the new name).

### Linked items

Images (about 60 `github.com/user-attachments/assets/...` and `github.com/crocodyli/{Ransomwares-TTP,ThreatActors-TTPs}/assets/...`
URLs) were spot-checked: they 302 to signed S3 PNGs, so they are live. They are screenshots of leak sites, ransom
notes, and diagrams. Value: None. They are not listed one by one.

| Name | What it is | Live? | Value (phase) | Already in roadmap? |
|---|---|---|---|---|
| ransomware.live (home) | Ransomware leak-site tracker, public + PRO API | Yes | High (2, 3, 9), already used | Yes (PRO key, terms recorded) |
| ransomware.live /group/8base | Group page; credits crocodyli for background + TTP matrix; KQL, YARA, IoCs, Navigator link | Yes (group inactive, site seized) | High as a **lineage finding** (9) | Source yes; lineage no |
| ransomware.live /group/0mega, /alphalocker, /blacksuit, /dragonforce, /VanHelsing | Group pages | Yes (all 5) | Medium (9) | Yes |
| twitter.com/crocodylii | Maintainer's X profile | 301 to x.com, then HTTP 402 | None | No |
| twitter.com/DailyDarkWeb/status/1684488806240509953 | Cl0p statement image | Not checked (x.com returns 402) | None | No |
| twitter.com/crocodylii/status/1781290861680038183 | Maintainer tweet (Hunters Intl) | Not checked (x.com 402) | None | No |
| Kroll: Cactus ransomware | Vendor report (2023) | HTTP 403 to fetcher | Medium (9 reporting) | No |
| SOCRadar dark web profile: Cactus | Vendor profile | HTTP 403 | Low | No |
| SecurityScorecard Cactus whitepaper (PDF) | Vendor PDF | Not fetched (binary) | Low-Medium | No |
| The Hacker News: Cactus exploits Qlik Sense (2023-11-30) | News | Yes | Low | No |
| github.com/optiv/Freeze | Red-team payload/EDR-evasion tool | **Fetch refused by safety safeguard**; not retried | Low (stop-list context) | No |
| Medium @Pandemicboy: CrossLock | Blog | HTTP 403 | Low | No |
| Cyble: CrossLock ransomware (2023-04-18) | Vendor report; ATT&CK IDs + hash IOCs | Yes | Medium (2 extraction test) | No |
| VT file 495fbfec... (CrossLock), VT file 1b00ab6a... behaviour (Magaskosh) | VirusTotal GUI | JS shell only | Low (1, enrich via API instead) | VT yes |
| BlackBerry: Cuba deploys new tools (2023-08) | Vendor report | **Dead**: 301 to generic blog index | None | No |
| Mandiant: UNC2596 Cuba | Vendor report | **Dead**: 301 to Google Cloud services page | None | No |
| Elastic: Cuba campaign analysis (2022-09-08) | Vendor report; tactics + large IOC table | Yes | Medium (2, 9) | No |
| CISA AA22-335A (Cuba) | Government advisory; ATT&CK tables + IOCs | Yes | High (2, 9) | Yes (CISA advisory table parsing) |
| IC3 211203-2.pdf (Cuba, 2021) | FBI flash PDF | Not fetched (binary) | Medium | No |
| Profero: Cuba ransomware PDF | Vendor PDF | Not fetched (binary) | Low | No |
| Medium @yua.mikanana19: Mythic C2 | Blog | HTTP 403 | Low | No |
| YouTube Qq2HbvMqjNY (youtu.be and watch URL) | Mythic C2 video | **Fetch refused by safety safeguard**; not retried | None | No |
| VT IP 38.132.122[.]214 / [.]213 community | VT GUI pages for Devman hosting IPs | JS shell only | Low | VT yes |
| rdap.arin.net /ip/38.0.0.0, /entity/PSI | ARIN RDAP records (Cogent/PSINet) | Yes | Low (1 RDAP already built) | Yes (RDAP) |
| geofeed.cogentco.com/geofeed.csv | RFC 8805 geofeed, about 3.9 MB | Yes | Low-Medium (6: provider geofeeds) | No |
| rwhois://rwhois.cogentco.com:4321 | RWHOIS referral | Not checkable (non-HTTP) | None | No |
| Fortinet: KageNoHitobito and DoNex (2024-04-25) | Vendor report, SHA2 IOCs | Yes | Medium | No |
| BleepingComputer x2 (2021-10-29, 2023-11-28) | News | Yes | Low | No |
| Trend Micro: Play playbook (2022-09-06) | Vendor report, IOCs | Yes | Medium | No |
| Avertium: Play in-depth | Vendor report | **Dead**: DNS does not resolve | None | No |
| Symantec: Play VSS tools (2023-04-19) | Vendor report | Yes (301 to security.com) | Medium | No |
| Trend Micro encyclopedia PRIVICMD.YACCAT | Malware entry | Yes | Low | No |
| Malpedia win.mimikatz, win.cobalt_strike | Malware family pages | Yes | Medium (9 reference link) | Yes (link-only) |
| github.com/Fody/Costura | .NET embedding library (MIT) | Yes | Low (tool context) | No |
| github.com/alphaleonis/AlphaVSS | .NET VSS API (MIT/Apache), inactive | Yes | Low | No |
| processhacker.sourceforge.io | Process Hacker, now System Informer | Redirect (307) to systeminformer.io, live | Low (stop-list: admin tool) | No |
| github.com/BloodHoundAD/BloodHound | BloodHound legacy (unmaintained) | Yes | Low (stop-list) | Indirect (stop-list concept) |
| github.com/carlospolop/PEASS-ng winPEAS | Privilege-escalation scripts | Yes | Low (stop-list) | No |
| Fortinet community: FortiEDR vs RansomHub (2024-04-04) | Vendor KB | Yes | Low | No |
| Forescout: RansomHub and Change Healthcare (2024) | Vendor report | Yes | Medium | No |
| Trend Micro: Rhysida overview (2023-08-09) | Vendor report; ATT&CK IDs + IOC file | Yes | Medium (2 test) | No |
| HHS HC3 Rhysida sector alert (PDF) | Government PDF | Not fetched (binary) | Medium | No |
| FOFA query: title="VanHelsing Blog" | Live search result | Yes, partial without login | Low (6 title pivot idea, already planned) | Title pivots yes |
| FOFA query: title="VanHelsing Chat" | Live search result | Rate-limited ("frequency out of limit") | Low | as above |
| CYFIRMA: VanHelsing (2025-03-20) | Vendor report, ATT&CK IDs | Yes | Medium | No |
| Cisco Talos: Yashma (2023-08-07) | Vendor report, IOCs in linked file | Yes | Medium | No |
| Onion leak and negotiation sites (3AM, APT73, Black Basta x2, Cactus, Cuba, DoNex, RansomHub, Akira x2) | Actor infrastructure | **Not visited by policy** (no engagement, no Tor) | None here (Phase 5 collectors have their own rules) | Phase 5 |

### Can it seed or cross-check our actor profiles?

**Seed: no.**
- There is no licence, so nothing can be copied in.
- No technique row has a source, so under our "rigor on every claim" rule each row would carry the repo as its only
  source, at the lowest reliability.
- Its alias claims (Akira = Storm-1567 / GOLD SAHARA / PUNK SPIDER; Black Basta = Cardinal / Storm-1811 / UNC4393)
  have no source. They would sit as single-source "reported alias" entries at best, and MISP galaxy already covers
  the main ones.
- ransomware.live republishes this content, so it must not count as independent corroboration of ransomware.live
  (or the reverse).

**Cross-check: yes, as a hint only.**
- **Gap finder:** fetch the group's TTP file at runtime (raw URL, cached, never committed) and diff its IDs against
  our sourced technique list (ATT&CK group/software "uses", CISA #StopRansomware tables, report extractions).
- **Community-only techniques:** IDs present only in crocodyli become a "community-only, unsourced" list the analyst
  can chase. They never enter the profile's technique set or any overlap score until a sourced document confirms
  them.
- **Group list check:** the repo's group list (Tengu, Sinobi, CoinbaseCartel, 0apt, Devman, and others) is a quick
  check for groups our RansomLook and MISP list lacks.

---

## 2. curated-intel/Attribution-to-IP

### Description

"A collection of methods to learn who the owner of an IP address is." The announcing blog post (curatedintel.org,
2025-05) and the README frame it for **victim notification** (the IP was victimised, is compromised, or is
misconfigured) and **bug bounty** work. It does **not** discuss attributing an IP to a threat actor. The post
explicitly frames a Tor, VPN, or proxy hit as a limit on identifying the owner.

### Format, licence, maintenance

- **Format:** one README.md (the only file). It has two Markdown tables, "OSINT & Freemium Services"
  (18 methods: method | description | sources) and "Commercial" (3 methods), plus "Additional Resources"
  (3 links) and credits (Team Cymru staff, Curated Intel members).
- **Licence: none** (`license: null`). It may be read and linked; its text must not be copied.
- **Maintenance:** created 2025-05-17, 61 commits (most on 2025-05-18, then community PRs), last push 2025-09-29.
  250 stars, 32 forks, 1 open issue. It has been idle for about 13 months, and it already has dead links
  (BGPView, dan.me.uk Tor list).

### What it says about attributing infrastructure

The 18 methods are passive DNS, domain DNS records (PTR/MX/TXT), IP WHOIS, open ports and banners, X.509
certificates, ASN, geolocation, BGP, content archives, manual browsing, dorking, code repositories, Tor/VPN/proxy
lists, cloud storage buckets, IP behaviour (honeypots, crowdsourced reports), security.txt (HTTP and DNS),
crypto-network node lists, and service-provider IP ranges. The commercial methods are NetFlow, breach data, and
"internet scraping databases" (dark web, forum, and paste citations). The caveats it gives are thin: pDNS is
historical; anonymisation networks mean "not an end user"; breach data only "implies" ownership; geolocation is
approximate; no single method is conclusive. **It gives no guidance** on shared hosting, CDN fronting, false
positives, ethics, or law.

### Rules and checks to adopt (Phase 6 and Phase 9)

What is already planned (no action): CDN and cloud range suppression, Tor exits, Spamhaus DROP, MISP warninglists,
recycled-IP interval overlap, two-independent-feature-class rule, pDNS time windows, "default profile identifies the
software, never the operator", and RDAP abuse contact (built in `rdap.py`).

New, to add:

1. **Owner is not operator (Phase 6 grid + Phase 9 evidence classes).** Label ownership fields as what they are:
   *registered holder* (RDAP), *routing origin* (BGP origin AS), *hosting provider* (ASN org), and *operator*
   (unknown unless shown otherwise). Add a stated rule to the infrastructure evidence class: an RDAP holder, ASN,
   hosting provider, or geolocation can never by itself support "same actor". Only operator-specific artefacts
   (unique certificate, config value, registration tuple, tracker ID) count. This is mostly implied today. Write
   it down.
2. **IP-type classification before any pivot (Phase 6 "prior art" step).** Classify the seed first: anonymisation
   (Tor, VPN, residential or commercial proxy); cloud, CDN, or SaaS range; crypto-network node; scanner seen by
   honeypots (GreyNoise, AbuseIPDB, already wired); **likely compromised third party**; or dedicated/unknown. The
   class decides what pivots are offered. New inputs to that step: **crypto node lists** (btcnodes JSON API;
   Ethernodes 403'd) and the **GitHub meta ranges** (api.github.com/meta). Check whether MISP warninglists already
   cover Oracle, GitHub, and Imperva; if not, load the provider feeds directly.
3. **"Likely compromised third party" flag (Phase 6, new).** Evidence includes long-lived legitimate pDNS history,
   a certificate with a real organisation name, archived branding, a security.txt (seen through existing urlscan
   scans, never by probing the host), or an org-assigned netblock rather than a hosting ASN. A host flagged this way
   goes to **hunt/notify**, never to block or attribute, and its owner evidence is excluded from actor overlap
   scoring.
4. **Victim-notification panel (new; Phase 6 case outcome, or Phase 3).** Add "notify" beside the outcome ladder
   (monitor, detect, hunt, block, share). The panel collects the RDAP abuse contact (built), the DNS
   `_security.<domain>` TXT record (dnssecuritytxt.org: `security_contact`, `security_policy`, `security_expires`;
   still a draft), RFC 9116 security.txt from existing scans, and the national CERT. It **drafts nothing and sends
   nothing**; the operator acts by hand.
5. **Ownership at time of activity.** Our pDNS-window rule covers domains. Extend it to routing: **RIPEstat Data
   API** (keyless, non-commercial) gives prefix and origin-AS history, so "who announced this prefix on the date of
   the activity" can be answered. This complements the parked Team Cymru BGP-prefix note.
6. **Geolocation is never origin evidence (Phase 9 gate).** Hosting country and IP geolocation say nothing about
   the actor's origin. Add this as an explicit "not evidence" entry beside "technique overlap alone never suffices".

### Linked items

| Name | What it is | Live? | Value (phase) | Already in roadmap? |
|---|---|---|---|---|
| Pivot Atlas tools (gopivot.ing/tools) | Catalogue of 47 pivot tools; repo korniko98/pivot-atlas, no licence | Yes | High (6) | **Yes** (pivot catalogue model) |
| IOC Vetting Sources (BushidoUK/Open-source-tools-for-CTI) | About 32 IP reputation and info tools; repo has no licence file | Yes | Medium (6 query-template links) | No |
| ThreatFox browse | abuse.ch IOC platform | Browser check page (fetch) | High (1), built | **Yes** |
| ViewDNS.info | DNS and IP lookup tools + paid API | Yes | Low | No |
| VirusTotal | Multi-engine and pDNS | JS shell | High (1, 6), built | **Yes** |
| OTX AlienVault (now LevelBlue) | Pulses, pDNS | Loading shell | High (1, 6), built | **Yes** |
| mnemonic passive DNS | Keyless pDNS | Portal loading shell | High (6) | **Yes** (first pDNS source) |
| DNSlytics | DNS and IP tools | HTTP 403 | Low | No |
| subdomainfinder.c99.nl | Subdomain finder | Yes | Low (3, 7) | No |
| Validin | DNS and host intel | Yes | High (6) | **Yes** (community, manual) |
| Silent Push | DNS and infra intel, Community Edition | Yes | Medium (6) | **Yes** (template links) |
| Driftnet (SecurityScorecard) | Internet scan search + API docs | Shell only | Low-Medium (6 template link) | No |
| SecurityTrails | pDNS, WHOIS history | HTTP 403 | Medium (3, 6) | **Yes** (free tier) |
| Rapid7 Project Sonar (opendata) | Scan datasets | Redirects to sonardata.rapid7.com, access by request | None | **Yes** (noted unusable) |
| CentralOps | Free network tools (whois, dig, traceroute) | Yes | Low | No |
| DNSDumpster | Domain recon, API | Yes | Low (3, 7) | No |
| DomainTools WHOIS | WHOIS lookup | Yes | Low (guided-pivot bands already cited) | Indirect |
| Who.is | WHOIS lookup | Yes | Low | No |
| IPVOID | IP blacklist and whois tools | Yes | Low | No |
| ZoomEye | Internet asset search | Title only | Low-Medium (6 template link) | No |
| SANS ISC ipinfo | IP reports + public API | Yes | Medium (1 keyless enrichment) | Only the Patch Tuesday API (dropped) |
| Shodan | Internet scan search | Yes | High (1, 6), built | **Yes** |
| FOFA | Internet scan search, API + pricing | Yes | Low-Medium (6 template link) | No |
| Censys search | Host and cert search | HTTP 403 | Medium (6) | **Yes** (parked, lookups only) |
| ONYPHE | Internet scan search | Yes | Low-Medium (6 template link) | No |
| Modat Magnify | Infra investigation platform, API | Yes | Low (6 template link) | No |
| ODIN | Scan search incl. exposed buckets, REST API | Yes | Low-Medium (3 buckets, 6) | No |
| Netlas host | Scan search | HTTP 403 | Low-Medium (6) | Mentioned as write-up source |
| crt.sh | CT search | HTTP 502 at check time (intermittent) | High (1, 3, 6), built | **Yes** |
| Certstream (calidog) | CT firehose | Title only | Medium (3) | **Yes** (self-hosted listener parked) |
| Team Cymru IP-to-ASN | ASN and prefix lookup | Yes | Medium (6 prefix) | **Yes** (parked note) |
| IPinfo | Geo, ASN, privacy; IPinfo Lite free | Yes | Medium (1) | **Yes** (Phase 1 expansion list) |
| InfoByIP | IP info | HTTP 403 | None | No |
| IPQS | Fraud and proxy scoring; 1,000 free lookups | Yes | Low (ipapi.is already chosen) | No |
| Cloudflare Radar IP | IP and ASN insight | HTTP 403 | Low | No |
| RIPEstat | Prefix and AS data + Data API (non-commercial) | Yes | **Medium-High (6 routing history)** | **No** |
| MaxMind GeoIP demo | Geo demo | Yes | Low (geo is not attribution) | No |
| BGP Hurricane Electric | BGP toolkit | Yes | Low (manual link) | No |
| bgp.tools | BGP explorer + scripting/API page | Yes | Medium (6 prefix and upstream) | No |
| Qrator Radar | BGP monitoring | Yes | Low | No |
| BGPView | BGP API | **Dead** (DNS does not resolve) | None | Dropped 2026-11-02 |
| cachedview.com | Cached-page viewer | **TLS error** | None | No |
| urlscan.io | URL scans | Yes | High (1, 6), built | **Yes** |
| Wayback Machine | Web archive | **Not fetchable by this tool** (blocked domain) | Medium (6 content history, CDX API) | No |
| WebPageTest | Page performance test | HTTP 403 | None | No |
| Browserling | Remote browser (free plan) | Yes | Low (manual safe browsing) | No |
| ANY.RUN | Sandbox | Title only | Low (paid API) | **Yes** (parked) |
| Google Dork Examples (BushidoUK GoogleDorks.csv) | 42 rows `Target, Search Operator`; repo has no licence | Yes | Low-Medium (4, 7 dork templates; link only) | Dorking yes; this list no |
| GitHub | Code search for hard-coded IPs | Yes | Medium (7: add IP as a selector) | **Yes** (GitHub code search, Phase 7) |
| Bitbucket | Code hosting; no public code search | Yes | None | No |
| TOR Node List (dev.dan.me.uk) | Tor node list | **Dead** (DNS does not resolve) | None; use check.torproject.org | Tor list **yes** |
| Spur context | VPN and proxy attribution | HTTP 429 | Low (no free API) | **Yes** (not integrated) |
| IP2Proxy | Proxy, VPN, Tor detection; LITE DB not shown on page | Yes | Low-Medium (offline gate; licence to verify) | No |
| proxycheck.io lookup | Proxy check; page shows paid plans | Yes | Low | No |
| GrayHatWarfare | Open bucket search | Yes | Medium (3) | **Yes** (Phase 3 mention) |
| GreyNoise viz | Scanner classification | HTTP 403 | High (1), built | **Yes** |
| AbuseIPDB | Abuse reports | HTTP 403 | High (1), built | **Yes** |
| CrowdSec CTI | IP reputation; console shows 30 free queries/week | Yes | Medium (1 enrichment candidate) | **No** |
| Project Honey Pot list | Malicious IP directory, "All rights reserved" | Yes | Low | No |
| MxToolbox DNS lookup | DNS tools | Yes | Low | No |
| securitytxt.org | RFC 9116 security.txt | Yes | Medium (notify panel) | **No** |
| dnssecuritytxt.org | `_security` TXT draft | Yes | Medium (notify panel) | **No** |
| Bitnodes.io | Bitcoin nodes; now redirects to btcnodes.io, JSON API | Yes (302) | Low-Medium (6 IP-type gate) | **No** |
| Ethernodes.org | Ethereum nodes | HTTP 403 | Low | No |
| Cloudflare IPs | ips-v4/ips-v6 text lists | Yes | High (6 suppression) | **Yes** (cloud range feeds) |
| Oracle public_ip_ranges.json | OCI ranges, updated 2026-10-28 | Yes | High (6) | **Yes** (provider feeds, generic) |
| GitHub meta API | GitHub service ranges | Yes | Medium (6 suppression) | **No** (not named) |
| Microsoft Azure service tags | Weekly JSON (v2026.11.09) | Yes | High (6) | **Yes** |
| Microsoft 365 endpoints change feed | M365 endpoint changes | Yes | Medium (6) | Partly (Azure only named) |
| Google Cloud cloud.json | GCP ranges, created 2026-11-11 | Yes | High (6) | **Yes** |
| AWS ip-ranges.json | AWS ranges, created 2026-11-11 | Yes | High (6) | **Yes** |
| Fastly public-ip-list | Fastly ranges | Yes | High (6) | **Yes** |
| Imperva ranges KB | Now on docs-cybersec.thalesgroup.com; page body did not render | Partly (redirect, shell) | Low-Medium (6) | No |
| Akamai origin IP ACL | Origin-ACL CIDRs only, not all Akamai IPs | Yes | Low (incomplete list) | Akamai via warninglists |
| Team Cymru Pure Signal | Commercial netflow and recon | Yes | None (paid) | NetFlow "recorded, not built" |
| SpyCloud | Commercial breach and identity data | Yes | None (paid) | No |
| AmIBreached | Breach data | HTTP 403 | None | No |
| Intelligence X | Leak and dark-web search; 50 lookups/day free | Yes | Medium (3, 7) | **Yes** |
| DeHashed | Breach search (paid) | HTTP 403 | Low (paid adapter slot) | **Yes** |
| SOCRadar | Commercial CTI | HTTP 403 | None | Mentioned (Lazarus example) |
| Hudson Rock | Infostealer intel, free API | Title only | Medium (3, 7) | **Yes** |
| Recorded Future | Commercial CTI | Yes | None | No |
| Anomali ThreatStream | Commercial TIP | Yes | None | No |
| Intel 471 | Commercial underground intel | Yes | None | No |
| Flashpoint | Commercial CTI | Yes | None | No |
| Cyble | Commercial CTI | HTTP 403 | None | No |

### How the toolkit would use it

- **Phase 6:** use the method list as a checklist for the pivot grid's "seed suitability and IP type" step
  (rules 2, 3, 5 above). Add RIPEstat and bgp.tools to the query-template link table, and FOFA, ZoomEye, ONYPHE,
  ODIN, Driftnet, and Netlas as link-only engines (no keys, no calls). Add the GitHub meta and M365 feeds to the
  suppression lists if warninglists lack them. Add a "notify" outcome.
- **Phase 9:** add "owner/hoster/geolocation is not actor evidence" to the evidence-class definitions.
- **Phase 1 (optional):** CrowdSec CTI and SANS ISC IP API are keyless or free reputation sources not yet listed.
  Both duplicate GreyNoise and AbuseIPDB in part. Low priority.
- The README itself is linked from the in-app Phase 10 docs. It is not copied (no licence).

---

## 3. curated-intel/Threat-Actor-Profile-Guide

### Description, format, licence, maintenance

- **Files (tree, complete):** README.md (331 B: title, image, PDF link); `The Threat Actor Profile  Guide for CTI
  Analysts.txt` (6 KB; note the double space in the filename, which makes the obvious raw URL 404); `... .pdf`
  (v1.0, 360 KB); `... v1.1.pdf` (362 KB, "Additional Edits by @SteveD3").
- **Author:** BushidoToken (Curated Intelligence). All 14 commits were made on 2023-07-13 and 2023-07-15. **Not
  maintained since.** 122 stars, 14 forks.
- **Licence: none** in the repo or the documents. Use the ideas only; do not copy the text or template.
- The **.txt (v1.0) was read in full.** The v1.1 PDF could not be read as text: its text streams are compressed, and
  WebFetch saved a binary copy (see "Not checked"). v1.1's commit note says only "additional edits". It is assumed to
  have the same structure, but this is **not verified**.

### Recommended profile sections (v1.0 text)

1. **Foreword:** a profile is created after an incident (internal detection, supply-chain breach) or when research
   shows the organisation or its clients are likely targets. The guide is aimed at newer analysts.
2. **Executive Summary:** opens "As of <Month Year>, the CTI team has researched <Actor>". It is 10-15 lines in 2-3
   paragraphs and answers *What? So what? What now?* It must state early whether the actor targeted our sector,
   country, or region; why we could be or were targeted; and how well our defences mitigate it. It is tailored to
   the audience: leadership (potential losses: IP, customer data, money; impact on investments) vs operations
   (SOC, CERT, engineering, awareness: TTPs, CVEs prevalent in our estate).
3. **About <Actor>:** an **alias table** of vendor cryptonyms, the "analytical foundation". An optional
   **attribution diagram**. A link to Curated Intel's naming-schemes post. Intro questions: actor type
   (crime, espionage, hacktivism), specialisation, campaign types, **how advanced and why (reasons X, Y, Z)**,
   and notable technical observations.
4. **Targets:** sectors with proximity to ours and recency; **what it does after access**; **how long it persists
   (dwell time)**; whether targets are related (**cyber-enablement**, for example hitting providers to reach
   downstream victims).
5. **Diamond Model attributes:** Adversary (origin, motivation, activity); Victim (targeting, locations,
   **systems**); Capabilities (IN, THROUGH, OUT); Infrastructure (**attack vs support**). These feed a Diamond
   diagram that supports the introduction.
6. **TTPs:** a summary by Unified Kill Chain **IN / THROUGH / OUT**, then an ATT&CK table with columns
   **ATT&CK ID | Description | Observable | Source**. It serves engineering (detections), red team (emulation),
   and SOC (triage).
7. **References:** in-line citations; evaluate and flag problematic sources; add a **footnote on the actor card
   where attribution or technical contention exists**, only when readers need it.

It does **not** mention the Admiralty scale, confidence levels, likelihood language, TLP, or ATT&CK versioning. On
those, our plan goes beyond it.

### Comparison with our Phase 9 profile layout: what we lack

| Guide element | Our Phase 9 plan | Gap |
|---|---|---|
| Profile trigger (incident, or research shows we are a target) | Proximity tag (direct, industry, opportunistic), priority set | **Minor:** a "why this profile exists" field (trigger: incident, PIR, research, request) linked to the case or PIR |
| Dated executive summary, What / So what / What now | Short description paragraph (analyst-written or quoted) | **Lacking:** a structured, dated summary block with three prompts and an "as of" date tied to "last reviewed" |
| "Have they targeted our sector, country, region?" stated early | Proximity tag + victims tab | **Lacking:** a computed "relevance to us" line from operator profile vs actor targeting (deterministic), shown in the header |
| "How well do our defences mitigate?" | Detection-coverage gap on Defend tab; control coverage mapping | **Lacking:** a one-line **posture verdict** in the summary (for example "covers 41 of 63 sourced techniques; 6 rare techniques uncovered"), rule-generated like our verdict lines |
| Audience tailoring (leadership vs operations) | Report builder (Phase 9), CTI Blueprints export | **Lacking:** two export views: leadership (impact and loss categories, no TTP tables) and operations (TTPs, CVEs in our stack, rules) |
| Alias table | Alias claims with source, reported vs confirmed | Covered and stronger |
| Attribution diagram (optional) | Cluster split, claims model; Cytoscape vendored | **Lacking:** a rendered **alias/overlap graph** (vendor names as nodes, claim edges labelled with source and date) |
| Naming-scheme reference | MISP producer.json for name-attribution | **Optional:** a name-pattern hint (UNC####, TA###, Storm-####, DEV-####, Hive####, ITG##, element and animal schemes) to guess the producer of an unattributed alias; label it a hint |
| Actor type, specialisation, campaign types | Archetype, motivation, intent, capability ratings | **Lacking:** a **Campaigns** list on the profile (ATT&CK campaign objects are ingested for comparison but have no profile section) |
| "How advanced, reasons X, Y, Z" | Capability rating with a reason | Covered |
| Targets: sectors, recency | Targeting block, victims tab, last activity | Covered |
| What it does after access (objectives) | Implicit in techniques | **Lacking:** an **objectives/impact** field (extortion, espionage collection, destruction, resale of access) |
| Dwell time | Not planned | **Lacking:** a **dwell time** field (reported range, with source) |
| Related targets / cyber-enablement | Not planned | **Lacking:** an **enablement flag** on victim records (MSP, telecom, software vendor as stepping stone) and a "downstream" relation |
| Diamond Model card | Data exists across header and tabs | **Lacking:** a **Diamond card/diagram** assembled from existing fields |
| Victim "systems" (targeted technologies) | "Operator's stack matches highlighted" on CVEs | **Partly:** a **targeted platforms** list (ESXi, Citrix, Fortinet, Salesforce, Okta...) from CVE products and procedures |
| Infrastructure: attack vs support | Infrastructure tab aggregates hosting, registrars, certs, JARM | **Lacking:** a split between **attack infra** (C2, staging, phishing, leak sites) and **support infra** (registration emails, payment, comms channels such as Tox/Telegram) |
| TTP summary IN / THROUGH / OUT | ATT&CK tactics, matrix view | **Lacking:** a static tactic-to-UKC grouping (Initial foothold / network propagation / action on objectives) for the summary. UKC site is GPL-2.0 (2021); phase names are facts, not copied text |
| TTP table "Observable" column | Technique page has ATT&CK detection strategies and data components; Defend tab "data sources needed" | **Lacking per row on the profile:** an **Observable** column (artefact or log evidence for that procedure: event IDs, file paths, registry keys) |
| TTP "Source" column | Every row carries its source document | Covered |
| Uses: detection, red team emulation, SOC triage | Defend tab, hunting package, Atomic indexes | **Minor:** an "emulation" export (Atomic test IDs per technique) |
| References with in-line citations, flag problematic sources | Rigor on every claim, Admiralty letter | Covered and stronger |
| **Contention footnote** (attribution or technical dispute) | Reported vs confirmed aliases; hypotheses board on cases | **Lacking:** a **"contested" flag + footnote** on the profile header (for example "vendors disagree whether X and Y are one actor") |

**Sources the guide recommends:** only ATT&CK (have), Curated Intel's naming-schemes post (reference), and the
Unified Kill Chain (do not have). Nothing else.

### Linked items

| Name | What it is | Live? | Value (phase) | Already in roadmap? |
|---|---|---|---|---|
| Guide PDF v1.1 (GitHub blob) | The guide | Yes (binary saved by fetcher, unreadable) | Medium (9) | No |
| README image (user-attachments) | Cover image | Signed URL; not fetched | None | No |
| curatedintel.org post 2023-07 (About link) | Announcement; no extra content, no author named | Yes | Low | No |
| Curated Intel: Threat group naming schemes (2022-05) | Vendor naming schemes (Mandiant APT/FIN/UNC, Proofpoint TA, Symantec insects, Recorded Future colour+letter, IBM ITG/Hive, Microsoft elements (pre-2023), Secureworks colour+element, Dragos minerals, CrowdStrike animals); argues against adopting other vendors' names; overlaps rarely one-to-one | Yes | Medium (9 alias UX, name-pattern hint) | No (MISP producer.json is the data) |
| unifiedkillchain.com/assets/The-Unified-KillChain.pdf (as linked in guide) | UKC white paper | **Dead: 404** (moved) | | |
| unifiedkillchain.com (home) and /assets/The-Unified-Kill-Chain.pdf (current) | UKC by Paul Pols; site says GPL v2 (2021) | Yes (1.7 MB PDF; binary saved by fetcher) | Medium (9 summary grouping) | **No** |
| attack.mitre.org | ATT&CK; current v20.1 (2026-10-13), previous v19.2 (2026-04-28) | Yes | High (2, 9) | **Yes** |

Second-hop links on the naming post (Check Point "Twisted Panda", CrowdStrike GTR 2022, Caltagirone SANS talk on
YouTube, two tweets) were recorded but not opened. They are outside the three repos.

### How the toolkit would use it

Ideas only (no licence). It adds the items in the gap table to the Phase 9 profile layout, mostly as fields and
rule-generated lines built from data we already plan to hold. It is a good checklist for the Phase 9 report builder's
"actor profile" template and for the Phase 10 how-to page on writing profiles.

---

## Ranked recommendations

1. **(Phase 9, High) Record source lineage in the source registry.** Add a "derived from / republishes" field and
   enforce the existing "sources that cite each other count as one" rule automatically. First entry:
   ransomware.live TTP matrix and group background are derived from crocodyli/ThreatActors-TTPs. Without this, the
   same unsourced table counts twice.
2. **(Phase 9, High) ATT&CK ID validation on every imported technique.** Check against the local ATT&CK bundle:
   flag revoked and deprecated IDs and remap via `revoked-by` (T1064, T1089), reject non-existent IDs (T1005.002),
   flag ID and name mismatches (T1105 "Input Capture") and tactic IDs in technique fields. Show the count of fixes on
   the import. The same check belongs in the Phase 2 TTP-table extractor.
3. **(Phase 6 + 9, High) Write down "owner, hoster, and geolocation are not operator evidence"** in the evidence-class
   definitions, and label the grid fields (registered holder, routing origin, hosting provider, operator).
4. **(Phase 6, High) IP-type classification step before pivots**, including a **"likely compromised third party"**
   class that routes to hunt/notify and is excluded from actor overlap scoring.
5. **(Phase 9, Medium-High) Profile layout additions from the guide.** These are: a dated executive summary
   (What / So what / What now); a rule-generated "relevance to us" line and posture verdict; objectives; dwell time;
   a cyber-enablement flag; a campaigns list; attack vs support infrastructure; targeted platforms; a contention
   flag; an Observable column; and two export views (leadership vs operations).
6. **(Phase 6, Medium) Victim-notification outcome**, alongside monitor, detect, hunt, block, and share. It shows the
   RDAP abuse contact (built), the DNS `_security` TXT, security.txt from existing scans, and the national CERT. It
   never sends anything.
7. **(Phase 6, Medium) RIPEstat Data API** for prefix and origin-AS history ("who announced it on that date"), plus
   bgp.tools as a link. Keyless, non-commercial terms: register in the source registry before use.
8. **(Phase 9, Medium) crocodyli as a runtime-fetched cross-check, never a seed.** Show "community-only, unsourced"
   techniques for ransomware groups as hints, excluded from scores. Register it at the lowest reliability. Never
   commit its files, and do not use them as test fixtures. Build synthetic fixtures in the same messy table shape
   (blank tactic cells, deprecated IDs, mixed languages) for the Phase 2 extractor.
9. **(Phase 9, Medium) Diamond card and IN / THROUGH / OUT summary** assembled from existing fields, plus the
   alias/overlap graph in Cytoscape.
10. **(Phase 6, Low-Medium) Extra suppression and gate feeds:** GitHub meta ranges, M365 endpoints, Imperva ranges
    (check warninglists coverage first), and btcnodes JSON for crypto-node IPs.
11. **(Phase 6/7, Low) Link-only additions:** FOFA, ZoomEye, ONYPHE, ODIN, Driftnet, and Netlas query-template links;
    BushidoUK IOC-vetting list and GoogleDorks.csv as linked references (no licence: link, do not copy); and IP
    addresses as a selector for the Phase 7 GitHub code search.
12. **(Phase 1, Low) Optional reputation sources:** CrowdSec CTI (free quota) and the SANS ISC IP API (keyless). They
    largely duplicate GreyNoise and AbuseIPDB.

What is **not** recommended: copying any text or table from the three repos (none has a licence); counting crocodyli
or ransomware.live TTPs as independent corroboration; using IP geolocation or hosting country as actor-origin
evidence; any commercial service on the Attribution-to-IP list (all paid, or out of scope like NetFlow).

## Links not checked, and why

- **Refused by a safety safeguard (not retried by another route):** github.com/optiv/Freeze; YouTube
  watch?v=Qq2HbvMqjNY (and its youtu.be short link).
- **Onion addresses (policy: no Tor, no engagement):** the 3AM, APT73, Black Basta (2), Cactus, Cuba, DoNex, and
  RansomHub leak and negotiation sites, and the two Akira portals (the fetcher's summary omitted those two
  addresses).
- **PDFs not opened, to avoid downloading binaries:** SecurityScorecard Cactus whitepaper, IC3 211203-2.pdf, Profero
  Cuba PDF, HHS HC3 Rhysida alert, and the guide's v1.0 PDF. Two PDFs **were saved automatically by WebFetch** when
  fetched to read them: the guide v1.1 PDF
  (`<session folder>/tool-results/webfetch-1794439000025-a25drb.bin`)
  and the UKC white paper (`...\tool-results\webfetch-1794439554156-lpuf2v.pdf`). Neither was opened or run. They can
  be deleted.
- **x.com returned HTTP 402:** @crocodylii profile, DailyDarkWeb status 1684488806240509953, crocodylii status
  1781290861680038183.
- **HTTP 403 / 429 / blocked (exist, content not verified):** Kroll Cactus, SOCRadar Cactus, SOCRadar home, Medium
  (both posts), DNSlytics, SecurityTrails, Censys search, Netlas, InfoByIP, Cloudflare Radar, WebPageTest, GreyNoise
  viz, AbuseIPDB, Ethernodes, AmIBreached, DeHashed, Cyble home, Spur (429), and FOFA "VanHelsing Chat" (rate limit).
  web.archive.org cannot be fetched by this tool.
- **Rendered only a JavaScript shell or title:** VirusTotal (all GUI links), OTX, mnemonic portal, ZoomEye, ANY.RUN,
  Hudson Rock, Driftnet, Certstream, and the Thales/Imperva KB.
- **Dead or moved:** BGPView (DNS), dan.me.uk Tor list (DNS), explore.avertium.com (DNS), cachedview.com (TLS error),
  BlackBerry Cuba post and Mandiant UNC2596 post (redirect to generic pages), UKC PDF URL as written in the guide
  (404), crt.sh (502 at check time, likely transient).
- **Non-HTTP:** rwhois://rwhois.cogentco.com:4321.
- **Images:** about 60 GitHub user-attachment images, spot-checked (302 to S3 PNG); not opened individually.
- **Second-hop links** on the Curated Intel naming-schemes post and blog sidebars: recorded, not opened.
