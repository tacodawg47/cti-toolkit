# BushidoUK repositories: ransomware and APT resources

Research date: 2026-11-11. Read-only web research (WebFetch, one WebSearch).
Repository metadata came from the public GitHub API (keyless) and raw.githubusercontent.com.
Roadmap checks were done by grepping ROADMAP.md.

Value scale: High / Medium / Low / None, with the toolkit phase it serves.

---

## 1. Ransomware Vulnerability Matrix (RVM)

https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix

### Description
This is an OSINT-sourced list of CVEs that ransomware gangs, affiliates, initial access brokers and suspected
state actors have exploited, with a public report cited for each entry. Its stated audiences are CTI analysts,
vulnerability management teams prioritising patches, and DFIR teams. It started from the 2021
BleepingComputer/Allan Liska list and is the sibling of the Ransomware Tool Matrix.
Repo description: "A collection of CVEs weaponized by ransomware operators".

### Roadmap status
**Already planned.** Phase 2 view 9 ("Ransomware-linked") names it as the third source (ROADMAP.md lines 459-462; the
view's note in `views.py` line 394 says "joins later"). View 8 ("Edge and perimeter") seeds its product list from the
RVM categories (line 455-458). Phase 9 datasets list it (line 1992).

### Repo facts
| Item | Value |
|---|---|
| Created | 2024-10-24 |
| Last push | 2026-08-30 ("Update Drivers.md", Citrix/DragonForce additions) |
| Commits | 208 |
| Stars / forks | 156 / 20 |
| Releases | none |
| Licence | CC BY 4.0. The LICENSE file was added 2026-06-21 and reads "Copyright (c) 2025 BushidoUK". It is a short notice linking to the legal code, not the full text, so the GitHub API reports `license: other` rather than `cc-by-4.0`. The README also states CC BY 4.0. |
| Files | `README.md`, `HowToContribute.md`, `LICENSE`, `Vulnerabilities/` (8 files), `GroupProfiles/` (12 files) |

### Update cadence (visible commit history)
Updates come in bursts on a few days, with long gaps between them:
- 2026-05-06 to 05-09: RMM_Tools.md created, WarLock profile, Applications/FTS edits
- 2026-05-25: ~16 commits (TheGentlemen, DragonForce, NetworkEdge, Microsoft)
- 2026-06-21: licence added
- 2026-06-28: 11 commits (Drivers.md created, Qilin profile, NetworkEdge, Applications)
- 2026-08-30: 3 commits (Citrix CVE-2025-5777 / DragonForce, Drivers)
- No commits from 2026-08-30 to 2026-11-11.

Roughly 5 to 15 commits a month in active months, then silent months. Polling once a week is more than enough.

### Data format (all Markdown, no CSV/JSON)
Every data table in every file has the same 4-column header:

```
| Product | CVE(s) | Ransomware Group(s) | Source(s) |
|---|---|---|---|
```

The structure is: an `## Category` heading, then a `### \`Vendor\`` heading in backticks, then one table per vendor.
**The vendor appears only in the H3 heading**, so the parser must carry it down to the rows below.

| File (raw URL under `https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/`) | Category | Vendors (H3) | Rows | CVE IDs |
|---|---|---|---|---|
| `Vulnerabilities/NetworkEdge.md` | Network Edge (VPN, firewall, router, switch, load balancer, gateway) | Pulse Secure/Ivanti, Fortinet, F5, Palo Alto Networks, Sophos, SonicWall, Cisco, Check Point, WatchGuard, Zyxel | 38 | 42 |
| `Vulnerabilities/Microsoft.md` | Microsoft (H3 "Windows" 23 rows, "MS Server Products" 10 rows) | Windows, MS Server | 33 | 42 |
| `Vulnerabilities/Linux.md` | Linux (System Utilities) | (Polkit pkexec) | 1 | 1 |
| `Vulnerabilities/Applications.md` | Applications | Adobe, Apache, Atlassian, CyberPanel, Java Applications, Jenkins, JetBrains, Mitel, Oracle, PHP, SAP, Sitecore, SmarterTools, SolarWinds, SysAid, Telnet, Qlik, QNAP, Veeam, Veritas, Zoho, Zimbra (22) | 43 | 46 |
| `Vulnerabilities/Virtualization.md` | Virtualization | Citrix (7), VMware (6) | 13 | 13 |
| `Vulnerabilities/FileTransferServers.md` | File Transfer Servers | Accellion, CentreStack, Cleo, CrushFTP, Fortra, IBM, Progress Software, PaperCut, SolarWinds | 10 | 14 |
| `Vulnerabilities/RMM_Tools.md` | RMM Tools | ConnectWise, Kaseya, SimpleHelp | 3 | 5 |
| `Vulnerabilities/Drivers.md` | Drivers (BYOVD) | (Zemana AntiLogger, GIGABYTE gdrv.sys) | 2 | 2 |
| **Total** | 8 categories | ~50 vendors | **143** | **~165 mentions** (distinct count to be confirmed at parse time) |

Group profiles (`GroupProfiles/*.md`, 12 files): Akira, BlackBasta, BlackCat, Clop, DragonForce, LockBit,
PioneerKitten, ProphetSpider, Qilin, RansomHub, TheGentlemen, WarLock. Each profile has an H1 title, a `[!NOTE]`, the
same 4-column tables split by vendor H3, and then a `#### Sources` table `| Date | Report |`. **This Sources table is
the only place in the RVM that has dates.** Example: Qilin.md has 12 CVE rows and 6 dated sources.

Example rows (verbatim):
```
| WatchGuard Fireware OS | CVE-2025-9242 | Qilin | [ctrlaltintel.com](https://ctrlaltintel.com/research/Qilin/) |
| vSphere Client | CVE-2021-21972 | BlackCat, Akira | [crowdstrike.com](https://...) / [qualys.com](https://...) |
```

### How it maps CVEs to groups
Each row links one product, one or more CVEs, and one or more actors, and cites one or more public reports. There
are no dates, confidence levels, or roles beyond the name markers. Cell conventions a parser must handle:

- **CVE cell**: separators are `, `, ` & ` and ` and `. Aliases appear in parentheses: `("Pwnkit")`,
  `("Follina")`, `Log4Shell`. **The FileTransferServers PaperCut row uses en dashes (`CVE-2023–27350`)**, so
  normalise `[–—]` to `-`. Some cells have trailing spaces or no space before the pipe.
- **Group cell**: names are separated by `, `. Markers (defined in the README):
  - trailing `*` = affiliate (Storm-0501*, FIN7*, CosmicBeetle*)
  - leading `*` = initial access broker (*Prophet Spider)
  - trailing `+` = suspected state-sponsored (Pioneer Kitten+, Nemesis Kitten+)

  Aliases appear in parentheses (`Storm-2603 (Warlock)`), `Ghost/Cring` is one name, and case varies
  (`Bianlian` vs `BianLian`).
- **Source cell**: Markdown links `[label](url)` separated by ` / `. The label is usually the domain, but labels can
  be wrong (`sophos.co` points to sophos.com) or be handles (`@msftsecintel`, `CuratedIntel` on x.com). **Use the URL
  host, not the label.**
- **Anomalies**: an extra trailing pipe on the Citrix CVE-2023-4966 row (an empty 5th cell); the SimpleHelp row cites
  CISA AA23-352A for 2024 CVEs (possibly a citation mismatch); the FTS row count in the headings looks off by one.

Source domains are mostly vendor research (Microsoft, CrowdStrike, Sophos, Trend Micro, SentinelOne, Talos,
Mandiant/Google, Huntress, Check Point, Arctic Wolf, The DFIR Report), plus CISA/IC3, BleepingComputer and some
LinkedIn/X posts. A frequent recent source is ctrlaltintel.com (checked: live, a 2026-05-01 Qilin affiliate report
built from an exposed attacker open directory).

**Coverage note.** CISA AA24-109A (Akira, revised 2025-11-13) lists CVE-2020-3580 (Cisco ASA). The RVM's Cisco rows
list only CVE-2023-20269 and CVE-2020-3259. So the RVM adds to the ransomware.live and KEV data but is not complete.

### Vendors/products columns
There is **no vendor column**. The vendor comes from the H3 heading, the product from column 1, and the category from
the file name. Product names are free text ("FortiOS & FortiProxy", "NetScaler ADC & Gateway & SD-WAN",
"Exchange On-Prem"), so they are not CPE and not the same strings as KEV's `vendorProject` / `product`.

### How it joins our CVE tables
- **Key**: `cve_id`, after normalisation (uppercase, en dash to hyphen, split multi-CVE cells). It joins to `cves`,
  `kev`, `epss` and the rest directly.
- **Today**: `ransomware_cves(cve_id, grp, first_seen)` in `store.py` has no source column. View 9 uses
  `RANSOMWARE_IDS = SELECT cve_id FROM kev WHERE ransomware=1 UNION SELECT cve_id FROM ransomware_cves`.
- **Proposed**: a separate table so each source keeps its provenance, for example
  `rvm_cves(cve_id, grp, grp_raw, actor_role [gang|affiliate|iab|state], category, vendor, product, aliases,
  source_urls_json, profile_dates_json, first_seen, fetched_at)` with PK `(cve_id, grp)`. Add
  `UNION SELECT cve_id FROM rvm_cves` to `RANSOMWARE_IDS`. Priority logic can treat an RVM row like a
  ransomware.live group link (in-the-wild, cited) with the reason "exploited by X per Ransomware Vulnerability
  Matrix".
- **Group names**: normalise against `ransomware_groups` (ransomware.live names). Lowercase and strip
  non-alphanumerics, then apply a small alias map: BlackCat/ALPHV, Clop/CL0P, PLAY/Play, TheGentlemen/The Gentlemen,
  Storm-2603/Warlock, Ghost/Cring. Keep `grp_raw` for display.
- **Category to view 8**: rows from NetworkEdge, FileTransferServers, RMM_Tools and Virtualization seed the
  edge-and-perimeter vendor/product list. Match on vendor first and use the RVM product string only as a hint.
- **Aliases to the CVE alias table**: the parenthesised nicknames (Pwnkit, Follina, Log4Shell) can seed the
  Watchlist "nickname to CVE" table (ROADMAP line 300).

### Machine-readable fetch
There is no CSV/JSON, so the Markdown has to be parsed. Fetch these 8 raw files on a schedule (weekly is enough).
Profiles are optional and only add dates:
```
https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/Vulnerabilities/NetworkEdge.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/Vulnerabilities/Microsoft.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/Vulnerabilities/Linux.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/Vulnerabilities/Applications.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/Vulnerabilities/Virtualization.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/Vulnerabilities/FileTransferServers.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/Vulnerabilities/RMM_Tools.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/Vulnerabilities/Drivers.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/GroupProfiles/<Name>.md
```
For a cheap change check, call `https://api.github.com/repos/BushidoUK/Ransomware-Vulnerability-Matrix/commits?per_page=1`
(keyless, 60 calls an hour) or send a conditional GET with ETag to raw.githubusercontent.com. The file list can
change: RMM_Tools.md and Drivers.md were added in 2026. List the folder with
`https://api.github.com/repos/BushidoUK/Ransomware-Vulnerability-Matrix/contents/Vulnerabilities` rather than
hard-coding the names.

**Attribution (CC BY 4.0)**: wherever RVM rows are shown (view 9 note, CVE detail page, Feeds tab), add a line like
"Ransomware Vulnerability Matrix by BushidoUK, CC BY 4.0, <link>; parsed and normalised". Committing a parsed snapshot
as a test fixture is allowed under CC BY if the fixture keeps the attribution.

### Linked items (README)
| Name | What it is | Live / maintained | Value (phase) | In roadmap? |
|---|---|---|---|---|
| BleepingComputer 2021 article | Origin story: Allan Liska / Pancak3 crowd list (2021-09-18), an image diagram of ~21 CVEs, tweets as sources | Live, archival, not maintained | Low (background, Phase 10 docs) | No |
| Ransomware Tool Matrix | Sibling repo (section 2) | Live, maintained | High (8/9) | Yes |
| Vulnerabilities/*.md (8 links) | Data files above | Live, last edit 2026-08-30 | High (2) | Yes |
| GroupProfiles/ | 12 per-group CVE profiles with dated sources | Live | Medium (2, 9) | Implied |
| HowToContribute.md | Rules: vendor, product, CVE(s), actor, public evidence; reviewers judge evidence; no links, template has a typo "htttps" | Live | Low (evidence standard is useful to quote) | No |
| ransomware.live/vulns | ransomware.live page listing 126 CVEs grouped by vendor and by actor, with the same column layout and per-row sources. It does **not** credit the RVM. The newest reference is from 2026-10, so it may be ahead of the RVM. Footer says "All rights reserved". | Live, updated 2026-11-11 | Medium (2): cross-check. The toolkit already uses ransomware.live PRO group profiles. Whether the PRO API exposes `/vulns` is unconfirmed (the API page lists v2 and PRO docs but no endpoint detail). | ransomware.live yes; this page no |
| creativecommons.org/licenses/by/4.0 | Licence deed: credit creator, licence link, indicate changes, no endorsement | Live | n/a | Yes (licence noted) |

---

## 2. Ransomware Tool Matrix (RTM)

https://github.com/BushidoUK/Ransomware-Tool-Matrix

### Description
This repo lists the tools (mostly legitimate or dual-use) that each ransomware gang, affiliate, IAB or state actor
has used, from public reporting. It is meant for threat hunting, IR leads, spotting affiliate overlap, and purple-team
emulation. The README warns that many of these tools are used legitimately by IT staff. Custom malware (DarkGate,
RedLine) is excluded by its contribution rules.

### Roadmap status
**Already planned.** Phase 9 seeds the commodity-tool stop-list from the RTM "most used" list (line 1913), the
datasets list includes the RTM (line 1992), and the build order has a "tool matrix" step (line 1999).

### Repo facts
| Item | Value |
|---|---|
| Created | 2024-08-12 |
| Last push | 2026-08-29 ("Update Exfiltration.md") |
| Commits | 901 |
| Stars / forks | 1,467 / 161 |
| Licence | CC BY 4.0 (LICENSE created 2026-06-21; GitHub API reports `other`). Topics include threat-hunting and detection-engineering. |
| Files (64 paths) | `README.md`, `HowToContribute.md`, `LICENSE`, `RTM_ThreatHunt_Checklist.csv`, `Tools/` (8 category .md + `MostUsedTools.md` + `AllTools.csv`), `ThreatIntel/` (4 .md), `GroupProfiles/` (17 .md), `CommunityReports/` (24 reports + template) |

### Update cadence
Bursty. On 2026-05-25 there were ~15 commits in 2.5 hours (DragonForce, TheGentlemen). There were 2 commits in June
(licence), 4 in July (community report CR-024 via PR #47), and 1 in August. There have been none since 2026-08-29.
Weekly polling is plenty.

### Data format
**Category files** `Tools/<Category>.md` use a 2-column table: `| Tool Name | Threat Group Usage |`. Groups are
comma-separated and use the same markers as the RVM (trailing `*` affiliate, leading `*` IAB, trailing `+` state).
Each file has `[!TIP]`/`[!IMPORTANT]` callouts. There are no source links per row, no dates and no ATT&CK IDs.

| File | Tool rows | Distinct groups (approx., as written) | Notes |
|---|---|---|---|
| `Tools/RMM-Tools.md` | 50 | 43 | AnyDesk, Atera, ScreenConnect, Splashtop, TeamViewer, etc. Some groups repeat within a row |
| `Tools/Exfiltration.md` | 34 | 57 | RClone, MEGA, WinSCP, defanged hosts (`Temp[.]sh`, `Gofile[.]io`) |
| `Tools/CredentialTheft.md` | 51 | 52 | Mimikatz, LaZagne, many NirSoft tools, Veeam-Get-Creds |
| `Tools/DefenseEvasion.md` | 49 | 40 | Many `(BYOVD)` drivers, EDR killers, GMER, PCHunter |
| `Tools/Networking.md` | 38 | 29 | Tunnels/proxies: Chisel, Cloudflared, Ngrok, Ligolo, Tailscale. One row has "Proxifier" in the group column (data error) |
| `Tools/DiscoveryEnum.md` | 56 | 64 | AdFind, Advanced IP Scanner, SoftPerfect NetScan, SharpHound, Shodan/Censys |
| `Tools/Offsec.md` | 50 | 60 | Cobalt Strike, Impacket, Sliver, Brute Ratel, Metasploit, Velociraptor |
| `Tools/LOLBAS.md` | 23 | 54 | PsExec, WMIC, BITSAdmin, ntdsutil, Quick Assist |
| **Total** | **351 tool rows** | ~100+ distinct actors after normalisation | Spelling variants need folding: LockBit/Lockbit, Black Basta/BlackBasta, Medusa/MedusaLocker/Medusa Locker (these may be different families, so do not merge blindly) |

`Tools/MostUsedTools.md` has 5 columns: `Tool Name | Type | Threat Group Usage | MITRE ATT&CK TTPs | Detection Rules`.
It has 12 rows, each a tool used by at least 10 gangs:

| Tool | Groups | ATT&CK link | Detection link |
|---|---|---|---|
| Cobalt Strike | 25 | software S0154 | detection.fyi search |
| Mimikatz | 20 | software S0002 | " |
| PsExec | 17 | software S0029 | " |
| AnyDesk | 16 | technique T1219 | " |
| RClone | 16 | software S1040 | " |
| AdFind | 14 | software S0552 | " |
| SoftPerfect NetScan | 13 | technique T1046 | " |
| Advanced IP Scanner | 12 | technique T1018 | " |
| Splashtop | 11 | technique T1219 | " |
| GMER | 10 | technique T1562.001 | " |
| Atera | 10 | technique T1219 | " |
| MEGA | 10 | technique T1567.002 | " |

`Tools/AllTools.csv`: header `Discovery,RMM Tools,Defense Evasion,Credential Theft,OffSec,Networking,LOLBAS,Exfiltration`.
It has 42 rows and 225 tool names in 8 columns (a wide, ragged layout with no groups). **It is stale.** For example,
it has 42 RMM tools against 50 in the .md, and 24 defence-evasion tools against 49. Do not use it as the main source.

`RTM_ThreatHunt_Checklist.csv`: header
`Tool Name,Date of Hunt,Query Used,Findings?,Rule Coverage?,Blocked?,Analyst Comment,Course of Action,Ticket #`.
It has 9 rows: one placeholder and 8 empty tool rows (Cobalt Strike, Mimikatz, AnyDesk, Rclone, PsExec, SoftPerfect
NetScan, AdFind, MEGA). It is a template.

`GroupProfiles/*.md` (17): Akira, Beast, BianLian, BlackBasta, BlackSuit, DragonForce, EvilCorp, INC_Ransom,
Interlock, PLAY, ProphetSpider, Qilin, SafePay, ScatteredSpider, TheGentlemen, Warlock, Yurei. Each has an H1, a
table in the same 8-column layout as AllTools.csv holding that group's tools, a `[!NOTE]`, and a `#### Sources` table
(`Date Published | Report`). Akira has 23 tools and 2 sources (CISA AA24-109A and a BushidoToken blog post).

`ThreatIntel/*.md` lists the source reports behind the matrix:
| File | Columns | Rows | Links |
|---|---|---|---|
| CISAThreatGroups.md | Date Published, Ransomware/Extortionist, #StopRansomware Report | 29 (2021-05-06 to 2025-07-22) | 31 cisa.gov advisories (typo "10 Nay 2024") |
| TheDFIRReportGroups.md | Most Recent Publication, Ransomware/Extortionist, Report | 18 (2020-04 to 2025-04) | 25 thedfirreport.com |
| TrendMicroThreatGroups.md | Date Published, Ransomware/Extortionist, Report | 6 | 6 Trend Micro "Ransomware Spotlight" pages |
| ExtraThreatIntel.md | Date Published, Ransomware/Extortionist, Report | 113 (2020-07 to 2026-05-15) | 113 links, 47 domains (Trend 10, Microsoft 8, Google Cloud 8, Talos 7, CrowdStrike 7, Sophos 6, ...) |

`CommunityReports/` holds 24 reports (CR-001 to CR-024: Akira x6, RansomHub x4, Qilin x3, DragonForce x3, INC
Ransom x3, PLAY, BlackSuit, CrazyHunter, SpaceB) plus `Community_Report_Template.md`. The template sections are:
Contributor (real name, handle, employer), Adversary, Incident (time, sector, country, size band), Observed Tools
(the 8-column RTM table), an IOCs code block (domains, hashes, IPs, URLs, commands, process trees), Related Sources
(Date, Report), and a Mermaid diagram. There are no ATT&CK fields and no TLP. CR-024 (INC Ransom, July 2026, by a
Ctrl-Alt-Intel researcher) has 1 IP, 3 SHA-256 hashes, host artefacts and command lines. The repo itself says these
reports vary in reliability.

### ATT&CK mapping
**There is none in the main data.** Only MostUsedTools.md links to ATT&CK: 6 tools to software IDs (S0002, S0029,
S0154, S0552, S1040) and 6 to technique IDs. The toolkit can derive a mapping deterministically:
1. Match tool names to ATT&CK software objects (name and `x_mitre_aliases`) from the ATT&CK STIX bundle already
   planned for Phase 9. Software objects already carry technique "uses" relationships.
2. Use the category as a coarse fallback tactic: Discovery to TA0007, Credential Theft to TA0006, Defense Evasion to
   TA0005, Exfiltration to TA0010 / T1567, RMM to T1219, Networking to T1572/T1090. LOLBAS and OffSec have no
   reliable fallback.
3. Label the result "derived mapping, not from source".

### Machine-readable fetch
Parse the Markdown category files (no JSON is provided):
```
https://raw.githubusercontent.com/BushidoUK/Ransomware-Tool-Matrix/main/Tools/{RMM-Tools,Exfiltration,CredentialTheft,DefenseEvasion,Networking,DiscoveryEnum,Offsec,LOLBAS,MostUsedTools}.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Tool-Matrix/main/GroupProfiles/<Name>.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Tool-Matrix/main/ThreatIntel/{CISAThreatGroups,TheDFIRReportGroups,TrendMicroThreatGroups,ExtraThreatIntel}.md
https://raw.githubusercontent.com/BushidoUK/Ransomware-Tool-Matrix/main/Tools/AllTools.csv   (stale; avoid)
```
For change detection, use the same GitHub API `commits?per_page=1` check as for the RVM.

### How the toolkit would use it
- **Phase 9 (planned)**: a `tool_usage(tool, category, grp, grp_raw, actor_role, source='RTM')` table. It feeds the
  stop-list tiers (any tool with at least 10 groups is "commodity"; MostUsedTools gives the seed), the tool-stack
  overlap matrix, and the per-actor "Tools" tab. Join to ATT&CK software by name.
- **Phase 8**: the hunting package per actor. Join RTM RMM names to LOLRMM (Apache-2.0, planned) for domains and
  certificates, `(BYOVD)` rows to LOLDrivers, and LOLBAS.md rows to LOLBAS. Join MostUsedTools to Sigma rules by tag.
- **Phase 9/4 reading list**: the 4 ThreatIntel tables give ~170 dated, group-labelled report URLs. This is a ready
  seed for per-actor "Reporting" lists, and the CISA #StopRansomware links each carry STIX JSON IOC bundles (checked
  on AA24-109A: two STIX JSON downloads). The roadmap already notes that CISA STIX bundles are no shortcut for TTPs
  (line 181). They are still useful for IOCs.
- **Phase 2 IOC extraction**: CommunityReports IOC blocks are plain text. Give them a low default source rating (an
  individual submitter, unverified).
- **Hunt checklist CSV**: Low. It is a template for a Phase 8 "hunt log", an idea at most.

### Linked items (README)
| Name | What it is | Live / maintained | Value (phase) | In roadmap? |
|---|---|---|---|---|
| YouTube hyoOhAoaX1g | BSides London Dec 2024 talk, "Inside The Ransomware Toolbox..." (Will Thomas) | Live (title only seen) | Low (Phase 10 docs) | No |
| Tools/RMM-Tools.md | 50 RMM tools to groups | Live | High (8, 9) | Yes (RTM) |
| Tools/Exfiltration.md | 34 exfil tools/services | Live (edited 2026-08-29) | High (8, 9) | Yes |
| Tools/CredentialTheft.md | 51 tools | Live | High (8, 9) | Yes |
| Tools/DefenseEvasion.md | 49 tools incl. BYOVD | Live | High (8, 9) | Yes |
| Tools/Networking.md | 38 tunnel/proxy tools | Live | High (6, 8, 9): tunnelling tools overlap LOT Tunnels | Yes |
| Tools/DiscoveryEnum.md | 56 tools | Live | High (8, 9) | Yes |
| Tools/Offsec.md | 50 tools | Live | High (8, 9) | Yes |
| Tools/LOLBAS.md | 23 binaries | Live | Medium (8, 9): LOLBAS proper is planned | Yes |
| ThreatIntel/CISAThreatGroups.md | 29 #StopRansomware advisories | Live; last row 2025-07-22 (newer CISA advisories, e.g. AA26-222A Gunra, are missing) | Medium (4, 9) | CISA advisories yes; this list no |
| ThreatIntel/TheDFIRReportGroups.md | 18 groups, 25 DFIR Report links | Live; last row 2025-04 | Medium (4, 9) | DFIR Report yes (line 238) |
| ThreatIntel/TrendMicroThreatGroups.md | 6 Ransomware Spotlight pages | Live; last 2024-11 | Low (9) | No |
| Kaspersky "Common TTPs of the modern ransomware" PDF (go.kaspersky.com) | 2022 report on 8 groups (Conti/Ryuk, Pysa, Clop, Hive, LockBit 2.0, RagnarLocker, BlackByte, BlackCat), ATT&CK-mapped with Sigma rules | **Link dead**: 302 to kaspersky.com homepage. The article is live at securelist.com/modern-ransomware-groups-ttps/106824/ (2022-06-23); the PDF sits behind a form | Low (9, historical) | No |
| Talos Conti playbook translation | 2021-09-02 Talos post on the leaked Conti playbook | Live, archival | Low-Medium (9 procedures, 8 detections) | No |
| Bassterlord "FishEye" networking manual PDF (ecirtam.net autoblog) | A leaked affiliate tradecraft manual, hosted on a third-party autoblog | Loaded (8.6 MB image-only PDF; not read further) | None for ingestion (leaked criminal material, no licence). Mention only. | No |
| ThreatIntel/ExtraThreatIntel.md | 113 dated reports | Live; newest 2026-05-15 | Medium (4, 9) | No |
| Tools/MostUsedTools.md | 12 tools with at least 10 groups, ATT&CK and detection links | Live | High (9 stop-list) | **Yes** (line 1913) |
| GroupProfiles/ | 17 group tool profiles with sources | Live | Medium (9) | Implied |
| Tools/AllTools.csv | Wide CSV, stale | Live, not kept in sync | Low | No |
| RTM_ThreatHunt_Checklist.csv | Empty hunt-log template | Live | Low (8) | No |
| CommunityReports/ | 24 crowd reports with IOCs | Live; CR-024 2026-07 | Medium (2 IOC extraction, 9), low reliability | No |
| HowToContribute.md | Rules: public tools only, no custom malware, public evidence, community report path | Live | Low | No |
| x.com/JMousqueton status | ransomware.live integration announcement (Aug 2024, per README) | **Not checked**: x.com returns HTTP 402 to fetches | Low | ransomware.live yes |
| x.com/ecrime_ch status | eCrime.ch integration announcement | **Not checked**: HTTP 402 | Low | No |
| creativecommons.org BY 4.0 | Licence | Live | n/a | Yes |
| (repo description) blog.bushidotoken.net 2024/08 "The Ransomware Tool Matrix" | Launch post (2024-08-15): method is CISA #StopRansomware, DFIR Report, Conti playbook, Bassterlord manual | Live | Low (docs) | No |
| (MostUsedTools links) attack.mitre.org S0154/S0002/S0029/S0552/S1040, T1046/T1018/T1219/T1562.001/T1567.002 | ATT&CK pages | Live (well known) | n/a (ATT&CK planned) | Yes |
| (MostUsedTools links) detection.fyi/search?query=... | Detection-rule search site | Search page returned only a navigation stub. The root page exceeded the 10 MB fetch limit, and the first attempt was rate-limited. **Content not verified.** | Low (8, link-out) | No |
| (README Integrations) eCrime.ch | Commercial extortion/leak-site monitoring platform, 280+ sources, API, **paid** (Professional USD 2,799/yr) | Live (2026-11-11) | None (paid) | No |

---

## 3. Awesome-Ransomware

https://github.com/BushidoUK/Awesome-Ransomware

### Description, format, licence, cadence
This is a curated link list ("A curated list of Ransomware resources"). The repo holds only `README.md`, with no data
files. **No licence**, so treat it as all rights reserved: link to it, do not copy it. Created 2025-10-28 with 14
commits; last push 2026-05-11 ("Add Ransomware Breach Report Collection link"); 41 stars. Updated a few times a year.
Its value is as a directory of sources. Fetch URL (only if a "sources directory" feature ever wants it):
`https://raw.githubusercontent.com/BushidoUK/Awesome-Ransomware/main/README.md`.

### Linked items
| Name | What it is | Live / maintained | Value (phase) | In roadmap? |
|---|---|---|---|---|
| Ransomware Tool Matrix | Section 2 | Live | High (8, 9) | Yes |
| Ransomware Vulnerability Matrix | Section 1 | Live | High (2) | Yes |
| crocodyli/ThreatActors-TTPs | 39 actor folders, each with `<Actor>-TTP.md`, `CVEs-<Actor>.md`, `Tools-<Actor>.md` and Readme. ATT&CK-mapped prose. 421 stars, last push 2026-01-29, **no licence** | Live, slowing | Medium (2, 9): `CVEs-<Actor>.md` is a possible 4th CVE-to-group source (runtime read only, no copy) | No |
| ThreatLabz/ransomware_notes | Ransom note archive, 100+ family folders, **MIT**, last push 2026-08-13 | Live, maintained | Medium (9 lineage panel) | **Yes** (line 1969) |
| ID Ransomware (malwarehunterteam) | Upload a note or file to identify a family (1,191 families); no API stated | Live (v1.10.1, 2026-11-11) | Low (9 link-out; never upload case files automatically) | No |
| rivitna/Malware | YARA rules and programs (decryptors, config extractors) for ~50 ransomware families, **MIT**, last push 2026-10-17 | Live, maintained | Medium (parking-lot malware corpus: YARA and config parsers inside the VM; Phase 8 YARA reference) | No |
| ID Ransomware blog (Amigo-A) | Russian/English family digest, newest post 2026-11-04 | Live, maintained | Low (9 link-out) | No |
| VirusTotal comments search | VT GUI comment search for "ransomware" | JS app, content not visible to fetch | Low (VT key already used in Phase 1) | VT yes |
| Hatching Triage tag:ransomware | Public sample list (loads without login, ~50 rows a page, live 2026-11-11) | Live | Medium (parking-lot sandbox / Phase 1) | **Yes** (lines 2415, 2435) |
| MalwareBazaar tag:ransomware | Browse page | Bot check shown (not bypassed); the API is the right route | Medium (1, already queried) | **Yes** (Phase 1) |
| ANY.RUN tag:ransomware | Public submissions | JS app, not visible | Low (paid API) | **Yes** (line 2417) |
| RansomwareLive | Leak-site tracker: 33,926 victims, 422 groups; free v2 API (1 req/min/endpoint, personal use) and free PRO key | Live, maintained | High (2, 3) | **Yes** |
| RansomLook | Leak/market/forum tracker: 646 groups, 36,921 posts, Swagger at /doc/, source on GitHub | Live, maintained | High (3, 9) | **Yes** (line 672, 1793) |
| fastfire/deepdarkCTI ransomware_gang.md | ~700 leak-site rows (Name, Status, credentials, contact, RSS). GPL-3.0, pushed 2026-11-11. Onion links not followed | Live, maintained | Medium (3, 5) | **Yes** (lines 1219, 1250) |
| Google Drive DarkTracer victim list (2019-05 to 2021-07) | xlsx of historical leak-site victims | Sign-in wall; not confirmed public | Low (historical) | No |
| thetanz/ransomwatch INDEX.md | Leak-site index (group, title, status, last seen, location); last seen 2025-06-17; **repo archived 2026-03-03**; Unlicense | Live, archived | Low (historical gap-fill) | **Yes** ("ransomwatch archive", line 2793) |
| ransom.wiki | Victim lookup; data "up to 03-april-2024" | Up but stale | None | No |
| BushidoUK Breach-Report-Collection (Ransomware/BreachReports.md) | 17 victim post-incident disclosures (Organization, Breach Date, Adversary, Source), with archive copies; no licence; pushed 2026-09-20 | Live, slow | Low-Medium (9: first-party breach narratives per actor) | No |
| BushidoUK/Ransomware-Leaks | Index of ransomware gang leaks (chats, playbooks); **hosts leaked files in-repo**; no licence | Live | None: do not ingest or mirror leaked criminal material. Analyst reading only | No |
| Ransomwhere (ransomwhe.re) | Crowdsourced ransom payment tracker; `https://api.ransomwhe.re/export` returns all transactions; no licence named; cite Zenodo DOI 10.5281/zenodo.6512122 | Up (no timestamp) | Medium (9 actor wallets; 6 pivot on addresses) | **No** |
| Pulsedive threat tid=437 | Pulsedive "Ransomware" threat page | JS-gated ("unsupported browser") | Low (Pulsedive key planned for Phase 1) | Pulsedive yes |
| Twitter #ransomware search | Live search | **Not checked** (redirects to x.com, HTTP 402) | None | No |
| Twitter list of ransomware researchers | X list | **Not checked** (x.com, HTTP 402) | Low (4, manual) | No |
| OCD ransomware_map | Orange Cyberdefense ecosystem map, 300+ groups, 2015-2026, **PDF only, "All rights reserved"**, v29 2026-01-19 | Live, maintained | Low (9 link-out; nothing machine-readable) | No |
| ransomch.at | Negotiation chat browser (20+ brands); footer links Casualtek/Ransomchats (MIT, pushed 2026-09-21) | Up; counters JS-loaded | Medium via the GitHub repo (9 lineage panel) | **Yes** (Ransomchats, line 1970) |
| CISA StopRansomware newsroom | Advisory and news list; newest is the SafePay joint advisory; email subscription only, no RSS on page | Live | Medium (4 news source) | CISA yes |
| CISA official alerts (CISA) | 49 unique advisories; newest by number AA26-222A (Gunra) | Live | Medium (4, 9) | CISA yes |
| CISA official alerts (FBI) | 55 FBI/joint items to 2025-11-13 (Akira update) | Live | Medium (4, 9) | CISA yes |
| NCSC ransomware search | ncsc.gov.uk search URL | JS-rendered, no results visible | Low (4; NCSC has its own feeds) | Check Phase 4 sources |
| Virtual Routes Ransomware Countermeasures Tracker | ~240+ government actions (arrests, sanctions, takedowns) with fields date, country, operation, category, groups, cooperation, source; newest 2026-09-30; no download, no licence | Live, maintained | Medium (9 actor timeline "law-enforcement events"; link or manual entry only) | **No** |
| No More Ransom | Europol decryptor portal; no machine-readable list | Live | Low (9 link-out "decryptor exists") | No |
| Ransom payment legality (rkovar) | Now redirects to isitlegaltopay.com: interactive map, "data is still coming up"; repo last push 2023-12, no licence | Up, stale | None | No |
| Ransomware Overview Google Sheet | View-only sheet: Prevention tab (21 measures) plus Ransomware/Detection/Sources tabs | Partly loaded (old-browser warning) | Low | No |
| Contacts: linkedin.com/in/william-t, @BushidoToken | Author contact (not hyperlinks) | Not visited | n/a | No |

---

## 4. Malware-Zoo

https://github.com/BushidoUK/Malware-Zoo

### Description, format, licence, cadence
This is a single CSV of SHA-256 hashes of well-known malware and tools ("Hashes of infamous malware"). The README is
the title and that one line. **No licence.** Created 2021-01-23 with 19 commits, all from January 2021 apart from one
on **2023-07-10 (last update)**. 27 stars. It is effectively frozen.

Fetch URL: `https://raw.githubusercontent.com/BushidoUK/Malware-Zoo/main/Need-to-know%20malware.csv`

Format: header `Category,Name,Type,SHA256`, comma-delimited, **64 rows**, SHA-256 only (uppercase hex,
64 characters, no duplicates), no source URLs.
- Category values (12): Infamous 6, ICS 3, Espionage 4, Organised Cybercrime 14 plus "Organized Cybercrime" 2
  (spelling split), Ransomware 12, Crimeware 10, Android 7, MacOS 1, IoT 1, Red Team 3, LOLbin 1.
- Type values (20): Backdoor 8, Banking Trojan 8, Hands-on-Keyboard 7, RAT 7, Infostealer 5, RaaS 5, Loader 4, and so on.
- Names include WannaCry, NotPetya, Stuxnet, Triton, SUNBURST, Emotet, Qakbot, Conti, Ryuk, Mirai, Pegasus, and
  dual-use tools Cobalt Strike, Meterpreter, Mimikatz, **PsExec**.

### Linked items
None (the README has no links).

### Roadmap status
Not in the roadmap (no grep hit for "Malware-Zoo").

### How the toolkit would use it
Low value, Phase 1 test aid only. Read it at runtime as a "known sample" smoke test for hash enrichment. PsExec is a
good check that the known-good-file gate (CIRCL hashlookup) does not raise a false alarm on a signed Sysinternals
binary. Because there is no licence, do not commit the hashes as fixtures; read the file at runtime or pick your own
hashes. It is not a feed: there are no dates or sources, and it was last touched in 2023.

---

## 5. Exploring-APT-campaigns

https://github.com/BushidoUK/Exploring-APT-campaigns

### Description, format, licence, cadence
"Further investigation in to APT campaigns disclosed by private security firms and security agencies." The default
branch is **`master`** (raw `main` URLs 404). **No licence.** Created 2020-09-26; **last push 2022-06-04**; 85
commits, mostly 2021; 89 stars. Abandoned.

Files (13): `README.md` (7.6 KB) and 12 Maltego graph files (`.mtgl`, binary archives, 158-706 KB, ~4 MB in total):
AccellionFTA, Babuk, EvilCorp, FIN7, LazarusHeist, OrganisedCybercrime2.0, ProxyLogon, REvilKaseya, Shathak,
SolarWinds, WizardSpider, statesponsored. They were not fetched, because they are binary files and the rules forbid
downloads.

README structure: an intro with two profile links, then 46 "Virus Total map of ..." links to VirusTotal Graph embeds:
- **Espionage (24)**: Machete, Lazarus/CryptoCore, APT17, Cloud Atlas, APT29 WellMess, APT31, Kimsuky, SilentLibrarian,
  TrickyMouse, SideWinder, MuddyWater, Chimera, Aggah, AZORult JNLP, DPRK Amadey, Sandworm, APT28 Downdelph,
  Gamaredon, UNC2452, APT41/APT10, MustangPanda, IndigoZebra, BlackTech, IronTiger.
- **Crimeware (22)**: Thai Consulate phishing, SolarSpider, FIN7 (x3), Evilnum, WizardSpider Trickbot (x2),
  BazarLoader, BazarCall, ZLoader, Meyhod skimmer, EvilCorp WastedLocker, FIN8 BADHATCH, Cobalt Strike Akamai-themed,
  SocGholish, Android botnets (Oscorp, GINP, Hydra, TeaBot), Aviation RAT, MirrorBlast.

There is no machine-readable data. A scheduled fetch is not applicable.

### Linked items
| Name | What it is | Live / maintained | Value (phase) | In roadmap? |
|---|---|---|---|---|
| otx.alienvault.com/user/BushidoToken/pulses | Author's OTX pulses | Page is a JS app ("Loading...") so not verified by fetch. The OTX API (key on hand) could list `pulses/user/BushidoToken` | Low-Medium (Phase 2 OTX context already folds pulses per CVE) | OTX yes |
| virustotal.com/gui/user/BushidoToken | Author's VT profile | JS app; only the title came back | Low | VT yes |
| 46 x virustotal.com/graph/embed/g... | VT Graph embeds of 2020-2021 campaign IOC graphs | Checked 1 of 46: only the JS shell renders ("Your group graphs results"), with no nodes, owner or date, and access may be account-scoped. The other 45 have the same host and format, so were not fetched one by one (see the not-checked list) | Low (6/9 historical pivots; would cost VT quota via `/api/v3/graphs/{id}`) | No |
| 12 .mtgl Maltego graphs | Historical link charts | Not fetched (binary) | None (needs Maltego; stale) | No |

### How the toolkit would use it
Not as a data source. At most, link it from a Phase 9 actor page as "historical community graph (2021)". Value is Low
to None.

---

## Ranked recommendations

1. **Ingest the RVM in Phase 2 now (High; already planned for view 9).** Parse the 8 `Vulnerabilities/*.md` files
   into a new `rvm_cves` table keyed `(cve_id, grp)` with category, vendor (from H3), product, actor role from the
   markers, and source URLs. Union it into `RANSOMWARE_IDS`, show "Ransomware Vulnerability Matrix (CC BY 4.0)" as
   the reason on the CVE page, and seed view 8's edge list from the NetworkEdge, FileTransferServers, RMM_Tools and
   Virtualization rows. Handle the en-dash CVEs, `&`/`and` separators, `*`/`+` markers and label/URL mismatches.
   Weekly fetch with a GitHub commit check.
2. **Ingest the RTM category files for Phase 9 and Phase 8 (High; planned).** Build a `tool_usage` table from the 8
   category .md files (351 rows), not from the stale AllTools.csv. Seed the stop-list from MostUsedTools (12 tools,
   at least 10 groups each). Derive ATT&CK by name-matching ATT&CK software, with category-to-tactic as a labelled
   fallback. Join to LOLRMM, LOLDrivers and LOLBAS for hunting packages.
3. **Use the RTM ThreatIntel tables as a dated report index (Medium; new).** The tables give ~170 group-labelled
   report URLs (CISA #StopRansomware, DFIR Report, vendor blogs) to seed Phase 9 "Reporting" and the Phase 4 corpus.
   CISA advisories ship STIX JSON IOC bundles, which suit IOC import but not TTPs (roadmap line 181). The CISA list
   stops at 2025-07, so take newer advisories from CISA directly.
4. **Add Ransomwhere's export (Medium; not in the roadmap).** `https://api.ransomwhe.re/export` gives ransom payment
   addresses by family for Phase 9 actor pages and Phase 6 wallet pivots. No licence is named, so read it at runtime,
   do not vendor it, and cite the Zenodo DOI.
5. **Read crocodyli/ThreatActors-TTPs `CVEs-<Actor>.md` at runtime as a fourth CVE-to-group cross-check (Medium-Low;
   not in the roadmap).** It has no licence, so read at runtime and do not copy. Treat it as corroboration only.
6. **Use RVM GroupProfiles and RTM GroupProfiles for dates and per-actor views (Medium).** Their `Sources` tables are
   the only dated evidence in either matrix, so use them to fill `first_seen`-style "reported on" dates.
7. **Add the Virtual Routes Countermeasures Tracker as a Phase 9 link-out (Low-Medium; not in the roadmap).** It has
   no export and no licence, so link to it or enter events by hand (arrests, sanctions, takedowns per group).
8. **Add rivitna/Malware (MIT) to the parking-lot malware corpus notes (Medium; not in the roadmap).** It has YARA
   rules and config/decryptor programs for ~50 ransomware families. Use it only inside the analysis VM.
9. **Low or no value:** Malware-Zoo (frozen 2023, no licence; at most a runtime smoke test), Exploring-APT-campaigns
   (abandoned 2022, JS-only VT graphs and Maltego binaries), OCD ransomware map (PDF, all rights reserved), No More
   Ransom / ID Ransomware (link-outs), ransom.wiki (stale 2024), isitlegaltopay (stale), eCrime.ch (paid).
10. **Do not ingest:** BushidoUK/Ransomware-Leaks (hosts leaked gang material), the Bassterlord manual, and the onion
    links in deepdarkCTI/ransomwatch (read the directories only, as already planned, and never visit them
    automatically).

## Links not checked, or only partly checked, and why
- **x.com / twitter.com (4)**: JMousqueton status 1824434279251665259 and ecrime_ch status 1824469830613021070
  returned HTTP 402. The twitter.com list 1256159047755202560 and the #ransomware search returned 301 to x.com, which
  serves 402 to fetches, so they were not retried.
- **Kaspersky PDF (go.kaspersky.com)**: 302 to the kaspersky.com homepage (a dead link). The replacement Securelist
  article was found by search and checked live. The media.kaspersky.com PDF from the search was not opened (no
  downloads).
- **Bassterlord PDF (ecirtam.net)**: the fetch loaded an 8.6 MB image-only PDF, and **the fetch tool automatically
  saved a copy** to
  `<session folder>/tool-results/webfetch-1794439224189-04zdv4.pdf`.
  That was not intended under the no-download rule. The file is a leaked criminal manual; delete it if it is not
  wanted. After this, no other PDFs were fetched.
- **VirusTotal Graph embeds**: 45 of 46 not fetched individually. One was checked and returned only the JS shell, so
  the others would show nothing either. They can be checked by hand in a browser or via the VT API graphs endpoint
  (uses quota).
- **JS-only pages (content not verifiable by fetch)**: VirusTotal comments search, VT user profile, OTX user pulses,
  ANY.RUN submissions, Pulsedive threat page, NCSC search results, ransomch.at counters, YouTube video (title only).
- **MalwareBazaar browse page**: showed a "not a robot" check, which was not attempted. Use the abuse.ch API instead
  (already in Phase 1).
- **Google Drive DarkTracer xlsx**: sign-in wall. Google Sheet "Ransomware Overview": partly loaded.
- **detection.fyi**: first attempt rate-limited by the fetch safety check. The retry of the search page returned a
  navigation stub only. The root page exceeded the 10 MB fetch limit. What it indexes was not confirmed.
- **eCrime.ch**: first attempt rate-limited, second attempt succeeded.
- **Data-file source links (not README links), spot-checked only**: ~150 per-row source URLs in the RVM tables and
  profiles; 31 CISA, 25 DFIR Report, 6 Trend Micro and 113 ExtraThreatIntel links in the RTM ThreatIntel files;
  source links in 17 RTM and 12 RVM group profiles; 34 links in BreachReports.md. Spot-checked live:
  ctrlaltintel.com/research/Qilin/ and cisa.gov AA24-109A.
- **Exploring-APT-campaigns .mtgl files (12)**: binary Maltego archives, not fetched (no downloads). The GitHub API
  commits call for this repo returned 403 (keyless rate limit), so the HTML commits page was used instead.
- **Onion / leak links** in deepdarkCTI `ransomware_gang.md`, ransomwatch `INDEX.md`, and the "Copy of Leak" links in
  Ransomware-Leaks: deliberately not followed (no engagement with threat actor infrastructure or leaked data).
- **Folder contents not fully enumerated**: ThreatLabz ransomware_notes (listing truncated at 100 folders),
  rivitna/Malware subfolders, crocodyli actor folders (only Akira listed).
- **Author contacts** (linkedin.com/in/william-t, @BushidoToken): not hyperlinks, not visited.
