# Kraven Security "hunting-packages": review for the CTI toolkit

Reviewed 2026-11-11, read-only. Folder:
`<local path> downloads\hunting-packages-main\hunting-packages-main\`
Nothing in the folder was executed, imported or compiled. Text files were
read as data with a stdlib Python script run in isolated mode from the
scratchpad (`scratchpad\scripts\kraven_survey.py`, `kraven_check2.py`).
No web requests were made.

## 1. Licence

- No LICENSE, COPYING or NOTICE file anywhere in the 2,104 files.
- The root README.md (17 lines) states purpose only, with no terms of use.
  `.gitignore` holds one line, `template/`.
- Every package readme links back to
  `github.com/kraven-security/hunting-packages`, so the upstream is a
  public GitHub repository. Whether upstream has added a licence since this
  copy was taken was not checked (no web access in this review).
- Ruling under the project rule: **no licence, so all rights reserved.** The
  toolkit may read it at runtime (from the operator's local copy, or a
  clone fetched at runtime into the git-ignored data folder and registered
  in the source registry) but must not copy its files into the repo.
- Layered rights inside it. Most detection content is copied from third
  parties, each with its own terms:
  - YARA: Elastic Security rules carry `license = "Elastic License v2"` in
    their meta (not open source; read, do not vendor). Sekoia rules carry
    `classification = "TLP:GREEN"`. GTIG/Mandiant, Check Point, Citizen Lab,
    Synacktiv, WithSecure, Rapid7, CrowdStrike, Positive Technologies,
    EclecticIQ, Sysdig, GuidePoint, Darktrace, Arctic Wolf and individual
    researchers have no licence stated in the rule. CISA rules and Sigma are
    US-government work (generally public domain; CISA marks them TLP:CLEAR).
  - Hunting queries: mostly Microsoft Threat Intelligence blog queries,
    plus CISA, Securonix, CrowdStrike and Elastic examples.
  - IOC values are facts; the selection and arrangement is Kraven's.
  So even with a Kraven licence, the detection rules would still need each
  original author's terms. The clean route is always the original vendor
  report or rule repository.

## 2. Structure

```
hunting-packages-main/
  README.md, .gitignore
  threat-hunting-scripts/     config.py, iocs-to-cs.py, verify-iocs-vt.py
  osint-articles/
    template/                 readme.md (998 B) + 5 empty files
    2025/                     240 package folders
    2026/                     321 package folders
```

- 2,104 files, about 3.0 MB. Extensions: 1,472 .txt, 563 .md, 43 .yar,
  14 .kql, 3 .yml, 3 .py, 2 .yara, 1 .json, 1 .rules, 1 with no extension,
  plus .gitignore.
- 561 packages, one folder each, named `YYYY-MM-DD <article title>`. Date
  range 2025-01-02 to 2026-11-03 (23 months; 5 to 46 a month, about 24 on
  average; busiest 2026-08 with 46). The date is Kraven's posting date, not
  the vendor report's date.
- Files per package: 2 (116 packages), 3 (50), 4 (291), 5 (83), 6 (18),
  7 (2), 10 (1).
- Fixed files: `readme.md` (561), `iocs.txt` (559; missing in 2),
  `network-iocs.txt` (372), `endpoint-iocs.txt` (370). Everything else is
  optional and named freely: 61 other file names, with typos
  (`malicious-pacakges.txt`, `chrome-extentions-ids.txt`,
  `malicous-ruby-gems.txt`, `sigma-rules-yml`).

### The shape of a "hunting package"

Template (`osint-articles/template/readme.md`):

```
# {{Article Title}}
{{social post}}
## Package Content
- iocs.txt / endpoint-iocs.txt / network-iocs.txt
- <sigma-rule>.yml   (vendor-agnostic; convert with sigconverter or sigma-cli)
- <yara-rule>.yar
- other: "Other detection or threat hunting opportunities"
> NOTE: use verify-iocs-vt.py and iocs-to-cs.py
```

The readme body is a LinkedIn-style post. Two eras, found by parsing all
561 readmes:

| Era | Packages | Body sections |
|---|---|---|
| A: 2025-01 to 2026-04 | 324 | Title; one summary paragraph; "Key takeaways:" with 3 to 6 emoji bullets, each with a free label (e.g. "Phishing Campaign:", "Security Advice:"); source link; Package Content; script note |
| B: 2026-04 to 2026-11 | 236 (plus a few earlier) | Title; summary paragraph; **Target** (who is hit), **Insight** (how the attack works and why it evades), **Recommendation 1 to 3** (some labelled Short-Term/Long-Term or given a sub-title); `[Source](url)`; Package Content; script note |

Fields a package never has: vendor report date, publisher name as a field,
actor or malware family as a field, ATT&CK mapping in the readme, CVE as a
field, TLP, confidence, hunt hypothesis, required telemetry or data source,
false-positive notes, expiry, or a hunt result. **There are no hunt
hypotheses anywhere in the corpus.** The nearest things are the one-line
comments above vendor queries ("Find external Teams chats and available
impersonation signals") and the Insight paragraph.

Source links: every readme has one; 125 of them (all of 2025-01 to 2025-06)
are `buff.ly` shortener links only, so the original report URL is not in
the file. The rest point at 132 distinct hosts, led by microsoft.com (30),
socket.dev (24), securelist.com (19), cloud.google.com (14), huntress.com
(14), Talos (13), Check Point Research (12), ESET (12), security.com (11).

Readme-to-file consistency: 33 readmes list a file that does not exist and
31 packages hold files the readme does not list (mostly typos; one,
2025-01-27, lists `new-bc.yar` that is absent).

## 3. Component review

| Component | What it is | Format and size | Toolkit phase | Already in ROADMAP? | How we would use it (deterministic) | Value |
|---|---|---|---|---|---|---|
| Package readmes | Kraven's digest of one public vendor report: summary, takeaways or Target/Insight/Recommendations, source link, file list | 561 Markdown files, ~1-2.5 KB each, 2025-01-02 to 2026-11-03 | 4 (reading list), 8/9 (package shape) | Partly. Phase 9: "a hunting package per actor (non-commodity tools with their LOLRMM and LOLBAS artefacts, procedure idioms, tagged rules, CVEs, current ThreatFox indicators with their age)". Per-report packages: no | Shape only: borrow the Target / Insight / Recommendations block as the summary section of our own package template. Content (Kraven's prose) is not copied | Medium: a proven, compact layout analysts already read; the text itself cannot be reused |
| Source URL list | The vendor report behind each package | 561 links, 436 direct, 125 buff.ly; 132 hosts | 4 | Partly. Phase 4 "Starter feed list" names news sites and CERTs, not vendor research blogs (Microsoft TI, Securelist, Talos, Check Point, ESET, Huntress, Elastic, Unit 42 and so on) | Hostnames are facts: seed the Phase 4 vendor research feed list from the top hosts; for a package import, store the original URL as the document source. Buff.ly links stay "unresolved" unless the operator resolves them by hand | Medium: a ready, dated map of who publishes IOC-bearing research, about 24 reports a month |
| `iocs.txt` (all IOCs per article) | One indicator per line, no header, no type, no context | 559 files, 23,062 lines, 22,621 unique; median 17 per package, max 1,281. Types: domain 8,055, SHA-256 7,584, IPv4 2,485, URL 2,388, SHA-1 741, MD5 725, email 56, IPv6 a handful, other 964 (scheme-less URLs, ASN names, file paths, registry keys, commands, user agents). 203 lines defanged (mixed `[.]`, `hxxp`, `[:]`, `[@]`) | 1, 2, 6 | Partly. Phase 2: "a saved extraction is a document record in the shared corpus that carries its source ... Each extracted indicator is stored as a sighting linked to that document". The Kraven corpus is not named | Optional local importer: each package becomes a document (title, Kraven date, original source URL), each line goes through the Phase 2 extractor and Phase 1 gates (Tranco, private IP, known-good hash) and becomes a sighting. Gives "seen in report X on date Y" for 22.6k indicators, a Phase 6 "prior art" hit list, and a realistic test corpus. Runtime-only, never committed | Medium: large, dated, report-linked; but no licence, no per-IOC role, and quality issues (below) |
| `endpoint-iocs.txt` / `network-iocs.txt` | The same IOCs split host-side (hashes) and network-side (domain, URL, IP) | 370 / 372 files. 24 of 367 split packages do not add up to `iocs.txt`; 191 split lines are absent from `iocs.txt`; 92 SHA-256 and 11 SHA-1 sit in network files | 8 | Not as files. Phase 8 "Exports: STIX 2.1, CSV, TXT, PDF" | None needed: the split is a view over typed indicators, which the toolkit already has (`app/core/indicators.py`). Take the idea as two export presets (EDR list, network block/hunt list) | Low: derivable from types |
| Typed selector lists (non-IOC) | Malicious packages and extensions, actor identities, wallets, misc. | 115 files. Packages/extensions 54 files (npm, PyPI, Go, RubyGems, Packagist, Rust, Terraform, Android app IDs, iOS apps, Chrome and Edge extension IDs (737 in one file), VS Code and Open VSX extensions); actor identities 25 (emails, aliases, personas, GitHub users and repos, TikTok accounts, Telegram IDs and invite links); wallets 3 (plus wallets mis-filed as "malicious-packages"); plus user agents, Entra client IDs, ASN names, scam phone numbers, AWS IAM user names, local account names, Firebase projects | 2 (Supply chain), 3, 7, 9 | Language packages: yes (Phase 2 Supply chain, OSV "nine language ecosystems", OpenSSF). **Browser and IDE extension IDs: no** (no match for "extension" in the roadmap). Actor e-mails/aliases: partly (Phase 9 alias table, Phase 7 identity lookup). Wallets: partly (Phase 6 wallet pivots, Ransomwhere) | Cross-check list for the Supply chain tab; propose a new indicator type for Chrome/Edge/Firefox extension IDs (32 chars a-p) and VS Code/Open VSX `publisher.name`, with a malicious-extension source. Identity selectors as Phase 7 seeds, with the ecosystem recorded per row | Medium: shows a real gap (extension stores) and a cheap new indicator type; files themselves are unlabelled and inconsistent |
| Hunting queries (KQL and others) | Vendor-published hunting queries pasted per article | 33 files (14 `.kql`, 19 `.txt`), 29 packages from 2025-01 to 2026-11, ~100 queries. Mostly Microsoft Defender XDR advanced hunting (DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceRegistryEvents, DeviceImageLoadEvents, DeviceEvents, CloudAppEvents, GraphAPIAuditEvents, AlertInfo) and Sentinel ASIM IOC sweeps (`_Im_NetworkSession`, `_Im_WebSession`, `imFileEvent`; 30 lines). Also CrowdStrike LogScale (1 file), Elastic KQL (1), Securonix (1), an EDR Lucene-style line (1) | 8, 9 | Yes in principle. Phase 8: "Detection templates from IOC sets: YARA, Sigma, SQL, KQL. SPL skipped." | Reference patterns for our own Jinja2 KQL templates: (a) Defender `let iocs = dynamic([...]); DeviceNetworkEvents \| where RemoteUrl has_any (iocs) or RemoteIP in (...)`; (b) hash sweep over `union DeviceFileEvents, DeviceProcessEvents ... where SHA256 in (...)`; (c) Sentinel ASIM network, web and file sweeps with a `lookback`; (d) certificate serial and signer hunts (`DeviceFileCertificateInfo`); (e) behaviour hunts keyed on paths, task names and parent-child pairs. We write the templates ourselves from Microsoft's documentation; nothing is copied | Medium-High as design input for Phase 8; Low as a library (vendor-copied, often broken, see below) |
| YARA rules | Vendor YARA rules pasted per article, plus a few IOC-as-string rules | 44 rule files (42 `.yar`, 2 `.yara`), 133 rules, ~115 KB. Authors: Elastic (Elastic License v2), GTIG/Mandiant, Sekoia, CISA, Check Point, Citizen Lab, Synacktiv, WithSecure, Rapid7, CrowdStrike, PT ESC, EclecticIQ, Sysdig, GuidePoint, Darktrace, Arctic Wolf, Cyfirma, Trend Micro, individual researchers. 4 rules have no author (e.g. `new_bc`, `injected_cred_logger_owa`, `TamperedChef_Installers`, the Aquabot IOC rule) | 8, 9, parking lot (malware corpus) | Yes. Phase 9 Defend tab: "public Sigma, YARA, and Splunk rules tagged to the actor"; Phase 8 YARA templates; parking lot: YARA runs only inside the analysis VM | Index only: rule name, author, reference, malware family, package date, as pointers on actor and malware pages, each linking to the vendor's original. The Aquabot file shows the IOC-to-YARA template shape (strings for IPs/domains, `hash.sha256(0, filesize) in (...)`), which our Phase 8 templater can produce from scratch. Never compiled or run by the app | Medium: a useful "which vendor published a rule for this family" index; the rules must come from the authors |
| Sigma rules | CISA MAR rules and one unattributed set | 3 files: CISA Ivanti EPMM (curly quotes, invalid YAML), CISA BRICKSTORM (`product: cma`, keyword blocks, URLs split across lines), BigBear/Evilginx (5 rules in Markdown code fences, truncated `id` UUIDs) | 8, 9 | Yes. Phase 8 Sigma templates; Phase 9 Sigma (DRL 1.1) ingestion | Negative test fixtures for a Sigma linter (local only). For content, use SigmaHQ and CISA originals | Low |
| Snort rules | IOC-to-Snort conversion for one article | 1 file, 3 rules (IP in/out lists, DNS pcre); `sid:1000001` used twice; a stray `;;;` comment inside the DNS rule | 8 | No. Phase 8 lists YARA, Sigma, SQL, KQL; Suricata appears only as SSLBL input (Phase 6) | If network-IDS export is wanted, write a Suricata template (`dns.query; dataset` or IP lists) with unique sids. Not from this file | Low |
| ATT&CK technique lists | Technique ID and name per article | 31 files, 483 lines, 2025-01-03 to 2025-08-12 only (stop after that). Separators vary (`-`, `—`, `–`, tab, comma); Enterprise and Mobile mixed; duplicates; ID-name mismatches (e.g. `T1566.002 - Drive-by Compromise`, `T1020.001 - Automated Exfiltration`); two packages carry byte-identical lists (2025-04-02 PostgreSQL and QR-code phishing) | 2, 9 | Yes. Phase 9: "ATT&CK ID check on every imported technique against the local bundle: remap revoked IDs, reject IDs that do not exist, flag ID and name mismatches. The same check goes into the Phase 2 TTP-table extractor." | Local test fixtures for that ID check and for the `ID - name` line parser. Not a source of truth | Low-Medium: good real-world bad input |
| Command lists | Actor command lines and appliance commands | `medusa-commands.txt` (69 lines, from CISA AA25-071A, some with `[T####]` tags, `{hostname/ip}` placeholders), `commands.txt` (FortiOS admin creation, includes an actor-set password string), `detection-rules.txt` (one KQL query with a typo `Time Generated`) | 9 | Yes. Phase 9 procedure-level matching: "command lines and artefact strings from reports and case notes are normalised (paths, hosts, and GUIDs replaced by placeholders) and matched against stored procedures per actor" | Test input for the normaliser; take the Medusa commands from the CISA advisory itself (public domain) | Low-Medium |
| CyberChef recipe | Regex, From Hex, Fernet decrypt chain for a trojanised-repo loader | 1 JSON file, 629 B | Parking lot (malware analysis) | No | None in the app; a note for analysis-VM work | Low |
| Template folder | Package readme template and empty placeholder files | 6 files | 8, 9 | See readmes row | The template is the clearest statement of Kraven's intended package contents (IOCs, endpoint/network split, Sigma, YARA, "other hunting opportunities") | Medium (as shape) |
| `verify-iocs-vt.py` | Reads `iocs.txt`, types each line with `validators`, queries VirusTotal through `vt-py`, sleeps 15 s per IOC, prints malicious/suspicious/clean and an "upload to MISP" endpoint/network list | 195 lines Python, deps `vt`, `validators`; read as text only | 1 | Yes, already built better. Phase 1 IOC enrichment with VT rate limits and caching | None. Bugs noted: URL branch base64-encodes the literal string `"ioc"` and calls `scan_url` (submits instead of looking up); thresholds use `> 1`, so one engine is not enough; `except` reads `e.code` on any exception | Low |
| `iocs-to-cs.py` | Sorts IOCs by type, uploads to CrowdStrike Falcon IOC Management (action detect, severity medium, all platforms, 60-day expiry, retrodetect) | 168 lines Python, dep `falconpy` | 9 (push) | No for CrowdStrike. Phase 9: "MISP and OpenCTI push" | Only the ideas: an expiry on every pushed indicator (the roadmap's decay model already covers this) and "detect, not block" for low-confidence items (Phase 6 outcome ladder already says so) | Low |
| `config.py` | Empty credential placeholders (MISP, CrowdStrike, VirusTotal) and ANSI colours | 36 lines | none | n/a | None | Low |

### Data-quality findings (affect any import)

- ~58 malformed hashes in `iocs.txt` (hex strings of length 37, 38, 39, 60
  to 63, 65, 103: truncated or merged when copied from PDFs/blogs).
- 135 `iocs.txt` files with leading or trailing whitespace; 67 with
  duplicate lines; 3 private IPs (192.168.178.60, 192.168.16.19,
  172.23.182.202); legitimate services listed as IOCs (`ip-api.com` twice,
  `api.telegram.org`, `github.com`, `t.me`); the 2025-01-09 "neglected
  domains" package lists 160 short legitimate-looking domains (jt.net,
  hc.com) that were spoofed senders, not attacker-owned.
- The 2026-10-09 "malicious-android-packages.txt" lists stock names such as
  `com.android.browser` (trojanised pre-installs), which would match every
  Android device if used as a blocklist.
- "Other" lines mix ASN organisation names (147 in one package),
  scheme-less URLs, Windows paths with environment variables, registry
  keys and full command lines in the IOC file.
- Queries: truncated lines mid-query (2025-02-13 and 2025-03-07),
  `_Im_WebSessionn` typo, placeholder lists `['domain1','domain2']`,
  trailing spaces inside `dynamic([...])` values (`"181.49.105.59 "`),
  curly quotes in three files, prose lines pasted between queries, an
  undefined `ioc_domains` variable.
- YARA: 67 lines with curly quotes (CISA Ivanti and Cyfirma APT36 files
  will not compile), PT ESC rules use `pe.imphash()` with no `import "pe"`,
  one Sekoia rule needs the VirusTotal-only `vt` module, `banshee_macos`
  has an and/or precedence slip, and two Cyfirma rules match hashes and
  domains as strings inside files (weak).

Lesson for the toolkit: any detection content that enters the toolkit,
imported or generated, needs a lint step (straight quotes, no stray
whitespace in list values, non-empty lists, unique IDs and sids, balanced
brackets, YARA compile in the VM or via a pinned compiler, Sigma schema
check). Generated content should be clean by construction.

## 4. Threat hunting material in detail and a Phase 8/9 template

### What Kraven's packages actually are

A Kraven package is "one public report, made actionable": a short digest,
the report's indicators as plain lists, and whatever detection content the
vendor published (queries, YARA, Sigma), copied verbatim. It is a
campaign-level IOC and detection bundle, not a hypothesis-driven hunt in the
PEAK or TaHiTI sense. 29 packages carry hunting queries, 44 carry YARA, 3
carry Sigma; 485 packages (86%) carry indicators only.

### Hunt hypotheses

None are written down. Implicit hypotheses can be read off the query
comments and Insight paragraphs, and they follow three patterns that the
toolkit can template deterministically:

1. Indicator presence: "Hosts in our estate contacted infrastructure X or
   wrote file hash Y in the last N days" (the ASIM and Defender IOC sweeps).
2. Artefact presence: "A process ran from path P, a task named T exists,
   a DLL named D loaded from folder F, a service named S was registered,
   a certificate with serial C or signer S signed a binary" (the
   NeedyMantis, Star Blizzard, CornFlake, TerminalFix queries).
3. Behaviour sequence: "Event A was followed by event B within T minutes
   on the same device or account" (device-code phishing click then sign-in
   with error 50199; captive-portal check then file download within 2 min;
   sideloaded DLL then msiexec within 30 min; Graph discovery then content
   collection in the same hour).

### Query template patterns worth reproducing (written by us)

| Pattern | Inputs from the toolkit | Backends |
|---|---|---|
| Network IOC sweep | domains, IPs (with optional ports), URLs; lookback | Defender `DeviceNetworkEvents`; Sentinel ASIM `_Im_NetworkSession`, `_Im_WebSession(url_has_any=...)`; Sigma `network_connection` / `proxy`; Suricata |
| File hash sweep | SHA-256, SHA-1, MD5 | Defender `union DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents, DeviceEvents`; ASIM `imFileEvent`; YARA `hash.sha256(0, filesize)` (labelled weak) |
| Code-signing sweep | certificate serials, signer names, thumbprints | Defender `DeviceFileCertificateInfo` joined to `DeviceProcessEvents` |
| Identity sweep | IP prefixes, user agents, app/client IDs | Sentinel `SigninLogs`, `AADNonInteractiveUserSignInLogs`; Defender `CloudAppEvents` |
| Artefact hunt | paths, file names, task names, service names, registry keys, mutexes, command substrings | Defender `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`; Sigma `process_creation`, `registry_set`; YARA strings |
| Sequence hunt | event A spec, event B spec, window, join key | Defender `join kind=inner ... on DeviceId \| where tB between (tA .. tA + window)` |

Each generated query carries a header comment with package ID, source
document, indicator count, generation time, and lookback, and is linted
before export.

### Proposed toolkit "hunt package" (Phase 8 export, Phase 9 per-actor view)

One schema, two scopes: per report or campaign (Kraven's scope) and per
actor (the Phase 9 scope already in the roadmap). Sections:

1. Header: package ID, title, scope (report, campaign, actor, case),
   created, last reviewed, review interval, TLP, status, author.
2. Provenance: source documents (resolved URL, publisher, report date,
   reliability letter from the source registry), licence of every
   included item, and "derived from / republishes" lineage.
3. Summary (Kraven era B shape): Target (sectors, regions, platforms),
   Insight (one analyst-written paragraph), Recommendations 1 to 3.
4. Hypotheses (missing in Kraven): one row each with statement, pattern
   (indicator, artefact, sequence), ATT&CK technique, required telemetry
   (ATT&CK data component and the concrete table), expected benign
   activity, and what a hit would mean.
5. Indicators: typed table with value, type, role (C2, delivery, payload,
   sender, staging), first seen in source, gate results (Tranco, private,
   known-good, warninglists), latest enrichment verdict, decay state, and
   the Phase 6 confidence gate ("only entities at Moderate or above reach
   a hunt package").
6. Other selectors: packages (ecosystem, name, versions), browser and IDE
   extension IDs (store), accounts and handles (platform), wallets (chain),
   user agents, client IDs, certificate serials and signers, file paths,
   registry keys, task and service names, mutexes, command lines
   (normalised).
7. Techniques: ID, name, tactic, procedure sentence, validated against the
   local ATT&CK bundle.
8. Detections: generated queries and rules per backend (KQL Defender,
   KQL Sentinel ASIM, Sigma, YARA, Suricata, SQL), each with lint status;
   third-party rules as links with author and licence, embedded only where
   the licence allows (CISA, DRL 1.1 Sigma, MIT/Apache).
9. Limitations and false positives, expiry date per item.
10. Hunt log: run date, platform, hits, verdict, notes; feeds the Phase 6
    hunt quality score.

Rendering: Jinja2 templates to Markdown, HTML and a ZIP with one file per
backend (the Kraven folder layout is a fine default:
`readme.md`, `iocs.txt`, `endpoint-iocs.txt`, `network-iocs.txt`,
`hunting-queries.kql`, `rules.yar`, `rules.yml`), plus STIX 2.1.

## 5. Ranked recommendations

1. **Adopt the package shape, not the content, as the Phase 8/9 hunt
   package template** (section 4). The Kraven layout plus the roadmap's own
   fields plus the missing hypothesis, telemetry, provenance and hunt-log
   sections. High value, no licence issue, fits "hunting package per
   actor" and the Phase 6 export gate. Worth a line in ROADMAP Phase 8.
2. **Write our own IOC-to-query templates for Defender XDR and Sentinel
   ASIM first, then Sigma, YARA and Suricata, with a linter.** Kraven shows
   which patterns analysts actually use (ASIM sweeps, Device* tables,
   certificate and identity sweeps, time-window joins). Keep a few broken
   Kraven queries and rules as local, git-ignored negative fixtures for the
   linter.
3. **Add browser and IDE extension IDs as an indicator type** and a
   malicious-extension source on the Supply chain tab. Kraven has 20+
   extension lists (Chrome, Edge, Firefox, VS Code, Open VSX); the roadmap
   covers only language ecosystems through OSV. Pick an open source for the
   data (to be researched), not Kraven's files.
4. **Optional runtime importer for the operator's local copy** (or a
   runtime clone of github.com/kraven-security/hunting-packages registered
   in the source registry with licence "none"): packages become documents,
   lines become sightings through the Phase 2 extractor and Phase 1 gates,
   with the data-quality rules above. Gives "seen in a public report" on
   enrichment pages and a test corpus. Never committed, never re-exported.
   Medium value; needs the Phase 5 corpus.
5. **Seed the Phase 4 vendor research feed list** from the 132 source
   hosts (hostnames are facts). The current starter list has news and CERT
   feeds but few vendor research blogs.
6. **Use the ATT&CK lists and Medusa commands as local test fixtures** for
   the ATT&CK ID check and the procedure normaliser.
7. **Index YARA rule names and authors as pointers** on actor and malware
   pages, linking to each vendor's original; never run them in the app.
8. **Skip** the two scripts (Phase 1 already does VT better; CrowdStrike
   push is not planned), the Snort file, the CyberChef recipe and the
   Sigma files.
9. If any Kraven content is ever wanted in the repo, ask Kraven Security
   for a licence first, and still clear each embedded third-party rule
   with its author.

## 6. Not read, or read only in part, and why

- Package readmes: all 561 parsed by script (sections, labels, source
  links, file lists, style by month); 7 read in full by eye (2025-01-02,
  2025-03-13, 2025-08-27, 2026-02-26, 2026-09-30, 2026-11-03, template).
  The rest were not read word by word; their content is Kraven prose that
  the toolkit cannot reuse, and their structure was captured by the parse.
- `iocs.txt`, `endpoint-iocs.txt`, `network-iocs.txt` (1,301 files): all
  parsed for type, count, duplicates, whitespace, defanging and
  consistency; a handful read by eye.
- Other `.txt` selector lists (115 files): all counted, first four lines of
  each read.
- Hunting queries (33 files): all read in full.
- YARA (44 files): about half read in full (FireScam to GLOBAL GROUP,
  Plague, Akira, APT36, Silver Fox start, TamperedChef, BrickStorm start);
  the rest (CISA Ivanti, ShadowV2, Brickstorm GTIG, ChaosBot, LinkPro,
  2026 files) scanned for rule names, authors, licences, imports and module
  use only. Rule logic was not reviewed for every rule.
- Sigma, Snort, CyberChef JSON, command lists: all read in full.
- ATT&CK lists (31 files): about a quarter read in full, the rest scanned
  by header and first lines; one duplicate confirmed by file hash.
- Scripts (3): all read in full as text; not run.
- Not checked (no web access): whether upstream now has a licence, where
  the 125 buff.ly links resolve, and whether the vendor originals of the
  copied rules and queries have changed since.
