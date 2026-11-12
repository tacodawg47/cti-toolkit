# Sources review, 2026-11-11

Eleven GitHub repositories handed over on 2026-11-11, plus the parts of the
ChatGPT research handoff that the first pass skipped. Five research agents
read the sources the same day (read-only web fetches: nothing cloned,
installed, downloaded on purpose, or signed up for). Their full notes are in
[2026-11-11-sources/](2026-11-11-sources/):

| File | Covers |
|---|---|
| [c2-tracking.md](2026-11-11-sources/c2-tracking.md) | C2-Tracker, Adversary-Hunter, C2 Hunter and c2-iocs, framework defaults (Cobalt Strike, Havoc, Sliver, Mythic and others), other C2 feeds, a proposal for our own C2 tracking |
| [actors-attribution.md](2026-11-11-sources/actors-attribution.md) | crocodyli/ThreatActors-TTPs, curated-intel/Attribution-to-IP, curated-intel/Threat-Actor-Profile-Guide |
| [bushido-ransomware-apt.md](2026-11-11-sources/bushido-ransomware-apt.md) | Ransomware Vulnerability Matrix, Ransomware Tool Matrix, Awesome-Ransomware, Malware-Zoo, Exploring-APT-campaigns |
| [bushido-tools.md](2026-11-11-sources/bushido-tools.md) | Open-source-tools-for-CTI (36 sub-lists, 972 rows), OSINT-SearchOperators, Operational-Security-101 |
| [handoff-remaining.md](2026-11-11-sources/handoff-remaining.md) | The rest of the handoff: abuse.ch platforms, MISP feeds, traffic datasets, Hugging Face datasets, and a status for all 55 handoff links |

About 1,300 links were read in all. Each note file ends with a list of every
link that was not read and why. Licence rule used throughout: a repository
with no licence is all rights reserved, so the toolkit may fetch it at
runtime for local use but may not copy it into the repo; single facts (a
CVE-to-group pair, a certificate serial, an alias) can be re-keyed in our own
words. NC and share-alike data is fetched at runtime and never shipped.

---

## 1. Answers to the questions asked

### Feodo Tracker: "I can see IPs, should be in the abuse.ch API"

You are right that the files are not empty. abuse.ch's banner says the
datasets are empty after the Emotet and Operation Endgame takedowns, but the
files tell a different story: they are **frozen since 2026-03-04**.

- Recommended list: 1 IP (50.16.16.211, QakBot, last online 2026-03-12).
- 30-day list: 5 IPs, all stale (their last-online dates are months outside
  the 30-day window).
- Browse page: the full history since 2021, not current C2s. Four IPs were
  first seen in 2026, all QakBot, all offline.

Feodo Tracker has **no API**; its data is only in the download files, which
need no key. Nothing on any Feodo or abuse.ch page says Feodo entries are
copied into ThreatFox. A web search suggests ThreatFox holds 50.16.16.211, but
ThreatFox's pages sit behind a bot check, so this is unconfirmed. Five lookups
with our keyed ThreatFox client would settle it (the four 2026 IPs plus
50.16.16.211), keeping in mind that ThreatFox's API only serves six months.

Verdict: not a C2 source. At most a keyless historical lookup in Phase 1 ("was
a QakBot C2 in early 2026"). The roadmap line that said "empty" now says
"frozen".

### ArcSpan: "can we use that info?"

Yes, as a **private local evaluation set** for Phase 11, not as anything we
commit or publish. The card says Apache-2.0, but that tag does not cover the
22 upstream sources it was built from:

- about 27% of rows rest on a clear open licence or are the author's own
  synthetic data;
- about 19% is probably MIT (CyNER 2.0, unconfirmed);
- about 42% comes from APTNER, DNRTI and CyberNER, which have no licence;
- about 10% is copyrighted report text (vendor blogs, APT reports, news).

A clean subset filters by source to `cyner_train`, `mitre_attack*`, `nvd*`,
`cisa_advisories`, `synthetic*` and `securebert2`. About a quarter of rows
were labelled by an LLM, so scores on those rows measure agreement with
another model, not ground truth. The handoff's "about 50,600 rows" is two
overlapping versions of the training split; the total across splits is 61,212.

### KEVScope

The first pass was wrong to set it aside. The card defines
`days_published_to_kev` as KEV listing date minus NVD publication date, so a
negative value just means CISA listed the CVE before NVD published the record
(common with zero-days). The late-2026 dates are CISA due dates, set two to
three weeks after listing. The journal entry now says so.

What it is good for: a one-off offline test that compares our KEV count, EPSS
scores and CVSS selection against its snapshot for one day. It is built from
the same three feeds we already ingest and trails them by days, so it is a
test fixture, not a source. Its README statistics are from its first build;
`meta.json` is current.

### Which C2-tracking material can only be fetched at runtime

| Source | Runtime only (never in the repo) | Facts we may re-key | May be copied |
|---|---|---|---|
| C2-Tracker (archived) | its old data files | serials, hashes, titles, header strings, ports from its queries | nothing (no licence) |
| Adversary-Hunter | `data/*.txt` IP lists | same as above, plus its disabled set as "demoted" | nothing (no licence) |
| C2 Hunter / c2-iocs | `c2_sightings.csv` | framework-to-port counts as aggregate facts | nothing (no licence) |
| C2IntelFeeds | all feeds | fingerprint facts from its README table | not shipped (CC BY-NC-SA) |
| ThreatFox | all IOCs (already integrated) | n/a | no; and no AI training on it |
| ViriBack | CSV export | panel title and path patterns | nothing (no licence) |
| Malleable C2 profiles (Cobalt Strike, BC-SECURITY) | profile files, if ever parsed | default and example values | nothing (no licence) |
| Fox-IT 2022 GitHub data | all of it | aggregate facts (watermarks, public keys) | nothing (no licence file) |
| SSLBL | | | yes, CC0 (certificate SHA-1 list) |
| awesome-censys-queries | | | yes, CC0 |
| nuclei `ssl/c2` templates | | | yes, MIT (keep the notice) |
| Havoc, Sliver | | ports, URIs, headers, certificate names | GPL-3.0: re-key, do not copy files |
| Fox-IT 2026 Hugging Face corpus | | | CC BY 4.0 with credit (payload subset follows the malware storage rule) |

Status changes found: **c2-iocs has not updated since 2026-08-02**, although
it is described as automatic. C2IntelFeeds moved its raw data from Censys to
Modat on 2026-05-01. SSLBL's C2 **IP lists were deprecated on 2025-01-03** and
its JA3 list has been frozen since 2021; only the certificate SHA-1 list is
live.

### Could we track C2s ourselves, or feed the infrastructure module?

Yes. Section 7 of [c2-tracking.md](2026-11-11-sources/c2-tracking.md) has a
full proposal. In short:

- **Passive only.** Shodan indexed search and host lookups plus the feeds
  above. No probing, no computing JARM ourselves, never contacting a hit.
- **Four tables:** signatures (one fingerprint fact each, with its framework,
  component, feature class, source and licence, and a flag for facts that may
  only be used in combination, such as Go-stack JARMs and bare ports), hunts
  (signatures combined into a saved query), hunt runs, and sightings (one row
  per IP, port and signature, with validation states: unvalidated, rechecked,
  corroborated, suppressed, stale).
- **Seed list:** CC0 and MIT values copied with credit; facts re-keyed from
  C2-Tracker, Adversary-Hunter and BushidoUK's adversary query set; vendor
  defaults (Cobalt Strike certificate serial 146473198 and teamserver port
  50050, Havoc teamserver 40056, Mythic 7443 with certificate org "Mythic",
  Sliver's "multiplayer" and "operators" certificate names); observed port
  distributions used only for ranking.
- **Shodan budget.** Membership gives 100 query credits a month and no `tag`
  filter, so `tag:malware` is out. `/shodan/host/count` is free, so each hunt
  runs a free count first and spends one credit (page 1 only, with a date
  filter) only when the count changed: at most 3 credits a day, 30 a month
  kept for manual pivots. About 20 hunts can each run weekly.
- **What a hit means.** "This host matched signature S of tool T", which
  identifies software and maybe a configuration. It never identifies an
  operator: red teams, trainers and honeypots run default Cobalt Strike,
  Sliver, Havoc and Mythic too. Low-confidence hits go to a hunt list, never a
  blocklist. Attribution stays behind the Phase 9 evidence gate.

### Why Havoc, Mythic and Sliver weren't checked, and CyberSet

**Havoc, Sliver, Mythic:** the web-fetch tool runs pages through a safety
filter, and it refused 8 URLs in this area: the Havoc repository and its
`http.go`, the Sliver repository and its multiplayer docs, the MythicC2Profiles
organisation and its HTTP profile, and two newtonpaul.com posts on hunting
AI-generated C2. Elsewhere it also refused optiv/Freeze and one YouTube video.
The agents were told not to get around a refusal by another route, so they
didn't. The defaults above come from defender sources instead (nuclei
templates, awesome-censys-queries, vendor blogs). The handoff's Havoc path
(`havoc_default.yaotl`) is a 404; the shipped profiles are
`profiles/havoc.yaotl` and `profiles/http_smb.yaotl`. These pages can be read
by hand, or in the built-in browser, when Phase 6 is built.

**CyberSet:** not refused. The first pass simply did not get to it, which was
a gap on my side. It is now checked: a 28.8 GB personal research build
(2026-10-04, one build, no update schedule) with four tiers: a CVE knowledge
hub of 400,870 CVEs, 2.2 million code functions, 440 million network flows,
and IDS alerts. It has no single licence: a per-row column governs, and the
default flow set includes a non-commercial component (NF-UQ-NIDS-v2), plus GPL
and academic-only parts. Low value for us: our live feeds are fresher, and the
code and flow tiers are ML material.

### Were all the handoff links addressed?

Every link now has a status, listed in section 8 of
[handoff-remaining.md](2026-11-11-sources/handoff-remaining.md):

- 29 were read in this pass.
- 25 are marked "covered elsewhere": the C2 links went to the C2 agent, and
  the datasets were read in the first pass.
- One, the EMBER2024 GitHub upstream, was treated as part of its Hugging Face
  item.

Not everything is closed. The Havoc, Sliver and Mythic links were refused
(see above). The first pass left three things open: MWDB's access terms, the
DC3-MWCP licence and CAPE-parsers' details. Three pages could not be fully
read; reasons are in its section 9:

- the Stratosphere datasets index: rate-limited, so the IoT-23 page was read
  instead;
- the VB2022 Emotet abstract: HTTP 403;
- the tandevllc README: gated behind sign-in.

---

## 2. The eleven repositories

My earlier count of twelve was wrong: the message named eleven.

| # | Repository | What it is | Licence | Value | Action |
|---|---|---|---|---|---|
| 1 | BushidoUK/Ransomware-Vulnerability-Matrix | Markdown tables of Product, CVE(s), Ransomware Group(s), Source(s); 8 category files, about 143 rows and 165 CVEs; last commit 2026-08-30 | CC BY 4.0 | **High, Phase 2** | Fills view 9 directly: an `rvm_cves` table keyed (cve_id, group), parsed weekly, unioned into the ransomware view, credited on the CVE page. Its categories seed view 8 (edge devices). |
| 2 | BushidoUK/Ransomware-Tool-Matrix | Tools used by ransomware groups: 8 category files (351 rows), group profiles, a "most used" list, about 170 dated report links | CC BY 4.0 | **High, Phase 9** (also 8) | Tool table from the category files (not the stale AllTools.csv); stop-list from MostUsedTools; report links as a dated index. |
| 3 | BushidoUK/Open-source-tools-for-CTI | 36 link lists, 972 rows | none | Medium (as a discovery list) | Ten concrete picks, in section 3 below. Link, do not copy. |
| 4 | BushidoUK/OSINT-SearchOperators | 45 Shodan appliance queries, 38 Shodan adversary queries plus 3 certificate fingerprints, 42 Google dorks; adversary file updated 2026-09-27 | none | **High, Phase 6**; Medium, Phases 3 and 4 | Re-key facts into the signature library and query templates. The fetch tool would not reproduce the adversary query strings, so those are re-keyed by hand from a browser. |
| 5 | curated-intel/Attribution-to-IP | A checklist of 18 free and 3 paid ways to find an IP's **owner** (for victim notification), not its attacker | none | Medium-High, Phases 6 and 9 | Three rules adopted into the roadmap: owner, hoster and geolocation are not operator evidence; classify the IP type before any pivot, including "likely compromised third party"; a "notify" outcome. Plus RIPEstat for routing history. |
| 6 | curated-intel/Threat-Actor-Profile-Guide | A short 2023 profile template (4-page PDF) | none | Medium, Phase 9 | Our planned layout is already richer on sourcing. Gaps adopted: a dated What / So what / What now summary, leadership and operations views, a Diamond Model card, an Observable column, IN / THROUGH / OUT grouping, dwell time, contested-attribution notes. |
| 7 | crocodyli/ThreatActors-TTPs | Markdown profiles of 41 ransomware groups, about 670 technique rows, plus CVE lists per group | none | Low as data; **important as lineage** | No row cites a source, and several technique IDs are revoked, invalid, or mismatched. ransomware.live shows this repo's TTP matrix and credits it, so the two are **one source, not two**. Record that lineage; use it as a runtime hint at the lowest reliability; validate ATT&CK IDs on every import. |
| 8 | BushidoUK/Awesome-Ransomware | Link list | none | Medium (3 finds) | Ransomwhere export (payment addresses by family), rivitna/Malware (MIT YARA rules and decryptors for about 50 families, analysis VM only), crocodyli's CVE files. |
| 9 | BushidoUK/Operational-Security-101 | A copy of a 2020 OPSEC blog post | none | Low (Phase 10 reference) | Notable: WhatsMyName was **archived 2026-11-09** (Phase 7 relies on it); HIBP's keyless breach catalogue; self-hosted Canarytokens; Digital Defense checklist (MIT) for an operator OPSEC runbook. |
| 10 | BushidoUK/Malware-Zoo | Sample hash list, frozen 2023 | none | Low | At most a runtime smoke test. |
| 11 | BushidoUK/Exploring-APT-campaigns | VirusTotal graph embeds and Maltego files, abandoned 2022 | none | None | JS-only graphs and binary archives. Skip. |

---

## 3. Other findings by phase

**Phase 1 (enrichment)**
- abuse.ch terms (updated 2026-10-21): Feodo Tracker, SSLBL and YARAify are
  CC0-style. URLhaus, MalwareBazaar and ThreatFox are free for not-for-profit
  use only, and section 7.3 forbids training AI models on any abuse.ch data.
  The browse pages now have a bot check, so the API is the only route.
- Optional keyless sources: SANS ISC / DShield IP API (non-commercial; asks for
  a contact address in the User-Agent) and CrowdSec CTI (free quota). Both
  mostly duplicate GreyNoise and AbuseIPDB.

**Phase 2 (vulnerabilities)**
- Ransomware Vulnerability Matrix for view 9 (above).
- Google Project Zero's "0day In the Wild" sheet is **current** (latest row
  patched 2026-11-09), contrary to the roadmap's "dead end" note. Keyless CSV
  per year; no licence, so facts re-keyed. A source for view 11.
- ZDI RSS (published and upcoming): "(0Day)" advisories are public bugs with
  no vendor fix, a fit for view 7.
- KEVScope as an offline cross-check test (above).
- Emerging Threats Open rules: `reference:cve` could give a "network detection
  exists" flag.
- Gone or paid: Tencent bsafe (gone), Vulmon API and RSS (paid only).

**Phase 3 (digital risk)**
- phishunt.io: CC0, keyless, hourly JSON, CSV and STIX feeds.
- OSINT-SearchOperators appliance queries as "our exposed services" templates.
- HIBP keyless breach catalogue; self-hosted Canarytokens.

**Phase 4 (news)**
- A verified keyless starter feed list (now in the roadmap).
- 42 Google dorks for the dork launcher (re-keyed).

**Phase 5 (collection)**
- FireHOL blocklist-ipsets, CIRCL and Botvrij MISP OSINT feeds, Spamhaus DROP
  JSON. The MISP default feed catalogue (108 feeds) has no licence data and
  still lists dead feeds.

**Phase 6 (infrastructure)**
- The C2 tracking proposal (above).
- Attribution-to-IP rules (above).
- BinaryEdge has shut down; ThreatCrowd is gone.
- Extra suppression ranges: GitHub meta, Microsoft 365 endpoints, Imperva, and
  Bitcoin node IPs.

**Phase 7 (OSINT)**
- WhatsMyName archived 2026-11-09 (final dataset of 691 sites).
- spiderfoot.net now redirects to Intel 471; key-server.io is parked (use
  keys.openpgp.org).

**Phase 9 (actor profiles)**
- Source lineage field in the source registry (ransomware.live's TTPs come
  from crocodyli).
- ATT&CK ID validation on import.
- Alias crosswalks beyond MISP: Florian Roth's APT sheet (CC BY 4.0),
  EternalLiberty (no licence), the ETDA MISP export (CC BY-NC-SA), BSI's
  active APT list.
- Ransomwhere payment addresses. The two agents disagree on its licence
  (CC BY 4.0 against "none named"), so check before storing anything.

**Phase 11 (AI assist)**
- ArcSpan per-source licences (above); SecKnowledge-Eval is CC BY-NC 4.0
  (4,142 items); Malpedia is CC BY-NC-SA with vetted accounts; abuse.ch data
  may not be used for AI training.

**Parked malware corpus**
- rivitna/Malware (MIT). JR0driguezB/malware_configs was last pushed in 2018
  and has no licence. MalwareConfig.com is now an editorial site with no data.

All of the above is recorded in ROADMAP.md under the phase it belongs to.

---

## 4. Decisions for the operator

1. **LeakRadar** returns plaintext passwords and sells access. Does even its
   free tier sit under the "no purchase of stolen data" rule? (Added to Open
   questions.)
2. **SANS ISC** asks for a contact address in the User-Agent. Use a dedicated
   address kept in .env, or skip the source? (Added to Open questions.)
3. **ETDA's MISP export** (CC BY-NC-SA) is "link only" in the roadmap. Revisit
   when Phase 9 is built?
4. **Never ingest:** BushidoUK/Ransomware-Leaks (leaked gang chats; linking its
   index is fine), the Bassterlord manual, and onion links. **Never link:**
   cuckoosandbox.org and apt-ecosystem.com, which now serve spam. (Recorded in
   the decisions log.)

---

## 5. What was not read

Every note file ends with a full list. In summary:

- **Refused by the fetch tool's safety filter (11):** the Havoc, Sliver and
  Mythic pages listed above, two newtonpaul.com posts, optiv/Freeze, and one
  YouTube video.
- **Skipped on purpose:** onion addresses, defanged links, leaked material,
  and PDFs after the first few (see the note below).
- **Blocked to the fetcher:** x.com (HTTP 402 for every post), many vendor
  pages returning 403 or 429, and pages that render only through JavaScript
  (VirusTotal, OTX, ANY.RUN, C2 Hunter's site, Sliver's docs).
- **Spot-checked, not read one by one:** about 150 source links inside the
  RVM tables, about 175 report links in the Tool Matrix, 45 VirusTotal graph
  embeds (one checked; all are JS-only), and about 60 GitHub images.

**Files saved without being asked for.** The fetch tool writes any PDF it
fetches to the Claude session's `tool-results` folder (outside the repo).
Eleven landed there on 2026-11-11: vendor reports and guides, the Threat
Actor Profile Guide, a Unified Kill Chain paper, and one leaked criminal
manual (the Bassterlord PDF). None was opened. They can be deleted. Future
research briefs should tell agents not to fetch `.pdf` links.

---

## 6. Operator's decisions and follow-up (later on 2026-11-11)

| Item | Decision | Where it went |
|---|---|---|
| Ransomware Vulnerability Matrix | Use now | Built: `rvm` feed, view 9, CVE page card, P1 reason |
| Project Zero in-the-wild sheet | Use now | Built: `gp0` feed, a kev source, view 11 "confirmed" rows |
| Ransomware Tool Matrix | Use (Phase 9) | ROADMAP Phase 9 |
| Attribution-to-IP, profile guide | Use (Phases 6 and 9) | ROADMAP Phases 6 and 9 |
| ETDA MISP export | Revisit in Phase 9 | ROADMAP Phase 9 |
| crocodyli/ThreatActors-TTPs | Dropped | Removed from the roadmap |
| Feodo Tracker, SSLBL IP lists, c2-iocs feed | Dropped | ROADMAP Phases 1 and 6 |
| Own C2 tracking | Note the method for Phase 6 | ROADMAP Phase 6 |
| Havoc, Sliver, Mythic defaults | Phase 6 and the parking lot | Both |
| ArcSpan | Clean subset only; rest parked | ROADMAP Phase 11 and parking lot |
| LeakRadar, ThreatSTOP Check IoC | Parking lot | Parking lot |
| Leaked chats, onion links | Wanted, through the Phase 5 collectors | Decisions log |

Four more note files were added beside the first five:

| File | Covers |
|---|---|
| [pdfs-hunting-killchain.md](2026-11-11-sources/pdfs-hunting-killchain.md) | UK "Detecting the Unknown" hunting guide, Unified Kill Chain, Lockheed Martin "Gaining the Advantage", CyberEdge "Definitive Guide to CTI" |
| [pdfs-reports.md](2026-11-11-sources/pdfs-reports.md) | CrowdStrike Fancy Bear Android, Trend Micro MuddyWater, Lookout Pegasus, Heuer "Psychology of Intelligence Analysis" |
| [kraven-hunting-packages.md](2026-11-11-sources/kraven-hunting-packages.md) | Kraven's 561 hunting packages |
| [kraven-other-repos.md](2026-11-11-sources/kraven-other-repos.md) | Kraven's CyberChef recipes, hacks, python-threat-hunting-tools, testing-environments |
