# PDF threat reports review: ideas for the CTI toolkit

Reviewed 2026-11-11. Read-only review of four locally saved PDFs. Every page of
all four documents was read (288 pages in total; see the last section). Page
numbers are PDF page numbers; for the Heuer book the printed page follows in
brackets. Quotes are short and few; everything else is paraphrase. IOCs are
described by type only, not reproduced.

"In ROADMAP?" quotes ROADMAP.md (v3, 2026-11-10) where a matching line exists.
"Partly" means the roadmap has the general idea but not the specific piece
named in the row.

---

## 1. CrowdStrike: Fancy Bear Android malware and Ukrainian field artillery

- File: webfetch-1794439337141-72yxlf.pdf
- Title: "Use of Fancy Bear Android Malware in Tracking of Ukrainian Field
  Artillery Units"
- Publisher: CrowdStrike Global Intelligence Team (a "Tipper" product)
- Date: published 2016-12-22, updated 2017-03-23 (the update replaced the
  artillery-loss figures with numbers from an IISS analyst; p2)
- Pages: 11
- Copyright: "Copyright 2016" on the cover (p1). No licence for reuse stated.

**Summary.** A strategic/attribution paper with almost no technical IOCs. It
argues that a legitimate Android targeting app (made by a Ukrainian artillery
officer and spread through VK and forums, activated by a code from the author)
was repackaged with the X-Agent implant and redistributed on a Russian-language
Ukrainian military forum from late 2014. The development window comes from the
benign app's file timestamps and signing date and from the first sighting of
the malicious copy (pp6-7). Two colour-coded timelines (2013-2016) set app
events beside diplomatic, domestic, intrusion and military events (pp4-5).
Targeting is inferred from fit with the users (artillery units), the app's
Russian-language interface and regional language census data (pp8-9). One
alternative hypothesis (targeting pro-Russian forces) is raised and rebutted
(pp8-9). The conclusion ties the activity to the GRU on intent and
victimology grounds (pp2, 10). The causal claim about artillery losses was the
part revised in the March 2017 update.

| Idea | Page | Phase | In ROADMAP? | Deterministic build | Value |
|---|---|---|---|---|---|
| **Development-window dating from artefact timestamps.** Bound when an implant was built using the benign original's file times and signing date (lower bound) and first malicious sighting (upper bound). | 6-7 | 9 (artefact registry, cases) | Partly: the artefact registry lists "compile time"; no bounding logic. | Case "artefact timeline": each timestamp is a row (value, source artefact, forgeability label from the planned registry). The page computes earliest and latest bounds and flags contradictions, e.g. a compile time after first sighting. | Medium: cheap; turns loose timestamps into a stated window with its weakest link visible. |
| **Typed context timeline.** One timeline mixing cyber events with geopolitical, diplomatic and domestic events, colour-coded by category. | 4-5 | 9 (profile Strategic context tab, cases) | Partly: "a short activity timeline" in the Strategic context tab; no event typing. | Timeline events table (date, category enum, source, document link); server-rendered SVG like the Phase 2 charts. Context events need a source like any claim. | Medium: the visual that makes "why now" arguments checkable. |
| **Trojanised legitimate app (repackaging).** The same app name and function appears with and without the implant; distribution sits outside official stores. | 3, 6-7 | 1 / parked malware corpus | No: no mobile handling anywhere in the roadmap. | For any APK hash: store package name and signing-certificate digest from a sandbox or VirusTotal file report (VT's Android section; check which fields the free API returns before building). Flag "same package name, different signer" across sightings as likely repackaging. | Medium: a solid, hard-to-forge mobile pivot (see doc 2 for the signer pivot). |
| **Explicit alternative hypothesis with rebuttal.** The report states the main rival explanation and why it fails. | 8-9 | 9 (hypotheses board) | Yes: "Hypotheses board: an analysis-of-competing-hypotheses matrix per case". | Nothing new. Use this report as a teaching fixture: one rival hypothesis, rebutted by assumption ("an opposing force would not adopt enemy software"), not by evidence. The board should label that rebuttal "assumption", not "evidence". | Low: confirms the planned design. |
| **Report revisions.** The PDF carries "updated" banner text and a changed claim. | 1-2 | 2 (document records) / 9 (Reporting tab) | No: document records carry title, publisher, date and TLP, but no revision. | Add `updated_date` and `revision_note` to the document record. Claims point to the document version; a re-ingested newer version that changes a claim marks the old claim "superseded". | Medium: vendor reports do get revised, and profiles should not keep the old wording. |
| **Targeting inferred from lure language and population data.** | 8-9 | 9 (Victims tab) | Partly: victimology heatmap with base-rate column exists; "inferred" versus "observed" targeting is not split. | Victim and targeting rows carry `basis` (observed victim, leak-site claim, inferred from lure language, inferred from lure filename, inferred from hard-coded target IP geolocation). Inferred rows are drawn differently and never feed counts. | Medium: stops inference leaking into victim statistics. Used again in doc 2, p11. |
| **Intent and victimology as attribution evidence (cui bono).** | 2, 10-11 | 9 (evidence classes) | Yes: evidence classes include "victimology" and "external vendor assessment". | Tag such items victimology/intent and keep the rule that one class never makes "likely". | Low: already covered. |

---

## 2. Trend Micro: New MuddyWater Activities Uncovered

- File: webfetch-1794439405030-6dberl.pdf
- Title: "New MuddyWater Activities Uncovered: Threat Actors Used Multi-Stage
  Backdoors, New Post-Exploitation Tools, Android Malware, and More"
- Authors / publisher: Daniel Lunghi and Jaromir Horejsi, Trend Micro Research
- Date: no publication date printed. The content runs to May 2019 and the
  copyright line is 2019 (so published mid-2019).
- Pages: 28
- Copyright: "©2019 by Trend Micro, Incorporated. All rights reserved." (p28)

**Summary.** Spear-phishing sent from compromised legitimate government and
university mailboxes, so SPF passes (p3), delivers a multi-stage PowerShell
backdoor. The C2 is GUID-polled, works through PHP endpoints and uses a
hard-coded token (pp4-5). A table charts delivery methods, dropped file types
and final payloads per discovery month (p6). Other content: a table of
open-source post-exploitation tools (p9), including a LaZagne build patched to
drop the backdoor; four Android families linked to the group (pp10-11);
deliberate false flags (pp12-13); validation of a Telegram leak of the
group's C2 backend (pp14-15); and C2 habits (p16). The C2 habits are direct-IP
C2, compromised WordPress sites used as a proxy tier, uncommon ports, and
servers that are up for hours and then move to a new port. Long IOC
appendices (pp18-27) give hashes by file category with detection names, then
C2 URLs. Some URLs are marked "(abused)" for a legitimate JSON-storage service.

| Idea | Page | Phase | In ROADMAP? | Deterministic build | Value |
|---|---|---|---|---|---|
| **IOC tables with row context.** Hash tables carry a section heading ("…of the Android malware variants", "…of the patched LaZagne") and a detection-name column. URL rows carry an "(abused)" note. | 18-27 | 2 (extract) | Partly: TTP tables keep row context ("captures the whole row as a TTP record"); plain IOC tables keep none. | Reuse the TTP table logic for IOC tables: when a block's rows hold hashes, URLs or IPs, store the nearest heading as `section_label`, the other cells as `row_note`, and the tokens "abused" or "legitimate" as a flag. Saved with each sighting. | High: one change, and every IOC from a report keeps its stated role (family, platform, abused service). |
| **Hashes split across lines and pages.** In the PDF text layer every SHA-256 in these tables wraps onto two lines. One row is split across a page break (pp20-21). | 18-24 | 2 (extract, PDF route) | No: the PDF notes cover TTP columns only. | Before matching: join hex runs broken by a newline (and a page break) when the halves add up to 32, 40 or 64 hex characters inside a table-shaped block. Keep a "repaired" flag. Use pp18-24 of this file as an offline fixture. | High: without this, hash extraction from vendor PDFs silently loses rows. |
| **Patched commodity tool.** The LaZagne build is modified to drop the backdoor, with an idiosyncratic typo in the added function name. | 9 | 9 (stop-list) | Partly: stop-list tier "commodity or open source … counts for nothing". | Stop-list match by tool name or detection name does not suppress a sample whose hash is not a known public release build: check CIRCL hashlookup, NSRL, or the GitHub release asset hashes. Label it "modified commodity tool: counts as tooling evidence". | Medium-High: closes a real hole in the planned stop-list. |
| **APK signing certificate as a pivot.** Two Android families were linked by a shared signing certificate. | 11 | 6 (pivot catalogue) / parked malware corpus | No: the pivot catalogue lists TLS certificate, sample and others, but not APK signer. | Add the artifact type "APK signing certificate (SHA-256)" to the pivot catalogue: lossless, hard to forge without the key, free route = none known (VT search is paid), paid route as a deep link. Record the trap that debug and test keys are shared. | Medium: mobile is a gap the roadmap does not cover at all. |
| **Cross-platform infrastructure link.** An Android C2 IP was also the second-stage server of a Windows campaign; an Android RAT's dynamic-DNS C2 was shared with Windows samples. | 10-11 | 6 | Yes: sample-to-infrastructure pivots and "VT relationship walks" are planned. | Nothing new. Make sure the sample table has a `platform` field so the grid can show "same C2, different platform" as its own row. | Low-Medium. |
| **Code-structure similarity through command tables.** Two Android families share a command-constant layout (opcode name and integer tables). | 10-11 | parked malware corpus | No. | Store parsed command and opcode sets per sample (from configs or reports, entered by hand). Jaccard over sets, shown as a "code" evidence class item. No sample handling on the host. | Low: needs analysis in the VM first. |
| **False-flag artefacts.** Unused variables holding Chinese text or Hebrew quotes; Cyrillic document metadata and a Cyrillic PDB path user name, all in one cluster. | 12-13 | 9 (artefact registry, hypotheses board) | Partly: "Forgeability label per artefact type" and "deliberate imitation" always present. | Consistency rule: if one cluster's language artefacts (doc `lastModifiedBy` and `creator`, PDB path user segment, embedded strings) point to two or more language families, raise "contradictory language artefacts: possible false flag" and add the item to the "deliberate imitation" column. Language detection by Unicode script range only. | Medium: deterministic, and it would have fired on exactly this case. |
| **Leak validation method.** The leak was corroborated by C2 traffic to listed victims, independently found backend builds matching leaked screenshots (version banner and compile dates), and an earlier VT upload whose filename matched a named person. | 14-15 | 5 (Telegram collection) / 9 | No: the roadmap collects Telegram but has no leak-claim record. | A "leak claim" record (channel, date, contents summary, claimed actor) with corroboration items. Each item is classed (independent sample, infrastructure overlap, victim overlap, timing) and marked confirmed or unconfirmed. The claim's status is computed from the items. Never stores the leaked personal data itself (data policy). | Medium-High: actor leaks are frequent and easy to over-trust. |
| **Short-lived C2 on rotating uncommon ports.** | 16 | 1 (verdict lines) / 6 | No. | Store observations as ip:port with first and last seen. Verdict-line rule: "not seen by Shodan/InternetDB" on an IP from a report of short-lived C2 is shown as "no observation", not "clean". | Medium: ties to Heuer's absence-of-evidence point (doc 4). |
| **Two-tier C2: compromised WordPress sites as proxies.** | 16 | 6 | Yes: "'likely compromised third party' … left out of actor overlap scores". | Add an infrastructure `role` field (proxy or relay, final C2, staging, abused service) beside the IP-type step. A role set from report notes ("compromised", "abused") comes from the row context above. | Low-Medium. |
| **Brand-impersonating C2 hostnames on dynamic DNS.** Look-alike tokens for big brands sit under free dynamic-DNS apexes. | 25-26 | 6 / 9 (Infrastructure tab "naming patterns") | Partly: dynamic-DNS list for suppression; "naming patterns" in profiles. | Naming-pattern features per hostname: dynamic-DNS apex (from the existing list), brand token present (small brand list, edit distance from rapidfuzz once approved), digit-for-letter swaps. Aggregate per actor. | Low-Medium. |
| **Delivery-evolution table:** date, delivery method, dropped file types, final payload. | 6 | 9 (Capability tab) | Partly: "first seen using" timeline and yearly drift per actor. | Capability tab section "delivery chains" (date, initial vector, intermediate file types, final payload, source document), hand-entered or from Phase 11 proposals. | Medium: shows drift at a glance. |
| **Phishing from compromised legitimate accounts.** The headers show SPF pass from the real domain. | 3 | 1 or 2 (new small tool) | No: no e-mail header handling in the roadmap. | Paste a raw header or an .eml file and parse it with the stdlib `email` module: Received chain hops and IPs, Authentication-Results, From/Return-Path/Reply-To mismatch. Verdict line, for example "SPF/DMARC pass from sender domain: likely compromised account, not spoofing". The IPs and domains go to enrichment. The file is not opened beyond the headers. | Medium-High: a daily analyst task, zero dependencies. |
| **Adversary reacts to disclosure.** The encoding alphabet changed within a week of the vendor's previous report. | 17 | 9 (timeline) | No. | Plot publication dates of reports about an actor on the actor timeline, so TTP changes just after a disclosure are visible. Link the change to the faster decay of published indicators. | Low. |
| **Gophish used by the actor before.** | 3 | 6 (default-signature library) | Partly: phishing kits via IOK rules. | Add phishing-framework defaults (Gophish's tracking parameter and header defaults; verify by hand) to the signature library as "tool default". | Low. |

---

## 3. Lookout: Technical Analysis of Pegasus Spyware

- File: webfetch-1794439415523-ytbl8s.pdf
- Title: "Technical Analysis of Pegasus Spyware: An Investigation Into Highly
  Sophisticated Espionage Software"
- Publisher: Lookout (with Citizen Lab credited), six named Lookout authors (p34)
- Date: not printed. The disclosure timeline ends with the iOS 9.3.5 patch on
  2016-08-25 (p6), so late August 2016 or later.
- Pages: 35
- Copyright: no copyright or licence notice found on any page.

**Summary.** Covers the one-click iOS chain ("Trident": a WebKit memory
corruption, a kernel info leak that defeats KASLR, and a kernel memory
corruption that jailbreaks the device). It also covers the three-stage
loader with per-download encryption, and persistence by replacing a system
daemon with the signed `jsc` binary (pp7-14). Anti-forensics include
disabling updates, removing other jailbreaks, and self-destruct (pp14-19).
The data theft covers calendar, contacts, location, keychain, Wi-Fi and
router passwords, and per-app interception through injected dylibs for
WhatsApp, Viber, Skype and Telegram (pp19-30). A fallback C2 path takes
commands in SMS made to look like two-factor codes from big brands (pp17-18).
The appendices give the planted root CA certificate, whose subject strings
are placeholder-like (pp32-33), and jailbreak IOC file paths (p33). Several
pages introduce a code listing that is missing from the PDF (pp13, 15, 17),
so the source itself has gaps.

| Idea | Page | Phase | In ROADMAP? | Deterministic build | Value |
|---|---|---|---|---|---|
| **Mobile forensic indicator types**: on-device file paths, masquerading process and daemon names, LaunchDaemon plist names, a replaced system binary, an installed root CA. | 8, 12-14, 19, 33 | 2 (extract) / 9 | No: types are IP, domain, URL, hashes, e-mail, CVE, ATT&CK IDs. | Add `file_path` (Unix and Windows path regex, with a minimum depth to cut noise) and `process_name` (only from tables or lists under a heading containing "process" or "daemon") as extracted types. They are stored as sightings and never sent to enrichment vendors. Searchable in the corpus. | Medium: lets mobile and host reports be searched and compared; matches MVT-style IOC sets. |
| **Non-file hash strings.** Notification IDs are 56-hex SHA-224 digests. | 26, 28-29 | 2 (extract) | No: "MD5/SHA-1/SHA-256" only. | Recognise 56- and 128-hex strings as "other digest", not file hashes. Never forward them to VirusTotal. Keep them as sightings. | Low-Medium: prevents wasted quota and false classification. |
| **SMS command templates mimicking 2FA messages.** Brand verification-code wording with a URL and an encoded parameter; the command ID is carried in a digit. | 17-18 | 3 / 7 (brand abuse), 9 | No. | Keep a small regex library of known spyware SMS lure templates (from reports, cited) to match against pasted message text in the extraction tool. Label it "matches published spyware SMS template", nothing more. | Low-Medium: niche but deterministic. |
| **Exploit chain as an entity.** Three CVEs used in order (browser RCE, info leak, kernel LPE) under one nickname. | 3, 8, 11 | 2 (vuln intel) | Partly: "CVE alias table (nickname to CVE)"; view 11 "Probable zero-days". | `exploit_chains` table: name, ordered CVE list with stage role, actor or vendor, first-seen in the wild, source. The CVE page shows "part of chain X (stage 2 of 3)". Project Zero's ITW sheet (already noted) can seed it. | Medium: chains matter for patch priority; one weak link breaks the chain. |
| **Disclosure milestones.** Found by NGO, vendor informed, patch released, publication. | 6 | 2 (CVE page timeline) | Partly: the Previdian idea "timeline (reserved, published, listed)". | Add optional "discovered in the wild" and "reported to vendor" milestones with source to the planned CVE timeline. | Low-Medium. |
| **Commercial surveillance vendor as an actor type.** NSO is a company selling to governments, not a state group. | 3-5, 31 | 9 (profiles) | No: the list filters "state, crime, hacktivist, ransomware". | Add `type = commercial surveillance vendor`, with "customer" links to state clusters as claims. Vendor, customer and operator are kept apart so attribution to the vendor is not read as attribution to the operator. | Medium: needed for Pegasus, Predator, FinFisher and Hacking Team reporting. |
| **Placeholder certificate subjects** ("…Private CA", "My Super Company"-style org names). | 32 | 6 (default-signature library) | Partly: certificate subject quirks and defaults like "AsyncRAT Server". | Add a "placeholder subject" list (OpenSSL defaults, test-company strings) as a feature: rare enough to pivot on as one term of a conjunction, never alone. | Low-Medium. |
| **NGO mobile-forensics IOC sets as a source.** Citizen Lab and Amnesty Tech publish STIX2 IOC bundles for mercenary spyware. | 3, 14, 34 | 9 (sources) / 4 (Citizen Lab feed already listed) | Partly: Citizen Lab is in the Phase 4 starter feed list. | Register the Amnesty Tech investigations repository and Citizen Lab IOC repos in the source registry. Check each licence (MVT uses its own licence; read it before reuse). Ingest STIX2 indicators as documents with sightings. | Medium: the main public source of mobile spyware indicators. |
| **Report structure for capability write-ups**: exploit chain, then install and persistence, then anti-forensics, then data theft per app, then appendices. | 2 | 10 / 9 (report builder) | No (report builder named only). | A "malware capability" report template in the report builder with these fixed sections, each holding claims with sources. | Low. |

---

## 4. Richards J. Heuer Jr.: Psychology of Intelligence Analysis

- File: webfetch-1794442341346-r71vul.pdf
- Identification: not an IALEIA or UK Home Office guide. It is Richards J.
  Heuer, Jr., *Psychology of Intelligence Analysis*, Center for the Study of
  Intelligence, Central Intelligence Agency, 1999 (pp1, 3, 5; ISBN
  1 929667-00-0). Foreword by Douglas MacEachin and introduction by Jack Davis.
- Pages: 214 (front matter pp1-28, chapters 1-14 on pp29-212 (printed 1-184),
  back cover p214). Blank: pp2, 4, 6, 10, 14, 28, 78, 92, 142, 213.
- Text layer: the Read tool returned a text layer for every content page;
  only the covers (pp1, 214) are image-only. "No extractable text" should be
  re-checked: the extractor that said so may have failed on this file. That
  matters for the Phase 2 pypdf route.
- Copyright: p5 says the PDF may be copied by US Government agencies for
  government purposes and by non-governmental organisations for educational
  purposes, "may be subject to copyright restriction", and may not be copied
  for any commercial purpose. Fine for the operator's own study. Do not ship
  text from it in the repository; paraphrase and cite.

**Summary.** Fourteen chapters in four parts. Part I covers perception,
memory and mind-sets (we see what we expect; mind-sets form fast and resist
change; working memory holds about seven items). Part II gives the tools:
strategies for judgment, the limited value of more information,
open-mindedness techniques, problem structuring, and the eight-step Analysis
of Competing Hypotheses. Part III covers cognitive biases in evidence,
causation, probability and hindsight. Part IV is an analyst checklist and
management advice. Most of its method is already in the roadmap's Phase 9
rigor block (ACH board, ICD 203 language, assumptions as records). The
additions below are the pieces the roadmap does not yet have.

| Idea | Page | Phase | In ROADMAP? | Deterministic build | Value |
|---|---|---|---|---|---|
| **Judgment register and calibration scoring.** People misremember their past estimates after the outcome. The remedy is stating judgments numerically and comparing them with outcomes routinely. | 191-193 (163-165), 208 (180) | 9 (rigor) and 2 (self-scoring now) | No: "a 'what changed and why' note on every edit" exists; no outcome scoring. | `judgments` table: statement, probability or band, resolution criterion, resolve-by date, created (immutable), outcome, resolved date. Brier score and a calibration chart per analyst and per category. Apply it first to the toolkit's own Phase 2 outputs: did "Likely next" or P2 CVEs reach any exploited list within 30, 60 or 90 days? The data is already stored (first-seen-exploited dates). | High: no hindsight bias in the record, and it measures whether the heat score and views work. |
| **Indicators that would change the judgment (ACH step 8).** Each conclusion lists what to watch for that would change the probabilities. | 135-136 (107-108), 205 (177) | 9 (cases, board) + 5 (alert inbox) | No: no "milestones" or "indicators to watch" item. | Each hypothesis or judgment gets a list of watch items, each optionally bound to a machine rule: a watchlist selector, a saved hunt, a CVE entering an exploited list, a new leak-site victim in a sector. A hit lands in the alert inbox with a link back to the judgment and a "re-assess" prompt. | High: ties analysis to the collection already planned. |
| **Unproven versus disproved; expected observability.** Do not reject a hypothesis for lack of evidence if, were it true, you would not expect to see evidence (deception, short-lived infrastructure). | 126 (98), 127 (99), 136-137 (108-109) | 9 (hypotheses board) | Partly: the board ranks by inconsistency; there is no hypothesis state or expected-visibility field. | Hypothesis state enum: open, weakened, disproved (needs a cited inconsistent item). Evidence items get `expected_if_true` (yes, no, unknown) and `observed` (yes, no). "Expected but not observed" rows are negative evidence. The board refuses "disproved" when the only support is absence and `expected_if_true` is unknown. Prompt on "no evidence" text: "If true, would we expect to see it?" | High: directly counters the biggest failure mode the book describes. |
| **Report checklist and lint.** Alternatives considered and why rejected; numeric odds in parentheses after verbal terms; a time frame on every likelihood; assumptions listed; indicators listed. | 134-135 (106-107), 180-184 (152-156), 201-205 (173-177), 209-211 (181-183) | 9 (report builder, estimative builder) | Partly: "likelihood from the seven ICD 203 terms" and a check against mixing likelihood and confidence. | Report builder lint that blocks "final" until: (1) an alternatives section is non-empty; (2) every ICD 203 term renders its numeric band; (3) every likelihood has a time window ("at this time" without a date fails); (4) at least one assumption and one watch item are linked. Pure template checks. | High: cheap, and it enforces the tradecraft rather than only describing it. |
| **Show what was not checked.** Mechanics given a fault tree with branches removed did not account for the missing branches. Gaps drop out of mind. | 147-148 (119-120) | 1 (verdict card), 7 (results) | Partly: Phase 7 marks blocked sites; the enrichment verdict has no gap list. | Verdict card footer: "Not checked: <source> (no key / quota / error / not applicable)". The verdict line is suffixed "partial coverage" when keyed sources failed. | Medium-High: tiny change, real effect on over-confident verdicts. |
| **Discredited evidence keeps its influence.** Impressions persist after their basis is withdrawn. | 152-154 (124-126) | 2 (corpus), 9 (cases) | No: no retraction handling. | When a document, sighting or source is marked retracted or false-positive, list every case item, judgment, profile claim and verdict that cites it (sightings already link to documents). Put a banner on each until an analyst re-confirms or removes it. | Medium-High: provenance links are already planned; this uses them backwards. |
| **Anchoring on predecessors' judgments.** | 178-180 (150-152) | 9 / 2 | No. | Optional "blind re-estimate" mode: when re-reviewing a profile rating or case judgment, the analyst enters a new value before the old one is revealed; both are stored. | Low-Medium: easy UI rule; benefit is hard to measure. |
| **Diagnosticity, extra cell scales (importance, ease of deception), and keeping deleted evidence.** | 128-131 (100-103) | 9 (board) | Partly: "evidence that fits every hypothesis greyed out as non-diagnostic", forgeability labels. | Board cells carry consistency (C, I, N/A, or a probability), and each evidence row carries weight and the forgeability label. Rows removed as non-diagnostic move to a "considered and set aside" list, not deleted. | Medium: closes the audit trail. |
| **Linchpin assumptions and sensitivity** (MacEachin's drivers and linchpins; Heuer's sensitivity analysis). | 20 (xviii), 97 (69), 133-134 (105-106) | 9 | Yes: "a view of which single item would change the ranking if wrong", "assumptions stored as records". | Nothing new. Link assumptions to the board so flipping an assumption re-ranks the hypotheses live. | Low: covered. |
| **Weighted scoring with sensitivity** (multiattribute utility worked example). | 118-121 (90-93) | 2 (heat score) | Partly: weights for the heat score are in the runbook. | A "what if" panel on the heat score: change a weight and see which top-N CVEs enter or leave. Same for the P1-P5 rule thresholds. | Low-Medium. |
| **Scenario probability is a product; added detail lowers it.** | 184-185 (156-157) | 9 (scenarios / estimative builder) | No. | When a judgment is written as a chain of steps, each with a probability, show the product beside the analyst's overall figure and warn if the overall exceeds the weakest step. | Low-Medium. |
| **Base rates and source hit rates.** An 80%-accurate identification in an 85/15 population is right only 41% of the time. | 185-187 (157-159) | 5 (source registry) / 1 | Partly: Admiralty rating set by hand; Kraven "hunt quality score". | Per source, compute observed precision from outcomes the toolkit records (a "malicious" verdict later confirmed or overturned). Show it beside the hand-set Admiralty letter, never replacing it. | Medium: needs the judgment register first. |
| **Contingency table, not just positive cases (illusory correlation).** | 168-174 (140-146) | 9 (behaviour pivoting) | Yes in spirit: "victimology heatmap with a base-rate column", co-occurrence "lift". | Wherever the UI claims "X goes with Y" (actor and sector, CVE and ransomware), show all four cells or say which cells are unknown. | Low-Medium. |
| **Surprise log.** A run of small surprises signals the model is wrong. | 101-102 (73-74), 205 (177) | 9 (cases) | No. | Case note type "surprise", counted on the case header; three or more opens a "re-examine from the ground up" task. | Low-Medium. |
| **Periodic ground-up re-examination** against incremental drift. | 44 (16), 211 (183) | 9 | Partly: "a 'last reviewed' date and review interval per profile". | Extend the review interval to cases and standing judgments (the register above). | Low: small extension. |
| **Fact versus assessment** (Gates's standard of keeping what is known apart from what is believed). | 18 (xvi) | 9 (claims) | Partly: claim types exist in the cti-skills claim-extraction skill, not in the roadmap's data model. | Every claim row gets `kind` (observed fact, reported fact, analyst assessment), shown with a distinct style in reports. | Medium. |
| **Default hypotheses: deception, and an uncoordinated or accidental cause** (bias toward seeing central direction). | 126 (98), 159-160 (131-132), 202 (174) | 9 (board) | Partly: "'unrelated actor using shared tooling' and 'deliberate imitation' always present". | Add "denial and deception" and "uncoordinated / coincidence" to the always-present hypotheses, removable only with a recorded reason. | Low-Medium. |

---

## Ranked top 10 across the four documents

1. **Judgment register with calibration scoring** (Heuer pp191-193, 208).
   Store numeric judgments immutably, resolve them, score them. Start with
   the toolkit's own Phase 2 views: did "Likely next" or P2 CVEs become
   exploited? Not in the roadmap; the data already exists.
2. **IOC-table row context and split-hash repair in the Phase 2 extractor**
   (MuddyWater pp18-27). Keep the section label, detection name and
   "(abused)" notes per IOC. Re-join hashes wrapped across lines and page
   breaks. Use this PDF as a fixture. Relevant to work in progress now.
3. **"Indicators that would change the judgment" bound to alerts** (Heuer
   step 8, pp135-136, 205). Watch items on every hypothesis, wired to
   watchlists, saved hunts and exploited-list changes through the Phase 5
   alert inbox.
4. **Unproven versus disproved, expected observability, negative evidence on
   the hypotheses board** (Heuer pp126-127, 136-137; MuddyWater p16
   short-lived C2). Absence of evidence counts only when evidence was
   expected.
5. **Report-builder lint** (Heuer pp134-135, 180-184, 201-211). Alternatives
   section, numeric band beside each ICD 203 term, a time window on every
   likelihood, linked assumptions and watch items.
6. **Mobile and APK support: package name, signing-certificate digest,
   signer pivot, repackaging flag** (MuddyWater p11; CrowdStrike pp3-7).
   The roadmap has no mobile handling at all.
7. **"Not checked" coverage-gap footer on verdict cards** (Heuer pp147-148).
   A tiny change that prevents verdicts reading as complete when keyed
   sources failed.
8. **"Modified commodity tool" rule for the stop-list** (MuddyWater p9). A
   name match does not discount a sample whose hash is not a known public
   build.
9. **Retraction propagation** (Heuer pp152-154). A retracted source or
   sighting lists and flags everything that relied on it.
10. **Leak-claim record with classed corroboration** (MuddyWater pp14-15).
    Ready for Phase 5 Telegram collection, where actor leaks will show up.

Next in line: e-mail header parser (MuddyWater p3); false-flag
language-consistency check (MuddyWater pp12-13); commercial surveillance
vendor actor type and NGO mobile IOC bundles (Pegasus pp3-5, 31); exploit-
chain entity (Pegasus pp3, 8, 11); document revision tracking (CrowdStrike
pp1-2); artefact-timestamp development window (CrowdStrike pp6-7).

## Pages not read, and why

- None. All pages of all four documents were read: CrowdStrike 1-11,
  Trend Micro 1-28, Lookout 1-35, Heuer 1-214 (288 pages).
- Blank pages, nothing to read: Heuer pp2, 4, 6, 10, 14, 28, 78, 92, 142,
  213. Lookout p35 is a logo-only back cover.
- Image-only pages, read visually: Heuer covers pp1 and 214. All figures and
  code screenshots in the three vendor reports were read as rendered images.
- Gaps in the sources themselves, not in the reading: Lookout pp13, 15 and 17
  introduce code or file lists that are missing from the PDF. The Trend
  Micro IOC tables wrap hashes over two lines and split one row across
  pp20-21.
- Method note: the Read tool's `pages` parameter failed (no pdftoppm
  installed), so each PDF was read whole in one call, which rendered every
  page.
