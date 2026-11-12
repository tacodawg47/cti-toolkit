# PDF review: threat hunting, kill chains, CTI program guides

Reviewed 2026-11-11 against ROADMAP.md (v3, last updated 2026-11-10). Read-only;
nothing executed or fetched. Page numbers are PDF page numbers; where the
printed page number differs it is given as "printed p.N". Quotes are kept under
15 words; everything else is paraphrase.

Scope reminder for every "how it would be built" cell: the toolkit is local and
has no access to the operator's SIEM or endpoint logs. Anything about hunting
*inside* a network is built as records, templates and exports (Phase 8 Sigma /
KQL) that the operator runs elsewhere; the toolkit never runs those hunts
itself. Infrastructure hunts (Phase 6) are the exception and already planned.

---

## 1. Detecting the Unknown: A Guide to Threat Hunting (v2.0)

| Field | Value |
|---|---|
| File | webfetch-1794439170328-h7v83y.pdf |
| Author / publisher | Home Office Cyber Security Programme (UK), funded by the Cabinet Office National Cyber Security Programme (p.45); cover carries Digital, Data & Technology and Cyber Security Programme marks (p.1) |
| Date | March 2019, v2.0 (p.1); engagements Oct 2018 to Jan 2019 (p.44) |
| Pages | 50 (p.2 and p.49 blank) |
| Licence | Crown copyright 2019, Open Government Licence v3.0 "except where otherwise stated"; third-party material needs the holder's permission (p.50). OGL allows reuse with attribution, so the CMM table and metrics table can be reproduced with an OGL attribution line. Embedded third-party figures (Pyramid of Pain, Sqrrl Hunting Loop, Diamond Model, ATT&CK tactic text) are not covered by OGL. |

**Summary.** A UK government guide for SOCs on standing up threat hunting.
Defines hunting as proactive, iterative, human-centric search for threats that
evaded controls (p.8). Offers a five-level Threat Hunting Capability Maturity
Model across People / Process / Tools (pp.10-13), adopts Sqrrl's four-stage
Hunting Loop (create hypotheses, investigate, uncover patterns, inform and
enrich analytics; p.17) and extends it with prioritisation, workflow,
knowledge repository and extra outcomes (pp.21-22). Gives three worked
hypothesis types (actor, tool, technique; p.18), Crown Jewels Analysis steps
(p.18), hunting techniques (search, clustering, grouping, stack counting, ML;
p.20), an Epic/Story/Kanban hunt tracker (pp.23-24), ATT&CK-driven data
visibility tracking with a data-source table and a 1-5 heatmap worked example
(pp.27-31), investment advice (people before tools, FOSS first; pp.32-33),
example hunt metrics (p.34), and UK-government policy recommendations
(pp.35-43, not relevant to the toolkit). Appendix II names two companion
guides, one of which ("Controlling Your Exposure – A Guide to Digital Risk and
Intelligence") is directly relevant to Phase 3 (p.45).

| # | Idea | Where | Phase | Already in ROADMAP? | How it would be built (deterministic) | Value |
|---|---|---|---|---|---|---|
| 1.1 | **Hunt hypothesis record** with type (actor / tool / technique), basis (CTI / situational awareness / domain expertise), a testable statement ("if X is present we would see Y in data Z"), the data needed, and an ATT&CK tactic as the grouping "epic". | p.17-18 (box "Example Hypotheses"), p.23 | 6 (Hunts sub-tab), 9 (hunting package) | Partly. Phase 6 has "Hunts (saved pivots that re-run on a schedule)" and Phase 9 a "hunting package per actor"; neither has a hypothesis object. | Table `hunt_hypothesis(id, type, basis, statement, actor_id?, technique_ids, tactic, required_data_components, source_refs, status, created, retired_reason)`. Statement is free text from a template with three slots. For Phase 6 the hypothesis links to one or more saved pivots; for internal hunts it links to exported Sigma/KQL. | High: gives the planned Hunts tab a reason-for-existing per hunt and makes hunts reviewable. |
| 1.2 | **Hypothesis lifecycle and hunt-run lifecycle**: hypothesis Initial → Development → Production → Retired; hunt run To-Do → In-Progress → Outcome, with outcome Malicious / Non-malicious / Not proven. | p.23-24 (Figure 8) | 6, 9 | No. Phase 6 saved pivots have "first-used date, a last-yield date, and a time-to-live" but no states. | Two enum columns plus a `hunt_run(hypothesis_id, started, ended, outcome, notes)` table; a Kanban-style page is just a GROUP BY status rendered as columns (HTMX, no JS framework). | High: cheap and turns ad-hoc pivots into a tracked practice. |
| 1.3 | **"Not proven" is not "absent"**: an unproven hunt must record why (data missing, tooling missing, analyst missed it) and be re-tested later; side findings (risky configs, logging blind spots) go to vulnerability management. | p.8, p.20 (3.3.3), p.21-22 (Extended Hunting Loop) | 6, 9 | No (the Phase 6 outcome ladder covers monitor/detect/hunt/block/share/notify, not a "gap" or "retest" outcome). | On `hunt_run`: `gap_reason` enum (no data, insufficient data, tool limit, analyst), `retest_after` date, `side_findings` text. The scheduler (Phase 5) lists due re-tests in the alert inbox. | Medium-High: a rigor rule that matches the toolkit's evidence-gate style. |
| 1.4 | **ATT&CK telemetry visibility inventory and heatmap**: the operator records which data sources they collect and how widely; each technique gets a 1-5 visibility score; rendered as a Navigator layer. Five-level scale: little or none; moderate variety from key areas; high variety from key areas; moderate variety across the estate; high variety across the estate. | p.28-31 (heatmap box p.31) | 9 (Defend tab, "my threat landscape"), 8 (layer export) | Partly. Phase 9 plans "detection-coverage gap per actor" via rules and "the data sources needed to detect the actor"; no operator telemetry inventory or visibility score. | Local, git-ignored `telemetry_inventory(data_component_id, variety: moderate/high, scope: key_areas/estate)`. Per technique, take the ATT&CK "detects" relationships from the local STIX bundle (data components, or v18 detection strategies → analytics → log sources) and score by the lowest-covered required component, using the 5-level rule. Output a Navigator JSON layer and an HTML matrix. | High: joins with actor profiles to say which of a pinned actor's techniques the operator could not see at all. |
| 1.5 | **Data-source shopping list**: rank data sources by how many techniques they help detect (the doc's Table 2 had process monitoring first at 155 of 223 techniques); weight by pinned actors. | p.30 (Table 2) | 9 | No. | One SQL count over the local ATT&CK bundle (data component → technique), optionally restricted to techniques of pinned actors or of the current case. The doc's numbers are from an old ATT&CK version; compute fresh. | Medium: a useful planning view at near-zero cost once the bundle is local. |
| 1.6 | **Hypothesis skeletons generated from an actor profile** (the actor-type hypothesis on p.18 says: if this actor is present we should see several of its known techniques along its known paths). | p.18 | 9 (hunting package) | Partly: "hunting package per actor (non-commodity tools ..., procedure idioms, tagged rules, CVEs ...)". No hypothesis sentences. | For each non-commodity technique of the actor (stop-list applied), fill a fixed template: "If {actor} is present, expect {procedure sentence} visible in {data component}", with the source citation of the procedure. Analyst ticks which ones become hypotheses (1.1). | Medium: turns the planned hunting package into actionable hunts. |
| 1.7 | **Crown Jewels Analysis** steps: core missions → assets and information they rely on → network assets used → attack graphs and severity. People and processes count as assets. | p.18 (box) | 2 (SSVC mission prevalence), 9 | Partly: the technology watchlist and "derive mission prevalence from the technology watchlist". No asset/mission register. | Git-ignored `asset_register(name, mission, value H/M/L, technologies → watchlist rows, owner, notes)`. Feeds SSVC mission prevalence and the gap matrix (5.7). Attack graphs left out (no internal data). | Medium (see 5.7, same build). |
| 1.8 | **Hunt metrics** for a dashboard: hypotheses per ATT&CK tactic, hunts per tactic, incidents per tactic, share of hunts that produced a new detection rule, true/false positive rates of hunt-derived rules, dwell time proactive vs reactive, data coverage %. | p.34 (Table 3) | 6, 8 | Partly: Phase 6 "Hunt quality score" (share of returned hosts already known bad). The other metrics are not planned. | GROUP BY over `hunt_hypothesis`/`hunt_run`; "produced a rule" = a Phase 8 export linked to the run. Dwell time is out of scope (no incident data). | Medium: cheap once 1.1-1.2 exist. |
| 1.9 | **Stack counting / grouping as a generic table action**: frequency analysis with least-common values first; grouping = values that co-occur inside a time window. | p.20 (box "Threat Hunting Techniques") | 5, 6, 7 | Partly: Phase 6 counts shares per attribute and the "created within 5 minutes" conjunction. No generic "stack this column" view over local data. | A reusable SQL helper `stack(table, column, where)` returning value, count, first/last seen, ascending; a button on any corpus table (sightings, collected posts, pDNS history). | Medium: simple and broadly useful for the collector corpus. |
| 1.10 | **Pyramid of Pain level** on indicators and exports: hash (trivial), IP (easy), domain (simple), network/host artefact (annoying), tool (challenging), TTP (tough). | p.9 (Figure 3) | 1, 6, 8 | No (Phase 9 has a forgeability label for artefacts; Phase 6 has decay half-lives per type; neither names PoP). | Static map from indicator type to PoP level; each export package shows a PoP breakdown ("9 of 10 items are hashes or IPs"). | Low-Medium: cheap labelling, mostly communicative. |
| 1.11 | **Periodic relevance review of automated analytics** and retirement of ones that test for TTPs no longer possible. | p.21 (Recommendation 4) | 6, 8 | Partly: saved pivots have TTL and last-yield date. Phase 8 detection templates have no review date. | `last_reviewed`, `review_interval`, `retired_reason` on saved hunts and exported rules; due reviews go to the alert inbox. | Low-Medium. |
| 1.12 | **Threat Hunting Capability Maturity Model** (Initial, Managed, Defined, Quantitatively Managed, Optimising × People / Process / Tools). Process row moves from IOCs at the bottom of the pyramid (L2) to the middle (L3) to TTPs (L4). | p.10-13 (Figure 4 p.13) | 10 (docs) | No. | Docs page or runbook only; optionally a self-assessment form. OGL permits reproducing the table with attribution. | Low for a solo tool; useful as a learning reference for the operator. |
| 1.13 | **Hunting needs operational CTI** (actor TTPs); tactical CTI should be auto-matched; strategic CTI is for business decisions. | p.25-26 | 9, 10 | Yes in substance (leadership vs ops views; TTP extraction). | None needed. | Low. |
| 1.14 | **Follow-up reading**: companion NCSP guide "Controlling Your Exposure – A Guide to Digital Risk and Intelligence" (and "Cyber Threat Intelligence – A Guide for Decision Makers and Analysts"). | p.45-46 | 3 | Not referenced. | Fetch and review when Phase 3 is built (needs approval; not fetched here). | Medium: likely the most Phase 3-relevant document in this series. |

---

## 2. The Unified Kill Chain (white paper)

| Field | Value |
|---|---|
| File | webfetch-1794439554156-lpuf2v.pdf |
| Author / publisher | Paul Pols, with thanks to Francisco Dominguez and Fox-IT (p.1); site UnifiedKillChain.com (p.18) |
| Date | Version 1.3, February 2023 (p.18); model first published December 2017 in the author's Executive Master's thesis on modelling APT28 attacks (p.5, p.6 footnote 2) |
| Pages | 18 (p.17 is an infographic, p.18 a back cover) |
| Licence | "Released under GNU GPL v2" (p.18). Under the roadmap rule (GPL: do not copy), use the phase names and order (facts) and write our own definitions; do not vendor the descriptions or graphics. |

**Summary.** The UKC merges Lockheed Martin's Cyber Kill Chain, ATT&CK and four
other models into 18 ordered attack phases (pp.1-6), refined through three
Fox-IT red-team case studies and APT28 reporting (p.5, Table 1 shows how each
source model's phases map). The phases fall into three loops: **In** (initial
foothold), **Through** (moving through the network to the target), **Out**
(acting on objectives) (pp.6-10). Key claims: attacks do not have to pass every
phase in order, phases can be skipped, repeated, or out of sequence, which
falsifies the CKC's "one mitigation breaks the chain" assumption (p.11, p.14);
defence should favour phases that occur most often or that are choke points on
the path to critical assets (p.11). Attack-specific and actor-specific kill
chains are built from the phases and compared (p.10). Comparison table of CKC
vs ATT&CK vs UKC coverage on p.12.

The 18 phases (names as in the paper, definitions paraphrased):

| # | Phase | Loop | Paraphrased meaning | Nearest ATT&CK (crosswalk to build) |
|---|---|---|---|---|
| 1 | Reconnaissance | In | Research and choose targets | TA0043 |
| 2 | Resource Development | In | Set up infrastructure, weaponise | TA0042 |
| 3 | Delivery | In | Get the weaponised object to the target | Initial Access (phishing, drive-by, supply chain techniques) |
| 4 | Social Engineering | In | Manipulate a person into an unsafe action | technique-level only (e.g. T1204 User Execution, phishing sub-techniques) |
| 5 | Exploitation | In | Exploit a vulnerability, often for code execution | technique-level (T1190, T1203, T1210, T1068 …) |
| 6 | Persistence | In | Keep a foothold on the system | TA0003 |
| 7 | Defense Evasion | In | Avoid detection or defences | TA0005 |
| 8 | Command & Control | In | Talk to compromised systems | TA0011 |
| 9 | Pivoting | Through | Tunnel through a controlled host to reach others | technique-level (T1090 Proxy, T1572 Protocol Tunneling) |
| 10 | Discovery | Through | Learn about the system and network | TA0007 |
| 11 | Privilege Escalation | Through | Gain higher permissions | TA0004 |
| 12 | Execution | Through | Run attacker code locally or remotely | TA0002 |
| 13 | Credential Access | Through | Obtain or control credentials | TA0006 |
| 14 | Lateral Movement | Through | Access and control other systems | TA0008 |
| 15 | Collection | Out | Find and gather target data | TA0009 |
| 16 | Exfiltration | Out | Remove data from the network | TA0010 |
| 17 | Impact | Out | Manipulate, disrupt, or destroy | TA0040 |
| 18 | Objectives | Out | The strategic, socio-technical goal | none (analyst field) |

| # | Idea | Where | Phase | Already in ROADMAP? | How it would be built (deterministic) | Value |
|---|---|---|---|---|---|---|
| 2.1 | **UKC ↔ ATT&CK ↔ CKC crosswalk as local data**, driving the planned IN / THROUGH / OUT grouping and giving every technique a phase position. | p.1, p.5-6, p.12 | 9 | Partly: "an IN / THROUGH / OUT grouping" (from the Curated Intel guide, line 2127). The 18-phase list and the crosswalk are not there. | Hand-built YAML/CSV in the repo: tactic → UKC phase for the 1:1 tactics, plus a technique-level override list for Delivery, Social Engineering, Exploitation and Pivoting (the four phases ATT&CK does not have as tactics). Each row cites its basis. A test checks every technique in the bundle resolves to exactly one phase. | High: unlocks 2.2-2.4 and the planned grouping with one small table. |
| 2.2 | **Campaign × phase matrix**: rows are cases or campaigns, columns the 18 phases, cells list the techniques seen. Shows where attacks converge or diverge. | p.10 (4.1) | 9 | No (Phase 9 compares technique sets and ordered technique runs; not a phase-level matrix). | Pivot query over case/campaign techniques joined to the crosswalk; HTML table, CSV export. | Medium-High: an at-a-glance comparison that is far less noisy than technique-level overlap. |
| 2.3 | **Attack-specific vs actor-specific kill chain**: the ordered phases seen in one attack, vs the union of phases in an actor's repertoire in typical order. | p.10 | 9 | Partly: "Sequence comparison: longest common ordered run of techniques" (technique level). | Store a case's phase occurrences as an ordered list with repeats allowed; an actor's chain is the union over its campaigns ordered by median position. Compare chains with the same longest-common-run code planned for techniques, at phase level. | Medium. |
| 2.4 | **Phases may be skipped, repeated, or out of order** → data-model rule: never infer a missing phase; never treat the chain as a checklist that must be complete. | p.11, p.14 | 9 | No explicit rule. | Model as an ordered list, not 18 booleans; UI shows "not observed" rather than "missing". | Medium: prevents a subtle analytic error. |
| 2.5 | **Phase frequency and choke points** across the pinned actors: defend the phases most actors use and the Through-loop phases (Pivoting, Credential Access, Lateral Movement) that sit on the path to critical assets. | p.11 | 9 ("my threat landscape") | Partly: "most common techniques, shared initial-access methods" (technique level). | Per phase: share of pinned actors/campaigns with ≥1 technique in it; highlight top phases and flag the Through-loop phases. | Medium. |
| 2.6 | **Resource Development as early warning**: registered typosquat domains in the case studies could have warned of an attack. | p.13 | 3, 6 | Yes in substance: Phase 3 lookalike-domain monitoring; Phase 6 C2 hunts. | Label those alerts with phase "Resource Development" / TA0042 so they read as pre-attack signals. | Low (labelling only). |
| 2.7 | **Objectives as an explicit field** (strategic goal), separate from Impact; CIA coverage (Collection + Exfiltration = confidentiality, Impact = integrity/availability). | p.10, p.13 | 9 | Mostly: archetype, motivation, intent ratings, PESTLE. | Optional `objective` free-text and a derived CIA tag per campaign. | Low. |

---

## 3. Gaining the Advantage: Applying Cyber Kill Chain Methodology to Network Defense (Lockheed Martin)

| Field | Value |
|---|---|
| File | webfetch-1794439400348-s6zmo1.pdf |
| Author / publisher | Lockheed Martin Corporation (no named author) |
| Date | 2015 (copyright line, p.13; document code #CMK201503001) |
| Pages | 13 |
| Licence | © 2015 Lockheed Martin Corporation, All Rights Reserved; Cyber Kill Chain® and Intelligence Driven Defense® are registered trademarks (p.3, p.13). Use the seven phase names as facts with the ® noted once; do not copy text or graphics. |

**Summary.** A marketing brochure, not the 2011 Hutchins/Cloppert/Amin paper.
It lists the seven phases (Reconnaissance, Weaponization, Delivery,
Exploitation, Installation, Command & Control, Actions on Objectives), each
with an Adversary column (what they do) and a Defender column (what to
collect, detect or analyse) (pp.4-10). Closing pages argue for analysing
multiple kill chains over time to find campaigns, analysing backwards from
late detections, analysing blocked intrusions as if they had progressed, and
measuring defence effectiveness (pp.11-12). It repeats the "one mitigation
breaks the chain" claim (p.3, p.12) that the UKC paper disputes. It does
**not** contain the courses-of-action matrix (detect / deny / disrupt /
degrade / deceive / destroy); that is in the 2011 paper, which was not among
the files.

| # | Idea | Where | Phase | Already in ROADMAP? | How it would be built (deterministic) | Value |
|---|---|---|---|---|---|---|
| 3.1 | **Build-freshness signal for samples**: compare when malware was made with when it was used; old builds suggest off-the-shelf tooling, new ones an active tailored operation. Watch for timestomping. | p.5 (Weaponization, defender), p.8 (Installation: compile time; adversary timestomps) | 1 (hash enrichment), 9 | Partly: Phase 9 artefact registry lists "compile time" as a fingerprint. The delta as a signal is not planned. | From data Phase 1 already fetches (VirusTotal `pe_info.timestamp`, `first_submission_date`; MalwareBazaar `first_seen`): show compile → first-seen delta and first-seen → case date, with fixed bands (<7 days "fresh build", >1 year "old build") and a caveat line when the timestamp is zero, in the future, or before 2000 (likely forged). A verdict-line rule, no new source. | Medium-High: buildable now from existing Phase 1 data. |
| 3.2 | **Time-of-day pattern** of when an operation began / activity timestamps. | p.6 (Delivery, defender) | 9 (evidence class "timing") | Partly: "timing" is one of the planned evidence classes; no view for it. | Histogram of a case's or actor's event timestamps by UTC hour and weekday, with an overlay for a chosen time zone; marked "forgeable, weak alone" per the existing forgeability labels. | Medium. |
| 3.3 | **Furthest phase reached and blocked attempts**: record failed or blocked intrusions too and how far they would have progressed; analyse backwards. | p.11 (tips) | 6/9 (cases) | No. | Case fields `furthest_phase` (from the UKC crosswalk), `stopped_by` (free text or control name), `outcome` (blocked / partial / succeeded). | Low-Medium: limited own-org data in a solo tool. |
| 3.4 | **Weaponizer / builder artefacts**: detect the builder to find new campaigns; ask whether an artefact is widely shared or closely held. | p.5 | 9 | Yes: "a 'builder default' list (a builder fingerprint links to the builder, not the operator)" and the commodity / shared / exclusive stop-list. | None new. | Low (confirms existing design). |
| 3.5 | **Mission ID embedded in malware**. | p.5 | parking lot (malware corpus) | Yes: extracted configs include "campaign IDs". | None new. | Low. |
| 3.6 | **Extract certificates of signed executables**. | p.8 | 9 | Yes: "signer certificate" in the artefact registry; lolcerts in Phase 8. | None new. | Low. |
| 3.7 | **Proxy blocks on uncategorised/new domains, DNS sinkholing** as C2 defences. | p.9 | 3 / 8 | Yes in substance: NRD files (Phase 8 health page lists them), MISP warninglists include sinkholes. | None new. | Low. |
| 3.8 | **CKC as a third column in the crosswalk** (2.1) so reports can speak either vocabulary. | p.3-10 | 9 | No. | Add a `ckc_phase` column to the 2.1 crosswalk (Recon, Weaponization ≈ Resource Development, Delivery, Exploitation, Installation ≈ Persistence, C2, Actions on Objectives ≈ everything after). | Low-Medium (free once 2.1 exists). |
| 3.9 | **Follow-up reading**: the 2011 Hutchins, Cloppert, Amin paper for its courses-of-action matrix, which would give a "defender action per phase" table. | (absent from this file) | 9 | Not referenced. | Fetch and review later (needs approval). | Medium. |

---

## 4. The Threat Actor Profile Guide for CTI Analysts (Curated Intelligence)

| Field | Value |
|---|---|
| File | webfetch-1794439000025-a25drb.bin |
| Status | **Not read.** |
| What was verified | The file is a PDF: header `%PDF-1.7` and a page tree with `/Count 4` (checked with a read-only text search). |
| Why not read | The Read tool refuses files with a `.bin` extension, and the page content is compressed, so a text search cannot recover it. Reading it needs the file copied to a `.pdf` name (one copy command into the scratchpad), which the brief ruled out (no execution, no files other than this output). |
| Fallback | The roadmap already records what was taken from this guide (line 2122-2128: exec summary What/So what/What now, leadership and operations views, campaigns list, Diamond card, Observable column, IN/THROUGH/OUT, dwell time, stepping-stone flag, contested attribution). No additional ideas can be reported from this document. |

---

## 5. Definitive Guide to Cyber Threat Intelligence (identified)

| Field | Value |
|---|---|
| File | webfetch-1794439399406-mza3p1.pdf (webfetch-1794442341982-x8e1xr.pdf skipped as a duplicate, per the brief) |
| Title | *Definitive Guide to Cyber Threat Intelligence: Using Knowledge about Adversaries to Win the War against Targeted Attacks* (p.1, p.3) |
| Authors / publisher | Jon Friedman and Mark Bouchard, CISSP; foreword by John P. Watters (then iSIGHT Partners chairman and CEO); contributions by Jonathan Couch and Matt Hartley. Published by CyberEdge Group, LLC (CyberEdge Press), distributed "compliments of iSIGHT Partners" (p.1, p.3-4) |
| Date | 2015 (p.4) |
| ISBN | 978-0-9961827-0-6 (paperback); 978-0-9961827-1-3 (eBook) (p.4) |
| Pages | 74 PDF pages: covers and front matter, 62 printed pages (7 chapters plus glossary), a full-page iSIGHT advert (p.73), back cover marked "Not for resale" (p.74) |
| Text layer | Contrary to the brief's note, most pages have a text layer; only the covers, the iSIGHT "About" page and the advert (pp.1, 2, 73, 74) are image-only. All pages were read. |
| Licence | Copyright © 2015 CyberEdge Group, LLC, all rights reserved; no reproduction without written permission (p.4). Ideas only. |
| Bias note | Vendor-sponsored; Chapter 7 (partner selection) and the foreword promote iSIGHT's model. Treat claims as a 2015 vendor view. |

**Summary.** A short primer. Ch.1 defines CTI around adversaries, risk,
process and tailored consumers, and frames problems and benefits at tactical
(NOC, infrastructure, SOC), operational (IR, forensics, fraud) and strategic
(CISO, management) levels (Table 1-1, p.14 / printed 4). Ch.2 builds
requirements from assets (card data, PII, IP, confidential business info,
credentials, operational systems), adversary types (cybercriminals,
espionage, hacktivists; Table 2-1 p.23) and consumers. Ch.3 sorts information
into Level 1 threat indicators, Level 2 threat data feeds, Level 3 strategic
intelligence (Table 3-1 p.28). Ch.4 covers validation (risk scores from
technical, statistical and human inputs; context tags), human media-claim
assessment, an "anatomy of an attack" report template, a threat landscape
report template, platform elements and dissemination. Ch.5 shows uses: better
blocking, patch prioritisation (with a three-cycle patch window example), SOC
triage, IR pivoting (worked example p.50), executive reporting. Ch.6 gives an
eight-step program (roadmap, knowledge base, monitoring, staffing, automation,
communications, hunt missions, refine) with a gap-analysis matrix (p.57) and a
fill-in-the-blank investment recommendation (p.58). Ch.7 lists partner
selection criteria.

| # | Idea | Where | Phase | Already in ROADMAP? | How it would be built (deterministic) | Value |
|---|---|---|---|---|---|---|
| 5.1 | **Remediation windows per priority**: one agency assigns each patch to a 24-hour, one-week, or one-month cycle based on intelligence. | p.47 (printed 37), box "Pick the patching cycle" | 2 | Partly: P1-P5 priority and the CISA KEV due date (line 667). No own due dates. | Setting: P1 → 1 day, P2 → 7 days, P3 → 30 days, P4/P5 → none (operator-editable). Watchlist-matched CVEs show "due by" = first matched date + window, with an "overdue" filter and a verdict line naming the window. | Medium-High: tiny build on existing P1-P5, directly useful for the weekly review runbook. |
| 5.2 | **Context tags and an operator relevance profile**: tag indicators with sector ("Financial"), region ("Eastern Europe"), malware family ("Citadel family"); a rule flags anything carrying a tag that matters to this organisation. | p.39 (printed 29), p.48 (printed 38), p.61-62 (printed 51-52) | 1, 3, 5, 6 | Partly: tech watchlist (Phase 2), org/sector/country watchlists (Phase 3, line 702), topic watchlists (Phase 4). No cross-module relevance profile applied to indicators. | Normalised tag vocabulary (sector, region, family, actor) filled from fields sources already return (OTX pulse `industries`, `targeted_countries`, `malware_families`; ThreatFox `malware`; MISP galaxy tags). A git-ignored relevance profile (sectors, regions, technologies) marks matching enrichment results and alerts as "relevant to us", with the matching tag named in the verdict line. | Medium-High: uses data already fetched; makes enrichment answer "does this matter to us?". |
| 5.3 | **Three-part risk score kept apart**: automated technical (did a sandbox see malice?), statistical (how often seen in attacks on our kind of business?), human judgement (our exposure and impact). | p.39 (printed 29) | 1, 2 | Partly: verdict lines and P1-P5 reasons keep signals separate. The "attacks on our sector" component is missing. | Three labelled fields, never blended: technical from sandbox/vendor verdicts, statistical from 5.2 tag matches, judgement as an analyst-set rating with reason. | Medium. |
| 5.4 | **Media claim assessment card** on news items: accuracy (on-target / off-target), relevance to us, recommended action, short analyst comment. Also "what not to fear" for executives. | p.40 (printed 30, Figure 4-2), p.15 (printed 5, tip on countering FUD) | 4 | No. Phase 4 has keyword highlighting and chips; no per-article assessment. | Columns on the article record: `accuracy` enum (accurate / partly / off-target / unverified), `relevance` enum (yes / watch / no), `action` enum (none / monitor / act), `comment`. Filters "assessed this week" and "off-target" give a deterministic weekly "headlines we checked" list for leadership. | Medium: cheap, and supports the leadership view already planned. |
| 5.5 | **"Anatomy of an attack" report template** with ten sections: attribution; history and where observed; motives; typical victims (sector, location, vulnerabilities); impact and risk by enterprise type; tactic breakdown (recon, phishing, malware, systems compromised, C2, exfiltration); similar threats; indicators and events to detect it; mitigations; outlook. | p.41 (printed 31) | 9 (report builder), 8 (PDF export) | Partly: "Report builder." (one line), exec summary, CTI Blueprints export. Section content not specified. | Jinja template with those headings. Deterministic fill: indicators (with PoP level, 1.10), techniques grouped by UKC phase (2.1), victims and sectors from the profile, "similar threats" from the planned overlap and discriminator features, mitigations from ATT&CK mitigations; attribution, motives, impact and outlook are analyst-written fields with estimative-language checks. | Medium-High: gives the one-line "Report builder" a concrete shape. |
| 5.6 | **Threat landscape report**: business risks; threat types affecting us and peers; most likely adversaries with motivation, intent and TTPs; ranked security priorities. | p.42 (printed 32) | 9 | Mostly: "my threat landscape" page over pinned actors. Missing: a ranked priorities section and "peers" view. | Add a ranked-priorities table (from 5.7) and a peers section (actors whose victims share the operator's sector, from Phase 3 victim data). | Low-Medium. |
| 5.7 | **Gap matrix**: likely adversary × defence strength × asset value → priority. High = weak defence on a high-value asset; Medium = weak on low-value or strong on high-value; Low = strong on low-value, or not targeted by any likely adversary. | p.56-57 (printed 46-47, Figure 6-2) | 9 (control coverage) | Partly: "Control coverage mapping." (one line); Kraven threat-modelling note. No asset value × defence matrix. | Uses the asset register (1.7) with operator-set value and defence strength per asset, and actor targeting from profiles (sector, techniques). A fixed rule table yields High / Medium / Low; rendered as a sorted table with the rule that fired. | Medium: same build as 1.7; strongest for a reader who models their own organisation. |
| 5.8 | **Investment recommendation template** with slots: improvement, asset, loss effects, likely adversaries, current defence, what it lacks, cost, defects fixed, initiative enabled. | p.58 (printed 48) | 9 (report builder) | No. | A report-builder template whose slots fill from the asset register, gap matrix and actor profiles; cost and lacks are analyst input. | Low-Medium. |
| 5.9 | **Consumer-specific products and cadence**: immediate flashes for SOC/IR, full analyses for IR/forensics, weekly or monthly summaries for managers, quarterly business summaries and press-driven assessments for executives. | p.44 (printed 34), p.62-63 (printed 52-53) | 8, 9 | Partly: leadership and operations views; weekly chatter brief (parked). | Product type and cadence as metadata on reports; scheduler reminders when a cadence is due. | Low-Medium. |
| 5.10 | **Alert triage states and consumer feedback**: escalate now / investigate when time permits / ignore; rate how usable and helpful intelligence is; track alert quality and time to investigate. | p.48 (printed 38), p.64 (printed 54, tip) | 5 (alert inbox) | No: the alert inbox is planned ("In-app alert inbox first") without dispositions. | `disposition` enum on alerts (escalate, later, ignore, false positive) with a timestamp; per rule and per source, show the share marked false positive or ignore. Feeds source reliability review. | Medium: makes noise measurable from day one of the inbox. |
| 5.11 | **Hunt mission**: tag specific indicators for special monitoring so any encounter notifies the hunt team at once, then pivot. | p.63-64 (printed 53-54) | 5, 6 | Partly: Phase 6 hunt list, watchlist change feed, saved pivots alerting on new members. A cross-module "seen again anywhere" alert is not explicit. | A `hunt_tag` on indicators; the corpus sighting writer raises an inbox alert when a hunt-tagged indicator appears in any new document, enrichment, or collector post. | Medium-Low. |
| 5.12 | **IR pivot checklist**: from one indicator to the actor's known method, then a list of checks (similar emails to the same department, rise in privileged accounts, unusual data exports from the targeted application, traffic to the actor's IPs). | p.50 (printed 40, box) | 9 | Partly (hunting package). | Same build as 1.6: actor profile → templated check list per technique, for use in the operator's own SIEM. | Medium (merged with 1.6). |
| 5.13 | **Hacktivist trigger events**: layoffs, entering new markets, legal or environmental controversies, dealings with dissidents or opposed governments. | p.25 (printed 15, tip) | 3, 5 | No (hacktivism appears as a keyword topic and an actor type). | Operator-maintained dated "trigger events" list; around each date, the scheduler raises the Phase 5 hacktivist keyword category's priority for the operator's selectors. | Low-Medium. |
| 5.14 | **Three information levels** (indicators, data feeds, strategic) with content, uses and sources, as a classification on each source. | p.28 (printed 18, Table 3-1) | 5 (source registry) | Partly: registry records class, terms, reliability, lineage. | One more enum column on the source registry. | Low. |
| 5.15 | **Partner/source evaluation criteria**: languages and regions covered, history depth and when the knowledge base started, how obsolete items are weeded, range of deliverables, APIs, portal search, client services, access to experts, references. | p.67-70 (printed 57-60) | 5 (source registry) | Partly (terms, licence, reliability, lineage). | Optional fields on registry entries: history start date, update cadence, retirement policy, coverage languages. | Low. |
| 5.16 | Knowledge base with multi-year history; check whether today's indicator appeared before. | p.44 (printed 34), p.59 (printed 49) | 6 | Yes: "Prior art" step and "nothing is deleted" retention. | None new. | Low (confirms design). |

---

## Ranked top 10 across all documents

1. **Hunt hypothesis and hunt-run records with lifecycle states and a "not proven ≠ absent" outcome with re-test date** (Doc 1, pp.8, 17-24; ideas 1.1-1.3). Gives the planned Phase 6 Hunts tab and Phase 9 hunting package a structure; pure SQLite tables and enums.
2. **ATT&CK telemetry visibility inventory with a 1-5 per-technique score and Navigator layer** (Doc 1, pp.28-31; 1.4). Joins the operator's log sources with pinned actors' techniques to show blind spots; computed from the local STIX bundle.
3. **UKC 18-phase crosswalk to ATT&CK (and CKC) as repo data** (Doc 2, pp.1-12; Doc 3; 2.1, 3.8). One small table that powers the already-planned IN/THROUGH/OUT grouping, phase-level comparisons and report sections.
4. **Build-freshness signal on hash enrichment** (Doc 3, pp.5, 8; 3.1). Compile time vs first seen, with timestomp sanity checks; uses data Phase 1 already fetches, so it can ship now.
5. **Remediation windows and "due by / overdue" per P1-P5** (Doc 5, p.47; 5.1). A setting and one computed column on the Phase 2 watchlist view.
6. **Context tags and an operator relevance profile applied to indicators** (Doc 5, pp.39, 48, 61; 5.2-5.3). Uses OTX `industries` / `targeted_countries` / `malware_families`, ThreatFox family and MISP galaxy tags to answer "relevant to us?".
7. **Campaign × UKC-phase matrix** (Doc 2, p.10; 2.2). A low-noise comparison view that complements the planned technique-overlap features.
8. **"Anatomy of an attack" report template with deterministic sections** (Doc 5, p.41; 5.5). Turns the one-line "Report builder" into a defined product.
9. **Alert dispositions and per-rule / per-source noise rates in the alert inbox** (Doc 5, pp.48, 64; 5.10). Cheap to add when the Phase 5 inbox is built; makes source reliability measurable.
10. **Media claim assessment card on news items** (Doc 5, pp.15, 40; 5.4). Accuracy, relevance, action and comment on Phase 4 articles, feeding a leadership "headlines we checked" list.

Next in line: data-source shopping list (1.5), asset register plus gap matrix incl. Crown Jewels steps (1.7, 5.7), hypothesis skeletons from actor profiles (1.6, 5.12), hunt metrics per tactic (1.8), generic stack-count action (1.9), time-of-day histogram (3.2), phase frequency / choke points (2.5).

Follow-up reading worth approving later: the companion UK guide "Controlling Your Exposure – A Guide to Digital Risk and Intelligence" (Phase 3), and the 2011 Hutchins/Cloppert/Amin kill-chain paper (courses-of-action matrix).

## Pages not read, and why

- **Document 4 (webfetch-1794439000025-a25drb.bin), all 4 pages.** The Read tool refuses the `.bin` extension, and the PDF's content streams are compressed, so a read-only text search could only confirm it is a 4-page PDF 1.7. Reading it needs a copy to a `.pdf` filename in the scratchpad, which the brief did not allow. No ideas reported beyond what the roadmap already took from it.
- **Document 1, p.29 (Figure 10, ATT&CK matrix):** rendered, but technique names are too small to read at the rendered resolution. Not material: it is an old ATT&CK snapshot, and the local bundle supersedes it.
- **Document 1, pp.2 and 49:** blank pages (read; nothing on them).
- **Document 5, pp.1, 2, 73, 74:** image-only (cover, iSIGHT "About" page, advert, back cover); read visually, no gaps.
- **Duplicate webfetch-1794442341982-x8e1xr.pdf:** skipped per the brief (not checked for byte identity by me).
- Every other page of documents 1, 2, 3 and 5 was read in full.
