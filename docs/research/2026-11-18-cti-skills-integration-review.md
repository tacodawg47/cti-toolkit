# Installed CTI Skills: Integration Review

Reviewed 2026-11-18. Inventory: 78 CTI skill directories, excluding host
skills. Reviewed all capability cards and section/supporting-file inventories,
with deeper reading of the orchestration, evidence, export, collection,
control mapping and API integration workflows. This is a feature review,
not a security audit of every script or verification of every historical
claim in the knowledge cells. No skill script or setup command was run.

Follow-up on 2026-11-18: the installed folders changed after that inventory.
There are now 71 CTI SKILL.md cards, excluding .system. Enrichment and
pivoting have replacement local routing; IP, domain, hash and URL
investigation have a Local Source Profile override. Six cards now direct
lookups to the configured source profile, which prohibits new scans,
sample uploads and publishing without separate authorization. Some unused
upstream sections still contradict these overrides. The 78-row matrix
below describes the earlier reviewed snapshot, not a current installed
feature count. Re-inventory and resolve conflicting instructions before
actual Phase 11 integration. No skill outside the project was edited here.

Clarified 2026-11-19: a local override means text in an installed card tells
the agent to use the local Available Sources routing instead of the broader
upstream instructions. For example, use existing URL scan records and obtain
authorization before a new submission. This is not an app feature, a change
to provider permissions or evidence that any submission has occurred. The
operator's current chat remains the source of action authorization.

## External Actions: Exact Examples

| Card or workflow | Upstream behavior | Current adoption decision |
|---|---|---|
| url-investigation | Submits a URL to urlscan with unlisted visibility, and describes additional configured-provider queries | The current Local Source Profile instead requires existing-record lookups and separate permission for a new scan. Unlisted still discloses the URL to a third party. |
| lookup-urlscan | Searches recent existing scans, otherwise describes a new submission for stale/missing results | Stale or absent results must remain unknown until a new submission is authorized. Its body does not contain the investigation override. |
| cti-orchestrator | Advises extra provider chaining when credentials exist and updating knowledge cells after findings | Existing keys do not grant unlimited query scope, quota or writes. Removed integrations remain unavailable despite stale upstream references. |
| ioc-enrichment-workflow and indicator-pivoting | Earlier pack routed broadly; both now use locally bounded source routing | Reuse bounded typed pivots and provenance, not historical provider defaults. Current pivot defaults are at most two hops and ten candidates per hop, subject to scope/quota. |
| lookup-misp | Can read correlations and publish attributes/events | Keep read access separate from approved publishing. Capability is not evidence that it has run. |
| cti-setup | Offers to write API keys into Claude configuration and verify them through clients | Do not migrate project secrets or run setup. Keep the existing .env workflow. |

The earlier full pack also exposed Liberty91 upload-document, ingestion and
report-generation actions. That card required confirmation; it was not a
silent-upload default and is absent from the current installed set. Do not
conflate available commands with automatic behavior or claim that files were
uploaded merely because a card supports it. None of these actions was run.

## Decisions From the Follow-up

Adopt bounded report context in the current Phase 2 IOC extractor. Preserve
existing source selection, local processing and passive text display.
Forms, provenance, validation, templates and bounded deterministic pivots
remain assigned to their existing roadmap phases. Installing the pack does
not make its natural-language instructions executable application features.

Revisit actual skill-derived assistance in Phase 11: an IOC entry or a
button can select an approved workflow. Keep model output away from raw
shell execution, validate tool arguments and destinations in application
code, and test malicious instructions in all input surfaces. Include IOC
fields, retrieved pages, embedded metadata, source excerpts, tool errors
and graph labels. Test unauthorized query expansion, credential disclosure,
publishing and scan submission, as well as ordinary XSS/SQL/command/SSRF
input handling. Injection testing reduces risk; it does not establish immunity.

## Provenance and Packaging

The existing Claude marketplace checkout identifies Liberty91 Ltd and an
MIT license. It contains the full tools, clients and mapping data. The
new Codex skill folders contain instruction files and some local references
and scripts. Many lookup instructions still depend on pack-root
`tools/clis/` paths and `data/` directories; those are not installed inside
the individual skill folders. Installing the instructions did not add
these features to the toolkit or establish that every command now works.

All 78 instruction bodies match that local MIT source after newline
normalization. Ten capability descriptions were reworded in the installed
copies; the instruction bodies were unchanged. This provenance comparison
does not independently certify that all source code or embedded facts are safe.

Before porting, compare the exact file with the licensed source and retain
attribution. Check separate licenses for underlying data and vendor terms.
Do not execute plugin setup or copy credential configuration. Reuse our
existing HTTP client, rate limits, .env loader and secret handling instead.

## Best Uses Before AI

1. Evidence and provenance records: source URL, exact source excerpt,
   claim type, publication versus observation date, upstream citation chain,
   retraction and supersession. Explicit links can be collected by rules;
   independence and credibility cannot be established just by counting URLs.
2. Case and campaign templates with saved observations, hypotheses,
   assumptions, gaps and review decisions. Forms and exports need no model.
3. Bounded IOC pivots with provenance on every edge, cost estimates and
   distinct external reputation versus internal sightings. Reuse existing
   enrichment adapters rather than duplicate the lookup clients.
4. CSV/STIX/MISP export validation and sharing markings. Preserve evidence
   and unknown values instead of inventing numerical confidence.
5. Candidate detection templates with required telemetry, field mappings,
   false positives and validation status. A saved template or a matching
   ATT&CK tag is not a tested detection.
6. Source maintenance and operating checklists tied to the Phase 5 registry,
   rather than auto-updating instructions or narrative knowledge cells.

## Complete Capability Map

Pre-AI means deterministic logic, templates or manual analyst input. It does
not mean every feature belongs in the current Phase 2 implementation.
Phase numbers retain the roadmap's build order. Conditional integrations
need the relevant account, entitlement and an approved query scope.

| Skill | Pre-AI integration | Later optional AI use / caution |
|---|---|---|
| abuseipdb-api | Phase 1 existing adapter reference | Verify current vendor docs before changes. |
| ach | Phase 6 Cases hypothesis/evidence matrix | Suggest alternatives; scores are not probabilities. |
| campaign-tracking | Phase 6/9 dated campaign records and linked cases | Draft updates from cited observations. |
| carding-financial-fraud | Phase 4/5 topic tags and source leads | Dated knowledge reference; verify claims. |
| censys-api | Phase 6 optional host/certificate adapter | Entitlement and current API verification required. |
| china-cyber-espionage | Phase 9 sourced profile/alias leads | Verify each dated actor claim before use. |
| claim-extraction | Manual atomic claims with source anchors | Extract draft claims; validate anchors and hedging. |
| confidence-levels | Manual bands, rationale and unknown state | Suggest rationale; avoid invented precision. |
| control-coverage-mapping | Phase 9 versioned technique/control joins | Explain gaps; mapped relevance is not tested efficacy. |
| crowdstrike-api | Optional Phase 1/9 vendor adapter reference | Subscription and scopes required. |
| cti-hyperloop | Collection-to-action workflow and feedback fields | Organize draft briefings, not an external dependency. |
| cti-orchestrator | Explicit deterministic job routing and source selection | Phase 11 planner; do not inherit autonomous API chaining. |
| cti-setup | Key-presence checks and setup documentation | Keep our .env workflow; never ask a model to hold keys. |
| darkweb-collection | Phase 5 selector/source registry and isolation ideas | Summarize collected text; no automatic joining or engagement. |
| devils-advocacy | Case checklist for contrary evidence | Draft the strongest alternative explanation. |
| domain-investigation | Phase 6 saved domain investigation workflow | Synthesize cited results only. |
| dprk-cyber-espionage | Phase 9 profile and source leads | No automatic attribution from its narrative. |
| feedback-loops | Review outcomes and source error tracking | Summarize feedback later. |
| greynoise-api | Phase 1 existing adapter reference | Preserve scanner context and quota policy. |
| hacktivism | Topic taxonomy and actor-claim records | Separate claimed disruption from observed disruption. |
| hash-investigation | Existing hash enrichment plus Phase 6 pivots | No sample download or detonation by default. |
| horizon-scanning | Saved signals, indicators and thresholds | Draft scenarios; distinguish forecasts from observations. |
| indicator-pivoting | Phase 6 bounded pivot graph and edge evidence | Suggest pivots; shared infrastructure is not attribution. |
| infostealers | Phase 3/7 service/device fields and source taxonomy | Keep private corpus and secrets out of cloud assist. |
| initial-access-brokers | Phase 3/5 selectors and listing-claim schema | No purchases, messages or automatic contact. |
| intelligence-sharing | Phase 8 export review and recipient restrictions | Draft products; sending remains an explicit action. |
| intelligence-writing | Phase 8 report templates and citations | Phase 11 drafting with evidence links. |
| ioc-enrichment-workflow | Existing routing, batch jobs after scheduler | Do not import its automatic submissions or vendor preferences. |
| ioc-export | Phase 8 CSV/OpenIOC/STIX/MISP formats | Its confidence conversion is a local convention, not calibrated fact. |
| ip-investigation | Phase 6 reproducible IP workflow | Keep InternetDB routine and keyed Shodan on demand. |
| iran-cyber-espionage | Phase 9 sourced actor/alias leads | Verify individual claims and dates. |
| key-assumptions-check | Case assumption register and review dates | Propose assumptions for analyst review. |
| kql-writing | Phase 8 candidate queries and telemetry requirements | Generate drafts; validate against actual tables. |
| likelihood-language | Probability vocabulary and stated time window | Forecast wording, separate from confidence. |
| lookup-abuseipdb | Reuse Phase 1 client | Wrapper duplicates an existing integration. |
| lookup-censys | Optional Phase 6 certificate/host lookups | Current quota/API verification required. |
| lookup-crowdstrike | Optional Phase 1/9 indicators and reports | No free-feed assumption. |
| lookup-greynoise | Reuse Phase 1 client | Do not turn one benign result into a global clean verdict. |
| lookup-liberty91 | Optional report/occurrence adapter | Commercial entitlement; pack's first-party label is vendor-relative. |
| lookup-misp | Phase 8 optional correlation and export | Separate read scopes from approved external writes. |
| lookup-opencti | Phase 8 optional correlation and STIX exchange | Same explicit read/write separation. |
| lookup-otx | Reuse Phase 1 client | Pulse counts are not independent corroboration. |
| lookup-ransomwarelive | Existing Phase 2; Phase 3 victim monitoring | Leak-site assertions remain claims. |
| lookup-reversinglabs | Optional Phase 1/8 sample-result adapter | Paid/platform-specific; no automatic submissions. |
| lookup-sentinel | Later optional internal exposure queries | Discover schema/ingestion first; a miss does not prove no compromise. |
| lookup-shodan | Existing adapter, Phase 6 targeted hunts | Preserve on-demand credit decisions. |
| lookup-urlscan | Existing scan lookup | New submission is a separate data-disclosure action. |
| lookup-virustotal | Existing client, Phase 6 relationships | Bound relation fan-out and report quota use. |
| malware-analysis | Phase 8 result-import/checklist schema | Active samples and orchestration remain parked. |
| maturity-assessment | Optional manual programme questionnaire | Low priority for a personal toolkit. |
| mitre-attack | Existing local catalog; Phase 9 profile joins | Keep bundle version, revoked IDs and source lineage. |
| osint-methodology | Phase 7 query plan, source picker and evidence log | No automatic identity merging. |
| otx-api | Existing adapter documentation | Revalidate live API before porting examples. |
| phishing-social-engineering | Phase 3/4 topic tagging and source leads | Historical narrative is not a live verdict. |
| pir-management | Lightweight saved questions and selectors | No mandatory enterprise workflow for every lookup. |
| quality-control | Anchor/schema/completeness validation | Semantic critique remains suggested review. |
| quality-of-information-check | Manual evidence fields, provenance and flags | Grade suggestions; do not mechanically award truth from source counts. |
| ransomware-ecosystem | Existing source leads, Phase 3/9 actor taxonomy | Version and cite dynamic claims. |
| reversinglabs-api | Optional adapter reference | Spectra Analyze and Intelligence are distinct products. |
| russia-cyber-espionage | Phase 9 profile/alias leads | No uncited migration of its assertions. |
| shodan-api | Existing adapter reference | Do not restore routine credit-spending lookups. |
| sigma-writing | Phase 8 candidate templates and validation checklist | Generated rule remains a candidate until tested. |
| sops | Optional checklists and repeatable runbooks | Keep the personal workflow lightweight. |
| source-assessment | Editable source/item ratings with rationale | Vendor-wide default grades are not universal evidence. |
| source-provenance | Phase 4/5 citation edges and unresolved hops | Heuristic resolution needs limits and review. |
| stakeholder-management | Optional audience/purpose on report exports | Low priority; no CRM module. |
| stix-bundle | Phase 8 deterministic objects and references | Preserve unknown confidence and source-specific claims. |
| structured-analytic-techniques | Optional case-method selector | AI can suggest a method, not silently apply one to every lookup. |
| supply-chain-threats | Phase 2 source leads and incident taxonomy | Verify campaign statements; PyPI coverage remains a planned expansion. |
| threat-actor-profiling | Phase 9 sourced profiles and version history | Draft prose without promoting matches to attribution. |
| threat-assessment | Manual intent/capability/opportunity fields | Qualitative framework, not an objective risk equation. |
| tlp-guide | Phase 8 markings and export checks | Honor originator restrictions; no invented blanket marking. |
| url-investigation | Existing scan evidence and Phase 6 workflow | Override the skill's automatic submission default. |
| urlscan-api | Existing client reference | Search and submission have different disclosure effects. |
| virustotal-api | Existing client reference | File upload and intelligence search are separate capabilities. |
| vulnerability-intelligence | Evidence/EPSS/CVSS context already built | Do not restore hard deadlines, implicit applicability or PoC certainty. |
| writing-assessments | Phase 8 threat/risk/vulnerability report forms | Phase 11 source-grounded drafting. |
| yara-writing | Phase 8 candidate file rules and corpus-validation record | Never deploy or declare tested without validation. |

## What Not to Adopt Verbatim

- The default orchestrator calls more services whenever keys exist. Our
  source picker, purpose, quota and disclosure controls take precedence.
- Source grades such as A1/A2 describe a chosen methodology, not a guarantee
  that every event or vendor judgment is correct. A direct telemetry hit
  establishes the observed event, not every interpretation of it.
- Fixed numerical conversions between evidence words and STIX confidence
  are export conventions. They must not be presented as measured certainty.
- Claim independence, attribution and analytical credibility require
  judgment. Before Phase 11, retain manual/unassessed fields rather than
  smuggling semantic AI work into a supposedly deterministic service.
- Control mappings show documented relevance and sometimes vendor-assessed
  strength. They do not establish this environment's actual configuration,
  detection coverage or probability of stopping an attack.
- Knowledge-cell self-modification and arbitrary source updates should not
  change production rules silently. Keep versions, review diffs and record
  evidence dates. Validate underlying facts from their original sources.

## License and Missing-Dependency Follow-up

MIT permits considered code reuse with its notice. The datasets referenced
by control mapping and ATT&CK still need their own provenance/version/license
records. A statement in a skill that data is bundled does not mean it exists
in the Codex skill directory. The full marketplace pack is reference
material, not an installed toolkit dependency. No new paid account, provider
integration, task automation or AI runtime was enabled by this review.
