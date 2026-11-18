# Phase 2 Coverage Audit

Date: 2026-11-17. Scope: the current working tree, not a particular commit.
Phase 2 remains open. This is a coverage and behavior audit, not a full
security review or a fresh assessment of every upstream source.

## Resolution Update, 2026-11-17

Findings F1-F3 were fixed after the operator approved that implementation
batch. `evidence.py` supplies shared positive-source rules, typed dates,
advisory facts and product pairs. Linked manual reports, sightings,
ransomware evidence, OT remediation and legacy ambiguous dates now have
cross-feature regression tests in `tests/test_vulnerability_evidence.py`.
The additive migration preserves source records and review history.

The original findings and coverage matrix below remain an audit snapshot.
They describe the pre-fix behavior and are superseded by this update for
F1-F3. The probe now prints the corrected results. ATT&CK procedure gaps,
backfill scope, optional sources and other deferrals remain open. See the
newest journal checkpoint and runbook for verification and migration limits.

## Result

The module has substantial usable coverage. All 14 numbered views and All
Vulnerabilities have entry points. The latest decoder, wrapped PDF hashes,
and six vendor connectors are implemented. The main closeout problem is
that different consumers still interpret different subsets of the evidence.
Adding more feeds before correcting this would spread the inconsistencies.

The recommended next implementation batch is F1 through F3 below: unify
exploitation and remediation decisions, then preserve date provenance.
Finish the remaining ATT&CK procedure layouts after that. Do not begin a
new phase based only on the existence of the view pages.

## Method and Limits

- Compared the complete Phase 2 roadmap section with the build-order and
  parking-lot decisions, journal checkpoints, both module runbooks,
  source-review summary, implementation and existing tests.
- Ran the offline suite: 381 tests, 380 passed and one skipped. The skip
  covers missing-pypdf behavior when pypdf is installed.
- Added and ran `tests/phase2_coverage_probe.py`. It prints synthetic
  cross-feature observations in a temporary database with the suite's
  network refusal transport. It deliberately does not turn current bugs
  into passing regression expectations. No live watches or reports change.
- Checked 30 local GET pages and representative filters; all returned
  HTTP 200. Read aggregate public feed status. No
  refreshes, external source calls, dependency installs or git operations
  are part of this audit. Prior live-import validation is documented in
  the 2026-11-17 journal entry.
- Tests demonstrate their fixtures, not complete publisher coverage. No
  Linux execution was performed in this audit. The
  original MuddyWater PDF and the full twelve-layout survey fixture set
  were not newly validated. Upstream licences and endpoints were not
  re-reviewed during this local audit.

## Findings to Fix Before Closeout

### F1. Exploitation Decisions Differ Across Features

Reproduced offline. A linked manual report classified Confirmed Zero-Day
makes the CVE detail say Exploitation Reported, while its priority stays
P5 Low and its action stays Monitor in the synthetic scored-CVE case.
The linked report does not place the CVE in Known Exploited or Zero-Days,
and creates no Since Last Review exploitation event.

Separately, an exploitation sighting plus an Exploit-DB record produces
Hunt but can still appear in Exploit Leads Without Reported Exploitation.
That view excludes only `kev` and SSVC active; the sighting is stored
elsewhere. Ransomware evidence has a similar source-set separation by
inspection, although that variant was not independently probed here.

Evidence: `views.EXPLOITED_IDS`, `_code_not_exploited`, `_likely_ids`,
`service.report`, `detail.exploitation_status`, `reports.link`, and
`review._EVIDENCE`. The detail route loads linked reports after the report
service has calculated priority and actions. Existing linking tests mock
that service and therefore do not test the whole decision path.

Required result: define one positive-exploitation evidence contract with
source, date meaning and scope. Use it consistently for status, Hunt,
priority, view membership, counters and review events. A linked report
must retain its original assessment and timeline after CVE assignment.
Opening a CVE supported only by a linked local report should also use
that local evidence without requiring a fresh external lookup.
Unknown or unconfirmed reports must not promote a CVE. Unlinking or
correcting evidence must remove its current effect without erasing history.
Add end-to-end tests for manual, sighting-only and ransomware-only cases.

### F2. OT Evidence Does Not Reach the Shared Consumers

Reproduced offline with a CISA CSAF fixture. The detail page offers Patch
and Mitigate and uses vendor CVSS 8.8. The shared row offers Monitor and
has no score. Watching the fixture's exact vendor/product produces no
match, and importing the fix creates no review event.

Evidence: `feeds.ot._save`, `service.report`, `views._SELECT`,
`views._ot`, `views.read_watchlist_hits`, and `review._EVIDENCE`.
The OT view augments its own rows, while shared queries omit OT fix,
mitigation, score and product evidence. Recent generic vendor notices
already have broader integration, making the difference more visible.

Required result: reuse scoped OT evidence in All Vulnerabilities,
Watchlist, the CVE detail, actions and review history. Preserve affected
product scope and source credit. A fix for one target must not imply that
all targets are fixed. Include generic vendor-only rows in this check:
their structured product matches can drive a watchlist hit while the
shared vendor/product display still lacks a fallback. Edge and Perimeter
also currently reads the older source tables rather than new vendor
product evidence; expanding those sources should preserve curated rules.

### F3. A Publication Date Can Become a Zero-Day Lead

Reproduced offline. EUVD supplies `datePublished` but no `exploitedSince`.
The parser saves publication as `date_added`. The zero-day query treats
that value as dated exploitation and includes the CVE when it predates
CVE publication. The detail's First Reported Exploitation correctly omits
the same EUVD fallback, so the two pages disagree.

Evidence: `feeds.euvd.parse_items`, `views._zero_day_ids`, and
`detail.first_exploitation_report`. A similar distinction is needed for
Project Zero patch dates and Microsoft advisory revision dates. Project
Zero's explicit classification should remain sufficient for its confirmed
label independently of a missing exploitation date.

Required result: retain exploitation-observation, source-report,
catalog-added, advisory-revised, publication and patch dates with their
meaning. Only use a suitable dated positive exploitation signal for an
early-exploitation inference. Do not promote a publication or patch-date
fallback. Keep the accepted Possible Zero-Day label for a supported lead.
Test missing dates, fallback dates, explicit dates and later corrections.

## Coverage Matrix

Covered means implemented for the stated current slice. Partial means
there is working behavior and a defined remaining requirement. Deferred
means an explicit later phase or operator decision applies.

| Area | Status | Evidence and Remaining Work |
|---|---|---|
| Paste, upload and public-report URL intake | Covered | `app.main.extract`, `extract/fetch.py`, `test_extract.py`; bounded inputs, URL refusals and redirect checks |
| IOC types, refanging, counts and handoff buttons | Covered | `extractor.py`, `extract.html`; IP, domain, URL, hashes, email, CVE, flags and plain lists |
| Local decode helper | Covered | `decode.py`, `test_decode_pdf.py`; expansion explicitly parked in this pass |
| Wrapped PDF hashes and context | Covered slice; validation gap | Shared upload/fetch repair, synthetic text and real in-memory PDF tests; original report and wider table corpus still needed |
| ATT&CK ID and catalog lookup | Covered | `attack_catalog.py`, `attack.py`; Enterprise/Mobile/ICS IDs, catalog state, official names and replacement information |
| ATT&CK procedure extraction | Partial | HTML tables and explicit Markdown tables/lists work; HTML lists, div grids, pre/br blocks, ID-bearing headings, prose fallback and aligned PDF procedures remain |
| Procedure tactic/context inference | Partial | Captions, table tactic cells and Markdown headings work; offline probe loses an HTML heading above a table. Content-first column role selection is incomplete |
| Source-backed saved extraction and Enrich All | Deferred | Shared corpus, sighting links and job runner need the Phase 5 foundation; source metadata must be required when saved |
| CVE search, aliases, description, scores, CWE, products and references | Covered slice | `routes.py`, `service.py`, `cve.html`; source fallbacks exist; historical product coverage is incomplete |
| Exploitation status, actions and priority | Partial | Individual paths tested; F1 and F2 demonstrate inconsistent source sets |
| Since Last Review | Partial | Checkmarks, late arrivals, baseline and 90-day retention tested; F1/F2 evidence paths are missing; case links wait for Cases |
| Watchlist management and optional context | Covered slice | Vendor/product watches, optional version/exposure/owner/importance/date; product match is not confirmed asset applicability; F2 affects OT-only matches |
| Views, filters, counters and dashboard pinning | Covered entry points | All plus numbered 1-14; up to four saved pins; F1-F3 affect specific memberships and evidence |
| All Vulnerabilities and Known Exploited Watchlist filters | Covered UI; partial source coverage | Shared table and local catalog paging tested; exploitation predicate and OT matches need F1/F2 |
| Exploit Leads Without Reported Exploitation | Partial | Typed Metasploit exploit, Exploit-DB/XDB and claimed GitHub PoC leads; sighting-only exclusion fails in F1 |
| Microsoft Patch Tuesday and Likely Next | Covered slice | CSAF and monthly CVRF fallback, source precedence, scoped remediation, release types and More Likely filter; monthly comparison recorded in journal |
| Exploited and Unfixed | Partial coverage | Explicit Red Hat VEX no-fix statements with target scope; equivalent no-fix evidence from generic vendor/OT CSAF is stored but not consumed by this view |
| Edge and Perimeter; AI and ML Stack | Covered slice | Curated product/package evidence and separate keyword leads; generic vendor-source expansion and GHSA-only AI advisories remain |
| Ransomware-linked | Covered slice | KEV flags, ransomware.live and RVM with source links; its exploitation evidence must share the F1 predicate |
| Zero-Days and no-CVE reports | Partial | Project Zero confirmed rows and manual intake/linking work; F1/F3 affect linking and date-derived membership. Report corrections and automated intake remain follow-ups |
| Exploitation Sightings and Trending Attention | Covered slice | Dated, linked sightings and Shadowserver filter; Intruder rank/score/freshness; longer sighting history and polling remain deferred dependencies |
| Bulk feeds and local-first CVE details | Covered slice | Existing feed adapters, cached on-demand lookups and local-only display path; historical depth differs by source |
| Fortinet, Palo Alto, Cisco, Red Hat, SUSE, Chrome | Covered connectors; partial history | Current feed windows, per-source refresh and status; bounded Red Hat/SUSE batches remain pending. Cisco/Chrome are references, not parsed remediation/exploitation |
| GitHub, Metasploit and Nuclei evidence classes | Covered | CVE/keyword claims and bounded README checks; exploit/auxiliary/scanner/post types retained; Nuclei does not establish exploit code |
| GreyNoise per-CVE and Shodan CVEDB cross-check | Unimplemented scope decisions | Mentioned in original plans; no corresponding vulnerability module adapter. Existing IP enrichment is a separate capability |
| npm and GitHub Actions Supply Chain intake | Covered first delivery | OSV and GitHub malware cross-check, explicit alias merging, source-specific ranges, corrections/withdrawals, dates, filters and links |
| Broader Supply Chain toolkit | Deferred after v1 | Other ecosystems, ordinary advisory backfill, package history/pages, watchlists, lockfiles, deps.dev, Datadog and OSM; news reporting needs Phase 4 |
| Partial reloads and historical NVD coverage | Open scope decisions | Existing catalog SQL paging and local-first detail help; HTMX vendor/runtime integration and full historical load are not built |
| Raw JSON for every per-CVE source | Partial | Current Raw Facts includes normalized KEV, EPSS, NVD and SSVC; not a complete raw-source archive. Additional evidence is formatted and source-linked |
| Scheduled refresh, alerts, direct social/news feeds and exports | Deferred | Phase 5 foundation/collectors, Phase 4 reader and Phase 8 exports respectively |
| Sigma/network-detection indexes, evidence strength, performance work and broader decoding | Parked | Existing post-v1 decisions; no automatic promotion into Phase 2 scope |
| Browser and IDE extension indicator IDs | Unimplemented scope decision | Recorded as a research idea, not delivered by the current extractor or package feed |

## ATT&CK Acceptance Work

The 2026-11-09 survey is broader than the current parser. Recover only
procedures supported by source structure and retain an explicit evidence
type. Add fixtures for HTML lists, sibling grids, pre/br rows, heading
blocks and aligned PDF paragraphs. A prose sentence must be labelled
as prose fallback, with lower confidence for several IDs. Keep IDs only
when alignment is ambiguous. Test nearby HTML headings and combined
name/ID cells, content-first column roles, malformed tables, tactic
carry-forward and shared procedures. Compare against the original survey
pages when they are available, without claiming the synthetic cases prove
all publisher layouts. OCR, JavaScript-only tables and AI extraction stay
outside the deterministic slice.

## Decisions Needed, Without Expanding Scope Silently

Local snapshot: NVD has 22,742 records and CVE List has 425,847. Of
24,593 IDs selected by the current Exploit Leads query, 22,900 lack a
complete nonblank vendor/product pair in the NVD, CVE List product, or
KEV tables. This measures those source tables, not every possible source
or every rendered row. It supports a real historical-data gap; it does
not prove that a full NVD import is the best remedy.

All six new vendor statuses were error-free. Current imports were Fortinet
50, Palo Alto 25, Cisco 50, Chrome 15, Red Hat 100 and SUSE 137 notices.
The Red Hat index still reported 25,394 additional changed documents and
SUSE 28,812. These counts describe pending changed documents, not new CVEs.
No batch was drained during this audit.

The slowest GET in this single local pass was the dashboard at 7.789
seconds, followed by All Vulnerabilities at 3.355 seconds and Likely Next
at 2.571 seconds. These are observations, not a cold/warm benchmark or
attribution of the delay. Broader profiling stays in its existing parking
lot entry; the timings make that follow-up worth retaining.

1. Historical NVD backfill: choose a measured targeted fill or the proposed
   full historical import. The older 2 GB estimate is a historical planning
   estimate, not a new measurement. No download was performed by this audit.
2. Red Hat/SUSE: the connectors work, but importing 50 documents per click
   does not complete current changed-index coverage after a mass rebuild.
   Decide a resumable batch-drain workflow and distinguish recent publication
   coverage from historical revision coverage. Scheduling stays in Phase 5.
3. HTMX partial reloads: still a planned Phase 2 item, while broader latency
   profiling is parked. Decide whether partial reloads are a closeout gate
   or explicitly move them. Do not silently mark them delivered.
4. GreyNoise per-CVE, CVEDB and extension IDs: verify value, terms and
   access in a separate source review before treating them as commitments.
5. Optional detection indexes, case links, saved extractions, full Supply
   Chain scope and evidence-strength scoring retain existing deferrals.

## Documentation Corrections

The older five-tab description, planned Trending Attention text, generic
"vendor feeds remain" wording and probable/day-after zero-day description
are stale. Later decisions supersede Nuclei-as-exploit-code and blanket
Metasploit-module qualification. Patch deadlines were removed from triage.
AGENTS.md still described pinning and Patch Tuesday as next; CLAUDE.md's
status lacked the newer deliveries. Both status summaries are updated
together by this audit. Historical
journal entries remain historical, with a new checkpoint at the top.

## Repeat the Audit

From the project root, no running app is needed for these checks:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -t .
.\.venv\Scripts\python.exe -B -m tests.phase2_coverage_probe
```

Linux equivalents use `.venv/bin/python`. The probe prints observations;
read them against F1-F3 and the procedure requirements above. Its success
exit status means it ran, not that all phase acceptance checks passed.
Turn the intended corrected behaviors into regression tests during fixes.
