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

### 2026-11-10: NVD answers 404 for the configured key

The feed refresh reported "HTTP 404 from NVD" for the recent-changes feed,
and detail pages said "NVD has no record with that ID" for CVEs NVD
certainly has. Cause: the NVD_API_KEY in .env is rejected. NVD answers
an invalid, revoked, or unactivated key with HTTP 404 and a
`message: Invalid apiKey.` header (not 401). The same requests without
the key return 200. The key had worked on 2026-11-04 (health page showed
50 requests a minute), so it was replaced or revoked since, possibly in
the key rotation. Fix on the operator's side: request a new key, click the
activation link, put it in .env, restart. Code change: a 404 with a key
configured is now reported as a rejected key on the Feeds tab and the
detail page, since an unknown CVE comes back as 200 with no results. The
by-hand check is in the vulnerability runbook under Troubleshooting.

## Policy exceptions

### 2026-11-03: pypdf installed one day inside the one-week rule

pypdf 6.21.4 was installed at six days old, one day inside the dependency
policy's one-week rule, by operator decision: the 6.21.x line is security
hardening for hostile PDFs, which is exactly the input this toolkit feeds it.
The vetting record is in docs/runbooks/vetting-a-dependency.md.

## Build narrative

### 2026-11-17: Phase 2 checkpoint prepared for commit and push

The operator authorized one checkpoint commit and its push before the next
Phase 2 extraction pass. The pending working tree includes earlier approved
AI/ML and OT views, passive C2 feed browsing, Trending Attention, sourced
sightings, CVE evidence presentation, Microsoft monthly fallback, optional
watchlist context, local decoding/PDF repair, six vendor connectors, and
the F1-F3 evidence corrections. Include their tests, source reviews,
roadmap and runbooks together. Proposed message:
`Advance Phase 2 coverage and unify vulnerability evidence`.

Reviewed 88 changed/new/deleted paths, including removal of the superseded
GitHub-only table template. Scanned the candidate files without printing
matching values for secret-like tokens, private keys, personal home paths,
runtime databases and conversation exports. No candidate was flagged.
Verified the intended GitHub repository without exposing remote credentials.
The pre-commit transcript guard is retained. The post-push result and
commit identifier will be recorded in the next working entry. Continue
with deterministic ATT&CK procedure layouts after this checkpoint.

### 2026-11-17: Fixed Phase 2 audit findings F1-F3

The operator approved fixing all three consistency findings. Clarified
that ATT&CK procedures belong to Phase 2 report extraction: preserve a
report's technique, tactic and observed procedure, not generate actor
attribution or hunts. Supply Chain's npm and GitHub Actions first slice
remains in Phase 2. Other ecosystems, ordinary advisory backfill, package
history, lockfiles and package watchlists retain their earlier post-v1
scope. No additional feature was deferred by this clarification.

`evidence.py` defines the shared positive-source rules and derived SQL
views. Catalogs, SSVC active, rolling exploitation sightings, the current
per-CVE sighting assessment, ransomware.live, RVM and positive linked
manual reports feed the same membership contract. The report service
uses those facts before priority/actions are computed. A report-only CVE
opens locally. Unknown reports do not promote it. Linking produces a
review event and invalidates counter state. Unlinking removes the current
assertion and preserves the original report and event history. Another
independent source continues to count. Positive per-CVE lookups survive
cache expiry and errors; a later successful corrected response can
remove their own assertion. This is not a full sighting-history feature.

The OT source now supplies shared fix/mitigation flags, CVSS fallback,
watchlist product pairs and review evidence. Generic vendor products
also fill shared display and filter gaps. A fallback displays an actual
vendor/product pair from one source instead of independently taking
alphabetic minima. Edge and Perimeter applies its curated matches to
these additional advisory facts. The source's product/version scope is
retained. The badges remain leads to check against that scope.

KEV records retain typed date context and validated report-date fields.
EUVD's explicit exploitedSince can supply an exploitation observation;
datePublished cannot. Project Zero discovery and patch dates remain
context, while its explicit zero-day classification remains confirmed.
Catalog addition, source-report and Microsoft positive-revision dates
retain their meanings. The first-date summary names the meaning. Legacy
EUVD/Project Zero rows with ambiguous dates stay unknown until a source
refresh supplies typed data. No dates were invented during migration.
SQLite can normalize February 30 into March, so calendar validation is
explicit. Publication/patch fallback and malformed dates cannot create
the early-exploitation lead. A linked confirmed manual report qualifies
for Zero-Days without requiring missing CVE publication metadata.

The additive migration preserves existing records and review history.
It adds date metadata/validated fields, a current sighting-assessment
table, and four derived views. View definitions are replaced in one
transaction at startup so existing databases get the current query rules.
Existing newly connected OT/report facts can appear as first tracked in
Since Last Review; that time describes local tracking, not vendor release.

Regression tests cover report-only local rendering; P1/Hunt and view
membership; unlinking; independent surviving sources; sighting, lookup,
ransomware and RVM exclusions; cached SSVC/counters; OT scope, scores,
watchlist/filter/review behavior and corrected advisory membership;
paired product fallbacks; EUVD explicit and fallback dates, invalid dates,
legacy rows and Project Zero patch/discovery context. A shared test
fixture copied a CISA record to Shadowserver with a new date but retained
CISA's typed date. Corrected the fixture to specify its own source-report
date rather than discarding provenance in production code.

The audit probe prints the expected fixed results for F1-F3. The full
suite ran 393 tests with 392 passing and one missing-pypdf-path skip.
Twenty-six live page/filter checks passed after migration, including a
real OT CVE with Patch/Mitigate evidence. The app was restarted on
127.0.0.1 with the final schema and code. Source feeds were not refreshed
and no external report, credential or indicator was uploaded.

Live data exposed avoidable query cost from repeatedly evaluating date
JSON inside membership checks. Added a date-free membership view generated
from the same positive-source conditions, and validate/store date fields
once at ingestion. The membership count fell from roughly 0.7 seconds
to 0.036 seconds in local checks. Full navigation profiling remains parked;
these changes address work introduced by this evidence integration.
Final observations: Known Exploited membership count 0.033 seconds;
Zero-Days count 4.214 seconds; first dashboard GET 23.27 seconds; Likely
Next 3.00 seconds; Zero-Days page 7.20 seconds; Watchlist-filtered catalog
1.64 seconds; OT detail 0.23 seconds. All returned HTTP 200. These single
local observations are not benchmark claims. The first dashboard is still
slow. Keep the performance issue open, including counter calculation,
matching and pinned-view hydration; do not describe the module as fully
optimized because membership improved. Two immediate warm dashboard
requests took 4.46 and 4.53 seconds, both HTTP 200. Treat cold counter
calculation and repeated navigation as separate measurements at the
parked performance review.

Roadmap, runbook, audit-resolution note and both agent status summaries
are updated. ATT&CK layout gaps and other Phase 2 scope decisions remain
open. No dependency was added. No git operation, commit or push was run.

### 2026-11-17: Phase 2 coverage audit and decoder expansion parked

Audited the current working tree against the entire Phase 2 roadmap,
later scope decisions, journal, runbooks, implementation and tests. The
full report is
[Phase 2 coverage audit](review/2026-11-17-phase2-coverage-audit.md).
This pass changes documentation and adds an offline audit probe. It does
not fix application behavior, refresh feeds, install dependencies, restart
the app, or run git operations. No commit or push was performed.

All 15 view entry points exist, including All Vulnerabilities, but that
does not close the phase. The strongest findings are cross-feature gaps:

- A linked manual report can make a detail show Exploitation Reported and
  Confirmed Zero-Day while priority remains P5 and the action Monitor.
  Known Exploited, Zero-Days and review events omit that linked evidence.
- A sighting-only exploitation report can produce Hunt while its CVE is
  still included in Exploit Leads Without Reported Exploitation.
- An OT CSAF fix and workaround give Patch/Mitigate and CVSS 8.8 on the
  detail, but the shared row gives Monitor without a score. The exact
  vendor/product is absent from watchlist matching and review events.
- EUVD's publication fallback is excluded from the detail's first
  exploitation date but can still drive Possible Zero-Day membership.
- HTML tables recover procedure text, but a nearby HTML heading loses
  tactic context. HTML lists and prose produce IDs without procedures.
  The remaining grids, pre/br blocks, ID-bearing headings and aligned PDF
  procedures still need the deterministic extractor work promised by the
  2026-11-09 survey. Real publisher fixtures need separate validation.

These observations are reproducible with
`python -B -m tests.phase2_coverage_probe` using the project venv. The
probe uses synthetic data and a temporary database, and imports the suite's
network refusal guard. It prints observations rather than asserting that
incorrect behavior is desired. Future fixes should add regression tests
for the corrected contracts, including corrections and unlinking.

The existing suite ran 381 tests, with 380 passing and one skipped. Thirty
read-only local page/filter requests returned HTTP 200. These checks show
that entry points work and existing fixtures pass, not that the missing
cross-feature requirements are covered. No Linux runtime or original
MuddyWater PDF was revalidated. No external source review was repeated.

Public-data aggregates showed 22,742 NVD records and 425,847 CVE List
records. Of the 24,593 IDs in the current Exploit Leads query, 22,900 have
no complete nonblank product pair in the NVD/CVE List/KEV source tables.
That is a source-table measure, not a complete census of all evidence.
Red Hat and SUSE still report 25,394 and 28,812 pending changed documents.
Their healthy connector status is not complete historical coverage.

Single-pass GET timings were 7.789 seconds for the dashboard, 3.355 for
All Vulnerabilities and 2.571 for Likely Next. Do not infer a cause from
those numbers. Keep the existing post-v1 performance profiling task and
decide HTMX partial reload scope separately.

Updated stale roadmap and runbook summaries, including current navigation,
Trending Attention, deadlines, evidence classes and zero-day wording.
Refreshed status in AGENTS.md and CLAUDE.md without changing the working
agreement. Broader Supply Chain, scheduler, alerts, saved extractions,
case links, Sigma coverage and exploitation evidence strength retain their
existing deferrals. GreyNoise per-CVE, CVEDB, extension IDs, older NVD
backfill and partial reloads need explicit scope disposition, not an
assumption that they are done.

Recommended next implementation batch: F1-F3 in the audit. Share the
positive-exploitation evidence contract, make OT remediation/products
available to shared consumers, and retain date meaning across inference
and display. Then finish the remaining ATT&CK procedure layouts. The
decoder is sufficient for now; its broader expansion is explicitly parked
with candidates and acceptance checks below. Phase 2 remains open.

### 2026-11-17: Local decoding, wrapped PDF hashes, and vendor coverage

Completed the three requested Phase 2 slices together. No new dependency,
AI feature or phase transition. Existing work from earlier passes was
preserved. No commit or push was performed in this pass.

The extractor has an explicit Decode Text form. `extract/decode.py`
handles plain Base64 UTF-8, PowerShell UTF-16LE, Base64 with gzip/zlib/raw
deflate, character-code lists, and JWT header/payload JSON. The original
input and decoded text stay in the response. Decoded commands are not
executed; the normal indicator extractor processes the output. JWT
signatures are not verified. Input and decompressed-output limits are
enforced, including truncated or concatenated compressed streams.

`extract/pdf.py` now returns a Document with per-hash context. It joins
hex fragments over short line or page boundaries, skips numeric footers
and repeated hash headings, and retains recent headings, detection labels
and trailing annotations. Two adjacent valid MD5s are not joined without
an explicit SHA256 heading. Upload and URL-fetch paths share the repair.
The result exposes PDF Row Context rather than losing the reason a hash
appeared in the report. This is best-effort text-layer repair. Scanned
PDFs and arbitrary multi-column row reconstruction are outside the slice.
The original Trend Micro report was not available locally; tests use
synthetic text and a real in-memory PDF, not a claim of testing that report.

Vendor coverage is in `feeds/vendors.py` with `vendor_notices.py` and
two local SQLite tables. Vendor Updates is a separate tab linked from
Patch Tuesday and Feeds. It filters publisher, publication month and
Watchlist, paginates notices, and links their CVEs. Fortinet follows the
CSAF links embedded in its RSS; Palo Alto reads its documented JSON list;
Cisco and Chrome retain public feed references; Red Hat and SUSE process
their advisory CSAF change indexes. Microsoft and OT views keep their
existing entry points. No Cisco OAuth account or new key is needed.

Structured fixes and scoped workarounds flow into shared table actions,
CVE detail, fallback CVSS, optional product matching, and Since Last
Review. A plain feed reference does not assert a patch or exploitation.
Corrections replace evidence for the advisory revision rather than
leaving removed CVE links behind. A known vendor-only CVE opens locally.
The detail names the scoring publisher and displays original version
scope. Long scope lists show the first 100 entries and direct the analyst
to the original notice; full evidence remains stored locally.

Live checks found and corrected several assumptions that synthetic
fixtures initially missed:

- Fortinet's public RSS redirects to its file host. Use the canonical
  HTTPS filestore URL directly. Its CSAF dates omit timezones, so retain
  dates rather than manufacturing UTC times. RSS revision dates determine
  whether a linked advisory needs another download.
- Cisco RSS dates also omit timezones. Preserve the date. Remove feed
  tracking query strings from source links.
- SUSE publishes some JSON with invalid UTF-8 prose. Replace undecodable
  bytes with replacement symbols and show a source warning, rather than
  guessing cp1252 or discarding the complete advisory. One real document
  is 46,169,553 bytes. Use a 64 MB cap for SUSE and 32 MB elsewhere.
- Red Hat and SUSE regenerate old advisories in bulk. Their latest
  change timestamps do not mean latest vulnerability publication. Process
  newer numbered advisory IDs first within the changed set. Each refresh
  takes up to 50 documents from the last 45 days and reports pending
  batches. Large historical continuation remains open and is not silently
  presented as complete coverage.

Validation includes new offline tests for all decoder formats, compression
limits, malformed inputs, browser cross-site refusal, escaped decoded HTML,
PDF repair and ambiguity, all six source formats, source identity and host
validation, revisions, retry/resume, and consistent actions across views.
Live POSTs tested decoding and PDF upload. Vendor Updates, Watchlist
filter, Feeds, Patch Tuesday and CVE detail from every publisher returned
HTTP 200. Final validation: 381 tests ran, 380 passed and one was skipped
because pypdf is installed, making the missing-pypdf branch inapplicable.
All six vendor statuses were error-free. Local totals were 377 notices
referencing 3,674 distinct CVEs: Fortinet 50, Palo Alto 25, Cisco 50,
Chrome 15, Red Hat 100 and SUSE 137. Red Hat still reported 25,394
additional changed documents and SUSE 28,812. These are pending batches,
not imported history. Chrome notice identity includes year/month/path
because Blogger can reuse filenames in different months. A regression
test and local normalization preserve distinct posts. Fortinet's unchanged
revision test confirms that a second refresh skips CSAF downloads.
Runbooks contain the exact repeatable commands.

Phase 2 remains open. Next useful work is a coverage audit to distinguish
remaining Phase 2 requirements from parked improvements. Chrome's
explicit exploitation statements, historical NVD coverage, and UI reload
work remain open. The full NVD download needs a separate scope decision.
Original-source exploitation evidence strength remains parked as agreed.
Do not jump to later phases because these three slices are built.

### 2026-11-17: Microsoft monthly fallback and Phase 2 workflow audit

The Microsoft refresh now reads recent monthly CVRF releases alongside
the per-CVE CSAF index. The cutoff is the start of the oldest month in
the existing initial 45-day window. Read the public update metadata
and download a month only when its revision changes. Construct the
Microsoft API URL from a validated release ID. A data-supplied link
does not select a download host. The monthly files are about 19 MB for
November and 32 MB for October in the checked snapshot.
[Microsoft API documentation](https://github.com/microsoft/MSRC-Microsoft-Security-Updates-API)
[Monthly API schema](https://api.msrc.microsoft.com/cvrf/v3.0/swagger/v3/swagger.json).

Each CVE keeps one advisory. Existing per-CVE CSAF records take precedence
over monthly records even when the monthly document timestamp is newer.
If a per-CVE record arrives later, it replaces the monthly fallback.
Monthly updates are applied in one transaction with their revision
checkpoint. A removed monthly entry removes only the corresponding
fallback and its Microsoft exploitation listing. Malformed downloads
preserve the previous snapshot and checkpoint. October includes
ADV260001, which is outside this CVE view and is skipped.

The parser preserves product IDs on remediations and converts HTML
description fields to plain text. Blank Release Notes placeholders
leave vendor-fix status unknown. A URL or fixed build, or substantive
fix guidance, provides evidence for the scoped fix. The UI links the
monthly source and shows Customer Action Required when the document
supplies it. Existing NVD and CNA evidence continues to contribute its
own patch references on a CVE page.

The first live refresh encountered HTTP 502 from the per-CVE index.
The refresh was corrected to attempt both sources independently.
The retry completed with 5,811 Microsoft advisories, including 3,068
monthly fallback records across the October and November releases.
All seven missing November 10 CVEs were loaded. Four belong in
Patch Tuesday and three Azure Linux CVEs belong in Also Released.
The live November views had 1,093 scheduled and three Also Released
records, covering all 1,096 release-day records from the earlier
comparison. Each of the seven CVE detail pages displayed the monthly
source and evidence. Product-specific remediation was checked on
CVE-2026-109467.

The workflow audit found that the previously agreed optional watchlist
context was still missing. It is now implemented and editable for old
and new watches. The fields are version, exposure, business importance,
owner, and last-confirmed date. They are optional local reference fields.
The existing vendor and product matching rules still determine watchlist
membership. Old entries migrate with blank context. An invalid date or
cross-site update leaves the entry intact. These behaviors are covered
by offline store and route regressions.

Ran 363 offline tests with one skip. Thirty live GET checks passed across
the dashboard, all 15 views, feeds, watchlist, review inbox, exploitation
reports, supply chain, and representative filters and pagination. The
live watchlist form rendered all optional fields. Writes and validation
were verified with temporary-database tests to preserve the live watches.
The seven monthly CVE details took 0.05 to 0.20 seconds in this run.
The remaining Phase 2 scope includes
the decode helper and wrapped PDF hashes, grid and PDF procedure
extraction, additional vendor feeds, and older CVE product coverage.
Scheduled refresh, document saving, queued bulk enrichment, and alerts
depend on the Phase 5 foundation. The later Supply Chain backfill,
package watchlist, lockfiles and remaining ecosystems stay in their
existing post-v1 scope. Phase 2 remains open.

### 2026-11-16: November Patch Tuesday check and Markdown ATT&CK evidence

Check the November release against Microsoft's public monthly CVRF and
per-CVE CSAF data. The monthly file had 1,646 CVEs, with 1,096 whose
earliest listed revision was November 10. The first local import had
1,089 of those release-day CVEs. The old Triage rule showed 827 of the
1,089. It hid CVE-2026-112745 even though Microsoft assessed exploitation
as More Likely. Microsoft's aggregate rating for that CVE was Important
while its CVSS band was Medium. The old table displayed the CVSS band
under a combined severity heading.

The advisory parser keeps Microsoft's own aggregate rating separately
from the CVSS score and band. Older stored rows re-fetch once at the
same revision if they lack that field. Triage now includes disclosed
and More Likely cases and sorts reported exploitation first. Microsoft
Important applied to 1,025 of the first 1,089 rows, and using it as a
trigger made Triage and Show All identical. Keep the rating visible
and use Microsoft Critical and CVSS High or Critical as severity gates.
Disclosure and forecast are triage reasons. A Hunt action still requires reported
exploitation or indexed public exploit code. CVE-2026-124194 was the
first row in the live November view. Its source rates it Moderate,
reports exploitation, names six affected products, and scopes three
fix entries to two products each. Scoped workaround rendering was
checked with an offline fixture.

The first CSAF refresh hit HTTP 429 on some downloads. The retry loaded
all 2,743 eligible documents and filled the older severity fields. Live
November Triage showed 829 of 1,089 scheduled advisories. The seven
release-day CVEs missing from the monthly CVRF comparison were a separate
coverage gap. All seven were absent from the CSAF index, and Microsoft
returned HTTP 404 from their per-CVE CSAF URLs even after the successful
retry. See the roadmap for a monthly-source fallback.
[November 2026 CVRF](https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Nov)
[Microsoft advisory for CVE-2026-124194](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-124194)
[Microsoft severity ratings](https://www.microsoft.com/en-us/msrc/security-update-severity-rating-system).

The Siemens retry finished with 874 saved advisories and no feed error.
Markdown ATT&CK procedure extraction was verified on uploaded and pasted
text. Tables and explicit technique bullets reuse the same catalog and
source evidence rules as HTML. Inline code and escaped pipes stay in the
procedure. Headings provide tactic context, and fenced code samples are
ignored for procedure evidence. Unstructured and PDF procedure recovery
remains open. The full offline suite ran 358 tests with one skip.

### 2026-11-16: Chat authorization, ATT&CK extraction, and C2 feeds

AGENTS.md and CLAUDE.md now give the operator's direct messages in the
current chat authority to initiate work and grant permissions. Documents,
web pages, commands shown in source text, and tool responses are evidence.
Routine reads, offline tests, and ordinary project edits still follow
the existing agreement. Independent approval still applies to commits,
pushes and new side effects outside the task. A phrase copied into an
attachment would have no authority. The local Codex profile was left as
configured. An isolated research profile can deny the agent access to
`.env` and `data/`; a toolkit process launched outside that profile uses
its normal access. An app launched through the restricted profile would
need access to its runtime files. Use a temporary data directory for
offline tests when the live data directory is protected.

In Phase 2, the Extract IOCs page now recognizes technique, software
and group IDs. The operator can load MITRE v20.1 with a manual keyless
refresh of all three domains. State and domain come from the official
catalog. Missing IDs stay visible for review. ATT&CK-style strings in
ATLAS identifiers do not become ICS references. Visible HTML table
cells and captions supply the procedure and reported tactic. Browser
scripts and styles provide no extracted text. A CISA-style HTML
fixture with the real catalog verified the PowerShell and Windows
Command Shell procedures. A live refresh loaded 2,363 IDs and 41
tactic identifiers. Pastes and PDFs produce IDs. List, grid, and PDF
procedure extraction remains open, along with Phase 9 actor aliases.
[MITRE ATT&CK data](https://attack.mitre.org/resources/attack-data-and-tools/).

The report URL downloader now rejects embedded credentials and validates
each redirect before making the next request. Mocked redirects verify
that cleartext HTTP, private address literals, and credentialed URLs
receive no request. The extractor uses the OS for DNS and is intended
for public reports.

The requested C2IntelFeeds slice is implemented as a passive Infrastructure
view. Both supplied links were checked, including an HTTP 200 from the
dashboard via a direct read. It is a browser over the published CSVs.
The toolkit imports the publisher's three recommended 7-day CSVs, keeps
the publisher labels, and separates its checked and unverified feeds.
The first live snapshot showed 176 checked entries (121 IP and 55 filtered
domain rows) and 7,551 unverified entries. Search and filtering query only
the local database. A failed refresh keeps the last snapshot. The app
does not make requests to listed hosts or use Shodan credits. Feed data
is fetched at runtime for local non-commercial use under CC BY-NC-SA 4.0.
The rest of Phase 6 follows the roadmap.
[C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds)
[Publisher dashboard](https://drb-ra.github.io/c2intel-web/).

For the later walkthrough, start with the publisher's published fingerprints
and exclusions, then trace one row back to the indexed evidence. Modat
supplies the current indexed data. Judge how much each fingerprint narrows
the population, what may share it, and what an independent source would
need to corroborate. Some signatures in the publisher's documentation have
redacted criteria. The Phase 6 research notes explain how to design and
evaluate our own passive hunts.

Ran 357 offline tests with one skip. Repeatable commands are in the IOC
extraction and infrastructure runbooks. Also resumed the earlier Siemens
import. It now has 694 saved advisories, up from 336. The publisher
returned HTTP 429 partway through the retry, so the import remains
partial and the next refresh can resume.

### 2026-11-16: Trending Attention, sourced sightings, and First Steps

View 14 reads Intruder cvemon's public hourly RSS. The published
rank and Hype Score describe social media attention. The shared
CVE table shows exploitation separately from this signal. The
parser keeps four fields: CVE ID, rank, score, and snapshot date.
It discards RSS text, links, and attachments. Source links use
the fixed Intruder host and validated CVE IDs. A malformed feed
keeps the last good snapshot. A snapshot more than three hours
old carries an age warning. Monthly and other historical trends
are outside the scope of this snapshot.
[Publisher feed documentation](https://cvemon.intruder.io/feeds).

The public Vulnerability-Lookup refresh now retains an attribution,
date, count, and link when provided for records marked exploited.
The row count describes received records. The live source includes
social and catalog links, so a large count can reflect repeat
reporting. The Shadowserver Source filter uses the source marker or
the Shadowserver domain. History still covers the 48-hour import
window. Legacy summaries keep their counts until the next refresh.

First Steps uses the current CVE fields and links to the evidence.
Reported exploitation triggers an exposure and hunt step. Patch
and explicit Red Hat no-fix evidence use their named source and
product scope. The fallback says patch status unknown. Public
exploit references, Exploit-DB, XDB, and Metasploit exploit modules
can trigger a behavior review step. This adds no AI or dependencies.

During the credential review, NVD recent changes and VulnCheck KEV
were found to use the bulk downloader's default redirect behavior.
Both authenticated requests now refuse redirects. An offline
regression uses dummy keys and verifies that the redirected host
receives no requests. The toolkit uses vendor API keys with their
respective services, and enrichment searches send the selected IOC.
Loopback binding limits inbound access. The active Codex session
allowed broad file reads with restricted shell networking, including
read access to the workspace as configured. Git ignore does not
restrict reads. The review used configuration and code without
printing credential values or modifying the Codex profile.

The running app loaded 10 ranked CVEs and rendered First Steps on
CVE-2025-29927. The 48-hour sightings refresh saved 1,257 aggregate
rows and 105 exploitation source rows, 74 with Shadowserver
attribution. One oversized upstream page was skipped and the
snapshot status says so. The offline suite ran 354 tests with one
skip. Next open Phase 2 work includes remaining watchlist and
vendor coverage checks, the extractor work in the Phase 2 handoff,
and staged follow-ups with their dependencies.

### 2026-11-15: Direct Siemens and Schneider Electric advisories

Extend the existing OT & ICS view with public direct vendor feeds.
Prior CISA data remains in the database. Each source has its own
refresh and status. Siemens publishes a ROLIE JSON index with 874
advisory entries in the checked snapshot. Schneider's public
directory had 294 indexed paths, including security bulletins with
the SESB prefix. The first CISA refresh after this change reloads
the public archive to recover publisher links from previously stored
advisories. The parser now accepts published CISA IDs with revision
suffixes and the legacy ICSA-16-231-01-0 path.
[CISA CSAF](https://github.com/cisagov/CSAF)
[Siemens ProductCERT advisory policy](https://cert-portal.siemens.com/advisory-policy/)
[Schneider Electric CSAF directory](https://www.se.com/.well-known/csaf/).

The importer validates an indexed filename and pins the document
request to the configured publisher. It checks the identity in the
document before replacing a prior revision. Vendor notices and
selected details are fetched at runtime for the local database.

Group a CISA advisory under a direct vendor advisory only when CISA
links to a single recognized vendor ID and both documents contain
the CVE. The vendor entry shows its own evidence first. Expand
CISA Advisory Coverage for CISA's date, product scope, guidance
and original link. Keep separate entries for other advisories on
the same CVE. The CISA Industrial and Medical filters and the
publisher filters use source membership even when entries group.

The unpaced temporary test hit HTTP 429 from Siemens after
708 saved advisories. The importer now paces Siemens requests
and stops after a batch returns 429. A retry resumes with missing
or newer revisions. The Schneider test completed independently.
Regression tests cover the stop and retry behavior, non-publisher
ROLIE links, exact publisher grouping, and separate advisories that
share a CVE.

The running app loaded 3,999 CISA advisories and 283 Schneider
advisories with CVEs. The Schneider filter returned data. The detail
page for CVE-2025-6625 showed Schneider SEVD-2025-224-05 with CISA
ICSA-26-260-04 under CISA Advisory Coverage. The first live Siemens
refresh hit HTTP 429 at the index. A later retry loaded 336 Siemens
advisories before another 429. The Siemens filter and SSA-104023 on
CVE-2026-0266 both worked with the saved data. The remaining import
can resume from Feeds > Refresh Siemens ProductCERT after the
publisher limit clears. The offline suite ran 350 tests with one skip.

### 2026-11-15: CISA OT, ICS, and Medical, view 13

The operator chose **OT & ICS** for the view title. It stays
pinnable under Vulnerability Intelligence with Industrial Advisory
and Medical Advisory filters.

Phase 2 resumed with CISA's industrial and medical advisories.
The live view and CVE detail use the same stored advisory
evidence. The table supports the existing Watchlist and
exploitation filters, separate Industrial Advisory and Medical
Advisory tags, and dashboard pinning. The default date is the
latest advisory revision across a CVE's matched documents.

#### Source and import

CISA's CSAF provider metadata returned HTTP 403 from this
environment. Its own public GitHub repository documents the OT
feed and serves a working distribution. The first refresh reads
the repository ZIP and selects only public ICSA and ICSMA JSON
members by path. The downloaded ZIP was about 22 MB, with about
97 MB of selected JSON. The archive and individual documents
have size limits. Parsing reads data in place from the ZIP and
never extracts a source file onto the project filesystem.
[CISA CSAF repository](https://github.com/cisagov/CSAF).

The matching change index had 3,879 distinct advisory paths.
One source document was a draft and contributes no CVE
membership. One archive document had a revision date earlier
than the same snapshot's change index. Store the document's
revision date for display and the indexed timestamp for sync.
Later refreshes fetch newer indexed paths. When a download
fails or returns a revision older than its index, retain the
last import and retry on the next refresh. Successful
revisions replace that advisory's old CVE memberships in a
single SQLite transaction.

#### Analyst evidence

Resolve CSAF product IDs to filed versions and groups. Preserve
the status of each version, including First Fixed, and show
remediation next to the named products it applies to. An
explicit fixed version or a vendor fix with a resolved scope
can produce an OT Advisory Fix. A scoped workaround or
mitigation can produce Mitigate. Advisory self-links with
generic instructions supply a citation without producing a
mitigation action. Known Exploited continues to use its own
tracked exploitation evidence.

#### Validation and next work

The full temporary import produced 3,878 CVE-bearing advisories
and 12,593 distinct CVEs. The running view showed 12,578 after
applying local rejection status, with 518 under Medical
Advisory. The live import and page render took about 8.6
seconds. A repeat refresh completed without retry errors.
CVE-2026-111594 displayed the InterSystems IRIS for Health
product and ICSMA-26-295-01 link. Tests cover draft exclusion,
overlap, scoped product names, a fixed version without
remediation text, dashboard pinning, and retry behavior.
[CISA InterSystems advisory](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsma-26-295-01.json).

The live import ran before the final First Fixed rule. During
development a scoped SQLite update set `patch = 1` on 128 OT
advisory rows whose stored product states explicitly said Fixed
or First Fixed. A fresh import runs that rule during advisory
storage.

Direct vendor feeds are the next extension of this view.
Schneider Electric's public changes CSV answered HTTP 200.
Siemens ProductCERT's public ROLIE JSON answered HTTP 200.
Check each publisher's revision and product-scope conventions
before importing. Where a vendor advisory is republished by a
catalog, retain the original publisher and document identity
so both copies do not inflate coverage.
[Schneider Electric CSAF](https://www.se.com/.well-known/csaf/)
[Siemens ProductCERT CSAF feed](https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json).

### 2026-11-15: One first reported exploitation date

Use **First Reported Exploitation** in the shared CVE summary.
Select the earliest usable date and show the source beside it.
Candidates are dated positive catalog entries, VulnCheck's dated
exploitation citations, CISA SSVC active assessments, Microsoft
advisory revisions reporting exploitation, CIRCL exploitation
sightings, and the publication date of linked reports that assert
active exploitation. The date describes the available reporting
record. It can change when an earlier report is ingested.

ENISA EUVD can fall back to the CVE publication date and Project
Zero can fall back to the patch date. The local rows do not
distinguish those fallbacks, so they can establish Exploitation
Reported while the date remains unknown. PoCs, generic mentions,
vulnerability validation, and SSVC `none` provide no exploitation
date. The detail view now shows source links and assessments without
duplicating dates. The original inputs remain in the local store.
The running app showed 2026-11-15 from VulnCheck KEV for
CVE-2026-119618 and 2023-10-10 from CISA SSVC for CVE-2023-4966.

### 2026-11-15: CVE detail evidence and response time

The operator walked through CVE-2026-119618. The local VulnCheck
KEV row lists it on 2026-11-15 and cites Coalition. The CISA SSVC
assessment in the CVE record is dated 2026-11-13 and reports no
evidence at assessment, Automatable No and Technical Impact Total.
The summary now says Exploitation Reported. The details retain
each source and date and link to the catalog and underlying
citation. The priority reasons still explain known-exploited
list membership.

CIRCL's public sightings response supplies a Karen IT article
URL with type `confirmed`. CIRCL uses that type for analyst
validation of the vulnerability. Its separate `exploited` type
records reported exploitation. The new sightings display makes
the distinction, keeps original HTTP(S) references, and links to
the upstream CVE when source details are unavailable. Older
cached sightings may have only source names until refreshed.
Exploitation and PoC sightings stay in their source categories.
[Vulnerability-Lookup sightings documentation](https://www.vulnerability-lookup.org/user-manual/sightings/).

Affected Products follows the summary. Use NVD ranges when
available and show CVE List product names with a direction to the
CVE record for other ranges. MITRE CWE links use short labels
for frequent IDs, including CWE-362 Race Condition. Refresh
Feeds downloads and parses the MITRE catalog locally. The live
catalog was version 5.0 with 984 weakness names. The SQLite sync
record keeps the source, version, copyright, and terms link.
[MITRE CWE catalog](https://cwe.mitre.org/data/downloads).

Exploit Code and Detection Templates shows Metasploit types,
Exploit-DB, XDB, Nuclei, source-linked PoC sightings, and GitHub
claims or exploit references. Combine feed and lookup GitHub
matches by repository. Display the matching excerpt when available
and point to the text on supported browsers. Bare mentions stay
out of the page. Preserve the Claimed PoC label for self-reported
text. Recognize variations such as proof of concept,
proof-of-concept, exploit code, and exploit script near the CVE.
An NVD-tagged GitHub file or release can link straight to the
artifact. Move general References to the end and park the
CVE-specific OTX pulse card as optional context.

Opening a known CVE reads stored NVD, CVE List, catalog, and cached
per-CVE evidence. Unknown CVEs still use the normal network
lookup. Fetch Source Updates bypasses caches for NVD, GitHub,
CIRCL sightings, and the CVE record. The rolling sightings feed
can add newer exploitation evidence between manual lookups.
The running app returned HTTP 200 for three normal detail opens
at 138 ms, 52 ms, and 54 ms. These are local server timings on the
current catalog. The live check verified both exploitation dates,
the Coalition and Karen IT links, and the LLCForge PoC claim
in the exploit section. Supply Chain also returned 200.
Regression coverage includes a local CVE whose mock transport
fails if any vendor request is made, a dated SSVC assessment
alongside a KEV listing, source URLs, Github filtering, and a
mock MITRE catalog refresh. The complete suite ran 345 tests,
with one skipped.

### 2026-11-15: AI and ML Stack, view 10

The operator approved the Red Hat VEX checkpoint. It is local commit
`ab42e64`, Add Exploited and Unfixed view with Red Hat VEX. The Git
runbook shows how to stage only the Red Hat roadmap and journal hunks.
The last verified remote checkpoint remains `f43350d`.

#### Membership and Evidence

The AI and ML Stack view reuses the vulnerability table, watchlist
filter, and dashboard pin. It joins three pieces of structured evidence:
an exact curated affected vendor and product in CVE List or NVD, an
affected package filed in the CVE record, or CWE-1427 in the record.
Match Evidence shows the original value and links to the source.
Membership and reasons derive from stored evidence and the curated
rules on read, so a source correction takes effect on the next view
load without rebuilding a second membership table.

The local catalog has CIENA MCP and MCPJam Inspector entries. Bare
product names would classify them as the official MCP SDK and Inspector.
The product rule requires both vendor and product. Package rules
check the registry if the CNA filed a collection URL. Older records
with distinctive package names can match with Registry Unspecified.
Ambiguous package names such as `mcp` and `torch` require a matching
affected vendor and product or a known registry. PyPI names follow
its punctuation normalization rules.

Needs Review matches whole phrases and words in stored CVE titles
and descriptions. It shows the term and source, excludes CVEs that
already have structured matches, and leaves dashboard totals and
pins on structured matches. Adding coverage after confirming a
lead is a rules-file change.

#### Feed Compatibility and Sources

Keep the primary CWE for existing consumers. New CVE List imports
save all filed CWE IDs and preserve the registry inferred from the
CNA package's `collectionURL`. SQLite adds the fields at startup.
Existing rows keep their primary CWE and package name. A CVE List
delta updates revised records. A full reload backfills secondary
CWEs and registries in historical records where the source supplies
them. GHSA-only advisories still need an intake path.

Valyu's [2026 AI-tooling dataset](https://www.valyu.ai/blogs/mcp-ai-agent-vulnerabilities)
(CC BY 4.0, 2,675 rows in the checked CSV) informed the starter list,
including Dify. Runtime inputs are the curated identifiers and local
CVE evidence.
Primary checks included [Langflow CVE-2026-33017](https://www.cve.org/CVERecord?id=2026-33017),
[Flowise](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-g98q-rm45-q9h8),
[Dify](https://github.com/langgenius/dify/security/advisories/GHSA-phpv-94hg-fv9g),
[MCP Inspector](https://github.com/modelcontextprotocol/inspector/security/advisories/GHSA-4fc4-wcmh-4g86),
and [MITRE CWE-1427](https://cwe.mitre.org/data/definitions/1427.html).

#### Verification and Next Work

The running app returned 761 structured CVEs and 783 keyword leads.
The Dify vendor filter rendered the filed `langgenius / dify` pair.
The initial Needs Review scan took 8.4 seconds on the local store.
SQLite now prefilters likely text in bulk before applying exact
word boundaries in Python. The same 783 leads loaded in 3.8
seconds in the next check. These are single-run timings.

The regression test covers NVD and CVE List product evidence,
registry mismatches, PyPI spelling variants, secondary CWE-1427,
ambiguous names, rejected records, whole-word leads, and the
dashboard pin. The Phase 2 view after this is OT, ICS, and Medical.
Start with CISA's advisory coverage and keep vendor remediation
evidence tied to the affected product and advisory revision.

### 2026-11-15: Exploited and Unfixed, view 7

The operator approved the previous triage batch. It is local commit
`5682ee4`, Improve vulnerability triage signals and filters. GitHub
was last verified at `f43350d`. The Git runbook records the exact
commands for the triage commit. The new Red Hat work is still local.

#### Source and Membership

Red Hat's public per-CVE CSAF VEX feed supplies explicit product-level
status. The index is a CSV of relative paths and revision timestamps.
The current sample had 76,669 records, about 4 MiB, and 811 IDs
intersected the local Known Exploited view. The oldest update in that
sample was 2025-08-22. A separate button keeps the first wave of
downloads out of the normal vulnerability feed refresh. No key or
dependency was needed.

The parser resolves product IDs and group IDs from product branches,
full product names, and relationships. It intersects the explicit
`none_available` or `no_fix_planned` targets with named affected
products and removes conflicting fixed, unaffected, or under
investigation targets. It keeps workarounds only when their scope
overlaps the unfixed evidence. Other fixed targets are indicated
separately and can be inspected in the source. A CVE with only a
general advisory or a missing patch reference stays outside this
view. The view still requires Known Exploited membership.

SQLite stores the index date, document date, normalized evidence,
and fixed target count per CVE. Refresh skips known revisions,
keeps the previous evidence on failure, and retries failed revisions
on the next run. When a new revision clears the last unfixed target,
the CVE leaves the view. The view and CVE page both show the source
revision date. In the unfixed view, the actions are scoped to
the unfixed targets, so a fix listed for a different release cannot
produce a Patch badge there.

- [Red Hat VEX format and terms](https://redhatproductsecurity.github.io/security-data-guidelines/csaf-vex/)
- [OASIS CSAF 2.0 specification](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)

#### Verification and Follow-up

Four public advisories passed parser checks and a real refresh into a
temporary database. The rendered view returned HTTP 200 and included
`CVE-2024-21626`, `CVE-2026-116690`, and `CVE-2026-90436`.
`CVE-2024-3094` carried no affected no-fix targets and stayed out.
The full offline suite ran 344 tests with one skip. The new route
test covers group and relationship resolution, a temporary HTTP
failure, retry, the mixed fixed/unfixed case, scoped mitigation, and
removal after a revision fixes the last affected target. Its first
assertion checked the whole page for an excluded CVE and matched
the feed error message. The test now checks CVE row links separately.

The live app was restarted. Exploited and Unfixed and Feeds both
returned HTTP 200 and the refresh button was visible. The full
Red Hat import into the live store remains pending. The vulnerability
runbook has the test and local HTTP commands. Coverage beyond Red
Hat's rolling index and other vendors remains open. A later pass can
add another vendor with an explicit product-scoped no-fix field.

### 2026-11-15: Likely Next, recent sightings, and score disagreement

The operator asked for one reviewable batch before the next commit
approval. This Phase 2 batch changes three triage workflows and uses
the existing feed tables. No schema migration or dependency was added.
The last pushed baseline is `f43350d`. The new edits are local.

- **Likely Next.** A CVE qualifies through a FIRST EPSS score of at
  least 10% or the Microsoft advisory's Exploitation More Likely
  assessment. The latter can qualify a CVE without an EPSS score.
  Show both reasons when both apply. The Microsoft badge links to
  the advisory section and shows the source's revision date. The view
  excludes rejected records and exploitation already recorded in KEV,
  SSVC active assessments, stored exploitation sightings, or the
  ransomware group feeds. Manual exploitation reports stay separate.
  The saved data uses the latest imported Microsoft revision.
- **Recent Sighting.** The filter in Known Exploited uses the latest
  Vulnerability-Lookup `exploited` day bucket. Today and yesterday UTC
  qualify. The feed collects about 48 hours of data, but SQLite stores
  days, so an exact rolling window cannot be reconstructed. The first
  exploitation date still drives the existing date filter and sort.
  The table shows the date of the last stored sighting separately.
- **Score Disagreement.** Compare a dated FIRST EPSS score with the
  CVSS shown to the analyst. High EPSS means at least 50%, paired with
  CVSS below 7.0. Low EPSS means at most 1%, paired with critical CVSS
  at 9.0 or above. Both scores are required. These cutoffs are the
  toolkit's triage choices. See `signals.py` for the shared rule.
  The CVE detail page explains the two signals and the shared CVE
  tables can filter on them. The priority calculation is independent.

The first catalog query evaluated severity and EPSS against every
catalog entry and took 8.04 seconds in the read-only check. The
revised query narrows to CVEs with high FIRST EPSS or a potential
critical CVSS before it applies the usual source precedence. It
returned the same 16,258 matches in 3.38 seconds.

The full offline suite ran 343 tests with one skip. New tests cover
Microsoft-only and dual qualification, exclusions for rejected and
exploited CVEs, sighting dates and Watchlist, and the score filter
in both the Python and SQL table paths. Restarted the live toolkit.
Likely Next, Known Exploited, and All Vulnerabilities each returned
HTTP 200. The live Recent Sighting filter returned 90 matches.
The live Score Disagreement filter returned 16,258. The local store
had zero Microsoft advisories, so Likely Next displayed the load
link. Microsoft qualifying rows were verified in the offline
fixture. The next Microsoft live check starts with **Feeds → Refresh
Microsoft Advisories** and then **Likely Next → Microsoft More Likely**.
The vulnerability runbook has the test and HTTP check commands.

Next recommended Phase 2 slice is **Exploited and Unfixed** using
explicit vendor evidence that a fix is unavailable for a specific
affected product or release. Use Unknown for gaps, and keep lifecycle
and mitigation evidence visible. First identify a source with a reliable
explicit no-fix field, then test it with both an affected release with
no fix and a different affected release that has a fix.

### 2026-11-15: Edge and Perimeter, view 8

The operator approved the Exploitation Reports commit and requested
Edge and Perimeter as the next Phase 2 slice. The approved report
files and related roadmap, journal, and runbook edits went into
`80082c7`, Track exploitation reports before CVE assignment.
On 2026-11-15 the operator approved pushing Edge and Perimeter
(`f43350d`), Exploitation Reports (`80082c7`), and Supply Chain
(`4250728`) together. GitHub's `main` was verified at `f43350d`.
The Git runbook records the push and verification commands.

The view at `/vulnerability-intelligence/views/edge` classifies
affected products using 29 curated families in `edge.py`. It reads
vendor and product pairs already stored from NVD, the CVE List,
exploited lists, and the Ransomware Vulnerability Matrix. It ignores
punctuation, spacing, and case and requires a complete pair. It
checks every affected pair and excludes rejected CVEs. One CVE can
match several families. Combined labels such as FortiOS & FortiProxy
map to both named families. In the table, the main vendor and
product come from the first sorted match. Vendor filter options
include every matching vendor. Expand Edge Match to see all reasons,
including the original source spelling. The same reasons appear
on the CVE detail page.

The starter list was informed by the Matrix's Network Edge and
File Transfer Servers files (BushidoToken, CC BY 4.0). A Matrix
category is too broad to use as automatic membership. PaperCut
is grouped under file transfer and FortiClient EMS under network
edge. Both are outside this initial product list. Cisco IOS XE
and Juniper Junos extend the routing and switching coverage.
Review an affected product in the authoritative source before
adding an alias. A product match describes the affected technology.
Check deployment and configuration for exposure.

- [Ransomware Vulnerability Matrix](https://github.com/BushidoUK/Ransomware-Vulnerability-Matrix)
- [Cisco IOS XE advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z)
- [Juniper SRX advisory](https://supportportal.juniper.net/s/article/2026-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-SRX-Series-Multiple-vulnerabilities-resolved)

The read-only local benchmark found 2,569 CVEs.
Initial membership took about 1.1 seconds. The shared table rows
took about 1.2 seconds to build. Spot checks found CVE-2024-3400
(PAN-OS), CVE-2023-20198 (IOS XE), and CVE-2023-34362 (MOVEit Transfer).
The offline suite ran 340 tests with one skip. The new integration
test covered evidence from all four source types, a compound product
label, a secondary vendor filter, Watchlist, rejected records,
unrelated products, and a dashboard pin.

After restarting the app, the live view returned HTTP 200 and
showed 2,569 matches. The first smoke check expected CVE-2024-3400
on page one. The second checked pagination and found it on page
two of the Palo Alto Networks and exploited filter. Exploitation
Reports still returned HTTP 200. No feed refresh was needed for
this feature. The vulnerability runbook has the offline test and
the local verification commands.

Phase 2 remains active. The next suggested slice is to carry
Microsoft's Exploitation More Likely assessment into Likely Next
using the stored MSRC data. Keep the source assessment visible
and apply the existing exclusion for reported exploitation.

### 2026-11-14: Exploitation reports before CVE assignment

The local app can record an exploitation report before an identifier
exists. Open Views or Search and follow Exploitation Reports. The
Zero-Days view links to the same page. The report list is paginated and
has a Show Unlinked Reports filter.

`reports.py` validates the source, affected product, evidence summary,
report date, optional exploitation date, and evidence statuses.
`store.init_schema()` creates `exploitation_reports` in the existing
SQLite store. A local numeric ID stays stable after CVE assignment.
The source URL and optional source record ID together deduplicate
submissions. A repeated submission opens the existing row. A source
URL is stored as a citation and the app does not fetch it.

The form records patch, public vendor advisory, and CVE assignment
status at the time of exploitation. All default to Unknown. Active
exploitation with a date and documented absence of all three yields
Confirmed Zero-Day. Active exploitation with an incomplete timeline
yields Possible Zero-Day. A documented patch, public advisory, or
CVE at that time yields Exploitation Reported. Unconfirmed
exploitation has its own label. These are assessments of the
source evidence the operator entered.

Link CVE accepts a syntactically valid CVE ID even before it appears
in the local feeds. The CVE detail page links back to the report.
Updating or removing the association changes only the linked CVE
and link time. The source, timeline, and original assessment stay on
the report. These records do not enter the KEV feed or recalculate
CVE priority.

Verification: the focused test first exposed an incomplete mocked
CVE detail response. The fixture was corrected to include the raw
evidence fields the template renders. The full offline suite ran 339
tests with one skip. The tests exercised a confirmed report, unknown
and present evidence, duplicate submission, invalid dates and URLs,
cross-site POST rejection, and a later CVE link with a backlink.
The live toolkit was restarted on localhost. Exploitation Reports
and Supply Chain returned HTTP 200 and the Zero-Days page linked to
the new workflow. Record creation and CVE linking were exercised in
temporary test databases. The vulnerability runbook has the exact
commands and a manual walkthrough.

Still open: automated intake and handling a publisher correction to
a stored source report. Keep those separate from CVE association.
For the next Phase 2 slice, Edge and Perimeter can reuse the stored
product evidence, shared table, and Ransomware Vulnerability Matrix
categories. The first decision is which categories count as edge
products and how to show the reason each CVE matches.

### 2026-11-14: Phase 2 handoff and remaining work

Phase 2 is still active. The operator asked to work through it one item
at a time. Use the build order in ROADMAP.md and review the current
feature in the running app before starting a new phase. This entry is
a checkpoint for the next agent.

The build entry immediately above records the completed manual
no-CVE workflow and supersedes the recommendation at the end of
this checkpoint.

#### Built and Verified

- IOC extraction accepts pasted text, public HTTPS report URLs, and
  PDF or text uploads. It deduplicates IOCs and routes CVEs to
  Vulnerability Intelligence. See the IOC extraction runbook.
- Vulnerability Intelligence has the CVE detail page, Dashboard,
  Watchlist, Exploits & Detection, Feeds, and named Views. The built
  numbered views are 1 through 6, 9, 11, and 12. All Vulnerabilities is
  also available. All Vulnerabilities and Known Exploited both offer a
  Watchlist filter. Dashboard pins, independent action badges, and
  Since Last Review with 90-day history are built.
- Microsoft Patch Tuesday is built from the MSRC CSAF index. The
  parser was checked against live advisory samples. A full monthly
  review of the default Triage filter remains to be recorded.
- The Supply Chain tab is in local commit `4250728`. The app was
  restarted and its refresh was run against the live local store.
  Both sources reported success on 2026-11-14. The app showed 2,528
  npm report rows and five GitHub Actions rows. The test suite at this
  checkpoint ran 336 tests with one skip. GitHub's last verified
  checkpoint in this handoff is `c16e07a`. The Supply Chain push has
  separate approval pending.
- Supply Chain spot checks: search npm for `@zread/cli-win32-arm64`.
  The GHSA and MAL source entries appear under the same package report
  with their own ranges. Search GitHub Actions for
  `tj-actions/changed-files`. The 2025 source publication and the 2026
  local import date appear separately. Use the advisory for the
  compromise window, since the table shows version or ref bounds.

#### Open Phase 2 Work

- **Exploitation reports without a CVE.** Store a source identifier,
  source link, product, evidence, and dates independently of a CVE.
  Link the CVE when one is assigned. The current Zero-Days view only
  handles CVEs. Project Zero listings are Confirmed Zero-Day. Dated
  exploitation evidence on or before publication is a Possible
  Zero-Day lead. A report without a CVE needs explicit evidence about
  exploitation, patch, and disclosure status for the confirmed label.
- **Five unbuilt views.** View 7 Exploited and Unfixed needs explicit
  no-fix evidence for the affected version. Missing patch data stays
  Unknown. View 8 Edge and Perimeter needs a curated product list.
  View 10 AI and ML Stack needs validated package or product matches
  and the match reason. View 13 OT, ICS, and Medical needs vendor or
  CISA advisory feeds. View 14 Trending Attention needs an attention
  signal distinct from exploitation. The Dashboard already shows
  EPSS risers.
- **Finish existing views and detail pages.** Known Exploited needs a
  recent-observation filter tied to observation dates. The current
  Exploitation Sightings view covers the feed's 48-hour window. Likely
  Next uses EPSS and still needs the Microsoft Exploitation More
  Likely signal. Patch Tuesday needs a full monthly triage check and
  later vendor coverage. Watchlist entries still need the optional
  version, exposure, owner, importance, and last-confirmed fields.
  Score disagreement and the separate rule-based verdict lines remain
  open. The current action reasons already explain Patch, Mitigate,
  Hunt, Monitor, and Investigate Applicability.
- **Coverage and extraction.** Older CVEs still have gaps in vendor
  and product fields. The roadmap proposes a full NVD backfill.
  ATT&CK ID extraction and table-aware TTP capture are still planned.
  Read the extractor survey and fixtures in the journal before
  choosing a parser. The decode helper and wrapped PDF hashes are
  additional extractor follow-ups.

#### Dependencies and Deferred Work

- Saved extractions and Enrich All need the shared corpus and job
  runner. Scheduled refresh and watchlist alerts need the scheduler
  and alert inbox. Review events can link to cases when cases exist.
  Vendor news and social chatter have their own collector dependencies.
- Supply Chain package watchlists, lockfile checks, broader ecosystem
  coverage, and the ordinary vulnerability backfill are parked for
  post-v1. Vendor research reporting follows the Phase 4 feed. HTMX
  partial reloads, export work, and optional detection indexes remain
  tracked in the roadmap. The older roadmap summary of patch deadlines
  is superseded by the 2026-11-12 decision to omit them from triage.

#### Recommended Next Slice

Build the no-CVE report workflow before adding a new feed. Prove it with
one sourced report, a report whose patch or disclosure status is
unknown, and a later CVE assignment. Verify that the original source
and dates survive linking, and that the analyst can distinguish
exploitation reported from the zero-day assessment. Add the exact
verification commands to the vulnerability runbook. Continue recording
what changed, why, live checks, failures, and the next open decision at
each Phase 2 checkpoint. Keep the journal free of session transcripts
and private operator details.

### 2026-11-14: First Supply Chain feed

The GitHub malware endpoint returned no results for the Actions ecosystem.
The OSV Actions archive contained 64 advisories. The incident filter
selected four advisories covering five packages, including Reviewdog and
tj-actions. Generic code-injection descriptions were excluded from that
selection.

The npm index had 1,978 malware records changed in the first 30-day
window. Two OpenSSF records were checked against their OSV exports. Their
package names, affected versions, aliases, and published dates matched.
OSV added source metadata inside the affected records. This supports
using OSV for the primary feed.

A full keyless refresh in a temporary database loaded both sources
without errors. The table showed 2,528 npm report rows, five Actions
rows, and 285 leads. A separate route check rendered the Actions
results with HTTP 200. The running app's data was left in place.

### 2026-11-13: Vulnerability actions and review history

Microsoft remediation and explicit NVD and CNA references support the
same action badges. CNA workaround text is stored when a CVE record is
ingested or looked up. A general advisory link leaves patch status
unknown.

The review panel compares the current evidence with a SQLite baseline.
Only new signals enter the review history. A review action records the
acknowledgment. Mark All Reviewed uses the latest event ID from the
rendered page, so a refresh can add new unread items while it is open.
Events expire after 90 days. Active evidence stays in the baseline so
an old signal does not reappear just because its event expired.

### 2026-11-13: Local catalog and Microsoft release triage

The first All Vulnerabilities query took about 15 seconds on 404,849
local CVEs. It calculated every display field before paging. The revised
query selects the page of CVE IDs first, then fetches the complete display
fields for those rows. The default query took 2.7 seconds and the
Watchlist query took 1.3 seconds in a read-only check of the local store.

Microsoft's index uses the date a document changed. The advisory for
CVE-2026-94522 had a 2026-11-13 index date and a 2026-11-10 initial
release. That initial date puts it in November's Patch Tuesday. The
verified index held 10,146 advisories, with 2,754 changed in the initial
45-day window. A separate Feeds button lets the operator choose when to
run that first download.

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
~~~

### Phase 2: VulnCheck KEV and the dashboard review (2026-11-10)

~~~text
- VulnCheck KEV wired: cursor-paged API, 5,857 entries and 11,095 XDB
  exploit links on the first run (13 pages of 500, about 10 seconds).
  The XDB index itself answered 402 (subscription required) on the
  community token, so XDB coverage is limited to exploited CVEs.
  Citations (the reports VulnCheck cites as exploitation evidence) show on
  the detail page; entries VulnCheck's own honeypots confirmed say so.
- Dashboard review: tags moved under the CVE ID; "Listed as exploited";
  "Exploit code available?" as yes or no (hover for sources, the detail
  page has the links); "Why it's hot"; a CVSS filter (4, 7, 9) next to
  EPSS; sort, filter, and page links return to their table with a
  `#t-<key>` anchor instead of the top of the page. The New exploit code
  table left the Dashboard (the Exploits tab already showed the same rows
  over 30 days) and became a one-line count with a link.
- "advisory" in the Fix column, explained to the operator: NVD tagged a
  Vendor Advisory reference but no Patch reference.
- Trending was empty because EPSS had been loaded once (2026-11-03 scores);
  the 2026-11-10 refresh gave it a previous score, and it filled in.
- 2026-11-11: OTX pulses and CISA SSVC on the detail page. First live look
  at CVE-2024-3400: OTX returned 50 pulses from 4 authors, 39 of them one
  account's daily "Actively_Exploited_Kev" list, which pushed every real
  report off the first ten rows; pulses from one author with the same
  title minus dates now fold into one row. Another account clones
  AlienVault's pulses, so titles appear twice under different authors (left
  visible on purpose). One account pastes hashes and paragraphs into tags;
  tag, title and adversary lengths are capped. SSVC for CVE-2024-3400:
  active / yes / total, assessed 2024-04-17.
- Ingest everything, surface selectively (decided): KEV ignores CVSS and
  many exploited CVEs are medium severity, EPSS is needed for every CVE a
  page can open, and the exploit indexes are small. Filtering happens on
  the dashboard (heat, exploitation, exploit code), not at ingest.
~~~

## Research notes

### 2026-11-17: Public vendor notice endpoints

Inspected all six requested publishers' live formats and read applicable
publisher documentation before choosing endpoints. No third-party parser
code or publisher dataset was copied into the repository.

- Palo Alto's [API documentation](https://security.paloaltonetworks.com/api)
  documents the public `/json` list and per-ID JSON. The current list has
  25 notices with product, version, affected and fixed arrays. The
  authenticated or beta API is unnecessary for this slice.
- Fortinet's [news-feed guidance](https://community.fortinet.com/fortigate-3/technical-tip-fortinet-product-vulnerabilities-news-feeds-143896)
  and [monthly PSIRT note](https://community.fortinet.com/fortiguard-23/psirt-note-fortinet-psirt-and-monthly-psirt-advisories-94244)
  describe its public notices. The canonical
  [RSS](https://filestore.fortinet.com/fortiguard/rss/ir.xml) carries direct
  CSAF links and revision text. Live parsing was tested, including all
  50 linked current documents.
- Cisco's [PSIRT API documentation](https://developer.cisco.com/docs/psirt/obtain-all-advisories/)
  describes an OAuth workflow. The keyless
  [public RSS](https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml)
  works for references. A guessed public CSAF metadata route returned a
  login page, not JSON. Do not describe Cisco as a direct CSAF import.
- Red Hat's [provider metadata](https://security.access.redhat.com/data/csaf/v2/provider-metadata.json)
  points to its advisory and VEX distributions. Use the
  [advisory changes](https://security.access.redhat.com/data/csaf/v2/advisories/changes.csv)
  for this source. Existing Red Hat VEX no-fix evidence remains separate.
- SUSE's [public CSAF directory](https://ftp.suse.com/pub/projects/security/csaf/)
  provides changes.csv and year directories. Include SUSE and openSUSE IDs,
  excluding reposted third-party RHSA/ESSA IDs. Read its complete
  [license notice](https://ftp.suse.com/pub/projects/security/csaf/LICENSE):
  CC BY 4.0, changed from CC BY-NC in 2021. A search surfaced SUSE's 2025
  security-report PDF, but that full PDF was not read and was not used
  as implementation evidence.
- Chrome's [Stable Releases Atom](https://chromereleases.googleblog.com/feeds/posts/default/-/Stable%20updates?alt=atom&max-results=15)
  supplies the latest 15 posts. Some posts contain no CVEs and stay useful
  release notices. Parse only CVEs explicitly present in each post.

Fortinet and Cisco naive timestamps, SUSE malformed prose and large
product trees, and regenerated CSAF indexes are covered in the build note
above and synthetic regression tests. Historical backfill, Chrome's
explicit exploitation language, and automatic polling remain open.

### 2026-11-15: Feedly workflow library and skills

Reviewed both supplied skill bundles and the 44 Markdown prompts
across the four Feedly reports. The cyberattack tracker records an
original reporting organization, a separately graded claim and a
reproducible source passage. It can support both case timelines and
the parked exploitation evidence-strength work. The hunt prompts
trace a lead through feasibility and validation. The risk-reduction
skill records action and verification history, with organization-specific
scoring as a later option.

The prompt-by-prompt dispositions, source links, and suggested
regression fixtures are in
[the Feedly source review](research/2026-11-15-feedly-workflow-review.md).
The roadmap records these as candidates. Runtime prompt automation
belongs to Phase 11.

### 2026-11-12: HEARTH and candidate detections

- The HEARTH site and README describe a CTI-to-hunt drafting workflow.
  Its schema includes a hypothesis, data sources, false positives, and
  optional queries. The operator's test was issue 467 and the corresponding
  Keep Me Signed In draft. Both URLs returned cache misses, including an
  attempt to read the raw draft. The specific output was not verified.
- Use the format as inspiration. Start with a cited hypothesis and required
  telemetry. Add candidate pseudocode or queries that name the fields they
  need. A Sigma rule can describe log events. A YARA rule needs a relevant
  file or memory artifact. Keep the candidate label until validated.
- A useful cloud hunt draft should name the sign-in or audit records it needs,
  the behavior those records can test, and likely benign explanations.
  Identify gaps where telemetry cannot show the hypothesized behavior.
  Sigma conversion is a later feature. Query syntax, log mappings, and field
  names all need validation against the intended SIEM or EDR.

### 2026-11-11: sources review (12 repositories and the rest of the handoff)

- Full report: docs/research/2026-11-11-sources-review.md; the five
  detailed note files are beside it in docs/research/2026-11-11-sources/.
  Five research agents read about 1,300 links; each file ends with a list
  of links not read and why.
- The research tool's safety filter refused 11 URLs (Havoc and Sliver
  repositories and docs, MythicC2Profiles, two newtonpaul.com C2 posts,
  optiv/Freeze, one YouTube video). They were not retried another way.
  Read them by hand when Phase 6 is built.
- WebFetch saves any PDF it fetches to the session's tool-results folder
  without asking. Eleven PDFs landed there this way, one of them a leaked
  criminal manual (Bassterlord). None was opened. Lesson for future
  research briefs: tell agents not to fetch .pdf links at all.
- Two agents disagreed on the Ransomwhere export's licence (CC BY 4.0
  against "none named"); recorded as unresolved.

### 2026-11-11: operator's calls, RVM and Project Zero built, Kraven and PDFs

- Built the Ransomware Vulnerability Matrix (`rvm`) and Project Zero
  (`gp0`) feeds. First live run: 287 CVE-to-group pairs over 165 CVEs,
  and 414 zero-day rows for 2014 to 2026. View 9 went to 646 CVEs; view
  11 has 2,283 rows.
- RVM parsing traps: CVE cells joined with ",", "&" or "and", nicknames in
  brackets, and one row (CVE-2023-27350) whose dash is not valid UTF-8,
  so the CVE pattern accepts any separator character. Two spellings of
  one group ("Black Basta", "BlackBasta") are merged on a key without
  spaces or case. "Ghost/Cring" is one name, so "/" is not a separator.
- Project Zero trap: asking for a year tab that does not exist returns
  the sheet's intro tab with HTTP 200, so the parser checks the header.
  Date Discovered is "???" for every 2026 row; the patch date stands in.
- c2-iocs carries only IP, framework, port, country and publish date: no
  configurations. Dropped as a feed; the per-framework port observations
  stay as facts in the research notes.
- The research agents' "never ingest onion links and leaked chats" line
  was wrong for this project: Phase 5 already plans Tor collection and
  Phase 9 plans Ransomchats. Corrected in the decisions log. Agents still
  do not visit them.
- Deleted the Bassterlord PDF from the session's tool-results folder at
  the operator's request. The other saved PDFs were read in full by two
  agents: the UK "Detecting the Unknown" threat hunting guide (OGL v3),
  the Unified Kill Chain paper (GPL v2), Lockheed Martin's "Gaining the
  Advantage", CyberEdge's "Definitive Guide to Cyber Threat Intelligence"
  (2015), Heuer's "Psychology of Intelligence Analysis" (1999), and the
  CrowdStrike, Trend Micro and Lookout reports. One agent reported "no
  text" for two PDFs whose text layer is fine: re-check before relying
  on pypdf's first-page extraction as a "scanned" test.
- Kraven downloads (`Documents\Kraven downloads`, five repositories, about
  3,200 files) reviewed for the first time. None has a licence. The
  testing-environments Terraform holds a hard-coded password and a
  committed cluster join token (not copied anywhere).

### 2026-11-11: operator review of the module, Previdian, dataset handoff

- Overflow cause: the page was capped at 900 px and the CVE cell had
  `white-space: nowrap`, so a CVE with seven source badges stretched the
  Hottest table to 1,654 px and the stack table to 1,289 px. Fixed with a
  1,280 px page for this module, badges that wrap, and sideways scrolling
  inside a table's own box as the fallback (on the table, not the card:
  scrolling the card would clip the vendor drop-down).
- The roadmap's "Newly known-exploited (7 or 30 days)" needed its own
  window links because its rows came pre-cut from the store. It now takes
  view 1's rows and opens the "last" filter on 7 days; "any time" needed a
  value of its own ("all"), since an empty value brings the default back.
- Vendor chart fix found on the way: the vendor count took each CVE's
  date only from lists that carry a vendor, so CVEs whose earliest listing
  came from CIRCL's aggregation (no vendor) were dated later than in the
  monthly chart above it.
- Previdian through CIRCL: 376 assertions, all but one dated 2026. The
  note field carries title, affected product, CVSS, EPSS, "used in
  malware", and "listed N days ahead of CISA KEV". Earliest of our lists
  on 241 CVEs; ahead of CISA on 45 of the 101 both list, by 3.3 days on
  average. Only 4 CVEs come from Previdian alone.
- Research handoff (ChatGPT, 2026-11-11) checked by a research agent the
  same day. Corrections to the handoff: Fox-IT's 2022 dataset is on
  GitHub (fox-it/cobaltstrike-beacon-data); the Hugging Face corpus gives
  about 190,000 sightings and 56,800 payloads (rounded on the card);
  Project Sonar is access-by-request, not public; Feodo Tracker's datasets
  were empty (corrected the same day: frozen since 2026-03-04, not
  empty; see the sources review entry); ThreatFox's six-month cut applies
  to the API and exports, not the web pages; ArcSpan is 61,212 rows in all
  (50,600 is two overlapping train versions); joyce8/EMBER2024's preview
  showed Android samples, not the Windows set the name suggests; the
  domain-intelligence graph is 186 GB on the Hub (about 1 TB is the
  uncompressed source). KEVScope was first set aside for "future dates and
  negative days-to-KEV" without reading its card; that was wrong. The
  card defines days-to-KEV as KEV listing minus NVD publication, so a
  negative value means CISA listed the CVE before NVD published it, and
  the late dates are CISA due dates. Most of the C2 material (C2 Hunter,
  c2-iocs, C2-Tracker, Adversary-Hunter, both Malleable profile
  repositories) states no licence; Elastic's extractors are under the
  Elastic License 2.0. Left unchecked by that first pass (picked up in the
  sources review): Havoc and Mythic profiles, CyberSet, and about half the
  handoff's links. MWDB's access terms are still unchecked.

### 2026-11-11: views 5, 6, 9, 11 and 12

- Sized each rule on the live store before building: new and severe 354
  (347 by CVSS 9.0+, 146 by SSVC automatable plus total, overlapping);
  likely next 14,509; ransomware-linked 641 (CISA flags 361, VulnCheck
  630, ransomware.live adds 11); probable zero-days 2,270; exploitation
  sightings 21.
- Likely next: the roadmap's three EPSS clauses collapse into one. EPSS
  0.10 was already above the 95th percentile (the percentile clause added
  2,470 CVEs below 0.10, which is the opposite of "likely"). A rise of
  0.10 cannot end below 0.10. Kept the absolute line, which also matches
  the EPSS filter.
- Probable zero-days by how early the first listing came: 1,392 within a
  day of publication, 498 two to 30 days earlier, 380 more than 30 days
  earlier. The early ones are almost all VulnCheck, and samples were
  WordPress plugin CVEs assigned years after VulnCheck's first
  evidence (CVE-2015-9499 ShowBiz Pro, CVE-2020-36720 Kali Forms,
  CVE-2021-4380 Pinterest Automatic, CVE-2017-18580 Shortcodes Ultimate;
  1.7 to 4.9 years). Left in, explained on the page.
  The same-day ones include the November Patch Tuesday zero-days (Office,
  Chrome).
- Sightings: the store keeps only type, day and count per CVE, not the
  sighting's source, and only the 48-hour window, so "from Shadowserver in
  the last 7 days" became "any exploited sighting in the window".
- Ransomware.live links now set the ransomware badge in views (they did
  only through KEV before), and the badge's tooltip names the groups.
- Counters: the five new ones added about 0.3 s to every Dashboard load;
  with the watchlist's 0.66 s, the Views tab took 1 s. Cached until a
  feed refresh, a watchlist change, or a new day: Views tab 8 ms warm,
  Dashboard 1.4 s.

### 2026-11-11: the CVE List feed (cvelistV5)

- Release layout checked on GitHub: every hourly release carries that
  day's midnight snapshot (`<day>_all_CVEs_at_midnight.zip.zip`, 660.2 MB)
  and a delta of everything changed since midnight (`<day>_delta_CVEs_at_
  <HH>00Z.zip`, 0.3 to 0.6 MB in the early hours); each day also gets an
  `at_end_of_day` release with the whole day's delta. The repository
  README confirms the deltas are cumulative from the midnight baseline.
  Records sit under `deltaCves/` in a delta and `cves/<year>/<n>xxx/` in
  the snapshot.
- First load: 114 seconds for the download and 423,869 records, then the
  04:00Z delta (427 records). cti.db grew from 187 MB to 495 MB. 486,004
  vendor/product pairs over 260,219 CVEs; SSVC on 219,097 CVEs (active
  1,784, poc 47,487). All 1,784 "active" CVEs were already on an exploited
  list.
- Vendor coverage, CVEs published since 2026-10-01: 23,088 records, 1,418
  (6%) still without any vendor, against 76% before (NVD alone).
- Watchlist view grew from 52 to 426 CVEs with the CVE record's products,
  and slowed to 2.1 s (Python matching over every pair). SQL now narrows
  by vendor with `instr` first (0.7 s) and the matches are cached until
  the watchlist or a feed changes (0.01 s warm).
- Bug caught live: `A UNION B EXCEPT C UNION D` in SQLite runs left to
  right, so appending the SSVC-active set to the exploited set inside an
  EXCEPT added those 1,784 CVEs to "not yet exploited" (Struts
  CVE-2017-5638 appeared there). Fixed by bracketing the exploited set as
  a subquery; a test pins it.

### 2026-11-11: views 1 to 3 and the CIRCL KEV aggregation

- Vulnerability-Lookup `/api/kev/` held 6,521 entries. First full load,
  confirmed only, CISA skipped: KEVIntel 2,759, Shadowserver 1,417,
  Previdian 376, ENISA CSIRTs Network 82, CIRCL (its own catalogue, CTI
  feed and incident response) 26, SiberKapan 11, Check Point 1,
  host-logs 1. Distinct exploited CVEs went from 5,863 to 5,877: the
  catalogues overlap heavily with CISA and VulnCheck.
- Source names arrive with dots (`cti-feed.circl.lu`); they are normalised
  before mapping. A first load stored six rows under the raw names; they
  were deleted from the local database and reloaded.
- With the new catalogues, Hottest filled with 2019-2021 CVEs again
  (Log4Shell, Citrix CVE-2019-19781) because honeypot catalogues give old
  CVEs fresh dates and recency used the latest listing. Switched to the
  earliest listing. Two old CVEs (CVE-2017-12636, CVE-2011-3923) still rank
  high because 2026-11-09 is genuinely the first time any list named
  them.
- Performance: the dashboard took 4.5 s after the load; 3.7 s of it was
  the per-CVE hottest query. Rebuilt on the views' one-pass query: 1.4 s.
  View timings on real data: exploited 0.22 s (5,877 rows), watchlist
  0.14 s (52), code 0.59 s (26,995).
- NVD backlog: of 12,892 CVEs published since October with an NVD record,
  9,853 have no CPE product data (Awaiting Analysis or Deferred).

### 2026-11-11: supply-chain sources for the Phase 2 Supply chain tab

The operator proposed sources; each was checked for access, licence, and
fit. Findings:

- OSV.dev bulk data: per-ecosystem `all.zip` and `modified_id.csv`
  (`<iso date>,<id>`, newest first) at
  storage.googleapis.com/osv-vulnerabilities/; upstream licences listed
  per source (GitHub Advisory Database CC-BY 4.0, OpenSSF Malicious
  Packages Apache 2.0, Rust and Haskell CC0, Chainguard CC-BY-NC-ND).
  https://google.github.io/osv.dev/data/
- Change volume, measured 2026-11-11 from the `modified_id.csv` files over
  7 days: npm 620 (MAL 538, GHSA 82), PyPI 112 (GHSA 65, MAL 41, PYSEC 6),
  Go 208 (GHSA 127, GO 81), crates.io 97 (RUSTSEC 74, GHSA 21, MAL 2),
  NuGet 48, Packagist 39 (DRUPAL 24, GHSA 15), Maven 36, RubyGems 26
  (GHSA 19, MAL 7), GitHub Actions 7. These are changed records, not only
  new ones.
- OpenSSF malicious-packages: Apache-2.0 repository, OSV format, a live
  counter rather than a fixed total (the 238,000 figure found by search
  could not be confirmed). https://github.com/ossf/malicious-packages
- GitHub Advisory Database REST: `GET /advisories?type=malware`,
  ecosystem filter, cursor paging, up to 100 a page.
  https://docs.github.com/en/rest/security-advisories/global-advisories
- Datadog malicious-software-packages-dataset: Apache-2.0, `manifest.json`
  per ecosystem (npm, PyPI, IDE extensions, AI skills), about 29,847
  packages, samples in zip archives with the password "infected".
  https://github.com/DataDog/malicious-software-packages-dataset
- deps.dev API v3: Google API terms, caching expressly allowed, generated
  data CC-BY 4.0; GetPackage (versions, publish dates), GetProject
  (Scorecard), advisories. https://docs.deps.dev/api/v3/
- Aikido Intel: described by Aikido as AGPL-licensed, free to browse at
  intel.aikido.dev, product use needs a paid licence; no documented feed
  URL found. Dropped.
- Snyk: its API docs say most APIs are Enterprise-only; the free plan is
  for scanning one's own projects. Blog only.
  https://docs.snyk.io/snyk-api
- Checkmarx: the AppSec Knowledge Center (commercial) searches by package
  (every version, flagged vulnerable or not) or by vulnerability (details
  and affected packages). The package view is the model for the Supply
  chain tab's package page. Checkmarx Zero research posts are at
  checkmarx.com/zero-post/.
- Veracode bought Phylum's technology and team in January 2025, so
  Phylum's research now appears on the Veracode blog.
  https://www.veracode.com/press-release/veracode-acquires-phylum-inc-technology-to-transform-software-supply-chain-security/
- Sonatype publishes a quarterly Open Source Malware Index (Q3 2026:
  149,329 malicious packages logged, 1,960,846 since 2017). Its counting
  differs from OSV's, so the numbers are context only.
  https://www.sonatype.com/blog/q3-2026-open-source-malware-index-when-compromise-compounds
- Backstabber's Knife Collection: access by request with an institutional
  e-mail address; parked with the malware research corpus.
  https://dasfreak.github.io/Backstabbers-Knife-Collection/
- OSV bulk file sizes (HEAD requests, 2026-11-11): npm 220.5 MB, PyPI
  37.8, Go 12.9, Packagist 11.1, Maven 10.5, RubyGems 5.3, crates.io 3.8,
  NuGet 2.8, GitHub Actions 0.1; about 305 MB zipped in total.
- Triage (tria.ge): free researcher accounts get an API key; every
  submission to the free sandbox is public and cannot be deleted.
  https://us-sandbox.recordedfuture.com/docs/faq
- GitHub on a free personal account: secret scanning and push protection
  on private repositories need the paid Secret Protection add-on; both are
  free on public repositories, as are CodeQL and private vulnerability
  reporting. Dependabot alerts were enabled by the operator on
  2026-11-11.
  https://docs.github.com/en/code-security/getting-started/github-security-features

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

### 2026-11-17: Expand the Local Encoding and Decoding Workbench

The current helper is sufficient for the present Phase 2 slice. Revisit
after v1 rather than growing it while the evidence consistency work is
open. Candidate transformations:

- Hex to/from bytes; Base32 and Base85; explicit alphabet and padding
  variants where there is a clear report-analysis need.
- URL percent encoding, HTML entities, Unicode and JavaScript escapes,
  quoted-printable and ROT13. Keep byte encodings and text escaping
  distinct so the displayed result explains the operation used.
- Bzip2 and XZ/LZMA as bounded compression candidates. Evaluate archive
  members separately before accepting multi-file archives.
- XOR with an analyst-supplied key as a visible transformation. Distinguish
  encoding from encryption and require the needed key material locally.
- Encode as well as decode; explicit character sets; hex/byte previews
  and local file output for non-text results. Preserve undecodable bytes
  rather than quietly dropping them.
- Visible multi-step recipes with undo and an input/output preview for
  every step. Allow repeating a known recipe while retaining its exact
  operations and parameters. Link resulting text to IOC extraction.
- Format suggestions as labelled leads, not claims that a transformation
  is correct. Let the analyst choose the step. A printable result alone
  does not establish that the interpretation is right.

Keep the workbench deterministic and local. Do not execute recovered
commands or scripts, evaluate source-provided recipes as code, or send
input to an online decoder. Revisit CyberChef-style interaction as design
inspiration; review licences before importing code or recipes.

Acceptance checks: round-trip encoding where meaningful; standard test
vectors; malformed input and ambiguous alphabets; explicit errors for
unsupported binary/text conversions; bounded input, output, nesting,
steps and decompression time; inert HTML/script output; no external
requests or automatic input retention. Generated output should identify
its recipe so an analyst can repeat and explain the result.

### 2026-11-15: Case Attack Flow, inspired by FlowViz

FlowViz takes a report URL or pasted text, uses a model to draft an
interactive ATT&CK flow, and supports exports including STIX and
Attack Flow Builder files. Its docs and MIT-licensed repository were
reviewed for workflow ideas.
[FlowViz documentation](https://www.flowviz.io/docs)
[FlowViz repository](https://github.com/davidljohnson/flowviz).

Candidate placement is a view inside Cases. Start with analyst
authoring from saved report excerpts, logs, and case notes. Build on
the planned case graph and ATT&CK lookup. Let a step link to saved
IOCs, CVEs, tools, required telemetry, and candidate detections.
An ATT&CK mapping is optional. Use the evidence to decide whether a
connection means chronology, dependency, or an inferred relationship.
Save the cited excerpt or event with each finding. Leave gaps visible
where a report gives no sequence or supporting evidence.

For interoperability, evaluate CTID Attack Flow's STIX 2.1 extension.
Its action-to-action edge means dependency. Export dependency edges
only where the case supports that interpretation. Keep report ordering
and unverified relationships in the local case data. Test import and
export with a sample that has two possible branches and an unmapped step.
[CTID Attack Flow concepts](https://center-for-threat-informed-defense.github.io/attack-flow/introduction/)
[CTID Attack Flow language](https://center-for-threat-informed-defense.github.io/attack-flow/language/).

In Phase 11, consider a draft from pasted text or a collected report.
Show the source passage beside each proposed step, ATT&CK mapping, or
connection and accept edits at that level. The manual flow stays usable
with the provider set to none. Reuse the case's hunting package and
detection workflow to record whether telemetry exists and a candidate
detection has been validated.

### 2026-11-15: Exploitation evidence strength

Consider an evidence label in Exploitation Details once the app
can trace provenance. Use **Direct Observation** for an explicit
firsthand vendor, responder, or telemetry report. Use **Catalog
Assertion** for a reputable listing when its underlying evidence
is not available or has yet to be reviewed. Use **Relayed Report**
when the source quotes another report. Use **Independently
Corroborated** only when separate origins describe their own
observations. Keep attempts and confirmed compromise distinct.

Record the original reporting organization, link and report ID
where available, the upstream source each report cites, and the
kind of evidence. Test a vendor report repeated by a news outlet
and two catalogs as one origin. Test two security teams with
separate telemetry as independent observations. Test a media
reporter who conducted an original incident interview, and a
catalog entry with an inaccessible underlying citation. Avoid a
count-based or numerical confidence score while the source chain
is incomplete. CISA SSVC already accepts credible reports from
vendors, ISACs and threat researchers.
[CISA SSVC guide](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf)
[VulnCheck coverage criteria](https://docs.vulncheck.com/community/vulncheck-kev/coverage-criteria).

### 2026-11-15: Cross-module performance

After v1, profile the dashboard-to-CVE path, IOC enrichment, and
large vulnerability views first. Capture cold and warm request
times and measure SQLite queries, rendering, and each upstream
call separately. Compare repeat visits on an empty cache and a
populated cache using the same local dataset. Inspect slow queries
with SQLite EXPLAIN QUERY PLAN. Try concurrent feed refresh and
page navigation to check that recent local evidence stays visible
during writes. Track time to first useful results, source freshness,
and whether a cold provider or quota delay can block the page.
Consider expanding local-first results and progressive source
loading where this improves task time. Keep CVE-specific OTX
pulses available as a candidate opt-in context lookup if a later
investigation finds a concrete use for them.

The 2026-11-17 live navigation check measured AI and ML Stack at
5.19 seconds, Edge and Perimeter at 4.67 seconds, the catalog's
second EPSS-sorted page at 3.61 seconds, and the default catalog
at 3.16 seconds. These are single observations on the current
local data. Use them to choose repeatable profiling cases after v1.

### Public deployment and hosting (parked 2026-11-03), full text

The roadmap parking lot keeps a short summary. This is the full first-cut
design, to be revisited as its own hardening phase before any non-localhost
deployment.

~~~text
- Public deployment / hosting (parked 2026-11-03): if this is ever turned from
  a local-only tool into a reachable website, design the security posture
  before exposing it. Open questions to work through then, with first-cut
  first-cut notes as a starting point:
  - After AI is integrated, create a collections management archive where we store whatever reports we decide at the time to be relevant in an excel table or google sheets table with the following column and structure - Activity ID	Activity Descriptor	Activity Type	Activity Start	Activity End	Publication Date(s)	Threat Actor / Attribution	Attribution Confidence	Motivation	Target Industries	Target Regions	Targeted Technology	CVEs	Initial Access	ATT&CK TTPs	Malware / Tools	Activity / Impact	Relevance Type	Source(s)	Source Assessment (Admiralty)	Intelligence Gaps / Discrepancies	Organization Relevance / PIR	Collection Method	Review Status	Evidence / Validation Notes	Last Reviewed
ACT-2026-001	Hypothetical credential phishing targeting aerospace contractors	Reported campaign	2026-08-01	2026-08-20	2026-09-05	Unknown	Not assessed	Espionage (suspected)	Aerospace; Defense	North America	Microsoft 365	Not reported	Credential phishing	T1566.002; T1078	Not reported	Credential theft reported; downstream impact unknown	Direct sector; Technology	https://example.org/research/sample-report	Publisher A: B2 (illustrative; not assessed)	Attribution unknown; extent of access not established	Relevant to identity monitoring and phishing detection; PIR-001	Manual	Example — not validated	Entire row is synthetic demonstration data; example.org is a placeholder, not a source	2026-11-11 - with AI doing first pass data input from reports.
  - local AI model to analyze files (such as potential malware) and extract its configuration, metadata, PDB strings, hardcoded C2 information, loaded dlls, other relevant info, for tracking, correlation, research.
  - Lets exploire some ways to include the gui?
  - AI-powered deobfuscator (Label it as ClickFix script decoder?) Leverage similar techniques used in cyberchef? Or other online methods
  - Login-only vs fully public: default to authenticated (even a single
    account, or basic auth at a reverse proxy). The app spends metered API
    keys and exposes `/health` (key presence, versions), so an open instance
    lets anyone burn your quota and fingerprint the stack.
  - In ransomware tracker, also monitor for 8-k notices related to cyber breaches
  - Look into how breach.house contains their info stealer data, look at all their sources, find links, make them our sources, for info stealers and leaks in general. same with ransomlook.io, find their sources for ransomware leak sites and darkweb markets.
  - "Not storing sensitive data" is not the whole risk. Even with nothing
    sensitive stored, an exposed instance still risks: quota/credit theft
    (every open lookup spends your keys), being used as an SSRF/proxy to fetch
    attacker-chosen URLs through your host, resource exhaustion / DoS, and info
    leak via `/health` and error pages. And the `.env` keys themselves ARE
    sensitive and sit on the host.
  - Fillable templates maybe with brief guidelines for a structured analytic and forecasting techniques
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
  - Translator for foreign language forums, messaging boards, messaging apps, in general. (AI or is there non-AI tool?)
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
