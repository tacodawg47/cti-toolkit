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

### 2026-11-19: Built Static Artifact Reports and Resumable Vendor Imports

The operator approved the proposed static checks and continuing Phase 2.
Implemented the bounded wheel review using only the standard library.
scripts/artifact_strings.py reads ASCII/UTF-16 strings and Python constant
expressions, never evaluating or importing the artifact. Common Base64,
hex, escaped literals, constant concatenation and bounded gzip/zlib decoding
retain origin/transform details. Decoded Python values retain source line
numbers. Python attributes such as os.environ are not bare-domain evidence.
No extracted host is visited or submitted to a service.

The auditor now writes a new local JSON report with artifact/member digests,
destination candidates, locations, heuristic usage context, pattern findings,
bounded string previews and explicit limits. --baseline highlights new and
removed hosts and changed/removed files compared with a previous reviewed
report. It does not declare previously listed hosts trustworthy. Refuse
overwriting artifacts or earlier reports. URL credentials/query values and
common secret assignments are redacted where recognized; this is best
effort and reports remain private local material, not automatic exports.

Added archive input/member/count/expansion/ratio guards, bounded reads,
path/duplicate/symlink/encryption/compression checks, a cooperative deadline,
strong RECORD algorithms and CSV parsing, and rejection of unhashed payload
members. Source comparison now checks every top-level package/module and
avoids symlink/escaped-file reads. Syntax/string/decoding limits become
explicit hard findings instead of a false clean result. The helper is not
an OS sandbox, universal deobfuscator or binary emulator. FLOSS, an actual
monitored guest, custom unpacking and stronger worker isolation remain
separate setup/review work. No new dependency or monitoring driver was
installed. No downloaded code was executed.

For Red Hat/SUSE, added vendor_import_state and vendor_import_queue through
the normal additive schema initialization. Index refresh merges recognized
advisories changed within 45 days. Pending records do not age out or vanish
when a newer index window no longer lists them. Continue reads the saved
queue without fetching the index. Complete the exact saved revision only
after its advisory is parsed and stored. Newer revisions requeue the work.

Vendor Updates shows tracked/completed/pending/failed counts, last index
check and window cutoff, and failure examples. Runs can select upper limits
of 50/250/500 documents but also stop under a soft 60-second deadline and
128 MiB body budget. The next request must fit its full allowance; failed
requests charge their full allowance because the transport discards some
error/oversized bodies. An in-flight fetch can use the existing 120-second
timeout. Failed items do not block unattempted work. Explicit retry requeues
them; 429 leaves work pending and pauses. A publisher refresh also retries
failures. Source paths are revalidated against the fixed publisher pattern,
and the new POST uses the existing cross-site guard and validated batch
choices. No scheduler or automatic background continuation was added.

Targeted tests exposed one test-assumption mistake: the existing cross-site
helper uses Sec-Fetch-Site, not Origin alone. Corrected the test to exercise
the actual established contract. This pass did not broaden that shared
security helper. Offline tests cover queue/window persistence, no-index
resume, failure isolation, rate/body budgets, revision changes and request
scope; artifact tests use inert synthetic wheels, encoded/binary strings,
resource guards, baseline comparison, redaction and multi-package source
comparison. The full suite ran 437 tests: 436 passed and one expected skip.
Final focused suite ran 30 tests successfully after report/UI refinements.
Existing Starlette/httpx warning and synthetic invalid-PDF diagnostics remain.

Used standing app-restart authorization and verified the prior launcher
before restarting hidden. Logs are data/vendor-imports.*.log. Startup added
the new tables; GET Vendor Updates returned 200, showed queue/initialization
wording and preserved existing notices. Listener stayed 127.0.0.1:8000.
Pending-state controls were also checked through the test client with a
synthetic queue. No live index refresh, vendor document import, package
download, installation, external submission, git operation, commit or push
was performed. Preserve the unrelated local Claude settings file.

Updated the roadmap, paired instructions and repeatable runbooks. The
operator accepted targeted older-CVE metadata filling before a full NVD
history; implementation remains next. Phase 2 stays open for that work,
the separate original wrapped-hash report check, HTMX and optional-source
scope decisions. The saved vendor changed-window queue is not full vendor
historical coverage and has not yet been used to drain the live backlog.

### 2026-11-19: Clarified Acceptance Limits and Static Supply-Chain Review

The operator asked whether strings, deobfuscation and reporting embedded
domains would improve dependency safety, including when malware evades a
sandbox. Read the current wheel auditor and its tests, dependency and
isolation runbooks, current roadmap and publisher acceptance record. The
auditor already flags Python network/credential/dynamic-code/encoding
patterns and startup hooks. It does not yet inventory all domains, extract
binary strings or universally deobfuscate packages. No such new capability
was presented as implemented.

Reviewed MITRE sandbox-evasion/obfuscation descriptions and Mandiant FLOSS's
full README, theory and usage guides as passive reference. Recorded a small
review enhancement candidate: archive resource guards, string inventory,
bounded common decoding, domain/IP locations and call context, comparison
with the last reviewed release, and explicit unresolved coverage. Manual
domain review remains useful, but reputable hosts can receive stolen data
and domains can be constructed or obtained later. Plain-source reading is
more useful than strings alone for Python; binaries need other techniques.
Custom packing/runtime keys can require specialist reverse engineering.
No claim that arbitrary obfuscation can always be solved. Existing Defender
and monitored isolation remain complementary. No FLOSS tool was installed,
no sample submitted and no discovered domain contacted.

Clarified that the 5 MiB limit was a conservative acceptance-helper download
budget, not a parser/PDF/security requirement. The measured PDF was safely
retried with the already recorded 6 MiB cap. The 13 reports were a fixed
set of original-layout checks for the Phase 2 extractor, not dependency
adoption or a collection expansion. No repeat download occurred this pass.

Corrected the acceptance wording: no-ID reports already support IOC
extraction. Automatic behavior-to-ATT&CK mapping without explicit IDs is
what remains outside this acceptance slice. Phase 5 already plans permitted
browser rendering. Added explicit later candidates for local OCR with
page/region provenance and analyst-selected mappings with Cases; tool/model
selection and placement still need review under the no-AI-before-Phase-11
policy. Do not quietly treat an OCR recognition model as an approved
dependency. OCR/rendering do not establish truth or semantic mapping.

This was research and documentation only. No application code or dependency
changed, so the already-passing suite was not rerun. No installation,
runtime/security setting change, git operation, commit or push occurred.

### 2026-11-19: Original Publisher Acceptance and Approved Defender Process

The operator approved making Defender scanning part of the process and
allowing Microsoft cloud analysis of project artifacts downloaded from the
internet, while excluding personal local files. Added the same rule to
AGENTS.md and CLAUDE.md, and updated both dependency/isolation runbooks.
This is standing authorization for selected artifact scans, not permission
to install packages, change global Defender settings, scan personal folders
or upload private runtime data. Existing real-time sample submission is
system-wide; our selected scan path cannot impose a global folder boundary.

Clarified containment versus detection. A disposable guest with no host
credentials or networking limits harm even when no alert fires. Process
Monitor or a configured Sysmon inside a guest can add observation. Neither
was installed, and no sandbox/VM, driver, Windows feature or security setting
was enabled. No monitoring tool automatically establishes that a program is
safe. VM evasion, absent secrets and unexercised paths limit what is seen.

Continued Phase 2 rather than jumping ahead. Added our own passive
scripts/check_report_layouts.py to retrieve the fixed 12-page survey and
accompanying Recorded Future PDF, then analyze captures offline. Raw source,
extracted text, digests and local findings stay in git-ignored
data/phase2-acceptance-2026-11-19/. No original source fixture or code was
copied into the repository. All 13 sources returned 200. The first PDF
attempt stopped at 5 MiB. HEAD advertised 5,895,616 bytes; raised the per-file
guard to 6 MiB and retried only it, retaining the 30 MiB per-run cap. Retained
captures total 8,707,026 bytes. No external dependencies were installed.

Used the signed installed Defender binary via Platform/CurrentVersion to
scan only the incoming HTML reports, then the separately downloaded PDF.
Both completed with exit 0 and explicit no-threat output. The signature date
read before scanning was 2026-11-18. No signature update or global preference
change was made. Microsoft analysis was permitted for these public inputs,
but the output does not prove a sample was uploaded. No personal files or
private project data were selected. The scan is an additional check, not a
malware-free certificate. Never restore a future quarantined artifact just
to make the acceptance script finish without reviewing the detection.

The real captures exposed two false procedure associations that synthetic
tests had missed. Fortinet/Group-IB article wrappers were interpreted as
div grids, allowing a different table's contents to be attached to a
technique. Reject grid cells containing nested headings/tables/lists/report
sections, then recurse to real inner structures. Recorded Future's combined
tactic/name labels supplied false procedures for six IDs; match the known
tactic and catalog name instead. All 14 HTML grid IDs now have no procedure,
consistent with its PDF. Added two independent synthetic regressions. Kept
source/catalog name or tactic differences visible. Clarified in the UI that
aligned source text can be a general description, not observed behavior.

All 13 captures were processed with the local ATT&CK v20.1 catalog. Reviewed
candidate structures and representative aligned cells, not the truth of
every report claim or every row's semantic meaning. Full matrix and limits
are in docs/review/2026-11-19-publisher-acceptance.md. This does not cover
all 69 older survey renditions, OCR/JavaScript-only sources, or the separate
MuddyWater wrapped-hash original. Phase 2 remains open for that check and
historical-data/closeout decisions. Updated paired status notes accordingly.

The full offline suite ran 424 tests: 423 passed, one expected missing-pypdf
branch skipped because pypdf is installed. Existing Starlette/httpx warning
and synthetic invalid-PDF diagnostics remain. Used standing restart
authorization, verified the existing launcher, and restarted hidden with
logs in data/publisher-acceptance.*.log. Live local uploads of Recorded
Future and Fortinet both returned 200. Recorded Future rendered 14 rows
without procedure text, Fortinet rendered no false HTML Grid, and the new
general-description clarification appeared. Listener remained 127.0.0.1:8000.
No feed refresh or enrichment was requested. No git operation, commit or
push was performed. Preserve the unrelated local Claude settings file.

### 2026-11-18: Added IOC report context and clarified pre-install scanning

The operator approved adopting useful deterministic skill components while
keeping actual AI assistance in Phase 11. Added Report Context to each
extracted IOC: a bounded nearby excerpt from the refanged extracted text,
shown in an expandable section. Keep the first mention, retain existing
PDF hash-row context and do not infer maliciousness from a mention. No new
network action, storage, provider or dependency. This is a small Phase 2
evidence aid, not the later saved-document/case implementation.

Four regressions cover refanged context with a negative claim preserved,
bounded excerpts and duplicate ordering, earliest URL-host context, and
escaped markup/instruction-like text through the route. The last case
verifies passive rendering, not model prompt-injection resistance. The
complete offline suite ran 422 tests: 421 passed and one expected skip.
Existing Starlette/httpx deprecation and synthetic invalid-PDF diagnostics
remain. Original-report ATT&CK acceptance still needs its separate pass.

Read Microsoft Defender's current custom-scan and cloud-submission docs.
Read-only host queries initially failed in the command sandbox and succeeded
under the authorized read-only escalation. Antivirus and real-time
protection were enabled. MAPSReporting was 2; SubmitSamplesConsent was 1.
The latter permits automatic samples considered unlikely to contain personal
information. A custom host scan can therefore involve cloud disclosure.
No scan, signature update, remediation or setting change was run. Added
the exact manual workflow in docs/runbooks/defender-artifact-scan.md, with
completion/exit-code caveats and a disconnected-research option. Defender
adds a useful check; neither a miss nor matching artifact hashes certifies
software as harmless or detects every instruction attack.

The sandbox is for unfamiliar artifact research, disposable execution and
isolation from credentials. Normal development and the localhost app need
not move wholesale. Prepared sandbox configuration remains unlaunched.
No dependency install, account change or external sample submission occurred.

No commit or push was made for this pass. The operator's individual approval
workflow still applies. Preserve the unrelated local Claude settings file.

No listener remained on port 8000. Used the operator's standing app-start
authorization to start run.py in a hidden Windows process, with stdout and
stderr under git-ignored data/report-context.*.log. Local GET and synthetic
text POST to /extract both returned 200; the result included Report Context
and preserved the negative claim. The listener was 127.0.0.1:8000 only. No
feed refresh or enrichment was requested. Rechecked the 48 extraction tests
after a readability-only change: 47 passed, one skipped.

### 2026-11-18: Tightened passive dependency review after Agent Framework report

The operator asked whether the reported PyPI agent-framework compromise
affects this toolkit and how to isolate research cheaply. Read SecurityWeek
and its Wiz/SafeDep primary analyses. The linked Microsoft issue returned
404. Checked requirements and package/startup-file names without launching
the environments' normal Python: app venv 55 distribution directories,
audit venv 29, base Python 3.12 five, standard user site absent. No relevant
package declaration, distribution, module or malicious startup filename
matched. Only the expected setuptools .pth appeared in the app environment.
This is a scoped negative result, not a machine-clean or historical verdict.

The existing wheel auditor already flags .pth. Added sitecustomize.py and
usercustomize.py hard findings, including relocated members, and eight
inert synthetic-wheel regressions. None of the wheel contents was installed
or imported. The targeted tests passed under Python -I -S. Corrected the
auditor and runbooks: -I alone still loads site initialization; hashes and
wheels do not certify harmlessness; review release artifacts and transitive
updates before installation, not just the upstream repository.

Prepared docs/examples/research-offline.wsb and a manual isolation runbook.
The example disables network, clipboard, audio/video, printer sharing and
vGPU, maps no folders and runs no startup command. It was not launched and
does not enable the Windows feature. Host inspection reports Windows 11
Pro and a hypervisor, making Sandbox the first candidate; persistent Linux
VMs fit later repeated research. No OS feature, account, firewall, global
agent setting, allowlist, dependency or credential was changed. The paired
agent instruction files now point to the stronger release-review procedure.
Final full suite ran under -I -S with only the trusted project and existing
site-packages explicitly added: 418 tests, 417 passed and one skipped.
The 78-row skill matrix was checked against the installed directory names;
none is missing. The Sandbox XML passed configuration checks; it was not
launched. Research findings do not change the Phase 2 build sequence.
No new commit or push was authorized or performed.

### 2026-11-18: Retried extraction tests and completed deterministic layouts

The usage-limit rejection did not execute the declined test command. The
operator requested a retry after usage refilled. The existing 53 extraction
tests completed successfully, with the installed-pypdf skip. Continued the
already authorized Phase 2 procedure pass after the saved checkpoint.

Checkpoint `a07898b` (`Advance Phase 2 coverage and unify vulnerability
evidence`) was committed and pushed to main. The exact remote SHA was
verified. That approval covered that checkpoint only. The extraction and
research work below remains local until a new commit and push are approved.

Added bounded passive HTML structure extraction for lists, sibling div
grids, pre/br blocks and ID-bearing headings. Markdown headings can carry
following paragraphs. Column roles use catalog content before header hints.
Catalog label splitting accepts full/sub-technique names and parent::child
prefixes. Names and IDs alone do not become procedures. Evidence records
carry source structure, paragraph alignment or prose fallback labels;
sentences with three or more IDs show Low confidence. These labels describe
association, not source credibility or independently verified behavior.

PDF text retains page boundaries. A clear paragraph may attach to its ID;
flattened label columns, multiple IDs in one PDF paragraph and page-crossing
associations remain IDs only. Hash repair keeps its separate behavior.
No OCR, JavaScript rendering, AI or additional dependency was introduced.

Seventeen new synthetic regressions exposed and fixed a grid boundary bug:
adjacent inline spans could concatenate an ID with its name so the text
matcher missed it. Explicit bounded grid cells now preserve that ID without
inflating ordinary reference counts. The original publisher fixture set is
not available in this pass and has not been certified. Phase 2 stays open.

Final offline suite: 410 tests, 409 passed and one skipped. The audit probe
ran against a temporary database; table, list and prose examples now retain
their procedures. Restarted only the verified toolkit process, hidden and
bound to localhost. Extract, vulnerability dashboard and Supply Chain GETs
returned 200. A harmless uploaded list showed each procedure and its
Execution summary with HTML List / Source Structure labels. The initial
smoke assertion expected redundant "Reported tactic Execution" text; the
template intentionally uses the existing Execution summary instead, so the
check was corrected to the actual UI contract. No upstream refresh ran.

Updated both agent instruction files, roadmap, coverage audit and runbooks.
The project-local Claude settings file is operator configuration and is not
part of the proposed source changes. It must not be staged incidentally.

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

### 2026-11-27: Executed Individually Approved 3A.4 and Prepared 3A.5 Checkpoints

The operator directly approved local inspection and instructed commit and
push each of 3A.4 and 3A.5. Main/HEAD/local origin/main initially matched
749d973 with an empty index. Reviewed exact path/block inventories and
prepared selective copies under ignored data/3a45-checkpoint/. Preserved
independent rules, research, prototypes, settings, reconciliation and notes.
No blanket staging, reset, discard or stash. Kept runtime data/keys/exports out.

The isolated 3A.4 source copy passed 80 offline tests in 52.900 seconds,
including its 35 disabled schedules. Its exact 40-path index was checked
against reviewed blobs, with clean whitespace and the configured hook.
Commit eccbf441db7ffbd6647d11fab7db7f8dcb304216, message Add bounded GitHub
public-code exposure leads, succeeded. Its explicitly authorized origin/main
push succeeded. Local HEAD/origin/main/live main matched; the index was empty.
Remote inspection first hit an automatic approval-review timeout, then a DNS
failure. DNS recovered for push. No network/security setting changed.

The separate exact 38-path 3A.5 checkpoint is reviewed and prepared with
message Add bounded passive subdomain inventory. The operator directly
authorized its commit and push. Actual closing hash/result supersedes this
prepared note. Final application acceptance remains 841 tests in 302.124
seconds, 840 passed and one existing skip; checkpoint changes are docs only.
All collection remains off. No live database or provider action is attached.
Exact manual commands are recorded in the two feature runbooks. No saved
note grants Git approval in a future chat. Next implementation remains 3A.6.


### 2026-11-27: Built Passive Exact-Domain CT Inventory, 3A.5

**Subphase 3A.5 Complete, implementation/offline acceptance, 2026-11-27.**

The operator directly scoped one API-only passive inventory consumer and
permitted public-doc research, in-scope edits and offline tests. Read the
Build order, domain/subdomain/foundation/data handling, newest research and
handoff, 3A.4 closeout, CT API/pattern and GitHub reviews, and named runbooks.
Reviewed the full public CTLogs API docs/terms/privacy, relevant full OpenAPI
hosts contract and coverage claims. Revisited the 3A.3 alternatives without
adopting a second source. Full review and unchecked material:
[API Review](research/2026-11-27-subdomain-api-review.md).

Chose /v1/hosts, not certificate lists or paid historical/first-seen methods.
Important correction to casual date labels: OpenAPI explicitly says hosts
first_seen/last_seen are certificate validity starts in the current window,
not SCT logging dates. Literal fields stay separate from unknown generic
dates and local first capture. Wildcards remain patterns; returned names
must equal or lie under an authorized exact domain at a full label boundary.
No name proves live DNS, ownership, registration, a dangling service,
compromise or maliciousness. Provider/index/local coverage is bounded.

Implementation uses the existing app loop/client, jobs, evidence and inbox.
At most ten exact expiring permissions, immutable empty/nonempty plans and
two 100-name pages, original-cursor restart, atomic row/citation/match/page
writes, stable source/name events and retained reviews. Key/tier/query/API
changes and authority loss stop cooperative units. No generic cross-type
match or external permission is inferred from a local selector. Raw is
forced omitted. Daily per-domain success uses the oldest original capture
of a terminated distinct ordered bounded window. Partial windows retain
leads without renewing age. All 36 schedules/workers/bulk/raw remain off.

Real access gap: paging requires a key, and anonymous quotas differ in terms
and API docs. Actual key/tier/purpose/contracts/privacy handling and live
schema/quota behavior remain unapproved. Config defaults blank. Source
eligibility stays unapproved. No access purchase, account/key creation,
provider data request, selector submission, install or live change occurred.

A concurrent editor changed the new model while work was active. Paused
shared implementation edits and resumed only after the operator directly
confirmed the other editor stopped. Reconciled names/configuration/two-page
bounds and incompatible date-model import. No unrelated work was discarded.
A too-long Windows test-authoring command failed before file creation; split
writes into smaller blocks. The managed venv launcher failed; established
external offline test execution worked without environment/security changes.

Initial 24 cases: one invalid-fixture error in 18.311 seconds. A single-label
wildcard correctly raised; corrected the test assumption. Expanded 35 cases
passed in 40.030 seconds. Review found a real success-cooldown crash window:
stage could survive while its later cooldown did not. Persist quota exhaustion
before recoverable capture and test a crash after staging. Focused inventory/
GitHub/inbox/shared evidence then passed 113 in 91.091 seconds (36 inventory).
Two final frozen-plan/changed-byte recovery cases passed in 2.563 seconds.
Final inventory has 38 cases. Full compatibility: 841 tests in 302.124 seconds, 840 passed and one existing skip.
These are new runs, distinct from the supplied prior 3A.4 results.
The first full run executed 841 tests in 304.350 seconds with two old breach/CT
expectations for 35 schedules instead of 36, plus one existing skip. Corrected
only counts/test name; both affected cases passed in 1.078 seconds. Repeated
the full suite on that final state.

See [Closeout](review/2026-11-27-3a5-closeout.md),
[Runbook](runbooks/subdomain-inventory.md) and
[Authored Scope](review/2026-11-27-3a5-checkpoint-files.md). Live database stays
unmigrated/unrestarted for 5F.1 through 3A.5. Linux, native-browser visuals
and measured live v1 acceptance remain unperformed. No Git operation occurred.
3A.1/3A.2/3A.3 supplied checkpoints stay completed; 3A.4/3A.5 and earlier
independent reconciliation/handoff-rule work remain uncommitted/unpushed.
Inventories are not inspected diffs or approvals. Preserve unrelated work.

Next proposed bounded scope from slice A: 3A.6, one API-only indexed public
cloud metadata lead consumer for exact authorized domains, reviewing Shodan
first. No target probes, storage-name guessing or exposure/ownership verdict.
No 3A.6 implementation started. Full concrete prompt is in docs/handoff.md.

### 2026-11-27: Built Bounded GitHub Public-Code Metadata Leads, 3A.4

**Subphase 3A.4 Complete, implementation/offline acceptance, 2026-11-27.**

The operator directly scoped one API-only exposure lead consumer, metadata
references only, and authorized public-doc research, routine project edits
and offline tests. Read the Build order, Phase 3/data-handling and shared
foundation contracts, newest research/handoff and 3A.3 closeout/reviews.
Revisited the Phase 2 GitHub repository/README, PoC feed and advisory clients
and relevant historical catalog candidates. No external tool code was copied
or installed. The consumer uses the existing app loop/client/limiter, jobs,
evidence and inbox. No other consumer or subphase was started.

Read current search overview and full code-search endpoint, legacy syntax,
authentication, version, pagination and rate-limit guides; full primary
terms/AUP; privacy sections and current main plan prices. The dated API
review distinguishes full relevant review from unchecked add-ons, contracts,
account/token pages, outbound links and real service behavior. Current code
docs conflict on mandatory authentication versus public anonymous access.
Fine-grained token support is documented but has not been live-tested.
Chose a separate human-reviewed public-only token and default-false access
attestation, never inheriting Phase 2 private-repository capability. Source
eligibility stays unapproved. No real credential or account was inspected.

Exact bounded organization/domain values produce only quoted in:file queries.
Legacy punctuation may be ignored; local observations therefore mean query
attribution, not an exact content match or exposure proof. Separate permission
IDs bind selector/query, API/query versions and token identity. Empty plans
stay empty; two fixed page slots cap each of at most ten queries. Token changes,
expiry/revocation/suppression and source/schedule/selector disablement stop
cooperative units, retries, quota waits, response/stage and ingestion boundaries.

Only validated repository ID/full name, path, blob SHA and literal html_url
survive. Unknown metadata, descriptions, profiles and repository dates are
discarded; snippets/content-bearing results fail. Source/file dates remain
unknown. Raw bodies are omitted and captures sensitive. Page staging retains
original capture/run identity. Atomic observations, citations, local matches
and page completion preserve evidence and reviews on recovery. Stable
provider repository-ID/file-path events deduplicate revisions without merging
captures. Incomplete/truncated/drifting pages retain leads but do not renew
per-selector success. Passive views show original age and review links.

Initial 34-case acceptance found two failures. A real multi-page progress
bug mixed response counts with selector totals. Added an explicit consumer
unit_progress option in Scope.validated; only the new consumer opts in.
Existing adapters retain the default. The other was a fixture assumption:
schedule configuration does not identify a changed nonempty token; saved
permission identity refuses it when work runs. Corrected the assertion.
The next 40-case run passed in 43.925 seconds. After binding API version and
adding final authority/recovery cases, focused GitHub/inbox/shared-evidence
acceptance passed 77 in 51.547 seconds, including 43 GitHub cases.

The first full suite ran 803 tests in 256.216 seconds, with one old ransomware
catalog-count assertion failure and one existing skip. Updated that one
expectation from 34 to 35; earlier breach/CT catalog expectations were already
updated. Final compatibility: 803 tests in 255.655 seconds, 802 passed and
one existing skip. Tests use temporary databases
and synthetic/refused HTTP. The managed Windows launcher could not start the
existing venv, so the established external execution path ran the authorized
tests without interpreter/package/security changes. Existing diagnostics remain.

All 35 schedules, workers, bulk and raw storage default off. No provider data
request, selector submission, source enabling, install, live migration/restart
or Git operation occurred. The live database remains unmigrated/unrestarted
for 5F.1 through 3A.4. Linux, native-browser visuals and live v1 acceptance
remain unperformed. The new runbook records exact offline commands, finite
budgets, limitations and separately approved measured live acceptance.

Reconciled the operator-supplied actual 3A.3 commit/push result:
749d97351c5158558789afa8a297a461999b9c42 on 2026-11-27, with matching local
HEAD/local origin/main/live remote main and an empty index afterward. It
supersedes prepared-execution notes below. No Git operation was run to verify
or repeat it. 3A.1/3A.2 checkpoints stay complete. 3A.4 and independent earlier
reconciliation/handoff-rule work remain uncommitted. A 40-path authored scope
inventory is not a Git-inspected diff or approval. Preserve unrelated work;
inspect/select/commit only after direct approvals, with push approved separately.

Next proposed bounded capability is 3A.5, one passive exact-domain subdomain
inventory API consumer, reviewing CTLogs' domain API first. Its full prompt
is in docs/handoff.md. No DNS, target probing, combined provider, fuzzy search,
code/secret fetching, credential testing, collector, playbook or AI was added.
The final dated closeout status and result are in the 3A.4 review record.

### 2026-11-27: Inspected the 3A.3 Checkpoint After Direct Approval

The operator directly approved read-only local Git inspection after 3A.3
implementation/offline closeout. Confirmed main, HEAD and local origin/main
at 3eaf484bcdb803555c5f199c1906b30969dce80f and an empty index. No remote
contact, staging or Git mutation occurred. Reviewed tracked scoped diffs,
new authored files and the exact 35-path proposal. Whole-tree whitespace
found the known unrelated ROADMAP.md line; exclude it with the independent
work rather than changing it. Global-ignore access and LF/CRLF notices were
nonfatal and no configuration was changed.

Prepared five local document review copies under ignored data/3a3-checkpoint/,
based on inspected HEAD plus only the proposed status/scope/handoff blocks.
Current status includes the minimum completed 3A.2 result needed to replace
stale prepared-execution wording. Independent handoff-rule, OSINT, detection,
prototype and historical journal blocks remain in the real working files
and outside the proposed copies. Updated the paired summaries, roadmap,
closeout, manifest, runbook and handoff to reflect this inspection. No code
or acceptance result changed. The operator subsequently approved this exact
35-path/selective-block commit and explicitly authorized its push in the
current chat. Execution is prepared; the actual hash and verified push belong
to the closing result. Saved records grant no future Git permission.

### 2026-11-27: Subphase 3A.3 Complete, Provisional CT Candidate Watches

The operator directly scoped a bounded API-only CT watch consumer. Read the
roadmap, current journal/handoff and foundation/breach/inbox contracts, and
revisited the existing crt.sh client and historical source findings. Preserved
the supplied completed 3A.2 result and later uncommitted reconciliation and
handoff-rule edits. No Git operation was authorized or run.

Curated patterns-v1.json first from complete public Okta reporting dated
2026-07-10 and 2026-11-23. Separated reported passkey/legal/legaldept domain
tokens from behavioral hypotheses and roadmap IAM/auth vocabulary. Themes
only annotate an exact seed match. No provider/source data or service code
was imported. The pure matcher handles explicit DNS seeds, strict IDNA2008,
complete domain-label and hyphen-component sequences, and literal wildcard
patterns. It performs no network or fuzzy/permutation expansion.

The first focused run found idna accepting a Unicode full stop even without
UTS46. Added explicit separator refusal and a hyphenated-seed boundary case.
Initial matcher acceptance: 8 passed in 0.007 seconds. The established Windows
managed-launch restriction required the existing external test execution
path, with no interpreter/package/security setting changes. The completed
consumer was subsequently integrated and tested as recorded below.

Reviewed the full relevant crt.sh maintainer discussions: historical reasonable
automation permission, service limits and instability. The homepage timed
out; no current service-specific terms, access tier, cost policy, stable
schema or quota was verified. Inspected only the GPL web-interface header/
parameter declarations, without copying or executing code. SSLMate's inspected
API supports specific domains, not arbitrary brand searches; its partial
review is not adoption approval. Research notes enumerate checked and
unchecked sources without claiming a full current provider review.

Requested the exact unresolved decision before adapter work. The operator
directly chose the provisional disabled adapter and asked for CTLogs and
alternatives to be considered. Read the submitted comparison, CTLogs API/
pricing, terms, privacy, about and homepage text; inspected coverage without
visiting individual logs. Its documented organization search is subject O=,
not arbitrary brand tokens in hostnames. Its domain-focused APIs and SSLMate
remain candidates for later scope. No second provider or silent fallback
was added. The API review records rate-document inconsistencies, privacy,
cost, coverage and unchecked material. No live source decision was inferred.

Implemented one original provisional crt.sh adapter, an independent additive
schema, explicit expiring seed permissions and a frozen normalized plan.
Permissions bind pattern version/content digest and matcher version. Existing
jobs, app loop/client/limiter and shared evidence/inbox remain owners.
Atomic candidate/citation/alert/completion writes preserve capture time,
originating execution and reviews on restart. Stable source/hostname events
deduplicate alerts across certificates while keeping separate observations.
Constructed certificate-ID references are labelled, not invented as supplied
URLs or original-log citations. Literal certificate dates stay separate from
unknown observation/publication dates. Per-seed health uses original captures.
All 34 composed schedules, worker, bulk and raw storage default off. Raw
bodies are forced omitted and captures sensitive. No dependency was added.

The first consumer run passed 34/35; its page test used the test client's
default hostname and correctly hit the real Host gate. Changed the fixture
to 127.0.0.1. The next grouped run had one wrong expected fixed failure code;
corrected transient_error to the existing transient value. No guard was
weakened. Final CT/inbox/shared-evidence acceptance: 77 passed in 30.994 seconds,
including 43 CT cases. Full compatibility: 760 tests in 208.414 seconds,
759 passed and one existing skip. Tests used temporary databases and synthetic/
refused HTTP. The full suite includes the final bounded eligibility read.
Existing deprecation, synthetic PDF and asyncio diagnostics remain.

**Subphase 3A.3 Complete, 2026-11-27.** Provisional implementation/offline
acceptance only. Updated closeout, paired summaries, roadmap, runbooks/testing
and handoff. No Git operation, enabling, provider data request, selector
submission, live migration/restart, install or external private-data transfer.
The live database remains unmigrated/unrestarted for 5F.1 through 3A.3.
Current hosted-service terms/access/schema, Linux/native-browser visuals and
live v1 acceptance remain unverified. Source eligibility stays unapproved.
The 35-path authored proposal awaits approved actual Git inspection and
individual commit/push approvals; new and independent prior edits remain
uncommitted. Proposed next scope is 3A.4 bounded GitHub public-code exposure
metadata leads. No other consumer was started in this chat.

### 2026-11-27: Authorized the 3A.2 Commit and Push

After the exact 34-path/selective-block proposal and message were shown,
the operator directly approved the commit and explicitly authorized its
push in the current chat. The prior local inspection confirmed main/HEAD/
local origin/main at d34a37d and an empty index. Three reviewed ignored
staging inputs preserve the independent working text while excluding it
from this checkpoint. Updated the approval records and repeatable runbook
before execution. No application code or acceptance result changed.
Execution is prepared; the actual commit ID and verified push result belong
to the closing message. Saved prepared notes cannot approve another chat's
Git operation or justify repeating an already completed checkpoint.

### 2026-11-27: Inspected the 3A.2 Checkpoint After Direct Approval

The operator approved the local read-only Git inspection after implementation
closeout. Confirmed main, HEAD and local origin/main at
d34a37d68aa120b58ee3d18822ccf5ebcc54b31c with an empty index. No remote contact
or Git mutation occurred. Reviewed the tracked diffs, new authored files and
exact 34-path manifest. Independent OSINT, detection and prototype additions
remain outside the checkpoint, including their shared-document blocks.
The whole-tree whitespace check found only the known unrelated roadmap line;
exclude it rather than changing that independent work. Global-ignore access
and LF/CRLF notices were nonfatal. Recorded the exact commands in the breach
runbook and updated paired status, roadmap, closeout, manifest and handoff.
Individual staging/commit and separate push remain unapproved. No application
code or test result changed; no compatibility rerun is needed for these
checkpoint-record edits. Saved notes grant no future Git permission.

### 2026-11-27: Subphase 3A.2 Complete, Bounded HIBP Watched Email Lookups

Implemented only the requested Phase 3 slice A breach consumer after the
required roadmap/foundation/provenance/data-handling, newest research,
handoff, closeout, runbook and source-review reading. The operator supplied
the actual 3A.1 closing result: d34a37d68aa120b58ee3d18822ccf5ebcc54b31c,
individually committed and separately pushed on 2026-11-27 with matching
local/remote hashes and an empty index afterward. Reconciled the prepared
notes without repeating or newly inspecting any Git operation. No saved
handoff or earlier approval was treated as current-chat permission.

Selected HIBP direct email lookup after reading its full current v3 API,
2026-10-27 terms, canonical pricing, sign-in and privacy pages. Core allows
direct email searches for own users/customers; the published annual Core 1
price is USD 52.68 before taxes. Actual account tier/RPM/expiry and live
schema are still unverified. No account, payment, key or selector submission
was performed. The unavailable guessed pricing path was replaced with the
documentation's canonical link, not a block workaround. Other providers
were not newly reviewed. The dated source review identifies unchecked
material and separates documented access from activation authority.

Revisited the shared vendor client/limiter, original RansomLook consumer and
historical source/OSINT reviews. No HIBP client existed in project/reference
scripts to port. Added original app/modules/breaches code and an independent
transactional migration. One disabled daily registration composes with the
existing 32. The runner, app loop/client, existing limiter, durable quotas,
cooldowns, evidence and inbox retain their ownership. No extra dependency,
parallel worker, upstream service implementation or AI was introduced.

Each of at most ten exact email watches needs a separate expiring submission
permission with explicit authority/consent record references and defensive
purpose. Local watch creation cannot grant that permission. Revocation and
case-insensitive suppression stop units/retries/resumption. A new permission
cannot replace the immutable identity in a queued plan. Actual source review,
paid entitlement and schedule/worker controls remain separate gates.

The pass snapshots bounded permission IDs, stages validated normalized input
and commits each lookup's reported associations, literal citation hops,
stable inbox events and completion atomically. Resume saved input without
another request or changed upstream substitution. A crash after completion
but before progress repairs progress from committed units. Source/email/
breach identity deduplicates alerts while retaining separate observations,
captures, originating executions and revision-checked reviews. Failed
terminal/cancelled scopes retain staged evidence but are not automatically
resurrected under another daily scope; later passes are new acquisitions.

The full breach response preserves titles, approximate breach dates,
addition/modification dates, category caveats, attribution and literal
DisclosureUrl. Dates with unknown values remain unknown. Minute precision
and offsets stay literal. No provider date is invented as publication,
observation or collection time. HIBP's public account results can omit
sensitive, retired and opted-out data. A 404 records no publicly disclosable
result and never erases an earlier claim or asserts a clean account.

Passwords, authentication secrets, descriptions, logos, source account records
and unknown fields are discarded. Common credential patterns in retained
metadata fail closed. Captures are sensitive, with originals forced omitted
even under generic public archive settings. The saved request surface is
explicitly redacted: email URL segment, query and headers are omitted.
Audit units retain job/permission, attempt, staged status and completion;
provider error text never becomes a job error. No new export/raw route or
privacy-deletion/encryption policy is implied by local handling labels.

The consumer allows ten requests/10 MiB charged bytes/120 seconds per
attempt, 1 MiB and 30 seconds per response, 100 associations and 512 KiB
normalized input per lookup, three total attempts, 10/minute and 240/day
local bounds with persisted cooldowns. Eligibility is rechecked after quota
waits/responses/parsing and inside staging/ingestion. In-flight requests
cannot be retracted; parsing/writes use cooperative elapsed checks.

Passive /breaches pages show per-address last attempt, original last-good
age, failure/incomplete/stale states, paged captures and inbox reviews.
Source-wide pass success cannot replace an address's capture age. All HIBP
result views carry linked attribution. No GET collects, authorizes a
selector, scans history or resolves a citation.

The first consumer tests exposed an async-generator selection mistake;
returning the saved capture ID directly removed that mistake. Intermediate
breach suite: 35 passed in 28.061 seconds. Added a crash-before-progress
repair case and finalized list/detail attribution. First full compatibility
ran 717 tests in 180.748 seconds with one failure and one existing skip:
the legacy migration fixture mistook new breach tables for old rows. It now
freezes every actual pre-migration legacy table instead of maintaining
prefix exclusions. No existing row/view/user_version assertion was removed.
Final focused breach/shared-evidence suite: 54 passed in 32.105 seconds.
Final full compatibility: 717 tests in 180.083 seconds, 716 passed and one
existing skip. Tests use only temporary databases and synthetic/refused HTTP.
Existing deprecation/PDF/asyncio diagnostics remain. The established Windows
managed launcher restriction required the existing test execution path;
no environment, dependency or security setting changed.

**Subphase 3A.2 Complete, 2026-11-27.** Implementation/offline acceptance
ended here. All 33 schedules, feed worker, bulk and raw storage default off.
No live migration/restart, enabling, API data request, live submission
permission, install, historical reload or private-data transfer occurred.
The live database remains unmigrated/unrestarted for 5F.1 through 3A.2.
Linux, native-browser visual and live v1 operational acceptance remain
unperformed. The current source review/runbook specify approved measured
live acceptance still required.

Updated roadmap, paired summaries, runbooks, dated closeout and handoff.
The exact 34-path authored checkpoint is prepared; actual Git inspection,
individual commit approval/execution and separate push remain pending.
Preserve unrelated Feedly/local settings, prototypes and their notes,
OSINT/untrusted-repository-review, detection/catalog additions and independent
shared-document edits. No blanket staging/reset/discard/stash. Exclude keys,
runtime data and conversation exports. The full saved/on-screen next prompt
resumes only the checkpoint and stops. No other Phase 3 capability was begun.

### 2026-11-27: Inspected the Pending 3A.1 Checkpoint After Approval

The operator approved read-only Git inspection in the current chat and then
requested a retry. Confirmed main and local origin/main at the completed
5F.5 commit a947eb0c83f0f5260c1c1844e64d1b8402ffb332 with an empty index.
No remote contact or Git mutation. Reviewed tracked diffs and the exact
33-path authored manifest. Preserve all independent roadmap/journal/handoff
research and prototype blocks, plus the unrelated files named in the manifest.
Focused tracked whitespace passed; the whole-tree check identified trailing
spaces in an unrelated roadmap addition. Leave that addition outside this
checkpoint. Global-ignore permission and LF/CRLF notices were nonfatal.
Updated handoff, paired summaries, closeout, checkpoint and the ransomware
runbook with the actual inspection result. Individual staging/commit and
separate push remained pending at inspection. The operator subsequently
individually approved the exact 33-file/selective-block commit proposal and
message. Execution is prepared; separate push approval remains pending.
No implementation or test result changed. The closing result records actual
execution; prepared notes never grant another chat Git permission.

### 2026-11-26: Subphase 3A.1 Complete, API-Only Ransomware Victim Watches

Built only the first coherent Phase 3 slice A consumer after the required
build-order, current journal/handoff, foundation closeout/runbook and source
review reading. The operator reports 5F.5 committed and pushed as
a947eb0c83f0f5260c1c1844e64d1b8402ffb332 with matching hashes and an empty
index afterward. Saved prepared checkpoint notes were not treated as current
Git state or permission. No Git operation occurred before the subsequent
2026-11-27 approved checkpoint inspection recorded above.

Selected RansomLook's public recent-100 API after reading its full current
About/API documentation and Swagger schema. Its data terms declare CC BY 4.0;
the service docs describe AGPL v3, correcting old GPL wording. No service
code was imported. Existing ransomware.live group-profile client/limiter and
historical reviews were revisited. Current ransomware.live documentation and
terms failed in the web reader; the browser then explicitly blocked the PRO
documentation under its site-safety policy. No subsequent workaround.
Third-party examples did not establish current schema/terms/quotas.
Details and unchecked material are in the dated ransomware API review.

Added app/modules/ransomware with original parsing, an independent additive
migration, bounded normalized staging, atomic row ingestion and read-only
/ransomware claim/capture pages. A composed trusted core catalog includes
the new opt-in registration and the existing 31 surfaces. The shared app
loop, client, limiter, durable runner, quota/cooldown ledger and inbox remain
the owners of execution. No dependency or alternate worker was added.

Organization watches compare exact normalized titles with Unicode NFKC,
case folding and whitespace collapse; punctuation stays significant. Sector
and two-letter country code watches require explicit structured values.
Synthetic normalized integration fixtures verify those types. RansomLook's
documented Post schema supplies neither, so the adapter leaves both unknown,
ignores undocumented fields and makes no inference from websites/prose.
Several watches are independent OR matches, not one combined filter.

Preserved source/group/exact-title claim identity separately from normalized
matching. Optional trusted inbox event keys retain one alert per watch and
source claim without merging immutable capture observations. Existing
generic evidence keeps per-observation semantics. Repeat retrieval, catch-up,
failed work and restart cannot reset original review revisions. Claim pages
link every capture and the original alerts. Literal cited references and
explicit resolutions remain separate. Discovery is aggregator discovery,
not attack/publication time; naive values stay literal with no guessed zone.
Originating interrupted execution and later successful job stay distinct.

Durable normalized batches retain at most 100 rows/1 MiB. At each row,
claim/capture/assertions/citations/alerts/cursor commit atomically, with source
and schedule eligibility checked at the write boundary too. Resume saved
input before a changed upstream snapshot. Later eligible scopes can drain
failed terminal batches; cancelled queues remain retained but do not auto-
resume. Production raw bodies are forced omitted because API Post records
can include encoded HTML/screenshots. No decoding/rendering/following source
content. Synthetic metadata-only archive expiry preserves queues/citations/
reviews. Omission is honest availability, not a claim that originals exist.

One endpoint, one request, 2 MiB response/charged bytes, 60-second soft pass,
three attempts, local 1/minute and 24/day limits, persisted 429 cooldown and
cooperative cancellation keep collection bounded. At most one old and one
new batch drain per attempt. The one-hour cadence/six-hour stale threshold
are local proposals, not upstream guarantees. Coverage says recent 100 posts
only, history/continuity not assessed. Restart never creates a catch-up burst.
Failed refresh keeps last-good age/coverage and visible failure/stale states.

The Windows venv launcher hit its established managed-launch restriction.
Authorized offline tests ran through the existing execution path, changing
no interpreter, dependency or security setting. The first focused run found
a test using Origin instead of the established Sec-Fetch-Site header; fixed
the fixture. Earlier inbox/scheduler compatibility passed 48 tests in
32.656 seconds. An intermediate grouped consumer/foundation run passed 167
tests in 82.121 seconds. Added three final cases and tightened literal title/
citation preservation and transaction-boundary checks. Final focused run:
31 passed in 28.725 seconds. Final full compatibility: 681 tests in
151.119 seconds, 680 passed and one existing skip. Existing deprecation,
invalid-PDF and asyncio timing diagnostics remain. All provider HTTP was
synthetic MockTransport or refused; databases were temporary.

No live migration/restart, source enabling, API data request, install,
historical reload or external private-data transfer occurred. All 32
schedules, worker, bulk and raw storage default off. The live database is
still unmigrated/unrestarted for 5F.1 through 3A.1. Mocks do not establish
live schema/quotas/availability, Linux, native-browser visual or v1 readiness.
The source review, runbook and closeout specify approved bounded live
acceptance still required before daily use.

**Subphase 3A.1 Complete.** Implementation/offline acceptance ended here.
The exact 33-path checkpoint and selective shared-doc scope are prepared,
message Add API-only ransomware victim tracking and local watches.
At implementation closeout, inspection, individual commit approval/execution
and separate push remained pending. See the subsequent inspection update.
Preserve Feedly rules, local Claude settings, prototypes and their
notes, OSINT/untrusted-repository-review work, detection/catalog-review work
and every independent shared-document block. Exclude secrets, runtime data
and exports. docs/handoff.md contains the full prompt to resume only this
checkpoint first, then one bounded vendor breach consumer in a fresh chat
after that checkpoint is resolved. Other slice A capabilities, email/webhooks, playbooks,
collectors and AI remain later work.

### 2026-11-26: Subphase 5F.5 Complete, Alert Inbox and Foundation Acceptance

Implemented only 5F.5 after the required foundation, provenance, handling,
handoff and runbook reading. The operator supplied the completed 5F.4 commit
and push result. Current-chat approved read-only Git inspection confirmed
main and local origin/main at c5cdae9ec0cd378b1d4fc90bfdaf912490958bb6, with
an empty index. No remote contact or repeated checkpoint occurred. Inspection
also identified unrelated roadmap whitespace; it remains outside this work.

Added an independent additive inbox migration and a local module at /alerts.
Selectors are immutable typed definitions with exact, domain-tree and strict
IP-network matching, capped at 100 definitions. New shared observations and
saved report mentions match enabled selectors atomically. Older observations
use explicit pages of at most 200 with a durable cursor committed alongside
the alerts. Incremental matches need no new worker. Unsupported generic
subjects remain evidence without a guessed match. No regex, content-derived
commands, destinations, credentials, registrations or collection approvals.

Alert uniqueness is selector plus immutable observation. Replay cannot reset
review state. Separate assertions and captures stay separate even for equal
values. New, Reviewed and Dismissed have dated review history and revision
conflict checks. No destructive delete/reset or automatic credibility rating.
Details retain source assertions, distinct dates, literal/resolved citation
hops, capture identity and originating run. An interrupted originating run
can belong to a logical job that later succeeds; both states are visible.
Archive expiry, omission and reconciliation failure preserve all alert and
indicator history. Restricted/non-public excerpts are suppressed in the inbox.

The inbox reuses source freshness; details show relevant source health or an
explicit absence of a scheduled freshness assessment. Read-only page loads
do not scan observations, reconcile files, enqueue work or poll providers.
The existing app loop, shared client/limiter, durable runner, eligibility
checks, request/byte/time budgets and archive maintenance remain the owners
of collection and recovery. Broad Phase 3 brand/identity and source matching,
notifications, collectors and playbooks remain later work.

The initial command met the documented Windows venv launcher restriction.
Used the established execution path outside that restriction with no package,
interpreter or security-setting change. The first completed new-suite run
found a test fixture expecting the wrong source ID, then passed all 23 new
tests in 10.276 seconds after correcting that assertion. Added explicit
originating-execution/current-job visibility and verified the grouped
foundation suite: all 139 passed in 61.754 seconds. Final full compatibility
ran 650 tests in 138.479 seconds: 649 passed and one existing skip.
Existing Starlette/httpx, invalid-PDF and asyncio timing diagnostics remain.

New integration tests use synthetic scoped mock HTTP and temporary databases.
They cover a crash between alert creation and progress, restart replay with
review preservation, failed refresh retaining last good age/coverage, offline
first startup, cooldown/quota persistence, cancellation/revocation between
capture and ingestion, downtime and missing-original reconciliation. The
real calculated failure state is rendered through panels on eight consuming
pages. Earlier grouped tests additionally cover actual process-death
recovery/exclusion, interrupted pagination, source windows, budgets, archive
write/rename recovery and expiry. No live source terms, schema or quota,
deployment uptime, Linux or native-browser visual acceptance is established.
See docs/runbooks/alert-inbox.md and the closeout's acceptance matrix.

No live migration/restart, source enabling, worker enabling, provider traffic,
installation, external transfer or Git index/history mutation occurred.
The live database has not been migrated/restarted for 5F.1 to 5F.5. Raw
storage, bulk work, all 31 schedules and the feed worker default off. V1
daily use still requires approved source reviews and measured bounded live
freshness/recovery acceptance. No large historical reload was performed.

**Subphase 5F.5 Complete.** The proposed 26-path checkpoint is documented in
docs/review/2026-11-26-5f5-checkpoint-files.md with message Add local alert
inbox and accept foundation integration. The operator individually approved
this exact commit proposal. Execution is prepared; separate push approval
remains pending. Preserve unrelated prototype, Feedly,
local settings, OSINT research and all independent shared-document edits.
Stop at this boundary. Next chat: Phase 3 slice A, first coherent subphase
ransomware victim tracking and local watch alerts, using docs/handoff.md.

### 2026-11-26: Subphase 5F.4 Complete, Saved Reports and Original Archives

Implemented only 5F.4 after the required roadmap, newest research, handoff,
review and runbook reading. Current-chat approved read-only Git checks found
5F.3 committed at 2491fb3 with matching local origin/main tracking and an
empty index. No remote contact or repeated 5F.3 commit occurred. Separate
prototype and OSINT research work remains preserved in shared documents,
along with Feedly rules and local settings.

Added a transactional version 2 shared schema for report manifests, raw
availability and normalized bulk results. Extract and Save requires source
title/name, publisher and a publication date or explicit unknown. Report,
file and paste origins retain input digests, separate source/observation/
collection dates, citation references and originating execution. Parsed
mentions remain mentions. Unknown sources stay F and collection-disabled.
Save replay binds capture identity, original bytes, metadata and parser
output/version. Changed input makes another capture. A repeated unchanged
save preserves its original collection time and later citation resolution.
Documents, sightings and citations commit together; archives are separate.

Original capture bytes are retained before normalization, without refetching
for a save. Raw storage requires an explicit private root and finite response,
source, total and age limits. Capacity reservations, generated paths, an OS
lock, temporary file/fsync/rename and bounded reconciliation recover interrupted
writes. A local maintenance loop handles expiry and missing files without
collection. Health exposes failure/page progress. Expiry changes availability
immediately and preserves document/indicator/citation history and digests.
Unknown, sensitive and restricted-TLP material is omitted. Common credential
patterns and configured keys are guarded, without claiming universal secret
detection or encryption. Raw data has no web render/download/export route.

Enrich All creates bounded durable batches. Keyless units precede additional
explicitly chosen providers within each batch. Source review/enabling,
handling, private-IP/Tranco/hashlookup gates, request/byte/time/day quotas,
429 cooldowns and retry/cancellation checks apply through resumption. Sync
jobs submit to the app's existing loop/client/limiter. The worker defaults
off. Proposed RDAP redirects are restricted to finite named registry routes,
not arbitrary destination instructions. Endpoint availability and current
terms were not newly researched; source enabling remains a separate review.
Normalized results preserve provider attributes and report/capture links.
Cached results retain query time and make no new-original claim. Hashing
request inputs prevents identical bodies from different queries sharing
capture metadata; request secrets themselves are not saved as metadata.

Initial acceptance found and corrected an archive SQL placeholder mismatch,
an overridden test fixture argument and old one-migration assertions. The
expanded report/evidence/scheduler run passed 85 tests. Full compatibility
first ran 626 tests in 133.056 seconds, passing with one existing skip.
After the RDAP/media refinements, the 627-test run passed 626 with one skip
in 118.318 seconds. Final focused acceptance passed all 42 new tests in
17.239 seconds after the last credential suppression refinement. Existing
deprecation, invalid-PDF and asyncio diagnostics remain. Tests used temporary
databases and mock HTTP, with the established venv sandbox execution path.

No live migration/restart, source enabling, provider traffic, package change,
external submission or index/history mutation occurred. Linux and browser
visual checks were not performed. Full operational v1 acceptance remains
separate. Runbook saved-reports-and-archives.md records repeatable commands,
activation gates, bounded history views, local filesystem and handling limits.

**Subphase 5F.4 Complete.** See docs/review/2026-11-26-5f4-closeout.md.
The exact 28-path proposal uses message Add saved reports and bounded original
archives. The operator individually approved this exact proposal in this chat;
execution is prepared and separate push approval remains pending.
Stage only 5F.4 blocks from the three shared documents; preserve all prototype
and OSINT research edits. Stop at this boundary. Next chat: only 5F.5 using
the full prompt in docs/handoff.md.

### 2026-11-26: Subphase 5F.3 Complete, Scheduled Feed Refresh and Source Health

Checkpoint update: the operator individually approved the exact 58-path
proposal and message Add scheduled feed refresh and source health. Stage
only 5F.3 content from the three shared documents, retaining prototype work
unstaged. Execution is prepared; its actual result belongs in the closing
chat message. Separate push approval is still pending.

Implemented only 5F.3 after the required foundation, newest research,
handoff, closeout and runbook reading. Inspected the runner, async client,
limiter, source queues, ingestion/status semantics and legacy consumers.
The operator confirms 5F.2 commit eff4b41 was pushed and verified. Approved
read-only Git inspection confirmed main at that commit, an empty index and
.githooks configured. No repeat 5F.2 checkpoint was attempted.

Added versioned feed schedule, request reservation, cooldown and capture
progress tables. Registered 31 explicit existing feed surfaces, including
C2IntelFeeds, with individual cadence/stale thresholds and finite budgets.
All schedule switches and the application worker default off. No source
metadata was approved or enabled. Proposals reuse existing adapters and saved
research; they are not fresh current-terms judgments. Actual enabling still
needs direct approval and review of the exact surface and quota.

APScheduler is not installed, so used a small stdlib asyncio timer with
durable due work. The runner thread submits coroutines to the existing app
loop, preserving shared HTTP/locks/quotas without fresh loops per job.
Scheduled transports reserve finite requests/bytes, apply durable courtesy
quotas and shared provider limits, recheck eligibility after waits, and
persist 429 cooldowns. Retry-After can extend runner backoff. Shutdown drains
legacy sibling tasks and save threads before releasing ownership/client.

Persist capture endpoint/digest metadata before ingestion. Replays retain
original capture key, collection time and originating run; changed bytes get
another capture. Keep validated retrieval, ingestion units, source windows
and completed coverage separate. Scheduled legacy success is staged until
completion. Empty/malformed snapshots retain last-good data. NVD and vendor
queues retain unfinished windows/revisions. CVE delta validation cannot
advance a skipped record's checkpoint. Group facts commit before their
per-group checkpoints. Large initial loads and metadata backfills stay manual.

Added source health to consuming pages. Last-good snapshot age is separate
from a partial validated retrieval. Old NVD windows and old EPSS score dates
remain visibly stale/incomplete during catch-up. Existing source publication
dates are not relabeled as retrieval time. Rolling sightings remain only a
48-hour snapshot, not downtime history. No archives or saved reports were added.

The first full suite passed 571 tests with one existing skip. Expanded checks
then found the infrastructure test's module-only initialization lacked core
scheduler tables. Changed health to read legacy state without migrations on
GET. Focused scheduler/infrastructure acceptance passed 33 tests in 19.486
seconds. Final full suite: 585 tests in 92.493 seconds, 584 passed and one
existing skip. This includes 32 new schedule/health/bridge/recovery cases and
the existing Windows process-death/duplicate-execution checks. Existing
Starlette/httpx, invalid-PDF and asyncio diagnostics remain. The installed
venv needed the authorized execution path outside its launcher restriction.
No package, interpreter or security setting changed.

No live migration, restart, provider traffic, source enabling, install or
external submission occurred. Linux and a browser visual walkthrough were
not run. The runbook records all policies, commands, activation gates and
limits. V1 operational acceptance still requires approved live configuration
and foundation acceptance. Saved reports/archives are 5F.4; alerts are 5F.5.

**Subphase 5F.3 Complete.** See docs/review/2026-11-26-5f3-closeout.md.
Read-only Git inspection is complete and the exact commit was approved;
execution is prepared and separate push approval remains pending. The
approved message is Add scheduled feed refresh and source health. Preserve
the separate actor-profile prototype and its notes in these
shared docs; stage only 5F.3 content. Exclude its files/review/runbook, Feedly
rules, local Claude settings, runtime data, secrets and conversation exports.
Stop here after the approved checkpoint. Next chat: 5F.4 using docs/handoff.md.

### 2026-11-26: Authorized the 5F.2 Checkpoint and Required On-Screen Handover

The operator directly instructed commit and push after reviewing the 5F.2
proposal. They also requested that the subphase instructions explicitly
require a complete handover prompt printed on screen for the next session.
Updated session-handoff.md and the paired AGENTS.md/CLAUDE.md rules: print
the full ready-to-paste prompt in a fenced text block in the final response,
in addition to saving docs/handoff.md. A link, summary or offer is insufficient.
The requested documentation adds session-handoff.md to the earlier 18-path
proposal, giving 19 exact checkpoint paths with the same approved message,
`Add durable job runner`. No implementation changed after final acceptance,
so the verified 553-test result remains applicable.

Pre-checkpoint inspection still shows main at 6341acc and an empty index.
An unrelated untracked prototypes/ directory appeared since the earlier
inspection; it remains untouched and excluded alongside Feedly rules and
local Claude settings. Both checkpoint actions are authorized in this chat.
This entry is prepared before execution; report the actual commit and push
result in the closing message rather than chase a self-referential hash in
tracked notes. Stop at the 5F.2 boundary and print the 5F.3 prompt directly.

### 2026-11-26: Inspected the 5F.2 Checkpoint After Approval

The operator approved read-only Git inspection separately from commit/push.
Confirmed main at 6341acc (`Add shared evidence model and source registry`),
an empty index and .githooks configured. Reviewed tracked diffs and the exact
18-path proposal. The only unrelated local paths are feedly-review-rules.md
and .claude/settings.local.json, which remain untouched and excluded. Tracked
whitespace checks passed. Git reported its existing inaccessible global-ignore
warning and normal LF/CRLF notices; no configuration changed. No staging,
commit, push or remote contact occurred. Updated closeout, manifest and
handoff to reflect inspection completion. Commit approval and later separate
push approval remain pending. Repeatable inspection commands are in the
durable-jobs runbook. Acceptance remains the final 553-test result; only
checkpoint documentation changed. Stop at the 5F.2 boundary.

### 2026-11-26: Subphase 5F.2 Complete, Durable Job Runner

Implemented only the durable runner. Read focused foundation scope, newest
research notes, handoff, 5F.1 closeout and source/replay/session/freshness
contracts in the required order. Inspected the core connection model,
source-specific vendor and NVD queues, async locks and limiter, normal app
lifespan, existing temporary-database tests and focused Phase 1 review notes.
No source was fetched or newly reviewed. The operator confirms 5F.1 commit
6341acc was pushed to origin/main and verified. Older pending notes do not
authorize or require repeating that checkpoint.

Added job_schema.py, job_lock.py and jobs.py under app/core. Normal startup
adds versioned job tables but starts no worker. Explicit trusted Task objects
bind handler, parameter model, version, source/method and retry policy. Unique
task/work identity returns the same job on duplicate enqueue, including
terminal jobs. Each attempt has a separate execution ID. Conflicting policy
or parameters cannot reinterpret saved work. Removed/changed registrations
fail closed. No dynamic import, shell dispatch, automatic destination or
content-derived approval exists.

Chose serial execution per canonical local database path. SQLite write
transactions serialize enqueues/claims; an OS-held sidecar lock spans the
handler. A slow live handler cannot lose ownership to an expired lease.
Windows uses msvcrt and Linux flock. Real process death releases the lock;
the next explicit dispatch records interrupted attempts and saved backoff,
preserving progress within the original total attempt budget. There is no
automatic startup dispatcher yet. Handlers must be bounded and cooperative,
with no detached work. A hung handler blocks runner throughput. Cancellation
is durable and observed at work boundaries or on return; it does not kill a
thread or retract an in-flight request. No exactly-once external-effect claim.

Kept separate execution attempt, validated retrieval, ingestion progress and
explicit complete-coverage fields. Failed attempts do not refresh retrieval
or coverage. Known totals cannot be erased or changed. Retry requests use
fixed typed codes, exponential persisted delay capped at one day, and 1 to 10
total attempts including interruptions. Other errors are terminal; provider
exception text is never persisted. No generic terminal-job reset was added.

Reused 5F.1 require_collection with an optional existing connection, keeping
eligibility checks in the runner's transaction without duplicating policy.
Check before enqueue, handler invocation, cooperative units, retries and
successful return. A document helper persists metadata before evidence
writes, retaining original capture key, originating run ID and time across
later attempts. Deterministic observation/citation keys complete replay after
interrupted writes. Adapters must verify original input/digest/revision rather
than attach a fresh changed response to old capture metadata. No raw archive
or retroactive FK/backfill of legacy opaque document job IDs was introduced.

Existing manual source routes, durable source-specific queues and async
limiter remain unchanged. Their quota/async bridge, global source health and
scheduled dispatch need explicit 5F.3 adapters and tests. No production task
was registered, source enabled, live database migrated, app restarted or
provider contacted. No dependency was added/installed. JSON and document
snapshot budgets bound each job; job history has no pruning yet.

The venv launcher hit its recorded sandbox interpreter restriction. Authorized
offline test execution outside that restriction worked without environment
changes. All 20 initial runner tests passed, then simultaneous legacy startup
exposed SQLite returning BUSY on the fresh-file WAL transition. Added a narrow
five-second retry deadline for BUSY/LOCKED with 50 ms polling and tests for
deadline/non-lock errors. Expanded acceptance to 24 runner tests, including
progress-total preservation, source revocation after restart and completed
coverage retention. Focused suite: 42 tests passed in 8.624 seconds. Final
full suite: 553 tests in 71.144 seconds, 552 passed and one existing skip.
Existing Starlette/httpx warning, synthetic invalid-PDF messages and asyncio
timing notices remain. Six normal-lifespan GET pages returned 200 offline;
legacy rows/views and user_version were preserved. Real spawned-process crash
and independent competing-process checks ran on Windows. Linux was not run.

**Subphase 5F.2 Complete.** Dated acceptance and limits are in
docs/review/2026-11-26-5f2-closeout.md. Updated roadmap, paired summaries,
testing/shared-evidence runbooks and handoff, with repeatable commands in
docs/runbooks/durable-jobs.md. Read-only Git inspection was requested but not
yet approved. No Git operation, staging, commit or push has occurred in this
pass. Exact 18-file proposal: docs/review/2026-11-26-5f2-checkpoint-files.md,
message `Add durable job runner`. Individual commit and separate push
approval remain pending. Unrelated Feedly rules and local Claude settings
were untouched. Stop here. Next chat: 5F.3 Scheduled Feed Refresh and Source
Health, after resolving any pending checkpoint.

### 2026-11-26: Approved the 5F.1 Commit and Push

After the exact 14-file proposal, the operator explicitly approved both the
named commit and its push in the current chat. Rechecked main at 8df28b0,
the empty index, the approved paths and the existing origin/main destination.
The destination resolves to the project's existing GitHub repository with no
credential-bearing URL components, and .githooks remains configured. No
unrelated local file is part of this approval.

Updated the handoff, closeout and manifest to record the approval rather than
leave an obsolete pending-approval state. Added exact manifest-based commands
to the shared-evidence runbook. This entry is prepared for the approved
checkpoint; actual commit and push results belong in the closing chat message
to avoid a self-referential commit hash. No implementation changed, so the
final 529-test result remains the acceptance evidence. Stop at this boundary.

### 2026-11-26: Subphase 5F.1 Complete, Shared Evidence and Source Registry

Implemented only the first foundation subphase. Read the foundation scope,
current handoff/session runbook, newest research notes, existing core and
vulnerability/infrastructure schemas and evidence views, Phase 2 closeout,
focused Phase 1 review guidance and saved source research. No upstream source
was fetched or newly judged. The operator confirmed Phase 2 commit 8df28b0
was already pushed and verified; older pending-checkpoint notes are history.

Added app/core/evidence_models.py, evidence_schema.py and evidence.py. Core
startup runs a versioned additive migration in a serialized transaction.
It creates sources, document captures, observations, citations and scoped
source links plus its own version ledger. No legacy data backfill, table/view
replacement or SQLite user_version takeover. Shared connections enforce
foreign keys without changing legacy connections' behavior.

Sources carry explicit collection class/method, terms decision/date/reference,
rate-limit notes, reliability and a separate dated license finding. Unknown
sources register automatically as F, unreviewed and disabled when existing
evidence is saved. Trusted local source review is explicit. The sole starter
entry is the existing RVM provider, using the 2026-11-11 saved license finding
and reference. This is historical metadata, not a current upstream terms
review or collection authorization. Existing manual routes are unchanged;
future source jobs must check the gate before each bounded unit and retry.

Document source record, local capture key, upstream revision, original-byte
digest, publisher and optional job-run association remain distinct. Unknown
source dates stay null; date-only precision is retained and aware instants
normalize to UTC. Observed, published, collected and source first/last-seen
dates never substitute for one another. Observations keep separate assertions
for each document. A mention produces no malicious or exploitation verdict.
Bounded excerpts/locators, unresolved citation hops and scoped source lineage
preserve provenance. Replays are idempotent; conflicting metadata requires
new keys. Explicit citation resolution preserves the original reference and
can itself be safely replayed, including the original unresolved input.

Documented later job and bounded-archive contracts in the new shared-evidence
runbook. Raw bodies, archive paths and pruning are absent here. Future raw
retention must have finite byte/age budgets and sensitivity rules while
retaining indicator/provenance history. No scheduler, collector, AI, alert UI,
source-review UI or new dependency was added. Dedicated entity/assessment
catalogs, automatic corroboration, review history and source-health expiry
remain later consumers rather than unused foundation machinery.

The venv launcher first failed to create its known installed base interpreter
inside the managed sandbox. Running the authorized offline tests outside that
launcher restriction worked; no environment change or reinstall. Initial
targeted tests found a reused pydantic class-validator signature mistake and
an incomplete legacy test fixture. Corrected both. Review also separated
capture identity from source revision, preserved resolved citation replays,
and rejected malformed timezone offsets and UTC overflow explicitly.

All 18 focused tests pass. Final full suite: 529 tests in 68.220 seconds,
528 passed, one existing skip, no failures/errors. Migration tests preserve
legacy rows/views and user_version, exercise rollback/retry and concurrent
initialization, and verify FK integrity and source defaults. Provenance tests
exercise four independent source assertions, typed/unknown dates, correction
history and citation chains. The normal app lifespan and six existing pages
returned 200 on a temporary database with network refusal. Existing
Starlette/httpx deprecation, invalid synthetic PDF diagnostics and asyncio
timing notices remain. No live database migration, app restart or provider
refresh was performed. Linux was not executed in this Windows pass.

The operator approved read-only Git inspection in this chat. It confirmed
main at 8df28b0 with an empty index. Git warned that the global ignore file
was inaccessible in the sandbox and about normal LF/CRLF conversion; no
configuration changed. The unrelated Feedly rules and local Claude settings
were left untouched. Commit and push remain individually pending. The exact
14-path proposal and message are in
docs/review/2026-11-26-5f1-checkpoint-files.md. No staging or remote contact.

**Subphase 5F.1 Complete.** Acceptance and limits are in
docs/review/2026-11-26-5f1-closeout.md. Updated paired status summaries,
roadmap, test runbook and handoff. Stop here after checkpoint handling.
Next chat: 5F.2 Durable Job Runner, using the ready-to-paste handoff prompt.

### 2026-11-26: Approved the Exact Phase 2 Checkpoint Commit

The operator explicitly approved staging and committing the 119-path proposal
as Complete Phase 2 and document subphase handoffs. Push was not authorized.
Rechecked the branch, empty index and named pending files before staging.
Updated the existing checkpoint record, handoff and session runbook to reflect
the approval and repeatable manifest-based commands. No path was added to the
approved scope. The two excluded local files remain outside it.

This note is prepared for the approved commit. The actual commit ID/result
and subsequent push decision are recorded in the closing chat message and
verified Git state, avoiding a self-referential hash in this same commit.
The next session must verify that checkpoint rather than blindly repeat it.

### 2026-11-26: Inspected the Pending Phase 2 Git Checkpoint

The operator approved read-only Git status/diff inspection to prepare the
commit proposal. No staging, commit or push was authorized or performed.
Branch main is at a07898b, Advance Phase 2 coverage and unify vulnerability
evidence. The staging area is empty. HEAD matches the locally stored
origin/main reference; no fetch or live GitHub check was run. The accumulated
working changes span multiple earlier Phase 2 passes and their documentation,
not just the most recent handoff edits.

Prepared docs/review/2026-11-26-phase2-checkpoint-files.md with the exact
119-path proposal and message, Complete Phase 2 and document subphase
handoffs. The removed manual report intake template is an intentional
deletion. Related passive artifact-review tooling, research notes, runbooks
and tests are included. The reader prototype file is only a static Phase 4
research note linked by project planning. Excluded .claude/settings.local.json
and the separate feedly-review-rules.md workflow. Neither excluded file was
changed or staged. Do not use git add . for this checkpoint.

A local bounded filename/text scan checked about 1.67 MB of proposed content
before the proposal file was added. No matching private-key/token patterns
or operator home paths. Two credentialed URLs were intentional synthetic
fixtures: the extractor redirect-refusal test and the wheel auditor redaction
test. This limited check does not certify arbitrary code as benign. The
working report is data/checkpoint-inspection.json and stays local/ignored.
Reviewed the scoped diffs and normalized line-ending noise while reading;
no repository/global line-ending configuration was changed. Tracked diff
whitespace checks passed. The sandbox could not access a global Git ignore
file; did not alter it. hooksPath is .githooks and the existing transcript
guard remains configured. No hook bypass is proposed.

The prior final 511-test result and 26-page walkthrough remain the acceptance
evidence. No implementation changed during checkpoint preparation, so no
test rerun, provider refresh, install or application restart was needed.
Updated docs/handoff.md from unverified Git state to the actual inspected
checkpoint, with commit approval and subsequent push approval still pending.

### 2026-11-26: Parked the Reviewed Reader Prototype

The operator requested a static opinion on a standalone RSS/newsletter draft
and then deferred integration. Read the context and all prototype source,
templates, tests and configuration examples in the nested Downloads folder.
The review is complete; Phase 4 integration is operator-deferred. Reusable
pieces, local location, failure cases and future acceptance requirements are
in docs/review/2026-11-26-reader-prototype.md. No downloaded code was executed
and the claimed four passing tests were not independently verified.

The operator challenged the prototype's separate KEV import. Agreed: news
feeds can be ordinary reader sources where publishers provide them, while
structured CVE/KEV badges reuse the vulnerability module's stored evidence
and freshness. Recorded this ownership in Phase 4. News mentions alone do
not promote exploitation status. Preserve the Phase 5 foundation dependency
and existing Build order. No integration, installation, network request,
Git operation or copy of the prototype/context into the project occurred.

### 2026-11-26: Adopted Subphase Sessions and Explicit Handoffs

The operator agreed with dividing future work into coherent subphases and
asked for explicit notes when each ends, plus a handoff prompt for the next.
They also proposed committing and pushing before new sessions. Documented
that as the normal checkpoint, preserving individual commit and push
approvals. The message did not authorize a particular commit or push; no
Git command was run, including status/diff inspection. Current HEAD,
staging and remote synchronization remain unverified. This is not a claim
that all earlier local Phase 2 changes are cleanly staged or saved remotely.

Added the same session-boundary rule to AGENTS.md and CLAUDE.md. Each subphase
ends with a dated Complete, Incomplete or operator-deferred record, acceptance
evidence, remaining limits, a journal/roadmap update and a focused next-chat
prompt. A session/credit limit alone does not complete work. Pending Git
approval or an unavailable push must be stated instead of silently discarded
or stashed. The next agent must not treat saved prompts or old approvals as
permission for new Git operations. A fresh operator message starts the work.

Created docs/runbooks/session-handoff.md with the closeout checklist, compact
handoff template and exact example Git commands under separate approvals.
Explain why a commit is a local checkpoint and a push is a remote code copy;
neither backs up ignored data. Stage only reviewed named files and exclude
secrets, transcripts, runtime state and unrelated local settings. Record the
actual commit/push result in the closing message after it occurs. Avoid an
endless amend loop trying to put a commit's own hash into its tracked handoff.

Created docs/handoff.md with current Phase 2 completion, prior verified test
and page results, unresolved Git checkpoint and a ready-to-paste 5F.1 prompt.
It explicitly warns that earlier Phase 2 batches may be uncommitted and must
be inventoried under approved Git inspection. Do not blindly stage everything.
The prompt first resolves that checkpoint, then scopes work to the shared
evidence model/source registry and defines acceptance and the next closeout.
No new chat was created and no foundation implementation began.

Split the existing foundation scope in ROADMAP.md into 5F.1 evidence/source
registry, 5F.2 durable jobs, 5F.3 scheduled freshness/health, 5F.4 saved reports
and archives, and 5F.5 alert inbox/integration acceptance. Each has a concrete
done-when condition. All remain not started. This does not bring forward
collectors, AI or parked Phase 2 features. A large subphase may be divided
again at a tested milestone. The shared job/corpus contracts start in 5F.1
to reduce rediscovery and incompatible schemas in later sessions.

Shortened the lengthy current-status sections in both agent files to the
same compact summary and pointers. Retained the existing approval, research,
dependency and secret-handling rules. Detailed Phase 2 facts remain in the
journal and dated reviews. Routine next-session context should come from
the current handoff and linked relevant sections, not a copied transcript
or a reread of every historical entry. This preserves extensive Claude
handoff notes while reducing repeated onboarding context.

Added an explicit session boundary and handoff link to the Phase 2 closeout.
This pass changes documentation only, so no application test rerun, provider
refresh, install or restart was needed. The recorded 511-test/26-page results
are the prior closeout evidence, not newly generated results on 2026-11-26.
Checked the new local links and matched the paired workflow/status guidance.

### 2026-11-25: Finished Phase 2 First-Delivery Scope and Review Redesign

This continues the 2026-11-24 pass. The operator authorized the remaining
Phase 2 implementation work in one pass, with questions only for decisions
that actually needed their input. Three answers resolved the remaining
product choices: keep the existing CISA SSVC decision points and park the
full outcome; expose retained normalized source data and put full original
response archives in the shared evidence store; change the Since Last Review
table rather than remove it. Used the proposed compact recent grouping for
the last choice. No answer authorized deleting or acknowledging the backlog.

The accepted first-delivery implementation is now closed. The detailed
scope matrix, validation and exclusions are in
docs/review/2026-11-25-phase2-closeout.md. This is not a declaration of full
historical coverage, all roadmap ideas implemented, or operational v1
readiness. Scheduled source freshness and reliable recovery remain important
before real daily use. They belong to the next existing Build order item,
the Phase 5 foundation: scheduler, job runner, alert inbox, shared corpus and
source registry. This does not jump ahead to collectors, OSINT or honeypots.

Expanded Exploited and Unfixed beyond the existing Red Hat VEX adapter.
The new unfixed.py helper resolves raw CSAF product IDs and group IDs before
normalization loses identity. It accepts explicit none_available or
no_fix_planned assertions only for resolvable affected targets. Fixed,
unaffected, under-investigation and contradictory targets do not qualify.
Repeated CVE entries are merged before evaluation. Identical display names
do not merge distinct product IDs. Workarounds are limited to the matching
targets. Ambiguous vendor-fix scope conservatively suppresses a finding.
The relevant OASIS CSAF remediation and scope sections were reviewed; this
helper is not a full schema/conformance validator or a semantic text parser.

Both the existing generic vendor CSAF parser and OT parser retain these
findings. A derived SQL view unifies them with Red Hat VEX. Shared CVE rows,
view membership/counts, detail evidence, action badges, First Steps and
review capture consume the same current source facts. Successful corrections
remove current findings without erasing historical review events. A change
to the document date alone does not generate a duplicate target finding.
Mixed fixed and unfixed releases remain possible. The previous Red Hat test
expected Patch to disappear globally when one release was unfixed. Changed
that expectation because a patch for another release remains useful scoped
evidence. Patch, Mitigate and Hunt can therefore appear together when their
independent evidence warrants it. Missing patch links never establish no-fix.

Legacy normalized vendor/OT records lack the product-ID provenance needed
for safe retrospective scope inference. Do not silently promote them.
The new advisory_reload.py helper and same-site POST let the analyst reread
one existing advisory from a fixed publisher endpoint. Paths must match an
eligible stored record and the existing source patterns. No arbitrary URL,
redirect following or full-feed refresh. SUSE has a 64 MiB body cap and the
other supported sources 32 MiB, using the existing bounded HTTP helper.
Invalid documents and request failures preserve previous evidence, with a
short dated result instead of a raw provider error. OT refuses older document
revisions. Vendor imports retain the index checkpoint separately from the
actual scope_revision stored with the evidence. The UI is a bounded local
workflow, not a distributed concurrency guarantee. No live advisory reload
was performed in this closeout; HTTP paths were mocked in tests.

Replaced the CVE page's narrow raw-data area with Stored Source Data. It
uses a fixed list of retained source fields, rendered as escaped JSON under
collapsible source labels. This includes the local CVE record, NVD, SSVC,
EPSS, Microsoft, vendor and OT evidence, no-fix sources, exploit indexes,
GitHub, sightings and related retained facts. The explanatory text says these
are normalized retained fields, not complete original responses. The shared
evidence store must add bounded original archives with source/retrieval
provenance, source revision, retention and redaction. Full SSVC outcomes
remain parked rather than inventing organizational mission/well-being inputs
from a public product watchlist.

Since Last Review now groups the dashboard's unread events by CVE over the
last seven days, limited to five recent CVEs. Show types, source/change
counts and last local observation. Counts do not imply independent reporting.
Review This CVE opens a filtered queue. Its item and bulk controls scope SQL
updates to that CVE and stop at the displayed latest event ID. The full queue
and 90-day history remain available. Opening pages never acknowledges events.
No migration reset, deletion or automatic Mark All was added. This first
slice removes the enormous dashboard count; it does not yet suppress every
additional citation as immaterial. Keep a future material-change/watchlist
digest improvement in the parking lot. Existing retention/pruning is unchanged.

Added ten no-fix/reload tests and four digest tests. They cover product/group
resolution, conflicting targets, mixed releases, source corrections, legacy
guards, fixed publisher request paths, failed-request retention, source-data
rendering, grouped limits/order, read-only GET behavior, CVE-scoped review
and cross-site refusal. The final suite ran 511 tests: 510 passed and one
existing skip, zero failures/errors. The separate temporary-database coverage
probe confirmed OT table/detail scores and actions, watchlist/review effects,
retained legacy report behavior and explicit-ID layout handling. Its uncited
sighting stays outside Known Exploited; Hunt in that fixture is justified by
the separate Exploit-DB entry. EUVD publication fallback does not become a
first exploitation date or a zero-day lead. Manual report intake stays removed.

The trusted interpreter used -B -I -S with explicit project/reviewed-package
paths for this diagnostic run. No new dependency was installed. The existing
Starlette/httpx deprecation warning was observed; it did not authorize an
installation. Initial final-check output was lost in a context interruption,
so the full suite was repeated while verification was unresolved. That repeat
completed successfully; do not keep rerunning it without a new reason.

Restarted only the verified project run.py server, with a hidden launcher and
local logs. Startup completed at 127.0.0.1:8000. On resuming after the credit
limit, confirmed that restart and the saved successful test result rather
than repeating completed work. All 26 local acceptance GETs returned 200.
The new digest and Stored Source Data rendered. Read-only SQLite snapshots
confirmed unchanged feed status and total/reviewed event counts across the
walkthrough. No provider refresh, review acknowledgement or arbitrary remote
request was part of that walkthrough. Runtime result:
data/phase2-closeout-acceptance.json. Logs:
data/phase2-closeout.stdout.log and .stderr.log. They stay ignored.

One sequential local pass measured dashboard 16.98 seconds, Zero-Days 7.12,
and loaded CVE detail 0.30. This is not a benchmark or a performance fix.
Retain the parked profiling/HTMX work and its focus on actual query costs.
The original PDF acceptance remains 105 of 106 hashes for the separate
MuddyWater artifact; the out-of-order cross-page row is still unsupported.
Preserve other documented later work: broader Supply Chain ecosystems and
advisory intake, saved extraction/Enrich All, source archives, social/news
collection, exports, cases, full SSVC, and optional AI narrative inference.
GreyNoise per-CVE stays at honeypots or the final backlog regardless of keys.

Updated ROADMAP, both agent status summaries, the module/testing runbooks and
new docs/runbooks/phase2-closeout.md. No git operation, staging, commit or
push. No credential/configuration change or downloaded artifact execution.
The pre-interruption roadmap edit briefly referenced a not-yet-written
closeout document dated 2026-11-24. The completed record is dated 2026-11-25;
corrected the links and milestone date before handoff. No dangling reference
should be treated as a completed acceptance record.

### 2026-11-24: Parked GreyNoise and Added Chrome Vendor Exploitation

The operator moved optional GreyNoise per-CVE integration to the very end,
or no earlier than the honeypot stage. Updated the roadmap parking lot,
current module notes and both agent status summaries. An available key is
not a reason to reopen this in Phase 2. Existing Phase 1 community IP lookup
is separate; no removal or provider operation was requested or performed.

Continued with the existing Chrome exploitation-statement feature. Read
three original publisher article bodies, with source links in the review.
They demonstrate why a CVE mentioned elsewhere in a notice must not inherit
exploitation from the one explicitly named. One other article URL redirected
to a Google challenge and was not reviewed or bypassed. No live feed import,
key lookup, dependency installation or upstream code execution in this pass.

Added a small deterministic Chrome prose parser. It recognizes explicit
Google awareness/report sentences about a named CVE's exploit existing in
the wild, plus explicit plural CVE lists. Whole-statement grammar avoids
common quoted examples, conditions, negations and inline corrections. HTML
quote/code/script blocks are excluded. Non-whitespace barriers prevent a
removed inline code qualifier from turning the remainder into a positive
claim. Unknown prose remains a reference; this is not semantic AI extraction
or protection against every possible misleading publisher statement.

Store the statement and typed report revision with per-CVE vendor evidence.
Extend the shared positive-source SQL views so Known Exploited, summary,
P1, Hunt, First Steps, table labels and review events agree. Show a dated
vendor citation under Exploitation Details. Other CVEs in the same notice
remain references. Do not infer patch/version status from a stable-channel
announcement, or Confirmed Zero-Day from this sentence alone.

Use the Atom updated date, not the original publication, discovery or
mitigation date. This dates a positive advisory revision. Preserve the
earliest recorded positive revision through continuous later assertions;
otherwise an unrelated edit would advance the supposed first report date.
A successful withdrawal removes current evidence; reassertion starts from
the new revision. Older entries cannot restore a newer withdrawn assertion.
An HTTP/parse failure retains the previous successful notice. Other source
assertions survive. Historical review events remain historical.

Vendor notice saves now invalidate view counters after commit. Direct
same-day imports/corrections would otherwise leave cached counts unchanged.
The existing schema startup recreates derived SQL views, without a new data
table or a historical import. Old saved summaries are not reparsed into
claims because they may be truncated and lack quote/code boundaries. Use
the existing explicit Refresh Chrome control to populate current-feed data.

The initial focused tests used nonexistent helper names and an incomplete
KEV fixture. Corrected the tests to the actual BY_SLUG, review.page and
complete upsert input. Those were test-authoring errors, not application
failures. Added eight synthetic contracts for parsing, scoping, dates,
continuous revisions, correction/reassertion, provider failure, shared
consumers, citations, UI rendering and counter invalidation. The review is
docs/review/2026-11-24-chrome-exploitation.md; repeatable commands are in
docs/runbooks/chrome-exploitation.md. No git operation, commit or push.
The final full offline suite ran 497 tests: 496 passed, one existing skip,
zero failures/errors. This includes the revision-continuity and excluded-code
barrier regressions. No provider quota or live feed request was used.
Restarted the verified project app with hidden logs at
data/phase2-chrome.stdout.log and .stderr.log. Startup completed and the
listener remained 127.0.0.1:8000 only. Chrome-filtered Vendor Updates and an
already loaded CVE returned HTTP 200. A mode=ro SQLite check confirmed the
new derived evidence view exists in the operator's database. It has zero
stored assertions because no current-feed import was run and old summaries
were deliberately not promoted. Do not claim live data was populated by the
code change. The existing Refresh Chrome POST activates the parser against
the current public feed when that explicit update is desired.

### 2026-11-24: Resolved Phase 2 Optional Sources and Loading Scope

The operator clarified that freshness is optional only during the build.
Once v1 is used for actual investigations, it is important. Corrected the
roadmap, both agent status summaries and runbooks to preserve that boundary.
Added v1-data-freshness.md: per-source schedules/stale thresholds, distinct
attempt/success/source/coverage dates, startup gap recovery, visible stale and
failed states, quotas/backoff and failure-injection acceptance. These are
Phase 5 foundation requirements before operational v1 use, not delivered
scheduler functionality. Commits remain separate from network jobs.

Resolved the loading scope explicitly: HTMX partial reloads move to the
existing post-v1 performance item. No JS artifact was fetched, installed or
executed. Ordinary URLs, anchors, filters, sorting and SQL catalog paging
remain. Revisit measured page/database cost before assuming fragment swaps
will fix latency. Keep history/focus/race/error-fallback/no-JS acceptance in
that follow-up. Do not label partial loading as built.

Reviewed GreyNoise's current per-CVE operation and plans. The older-looking
v3getvulndetails documentation URL was inaccessible; getcve is readable and
documents /v1/cve/{cve_id}, with entitlement-dependent data. Plans distinguish
community basic IP access from richer CVE products. Deferred this adapter
until useful permitted access is confirmed. No credentials were read, no
authenticated provider requests were attempted and no IP allowance was spent.
The existing keyless community IP enrichment is a separate capability.

CVEDB's primary FAQ and OpenAPI schema support an immediate keyless,
non-commercial comparison. The interactive docs page had no readable body
through the web tool, so schema/operation definitions came from OpenAPI.
Wrote a small own adapter using the existing bounded JSON client, limiter
and SQLite cache. No upstream executable code or runtime data is shipped.
No new dependency, key or account was required.

Added an explicit CVE-page comparison POST and collapsible card before
References. Ordinary GET reads only saved CVEDB state. A fresh success is
reused for 24 hours unless Refresh Saved Result is selected. Cache retention
is 30 days, with the normal startup purge. Record success and attempt times
separately, keep a previous success after an error/404/429/identity mismatch,
and label stale data without renewing its date. Concurrent duplicate calls
share the fresh result. Fixed-host HTTPS, no redirects/keys, shared 30-second
timeout and 5 MiB cap; ten requests/minute is our courtesy limit, not a
published entitlement. These controls do not make a provider's facts true.

Show CVSS/EPSS/exploitation fields beside current page evidence. Require
known aligned CVSS versions before flagging a score difference. CVEDB's
reviewed schema has no EPSS score date, so do not claim a same-day conflict.
Keep aggregate exploitation coverage uncertain; agreement may share upstream
sources, while Not Flagged does not mean never exploited. No product import,
priority/action promotion, view membership change or review capture from the
comparison. Supplied ransomware text remains escaped source context.

Six new synthetic offline tests cover keyless isolation, cache/force/stale
behavior, failure retention and dates, concurrency, hostile values, identity
and comparison semantics, same-site POST, passive escaped rendering and
unchanged triage. Full suite: 489 tests, 488 passed, one existing skip. No
live provider API fetch was performed in this pass. The source review and
scope dispositions are in docs/review/2026-11-24-phase2-source-scope.md;
repeatable steps are in docs/runbooks/cvedb-comparison.md.

Restarted the verified project app with a hidden launcher and logs at
data/phase2-source-scope.stdout.log and .stderr.log. Startup completed with
only a 127.0.0.1:8000 listener. Read-only GET of the already loaded
CVE-2018-13257 page returned 200 and the new comparison card/control, with
no saved result. No CVEDB fetch was invoked. Then completed 25 local GETs:
eight module entry points, all 15 catalog/view routes, Report Extraction and
Decoder Tool. Every page returned 200; feed status was identical before and
after. Paths/status/timings are in ignored data/phase2-scope-acceptance.json.
This proves those routes rendered, not full data correctness or live provider
availability. Existing semantic regression tests carry the stronger contracts.
Observed slow GETs were Dashboard 16.31 seconds, Zero-Days 7.78 and AI and ML
Stack 6.05. These are one-pass timings, not controlled benchmarks. Retain them
for the existing performance follow-up; all-200 does not mean the UI is fast.

No git operation, commit or push. These scope questions are now resolved.
Phase 2 retains documented history/coverage limits and one out-of-order PDF
hash row. The next real feature item is explicit Chrome vendor exploitation
statements. The current Chrome feed keeps those notices as references; do
not label that capability delivered or declare all of Phase 2 complete from
this scope pass. Finish the remaining accepted feature scope before the
Phase 5 foundation. Do not confuse that foundation with skipping ahead to
collectors or relaxing data quality once the operator uses v1.

### 2026-11-24: Feature Work, Manual Refresh and Original PDF Check

The operator corrected the direction of work: repeated NVD/CVE List catch-up
was delaying visible features. Accept that correction. Data freshness is
optional maintenance during development, not a Phase 2 feature gate. Do not
add automatic network work to commits. Existing general refresh and isolated
NVD controls remain available. No live feed import was run in this pass.

Added Fetch New CVE Records under Feeds. Its same-site POST calls CVE List
incremental refresh only, captures local review changes and redirects to feed
status. GET remains read-only. Existing missing-snapshot/14-day age checks
remain. The button never falls back to the large snapshot download or calls
NVD/unrelated feeds. No new dependency, git operation, commit or push.

Delivered the Phase 2 extension-ID scope item as a small deterministic report
feature. Chrome IDs require explicit ecosystem labels, recognized official
store URLs or chrome-extension resource URLs. VS Code requires explicit
labels or its marketplace URL. Firefox requires a labelled stable add-on ID;
AMO listing slugs and moz-extension runtime UUIDs do not establish it. Show
ecosystem, bounded context, copy controls and manual fixed-host store links.
Do not call stores or install extensions. Recognized references are masked
before ordinary IOC scans, including after the 200-unique-reference display
cap. This prevents hex-shaped Chrome IDs becoming MD5s and Firefox IDs
becoming email IOCs. Rules/YARA remain excluded. Bare strings retain legacy
behavior. Primary Chrome/Chromium, Microsoft and Mozilla docs are linked in
the review. No upstream extension code was copied or executed.

Recovered the original 28-page Trend Micro MuddyWater PDF from its publisher.
The selected public download is 1,617,194 bytes, stored only under ignored
data/phase2-acceptance-2026-11-24. Defender custom scan completed with explicit
no-threat output and exit 0. Signature/engine metadata and digest are in the
review. The sandbox initially blocked the download; the authorized scoped
retry succeeded. Reading Defender metadata required an elevated read. No
personal files, secrets, private data or settings were selected or changed.

The original report exposed two deterministic parser issues: SHA-256s was
not recognized as an explicit heading, leaving 32+32 rows as fragment MD5s;
and detection names on the following line were not consistently attached.
Fixed plural headings and next-line detection context, including underscore
labels. Reset old hash-section headings and avoid carrying previous detection
names into the next row. Added synthetic regressions. Source material remains
ignored, never a committed fixture.

Important correction for handoff: I initially described suspicious row
fragments as publisher errors. That was incorrect. An independent row-end
scan found 105 complete values plus a 41-character head. Visual appendix
inspection confirmed its 23-character tail at the next printed page's top.
The PDF content stream emits that tail after other tables, outside the
bounded adjacent-line repair. Thus 105 of 106 source rows are recovered,
all 105 with their detection labels; one remains missed, with no fragment
MD5s after the fix. This is a reading-order limitation, not missing source
bytes. Added a specific parking lot follow-up rather than widening PDF layout
scope silently or blocking other feature work. A trial pypdf layout-mode
comparison was unreliable and is not evidence of acceptance. Bundled Poppler
renders pages but does not include pdftotext. Printed pages 19-21 were rendered
and inspected. The original text, trial output and comparison JSON stay local.

Full offline suite: 483 tests, 482 passed, one existing skip. No external
requests are allowed by the suite. Synthetic coverage includes extension
identity ambiguity, disguised stores, code exclusion, truncation, hrefs,
escaped passive rendering, copy controls and isolated refresh guards. Restarted
the verified project app with a hidden launcher. Loopback feed GET, synthetic
three-ecosystem extraction and original PDF upload returned HTTP 200. The
upload showed 105 hashes; copy controls and row detection context were present.
No provider refresh POST was invoked during smoke checks. Existing test-client
deprecation warnings do not authorize installing a replacement dependency.
The final small URL-context refinement passed all 17 focused tests after the
full run. Restarted again using the same verified hidden procedure, with logs
data/phase2-features-final.stdout.log and .stderr.log. Startup completed on
127.0.0.1:8000. Final loopback checks confirmed feed/control availability,
nearby source text and removal of a synthetic query token from results.

Files added this pass: software.py, test_software_references.py, the feature
runbook and acceptance review. Updated extractor, main, PDF repair, feed route,
two templates, PDF tests, roadmap, testing/module runbooks and paired agent
status notes. Exact repeatable steps are in
docs/runbooks/manual-refresh-and-extension-references.md. Phase 2 remains open.
Next work is the small closeout disposition for HTMX/optional source lookups,
not another freshness audit. Preserve the remaining known PDF limit, optional
source decisions and the existing build order when handing back to Claude.

### 2026-11-24: Isolated and Resumed NVD Recent Changes

Continued the next Phase 2 action from the previous handoff: recover the
interrupted NVD recent-changes import, without refreshing other feeds.
Read-only baseline still showed 4,000 of 6,472 records processed in the
old partial run, error=NULL and no completed/pending checkpoint. NVD held
22,752 local rows, including the nine records loaded in the earlier targeted
backfill. Catalog and Known Exploited gap counts matched the 2026-11-20
post-backfill acceptance. No git operation or dependency change was made.

Added a dedicated NVD-only POST and a read-only preview/progress card on
Feeds. It defaults to public/keyless mode and validates mode/cross-site
requests. General Refresh feeds retains its separate behavior. The source
shares a single-worker run lock between general refresh and isolated
recovery, preventing duplicate concurrent walks. Previewing dates creates
no pending state and makes no request. Last-run state is retained in
sync_state, with requested UTC bounds, requests, processed records, source
total, charged bytes, mode, status and safe errors. It contains no key.

Each dedicated run allows six requests, a 64 MiB response cap, 192 MiB of
charged bodies and 180 seconds of network/rate-wait time. Parse/write/review
time is additional. Failed/abandoned responses charge their full allowance.
At page/body/time limits the pending interval is halved without advancing
the completed checkpoint. If the first page already reports more records
than the request allowance covers, split after that page instead of spending
the rest of an inevitably incomplete run. Ordinary HTTP/quota/parse errors
retain the requested window. Interrupted writes/cancellation are not marked
complete. No scheduler, silent key fallback or unrelated source request.

Focused testing found the legacy offset calculation advanced by requested
page size even if a shorter page was returned. It could skip records or
declare completion early. Fixed offsets to advance by actual returned count.
Reject duplicate IDs/pages, total-count changes and wrong response offsets.
Known page-integrity errors have static, useful messages; malformed source
values do not get echoed as arbitrary exception text. Window timestamps are
normalized to the seconds actually sent to NVD. Do not call this a snapshot
guarantee: historical membership can change as records are revised later.

An old page-walk test requested 2,000 but returned one synthetic row while
expecting offset 2,000. Corrected it to a realistic one-record page size.
Added ten independent recovery tests for read-only preview, route isolation,
public headers/limiter, short pages, duplicate/drifting responses, proactive
split, body/time budgets, storage interruption, concurrent rejection and
rate-limit preservation. Full suite: 475 tests, 474 passed, one existing skip.
The earlier focused budget test initially used a total below the requested
page size, so no second page was needed. Corrected that fixture; do not
misreport it as a production body-budget failure.

After tests, restarted the verified loopback app with a hidden launcher.
Announced each live window and the resource limits before its NVD-only POST.
Fixed recovery target: 2026-11-25 00:04:21 UTC, which is 2026-11-24 in the
operator timezone. Public date filters only; no key, private IOC, report,
watchlist profile or file was uploaded. Provider JSON remains passive data.

Run 1 covered 2026-11-11 00:47 through 2026-11-18 00:47 UTC. Completed
7,058 records in four requests and 30,390,985 response bytes. Local NVD rows
increased to 25,268, a gain of 2,516. The legacy original query retained
only its start date in status; recovery extends that start into bounded
catch-up windows rather than pretending the old result membership is fixed.

Run 2 covered 2026-11-17 23:47 through 2026-11-24 23:47 UTC. Completed
8,003 records in five requests and 33,785,400 response bytes. NVD rows
increased to 31,728. The one-hour overlap is intentional. Inspection during
this run found 6,953 first-run rows still carrying their original fetch
times, all with modification dates inside the first window; overlapping
rows had already been replayed. Do not claim that transient fetch-time
query was a complete immutable capture of all 7,058 first-run IDs.

Run 3 covered 2026-11-24 22:47 through 2026-11-25 00:09:21 UTC.
Completed 98 records in one request and 334,334 response bytes. All were
already stored; this final overlap added no unique rows. Completed coverage
exceeds the fixed recovery target, pending state is empty and error is NULL.
The completed UTC time is 2026-11-24 19:09:21 Eastern. Do not equate that
checkpoint with automatically staying current after the run.

Total: ten public requests, 15,159 processed rows, 64,510,719 charged body
bytes, about 61.5 MiB. Processed rows include overlap; the unique touched
cohort is 14,956 CVEs. All have valid modification dates inside the recovered
date range. NVD rows grew from 22,752 to 31,728, or 8,976 new rows. Other
feeds' most recent fetched time is still 2026-11-17, confirming that recovery
did not refresh them. No API key was sent. No provider error or resource
split occurred in these three live runs; those branches remain tested offline.

The catalog grew from 407,115 to 412,704 active IDs. Local gaps afterward:
381,923 NVD rows, 165,049 scores, 185,074 CWE IDs, 166,244 vendor/product
pairs. Do not present these as a fixed-cohort before/after improvement:
new IDs widened the population. Among touched active records, 5,955 lack a
local CNA record and 5,630 of those also lack NVD products. CVE List still
shows sync only through 2026-11-15 1900Z. That source was intentionally not
refreshed. The next metadata priority is its independent incremental catch-up,
rather than inferring vendors/products from descriptions or claiming that
NVD alone supplies all fields. It is not a proof that upstream CNA has
every missing field. Known Exploited stays at 5,950 active CVEs: NVD-row gaps
fell from 5,700 to 5,659; scores stay 1,619, CWE IDs 1,865, product pairs one.

Exact repeat commands and limits are in docs/runbooks/nvd-recovery.md;
acceptance is docs/review/2026-11-24-nvd-recovery.md.
The separate targeted historical queue, wrapped-PDF acceptance, and Phase 2
scope decisions remain separate work. No review acknowledgment reset,
commit, push, full-history import or new dependency was performed.

### 2026-11-20: Built the Targeted NVD Repair Queue

Continued Phase 2 with the bounded historical repair recommended after the
coverage audit. The operator's continue authorizes that work. The first
scope is Known Exploited, not all 407,115 local CVEs. No new dependency,
AI, scheduler, remote hosting or git operation is involved.

Added metadata.py, an additive nvd_backfill_queue table and a repair page
linked from Feeds. GET reads local candidates and recent results without
creating queue entries or making requests. POST prepares/reconciles the
queue, processes 5 or 10 records and redirects to results. Product gaps
rank first, then CVSS, CWE and absent NVD records. Stored fallback sources
count toward coverage. Only valid public CVE IDs on the known-exploited
source set qualify; rejected CVEs are excluded. Watchlist-only scope and
full-history NVD imports remain follow-ups.

Public/keyless mode is the default. Configured-key mode is explicit and
never silently falls back. The endpoint validates mode, record limits,
retry options and cross-site headers. Requests use the existing NVD
client, fixed HTTPS API, 5 MiB accepted-body cap and rate limiter.
There is a 90-second network deadline. Local candidate selection and
review capture are outside that network budget. The app has one worker;
an in-process lock prevents overlapping batches. Future multi-worker
hosting needs persistent leases. No automatic background continuation.

Queue progress survives restarts. Pending work remains pending until a
completed response is handled. Interrupted work can replay safely. Quota
and rejected keys pause rather than spending the rest of a batch. Ordinary
errors mark failed items and preserve previous metadata; explicit Retry
Failed requeues them. Retrieved and not-found entries do not loop merely
because fields remain absent. Result labels deliberately distinguish
retrieved from fully populated. A pending gap resolved by another source
can close without another request. Deadline-limited attempts count and
rotate behind unattempted work of the same priority.

Hardened per-CVE NVD handling: 429 is quota, malformed bodies and incomplete
empty pages are errors, and an unexpected CVE ID cannot be saved. This is
separate from the completed-window fix for NVD's recent-changes feed.
Raw source data is passive. No page scripts or downloaded commands execute.

Added 12 offline backfill regressions for selection, limits, resume, unknown
fields, missing records, failed retries, preserved metadata, quota/auth
pause, wrong identity, deadlines, concurrent runs, reconciliation and routes.
Initial full suite: 464 tests, 463 passed and one existing skip. Deadline
attempt tracking then passed all 11 targeted tests. A later interruption
guard records storage exceptions/cancellation as interrupted, preserves
pending work and releases the lock. Its added regression brought the final
full suite to 465 tests, 464 passed and one existing skip.

Read-only live preview found 5,709 candidates, including nine product gaps.
Announced the first five CVEs, five requests, public/no-key mode and a
25 MiB accepted-body budget before the first live batch. Reused the verified
loopback launcher and hidden-window restart procedure. The live preview
matched the announced IDs before POST. Exact commands are in
docs/runbooks/nvd-backfill.md.

Live batch 1 retrieved four records and recorded one not found. The not-found
ID, CVE-2016-200017, is present in the locally stored VulnCheck assertion.
Do not guess a replacement or label the assertion false merely because NVD
has no record. Original-source validation remains a follow-up. A second
announced five-request batch covered the four remaining product candidates
and first score candidate. It retrieved all five. Ten total public/keyless
requests, no failed requests, and each attempted ID has exactly one attempt.
Queue state after both runs: 5,699 pending, nine retrieved, one not found.

Known Exploited gaps fell from 5,709 to 5,700 NVD rows, 1,623 to 1,619
scores, 1,872 to 1,865 CWE IDs and nine to one product pair. Population
stays 5,950 non-rejected CVEs. The remaining product gap is the not-found
ID. CVE-1999-0192 gained a CVSS 2.0 score and products but still has no
CWE; its retrieved status must not hide that gap. CVE-2015-0279 also
demonstrates the older CVSS 2.0 fallback with its version retained.

Both POSTs returned successful result pages. Read-only queue inspection and
the independent coverage audit confirmed progress and no duplicate attempts.
The 85 uncited claims and six without other exploitation evidence are
unchanged. The separate incomplete recent-NVD window was not retried, and
no review acknowledgment reset, git operation, commit or push occurred.
Acceptance details are in docs/review/2026-11-20-nvd-backfill.md. Phase 2
remains open; scheduled continuation still belongs to the Phase 5 foundation.
After the final interruption guard passed the full suite, restarted the
idle app again. GET checks confirmed durable queue counts, the unresolved
NVD result, the Feeds link and the RichFaces score/CWE/product on its detail
page. No additional NVD request was needed for those checks.

### 2026-11-20: Counted Coverage Gaps and Retired Two Workflows

The operator asked how many uncited exploitation leads and missing metadata
records remain, why the gaps exist, and how recurrence is prevented. They
also directed removal of non-explicit TTP mapping until AI assist and removal
of manual exploitation report intake. This pass stayed within Phase 2.
No git operation, commit, push, dependency install or bulk feed refresh was
performed. No credentials or private records were submitted anywhere.

Read-only snapshot: 407,115 non-rejected local catalog CVEs; 385,260 lack
an NVD row. Across locally stored fallback sources, 165,146 have no CVSS,
185,000 no CWE ID and 160,987 no usable structured vendor/product pair.
Among 5,950 non-rejected known-exploited source records, the corresponding
gaps are 5,709 NVD rows, 1,623 scores, 1,872 CWE IDs and nine product pairs.
These are local gaps, not proof that upstream NVD has the missing facts.
Counts overlap. A full CVE List load is not a full NVD load. Local-first
details intentionally avoid fetching remote data just because a page opens.
The previous selected-CVE button did not solve historical coverage.

For CVE-2018-13257, NVD lastModified is 2026-06-17. That is outside the
November recent-change import. Its selected load supplied the previously
missing authoritative score, CWE and product data. The parser already
supported CVSS 3.x. Do not attribute the original absence to v4-only parsing.

The first day-level query counted 84 CVEs with an uncited-only daily
sighting group. A source-level audit counts 85 CVEs with uncited assertions:
74 labelled The Shadowserver, 11 Telegram. One also has a cited sighting,
which explains the difference. Six have no other exploitation evidence;
the other 79 have an independent stored positive source, whose actual
reporting independence is not established by this count. The snapshot's
rolling sightings cover 2026-11-14 through 2026-11-16. These are exploitation
claims, not all GitHub PoC leads or infrastructure candidates. Uncited does
not mean false. Citation-qualified gating and requested-CVE response checks
were already implemented and remain. A URL provides traceability, not proof.

Found another correctness bug: the stored NVD recent-changes refresh saved
4,000 of 6,472 records, with a ReadTimeout in its version text but error=NULL.
Old code labelled a partial run successful and could use its fetched_at as
the next starting point. A retry could then skip the unfinished data.
NVD now pins a pending time window before requests. Only a complete page
walk advances the completed checkpoint. Failures replay the same window
from page zero; upserts make replay safe. Avoid claiming API pagination is
an immutable snapshot. Dense page-capped windows are halved and retried.
Completed old windows catch up in seven-day slices with an hour of overlap,
without dropping a watermark merely because it is old. Recognize legacy
partial version strings and recover their original start. Reject missing
result metadata, malformed CVE entries, wrong response offsets and empty
pages before the reported total. Feeds displays the legacy partial state
as incomplete instead of green OK. Version text shows the window end.
No live retry ran in this pass. This fix prevents the identified cursor bug;
it does not promise complete history or populated upstream fields.

Added scripts/audit_vulnerability_coverage.py. It uses only stdlib, opens
SQLite in mode=ro, takes a consistent read snapshot and reports aggregate
counts. It does not import the app, load .env or make requests. Its source
and field rules are covered with a synthetic temp database. Exact repeat
commands are in the vulnerability runbook. Results and limits are in
docs/review/2026-11-20-metadata-coverage.md.

Removed behavior.py, its application call and Candidate Behavior Mappings
UI. Retained explicit ATT&CK/ATLAS ID extraction and inert command/rule
artifacts. Inferred TTPs wait for optional Phase 11 and still need review;
AI will not guarantee their correctness. Regression checks ensure a scan
command remains readable without generating T1046.

Removed manual report list/intake/link routes, navigation, forms and
production write helpers. The snapshot has zero saved manual reports.
Kept the table and read-only legacy evidence access so an existing install
does not lose saved evidence or gain broken source links. Only synthetic
test fixtures can create/link old-format records now. Existing shared
evidence compatibility remains tested. No rows or history were deleted.
The manual feature is off the current scope and should return only if
the operator requests it. Automatic article discovery remains Phase 4/5.

Updated roadmap, paired agent status, runbooks and regression tests. Initial
full offline pass: 452 tests, 451 passed and one existing skip. Subsequent
malformed-response hardening adds one test. Final full suite: 453 tests,
452 passed and one existing skip. The app was restarted using the verified
loopback launcher and the existing documented hidden-window procedure.
Live checks passed after startup: retired listing returns 404; nmap text
remains a Command Line artifact without T1046; manual navigation is absent;
the existing partial NVD import displays Incomplete Download. No feed retry
or manual report write was triggered by those live checks.

### 2026-11-19: Operator Walkthrough, Exploitation Claims and Report Extraction

The operator found missing Microsoft publisher coverage, confusing blank
code evidence, implausible review volume, missing older-CVE metadata and
false-positive/partial report extraction. This was a broad corrective pass
within Phase 2. No dependency was added. No git operation, commit or push
was performed. Original reports and debug helpers remain in ignored data.

The Blackboard example CVE-2018-13257 had a CVE List description but no NVD
row, no structured CNA products and no KEV row. NVD's public record supplies
CVSS 3.1 6.1 Medium, CWE-601 and Blackboard Learn CPE products. Existing
code already supported CVSS 3.x. Added a bounded per-CVE metadata load and
explicit public/keyless option rather than inventing products from prose.
Hardened score selection so empty/invalid newer metrics cannot hide valid
older metrics. The keyless path has its own conservative rate limit and
never sends the configured NVD key. Loaded the selected example through
the local app and verified score, weakness and products in its response.
This is not a bulk repair of every incomplete historical record.

The exploitation source was an uncited community Telegram assertion. It
was not a CIRCL KEV assertion. Require an HTTPS citation for community
exploitation to affect shared views, priority, Hunt or zero-day leads.
Keep uncited rows and source labels visible as leads. Added an additive
citation column and a versioned per-CVE cache key; old uncited cached
summaries are not reused. A wrong-CVE API response is rejected. Citation
presence provides traceability, not independent credibility or confidence.
One diagnostic initially used `vulnerability` instead of `vuln_id`, which
the server ignored. The application already used the correct parameter;
this was not an application filter fix. Added the response identity guard
as defense in depth. Do not repeat the diagnostic result as a finding.

Microsoft Publisher rows reuse the existing MSRC advisory store and refresh.
Watchlist follows Supply Chain; New and Severe is capitalized consistently.
The shared table now distinguishes Exploitation Evidence from executable
code/templates, naming the actual source instead of guessing vendor versus
researcher. The Reports page explains the manual pre-CVE notebook and the
remaining Phase 4/5 reader/collector work. Direct original free KEV feeds,
feed administration under Health and a later distinct GUI were recorded.
Infrastructure already supports C2 IPs and filtered domains; passive DNS,
certificates, fingerprints, hosting and other infrastructure pivots remain
in Phase 6. This pass does not advance to that phase.

Review snapshot: 547,973 events across 28,638 CVEs, including reviewed
events. VulnCheck alone accounts for 468,815 exploitation events across
5,926 CVEs. Citation-level imports overwhelmed the global counter. Asked
for a choice between a watchlist digest, no dashboard panel and a grouped
global digest. No reply arrived during implementation. Recommended removing
the global counter or using an optional watchlist digest, grouped by CVE
and material change. No history reset, deletion or mark-reviewed action was
performed. Existing retention behavior remains unchanged.

ReversingLabs has 193 report hashes in declarative streamed page data;
ordinary visible HTML exposed 51. Raw HTML contains one additional site
verification hash. JSON-only reconstruction now recovers the 193 report
hashes without executing JavaScript. It uses depth, node, input and total
render-work limits and replaces visible content only when richer. Unknown
components remain unsupported. The reported hash now retains the Favicon
SHA256s caption and ARTEX console group. Full source pages were not copied
into permanent fixtures. Defender scanned the incoming public files and
completed with no detections; it does not prove content benign.

Google's report yields all 11 IPs from its indicator table with adjacent
descriptions. Six YARA rules are retained separately, along with recognized
queries and command lines. Code blocks are inert artifacts, excluded from
ordinary enrichment. Unlabelled plain-text code and publisher changes still
need review. Source links are references, not automatic IOCs. A first pass
that appended every anchor target created social-share/related-article
noise; corrected it to a separate reference list. Known TLD filtering drops
img.src, data.mdb and request.getparameter. The scanned public IANA list was
loaded into the ignored local cache. Pasted defanged hosting URLs remain
candidates rather than blanket-suppressing every GitHub path.

ATLAS IDs are kept separately from ATT&CK. The supplied ATLAS matrix URL
returned 404; reviewed MITRE's own repository docs and Apache-2.0 license.
Official ATLAS catalog loading/names are not built. Google has no explicit
ATT&CK IDs; the previous empty explicit table was therefore not a missing-ID
parser failure. Added narrow command-pattern candidate mappings, clearly
separate from reported techniques. Do not claim complete narrative TTP
mapping. Images have explicit click-to-load previews, not automatic fetches.
They remain outside IOC enrichment. The browser contacts the source on click.

Report success clears text, URL and upload inputs; errors preserve them.
Copy controls trim values, and indicator markup keeps spacing outside the
value. Decoder has its own tab. Regression fixtures cover streamed JSON,
rule isolation, context, controls, Microsoft, metadata and exploitation
traceability. Full offline suite: 448 tests, 447 passed, one existing skip.
Live checks passed Microsoft Publishers, the selected NVD record, Views
capitalization, Decoder separation and the Zero-Day exploitation column.
Avoided querying the full exploitation union for each last-sighting lookup
by using a small shared citation-qualified sightings view, followed
by affected-view regression checks. This is a query correction, not a full
performance audit. See docs/review/2026-11-19-operator-report-checks.md and
the updated extraction/vulnerability runbooks for behavior and limits.
The first request after the final restart raced database initialization
and received connection refused; the startup log completed normally, then
both original URL checks succeeded. Do not interpret a started launcher as
an already-ready server. Final plain-text replay found method calls ending
in `.read`, which is also a delegated TLD; added a separate plain-call
filter with a regression. Special-use names such as vsphere.local remain
source candidates rather than being called public DNS names. Later affected
checks passed: 51 view/evidence tests, 87 extraction tests with one existing
skip, and 59 tests after the final method-call change. The warm Zero-Day
page still took 8.95 seconds; broader query optimization remains open.
Final context presentation prefers source rows/group labels inside Report
Context instead of making the analyst open a second non-PDF dropdown.
PDF Row Context remains available. Its 20 affected parser/route tests passed.
The app is running on loopback with the final filter loaded; live checks
confirmed method-call rejection, a valid defanged domain, and row context.

### 2026-11-19: Strings, Deobfuscation and Domain Review Proposal

Detailed recommendations and primary sources are in
docs/research/2026-11-19-static-supply-chain-review.md. Prioritize changed
artifacts and transitive dependencies; keep location and decode lineage for
every destination. Redact credentials/query values, keep decoded instructions
passive and report partial/unsupported analysis. Do not automatically visit
discovered hosts. No dependency decision follows merely from a domain
reputation result. A scan with no findings can still have blind spots.

The Phase 2 closeout terms mean: select an older-CVE metadata strategy;
provide resumable visibility into Red Hat/SUSE changed-document backlogs;
decide whether HTMX partial refresh is required for closeout; and review the
incremental value/access of optional GreyNoise/CVEDB/extension sources.
Recommendation remains targeted missing-CVE enrichment and resumable bounded
vendor batches before a blanket historical import. No backfill or new feed
refresh was authorized or run by this clarification.

### 2026-11-19: Explain Skill Overrides and Retain Explicit Retry Controls

The operator asked what local overrides meant. They are text already in
installed cards directing use of a local source profile instead of broader
upstream examples. For instance, the URL profile uses existing scan records
and requires authorization for a new submission. They are not implemented
toolkit features, changes to provider permissions or evidence of uploads.
No installed skill was changed during this pass. Current chat authorization
still governs actions. Microsoft sample analysis may use additional cloud
scanning/detonation, but not every scanned file is necessarily submitted.

Retained explicit Try Headless Browser and Try Alternate HTTP/TLS Client
controls in the Phase 7 requirements after a failed username check. Record
each attempted method, time and outcome; show unavailable methods with their
setup/policy reason. A TCP reachability probe is diagnostic, not proof a
profile exists. Source-specific review and the existing legitimate-platform
policy remain. No new browser/TLS client or challenge bypass was installed.

### 2026-11-18: Follow-up source decisions and changed installed skill profile

On re-reading the installed cards, found 71 CTI cards rather than the earlier
78-card snapshot. Enrichment and pivoting were replaced with local routing;
IP/domain/hash/URL cards carry a Local Source Profile override. The profile
requires existing-record lookups and separate authorization for scans,
samples and publishing. Underlying upstream text still describes broader
defaults. These files were not edited by this project pass. Updated the
review to distinguish upstream examples from effective local restrictions;
the earlier 78-row matrix is a historical inventory, not today's installed
count. Re-inventory before Phase 11 rather than silently wiring stale text.

Specific examples retained: url-investigation's upstream unlisted urlscan
submission, lookup-urlscan's stale/missing-scan fallback, orchestrator extra
provider chaining and knowledge-cell updates, MISP publishing capability,
and cti-setup's different credential store. The earlier Liberty91 upload
card required confirmation and is now absent; it was not a silent upload.
No lookup or setup workflow was invoked. An installed key is not blanket
permission for query expansion or disclosure.

Recorded the operator's decisions in the relevant phases and parking lot:
revisit username tools at Phase 7; automate permitted rendering/backoff and
show actionable challenged states; preserve Principle 8's source distinction.
The operator questioned blanket refusal of automatic fallback, not a need
to mark all blocks as permanent failures. Reviewed per-source rendering can
be automatic. A TLS-client change is not a guaranteed challenge solution.

For Common Crawl, cover useful archive/index/graph families but show transfer,
expanded and temporary storage estimates and free disk before downloads.
Unknown size needs a bounded sample and explicit label, not a guessed number.
No bulk dataset was downloaded. IODA fits IP/ASN context and case timelines;
its widget remains a later candidate, without claiming per-site cause or
DDoS attribution. Parked saved dashboard layouts with source/time/freshness
controls. Added a phase-entry checkpoint to revisit SitDeck candidates for
usefulness, cost, access, overlap, terms and maintenance. The previous 319
catalog-entry review is not 319 independently accepted live integrations.

Actual skill-derived pivot buttons remain Phase 11 candidates. Keep a
deterministic tool boundary, typed values, bounded scope, credential isolation
and tests for instructions in all inputs and tool results. Include ordinary
web injection and SSRF cases too. No claim of complete injection immunity.

### 2026-11-18: Full honeypot paper, 78 skills and OSINT source review

The operator supplied the main Gone in 8 Seconds PDF after ACM access failed.
Read all 15 pages and visually checked the instrumentation diagram and
timing table. The earlier appendix-only review is now completed, though no
experiment or artifact was executed. Added Cowrie/MySQL-style session
logging, resource limits, rotation, distinct provider/session/lifecycle
streams and outcome-aware events to the parked sensor design. Missing
beacons are not proof of no execution; aggregate sequences are not actor
identities. The paper's funded AI keys are not the default for our pilot.

Inventoried 78 installed CTI capability cards and their supporting files.
Mapped every skill to pre-AI templates/logic/manual fields or optional
Phase 11 assistance. Reviewed selected workflow bodies in depth, not every
bundled script or every historical knowledge-cell claim. All 78 bodies match
the existing local MIT Liberty91 pack after newline normalization; ten
descriptions were reworded. Individual skill copies omit pack-root clients
and data referenced by some commands. Installation is not toolkit wiring.
The per-skill matrix and adoption limits are in
docs/research/2026-11-18-cti-skills-integration-review.md.

Used the in-chat browser to expand all 38 SitDeck catalog categories and
read 319 feed entries. Search-readable content and llms.txt show older
counts. Prioritized network context, historical web evidence, company
identifiers and public profile sources; not every upstream endpoint or
license was vetted. No SitDeck account or normalized data was used.

Read WMN's complete README/schema and all three username rulesets as inert
JSON in memory. WMN has 691 entries in the final archived snapshot, Maigret
9,978 public entries and Sherlock 481 targets. These are inventory counts,
not live working-rule counts. Maigret's README, generated statistics and raw
flags disagree in some details. Read MIT licenses for Maigret and Sherlock;
WMN's CC BY-SA 4.0 data/schema stay runtime-only under project policy.
Retain our own async checker, reviewed upstream imports and local overrides.
Record typed failures and positive/negative health controls. Protection tags
explain blocked checks; they do not override the no-bypass rule for
legitimate platforms. No curl_cffi or CLI dependency was added.

Reviewed Common Crawl's index, URL/Parquet and CDXJ guides, archive formats,
web graphs, host index, statistics and terms. Checked the Hugging Face
organization's 12 dataset cards: nine accessible and read, three HTTP 401
(CommonLID, commonlid-cache_commonlid_nano, eot2024_hostlevel_logs). No corpus,
model or graph dump was fetched. Primary next slice is bounded CDXJ and
selected archived response retrieval. Large graph/Parquet/model work remains
later. IODA supplies macro network-disruption context, not website discovery
or proof of DDoS. Documented the public API entry point and originating
methodology, not a validated live connector. Full source/access/terms notes
are in docs/research/2026-11-18-osint-source-expansion.md.

Recorded these candidates in the existing phases and parking lot. Phase 2
and its original-report acceptance work remain open; research did not change
the agreed build order or silently add new modules.

### 2026-11-18: Registry honeytokens and malicious agent repositories

The operator supplied an ACM paper, its local artifact appendix and a
Bitdefender report about agent-targeting repositories. Read both appendix
pages and the authors' project summary. ACM epdf/pdf returned HTTP 403;
neither author's publication page supplied an alternate manuscript. The
main paper remains unread, so this is explicitly a partial paper review.
The local appendix belongs to the same study, not a second independent one.
No archive, notebook, image or payload was fetched or executed. Parked a
small isolated registry honeytoken experiment beside the VPS sensor plans,
with unique decoys and distinct pull, execution and credential-use events.

Read the full Bitdefender article and all 22 repository indicators. Checked
those names against 186 project files, 703 stored GitHub leads, 49,660
exploit links and the empty cache table, using a read-only database
connection. No matches. No explicit hooks were present in the inspected
global/project Claude settings. Plugins, editor configuration, downloads
outside the project and historical sessions were not exhaustively audited.
This is a scoped exposure check, not a machine-clean verdict.

The current session restricts writes and command networking but has broad
read access. .env/data ignore rules do not prevent credential reads. The
transcript hook is not a general secret scanner. Recommended stronger
isolation, separate research credentials, enforced egress and explicit
hook/task/MCP reviews. No global profile, permission list or security
software was changed. Full evidence, limits and future implementation notes
are in docs/research/2026-11-18-honeypots-agent-repository-safety.md; the
manual workflow is docs/runbooks/untrusted-repository-review.md.

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
