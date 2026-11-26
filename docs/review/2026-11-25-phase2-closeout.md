# Phase 2 First-Delivery Closeout

Date: 2026-11-25. This records the accepted implementation scope, not full
historical source coverage or readiness for unattended daily use. It
supersedes open-scope wording in earlier audits without changing their
historical findings. The operator authorized completion of the remaining
Phase 2 steps and answered the three product decisions below.

## Accepted Scope

| Area | Delivered Behavior and Evidence |
|---|---|
| Vulnerability views | All 14 numbered views, All Vulnerabilities, filtering, sorting, paging and pinning. Microsoft Publisher integration and source-specific vendor updates are built. |
| Shared triage | Positive exploitation evidence, typed dates, scoring fallback, product matching, independent action badges and source citations feed the shared tables and CVE details. F1-F3 from the coverage audit are fixed. |
| Exploited and Unfixed | Existing Red Hat VEX plus explicit target-scoped statements from supported vendor and OT CSAF advisories. Missing patch information stays unknown. A fix for another target remains visible. |
| Legacy advisory scope | Explicit one-document reload from a stored, allowlisted publisher path. Legacy names alone cannot establish product-ID scope. Mocked requests cover validation and failure retention. |
| Since Last Review | Up to five recent CVEs grouped over seven days. Full review/history stays available. CVE-filtered acknowledgements are scoped to that CVE. No automatic backlog reset. |
| Source inspection | Stored Source Data exposes retained normalized source fields. It is explicitly not a full original-response archive. |
| Supply Chain | Accepted first slice for npm and GitHub Actions. Broader ecosystems and advisory intake remain the documented later expansion. |
| Reports and local helpers | Text, URL and PDF extraction; report context; rules/queries, references and images separated; explicit ATT&CK/ATLAS references; local decoder; extension references and wrapped hashes. Inferred techniques remain excluded. |
| Source recovery | Bounded NVD recovery and metadata queue; independent CVE List refresh; durable Red Hat/SUSE continuation; read-only coverage audit. No bulk refresh is tied to a commit. |
| Optional comparison | Manual CVEDB comparison is dated and isolated from triage. GreyNoise per-CVE and partial-page loading are explicitly deferred. |

No-fix scope is resolved from raw CSAF identities before normalization. It
requires fully resolvable product/group IDs and a named affected target.
Contradictory fixed, unaffected and investigation states are excluded.
Repeated CVE entries are merged before scope evaluation; equal display names
do not merge different product IDs. Workarounds appear only for overlapping
targets. An ambiguous vendor-fix scope conservatively prevents a no-fix
finding. This does not validate every rule in the CSAF standard.

The relevant source specification is
[OASIS CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html),
particularly remediation categories, product/group scope and per-product
fix consistency. The project implementation is deterministic Python and
adds no dependency.

## Operator Decisions

- Change the Since Last Review table. Use the compact recent CVE grouping;
  preserve the full queue and explicit review controls. Further material-change
  suppression and a watchlist-only digest remain possible improvements.
- Keep CISA's existing SSVC decision points. Park the full organization-specific
  outcome calculator. Product Match does not establish mission prevalence.
- Expose retained source data now. Archive complete original responses with
  the Phase 5 shared evidence store instead of creating a separate archive here.

## Later Dependencies and Known Limits

| Item | Disposition |
|---|---|
| Scheduled updates, recovery and alerting | Next Phase 5 foundation: scheduler, job runner, alert inbox and shared corpus. Source freshness is required before operational v1 acceptance. |
| Saved report extraction and Enrich All | Use that shared corpus and durable job runner. They are not implemented by the current ephemeral extraction page. |
| Full source response archives | Same foundation, with provenance, bounds, retention and redaction. Current normalized facts are not a substitute. |
| Historical CVE/vendor depth | Bounded manual recovery exists. Complete historical loads and watchlist-specific backfill remain separate work, not a reason to hold feature delivery during the build. |
| Supply Chain expansion | Post-v1 additional ecosystems, broader advisory intake including no-CVE advisories, package details and watchlist/lockfile workflows. Existing roadmap scope is retained. |
| More source collection | Social/news reporting follows Phase 4/5; collectors follow the foundation. Direct KEV catalog review and richer source-overlap analysis remain parked. |
| UI and performance | HTMX partial loads, profiling, larger dashboard redesign and moving feed administration under Health remain parked. Existing full-page controls are supported. |
| GreyNoise per-CVE | Honeypot work or the final backlog, even if a key is available. Phase 1 IP lookup is separate. |
| Full SSVC outcome | Parked by the operator; existing source decision points remain visible. |
| Export and case integration | Existing later phases. No case or full export implementation is implied here. |
| Report layout coverage | The original publisher acceptance set covered 12 pages and one PDF. The separate MuddyWater check recovered 105 of 106 hashes; one visually out-of-order cross-page row remains unsupported. Other layouts, OCR and richer deterministic extraction remain follow-ups. |
| Semantic TTP extraction | Optional Phase 11 with evidence and analyst review. Current output lists explicit IDs only. |

## Validation

The final offline suite completed 511 tests: 510 passed, one existing skip,
zero failures or errors. Fourteen new tests cover no-fix parsing/integration,
legacy reloads and grouped review behavior. The mixed-target Red Hat test
now expects Patch to remain visible when patch evidence exists for other
targets. Its old global suppression was the behavior being corrected.

The separate temporary-database probe confirmed matching OT table/detail
actions and scores, watchlist/review integration, retained legacy report
behavior, publication-date exclusion from first exploitation/zero-day
inference, and explicit-ID procedure layouts. Its uncited sighting does not
establish Known Exploited membership; the fixture's separate Exploit-DB entry
still supports Hunt. No manual report intake was restored.

The verified local app was restarted with the new code. All 26 checked GET
pages returned HTTP 200: dashboard, view index, 15 vulnerability views,
Vendor Updates, Supply Chain, Feeds, full and CVE-filtered review, metadata
audit, an already loaded CVE, Extract and Decoder. The dashboard contained
the bounded digest without the old counter, and the CVE page rendered
Stored Source Data. Read-only SQLite comparisons before and after showed
unchanged feed status and unchanged total/reviewed event counts. No provider
refresh or review POST was submitted. Startup completed on 127.0.0.1:8000.

The local result is `data/phase2-closeout-acceptance.json`; stdout/stderr are
`data/phase2-closeout.stdout.log` and `.stderr.log`. These stay git-ignored.
One sequential pass took 16.98 seconds for the dashboard, 7.12 for Zero-Days,
and 0.30 for the loaded CVE detail. These are observations, not benchmarks.
The dashboard remains slow enough to warrant the already parked profiling
work. The grouped review UI is a volume/usability change, not a claim that
all dashboard SQL has been optimized.

Repeatable steps: [Phase 2 Closeout Checks](../runbooks/phase2-closeout.md).

Earlier evidence:
[Coverage Audit](2026-11-17-phase2-coverage-audit.md),
[Publisher Acceptance](2026-11-19-publisher-acceptance.md),
[Report Extensions and PDF](2026-11-24-report-extensions-and-pdf.md),
[Optional Source Scope](2026-11-24-phase2-source-scope.md),
[Chrome Exploitation](2026-11-24-chrome-exploitation.md).

No dependency installation, git operation, commit or push was performed in
this closeout pass. Commit and push approval remain separate.

## Session Boundary

Recorded 2026-11-26: **Phase 2 accepted first-delivery implementation
complete.** The next implementation subphase is 5F.1, Shared Evidence Model
and Source Registry. The current checkpoint state and ready-to-paste
next-chat prompt are in [Current Handoff](../handoff.md).
The Phase 2 Git checkpoint still needs inspection, commit and push approvals.
No foundation implementation began in this session.
