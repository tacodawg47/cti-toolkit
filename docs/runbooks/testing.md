# Runbook: Running the tests

Written 2026-10-28. Updated 2026-11-27.

3A.6 focused acceptance, 2026-11-27: expanded cloud/inbox/shared evidence
passed 80 tests in 53.683 seconds, including 46 cloud cases. Final cloud-only
acceptance passed 47 in 50.715 seconds, including the final per-result
metadata.truncated guard. Full compatibility before that narrow follow-up:
888 tests in 366.300 seconds, 887 passed and one existing skip.
Temporary databases and synthetic/refused HTTP only. See
[Indexed Cloud Leads](cloud-exposure.md). Earlier results are historical.

3A.5 acceptance, 2026-11-27: focused inventory/GitHub/inbox/shared evidence
passed 113 tests in 91.091 seconds, including 36 inventory cases. Two final
recovery cases passed in 2.563 seconds. Final inventory has 38 cases.
Full compatibility: 841 tests in 302.124 seconds, 840 passed and one existing skip.
Temporary databases and synthetic/refused HTTP only. See
[Passive Inventory](subdomain-inventory.md). Earlier results are historical.

3A.4 acceptance, 2026-11-27: GitHub/inbox/shared-evidence passed 77 tests in
51.547 seconds, including 43 GitHub cases. Full compatibility ran 803 tests
in 255.655 seconds: 802 passed and one existing skip. Temporary databases
and synthetic/refused HTTP only. See [GitHub Leads](github-exposure.md).
Earlier results below are historical verification, not the current count.

3A.3 acceptance, 2026-11-27: CT/inbox/shared-evidence passed 77 tests in
30.994 seconds, including 43 CT cases. Full compatibility ran 760 tests in
208.414 seconds: 759 passed and one existing skip. Temporary databases and
synthetic/refused HTTP only. See [CT Watches](ct-lookalike-watches.md).
The full-suite result below is retained as prior 3A.2 verification.

The current suite ran 717 tests, with 716 passing and one existing skip,
verified at the 2026-11-27 subphase 3A.2 closeout in 180.083 seconds. Final
breach/shared-evidence acceptance passed 54 tests in 32.105 seconds, including
all 36 breach cases. The intermediate breach suite passed 35 in 28.061 seconds
before the final progress-recovery case. Prior 3A.1 results remain in its
dated closeout.
They use Python's built-in `unittest`,
so no extra dependency is needed, and they never touch the network: importing the
`tests` package replaces the shared HTTP client with one that refuses every
request, so a test that forgets to mock fails loudly instead of spending
quota. Tests that need HTTP install an `httpx.MockTransport` (built into
httpx) that returns canned responses.

## Run all tests

From the project root:

```bash
# Windows
.venv/Scripts/python.exe -m unittest discover -s tests -t . -v

# Linux
.venv/bin/python -m unittest discover -s tests -t . -v
```

`-s tests` says where the test files are, `-t .` sets the project root as the
import base (so `import app...` works), and `-v` lists each test.

## Run one file or one test

```bash
.venv/Scripts/python.exe -m unittest tests.test_indicators -v
.venv/Scripts/python.exe -m unittest tests.test_vendors.RegistryTrancoGateTests -v
```

## What is covered

| File | Covers |
|---|---|
| `tests/test_cloud_exposure.py` | 47 offline Shodan indexed cloud metadata cases: exact domain/label boundaries and query permissions; explicit cloud/hostname inclusion; literal provenance and provider/index/local dates; immutable plans/captures; staged and changed-response restart; atomic inbox rollback and stable retained reviews; exact-selector review links; partial/duplicate/drifting/capped windows; finite byte/request/time/page bounds; durable month/minute/day reservations, cooldowns/pacing, cancellation and per-domain freshness. See [Cloud Leads](cloud-exposure.md). |
| `tests/test_github_exposure.py` | 43 offline query/authority/public-metadata cases: fixed pagination and bounds, immutable plans/captures, source/token/version changes, original staged recovery, atomic inbox rollback, retained reviews, partial/stale health, quotas/cooldowns, cancellation, passive pages and additive migration. See [GitHub Leads](github-exposure.md). |
| `tests/test_ct_watch.py` | 43 provisional CT cases: versioned patterns, strict IDNA/wildcards and exact boundaries; explicit submission permissions/content/version bindings; disabled defaults; parser/request/response/normalized-byte/time bounds; source/selector/schedule/retry/resumption gates; stable inbox events/reviews, immutable captures, staged/atomic crash recovery, cancellation, durable quota/cooldown, per-seed health, passive pages and additive migration. |
| `tests/test_breaches.py` | 36 bounded HIBP cases: explicit submission consent/authority, ten-watch cap, disabled defaults, fixed encoded requests, immutable plans, claim/event deduplication and review preservation, literal dates/citations, sensitive raw omission and field minimization, suppression, atomic rollback, staged changed-response recovery, progress repair, source/selector/schedule/expiry/retry gates, cancellation, durable quota/cooldown, real stream timeout and response/request/byte/elapsed bounds, partial per-address freshness, passive escaped attributed pages and additive migration. See [HIBP Lookups](breach-lookups.md). |
| `tests/test_ransomware.py` | 31 API-only ransomware cases: disabled defaults, fixed destinations and scoped calls, explicit typed watch semantics, claim/capture deduplication and preserved reviews, local catch-up, literal dates/citations, omitted or expired originals, staged changed-response recovery, atomic row failure, revocation at requests/waits/rows/retries/resumption, cancellation, schedule disablement, durable/shared quota and cooldowns, finite requests/bytes/time, passive escaped local pages and additive migration rollback/newer-version refusal. See [Ransomware Victim Claims](ransomware-victims.md). |
| `tests/test_alerts.py` | 16 inbox cases: atomic report/observation matches, canonical typed values, domain/CIDR boundaries, passive/invalid rules, separate assertions, disabled/replayed selectors, paged restart/concurrent catch-up, rollback, review conflicts/history, provenance/citation resolution, expiry preservation, capacity/paging, migration rollback and guarded escaped routes. |
| `tests/test_foundation_acceptance.py` | 7 cross-feature integrations: crash after alert before progress, retained originating run and review on restart, failed/stale freshness rendered on eight consuming pages, offline first start/recovery, 429/cancellation, revocation at ingestion, downtime/daily quotas and missing-original reconciliation. See [Alert Inbox](alert-inbox.md) for commands and live acceptance limits. |
| `tests/test_saved_reports.py` | 42 offline save/archive/bulk cases: atomic saves and migrations, replay/changed input, source/run/date/citation provenance, malformed/bounded input, handling and credential guards, capacity/concurrency, interrupted file writes/rename recovery, corruption/orphans, expiry preserving history, local escaped views, provider selection/gates, app-loop quota ownership, request/byte/time/day budgets, 429 cooldowns, cancellation/revocation/retry, cached originals, Enrich All batching and finite RDAP redirects. See [Saved Reports and Archives](saved-reports-and-archives.md). |
| `tests/test_feed_scheduler.py` | 32 offline schedule/health tests: disabled defaults, durable due work, restart and interrupted pagination, capture replay, source/schedule revocation, shared-loop quotas/client, persisted 429/daily caps, request/byte/time bounds, vendor queue continuation, retained snapshots/checkpoints, constrained redirects, shutdown/drained siblings, archive validation and analyst-page freshness. See [Scheduled Feeds](scheduled-feeds.md). |
| `tests/test_jobs.py` | 24 durable-runner acceptance tests: registration/parameter limits, additive migration rollback/retry and schema guards, actual process-death recovery, independent process exclusion, concurrent enqueues/claims, immutable logical identity, bounded retries/backoff, queued/running/interrupted cancellation, source revocation on units/retries/restart, separate retrieval/coverage checkpoints, evidence replay with originating run identity, progress bounds and startup WAL contention handling. Commands and handler limits: [Durable Jobs](durable-jobs.md). |
| `tests/test_shared_evidence.py` | 18 shared-corpus acceptance tests: additive/repeated/concurrent migrations, atomic rollback/retry and newer-version refusal, unchanged legacy rows/views, explicit source eligibility, dated license findings, distinct source times, idempotent captures and citation resolution, scoped lineage, FK integrity, bounded metadata/reads, job identifiers and six offline startup/page checks. Commands and future integration contracts: [Shared Evidence](shared-evidence.md). |
| `tests/test_indicators.py` | `refang` (defanged input) and `detect_type` (hash/ip/url/domain/unknown) |
| `tests/test_virustotal.py` | VT URL id, path building, and the malicious/suspicious/clean/unknown heuristic |
| `tests/test_vendors.py` | every other vendor's `_summarise`; `normalise` and `canonical` (ports, punycode, IPv6); `fetch_json` branches (404, non-JSON, wrong shape, oversized body, total timeout, non-HTTPS, redirects); an end-to-end AbuseIPDB and URLhaus lookup with a mock transport and a temp database (cache round trip); the rate-limiter loop with a fake clock; the registry's crash handling, aggregate line, and the private-IP, Tranco and hashlookup gates with the "query anyway" override; the Tranco loader; config host validation; allowed Host headers; health-page path display |
| `tests/test_vulnintel.py` | Phase 2 vulnerability intelligence: the priority matrix; KEV and EPSS parsers (including the bounded gunzip); NVD and GitHub summarisers; reference grouping and version ranges; the store with a temp database (KEV upsert, EPSS previous-score tracking and risers, feed status, CVE save, watchlist matching, aliases); the report service with mocked NVD and GitHub; a mocked end-to-end feed refresh; every route including form posts and the cross-site check |
| `tests/test_msrc_cvrf.py` | Microsoft monthly fallback, independent source failures, source precedence, scoped fixes and workarounds, changed-month caching, source corrections, and monthly withdrawals |
| `tests/test_extract.py` | Phase 2 extraction: the CVE indicator type; document-wide refang; every pattern (IPv4 validation, IPv6 candidates, filename-vs-domain, URL trimming, hash kinds, email, CVE); de-duplication, counts and the defanged flag; bounded report context, preserved negative claims, first-mention ordering and escaped instruction-like text; the Tranco tag; HTML to text; the URL fetcher's refusals and mocked responses; a hand-built one-page PDF through `pdf_text` and the upload route, plus the pypdf error paths; and the `/extract` route through FastAPI's test client |
| `tests/test_decode_pdf.py` | Local decoder modes, malformed inputs, output limits, escaped rendering, and wrapped PDF hashes with context |
| `tests/test_software_references.py` | Explicit extension IDs/URLs, namespace and hash/email separation, hidden hrefs, fake stores, code exclusion, limits, passive copy controls and isolated manual CVE List refresh |
| `tests/test_cvedb.py` | Keyless isolated requests, snapshot reuse/expiry, failed-attempt retention, concurrent duplicate requests, hostile/invalid values, aligned comparisons, passive GET, same-site POST and unchanged triage |
| `tests/test_chrome_exploitation.py` | Explicit CVE-scoped statements, excluded prose, revision dates and continuity, corrections/reassertions, source failures, citations and shared priority/actions/views/review/counts |
| `tests/test_unfixed.py` | Explicit product/group identity, repeated CVE entries, contradictory status, ambiguous scope, vendor/OT integration, mixed fixed/unfixed actions, corrections, legacy guards and bounded per-advisory reloads |
| `tests/test_review_digest.py` | Bounded recent CVE grouping, history preservation, no acknowledgement on GET, CVE-scoped review actions, cross-site refusal and dashboard removal of the global backlog counter |
| `tests/test_attack_layouts.py` | Synthetic HTML lists/grids/headings/pre/br, Markdown headings, content-first column roles, shared procedures, tactic carry-forward/mismatch, names-only guards, labelled prose, aligned/ambiguous PDF paragraphs and page boundaries, structure limits and passive resource handling |
| `tests/test_wheel_audit.py` | Inert wheels: startup hooks, digest/RECORD failures, weak hashes, archive limits/paths, source comparison across packages, ASCII/UTF-16/constant/encoded destinations, decoded source lineage, redaction, baseline diffs and incomplete-coverage flags; no payload execution or network |
| `tests/test_vendor_notices.py` | Six source formats, shared vendor evidence, Chrome cross-month IDs, Fortinet unchanged revisions, durable queues across moving windows/connections, no-index continuation, failed-item isolation/retry, newer revisions, rate/body budgets and route scope/cross-site guards |
| `tests/test_vulnerability_evidence.py` | Cross-feature exploitation and OT remediation, report linking/unlinking, independent sources, cached SSVC, review events, paired product fallbacks, typed dates and corrected early-exploitation inference |
| `tests/test_report_quality.py` | Streamed declarative report data, richer-content guard, domain/reference filtering, code exclusion, hash/IP context, ATLAS separation, copy/input/decoder controls, Microsoft publisher filters, NVD metadata loading/version fallback/keyless requests, uncited exploitation claims and wrong-CVE sighting responses |
| `tests/test_metadata_coverage.py` | Read-only metadata/claim counts; NVD partial-window replay, completed checkpoints, old cursor retention, dense-window splitting, legacy partial status, premature empty pages and malformed/mismatched responses |
| `tests/test_nvd_backfill.py` | Gap priority, scope exclusions, bounded requests, restart/resume, retrieved-but-incomplete and missing records, failed retry, quota/auth pause, CVE identity, deadline and concurrent-run guards, reconciliation after other updates, and POST validation |
| `tests/test_nvd_recovery.py` | Isolated NVD-only routes, read-only previews, key omission, actual page offsets, count/membership consistency, proactive dense-window split, body/time caps, preserved checkpoints, interrupted writes and overlapping-run rejection |

The separate `tests/phase2_coverage_probe.py` audit helper is outside
`test*.py` discovery. Run it with
`.venv/Scripts/python.exe -B -m tests.phase2_coverage_probe` to print
synthetic cross-feature observations in a temporary database. Its findings
are documented in `docs/review/2026-11-17-phase2-coverage-audit.md`.
The new regression file verifies the corrected F1-F3 contracts. The
probe now recovers its HTML table, list and prose procedures. The original
publisher-page acceptance set covered 12 pages and one PDF; the separate
MuddyWater check recovered 105 of 106 hashes. Synthetic tests do not prove
all publisher layouts. The accepted implementation closeout and remaining
limits are in `docs/review/2026-11-25-phase2-closeout.md`.

## How a mocked HTTP test works

```python
base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(
    lambda req: httpx.Response(200, json={"query_status": "no_results"}))))
res = await urlhaus.lookup("url", "http://x.com/")
```

`set_client` swaps the shared client for one whose transport is your lambda,
so the vendor code runs unchanged against the response you wrote. Call
`await base.aclose()` in `asyncTearDown` so the next test starts clean.
Tests that touch the cache or the rate limiter point `settings.data_dir` at a
temporary directory and call `db.init_db()` in `setUp`.

## What is not covered

The real vendor APIs. The offline suite proves our handling of each response
shape, not that the vendors still send those shapes. A short live smoke test
(one indicator per type in the browser) is the check for that, and spends a
little quota; do it after a change to a client, not on every run.
