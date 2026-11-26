# Runbook: Running the tests

Written 2026-10-28. Updated 2026-11-25.

The current suite ran 511 tests, with 510 passing and one skipped, verified
at the 2026-11-25 closeout. They use Python's built-in `unittest`, so no
extra dependency is needed, and they never touch the network: importing the
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
