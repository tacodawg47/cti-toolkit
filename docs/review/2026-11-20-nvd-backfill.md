# Targeted NVD Backfill Acceptance

Date: 2026-11-20, operator timezone. Phase 2 remains open.

## Execution

Prepared implementation and offline regressions first. Announced two live
five-record batches and their limits before running them through the local
POST endpoint. Ten public/keyless NVD requests total, at most 50 MiB of
accepted response bodies across both batches. No configured key, local
report, watchlist profile or private file was uploaded. Source metadata
remained passive. No code, page script or command was executed from it.

| Batch | CVE | Result |
|---|---|---|
| 1 | CVE-2015-0279 | Retrieved; Red Hat RichFaces, CVSS 2.0 and CWE-94 |
| 1 | CVE-2016-200017 | NVD returned no record for this exact ID |
| 1 | CVE-2020-24186 | Retrieved |
| 1 | CVE-2020-35948 | Retrieved |
| 1 | CVE-2020-35949 | Retrieved |
| 2 | CVE-2020-6167 | Retrieved |
| 2 | CVE-2020-8417 | Retrieved |
| 2 | CVE-2021-20083 | Retrieved |
| 2 | CVE-2021-24217 | Retrieved |
| 2 | CVE-1999-0192 | Retrieved; CVSS 2.0 and products available, CWE still unknown |

The not-found ID is present in the locally stored VulnCheck assertion.
Do not guess a replacement ID, silently merge it or call the assertion
false because NVD returned no record. Original-source validation remains
a follow-up. No extra VulnCheck request or credential use was performed.

## Coverage Before and After

Population: 5,950 non-rejected known-exploited CVEs.

| Missing Locally | Before | After |
|---|---:|---:|
| NVD record | 5,709 | 5,700 |
| CVSS across local sources | 1,623 | 1,619 |
| CWE ID | 1,872 | 1,865 |
| Structured vendor/product pair | 9 | 1 |

Full catalog count stays 407,115. Its remaining gaps are 385,251 NVD
records, 165,142 scores, 184,993 CWE IDs and 160,979 product pairs.
The 85 uncited community exploitation claims and six without another
positive source are unchanged. No review acknowledgments were reset.

Queue checkpoint: 5,699 pending, nine retrieved, one not found. Each
attempted ID has exactly one attempt. Retrieved does not imply every field
is populated; CVE-1999-0192 demonstrates the limit. Remaining-gap counts
and pending lookups need not match. Successful unknown fields are not
automatically fetched again merely to chase the counter.

## Verification and Limits

Final full offline suite: 465 tests, 464 passed and one existing skip.
Tests cover scope, limits, resume, unknown fields, missing records, retained
data, source identity, quota/auth pause, concurrency, interrupted saves and
route guards. A storage exception or cancellation cannot label an unfinished
run complete, and the run lock is released after an interruption.

Both live POSTs redirected to HTTP 200 result pages. Read-only SQLite
checks confirmed saved metadata, queue state and exactly ten attempts.
The independent read-only coverage audit produced the before/after totals.
Final live checks after another verified restart confirmed the queue still
has nine retrieved, one not found and 5,699 pending records. The RichFaces
detail page renders its backfilled 6.8 score, CWE-94 and product. The
unresolved record and Feeds navigation remain visible. These checks made
no additional NVD requests.
Repeat commands and budget definitions are in
[the backfill runbook](../runbooks/nvd-backfill.md).

The separate incomplete recent-NVD window was not retried. Its warning
remains visible. No full-history download, scheduler, new dependency,
git operation, commit or push was performed. Watchlist-specific scope,
larger authorized batches or Phase 5 scheduled continuation, and the full
historical strategy remain separate follow-ups.
