# NVD Recent-Changes Recovery Acceptance

Date: 2026-11-24 in the operator timezone. Phase 2 remains open.

## What Was Recovered

The old NVD status recorded 4,000 of 6,472 rows before a timeout but had
error=NULL and no coverage checkpoint. Recovered from its saved start,
then caught up in independent NVD-only windows. The original failed result
membership is not an immutable snapshot and is not claimed restored exactly.

All requests used the fixed public NVD API, without a key. No local report,
private seed, file or watchlist profile was uploaded. No other feed refreshed.
Provider JSON was parsed as data. No code or command was executed from it.

| Window, UTC | Requests | Rows Processed | Charged Body Bytes |
|---|---:|---:|---:|
| 2026-11-11 00:47 to 2026-11-18 00:47 | 4 | 7,058 | 30,390,985 |
| 2026-11-17 23:47 to 2026-11-24 23:47 | 5 | 8,003 | 33,785,400 |
| 2026-11-24 22:47 to 2026-11-25 00:09:21 | 1 | 98 | 334,334 |
| Total | 10 | 15,159 | 64,510,719 |

About 61.5 MiB of charged decoded response bodies, not measured wire traffic.
Windows deliberately overlap by one hour. There were 14,956 unique touched
CVEs and 8,976 new NVD rows. NVD row count rose from 22,752 to 31,728.
The unique touched cohort has zero invalid modification dates and zero
dates outside the recovered range. Counts include rejected records here;
the catalog coverage audit below excludes them.

Recovery target was fixed at 2026-11-25 00:04:21 UTC. Completed coverage
is 2026-11-25 00:09:21 UTC, or 2026-11-24 19:09:21 Eastern. Pending state
is empty and the NVD error is cleared. All three result pages returned
HTTP 200 after redirects. Last-run counts describe that window, not the
total NVD database size. No automatic scheduling was added.

## Implementation Checks

- NVD-only POST, mode validation and cross-site protection. GET preview is
  read-only and does not start imports or create a pending window.
- Public mode omits the configured key and uses the public rate limiter.
- Dedicated run cap: six requests, 64 MiB per response, 192 MiB of charged
  bodies and 180 seconds of network/rate-wait time. Local work is additional.
- Advance offsets by actual returned rows. Reject inconsistent counts,
  duplicate membership and wrong response offsets before completion.
- Retain unfinished coverage. Narrow dense/budget-limited windows without
  advancing the completed checkpoint past unprocessed records.
- Keep ordinary source failures pending; label interruptions accurately.
  The single-worker lock rejects overlapping imports.

Full offline suite: 475 tests, 474 passed and one existing skip. Ten new
recovery tests supplement existing metadata and NVD page-walk tests.
The live runs did not trigger resource splits or failures; those branches
are covered offline. No dependency or system security setting was changed.

## Metadata Coverage and Limits

| Scope | Active CVEs | No NVD Row | No CVSS | No CWE ID | No Vendor/Product Pair |
|---|---:|---:|---:|---:|---:|
| Catalog before | 407,115 | 385,251 | 165,142 | 184,993 | 160,979 |
| Catalog after | 412,704 | 381,923 | 165,049 | 185,074 | 166,244 |
| Known Exploited before | 5,950 | 5,700 | 1,619 | 1,865 | 1 |
| Known Exploited after | 5,950 | 5,659 | 1,619 | 1,865 | 1 |

The larger catalog includes new IDs. These totals are not a fixed-cohort
improvement measure. Among touched active records, 5,955 have no local
CNA record; 5,630 of those also have no NVD product data. CVE List still
shows synchronization through 2026-11-15 1900Z. Its independent incremental
catch-up is the next metadata priority. Do not infer products from prose
or assume that NVD or upstream CNA will have every missing field.

The 85 uncited community claims, six without other exploitation evidence,
and zero saved manual reports are unchanged. The separate targeted repair
queue and historical scope remain open. No review acknowledgments were
reset. No full-history import, git operation, commit or push was performed.

Repeat commands and budget details: [NVD recovery runbook](../runbooks/nvd-recovery.md).
