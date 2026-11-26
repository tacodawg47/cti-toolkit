# Local Exploitation Leads and Metadata Coverage

Date: 2026-11-20. Read-only snapshot of the local database.

## Exploitation Leads

85 CVEs have an uncited source assertion: 74 labelled The Shadowserver
and 11 Telegram. These are not 85 confirmed false reports. A source name
without a report URL cannot be checked directly. Six CVEs have no other
exploitation evidence; the other 79 have a separate positive source.
The stored rolling sightings cover 2026-11-14 through 2026-11-16, not a
fresh Internet-wide count. Per-CVE positive lookup storage contains no rows.

A previous day-level count returned 84 because one CVE had both an uncited
assertion and a cited sighting. The audit now counts uncited source entries
as well, avoiding that undercount. Figures refer to exploitation leads,
not every GitHub claimed-PoC lead or unverified infrastructure entry.

The source-qualified evidence gate already prevents uncited community
claims from establishing Known Exploited, zero-day leads, priority or Hunt.
The API response must match the requested CVE. Raw labels remain leads;
they are not silently deleted. A URL supplies traceability, not proof of
truth or independent corroboration. Do not call these independent sources
without tracing their reporting origins.

## Missing Local Metadata

| Scope | CVEs | No NVD Row | No CVSS | No CWE ID | No Structured Vendor/Product Pair |
|---|---:|---:|---:|---:|---:|
| Local catalog | 407,115 | 385,260 | 165,146 | 185,000 | 160,987 |
| Known-exploited source records | 5,950 | 5,709 | 1,623 | 1,872 | 9 |

Rejected CVEs are excluded. Field counts consider locally stored fallback
scores and products. They do not establish which unqueried upstream records
have those fields populated. Counts overlap; they must not be added.

CVE-2018-13257 was last modified in NVD on 2026-06-17. The recent feed
window was in November. The full CVE List load does not load NVD's separate
database. A local-first detail page can therefore display its CNA
description without an NVD row. The selected-CVE load fixed the example;
it did not repair the entire catalog or eliminate future missing data.

The last recorded NVD refresh downloaded 4,000 of 6,472 records and timed
out, but stored error=NULL. Old code treated the partial run as success and
could advance the next window past unfinished data. This was a correctness
bug, separate from the intentionally absent historical import.

## Changes

- NVD now keeps a pending window and advances its completed checkpoint only
  after a full walk. Partial windows replay from page zero. Page caps split
  time windows; they do not skip remaining records. Old partial version
  strings recover their original start. Pending state is local sync data.
- Legacy partial NVD status is visibly incomplete on Feeds.
- The coverage audit is stdlib-only, SQLite read-only and makes no requests.
- Removed command-pattern TTP inference. Only explicit ATT&CK and ATLAS IDs
  remain. Commands/rules are still readable artifacts. AI-assisted inferred
  mappings are deferred to Phase 11 and will still need validation.
- Removed manual report intake, listing, navigation, write helpers and
  link-editing routes. Preserved the table and read-only legacy evidence
  compatibility. There were zero saved manual reports in this snapshot.

No bulk NVD repair, dependency installation, git operation, commit or push
was performed. Historical backfill and Phase 2 closeout remain open.

## Repeat

See the coverage audit and NVD retry commands in
[the vulnerability runbook](../runbooks/vulnerability-intelligence.md).
Permanent tests use synthetic data and mocked requests.
Final full suite: 453 tests, 452 passed and one existing skip.
Live loopback checks confirmed the retired listing returns 404, commands
produce no inferred TTP, navigation is removed and NVD's incomplete warning
is visible. No live bulk retry was run.
