# V1 Data Freshness Requirements


Update 2026-11-27, 3A.5: [Passive Subdomain Inventory](subdomain-inventory.md)
adds daily per-domain two-day staleness. Original oldest-page age survives
restart. Partial, duplicate, out-of-order or nonterminated bounded windows retain
evidence without renewing success. All 36 schedules default off. Actual CTLogs
access and measured live freshness/recovery remain separate.

Update 2026-11-27: [GitHub Public-Code Leads](github-exposure.md) adds a
disabled daily consumer with per-selector two-day staleness. A bounded
consistent query window uses its oldest original page capture for age.
Partial, drifting, short or truncated windows retain leads without renewing
success. All 35 composed schedules default off. Reviewed public-only access,
exact disclosures and measured live freshness/recovery remain separately
approved operational acceptance; none occurred in this subphase.

Update 2026-11-27: [CT Lookalike Watches](ct-lookalike-watches.md) adds a
provisional daily schedule with a two-day stale threshold and per-seed
original collection age. All 34 schedules default off. Success describes
bounded unexpired query snapshots only, not provider completeness, continuity
or registration/DNS activity. Current service review and measured live
acceptance remain required; no live acceptance occurred.

Update 2026-11-27: [HIBP Watched Email Lookups](breach-lookups.md) adds one
disabled daily schedule with a two-day stale threshold. Each address shows
its own last attempt, last good original capture and failure/incomplete
state. The composed catalog has 33 disabled schedules. Source/selector
approval and measured live acceptance remain required before daily use.

Update 2026-11-26: [Ransomware Victim Claims](ransomware-victims.md) adds an
hourly recent-100 snapshot proposal with a six-hour stale threshold. Scoped
Current status cannot establish continuous monitoring or historical coverage.
All 32 composed schedules remain disabled. Approve and measure source-specific
live freshness/recovery before daily use; no live acceptance occurred here.

Update 2026-11-26: 5F.5 connects local alerts to evidence and displays the
shared freshness panel in the inbox. Its cross-feature mock acceptance and
the earlier failure-injection suites establish application invariants. They
do not establish live operational acceptance. Named source reviews, approved
live migration/restart, bounded refresh/recovery measurements and deployment
checks are still required before daily v1 use. See [Alert Inbox](alert-inbox.md).

Update 2026-11-26: Subphase 5F.3 passed offline schedule/health/recovery and
compatibility acceptance. See [Closeout](../review/2026-11-26-5f3-closeout.md)
and [Scheduled Feeds](scheduled-feeds.md). All schedules and the worker
remain off. No live migration, enabling or restart occurred. These results
do not establish v1 operational acceptance; approved live configuration,
source-specific review and the later foundation acceptance remain required.

Written 2026-11-24. This records the operator's requirement, not a delivered
scheduler. Bulk catch-up may be postponed during the build. Once v1 is used
for actual investigations, freshness is important and is not optional.

The Phase 5 foundation is next in the existing build order after Phase 2.
It must make routine refresh reliable before v1 operational acceptance.
Do not attach network jobs to commits. A commit saves code, not source state.

## Operational Acceptance

- Configure a cadence and stale threshold for each source, based on the
  publisher's cadence, API allowance and analyst need. There is no single
  valid threshold for a daily score, hourly feed and historical archive.
- Track last attempt, last successful fetch, coverage checkpoint and error
  separately. Preserve the source's own update/publication dates when known.
  Retrieval time does not establish when the source published a change.
- Show stale, failed, never loaded and incomplete coverage states. Keep
  previous successful data visible with its age. A failed attempt or an
  empty/malformed response must not silently renew that successful date.
- Schedule only configured, authorized sources. Use the job runner, source
  quotas, bounded requests, retry/backoff and source-specific checkpoints.
  Manual refresh stays available; ordinary page loads do not refresh every
  source. UI performance work must not remove freshness warnings.
- On startup after downtime, detect gaps and resume supported incremental
  windows without skipping unfinished work. If a large full reload is
  needed, show its expected size and require the existing explicit action.
- Surface refresh failures and overdue sources in Health or the alert inbox.
  Do not leave the analyst relying on an old green success indication.

## Tests Before Operational Use

Use mocked providers and temporary databases for failure injection. Test a
successful refresh, a stale snapshot, offline startup, failed refresh after
success, 429/backoff, interrupted pagination and source recovery. Verify
that only success advances the appropriate checkpoint and that stale/error
states appear where the analyst consumes the data. An upstream publication
date, a successful request and complete historical coverage are different facts.

Record real source sizes and elapsed times for a bounded initial refresh in
the local acceptance notes when that work is resumed. Do not make a bulk
history import the substitute for these scheduler and recovery tests.

Current manual procedures: [NVD Recovery](nvd-recovery.md),
[NVD Metadata Backfill](nvd-backfill.md),
[CVE Program Refresh](manual-refresh-and-extension-references.md) and
[CVEDB Comparison](cvedb-comparison.md).
