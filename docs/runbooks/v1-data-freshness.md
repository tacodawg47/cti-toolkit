# V1 Data Freshness Requirements

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
