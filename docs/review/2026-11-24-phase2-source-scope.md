# Phase 2 Source and Loading Scope

Date: 2026-11-24. Resolves the three remaining scope questions from the
coverage audit. It does not claim every historical source row is loaded or
that operational scheduling already exists. No git operation was performed.

## Freshness Clarification

The operator clarified the previous decision: optional freshness applies
only during the build. Once v1 is used for real work, current data, visible
failures and reliable recovery are important. Updated the roadmap, paired
agent status files and runbooks. The Phase 5 foundation must deliver source
schedules and freshness/recovery acceptance before daily-use v1 readiness.
See `docs/runbooks/v1-data-freshness.md`. No refresh-on-commit mechanism.

## Partial-Page Loading

Disposition: explicitly defer HTMX partial loads to the already parked
post-v1 performance pass. Ordinary sort, filter and pagination URLs remain
the supported UI. The existing SQL catalog paging and local-first detail
behavior remain useful. No HTMX runtime was installed or vendored, and no
replacement browser navigation framework was introduced.

When revisited, profile page/database work first. Fragment replacement alone
does not make expensive queries cheaper. Review the exact HTMX release and
license, pin its digest and scan the selected artifact before execution.
Acceptance must cover URL/history behavior, Back/Forward, focus, concurrent
requests, stale responses, error fallback and full-page operation without JS.
This is an explicit deferral, not a completed partial-load implementation.

## GreyNoise Per-CVE

Superseded by the operator later on 2026-11-24: keep this adapter parked until
the honeypot stage or the very end. Suitable access alone does not reopen it.
The access review below remains reference material, not an immediate task.

Disposition: defer the adapter until useful authorized access is confirmed.
The current primary reference documents GET `/v1/cve/{cve_id}`, with fields
dependent on entitlements. The plans page describes community access for
basic IP lookups and richer CVE intelligence through its product modules.
We did not inspect credentials, attempt an authenticated request, purchase
access or assume an existing IP entitlement covers CVEs.

The initially checked older-looking reference URL
`https://docs.greynoise.io/reference/v3getvulndetails` was inaccessible. The
current `getcve` reference and plans FAQ were readable and reviewed. The
published API operation and plans are enough to avoid promising a free CVE
integration; they do not prove which fields any particular account receives.
Existing Phase 1 community IP enrichment is unchanged.

Sources: [CVE operation](https://docs.greynoise.io/reference/getcve) and
[plans and access FAQ](https://www.greynoise.io/plans).

## CVEDB

Disposition: implemented an optional keyless comparison for non-commercial
local use. Primary FAQ states daily updates, no Shodan account/key requirement,
and enterprise licensing for commercial use. The homepage was read, including
usage examples and restrictions. Its interactive docs route had no readable
body in the web tool; the published OpenAPI schema supplied operation/field
definitions instead. No runtime provider lookup was used as a test fixture.

Sources: [CVEDB usage FAQ](https://cvedb.shodan.io/) and
[OpenAPI schema](https://cvedb.shodan.io/openapi.json).

An explicit same-site CVE-page POST sends the validated CVE ID to a fixed
HTTPS endpoint. It reuses the shared bounded JSON client without credentials
or redirects, with a ten/minute local courtesy limiter. It does not register
as a bulk feed, schedule requests or fetch when its comparison card opens.
The record must match the requested CVE; malformed values are discarded.
UI text and ransomware source strings are escaped. No links returned in
provider content are contacted automatically.

The existing ignored SQLite cache stores normalized snapshots and attempt
status for 30 days. Freshness is 24 hours; a checkbox requests an earlier
refresh. Error/404/429 responses preserve a prior successful snapshot and
timestamp, record the attempt separately and show failure context. An older
saved result remains visibly stale. Startup purges expired retained entries.
This cache is not a durable provenance archive. No upstream data or raw JSON
is shipped in the repository. Recheck terms before public/commercial use.

Comparison rules:

- Prefer valid CVSS 4, then 3, then 2 from the provider. Compare exact known
  versions only. A major-only 3 value does not establish 3.0 versus 3.1.
- Keep EPSS beside the local score date. The reviewed CVEDB schema supplies
  no EPSS score date, so a numeric difference is not a same-day conflict.
- Treat the exploitation flag as an aggregate source flag, with unspecified
  coverage. It is not a new independently corroborating exploitation vote.
  Not Flagged does not establish absence of exploitation.
- Do not change local products, priority, exploitation status, action badges,
  view membership or review events from these comparison fields.

This is a supplemental comparison, not a second authoritative source of
truth. Existing references remain last on the CVE page.

## Verification and Handoff

Six new synthetic tests cover request isolation/cache reuse, stale/forced
refresh, retained successes after failure/404/429/mismatched identity,
concurrent duplicate calls, numeric/identity/version guards, comparison
semantics, escaped passive GET, cross-site POST refusal and unchanged triage.
Full offline suite: 489 tests, 488 passed and one existing skip. No provider
query, dependency installation, credential inspection, commit or push was performed.

Restarted the verified project listener with a hidden launcher. Its startup
completed on 127.0.0.1:8000. The already loaded CVE-2018-13257 page returned
200 with the comparison card and POST control, without fetching CVEDB.
A separate GET-only walkthrough returned 200 for 25 local pages: the eight
module entry points, all 15 catalog/named-view pages, Report Extraction and
Decoder Tool. Feed status was unchanged before/after. The ignored local
`data/phase2-scope-acceptance.json` records paths, status and elapsed times.
This is route/render acceptance, not proof of all historical data or live
CVEDB availability. No comparison fetch or source refresh was invoked.
The slowest observed GETs were Dashboard 16.31 seconds, Zero-Days 7.78 and
AI and ML Stack 6.05. This single sequential pass is not a controlled
benchmark or a diagnosis. Keep those observations with the existing
performance follow-up; HTTP success must not be reported as fast rendering.

The three scope items are resolved. Phase 2 still carries its documented
coverage limits and the 105/106 MuddyWater PDF result. Next feature work is
the existing roadmap item for explicit Chrome exploitation statements, which
currently remain plain vendor references. Complete the remaining accepted
feature scope before the Phase 5 foundation. Do not re-open a bulk refresh
as a feature gate, or describe optional build freshness as a v1 operational
policy. This scope pass alone does not declare Phase 2 complete.
