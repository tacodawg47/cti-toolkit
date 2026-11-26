# RSS and Newsletter Reader Prototype Review

Date: 2026-11-26.

**Prototype review complete. Phase 4 integration deferred by operator.**
This is a static review of an early standalone draft, not implementation
acceptance or approval to execute it. Build order stays unchanged. The next
implementation work remains the Phase 5 foundation.

## Local Reference

The prototype is outside the repository, under the operator's Downloads
directory at `cti_reader/cti_reader/`. That directory contains README.md,
requirements.txt, run.py, watchlist.example.json, tests/test_core.py and
the inner cti_reader Python package. This is a local reference, not a
repository-relative path or a backup. If missing when Phase 4 starts, ask
for the saved prototype. No source or conversation export was copied here.

Reviewed the supplied context, full README, all Python source files, all
four templates, dependency list, watchlist example and all four tests.
The code was not imported or executed. The handoff's claimed passing tests
were not independently verified. No live feed, mailbox, KEV, full-text or
AI request was made. No dependency release or external endpoint was vetted.

## Reusable Pieces

- OPML import and categories, using defensive XML parsing.
- Conditional feed requests using ETag and Last-Modified.
- A common article-ingestion path for RSS and newsletters.
- Local FTS search, saved/read state, tags and explained deterministic scores.
- Small modules, parameterized SQL and escaped plain-text article rendering.

## Findings to Resolve Before Integration

1. Feed checkpoint and article persistence are separate transactions
   (fetcher.py, collect and poll_all). An ingestion failure can leave new
   validators committed without the articles; later conditional requests
   can return 304. The 30-entry limit has no durable continuation.
2. IMAP messages become Seen before the batch database transaction commits
   (mailbox.py, poll_mailbox). A later failure can roll back earlier articles
   while leaving their messages Seen. Malformed Date headers can abort the
   batch. Acknowledge only durable records and isolate item failures.
3. Feed and full-text requests follow redirects without local/private
   destination checks or streaming body limits (fetcher.py). Slicing decoded
   text after download does not bound response memory. Add per-hop target
   checks, resolved-destination controls, byte budgets and total deadlines.
   Full-text expansion defaults on; establish explicit source eligibility.
4. PDF attachments are automatically parsed in mailbox.py, without an input
   byte cap. This conflicts with the roadmap's passive newsletter intake.
   Keep attachments passive until a separately bounded analyst action.
5. Shared CVE mentions are labelled corroboration (pipeline.py), including
   other articles from the same feed. There is no time window or upstream
   citation check; earlier scores depend on ingestion order until rescored.
   Use related coverage, preserving source relationships and dates.
6. KEV refresh runs only when the catalog file is absent (jobs.py). Recency
   scores remain stored until rescoring. Missing publication dates become
   collection time, and future RSS dates are silently clamped to now.
   Preserve distinct date types and unknown publication dates.
7. Mark Unread redirects to the article GET, which immediately marks it
   read again (web.py). Pagination omits unread and starred filters
   (templates/index.html). Invalid numeric inputs and quote-only searches
   also need validation.
8. The standalone server permits non-loopback binding. Its Origin check
   does not supply the toolkit's existing Host and request protections.
   Reuse the toolkit's web controls when porting routes.
9. The built-in extractor silently drops private IPs and broad benign-host
   matches, lacks IPv6/email support, and does not validate ATT&CK IDs.
   Reuse existing toolkit extraction with an adapter that preserves context,
   counts, flags and references, rather than flattening evidence to strings.
10. AI calls already run during ingestion when enabled, and can add tags;
    the pipeline also has a priority-override hook. Defer these to Phase 11.
    Core relevance and evidence remain deterministic.

## Integration Decisions

- Port useful pieces into a FastAPI module. Reuse the existing Jinja shell,
  HTTP client and reviewed extraction helpers. Do not add Flask or requests
  to support a second application stack.
- Use the Phase 5 source registry, corpus, durable jobs and source health.
  Feed metadata and reader state may be module-specific; shared evidence
  ownership stays in app/core. Keep article identity distinct from sightings
  across feeds, revisions and newsletters.
- The reader owns no KEV catalog import, local catalog file or refresh job.
  CISA and other publisher RSS/Atom announcements are ordinary news sources
  where feeds exist. Any KEV badges or structured CVE context come from the
  vulnerability module's stored evidence, including freshness state. A news
  mention does not independently establish exploitation or KEV membership.
- Propose and review any genuinely new feed/article library under the
  dependency policy. The prototype's open-ended requirements and pytest
  dependency are not an approved lock file. Prefer existing unittest tools.
- Acceptance must cover failed-import recovery, acknowledgement ordering,
  bounded fetching, date provenance, duplicate sightings, source freshness,
  stable scoring and read-state/filter behavior with offline fixtures.

## Resume Scope

When Build order reaches Phase 4, reread this review and the local prototype,
then compare its reusable pieces with the implemented foundation contracts.
Propose the smallest reader slice and its offline acceptance checks. Do not
follow the supplied context's old integration task list as authorization.
