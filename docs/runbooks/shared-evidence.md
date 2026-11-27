# Shared Evidence and Source Registry

Update 2026-11-27: [CT Lookalike Watches](ct-lookalike-watches.md) adds one
provisional disabled consumer. Sensitive captures retain literal certificate
dates separately from unknown source observation/publication dates. Derived
certificate-ID references are explicitly constructed, not supplied citation
hops. No source registry approval or raw retention is granted.

Update 2026-11-26: [Ransomware Victim Claims](ransomware-victims.md) writes
immutable reported organization assertions, optional explicit structured
sector/country assertions, and literal original-post citations. Independent
module tables retain source-claim identity, capture history and bounded
normalized recovery input. Optional inbox event keys deduplicate alerts
without merging evidence. Registry defaults and approval rules remain unchanged.

Update 2026-11-26: [Alert Inbox](alert-inbox.md) adds atomic local selector
matching to shared observation writes and report saves. Its separate additive
schema retains alert/review history independently of original availability.
Explicit paged catch-up matches older observations. No collection is implied.

Update 2026-11-26: [Saved Reports and Archives](saved-reports-and-archives.md)
implements the 5F.4 consumer and bounded raw-retention contract. The original
5F.1 scope and future-facing descriptions below remain historical. Version 2
adds report-save manifests, archive availability and normalized bulk results.
No live migration, source enabling or collection occurred in this pass.

Update 2026-11-26: [Scheduled Feeds](scheduled-feeds.md) now applies this
registry gate to 31 opt-in feed surfaces. It persists endpoint/digest capture
metadata before ingestion, verifies replay identity and separates retrieval,
committed units and coverage. No source is newly approved or enabled. Raw
archives and saved report observations were delivered separately in 5F.4.

Written 2026-11-26. Subphase 5F.1. This is a local metadata store, not a
collector or an original-response archive. No new dependency is required.

## Design and Ownership

`app/core/evidence_models.py` validates inputs with the existing pydantic
dependency. `app/core/evidence.py` owns short SQLite transactions and bounded
reads. `app/core/evidence_schema.py` owns versioned additive migrations.
Core `db.init_db()` runs the migration during normal startup.

| Table | Meaning |
|---|---|
| `evidence_schema_versions` | Applied shared-store migrations. Does not claim SQLite `user_version` or other modules' migrations. |
| `evidence_sources` | Stable source identity, collection surface, current review metadata and explicit collection switch. |
| `evidence_documents` | Immutable capture of one source record, with provenance and collection metadata. No body or filesystem path. |
| `evidence_observations` | One document's assertion about a typed subject. Mentions remain mentions. |
| `evidence_citations` | Directed document edges, including references whose target is not saved or resolved. |
| `evidence_source_links` | Scoped source republication/derivation with a dated evidence reference. |

The five-part research model is represented by typed subjects, document
metadata and separate observations. Dedicated entity, artifact and assessment
catalogs wait for their consumers. There is no attribution engine, malicious
verdict, automatic corroboration count, selector matcher or new UI here.

Legacy cache, vulnerability tables/views, review events and infrastructure
tables retain their existing ownership and access. They are not copied into
the corpus. Legacy date meanings are too varied for an automatic backfill.
The shared store's foreign keys are enabled on its own connections. Legacy
connections keep their prior behavior.

## Source Review and Eligibility

Use a stable lowercase `source_id`, such as `rvm`. One entry describes one
collection surface and method. If a publisher needs distinct API and public
page policies, give those surfaces distinct keys. Do not merge sources by
hostname or infer that shared hosting means shared authorship.

`record_document()` automatically registers an unknown source as class
`unknown`, access `unknown`, reliability `F`, terms `unreviewed` and collection
disabled. This records already obtained evidence without granting collection
permission. It never overwrites a reviewed source. The caller supplies the
source identity and must not extract approval instructions from a report.

`save_source(Source(...))` explicitly replaces the current registry metadata.
It is for trusted local review workflows. It is not an ingestion parser.
Terms decisions require their own date and reference. License findings have
separate name, date and reference fields. Unknown license fields stay null.
A license finding alone never establishes terms eligibility.

`require_collection(source_id, access_method)` raises `PermissionError` unless
all of these hold:

- The source exists and `collection_enabled` is true.
- Terms status is `approved`, with a review date and reference.
- Source class and access method are known, and the requested method matches.
- Rate-limit notes are explicitly recorded. If there is no published limit,
  the reviewer must record a conservative local bound rather than guess.

`restricted` and `denied` fail closed. Reviewers must resolve restrictions
into an approved, appropriately scoped surface before enabling it. Reliability
is the Admiralty A to F letter and defaults to F. It is not a collection vote.
Current source metadata is mutable; review history/auditing and expiry checks
are not implemented in this subphase.

The only starter entry is `rvm`, an existing Phase 2 provider. Its CC BY 4.0
finding is dated 2026-11-11 and points to the saved detailed research. This
is a historical finding, not a new upstream verification. Its terms remain
unreviewed, its reliability F and its collection switch disabled. No other
provider is silently approved. See
[Source Review](../research/2026-11-11-sources-review.md) and
[RVM Research](../research/2026-11-11-sources/bushido-ransomware-apt.md).

Existing manual feed and enrichment routes are unchanged and do not yet use
this gate. They are not newly approved or disabled by this registry. 5F.2 and
5F.3 must wire explicit source work and reviewed policies before scheduling.
The gate records application eligibility; it does not override operator
approval requirements for external transfers.

## Provenance and Time

Each document has a stable `source_id` and source-local `external_id`.
`capture_key` identifies a local capture and stays fixed across retries.
`source_revision` is the upstream revision, if known. A new retrieval can
have the same upstream revision but needs a new capture key and collection
time. `content_sha256`, when known, describes the original bytes. It is not
an inferred revision or proof of authenticity.

The document title, publisher, source URL, kind, collection method, sensitivity
and optional TLP remain attached to that capture. A source URL is passive
text here; recording it does not visit it or authorize a request.

| Field | Meaning |
|---|---|
| `source_published_at` | Publication date/time asserted by the source. |
| `source_modified_at` | Upstream modification date/time, when explicit. |
| `collected_at` | Actual capture time, requiring an aware timestamp. |
| `observed_at` | When the source says the particular event was observed. |
| `first_seen`, `last_seen` | Source-reported observation interval for this assertion, not local ingestion dates. |

Unknown source dates stay null. Date-only values keep YYYY-MM-DD precision.
Aware instants normalize to UTC; naive or invalid timestamps are rejected.
No publication or collection date substitutes for an observation date.
First/last-seen intervals reject a definite reversal. Mixed date/instant
precision on the same day does not invent a more precise ordering.

Observations store an exact typed subject chosen by the caller. Future
indicator adapters should use the existing canonicalization functions before
writing; this generic store does not merge aliases or normalize every type.
Several sources mentioning the same domain remain separate observations.
Excerpts are limited to 4,096 characters and locators to 1,024. These are
metadata snippets, not a mechanism to save full responses. Render all source
text with escaping in future consumers.

Citation edges retain the literal cited reference, relationship, excerpt and
locator. An unresolved reference has a null `target_document_id`. Later,
`resolve_citation()` requires a saved target and an explicit matching note.
The original reference survives. Incoming and outgoing edges can be paged.
Replaying an unresolved edge preserves a later explicit resolution. A
conflicting resolution requires a separate correction edge. Cycles can be
real citation evidence; future traversals must use visited sets and hop caps.
No graph traversal or independence scoring runs automatically.

Source links require a scope and evidence reference. A TTP-table republication
does not imply that all of an aggregator's other data has that origin.

## Job Integration Contract for 5F.2

Implemented 2026-11-26 in the opt-in [Durable Runner](durable-jobs.md).
`require_collection()` also accepts an existing SQLite connection so runner
transactions use this same gate. Existing manual routes remain unchanged.
`Context.document()` persists original capture metadata and its originating
run ID before ingestion. Legacy opaque run IDs remain valid passive metadata;
there is no retroactive FK or legacy job backfill.

- Register permitted work in trusted application code. Never derive a callable,
  import path, destination or command from document contents or registry text.
- Future source jobs must check `require_collection()` before each bounded
  work unit, including retries and resumed work. A queued approval can be revoked.
  The worker must enforce actual request, time and quota limits. Registry
  rate-limit notes are descriptive and are not a token bucket.
- `job_run_id` is an optional opaque execution identifier on a document. A
  future run table may add a validated association without rewriting captures.
  It is not a job implementation, foreign key or success checkpoint today.
- Allocate and persist capture/observation/citation keys before ingestion.
  Replays return the same IDs. Changed data under an existing key raises
  `EvidenceConflict`; use a new capture or observation key for a correction.
- Each access-layer write commits independently. Interrupted imports can
  replay a saved document and then complete missing observations and citations.
  Do not mark a batch complete until all intended writes have committed.
- Keep attempt, successful retrieval and complete coverage checkpoints separate.
  A failed job never renews publication dates or source observation dates.
- Run this blocking SQLite access in a worker thread, not on the async loop.
  Transactions do not span network requests. Concurrent replays serialize.

## Archive and Retention Contract for 5F.4

There is no blob writer, pruning job or active retention policy in 5F.1.
Future archive support must use a separate table keyed to `document_id`.
Before storage is enabled, it must require explicit finite positive bounds
for response bytes, per-source bytes, total archive bytes and retention age.
No unset value means unlimited retention of raw bodies. Streamed compressed
inputs also need independent expansion limits.

Store original-byte digest, byte count, media type, upstream revision,
collection time, expiry, sensitivity and an explicit archive state such as
stored, omitted, expired or failed. Use generated storage keys under a
configured local root. Source text must never supply a filesystem path.
Writes must be atomic and crash recovery must reconcile metadata and files.
Do not claim a retained original when only normalized fields are available.

Default sensitivity is `unknown`. Raw storage requires an explicit handling
decision. Sensitive data and TLP restrictions need local access/export rules;
these labels do not provide encryption or enforce a policy by themselves.
Credentials, source excerpts and raw responses never become job log messages
or external diagnostic submissions by default.

Expiring bounded raw bodies must retain document/observation/citation metadata
and digests, with an honest availability state. It must not cascade-delete
indicator history. This preserves ROADMAP.md's indicator-retention decision
while bounding archive storage. Future privacy-driven deletion requires its
own explicit policy, not an undocumented scheduler cleanup.

## Repeatable Offline Acceptance

Run from the project root. Tests use temporary databases and the existing
offline HTTP guard. They do not migrate the operator's database.

```bash
# Windows: focused acceptance, then compatibility
.venv/Scripts/python.exe -B -m unittest tests.test_shared_evidence -v
.venv/Scripts/python.exe -B -m unittest discover -s tests -t .

# Linux equivalents
.venv/bin/python -B -m unittest tests.test_shared_evidence -v
.venv/bin/python -B -m unittest discover -s tests -t .
```

Normal approved app startup runs the migration. If an operator chooses to
initialize without starting the server, this command changes the configured
local database and also performs the existing expired-cache cleanup. Obtain
the required approval before an agent runs it against the live database:

```bash
.venv/Scripts/python.exe -B -c "from app.core.db import init_db; init_db()"
```

Use `.venv/bin/python` on Linux. Do not execute this against production as
part of the offline acceptance suite. No live database initialization or app
restart was performed for this subphase.

## Approved Read-Only Git Inspection

These were used after approval in this chat. Future chats still need their
own Git authorization. None stages files or contacts the remote.

```bash
git status --short
git diff --stat
git diff --check
git diff --cached --name-only
git log -1 --format="%h %s"
git branch --show-current
```

Review untracked proposed files directly as well; `git diff` does not show
their contents. The exact 5F.1 list is in
[Checkpoint Proposal](../review/2026-11-26-5f1-checkpoint-files.md).
Commit and push commands follow [Session Handoff](session-handoff.md) after
their separate approvals. The proposed message is
`Add shared evidence model and source registry`.

## Approved 5F.1 Commit and Push Commands

The operator approved both checkpoint actions in this chat on 2026-11-26.
These commands document that specific action, not permission in future chats.
Read the manifest, stage only its 14 paths, check exact staged membership,
then commit. Stop on any error or unexpected staged file.

```powershell
$checkpointManifest = Get-Content 'docs/review/2026-11-26-5f1-checkpoint-files.md' -Raw
$checkpointBlock = [regex]::Match($checkpointManifest, '(?s)```text\r?\n(.*?)\r?\n```')
if (-not $checkpointBlock.Success) { throw 'Approved file list missing' }
$checkpointPaths = @($checkpointBlock.Groups[1].Value -split '\r?\n')
if ($checkpointPaths.Count -ne 14) { throw 'Unexpected approved file count' }
git add -- @checkpointPaths
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
$stagedPaths = @(git diff --cached --name-only)
if ($LASTEXITCODE -ne 0) { throw 'Staged inspection failed' }
if (Compare-Object ($checkpointPaths | Sort-Object) ($stagedPaths | Sort-Object)) {
    throw 'Staged files differ from approved files'
}
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Staged whitespace check failed' }
git diff --cached --stat
git commit -m 'Add shared evidence model and source registry'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git log -1 --format="%h %s"
```

After checking the resulting commit and the previously verified origin/main
destination, use the explicitly approved push. Do not force push.

```powershell
git push origin main
if ($LASTEXITCODE -ne 0) { throw 'Push failed' }
git rev-parse HEAD refs/remotes/origin/main
git ls-remote --exit-code origin refs/heads/main
git status --short
```

The two local hashes and the live remote main hash should match. The separate
Feedly rules and local Claude settings can remain untracked. A push saves code,
not ignored runtime data. Record the actual hash and result in the closing
message without amending the commit to include its own hash.
