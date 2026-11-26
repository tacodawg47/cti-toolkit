# Current Session Handoff

Updated: 2026-11-26.

**Ended: Subphase 5F.3 Complete.** 31 explicit feed surfaces now have
opt-in durable schedules, bounded shared-loop async/quota integration,
source health and preserved retrieval/progress/coverage/capture contracts.
See [Closeout](review/2026-11-26-5f3-closeout.md) and
[Scheduled Feeds](runbooks/scheduled-feeds.md) for policies and limits.

Acceptance: final offline suite ran 585 tests in 92.493 seconds: 584 passed
and one existing skip. Includes 32 new scheduler tests, retained runner and
evidence compatibility, interrupted pagination, vendor continuation, cooldowns,
shutdown, source revocation and freshness at consuming pages. All schedules
and the worker default off. No source enabling, provider traffic, dependency
change, live migration or app restart. The live database has not been
migrated for 5F.1 to 5F.3. Linux/browser visual checks were not performed.
V1 operational acceptance still requires approved activation and later
foundation acceptance.

Checkpoint: approved read-only Git inspection confirmed main at `eff4b41`,
`Add durable job runner`, with an empty index and .githooks configured. The
operator confirms its push was verified. Do not repeat 5F.2. The 5F.3 exact
proposal is [Checkpoint Files](review/2026-11-26-5f3-checkpoint-files.md),
message `Add scheduled feed refresh and source health`. The operator approved
that exact commit in this chat. Execution is prepared; separate push approval
remains pending. Reconcile the closing chat result
and latest operator message with this prepared note before deciding what
remains. Saved notes never grant Git permission.

Preserve unrelated Feedly rules, local Claude settings, prototypes/ and its
review/runbook. Shared roadmap/journal/handoff also contain separate prototype
edits; stage only approved 5F.3 content. Exclude secrets, runtime data and
conversation exports. Normal source jobs use the existing app loop, not new
loops per job. Large archives/reloads stay behind their explicit actions.
Next: only 5F.4, Saved Reports and Original-Source Archives.

## Next-Chat Prompt

```text
Continue CTI Toolkit at C:\Users\Robert\Projects\cti-toolkit.
Implement only 5F.4: Saved Reports and Original-Source Archives.

Follow AGENTS.md and its required reading order. Read focused ROADMAP.md
foundation/archive/data-handling sections, newest Research notes in
docs/journal.md, docs/handoff.md, docs/review/2026-11-26-5f3-closeout.md,
and runbooks shared-evidence.md, durable-jobs.md, scheduled-feeds.md,
session-handoff.md and v1-data-freshness.md. Inspect extraction, enrichment,
source controls and evidence replay before wiring consumers.

Subphase 5F.3 Complete: final offline suite ran 585 tests, 584 passed and
one existing skip, including 32 new scheduler tests. Schedules for 31
existing feed surfaces and the worker default off. No source was enabled
or contacted. The live database has not been migrated or restarted for
5F.1 to 5F.3. Linux and browser visual acceptance were not performed.
5F.2 commit eff4b41 was pushed and verified. The exact 5F.3 commit proposal
was individually approved in its chat; this saved note precedes execution.
Its exact 58 paths are in docs/review/2026-11-26-5f3-checkpoint-files.md.
Reconcile the latest operator message and closing chat result for the actual
commit and separately approved push. Resolve any pending checkpoint before
new implementation unless the operator directs otherwise. Never repeat a
completed checkpoint or infer Git permission from a saved handoff.

Implement saving extracted reports with source metadata, documents and
indicator sightings. Preserve publication, observation and collection times,
literal citation hops, capture identity and originating execution metadata.
Use deterministic replay keys; changed input must not reuse old capture data.
Support report/file/paste origins with the agreed required source fields.

Implement bounded original-response storage under a configured local root.
Require explicit finite response/per-source/total byte and retention-age
limits before raw storage can be enabled. Define handling for unknown or
sensitive material. Use generated paths, atomic writes and recoverable
metadata/file reconciliation. Preserve digest/provenance and honest
stored/omitted/expired/failed availability after expiry. Do not cascade-delete
indicator history. Do not claim an original exists when only normalized
data or metadata is retained. Keep keys, credentials and private runtime
data out of logs, exports and commits.

Wire the agreed bulk IOC enrichment workflow through durable jobs. Keep
keyless-first and keyed-on-request source controls, finite quota/request/time
budgets and rechecks before every unit/retry/resumption. Reuse the existing
application-loop bridge; never wrap the shared async limiter in fresh
event loops per job. Do not convert saved content into callables, commands,
destinations or collection permission. Existing manual routes and registry
notes do not authorize new traffic.

Done when meaningful offline tests cover saves/replays, provenance and
citation relationships, limits, malformed inputs, interrupted writes,
restart reconciliation, expiry preserving history, sensitive handling and
bulk-job source/quota controls; compatibility passes; and repeatable commands,
decisions, limits and a dated closeout are documented.

Preserve unrelated Feedly rules, local Claude settings, prototypes/ and the
actor-prototype notes/review/runbook, including separate working-tree edits
in ROADMAP.md, docs/journal.md and docs/handoff.md. Stage only this subphase's
approved changes from shared files. Exclude secrets, runtime data and
conversation exports. Alerts are 5F.5. Collectors and AI remain outside scope.
Do not enable schedules or perform large historical reloads in this pass.

Routine project edits and offline tests need no additional permission.
Obtain direct approval before provider traffic, source enabling, live
migration, app restart, installs, external transfers or other system changes.
Every Git operation requires current-chat approval. Show exact commit files
and message, obtain individual commit approval, then separate push approval.

Work proactively through this one subphase, then stop. State Subphase 5F.4
Complete only if acceptance passes. Update the dated closeout, journal,
roadmap, paired status summaries and docs/handoff.md. Print the complete
ready-to-paste 5F.5 handover prompt directly in the final response in a
fenced text block. If incomplete, record actual status and print a resume
prompt instead.
```
