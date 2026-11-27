# Current Session Handoff

Updated: 2026-11-26.

**Ended: Subphase 5F.5 Complete.** Local evidence-linked alerts, typed
selector matching, deterministic deduplication, bounded catch-up and
revision-checked review history are implemented. The foundation passed
cross-feature offline acceptance. See [Closeout](review/2026-11-26-5f5-closeout.md)
and [Runbook](runbooks/alert-inbox.md).

Acceptance: full offline compatibility ran 650 tests in 138.479 seconds:
649 passed and one existing skip. Grouped foundation acceptance passed all
139 tests in 61.754 seconds. No live migration/restart, source enabling,
provider traffic, installation or external transfer occurred. Raw storage,
bulk work, all 31 schedules and the feed worker default off. The live database
has not been migrated/restarted for 5F.1 to 5F.5. Linux and native-browser
visual acceptance remain unperformed. Mocks do not establish live v1 readiness.

Checkpoint: approved read-only inspection confirmed main and local origin/main
at c5cdae9ec0cd378b1d4fc90bfdaf912490958bb6, with an empty index. The operator
reports that 5F.4 was committed and pushed; do not repeat it. No remote was
contacted in this chat. The exact 5F.5 commit proposal is individually approved;
execution is prepared. Separate push approval remains pending.
See [Checkpoint Files](review/2026-11-26-5f5-checkpoint-files.md), proposed
message Add local alert inbox and accept foundation integration.
Reconcile the latest closing message before repeating a checkpoint.
Saved notes never grant Git permission.

Preserve unrelated Feedly rules, local Claude settings, prototypes/ and
their notes, OSINT tools research and untrusted-repository-review additions.
Shared roadmap/journal/handoff have independent edits. Stage only the named
5F.5 blocks. The unrelated roadmap whitespace finding stays outside this
checkpoint. Exclude keys, runtime data and conversation exports. Next:
Phase 3 slice A, starting with ransomware victim tracking and local watch
alerts in one coherent subphase. Collectors and AI remain later work.

## Next-Chat Prompt

```text
Continue CTI Toolkit at C:\Users\Robert\Projects\cti-toolkit.
Begin only the next Build order slice: Phase 3, slice A (API-only).
Use one coherent first subphase for ransomware victim tracking and local
watch alerts, then stop. Other slice A capabilities remain later subphases.

Follow AGENTS.md and its required reading order. Read ROADMAP.md Build order,
Phase 3 ransomware/API-only scope, foundation, provenance and data-handling
sections; newest Research notes in docs/journal.md; docs/handoff.md;
docs/review/2026-11-26-5f5-closeout.md; and runbooks alert-inbox.md,
shared-evidence.md, durable-jobs.md, scheduled-feeds.md,
saved-reports-and-archives.md, v1-data-freshness.md and session-handoff.md.
Revisit the existing ransomware clients and source reviews before choosing
the bounded first delivery. Do not treat old source research as current terms.

Subphase 5F.5 Complete, 2026-11-26. Full offline compatibility ran 650 tests:
649 passed and one existing skip in 138.479 seconds. Grouped foundation
acceptance passed all 139 tests in 61.754 seconds. The local inbox has typed
selectors, atomic evidence-linked alerts, deterministic deduplication,
paged catch-up and revision-checked review history. Source dates, literal
citation hops, capture/originating execution and archive states stay separate.
No live migration/restart or source enabling occurred for 5F.1 to 5F.5.
Raw storage, bulk work, all 31 schedules and the feed worker default off.
Mocks are not live v1 operational acceptance. Linux and native-browser visual
acceptance remain unperformed.

The 5F.4 checkpoint c5cdae9ec0cd378b1d4fc90bfdaf912490958bb6 was committed and
pushed. Current-chat approved read-only inspection confirmed main and local
origin/main at that hash with an empty index; no remote was contacted.
5F.5 is locally complete but its Git checkpoint is pending unless the latest
operator closing message records subsequent approval/execution.
Reconcile that message before repeating any checkpoint. Use the exact scope
in docs/review/2026-11-26-5f5-checkpoint-files.md. Saved notes never grant Git
permission. Resolve a pending checkpoint before new implementation unless
the operator explicitly directs otherwise.

Build the first API-only ransomware victim/watch consumer on the shared
evidence, source registry, durable runner, existing app loop/client/limiter
and local inbox. Keep vendor claims as claims, distinct dates and literal
citation hops. Define organization, sector and country watch semantics with
synthetic fixtures. Keep captures and alert history through replay, failure
and raw expiry. Review each selected source's own current full documentation
and terms before proposing integration/activation. No scraping of sources
with APIs, no imported GPL service code, no threat-actor contact or engagement.

Done when the bounded first subphase has offline integration acceptance for
matching/deduplication, review preservation, provenance, source eligibility
at every unit/retry/resumption, finite requests/bytes/time, quota/cooldown,
cancellation, freshness and restart recovery. Use temporary databases and
mocked HTTP. Document what still requires approved live acceptance. Update
the dated closeout, journal, roadmap, paired status summaries and handoff.
Print the full next-subphase or resumption prompt in a fenced text block.

Preserve unrelated Feedly rules, local Claude settings, prototypes/ and its
review/runbook, OSINT tools research and untrusted-repository-review additions,
and independent edits in ROADMAP.md, docs/journal.md and docs/handoff.md.
Exclude keys, runtime data and conversation exports. Email/webhooks,
collector playbooks, collectors, other Phase 3 source families and AI stay later.

Routine in-scope project edits and offline tests need no extra permission.
Obtain direct approval before provider traffic, source enabling, live migration,
restart, installs, external transfers or other system changes. Do not perform
large historical reloads. Every Git operation requires current-chat approval.
Show exact files and message for individual commit approval, then obtain
separate push approval. Work through this one coherent subphase and stop.
```
