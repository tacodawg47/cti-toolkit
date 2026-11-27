# Current Session Handoff

Updated: 2026-11-26.

**Ended: Subphase 5F.4 Complete.** Report/file/paste saves preserve source
metadata, indicator mentions, citation hops and capture replay. Separate
original archives have explicit finite capacity/age limits and recoverable
file reconciliation. Enrich All uses bounded durable jobs on the app loop.
See [Closeout](review/2026-11-26-5f4-closeout.md) and
[Runbook](runbooks/saved-reports-and-archives.md).

Acceptance: full offline compatibility ran 627 tests in 118.318 seconds:
626 passed and one existing skip. Final focused acceptance passed all 42
new tests in 17.239 seconds after the last credential guard refinement.
No live migration/restart, source enabling, provider traffic, installation
or external submission occurred. Raw storage, bulk work, all 31 schedules
and the feed worker default off. The live database has not been migrated
for 5F.1 to 5F.4. Linux and browser visual acceptance were not performed.
Mocks do not establish live v1 operational acceptance.

Checkpoint: current-chat approved read-only inspection found main and local
origin/main at 2491fb3a7e6cdd9f4c4ba1d2d315cbf59965e73e, Add scheduled feed
refresh and source health. No remote contact occurred. Do not repeat 5F.3.
The exact 5F.4 commit proposal is approved; execution is prepared. Its exact 28-path proposal is
[Checkpoint Files](review/2026-11-26-5f4-checkpoint-files.md), with message
Add saved reports and bounded original archives. Individual commit approval
was received; separate push approval remains pending. Reconcile the closing chat result
before deciding what remains. Saved notes never grant Git permission.

Preserve unrelated Feedly rules, local Claude settings, prototypes/ and
their notes, plus OSINT tools research and its runbook additions. Shared
roadmap/journal/handoff contain separate edits; stage only 5F.4 blocks.
Exclude keys, runtime data and conversation exports. Collectors and AI
remain later work. Next: only 5F.5, Alert Inbox and Foundation Acceptance.

## Next-Chat Prompt

```text
Continue CTI Toolkit at C:\Users\Robert\Projects\cti-toolkit.
Implement only 5F.5: Alert Inbox and Foundation Acceptance.

Follow AGENTS.md and its required reading order. Read the focused ROADMAP.md
foundation, provenance and data-handling sections, newest Research notes in
docs/journal.md, docs/handoff.md, docs/review/2026-11-26-5f4-closeout.md,
and runbooks shared-evidence.md, durable-jobs.md, scheduled-feeds.md,
saved-reports-and-archives.md, session-handoff.md and v1-data-freshness.md.
Inspect existing evidence, selector requirements, consumer freshness,
job recovery and archive availability before wiring the alert inbox.

Subphase 5F.4 Complete. Full offline compatibility ran 627 tests: 626 passed
and one existing skip in 118.318 seconds. Final focused acceptance passed
all 42 new tests in 17.239 seconds after the last credential guard refinement.
Report/file/paste saves, bounded originals and durable Enrich All are built.
Raw storage, bulk work, all 31 schedules and the feed worker default off.
No source was enabled/contacted. The live database has not been migrated or
restarted for 5F.1 to 5F.4. Linux/browser visual acceptance was not performed.
Mock acceptance is not live v1 operational acceptance.

Approved read-only inspection found 5F.3 commit
2491fb3a7e6cdd9f4c4ba1d2d315cbf59965e73e and matching local origin/main.
Do not repeat it. The saved 5F.4 proposal has 28 paths in
docs/review/2026-11-26-5f4-checkpoint-files.md and message
Add saved reports and bounded original archives. The exact commit proposal was individually approved; execution was prepared
and separate push approval remained pending when this handoff was prepared. Reconcile the
latest operator message and closing chat result for actual execution.
Resolve any pending checkpoint before new implementation unless the operator
directs otherwise. Never infer Git permission from a saved handoff.

Deliver the local evidence-linked alert inbox, deterministic deduplication
and review state, with selector matching covered by integration tests.
Keep source assertions and dates distinct. Preserve literal citation hops,
capture identity, originating execution and original availability states.
An expired or omitted raw body must not erase indicator or alert history.
Saved content and selectors never grant collection permission or select
callables, commands, arbitrary destinations, credentials or approval.

Complete foundation integration acceptance for freshness at consuming pages,
failed/stale/never-loaded/incomplete states, downtime/restart recovery,
interrupted units, quota/cooldown/cancellation handling and archive
reconciliation. Use temporary databases and mocked HTTP for failure injection.
Reuse the existing app loop, shared client/limiter, durable runner and source
eligibility checks before every unit/retry/resumption. Keep public/sensitive
handling gates and finite request, byte, time and retention policies.
Document what mocks establish and what still needs approved live acceptance.
Do not enable sources/workers, migrate the live database or restart the app
without direct approval. Do not run large historical reloads.

Preserve unrelated Feedly rules, local Claude settings, prototypes/ and its
review/runbook, and OSINT tools research and its untrusted-repository-review
runbook additions. Shared ROADMAP.md, docs/journal.md and docs/handoff.md
contain independent edits. Stage only this subphase's approved changes.
Exclude keys, runtime data and conversation exports. Email/webhooks,
collector playbooks, collectors, new source integrations and AI stay later.

Routine in-scope project edits and offline tests need no extra permission.
Obtain direct approval before provider traffic, source enabling, live
migration, restart, installs, external transfers or other system changes.
Every Git operation requires current-chat approval. Show exact files and
message, obtain individual commit approval, then separate push approval.

Work proactively through this one subphase, then stop. Mark Subphase 5F.5
Complete only if acceptance passes. Update the dated closeout, journal,
roadmap, paired status summaries and docs/handoff.md. Print the full
ready-to-paste prompt for the next Build order slice directly in the final
response in a fenced text block. If incomplete, record actual status and
print a resumption prompt instead.
```
