# Current Session Handoff

Updated: 2026-11-26.

**Ended: Subphase 5F.1 Complete.** Shared evidence schema, versioned migration,
validated access layer, source registry and later job/archive contracts are
implemented. See [Closeout](review/2026-11-26-5f1-closeout.md) and
[Shared Evidence Runbook](runbooks/shared-evidence.md).

Acceptance: all 18 new tests passed. Final full offline suite ran 529 tests:
528 passed and one existing skip. Migration preserved legacy rows/views;
six existing pages returned 200 through the normal app lifespan on a temporary
database. No live database migration, app restart or provider refresh. Phase 2
deferrals and v1 operational freshness requirements remain.

Checkpoint: approved read-only Git inspection confirmed main at 8df28b0 and
an empty index. The operator confirms that Phase 2 commit was already pushed
and verified in the previous chat; do not repeat it. The operator explicitly
approved the named 5F.1 commit and its push in this chat. This handoff is
prepared for those operations. Exact approved files/message:
[14-Path Proposal](review/2026-11-26-5f1-checkpoint-files.md). The closing chat
message records the actual result. Saved notes are not Git permission.

Local work: the proposal names all 5F.1 code/tests/docs. Preserve and exclude
`feedly-review-rules.md`, `.claude/settings.local.json`, secrets, runtime data
and conversation exports. Source metadata stays disabled by default. The
historical RVM license finding is not a current terms approval. Existing
manual feeds retain their own behavior until explicit runner integration.

Next: **5F.2 Durable Job Runner**. No job execution or scheduling has started.
Follow [Session Handoff](runbooks/session-handoff.md) at this boundary.

## Next-Chat Prompt

```text
Continue the CTI Toolkit in this repository. Follow AGENTS.md and its required
reading order. Read focused ROADMAP.md foundation sections, the newest
Research notes in docs/journal.md, docs/handoff.md, the 2026-11-26 5F.1 closeout
and docs/runbooks/shared-evidence.md, session-handoff.md and v1-data-freshness.md.

5F.1 is complete: final offline suite ran 529 tests, 528 passed and one
existing skip. Read the shared schema/access layer and integration contracts.
The live database was not migrated or restarted in that pass. Phase 2 commit
8df28b0 was already pushed and verified in the previous session. Do not repeat
it. Reconcile the latest operator message and closing checkpoint result with
the handoff before deciding whether the 5F.1 checkpoint is still pending.
Obtain Git inspection approval if needed; every commit and push requires its
own approval in this chat. Preserve the separate Feedly rules and local Claude
settings and exclude all secrets, runtime data and conversation exports.

Implement only 5F.2: Durable Job Runner. Inspect existing queues, rate limits
and thread/SQLite patterns first. Build durable progress, bounded retries,
cancellation, interrupted-job recovery and duplicate-execution control using
temporary-database offline tests. Register source work explicitly in trusted
code and use the 5F.1 eligibility and evidence replay contracts. Preserve
separate execution IDs, logical work identity and success/coverage checkpoints.
Source content cannot choose callables, destinations or approval decisions.

Done when crash/restart, concurrent claims, retry bounds, cancellation and
duplicate-execution tests pass; existing modules remain compatible; repeatable
commands, design decisions and remaining limits are documented. Do not quietly
schedule feeds or enable sources: scheduled refresh/source health are 5F.3,
saved reports/archives 5F.4 and alerts 5F.5. Collectors and AI remain outside
this pass. New dependencies, installs, external transfers and other system
changes follow AGENTS.md approval rules. Routine project edits and offline
tests need no additional permission.

Work through this one subphase. At the boundary state Subphase 5F.2 Complete
only if acceptance passes, write a dated closeout and update journal, roadmap,
paired status summaries and handoff. Prepare exact commit files/message for
individual approval and request push approval separately. Provide a ready-to-
paste 5F.3 prompt and stop. If incomplete, record actual status and a resume
prompt instead of claiming completion.
```
