# Current Session Handoff

Updated: 2026-11-26.

**Ended: Phase 2 accepted first-delivery implementation complete.**
The session workflow and foundation subphase boundaries are now documented.
No foundation subphase has started.

Acceptance: final Phase 2 suite ran 511 tests, 510 passed and one existing
skip. All 26 local page checks returned 200 without changing feed status or
review counts. These are prior verified results, not a new run on 2026-11-26.
See [Phase 2 Closeout](review/2026-11-25-phase2-closeout.md). This milestone
does not imply full history, complete extraction coverage or operational v1
freshness. Known limits and deferrals remain in that review and ROADMAP.md.

Checkpoint: Git inspection performed 2026-11-26 on main at a07898b, with an
empty staging area and matching local origin/main reference. The operator
then approved the [119-path checkpoint](review/2026-11-26-phase2-checkpoint-files.md)
as `Complete Phase 2 and document subphase handoffs`. This handoff is prepared
for that commit; verify actual HEAD and push state before resuming. Push
requires separate approval and was not authorized with the commit. The
closing chat message records the actual result. Workflow:
[Session Handoff](runbooks/session-handoff.md).

Local work: implementation spans vulnerability evidence, views/routes,
vendor/OT parsers, advisory reloads, review grouping, templates and tests.
Earlier Phase 2 batches are included in the exact approved checkpoint list.
Reconcile it against actual Git state rather than staging everything blindly.
Do not include `.claude/settings.local.json`,
`.env`, runtime data or conversation exports.

Next: **5F.1 Shared Evidence Model and Source Registry**, the first foundation
subphase. See ROADMAP.md's Foundation slice table and
[V1 Data Freshness](runbooks/v1-data-freshness.md). Saved reports/archives are
5F.4 consumers of this schema; the job runner is 5F.2. Collectors and AI are
outside this first subphase.

## Next-Chat Prompt

Parked reference, 2026-11-26: the RSS/newsletter prototype review is complete;
Phase 4 integration is operator-deferred. Revisit
[Reader Prototype Review](review/2026-11-26-reader-prototype.md) when Phase 4
starts. The reader will reuse vulnerability evidence instead of importing a
separate KEV catalog. This documentation pass ran no tests or Git operations
and does not change the next foundation subphase or pending checkpoint.

```text
Continue the CTI Toolkit in this repository. Follow AGENTS.md and its reading
order: ROADMAP.md, the newest Research notes in docs/journal.md, then the
relevant runbooks, research and reviews. Read docs/handoff.md for current
state and docs/runbooks/session-handoff.md for the closeout workflow. Start
with focused linked sections rather than replaying the full project history.

First verify the Phase 2 Git checkpoint. This handoff may predate its commit
and push, so check the operator's current message and actual repository state
after obtaining Git inspection approval. If still pending, inspect the local
changes and show exact files and message before requesting commit approval.
Request push approval separately after the approved commit. Do not repeat a
checkpoint that has already completed. Do not infer
that this saved prompt, an old approval or existing local edits grant Git
permission. Do not discard or silently include unrelated local work.

After the checkpoint is resolved, implement only 5F.1: the shared evidence
model and source registry. Inspect existing schema, evidence handling and
reviewed source research before proposing the smallest compatible design.
Preserve source identity, citation relationships and distinct observation,
publication, collection and first/last-seen dates. Source review and
collection eligibility must be explicit. Define bounded archive/retention
and job integration contracts for later subphases. Do not guess current
license or terms reviews for sources.

Done when: the local schema/access layer and migration are implemented,
offline migration/provenance tests pass, compatibility with existing
modules is checked, and the design, limits and runbook are documented.
Do not add AI, collectors, scheduled provider traffic or new dependencies
without the required separate approval. Keep secrets and private runtime
data local. Existing Phase 2 deferrals remain deferred.

Work through this coherent subphase without asking about routine project
edits or offline tests. At its end, explicitly state Subphase 5F.1 Complete
only if acceptance passes. Write its dated closeout, update the journal,
roadmap and docs/handoff.md, and provide a ready-to-paste prompt for 5F.2.
Prepare the reviewed commit and push checkpoints under separate approvals
before moving to the next session. If interrupted or incomplete, record
that status and a resume prompt instead of claiming completion.
```
