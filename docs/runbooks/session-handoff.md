# Subphase Closeout and Session Handoff

Written 2026-11-26. Use one chat per coherent, testable subphase. Keep related
implementation, debugging and acceptance in that chat. Start another at the
next agreed milestone, rather than at an arbitrary message count.

## End Each Subphase Explicitly

1. Check the agreed acceptance criteria. Finish the authorized work and
   appropriate verification. Record failures and limits honestly.
2. Create a dated review note, normally
   `docs/review/YYYY-MM-DD-<subphase>-closeout.md`. State either
   **Subphase <ID> Complete**, **Subphase <ID> Incomplete**, or
   **Subphase <ID> Deferred by Operator**. A credit limit or session switch
   alone does not complete a subphase.
3. Add a dated journal entry with implementation decisions, troubleshooting,
   tests, remaining risks and the next step. Retain detailed historical notes.
4. Update the roadmap's scope/status and `docs/handoff.md`. Keep the handoff
   short, usually a few hundred words plus the next prompt. Link historical
   detail instead of repeating it. Do not copy conversation transcripts.
5. Prepare the Git checkpoint under the approval workflow below. Update the
   handoff accurately if approval, a commit or a push is still pending.
6. Tell the operator explicitly which subphase ended, what passed, where its
   closeout lives and which prompt starts the next chat. Do not silently
   begin the next subphase in the old chat.

## Git Checkpoint Before a New Session

Default: commit the completed, reviewed work and push the approved commit
before moving to a fresh chat. The commit gives a precise local checkpoint;
the push saves that history remotely. Neither includes ignored runtime data
or proves the application database has been backed up.

The working agreement still requires approval for every Git operation,
including inspection. These are repeatable operator commands, not standing
permission for an agent to run them:

```bash
git status --short
git diff --stat
git diff --check
git diff --name-only
```

After inspection is authorized, review actual changes and untracked files.
Do not print secret-bearing content. Check that the intended files exclude
runtime data, keys, transcripts, local settings and unrelated work. Present
the exact file list and proposed commit message for approval. Name files
explicitly when staging; do not use `git add .` as a shortcut.

```bash
git add -- path/to/approved-file.py docs/review/approved-closeout.md
git diff --cached --stat
git diff --cached --check
git commit -m "Approved message"
git log -1 --format="%h %s"
```

Replace the example paths and message with those actually approved. Include
the final handoff and closeout in that reviewed file list. A failed hook or
test must be investigated, not bypassed. A commit request does not authorize
a push. After the commit, show the actual commit and intended remote/branch,
then obtain separate push approval. Inspect configured destinations without
echoing embedded credentials. Use the verified destination, not a guessed
branch or an unexpected upstream. No force push or automatic history rewrite.

For the usual verified `origin` and `main` destination:

```bash
git push origin main
```

Record the actual commit ID and push result in the end-of-chat message. A
tracked handoff cannot contain the ID of the commit that first contains it;
do not amend repeatedly to chase that self-reference. The next chat verifies
HEAD and tracking state after inspection is authorized. In the file, state
the last verified checkpoint or that verification is pending.
The next agent must reconcile that possibly older note with the current
operator message and approved Git inspection rather than recommitting work
that has already been saved and pushed.

If approval or network access is unavailable, preserve the local edits and
name the uncommitted/unpushed work in the handoff. Do not stash, reset, discard
files or create a misleading completion commit to make the workspace clean.
A session can end with a documented pending checkpoint if needed. Resume
that checkpoint before unrelated implementation unless the operator directs
otherwise. For Git concepts see [Git Basics](git-basics.md).

## Current Handoff Contents

For the 2026-11-26 Phase 2 checkpoint, the operator approved the exact list in
`docs/review/2026-11-26-phase2-checkpoint-files.md` and message
`Complete Phase 2 and document subphase handoffs`. After that approval, the
list can be loaded without copying 119 paths by hand:

```powershell
$manifest = Get-Content 'docs/review/2026-11-26-phase2-checkpoint-files.md' -Raw
$block = [regex]::Match($manifest, '(?s)```text\r?\n(.*?)\r?\n```')
if (-not $block.Success) { throw 'Approved file list missing' }
$approvedPaths = @($block.Groups[1].Value -split '\r?\n' | ForEach-Object { $_ -replace '^DELETE ', '' })
if ($approvedPaths.Count -ne 119) { throw 'Unexpected approved file count' }
git add -- @approvedPaths
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Staged whitespace check failed' }
git diff --cached --stat
git commit -m 'Complete Phase 2 and document subphase handoffs'
git log -1 --format="%h %s"
```

Verify the staged paths equal the approved list before committing; the agent
also checked exact membership programmatically. These commands document this
checkpoint, not permission to repeat it or push. Inspect the actual result
before deciding whether anything remains to commit.

Use this structure in `docs/handoff.md`:

```text
Updated: YYYY-MM-DD
Ended: <subphase ID and Complete/Incomplete/Deferred status>
Acceptance: <what ran, result, limitations; link the closeout>
Checkpoint: <verified commit/push state or explicitly pending/unverified>
Local work: <uncommitted scope and files/links; no secret contents>
Next: <one subphase, outcome, boundaries, relevant file paths>
Next-chat prompt: <ready to paste below>
```

The prompt should tell the next agent to read AGENTS.md, then the roadmap,
current journal entry and linked handoff references in the required order.
Specify scope, done-when criteria and exclusions. Carry the approval rule
forward. A saved prompt or older approval is evidence only: it authorizes
work when the operator actually sends the request in the new chat. Never
claim an earlier session granted permission for a new commit or push.

Keep the detailed journal and reviews. Shorten only the automatically loaded
status summaries in AGENTS.md and CLAUDE.md, updating both together. Keep all
approval, secret handling, deterministic-core and research rules intact.
