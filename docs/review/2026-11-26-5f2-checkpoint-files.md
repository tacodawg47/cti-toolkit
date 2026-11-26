# 5F.2 Checkpoint Proposal

Date: 2026-11-26. Proposed message: `Add durable job runner`.

These are the exact 19 checkpoint paths. The operator explicitly instructed
commit and push in this chat, and requested the on-screen handover rule in
the same message. That documentation adds session-handoff.md to the earlier
18-path proposal. Approved
read-only Git inspection confirmed main at 6341acc, an empty index and
.githooks configured. The changes match this proposal; the two unrelated
local files remain excluded. Tracked whitespace checks passed. Stage only
these paths for the authorized commit. Verify the resulting commit and
existing origin/main destination before carrying out the authorized push.

```text
.gitignore
AGENTS.md
CLAUDE.md
ROADMAP.md
app/core/db.py
app/core/evidence.py
app/core/job_lock.py
app/core/job_schema.py
app/core/jobs.py
tests/test_jobs.py
tests/test_shared_evidence.py
docs/handoff.md
docs/journal.md
docs/review/2026-11-26-5f2-closeout.md
docs/review/2026-11-26-5f2-checkpoint-files.md
docs/runbooks/durable-jobs.md
docs/runbooks/session-handoff.md
docs/runbooks/shared-evidence.md
docs/runbooks/testing.md
```

Exclude and preserve `feedly-review-rules.md` and
`.claude/settings.local.json`. Never stage secrets, runtime data, lock files
or conversation exports. The operator confirms that 5F.1 commit `6341acc`,
`Add shared evidence model and source registry`, was pushed to `origin/main`
and verified. That checkpoint is complete and must not be repeated.

The exact file list can be loaded and checked without broad staging.
The following documents these authorized actions, not future permission:

```powershell
$jobManifest = Get-Content 'docs/review/2026-11-26-5f2-checkpoint-files.md' -Raw
$jobBlock = [regex]::Match($jobManifest, '(?s)```text\r?\n(.*?)\r?\n```')
if (-not $jobBlock.Success) { throw 'Approved file list missing' }
$jobPaths = @($jobBlock.Groups[1].Value -split '\r?\n')
if ($jobPaths.Count -ne 19) { throw 'Unexpected approved file count' }
git status --short
git diff --check
git diff --cached --name-only
# Stop if the index contains unapproved paths. Inspect diffs and new files.
git add -- @jobPaths
if ($LASTEXITCODE -ne 0) { throw 'Staging failed' }
$jobStagedPaths = @(git diff --cached --name-only)
if ($LASTEXITCODE -ne 0) { throw 'Staged path inspection failed' }
if (Compare-Object ($jobPaths | Sort-Object) ($jobStagedPaths | Sort-Object)) {
    throw 'Staged paths differ from the approved manifest'
}
git diff --cached --check
if ($LASTEXITCODE -ne 0) { throw 'Staged whitespace check failed' }
git diff --cached --stat
git commit -m 'Add durable job runner'
if ($LASTEXITCODE -ne 0) { throw 'Commit failed' }
git log -1 --format="%h %s"
```

Stop on an error, unexpected change or failed hook. Do not bypass hooks or
infer remote permission. After destination verification and separate push
approval, the expected project destination is `git push origin main`.
Both actions were explicitly authorized for this checkpoint in the current
chat. The closing message records their actual result; this file is prepared
before that containing commit and must not claim a future result.
See [Session Handoff](../runbooks/session-handoff.md).
