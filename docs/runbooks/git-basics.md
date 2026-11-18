# Runbook: Git basics and how this repository was set up

Written 2026-10-23. Commands are for Git Bash or PowerShell on Windows; they
are identical on Linux.

## The four places a change can be

| Place | What it is | Command that moves a change here |
|---|---|---|
| Working folder | The files on your disk, as you see them | editing a file |
| Staging area | A list of changes marked for the next snapshot | `git add <file>` |
| Local history | Snapshots (commits) stored in the hidden `.git` folder | `git commit -m "message"` |
| GitHub (remote) | A copy of the history on github.com | `git push` |

`git status` shows which place each change is in. Read it before every commit.

## How this folder was linked to the GitHub repository

The folder already existed with the planning files, and the repository on
GitHub already had copies of them (uploaded through the browser). These
commands made the folder a clone of the repository without re-downloading.

```bash
# 1. Turn the folder into a git repository with a branch called main
git init -b main

# 2. Tell git who is making commits (stored for this repository only)
git config user.name "tacodawg47"
git config user.email "linuxtaco703@gmail.com"

# 3. Register the GitHub repository under the nickname "origin"
git remote add origin https://github.com/tacodawg47/cti-toolkit.git

# 4. Download the history from GitHub (no files change yet)
git fetch origin

# 5. Point the local main branch at the downloaded history.
#    Safe here only because the local files were byte-identical to GitHub's.
git reset --hard origin/main

# 6. Move a file in a way git records as a rename
git mv notes.md docs/notes.md
```

The usual way to get a repository onto a new machine is one command instead:

```bash
git clone https://github.com/tacodawg47/cti-toolkit.git
```

Git Credential Manager (installed with Git for Windows) handled the GitHub
sign-in the first time and remembers it, so later pushes do not prompt.

## .gitignore: the "do not pack" list

`.gitignore` is a text file listing filename patterns git must never track.
Our list covers the secrets file `.env`, Python cache folders, the local
database, Telegram session files, and `docs/exports/` for future session
exports. Check whether a file is ignored with:

```bash
git check-ignore -v .env
```

If it prints the file and the matching rule, git cannot stage it.

## .env and .env.example

`.env` holds real API keys as `NAME=value` lines and is ignored.
`.env.example` has the same names with blank values and is committed, so
anyone cloning the project knows which keys to supply. Never put a real
value in `.env.example`.

## Making a commit, step by step

```bash
# See what changed
git status

# Stage specific files (prefer naming files over "git add ." so you see what goes in)
git add .gitignore .env.example CLAUDE.md ROADMAP.md docs/

# Review exactly what is staged
git diff --staged --stat

# Snapshot it with a message in the imperative mood ("Add", "Fix", "Move")
git commit -m "Short summary line" -m "Optional longer explanation."

# Send the new commit to GitHub. -u links the branches so later pushes are just "git push".
git push -u origin main
```

Useful checks:

```bash
git log --oneline          # history, newest first
git diff                   # unstaged changes
git show --stat HEAD       # what the last commit contained
git remote -v              # where "origin" points
```

### Stage one edit in a shared file

When the journal has separate edits, stage the section for the current
commit. From the project root:

```bash
git diff -- docs/journal.md
git add -p -- docs/journal.md
git diff --cached -- docs/journal.md
git diff -- docs/journal.md
```

In `git add -p`, answer `y` for the section you want in the commit and `n`
for the others. The first diff after staging shows what the commit will
contain. The second shows what is still in your working folder. Review the
full staged file list with `git diff --cached --stat` before committing.

For the vulnerability catalog checkpoint, stage the Phase 2 roadmap
sections and the new build note using the same hunk review:

```bash
git add -p -- ROADMAP.md docs/journal.md
git add -- app/modules/vulnerability_intelligence/ app/templates/base.html app/templates/vulnintel/ docs/runbooks/vulnerability-intelligence.md tests/test_vulnintel.py
git diff --cached --check
git diff --cached --stat
git commit -m "Add vulnerability catalog and Microsoft Patch Tuesday triage"
git log -1 --oneline
git status --short
```

For the action badges and review checkpoint, review the action and review
hunks in the roadmap and journal, then stage the module, templates, runbook,
and tests:

```bash
git add -p -- ROADMAP.md docs/journal.md
git add -- app/modules/vulnerability_intelligence/ app/templates/vulnintel/ docs/runbooks/vulnerability-intelligence.md tests/test_vulnintel.py
git diff --cached --check
git diff --cached --stat
git commit -m "Add vulnerability action badges and review history"
git log -1 --oneline
git status --short
```

For the Supply Chain checkpoint, stage the Phase 2 Supply Chain roadmap
edits and the first build note in the journal:

```bash
git add -p -- ROADMAP.md docs/journal.md
git add -- app/modules/vulnerability_intelligence/feeds/supply.py app/modules/vulnerability_intelligence/http.py app/modules/vulnerability_intelligence/routes.py app/modules/vulnerability_intelligence/store.py app/modules/vulnerability_intelligence/supply_chain.py app/templates/vulnintel/layout.html app/templates/vulnintel/supply_chain.html docs/runbooks/vulnerability-intelligence.md tests/test_vulnintel.py
git diff --cached --check
git diff --cached --stat
git commit -m "Add supply chain malware advisory triage"
git log -1 --format='%h %s'
git status --short --untracked-files=all
```

The Exploitation Reports checkpoint was committed as `80082c7`.
Stage the Phase 2 report entry in the roadmap and the new build and
handoff entries in the journal. Check the staged diff before committing:

```bash
git add -p -- ROADMAP.md docs/journal.md
git add -- app/modules/vulnerability_intelligence/reports.py app/modules/vulnerability_intelligence/routes.py app/modules/vulnerability_intelligence/store.py app/templates/vulnintel/cve.html app/templates/vulnintel/report.html app/templates/vulnintel/reports.html app/templates/vulnintel/search.html app/templates/vulnintel/view.html app/templates/vulnintel/views.html docs/runbooks/vulnerability-intelligence.md tests/test_vulnintel.py
git diff --cached --check
git diff --cached --stat
git commit -m "Track exploitation reports before CVE assignment"
git log -1 --oneline
```

The Edge and Perimeter checkpoint was committed as `f43350d`.
Stage the view 8 roadmap hunk and its build entry in the journal.
The other files can be staged in full:

```bash
git add -p -- ROADMAP.md docs/journal.md
git add -- app/modules/vulnerability_intelligence/edge.py app/modules/vulnerability_intelligence/routes.py app/modules/vulnerability_intelligence/tables.py app/modules/vulnerability_intelligence/views.py app/templates/vulnintel/_cve_table.html app/templates/vulnintel/_edge_matches.html app/templates/vulnintel/cve.html app/templates/vulnintel/view.html app/templates/vulnintel/views.html docs/runbooks/vulnerability-intelligence.md tests/test_vulnintel.py
git diff --cached --check
git diff --cached --stat
git commit -m "Add Edge and Perimeter vulnerability view"
git log -1 --oneline
git status --short --untracked-files=all
```

For the vulnerability triage checkpoint (`5682ee4`), stage the
triage roadmap hunks and journal build entry separately:

```bash
git add -p -- ROADMAP.md docs/journal.md
git add -- app/modules/vulnerability_intelligence/feeds/msrc.py app/modules/vulnerability_intelligence/routes.py app/modules/vulnerability_intelligence/service.py app/modules/vulnerability_intelligence/signals.py app/modules/vulnerability_intelligence/tables.py app/modules/vulnerability_intelligence/views.py app/templates/vulnintel/_cve_table.html app/templates/vulnintel/_filterbar.html app/templates/vulnintel/cve.html app/templates/vulnintel/view.html docs/runbooks/vulnerability-intelligence.md tests/test_vulnintel.py
git diff --cached --check
git diff --cached --stat
git commit -m "Improve vulnerability triage signals and filters"
git log -1 --oneline
```

For Exploited and Unfixed with Red Hat VEX (`ab42e64`), stage the
view 7 roadmap hunk and its build entry. The automated commit used
`git apply --cached` with only those two hunks. To repeat this by hand,
use the interactive staging command below and leave the other edits
unstaged.

```bash
git add -p -- ROADMAP.md docs/journal.md
git add -- app/modules/vulnerability_intelligence/feeds/redhat.py app/modules/vulnerability_intelligence/feeds/__init__.py app/modules/vulnerability_intelligence/routes.py app/modules/vulnerability_intelligence/store.py app/modules/vulnerability_intelligence/views.py app/templates/vulnintel/_vendor_vex.html app/templates/vulnintel/_cve_table.html app/templates/vulnintel/cve.html app/templates/vulnintel/feeds.html app/templates/vulnintel/view.html app/templates/vulnintel/views.html docs/runbooks/vulnerability-intelligence.md tests/test_vulnintel.py
git diff --cached --check
git diff --cached --stat
git commit -m "Add Exploited and Unfixed view with Red Hat VEX"
git log -1 --oneline
git status --short
```

### Push an approved checkpoint

Name the approved commit explicitly so Git pushes that checkpoint even if
another local commit has since been made. For the vulnerability evidence
checkpoint, the command was:

```bash
git push origin bc38a5e:refs/heads/main
```

For the next approved checkpoint, replace `bc38a5e` with its commit ID.
Confirm that the output reports the commit was sent to `main`.

For the vulnerability catalog and Patch Tuesday checkpoint, these commands
push the approved commit and confirm that both checks return the same ID:

```bash
git push origin 0d913cb:refs/heads/main
git ls-remote --exit-code origin refs/heads/main
git rev-parse 0d913cb
```

For the action badges and review checkpoint:

```bash
git push origin c16e07a:refs/heads/main
git ls-remote --exit-code origin refs/heads/main
git rev-parse c16e07a
```

The Edge and Perimeter push also included Supply Chain and Exploitation
Reports. The remote and local checks returned the same commit ID.

```bash
git log --oneline c16e07a..f43350d
git push origin f43350d:refs/heads/main
git ls-remote --exit-code origin refs/heads/main
git rev-parse f43350d
```

## Undo cheat sheet

### Save the Phase 2 Evidence Checkpoint

The operator approved this checkpoint commit and push in the same request.
The checkpoint includes the pending Phase 2 coverage work, passive C2
feed browser, tests and documentation. Inspect the paths first. Stage only
the reviewed project paths; do not add `.env`, `data/`, exports or session
files. From the project root:

```bash
git status --short
git diff --stat
git add -- AGENTS.md CLAUDE.md ROADMAP.md app docs/journal.md docs/runbooks docs/research/2026-11-15-feedly-workflow-review.md docs/review/2026-11-17-phase2-coverage-audit.md tests
git diff --cached --check
git diff --cached --stat
git -c core.hooksPath=.githooks commit -m "Advance Phase 2 coverage and unify vulnerability evidence"
git rev-parse HEAD
git push origin HEAD:refs/heads/main
git ls-remote --exit-code origin refs/heads/main
```

The automated stage command enumerates the exact reviewed paths before
passing them to `git add`. The equivalent grouped command above is only
appropriate after reviewing everything in those directories. The commit
command explicitly runs the transcript hook without changing local Git
configuration. Never bypass that hook. Compare the remote SHA with the
local commit SHA. New work after the push remains local until another
commit and push are approved.

```bash
git restore <file>          # throw away unstaged edits to a file
git restore --staged <file> # unstage, keep the edits
git commit --amend          # fix the last commit message (before pushing only)
```

## Rules for this project

- Every commit and push is approved by the owner first.
- Secrets never enter a commit. If one ever does, rotate the key at the
  vendor; deleting the file in a later commit does not remove it from history.
