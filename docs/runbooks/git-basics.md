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
git mv planning-session-2026-10-22.zip docs/planning-session-2026-10-22.zip
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

## Undo cheat sheet

```bash
git restore <file>          # throw away unstaged edits to a file
git restore --staged <file> # unstage, keep the edits
git commit --amend          # fix the last commit message (before pushing only)
```

## Rules for this project

- Every commit and push is approved by the owner first.
- Secrets never enter a commit. If one ever does, rotate the key at the
  vendor; deleting the file in a later commit does not remove it from history.
