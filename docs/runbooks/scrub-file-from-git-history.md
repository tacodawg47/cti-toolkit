# Runbook: scrub a file out of git history (permanently)

Use this when a file that should never have been committed is already in the
repo's history (for example a conversation transcript or a leaked secret).
Deleting the file in a new commit is **not** enough — the old version stays in
history forever. You must rewrite history so the file never existed, then get
the rewritten history onto the remote.

> Rewriting history changes commit hashes. Do it when you are the only person
> working on the repo, or everyone else re-clones afterwards.

## 0. Back up first (always)

A rewrite is destructive. Make a full-history backup bundle you can restore
from, and remember the remote still holds the original until you force-push.

```bash
git bundle create ../cti-toolkit-pre-rewrite.bundle --all
git bundle verify ../cti-toolkit-pre-rewrite.bundle
```

To restore from it later if needed: `git clone ../cti-toolkit-pre-rewrite.bundle restored`

## 1. Install git-filter-repo (the right tool)

`git filter-branch` exists but is slow and error-prone; `git-filter-repo` is
the recommended tool.

```bash
python -m pip install --user git-filter-repo
```

On Windows the script may land somewhere not on PATH. Find it with:

```bash
python -c "import git_filter_repo as g; print(g.__file__)"
```

Then call it as `python "<that path>" ...` (shown below).

## 2. Make the working tree clean

filter-repo rewrites committed history, so stash or set aside any uncommitted
changes first. `git status` should show nothing before you continue.

## 3. Find every place the file lives in history

A file can sit at more than one path across history (ours was at the repo root
early on, then moved to `docs/`). List every blob + path for the name:

```bash
git rev-list --all | while read c; do git ls-tree -r "$c"; done | grep -i "<filename>" | sort -u
```

Note the blob id (the 40-char hash in the middle column). Stripping by blob id
removes the file from **every** path at once, which is more reliable than
listing paths.

## 4. Rewrite history

By blob id (preferred — catches all paths):

```bash
echo "<blob-id>" > blobs-to-strip.txt
python "<git_filter_repo.py path>" --strip-blobs-with-ids blobs-to-strip.txt --force
```

By path (if you prefer): `--path <path> --invert-paths --force`. Watch out:
this only removes that one path, so re-check step 3 afterwards.

filter-repo removes the `origin` remote on purpose (a safety feature) so you
review before pushing. We re-add it in step 6.

## 5. Verify it is really gone

```bash
# filename in any commit? (want: empty)
git log --all --oneline -- <path>
# blob in any tree? (want: nothing printed)
git rev-list --all | while read c; do git ls-tree -r "$c"; done | grep -i "<filename>"
# does the object still exist at all? (want: non-zero exit = gone)
git cat-file -e <blob-id>
```

## 6. Put the cleaned history on GitHub

Two options:

**A - force-push the same repo.** Lighter. Residual: GitHub may keep the old
commit cached and reachable only by its exact SHA until its background cleanup
runs; for a private repo that is very low risk (needs repo access AND the
exact SHA). You can ask GitHub Support to purge if you want certainty.

```bash
git remote add origin https://github.com/<you>/<repo>.git
git push --force origin main
```

**B - delete and recreate the repo.** Maximum certainty (a brand-new repo has
no cached copy). Delete the repo in GitHub settings, create a fresh empty one,
then `git remote add origin ...` and `git push -u origin main`. You do NOT
re-upload files by hand — the single push carries the whole cleaned history.

## 7. Prevent a repeat

- `.gitignore` patterns for transcript/export files.
- A `.githooks/pre-commit` hook that blocks them, enabled with
  `git config core.hooksPath .githooks`.
- Note: neither guard stops a **web upload** to github.com — that bypasses
  local git entirely. The only rule there is: never drag a transcript into the
  web uploader.
