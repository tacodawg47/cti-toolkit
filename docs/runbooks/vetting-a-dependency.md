# Runbook: Vetting a dependency before installing it

Written 2026-11-03. Companion to `dependency-policy.md`, which says WHAT the
rules are; this says HOW to check a package against them by hand, in the
order that catches the cheapest problems first. First used on pypdf.

The threat this guards against is a supply-chain attack: a package that is
hijacked on PyPI, a release that was built from something other than the
public repository, a typosquat with a similar name, or a maintainer account
takeover. No single check catches all of these; together they make each one
expensive for an attacker.

## 1. Identity (no download yet)

Read the PyPI JSON for the exact name you intend to type:

```bash
curl -s https://pypi.org/pypi/<name>/json | python -c "import json,sys; d=json.load(sys.stdin)['info']; print(d['name'], d['version'], d.get('license_expression') or d.get('license'), d.get('project_urls'))"
```

Confirm: the name is spelled exactly as the project spells it (watch for
`py-pdf` vs `pypdf` style confusions), the license is acceptable, the
source link goes to the organisation you expect, and `requires_dist` lists
only dependencies you are willing to vet too. A package with no required
dependencies is the easy case.

## 2. Release age and changelog

```bash
curl -s https://pypi.org/pypi/<name>/<version>/json | python -c "import json,sys; [print(u['filename'], u['upload_time'], u['size'], u['digests']['sha256']) for u in json.load(sys.stdin)['urls']]"
```

Policy: prefer a version at least a week old, so a hijacked release has
had time to be noticed and yanked. Read the changelog entries between the
version you pin and the latest, so you know what you are giving up.

## 3. Provenance

PyPI can hold a signed attestation that a file was built by a named
GitHub Actions workflow in a named repository (Trusted Publishing). Check:

```bash
curl -s https://pypi.org/integrity/<name>/<version>/<filename>/provenance
```

A JSON document naming the repository and workflow is good evidence that the
file came out of the public repository's CI. A 404 means no attestation was
uploaded; that is common and not damning on its own, it just means step 5
carries more weight.

## 4. Download without installing

```bash
# into a fresh, empty directory outside the project (downloads are untrusted data)
.venv/Scripts/python.exe -m pip download <name>==<version> --no-deps --only-binary=:all: -d <empty-dir>
```

`--no-deps` so only this one file arrives; `--only-binary` so it is a wheel
(a zip that is copied, never executed, at install time). Also fetch the
source archive for the same version tag from the project's GitHub:

```bash
curl -L -o <empty-dir>/src.zip https://github.com/<org>/<repo>/archive/refs/tags/<tag>.zip
```

and unzip it there. Do not run anything from these directories.

## 5. Audit the wheel

```bash
.venv/Scripts/python.exe -I scripts/audit_wheel.py <empty-dir>/<file>.whl --expect-sha256 <digest from step 2> --source <empty-dir>/<unzipped repo>
```

`-I` is isolated mode: Python ignores the current directory and environment,
so a planted module in the download folder cannot be imported by accident.
The script checks the digest, the wheel's own RECORD manifest, startup hooks
(`.pth`), binaries in a pure-Python wheel, installed scripts, and compares
every file in the wheel's package with the repository at that tag. It then
lists lines that use subprocess, eval/exec, pickle, sockets, base64
decoding, or long encoded strings. Those are leads: open each one and
decide whether a library of that kind should be doing that. A PDF library
needs zlib and may need base64 (PDF streams use both); it has no reason to
open a socket or spawn a process.

Exit status 1 means a hard finding: stop and investigate.

## 6. Known vulnerabilities

```bash
.venv-tools/Scripts/python.exe -m pip_audit --no-deps -r <(echo "<name>==<version>")
```

(or run pip-audit after step 7 against the full requirements.txt, which is
what the dependency policy already requires).

## 7. Pin and install

Only now add the name to `requirements.in` (pinned: `<name>==<version>`),
regenerate the hash-locked file, and install with hashes required:

```bash
.venv/Scripts/python.exe -m piptools compile --generate-hashes --output-file=requirements.txt requirements.in
```

```bash
.venv/Scripts/python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.txt
```

The hash in requirements.txt must equal the digest you verified in step 5.
From then on `--require-hashes` makes every future install fail if PyPI
ever serves a different file under that version.

## What this does not catch

A maintainer who turns malicious and commits the payload to the public
repository, properly, in a release that waits a week. Reading the diff
between versions (step 2, the changelog, and `git diff <old>..<new>` on
the repository) is the only defence for that, and it only scales to small
packages with small changes. That is one more reason for the policy's
first rule: few dependencies.
