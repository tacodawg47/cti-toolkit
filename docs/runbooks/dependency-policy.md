# Runbook: Installing dependencies safely

Written 2026-10-27. Companion to the policy section in ROADMAP.md.

## The threat

Supply-chain attacks on package registries take a few shapes:

- **Typosquats**: a package named `requestss` or `python-dotenv2` that looks
  like the real one.
- **Hijacked releases**: a maintainer's account is phished and a malicious
  version of a real package is published for a few hours or days.
- **Install-time code**: source packages (sdists) run `setup.py` during
  install, so a malicious package can execute code before you import it.
- **Dependency confusion**: a public package shadows an internal name.

Each defence below closes one of those doors.

## 1. Choose carefully

Copy the package name from its PyPI page, not from memory or a blog. On the
PyPI page check: the project links point to the GitHub repository you expect,
the release history is long, and the latest release is not brand new. Prefer
packages that are well known: FastAPI, httpx, pydantic, Jinja2 are all
mainstream with large maintainer teams.

## 2. Pin with hashes

`requirements.in` lists what we want, loosely:

```
fastapi
uvicorn
httpx
```

`requirements.txt` is generated from it with every version pinned and every
file's SHA-256 recorded:

```bash
.venv/Scripts/python.exe -m pip install pip-tools
.venv/Scripts/python.exe -m piptools compile --generate-hashes requirements.in -o requirements.txt
```

Install only from the locked file:

```bash
.venv/Scripts/python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.txt
```

`--require-hashes` makes pip refuse any file whose hash differs from the
lock, so a swapped or hijacked upload cannot install. `--only-binary=:all:`
refuses source packages, so nothing runs build code on your machine.

## 3. Audit

`pip-audit` (maintained by the Python Packaging Authority) checks installed
packages against known-vulnerability databases:

```bash
.venv/Scripts/python.exe -m pip install pip-audit
.venv/Scripts/python.exe -m pip_audit -r requirements.txt
```

On GitHub, enable Dependabot alerts: repository Settings, then Security,
then "Dependabot alerts". GitHub then emails you when a pinned version gets
a published vulnerability. Free on private repositories.

## 4. Upgrade deliberately

Never `pip install --upgrade` on a whim. To move a package forward: read its
changelog, regenerate `requirements.txt`, review the diff of the lock file,
run the tests, then commit. Waiting a week after a release is a cheap way to
let the community catch a hijacked version first.

## 5. Isolate the risky stuff

The app's venv holds only the app's dependencies. Third-party OSINT tools
get their own venv each (`tools/<name>/.venv`) or, later, their own
container. Anything from a small or unfamiliar repository runs inside a
VirtualBox VM first, where a bad package can only damage a disposable disk.

## 6. Check the state of your venv any time

```bash
.venv/Scripts/python.exe -m pip list                 # what is installed
.venv/Scripts/python.exe -m pip check                # broken dependency links
.venv/Scripts/python.exe -m pip show <package>       # where a package came from
```
