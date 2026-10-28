# Runbook: Python virtual environment

Written 2026-10-27.

## What a virtual environment is

A virtual environment ("venv") is a private copy of Python inside the project
folder. It has its own `python.exe`, its own `pip`, and its own `site-packages`
folder where installed packages go. Nothing it installs touches the system
Python or any other project. Deleting the `.venv` folder removes everything.

Why bother: two projects can need different versions of the same package,
and a package you are only trying out should not live on your machine
forever. The venv is also what makes "which packages does this project
need" an exact, reproducible list.

## Create it (once per machine)

```bash
# Windows, from the project folder. "py -3.12" picks the 3.12 interpreter.
py -3.12 -m venv .venv

# Linux / macOS
python3.12 -m venv .venv
```

`.venv/` is listed in `.gitignore`, so it is never committed. Each machine
creates its own.

## Use it

Either activate it, which puts its `python` first on your PATH for that
terminal session:

```bash
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# Windows Git Bash
source .venv/Scripts/activate

# Linux / macOS
source .venv/bin/activate
```

Your prompt gains a `(.venv)` prefix. `deactivate` leaves it.

Or skip activation and call the venv's interpreter by path, which is what
scripts and Claude do:

```bash
.venv/Scripts/python.exe -m pip list          # Windows
.venv/bin/python -m pip list                  # Linux
```

Always run pip as `python -m pip` so you are certain which Python it belongs to.

## Check it

```bash
.venv/Scripts/python.exe --version            # expect Python 3.12.x
.venv/Scripts/python.exe -m pip list          # fresh venv shows only pip
```

## Install the project's dependencies (after they exist)

Dependencies are pinned with hashes in `requirements.txt`. Install with:

```bash
.venv/Scripts/python.exe -m pip install --require-hashes --only-binary=:all: -r requirements.txt
```

See `docs/runbooks/dependency-policy.md` for why those two flags matter.

## If PowerShell refuses to run Activate.ps1

Windows blocks unsigned scripts by default. Allow local scripts for your
user only:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```
