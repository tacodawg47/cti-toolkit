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

Use a known-clean download environment, not a suspect interpreter. `--no-deps`
limits this request to one file; `--only-binary` avoids source builds.
A wheel can plant a startup hook that executes when Python next starts.
Downloading for inspection is different from installing or importing.
Also fetch the
source archive for the same version tag from the project's GitHub:

```bash
curl -L -o <empty-dir>/src.zip https://github.com/<org>/<repo>/archive/refs/tags/<tag>.zip
```

and unzip it there. Do not run anything from these directories.

## 5. Audit the wheel

```bash
.venv/Scripts/python.exe -I -S scripts/audit_wheel.py <empty-dir>/<file>.whl --expect-sha256 <digest from step 2> --source <empty-dir>/<unzipped repo>
```

`-I` isolates import paths and ignores Python-specific environment settings.
`-S` also disables site initialization, including installed `.pth` hooks.
`-I` alone does not disable those hooks. These flags do not repair a
compromised interpreter or provide OS isolation.
The script checks the digest, the wheel's own RECORD manifest, startup hooks
(`.pth`, `sitecustomize.py`, `usercustomize.py`), binaries in a pure-Python wheel, installed scripts, and compares
every file in the wheel's package with the repository at that tag. It then
lists lines that use subprocess, eval/exec, pickle, sockets, base64
decoding, or long encoded strings. Those are leads: open each one and
decide whether a library of that kind should be doing that. A PDF library
needs zlib and may need base64 (PDF streams use both); it has no reason to
open a socket or spawn a process.

Exit status 1 means a hard finding: stop and investigate.

### Strings and Network Destinations

The auditor now provides a bounded strings/destination report. It does not
automatically deobfuscate arbitrary packages. The design and limits are in
[the static review note](../research/2026-11-19-static-supply-chain-review.md).

Write a new local report for each exact artifact, without installing it:

```powershell
New-Item -ItemType Directory -Path data/release-review -Force
.venv/Scripts/python.exe -I -S scripts/audit_wheel.py <artifact.whl> --expect-sha256 <reviewed-digest> --source <reviewed-source-directory> --report data/release-review/<package-version>.json
```

On the next release, compare with a report that was actually reviewed:

```powershell
.venv/Scripts/python.exe -I -S scripts/audit_wheel.py <new-artifact.whl> --expect-sha256 <new-reviewed-digest> --source <new-reviewed-source-directory> --baseline data/release-review/<previous-version>.json --report data/release-review/<new-version>.json
.venv/Scripts/python.exe -I -S -m unittest discover -s tests -p test_wheel_audit.py -v
```

Use `.venv/bin/python` on Linux. Replace bracketed examples with real paths.
The report path must be a new .json file; prior reviews and artifacts cannot
be overwritten. Reports stay git-ignored and are not uploaded automatically.

The report includes member digests, destination candidates, source location,
transform chain, usage hints, new/removed hosts, changed/removed members,
pattern hits, coverage issues and at most 200 string previews. Decoded
Python literals retain their source line; decoded payload offsets identify
the recovered content rather than claiming a direct original byte mapping.
Python attribute names are not bare-domain evidence. Test/doc hints are
heuristics, not trust decisions. Domain candidates need manual validation.

Limits: 256 MiB archive input and declared expanded content, 64 MiB per
member, 10,000 members, 1,000:1 declared expansion ratio and a soft 30-second
processing deadline. Reads enforce the member cap. Strings, decoded output
and syntax reconstruction have separate limits: 10,000 strings, 2,000
destination records, 256 decode attempts, 64 KiB per decoded result, 4 MiB
decoded total and at most two decoding layers. Python syntax reconstruction
is limited to 128 KiB and 10,000 syntax nodes. Nested archives are not
expanded. Fatal archive guards stop before member analysis.

ASCII and UTF-16 strings, Python constant strings/concatenation, Base64,
hex and bounded gzip/zlib are supported. These transforms do not execute
artifact code. XOR solving, custom unpacking and universal deobfuscation are
not supported. An explicit coverage-limit finding fails the run; review
the gap rather than assuming a zero host count clears the artifact.
The deadline is cooperative, not an OS-enforced CPU/memory sandbox. Keep
hostile samples in an isolated worker. Context redaction is best effort;
reports can still contain sensitive paths or text and require review before
sharing. No extracted host is visited or sent to a reputation service.

During manual review, record network destinations with member path,
line/offset, raw or decoded origin and what data reaches the network call.
Prioritize new or changed destinations compared with the last reviewed
release. Documentation URLs and examples are context, not proof a package
contacts them. Conversely, a reputable host is not proof that sending
credentials there is appropriate. Do not visit or submit discovered hosts
automatically. Keep unresolved decoding and unsupported files explicit.

Decode only using reviewed bounded operations. Never run a downloaded
package or its supplied decoder to make strings visible on the host.
Keep Defender and monitored isolated testing as separate checks. Ordinary
encoding can be legitimate; unexplained sensitive behavior needs review.

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

A matching repository, digest or attestation does not prove benign code.
The publisher or build process can itself be compromised. Review diffs and
exact release artifacts, but static patterns miss obfuscation, native code,
delayed activation and behavior fetched later. Dynamic tests cover only
the observed run. Neither a passing scanner nor an AI review certifies an
artifact malware-free. Use least privilege, credential separation and
network containment as independent controls. Keep dependencies few.

Apply the same review to updates and all changed transitive dependencies.
Never import a package or start a suspect environment just to check its
version. Inspect dist-info/METADATA and startup files passively first. The
2026-11-18 agent-framework incident check is recorded in the journal.
