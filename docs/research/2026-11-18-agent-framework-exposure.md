# Agent Framework Incident: Scoped Exposure Check

Checked 2026-11-18. This is a targeted local check, not a forensic clearance.

## Sources

Read the supplied [SecurityWeek article](https://www.securityweek.com/microsoft-agent-framework-releases-poisoned-with-credential-stealer/)
and followed its reports from [Wiz](https://www.wiz.io/blog/malicious-version-of-microsofts-agent-framework-published-to-pypi)
and [SafeDep](https://safedep.io/blog/microsoft-agent-framework-pypi-compromise).
The linked Microsoft issue returned 404, so Microsoft's investigation
details could not be verified there. No affected wheel was downloaded.

The researchers identify agent-framework 1.26.1 and 1.26.2 and Python
startup files agent_framework_meta.pth and af_runtime_diag.pth. Their
corresponding modules collect credentials and send them externally. These
are reported malicious versions, not a finding that all Microsoft packages
or the installed coding agent are compromised. Related publishing access
is not proof that each sibling package contains malware.

## Local Scope and Results

Used PowerShell to inspect package directories and startup-file names
without starting the inspected environments' normal Python. No .env,
token values or credential files were read. An initial sandbox read of the
base interpreter's site-packages was denied; the authorized read-only check
was repeated successfully with the required tool permission.

| Location | Observed distribution directories | Incident-name matches |
|---|---:|---:|
| Toolkit .venv | 55 | 0 |
| Toolkit .venv-tools | 29 | 0 |
| Standard base Python 3.12 site-packages | 5 | 0 |
| Standard Python 3.12 user site-packages | Directory absent | None checked there |

No agent-framework declaration appeared in requirements.in or the locked
requirements.txt. The project source/script search found no use of it.
The inspected startup-file inventory found only the existing setuptools
distutils-precedence.pth in the app venv. Its text was read passively.
No reported malicious startup filename or module name was present.

Conclusion: no indication that the inspected toolkit environments are
affected by these specific releases. This does not prove absence of other
malware, historical installation/removal, renamed payloads, an environment
elsewhere on disk, or another application's bundled runtime. No whole-disk
payload-hash scan, process analysis, DNS/proxy log review or credential-use
audit was performed. Do not recommend blanket key rotation based solely
on these negative scoped checks. If a malicious startup file is later
found, do not start that environment to query its version.

## Improvements Made Locally

The existing scripts/audit_wheel.py already rejected .pth files. Added hard
findings for sitecustomize.py and usercustomize.py, including relocated
wheel members. Updated audit commands to use a trusted interpreter with
both -I and -S: isolated mode alone still processes installed startup hooks.

Eight offline tests use synthetic wheels to check normal integrity, wrong
digest, modified RECORD, .pth, both customization hooks, a binary in a pure
wheel and network-code flagging. They do not install or import the contents.
The eight targeted tests passed with site initialization disabled.

Corrected dependency documentation: hashes identify approved bytes, not
benign intent; wheels avoid source build hooks but can carry executable
startup files or native code. Review the exact release artifact and every
changed transitive dependency, not just upstream source or a changelog.
Static review cannot certify malware-free behavior. Keep independent OS,
credential and network boundaries.

Prepared an offline Windows Sandbox example and manual isolation runbook.
Neither was launched. No security profile, feature, user account, firewall,
dependency, credential or system setting changed. No new commit or push
was made during this review.
