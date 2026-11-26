# Static Review Before Dependency Adoption

Reviewed 2026-11-19. The operator asked whether strings, deobfuscation and
manual domain review would improve safety before adopting downloaded code.
This records a recommended extension, not an implemented universal scanner.
No new tool, dependency, artifact download or execution was needed.

Implementation update 2026-11-19: the operator approved the extension.
scripts/artifact_strings.py and the updated wheel auditor implement a
bounded strings/destination report, common encodings, archive guards,
baseline comparison and source locations. Source comparison now visits
all top-level packages/modules. The original assessment below remains the
design rationale; universal deobfuscation, binary emulation and a monitored
guest are not claimed as implemented. Exact bounds and commands are in
docs/runbooks/vetting-a-dependency.md. No new third-party dependency was added.

## Assessment

Yes. Static review and monitored isolated execution cover different gaps.
Malware can check for virtual machines, monitoring tools, user activity or
elapsed time and hide its behavior. Static inspection does not need that
malware branch to run. It can still miss encoded, encrypted, assembled or
remotely obtained content. Neither approach establishes harmlessness.

Download the exact release into quarantine/research staging for inspection
before installing, importing, executing or copying it into the application.
Some bytes must be retrieved for inspection. Do not promise inspection
before any copy exists anywhere. Include changed transitive dependencies,
vendored scripts, native components and release artifacts, not just the
repository README or top-level source package.

## Current Coverage

scripts/audit_wheel.py checks expected digests, RECORD consistency, startup
hooks, installed scripts, pure-wheel binary surprises and a selected package's
source comparison. It flags Python lines containing common network,
credential-access, dynamic execution and encoding primitives. Those findings
require human interpretation. It does not yet provide a complete domain
inventory, binary string extraction, universal deobfuscation or complete
multi-package source comparison. Its current archive-reading work also needs
resource limits before automatic broad decoding is added.

## Recommended Small Extension

1. Inventory the artifact's member names, types and sizes. Bound compressed
   bytes, expanded bytes, member count, per-member size, nesting and runtime.
   Do not extract executable content into import paths. Report skipped or
   unsupported files explicitly.
2. Read source/configuration text directly. Extract printable strings from
   binary/data members, including ASCII and UTF-16 where appropriate. Retain
   member path and line/byte offset, encoding and original artifact digest.
3. Decode common encodings with reviewed bounded operations: Base64, hex,
   escaped literals and simple constant concatenation. Preserve the original
   expression and transformation chain. Limit layers and expanded output.
   Never use eval/exec, import the package or run its supplied decoder.
4. Report hostnames, literal IPs and network destinations with their source
   locations, decoded/raw origin and call context. Separate documentation,
   tests/examples, runtime endpoints and unresolved candidates without hiding
   the raw inventory. Redact credentials and URL query values in reports.
5. Compare with the last reviewed release. Prioritize new destinations,
   changed startup/network paths, native code and unexplained obfuscation.
   A baseline is context, not a permanent trust grant.
6. Present the inventory for manual review. Do not visit discovered hosts or
   submit selectors to reputation services automatically. A domain mention
   does not establish a connection; a connection does not alone establish
   exfiltration. Trace what data reaches it and when.
7. Keep Defender, source/artifact comparison and monitored isolated testing.
   Unresolved sensitive paths remain a review blocker for that release;
   choose an alternative or investigate further rather than treating an
   incomplete scan as approval.

Useful review questions: Is a new HTTP call appropriate to this library?
Does it send only an intended query, or environment variables, local files
or credentials? Does it occur on import/startup? Can a server response become
code? Can repository text or tool output redirect our own agent's actions?

Expected documentation or API hosts can still be abused. Exfiltration may
use a reputable code host, messaging service, literal IP, proxy or a hostname
constructed at runtime. Looking up domain reputation is only one step.
Minification, Base64 data, compression and native extensions also have
legitimate uses. Do not flag every encoded string as malware.

## Deobfuscation Limits

Common encodings and simple script transformations are practical. Custom
virtual machines, packing, encrypted payloads whose keys arrive later and
multi-stage control flow may require specialist reverse engineering or
debugging. There is no general promise to deobfuscate arbitrary code fully.
Use a quick first pass on all changed artifacts and escalate suspicious or
unexplained cases, rather than making exhaustive reverse engineering of
every unchanged dependency a prerequisite.

Mandiant FLOSS is a relevant later candidate for compiled binaries. Its
README describes ordinary, stack, tight and decoded strings. Its theory
explains that decoding-function recovery uses emulation, so this is more
complex than reading bytes. It does not replace source review for Python
or every other language. Current usage docs describe optional pickle-based
workspace loading and a hosted results viewer; neither should be inherited
blindly. Keep untrusted workspaces unloaded and analysis/results local.
No FLOSS executable, package or sample was installed or run in this review.

## Sources and Reading Scope

- [MITRE T1497](https://attack.mitre.org/techniques/T1497/): sandbox and VM
  evasion, including system, user-activity and time checks.
- [MITRE T1027](https://attack.mitre.org/techniques/T1027/): encoding,
  encryption, packing and split payloads that limit plain strings searches.
- [FLOSS README](https://github.com/mandiant/flare-floss): full capability
  overview read, plus its complete theory and usage guides.
- [FLOSS theory](https://github.com/mandiant/flare-floss/blob/master/doc/theory.md)
  and [usage](https://github.com/mandiant/flare-floss/blob/master/doc/usage.md).

This is a methodology/source-document review, not a security audit or
release-artifact vetting of FLOSS. Any actual adoption retains the project's
dependency proposal, exact release review and installation approval steps.
