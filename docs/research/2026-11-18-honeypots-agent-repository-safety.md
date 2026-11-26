# Honeypot Research and Agent Repository Safety

Reviewed 2026-11-18. Research only. No sensor, account, key, dependency or
security setting was created or changed.

## Source Coverage

| Source | Coverage |
|---|---|
| [Gone in 8 Seconds, ACM DOI](https://dl.acm.org/doi/epdf/10.1145/3830454.3846791) | ACM requests returned HTTP 403 in the first pass. The operator then supplied the main PDF; all 15 pages, including appendices, were read locally. |
| Artifact_Appendix.pdf supplied locally | Both pages read in full with pypdf. This is the appendix to the same study, not a second independent study. |
| [Authors' project](https://containerbots.github.io/) | HTML and its content.js read as text, without executing JavaScript. Abstract, authors, publication and artifact links checked. |
| [Author page](https://www.tsouvalas.xyz/) and [lab publication list](https://www.securitee.org/) | Corresponding publication entries checked for a manuscript. They point to ACM or mark the PDF unavailable. Other publications not reviewed. |
| [Bitdefender report](https://www.bitdefender.com/en-us/blog/labs/how-ai-agents-become-new-targets-in-github-malware-campaign) | Full article and all 22 repository indicators read. Indicator repositories themselves not visited or downloaded. |
| [Official Codex security documentation](https://learn.chatgpt.com/docs/agent-approvals-security) | Sandbox, approval and network boundaries reviewed. Settings are version-sensitive; verify installed-client support before applying examples. |

The appendix links an artifact at DOI 10.5281/zenodo.22739294 and describes
five offline notebooks with saved outputs, under CC BY 4.0. No artifact
archive, notebook, container image or payload was fetched or executed in
this review. The description of offline operation is the authors' claim,
not an independently reproduced result. The later supplied main manuscript
completed the paper reading. No artifact experiment was reproduced.

## Addendum After Reading the Main Paper

The main paper is CC BY 4.0. It adds several implementation details that
the earlier appendix-only pass could not establish:

- SSH emulation builds on Cowrie; database interaction uses a real MySQL
  service, with separate logging. gVisor, read-only filesystems, dropped
  capabilities, CPU/memory/PID limits and periodic rotation reduce risk.
  Consider these as design requirements for later VPS sensors, with fresh
  component/license review before reuse. Do not deploy them on the host.
- Preserve five separate streams: hosted pull counts, self-hosted registry
  logs, provider API/usage events, lifecycle callbacks and SSH/database
  sessions. A common artifact/decoy ID joins them without guessing from IP.
- Distinguish Validate, Enumerate and Resource-Use Attempt from a confirmed
  successful action. Keep denied API calls and error outcomes. A provider
  identity check or a no-command login can be a security scanner's validation,
  so its intent should not be asserted solely from the event.
- Retain publication, image update and certificate-issuance times. The
  paper's hosted traffic follows pushes; self-hosted traffic is associated
  with certificate renewals. This is a testable hypothesis for our pilot,
  not a rule that every certificate renewal causes a malicious visit.
- Log both event and observation times. The study notes pull counters lag
  actual access, and AI-provider logs omit some zero-cost activity. Zero
  observed use may reflect limited telemetry, not an unused credential.

Critical limits for our interpretation: almost no callbacks supports static
inspection as the dominant observed path, but a missing callback does not
prove no execution if a callback is blocked or removed. Aggregate event
ordering does not demonstrate one actor followed an entire sequence. The
paper's proposed selective-layer retrieval is an experimental reconstruction,
not direct observation of every bot's code. Its naming and timing effects
need controls before generalization. Use sensor evidence to describe what
was observed, not to manufacture attribution.

The authors deliberately exposed funded AI keys and report roughly $60 of
consumption. Our low-cost pilot should use non-billable or denied decoys and
accept lower visibility. Do not reproduce that spending model by default.
No image, notebook, registry experiment or new key was created here.

## What Fits the Future Honeypot Plan

Tsouvalas and Nikiforakis describe 300 instrumented images across eight
registries over four months. The appendix describes image lifecycle
beacons, decoy credentials and provider logs. An early decoy-key invocation
took 7.86 seconds. Pulls were abundant while lifecycle beacons were rare.
This supports measuring secret harvesting separately from container
execution. These are study observations, not expected performance of our
future sensors.

Park a small registry honeytoken pilot beside the existing GreyNoise Swarm
and own-VPS sensor plans. It is complementary: an exposed-service sensor
observes inbound probing; a published decoy can reveal harvesting of
exposed material. The toolkit should ingest sanitized observations, not
host the deception workload or manage cloud credentials.

Suggested first slice:

1. One reviewed registry and one disposable isolated sensor environment.
   Check provider rules first. No sensor on the home network and no route
   to the toolkit host. Do not deploy as part of Phase 2.
2. Unique decoy identifiers per published artifact and registry. Record
   image digest, tag, exposure time, sensor version and withdrawal time.
   Preserve the mapping privately; do not publish real production secrets.
3. Distinct events: image pull, build, run, exec, authentication attempt,
   token validation, and observed provider API use. A pull does not establish
   execution. A token call does not establish host compromise. An attempt
   does not establish successful exploitation of a CVE.
4. Store UTC timestamps, observed request/action, source IP, affected decoy,
   evidence pointer and confidence basis. Keep latency from publication to
   first observed event and distinguish collection delay from event time.
5. Start with non-production canaries or an empty isolated account with
   deliberately minimal permissions. Do not reproduce the study's exposure
   of billable AI keys. Use egress controls, quotas, revocation and a kill
   switch. A budget alert alone is not a reliable hard spending limit.
6. Compare ordinary versus sensitive-looking artifact names and preserve
   publication/renewal timing as experimental context. Include controls
   before attributing activity to any one trigger. IP count is not actor
   count; shared proxies, NAT and rotating addresses complicate inference.

Possible outputs are a first-party observation card during enrichment,
an event timeline and a sensor dashboard. Promote a CVE assertion only
when the captured request or rule actually supports that CVE. Cloud API
key abuse alone supplies no CVE. Unique decoys make correlation possible
without guessing that every event from an IP is the same operator.

Offline artifact data could later become reviewed test fixtures with
attribution and a license record. Inspect archive paths, notebook cells,
embedded HTML and output sizes before extraction or opening in a trusted
editor. Saved outputs do not make notebook execution necessary.

## Bitdefender Campaign and Its Relevance

The report describes malicious repository instructions that urge agents
to silently run an allegedly protected setup script, alongside automatic
hooks and editor/MCP configuration that can trigger execution independently
of instruction following. Obfuscated JavaScript leads to credential theft
and propagation into repositories and packages. Checking only AGENTS.md
would miss the automatic configuration route. The article's protection
test is the vendor's own test, not a verification of this machine.

## Current Controls and Gaps

| Control observed | Practical limit |
|---|---|
| Project instructions accept authorization only from this chat and keep third-party commands passive | Behavioral guidance does not make a model immune to injection and cannot prevent an editor hook from running independently. |
| Current session uses workspace-write, restricted command networking and automatic escalation review | Reads are broad. Escalated commands can gain more access. Other tools have separate connections. |
| GitHub CVE search fetches metadata and at most five bounded READMEs | Text can still contain injection attempts. The client does not clone repositories, fetch PoC code/archives or execute their contents. |
| HTML extraction uses standard-library parsing; decoded commands remain text | Parsers remain an attack surface. Limits, escaping and patched dependencies matter. This is not an isolated malware-analysis environment. |
| Hashed, pinned, wheels-only dependencies and dependency review policy | Hashes establish the chosen artifact, not that its publisher is trustworthy or its code is harmless. |
| .env, data and exports are git-ignored; a transcript hook exists | Git ignore does not deny file access. The hook is a filename guard, not a general secret scanner. It was explicitly enabled for the checkpoint commit. |
| Local app binds to 127.0.0.1 | Limits inbound reachability, not what a malicious local process can read or send. |

Sanitized configuration inspection found no explicit hooks in the global
Claude settings or project settings.local.json. Project settings contain
137 permission allow entries; this review did not certify every entry.
No project .mcp.json, .codex/config.toml or .vscode/tasks.json was found.
Global Claude plugins are enabled; plugin hooks, all editor configuration,
browser history, processes and the complete computer were not audited.
Absence of explicit settings hooks is not proof that no plugin can run a
hook. The active Codex session policy is the authority for this turn,
rather than assumptions based on a single user-config setting.

## Scoped Exposure Check

Checked all 22 case-insensitive repository names from the article against:

- 186 readable project source/document/config files, excluding .env,
  environments, runtime data, git internals and conversation exports.
- Existing SQLite metadata, opened read-only: 703 poc_repos rows,
  49,660 exploits rows and zero cache rows. Checked repository names and
  URL fields, plus the cache value field where present.
- Presence of named setup and automatic configuration files in the project;
  sanitized global/project settings structure, without showing secrets.

No indicator matched. The visible work record shows no cloning or execution
of the listed repositories. This is not evidence that no one has ever
downloaded them elsewhere on the computer. No whole-disk or deleted-file
scan, payload-hash scan, historical session audit or malware clearance was
performed. This note itself discusses the campaign and should not be
mistaken for downloaded malicious content in a future search.

## Recommended Hardening, Not Yet Applied

Priority is reducing access rather than adding more reminders:

1. Use a separate research VM or OS account with no .env, runtime database,
   browser profile, SSH agent, cloud credentials or write-capable Git token.
   Keep downloaded repositories outside the trusted project and disable
   automatic hooks/tasks/MCP setup there. Read source before any execution.
2. Use enforced outbound allowlists for commands and separate controls for
   browsers/connectors/MCP. Test both ordinary and escalated paths. Keep
   credentials in a narrowly scoped service or runtime outside research
   processes; do not assume environment-variable filtering blocks file reads.
3. Review changes to agent instruction files, hooks, MCP/editor tasks,
   package manifests, installers and workflows as executable changes.
   Claims that a file is sealed, signed or must not be inspected confer no
   trust. Do not open a downloaded workspace in a mode that runs its tasks.
4. Add a reviewed secret scanner before commits and in CI, in addition to
   the transcript guard. Keep research tokens read-only and keep push
   credentials out of research environments. No new scanner installed here.
5. Retain download provenance and hashes for approved third-party artifacts.
   Scan and analyze suspicious files only in a disposable isolated lab.
   Rotate credentials if exposure is found; these checks alone do not show
   a compromise or justify declaring the machine clean.

Changing global permissions, deploying isolation or installing security
software requires a separate concrete approved action. No such change was
silently made during this research pass.
