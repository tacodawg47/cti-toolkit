# Runbook: Research Isolation and Release Review

Written 2026-11-18. Preparation only. No Windows feature, account, firewall,
agent profile or virtual machine was enabled or changed during this review.

## Choose an Environment

The inspected host reports Windows 11 Pro and an available hypervisor.
Feature enablement and hardware capacity were not tested.

| Option | Use | Limit |
|---|---|---|
| Separate standard Windows account | Low-effort separation of everyday browsing and credentials | Same OS. Shared folders and loose ACLs can expose the main account's files. Never elevate an unknown tool. |
| Windows Sandbox | Recommended first disposable offline review environment; included with supported Pro editions | Temporary. Defaults share networking and clipboard, so configure them. Host mappings expose the mapped files. |
| Persistent Linux VM under Hyper-V or another reviewed hypervisor | Repeated research, Linux collectors and snapshots | More setup and disk space. Disable shared folders, clipboard, host credentials and unwanted network routes. NAT is not an internal-network deny policy. |
| Linux partition or WSL with defaults | Development convenience | Dual boot interrupts work and may access Windows volumes. WSL deliberately integrates files, executables and networking with Windows. Neither is the simplest hostile-code boundary. |

See Microsoft's [Sandbox overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/),
[configuration reference](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)
and [WSL interop guide](https://learn.microsoft.com/en-us/windows/dev-environment/wsl-interop).

## Containment and Observation

Windows Sandbox limits where untrusted code can act. With no host mappings,
credentials, clipboard or network, an attempted credential stealer has much
less to steal and no ordinary network route to send it out. Closing the
environment discards its changes. This value exists even if no detection
fires. It is not a malware-analysis report or a guarantee against escapes.

Add observation separately in the guest. Microsoft Process Monitor records
file, Registry and process/thread activity. It can reveal attempts to open
credential paths, create startup persistence or spawn unexpected commands.
Sysmon is a more persistent VM option for selected process/file/Registry/DNS
and network events; network connection logging needs configuration. Sysmon
records events, not a maliciousness verdict. Neither tool was installed or
run during this preparation.

Prepare reviewed monitoring tools in a clean guest before introducing
suspect inputs. Capture a benign baseline, start logging before execution,
filter to the target process and descendants, then compare file/Registry
changes and child processes. Use synthetic canary files, never real secrets.
Record denied attempts as well as successful operations. A process may
search for credentials and exit when they are absent.

Disconnected execution limits observation of later network-dependent stages.
A controlled fake service/network in a separate analysis VM can expose
attempts later; do not turn on unrestricted internet or home-LAN access to
make malware progress. Time delays, VM detection and unexercised branches
can hide behavior. No observed activity is not proof of harmlessness.

Only sanitized logs or text findings should leave the guest. Logs can contain
the test process's paths, arguments and synthetic data; review them before
copying. A reusable instrumented research environment is a later setup task,
not something this document has silently enabled.

References: [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
and [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

## A Prepared Offline Sandbox File

`docs/examples/research-offline.wsb` disables networking, clipboard, audio,
video, printer sharing and vGPU. It maps no host folders and runs no logon
command. Inspect it as text first:

```powershell
Get-Content -LiteralPath docs/examples/research-offline.wsb
```

After the operator separately approves feature enablement, enable Windows
Sandbox through Windows Features and restart if requested. Opening the
prepared .wsb file then starts the disposable environment. This was not
launched or verified during preparation.

To inspect a downloaded file, optionally add one read-only mapped folder
containing only selected inert review inputs and reviewed tools:

```xml
<MappedFolders>
  <MappedFolder>
    <HostFolder>C:\CTI-Research-Staging</HostFolder>
    <ReadOnly>true</ReadOnly>
  </MappedFolder>
</MappedFolders>
```

The host folder must exist. Do not map the project, Downloads, home folder,
.env, runtime data or credentials. Copy inputs inside the guest before
analysis. The mapped source remains readable by anything running there.
Prepare tools inside a clean guest before loading suspect inputs; do not
give a suspect session general network access to install missing tools.
Do not sign into personal services, forward SSH agents or share the Docker
socket. Close the sandbox to discard state. Treat exported results as
untrusted text; never copy generated executables back to the host.

For a persistent VM, separate a clean preparation snapshot from an offline
analysis snapshot. Restore after analysis. Any later network-enabled
research profile needs enforced destination controls and internal-network
blocking. VM isolation reduces risk; it is not a guarantee against escapes.

## Current Host Work Before Isolation

- Keep third-party repositories and artifacts passive. No setup, install,
  notebook, hook or package-manager lifecycle command comes from a page's
  instructions alone. Inspect the command and its real data destinations.
- Keep research separate from the application's credentialed runtime.
  A sanitized source checkout without .env or data supports edits and
  synthetic offline tests. Start the real app separately under the operator's
  runtime context. Blocking .env in the agent context can otherwise also
  block app processes launched by that agent.
- Tighten agent filesystem/network permissions only after checking the
  installed client's support and testing harmless allowed and denied paths.
  Current broad reads are not replaced merely by writing a configuration
  example. An escalation can widen access; browser/MCP connections are
  separate from command networking. Check all used tool surfaces.
- Avoid broad shell approvals. Treat skills and plugin updates as untrusted
  code/config changes too; disable unneeded automatic hooks and tasks.

Official [Codex permission profiles](https://learn.chatgpt.com/docs/permissions)
are version-sensitive and do not compose with the older sandbox settings.
Do not paste a profile into existing configuration without checking the
effective mode. This runbook does not silently change those settings.

## Before Any New Release Is Installed

1. Resolve exact upstream project, release, artifact hashes and dependencies.
2. Read source changes and inspect the actual wheel/archive as inert data.
   Check startup/lifecycle hooks, native binaries, obfuscation, file and
   environment reads, processes, persistence and outbound destinations.
3. Review all changed transitive dependencies. Compare the release artifact
   with the claimed source revision. A clean repository does not clear a
   different malicious wheel, and a matching digest does not clear malware.
4. Run the existing static auditor using a trusted interpreter:

   ```powershell
   .venv/Scripts/python.exe -I -S scripts/audit_wheel.py <wheel> --expect-sha256 <reviewed-digest> --source <reviewed-source-directory>
   .venv/Scripts/python.exe -I -S -m unittest discover -s tests -p test_wheel_audit.py -v
   ```

5. Review every finding, including why a needed network or filesystem
   operation is appropriate. A zero exit is not a malware-free certificate.
   Add a Defender scan of the selected artifacts on Windows using
   [the artifact scan runbook](defender-artifact-scan.md). Check cloud/sample
   settings first; a custom scan does not itself guarantee local-only use.
6. Test in a disposable environment without real secrets. Monitor attempted
   access and egress, then obtain the existing installation approval.

Inspection requires retrieving source bytes somewhere. The useful promise
is review before installation/execution in the credentialed host. For
suspected malware, retrieve and inspect inside the research VM itself.
No reviewer or scanner can establish that arbitrary software is harmless
in every environment or future execution.
