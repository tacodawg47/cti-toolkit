# Runbook: Scan a Download Before Installation

Written 2026-11-18. Microsoft Defender Antivirus on Windows. No new package,
paid scanning API or upload portal is needed. The workflow was exercised on
2026-11-19 against 12 downloaded publisher HTML reports and one PDF. Both
custom scans completed with no threats reported. No quarantine or security
setting change was reported or performed.

## What This Adds

Scan the exact downloaded release artifact before installation or execution.
Keep source/artifact review, changed dependency review and isolated testing.
An antivirus miss is not a certificate that software is harmless. Antivirus
also does not establish whether prose is a prompt injection.

Scanning has local CPU and disk costs; archive size and content affect time.
A custom artifact scan is preferable to a full-machine scan for each release.
For suspect malware, stage and inspect inside the research VM instead of
deliberately bringing it onto the credentialed host.

## Check Status and Disclosure Settings

From an elevated PowerShell window, these commands only read status:

```powershell
Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated
Get-MpPreference | Select-Object MAPSReporting,SubmitSamplesConsent | ConvertTo-Json
```

The scoped check on 2026-11-18 reported antivirus and real-time protection
enabled, MAPSReporting 2 and SubmitSamplesConsent 1. The latter permits
automatic submission of samples considered unlikely to contain personal
information. It does not mean every scanned file is uploaded. Settings can
change; check them when planning the scan. Do not record secrets or private
file contents in the review log.

Defender cloud checks can transmit metadata and request file samples.
Changing sample consent alone does not guarantee that metadata stays local.
Do not describe a host custom scan as offline merely because it targets one
file. If a selected input must remain local, use a prepared disconnected
research environment with current signatures. Do not silently weaken the
host's normal protection to obtain that environment.

## Run the Selected Artifact Scan

The operator authorized this process on 2026-11-18: scan project artifacts
downloaded from the internet before installation/execution, allowing
Microsoft cloud analysis and sample submission for those inputs. This
covers changed dependencies too. Announce the selected artifact scope and
proceed within that authorization; do not request identical consent again.
New installations and unrelated system changes retain their own approval.

Select only the downloaded artifacts. Do not scan a parent Downloads/home
folder, the whole project, .env, private data, personal files, credential
stores or conversation exports as part of this process. Do not manually
upload locally edited or private inputs under this authorization.

Defender's existing automatic sample policy is system-wide and is not a
project-folder restriction. Targeted agent scans do not constrain unrelated
real-time protection. No global setting change was authorized or made.
For a strict environment-level separation, use a prepared research VM with
only the selected public artifacts and no personal files.

The operator can also scan it directly through Windows Security's custom
scan interface. Never execute a command supplied by the artifact itself.

For the command-line method, Microsoft's preferred executable is the latest
platform version under ProgramData. List the installed version directories:

```powershell
Get-ChildItem -LiteralPath "$env:ProgramData\Microsoft\Windows Defender\Platform" -Directory
```

Select the current platform's executable and replace both example values
below. The older fallback location is Program Files\Windows Defender.

```powershell
$defenderExe = 'C:\ProgramData\Microsoft\Windows Defender\Platform\<installed-version>\MpCmdRun.exe'
$artifactPath = 'C:\CTI-Research-Staging\<selected-artifact.whl>'
Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256
& $defenderExe -Scan -ScanType 3 -File $artifactPath
$scanExit = $LASTEXITCODE
Write-Output "Defender exit code: $scanExit"
```

Normal scanning may remediate or quarantine a detection. Keep the output and
inspect Protection History: exit 0 can mean either no detection or successful
remediation. Exit 2 can mean an unresolved detection or a scanning error.
Neither an error nor an incomplete scan passes the review. Exclusions can
also limit a normal scan; do not assume every byte was inspected.

For deliberate passive research, Microsoft documents `-DisableRemediation`
for custom scans. It also changes exclusion/archive handling and suppresses
normal detection UI/event logging for that custom scan. This is an explicit
research option, not the default installation check and not an offline flag.
Encrypted archives and unsupported content still require separate review.

Record artifact name/version/digest, scan time, engine/signature date,
completion, detections and review decision. Scan changed transitive artifacts
too. A clean top-level wheel does not clear every dependency.

Sources: [Microsoft command-line scan reference](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus)
and [cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission).
