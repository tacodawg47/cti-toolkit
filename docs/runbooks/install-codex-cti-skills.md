# Install CTI Skills in Codex

Installed on 2026-11-18 from Liberty91LTD/cti-skills. These are local Codex skills, outside this repository.

Run from the project root in PowerShell. The installer refuses to overwrite existing skills. Do not rerun to update an existing installation.

```powershell
$items = Invoke-RestMethod -Uri 'https://api.github.com/repos/Liberty91LTD/cti-skills/contents/skills?ref=main'
$paths = @($items | Where-Object { $_.type -eq 'dir' } | ForEach-Object { $_.path })
& '.\.venv\Scripts\python.exe' "$env:USERPROFILE\.codex\skills\.system\skill-installer\scripts\install-skill-from-github.py" --repo Liberty91LTD/cti-skills --method download --dest "$env:USERPROFILE\.codex\skills" --path @paths
```

This downloads skill files without running the downloaded code or configuring API keys. Skills become available on the next turn.

## Remove Selected Integrations

On 2026-11-18, removed Sentinel, CrowdStrike, OpenCTI, ReversingLabs, and Liberty91 skills at the operator's request. Shared investigation skills remain and may mention these optional integrations.

To repeat this removal in PowerShell:

```powershell
$skillRoot = [System.IO.Path]::GetFullPath((Join-Path $env:USERPROFILE '.codex\skills'))
$names = @('lookup-sentinel', 'lookup-crowdstrike', 'crowdstrike-api', 'lookup-opencti', 'lookup-reversinglabs', 'reversinglabs-api', 'lookup-liberty91')
foreach ($name in $names) {
    $target = [System.IO.Path]::GetFullPath((Join-Path $skillRoot $name))
    if ([System.IO.Path]::GetDirectoryName($target) -ne $skillRoot) { throw 'Target outside skills folder' }
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
}
```

This removes skill files only. It does not revoke vendor credentials or change accounts.

## Local Source Profile Update, 2026-11-18

Updated the installed ioc-enrichment-workflow and indicator-pivoting skills and added a Local Source Profile section to the four first-hop investigation skills. Their source reference lives at:

`$env:USERPROFILE\.codex\skills\ioc-enrichment-workflow\references\available-sources.md`

The workflows use the project's existing credential names, add abuse.ch and keyless CIRCL routing, and reserve NVD, GitHub and VulnCheck for vulnerability follow-ups. GreyNoise is deferred. No credentials were read or tested. No application code changed. These are instruction changes, not newly implemented API clients. Check current endpoint docs and available clients before a live lookup.

Repeat offline validation in PowerShell from the project root:

```powershell
& '.\.venv\Scripts\python.exe' "$env:USERPROFILE\.codex\skills\.system\skill-creator\scripts\quick_validate.py" "$env:USERPROFILE\.codex\skills\ioc-enrichment-workflow"
& '.\.venv\Scripts\python.exe' "$env:USERPROFILE\.codex\skills\.system\skill-creator\scripts\quick_validate.py" "$env:USERPROFILE\.codex\skills\indicator-pivoting"
```

Upstream reinstalls may replace these local customizations. Keep the source reference consistent in both workflow folders when editing it.
