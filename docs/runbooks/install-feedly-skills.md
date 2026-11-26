# Install Feedly CTI Skills

Installed 2026-11-19 from feedly/skills commit
`7914f02b6eaf2e46ececf75c3578a957d1737b10`.

All five packaged skills were installed in the user Codex skills folder:
intelligence-requirements-builder, cti-risk-reduction-report,
create-sigma-rule, map-attack-techniques, and track-cyberattack.
The standalone prompt library was not installed as skills.

## Review and Verification

The installer helper downloaded the selected skill directories at the pinned
commit into a temporary staging folder. The MIT license was preserved in each
installed skill. Existing skills were not overwritten. Every installed file
was SHA256-compared with staging. The manifest is in
`docs/review/2026-11-19-feedly-skills-manifest.sha256`.

Defender custom scan completed on the downloaded staging folder, reporting
no threats, exit 0. Platform: 4.18.26100.4-0. Antivirus and real-time
protection were enabled. Signature timestamp: 2026-11-19T10:19:43-05:00.

Review covered workflow instructions and a passive search of script network,
process, file and credential operations. This was not a full line-by-line
security audit. No downloaded helper or test was executed. No dependency
was installed. Helpers can fetch ATT&CK data, invoke external rendering and
Sigma tools, and write outputs. The tracker includes a CDN reference in its
HTML generation code; inspect generated output before assuming it is fully
offline. Project approval and dependency rules apply on first use, including
when upstream instructions propose automatic installation.

## Repeat by Hand

From the project root in PowerShell, choose a new empty staging directory.
The helper refuses existing destinations. Downloads and installation require
operator authorization. Use the pinned commit to reproduce this snapshot.

```powershell
$feedlyRef = '7914f02b6eaf2e46ececf75c3578a957d1737b10'
$feedlyStage = Join-Path $env:TEMP 'feedly-skills-review'
$feedlyNames = @('intelligence-requirements-builder', 'cti-risk-reduction-report', 'create-sigma-rule', 'map-attack-techniques', 'track-cyberattack')
$feedlyPaths = @($feedlyNames | ForEach-Object { 'skills/' + $_ })
& '.\.venv\Scripts\python.exe' "$env:USERPROFILE\.codex\skills\.system\skill-installer\scripts\install-skill-from-github.py" --repo feedly/skills --ref $feedlyRef --method download --dest $feedlyStage --path @feedlyPaths
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/feedly/skills/$feedlyRef/LICENSE" -OutFile (Join-Path $feedlyStage 'LICENSE')
& 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpCmdRun.exe' -Scan -ScanType 3 -File $feedlyStage
```

Check the installed Defender platform path before repeating. Inspect the
complete output for detections or failures. Passively review the snapshot
before copying. Do not run embedded install commands as review steps.

```powershell
foreach ($name in $feedlyNames) {
    $src = Join-Path $feedlyStage $name
    $dst = Join-Path (Join-Path $env:USERPROFILE '.codex\skills') $name
    if (Test-Path -LiteralPath $dst) { throw "Destination exists: $name" }
    Copy-Item -LiteralPath (Join-Path $feedlyStage 'LICENSE') -Destination (Join-Path $src 'LICENSE')
    Copy-Item -LiteralPath $src -Destination $dst -Recurse
    foreach ($file in Get-ChildItem -LiteralPath $src -Recurse -File) {
        $relative = [System.IO.Path]::GetRelativePath($src, $file.FullName)
        if ((Get-FileHash -LiteralPath $file.FullName).Hash -ne (Get-FileHash -LiteralPath (Join-Path $dst $relative)).Hash) { throw "Hash mismatch: $name/$relative" }
    }
}
```

Skills are available on the next turn. Installing them adds assistant
workflows, not features or dependencies to the CTI Toolkit application.
