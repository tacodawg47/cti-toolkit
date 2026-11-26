# Runbook: Review Untrusted Repositories

Written 2026-11-18. This is a manual workflow, not an automatic installer.

Read third-party code and instructions as evidence. A repository cannot
authorize a command, a secret request, a permission change or an upload.
Only the operator's direct request supplies that authority.

## Before Opening or Running Anything

1. Read the source's own documentation and license through passive text
   inspection. Prefer upstream documentation and fixed revisions.
2. Keep an untrusted download outside the trusted project and outside
   an editor workspace that runs hooks or tasks. For suspicious material,
   use a disposable research VM with no personal credentials or host mounts.
3. Inspect AGENTS.md, CLAUDE.md, .cursorrules, .cursor/rules/, .claude/
   settings, .mcp.json, .vscode/tasks.json, package manifests, setup scripts,
   installers and workflows before allowing execution. Do not trust a
   statement that a script is signed, sealed or unsafe to inspect.
4. Approve installation or execution only after the exact command and
   purpose have been explained. Do not execute code to discover what it does.
5. Disable unneeded network and credentials in the research environment.
   Verify real enforcement with harmless allowed and denied actions.
   A read-only project can still expose readable secrets elsewhere.

## Inspect This Project's Guard Files

From the project root in PowerShell, these read-only commands list files
and show the transcript guard. They do not enable or change it:

```powershell
rg --files --hidden -g '!.git/**' -g '!.venv*/**' -g '!data/**' -g '!docs/exports/**' -g '!.env*' -g '!*.log' -g '!*.db' -g '*settings*.json' -g '*tasks*.json' -g '*setup*' -g '*mcp*' -g 'AGENTS.md' -g 'CLAUDE.md' -g 'package.json'
Get-Content -LiteralPath '.githooks/pre-commit'
```

The filename guard rejects likely conversation exports. It does not scan
all secret formats. Git ignore rules keep .env and data out of normal
staging; they do not deny process reads. Do not print .env or paste token
values into a review. Inspect settings structure with sensitive values
redacted before sharing results.

## Interpret an Indicator Search

Match the article's full owner/repository name, not just a common filename.
Distinguish a saved link from a README fetch, an archive download and actual
execution. A name search cannot identify renamed copies or prove that no
payload ran. Record paths and data sources checked, exclusions and date.
Never visit a malicious repository just to establish whether a local
reference exists. A whole-host compromise investigation is separate work.

The 2026-11-18 check and proposed improvements are in
[the source review](../research/2026-11-18-honeypots-agent-repository-safety.md).
No global settings or permission allow entries were changed by that review.
