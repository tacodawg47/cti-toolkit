# Approved Phase 2 Git Checkpoint

Date: 2026-11-26. The operator approved staging and committing this exact
file list and message. Push approval remains separate. This document is
prepared for that checkpoint; verify the actual Git result before resuming.

Proposed message: `Complete Phase 2 and document subphase handoffs`.

Inspected branch: `main`. HEAD: `a07898b`,
`Advance Phase 2 coverage and unify vulnerability evidence`.
The staging area was empty. HEAD matched the locally stored `origin/main`
reference; no fetch or live GitHub synchronization check was performed.

## Scope

This checkpoint contains the accumulated Phase 2 extraction, metadata
recovery, evidence and UI corrections; passive artifact-review tooling;
related research/runbooks/tests; and the subphase session/handoff workflow.
The reader prototype item is a static research note for later Phase 4,
not an application implementation or copied external source.

The exact proposed list has 119 paths below. One tracked template,
`app/templates/vulnintel/reports.html`, is intentionally deleted with the
retired manual report intake. Previously saved reports remain readable.

Excluded: `.claude/settings.local.json` and `feedly-review-rules.md`.
Keep those local and untouched. Runtime databases, downloaded artifacts,
credentials and conversation exports are not in the proposed list.

## Checks

- Git status/diff inspection was explicitly authorized. The operator then
  approved staging and committing the exact list below.
- The prior final suite ran 511 tests: 510 passed, one existing skip.
  The prior 26-page local acceptance passed. These were not rerun just for Git.
- Tracked diffs passed whitespace checks. Git reported line-ending conversion
  notices and could not read a global ignore file under the sandbox.
  No global Git setting or ignore file was changed.
- A bounded local filename/text check examined about 1.67 MB before this
  manifest was added. It found no candidate private-key/token patterns or
  operator-specific home paths. Two credential-URL matches are deliberate
  synthetic test inputs for redirect refusal and output redaction.
  This check is not a guarantee that arbitrary code is benign.
- The repository config points hooksPath at `.githooks`. The transcript
  guard remains enabled; no hook or test bypass is proposed.

Recheck the actual file list and changes before staging. The handoff and
journal are updated with this inspection. If other work changes before
approval, review it rather than silently widening this list.

## Exact Proposed Files

```text
AGENTS.md
CLAUDE.md
ROADMAP.md
app/core/ratelimit.py
app/main.py
app/modules/extract/atlas.py
app/modules/extract/attack.py
app/modules/extract/content.py
app/modules/extract/embedded.py
app/modules/extract/extractor.py
app/modules/extract/html.py
app/modules/extract/layouts.py
app/modules/extract/markdown.py
app/modules/extract/pdf.py
app/modules/extract/software.py
app/modules/extract/tlds.py
app/modules/vulnerability_intelligence/advisory_reload.py
app/modules/vulnerability_intelligence/detail.py
app/modules/vulnerability_intelligence/evidence.py
app/modules/vulnerability_intelligence/feeds/chrome.py
app/modules/vulnerability_intelligence/feeds/nvd_recent.py
app/modules/vulnerability_intelligence/feeds/ot.py
app/modules/vulnerability_intelligence/feeds/vendors.py
app/modules/vulnerability_intelligence/metadata.py
app/modules/vulnerability_intelligence/priority.py
app/modules/vulnerability_intelligence/reports.py
app/modules/vulnerability_intelligence/review.py
app/modules/vulnerability_intelligence/routes.py
app/modules/vulnerability_intelligence/service.py
app/modules/vulnerability_intelligence/sources/cvedb.py
app/modules/vulnerability_intelligence/sources/nvd.py
app/modules/vulnerability_intelligence/sources/vulnlookup.py
app/modules/vulnerability_intelligence/store.py
app/modules/vulnerability_intelligence/unfixed.py
app/modules/vulnerability_intelligence/vendor_notices.py
app/modules/vulnerability_intelligence/views.py
app/static/extract.js
app/templates/_attack_findings.html
app/templates/extract.html
app/templates/vulnintel/_cve_table.html
app/templates/vulnintel/_cvedb.html
app/templates/vulnintel/_exploitation_details.html
app/templates/vulnintel/_review_items.html
app/templates/vulnintel/_unfixed_evidence.html
app/templates/vulnintel/_vendor_advisories.html
app/templates/vulnintel/cve.html
app/templates/vulnintel/dashboard.html
app/templates/vulnintel/feeds.html
app/templates/vulnintel/layout.html
app/templates/vulnintel/metadata.html
app/templates/vulnintel/report.html
DELETE app/templates/vulnintel/reports.html
app/templates/vulnintel/review.html
app/templates/vulnintel/search.html
app/templates/vulnintel/vendor_updates.html
app/templates/vulnintel/view.html
app/templates/vulnintel/views.html
docs/examples/research-offline.wsb
docs/handoff.md
docs/journal.md
docs/research/2026-11-18-agent-framework-exposure.md
docs/research/2026-11-18-cti-skills-integration-review.md
docs/research/2026-11-18-honeypots-agent-repository-safety.md
docs/research/2026-11-18-osint-source-expansion.md
docs/research/2026-11-19-static-supply-chain-review.md
docs/review/2026-11-17-phase2-coverage-audit.md
docs/review/2026-11-19-feedly-skills-manifest.sha256
docs/review/2026-11-19-operator-report-checks.md
docs/review/2026-11-19-publisher-acceptance.md
docs/review/2026-11-20-metadata-coverage.md
docs/review/2026-11-20-nvd-backfill.md
docs/review/2026-11-24-chrome-exploitation.md
docs/review/2026-11-24-nvd-recovery.md
docs/review/2026-11-24-phase2-source-scope.md
docs/review/2026-11-24-report-extensions-and-pdf.md
docs/review/2026-11-25-phase2-closeout.md
docs/review/2026-11-26-phase2-checkpoint-files.md
docs/review/2026-11-26-reader-prototype.md
docs/runbooks/chrome-exploitation.md
docs/runbooks/cvedb-comparison.md
docs/runbooks/defender-artifact-scan.md
docs/runbooks/dependency-policy.md
docs/runbooks/install-codex-cti-skills.md
docs/runbooks/install-feedly-skills.md
docs/runbooks/ioc-extraction.md
docs/runbooks/manual-refresh-and-extension-references.md
docs/runbooks/nvd-backfill.md
docs/runbooks/nvd-recovery.md
docs/runbooks/passive-ioc-pivot-investigation.md
docs/runbooks/phase2-closeout.md
docs/runbooks/research-isolation.md
docs/runbooks/session-handoff.md
docs/runbooks/testing.md
docs/runbooks/untrusted-repository-review.md
docs/runbooks/v1-data-freshness.md
docs/runbooks/vetting-a-dependency.md
docs/runbooks/vulnerability-intelligence.md
scripts/artifact_strings.py
scripts/audit_vulnerability_coverage.py
scripts/audit_wheel.py
scripts/check_report_layouts.py
tests/legacy_reports.py
tests/phase2_coverage_probe.py
tests/test_attack_layouts.py
tests/test_chrome_exploitation.py
tests/test_cvedb.py
tests/test_decode_pdf.py
tests/test_extract.py
tests/test_metadata_coverage.py
tests/test_nvd_backfill.py
tests/test_nvd_recovery.py
tests/test_report_quality.py
tests/test_review_digest.py
tests/test_software_references.py
tests/test_unfixed.py
tests/test_vendor_notices.py
tests/test_vulnerability_evidence.py
tests/test_vulnintel.py
tests/test_wheel_audit.py
```

## Approval Boundary

The current-chat operator approved this exact file list and message.
After the actual commit, present its ID and the verified remote/branch for
separate push approval. This historical approval does not authorize a
different commit or a new session's Git operations.
