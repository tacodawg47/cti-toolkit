# Phase 2 Original Publisher Acceptance

Date: 2026-11-19. Phase 2 remains open. Scope: the 12 publisher pages and
one accompanying PDF listed in the 2026-11-09 journal survey. This is parser
acceptance, not a reassessment of those reports' threat claims or an audit
of all 69 renditions in the earlier survey.

## Method

Retrieved all 13 original sources without credentials, browser rendering,
page code execution or linked assets. Every source returned HTTP 200.
Captures, hashes, retrieval times, final URLs and extracted text stay under
git-ignored data/phase2-acceptance-2026-11-19/. No publisher content is
copied into committed fixtures. scripts/check_report_layouts.py contains
only our review logic and the source URLs, not copied publisher code.

The initial per-file limit was 5 MiB. This was a conservative test-download
budget, not a PDF format requirement, maliciousness threshold or measured
safe size. The Recorded Future PDF exceeded it. A HEAD request advertised
5,895,616 bytes. Retried that source alone with
a 6 MiB limit. The 30 MiB per-run total cap stayed in place. Retained
captures total 8,707,026 bytes. No bulk dataset or dependency was downloaded.

Ran the approved Defender custom scan on the dedicated incoming HTML
directory, then separately on the new PDF. Both completed with exit 0 and
explicitly reported no threats. Used the signed installed Defender binary
through Platform/CurrentVersion. The signature date read before the scan
was 2026-11-18. No signatures or system settings were changed. Cloud analysis
was permitted for these public project downloads, but the scan output does
not establish whether a sample was actually submitted. No unrelated or
personal file was selected. A negative scan is not a safety certificate.

Parsed captures with the existing local MITRE ATT&CK v20.1 index. Inspected
candidate structures, per-ID association summaries, representative source
cells and extracted excerpts. Counts below are per document, not unique
techniques across the collection. Name/tactic differences from the current
catalog remain visible. The check does not validate every report assertion,
semantically classify every paragraph or prove every page variant works.

## Results After Corrections

The exact URLs remain in the script's REPORTS list and capture manifest.

| Original source | IDs | IDs with aligned text | Accepted outcome |
|---|---:|---:|---|
| ESET SlippyNunchucks | 9 | 9 | HTML tables; retain published name/tactic differences |
| Talos Q3 incident-response trends | 50 | 50 | HTML descriptions; some are general technique definitions, not observed procedures |
| Intel 471 OpenClaw | 13 | 13 | HTML table text; retain published label differences |
| Fortinet QuickFox | 9 | 9 | Real tables only; article wrapper no longer adds false grid evidence |
| Group-IB KGB RAT | 42 | 29 | Mixed tables, shared text and labelled prose; remaining IDs stay without procedure text |
| Group-IB Stray Cat | 32 | 32 | Headerless/content-based table recognition |
| Microsoft fake-download campaign | 7 | 7 | HTML list entries, preserving source wording |
| Recorded Future HookEdge HTML | 14 | 0 | Tactic/name grid remains labels only |
| Recorded Future HookEdge PDF | 14 | 0 | Labels only, consistent with the HTML matrix |
| DFIR Bumblebee/AdaptixC2/Akira | 38 | 0 | Names and IDs, no invented adjacent procedures |
| Picus Famous Chollima | 18 | 18 | ID-bearing headings and following paragraphs |
| Zscaler AI-assisted campaign | 0 | 0 | Six AML.T references remain outside the ATT&CK matcher |
| Genians OpenCode | 12 | 12 | Korean table text, with source/catalog differences preserved |

## Corrections Found by Real Sources

1. Article containers could look like a div grid. On Fortinet this attached
   an entire unrelated table to a different technique; Group-IB also gained
   a spurious grid. Require grid cells to be bounded text containers without
   nested headings, tables, lists or whole report sections. Continue walking
   rejected wrappers so real tables and inner grids remain available.
2. Recorded Future combines tactic and technique in one label. Six of its
   14 labels had been misclassified as procedures. Match the known tactic
   prefix and catalog technique name, preserve the reported tactic, and keep
   all 14 entries labels-only. A generic label is not behavior evidence.

Added two independent synthetic regressions reproducing these failures
without copying source text. Also clarified the UI: source-aligned text can
be a general description and does not independently establish observation.

## Remaining Limits and Closeout

This accepts the current captures of the named survey examples, not an
exhaustive publisher guarantee. Image-only/OCR, JavaScript-only structures
and automatic semantic ATT&CK mapping without explicit IDs stay outside this
acceptance slice. Reports without ATT&CK IDs already support IOC extraction;
the missing feature is automatic behavior-to-technique mapping. Browser
rendering is planned with Phase 5. Local OCR and analyst-selected technique
mapping are separate later candidates, not deliveries of this check.
A changed source hash or layout needs renewed review. Original
MuddyWater wrapped-hash PDF acceptance is separate and is not claimed here.

Update later on 2026-11-19: the Red Hat/SUSE saved queue and bounded
continuation workflow is built and tested offline. No live backlog was
drained in that implementation pass. Phase 2 still needs its targeted
historical NVD work, separate wrapped-hash check, HTMX closeout decision and
optional-source scope decisions. Scheduled vendor continuation remains Phase 5.
Do not mark the module complete merely because these parser examples work.

## Repeat

See the exact fetch, scan and offline-analysis commands in
[the extraction runbook](../runbooks/ioc-extraction.md). Fetch is opt-in;
running the helper without --fetch makes no network request. Do not replace
local ignored captures with checked-in publisher pages. The permanent
synthetic tests remain independent of the live sites.
