# Feedly workflow review

Reviewed 2026-11-15. Inputs were the two supplied `.skill` archives and
the 44 Markdown prompts in Feedly's library, plus its README. The archive
review covered the workflow text, reference documents, and selected
helper and test source. The bundled slide template was inventoried.
This was a design review of the supplied materials.
[Feedly's skills and prompt library](https://github.com/feedly/skills).

## What to use

1. **Claim and source records.** Use the Phase 5 source registry for
   publisher identity, original reporting organization, and links to
   upstream reports. Use Phase 6 Cases for stable claim IDs, the citation
   passage, claim status, conflicting claims, and what replaced each
   claim. Record the date of activity separately from report publication
   and preserve date precision. A case update can show new facts,
   changed judgments, and closed gaps. The same structure can support
   the parked exploitation evidence-strength labels when the provenance
   is known. [Track a Cyberattack](https://feedly.com/ti-essentials/posts/claude-skill-05-track-a-cyberattack).
2. **Hunt and detection handoff.** Carry the cited procedure or artifact
   into a case's hunt lead, record whether the required telemetry and
   fields exist, then develop a hypothesis and candidate detection.
   Keep expected matches, benign examples, blind spots and test results
   with the candidate. A syntax check and a successful telemetry test
   are different validation fields. Connect an approved candidate to
   the relevant Attack Flow step and Phase 8 packaging.
   [Feedly Volume 2](https://feedly.com/ti-essentials/posts/cti-prompt-library-volume-2).
3. **Case reports from the same records.** Render a short advisory,
   incident situation report, technical handoff or executive brief
   from versioned case facts. Show the decisions needed for each
   audience. Add local deterministic checks for missing references,
   invalid ATT&CK/ATLAS IDs, unsupported quotes and missing dates.
   Citation checks confirm a passage is present. The analyst still
   assesses whether it supports the claim.
   [Feedly automation workflows](https://feedly.com/ti-essentials/posts/how-to-automate-common-cti-workflows)
   [Feedly financial-sector workflows](https://feedly.com/ti-essentials/posts/accelerating-banking-financial-services-and-insurance-cti-workflows-with-prompt-driven).
4. **Mitigation outcomes.** Record the affected environment and assessment
   horizon. Save the baseline, actions recommended, actions with an
   owner and target date, and changes verified to work, with the evidence
   for each. Start with this action history. A fuller OWASP worksheet is
   a later option for cases with organization inputs. Its severity
   stays separate from the toolkit's CVE priority. Treat the supplied
   loss bands as scenario inputs. They require organization figures
   and carry the assumptions behind any comparison.
   [CTI Risk Reduction Report](https://feedly.com/ti-essentials/posts/claude-skill-03-cti-risk-reduction-report).

## Bundle details

### Track a Cyberattack

The skill's `tracker.json` represents sources, a claims ledger, timelines,
victims, ATT&CK mappings, attribution signals, conflicts, software,
actions and gaps. A source has a publisher, an originator, any source
it relays, a retrieval status and a reliability grade. An individual
claim has its own credibility and can cite a saved line. The rubric
counts independent originators and distinguishes a report of a
technique from a production observation or a lab demonstration.
Useful reference files are `schema.md`, `rubrics.md`,
`update-mode.md` and `soc-handoff.md`.

The bundled helper can check line references and evidence labels and
compare tracker revisions. A single record feeds its interactive
tracker, technical and executive reports, STIX bundle and Navigator
layers. The reference STIX export leaves indicators out on purpose.
The toolkit can keep IOC disposition and export under its existing
case and Phase 8 design. Use the schema and fixture patterns as a
reference. The source archive combines a Claude workflow, a static
dashboard, scripts and an ATT&CK snapshot, each with its own runtime
or attribution requirements. Feedly's product integration is optional
for its published workflow. Our collection can use the toolkit's
planned sources and analyst imports.

### CTI Risk Reduction Report

The workflow stores three views of a single assessment. The baseline
records the starting exposure. Current residual risk counts verified
mitigations. Target residual risk also allows unverified implemented
controls and dated commitments within the assessment horizon. It
tracks CTI output and operational changes as separate records. Its
references explain the factor scales, the mitigation checks, evidence
basis, and the assumptions behind financial bands. It also inventories
source artifacts and records why each one was used or set aside.

The action and verification model is the part to adopt first. A public
report can establish technical threat facts, while business impact and
control effectiveness need information about the actual organization.
Keep estimates and missing context visible. The archive includes an
assessment outline and an optional executive PowerPoint template.

## Prompt-by-prompt disposition

### R1, core CTI workflows

| ID | Fit for the toolkit |
|---|---|
| R1-01 | Use the Diamond Model as a case view of adversary, capability, infrastructure and victim, with gaps plainly visible. Combine with R3-03. |
| R1-02 | Defer the emulation plan. Reuse the detection validation handoff and links to existing safe test procedures. Execution belongs in an authorized lab workflow. |
| R1-03 | Feed the planned Case Attack Flow with cited stages, alternative paths and gaps. Preserve an optional ATT&CK mapping. |
| R1-04 | Use the hypothesis, expected observation and log source fields in the hunt package. Combine with R3-07. |
| R1-05 | Use cited procedure records for the planned actor profiles. Review cross-actor summaries after the underlying coverage is known. |
| R1-06 | Use the advisory table as an export layout for existing vulnerability facts. Preserve missing CVSS scores as missing. |
| R1-07 | Allow a case to link CVEs and show the prerequisites for each link. Require evidence for observed chains and record plausible chains as hypotheses. |
| R1-08 | Keep as an optional strategic-report template for a relevant collection requirement. |
| R1-09 | Optional strategic brief with provenance, alternate interpretations and indicators to watch. Record the reporting window and analyst confidence. |
| R1-10 | Reuse the sector brief layout once sector tagging and case exports exist. |
| R1-11 | Good early export candidate because the CVE page already has evidence, affected versions, exploit status and remediation. |
| R1-12 | Reuse as an actor-profile export from accepted evidence and existing profile records. |

### R2, analysis, hunting and detection

| ID | Fit for the toolkit |
|---|---|
| R2-01 | Build deterministic reference, schema and coverage checks first. Optional Phase 11 audit can flag unsupported inference for analyst review. |
| R2-02 | Use its source inventory and separate source reliability from claim credibility. Treat circular reporting as a provenance link. |
| R2-03 | Optional ATLAS mapping for AI-related behavior. Validate the framework and technique ID against the applicable local data. |
| R2-04 | Use the telemetry, field, false-positive and schema-assumption fields for Sentinel detection candidates. |
| R2-05 | Keep the original detection and record translation losses. Evaluate a supported conversion backend before using generated SPL. |
| R2-06 | Model detection candidates with required telemetry, benign and positive test cases, limitations, receiving team and validation status. |
| R2-07 | Add a cited, observable hunt lead and a disposition without requiring a complete hypothesis at intake. |
| R2-08 | Use optional telemetry coverage, existing detections and analyst effort to decide whether a hunt can run. Record Unknown when coverage is unavailable. |
| R2-09 | Use deduplicated observations and time windows for topic or campaign trend reporting. Keep this distinct from Phase 2 attention signals. |
| R2-10 | Defer until stakeholder feedback is stored. Reuse the product, audience and decision fields. |
| R2-11 | Offer a case assessment template for alternate scenarios, grounds and evidence gaps. |
| R2-12 | Optional audience-specific awareness brief from validated phishing cases. |
| R2-13 | Link mitigations to the specific finding, affected products and owner. Share action records with the risk-reduction workflow. |
| R2-14 | Use explicit input and output schemas between steps. Optional Phase 11 drafting can consume those records. |

### R3, report to operational output

| ID | Fit for the toolkit |
|---|---|
| R3-01 | Extend existing IOC extraction with the saved source passage and per-indicator disposition. Reuse IOC enrichment and Phase 8 STIX export. |
| R3-02 | Use the citation and confidence fields for ATT&CK Navigator exports. Validate IDs and write the dataset version from our pinned local bundle. |
| R3-03 | Reuse with R1-01. Draw the Diamond Model from accepted case records. |
| R3-04 | Reuse control-gap recommendations once the relevant environment and coverage data are known. |
| R3-05 | Reuse format-specific telemetry and validation requirements for the Phase 8 rule adapters. |
| R3-06 | Store experimental Sigma candidates with precise log source, provenance and known benign patterns. Mark technical validation separately. |
| R3-07 | Reuse with R1-04, R2-07 and R2-08 as one hunt-package workflow. |
| R3-08 | Offer a brief export with analyst-confirmed exposure and a specific decision for the audience. |

### R4, financial-sector workflow templates

| ID | Fit for the toolkit |
|---|---|
| R4-01 | Reuse the triage disposition, action and rationale fields in the alert inbox. Make sector relevance optional. |
| R4-02 | Group repeated observations by identifiers and origin, preserving conflicting feed reports. Treat other overlaps as leads for review. |
| R4-03 | Optional third-party exposure brief. Institutional services and downstream impact need an actual dependency inventory. |
| R4-04 | Defer the fraud-specific template until a case needs payment or identity risk analysis. |
| R4-05 | Generate audience-specific views from the same case snapshot and source references. |
| R4-06 | Record action owner, dependencies and open decisions. Render a coordination brief from those records. |
| R4-07 | Generate an incident update from case revisions. Show new observables, changed judgments and closed or remaining gaps. |
| R4-08 | Render a short executive brief from the case, centered on business impact and decisions needed. |
| R4-09 | Later export exercise injects and decision points from a documented attack flow. Keep planned scenarios separate from actual events. |
| R4-10 | Later report control and recovery gaps against a supplied environment, with owners and an explicit basis for residual risk. |

## Suggested evaluation cases

- One first-party report is repeated by a news outlet and two catalogs.
  Each reference is available and all share one origin.
- Two teams publish separate telemetry, while an actor makes a conflicting
  public claim. Preserve the origin, claim type and disagreement.
- A report gives a patch date and confirms a vulnerability in a lab.
  A separate source reports in-the-wild use later. Only the latter
  contributes a first reported exploitation date.
- A candidate detection is syntactically valid and its log source exists.
  A required field is missing in the organization. The handoff records
  that it cannot yet be validated in that environment.
- A containment action is proposed, deployed and later verified. A
  case update records each date and the evidence behind the change.

## Reuse record

Feedly's upstream repository identifies itself as MIT licensed. The
prompt library README gives separate usage guidance and identifies
contributors. The tracker archive includes an ATT&CK data notice and
its own offline assets. Verify the upstream revision and applicable
notices for a component before porting it. This review records
workflow ideas and references in project wording.
[Feedly repository](https://github.com/feedly/skills)
[Prompt library usage](https://github.com/feedly/skills/blob/main/prompts/feedly-complete-cti-prompt-library/README.md#license-and-usage).
