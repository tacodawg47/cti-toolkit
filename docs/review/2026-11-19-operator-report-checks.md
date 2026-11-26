# Operator Report and Vulnerability Checks

Date: 2026-11-19. Phase 2 remains open.

## Original Sources Checked

- [ReversingLabs ARTEX report](https://www.reversinglabs.com/blog/threat-researchers-notebook-detection-strategies-for-artex-and-related-forks).
- [Google ARMORY CASTLE report](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere).
- [NVD CVE-2018-13257](https://nvd.nist.gov/vuln/detail/CVE-2018-13257), including its public API record.
- Vulnerability-Lookup sighting API implementation and the specific local
  records behind the operator's Blackboard example.
- [ATLAS matrix URL](https://atlas.mitre.org/matrices/ATLAS-matrix): returned
  404 during this check. Reviewed the official MITRE ATLAS data repository
  README and Apache-2.0 license instead. No ATLAS runtime dependency or
  full technique catalog was installed.
- IANA's official TLD list, used as a small local runtime cache.

Downloaded originals are ignored local research data. Defender scanned
the public incoming files and completed without a detection. No original
article, embedded command, credential or proprietary rule was checked in.
The parser treated embedded scripts as text/JSON only.

## Findings and Corrections

| Check | Result |
|---|---|
| ReversingLabs URL body | Previously 51 hashes in visible HTML. Declarative streamed data recovers 193 distinct SHA-256 values. The raw body also contains a site-verification hash, which is excluded. |
| ReversingLabs hash context | The reported `8b567c...` hash retains the Favicon SHA256s caption and ARTEX console group label. |
| Google IP table | 11 extracted IPs retain their adjacent report descriptions. |
| Google detection content | Six YARA rules retained as inert artifacts. Code-contained URLs are excluded from IOC enrichment. |
| Google domain noise | No `data.mdb`, `request.getparameter` or social-sharing URLs offered for enrichment. Hyperlink targets remain references. |
| Google ATT&CK | No explicit ATT&CK IDs occur in the captured article. Narrow command matches are candidate mappings, separate from reported IDs. |
| NVD example | Public source has CVSS 3.1 6.1 Medium, CWE-601 and Blackboard Learn CPE metadata. The local store lacked its NVD row; v3 support already existed. |
| Exploitation example | No local KEV entry. An uncited Telegram community sighting had promoted exploitation. Such claims remain leads and no longer promote exploitation by themselves. |
| Microsoft | Publisher view now includes existing MSRC advisories with filtering and the existing refresh connector. |

These results apply to the captured pages, not every revision or publisher.
Both original URLs also passed through the running app: ReversingLabs
193 hashes with group context and cleared inputs; Google 11 IPs with
descriptions, six YARA artifacts and explicit image controls. The selected
NVD record was loaded and verified locally. Its ID is no longer in the
shared known-exploited set. The Zero-Day page returned HTTP 200 with its
new exploitation evidence column. A single warm request took 8.95 seconds;
that is still a performance follow-up, not a completed optimization pass.
Full offline suite: 448 tests, 447 passed and one existing skip. Subsequent
affected-view tests passed 51/51; parser/UI tests passed 86/87 with the same
skip; the final method-call filter passed its 59 affected tests.

Plain-text replay of the captured report text also preserves 193
ReversingLabs hashes and the Google IP descriptions and six rules. It is
not a fresh capture of the operator's browser clipboard. A final replay
found `a.read()` and `b.read()` because `.read` is a real TLD. Plain method
calls are now filtered separately from defanged host indicators. This
shows why suffix validation alone cannot eliminate all code false positives.

No claim of exhaustive narrative TTP extraction, query validation, OCR,
full ATLAS catalog support or complete plain-text code parsing is made.
The permanent regression fixtures are independently written synthetic data.

## Review Backlog

The inspected snapshot had 547,973 stored events across 28,638 CVEs,
including already reviewed events. Of these, 468,815 exploitation events
came from VulnCheck evidence across 5,926 CVEs. This is citation-level
history, not that many newly exploited vulnerabilities.

Recommend removing the global dashboard counter or replacing it with an
optional watchlist digest, grouped by CVE and material state change.
Keep history separate and do not mark events reviewed as part of this fix.
The operator's choice remains pending. No review-state reset was performed.

## Remaining Work

Review free original KEV feeds before replacing CIRCL-proxied connectors.
Direct CISA, VulnCheck, ENISA EUVD and Project Zero connectors already exist.
Preserve aggregator versus origin lineage and avoid syndicated double counts.
Continuous article discovery belongs to the planned reader/collector work.
Broader older-CVE metadata batches, the separate wrapped-hash acceptance
and Phase 2 closeout decisions remain open.
