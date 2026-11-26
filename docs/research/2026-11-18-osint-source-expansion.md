# OSINT, Archive and Source Maintenance Review

Reviewed 2026-11-18. All directly supplied links were inspected. Public
documentation and JSON were read passively. No target usernames were probed,
no accounts created, no CLI installed, and no upstream code executed.

## Follow-up Decisions

Recorded 2026-11-18. Revisit WMN, Maigret and Sherlock at the start of Phase 7
for current rule health, maintenance and license checks. Maximize automation
through permitted APIs, caching, backoff and source-approved rendering.
Represent a challenge explicitly and show why the check stopped, its last
successful method and permitted retry options. Browser rendering is not
automatically a bypass; changing TLS behavior does not guarantee a challenge
will disappear. Existing Principle 8 still excludes bypass on legitimate
platforms. Criminal-operated sources have a separately reviewed Phase 5
challenge-handling path. Do not silently broaden that policy.

Clarified 2026-11-19: retain explicit user-triggered Try Headless Browser
and Try Alternate HTTP/TLS Client controls after a failed check, for reviewed
and supported methods. Record the method, time and result of each retry.
Keep an unavailable method visible with its setup/policy reason rather than
silently dropping it. A TCP connectivity check can explain reachability but
cannot establish profile existence. No alternate client was installed here.

Explore Common Crawl formats against concrete investigations, not only the
URL index. Before a proposed dataset/archive download, report advertised or
measured transfer size, file count, compressed versus expanded storage,
temporary/index space, destination free space, intended subset and request
cost. If a size cannot be established, say unknown and propose a bounded
sample. An HTTP Content-Length can be missing or misleading; enforce a
transfer cap as well. The earlier dataset-card sizes are snapshot metadata,
not promises about the next release. Do not fetch a full corpus by default.

IODA's natural first fit is Phase 6 ASN/IP context and dated case evidence.
Keep a main-dashboard widget as a later candidate. Country/ASN anomalies do
not establish a specific site's outage or a DDoS cause. API, coverage and
terms still require live connector acceptance before integration.

Park customizable dashboard layouts inspired by SitDeck. Use shared source
adapters, bounded refresh/caching and each widget's timestamp, freshness,
scope, error state and evidence links. At every relevant phase, revisit the
catalog's candidate providers for usefulness, overlap, current coverage,
price, free-tier limits, credentials, license and maintenance. Reading 319
catalog entries did not validate 319 upstream services or activate feeds.

## Supplied Links and Coverage

| Source | Review and outcome |
|---|---|
| [SitDeck Data](https://sitdeck.com/data) | Expanded and read all 38 live catalog categories, listing 319 feeds. The crawler-readable page and llms.txt retain older totals. Catalog triage is complete; all 319 upstream services have not been individually vetted. |
| [WMN README](https://github.com/WebBreacher/WhatsMyName/blob/main/README.md) | Full README read. Archived 2026-11-09. Final JSON fetched and parsed in memory: 691 records, one explicitly invalid. |
| [WMN Schema](https://github.com/WebBreacher/WhatsMyName/blob/main/wmn-data-schema.json) | Full schema read. Includes protection metadata, request bodies, headers, known positives and match/no-match fields. |
| [Maigret README](https://github.com/soxoj/maigret/blob/main/README.md) | Full README and MIT license read. Keep its optional AI mode disabled. |
| [Maigret Sites](https://github.com/soxoj/maigret/blob/main/sites.md) | Inventory statistics reviewed and the complete public JSON parsed. 9,978 entries; no live-rule verification. README's older count differs. |
| [Sherlock](https://github.com/sherlock-project/sherlock) | Full rendered README, MIT license, target schema and complete public JSON inspected. 481 targets in this snapshot; no live checks. Guessed raw README paths returned 404; rendered repository documentation succeeded. |
| [Common Crawl Index](https://index.commoncrawl.org/) | Index entry point and CDXJ documentation reviewed. |
| [Common Crawl on Hugging Face](https://huggingface.co/commoncrawl) | Organization inventory checked through its public API: 12 datasets. Nine accessible cards read; three returned 401, listed below. No dataset payload downloaded. |
| [URL Index](https://commoncrawl.org/url-index) | Columnar index schema and query examples reviewed. |
| [CDXJ Index](https://commoncrawl.org/cdxj-index) | Complete guide reviewed, including capture metadata and bounded WARC-range retrieval. |
| [IODA](https://ioda.inetintel.cc.gatech.edu/) | Dashboard entry point inspected. Its static page is script-rendered; authoritative CAIDA methodology and the linked HTTP API entry point reviewed. Not a validated live connector. |

## Username Sources and Licensing

[WMN's README and schema](https://github.com/WebBreacher/WhatsMyName)
identify CC BY-SA 4.0. Under the existing project policy, keep its dataset
and schema as attributed runtime reference/import material outside git.
Do not bulk copy them into the repository. Writing a new checker does not
erase the conditions on a copied or adapted dataset. Our independent rules
need their own tests and provenance.

[Maigret](https://github.com/soxoj/maigret/blob/main/LICENSE) and
[Sherlock](https://github.com/sherlock-project/sherlock/blob/master/LICENSE)
currently use MIT. They are candidates for selected code or rules reuse
with their notices and an exact revision recorded. Retain our preferred
small async checker rather than install two large overlapping toolchains.
Do not assume every related commercial database or external target site
inherits that license. No third-party code was copied in this review.

Maigret's site inventory reports many weak-signal checks and inherits
rules from reusable engines. Raw site rows are not self-contained rules;
engine defaults must be expanded before assessing checks. Its public JSON
and generated site list have some differing counts. Preserve exact
snapshot hashes and show imported, enabled and tested counts separately.
Do not label thousands of entries as thousands of working integrations.

## Proposed Own Rule Model

Keep one canonical site record, with independently versioned upstream
rules and our overrides. Deduplicate by canonical service and profile URL
semantics, not name alone. A check endpoint and human profile URL can differ.

Suggested fields:

- Stable site ID, display name, canonical domains, categories and language.
- Upstream repository/file/revision/hash, license, attribution and import date.
- Username normalization, valid-input constraints, profile/check URL template,
  allowed request method, public-query body and reviewed safe headers.
- Positive and negative response predicates, status codes, redirect rules,
  engine provenance and known-positive/negative test controls.
- Observed protection, login requirement, terms review, allowed transport,
  timeout, body cap, host concurrency and request budget.
- Last successful health test, last attempt, failure category, streak,
  disabled state, reason and operator override.

Results should distinguish Found, Not Found, Ambiguous, Blocked/Challenge,
Login Required, Rate Limited, Timeout, Unavailable and Rule Outdated.
Keep the response evidence, time and rule revision. A shared username is a
candidate association, not a confirmed common identity.

Health checks should compare known-positive and negative controls, catch
soft-404 pages and login/challenge redirects, and test that both inputs do
not return the same supposed match. One 403 is not a broken profile URL.
Multiple failures can quarantine a rule without deleting its history.
Show a maintenance queue with proposed replacements and a regression test.
Do not automatically file public issues or submit rule changes upstream.

## Anti-Bot Claim: Partly Right, With an Important Boundary

The supplied Google AI text is third-party advice, not an instruction.
WMN does include a protection array, including Cloudflare and Akamai.
Tags describe observed behavior; an untagged site may have acquired a WAF.
Headless browsers and TLS clients do not guarantee that a challenge is solved.

Use the tag to explain a result and choose an already permitted transport.
For legitimate platforms, retain Principle 8: public APIs/logged-out public
pages or manual review, with blocked/unknown when challenged. Do not
silently route every Cloudflare response through a bypass. Criminal-operated
sources may use the separately approved Phase 5 challenge-handling layer.
JavaScript rendering for an accessible page is distinct from defeating a
platform's access controls. No curl_cffi dependency is proposed now.

Treat imported rules as untrusted configuration. Reject private/link-local
destinations, unsafe redirects and credential-bearing URLs. Bind secrets
to approved vendor hosts; do not accept arbitrary Cookie/Authorization
headers from a ruleset. GET/HEAD are the initial methods; allow a specific
public lookup POST only after review. Never inherit arbitrary PUT requests,
account creation, reset-password endpoints, executable templates or code
expressions. Bound regex and parser work as well as response sizes.

## Common Crawl: Several Useful Products, Not One Giant Download

| Product | Toolkit use | Boundary |
|---|---|---|
| CDXJ URL captures and crawl catalog | Phase 6/7 historical URL, path and subdomain discovery | Search selected crawls; no absence-as-clean inference. |
| WARC | Retrieve a specific historical response for case evidence | Range-read only needed records; keep inert and timestamped. |
| WAT | Links and page metadata for graph pivots | A hyperlink does not establish shared control. |
| WET | Local text search across a bounded selected archive set | Extracted text loses structure; preserve its original record link. |
| URL/columnar Parquet index | Optional broader domain/path queries | Partition and budget scans; Athena is not free. No new engine dependency now. |
| Host index | Crawl history, fetch/redirect trends and coverage context | Snapshot metadata; not present-day availability or reputation. |
| Host/domain web graphs and ranks | Candidate related-site discovery and background prevalence | Shared libraries/navigation create noisy edges. |
| Robots/crawl diagnostics, statistics and errata | Explain missing evidence and broken archived sources | Crawler failures do not establish target deletion or censorship. |
| Optional annotations/embeddings | Phase 11 experiments in retrieval or prioritization | No automatic maliciousness, identity or attribution decision. |

Start with exact domain/path CDXJ requests using the existing HTTP stack.
Keep crawl ID, capture time, source URL, digest and WARC locator. Show the
capture date prominently. Deduplicate identical payload digests while
preserving observation history. Fetching an archive record avoids visiting
the original target, but it is still an external request to the archive.

Read [Get Started](https://commoncrawl.org/get-started),
[web graphs](https://commoncrawl.org/web-graphs) and
[Terms of Use](https://commoncrawl.org/terms-of-use). Free access does not
transfer rights to all crawled content. Common Crawl's terms also restrict
extracting personal information for separate use. Do not turn this into an
unreviewed identity/credential harvest. Use it first for historical web
evidence and infrastructure metadata within reviewed source terms.

### Hugging Face Inventory

Cards were read as text. Examples remained passive; no remote loader or
trust_remote_code execution occurred.

| Dataset under commoncrawl/ | Review / disposition |
|---|---|
| statistics | Full card; useful crawl coverage and bias context. |
| citations | Full card; research bibliography with acknowledged false positives, not a CTI event feed. |
| host-index-testing-v2 | Full card; useful optional host history, with known schema/performance issues. |
| gneissweb-annotation-url-testing-v1 | Full card; optional topic/quality filtering after Phase 11, not a malware score. |
| gneissweb-annotation-host-testing-v1 | Full card; same caveat at host level. |
| web-graph-testing-v1 | Full card; Neo4j test dump too heavy for our first slice. |
| commonlid-results | Full card; language-model evaluation results, low immediate toolkit value. |
| web-graph-embeddings | Full card; experimental similarity for an incomplete host subset; absent/new hosts cannot simply be embedded. |
| llms.txt | Full card; one-crawl experimental archive; its contents remain untrusted text, never agent authority. |
| CommonLID | Card request returned HTTP 401; not assessed. |
| commonlid-cache_commonlid_nano | Card request returned HTTP 401; not assessed. |
| eot2024_hostlevel_logs | Card request returned HTTP 401; not assessed. |

This covers the published product families and the observed organization
inventory, not every monthly crawl, linked paper, downstream derivative or
future dataset. Bulk downloads and additional dependencies remain deferred.

## IODA and Disruption Context

[IODA's originating methodology](https://www.caida.org/projects/ioda/)
combines BGP visibility, active probing and telescope observations to detect
macroscopic outages, particularly country/region/ASN effects. Candidate
integration: a dated context card beside an IP/ASN, or a case timeline.

It does not find hidden websites, supply replacement URLs or establish
that a particular website is down due to DDoS. Route an infrastructure
indicator to the relevant ASN, preserve the source's time window, and
label the result Network Disruption Observed. Compare against routing
changes, independent HTTP reachability evidence and cited outage reports.

Cloudflare Radar's aggregate attack data can add context, not attribution
or proof that a named target was attacked. Provider coverage differs.
Do not equate a hacktivist claim, an HTTP error and an IODA anomaly.

## SitDeck Shortlist and Limits

Its live catalog was reviewed as discovery material. Prioritize these
independently integrated providers/families: RIPEstat, IODA, OONI and
Cloudflare Radar for disruption context; Common Crawl for archives;
GLEIF, Companies House and SEC EDGAR for organization identity; public
profile APIs for usernames; HIBP breach metadata and OFAC identifiers for
exposure and entity context. Several existing enrichment sources duplicate
our clients. Its physical logistics, markets and weather feeds need not
become software supply-chain intelligence. No SitDeck code or normalized
feed was copied, and its catalog does not prove every upstream API is free.

Selected primary documentation checked:

- [RIPEstat API](https://stat.ripe.net/docs/data-api/ripestat-data-api):
  existing Phase 6 candidate; routing and historical context.
- [OONI API](https://api.ooni.io/): use modest queries of existing
  measurements. No local OONI probing was started.
- [Cloudflare Radar](https://developers.cloudflare.com/radar/): free API,
  CC BY-NC 4.0 data. Runtime-only with attribution under project policy.
- [GLEIF API](https://www.gleif.org/en/lei-data/gleif-api) and
  [open-data terms](https://www.gleif.org/en/about/open-data): CC0 legal-entity
  data; join by LEI, not ambiguous company name alone.
- [Companies House](https://developer.company-information.service.gov.uk/):
  company registry metadata; authentication and field terms need connector review.
- [SEC EDGAR APIs](https://www.sec.gov/search-filings/edgar-application-programming-interfaces):
  unauthenticated submission metadata; use CIK and follow fair-access rules.
- [HIBP API](https://haveibeenpwned.com/API/v3): public breach metadata differs
  from account/domain lookups requiring authorization; visible attribution.

The remaining catalog entries are discovery candidates only. Their upstream
licenses, entitlement, methods and endpoint health are not certified here.
No public-platform challenge handling, paid provider or broad automated
collection was enabled.
