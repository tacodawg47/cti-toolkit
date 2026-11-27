# Indexed Cloud Metadata API Review

Date: 2026-11-27. Subphase 3A.6. Public documentation only. No selector
submission, provider data request, account/key creation, checkout or install.

## Reading and Provider Choice

Read the complete relevant GET /shodan/host/search section, including its
examples, requirements and parameters, in the [API reference](https://developer.shodan.io/api).
It documents key authentication, 100 results/page, numbered paging,
minify and a fields projection. Filtered requests consume query credits.
Past page 100, pages must be requested in sequence. This consumer stops at
page two. The search envelope has matches and total; no snapshot token or
guaranteed stable ordering is documented. A fields projection is essential:
minify alone only truncates large fields and can still return content.
Documented per-result metadata.truncated lists mark the local window partial.
Nested projection shape, null handling, error and quota behavior need
separately approved measured acceptance. No token/count/quota endpoint is
queried. No facets or search cursor are used.

Read the full [Search Query Fundamentals](https://help.shodan.io/the-basics/search-query-fundamentals)
and [Filter Reference](https://www.shodan.io/search/filters). Unfiltered text
searches service data. The listed filters include hostname, domain and
cloud.provider/region/service. Use only hostname:"exact-domain". Query
matching need not enforce our DNS boundary, so local checks require a
returned hostname equal to the seed or ending with dot plus seed. No
Boolean queries, cloud wildcard predicate, fuzzy expansion or organization
inference. Cloud attribution is checked locally, avoiding extra searches.

Read the relevant full general-property table and the complete
[cloud definition](https://datapedia.shodan.io/property/cloud.html) in
[Datapedia](https://datapedia.shodan.io/), plus the complete
[_shodan definition](https://datapedia.shodan.io/property/_shodan.html).
hostnames are provider PTR/reverse-DNS names. org describes the IP manager.
cloud.provider is required within cloud; region/service are optional.
timestamp is banner acquisition in UTC. Its documented naive spelling may
therefore be normalized to UTC for observed_at while retaining the literal
timestamp. Missing dates stay unknown. No index-ingestion timestamp or
asset ownership follows from these fields. _shodan and protocol contents
are excluded from the projection and retained data.

Read the full [Data Timeframes](https://help.shodan.io/mastery/data_timeline)
page. Main search uses the latest banner per IP/port in a 30-day window;
the provider says it crawls at least weekly. Historical lookup, Trends and
Monitor have different windows and are excluded. These are provider
assertions, not measured completeness or freshness guarantees.

Read the relevant authentication, credits and search sections of the
[Shodan Book API chapter](https://book.shodan.io/developer-apis/shodan-api/).
Its credit prose says one credit per 100 pages, conflicting with the
endpoint/help text's 100 results. Use the stricter one credit per request
locally, including failed or interrupted requests. Actual debits remain
unmeasured. No SDK example was installed or executed.

## Access, Cost and Quota

Read the full public [billing and comparison page](https://account.shodan.io/billing)
and [Credits Explained](https://help.shodan.io/the-basics/credit-types-explained).
Published prices: Membership USD 49 once with 100 monthly query credits;
Freelancer USD 69/month with 10,000; Small Business USD 359/month with
200,000; Corporate USD 1,099/month with unlimited query credits; Enterprise
custom. Paid API plans list one request/second. Membership's filter list
excludes vuln/tag; higher tiers differ. This consumer uses neither.
The comparison's one-user rows conflict with the FAQ's organization-wide
key sharing description. Do not infer operator entitlement or sharing rights.
The free-account statement does not establish filtered/paged search access.
Membership's suitability for the actual professional purpose and contracts
also needs review. No purchase or paid-tier selection occurred.

Query credits renew monthly; scan credits are a different budget and never
used here. Existing IP enrichment and api-info remain unchanged and are
not called by this consumer. This consumer's durable monthly cap defaults
to 20 reserved requests; it is not the provider's remaining balance.
No undocumented quota-header guarantee is assumed. HTTP 429/503 save
bounded Retry-After cooldowns. Other apps, manual requests and shared-key
spending remain outside this ledger and require operational coordination.

## Terms and Privacy Gaps

Read the full official [Website and API Plans terms](https://static.shodan.io/legal/terms.html),
including access, content, attribution, account restrictions, submissions,
termination, warranties, liability and legal sections. Section 6.3 broadly
restricts automated access while the API/billing docs describe programmatic
integration. This is a real unresolved contract gap for this scheduled use.
Content reuse is restricted; Shodan attribution and ownership notices are
required. Academic/research access has non-commercial/institutional limits.
Submission licensing is broad and services/data carry no accuracy warranty.
Actual account agreements, permitted automated storage/derived metadata,
purpose and handling must be accepted separately. This review grants no
source eligibility or data-redistribution rights. No effective date was
verified on the accessible terms page.

Read the full [Privacy Policy](https://account.shodan.io/privacy). It describes
cookies and query-associated time, browser/language and IP records, aggregate
sharing, legal-process disclosure, consent and changes. It provides no fixed
query-log retention or confidential-search guarantee. Exact domains disclose
a private watchlist even when indexed results are public. Actual account/API
retention and processing obligations remain unresolved. No account was opened
or inspected and no private domain was submitted.

The initially guessed www.shodan.io/about/terms and /about/privacy pages
were inaccessible through the research tool. The official static terms and
account privacy pages above were subsequently read completely. No provider
data request was used to fill any access or schema gap.

## Local Integration and Coverage

Revisited app/modules/enrich/shodan.py, the installed MIT Liberty91
shodan-api reference, the historical source-review summary and Shodan rows
in the detailed CTI tool catalog and OSINT review. The reference's broad
free/paid rate description is not current entitlement evidence. Reuse the
shared httpx client and app loop with the existing jobs/evidence/inbox;
add only this consumer's durable quotas. No vendor code or dataset was
copied, no SDK/dependency added, and no GPL/AGPL implementation imported.
Historical Censys/GrayhatWarfare candidates are not adopted or combined.
Revisited the saved SitDeck source-selection review at
docs/research/2026-11-18-osint-source-expansion.md. Catalog access claims do
not establish Shodan entitlement; the current primary review above governs
this choice. No independent research/catalog file was edited.

Projection: ip_str, port, transport, hostnames, domains, org, isp, asn,
product, version, timestamp and cloud.provider/region/service. Fields are
bounded and literal, with local canonical comparison only. Unknown fields
are discarded; known content-bearing fields refuse the response. Raw
storage is always omitted. No banner, HTTP body, certificate, screenshots,
credentials, code, DNS endpoint, host lookup, scan or target is fetched.

Missing PTR names, virtual hosting, unsupported services, cloud-attribution
gaps, stale/reassigned addresses, index lag and local caps all limit leads.
An exact boundary is a source association, not proof of ownership, current
reachability, public exposure, misconfiguration, compromise or maliciousness.
Even stable totals and distinct endpoints cannot detect every paging drift
or provider omission. Empty output establishes no absence.

## Unchecked Material and Live Acceptance

No authenticated account/subscription/key, contract amendments, full SDK
implementation, unrelated API operations, protocol Datapedia definitions,
all outbound documentation links, checkout or external subprocessor policies
were reviewed. The full relevant search contract, selected field definitions,
primary terms/privacy and access pages were reviewed. This is not a review
of all Shodan products or another provider.

Keep source unapproved and collection off. Separately approve actual
key/tier/purpose/terms/handling, exact query disclosure, live changes and a
small measured acceptance of projection/schema, pagination, index lag,
request/body sizes, duration, real credit debits, quota/cooldown, freshness
and restart recovery. Synthetic tests establish local invariants only.
