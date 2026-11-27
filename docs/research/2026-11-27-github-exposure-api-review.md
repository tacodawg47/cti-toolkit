# GitHub Public-Code Exposure API Review

Date: 2026-11-27. Public documentation research only. No search, account,
credential probe, provider data request, purchase, download or installation.
Source eligibility remains unapproved. This review does not enable collection.

## Current Primary Documentation

Read the search overview and complete Search Code endpoint section, including
its parameters, authentication statements, response example and fields:
[REST Search](https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28#search-code).
Code search states authentication is required and has a 10 requests/minute
limit. Its generated token section lists fine-grained PAT and GitHub App
tokens with no permissions, then contradicts the authentication requirement
by saying public resources allow anonymous access. This is a real access
documentation gap, not verified anonymous entitlement. Standard JSON provides
file path, blob SHA, html_url and repository metadata. Text-match media adds
content fragments and is excluded. Search has a 1,000-result ceiling,
repository-scope limits and incomplete_results for provider timeouts. Only
default-branch files below 384 KB are considered. Page and per_page are
documented; deprecated sorting controls are omitted locally.

Read the complete [Legacy Code Search](https://docs.github.com/en/search-github/searching-on-github/searching-code)
guide. REST uses this syntax, not the newer website search language. It
documents in:file, organization/repository qualifiers, restricted fork
indexing, repository size/activity restrictions and exclusion of archived
repositories. Punctuation can be ignored, so an exact submitted domain does
not establish an exact domain occurrence. An organization string is search
text here, not an inferred GitHub organization account. The guide does not
establish is:public as a legacy code-search qualifier. Do not rely on the
repository-search visibility qualifier to constrain code search.

Read [Authentication](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api).
Tokens act with the holder's accessible resources. Fine-grained permissions,
SSO policies and token type affect access. Invalid or insufficient credentials
can return 401/403/404. The app must not assume a token's presence proves
scope, entitlement or approval. No account or token was inspected or tested.

Read [API Versions](https://docs.github.com/en/rest/about-the-rest-api/api-versions).
2026-03-10 and 2022-11-28 are supported; the latter ends support on
2028-03-10. The consumer deliberately pins 2022-11-28, matching the established
clients. No existing client is upgraded. Only the opening 2026 breaking-change
notes were inspected; a full version-upgrade review was not performed.

Read the complete [Pagination Guide](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api).
It describes Link relations and page-size controls. Local requests reconstruct
only fixed page numbers 1 and 2 at the fixed search endpoint. Returned Link
URLs, content URLs, git URLs and redirects cannot select another destination.
The guide's sample scripts were not executed or imported.

Read the complete [REST Rate Limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)
guide. General unauthenticated REST is 60/hour and PAT-authenticated REST
normally 5,000/hour; these do not override the smaller code-search limit.
Primary and secondary limits can produce 403/429. Honor Retry-After and
zero-remaining/reset headers. Secondary limits also depend on concurrency,
compute and unpublished controls. Limits can change. Headers are authoritative;
there is no live quota entitlement measurement in this review. No rate_limit
endpoint was queried. Local policy uses finite backoff and three total
attempts, not token rotation or parallel accounts.

## Terms, Privacy and Costs

Read the full [Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service),
effective 2026-04-27, including API terms. API abuse can cause suspension;
sharing tokens to evade limits and spam-related data collection are prohibited.
Public repository access does not establish an unrestricted redistribution
license. Special organizational contracts can apply. High-throughput or resale
access may require subscription arrangements. This local consumer does not
adopt a dataset, redistribute repository contents or offer a public service.
Current operator-specific contracts and lawful purpose still need review.

Read the full [Acceptable Use Policies](https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies).
They restrict excessive automated bulk activity, unauthorized access and
personal-information misuse. Public, non-personal research use has an
open-access publication condition. API collection is distinguished from
scraping, but privacy and information-use restrictions apply to both. This
review does not determine that all returned metadata is non-personal or
approve a professional processing purpose. Removal/suppression obligations
need an operational handling decision; suppression here stops future queries
and is not a delivered privacy-deletion workflow.

Read the [General Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement),
effective 2026-04-27, including collection, processing, sharing, international
transfers, retention, rights and state-specific sections. GitHub collects
usage/device/IP information and processes data internationally. Sending a
private watch selector is a disclosure even when the searched index is public.
No fixed query-log retention guarantee or confidential-search entitlement
was verified. Query/credential submission therefore remains separately approved.

Inspected the plan descriptions and main published prices at
[GitHub Pricing](https://github.com/pricing) and
[GitHub Plans](https://docs.github.com/en/get-started/learning-about-github/githubs-plans).
Free is listed at USD 0; Team at USD 4/user/month and Enterprise at
USD 21/user/month. No separately metered ordinary code-search request price
was identified in the reviewed endpoint/pricing material. That is not a
contractual zero-cost guarantee or an account entitlement verification.
Paid Secret Protection is a different product and is not used here.

## Existing Clients and Local Choice

Revisited sources/github.py, feeds/poc.py and the GitHub advisory portion of
feeds/supply.py in vulnerability_intelligence. The manual CVE client can fetch
READMEs; neither it nor its content-fetch method is called by this consumer.
Reuse the existing app loop, httpx client, GitHub limiter, durable scheduler,
evidence and inbox. Keep Phase 2 behavior intact. The .env.example comment
that incorrectly called the 30/minute repository limit a code-search limit
is corrected. No SDK, third-party source code or dependency is added.

Revisited the 2026-11-11 summary and relevant Bushido tool rows for GitHub
Code Search, Yar, GitGot and Git Hound, plus the 2026-11-26 OSINT findings
and 3A.3 API/pattern reviews. These historical catalogs are candidate evidence,
not current adoption approvals. No listed secret-hunting tool is imported,
installed, run or freshly evaluated for adoption.

Local choice: a dedicated GITHUB_EXPOSURE_TOKEN with separately reviewed
public-only access, plus a default-false human access attestation. Never
inherit the potentially broader Phase 2 token. Bind each permission to the
credential digest, API/query versions and exact selector/query. An attestation
is not an automated scope check. Access support, public-only scope and actual
response behavior still require separately approved measured live acceptance.

Only repository ID/full name, file path, blob SHA and the literal validated
html_url survive normalization. Dates, profiles, descriptions, snippets and
other unknown fields are discarded. Source/file dates stay unknown. Strict
bounded ASCII references exclude some legitimate names, encoded paths and
branch references. Common secret guards are best effort, not universal secret
recognition. Raw bodies are omitted even under generic archive settings.

## Unchecked Material and Activation Gaps

No authenticated account pages, actual token permissions, organization policy,
enterprise/customer contracts, checkout, provider schema/latency/index lag,
search results, repository/code/blob/README contents or credentials were
accessed. The pricing comparison/add-on contracts, all outbound policy links,
individual app/token management guides and unrelated REST endpoints were not
reviewed in full. The complete relevant code-search section and primary
terms/AUP were reviewed; this is not a claim to have read all GitHub products'
documentation. No provider data request was used to resolve the contradictory
authentication statements or public-only token support. Keep registry terms
unapproved until the real access, purpose, handling and contractual scope
are accepted separately.
