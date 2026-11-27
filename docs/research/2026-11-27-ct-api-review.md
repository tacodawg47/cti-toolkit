# CT Watch API Review

Date: 2026-11-27. Public documentation research only. No selector query,
provider data endpoint, account, checkout, key, install or live change.

Update: the operator directly authorized the provisional disabled crt.sh
adapter after the specific documentation gap was presented. This permits
offline implementation and tests only. It does not approve hosted-service
terms, source enabling or any selector/provider data request. The adapter
adds no automatic source approval. The decision-pending wording below
describes the earlier point in this same subphase and is superseded here.

## crt.sh Candidate

Revisited app/modules/enrich/crtsh.py and the historical 2026-11-11 source
reviews and 2026-11-26 OSINT review. The existing on-demand client uses
q/output=json/exclude=expired, caches results and truncates displayed names.
It does not provide immutable watch captures, bounded durable input recovery,
per-seed health or inbox matches. Its existing behavior was not changed.
Historical notes are not current terms approval for scheduled brand queries.

Read the full relevant maintainer discussions:

- [Automated use and identifiers, 2017-07-17](https://groups.google.com/g/crtsh/c/puZMuqBaWOE).
  The maintainer permits reasonable automation, discourages whole-database
  downloads and describes provider-local certificate IDs as stable.
- [Availability and access restrictions, 2017-09-21](https://groups.google.com/g/certificate-transparency/c/6IJ8eVBr9ro).
  It describes free public availability, terminated long queries, abuse
  blocking and no uptime guarantee. It is an old statement, not a current
  contractual assurance.
- [Rate limits, 2020-01-27 and later replies](https://groups.google.com/g/crtsh/c/NZJntKrBdmg).
  A historical announcement sets 60 requests per IP per minute. This does
  not verify today's quota. The suggested local future policy is much lower.
- [JSON documentation, 2020-02-07](https://groups.google.com/g/crtsh/c/IIb3h_v-P20/m/PJfiOc5PFQAJ).
  The maintainer explicitly describes certificate identity JSON output as
  intentionally undocumented and unstable.
- [JSON output discussion](https://groups.google.com/g/crtsh/c/sCpRljHP4dw).
  It describes output=json. That response is from a community participant,
  not a service access policy.

The current [repository README](https://github.com/crtsh/certwatch_db/blob/master/README.md)
only identifies the database schema. Inspected the header and parameter
declarations of its web interface implementation. It is GPL-3.0-or-later.
No implementation was copied, imported, installed or executed. It is not
a substitute for an API contract or hosted-service terms.

The [homepage](https://crt.sh/) timed out through the research fetcher.
A guessed /faq path was inaccessible. No current service-specific terms,
access tier, price schedule, contractual quota or complete supported JSON
schema was verified. The forum's Google Terms links concern Google Groups,
not the crt.sh service. Third-party assertions of free access were not
treated as provider terms. A provider data request was not used to fill gaps.

Specific unresolved decision: whether to allow an offline-only provisional
adapter for the existing undocumented JSON interface, with source terms
unapproved and collection disabled until separate live review, or require
verified current terms/access information before adapter implementation.
The operator subsequently chose the provisional disabled adapter. Implemented
only that API surface with conservative local bounds: ten exact authorized
seeds, ten requests/20 MiB/120 seconds per attempt, 2 MiB/30 seconds per
response, 200 certificate rows/1,000 names, 512 KiB normalized staging,
2/minute and 48/day, three total attempts. These are local limits, not claims
about the provider's present allowance. All collection stays disabled.

## SSLMate Alternative Inspected

Inspected its [API product/pricing page](https://sslmate.com/ct_search_api/),
[API v1 reference](https://sslmate.com/help/reference/ct_search_api_v1) and
[terms page](https://sslmate.com/policies/tos). This was an alternative
capability check, not a complete adoption review. The documented query takes
a specific domain with optional descendant/wildcard matching. It does not
document arbitrary brand-token search, so it cannot silently replace the
requested discovery surface. The product page distinguishes personal/
evaluation unauthenticated use from authenticated production use. Its Small
tier lists USD 0/month, 100 hostname and 10 full-domain queries per hour;
load can reduce limits. No account tier or entitlement was verified.
The guessed API reference path without _v1 returned 404; the canonical
v1 reference was inspected instead. No API data request was sent.

## Boundaries and Unchecked Material

No claim is made to have read every linked document, the full GPL service
implementation, authenticated pages or all SSLMate policy/reference sections.
Their partial inspection cannot satisfy the requested full adoption review.
Other CT providers, current account terms and live response schemas remain
unchecked. Do not approve a source registry entry from this note.

The local matching work needs no service access. CT-reported names and
wildcards establish neither registration dates nor DNS activity, ownership,
phishing or maliciousness. Certificate validity and entry timestamps require
their own literal fields; missing or naive dates must not be invented as
source observation/publication instants. A future adapter must retain these
distinctions and reject oversized/partial results without claiming coverage.

## Requested CTLogs Comparison

The operator also requested evaluation of
[ctlogs.dev/crt-sh-alternative](https://ctlogs.dev/crt-sh-alternative),
combination and alternatives. Read the entire submitted comparison page.
It advertises a compatible query shape but explicitly different response
fields. Its crt.sh uptime claims are provider marketing measurements, not
independent verification performed here.

Read CTLogs' complete [API reference and pricing](https://api.ctlogs.dev/),
[terms](https://ctlogs.dev/terms), [privacy](https://ctlogs.dev/privacy),
[about](https://ctlogs.dev/about) and homepage text. Inspected its
[coverage page](https://ctlogs.dev/logs) and machine-readable API overview,
without querying any certificate endpoint or following individual log links.
The documented organization search matches subject O=, not DNS brand tokens.
Exact domain/descendant APIs do not discover unrelated brand-bearing apexes.
Free/anonymous data covers valid certificates and those expired within 90
days; deeper history is tiered. API docs specify 100 anonymous requests/day,
while terms say 100/hour. Use the stricter allowance pending clarification.
Free keys are non-commercial; paid plans start at USD 50/month per package.
No plan/account/entitlement was obtained or verified.

Terms effective 2026-11-17 permit bounded non-commercial research and require
visible attribution when results are shown to others. Business operations
need paid access. Redistribution/competing database use needs additional
permission. No local terms acceptance or legal conclusion is implied.
Privacy effective 2026-11-10 describes 30-day query logs, hashed request IPs,
Cloudflare TLS termination and EU-hosted storage. Public CT source data does
not make an organization's submitted watch seeds non-sensitive.

Decision: retain provisional crt.sh alone for this exact-label discovery
slice. CTLogs is a candidate for later domain/hostname inventory and dated
CT context. Its web JSON route is not used to bypass the documented API
surface or its terms. Combining providers may improve index availability,
but would increase disclosed selectors, traffic and integration scope, and
duplicate CT logs are not independent corroboration. Keep source/capture
identity separate if a later approved slice adds it. SSLMate remains another
domain-focused option, subject to the incomplete review recorded above.

Not checked: CTLogs OpenAPI JSON in full, MCP functionality, authenticated
account/checkout, external infrastructure links, individual CT logs, actual
response latency/completeness and a new Censys/other paid search-provider
review. Those are not silently approved alternatives. No service code,
dataset, certificate body, MCP connection or account was imported or created.
