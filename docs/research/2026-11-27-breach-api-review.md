# Breach Lookup API Review

Date: 2026-11-27. Selected provider: Have I Been Pwned (HIBP).
Selected delivery: direct lookup of explicitly approved watched email addresses.
Public documentation research only. No API data endpoint, test endpoint,
account creation, checkout, key use or selector submission was performed.

## Current Primary Sources

Read the full [v3 API documentation](https://haveibeenpwned.com/API/v3),
including authentication, all endpoint descriptions, response models, test
addresses, limits, acceptable use and licensing. Direct email search requires
a subscription key and identifying User-Agent. Email matching is case
insensitive. The full response is requested with `truncateResponse=false`.
The adapter keeps names, display titles, provider dates, category flags,
attribution and literal disclosure references. Descriptions and other fields
are discarded. Sensitive and retired breaches are excluded from public
account searches. A 404 can include opted-out accounts and means no publicly
disclosable match. The API documents 429 Retry-After. Breach/paste API data
is CC BY 4.0 with visible linked HIBP credit. Domain and stealer-log searches
require separate verification and access. Neither is selected here.

Read the full [Terms of Use](https://haveibeenpwned.com/TermsOfUse), dated
2026-10-27. They restrict harmful use, solicitation, key redistribution,
resale of the data itself and substantially similar breach services. They
place consent, lawful processing and information-security responsibilities
on the subscriber. Subscription renewal, cancellation, payment, liability,
termination and definitions were also read. The selected use is private
defensive monitoring of a small approved watch set, not a public search service.

Read the full [pricing page](https://haveibeenpwned.com/Subscription),
including all three plan tables and FAQs. Core permits direct email searches
for own users/customers. Core 1 lists USD 4.39/month billed as USD 52.68/year
before applicable taxes. Pro starts at USD 379/month billed annually.
K-anonymity requires Pro or High RPM. The actual account RPM and entitlement
must be checked before activation; no subscription was selected or purchased.

Read the full [sign-in page](https://haveibeenpwned.com/Dashboard/SignIn?ReturnUrl=/Dashboard).
Sign-in offers an emailed verification link or an existing passkey. Pricing
requires email verification before payment. The operator must complete any
account, payment and verification steps manually after direct approval.
Account verification does not establish employee consent or submission authority.

Read the full [Privacy Policy](https://haveibeenpwned.com/Privacy). It
describes limited logging, overseas storage, sensitive-search restrictions,
correction and opt-out choices. Direct email search discloses the address
in the HTTPS path to the service. Local labels do not encrypt stored results.

## Existing References and Selection

Revisited the Phase 1 shared HTTP client/limiter, durable feed transport,
RansomLook staging/atomic inbox consumer and historical 2026-11-11 source
summary and Bushido tool findings. Revisited the 2026-11-26 OSINT review's
HIBP and shared email-adapter recommendations. Searching project code and
the installed MIT cti-skills scripts found no existing HIBP client to port.
The new consumer is original code against the published interface. It reuses
the app loop, pooled client, limiter, durable quotas/cooldowns and evidence.

HIBP was selected for its documented bounded association response and
absence of passwords/account source records. The delivery uses full breach
metadata to preserve category caveats and provider dates. It never follows
descriptions, references, redirects or logos. Synthetic fixtures establish
application behavior only. No live terms acceptance or legal basis is inferred.

## Unchecked Material and Activation

The guessed `/Pricing` page was inaccessible. The documentation's canonical
`/Subscription` link was read instead. `/API/Key` redirected to sign-in;
no authenticated dashboard or checkout was inspected. Actual account tier,
RPM, price at checkout, active expiry and provider response schema remain
unverified. Recheck them before approved live acceptance.

Other candidate providers (Hudson Rock, Intelligence X, LeakCheck and
breach.house) were not newly reviewed or integrated. Historical source
findings do not establish their current terms. CLI/MCP implementations,
third-party SDKs, linked blogs, brand assets, payment-provider terms and
organization-specific DPA/legal review were not selected for integration.
No claim is made to have reviewed every outbound link on these pages.
No software or source datasets were downloaded or imported.

Source review, individual email submission permissions, consent references,
paid access, schedule/worker enabling, migration/restart and measured live
acceptance each remain operator actions after direct approval. No provider
or watch is enabled by this review. See [Runbook](../runbooks/breach-lookups.md).
