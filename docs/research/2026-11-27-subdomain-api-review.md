# CTLogs Passive Inventory API Review

Date: 2026-11-27. Subphase 3A.5. Public documentation only. No domain query,
API data request, account, key, purchase, service code, download or install.

## Reading and Provider Choice

Read the complete public [API documentation](https://api.ctlogs.dev/),
[terms](https://ctlogs.dev/terms), [privacy](https://ctlogs.dev/privacy),
[about](https://ctlogs.dev/about), homepage and submitted
[crt.sh comparison](https://ctlogs.dev/crt-sh-alternative). Inspected the
[coverage page](https://ctlogs.dev/logs). Read the complete relevant hosts
operation, HostRow/HostList, parameters, security, quota headers and errors in
[OpenAPI](https://api.ctlogs.dev/openapi.json). The remaining unrelated
OpenAPI definitions were not reviewed in full. No example Run button or data
endpoint was invoked. Read the 3A.3 CT API/pattern and 3A.4 GitHub reviews.

Revisited 3A.3 alternatives: crt.sh still has unverified current hosted-service
terms/schema; its existing provisional lookalike adapter stays separate.
SSLMate was only partly reviewed then and is not adopted here. Neither is a
fallback. No fresh SSLMate adoption review, Censys review or combined index
is claimed. No GPL/AGPL or provider implementation was imported.

Choose only GET /v1/hosts/{exact-domain}, keyed, for the current certificate
window. The other domain/subdomains methods return certificate rows, not
one row per name. hosts-history and first-seen have other tiers and date
semantics and are excluded, as are certificate bodies, web JSON and MCP.

## Contract and Important Date Distinction

The hosts operation includes the apex and literal wildcard names, ordered
by reversed labels, up to 100 rows per page. Continue at the same endpoint
with after=next_cursor. Tokens are opaque. Paging after page one needs a key.
The documented fields are host, certs, first_seen, last_seen and last_not_after;
HostList permits hosts:null for no matches. has_next and next_cursor indicate
continuation. history_window_days identifies the window.

OpenAPI HostRow explicitly defines first_seen and last_seen as earliest and
latest certificate validity starts in this window, and last_not_after as
latest certificate expiry. These are not SCT logging dates, registration,
DNS activity or local first capture. Retain their literal spelling separately;
missing/null dates remain unknown. Generic observation/publication/modified
and CT logging dates remain unknown. No certificate/log reference is supplied
by HostRow. Literal host citations are passive text, not invented URLs or
original-log citations. Source capture/digest/row position provide provenance.

The window covers certificates valid now or expired within 90 days. It does
not establish live DNS, ownership, a dangling service, compromise or
maliciousness. Names without certificates, private/unlogged certificates,
older expired names, provider lag and local page caps limit inventory. The
coverage page is a provider assertion, not an independent completeness audit.
Pagination is not an atomic snapshot; ordered termination checks cannot detect
all omissions or drift. Empty output does not establish absence.

## Access, Cost and Terms Gaps

API docs list anonymous 100/day, free key 100/hour plus 10,000 monthly credits,
Standard USD 50/package/month and Pro Lite USD 100/package/month, each 50,000
credits/package. Pro starts at USD 250/month. Ordinary hosts pages cost one
credit. Paid entitlement/prices are those agreed with the provider, not a
locally verified subscription. Refused requests and documented busy responses
are uncharged; local reservations remain conservatively charged.

Terms effective 2026-11-17 restrict free/anonymous use to non-commercial
purposes and require visible credit when showing results to others. Business
operations need a paid key. Redistribution, bulk feeds and competing databases
need additional written permission. All plans lack a completeness guarantee.
Paid service credits and liability limits are described in the terms.

Real documentation gap: terms state 100/hour for anonymous access while API
docs say 100/day. Keyed-only local implementation avoids relying on anonymous
paging. Actual key, purpose, free versus paid eligibility, contract, privacy/
retention handling and schema still need direct separately approved measured
acceptance. No account entitlement is inferred or approved. Settings default
blank and the source registry remains unapproved/disabled. The configured tier
is a human review record, not an automated entitlement check.

## Privacy and Local Limits

Privacy effective 2026-11-10 describes 30-day query/status/time logs with
truncated IP hashes and key attribution, transient IP counters, EU storage,
Cloudflare TLS termination, account/sign-in retention and rights procedures.
Submitted domains disclose a private watchlist even when results are public.
Read the whole policy including accounts, correspondence and subprocessors.
No account/signup, analytics, external subprocessor policy or contact action
was performed. Account-specific agreements and actual retention behavior
were not verified. About-page cookie wording differs from the privacy
policy's signed-in session description; this API client uses no account UI.

Local policy: at most ten separately approved exact domains, two 100-name
pages each, 20 requests/40 MiB/120 seconds per attempt, 2 MiB/30 seconds per
response, 256 KiB normalized page, three attempts, 20/minute and 48/day.
One runner makes requests sequentially. Durable monthly/hourly/daily zero
headers pause to the next UTC boundary; 429/503 honor bounded numeric
Retry-After with finite backoff. These are conservative local limits, not a
provider entitlement or a global quota service for other applications.

Unknown remote fields are discarded and sensitive raw bodies forced omitted.
No external host, cursor URL, redirect, target, DNS name, certificate or page
is followed. Native-browser, Linux and measured live acceptance are separate.
