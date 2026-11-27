# Ransomware Victim API Review

Date: 2026-11-26. Selected scope: one RansomLook recent-post snapshot.
Documentation research only. No provider API data request, source enabling,
credential use, download, installation or service-code reuse occurred.

## Current Primary Sources

Read the full [RansomLook About page](https://www.ransomlook.io/about), its
[API documentation](https://www.ransomlook.io/doc/) and the full published
[Swagger schema](https://www.ransomlook.io/swagger.json), API version 2.1.0.
The About page states that website/API/dataset content is CC BY 4.0 and
permits commercial reuse with attribution. It describes operator posts as
unverified claims. Its service-code license is AGPL v3. The repository's
license section also describes AGPL, although GitHub's label still says GPL.
No service code was copied or imported. The app credits and links RansomLook.

No numeric public request allowance was found in these documents. The local
proposal is one request per hour, one per rolling minute, at most 24 per
rolling day, with a six-hour stale threshold. These are courtesy bounds,
not a statement of an upstream quota or an activation decision. Review
again before approved live use, including any changed instance policy.

The schema defines `GET /api/recent/{number}` as a recent-post list. Select
only `https://www.ransomlook.io/api/recent/100`. A Post has title, group,
discovery time, optional website and original link. It can also carry
encoded HTML and screenshots. The adapter discards those fields and
descriptions, never decodes them and forces raw omission. Country and sector
are absent from this documented schema. Do not infer them from a name,
website, country-code domain or description. The prose examples for `/posts`
do not match its current statistics schema; the implementation uses the
explicit recent-post schema instead. No search, export, group expansion,
leak details, screenshot, torrent or actor endpoint is selected.

## Existing Clients and Historical Research

Revisited the existing Phase 2 ransomware.live group-profile adapter,
its scheduled registration and shared provider limiter. It reads CVE/group
relationships, not victims. Its 2026-11-03 terms comments and earlier source
reviews are historical evidence, not current permission. Also revisited
the source-review summary and its actor/attribution, Bushido tools and
ransomware notes. The installed reference clients have no existing
RansomLook adapter to port. The new adapter is original project code.

The 2026-11-13 roadmap decision already selects RansomLook metadata first.
This delivery uses the public API. Self-hosting, Tor and collectors remain
later work. The service license finding updates the old GPL wording; the
data-license finding is separate from the registry's activation gate.

## Unchecked or Unavailable Material

ransomware.live's current documentation and terms could not be verified.
The web reader failed for its `/api`, `/doc/api`, `/docs`, `/openapi.json`,
`/terms` and `/t&c` attempts across the public and PRO hosts. The browser
then explicitly blocked the PRO documentation under its site-safety policy.
No further access workaround was attempted after that block. Third-party
examples were discovery leads only and were not used as authority for an
adapter, quota or terms decision. Victim integration with this provider
remains deferred until its own full current documentation and terms can
be reviewed through an allowed route. Its existing Phase 2 code is unchanged.

RansomLook's `/doc/swagger.json` and `/api/swagger.json` guesses were
unavailable; the canonical `/swagger.json` was read successfully. Linked
API data routes were not called. Links to threat-actor infrastructure,
leaked material, social profiles and unrelated integrations were not followed.
No claim is made to have checked every link inside these sites. breach.house,
ransomwatch historical ingestion and other Phase 3 families were not selected
or newly reviewed in this bounded subphase.

## Activation Still Requires Approval

The registry and schedule stay disabled. A license statement does not enable
collection. Before live acceptance, obtain direct approval for the exact
endpoint, local budgets, migration/restart and bounded retrieval/recovery
measurements. Unknown dates stay unknown; discovery is aggregator discovery,
not a breach or attack date. Multiple claims are not independent confirmation.
