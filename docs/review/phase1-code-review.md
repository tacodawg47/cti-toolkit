# Phase 1 code review

Reviewed 2026-10-29 against commits f43656b, 14975c9, cb21313, 8be7b1e.
Scope: app/core, app/modules/enrich, app/main.py, templates, run.py, tests.
No code was changed. The offline unit suite (49 tests) passes. Three live
checks were made with approval after the review; results are folded into
M8, M12 and L10 and summarised at the end.

Checks that passed outright: the app binds to 127.0.0.1 by default; keys are
read only from .env and only their presence is rendered; .env was never
committed and no key-shaped strings exist anywhere in git history; the
committed planning transcript zip does not contain any current key value;
there is no AI anywhere in the core; urlscan only searches and never submits;
every vendor call goes over HTTPS with certificate verification; Jinja
autoescape is on, so vendor-supplied strings cannot inject HTML; the fan-out
in registry.py isolates a crashing vendor from the others.

Severity scale: High = fix before the next phase. Medium = fix during
Phase 1 clean-up. Low = clarity or polish, do when convenient.

---

## High

### H1. Local endpoints can be driven by any web page you visit (CSRF and DNS rebinding)
File: app/main.py (whole app), run.py

Problem: binding to 127.0.0.1 keeps the network out, but not the browser.
Any website open in the same browser can submit a cross-site form POST to
http://127.0.0.1:8000/enrich. The attacker cannot read the response, but can
burn your VirusTotal, AbuseIPDB and GreyNoise daily quota and make the
toolkit look up indicators of their choosing. With DNS rebinding (a hostname
the attacker flips to 127.0.0.1) the page becomes same-origin and can read
/health (which keys exist, the data directory path with your username,
package versions) and every enrichment result. This is the one real
"exposed to the internet" path for a loopback-only app, and it matters more
if the project is ever released publicly.

Fix (small, no new dependency):
1. Add Starlette's TrustedHostMiddleware with allowed_hosts
   ["127.0.0.1", "localhost"]. That kills rebinding, because a rebound
   request arrives with the attacker's Host header.
2. On POST /enrich, reject requests whose `Sec-Fetch-Site` header is
   `cross-site` (modern browsers always send it). That blocks cross-site
   form posts without a token system. Return 403 with a short message.
3. Keep `docs_url=None` until there is a JSON API (see L12).

### H2. The 127.0.0.1 rule is one .env line away from being broken
File: app/core/config.py:35

Problem: `host` is an ordinary setting, so `HOST=0.0.0.0` in .env (or in the
shell environment, which pydantic-settings reads first) exposes the whole app
to the LAN with no authentication. The project rule says the app binds to
127.0.0.1 only; the code does not enforce it.

Fix: add a pydantic `field_validator("host")` that raises unless
`ipaddress.ip_address(host).is_loopback` (and allow the literal "localhost").
If remote access is ever wanted, make it a separate explicit setting with
auth, not a host override.

---

## Medium

### M1. A Claude session transcript is committed to the repo
File: a conversation-transcript archive committed under docs/ (~3 MB)

Problem: your own .gitignore says session exports can contain pasted keys
and ignores docs/exports/, but this one was committed under docs/. I checked:
none of the six current key values appears in it, and no key-shaped
`KEY=<token>` strings exist. It still holds a full conversation (and whatever
personal context was in it) and will ship with any public release. It also
bloats every clone.

Fix: `git rm --cached` the file, move it to docs/exports/ (already ignored),
commit. Note that the bytes stay in history; since the repo is private and no
secrets are inside, a history rewrite is not worth the risk now. Decide before
going public.

### M2. The whole Settings object (with key values) is handed to a template
File: app/main.py:83, app/templates/health.html:9-10

Problem: `"settings": settings` puts every API key into the Jinja context.
The template only renders host, port and data_dir today, so the rule is
obeyed, but one future `{{ settings }}` or a debug dump breaks it silently.
The data_dir line also renders an absolute path containing your username.

Fix: pass only what the page needs: `{"bind": f"{settings.host}:{settings.port}",
"data_dir": settings.data_dir}`. Consider showing data_dir relative to the
project root.

### M3. Rate limiter can exceed the per-minute cap by one after a wait
File: app/core/ratelimit.py:93-101

Problem: after sleeping `wait` seconds the code re-prunes with
`now - window[0] >= 60`, but `asyncio.sleep` plus monotonic rounding can land
at 59.999, so nothing is pruned and the request is appended anyway, giving
rpm + 1 inside a minute. VirusTotal answers that with a 429, which is then
shown as an error and not retried.

Fix: loop instead of a single sleep: `while len(window) >= rpm: await
asyncio.sleep(max(0.05, 60 - (now - window[0]))); prune`. A 50 ms cushion is
enough.

### M4. No overall deadline: one slow vendor or a rate-limit wait stalls the whole page
File: app/modules/enrich/registry.py:45, every vendor `timeout=30`

Problem: the form POST waits for the slowest vendor. VirusTotal's limiter can
sleep up to 60 s, each HTTP call can take 30 s, and the browser shows a blank
spinner with no feedback. Nothing breaks, but "a slow vendor must not break
the response" currently means "the response waits for it".

Fix: wrap each lookup in `asyncio.wait_for(m.lookup(itype, value), timeout=20)`
inside the gather and turn `TimeoutError` into a VendorResult with
error="timed out after 20 s". Later (HTMX phase) load each card
independently so fast vendors render first.

### M5. Non-JSON or non-200 responses surface as "client crashed"
File: every vendor client (`resp.json()` line), e.g. virustotal.py:114

Problem: all clients check `status_code >= 400` then call `resp.json()`
unguarded. A 200 with an HTML error page (vendor maintenance, captive
portal), an empty body, a 3xx (httpx does not follow redirects by default),
or a JSON list instead of an object raises inside the client. The registry
catches it, so the page still renders, but the card reads
"client crashed: Expecting value: line 1 column 1" instead of a clear message.

Fix: one shared helper in base.py, e.g. `async def get_json(client, ...)`
that treats only 200 as success, catches `ValueError` from `.json()`, checks
the result is a dict, and returns `(status, body_or_None, error_text)`. All
nine clients then share one tested path and lose about 20 lines each.

### M6. Private, loopback and reserved IPs are sent to every vendor
File: app/core/indicators.py:46, registry.py:28

Problem: `10.0.0.1`, `127.0.0.1`, `192.168.1.1` or `fe80::1` are detected as
"ip" and fanned out to VirusTotal, AbuseIPDB, GreyNoise (10/day!), Shodan.
Pure quota waste, and the answers are meaningless.

Fix: after detection, if `ipaddress.ip_address(value).is_global` is False,
skip the fan-out and render one card: "private or reserved address, not
queried". Same check can note multicast/reserved.

### M7. No input normalisation, so the cache misses and quota is spent twice
File: app/core/indicators.py, app/main.py:49

Problem: `ABCDEF...` and `abcdef...` are the same hash but different cache
keys; `Example.COM` and `example.com` likewise. Hosts written as
`1.2.3.4:443` (very common in ThreatFox and C2 reports) detect as "unknown".
There is also no length cap on the form field.

Fix: in `refang` or a new `normalise()`: lowercase hashes and domains, strip
surrounding quotes/angle brackets and a trailing dot, split an `ip:port` into
the IP (keep the port in the result context), and reject input over 2048
characters with a friendly message.

### M8. Two verdict heuristics will cry wolf
Files: app/modules/enrich/shodan.py:39, app/modules/enrich/otx.py:52

Problem:
- Shodan: any CVE in `vulns` makes the host "suspicious". Shodan's CVE list is
  mostly version-inferred and most internet servers have at least one, so
  almost every IP will show SUSPICIOUS.
- OTX: any pulse makes it "suspicious". 8.8.8.8 and example.com sit in
  dozens of pulses, so they will show SUSPICIOUS too. The docstring admits
  this, but the UI does not.

Fix:
- Shodan: keep "unknown" and show the CVE count in the summary; only bad
  tags nudge to suspicious. If you want CVEs to count, require the
  `verified: true` entries (available in the host banners).
- OTX: the `/general` response carries a `validation` list and a
  `false_positive` list. Verified live 2026-10-29 for 8.8.8.8: `validation`
  was `[{"source": "false_positive", "name": "Known False Positive", ...},
  {"source": "whitelist", "name": "Whitelisted IP", "message": "contained in
  whitelisted prefix"}]` and `false_positive` held one entry with
  `"assessment": "accepted"`. (Its pulse count was 0 that day, so the
  heuristic happened to be right, but the fields are the robust signal.)
  Rule: if `validation` is non-empty, or any `false_positive` entry has
  assessment "accepted", verdict "clean" with the validation names in the
  summary, regardless of pulse count. Otherwise keep the pulse rule, and
  consider requiring 3 or more pulses for "suspicious".

### M9. Uncapped vendors have no politeness limit, and the Shodan key lives in the URL
File: app/core/ratelimit.py:30-31, app/modules/enrich/shodan.py:117

Problem: OTX, ThreatFox, MalwareBazaar and URLhaus bypass the limiter
entirely (not even a counter on the health page). That is fine for single
lookups, but the Phase 1 bulk-paste feature will fire hundreds of concurrent
requests at abuse.ch. Separately, Shodan only accepts the key as a query
parameter, so the full URL contains the secret; httpx logs full URLs at DEBUG
level, and any proxy or error message that includes the URL would leak it.

Fix: give the uncapped vendors a soft `{"rpm": 30}` entry so they are
counted and spaced. Never enable DEBUG logging for httpx. In the Shodan
`except httpx.HTTPError` branch, do not interpolate `exc` into the message;
use `type(exc).__name__` instead (good practice for all clients).

### M10. urlscan query string is built by interpolation
File: app/modules/enrich/urlscan.py:29-32

Problem: a URL containing `"` or `\` breaks the Lucene query and urlscan
returns 400, shown as an error. Rare, but cheap to fix.

Fix: escape `\` and `"` in the value before wrapping in quotes.

### M11. URLhaus "invalid" answers are reported as "not listed"
File: app/modules/enrich/urlhaus.py:25,38

Problem: `query_status` of `invalid_url` or `invalid_host` falls through to
"unknown / not listed in URLhaus", which is wrong and hides a bug in our
input handling.

Fix: mirror MalwareBazaar: `no_results` -> unknown; anything else -> error
with the status text.

### M12. ThreatFox bare-IP search: verified, no change needed
File: app/modules/enrich/threatfox.py:68

Checked live 2026-10-29 (approved): a `search_ioc` for the bare IP of an
`ip:port` IOC listed that day returned the entry with the default settings,
with `exact_match: false`, and with the full `ip:port`. The client's current
query is correct. Closed.

---

## Low (correctness and robustness polish)

### L1. Cache never purges expired rows; `set` shadows a builtin
File: app/core/cache.py:33

Expired rows are skipped but never deleted, so the table only grows. Add
`DELETE FROM cache WHERE expires_at < ?` in `init_db()` or on first write of
the day. Rename `set` to `put` so a future `set()` inside the module does
not surprise a reader.

### L2. SQLite details
File: app/core/db.py, app/core/config.py:42

- `check_same_thread=False` is unnecessary (connections never cross threads)
  and the comment says the opposite of what the code does. Drop the flag.
- `PRAGMA journal_mode=WAL` is persistent; run it once in `init_db()`, not on
  every connection.
- `settings.db_path` calls `mkdir` on every access (every cache read). Make
  the directory once in `init_db()`.
- Pass `timeout=5` to `sqlite3.connect` so a rare write collision waits
  instead of raising "database is locked".
- The rate limiter and cache do blocking SQLite I/O on the event loop.
  Acceptable for a single-user local app; note it in a comment so nobody
  copies the pattern into the scheduler later.

### L3. VendorResult fields are looser than the code assumes
File: app/core/models.py:20-27

`VERDICTS` is defined but unused; `verdict: str` accepts anything. Use
`Literal["malicious", "suspicious", "clean", "unknown", "error"]`. Error
paths are inconsistent: some return `verdict="error"`, some leave "unknown"
and set `error`. The template then sniffs the error text for the word
"configured" (index.html:19) to pick a badge. Add an explicit
`status: Literal["ok", "not_configured", "quota", "error"]` and branch on
that.

### L4. `raw` is inconsistent and never shown
Files: greynoise.py:84, otx.py:108, shodan.py:145 (raw = summary again);
threatfox/malwarebazaar/urlhaus (no raw); virustotal (whole attributes).

The roadmap promises "raw vendor JSON" per card. Either store the real body
everywhere and add a collapsed `<details>` block in the card, or drop the
field until then. VirusTotal file attributes can be hundreds of KB; keep
`last_analysis_results` and `pe_info` out of the cache.

### L5. VirusTotal denominator counts non-engines
File: app/modules/enrich/virustotal.py:45

`total` sums every stat, including `timeout`, `type-unsupported`,
`confirmed-timeout`, `failure`. Sum only harmless + malicious + suspicious +
undetected so the ratio matches VT's own display.

### L6. "Clean" means different things per vendor
File: app/modules/enrich/abuseipdb.py:33

AbuseIPDB returns "clean" for "nobody has reported it", while abuse.ch
returns "unknown" for the same absence of evidence. Either make AbuseIPDB
"unknown" with a "0 reports" note, or document in the runbook that "clean"
from AbuseIPDB is weak. Also consider an aggregate verdict line at the top
of the results (worst-of across vendors, with the source named).

### L7. Lists and dicts render as Python repr
File: app/templates/index.html:41

`{{ v }}` on tags, ports, pulse names or URLhaus blacklists shows
`['a', 'b']` and `{'spamhaus_dbl': ...}`. Add a tiny Jinja filter (join lists
with ", ", render dicts as nested rows).

### L8. Refang coverage
File: app/core/indicators.py:25

Handles the common forms. Missing: `[dot]`, `(dot)`, ` dot `, `\.`, `hXxp`
(mixed case), `fxp://`, `[/]`. Add a small table-driven replace and tests
for each, since defanged pastes are the daily input.

### L9. Numeric-only "domains"
File: app/core/indicators.py:19

`1.2.3` matches the domain regex. Require the last label to be alphabetic
(TLDs never start with a digit).

### L10. GreyNoise runs on every IP lookup with a 10/day cap
File: registry.py:28, ratelimit.py:29

After ten IP lookups every later card shows "quota reached". Either make
GreyNoise opt-in (a checkbox on the form, which the planned bulk UI needs
anyway) or accept the noise. The community endpoint was verified live on
2026-10-29: keyless lookup of 8.8.8.8 returned HTTP 404 with JSON
`{"noise": false, "riot": false, "message": "IP not observed scanning the
internet."}`, which the client already handles as "not observed". The
endpoint is live and the 404 handling is correct.

### L11. Static mount at import time
File: app/main.py:37-39

`static_dir.mkdir()` runs on import (tests included) and the directory is
empty and untracked. Move it into `lifespan`, or create `app/static/.gitkeep`
and drop the mkdir.

### L12. /api/docs loads Swagger UI from a CDN
File: app/main.py:35

Every visit fetches JavaScript from cdn.jsdelivr.net and runs it in the
toolkit's origin. For a "nothing leaves the machine" tool, set
`docs_url=None` for now (the header's "API" link implies a JSON API that does
not exist yet), or self-host the two Swagger files when the API arrives.

### L13. Dependencies
File: requirements.in

`uvicorn[standard]` pulls httptools, watchfiles, websockets and colorama,
none of which Phase 1 uses; plain `uvicorn` is lighter and fits the "few
dependencies" policy. `python-dotenv` is redundant (pydantic-settings depends
on it and does the .env reading).

### L14. Stale runbook
File: docs/runbooks/running-the-app.md

Still describes the VirusTotal-only version (health page "VirusTotal quota",
file table without the other vendors). Update to match
enrichment-vendors.md.

---

## Testing gaps (no new dependency needed)

- httpx ships `httpx.MockTransport`. One fixture that returns a canned
  response lets you test every client's 404 / 429 / 401 / bad-JSON / timeout
  branches offline with `unittest`. Today only the `_summarise` helpers are
  tested; the HTTP branches (half of each file) have never run under test.
- Cache round trip: set `DATA_DIR` to a temp directory in `setUp`, call
  `cache.set` then `cache.get`, then an expired TTL, then `init_db` purge.
- Rate limiter: inject a clock (pass `now_fn=time.monotonic` to the class)
  and assert the sliding window, the off-by-one in M3, and `QuotaExceeded`.
- Registry: a fake module whose `lookup` raises; assert the other results
  still come back and the crashed one is an error card.
- Indicators: add the refang forms in L8 and the normalisation in M7.

---

## Additions worth doing in Phase 1

1. **One shared `httpx.AsyncClient`** created in `lifespan` and reused by all
   clients (connection pooling, one place for timeouts, headers, and a
   `User-Agent: cti-toolkit/0.1.0`, which several vendors ask for). Each
   client then becomes: build request -> `get_json` -> `_summarise`.
2. **Aggregate verdict** at the top of the results (worst-of, naming the
   vendor) so the analyst does not have to scan seven cards.
3. **Private-IP and allowlist gate** before fan-out (M6 now; Tranco and CIRCL
   hashlookup are already in the Phase 1 plan).
4. **URLhaus `/v1/payload/` for hashes**: free second opinion next to
   MalwareBazaar, same Auth-Key, five lines.
5. **Cache "age" on the card** ("cached 2 h ago") so the analyst knows how
   fresh a verdict is; `created_at` is already stored.
6. **Health page from `LIMITS`**: derive the quota table from the dict keys
   instead of a hard-coded tuple in main.py, so adding a vendor is one edit.
7. **Phase 1 scope still open** (not bugs, listed so nothing is forgotten):
   Shodan InternetDB, CIRCL hashlookup, RDAP, BGPView, ip-api, crt.sh,
   YARAify, bulk paste with background jobs and ETA, allowlist filter.

---

## Live verification (done 2026-10-29 with approval)

Calls made: ThreatFox `get_iocs` (1 day) plus three `search_ioc` variants,
OTX `/IPv4/8.8.8.8/general`, GreyNoise community `8.8.8.8`. One OTX request
and one keyless GreyNoise request spent quota; abuse.ch is uncapped.

- ThreatFox (M12): bare IP matches `ip:port` entries. Client is correct.
- OTX (M8): `validation` and `false_positive` exist with the shapes recorded
  above. Use them.
- GreyNoise (L10): community endpoint live; 404 "not observed" handled.
