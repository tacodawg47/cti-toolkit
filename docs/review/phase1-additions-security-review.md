# Security review of the 2026-11-02 additions

Scope: everything added after the Phase 1 fix verification, i.e. commits
4d90711, 9bad05f and 6551825: hashlookup, rdap, internetdb, yaraify and
crtsh clients; app/core/allowlist.py and the Tranco gate; the "query anyway"
override; the `follow_redirects` and `expect` options on `fetch_json`; the
template and health-page changes. Method: code read plus offline probes
(no network). No code was changed.

## Checked and found sound

- **No injection into vendor requests.** Every value that reaches a URL path
  or query has already passed `detect_type`: hashes are hex only, IPs are
  parsed by `ipaddress`, domains match the strict label regex (so no `%`,
  `/`, `?`, `#` or `@` can reach crt.sh's wildcard search or an RDAP path).
- **Tranco gate cannot be tricked by URL syntax.** `urlsplit().hostname` is
  used, so `https://google.com@evil.com/`, `https://evil.com#@google.com` and
  `https://google.com.evil.com/` all go to the vendors (probed). Case and an
  explicit port do not matter. Subdomains of popular hosts are never excused.
- **No key exposure.** The four new keyless clients send no key; YARAify
  sends the abuse.ch key in a header only; transport errors are still
  reported by exception type, never message.
- **Rendering is escaped.** File names from YARAify and hashlookup,
  certificate names from crt.sh, registrar names from RDAP and rule names
  all pass through Jinja autoescape or the `fmt` filter (string join), so
  vendor-supplied HTML is inert.
- **The override is covered by the CSRF check.** `force` is a form field on
  the same POST that `_reject_cross_site` guards; a cross-site page cannot
  use it to burn quota on an allowlisted domain.
- **Redirects stay off** for every client except RDAP, so a 3xx from any
  other vendor is reported, not followed.
- **The private-IP gate cannot be overridden**, by design.

## Findings

Update 2026-11-02 (later): all seven findings below were fixed in the
working tree with nine new tests (128 total, all passing). The "worth
knowing" items at the end remain as notes.

### M1. Internationalised and homograph domains are rejected as "unknown"
File: app/core/indicators.py (DOMAIN_PATTERN, `_is_host`)

Not a vulnerability, but the biggest practical weakness found. Phishing
domains that use non-ASCII letters (Cyrillic `о` in `gооgle.com`, or a plain
`münchen.de`) do not match the ASCII-only regex, so the toolkit says "could
not recognise" and looks nothing up (probed). The punycode form
`xn--mnchen-3ya.de` works. Analysts paste the Unicode form, because that is
what appears in the email.

Fix: in `normalise`, after refanging, convert any non-ASCII host to punycode
with the `idna` package (already installed as an httpx dependency):
`idna.encode(host).decode()` for a domain, and the same on the hostname of a
URL. Show the punycode in the "cleaned to" line so the analyst sees the
homograph. Add tests for the three probe rows.

### M2. Vendor responses have no size cap and no total deadline
File: app/modules/enrich/base.py (`fetch_json`), crtsh.py

`resp.json()` reads the whole body into memory, and httpx's `timeout=20`
is a per-phase limit (connect, each read, write), not a total one. A vendor
that trickles a large body can hold a request open for minutes and consume
memory. crt.sh is the realistic case: an identity search for a large domain
returns tens of thousands of rows even with `exclude=expired`, and the
Tranco gate only protects you when the list is loaded and the domain is on
it. A hostile vendor is not the threat model; a slow public service is.

Fix: in `fetch_json`, stream the response and stop at a byte cap (for
example 5 MB), returning "vendor response too large"; and give the registry
a total per-vendor deadline with `asyncio.wait_for(m.lookup(...), 30)` that
turns a timeout into an error card. The second half is M4 from the original
review, which is still partial.

### L1. RDAP follow-redirects does not insist on HTTPS
File: app/modules/enrich/rdap.py:118, base.py

rdap.org redirects to whichever server IANA lists for the TLD or RIR. If a
registry lists a plain `http://` URL, the domain or IP under investigation
travels in cleartext. Also, `fetch_json` does not expose the final URL, so a
client cannot check. Low likelihood (the bootstrap registry is nearly all
HTTPS), but the toolkit's own rule is that indicators never leave the
machine unencrypted.

Fix: have `fetch_json` return the final URL (or just its scheme) when
redirects are followed, and let the RDAP client reject a non-HTTPS final
hop. Alternatively follow the one redirect manually: read `Location`,
require `https://`, request again.

### L2. hashlookup gates the fan-out even when no trust score is present
File: app/modules/enrich/hashlookup.py:34

A record without `hashlookup:trust` is treated as clean (probed) and
therefore skips VirusTotal, abuse.ch and YARAify. hashlookup aggregates
public catalogues, and NSRL in particular contains dual-use tools. The trust
score is the only quality signal we have, so its absence should not be read
as "trusted".

Fix: keep the card as "clean" only when `trust` is present and at least
`MIN_TRUST`; otherwise mark it "unknown" with a "catalogued, no trust score"
note. The registry gate already keys off "clean", so it then stops skipping
in that case. One test.

### L3. A bad Tranco file stops the app from starting
File: app/core/allowlist.py:38-50

`load()` catches `OSError` but not `UnicodeDecodeError` (probed with one
Latin-1 byte: it raises). `load()` runs inside the lifespan, so a corrupt or
wrongly saved CSV turns into "app will not start" with a decode traceback,
instead of "allowlist not loaded" on the health page.

Fix: catch `(OSError, UnicodeDecodeError, csv.Error)`, remember the error
text, and show it in the health card.

### L4. YARAify crashes on a `data` that is not an object
File: app/modules/enrich/yaraify.py:44

`body.get("data") or {}` followed by `.get()` raises if the vendor ever
returns a list (probed). The registry turns that into a "client crashed"
card, so it is contained, but the message is unhelpful.

Fix: `if not isinstance(data, dict): return error dict`, mirroring the
isinstance guard in `fetch_json`.

### L5. The health page shows absolute filesystem paths
File: app/templates/health.html (data directory, Tranco path)

Both lines include your Windows username. Harmless on a loopback-only app,
and already noted in the Phase 1 review, but it now appears twice. Before
any public release, render the paths relative to the project root.

## Not findings, but worth knowing

- **Third parties see what you investigate.** rdap.org, the registries,
  crt.sh and CIRCL now receive every domain, IP or hash you look up, like
  every other vendor. The Tranco and hashlookup gates reduce that surface;
  the data-handling section of the roadmap should list the keyless sources
  with the keyed ones.
- **Memory at TRANCO_TOP_N=1000000** is roughly 100 to 150 MB for the
  rank dictionary. Fine on a workstation; worth a sentence in the runbook.
- **pip-audit** has not been run since the dependency trim. It needs one
  install into the venv (approval required by the working agreement).
