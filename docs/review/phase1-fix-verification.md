# Phase 1 fix verification

Verified 2026-10-29 against commits 4bf9269, e29ffd9, 5d22567 (on 29ea56f).
Method: read every changed file, ran the offline suite (76 tests, all pass),
and ran extra offline probes with httpx.MockTransport and Starlette's
TestClient (no network, no quota). No code was changed, nothing committed.

Deferred on purpose and not re-raised here: L4 (raw drill-down), L6
(AbuseIPDB "clean" semantics), L10 (GreyNoise opt-in).

## Summary

Of the 28 non-deferred findings plus six additions, 31 check out. Two are
partial (M4, M7) and one (M11) is implemented but introduced a status bug.
The refactor added three new defects, two of them worth fixing before the
next commit. Nothing new touches security.

---

## New defects introduced by the fixes

Update 2026-10-29 (later): N1, N2 and N3 were fixed in the working tree
(registry.py, urlhaus.py, indicators.py, main.py) with six new tests
(82 total, all passing). The "smaller gaps" section below is still open.

### N1 (Medium). Crashed-client and URLhaus-error results carry status "ok"
Files: app/modules/enrich/registry.py:106-109, app/modules/enrich/urlhaus.py:132-138

The new `status` field is what the template and `aggregate_verdict` branch
on. Two paths set `verdict="error"` but leave `status` at its default "ok":

- registry.py, the "client crashed" fallback;
- urlhaus.py, when `_summarise_*` returns the new `_error()` dict
  (invalid_url / invalid_host): the lookup builds a plain `vendor_result`
  with `error=` but no `status=`.

Verified offline: a crashing vendor yields `status='ok' verdict='error'`,
and `aggregate_verdict` then returns `{'verdict': 'error', 'sources': [...]}`,
so the page prints "Overall: ERROR (worst of urlhaus)". The card shows an
ERROR badge with no message, because the error paragraph only renders for
status not_configured / quota / error.

Fix:
1. registry.py crash branch: add `status="error"` (or call `base.failed`).
2. urlhaus.py: after `parsed = summarise(body or {})`, do what ThreatFox and
   MalwareBazaar do: `if parsed["verdict"] == "error": return base.failed(...)`.
   The "don't cache errors" guard then becomes unnecessary.
3. Belt and braces in `aggregate_verdict`: also skip `r.verdict == "error"`,
   so a future slip cannot reach the Overall line.
4. Add a registry test with a fake module whose `lookup` raises, asserting
   `status == "error"` and that it is absent from the aggregate. That is the
   test the review asked for, and it would have caught this.

### N2 (Medium). Refang rewrites "fxp" and "hxxp" anywhere in the string
File: app/core/indicators.py:40-41

The scheme substitutions are unanchored, so they fire inside legitimate
indicators. Verified offline:

| input | after normalise |
|---|---|
| `fxp-trading.com` | `ftp-trading.com` |
| `http://example.com/fxp/report` | `http://example.com/ftp/report` |
| `shxxp.example.com` | `shttp.example.com` |

The UI does say "cleaned to", but the vendor lookup silently runs on the
wrong indicator and the wrong value is cached.

Fix: only treat these as defanged schemes at the start of the input and when
followed by a scheme separator:

```python
s = re.sub(r"^h[xX]{2}p(?=s?(://|\[:\]//|\[://\]))", "http", s)
s = re.sub(r"^f[xX]p(?=(://|\[:\]//|\[://\]))", "ftp", s)
```

(Run these before the `[:]` / `[://]` replacements, as now.) Add the three
rows above as "must not change" tests next to the existing refang tests.

### N3 (Low). HOST=::1 passes the config validator but TrustedHost rejects it
Files: app/core/config.py:46-50, app/main.py:78

The validator accepts `::1`; the middleware allows only `127.0.0.1` and
`localhost`. Starlette keeps the brackets on IPv6 literals, so a request
with `Host: [::1]:8000` returns 400 "Invalid host header" (verified). With
the default host nothing is affected; with `HOST=::1` every page is a 400.

Fix: `allowed_hosts=["127.0.0.1", "localhost", "[::1]"]`, or build the list
from `settings.host` so the two can never disagree.

---

## Smaller gaps in the new code (Low)

- **fetch_json accepts non-object JSON** (base.py:107-110). A 200 whose body
  is a JSON list or string returns `(200, [..], None)`; the caller's
  `(body or {}).get(...)` then raises AttributeError and surfaces as
  "client crashed" (verified). Add `if not isinstance(body, dict): return
  200, None, "vendor returned unexpected JSON"`.
- **fetch_json does not catch httpx.InvalidURL** (base.py:100). It is a
  ValueError, not an HTTPError. Unlikely with validated input; cheap to add
  to the except tuple.
- **Overall line for a gated IP** reads "UNKNOWN (worst of (local))"
  (verified). Skip the aggregate when the only result is the local gate.
- **IPv6 is not canonicalised** (indicators.py:66). `2001:DB8::1` and
  `2001:db8:0::1` cache separately. In `canonical`, for itype "ip" return
  `str(ipaddress.ip_address(value))`.
- **normalise strips a trailing dot from URLs too** (indicators.py:52) and
  does not strip `domain:port`. Both rare; note for later.
- **USER_AGENT hard-codes 0.1.0** (base.py:24) while `app.__version__`
  exists. Import it so they cannot drift.
- **M4 is partial by design.** HTTP calls are capped at 20 s, but a
  VirusTotal lookup can still wait up to 60 s in the limiter before that
  clock starts. That is the intended "wait for a slot" behaviour; worth one
  sentence in the runbook so a 70 s page is not mistaken for a hang.
- **Untested:** the rate-limiter loop (M3) and the registry crash path (N1)
  still have no tests. The other MockTransport tests added are good.

---

## Finding-by-finding verification

| # | Finding | Status | Notes |
|---|---|---|---|
| H1 | CSRF / DNS rebinding | Fixed | TrustedHostMiddleware + Sec-Fetch-Site check. Verified: rebinding Host gets 400, cross-site POST gets 403, same-origin POST 200. See N3 for the IPv6 edge. |
| H2 | Host override to 0.0.0.0 | Fixed | field_validator accepts loopback/localhost, rejects 0.0.0.0; tested. |
| M1 | Committed transcript zip | Fixed | Zip is gone from the working tree and from all history (hashes rewritten). 29ea56f adds .gitignore patterns, a pre-commit hook, .gitattributes LF rule, a scrub runbook, and a CLAUDE.md rule. hooksPath is set in this clone. |
| M2 | Settings object in template | Fixed | Health gets `bind` and `data_dir` strings only. |
| M3 | Limiter off-by-one | Fixed | Sleep-and-reprune loop with 50 ms floor. Untested. |
| M4 | No overall deadline | Partial | 20 s per request on the shared client; limiter wait not bounded (by design, see above). |
| M5 | Non-JSON / non-200 handling | Fixed | fetch_json: only 200 + JSON is success; typed transport errors; tested. Gap: non-dict JSON (above). |
| M6 | Private IPs sent to vendors | Fixed | `_non_global_ip_note` gate before fan-out; tested for private and loopback. |
| M7 | Input normalisation | Mostly | ip:port stripped, trailing dot stripped, hashes/domains lowercased, 2048-char cap with a friendly page (verified). Port is not kept in context; domain:port not handled; IPv6 not canonicalised. |
| M8 | Noisy Shodan / OTX heuristics | Fixed | Shodan CVEs are informational only. OTX uses `validation` and accepted `false_positive`, matching the live-verified shape; tested. |
| M9 | Uncapped vendors; Shodan key in URL | Fixed | Soft rpm 30 for OTX and abuse.ch, counted on health. fetch_json never interpolates the exception. |
| M10 | urlscan quote escaping | Fixed | Backslash and quote escaped; tested. |
| M11 | URLhaus invalid_* as "not listed" | Fixed, with N1 | `_error()` path exists and is tested at the summariser level, but the lookup drops the status (N1). |
| M12 | ThreatFox bare IP | n/a | Closed by the live check; nothing to change. |
| L1 | Cache purge; `set` shadowing | Fixed | `put`; purge in init_db. |
| L2 | SQLite details | Fixed | WAL once, timeout=5, mkdir in init_db, no check_same_thread, loop-blocking note. Side effect: any cache call before init_db now fails if data/ is missing; fine in the app, worth knowing in scripts. |
| L3 | Loose VendorResult | Fixed | `Verdict` and `Status` Literals; template branches on status. N1 is the one leak. |
| L5 | VT denominator | Fixed | `_ENGINE_STATS`; tested. |
| L7 | Lists as Python repr | Fixed | `fmt` filter. |
| L8 | Refang coverage | Fixed, with N2 | [dot], (dot), " dot ", wrappers, `\.`, `[at]` added and tested; scheme rules over-match. |
| L9 | Numeric TLD | Fixed | Tested. |
| L11 | Static mkdir at import | Fixed | `.gitkeep` plus `check_dir=False`. |
| L12 | Swagger from CDN | Fixed | `docs_url=None`; nav link removed; runbook explains. |
| L13 | Dependencies | Fixed | Plain uvicorn, python-dotenv line removed; lock regenerated. |
| L14 | Stale runbook | Fixed | running-the-app.md and enrichment-vendors.md updated. |
| Add 1 | Shared AsyncClient | Done | Created in lifespan, closed on shutdown, injectable for tests. |
| Add 2 | Aggregate verdict | Done | Worst-of with sources. See N1 and the gate cosmetic. |
| Add 3 | Private-IP gate | Done | Allowlist (Tranco/CIRCL) remains Phase 1 scope, not a fix. |
| Add 4 | URLhaus payload for hashes | Done | MD5/SHA256 routed; SHA1 returns a note. |
| Add 5 | Cache age on card | Done | `ago` filter on the stored query_time. |
| Add 6 | Health table from LIMITS | Done | |
