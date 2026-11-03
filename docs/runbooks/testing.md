# Runbook: Running the tests

Written 2026-10-28. Updated 2026-11-02.

Phase 1 ships 128 unit tests. They use Python's built-in `unittest`, so no
extra dependency is needed, and they never touch the network: importing the
`tests` package replaces the shared HTTP client with one that refuses every
request, so a test that forgets to mock fails loudly instead of spending
quota. Tests that need HTTP install an `httpx.MockTransport` (built into
httpx) that returns canned responses.

## Run all tests

From the project root:

```bash
# Windows
.venv/Scripts/python.exe -m unittest discover -s tests -t . -v

# Linux
.venv/bin/python -m unittest discover -s tests -t . -v
```

`-s tests` says where the test files are, `-t .` sets the project root as the
import base (so `import app...` works), and `-v` lists each test.

## Run one file or one test

```bash
.venv/Scripts/python.exe -m unittest tests.test_indicators -v
.venv/Scripts/python.exe -m unittest tests.test_vendors.RegistryTrancoGateTests -v
```

## What is covered

| File | Covers |
|---|---|
| `tests/test_indicators.py` | `refang` (defanged input) and `detect_type` (hash/ip/url/domain/unknown) |
| `tests/test_virustotal.py` | VT URL id, path building, and the malicious/suspicious/clean/unknown heuristic |
| `tests/test_vendors.py` | every other vendor's `_summarise`; `normalise` and `canonical` (ports, punycode, IPv6); `fetch_json` branches (404, non-JSON, wrong shape, oversized body, total timeout, non-HTTPS, redirects); an end-to-end AbuseIPDB and URLhaus lookup with a mock transport and a temp database (cache round trip); the rate-limiter loop with a fake clock; the registry's crash handling, aggregate line, and the private-IP, Tranco and hashlookup gates with the "query anyway" override; the Tranco loader; config host validation; allowed Host headers; health-page path display |

## How a mocked HTTP test works

```python
base.set_client(httpx.AsyncClient(transport=httpx.MockTransport(
    lambda req: httpx.Response(200, json={"query_status": "no_results"}))))
res = await urlhaus.lookup("url", "http://x.com/")
```

`set_client` swaps the shared client for one whose transport is your lambda,
so the vendor code runs unchanged against the response you wrote. Call
`await base.aclose()` in `asyncTearDown` so the next test starts clean.
Tests that touch the cache or the rate limiter point `settings.data_dir` at a
temporary directory and call `db.init_db()` in `setUp`.

## What is not covered

The real vendor APIs. The offline suite proves our handling of each response
shape, not that the vendors still send those shapes. A short live smoke test
(one indicator per type in the browser) is the check for that, and spends a
little quota; do it after a change to a client, not on every run.
