# Runbook: Running the tests

Written 2026-10-28.

Phase 1 ships unit tests for the pure logic (indicator detection and the
VirusTotal verdict heuristic). They use Python's built-in `unittest`, so no
extra dependency is needed, and they make no network calls.

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
.venv/Scripts/python.exe -m unittest tests.test_virustotal.SummariseTests -v
```

## What is covered

| File | Covers |
|---|---|
| `tests/test_indicators.py` | `refang` (defanged input) and `detect_type` (hash/ip/url/domain/unknown) |
| `tests/test_virustotal.py` | VT URL id, path building, and the malicious/suspicious/clean/unknown heuristic |

## What is not covered yet

Network calls (the live VirusTotal request), the cache, and the rate limiter
are integration concerns. When we add more vendors we will introduce mocked
HTTP tests; at that point we may adopt `pytest` for fixtures, which will be
proposed as a dev dependency first per the dependency policy.
