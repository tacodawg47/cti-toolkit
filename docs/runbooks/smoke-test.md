# Runbook: Live smoke test (phase 1)

Written 2026-11-02, when Phase 1 was closed.

The unit suite never touches the network, so it proves our handling of each
vendor's response shape, not that the vendors still send that shape. This
smoke test is the live check: one indicator per type, read in the browser.
It spends roughly a dozen vendor calls across every quota (about four of
them VirusTotal), so run it after a change to a vendor client, not daily.

## Run it

1. Start the app (`.venv/Scripts/python.exe run.py`) and open
   http://127.0.0.1:8000/health. Check: every key you have shows `yes`,
   the Tranco card says `loaded`, and the Shodan balance appears.
2. On the enrichment page, submit each of these and compare with the
   expectations below.

| Input | Type | What you should see |
|---|---|---|
| `8.8.8.8` | ip | Nine cards. RDAP shows the netblock and `network-abuse@google.com`; OTX shows `Whitelisted IP`; InternetDB and Shodan list ports 53 and 443; GreyNoise says not observed. |
| `example.com` | domain | ONE local card: "#N in the Tranco top 100,000 — vendors skipped". No quota spent. |
| `example.com` with "query anyway" ticked | domain | The full set. RDAP shows registered 1995-08-14 and the IANA registrar; crt.sh may show UNAVAILABLE (it is slow for huge domains; that is expected). |
| `https://www.eicar.org/download/eicar.com.txt` | url | VirusTotal MALICIOUS with a double-digit ratio; urlscan shows dozens of past scans. |
| `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` (EICAR) | hash | hashlookup MALICIOUS (its `KnownMalicious` flag); VirusTotal about 65/68 with label `virus.eicar/test`; YARAify MALICIOUS with ClamAV `Eicar-Test-Signature` and four YARA rules. |
| `8.8.8.8` again | ip | Same cards, each marked `(cached Nm ago)`; the health page's "used today" counters do not move. |
| any made-up 64-hex string | hash | Every card UNKNOWN; YARAify's note reads `not found in YARAify (no_results)`. |

## What the 2026-11-02 run showed

Everything above matched. Two verdict-tuning observations came out of it,
recorded here so they are not lost (neither is a bug, both are heuristics
worth revisiting):

- VirusTotal calls `8.8.8.8` SUSPICIOUS on a 1/92 ratio (one engine's false
  positive). The "one malicious engine means suspicious" rule, ported from
  the cti-skills plugin, is noisy on famous infrastructure. Options: require
  two engines, or let OTX's whitelist / AbuseIPDB's whitelisted flag
  downgrade it.
- URLhaus calls `example.com` MALICIOUS from one offline URL first seen in
  2023, which then becomes the Overall line. A host hit with zero online URLs
  should probably be SUSPICIOUS, with MALICIOUS reserved for hosts that
  currently serve malware.

crt.sh also returned one transient non-JSON answer during the run; the app
showed UNAVAILABLE and the retry worked. That is the designed behaviour for
a free, best-effort service.
