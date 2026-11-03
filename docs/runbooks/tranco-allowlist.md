# Runbook: Tranco allowlist (phase 1)

Written 2026-11-02.

## What it does

Tranco (https://tranco-list.eu/) ranks the top one million websites, averaged
over 30 days from several sources, and republishes the list daily. The toolkit
loads the top N rows (default 100,000) at startup. When you enrich a domain or
a URL whose host is on that list, no vendor is called: one local card shows
the rank instead, so a lookup of `google.com` costs no quota. Tick
"query anyway" on the form to override the gate for one lookup.

Matching is exact (plus the `www.` form). `evil.github.io` is NOT allowlisted
just because `github.io` is popular; free hosting and cloud subdomains are a
common phishing home, so they always go to the vendors.

Nothing is downloaded automatically. You fetch the file by hand, which is a
side effect you control, and refresh it whenever you like (monthly is plenty
for this purpose). If the file is missing the gate is off and the health page
says "not loaded".

## Download the list

The permanent URL always points at the latest list. It is a ~5 MB zip holding
one CSV named `top-1m.csv` with two columns and no header: `rank,domain`.

Windows (PowerShell), from the project folder:

```powershell
Invoke-WebRequest -Uri https://tranco-list.eu/top-1m.csv.zip -OutFile data\tranco.zip
Expand-Archive -Path data\tranco.zip -DestinationPath data\tranco-tmp -Force
Move-Item -Force data\tranco-tmp\top-1m.csv data\tranco.csv
Remove-Item -Recurse -Force data\tranco-tmp, data\tranco.zip
```

Linux, from the project folder:

```bash
curl -L -o data/tranco.zip https://tranco-list.eu/top-1m.csv.zip
unzip -o -j data/tranco.zip top-1m.csv -d data/
mv data/top-1m.csv data/tranco.csv
rm data/tranco.zip
```

`data/` is git-ignored, so the file never enters the repository.

## Check it loaded

Restart the app and open `/health`. The "Tranco allowlist" card shows
`loaded`, the number of entries, and the file date. Then enrich `google.com`:
you should get one card saying it is #1 (or thereabouts) and that vendors were
skipped.

## Tune it

`TRANCO_TOP_N=250000` in `.env` loads more rows (more suppression, more
memory); a smaller number is stricter. The default of 100,000 is the usual
false-positive-suppression range.

## Attribution

Tranco: Le Pochat et al., "Tranco: A Research-Oriented Top Sites Ranking
Hardened Against Manipulation", NDSS 2019. The list is built from Cisco
Umbrella, Majestic (CC BY 3.0), Chrome UX Report (CC BY-SA 4.0), Cloudflare
Radar (CC BY-NC 4.0) and Farsight. Non-commercial use only on this machine.
