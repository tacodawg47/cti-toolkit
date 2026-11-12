# Kraven Security downloads: CyberChef-recipes, hacks, python-threat-hunting-tools, testing-environments

Reviewed 2026-11-11, read-only. Nothing was executed, imported, compiled,
built or fetched. Notebooks were read as JSON text. Archives (wheels,
sdists) had their member names listed only. Binaries were not opened.
Folder: `<local path> downloads\`.

Context used: ROADMAP.md (Principles, Phases 1, 2, 3 paste-C2 classifier,
5 source registry and scraping layer, 6 outcome ladder, 7, 8, 9 threat
landscape, Parking lot, Data handling, Dependency policy, Decisions log)
and the built code under `app/modules/` (enrich, extract,
vulnerability_intelligence) and `app/core/`.

## Summary

- **Licences: none of the four repositories has a LICENSE file.** All four
  are "all rights reserved": reference and ideas only, no copying of code
  or prose. The only licence files present are the Tcl/Tk `license.terms`
  inside a bundled py2exe build, which is third-party runtime, not Kraven
  code. The CyberChef README credits three upstream sources (mattnotmax,
  Thomas Leplus, Gaijin.at) whose licences were not checked (no web
  access in this review).
- These are training material: short single-purpose scripts, several with
  bugs, mostly duplicating what the toolkit already does better (VT
  verdict thresholds, CVSS filtering, NVD/CVE List ingestion, IOC type
  detection).
- The one thing worth building from them is a **deterministic decode
  helper** (Base64, UTF-16LE PowerShell, raw inflate and gzip, hex,
  charcode, URL-encoding, JWT segments) in Phase 2 extraction, shared with
  the Phase 3 paste classifier. Python standard library only.
- The malware-analysis lab (Proxmox, Terraform, FLARE-VM + REMnux +
  Guacamole) is a useful reference for the parked malware analysis item,
  mostly as a pattern (two analysis VMs on an isolated bridge, golden
  templates, rebuild instead of clean-up) and as a list of things not to
  copy (hard-coded password, committed join token, TLS verification off,
  dual-homed gateway).
- Secrets and personal data seen (values not reproduced here):
  - `hacks-main/config.py`: MISP, CrowdStrike and VirusTotal key fields are
    present but empty. No secrets.
  - `testing-environments-main/*/main.tf`: a hard-coded sudo password in
    the `remote-exec` provisioners (both environments).
  - `testing-environments-main/kubernetes-env/Remote_Files/worker_conn_string`:
    a committed `kubeadm join` token and CA certificate hash for a private
    10.0.6.x lab address (kubeadm tokens expire after 24 hours by default,
    but it is still a committed credential).
  - `hacks-main/misp/misp-data.ipynb` saved outputs: public IP addresses of
    the author's former MISP instances, the author's local filesystem path,
    and a former employer's internal MISP tag names. Do not copy any of
    this into the project.
- `hunting-packages-main` (about 2,100 files) sits in the same folder but
  was not part of this assignment and was not reviewed.

## 1. CyberChef-recipes-main

**Licence:** none (all rights reserved). Upstream credits in the README:
mattnotmax/cyberchef-recipes (inflate recipe), thomasleplus/cyberchef-recipes
(JWT, SAML), gaijin.at (Apache log, EXIF, UserCheck); licences unchecked.

**Structure:** `README.md` (13 KB, ten recipes in CyberChef "Chef" format,
grouped Malware Analysis / Web Tokens / Log Parsing / Images / Email / Data
Formatting) and `images/` (12 PNG screenshots, one per recipe plus a
"loading a recipe" screenshot; not opened, the README text carries every
recipe).

**Fit with the toolkit:** the extractor (`app/modules/extract/extractor.py`)
refangs and runs patterns over plain text, but nothing decodes encoded
blobs first. The roadmap names the shapes only for detection: the Phase 3
paste-C2 content classifier lists "Base64 PE headers (`TVqQAAMAAAAEAAAA`
and variants, and the same reversed), gzip `H4sI`, hex `4D5A9000`, decimal
`77,90`, encoded PowerShell"; the parked EtherHiding item says "Decode the
ABI string, Base64 and gzip deterministically and never evaluate it". No
decode helper is planned as such.

### Recipe-by-recipe

| # | Recipe | What it does | Deterministic Python equivalent | Belongs in the toolkit? |
|---|---|---|---|---|
| 1 | Decoding Base64 encoded PowerShell | Regex `[A-Za-z0-9+/=]{30,}`, From Base64, decode UTF-16LE, syntax highlight | `re` + `base64.b64decode(validate=False)` + `.decode("utf-16-le", errors="replace")`; stdlib | **Yes, High.** `-EncodedCommand` blobs are the most common encoded payload in reports, pastes and sandbox output. Decoded text goes back through the IOC extractor. |
| 2 | Extract Base64 and inflate PowerShell code | Same regex, From Base64, Raw Inflate, beautify | `zlib.decompressobj(-15)` for raw deflate (`IO.Compression.DeflateStream`), `gzip`/`zlib.decompress(…, 31)` for `H4sI` gzip; stdlib | **Yes, High.** Same helper. Must use `max_length` on the decompressor to stop decompression bombs. |
| 3 | Decoding CharCode | Regex for comma-separated 2-3 digit numbers, From Charcode, Jump back up to N times for nested layers | `re` + `"".join(chr(int(n)) for n in …)`, loop with a fixed depth cap; stdlib | **Yes, Medium.** Matches the classifier's "decimal `77,90`" shape and JavaScript `String.fromCharCode` droppers. The bounded-loop idea (max layers) is the useful part. |
| 4 | Deobfuscating malicious Python (Fernet) | Campaign-specific regexes (`exec(b'…')`, `Fernet(b'…')`, `decrypt(b'…')`, `get('…')`), From Hex, Fernet decrypt with the key found in the sample, extract next-stage URL | Needs `cryptography` (Fernet is AES-128-CBC + HMAC; not in stdlib). A new dependency would need the proposal process | **Not in the app.** Campaign-specific (one ReversingLabs write-up), needs a new compiled dependency, and it is sample handling, which the parked malware rules keep inside the isolated VM. Note the technique for the malware research corpus and the Supply chain tab's "vendor write-up" context. Low. |
| 5 | Decoding JWT tokens | URL-decode, split on `.`, Base64 each part, keep JSON lines, beautify | `base64.urlsafe_b64decode` with padding restored, `json.loads`; stdlib | **Yes, Medium**, as a decode option: shows `iss`, `sub`, `aud`, `exp` of a JWT found in a leak (Phase 3 GitHub secret leaks) or a phishing kit without using it. Same rule as the Telegram bot-token pivot: decode and correlate, never call a service with the token, never verify a signature against a live endpoint. |
| 6 | Decoding SAML | URL-decode, Base64, raw inflate, XML beautify | stdlib (`urllib.parse`, `base64`, `zlib`); show the XML as text, do not parse it with a full XML parser | **Low.** Incident-response and SSO debugging, not CTI. Comes free if the helper chains URL-decode, Base64 and inflate. |
| 7 | Format Apache HTTP access log | Regex for the combined log format, date to ISO UTC, labelled output | `re` + `datetime.strptime("%d/%b/%Y:%H:%M:%S %z")`; stdlib | **No, Low.** The toolkit does not ingest server logs. Possible later use: parsing honeypot sensor web logs in the parked "first-party exploitation sensing" item, which reads sensor data through an API instead. |
| 8 | Extract EXIF data | CyberChef `Extract_EXIF`, drop noise tags, Unix time to ISO | Needs Pillow or exifread (new dependency) | **No, Low.** No image-metadata feature is planned. If Phase 7 ever takes photos, ExifTool in the analysis VM is the usual tool. |
| 9 | Validate email address using UserCheck.com | `HTTP_request` to api.usercheck.com per address with a bearer token | n/a (external API) | **No, Low.** Sends selectors to a third party. The disposable-email question is already answered locally by the MISP warninglists planned in Phase 6 ("disposable e-mail"), which is the better route. |
| 10 | Convert CSV file to HTML table | Find/replace commas with `</td><td>` and wrap rows | n/a | **No, Low.** Built: every table is rendered by the shared Jinja table renderer; CSV export is Phase 8. The recipe also breaks on quoted commas and does not escape HTML. |

### Proposed design for the decode helper (from recipes 1, 2, 3, 5, 6)

- `app/core/decode.py`, standard library only, no new dependency.
- Input: text. Output: a list of layers, each `(operation, offset, input
  excerpt, output text, truncated?)`, so the analyst sees every step, like
  CyberChef's recipe pane but chosen by fixed rules.
- Candidates: Base64 runs of 30 or more characters (recipe 1's threshold),
  hex runs, decimal charcode lists, `%xx` URL-encoding, JWT
  (`eyJ…`.`eyJ…`.`…`), gzip magic `H4sI`, zlib header after decoding.
- Decoders in a fixed order: URL-decode, Base64 / Base64url, hex, charcode;
  then on the bytes: gzip, zlib, raw deflate; then text: UTF-8, else
  UTF-16LE when every second byte is zero.
- Bounds: depth cap (CyberChef's "maximum jumps", e.g. 5), output cap per
  layer (e.g. 1 MB, `decompressobj(...).decompress(data, max_length)`),
  total time cap. Never evaluate, never write decoded bytes to disk, never
  fetch a decoded URL (same rule as the paste classifier: "never
  downloads a decoded payload").
- Binary results (an `MZ` header) are reported as "PE header, N bytes,
  SHA-256 …" and never shown or saved as a file; the hash can go to
  enrichment.
- Decoded text is run through `extract_iocs` and each indicator is marked
  "found after decoding (layer N: base64 > utf-16le)".
- UI: a "Decode" option on the extraction page, and the same function
  used by the Phase 3 paste classifier and the parked EtherHiding work.
- Tests: offline fixtures built by encoding known strings in the test
  itself, so no real malware sits in the repository.

## 2. hacks-main

**Licence:** none (all rights reserved).

**Structure (9 files):** `README.md` (one line: "Scripts or programs to
quickly solve basic problems"), `config.py` (dataclasses for MISP,
CrowdStrike and VirusTotal settings, all empty, plus ANSI colour codes),
`iocs-to-cs.py`, `verify-iocs-vt.py`, `OctoparsePrettyIOC.ps1`,
`investigation-playbook.ipynb`, `misp/icos-from-misp-to-cs.py`,
`misp/misp-data.ipynb` (with saved outputs), `images/cyber-kill-chain.jpeg`
(not opened). Dependencies implied: `vt-py`, `validators`, `falconpy`,
`pymisp`, `pandas`, `matplotlib`.

| Component | What it does | Phase | Built or planned? | What we could take | Value |
|---|---|---|---|---|---|
| `verify-iocs-vt.py` | Reads `iocs.txt`, types each line with `validators`, queries VT (vt-py), labels malicious/suspicious/clean with thresholds of 1, sleeps 15 s per IOC, prints "IOCs to upload to MISP" split into endpoint and network lists | 1 | **Built.** `app/modules/enrich/virustotal.py` has a graded verdict (malicious at 5 or more engines, suspicious at 1 or more), the per-vendor token bucket and the cache. Bulk paste is parked for the Phase 5 job runner. | Only the "endpoint vs network" split for an output list (useful in Phase 8 exports, where hashes go to EDR and network IOCs to the firewall). Bugs to avoid, good teaching material: the URL branch encodes the literal string `"ioc"` instead of the URL and calls `scan_url`, which **submits** the URL to VT (an OPSEC leak for a lookup tool); `e.code` on a generic exception; `>` thresholds mean one malicious engine counts as clean. | Low: already built, better. |
| `iocs-to-cs.py` | Types IOCs from a file into buckets and pushes ipv4/ipv6/domain/sha256/md5 to CrowdStrike Falcon IOC Management with `action=detect`, severity, all platforms, retrodetect, and an expiry 60 days out; counts 400s as duplicates | 8 | Not planned (no Falcon tenant). Exports (STIX, CSV, TXT) are Phase 8; MISP/OpenCTI push is in Phase 9 and the parking lot. | Two ideas for Phase 8 exports: (1) an **expiry date per exported indicator** (STIX `valid_until`, a CSV column), matching Phase 6's "block (time-limited for IPs)"; (2) a per-target type map that says which types a destination accepts and lists what was dropped (Falcon takes no URL, hostname or SHA-1 here). | Low-Medium. |
| `misp/icos-from-misp-to-cs.py` | Pulls MISP attributes with `to_ids=1` published in the last 89 days, splits MISP composite types (`domain\|ip`, `ip-dst\|port`, `hostname\|port`, `filename\|sha256/md5/sha1`), buckets them, pushes to Falcon; a ThreatFox pull is a TODO | 5 / 8 | Partly planned: Phase 5 "CIRCL and Botvrij MISP OSINT feeds (MISP manifest format)"; Phase 6 "share (STIX or MISP export ...)". | **The composite-type split table** (which half of `domain\|ip`, `filename\|sha256` etc. is the indicator) and the **`to_ids` + time-window filter** when ingesting MISP feeds. Bug to avoid: `addr = ipv4.append(...)` stores `None`, so the split IPs bypass validation. | Medium: needed when MISP feeds are ingested. |
| `OctoparsePrettyIOC.ps1` | Reads an Octoparse JSON export and prints the comma-separated SHA1/MD5/SHA256/IP/DOMAIN fields one per line | 5 | Roadmap already reviewed Kraven's Octoparse guide (Phase 5 scraping layer: "Idea worth keeping: a small per-source extraction recipe ... held as data"). | Nothing new. Bug: the MD5 block prints the SHA1 field. | Low. |
| `investigation-playbook.ipynb` | Markdown only: a Cyber Kill Chain walk (map, fill from detection point down to KC7, go back up to the start, pivot), per-stage tables (things to look for / indicators / where to look / follow-on actions, mostly placeholders), follow-up list, and a Collection Management Framework (CMF): external sources by IOC type covered (urlscan, URLQuery, ThreatMiner, Zscaler Zulu, Maltiverse, filescan.io, ThreatFox, Feodo, URLhaus, YARAify, Hybrid Analysis, any.run, VirusTotal, Censys, Shodan, Talos, Intezer, GreyNoise, Joe Sandbox, Pulsedive, OTX) and internal tools by data type, kill-chain coverage, follow-on collection, retention | 5, 9, 10 | Partly planned: Phase 5 source registry (class, access, rate limits, terms, Admiralty rating); Phase 10 analyst runbooks. Kill-chain mapping is not planned (ATT&CK is). | (1) Add **"indicator types answered"** and **"retention / how far back"** columns to the source registry, so the UI can say which sources can answer a given IOC type. (2) **Manual link-outs per IOC** to the CMF sources that have no API or no key here (Talos, Zscaler Zulu, URLQuery, ThreatMiner, filescan.io, Intezer, Pulsedive, Hybrid Analysis): the enrichment card has no "open in" links today. Links only, nothing fetched. | Medium. |
| `misp/misp-data.ipynb` | PyMISP notebook: search an IOC and show its event and tags; count ATT&CK techniques across all events (and per tag) from `mitre-attack-pattern` galaxy clusters and plot a bar chart; instance statistics (users, events, tags, attribute types); the bucket function above | 9 | **Planned:** Phase 9 "my threat landscape" page ("most common techniques ... across the pinned set"). | The pattern "technique counts filtered by a tag" (past incident, actor research, malware research) for the landscape page, using the local ATT&CK dataset instead of the notebook's hard-coded list of 607 IDs. The saved outputs contain private data (see Summary); do not copy. | Low-Medium: confirms a planned feature. |
| `config.py` | Settings dataclass with empty key fields, `MISP_VERIFYCERT = False` | n/a | Built differently: `.env` + pydantic-settings. | Nothing; certificate verification off is the anti-pattern. | Low. |

## 3. python-threat-hunting-tools-main

**Licence:** none (all rights reserved). README: "Feel free to use, expand,
and adapt these tools", which is a statement of intent, not a licence.
`pyproject.toml` names the author.

**Structure (1,042 files; about 30 are Kraven's):**
- `README.md`, `.gitignore` (ignores `config.py`, `test.ipynb`).
- `browser_automation/virus_total_lookup.py` + `iocs.txt` (11 sample IOCs).
- `cmdline_args/cisa_vulns_scraper_v2.py`.
- `web_scraping/` (Poetry project: `pyproject.toml`, `poetry.lock`,
  `README.md`, `web_scraping_cisa_advisory/cisa_vulns_scraper.py`, and
  `dist/` with three wheels and three sdists whose members are only that
  same scraper; names listed, not extracted).
- `interacting_with_apis/maltiverse_ip_lookup-v1.py`, `-v2.py`;
  `jupyter_notebooks/threat-hunting-notebook.ipynb` and
  `jupyter_notebooks/interacting_with_apis/maltiverse_web_ip_lookup.py`
  (plus `__pycache__/*.pyc`, not opened).
- `parsing_csv/critical-vulns.py` + a 73-line CSV of the CISA bulletin for
  the week of 2023-04-03; `parsing_json/parsing_api_json_data.py`.
- `misp/misp-data.ipynb` (same as hacks-main without saved outputs and with
  generic tag names), `misp/misp-to-crowdstrike.py` (same as hacks-main
  `icos-from-misp-to-cs.py`, severity high, no ThreatFox TODO),
  `misp/misp-to-csv.py`.
- `vt_community_api/verify-iocs.py` (same as hacks-main
  `verify-iocs-vt.py`, adds `nest_asyncio`).
- `iocs.csv` (5.4 MB, 127,852 rows, `type,value`, a MISP attribute export).
- `creating_exes/setup.py` (py2exe, not PyInstaller) and
  `creating_exes/dist/`: `maltiverse_ip_lookup-v1.exe` (11 MB),
  `libcrypto-1_1.dll`, `libssl-1_1.dll`, `libffi-8.dll`, `tcl86t.dll`,
  `tk86t.dll`, `cacert.pem`, and about 1,000 Tcl/Tk library files
  (`.tcl`, `.msg`, `.enc`, tzdata, demos). Not opened. OpenSSL 1.1 has been
  end-of-life since 2023, another reason not to run it.

| Component | What it does | Phase | Built or planned? | What we could take | Value |
|---|---|---|---|---|---|
| `cisa_vulns_scraper.py` / `_v2.py` | Scrapes one CISA weekly Vulnerability Summary bulletin (SB23-100) HTML table with BeautifulSoup into dicts (product, vendor, description, published, CVSS, CVE, NVD link); v2 adds `--csv/--json/--txt` output | 2 | **Built, richer.** The bulletins are compiled from NVD; the toolkit already ingests NVD recent changes and the CVE List (cvelistV5) with vendor, product, CVSS, CWE and SSVC. Principle 7 (API before scraping) also applies. | Nothing for ingestion. The one-function-per-output-format pattern (`output_csv/json/txt`) is how Phase 8 exports should look. Bug: the bulletin cell is "vendor -- product" but the script assigns `product, vendor`, so the columns are swapped (the sample CSV lists `mingsoft` as product and `mcms` as vendor). | Low. |
| `parsing_csv/critical-vulns.py` + sample CSV | Keeps rows with CVSS 9.0 or higher | 2 | **Built:** CVSS filter on every table, view 5 "New and severe". | Nothing. Crashes on a blank or "N/A" score. | Low. |
| `maltiverse_ip_lookup-v1/-v2`, `maltiverse_web_ip_lookup.py`, `parsing_api_json_data.py`, notebook | Interactive loops that validate an IP (`ipaddress`) or domain (`validators`) and print Maltiverse's `classification` field; v1 uses the `maltiverse` SDK, v2 and the domain script plain `requests` with no key | 1 | **Not in the roadmap.** Maltiverse appears nowhere in ROADMAP.md. | A candidate keyless or free-key source for the "Additional free sources to consider" list: one call returns a classification for IP, hostname, URL or hash, aggregated from blocklists. Needs a terms and current-status check before any decision (not done here: no web). Likely largely duplicates URLhaus, ThreatFox, AbuseIPDB and OTX. Bug in v1: the prompt says "exit" but the code checks "quit". | Low. |
| `browser_automation/virus_total_lookup.py` | Selenium + Edge opens one VT GUI tab per IOC from `iocs.txt`, type by length heuristics | 1 | Built differently (VT API). | The underlying wish, "open this IOC in each vendor's web page", is better met by plain link-outs (see the CMF row above). Automating VT's GUI breaks Principle 7. | Low. |
| `creating_exes/` (py2exe) | Freezes the Maltiverse CLI into a Windows `.exe` with its DLLs | 8 | Not planned and not needed: the toolkit is a local web app; Phase 8 packaging is Docker Compose plus pip+venv. | Nothing. | Low. |
| `web_scraping/` Poetry package | Builds wheels/sdists of the scraper under three test names | 8 | Not planned: the project uses pip with hash-pinned requirements, wheels only. | Nothing. The lock file pins requests 2.30.0 and urllib3 2.0.2, both since patched for CVEs; a reminder of why the pip-audit step exists. | Low. |
| `misp/misp-to-crowdstrike.py`, `misp-data.ipynb` | Same as hacks-main (see section 2) | 5 / 8 / 9 | As in section 2. | As in section 2. | Medium (composite-type split), Low-Medium (TTP counts). |
| `misp/misp-to-csv.py` | Writes `type,value` of `to_ids` attributes to `iocs.csv` | 8 | Planned: Phase 8 CSV export. | Nothing new. Bug: `misp` is never created, so it cannot run as written. | Low. |
| `iocs.csv` | 127,852 MISP attributes: md5 23,920, hostname 22,505, sha256 16,575, domain 13,734, sha1 13,230, ip-dst 9,502, ip-src 7,350, url 5,354, plus `filename\|hash`, uri, yara, mutex, snort, ssdeep, regkey and others. Sample values look like an old public MISP OSINT feed (no provenance recorded) | 1 / 2 / 5 | Not planned. | A **local-only regression corpus** for `app/core/indicators.py` type detection and the extractor: 127k values labelled by MISP type, so a test can count disagreements (e.g. MISP `hostname` vs our `domain`, `ip-src` vs `ip`). Never committed (no licence, unknown provenance); kept under the git-ignored data folder and run as an optional test. | Medium. |
| `vt_community_api/verify-iocs.py` | Same as hacks-main `verify-iocs-vt.py` | 1 | Built. | As in section 2. | Low. |

## 4. testing-environments-main

**Licence:** none (all rights reserved).

**Structure (21 files):** `README.md`; `kubernetes-env/` (Terraform
`provider.tf`, `main.tf`, `outputs.tf`; three netplan files; Ansible
`ansible.cfg`, `inventory/hosts`, `deploy-k8s.yaml`; `files/` with a
containerd snippet, a Jinja template, an nginx pod and NodePort service;
`Remote_Files/worker_conn_string`); `malware-analysis-env/` (Terraform
`provider.tf`, `main.tf`, `outputs.tf`; one netplan file). Both use the
`telmate/proxmox` provider 3.0.1-rc1 (a release candidate) against a
Proxmox VE node called `pve`, with `pm_tls_insecure = true`. Credentials
come from a git-ignored `credentials.auto.tfvars` (variables marked
`sensitive`), which is the right pattern, but see the Summary for the
hard-coded password and committed join token.

| Component | What it does | Phase | Built or planned? | What we could take | Value |
|---|---|---|---|---|---|
| `kubernetes-env` | Full clones of an Ubuntu 20.04 template into a 1-master, 2-worker cluster on bridge `vmbr6` (10.0.6.200-202); Ansible upgrades packages, installs containerd (SystemdCgroup on), disables swap, enables IP forwarding and `br_netfilter`, installs kubeadm/kubectl/kubelet 1.29 and holds them, `kubeadm init`, Flannel from its `master` branch, fetches the join command to the controller and runs it on workers; demo nginx pod and NodePort 30080 | 5 / 8 | Not planned: the roadmap chose WSL2 (2026-11-09 decision) and Docker Compose in Phase 8. | Nothing for the toolkit. As a lesson list for runbooks: pin what you apply (Flannel from `master` is unpinned), never commit join tokens, never put a sudo password in a provisioner, kube config is written `0755` (should be `0600`), deleting `/var/lib/dpkg/lock` hides a real problem. | Low. |
| `malware-analysis-env` | See the comparison below | Parking lot | **Parked:** "Malware analysis: static and dynamic" and "Malware research corpus"; Phase 8 isolation ladder; review list "Analysis VM and OSINT distro choice (Tsurugi, REMnux, plain Ubuntu): decide when WSL2 is set up". | Lab pattern and rebuild-by-code approach, below. | Medium. |

### Malware-analysis lab: Kraven design vs the roadmap's parked item

**Kraven's design (from `main.tf`, `outputs.tf`, `01-netplan.yaml`):**
- Hypervisor: Proxmox VE on a dedicated server; VMs are **linked clones**
  (`full_clone = false`) of three hand-built templates.
- `flare-vm` (Windows with Mandiant's FLARE-VM tooling): 4 vCPU, 6 GB, 80 GB,
  one NIC (`e1000`) on `vmbr5` only.
- `remnux` (REMnux Linux): 2 vCPU, 4 GB, 60 GB, one NIC on `vmbr5` only.
- `guacamole` (Apache Guacamole, browser-based RDP/SSH/VNC gateway): 2 vCPU,
  4 GB, two NICs: `vmbr0` (the normal LAN, DHCP) and `vmbr5` (static
  10.0.5.20/24, a default route via 10.0.5.1 at metric 99, DNS 8.8.8.8).
- Outputs are the three IP addresses. A `winrm_pass` variable is declared
  and unused. Nothing in the repository defines `vmbr5` itself, a
  firewall, snapshots, a fake-internet service, or how files enter and
  leave the lab.

**Roadmap's parked item (summarised):** samples stay in encrypted archives
on the host and are only extracted, opened, or run inside the isolated
worker or VM; the app keeps metadata and extracted values only; staged
plan: (1) read existing public sandbox reports by hash, (2) static
analysis in an isolated worker (FLOSS, capa, YARA, config parsers), (3) a
self-hosted sandbox (CAPE, DRAKVUF Sandbox, Cuckoo3) on its own host read
through its API, (4) public sandbox submission only as an explicit
per-sample choice; isolation ladder ending in "VirtualBox VM for
unfamiliar or untrusted sources ... a VM is the security boundary"; the
VM distro choice is open.

| Aspect | Kraven lab | Roadmap | Take or avoid |
|---|---|---|---|
| Purpose | Manual analyst workstation lab (Windows + Linux tools) | Stage 2 static worker, stage 3 automated sandbox, app glue | Different layers. Kraven's lab is what the operator sits in; the roadmap's stages are what the app calls. Both are needed; Kraven's covers the manual part the roadmap leaves as "the isolated VM". |
| Host | Dedicated Proxmox server | Windows 11 workstation, WSL2 later; VirtualBox named | Proxmox needs a second machine. On Windows 11 Pro, Hyper-V with a **Private** virtual switch (no host or LAN connectivity) gives the same isolated bridge without new hardware, and coexists with WSL2. |
| Guests | FLARE-VM (Windows) + REMnux (Linux) | REMnux, Tsurugi or plain Ubuntu (open question) | **Take:** the pair. REMnux covers the Linux static tools the roadmap names (capa, FLOSS, YARA ship with it), and a Windows FLARE-VM is needed for Windows samples and debuggers. Settles the open review-list item with "REMnux for the worker, FLARE-VM for Windows". |
| Network | Analysis bridge `vmbr5`; the gateway VM is dual-homed (LAN + analysis), with a default route and public DNS on the analysis side | Isolation stated, not designed | **Avoid** the dual-homed gateway: one compromised Guacamole bridges the LAN and the lab. **Take** the single-NIC analysis guests. Add what the repo lacks: no route out by default, simulated internet inside the lab (INetSim on REMnux, FakeNet-NG on FLARE-VM), and real egress only through an explicit, logged path (VPN or Tor) when a sample needs it. |
| Reset | Linked clones from golden templates; destroy and re-apply rebuilds the lab | Not designed | **Take:** "rebuild instead of clean" from templates. On Hyper-V or VirtualBox the equivalent is a clean checkpoint/snapshot per guest restored after every session. |
| As code | Terraform + Proxmox provider; templates built by hand | Not designed | Partly take: record the build as a runbook (and later a script) so the lab is reproducible; the user wants to learn the manual steps first, which suits a runbook better than Terraform. |
| Access | Guacamole in a browser | Not designed | Not needed on a single workstation: the hypervisor console is enough and adds no network path. |
| Files in and out | Not addressed | Encrypted archives; never extracted on the host; metadata only back to the app | The roadmap's rule is stronger; keep it. Add: a one-way transfer (read-only shared folder or ISO in; text reports and extracted IOCs out) and never a shared writable folder. |
| Secrets hygiene | Sensitive tfvars git-ignored (good); hard-coded sudo password, TLS verify off, release-candidate provider (bad) | `.env`, never commit secrets | Use as a "what not to do" example in the runbook. |

## Ranked recommendations

1. **Build a deterministic decode helper** (`app/core/decode.py`, stdlib
   only) for Phase 2 extraction: Base64 to UTF-16LE PowerShell, Base64 plus
   raw inflate or gzip, hex, charcode with a depth cap, URL-decoding, JWT
   header and payload view; decoded text goes back through the extractor
   with the layer path recorded; size, depth and time bounds; never
   evaluate or save a payload. Reuse it in the Phase 3 paste classifier and
   the parked EtherHiding decode. Ideas from CyberChef recipes 1, 2, 3 and
   5; our own code. **High.**
2. **Write the malware lab pattern into the parked malware item** when it
   is next touched: FLARE-VM + REMnux, single-NIC guests on an isolated
   switch (Hyper-V Private switch on Windows 11 Pro), simulated internet
   (INetSim / FakeNet-NG), golden snapshot restored after each session,
   no dual-homed gateway, one-way file transfer, plus the hygiene lessons.
   It also answers the open "analysis VM distro" review item. **Medium.**
3. **MISP ingestion and export rules**: the composite-type split table
   (`domain|ip`, `ip-dst|port`, `hostname|port`, `filename|<hash>`) and the
   `to_ids` plus publish-window filter, for the Phase 5 CIRCL/Botvrij MISP
   OSINT feeds and the Phase 6/8 MISP export. **Medium.**
4. **Local-only type-detection regression corpus** from `iocs.csv` (127,852
   MISP-labelled values): an optional test that compares
   `app/core/indicators.py` with the MISP labels and lists disagreements.
   Never committed. **Medium.**
5. **Source registry columns and IOC link-outs** from the CMF: "indicator
   types answered" and "retention" per source; a row of "open in" links
   on each enrichment card for sources with no API or key here (Talos,
   Zscaler Zulu, URLQuery, ThreatMiner, filescan.io, Intezer, Pulsedive,
   Hybrid Analysis). Links only. **Medium.**
6. **Expiry on exported indicators** (STIX `valid_until`, a CSV column)
   and a per-destination type map listing what was dropped (Phase 8).
   **Low-Medium.**
7. **Tag-filtered technique counts** for the Phase 9 "my threat landscape"
   page: already planned; the notebook only confirms the idea. **Low-Medium.**
8. **Maltiverse**: add to "Additional free sources to consider" as "to
   check" (terms, current status, overlap). **Low.**
9. **Skip:** CISA bulletin scraper (NVD and the CVE List already cover it,
   and the scraper swaps vendor and product), CVSS filter script (built),
   Selenium VT tabs (API exists, Principle 7), py2exe and Poetry
   packaging, the Kubernetes environment, UserCheck (sends selectors to a
   third party; MISP warninglists cover disposable e-mail), SAML, Apache
   log, EXIF, CSV-to-HTML recipes (out of scope or built), Fernet
   deobfuscation in the app (new compiled dependency, campaign-specific,
   belongs in the analysis VM), CrowdStrike push (no tenant).

## Not read, and why

- **All PNG/JPEG images** (12 CyberChef screenshots, `example-loading-recipe.png`,
  `hacks-main/images/cyber-kill-chain.jpeg`, and chart images embedded in
  the hacks MISP notebook outputs): screenshots of content already in the
  README or notebook text.
- **`creating_exes/dist/`**: `.exe`, five `.dll` files, `cacert.pem`, and
  about 1,000 bundled Tcl/Tk library files (`.tcl`, `.msg`, `.enc`,
  tzdata, demos, two `license.terms`): binaries and third-party runtime
  of a py2exe build; per the brief, not opened.
- **`jupyter_notebooks/interacting_with_apis/__pycache__/*.pyc`**: compiled
  bytecode; the matching `.py` source was read.
- **`web_scraping/dist/` wheels and sdists**: member names listed only
  (each holds the same `cisa_vulns_scraper.py` already read, plus
  metadata); not extracted.
- **`iocs.csv`**: header, first rows and per-type counts read; the 127,852
  values were not read individually.
- **CISA bulletin CSV**: header and first rows read (73 lines of 2023 data).
- **`Remote_Files/worker_conn_string`**: read with the token and hash
  redacted at read time; values not reproduced.
- **`hunting-packages-main`**: in the same folder but outside this
  assignment.
- **Upstream licences** for the recipes credited in the CyberChef README
  (mattnotmax, Thomas Leplus, Gaijin.at): would need web access.
