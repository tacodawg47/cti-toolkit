# C2 tracking: how public projects find and fingerprint C2 servers, and what the toolkit can reuse

Research date: 2026-11-11. Read-only web research (WebFetch, WebSearch). Nothing
downloaded, cloned, installed or signed up for. Page content was treated as data.

Context read first: ROADMAP.md, Phase 6 (default-signature library, Kraven "C2
Hunting 101" notes, Fox-IT corpus notes, dataset research of 2026-11-11).

Labels used below:
- **Documented**: stated by the project or page itself.
- **Inferred**: my reading of code, data or behaviour; not stated by the author.
- **Observed**: a value seen in a data feed (for example a port that dominates a
  framework's rows), which is evidence of common practice, not a default.

---

## 1. montysecurity/C2-Tracker (archived)

**What it is.** A community IOC feed of C2, malware panel, tool and botnet IPs
built from Shodan (and once Censys) searches. Archived by its owner on
2026-04-13; last weekly update 2026-04-06 (date given by Adversary-Hunter). The
`data/` text files were removed from the repo at archiving.

**Method.**
- Documented: indexed search only. `tracker.py` runs a dictionary of Shodan
  queries through the official `shodan` library (`api.search_cursor(query)`),
  reads `ip_str` from each match, no facets. A Censys function exists
  (`censys.search.CensysHosts`) but is commented out in `main()`.
- Documented: weekly, Mondays. `autoupdate.sh` is a single line: `git pull`,
  run tracker, delete zero-byte files, `git commit -a -m "Weekly Auto Update"`,
  `git push`. No scheduler in the repo (Inferred: cron on the author's host).
- Documented: no validation step. Contributing guidance says only that fidelity
  (true to false positive ratio) matters.
- Output: `data/{Tool} IPs.txt` per tool, `data/all.txt`, one IP per line, no
  port, no timestamp. Shodan run wipes `data/` first. History was meant to be
  read from git history ("when did this IP appear").
- Inferred: no port is kept, so a hit on a teamserver port and a hit on a
  listener port look the same in the output.

**Licence.** No LICENSE file, no sidebar licence: all rights reserved. Facts
(serials, hashes, titles) may be re-keyed; the query dictionary and code must
not be copied.

**Queries (Shodan; all were in the active dictionary at archiving).** `hash:`
is Shodan's banner hash filter; `http.html_hash`, `http.favicon.hash` and
`http.headers_hash` are mmh3-style Shodan property hashes.

| Tool | Shodan queries |
|---|---|
| Cobalt Strike | `ssl.cert.serial:146473198`; `hash:-2007783223 port:50050`; `product:'Cobalt Strike Beacon'`; `ssl:foren.zik` |
| Metasploit | `ssl:MetasploitSelfSignedCA`; `http.favicon.hash:-127886975`; `product:Metasploit` |
| Covenant | `ssl:Covenant http.component:Blazor`; `http.favicon.hash:-737603591`; `product:Covenant` |
| Mythic | `ssl:Mythic port:7443`; `http.favicon.hash:-859291042`; `product:Mythic` |
| Brute Ratel C4 | `http.html_hash:-1957161625`; `product:'Brute Ratel C4'` |
| PoshC2 | `ssl:P18055077`; `product:PoshC2`; `http.html_hash:855112502`; `http.html_hash:-1700067737` |
| Sliver | `ssl:multiplayer ssl.cert.issuer.cn:operators`; `"HTTP/1.1 404 Not Found" "Cache-Control: no-store, no-cache, must-revalidate" "Content-Length: 0" -"Server:" -"Pragma:"`; `product:'Sliver C2'` |
| Deimos | `http.html_hash:-14029177`; `product:'Deimos C2'` |
| PANDA C2 | `http.html:PANDA http.html:layui`; `product:'Panda C2'` |
| NimPlant | `http.html_hash:-1258014549` |
| Havoc | `X-Havoc: true`; `product:Havoc` |
| Caldera | `http.favicon.hash:-636718605`; `http.html_hash:-1702274888`; `http.title:"Login \| CALDERA"` |
| GoPhish | `http.title:'Gophish - Login'` |
| AcidRain Stealer | `http.html:"AcidRain Stealer"` |
| Misha Stealer | `http.title:misha http.component:UIKit` |
| Patriot Stealer | `http.favicon.hash:274603478`; `http.html:patriotstealer` |
| RAXNET Bitcoin Stealer | `http.favicon.hash:-1236243965` |
| Titan Stealer | `http.html:'Titan Stealer'` |
| Collector Stealer | `http.html:"Collector Stealer"`; `http.html:getmineteam`; `product:"Collector Stealer"` |
| Mystic Stealer | `http.title:'Mystic Stealer'`; `http.favicon.hash:-442056565` |
| Gotham Stealer | `http.title:'Gotham Stealer'`; `http.favicon.hash:-1651875345` |
| Meduza Stealer | `http.html_hash:1368396833`; `http.title:'Meduza Stealer'` |
| XMRig | `http.html:XMRig`; `http.favicon.hash:-782317534`; `http.favicon.hash:1088998712` |
| 7777 Botnet | `hash:1357418825` |
| Quasar RAT | `product:'Quasar RAT'` |
| ShadowPad | `product:ShadowPad` |
| AsyncRAT | `product:AsyncRAT` |
| DcRat | `product:DcRat` |
| BitRAT | `product:BitRAT` |
| Empire | `product:'Empire C2'` |
| DarkComet | `product:'DarkComet Trojan'` |
| XtremeRAT | `product:'XtremeRAT Trojan'` |
| NanoCore | `product:'NanoCore RAT Trojan'` |
| Gh0st RAT | `product:'Gh0st RAT Trojan'` |
| DarkTrack RAT | `product:'DarkTrack RAT Trojan'` |
| njRAT | `product:'njRAT Trojan'` |
| Remcos | `product:'Remcos Pro RAT Trojan'` |
| Poison Ivy | `product:'Poison Ivy Trojan'` |
| Orcus RAT | `product:'Orcus RAT Trojan'` |
| Ares RAT | `product:'Ares RAT C2'` |
| ZeroAccess | `product:'ZeroAccess Trojan'` |
| Hookbot | `http.title:'Hookbot Panel'` |
| Hak5 Cloud C2 | `product:'Hak5 Cloud C2'`; `http.favicon.hash:1294130019` |
| BlackNET | `http.title:'BlackNet - Login'` |
| Doxerina | `http.title:'Doxerina BotNet'` |
| RisePro Stealer | `'Server: RisePro'` |
| Pantegana | `ssl:Pantegana ssl:localhost`; `ssl.cert.issuer.cn:'Pantegana Root CA'` |
| Supershell | `http.html_hash:84573275`; `http.favicon.hash:-1010228102`; `http.title:'Supershell - 登录'` |
| Viper | `http.html_hash:-1250764086` |
| Poseidon C2 | `http.favicon.hash:219045137`; `http.html_hash:-1139460879`; `hash:799564296` |
| Scarab Botnet | `http.title:'Scarab Botnet PANEL'` |
| Bandit Stealer | `http.title:Login http.html:'Welcome to Bandit' 'Content-Length: 4125' port:8080` |
| NetBus | `product:'NetBus Trojan'` |
| Unam Web Panel | `html:unam_lib.js http.favicon.hash:-1278680098,-1531496738`; `http.title:'Unam Web Panel &mdash; Login'` |
| Atlantida Stealer | `http.title:'Atlantida' http.html:'GY7HXsD.jpg'` |
| Vshell | `http.title:'Vshell - 登录'` |
| BurpSuite | `product:BurpSuite` |
| Hashcat | `product:'Hachcat Cracking Tool'` (sic) |
| MobSF | `http.title:'Mobile Security Framework - MobSF'` |
| Villain | `hash:856668804` |
| SpyAgent | `http.title:'SpY-Agent v1.2'` |
| RedGuard | `http.status:307 http:'307 Temporary Redirect Content-Type: text/html; charset=utf-8 Location: https://360.net'` |
| SpiceRAT | `http.headers_hash:1955818171 http.html_hash:114440660` |
| Oyster C2 | `http.html_hash:-51903740` |
| Mozi | `http.html_hash:-1245370368` |
| Prysmax Stealer | `http.title:'Prysmax Stealer'` |
| Spectre Stealer | `http.title:'Spectre Stealer - Login'` |
| SectopRAT | `http.headers_hash:-1731927497 port:9000,15647` |

**Censys queries (disabled in code, legacy Search 2.0 syntax).** Almost all are
`services.software.product:<name>` (Cobalt Strike, AsyncRAT, Supershell, Cloud
C2, SLIVER, SHADOWPAD, Mythic, Havoc, Quasar, VenomRAT, Orcus, DcRat, PoshC2,
DeimosC2, Covenant, BitRAT, NimPlant, Remcos, many stealers, EvilGinx, GoPhish
and so on) or `services.service_name:` (GHOST, DARKCOMET, DARKGATE). The ones
carrying their own facts:
- RisePro: `services.http.response.headers: (key: \`Server\` and value.headers: \`RisePro\`)`
- Vshell: `services.http.response.html_title:'Vshell - 登录'`
- Atlantida: html title `Atlantida` and body `GY7HXsD.jpg`
- Villain: `services.banner='whoami\n'`
- SpyAgent: title `SpY-Agent v1.2`
- Dust RAT: body `Dust RAT v1.4.0`
- 63256 botnet: `services.port:63256 and services.banner_hashes='sha256:13e9b4b65e60bd9c8e58232591012fa6e2240a7b348ccdd611490e17d00b25f6'`
- SectopRAT: `services.software.vendor=SectopRAT`; banner hash `sha256:e09e1b5b03b592b8e626296e1a7baa004cac61aaf0a75658af744f9e1d7853fc` on ports 9000 or 15647

**Key observation (Inferred).** About half of the Shodan queries are
`product:` lookups. Those do not fingerprint anything themselves: they return
whatever Shodan's own classifiers (largely the Malware Hunter crawler, see
section 5) already labelled. The independently useful facts are the
certificate serials and subjects, the property hashes, titles and header
patterns.

Related, credited by C2-Tracker: query contributors BushidoToken, Michael
Koczwara, ViriBack, Gi7W0rm, Glacius_, corumir, salmanvsf, SecurityJosh; a KQL
ingestion query by BertJanCyber; an OpenCTI connector (README says not for
production); FortiSIEM 7.2.0 consumed the feed; c2tracker.com (Y_nexro), now
"archived / paused".

---

## 2. cybersheepdog/Adversary-Hunter

**What it is.** The continuation of C2-Tracker after it was archived. Same
output design, Shodan only. 67 commits, 5 stars.

**Method.**
- Documented: indexed search only (Shodan). Queries live in `hunter.py`;
  private extra queries can be added in `shodan_queries.json` (a JSON object of
  product name to a string or list of strings; a custom name equal to a
  built-in one replaces the built-in queries). Key from `.env` via
  `python-dotenv`.
- Documented: runs Mondays 12:00 EST (weekly). `autoupdate.sh` present, no
  scheduler in repo.
- Documented: "validating the existing signatures" inherited from C2-Tracker
  is in progress. Inferred from the code: validation means the author
  disabling (commenting out) queries; there is no automated check against
  other sources, no minimum count, no benign-host filter. A TODO notes
  duplicate queries are not detected.
- Output: `data/{Product} IPs.txt` and `data/all.txt`, overwritten each run,
  numerically sorted, de-duplicated, no ports, no timestamps. If a run finds
  nothing, `data/` is left untouched.

**Licence.** No LICENSE file seen: all rights reserved. Re-key facts only.

**Active queries (differences from C2-Tracker marked NEW).**

| Tool | Shodan queries |
|---|---|
| AdaptixC2 (NEW) | `Server: AdaptixC2`; `http.html: 'AdpatixC2 404'` (sic, likely typo); `Server: AdaptixC2 Port:4321` |
| AsyncRAT | `product:AsyncRAT` |
| Brute Ratel C4 | `http.html_hash:-1957161625`; `product:'Brute Ratel C4'` |
| BurpSuite | `product:BurpSuite` |
| Caldera | `http.title:"Login \| CALDERA"` |
| Cobalt Strike | `ssl.cert.serial:146473198`; `hash:-2007783223 port:50050`; `product:'Cobalt Strike Beacon'` (the `ssl:foren.zik` query dropped) |
| Covenant | `product:Covenant` |
| DarkComet | `product:'DarkComet Trojan'` |
| DayBreak BAS (NEW) | `http.favicon.hash:991353327` |
| DcRat | `product:DcRat` |
| Gh0st RAT | `product:'Gh0st RAT Trojan'` |
| GoPhish | `http.title:'Gophish - Login'` |
| Hak5 Cloud C2 | `product:'Hak5 Cloud C2'` |
| Havoc | `X-Havoc: True` |
| Hookbot | `http.title:'Hookbot Panel'` |
| MobSF | `http.title:'Mobile Security Framework - MobSF'` |
| Mozi | `http.html_hash:-1245370368` |
| Mythic | `ssl:Mythic port:7443`; `http.favicon.hash:-859291042` |
| NanoCore | `product:'NanoCore RAT Trojan'` |
| NetBus | `product:'NetBus Trojan'` |
| NimPlant | `http.html_hash:-1258014549` |
| njRAT | `product:'njRAT Trojan'` |
| Orcus | `product:'Orcus RAT Trojan'` |
| PANDA C2 | `http.html:PANDA http.html:layui`; `product:'Panda C2'` |
| Pantegana | `ssl:Pantegana ssl:localhost` |
| PoshC2 | `ssl:Pajfds ssl:P18055077` (NEW form: two certificate subject terms) |
| PureRat (NEW) | `ssl:'PureRat Agent'`; `ssl:'PureCrack'` |
| Quasar | `product:'Quasar RAT'` |
| RedGuard | as C2-Tracker |
| Remcos | `product:'Remcos Pro RAT Trojan'` |
| SectopRAT | `http.headers_hash:-1731927497 port:9000,15647` |
| ShadowPad | `product:ShadowPad` |
| Sliver | 404 header pattern as C2-Tracker; `product:'Sliver C2'`; `http.html:sliver-client` (NEW); `ssl.jarm:28d28d28d00028d00043d28d28d43d47390d982d099a542ccbc90628951062` (NEW) |
| Supershell | as C2-Tracker |
| Unam Web Panel | as C2-Tracker |
| Villain | `hash:856668804` |
| Viper | `http.html_hash:-1250764086` |
| XMRig | as C2-Tracker |
| ZeroAccess | `product:'ZeroAccess Trojan'` |

Disabled (commented out, mostly without a reason): 7777, AcidRain, Ares,
Atlantida, Bandit, BitRAT, BlackNET, Collector, DarkTrack, Deimos, Doxerina,
Empire, Hashcat, Meduza, Misha, Mystic, Oyster, Patriot, Poison Ivy, Poseidon,
Prysmax, RAXNET, RisePro, Scarab, Spectre, SpiceRAT, SpyAgent, Titan, Vshell,
plus alternate favicon/HTML-hash queries for Covenant, Caldera, Havoc, Mythic,
Sliver, Cobalt Strike, Pantegana and PoshC2 (the Sliver certificate query
`ssl:multiplayer ssl.cert.issuer.cn:operators` is among the disabled ones).
Inferred: the disabled set is the author's fidelity judgement, which is itself
useful as a "demoted" flag in our library. Modlishka is named in the README
tool list but has no query in the code.

---

## 3. C2 Hunter (c2-hunter.newtonpaul.com) and newtonpaul-hunting/c2-iocs

**What it is.** A personal threat-intelligence site by Newton Paul and a
GitHub CSV mirror of its "sightings".

**Site (Documented).** Tag line "Curated threat intelligence from active
scanning". Dashboard: framework breakdown, top ASNs, Cobalt Strike panels
(spawn processes, POST URIs, jitter). Tables "All C2 Servers" and "Malware
Dirs" with columns Type, Host, Country, Network, Tags, Note, First seen, Last
seen; "Download IOC CSV". Entries carry a 0-10 confidence and analyst notes.
An "Add Entry" form (about 49 framework choices, including RATs, stealers,
and tunnelling tools such as Chisel, frp, Ligolo-ng) can "publish immediately"
to the feed; an "Authorize" dialog takes an API key. Both the home page and
`/frameworks` are rendered by JavaScript and showed no data to WebFetch, so no
counts could be read. No licence or terms shown.

**Feed (Documented).** README "C2 Sightings IOC Feed": "Live feed of confirmed
C2 infrastructure identified by active scanning", updated when entries are
published to C2 Hunter, plus a Defender for Endpoint KQL join. One file,
`c2_sightings.csv`, header `IP,Framework,Port,Country,PublishedAt`
(PublishedAt is YYYY-MM-DD). No LICENSE, no terms.

**Feed contents (Observed, read 2026-11-11, counts approximate because the
fetch tool summarised a 108 KB file):**
- Roughly 2,200 to 2,600 rows; PublishedAt from **2026-05-07 to 2026-08-02**.
- Framework values, roughly by size: cobalt-strike (~380), mythic (~330),
  sliver (~200), viper (~170), metasploit (~140), asyncrat (~130), quasarrat
  (~130), supershell (~120), dcrat (~110), covenant (~70), havoc (~70),
  adaptix (~50), unknown (~35), redguard, unam-web-panel, c2hunt (~15 each),
  playpraetor, dindoor, hookbot, chaos-rat, sparkrat, starkiller, nexus-c2,
  other, deimos, poshc2, nimplant, bitrat, tinyloader, neptune (single
  digits). At least one misspelt value ("uasarrat").
- Dominant ports per framework: cobalt-strike 50050 (then 8333, 443, 8443,
  18443); mythic 7443 (then 443); sliver 31337; viper 60000; metasploit 3790;
  supershell 8888; covenant 7443; havoc 443; adaptix 4321; quasarrat 4782;
  dcrat 443/8848/7777/8080; asyncrat spread widely.
- Commits: 1,280 on main, one per indicator, message template
  `add <IP> (<framework>)`, single account, no bot marker. Latest commit
  **2026-08-02**.

**Cadence (Observed vs Documented).** The README says "updated
automatically"; the commit history and the CSV both stop at 2026-08-02, about
14 weeks before this check. **The GitHub feed appears stalled.** The site may
hold newer data (it has first/last-seen columns the CSV lacks), but that could
not be read. This corrects ROADMAP's "updated automatically" note.

**Methodology.**
- Documented on the site: "active scanning", unspecified.
- Blog posts "Hunting New C2 Frameworks" (2026-05-05) and "Part 2 - Nexus C2,
  Shipped with Creds" (2026-05-10) could not be fetched (safety safeguard, see
  the end). From search-engine snippets only (not read in full): the author
  found a Chinese-language panel named **ZShell** on a couple of IPs (one shown
  on port 8084, AS967 VMISS, Hong Kong) and identified it from front-end code
  (a Zustand persist store keeping the JWT in localStorage under the key
  `zshell-auth`); Part 2 says an "automated C2 scanner" flagged the Nexus
  panel. No published queries were seen.
- Inferred: the author runs their own probing scanner (consistent with "active
  scanning", the per-host confidence and the Cobalt Strike config statistics,
  which require pulling beacon configs). This is active probing, which the
  toolkit does not do. The feed's value to us is as a corroboration source,
  not a method to copy.

**Licence.** None stated on site or repo: all rights reserved. Fetch at
runtime for local use only; never ship rows.

---

## 4. Framework fingerprints from public repos and docs

Store each with framework, version or commit, component (teamserver, operator
UI, listener, implant), type (vendor default, public profile, observed,
confirmed) and source. A teamserver port is not a listener port.

### 4.1 Cobalt Strike

Repos: Cobalt-Strike/Malleable-C2-Profiles (fork of rsmudge's; folders `APT/`,
`crimeware/`, `normal/`; README targets CS 3.x; advises changing defaults for
evasion) and BC-SECURITY/Malleable-C2-Profiles (folders APT, Crimeware,
Normal, `template.profile`; profiles "tested and work successfully with
Empire"; credits rsmudge, xx0hcd, threatexpress, and others). **Neither repo
has a licence**: do not copy profiles; values may be recorded as facts.

| Observable | Value | Component | Type | Source |
|---|---|---|---|---|
| Default TLS cert serial | `146473198` (hex `08:BB:00:EE`) | listener / teamserver default keystore | vendor default | C2-Tracker; nuclei `cobalt-strike-c2.yaml` (MIT) |
| Default cert issuer CN | `Major Cobalt Strike` | as above | vendor default | awesome-censys-queries (CC0) |
| Teamserver port | `50050` (banner hash `-2007783223` on Shodan) | teamserver | vendor default (Documented by query); Observed dominant in c2-iocs | C2-Tracker |
| Shodan product | `Cobalt Strike Beacon` | listener (beacon config pulled by Shodan) | Shodan classifier | C2-Tracker |
| reference.profile example values | sleeptime 60000 ("default sleep in ms"), jitter 0, pipename `msagent_###` (commented as default SMB pipe), `ssh_banner "Cobalt Strike 4.2"`, `tcp_port 4444`, https-certificate CN `localhost` (comment: do not leave as localhost), http-config `Server: Apache`, `block_useragents "curl*,lynx*,wget*"` | profile | public profile (example, not necessarily runtime default) | Cobalt-Strike/Malleable-C2-Profiles `normal/reference.profile` (no licence: facts only) |
| Beacon-config fields worth storing per sighting | watermark, public key SHA-256, user agent, submit URI, C2 host list, spawn-to, pipe name, sleep, jitter, kill date | implant config | observed | Fox-IT corpora (2022 GitHub set and 2026 HF set) |

Notes: `ssl:foren.zik` (C2-Tracker, dropped by Adversary-Hunter) is a
certificate string from a widely reused cracked kit; treat as "public
profile/kit", not vendor default.

### 4.2 Havoc

Repo licence: **GPL-3.0** (LICENSE file). The `profiles/` folder on `main`
holds `havoc.yaotl`, `http_smb.yaotl`, `webhook_example.yaotl`. The file
`Teamserver/profiles/havoc_default.yaotl` named in the brief returned 404 on
`main` (both raw and blob, both case variants); Inferred: it belonged to an
older layout.

| Observable | Value | Component | Type | Source |
|---|---|---|---|---|
| Teamserver bind/port | `0.0.0.0:40056` | teamserver | vendor default (both shipped profiles) | `profiles/havoc.yaotl`, `profiles/http_smb.yaotl` |
| Demon sleep/jitter | 2 s / 15 % (`havoc.yaotl`), 2 s / 20 % (`http_smb.yaotl`) | implant | vendor default | same |
| Spawn-to | `C:\Windows\System32\notepad.exe` / `SysWOW64\notepad.exe` | implant | vendor default | `havoc.yaotl` |
| Example HTTP listener | port 443, Secure false, URI `/Collector/2.0/settings/`, Teams-imitating request headers (`Referer: https://teams.microsoft.com/_`, `x-ms-client-type: desktop`), response `Server: Microsoft-HTTPAPI/2.0`, UA Chrome 96 on Windows 6.1 | listener | public profile (shipped example) | `http_smb.yaotl` |
| SMB pipe | `demon_pipe` | implant | shipped example | `http_smb.yaotl` |
| Response header | `X-Havoc: true` | listener | Documented as a query only; source code not readable (refused) | C2-Tracker, Adversary-Hunter |
| TLS cert subject | contains `postalCode=3540` | listener (Secure true) | vendor default per template | nuclei `havoc-c2.yaml` (MIT) |
| JARM | `3fd21b20d00000021c43d21b21b43de0a012c76cf078b8d06f4620c2286f5e` (with `ssl:postalCode=3540`) | listener | published fingerprint | nuclei `havoc-c2.yaml` metadata |

### 4.3 Sliver

Repo licence: **GPL-3.0** (LICENSE file read). The repo page, the docs
markdown and the docs site could not be read (refused or JavaScript-only), so
everything below comes from defender sources.

| Observable | Value | Component | Type | Source |
|---|---|---|---|---|
| Operator (multiplayer) cert | issuer CN `operators`, subject CN `multiplayer` | multiplayer listener (operator gRPC) | vendor default | nuclei `sliver-c2.yaml`; C2-Tracker; C2IntelFeeds |
| Multiplayer port | `31337` | multiplayer listener | Observed (dominant in c2-iocs); vendor default not confirmed from Sliver docs in this session | c2-iocs |
| HTTP 404 template | `HTTP/1.1 404 Not Found` with `Cache-Control: no-store, no-cache, must-revalidate`, `Content-Length: 0`, no `Server:`, no `Pragma:` | HTTP(S) listener | published query | C2-Tracker |
| Body string | `sliver-client` | unclear | published query | Adversary-Hunter |
| JARM (A) | `3fd21b20d00000021c43d21b21b43d41226dd5dfc615dd4a96265559485910` | TLS listener | published fingerprint | awesome-censys-queries (CC0) |
| JARM (B) | `28d28d28d00028d00043d28d28d43d47390d982d099a542ccbc90628951062` | TLS listener | published fingerprint | Adversary-Hunter |
| Host-side hunting (not network) | PsExec service named "Sliver", description "Sliver implant", 10-char random exe in Windows\Temp; notepad.exe as default injection target | implant | vendor default at 2022 | Microsoft, "Looking for the Sliver lining" (2022-08-24) |

Note (Inferred): Sliver JARM (A) and the Havoc JARM share the first half
`3fd21b20d00000021c43d21b21b43d`, which encodes the server's TLS stack (Go's
`crypto/tls`), not the C2. This is why a JARM may only be one term of a
conjunction (ROADMAP already says so); the library should flag "Go TLS
default" JARMs explicitly.

### 4.4 Mythic

The MythicC2Profiles organisation page and its `http` profile repo were
refused by the safety safeguard, so profile defaults and licences are not
recorded here. From the Mythic docs installation page (docs.mythic-c2.net):

| Observable | Value | Component | Type | Source |
|---|---|---|---|---|
| Web UI (nginx) | `NGINX_PORT="7443"`, `NGINX_USE_SSL="true"`, `NGINX_BIND_LOCALHOST_ONLY="false"` | operator UI | vendor default | Mythic docs |
| Other ports | server 17443, gRPC 17444, dynamic `7000-7010,1080` (exposed by default), Hasura 8080, docs 8090, Jupyter 8888, RabbitMQ 5672, Postgres 5432, React 3000 (most localhost-only by default; docs disagree on Postgres) | backend | vendor default | Mythic docs |
| Admin user | `mythic_admin` | UI | vendor default (not a detection signal) | Mythic docs |
| TLS cert | issuer/subject O `Mythic` | operator UI | vendor default (self-signed) | nuclei `mythic-c2-ssl.yaml` (MIT); awesome-censys-queries |
| Favicon | `http.favicon.hash:-859291042` | operator UI | published query | C2-Tracker |
| Login redirect | to `/new/login`, title contains "Mythic" | operator UI | published | Hunt.io C2 panels guide |

### 4.5 Other frameworks with published facts worth seeding

From awesome-censys-queries (CC0, copyable), nuclei `ssl/c2/` (MIT,
copyable with notice: asyncrat, bitrat, cobalt-strike, covenant, dcrat, gozi,
havoc, icedid, metasploit, mythic, onimai-rat, orcus, posh, quasar, shadowpad,
sliver, venomrat), C2IntelFeeds README (CC BY-NC-SA), Hunt.io guide:

- AsyncRAT cert CN `AsyncRAT Server`; DcRat `DcRat Server`; BitRAT `BitRAT`;
  Orcus `Orcus Server` / `OrcusServerCertificate`; Quasar `Quasar Server CA`
  / `Anony96`; NanoCore CN `unk`.
- PoshC2 subject DN `C=US, ST=Minnesota, L=Minnetonka, O=Pajfds, OU=Jethpro, CN=P18055077`.
- Covenant: issuer CN `Covenant`, body `Blazor` and `covenant.css`.
- Deimos: JARM `00000000000000000041d00000041d9535d5979f591ae8e547c5e5743e5b64`, title `Deimos C2`, cert O `Acme Co` on 8443.
- Merlin JARM `29d21b20d29d29d21c41d21b21b41d494e0df9532e75299f15ba73156cee38`.
- EvilGinx2 JARM `20d14d20d21d20d20c20d14d20d20daddf8a68a1444c74b6dbe09910a511e6`; issuer O `Evilginx API` (C2IntelFeeds).
- Brute Ratel body SHA-1 `1a279f5df4103743b823ec2a6a08436fdf63fe30` (Censys) and Shodan `http.html_hash:-1957161625`.
- NimPlant `Server: NimPlant C2 Server`.
- RedGuard subject DN beginning `C=CN, L=HangZhou, O=Alibaba (China) Technology Co.` and the 307 redirect to `https://360.net`.
- Metasploit: title "Metasploit", `MetasploitSelfSignedCA`, favicon `-127886975`; Observed port 3790.
- Supershell: title `Supershell - 登录`, path `/supershell/login/`, port 8888.
- Chaos RAT: body links `github.com/tiagorlampert/CHAOS`, port 8080.
- IcedID cert `CN=localhost, C=AU, ST=Some-State, O=Internet Widgits Pty Ltd` (OpenSSL default subject: very high false-positive risk, demote).
- Pupy: cert OU `CONTROL` with random 10-letter O (C2IntelFeeds).
- NetSupport: `Server: NetSupport Gateway/`.
- AdaptixC2: `Server: AdaptixC2`, port 4321 (Adversary-Hunter; Observed 4321 in c2-iocs).

---

## 5. Other C2 feeds and collections found along the way

| Source | What | Method | Format | Licence / terms |
|---|---|---|---|---|
| drb-ra/C2IntelFeeds | Verified and unverified C2 IPs, domains, domain+URL, IP+port, config metadata (CSV/JSON, 7/30/90-day windows), VPN and residential proxy lists | Indexed search: Censys until 2026-05-01, Modat since. Fingerprints by TLS fields, JARM, headers, titles, body and banner hashes; domains from implant configs; `exclusions.rex` drops CDNs and shared hosting | `feeds/IPC2s.csv` header `#ip,ioc`; about 129 rows on 2026-11-11, all "Possible Cobaltstrike C2 IP"; `feeds/domainC2s-filter-abused.csv`; `feeds/unverified/IPC2s.csv` | CC BY-NC-SA 4.0. Local non-commercial use with attribution is allowed; we keep it runtime-only so the repo is not pulled under share-alike |
| ThreatFox (abuse.ch) | IOCs incl. `ip:port` C2 with malware family, tags, confidence | Community submission, human-reviewed unless Trusted Reporter; many submitters hunt with scanners (Inferred) | API JSON, MISP, Suricata, hostfile, RPZ | abuse.ch Terms: free for non-profit under fair use; commercial needs Spamhaus subscription; **section 7.3 forbids using the data to train or improve AI models** without consent. Only last 6 months via API/exports since 2025-05-01 |
| SSLBL (abuse.ch) | Malicious cert SHA-1 list, botnet C2 IP list (IPs seen with a listed cert in last 30 days), JA3 list | abuse.ch sinkhole/sandbox analysis | CSV (`listing date, SHA1, reason`; `firstseen, DstIP, DstPort`; `ja3, first, last, reason`), Suricata, RPZ; every 5 minutes | CC0 (Terms 3.4: Feodo, SSLBL, YARAify). JA3 list warned as untested against benign traffic |
| ViriBack C2 Tracker (tracker.viriback.com) | 13,148 C2 panel URLs (family, URL, IP, first seen DD-MM-YYYY), newest 2026-11-09 | Not documented | Web table, "Export All CSV", `/dump.php` | No licence stated: runtime only. Some IPs are shared/CDN |
| Shodan Malware Hunter | Shodan's crawler that impersonates an infected client checking in to every IP; positive responders tagged `malware` | **Active probing by Shodan** (Documented); feeds the `product:` labels and `tag:malware` | Shodan search | **`tag` filter is not available on the Membership plan** (Shodan billing page: "All except vuln and tag"). `product:` queries still work |
| thehappydinoa/awesome-censys-queries | Censys query collection with a C2 section (section 4.5) | Indexed search queries | README + `queries.json` | CC0: copy freely |
| projectdiscovery/nuclei-templates `ssl/c2/` | 17 TLS templates matching cert serial, subject, issuer | **Active probing** when run; metadata carries Shodan/Censys queries | YAML | MIT (ProjectDiscovery, 2025): values copyable with notice; the toolkit uses the values, never runs probes |
| Fox-IT Cobalt Strike corpora | 2026 HF set (CC BY 4.0, already in ROADMAP); 2022 GitHub set `fox-it/cobaltstrike-beacon-data`: 128,340 records 2018-2022, JSONL.gz per year plus `iocs-export.csv`, fields incl. tls_subject/issuer/fingerprint, watermark-bearing config, SETTING_* (UA, URIs, pipe, public key SHA-256), geo/ASN | Their own beacon collection (active) | JSONL, CSV, notebook | 2022 set: **no LICENSE file** (raw `LICENSE` 404): all rights reserved; runtime/local study only, re-key facts. README warns IOC export is unsafe for blocking (arbitrary host headers, CDN IPs) |
| Hunt.io "Hunting C2 Panels" guide | Titles, paths, favicon MD5, body hash for Supershell, HookBot, Chaos, Unam, Metasploit, Mythic | Hunt.io's own scan datasets (HuntSQL) | Blog | Copyright blog: facts only. Page date inconsistent (metadata 2026-11-11, body 2025-09-25) |
| c2tracker.com (Y_nexro) | Dashboard built on C2-Tracker | n/a | n/a | Archived/paused; no data available |
| Referenced, not read | BushidoToken/OSINT-SearchOperators (404 on GitHub and raw), RST Cloud/Netlas C2 hunting posts, Virus Bulletin 2023 "C2F2" paper, Kraven (already in ROADMAP) | | | |

---

## 6. Reuse table

| Source | Fetch at runtime only (never in repo) | May be re-keyed as facts | May be copied (licence allows) |
|---|---|---|---|
| C2-Tracker | its (now deleted) data files via git history, if ever wanted | serials, hashes, titles, header strings, ports from its queries; our own query strings written from those facts | nothing (no licence) |
| Adversary-Hunter | `data/*.txt` IP lists | same as above, plus its disabled-set as "demoted" flags | nothing (no licence) |
| C2 Hunter / c2-iocs | `c2_sightings.csv` rows | framework-to-port observations as aggregate facts | nothing (no licence) |
| C2IntelFeeds | all feeds | fingerprint facts from README table | not shipped (CC BY-NC-SA share-alike) |
| ThreatFox | all IOCs (already integrated) | n/a | no (terms); also no AI training use |
| SSLBL | lists | | yes, CC0 (cert SHA-1 list, JA3 list) |
| ViriBack | CSV export | panel title/path patterns | nothing (no licence) |
| awesome-censys-queries | | | yes, CC0 (queries and values) |
| nuclei `ssl/c2` | | | yes, MIT (values; keep notice) |
| Cobalt Strike / BC-SECURITY Malleable profiles | profile files (if ever parsed) | default and example values | nothing (no licence) |
| Havoc profiles | | ports, sleep, URIs, headers (facts) | GPL-3.0: copying files would bring GPL obligations; re-key instead |
| Sliver | | defaults from defender sources | GPL-3.0 code/docs: re-key only |
| Mythic docs | | default ports and env values | (licence not read) |
| Fox-IT 2026 HF corpus | sightings subset | | CC BY 4.0 with attribution; payload subset falls under the malware storage rule |
| Fox-IT 2022 GitHub data | all | aggregate facts (watermarks, public keys) | nothing (no licence file) |
| Hunt.io, Microsoft, ProjectDiscovery blogs | | facts with citation | no |

---

## 7. Proposal: the toolkit's own C2 tracking

### 7.1 Principles
- Passive only: Shodan indexed search and host lookups (and abuse.ch/C2 feeds).
  No probing, no JARM computation, no contacting a hit. Never run C2 software.
- A hit says "this host matched signature S of tool T on port P at time X
  according to source Y". It identifies software with a given configuration,
  never an operator, campaign, or intent.

### 7.2 Schema (SQLite)

```sql
-- One row per fingerprint fact.
CREATE TABLE c2_signature (
  id              INTEGER PRIMARY KEY,
  key             TEXT UNIQUE NOT NULL,   -- stable slug, e.g. 'cs.cert.serial.default'
  tool            TEXT NOT NULL,          -- 'Cobalt Strike', 'Sliver', ...
  tool_kind       TEXT NOT NULL,          -- c2_framework | rat | stealer_panel | phishing_kit | dual_use_tool | botnet
  component       TEXT NOT NULL,          -- teamserver | operator_ui | listener | implant | panel
  feature_class   TEXT NOT NULL,          -- tls_cert | jarm | http_header | http_body | title | favicon | banner | port | product_label
  fingerprint_kind TEXT NOT NULL,         -- lossless | lossy | label (product:) | substring
  value           TEXT NOT NULL,          -- the fact: '146473198', 'CN=multiplayer', mmh3 int, JARM...
  port_hint       TEXT,                   -- '50050', '7443'; NULL if none
  sig_type        TEXT NOT NULL,          -- vendor_default | public_profile | observed | confirmed | provider_label
  version_scope   TEXT,                   -- 'Havoc main @ 2026-11-11', 'CS 4.x'
  shodan_query    TEXT,                   -- our own query text built from the fact
  censys_query    TEXT,                   -- reference only (search is paid)
  needs_conjunction INTEGER NOT NULL DEFAULT 0, -- 1 for Go-TLS JARMs, OpenSSL default subjects, ports
  fp_note         TEXT,                   -- known false-pivot trap
  source_name     TEXT NOT NULL,
  source_url      TEXT NOT NULL,
  source_licence  TEXT NOT NULL,          -- 'CC0', 'MIT', 'none (fact re-keyed)', ...
  status          TEXT NOT NULL DEFAULT 'active', -- active | demoted | retired
  added_on        TEXT NOT NULL,
  last_verified_on TEXT                   -- last date the count call returned > 0
);

-- A saved hunt is one or more signatures ANDed (plus optional NOT terms).
CREATE TABLE c2_hunt (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, query TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'shodan', priority INTEGER NOT NULL DEFAULT 3,
  cadence_days INTEGER NOT NULL DEFAULT 7, enabled INTEGER NOT NULL DEFAULT 1,
  first_used TEXT, last_yield TEXT, ttl_days INTEGER
);
CREATE TABLE c2_hunt_signature (hunt_id INTEGER, signature_id INTEGER, negate INTEGER DEFAULT 0);

CREATE TABLE c2_hunt_run (
  id INTEGER PRIMARY KEY, hunt_id INTEGER, run_at TEXT NOT NULL,
  total_count INTEGER,            -- from free count call
  credits_spent INTEGER NOT NULL DEFAULT 0,
  new_hosts INTEGER, known_bad_share REAL, -- hunt quality score
  error TEXT
);

-- One row per (ip, port, signature) observation.
CREATE TABLE c2_sighting (
  id INTEGER PRIMARY KEY,
  ip TEXT NOT NULL, port INTEGER, transport TEXT,
  signature_id INTEGER, hunt_id INTEGER, source TEXT NOT NULL, -- shodan | c2intelfeeds | threatfox | c2-iocs | sslbl | viriback
  source_seen_at TEXT,      -- provider's own timestamp (Shodan banner 'timestamp'; feed first/last seen; c2-iocs PublishedAt is publish date)
  first_seen_local TEXT NOT NULL, last_seen_local TEXT NOT NULL,
  asn INTEGER, org TEXT, country TEXT, cert_sha256 TEXT, jarm TEXT,
  validation TEXT NOT NULL DEFAULT 'unvalidated', -- unvalidated | rechecked | corroborated | suppressed | stale
  validation_note TEXT,
  UNIQUE (ip, port, signature_id, source)
);
```

### 7.3 Seed list (first release), by source and licence
1. **Copied (CC0/MIT, with attribution):** awesome-censys-queries C2 entries
   (certificate subjects, JARMs, body hashes) and nuclei `ssl/c2` matcher
   values (CS serial `08:BB:00:EE`, Sliver `operators`/`multiplayer`, Mythic
   `O=Mythic`, Havoc `postalCode=3540` + JARM, AsyncRAT/DcRat/Orcus/Quasar/
   BitRAT/PoshC2/Covenant subjects). SSLBL cert SHA-1 list as a matching table.
2. **Re-keyed facts (no licence, written in our own words and query syntax):**
   from C2-Tracker and Adversary-Hunter the hash and title facts for Cobalt
   Strike (teamserver banner hash on 50050), Metasploit, Covenant, Mythic
   favicon, Brute Ratel, PoshC2, Sliver 404 template and JARM (B), Deimos,
   NimPlant, Havoc `X-Havoc`, Caldera, Supershell, Viper, RedGuard, AdaptixC2,
   Unam, Hookbot, SectopRAT, and the panel titles. Mark Adversary-Hunter's
   disabled ones `status='demoted'`.
3. **Vendor defaults from framework sources:** Havoc teamserver 40056 and
   shipped profile values; Mythic port table; Cobalt Strike default
   certificate; Sliver multiplayer certificate. Port-only rows always
   `needs_conjunction=1`.
4. **Observed:** port distributions from c2-iocs and C2IntelFeeds as
   `sig_type='observed'`, used only to rank, never to match alone.
5. **`product:` labels:** stored as `feature_class='product_label'`,
   `sig_type='provider_label'`, so the UI says "Shodan classified this", which
   is a different claim from "we matched a fingerprint".

Leave out of the default hunt set (keep in library, disabled): dual-use
tools (BurpSuite, Hashcat, MobSF, GoPhish, XMRig, Caldera, Responder,
Interactsh) and the OpenSSL-default IcedID subject.

### 7.4 Daily Shodan hunt within the Membership quota

Plan limits (Shodan billing page, 2026-11-11): Membership = **100 query
credits a month**, 100 scan credits (unused: scanning is out of scope),
filters "All except vuln and tag" (so `tag:malware` is unavailable). API
docs: `/shodan/host/search` costs 1 credit if the query has a filter or for
each 100 results past page 1; **`/shodan/host/count` costs nothing**. Credits
renew at the start of the month.

Run order each day (scheduler from Phase 5):
1. **Count pass (free).** For every enabled hunt due today, call
   `/shodan/host/count?query=...&facets=port,org,country` and store
   `total_count` in `c2_hunt_run`. Respect a 1 request/second pace (common
   client practice; not confirmed on the API page). Whether an `ip` facet
   exists was not verified; test it once with a count call, which is free.
2. **Change gate.** Spend a credit only if the total changed since the last
   run, or the hunt's cadence is due. Add a date filter so page 1 holds only
   new banners (Shodan `after:` filter; verify with a free count call before
   relying on it).
3. **Search pass (paid).** `/shodan/host/search` page 1 only (1 credit, up to
   100 results). Hard budget: 3 credits a day, 70 a month for scheduled hunts,
   30 held back for manual pivots. If a hunt's count exceeds 100 after the
   date filter, it is too broad: flag it for narrowing instead of paging.
4. **Rotation.** Priority 1 hunts (default certificates of Cobalt Strike,
   Sliver, Mythic, Havoc; Cobalt Strike teamserver banner) run every few days;
   priority 3 panels weekly or monthly. With ~3 credits a day, about 20
   hunts can each run weekly.
5. **Feeds alongside (no Shodan credits):** C2IntelFeeds, SSLBL, ThreatFox
   (already integrated), c2-iocs and ViriBack CSV fetched daily into the
   sightings table with `source` set, never committed.

### 7.5 Validation and timestamps
- `source_seen_at` = the Shodan banner's own `timestamp` (crawl time), or the
  feed's first/last seen. `first_seen_local` / `last_seen_local` = when the
  toolkit first and last saw it. c2-iocs `PublishedAt` is a publish date and
  is stored as such, never as a first-seen.
- **Recheck** (`rechecked`): one host lookup (`/shodan/host/{ip}`, which does
  not use search credits according to third-party docs; confirm on own key)
  confirms the signature still matches on the latest banner and the same
  port, and records cert SHA-256 and JARM from that banner.
- **Corroborate** (`corroborated`): a second independent feature class
  matches (for example certificate + header hash), or the IP:port appears in
  ThreatFox, C2IntelFeeds verified, SSLBL, or the Fox-IT corpus within an
  overlapping window. One feature class alone never exceeds "Weak" (ROADMAP
  rule).
- **Suppress** (`suppressed`): CDN/cloud front ends, sinkholes, known
  research scanners and honeypots via MISP warninglists and the provider
  range lists; Shodan host `tags` such as honeypot or cdn, if present in the
  host response, recorded as a reason (not verified in this session).
- **Stale**: not seen by any source for N days (default 14); never deleted.
- **Hunt quality score** per run: share of returned hosts already known bad
  (ROADMAP, Kraven). Demote a hunt whose score falls below a threshold for
  several runs; set `last_yield` when it finds a new corroborated host.

### 7.6 What NOT to claim
- A match identifies software and, at most, a configuration (default or a
  public profile). It does not identify an operator, actor, campaign, or
  intent. Default-configured Cobalt Strike, Sliver, Havoc and Mythic are run
  by red teams, trainers, researchers and honeypots as much as by criminals.
- "Cracked kit" facts (for example a shared watermark or certificate string)
  link servers to a build, not to a single owner: many unrelated operators
  share one leaked build.
- A `product:` hit is Shodan's classification from its own active probing,
  not our finding; label it so.
- Port-only and JARM-only matches are not detections. Go-stack JARMs collide
  across frameworks (the Sliver and Havoc JARMs share their first half).
- Feed presence (c2-iocs, C2IntelFeeds unverified, ViriBack) is a third-party
  claim with no published method; record it as corroboration, not proof.
- Attribution stays a separate, optional step behind the Phase 9 evidence
  gate. Low-confidence hits go to a hunt list, never a blocklist.

### 7.7 Corrections for ROADMAP (for the operator to decide)
- c2-iocs: the GitHub feed's last row and last commit are dated 2026-08-02;
  "updated automatically" is not borne out as of 2026-11-11.
- Shodan Membership excludes the `tag` filter, so Malware Hunter's
  `tag:malware` view is unavailable; `product:` labels remain.
- Havoc `havoc_default.yaotl` is not at the given path on `main`; the shipped
  profiles are `profiles/havoc.yaotl` and `profiles/http_smb.yaotl`.
- Fox-IT 2022 GitHub set: no LICENSE file found (all rights reserved).
- C2IntelFeeds changed its raw data provider from Censys to Modat on
  2026-05-01; its verified IP feed held only ~129 Cobalt Strike rows that day.

---

## 8. URLs not read, and why

Safety-safeguard refusals (WebFetch returned: "API Error: Haiku 5.5's
safeguards flagged this message. Our intentionally broad safeguards allow us
to deliver more capabilities faster, but can sometimes flag legitimate
cybersecurity work." Details `[cyber]`). Not retried by another route.

| URL | Request ID |
|---|---|
| https://newtonpaul.com/blog/hunting-ai-generated-c2/ | req_011CgwzfMrcS7WLegkbLvW6q |
| https://newtonpaul.com/blog/hunting-ai-generated-c2-part_2/ | req_011CgwzfRfotGcThufNHUt76 |
| https://github.com/HavocFramework/Havoc | req_011CgwzhtgpBhypEaYUtBuMX |
| https://raw.githubusercontent.com/HavocFramework/Havoc/main/teamserver/pkg/handlers/http.go | req_011Cgwzji2gMu6qgcepgtWoY |
| https://github.com/BishopFox/sliver | req_011Cgwzk31Ryw1CyUYadCGAb |
| https://raw.githubusercontent.com/BishopFox/sliver/master/docs/sliver-docs/pages/docs/md/Multi-player%20Mode.md | req_011CgwzknX5MN7PVWn9npc6p |
| https://github.com/MythicC2Profiles | req_011CgwznESKo4FbSZY4Kvk3T |
| https://github.com/MythicC2Profiles/http | req_011CgwzoQQ8qSAz6NKTjN7FD |

The newtonpaul.com posts have a mirror at newton-paul.pages.dev; it was not
fetched (that would be another route to refused content). Only search-engine
snippets were used, and are marked as such in section 3.

Other failures:
- https://c2-hunter.newtonpaul.com/ and /frameworks: JavaScript-rendered; no
  data in the fetched page.
- https://sliver.sh/docs?name=Multi-player+Mode: JavaScript-rendered,
  "Loading documentation…" only.
- https://raw.githubusercontent.com/HavocFramework/Havoc/main/teamserver/profiles/havoc_default.yaotl
  and https://github.com/HavocFramework/Havoc/blob/main/Teamserver/profiles/havoc_default.yaotl: 404.
- https://github.com/BushidoToken/OSINT-SearchOperators and its raw README: 404
  (repo moved or renamed).
- https://raw.githubusercontent.com/fox-it/cobaltstrike-beacon-data/main/LICENSE: 404
  (no licence file).
- https://account.shodan.io/billing/member: 401 (https://account.shodan.io/billing was read instead).
- MythicC2Profiles licences and http-profile defaults: not obtained (refusals above).
- c2_sightings.csv: read in two parts; counts are the fetch tool's estimates,
  not an exact tally. Verify with a local count when the feed is wired.

## 9. Sources read
- https://github.com/montysecurity/C2-Tracker; raw `tracker.py`, `autoupdate.sh`
- https://github.com/cybersheepdog/Adversary-Hunter; raw `hunter.py`, `README.md`
- https://c2-hunter.newtonpaul.com/; https://github.com/newtonpaul-hunting/c2-iocs (+ commits, raw CSV); https://newtonpaul.com/blog
- https://github.com/Cobalt-Strike/Malleable-C2-Profiles; raw `normal/reference.profile`
- https://github.com/BC-SECURITY/Malleable-C2-Profiles
- Havoc: `profiles/` listing, raw `profiles/havoc.yaotl`, `profiles/http_smb.yaotl`, `LICENSE`
- Sliver: raw `LICENSE`; Microsoft blog 2022-08-24 "Looking for the Sliver lining"
- https://docs.mythic-c2.net/installation
- https://github.com/thehappydinoa/awesome-censys-queries
- nuclei-templates `ssl/c2/` listing; raw `sliver-c2.yaml`, `havoc-c2.yaml`, `mythic-c2-ssl.yaml`, `cobalt-strike-c2.yaml`, `LICENSE.md`
- https://projectdiscovery.io/blog/hunting-c2-servers/ (2023-08-08)
- https://github.com/drb-ra/C2IntelFeeds; raw README, `feeds/IPC2s.csv`
- https://threatfox.abuse.ch/faq/; https://abuse.ch/terms-of-use/; https://sslbl.abuse.ch/blacklist/
- https://malware-hunter.shodan.io/; https://tracker.viriback.com/; https://c2tracker.com/
- https://hunt.io/blog/hunting-c2-panels-beginners-guide
- https://github.com/fox-it/cobaltstrike-beacon-data
- https://developer.shodan.io/api; https://help.shodan.io/the-basics/credit-types-explained; https://account.shodan.io/billing
