# Handoff verification: remaining items (checked 2026-11-11)

Source handoff: <local path> (read as data).
Method: read-only WebFetch / WebSearch. Nothing downloaded, cloned, installed, or signed up for.
"ROADMAP" means ROADMAP.md (line numbers as of today).

Fields per resource: Exists / What it is / Type (live feed, static snapshot, article, tool) /
Licence and access / Maintenance / Corrections to the handoff / Value and phase / ROADMAP status.

---------------------------------------------------------------------------------------------------

## 1. Malware configuration resources and research articles

### Malpedia (malpedia.caad.fkie.fraunhofer.de)
- Exists: yes, live. Run by Fraunhofer FKIE (Daniel Plohmann, Steffen Enders).
- What it is: curated malware family encyclopedia: families, aliases, actor links, bibliography of
  reports, YARA rules, samples. Stats page today: 3,843 families, 9,986 samples (YARA and
  reference counts not shown as numbers).
- Type: live reference database (inventory last changed 2026-11-09: new family win.recorteiro).
- Licence and access: ToS says the whole website content is CC BY-NC-SA 3.0 (3.0, not 4.0).
  Informal policy: use with attribution, not to profit from community work. Non-public material is
  TLP:AMBER. Samples and non-public YARA rules need an account; Malpedia calls itself an
  "invite-only trust group", every registration vetted, API key instead of password, all requests
  logged with username and IP. REST API exists (separate usage page, not read).
- Maintenance: active.
- Corrections: handoff is accurate ("full sample access may be restricted"). Add the NC-SA 3.0
  licence and the vetted-account requirement.
- Value / phase: family naming, aliases and report bibliography for Phase 9 threat profiles; the
  NC licence suits linking, not bulk ingestion.
- ROADMAP: already planned. Phase 9 line 1803 ("Reference, not data: ETDA Threat Group Cards and
  Malpedia"), decision 2026-11-06 (line 2637: "linked, never stored"), and the Phase 1 enrichment
  expansion (lines 2783, 2787: free vetted account, last in priority).

### MalwareConfig.com
- Exists: the domain is up, but the service is not. The site now presents itself as an
  "archive": established 2014, archived 2019, "resumed 2026".
- What it is now: an editorial site with six writeups dated April to September 2026 (YARA
  maintenance, static config extraction, stealer config formats, alternative tools), archive
  pages for old aptnotes/viper/dridex subdomains, and an RSS feed. About page: "not run by Kevin
  Breen" (the original 2014-2019 author), no upload form, "the web app is not coming back", the
  original config index is gone, no data downloads. Operator not named; footer
  "(c) 2026 malwareconfig.com archive".
- Type: article site. No dataset.
- Licence: none stated.
- Corrections: the handoff calls it a "historical configuration archive" and says it "indexed
  approximately 25,473 configurations". The 25,473 figure is the site's own claim about the old
  service at its peak; none of those configs are reachable. Treat it as a re-registered domain run
  by an unnamed third party: read-only reference, and not an authority on the original project.
- Value / phase: low. At most background reading for the parked malware corpus.
- ROADMAP: not mentioned. Nothing to add beyond a "checked, no data" note.

### JR0driguezB/malware_configs (GitHub)
- Exists: yes. Public, not archived.
- What it is: "Various config files obtained during malware analysis". Folders: BackSwap, Cerber,
  IcedID, Kraken, PandaBanker, TrickBot, VPNFilter. 359 commits, 68 stars.
- Type: static historical snapshot. Created 2017-11-24, last push 2018-10-31 (GitHub API).
- Licence: none (API: license null). No licence means no reuse grant: read for reference, re-key
  facts, do not copy files into the repo.
- Corrections: none; handoff says "historical ... not a live feed", which is right. Add: last push
  2018, no licence.
- Value / phase: low; historical regression examples for a config parser in the parked malware
  corpus module. All families are defunct or rare today.
- ROADMAP: already listed, line 2402, as "not yet checked". Can be updated: last push 2018-10-31,
  no licence.

### kevoreilly/CAPEv2
- Exists: yes. Active (last push 2026-11-11), 3,681 stars, not archived.
- What it is: malware sandbox forked from Cuckoo v1: automated unpacking, config and payload
  extraction, debugger-driven countermeasures. Host: Ubuntu 24.04 LTS recommended, Python 3.10/3.12
  tested, KVM recommended. Guests: Windows 10 and Windows 11 23H2. Config parsers now live in the
  separate CAPESandbox/CAPE-parsers repo (installed as a dependency); RATDecoders, DC3-MWCP,
  MalDuck and MaCo also supported.
- Type: tool (self-hosted service).
- Licence: GPL-3.0 core (Cuckoo heritage); bundled pieces under MIT, Apache-2.0, CC BY 2.5
  (lightbox), MIT-or-GPL-2 (jquery). GitHub shows "NOASSERTION/Other" because of the bundle.
  Running it as a separate service and reading its API keeps GPL away from the toolkit's code.
- Corrections: none to the handoff. Note "analysis artifacts such as PCAPs" is accurate.
- Value / phase: dynamic analysis engine for the parked "Malware analysis: static and dynamic"
  module, needs a Linux/KVM host.
- ROADMAP: already planned, line 2423 (CAPE as sandbox option), line 2756 (open decision CAPE vs
  DRAKVUF vs Cuckoo3), and line 790/2382 (CAPE-parsers).

### VMRay: "Climbing the Pyramid of Lumma Pain"
- Exists: yes. Published 2026-02-05, author Julian Wolf (VMRay).
- What it is: research article. 7,000+ Lumma Stealer samples, July to October 2025, 1,207 unique
  C2 domains. Per domain: t0 first seen (earlier of registration or certificate date), t1 first
  used in a config, t2 last used, sightings, SHA-256 of earliest and latest sample, JARM, cert
  issuer. Findings: median domain in 3 samples (mean about 52; one domain in about 3,700); median
  first-to-last use 2.33 days; median 67 days between first seen and first use; five JARM hashes
  dominate. The author says neither JARM nor issuer is high-fidelity alone.
- Type: article. No dataset, CSV, IOC list or GitHub link; only two example VMRay reports and a
  promotion for VMRay's commercial UniqueSignal feed.
- Corrections: handoff is accurate. It lists fields correctly and says no downloadable corpus.
- Value / phase: method model for the parked malware corpus and for Phase 6 (the 67-day
  registration-to-use lag supports watching new certificates and registrations before use).
- ROADMAP: already recorded, lines 2403-2405 ("neither published its underlying configs").

### Proofpoint and IBM X-Force: "StealC You Later"
- Exists: yes. Published 2026-06-24, joint Proofpoint Threat Research and IBM X-Force.
- What it is: research on the June 2026 Operation Endgame StealC disruption (66 domains and 296
  servers across StealC and Amadey; Microsoft DCU civil action). Built a bot emulator that mimics
  StealC check-ins to pull payload URLs; ran samples (internal, VirusTotal, partners) in sandboxes
  with unnamed extraction scripts. Config fields: C2 server/URL, BuildID (often rotated), config
  RC4 key, communication RC4 key. A C2 panel flaw they found supported the seizures.
- Type: article. No sample or config counts given; no dataset, IOC list or code; no GitHub link.
- Corrections: none. Handoff's field list and "not a public configuration corpus" are correct.
- Value / phase: method reference for the parked corpus. Emulating C2 check-ins is active
  engagement with live criminal infrastructure, which the CLAUDE.md working rules already rule out
  for this toolkit; record as "read, not replicated".
- ROADMAP: already recorded, lines 2404-2405.

### VMware Emotet configuration research
- Exists: the handoff gives no link. Found: VMware TAU "Emotet Config Redux" (2022-05-25,
  Oleg Boyarchuk and Stefano Ortolani), "Emotet Exposed" blog (2022-10-10, Javier Inclan) with a
  registration-gated full report, and a Virus Bulletin 2022 talk (Jason Zhang, Oleg Boyarchuk,
  Stefano Ortolani) described as the first large-scale study of configs from Epoch 4 and 5 payloads.
- What they say: Config Redux describes Emotet splitting its C2 list into per-entry obfuscated
  functions (mid-May 2022) and recommends emulation (QEMU/Qiling); it gives no sample count.
  Search snippets of the TAU report say "over 2000 DLL dropped payloads".
- Type: articles and a gated report. No dataset or IOC release on the pages read.
- Corrections: the figure "2,181 extracted Emotet DLL configurations" could not be confirmed; the
  pages read say only "over 2,000" (search snippet) or give no count. The VB page returned 403
  twice. Emotet itself: Feodo Tracker's FAQ says no active Emotet C2s exist. Handoff already
  says drop it as a current focus; agreed.
- Value / phase: none beyond history. Drop, as the operator already said.
- ROADMAP: not mentioned; nothing to add.

---------------------------------------------------------------------------------------------------

## 2. abuse.ch platforms

Common terms (abuse.ch Terms of Use, read today): Feodo Tracker, SSLBL and YARAify are free "for
both commercial and non-commercial purposes" in line with CC0 principles (s. 3.4), best effort.
MalwareBazaar, URLhaus and ThreatFox: free for not-for-profit use under fair-use volume limits;
commercial use "may require a paid subscription" managed by Spamhaus (s. 4.1). s. 7.3 forbids
using abuse.ch Data to "customise, train, or otherwise improve any artificial intelligence model"
without Spamhaus consent: relevant to Phase 11 (assist): abuse.ch data may be shown to a model as
context only if that is not "training"; never fine-tune on it.

### MalwareBazaar (bazaar.abuse.ch)
- Exists: yes, live.
- API (mb-api.abuse.ch/api/v1/, Auth-Key header required on all calls): get_info (SHA-256, MD5 or
  SHA-1), get_file (zipped sample), get_recent (last 60 min or latest 100), recent_detections (up
  to 168 h), get_taginfo, get_siginfo, get_file_type, get_clamavinfo, get_imphash, get_tlsh,
  get_telfhash, get_gimphash, get_dhash_icon, get_yarainfo (max 1,000 results), code-signing
  lookups get_issuerinfo/get_subjectinfo/get_certificate, get_cscb (Code Signing Certificate
  Blocklist), update, add_comment, upload.
- get_info includes a vendor_intel block (ANY.RUN, CAPE, vxCube, Triage, VMRay and others); the
  API page does not say configs are returned, so do not assume extracted C2s arrive through it.
- Exports (Auth-Key in the URL): recent.csv (48 h, every 5 min), full CSV (hourly), plain-text
  hash lists, daily MISP feed, CSCB (every 5 min), YARA rule statistics (hourly), hourly and daily
  sample batches (encrypted zips). File downloads have a daily cap (FAQ, not read).
- Deprecations: none stated.
- Corrections: handoff is accurate. Note the Auth-Key requirement and fair-use / commercial terms.
- ROADMAP: built in Phase 1 (line 113: hash lookup); planned for corpus (line 2375) and code-sign
  pivots (line 1744).

### URLhaus (urlhaus.abuse.ch)
- Exists: yes, live.
- Feeds (Auth-Key required for every download): database dumps CSV/JSON (full = active or last 90
  days; active only; last 30 days; every 5 min), daily MISP events, DNS RPZ (hosts from active or
  48 h URLs, Tranco top 1M excluded), Snort/Suricata rules (active or 10 days), hosts file, plain
  URL list, collected payload hashes, ClamAV signatures (every 1 min). Bulk API at
  urlhaus-api.abuse.ch; submission API (malware_download only).
- Deprecations: none stated. No numeric rate limits.
- Corrections: handoff is accurate (delivery infrastructure, not necessarily C2).
- ROADMAP: built in Phase 1 (line 113); planned dump use at line 770 (note there: the key sits in
  the dump URL, so keep it out of logs).

### SSLBL (sslbl.abuse.ch)
- Exists: yes. Certificate blacklist is live: sslblacklist.csv "Last updated 2026-11-11 13:41:45",
  newest rows today (PureLogsStealer, Vidar, RatonRAT, ACRStealer, PureRAT, Havoc, CobraRAT,
  OffLoader C&C), every visible row from June to November 2026.
- Datasets that exist now and are live: SSL Certificate Blacklist CSV (SHA-1 + listing reason),
  Suricata cert rulesets (1.4+ and 4.1.0+ tls_cert_fingerprint).
- DEPRECATED / FROZEN (the blacklist page itself does not say so; the files do):
  - Botnet C2 IP Blacklist (sslipblacklist.csv/.txt) and the Aggressive variant: header says
    "ATTENTION: This list has been deprecated on 2025-01-03"; 0 data rows. The RPZ and IP
    Suricata rulesets are derived from the same lists (not fetched; presumably empty).
  - JA3 Fingerprint Blacklist (ja3_fingerprints.csv and Suricata JA3 rules): "Last updated
    2021-08-03", 97 entries, newest first_seen 2020-12-27, newest last_seen 2021-08-11. Frozen five
    years; the page still says untested against good traffic and may cause many false positives.
- Licence: CC0-style, commercial use allowed (abuse.ch ToU s. 3.4).
- Corrections: handoff says SSLBL tracks "malicious SSL certificates and associated fingerprints,
  including TLS-related characteristics" without warning that the IP lists are deprecated and JA3
  is a 2021 relic. Use the certificate SHA-1 list only. The MISP default feed catalogue still
  carries "abuse.ch SSL IPBL", which points at the deprecated empty list.
- Value / phase: Phase 6 default-signature library (cert SHA-1 with family label, e.g. "Havoc
  C&C") and Phase 1 enrichment (a certificate SHA-1 match). Do not ingest the JA3 list as
  current.
- ROADMAP: planned, line 1455 (SSLBL as a default-signature source). JA3/JA4 noted at line 1331
  as a pivot type; add that SSLBL's JA3 list is frozen since 2021 and its IP lists deprecated
  2025-01-03.

### Feodo Tracker (feodotracker.abuse.ch): browse, blocklist, FAQ, about
- Banner on every page: "Our Feodo Tracker datasets are currently empty." FAQ (the only entry)
  says: empty because of law-enforcement takedowns (Emotet 2021, Operation Endgame 2024), no
  active botnet C2s for these families now; it points users to the Spamhaus Botnet C2 IPs dataset
  (formerly BCL; maintained with abuse.ch; about 2,000 to 3,000 single IPv4 C2s, up to 50 new a
  day, re-evaluated several times a day; a Spamhaus product, not free abuse.ch data).
- About page: tracks Feodo-lineage families (Cridex, Dridex, Geodo, Heodo/Emotet) and, per the
  front page, TrickBot, QakBot, BazarLoader, Pikabot appear in the data. Detection method not
  described anywhere; the blocklist page says an IP is added only "if it responds with a valid
  botnet C2 response" (i.e. active verification). No API is documented: files only. No
  relationship to ThreatFox is stated on any Feodo page.

What the operator sees on the Browse page versus what the files contain:
- Browse page (/browse/): the full history of every C2 Feodo Tracker ever tracked (same set as the
  "aggressive" list), newest first, with Firstseen, Host, Malware, Status, Network, Country. It is
  not a list of current C2s. Rows with Firstseen in 2026: 4, all QakBot, all Offline:
  27.133.154.218 (2026-03-04), 178.62.3.223 (2026-02-17), 172.232.59.14 (2026-01-19),
  34.204.119.63 (2026-01-13). Rows in 2025: 12, all QakBot, all Offline except 50.16.16.211
  (first seen 2025-12-30, AWS AS14618, port 443) which still shows "Online". The newest
  Firstseen anywhere is 2026-03-04; nothing new in the eight months since. Families in recent
  rows: QakBot and Pikabot only.
- ipblocklist_recommended.txt ("only active C2s or active in the past hours"): exactly 1 entry,
  50.16.16.211 ("# END 1 entries").
- ipblocklist.csv / .json / .txt ("tracked C2s plus IPs acting as C2 within the past 30 days"):
  5 rows: 162.243.103.246:8080 Emotet (first seen 2022-06-04, last_online 2026-03-07),
  50.16.16.211:443 QakBot online (last_online 2026-03-12), and the 2026 QakBot IPs
  34.204.119.63, 178.62.3.223, 27.133.154.218. Fields (JSON): ip_address, port, status, hostname,
  as_number, as_name, country, first_seen, last_online, malware.
- ipblocklist_aggressive.csv ("all C2s ever seen", about 623 KB): full history from 2021; its
  2025-2026 tail is the same 16 rows as the Browse page.
- Every file header reads "Last updated: 2026-03-04 14:28:39 UTC", which is the first_seen of the
  last C2 added. The 30-day file still holds IPs whose last_online is March 2026, eight months
  outside its own 30-day window, and the one "online" IP was last seen online 2026-03-12. So the
  files are not literally empty: they are frozen since March 2026 and their status values are
  stale. The banner, the FAQ, and the files disagree; the files' content is the evidence.
- Correction to ROADMAP line 1554 ("Feodo Tracker's datasets were empty on 2026-11-11"): more
  precisely, abuse.ch says they are empty; the files hold 1 (recommended) and 5 (30-day) stale
  entries, with no new C2 since 2026-03-04. Not usable as a current blocklist either way. The
  Browse page's IPs are historical records (useful context for an IP lookup: "was a QakBot C2 in
  Jan-Mar 2026"), not active infrastructure.
- Reachable through the abuse.ch APIs the toolkit already uses? Feodo Tracker has no API; its data
  is only in the download files (fetched today without an Auth-Key). ThreatFox carries C2 IPs for
  QakBot, Pikabot, Emotet and many more families, reported by abuse.ch and the community, but no
  Feodo or ThreatFox page states that Feodo entries are mirrored into ThreatFox. A web search
  for 50.16.16.211 returned two indexed ThreatFox IOC pages (ioc/1566404, ioc/1288146), which
  suggests ThreatFox holds that IP, but both pages (and ThreatFox browse) are behind a browser
  verification / "confirm you are not a robot" check, which was not bypassed, so this is
  unverified. Check with the toolkit's own Phase 1 ThreatFox search_ioc using the key (about 5
  lookups: the 4 2026 IPs plus 50.16.16.211). Remember ThreatFox's API only serves the last six
  months (ROADMAP line 1556): the January to March 2026 IPs, if present, may already have aged out
  of the API.
- Licence: free, commercial and non-commercial (CC0-style, ToU s. 3.4).
- Value / phase: low now. Optional keyless historical lookup in Phase 1 enrichment ("seen on Feodo
  Tracker, family, first seen, last online") from a cached aggressive CSV fetched at most weekly;
  never as a blocklist.
- ROADMAP: mentioned only at line 1554 as empty.

---------------------------------------------------------------------------------------------------

## 3. MISP default feeds page (misp-project.org/feeds/)
- Exists: yes. A rendering of MISP's shipped feed metadata, source file
  MISP/MISP branch 2.5 app/files/feed-metadata/defaults.json. It "lists source metadata,
  including disabled entries" and "does not check feed availability".
- Size today: 108 feeds from 52 providers (47 CSV, 43 FREETEXT, 18 MISP format). Fields per feed:
  format, name, provider, URL, input source, enabled flag, tags.
- Licence per feed: not given. The page says "Providers may require a licence, authentication or
  impose rate limits"; one feed is marked "requires a valid license" (Bambenek high-confidence
  DGA IPs). Site text is CC BY-SA 3.0, which covers the page, not the feeds. Each provider's own
  terms must be read before use.
- Stale entries spotted: "abuse.ch SSL IPBL" (deprecated 2025-01-03, empty) and "Feodo IP
  Blocklist" (frozen since March 2026). The catalogue itself warns it does not check liveness.
- Corrections: handoff calls it a "catalog of public feeds"; add that it is unvalidated metadata,
  includes disabled and dead feeds, and carries no licence data.
- Value / phase: a discovery list for Phase 4 / Phase 5 feed matching (Threatview C2 Hunt Feed,
  Bambenek DGA, CINS, IPsum, dataplane.org, APNIC honeynet, Tor exits, OpenPhish, PhishTank,
  Phishing.Database). Each candidate needs its own licence check.
- ROADMAP: MISP warninglists (line 1460) and MISP galaxy (line 1780) are planned; MISP push is
  Phase 9/11 (lines 2011, 2103). The default feed catalogue as a discovery source is not listed.

---------------------------------------------------------------------------------------------------

## 4. Network traffic datasets

### Stratosphere CTU-13 (stratosphereips.org/datasets-ctu13)
- Exists: yes (page loaded on the second attempt after a rate-limit).
- What it is: 13 labelled scenarios (numbered 42-54) captured in 2011 at CTU Prague: botnet-only
  pcap, labelled bidirectional NetFlow (Argus .biargus; labels Background, Botnet/C&C, Normal),
  and the original malware executable per scenario. The full pcap with all traffic is withheld for
  privacy. About 1.9 GB tar from mcfp.felk.cvut.cz (Mega backup). Malware per scenario is in an
  image table that could not be read (commonly Neris, Rbot, Virut, Menti, Sogou, Murlo, NSIS.ay;
  from memory, not verified today).
- Type: static historical dataset (2011).
- Licence: the page states none; it asks for citation of Garcia et al., Computers & Security 45
  (2014), doi 10.1016/j.cose.2014.05.011. (cyberset's licence file calls CTU-13 "CC BY"; not
  confirmed on Stratosphere's page.)
- Note: archives contain live malware executables: follow the ROADMAP storage rule.
- Corrections: handoff is accurate.
- ROADMAP: listed at lines 2406-2409 as "not yet checked"; can be marked checked.

### Stratosphere IoT-23 (handoff link stratosphereips.org/datasets/ hit the rate limit; the
specific page /datasets-iot23 was read instead)
- What it is: 23 captures (20 malicious, 3 benign: Philips Hue, Amazon Echo, Somfy lock),
  2018-2019, published January 2020. Families: Mirai, Okiru, Torii, Kenjiro, Hakai, Hide and Seek,
  Muhstik, IRCBot, Hajime, Gagfyt, a Trojan. Files: pcap, Zeek conn.log.labeled, README. About
  20-21 GB full, 8.7-8.8 GB labelled flows only. Download mcfp.felk.cvut.cz/publicDatasets/
  IoT-23-Dataset/.
- Licence: CC BY 4.0 (Zenodo record 4743746, v1.0.0, 2020-01-20). The Stratosphere page itself
  states only a citation request.
- Corrections: handoff says "Twenty malicious IoT traffic captures ... plus benign captures":
  correct (20 + 3).
- ROADMAP: listed at line 2407, "not yet checked"; can be marked checked.

### CTU Malware Captures (stratosphereips.org/datasets-malware)
- What it is: Malware Capture Facility Project list: about 330 malware capture entries (some
  duplicates or mislabelled) plus 2 manual attack captures. Each folder: original pcap and a zip
  (password "infected") with the infecting binary. Years and latest capture date not shown.
- Licence: not stated. Maintenance: described as ongoing, no dates.
- Corrections: handoff accurate.
- ROADMAP: listed at line 2407, "not yet checked".

### malware-traffic-analysis.net
- Exists: yes, active. Latest 2026 posts: 2026-10-22 (scans and probes on own web server),
  2026-10-16 (Coruna-like iOS exploit kit traffic), 2026-10-09 (Macfinger ClickFix), 2026-10-02
  (AMOS stealer via malicious ad impersonating Claude Code), 2026-09-30 (SmartApeSG ClickFix to
  CNCmachineRMS RAT). Archives 2013-2026, plus traffic-analysis training exercises.
- Run by "Brad" (single author; the site gives no surname or organisation).
- Terms of use for the PCAPs: no licence, attribution, commercial-use or redistribution terms on
  the about page. It says use the site "at your own risk"; files labelled "malware" contain live
  malware; some pcaps also contain malware; zip password scheme is shown as an image (not
  readable here). Copyright (c) 2026. So: all rights reserved by default; downloading for local
  testing is the intended use; do not redistribute or commit any pcap into the repo.
- Corrections: handoff says "real-world infection PCAPs, write-ups, IOCs": correct; it does not
  mention the absence of a licence.
- Value / phase: regression pcaps for a future pcap/Suricata module and the sandbox; write-ups as
  an RSS/news source for Phase 4.
- ROADMAP: listed at line 2408, "not yet checked".

---------------------------------------------------------------------------------------------------

## 5. Hugging Face datasets

### cyber-pal-security/SecKnowledge-Eval
- What it is: "SecKnowledge 2.0" evaluation suite for the CyberPal 2.0 small models, paper
  "Toward Cybersecurity-Expert Small Language Models" (ICML 2026). Six subsets, 4,142 items:
  adversarial_cti 709 (4-choice, ATT&CK-derived, distractors chosen to mislead),
  cti_detection_mitigation 964 (4-choice, BRON graph), cti_relationship_prediction 778 (binary,
  CVE/CWE and malware/technique pairs), cve_reassessment 1,124 (free-form; CVE text, CVSS vectors,
  Red Hat state, Bugzilla), technical_weakness_impact 167 (CWE), threat_reports_to_ttp 400
  (full APT reports to ATT&CK, 4-choice).
- Type: static evaluation benchmark. Licence: CC BY-NC 4.0. Not gated. Build method (LLM-made or
  not) not stated.
- Corrections: handoff's task list is right; add NC licence and the counts.
- Value / phase: Phase 11 evaluation of an optional model (non-commercial use fits a local
  personal tool; would block a commercial product). threat_reports_to_ttp is the most relevant
  subset (report-to-technique mapping).
- ROADMAP: listed, line 2086, "not yet checked"; can be marked checked with the above.

### mvd001/cyberset
- Loaded through the API URL (https://huggingface.co/api/datasets/mvd001/cyberset) and raw
  README and LICENSE.md. Created and last modified 2026-10-04 (single build). Not gated.
  About 28.8 GB stored. A personal research project.
- What it is: four tiers. Knowledge hub: kb_vuln 400,870 CVEs (CVE List v5, NVD, OSV, GHSA, KEV,
  EPSS), CWE 4.20 (1,450), CAPEC 3.9 (615), ATT&CK Enterprise 19.2 (858), ET Open rule metadata
  72,048 (no rule bodies). Code: 2.21M functions (299,716 vulnerable) from CVEfixes, MoreFixes,
  CrossVul, PrimeVul, Big-Vul, Draper, Juliet; MegaVul 232,273 in a separate GPL-3.0 folder;
  restricted index 552,944 IDs only (DiverseVul, ReposVul, CleanVul, Devign). Joern graphs 12.0M
  rows. Network: 439.8M harmonised flows from 12 IDS datasets (CIC-IDS2017/2018, CTU-13, IoT-23,
  NF-UQ-NIDS-v2, UNSW-NB15 index only, DARPA 1999 and others), 141,097 CVE-linked flows,
  180,785 Suricata alerts.
- Licence: no single licence; per-row source_license column governs. Non-commercial:
  NF-UQ-NIDS-v2 (about 76M rows), which is inside the aggregate net_flow config. Academic only:
  UNSW-NB15 (index). GPL-3.0: MegaVul. CC BY-SA 4.0: Ubuntu OSV rows. Exploit-DB: IDs only.
- Snapshot dates for NVD, KEV and EPSS not stated; no update schedule. Card caveats: noisy
  commit-mined labels (25-50% accuracy on older sets), weak ATT&CK links, damaged CIC-IDS2017
  timestamps, possible label leakage in feat_pkt_seq.
- Corrections: handoff says "IDS rules, and vulnerable/patched code"; add the network-flow tier,
  the size, and the mixed licence with a non-commercial component in the default aggregate.
- Value / phase: low for this toolkit. The kb_vuln table could be a one-off cross-check of Phase 2
  joins, but our live feeds are fresher. Code and flow tiers are ML material, out of scope.
- ROADMAP: not mentioned.

### it4lia/BODMAS_cleaned
- What it is: cleaned derivative of BODMAS (Yang et al. 2021, UIUC and Blue Hexagon): 134,428 PE
  feature vectors (from 134,435), 77,138 benign and 57,290 malware, 2,326 float32 features (from
  2,381), sha256, timestamp, family and bodmas_family, label, quality flags; 580 families (top 20
  = 69.4% of malware). "Cleaned" = dedup, constant-feature removal, metadata and label checks,
  checksummed manifest. No binaries. Shared by "ACN".
- Licence: card states none of its own; says the original BODMAS files are "associated with the
  BSD-2 License" and asks users to check upstream terms.
- Date range: not stated on the card (upstream BODMAS covers August 2019 to September 2020; from
  memory, not verified today).
- Corrections: handoff correct (134,428, 2,326 features, no PE binaries).
- Value / phase: none for the toolkit's deterministic scope (static ML features). Parked research.
- ROADMAP: not mentioned (EMBER2024-capa is at line 2409).

### IQSeC-Lab/LAMDA
- What it is: longitudinal Android malware benchmark for concept drift; over 1 million APK
  feature records, 2013-2025 excluding 2015; static bag-of-words features feat_0..feat_4560
  (int8); label malware = 4+ VirusTotal detections; families via AVClass2; source AndroZoo.
  Paper arXiv 2505.18551 / ICLR 2026. No APKs.
- Licence: MIT on the card (AndroZoo's own access terms not addressed).
- Card inconsistencies: variance threshold 0.01 in config names vs 0.001 in notes; per-year
  counts not given (so the handoff's "recent-year coverage may be thinner" cannot be checked from
  the card).
- Value / phase: none for the toolkit (ML benchmark). Parked.
- ROADMAP: not mentioned.

### Shrutz72/cvefixes
- What it is: 12,987 vulnerability-fix records from CVEfixes v1.0.8 (11,726 CVEs, 4,205
  repositories): CVE metadata, CVSS, CWE, commits, diffs. The card text calls itself
  "hosted as hitoshura25/cvefixes", i.e. a re-upload of someone else's conversion. Columns not
  listed on the card.
- Licence: card says Apache 2.0 "derived from CVEfixes". Upstream CVEfixes (secureIT-project)
  is MIT for code and CC BY 4.0 for data (Zenodo 10.5281/zenodo.4476563). The Apache claim is
  wrong for the data; CC BY 4.0 (attribution) governs. Upstream v1.0.8 covers CVEs up to
  2024-07-23.
- Corrections: handoff's 12,987 is right; add the licence mismatch and that this is a third-hand
  copy. Use the upstream Zenodo release if ever needed.
- Value / phase: low; Phase 2 "fix commit" link-outs could use upstream CVEfixes, but OSV and GHSA
  already carry fix references.
- ROADMAP: not mentioned.

### AYI-NEDJIMI/supply-chain-attacks-en
- What it is: small educational set by a consultancy (AYI-NEDJIMI Consultants): 13 columns (id,
  category, name, description, real_world_example, attack_steps, impact, detection, prevention,
  mitre_attack_id, severity, source_url, data_type). Card breakdown about 30 vectors, 20
  incidents, 20 defences, 80 Q&A (about 150 rows) while metadata says 1K-10K: conflicting.
  Incidents 2017-2024 (SolarWinds, Log4Shell, XZ Utils). Authoring method (LLM or human)
  undisclosed. Heavy promotional links; citation calls it "Bilingual FR/EN" though this is the
  English card.
- Licence: Apache 2.0.
- Value / phase: negligible. At most a seed glossary for the Phase 2 supply chain tab; the
  ROADMAP's own sources (OSV, OpenSSF Malicious Packages, Datadog dataset, Backstabber's Knife
  Collection) are primary.
- ROADMAP: not mentioned.

### cybersectony/PhishingEmailDetectionv2.0
- What it is: 200,000 rows (train 120,000 / validation 20,000 / test 60,000), 22,644 emails and
  177,356 URLs, labels 0 legitimate_email, 1 phishing_email, 2 legitimate_url, 3 phishing_url.
  Created 2024-10-24, last modified 2024-10-28. Not gated.
- Licence: none (no licence in card or API metadata). Sources, dates, author and labelling method
  not stated. Schema inconsistent (label vs labels).
- Corrections: handoff omits that there is no licence and no provenance; that is disqualifying for
  reuse.
- Value / phase: none; Phase 3 DRP uses PhreshPhish (CC BY 4.0) instead.
- ROADMAP: not mentioned (PhreshPhish is, line 926).

### tandevllc/cybersecurity-atom-rss-feeds-2025
- What it is: 5,686 deduplicated entries from curated security RSS/Atom feeds in 12 categories
  (bigtech, cloudsec, dfir-malware, email-identity, general, gov-cert, ics-ot-iot,
  oss-foundations, platforms-oss-sec, redteam-appsec, vendor-ti, vuln-exploit); about 2.71M
  tokens, 15.4 MB. Columns: category, title, link, summary, content_html, published, updated,
  fetched_at, src_type, src_feed, src_title, hash, plus optional article_* fields (partial full
  text). Feed list not published. Created 2025-11-02, last modified 2025-11-05.
- Access: gated "manual" (must log in and agree to share Hugging Face profile; raw README returned
  401). Licence: "TanDev Proprietary License: All Rights Reserved"; each article stays under its
  publisher's terms; limited to research, education, defensive security; no commercial grant.
  Maintainer Smridh Gupta (Tan Dev LLC).
- Corrections: handoff says licence "other" and gated: correct; add "All Rights Reserved" and
  that the feed list is not disclosed (so it is not even useful as a feed-discovery list).
- Value / phase: none. Phase 4 builds its own feed list.
- ROADMAP: not mentioned. Access would need signing in and accepting terms, which this pass did not
  do.

### NewsDataHub/cybersecurity-news-dataset-english-3000
- What it is: 3,000 English news metadata rows, 2025-08-10 to 2026-02-11, deduplicated by title.
  Columns: id, title, source_title, article_link, description, pub_date, plus six keyword flags
  (mentions_ransomware, _ddos, _data_breach, _vulnerability, _hacking, _cyber_attack) from
  deterministic keyword matching on title and description. No full text. Comes from the
  NewsDataHub API (promotional UTM link); fixed snapshot.
- Licence: CC BY 4.0 (on the compilation; article text itself is not included).
- Value / phase: tiny test fixture for Phase 4 topic tagging; not a source.
- ROADMAP: not mentioned.

### CyberMax-tools/kevscope-cve-kev-epss-daily (whole card read: README, LATEST.md, meta.json, API)
- What it is: a free daily-overwritten snapshot joining CISA KEV, FIRST EPSS and NVD by CVE ID,
  built "with a plain Python script and direct downloads". Configs: kev (one row per KEV entry with
  EPSS and NVD CVSS), recent (CVEs published in the last 30 days, with EPSS and KEV flag; rejected
  CVEs excluded), epss (every CVE with an EPSS score and a KEV flag). Files: Parquet plus CSV for
  kev and recent, latest.json, meta.json, a notebook. Created 2026-09-24; last modified
  2026-11-07.
- Current build (meta.json): built 2026-11-07T08:30:57Z; KEV catalogue 2026.11.06, 1,769
  entries; EPSS model v2026.06.15, score date 2026-11-06, 400,985 scores; recent window
  2026-10-08 to 2026-11-07, 17,127 CVEs. Sources are the same URLs the toolkit uses:
  cisa.gov known_exploited_vulnerabilities.json, epss.empiricalsecurity.com
  epss_scores-current.csv.gz, NVD API 2.0.
- Update cadence: the card and LATEST.md say "Updated daily" / "refreshed every day". The Hub
  shows last modification 2026-11-07, four days before this check, so in practice it lags.
  The README's "Build snapshot" figures (1,721 KEV, catalogue 2026.09.23) are from the first
  build and were never refreshed; trust meta.json, not the prose.
- days_published_to_kev: the card defines it as "days between NVD publication and the KEV
  listing", i.e. date_added minus nvd_published. Observed range -290 to 7,190. A keyword search of
  the full README for "negative" and "future" found no sentence that discusses them, but the
  definition explains the sign: the value is negative whenever CISA listed the CVE in KEV before
  NVD published the record. That happens with zero-days, where CISA adds the CVE on disclosure
  while the record is still reserved or NVD has not yet published it. The -290 extreme is a CVE
  whose NVD record appeared about 290 days after its KEV listing; which CVE could not be found
  (the dataset-viewer filter API timed out, then returned HTTP 500). The 7,190 top end is a
  CVE whose NVD record is about 20 years older than its KEV listing (nvd_published starts at
  2002-06-25).
- Dates that look like the future: due_date is defined on the card as the "US federal
  remediation deadline", which CISA sets usually 2-3 weeks after date_added, so recent entries
  have due dates after the build date (maximum 2026-11-20 against a 2026-11-07 build). That is by
  design. Other date maxima are 2026-11-06 for date_added and nvd_published, which are not in the
  future as of 2026-11-11. A pass that assumed an earlier "today" would also misread late-2026
  dates as future.
- Licence: front matter "other", named "open-mixed-cc0-public-domain-epss-attribution":
  KEV CC0 1.0; NVD US-government public domain; CVE descriptions under the CVE Program Terms of
  Use (MITRE copyright, redistribution allowed); EPSS free use with attribution to FIRST; the
  compilation is "as is" from CyberMax, which says it is not affiliated with CISA, NIST, MITRE or
  FIRST. Fine for local use.
- Caveats: heavy commercial content on the card (paid API at $5 per 2,000 calls, a $49/year
  commercial licence, weekly briefs, a separate paid "Deltawren" feed); the free file keeps no
  history (each day overwrites the last; history and diffs are in the paid feed).
- Useful as a cross-check of our own KEV/EPSS joins? Yes, narrowly, as an independent test
  fixture: for one day, compare our KEV count and membership against kev (1,769 at catalogue
  2026.11.06), EPSS score and percentile per CVE against epss (same score_date), CVSS
  version/score/vector selection against kev and recent (it prefers NVD's Primary score over the
  CNA's, which tells us whether our selection rule differs), and the known_ransomware_use flag.
  Differences would point at join or selection bugs, not at fresher data. Not a source: it is
  built from the same three upstream feeds, trails them by days, and its README statistics are
  stale. A one-off offline comparison test is enough; no runtime dependency. Note the toolkit
  does not compute a "days published to KEV" measure today; if it ever does, define it from the
  CVE List datePublished as well as NVD's published date and expect negatives.
- ROADMAP: not mentioned. Phase 2 already ingests KEV, EPSS, NVD and the CVE List directly.

### chairulridjal/arcspan-cyber-ner (card read in full)
- What it is: CTI NER set with 5 entity types in the R9 release: Indicator 16,265 spans (25.6%),
  Malware 15,585, Organization 13,546, System 11,947, Vulnerability 6,114. Splits (records /
  spans): R9 Train 24,518 / 63,457; R9 Valid 2,821 / 5,681; R8 Train 26,079 / 76,824; R8 Valid
  2,821 / 5,681; APTNER Test 172; CyNER Test 748; SecureBERT2 Test 200; Enriched Test 3,853.
  Total 61,212 records (matches ROADMAP line 2084). The handoff's "approximately 50,600 rows" is
  R9 Train + R8 Train (50,597): two versions of the training set, which overlap, so unique
  records are fewer than either total suggests.
- Labelling (by source names; the card never claims human annotation): about 26% LLM-annotated
  (6,446 records), about 6% synthetic (1,384), about 3% defanged-IOC augmentation (652), about
  65% from existing datasets (16,036).
- Licence: card front matter Apache-2.0, with the note "individual source datasets may carry
  their own licenses"; "see the original dataset repositories". The card does NOT list a licence
  for any of the 22 sources and gives no URLs. Upstream licences researched today:

  | # | Source (R9 records) | Upstream | Licence found |
  |---|---|---|---|
  | 1 | cyner2_train (4,563) | Probably CyNER 2.0 augmented (PranavaKailash, HF) | MIT per a mirrored card (official card's licence field looked blank; unconfirmed) |
  | 2 | cyberner_stix_train (3,723) | CyberNER STIX corpus (yasirech-chammakhy/CyberNER; harmonises CyNER, DNRTI, APTNER, Attacker) | No licence file in the repo; inherits the sources below |
  | 3 | dnrti_train (2,834) | DNRTI (Wang et al. 2020; SCreaMxp GitHub) | No licence file; README states no terms |
  | 4 | aptner_train (2,584) | APTNER (Wang et al., CSCWD 2022; wangxuren/APTNER) | No licence file; README asks only for citation |
  | 5 | apt_reports (2,263, LLM-annotated) | Vendor APT reports (text) | Publisher copyright; no licence |
  | 6 | nvd_v2 (1,995, LLM-annotated) | NVD CVE descriptions | US government public data (CVE text under CVE Program ToU) |
  | 7 | mitre_attack_v2 (1,485, LLM-annotated) | MITRE ATT&CK | ATT&CK licence: royalty-free, keep MITRE copyright notice |
  | 8 | synthetic_v2 (1,292) | Generated by the dataset author | Covered by the card's Apache-2.0 |
  | 9 | cyberner (1,204) | CyberNER (as row 2) or the older CyberNER corpus | No licence found |
  | 10 | cyner_train (717) | CyNER (aiforsec/CyNER, IBM Research) | MIT (repository licence) |
  | 11 | defanged_augment (652) | Author's augmentation of the above | Inherits its source rows |
  | 12 | exploitdb (500, LLM-annotated) | Exploit-DB | GPL-2.0 (exploitdb repository LICENSE.md) |
  | 13 | nvd_cve (338) | NVD | Public data |
  | 14 | synthetic_ioc (92) | Generated | Apache-2.0 (card) |
  | 15 | vendor_blogs (61, LLM-annotated) | Vendor blog text | Publisher copyright |
  | 16 | security_news (45, LLM-annotated) | News articles | Publisher copyright |
  | 17 | cisa_advisories (39, LLM-annotated) | CISA advisories | US government work, public domain |
  | 18 | mitre_attack (39) | MITRE ATT&CK | ATT&CK licence |
  | 19 | alienvault_otx (37, LLM-annotated) | OTX pulse text | OTX terms (user-contributed; no open licence) |
  | 20 | securebert2_train (22) | Cisco SecureBERT 2.0 NER data (cisco-ai-defense/securebert2) | Repo and model Apache-2.0; NER data files not separately licensed |
  | 21 | malware_reports (21, LLM-annotated) | Malware report text | Publisher copyright |
  | 22 | dnrti_valid (12) | DNRTI | No licence |

  The card's own "Source datasets" line names CyNER, APTNER, DNRTI, CyberNER, MITRE ATT&CK, NVD and
  ExploitDB, with no links. Test splits APTNER Test, CyNER Test, SecureBERT2 Test carry the same
  upstream terms as rows 4, 10 and 20.
- Can the toolkit use it as a local evaluation set (not redistributed)? Yes, with care. Of the
  24,518 R9 Train records: about 27% (6,519) rest on a clear open licence or are author-generated
  (cyner_train, nvd*, mitre_attack*, cisa_advisories, synthetic*, securebert2, exploitdb); a
  further 19% (cyner2_train, 4,563) is probably MIT but unconfirmed; about 42% (10,357) comes from
  APTNER, DNRTI and CyberNER, which have no licence at all; about 10% (2,427) is copyrighted
  report text (apt_reports, vendor_blogs, security_news, malware_reports, OTX); defanged_augment
  (652) inherits whatever its source rows were. Local,
  private evaluation without redistribution is the low-risk use, which matches the ROADMAP's
  Phase 11 plan. Do not commit any of it to the repo, do not publish derived splits, and record in
  docs/journal.md that the Apache-2.0 tag does not cover upstream rows. For a clean subset, filter
  by source to cyner_train, mitre_attack*, nvd*, cisa_advisories, synthetic*, securebert2.
  Scores on the LLM-annotated rows measure agreement with another model, not ground truth.
- ROADMAP: already planned, line 2083-2086 (Phase 11 evaluation set; "partly LLM-labelled and
  synthetic"). Add the per-source licence finding.

---------------------------------------------------------------------------------------------------

## 6. One-liners

- OSV.dev: live, actively maintained (google/osv.dev pushed 2026-11-11); code Apache-2.0; data
  licence is per source (GHSA, PyPI, Go, OSS-Fuzz CC BY 4.0; RustSec, Haskell CC0; Ubuntu and Alpine
  CC BY-SA 4.0; OpenSSF Malicious Packages Apache-2.0; Chainguard/Wolfi CC BY-NC-ND 4.0;
  Debian and NVD-converted no licence stated). ROADMAP: planned for Phase 2, supply chain tab
  (lines 548-640).
- mitre-attack/attack-stix-data: live; latest release v20.1 (ATT&CK 20.1) on 2026-11-05; MITRE
  ATT&CK licence: royalty-free for research, development and commercial use, keep MITRE's copyright
  notice and licence text. ROADMAP: planned for Phase 2 extraction and Phase 9 (lines 163, 1773,
  1989); already used as a local dataset (ATT&CK v19/v20, line 217).

---------------------------------------------------------------------------------------------------

## 7. Corrections to the handoff, collected

1. SSLBL: the botnet C2 IP lists (normal and aggressive) were deprecated on 2025-01-03 and are
   empty; the JA3 list has been frozen since 2021-08-03 (97 entries). Only the certificate SHA-1
   list and its Suricata rules are live.
2. Feodo Tracker: no new C2 since 2026-03-04; files frozen with 1 (recommended) and 5 (30-day)
   stale entries; abuse.ch's banner says "empty". The Browse page is history, not current C2s.
   The handoff's "useful for dedicated botnet C2 tracking" no longer holds.
3. MISP feed catalogue: unvalidated metadata (includes the dead SSLBL IP list and frozen Feodo
   list), no per-feed licence data.
4. MalwareConfig.com: re-registered domain run by an unnamed party (explicitly not Kevin Breen),
   editorial only, no config data.
5. VMware Emotet: "2,181" not confirmed; sources say "over 2,000" or give no count.
6. ArcSpan: "about 50,600 rows" is two overlapping training versions; total across splits is
   61,212; the Apache-2.0 tag does not cover upstream rows; no per-source licences on the card.
7. Shrutz72/cvefixes: Apache-2.0 claim conflicts with upstream CVEfixes data licence CC BY 4.0.
8. PhishingEmailDetectionv2.0: no licence, no provenance.
9. tandevllc RSS: "All Rights Reserved", gated, feed list not disclosed.
10. KEVScope: README statistics are from the first (September) build; meta.json is current.
    Negative days_published_to_kev and late-2026 due dates follow from the card's own
    definitions and are not data errors.
11. SecKnowledge-Eval: CC BY-NC 4.0 (the handoff gives no licence).
12. Malpedia: CC BY-NC-SA 3.0, vetted invite-only accounts.
13. abuse.ch ToU s. 7.3 forbids training AI models on abuse.ch data without Spamhaus consent
    (relevant to Phase 11).

---------------------------------------------------------------------------------------------------

## 8. Every handoff link and its status

| # | Link | Status in this pass |
|---|---|---|
| 1 | https://huggingface.co/datasets/fox-srt/cobaltstrike-beacon-corpus | Out of scope here (covered elsewhere); ROADMAP line 1513-1531 already records it |
| 2 | https://www.fox-it.com/be/research/mining-data-from-cobalt-strike-beacons/ | Out of scope here (covered elsewhere) |
| 3 | https://mwdb.cert.pl/ | Out of scope here (covered elsewhere) |
| 4 | https://github.com/kevoreilly/CAPEv2 | Checked: live, GPL-3.0 core, active |
| 5 | https://github.com/CAPESandbox/CAPE-parsers | Out of scope here (covered elsewhere) |
| 6 | https://github.com/dod-cyber-crime-center/DC3-MWCP | Out of scope here (covered elsewhere) |
| 7 | https://github.com/JR0driguezB/malware_configs | Checked: exists, last push 2018-10-31, no licence |
| 8 | https://malpedia.caad.fkie.fraunhofer.de/ | Checked: live, CC BY-NC-SA 3.0, vetted accounts |
| 9 | https://github.com/elastic/labs-releases | Out of scope here (covered elsewhere) |
| 10 | https://malwareconfig.com/ | Checked: up, editorial archive by unnamed party, no data |
| 11 | https://www.vmray.com/climbing-the-pyramid-of-lumma-pain/ | Checked: article, no dataset |
| 12 | https://www.proofpoint.com/us/blog/threat-insight/stealc-you-later-proofpoint-and-ibm-x-force-support-operation-endgame | Checked: article, no dataset |
| 13 | (VMware Emotet research, no link in handoff) | Checked via search: 2022 VMware TAU posts; 2,181 not confirmed; VB2022 page 403 |
| 14 | https://c2-hunter.newtonpaul.com/ | Out of scope here (covered elsewhere) |
| 15 | https://github.com/newtonpaul-hunting/c2-iocs | Out of scope here (covered elsewhere) |
| 16 | https://github.com/montysecurity/C2-Tracker | Out of scope here (covered elsewhere) |
| 17 | https://github.com/montysecurity/C2-Tracker/blob/main/tracker.py | Out of scope here (covered elsewhere) |
| 18 | https://github.com/cybersheepdog/Adversary-Hunter | Out of scope here (covered elsewhere) |
| 19 | https://github.com/Cobalt-Strike/Malleable-C2-Profiles | Out of scope here (covered elsewhere) |
| 20 | https://github.com/BC-SECURITY/Malleable-C2-Profiles | Out of scope here (covered elsewhere) |
| 21 | https://github.com/HavocFramework/Havoc | Out of scope here (covered elsewhere) |
| 22 | https://github.com/BishopFox/sliver | Out of scope here (covered elsewhere) |
| 23 | https://github.com/MythicC2Profiles | Out of scope here (covered elsewhere) |
| 24 | https://threatfox.abuse.ch/ | Out of scope here (covered elsewhere); note: IOC pages hit a bot check in this pass |
| 25 | https://bazaar.abuse.ch/ | Checked (API and export pages) |
| 26 | https://feodotracker.abuse.ch/ | Checked (browse, blocklist, FAQ, about, host page, all CSV/JSON/TXT lists) |
| 27 | https://urlhaus.abuse.ch/ | Checked (API page) |
| 28 | https://sslbl.abuse.ch/ | Checked (front page, blacklist page, three CSVs) |
| 29 | https://www.misp-project.org/feeds/ | Checked: 108 feeds, 52 providers, no licences |
| 30 | https://www.stratosphereips.org/datasets-ctu13 | Checked (second attempt after rate limit) |
| 31 | https://www.stratosphereips.org/datasets/ | Not loaded (rate-limited on first attempt; not retried); IoT-23's own page /datasets-iot23 read instead |
| 32 | https://www.stratosphereips.org/datasets-malware | Checked (second attempt after rate limit) |
| 33 | https://www.malware-traffic-analysis.net/ | Checked (about page on second attempt, home, 2026 index) |
| 34 | https://huggingface.co/datasets/chairulridjal/arcspan-cyber-ner | Checked: full card; upstream licences researched |
| 35 | https://huggingface.co/datasets/reloading0101/threat-intelligence-dataset | Out of scope here (covered elsewhere) |
| 36 | https://huggingface.co/datasets/CZLi/apt-reports | Out of scope here (covered elsewhere) |
| 37 | https://huggingface.co/datasets/cyber-pal-security/SecKnowledge-Eval | Checked: CC BY-NC 4.0, 4,142 items |
| 38 | https://huggingface.co/datasets/joyce8/EMBER2024 | Out of scope here (covered elsewhere) |
| 39 | https://github.com/FutureComputing4AI/EMBER2024 | Not checked: upstream of #38, treated as part of the EMBER2024 item covered elsewhere |
| 40 | https://huggingface.co/datasets/joyce8/EMBER2024-capa | Out of scope here (covered elsewhere) |
| 41 | https://huggingface.co/datasets/it4lia/BODMAS_cleaned | Checked |
| 42 | https://huggingface.co/datasets/IQSeC-Lab/LAMDA | Checked |
| 43 | https://huggingface.co/datasets/mvd001/cyberset | Checked via API URL, raw README and LICENSE.md |
| 44 | https://huggingface.co/datasets/CyberMax-tools/kevscope-cve-kev-epss-daily | Checked: page, README, LATEST.md, meta.json, API |
| 45 | https://huggingface.co/datasets/Shrutz72/cvefixes | Checked; upstream CVEfixes licence checked |
| 46 | https://huggingface.co/datasets/AYI-NEDJIMI/supply-chain-attacks-en | Checked |
| 47 | https://huggingface.co/datasets/phreshphish/phreshphish | Out of scope here (covered elsewhere) |
| 48 | https://huggingface.co/datasets/cybersectony/PhishingEmailDetectionv2.0 | Checked: no licence |
| 49 | https://huggingface.co/datasets/tandevllc/cybersecurity-atom-rss-feeds-2025 | Checked (public card and API; raw README 401 because gated) |
| 50 | https://huggingface.co/datasets/NewsDataHub/cybersecurity-news-dataset-english-3000 | Checked |
| 51 | https://huggingface.co/datasets/sskapci/domain-intelligence-dataset | Out of scope here (covered elsewhere) |
| 52 | https://github.com/mitre-attack/attack-stix-data | Checked: v20.1, ATT&CK licence |
| 53 | https://osv.dev/ | Checked (repo status and data-sources licence page) |
| 54 | https://sonardata.rapid7.com/ | Out of scope here (covered elsewhere) |
| 55 | https://docs.greynoise.io/docs/swarm-overview | Out of scope here (covered elsewhere) |

---------------------------------------------------------------------------------------------------

## 9. Could not check, and why

- ThreatFox entries for the Feodo IPs: ThreatFox IOC and browse pages returned a browser
  verification ("confirm that you are not a robot") and "please enable cookies"; not bypassed.
  Two indexed ThreatFox IOC IDs for 50.16.16.211 were seen only in search results. Verify with the
  toolkit's keyed ThreatFox API.
- Whether Feodo Tracker entries are mirrored into ThreatFox automatically: not stated on any
  Feodo or abuse.ch page read.
- stratosphereips.org/datasets/ (index page): WebFetch safety check was rate-limited; the other
  two Stratosphere pages loaded on a single retry; the index was not retried.
- CTU-13 per-scenario malware names: in an image table, not readable as text.
- malware-traffic-analysis.net zip password scheme: shown as an image.
- Virus Bulletin VB2022 Emotet abstract: HTTP 403 twice. VMware's full Emotet report is behind a
  registration form (not filled). So the 2,181 figure is unconfirmed.
- KEVScope row with days_published_to_kev = -290: Hugging Face dataset-viewer filter API timed
  out, then returned HTTP 500; kev.csv not paged through.
- GitHub API returned 403 (unauthenticated rate limit) partway through; licence checks for APTNER,
  DNRTI and CyberNER were done from the github.com repository pages instead.
- CyNER 2.0 augmented dataset licence: only a mirrored card says MIT; official card not fetched.
- tandevllc RSS: gated; the full README and data need a signed-in account accepting terms (not
  done, per the no-sign-up rule).
- Malpedia YARA and reference counts, and its REST API terms page: not shown on the pages read.
- BODMAS upstream date range and CTU-13 family names were given from memory and marked as such.
