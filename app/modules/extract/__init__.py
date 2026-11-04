"""
IOC extraction (Phase 2).

Pull indicators out of free text, a fetched web page, or an uploaded PDF:
IPs, domains, URLs, file hashes, email addresses and CVE IDs, whether written
plainly or defanged. Pure text processing: no API keys, no cache, no
database. The results page hands each indicator to enrichment (or, for a
CVE, to vulnerability intelligence) with one click.

Modules:
  extractor  the patterns, the whole-document refang, and `extract()`
  html       HTML -> plain text with the standard-library parser
  fetch      download a report URL (HTTPS, public hosts, size-capped)
  pdf        PDF -> plain text via pypdf (optional dependency)
"""
