"""Passive Phase 2 publisher acceptance. Network only with explicit --fetch.

Original publisher content stays in git-ignored data/, never in fixtures.
This tool does not execute page code, render a browser or fetch page assets.
Use the existing trusted interpreter; no additional dependencies.
"""

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
REPORTS = [
    ("eset", "https://www.welivesecurity.com/en/eset-research/slippynunchucks-hijacks-sogou-input-methods-brand-promotion-mechanism-to-distribute-malware/"),
    ("talos", "https://blog.talosintelligence.com/ir-trends-q3-2026/"),
    ("intel471", "https://www.intel471.com/blog/openclaw-a-viral-ai-assistant-and-a-magnet-for-infostealer-malware-and-clickfix-trickery"),
    ("fortinet", "https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant"),
    ("groupib-kgb", "https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/"),
    ("groupib-stray", "https://www.group-ib.com/blog/stray-cat-network-edge/"),
    ("microsoft", "https://www.microsoft.com/en-us/security/blog/2026/11/03/fake-download-campaign-uses-trojanized-installers-deliver-monetization-payloads/"),
    ("recordedfuture", "https://www.recordedfuture.com/research/bluedelta-targets-with-hookedge"),
    ("recordedfuture-pdf", "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-ru-2026-0827.pdf"),
    ("dfir", "https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/"),
    ("picus", "https://www.picussecurity.com/resource/blog/famous-chollima-apt-group-major-activities-ttps-and-simulation"),
    ("zscaler", "https://www.zscaler.com/blogs/security-research/inside-global-ai-assisted-hacking-campaign"),
    ("genians", "https://www.genians.co.kr/blog/threat_intelligence/ai-agent-opencode"),
]
# The PDF advertises 5,895,616 bytes. Its first fetch stopped at 5 MiB;
# a 6 MiB cap admits that measured source without allowing large archives.
MAX_FILE = 6 * 1024 * 1024
MAX_TOTAL = 30 * 1024 * 1024


def fetch_reports(directory: Path, only: str | None = None) -> None:
    import httpx

    incoming = directory / "incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    manifest_path = directory / "downloads.json"
    records = json.loads(manifest_path.read_text(encoding="utf-8")) if only and manifest_path.exists() else []
    transferred = 0
    # Fixed publisher hosts only. Redirects cannot select another destination.
    allowed = {urlsplit(url).hostname for _, url in REPORTS}
    with httpx.Client(timeout=20, trust_env=False, follow_redirects=False) as client:
        for name, source in REPORTS:
            if only and name != only:
                continue
            record = {"name": name, "url": source, "retrieved": datetime.now(timezone.utc).isoformat()}
            try:
                target = source
                for _ in range(6):
                    with client.stream("GET", target) as response:
                        if response.is_redirect:
                            target = str(response.url.join(response.headers.get("location", "")))
                            parts = urlsplit(target)
                            if (parts.scheme != "https" or parts.hostname not in allowed
                                    or parts.username or parts.password or parts.port not in (None, 443)):
                                raise ValueError("redirect outside reviewed publisher hosts")
                            continue
                        record.update(status=response.status_code, final_url=str(response.url))
                        if response.status_code != 200:
                            break
                        chunks, size = [], 0
                        for chunk in response.iter_bytes():
                            size += len(chunk)
                            transferred += len(chunk)
                            if size > MAX_FILE or transferred > MAX_TOTAL:
                                raise ValueError("download budget exceeded")
                            chunks.append(chunk)
                        raw = b"".join(chunks)
                        suffix = ".pdf" if raw.startswith(b"%PDF-") else ".html"
                        filename = name + suffix
                        (incoming / filename).write_bytes(raw)
                        record.update(file=filename, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                                      content_type=response.headers.get("content-type", ""))
                        break
                else:
                    raise ValueError("too many redirects")
            except (httpx.HTTPError, ValueError) as error:
                # Error strings can include response data. Keep only known text.
                record["error"] = str(error) if isinstance(error, ValueError) else type(error).__name__
            records = [previous for previous in records if previous["name"] != name]
            records.append(record)
            print(name, record.get("status", "error"), record.get("bytes", 0), record.get("error", ""), flush=True)
            # Keep the manifest even if a later source fails or the run stops.
            manifest_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
            if transferred > MAX_TOTAL:
                break


def inspect_reports(directory: Path) -> None:
    from app.modules.extract import attack, html, pdf

    catalog_path = ROOT / "data" / "attack-index.json"
    if not catalog_path.is_file():
        raise ValueError("load the official ATT&CK catalog through the app first")
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    manifest = json.loads((directory / "downloads.json").read_text(encoding="utf-8"))
    summaries = []
    incoming = (directory / "incoming").resolve()
    for record in manifest:
        summary = {key: record[key] for key in ("name", "url", "status", "error", "sha256") if key in record}
        if "file" not in record:
            summaries.append(summary)
            continue
        path = (incoming / record["file"]).resolve()
        if not path.is_relative_to(incoming) or path.stat().st_size > MAX_FILE:
            raise ValueError("input path or size outside acceptance scope")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise ValueError("capture changed since download")
        if raw.startswith(b"%PDF-"):
            document, error = pdf.pdf_document(raw)
        else:
            document, error = html.parse_document(raw.decode("utf-8", errors="replace")), None
        if error:
            summary["parse_error"] = error
        else:
            findings = attack.extract(document, catalog)
            evidence = [item for finding in findings for item in finding["evidence"]]
            summary.update(chars=len(document.text), structures=len(document.tables),
                           layout_limited=document.layout_limited, ids=len(findings),
                           with_procedures=sum(any(item["procedure"] for item in finding["evidence"]) for finding in findings),
                           kinds=dict(Counter(item["kind"] for item in evidence)), findings=findings)
            # Local inspection aid. No original report text is committed.
            (directory / (record["name"] + ".text.txt")).write_text(document.text, encoding="utf-8")
            print(record["name"], "ids", len(findings), "procedures", summary["with_procedures"], summary["kinds"], flush=True)
        summaries.append(summary)
    (directory / "analysis.json").write_text(json.dumps({"catalog_version": catalog.get("version"), "reports": summaries}, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="capture directory inside project data/")
    parser.add_argument("--fetch", action="store_true", help="download the fixed survey sources; does not parse them")
    parser.add_argument("--only", choices=[name for name, _ in REPORTS], help="fetch only this source and retain other capture records")
    args = parser.parse_args()
    directory = args.directory.resolve()
    if not directory.is_relative_to((ROOT / "data").resolve()):
        parser.error("captures must stay inside git-ignored project data/")
    if args.fetch:
        fetch_reports(directory, args.only)
    else:
        if args.only:
            parser.error("--only requires --fetch")
        inspect_reports(directory)


if __name__ == "__main__":
    main()
