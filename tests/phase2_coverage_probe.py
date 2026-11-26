"""Print Phase 2 cross-feature audit observations using a temporary database.

Run: python -B -m tests.phase2_coverage_probe
This is an audit probe, not a regression test that enshrines current bugs.
Importing tests enables the suite's network refusal transport.
"""

import asyncio
import json

from app.core.db import connect
from app.modules.extract import attack
from app.modules.extract.html import parse_document
from app.modules.vulnerability_intelligence import detail, review, routes, service, store, views
from tests import legacy_reports as reports
from app.modules.vulnerability_intelligence.feeds import euvd, ot
from tests.test_vulnintel import TempDbMixin, ot_document


def row_for(cve):
    row = views._rows("SELECT ? AS cve_id", (cve,))[0]
    routes._add_actions([row])
    return row


def labels(row):
    return [action["label"] for action in row["actions"]]


async def observations():
    findings = {}
    review.capture()
    cve = "CVE-2026-20001"
    path = "2026/icsa-26-316-01.json"
    document = ot.parse_advisory(json.dumps(ot_document(path, [cve])).encode(), path)
    with connect() as conn, conn:
        ot._save(conn, document, "2026-11-12T07:00:00Z")
    review.capture()
    row = row_for(cve)
    rep = await service.report(cve, local_first=True)
    scope = [{"id": 1, "vendor": "Example Industrial, Inc.", "product": "Controller"}]
    findings["ot_evidence"] = {
        "shared_table_actions": labels(row), "ot_detail_actions": labels(rep),
        "shared_table_cvss": row["cvss"], "detail_cvss": (rep["cvss_fallback"] or {}).get("cvss_score"),
        "watchlist_match": cve in views.watchlist_hits(scope),
        "review_events": [item["kind"] for item in review.page()["rows"] if item["cve_id"] == cve],
    }

    cve = "CVE-2026-20002"
    store.save_cve({"cve_id": cve, "cvss_score": 5.0, "published": "2026-11-14T00:00:00Z"})
    ident, _ = reports.save({
        "title": "Example Gateway Exploitation", "product": "Example Gateway", "source_name": "Example Vendor",
        "source_url": "https://example.test/report", "source_ref": "AUDIT-1",
        "reported_on": "2026-11-12", "exploited_on": "2026-11-11", "evidence": "Synthetic dated observation.",
        "exploitation": "reported", "patch_status": "absent", "advisory_status": "absent", "cve_status": "absent",
    })
    reports.link(ident, cve)
    review.capture()
    rep = await service.report(cve, local_first=True)
    linked = reports.for_cve(cve)
    findings["linked_report"] = {
        "detail_status": detail.exploitation_status(rep, linked), "priority": rep["priority"].level,
        "detail_actions": labels(rep), "known_exploited_member": cve in views.exploited_ids(),
        "confirmed_report_label": linked[0]["assessment"],
        "zero_day_view_member": any(row["cve_id"] == cve for row in views._zero_days()),
        "review_events": [item["kind"] for item in review.page()["rows"] if item["cve_id"] == cve],
    }

    cve = "CVE-2026-20003"
    with connect() as conn, conn:
        conn.execute("INSERT INTO sightings_recent VALUES (?, 'exploited', '2026-11-17', 1)", (cve,))
        conn.execute("""INSERT INTO exploits (source, ref, cve_id, first_seen)
                        VALUES ('exploitdb', 'AUDIT-2', ?, '2026-11-17')""", (cve,))
    findings["sighting_only"] = {
        "table_actions": labels(row_for(cve)), "known_exploited_member": cve in views.exploited_ids(),
        "listed_without_reported_exploitation": any(row["cve_id"] == cve for row in views._code_not_exploited()),
    }

    cve = "CVE-2026-20004"
    store.save_cve({"cve_id": cve, "published": "2026-11-14T00:00:00Z"})
    parsed = euvd.parse_items([{"id": "EUVD-AUDIT", "aliases": cve, "datePublished": "Nov 13, 2026, 12:00:00 AM"}])
    store.upsert_kev(parsed, "euvd")
    rep = await service.report(cve, local_first=True)
    findings["euvd_date_fallback"] = {
        "exploited_since_supplied": False, "stored_date": parsed[0]["date_added"],
        "detail_first_exploitation": detail.first_exploitation_report(rep, []),
        "zero_day_view_member": any(row["cve_id"] == cve for row in views._zero_days()),
    }

    catalog = {"objects": {
        "T1059.001": {"name": "PowerShell", "tactics": ["execution"]},
        "T1059.003": {"name": "Windows Command Shell", "tactics": ["execution"]},
    }, "tactics": {"TA0002": {"name": "Execution", "slug": "execution"}}}
    samples = {
        "html_heading_above_table": '<h2>Execution</h2><table><tr><th>ID</th><th>Use</th></tr><tr><td>T1059.001</td><td>Ran encoded commands.</td></tr><tr><td>T1059.003</td><td>Launched cmd.exe.</td></tr></table>',
        "html_list": '<h2>Execution</h2><ul><li>T1059.001 PowerShell - Ran encoded commands.</li><li>T1059.003 Windows Command Shell - Launched cmd.exe.</li></ul>',
        "prose": '<p>The actor ran PowerShell using T1059.001.</p>',
    }
    findings["attack_procedures"] = {}
    for name, html in samples.items():
        rows = attack.extract(parse_document(html), catalog)
        findings["attack_procedures"][name] = [
            {"id": row["id"], "procedures": [e["procedure"] for e in row["evidence"]],
             "tactics": [e["tactic"] for e in row["evidence"]]} for row in rows]
    return findings


def main():
    fixture = TempDbMixin()
    fixture.setUp()
    try:
        print(json.dumps(asyncio.run(observations()), indent=2))
    finally:
        fixture.tearDown()


if __name__ == "__main__":
    main()
