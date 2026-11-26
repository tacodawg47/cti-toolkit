"""Synthetic fixtures for read-only compatibility with retired report intake."""

from app.core.db import connect
from app.modules.vulnerability_intelligence import review, store
from app.modules.vulnerability_intelligence.reports import for_cve, get


def save(row):
    row = {**row, "source_ref": row.get("source_ref", ""), "exploited_on": row.get("exploited_on") or None,
           "created_at": store._now()}
    with connect() as conn, conn:
        result = conn.execute("""INSERT OR IGNORE INTO exploitation_reports
            (title,product,source_name,source_url,source_ref,reported_on,exploited_on,evidence,
             exploitation,patch_status,advisory_status,cve_status,created_at)
            VALUES (:title,:product,:source_name,:source_url,:source_ref,:reported_on,:exploited_on,:evidence,
                    :exploitation,:patch_status,:advisory_status,:cve_status,:created_at)""", row)
        ident = conn.execute("SELECT id FROM exploitation_reports WHERE source_url=? AND source_ref=?",
                             (row["source_url"], row["source_ref"])).fetchone()[0]
        return ident, bool(result.rowcount)


def link(ident, cve_id):
    with connect() as conn, conn:
        conn.execute("UPDATE exploitation_reports SET linked_cve=?, linked_at=? WHERE id=?",
                     (cve_id, store._now() if cve_id else None, ident))
    review.capture()
