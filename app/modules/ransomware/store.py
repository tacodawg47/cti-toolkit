"""Permanent claim/capture metadata and a bounded normalized recovery queue."""

import json

from ...core import alerts, evidence
from ...core.evidence_models import Citation, Observation
from .models import Claim


def stage(scope, document_id, claims):
    payload = json.dumps([c.model_dump() for c in claims], ensure_ascii=True, separators=(",", ":"))
    if not 1 <= len(claims) <= 100 or len(payload.encode()) > 1024**2:
        raise ValueError("Normalized snapshot exceeds bounds")
    scope.check_sync()
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        scope.check_sync()  # Recheck after acquiring the atomic write boundary.
        evidence.require_collection(scope.feed.source, "api", connection=conn)
        job = scope.context.check()
        old = conn.execute("SELECT payload,job_id FROM evidence_ransomware_batches WHERE document_id=?", (document_id,)).fetchone()
        if old and (old[0] != payload or old[1] != job["id"]):
            raise evidence.EvidenceConflict("Snapshot input differs")
        conn.execute("INSERT OR IGNORE INTO evidence_ransomware_batches(document_id,job_id,payload,row_count) VALUES (?,?,?,?)",
                     (document_id, job["id"], payload, len(claims)))


def pending(scope):
    scope.check_sync()
    with evidence.connect() as conn:
        # Resume this logical job, or retained failed work on a later approved
        # pass. Cancellation never silently resurrects its unfinished queue.
        row = conn.execute("""SELECT b.* FROM evidence_ransomware_batches b
            JOIN evidence_documents d ON d.id=b.document_id JOIN durable_jobs j ON j.id=b.job_id
            JOIN feed_capture_progress p ON p.document_id=b.document_id AND p.job_id=b.job_id
            WHERE d.source_id=? AND (b.next_row<b.row_count OR p.ingested_at IS NULL) AND j.cancel_requested=0
            AND (b.job_id=? OR j.state='failed') ORDER BY b.document_id LIMIT 1""",
            (scope.feed.source, scope.context.check()["id"])).fetchone()
        return dict(row) if row else None


def ingest_row(scope, batch, index, claim):
    """Claim, immutable assertions, citation hops, alerts and cursor commit together."""
    scope.check_sync()
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        scope.check_sync()
        evidence.require_collection(scope.feed.source, "api", connection=conn)
        scope.context.check()
        saved = conn.execute("SELECT next_row FROM evidence_ransomware_batches WHERE document_id=?", (batch["document_id"],)).fetchone()
        if saved[0] != index:
            raise evidence.EvidenceConflict("Snapshot cursor differs")
        conn.execute("INSERT OR IGNORE INTO evidence_ransomware_claims(source_id,external_key) VALUES (?,?)",
                     (scope.feed.source, claim.key))
        ident = conn.execute("SELECT id FROM evidence_ransomware_claims WHERE source_id=? AND external_key=?",
                             (scope.feed.source, claim.key)).fetchone()[0]
        conn.execute("INSERT INTO evidence_ransomware_captures VALUES (?,?,?,?)",
                     (ident, batch["document_id"], index, claim.model_dump_json()))
        for kind, value in claim.subjects():
            observation = Observation(document_id=batch["document_id"], observation_key=claim.key+"."+kind,
                subject_type=kind, subject_value=value, assertion="reported", observed_at=claim.discovered_at,
                locator=f"Recent post row {index}; group {claim.group}; discovered is aggregator discovery, not attack time")
            observation_id = evidence._snapshot(conn, "evidence_observations", observation, ("document_id", "observation_key"))
            conn.execute("INSERT INTO evidence_ransomware_subjects VALUES (?,?)", (observation_id, ident))
            conn.execute("INSERT INTO evidence_alert_subjects VALUES (?,?)",
                         (observation_id, f"ransomware.{scope.feed.source}.{claim.key}.{kind}"))
            alerts.match_observation(conn, observation_id)
        if claim.reference:
            evidence._snapshot(conn, "evidence_citations", Citation(document_id=batch["document_id"],
                citation_key=claim.key+".post", target_reference=claim.reference, relationship="cites",
                locator=f"Recent post row {index}; literal original post reference supplied by aggregator"),
                ("document_id", "citation_key"))
        conn.execute("UPDATE evidence_ransomware_batches SET next_row=next_row+1 WHERE document_id=?", (batch["document_id"],))


def finish_batch(scope, batch):
    scope.check_sync()
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        scope.check_sync()
        evidence.require_collection(scope.feed.source, "api", connection=conn)
        job = scope.context.check()
        conn.execute("""UPDATE feed_capture_progress SET ingested_at=COALESCE(ingested_at,?)
            WHERE job_id=? AND document_id=? AND EXISTS (SELECT 1 FROM evidence_ransomware_batches b
            WHERE b.document_id=? AND b.next_row=b.row_count)""",
            (scope.context._runner._stamp(scope.context._runner._now()), batch["job_id"], batch["document_id"], batch["document_id"]))
        count = conn.execute("SELECT count(*) FROM feed_capture_progress WHERE job_id=? AND ingested_at IS NOT NULL", (job["id"],)).fetchone()[0]
    # No runner write while the module's SQLite transaction is held.
    scope.context.progress(count, checkpoint={"captures_ingested": count})


def claims(*, before=None, limit=50):
    evidence._page(limit, 0)
    with evidence.connect() as conn:
        rows = conn.execute("""SELECT c.*,x.metadata,d.collected_at,d.source_published_at,
            (SELECT count(*) FROM evidence_ransomware_captures n WHERE n.claim_id=c.id) AS captures
            FROM evidence_ransomware_claims c JOIN evidence_ransomware_captures x ON x.claim_id=c.id
            JOIN evidence_documents d ON d.id=x.document_id
            WHERE x.document_id=(SELECT MAX(n.document_id) FROM evidence_ransomware_captures n WHERE n.claim_id=c.id)
            AND (? IS NULL OR c.id<?) ORDER BY c.id DESC LIMIT ?""", (before, before, limit))
        return [{**dict(r), "claim": json.loads(r["metadata"])} for r in rows]


def detail(ident, *, before=None):
    with evidence.connect() as conn:
        row = conn.execute("SELECT * FROM evidence_ransomware_claims WHERE id=?", (ident,)).fetchone()
        if row is None:
            return None
        captures = [dict(r) for r in conn.execute("""SELECT x.*,d.collected_at,d.job_run_id,
            d.source_published_at,d.source_modified_at,d.content_sha256,d.capture_key,
            r.state AS originating_state,j.state AS job_state
            FROM evidence_ransomware_captures x JOIN evidence_documents d ON d.id=x.document_id
            LEFT JOIN durable_job_runs r ON r.id=d.job_run_id LEFT JOIN durable_jobs j ON j.id=r.job_id
            WHERE x.claim_id=? AND (? IS NULL OR x.document_id<?) ORDER BY x.document_id DESC LIMIT 50""",
            (ident, before, before))]
        for capture in captures:
            capture["claim"] = json.loads(capture["metadata"])
            capture["citations"] = [dict(c) for c in conn.execute(
                "SELECT * FROM evidence_citations WHERE document_id=? AND citation_key=?",
                (capture["document_id"], row["external_key"]+".post"))]
            capture["alerts"] = [dict(a) for a in conn.execute("""SELECT a.* FROM evidence_ransomware_subjects s
                JOIN evidence_alert_subjects g ON g.observation_id=s.observation_id
                JOIN evidence_alert_events e ON e.event_key=g.event_key
                JOIN evidence_alerts a ON a.id=e.alert_id
                WHERE s.claim_id=? AND s.observation_id IN
                (SELECT id FROM evidence_observations WHERE document_id=?) ORDER BY a.id LIMIT 100""",
                (ident, capture["document_id"]))]
            from ...core import archives
            capture["archive"] = archives.get(capture["document_id"])
        return {"record": dict(row), "captures": captures}


def for_observation(ident):
    with evidence.connect() as conn:
        row = conn.execute("SELECT claim_id FROM evidence_ransomware_subjects WHERE observation_id=?", (ident,)).fetchone()
        return row[0] if row else None
