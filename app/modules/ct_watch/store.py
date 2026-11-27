"""Explicit CT submission authority, immutable staging and atomic inbox writes."""

from datetime import datetime, timezone
from hashlib import sha256
import json

from ...core import alerts, archives, evidence
from ...core.evidence_models import Citation, Observation, instant
from . import matching, models


def approve(selector_id, *, authority_reference, purpose, expires_at):
    """Trusted local operation only after approval of the exact external query."""
    expires_at = instant(expires_at)
    now = datetime.now(timezone.utc)
    if datetime.fromisoformat(expires_at) <= now:
        raise ValueError("Use a future submission expiry")
    for value in (authority_reference, purpose):
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= 256 or archives.secret_material(value.encode()):
            raise ValueError("Use bounded private record references")
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM evidence_selectors WHERE id=?", (selector_id,)).fetchone()
        if not row or row["subject_type"] not in ("ct_domain", "ct_organization", "ct_brand") or row["mode"] != "exact" or not row["enabled"]:
            raise ValueError("Use an enabled exact CT seed selector")
        if conn.execute("SELECT 1 FROM ct_suppressions WHERE selector_id=?", (selector_id,)).fetchone():
            raise PermissionError("Seed is suppressed")
        if conn.execute("SELECT count(DISTINCT selector_id) FROM ct_permissions").fetchone()[0] >= 10 and not conn.execute(
                "SELECT 1 FROM ct_permissions WHERE selector_id=?", (selector_id,)).fetchone():
            raise ValueError("At most ten distinct CT seed selectors")
        return conn.execute("""INSERT INTO ct_permissions
            (selector_id,approved_at,expires_at,authority_reference,purpose,pattern_version,pattern_sha256,matcher_version) VALUES (?,?,?,?,?,?,?,?)""",
            (selector_id, now.isoformat(), expires_at, authority_reference, purpose, matching.PATTERN_VERSION,
             matching.PATTERN_SHA256, matching.MATCHER_VERSION)).lastrowid


def revoke(permission_id):
    with evidence.connect() as conn, conn:
        conn.execute("UPDATE ct_permissions SET revoked_at=COALESCE(revoked_at,?) WHERE id=?",
                     (datetime.now(timezone.utc).isoformat(), permission_id))


def suppress(selector_id):
    with evidence.connect() as conn, conn:
        conn.execute("INSERT OR IGNORE INTO ct_suppressions VALUES (?,?)", (selector_id, datetime.now(timezone.utc).isoformat()))


def eligible(conn, permission_id, now):
    row = conn.execute("""SELECT p.*,s.value,s.subject_type,s.enabled FROM ct_permissions p
        JOIN evidence_selectors s ON s.id=p.selector_id WHERE p.id=?""", (permission_id,)).fetchone()
    if (not row or not row["enabled"] or row["revoked_at"] or datetime.fromisoformat(row["expires_at"]) <= now
            or row["pattern_version"] != matching.PATTERN_VERSION
            or row["pattern_sha256"] != matching.PATTERN_SHA256 or row["matcher_version"] != matching.MATCHER_VERSION
            or conn.execute("SELECT 1 FROM ct_suppressions WHERE selector_id=?", (row["selector_id"],)).fetchone()):
        raise PermissionError("CT submission authority is absent, disabled, expired, changed or revoked")
    return dict(row)


def check(scope, permission_id, *, connection=None):
    scope.check_sync()
    if connection is not None:
        evidence.require_collection(scope.feed.source, "api", connection=connection)
        return eligible(connection, permission_id, scope.context._runner._now())
    with evidence.connect() as conn:
        return eligible(conn, permission_id, scope.context._runner._now())


def plan(scope):
    scope.check_sync()
    job_id = scope.context.check()["id"]
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        scope.check_sync()
        if not conn.execute("SELECT 1 FROM ct_plans WHERE job_id=?", (job_id,)).fetchone():
            conn.execute("INSERT INTO ct_plans VALUES (?)", (job_id,))
            for row in conn.execute("SELECT id FROM ct_permissions WHERE revoked_at IS NULL ORDER BY id LIMIT 10").fetchall():
                try:
                    eligible(conn, row[0], scope.context._runner._now())
                except PermissionError:
                    continue
                conn.execute("INSERT INTO ct_units(job_id,permission_id) VALUES (?,?)", (job_id, row[0]))
        return [dict(row) for row in conn.execute("SELECT * FROM ct_units WHERE job_id=? ORDER BY permission_id", (job_id,))]


def attempted(scope, permission_id):
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        check(scope, permission_id, connection=conn)
        conn.execute("UPDATE ct_units SET attempted_at=? WHERE job_id=? AND permission_id=?",
                     (scope.context._runner._stamp(scope.context._runner._now()), scope.context.check()["id"], permission_id))


def stage(scope, unit, document_id, candidates):
    payload = json.dumps([item.model_dump() for item in candidates], separators=(",", ":"), ensure_ascii=True)
    if len(payload.encode()) > models.MAX_PAYLOAD:
        raise ValueError("CT normalized input exceeds bounds")
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        check(scope, unit["permission_id"], connection=conn)
        saved = conn.execute("SELECT * FROM ct_units WHERE job_id=? AND permission_id=?",
                             (unit["job_id"], unit["permission_id"])).fetchone()
        if not saved or not conn.execute("SELECT 1 FROM feed_capture_progress WHERE job_id=? AND document_id=?",
                                         (unit["job_id"], document_id)).fetchone():
            raise evidence.EvidenceConflict("Capture is outside the CT unit")
        if saved["document_id"] is not None and (saved["document_id"], saved["payload"]) != (document_id, payload):
            raise evidence.EvidenceConflict("CT staged input differs")
        conn.execute("UPDATE ct_units SET document_id=?,payload=? WHERE job_id=? AND permission_id=?",
                     (document_id, payload, unit["job_id"], unit["permission_id"]))


def ingest(scope, unit):
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        permission = check(scope, unit["permission_id"], connection=conn)
        saved = conn.execute("SELECT * FROM ct_units WHERE job_id=? AND permission_id=?",
                             (unit["job_id"], unit["permission_id"])).fetchone()
        if saved["completed"]:
            return
        for index, row in enumerate(json.loads(saved["payload"])):
            check(scope, unit["permission_id"], connection=conn)
            item = models.Candidate(**row)
            result = matching.match(permission["value"], permission["subject_type"][3:], item.name)
            if result is None:
                continue  # An unrelated SAN is never an implicit matching seed.
            key = sha256(json.dumps([item.certificate_id, item.name, item.literal_name]).encode()).hexdigest()
            observation = Observation(document_id=saved["document_id"], observation_key=key,
                subject_type="ct_hostname", subject_value=item.name, assertion="reported",
                locator=f"crt.sh name_value; normalized row {index}; certificate id {item.certificate_id}; exact local seed match")
            ident = evidence._snapshot(conn, "evidence_observations", observation, ("document_id", "observation_key"))
            conn.execute("INSERT INTO ct_candidates VALUES (?,?,?,?)",
                         (ident, unit["permission_id"], item.model_dump_json(), json.dumps(result, sort_keys=True)))
            event = "ct.crtsh." + sha256(item.name.encode()).hexdigest()
            conn.execute("INSERT INTO evidence_alert_subjects VALUES (?,?)", (ident, event))
            alerts.match_observation(conn, ident)
            # JSON does not supply a citation URL. Label this constructed ID
            # reference explicitly; never present it as an upstream citation.
            evidence._snapshot(conn, "evidence_citations", Citation(document_id=saved["document_id"], citation_key=key,
                target_reference="https://crt.sh/?id="+item.certificate_id,
                locator="Constructed provider certificate-ID reference; not a literal supplied URL or original-log citation"),
                ("document_id", "citation_key"))
        check(scope, unit["permission_id"], connection=conn)
        conn.execute("UPDATE ct_units SET completed=1 WHERE job_id=? AND permission_id=?", (unit["job_id"], unit["permission_id"]))
        conn.execute("UPDATE feed_capture_progress SET ingested_at=COALESCE(ingested_at,?) WHERE job_id=? AND document_id=?",
                     (scope.context._runner._stamp(scope.context._runner._now()), unit["job_id"], saved["document_id"]))
    with evidence.connect() as conn:
        done = conn.execute("SELECT count(*) FROM ct_units WHERE job_id=? AND completed=1", (unit["job_id"],)).fetchone()[0]
    scope.context.progress(done, checkpoint={"ct_queries_ingested": done})


def watches(now=None):
    now = now or datetime.now(timezone.utc)
    with evidence.connect() as conn:
        rows = [dict(row) for row in conn.execute("""SELECT s.id,s.value,s.subject_type,s.enabled FROM evidence_selectors s
            WHERE s.id IN (SELECT selector_id FROM ct_permissions) ORDER BY s.id LIMIT 10""")]
        for row in rows:
            units = "FROM ct_units u JOIN ct_permissions p ON p.id=u.permission_id"
            row["last_attempt"] = conn.execute("SELECT max(u.attempted_at) "+units+" WHERE p.selector_id=?", (row["id"],)).fetchone()[0]
            good = conn.execute("SELECT u.document_id,d.collected_at "+units+" JOIN evidence_documents d ON d.id=u.document_id WHERE p.selector_id=? AND u.completed=1 ORDER BY d.collected_at DESC,d.id DESC LIMIT 1", (row["id"],)).fetchone()
            row["last_good"] = good["collected_at"] if good else None
            row["document_id"] = good["document_id"] if good else None
            row["state"] = "Never Loaded" if not good else "Stale" if (now-datetime.fromisoformat(good["collected_at"])).total_seconds() >= 2*86400 else "Current"
            latest = conn.execute("SELECT u.completed,j.state,j.error_code "+units+" JOIN durable_jobs j ON j.id=u.job_id WHERE p.selector_id=? ORDER BY j.created_at DESC,j.id DESC LIMIT 1", (row["id"],)).fetchone()
            row["incomplete"] = bool(latest and not latest["completed"])
            row["error"] = latest["error_code"] if row["incomplete"] else None
            row["authorized"] = False
            for permission in conn.execute("SELECT id FROM ct_permissions WHERE selector_id=? AND revoked_at IS NULL LIMIT 1", (row["id"],)).fetchall():
                try:
                    eligible(conn, permission[0], now)
                    row["authorized"] = True
                except PermissionError:
                    pass
        return rows


def capture(document_id, *, offset=0):
    evidence._page(100, offset)
    with evidence.connect() as conn:
        unit = conn.execute("SELECT * FROM ct_units WHERE document_id=?", (document_id,)).fetchone()
        if not unit:
            return None
        document = dict(conn.execute("""SELECT d.*,r.state AS originating_state,j.state AS job_state FROM evidence_documents d
            LEFT JOIN durable_job_runs r ON r.id=d.job_run_id LEFT JOIN durable_jobs j ON j.id=r.job_id WHERE d.id=?""", (document_id,)).fetchone())
        rows = []
        for row in conn.execute("""SELECT c.* FROM ct_candidates c JOIN evidence_observations o ON o.id=c.observation_id
            WHERE o.document_id=? ORDER BY c.observation_id LIMIT 100 OFFSET ?""", (document_id, offset)).fetchall():
            value = {**dict(row), "candidate": json.loads(row["metadata"]), "match": json.loads(row["match_metadata"])}
            value["alerts"] = [dict(a) for a in conn.execute("""SELECT a.* FROM evidence_alert_subjects s
                JOIN evidence_alert_events e ON e.event_key=s.event_key JOIN evidence_alerts a ON a.id=e.alert_id
                WHERE s.observation_id=? ORDER BY a.id LIMIT 100""", (row["observation_id"],))]
            rows.append(value)
        return {"document": document, "candidates": rows, "archive": archives.get(document_id),
                "citations": evidence.citations_for_document(document_id, offset=offset), "offset": offset}


def history(selector_id, *, before=None):
    with evidence.connect() as conn:
        return [dict(row) for row in conn.execute("""SELECT u.document_id,u.completed,d.collected_at FROM ct_units u
            JOIN ct_permissions p ON p.id=u.permission_id JOIN evidence_documents d ON d.id=u.document_id
            WHERE p.selector_id=? AND (? IS NULL OR u.document_id<?) ORDER BY u.document_id DESC LIMIT 50""", (selector_id, before, before))]
