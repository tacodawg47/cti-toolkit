"""Explicit submission permissions, immutable staged lookups and local views."""

from datetime import datetime, timezone
from hashlib import sha256
import json

from ...core import alerts, archives, evidence
from ...core.evidence_models import Citation, Observation, instant
from .models import Breach


def approve(selector_id, *, authority_reference, consent_reference, purpose, expires_at):
    """Trusted local operation only AFTER direct approval for this address.

    Consent/authority references are local record identifiers, not documents or
    personal narratives. A local watch never invokes this operation implicitly.
    """
    expires_at = instant(expires_at)
    now = datetime.now(timezone.utc).isoformat()
    if datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc):
        raise ValueError("Use a future permission expiry")
    for value in (authority_reference, consent_reference, purpose):
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= 256 or archives.secret_material(value.encode()):
            raise ValueError("Use bounded local authorization references")
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM evidence_selectors WHERE id=?", (selector_id,)).fetchone()
        if not row or row["subject_type"] != "email" or row["mode"] != "exact" or not row["enabled"]:
            raise ValueError("An enabled exact email watch is required")
        if conn.execute("SELECT 1 FROM breach_suppressions WHERE email_value=?", (row["value"].lower(),)).fetchone():
            raise PermissionError("Address is suppressed")
        if conn.execute("SELECT count(DISTINCT selector_id) FROM breach_permissions").fetchone()[0] >= 10 and not conn.execute(
                "SELECT 1 FROM breach_permissions WHERE selector_id=?", (selector_id,)).fetchone():
            raise ValueError("First delivery permits at most ten watched addresses")
        return conn.execute("""INSERT INTO breach_permissions
            (selector_id,approved_at,expires_at,authority_reference,consent_reference,purpose)
            VALUES (?,?,?,?,?,?)""", (selector_id, now, expires_at, authority_reference, consent_reference, purpose)).lastrowid


def revoke(permission_id):
    with evidence.connect() as conn, conn:
        conn.execute("UPDATE breach_permissions SET revoked_at=COALESCE(revoked_at,?) WHERE id=?",
                     (datetime.now(timezone.utc).isoformat(), permission_id))


def suppress(selector_id):
    """Stop all future breach submissions for this case-insensitive address.

    This is suppression, not privacy deletion of existing evidence. No public
    route/export or automatic removal of the suppression is provided.
    """
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT value FROM evidence_selectors WHERE id=? AND subject_type='email'", (selector_id,)).fetchone()
        if not row:
            raise ValueError("Email selector required")
        conn.execute("INSERT OR IGNORE INTO breach_suppressions VALUES (?,?)", (row[0].lower(), datetime.now(timezone.utc).isoformat()))


def eligible(conn, permission_id, now):
    row = conn.execute("""SELECT p.*,s.value,s.enabled FROM breach_permissions p
        JOIN evidence_selectors s ON s.id=p.selector_id WHERE p.id=?""", (permission_id,)).fetchone()
    if (not row or row["revoked_at"] or not row["enabled"]
            or datetime.fromisoformat(row["expires_at"]) <= now
            or conn.execute("SELECT 1 FROM breach_suppressions WHERE email_value=?", (row["value"].lower(),)).fetchone()):
        raise PermissionError("Email submission permission is absent, disabled, revoked or expired")
    return dict(row)


def check(scope, permission_id, *, connection=None):
    scope.check_sync()
    now = scope.context._runner._now()
    if connection is not None:
        evidence.require_collection(scope.feed.source, "api", connection=connection)
        return eligible(connection, permission_id, now)
    with evidence.connect() as conn:
        return eligible(conn, permission_id, now)


def plan(scope):
    scope.check_sync()
    job_id = scope.context.check()["id"]
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        scope.check_sync()
        if not conn.execute("SELECT 1 FROM breach_units WHERE job_id=?", (job_id,)).fetchone():
            # Snapshot immutable permission IDs, never expand queued work after
            # restart or substitute a new approval for a revoked old approval.
            rows = conn.execute("""SELECT p.id FROM breach_permissions p JOIN evidence_selectors s ON s.id=p.selector_id
                WHERE p.revoked_at IS NULL AND s.enabled=1 ORDER BY p.id LIMIT 10""").fetchall()
            for row in rows:
                eligible(conn, row[0], scope.context._runner._now())
                conn.execute("INSERT INTO breach_units(job_id,permission_id) VALUES (?,?)", (job_id, row[0]))
        return [dict(row) for row in conn.execute("SELECT * FROM breach_units WHERE job_id=? ORDER BY permission_id", (job_id,))]


def attempted(scope, permission_id):
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        check(scope, permission_id, connection=conn)
        conn.execute("UPDATE breach_units SET attempted_at=? WHERE job_id=? AND permission_id=?",
                     (scope.context._runner._stamp(scope.context._runner._now()), scope.context.check()["id"], permission_id))


def stage(scope, unit, document_id, status, breaches):
    payload = json.dumps([b.model_dump() for b in breaches], separators=(",", ":"), ensure_ascii=True)
    if len(payload.encode()) > 512*1024:
        raise ValueError("Normalized lookup exceeds bounds")
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        check(scope, unit["permission_id"], connection=conn)
        saved = conn.execute("SELECT * FROM breach_units WHERE job_id=? AND permission_id=?",
                             (unit["job_id"], unit["permission_id"])).fetchone()
        if saved["document_id"] is not None and (saved["document_id"], saved["payload"], saved["status"]) != (document_id, payload, status):
            raise evidence.EvidenceConflict("Lookup input differs")
        conn.execute("UPDATE breach_units SET document_id=?,payload=?,status=? WHERE job_id=? AND permission_id=?",
                     (document_id, payload, status, unit["job_id"], unit["permission_id"]))


def ingest(scope, unit):
    """One bounded lookup commits assertions, literal hops, alerts and completion."""
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        permission = check(scope, unit["permission_id"], connection=conn)
        if conn.execute("SELECT completed FROM breach_units WHERE job_id=? AND permission_id=?",
                        (unit["job_id"], unit["permission_id"])).fetchone()[0]:
            return
        for index, row in enumerate(json.loads(unit["payload"])):
            # Eligibility is checked at every assertion, inside the transaction.
            check(scope, unit["permission_id"], connection=conn)
            breach = Breach(**row)
            key = sha256(json.dumps([permission["value"].lower(), breach.name]).encode()).hexdigest()
            model = Observation(document_id=unit["document_id"], observation_key=key,
                subject_type="email", subject_value=permission["value"], assertion="reported",
                locator=f"HIBP association row {index}; not proof of identity or current compromise")
            ident = evidence._snapshot(conn, "evidence_observations", model, ("document_id", "observation_key"))
            conn.execute("INSERT INTO breach_associations VALUES (?,?,?,?)",
                         (ident, unit["permission_id"], breach.name, breach.model_dump_json()))
            conn.execute("INSERT INTO evidence_alert_subjects VALUES (?,?)", (ident, "breach.hibp."+key))
            alerts.match_observation(conn, ident)
            if breach.disclosure:
                evidence._snapshot(conn, "evidence_citations", Citation(document_id=unit["document_id"], citation_key=key,
                    target_reference=breach.disclosure, locator=f"HIBP row {index} DisclosureUrl, literal unresolved reference"),
                    ("document_id", "citation_key"))
        check(scope, unit["permission_id"], connection=conn)
        conn.execute("UPDATE breach_units SET completed=1 WHERE job_id=? AND permission_id=?", (unit["job_id"], unit["permission_id"]))
        conn.execute("UPDATE feed_capture_progress SET ingested_at=COALESCE(ingested_at,?) WHERE job_id=? AND document_id=?",
                     (scope.context._runner._stamp(scope.context._runner._now()), unit["job_id"], unit["document_id"]))
    # Progress can replay independently without resetting evidence/reviews.
    with evidence.connect() as conn:
        count = conn.execute("SELECT count(*) FROM breach_units WHERE job_id=? AND completed=1", (unit["job_id"],)).fetchone()[0]
    scope.context.progress(count, checkpoint={"lookups_ingested": count})


def watches(now=None):
    now = now or datetime.now(timezone.utc)
    with evidence.connect() as conn:
        rows = [dict(row) for row in conn.execute("""SELECT s.id,s.value,s.enabled,
            (SELECT max(u.attempted_at) FROM breach_units u JOIN breach_permissions p ON p.id=u.permission_id
             WHERE p.selector_id=s.id) AS last_attempt
            FROM evidence_selectors s WHERE s.id IN (SELECT selector_id FROM breach_permissions) ORDER BY s.id LIMIT 10""")]
        for row in rows:
            good = conn.execute("""SELECT u.*,d.collected_at FROM breach_units u
                JOIN breach_permissions p ON p.id=u.permission_id JOIN evidence_documents d ON d.id=u.document_id
                WHERE p.selector_id=? AND u.completed=1 ORDER BY d.collected_at DESC,d.id DESC LIMIT 1""", (row["id"],)).fetchone()
            row["last_good"] = good["collected_at"] if good else None
            row["state"] = "Never Loaded" if not good else "Stale" if (now-datetime.fromisoformat(good["collected_at"])).total_seconds() >= 2*86400 else "Current"
            latest = conn.execute("""SELECT u.completed,j.state,j.error_code FROM breach_units u
                JOIN breach_permissions p ON p.id=u.permission_id JOIN durable_jobs j ON j.id=u.job_id
                WHERE p.selector_id=? ORDER BY j.created_at DESC,j.id DESC LIMIT 1""", (row["id"],)).fetchone()
            row["incomplete"] = bool(latest and not latest["completed"])
            row["error"] = latest["error_code"] if latest and not latest["completed"] else None
            row["document_id"] = good["document_id"] if good else None
            row["no_result"] = bool(good and good["status"] == 404)
            row["breaches"] = json.loads(good["payload"]) if good else []
            row["authorized"] = False
            for permission in conn.execute("SELECT id FROM breach_permissions WHERE selector_id=?", (row["id"],)).fetchall():
                try:
                    eligible(conn, permission[0], now)
                    row["authorized"] = True
                except PermissionError:
                    pass
        return rows


def capture(document_id):
    with evidence.connect() as conn:
        unit = conn.execute("SELECT * FROM breach_units WHERE document_id=?", (document_id,)).fetchone()
        if not unit:
            return None
        document = dict(conn.execute("""SELECT d.*,r.state AS originating_state,j.state AS job_state
            FROM evidence_documents d LEFT JOIN durable_job_runs r ON r.id=d.job_run_id
            LEFT JOIN durable_jobs j ON j.id=r.job_id WHERE d.id=?""", (document_id,)).fetchone())
        rows = [dict(row) for row in conn.execute("SELECT * FROM breach_associations WHERE observation_id IN (SELECT id FROM evidence_observations WHERE document_id=?) ORDER BY observation_id", (document_id,))]
        for row in rows:
            row["breach"] = json.loads(row["metadata"])
            row["alerts"] = [dict(a) for a in conn.execute("""SELECT a.* FROM evidence_alert_subjects s
                JOIN evidence_alert_events e ON e.event_key=s.event_key JOIN evidence_alerts a ON a.id=e.alert_id
                WHERE s.observation_id=? ORDER BY a.id LIMIT 100""", (row["observation_id"],))]
        return {"document": document, "associations": rows, "archive": archives.get(document_id),
                "citations": evidence.citations_for_document(document_id), "status": unit["status"]}


def history(selector_id, *, before=None):
    with evidence.connect() as conn:
        return [dict(row) for row in conn.execute("""SELECT u.document_id,u.status,u.completed,d.collected_at
            FROM breach_units u JOIN breach_permissions p ON p.id=u.permission_id JOIN evidence_documents d ON d.id=u.document_id
            WHERE p.selector_id=? AND (? IS NULL OR u.document_id<?) ORDER BY u.document_id DESC LIMIT 50""",
            (selector_id, before, before))]
