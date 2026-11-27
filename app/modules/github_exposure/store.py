"""Separate submission authority and restart-safe, atomic metadata ingestion."""

from datetime import datetime, timezone
from hashlib import sha256
import json

from ...core import alerts, archives, evidence
from ...core.evidence_models import Citation, Observation, instant
from . import models


def approve(selector_id, *, authority_reference, purpose, expires_at):
    """Trusted local operation AFTER direct approval of exact query and access."""
    expires_at = instant(expires_at)
    now = datetime.now(timezone.utc)
    if datetime.fromisoformat(expires_at) <= now or models.prerequisite():
        raise ValueError("Future expiry and reviewed public-only access are required")
    for value in (authority_reference, purpose):
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= 256 or archives.secret_material(value.encode()):
            raise ValueError("Use bounded private record references")
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM evidence_selectors WHERE id=?", (selector_id,)).fetchone()
        if not row or row["subject_type"] not in models.TYPES or row["mode"] != "exact" or not row["enabled"]:
            raise ValueError("Use an enabled exact GitHub query selector")
        if conn.execute("SELECT 1 FROM github_exposure_suppressions WHERE selector_id=?", (selector_id,)).fetchone():
            raise PermissionError("Selector is suppressed")
        if conn.execute("SELECT count(DISTINCT selector_id) FROM github_exposure_permissions").fetchone()[0] >= 10 and not conn.execute(
                "SELECT 1 FROM github_exposure_permissions WHERE selector_id=?", (selector_id,)).fetchone():
            raise ValueError("At most ten distinct GitHub selectors")
        return conn.execute("""INSERT INTO github_exposure_permissions
            (selector_id,selector_type,selector_value,query,query_version,api_version,credential_sha256,approved_at,expires_at,authority_reference,purpose)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (selector_id, row["subject_type"], row["value"],
            models.query(row["value"], row["subject_type"]), models.QUERY_VERSION, models.API_VERSION, models.credential_identity(),
            now.isoformat(), expires_at, authority_reference, purpose)).lastrowid


def revoke(permission_id):
    with evidence.connect() as conn, conn:
        conn.execute("UPDATE github_exposure_permissions SET revoked_at=COALESCE(revoked_at,?) WHERE id=?",
                     (datetime.now(timezone.utc).isoformat(), permission_id))


def suppress(selector_id):
    with evidence.connect() as conn, conn:
        conn.execute("INSERT OR IGNORE INTO github_exposure_suppressions VALUES (?,?)", (selector_id, datetime.now(timezone.utc).isoformat()))


def eligible(conn, permission_id, now):
    row = conn.execute("""SELECT p.*,s.value,s.subject_type,s.mode,s.enabled FROM github_exposure_permissions p
        JOIN evidence_selectors s ON s.id=p.selector_id WHERE p.id=?""", (permission_id,)).fetchone()
    if (not row or not row["enabled"] or row["mode"] != "exact" or row["revoked_at"] or models.prerequisite()
            or datetime.fromisoformat(row["expires_at"]) <= now or row["query_version"] != models.QUERY_VERSION
            or row["api_version"] != models.API_VERSION
            or row["credential_sha256"] != models.credential_identity()
            or (row["selector_type"], row["selector_value"]) != (row["subject_type"], row["value"])
            or row["query"] != models.query(row["value"], row["subject_type"])
            or conn.execute("SELECT 1 FROM github_exposure_suppressions WHERE selector_id=?", (row["selector_id"],)).fetchone()):
        raise PermissionError("GitHub submission authority is absent, disabled, changed, expired or revoked")
    return dict(row)


def check(scope, permission_id, *, connection=None):
    scope.check_sync()
    if connection is not None:
        evidence.require_collection(scope.feed.source, "api", connection=connection)
        return eligible(connection, permission_id, scope.context._runner._now())
    with evidence.connect() as conn:
        evidence.require_collection(scope.feed.source, "api", connection=conn)
        return eligible(conn, permission_id, scope.context._runner._now())


def plan(scope):
    scope.check_sync()
    job_id = scope.context.check()["id"]
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        scope.check_sync()
        if not conn.execute("SELECT 1 FROM github_exposure_plans WHERE job_id=?", (job_id,)).fetchone():
            conn.execute("INSERT INTO github_exposure_plans VALUES (?)", (job_id,))
            for row in conn.execute("SELECT id FROM github_exposure_permissions WHERE revoked_at IS NULL ORDER BY id LIMIT 10").fetchall():
                try:
                    check(scope, row[0], connection=conn)
                except PermissionError:
                    continue
                conn.execute("INSERT INTO github_exposure_units(job_id,permission_id) VALUES (?,?)", (job_id, row[0]))
                conn.executemany("INSERT INTO github_exposure_pages(job_id,permission_id,page) VALUES (?,?,?)",
                                 [(job_id, row[0], page) for page in range(1, models.MAX_PAGES + 1)])
        return [dict(row) for row in conn.execute("SELECT * FROM github_exposure_units WHERE job_id=? ORDER BY permission_id", (job_id,))]


def pages(unit):
    with evidence.connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM github_exposure_pages WHERE job_id=? AND permission_id=? ORDER BY page",
                                                 (unit["job_id"], unit["permission_id"]))]


def attempted(scope, unit):
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        check(scope, unit["permission_id"], connection=conn)
        conn.execute("UPDATE github_exposure_units SET attempted_at=? WHERE job_id=? AND permission_id=?",
                     (scope.context._runner._stamp(scope.context._runner._now()), unit["job_id"], unit["permission_id"]))


def stage(scope, page, document_id, value):
    payload = value.model_dump_json()
    if len(payload.encode()) > models.MAX_PAYLOAD:
        raise ValueError("Search normalized input exceeds bounds")
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        check(scope, page["permission_id"], connection=conn)
        saved = conn.execute("SELECT * FROM github_exposure_pages WHERE job_id=? AND permission_id=? AND page=?",
                             (page["job_id"], page["permission_id"], page["page"])).fetchone()
        if not saved or scope.context.check()["id"] != page["job_id"] or not conn.execute(
                "SELECT 1 FROM feed_capture_progress WHERE job_id=? AND document_id=?", (page["job_id"], document_id)).fetchone():
            raise evidence.EvidenceConflict("Capture is outside the planned page")
        if saved["document_id"] is not None and (saved["document_id"], saved["payload"]) != (document_id, payload):
            raise evidence.EvidenceConflict("Search staged input differs")
        conn.execute("UPDATE github_exposure_pages SET document_id=?,payload=? WHERE job_id=? AND permission_id=? AND page=?",
                     (document_id, payload, page["job_id"], page["permission_id"], page["page"]))


def ingest(scope, page):
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        permission = check(scope, page["permission_id"], connection=conn)
        saved = conn.execute("SELECT * FROM github_exposure_pages WHERE job_id=? AND permission_id=? AND page=?",
                             (page["job_id"], page["permission_id"], page["page"])).fetchone()
        if saved["completed"]:
            return
        value = models.Page.model_validate_json(saved["payload"])
        for index, item in enumerate(value.leads):
            check(scope, page["permission_id"], connection=conn)
            key = sha256(item.model_dump_json().encode()).hexdigest()
            observation = Observation(document_id=saved["document_id"], observation_key=key,
                subject_type=permission["selector_type"], subject_value=permission["selector_value"], assertion="reported",
                locator=f"GitHub code search page {page['page']}, normalized item {index}; provider query attribution only; exact content unverified")
            ident = evidence._snapshot(conn, "evidence_observations", observation, ("document_id", "observation_key"))
            conn.execute("INSERT INTO github_exposure_leads VALUES (?,?,?)", (ident, permission["id"], item.model_dump_json()))
            conn.execute("INSERT INTO evidence_alert_subjects VALUES (?,?)", (ident, item.event))
            alerts.match_observation(conn, ident)
            evidence._snapshot(conn, "evidence_citations", Citation(document_id=saved["document_id"], citation_key=key,
                target_reference=item.html_url, locator="Literal GitHub search item html_url; unresolved, never fetched"),
                ("document_id", "citation_key"))
        check(scope, page["permission_id"], connection=conn)
        conn.execute("UPDATE github_exposure_pages SET completed=1 WHERE job_id=? AND permission_id=? AND page=?",
                     (page["job_id"], page["permission_id"], page["page"]))
        conn.execute("UPDATE feed_capture_progress SET ingested_at=COALESCE(ingested_at,?) WHERE job_id=? AND document_id=?",
                     (scope.context._runner._stamp(scope.context._runner._now()), page["job_id"], saved["document_id"]))


def finish(scope, unit):
    """Coverage is one bounded, consistent window, never complete GitHub coverage."""
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        check(scope, unit["permission_id"], connection=conn)
        saved = conn.execute("SELECT * FROM github_exposure_pages WHERE job_id=? AND permission_id=? ORDER BY page",
                             (unit["job_id"], unit["permission_id"])).fetchall()
        first = models.Page.model_validate_json(saved[0]["payload"])
        needed = 2 if first.total_count > models.PER_PAGE else 1
        if any(not row["completed"] for row in saved[:needed]):
            raise ValueError("Search pages have not committed")
        values = [models.Page.model_validate_json(row["payload"]) for row in saved[:needed]]
        identities = [(lead.repository_id, lead.path) for value in values for lead in value.leads]
        complete = (first.total_count <= models.PER_PAGE * models.MAX_PAGES
            and all(not value.incomplete_results and value.total_count == first.total_count for value in values)
            and sum(value.returned_count for value in values) == first.total_count
            and len(identities) == len(set(identities)) == first.total_count)
        conn.execute("UPDATE github_exposure_units SET completed=1,window_complete=? WHERE job_id=? AND permission_id=?",
                     (complete, unit["job_id"], unit["permission_id"]))
        if needed == 1:
            conn.execute("UPDATE github_exposure_pages SET completed=1 WHERE job_id=? AND permission_id=? AND page=2 AND document_id IS NULL",
                         (unit["job_id"], unit["permission_id"]))
        return complete


def watches(now=None):
    now = now or datetime.now(timezone.utc)
    with evidence.connect() as conn:
        result = [dict(row) for row in conn.execute("SELECT id,value,subject_type,enabled FROM evidence_selectors WHERE id IN (SELECT selector_id FROM github_exposure_permissions) ORDER BY id LIMIT 10")]
        for row in result:
            units = " FROM github_exposure_units u JOIN github_exposure_permissions p ON p.id=u.permission_id "
            row["last_attempt"] = conn.execute("SELECT max(u.attempted_at)"+units+"WHERE p.selector_id=?", (row["id"],)).fetchone()[0]
            good = conn.execute("""SELECT min(d.collected_at) AS collected_at,min(d.id) AS document_id"""+units+"""
                JOIN github_exposure_pages g ON g.job_id=u.job_id AND g.permission_id=u.permission_id
                JOIN evidence_documents d ON d.id=g.document_id WHERE p.selector_id=? AND u.completed=1 AND u.window_complete=1
                GROUP BY u.job_id,u.permission_id ORDER BY collected_at DESC LIMIT 1""", (row["id"],)).fetchone()
            row["last_good"] = good["collected_at"] if good else None
            row["document_id"] = good["document_id"] if good else None
            row["state"] = "Never Loaded" if not good else "Stale" if (now-datetime.fromisoformat(good["collected_at"])).total_seconds() >= 2*86400 else "Current"
            latest = conn.execute("SELECT u.completed,u.window_complete,j.error_code"+units+"JOIN durable_jobs j ON j.id=u.job_id WHERE p.selector_id=? ORDER BY j.created_at DESC,j.id DESC LIMIT 1", (row["id"],)).fetchone()
            row["incomplete"] = bool(latest and (not latest["completed"] or not latest["window_complete"]))
            row["error"] = latest["error_code"] if row["incomplete"] else None
            row["authorized"] = False
            current = conn.execute("SELECT id FROM github_exposure_permissions WHERE selector_id=? AND revoked_at IS NULL LIMIT 1", (row["id"],)).fetchone()
            if current:
                try:
                    eligible(conn, current[0], now)
                    row["authorized"] = True
                except PermissionError:
                    pass
        return result


def capture(document_id):
    with evidence.connect() as conn:
        page = conn.execute("SELECT * FROM github_exposure_pages WHERE document_id=?", (document_id,)).fetchone()
        if not page:
            return None
        document = dict(conn.execute("""SELECT d.*,r.state AS originating_state,j.state AS job_state FROM evidence_documents d
            LEFT JOIN durable_job_runs r ON r.id=d.job_run_id LEFT JOIN durable_jobs j ON j.id=r.job_id WHERE d.id=?""", (document_id,)).fetchone())
        leads = []
        for row in conn.execute("SELECT l.* FROM github_exposure_leads l JOIN evidence_observations o ON o.id=l.observation_id WHERE o.document_id=? ORDER BY l.observation_id LIMIT 50", (document_id,)):
            item = {**dict(row), "lead": json.loads(row["metadata"])}
            item["alerts"] = [dict(a) for a in conn.execute("""SELECT a.* FROM evidence_alert_subjects s
                JOIN evidence_alert_events e ON e.event_key=s.event_key JOIN evidence_alerts a ON a.id=e.alert_id
                WHERE s.observation_id=? ORDER BY a.id LIMIT 100""", (row["observation_id"],))]
            leads.append(item)
        unit = dict(conn.execute("SELECT * FROM github_exposure_units WHERE job_id=? AND permission_id=?", (page["job_id"], page["permission_id"])).fetchone())
        return {"document": document, "leads": leads, "page": dict(page), "unit": unit,
                "archive": archives.get(document_id), "citations": evidence.citations_for_document(document_id),
                "pages": pages(unit), "summary": models.Page.model_validate_json(page["payload"]) }


def history(selector_id, *, before=None):
    with evidence.connect() as conn:
        return [dict(row) for row in conn.execute("""SELECT g.document_id,g.page,u.completed,u.window_complete,d.collected_at
            FROM github_exposure_units u JOIN github_exposure_permissions p ON p.id=u.permission_id
            JOIN github_exposure_pages g ON g.job_id=u.job_id AND g.permission_id=u.permission_id
            JOIN evidence_documents d ON d.id=g.document_id WHERE p.selector_id=? AND (? IS NULL OR g.document_id<?)
            ORDER BY g.document_id DESC LIMIT 50""", (selector_id, before, before))]
