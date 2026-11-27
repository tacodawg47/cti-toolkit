"""Local, bounded typed matching. Selectors are passive data, never work policies.

One alert per selector and immutable observation. Separate captures/assertions
stay separate even when their indicator values or citations agree.
"""

from datetime import datetime, timezone
import ipaddress
import re
import unicodedata
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from . import archives, evidence
from .evidence_models import Metadata
from .indicators import canonical, detect_type, normalise

STATES = ("new", "reviewed", "dismissed")
TYPES = ("domain", "ip", "hash", "url", "email", "cve", "organization", "sector", "country",
         "ct_domain", "ct_organization", "ct_brand", "github_domain", "github_organization", "subdomain_domain")
MAX_SELECTORS = 100


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def normalize_subject(subject_type, value):
    if subject_type not in TYPES or not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("Use a bounded typed subject")
    if subject_type.startswith("ct_"):
        from ..modules.ct_watch.matching import seed
        return seed(value, subject_type[3:])
    if subject_type.startswith("github_"):
        from ..modules.github_exposure.models import selector
        return selector(value, subject_type)
    if subject_type == "subdomain_domain":
        from ..modules.subdomains.models import selector
        return selector(value)
    if subject_type in ("organization", "sector", "country"):
        value = " ".join(unicodedata.normalize("NFKC", value).split()).casefold()
        if not value or len(value) > (512 if subject_type == "organization" else 128):
            raise ValueError("Use a bounded watch value")
        if subject_type == "country":
            if not re.fullmatch(r"[a-z]{2}", value):
                raise ValueError("Use a two-letter country code, without aliases")
            return value.upper()
        return value
    value = normalise(value)
    if subject_type == "email":
        local, sep, domain = value.rpartition("@")
        domain = normalise(domain)
        if not sep or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local) or detect_type(domain) != "domain":
            raise ValueError("Invalid email selector")
        # Preserve the local part's case: SMTP local parts can be case-sensitive.
        return local + "@" + domain.lower()
    if detect_type(value) != subject_type:
        raise ValueError("Subject type does not match value")
    if subject_type == "url":
        parts = urlsplit(value)
        if not parts.hostname or parts.username is not None or parts.password is not None:
            raise ValueError("Invalid URL selector")
        parts.port  # Validate malformed ports, without following the URL.
    return canonical(subject_type, value)


class Selector(Metadata):
    subject_type: Literal["domain", "ip", "hash", "url", "email", "cve", "organization", "sector", "country", "ct_domain", "ct_organization", "ct_brand", "github_domain", "github_organization", "subdomain_domain"]
    mode: Literal["exact", "domain_tree", "network"] = "exact"
    value: str = Field(min_length=1, max_length=2048)

    @model_validator(mode="after")
    def valid(self):
        if archives.secret_material(self.value.encode()):
            raise ValueError("Credential-like selectors are refused")
        if self.subject_type.startswith("ct_") and self.mode != "exact":
            raise ValueError("CT seeds use explicit exact label/domain rules")
        if self.subject_type.startswith("github_") and self.mode != "exact":
            raise ValueError("GitHub query attribution uses exact selectors only")
        if self.subject_type == "subdomain_domain" and self.mode != "exact":
            raise ValueError("Inventory uses exact approved domain attribution")
        if self.mode == "network":
            if self.subject_type != "ip":
                raise ValueError("Networks match IP observations only")
            value = str(ipaddress.ip_network(self.value, strict=True))
        else:
            if self.mode == "domain_tree" and self.subject_type != "domain":
                raise ValueError("Domain trees match domain observations only")
            value = normalize_subject(self.subject_type, self.value)
        object.__setattr__(self, "value", value)
        return self


def add_selector(selector: Selector) -> int:
    """Explicit operator configuration; never invoked by evidence ingestion."""
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        values = (selector.subject_type, selector.mode, selector.value)
        previous = conn.execute("SELECT id FROM evidence_selectors WHERE subject_type=? AND mode=? AND value=?", values).fetchone()
        if previous:
            return previous[0]  # Replay does not re-enable a disabled selector.
        if conn.execute("SELECT count(*) FROM evidence_selectors").fetchone()[0] >= MAX_SELECTORS:
            raise ValueError("Selector capacity reached")
        return conn.execute("INSERT INTO evidence_selectors(subject_type,mode,value,created_at) VALUES (?,?,?,?)",
                            (*values, now())).lastrowid


def set_enabled(ident: int, enabled: bool):
    if type(enabled) is not bool:
        raise ValueError("Use an explicit boolean")
    with evidence.connect() as conn, conn:
        if not conn.execute("UPDATE evidence_selectors SET enabled=? WHERE id=?", (enabled, ident)).rowcount:
            raise KeyError(ident)


def selectors():
    with evidence.connect() as conn:
        return [dict(r) for r in conn.execute("""SELECT s.*, EXISTS(
            SELECT 1 FROM evidence_observations o WHERE o.id>s.scanned_through) AS pending
            FROM evidence_selectors s ORDER BY s.id LIMIT ?""", (MAX_SELECTORS,))]


def matches(selector, observation):
    if selector["subject_type"].startswith("ct_") and observation["subject_type"] == "ct_hostname":
        from ..modules.ct_watch.matching import match
        try:
            return match(selector["value"], selector["subject_type"][3:], observation["subject_value"]) is not None
        except ValueError:
            return False
    if selector["subject_type"] != observation["subject_type"]:
        return False
    try:
        value = normalize_subject(observation["subject_type"], observation["subject_value"])
    except ValueError:
        return False  # Generic evidence can hold types/values outside this matcher.
    if selector["mode"] == "domain_tree":
        return value == selector["value"] or value.endswith("." + selector["value"])
    if selector["mode"] == "network":
        return ipaddress.ip_address(value) in ipaddress.ip_network(selector["value"])
    return value == selector["value"]


def _match(conn, selector, observation):
    if matches(selector, observation):
        # Only a trusted consumer assigns a stable source-claim identity.
        # Ordinary evidence retains its original per-observation semantics.
        event = conn.execute("SELECT event_key FROM evidence_alert_subjects WHERE observation_id=?",
                             (observation["id"],)).fetchone()
        if event and conn.execute("SELECT 1 FROM evidence_alert_events WHERE selector_id=? AND event_key=?",
                                  (selector["id"], event[0])).fetchone():
            return
        conn.execute("INSERT OR IGNORE INTO evidence_alerts(selector_id,observation_id,matched_at) VALUES (?,?,?)",
                     (selector["id"], observation["id"], now()))
        if event:
            alert = conn.execute("SELECT id FROM evidence_alerts WHERE selector_id=? AND observation_id=?",
                                 (selector["id"], observation["id"])).fetchone()[0]
            conn.execute("INSERT INTO evidence_alert_events VALUES (?,?,?)", (selector["id"], event[0], alert))


def match_observation(conn, observation_id):
    """Caller owns the observation transaction. Failure rolls back both writes."""
    observation = conn.execute("SELECT * FROM evidence_observations WHERE id=?", (observation_id,)).fetchone()
    for selector in conn.execute("SELECT * FROM evidence_selectors WHERE enabled=1 ORDER BY id LIMIT ?", (MAX_SELECTORS,)):
        _match(conn, selector, observation)


def scan_page(selector_id: int, *, limit=200):
    """Explicit local catch-up, one atomic page with a persistent cursor.

    Includes existing observations and those saved while disabled. The cursor
    commits with the alerts; crashes can replay safely. No network/job dispatch.
    """
    evidence._page(limit, 0)
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        selector = conn.execute("SELECT * FROM evidence_selectors WHERE id=?", (selector_id,)).fetchone()
        if selector is None:
            raise KeyError(selector_id)
        if not selector["enabled"]:
            raise PermissionError("Selector is disabled")
        rows = conn.execute("SELECT * FROM evidence_observations WHERE id>? ORDER BY id LIMIT ?",
                            (selector["scanned_through"], limit)).fetchall()
        for row in rows:
            _match(conn, selector, row)
        cursor = rows[-1]["id"] if rows else selector["scanned_through"]
        conn.execute("UPDATE evidence_selectors SET scanned_through=? WHERE id=?", (cursor, selector_id))
        more = bool(conn.execute("SELECT 1 FROM evidence_observations WHERE id>? LIMIT 1", (cursor,)).fetchone())
        return {"processed": len(rows), "through": cursor, "more": more}


def review(ident: int, state: str, revision: int):
    if state not in STATES or type(revision) is not int or revision < 0:
        raise ValueError("Invalid review state or revision")
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM evidence_alerts WHERE id=?", (ident,)).fetchone()
        if row is None:
            raise KeyError(ident)
        if row["revision"] != revision:
            raise evidence.EvidenceConflict("Review changed; reload before reviewing")
        if row["state"] == state:
            return
        conn.execute("UPDATE evidence_alerts SET state=?,revision=revision+1 WHERE id=?", (state, ident))
        conn.execute("INSERT INTO evidence_alert_reviews VALUES (?,?,?,?)", (ident, revision+1, state, now()))


def inbox(*, state=None, before=None, limit=50):
    evidence._page(limit, 0)
    if state is not None and state not in STATES:
        raise ValueError("Invalid state filter")
    if before is not None and (type(before) is not int or before <= 0):
        raise ValueError("Invalid page cursor")
    with evidence.connect() as conn:
        return [dict(r) for r in conn.execute("""SELECT a.*,s.subject_type,s.mode,s.value,
            o.subject_value,o.assertion,o.document_id,d.title,d.source_id,d.source_published_at,d.collected_at
            FROM evidence_alerts a JOIN evidence_selectors s ON s.id=a.selector_id
            JOIN evidence_observations o ON o.id=a.observation_id JOIN evidence_documents d ON d.id=o.document_id
            WHERE (? IS NULL OR a.state=?) AND (? IS NULL OR a.id<?) ORDER BY a.id DESC LIMIT ?""",
            (state, state, before, before, limit))]


def detail(ident, *, citation_offset=0, review_offset=0):
    evidence._page(100, citation_offset)
    evidence._page(100, review_offset)
    with evidence.connect() as conn:
        row = conn.execute("SELECT * FROM evidence_alerts WHERE id=?", (ident,)).fetchone()
        if row is None:
            return None
        alert = dict(row)
        observation = dict(conn.execute("SELECT * FROM evidence_observations WHERE id=?", (alert["observation_id"],)).fetchone())
        selector = dict(conn.execute("SELECT * FROM evidence_selectors WHERE id=?", (alert["selector_id"],)).fetchone())
        reviews = [dict(r) for r in conn.execute("SELECT * FROM evidence_alert_reviews WHERE alert_id=? ORDER BY revision DESC LIMIT 100 OFFSET ?", (ident, review_offset))]
    document = evidence.get_document(observation["document_id"])
    with evidence.connect() as conn:
        execution = conn.execute("""SELECT r.id,r.job_id,r.attempt,r.state,r.error_code,
            j.state AS job_state,j.progress_done,j.progress_total,j.coverage_completed_at
            FROM durable_job_runs r JOIN durable_jobs j ON j.id=r.job_id WHERE r.id=?""",
            (document["job_run_id"],)).fetchone()
    return {"alert": alert, "observation": observation, "selector": selector, "document": document,
            "source": evidence.get_source(document["source_id"]), "archive": archives.get(document["id"]),
            "citations": evidence.citations_for_document(document["id"], offset=citation_offset), "reviews": reviews,
            "execution": dict(execution) if execution else None,
            "citation_offset": citation_offset, "review_offset": review_offset}
