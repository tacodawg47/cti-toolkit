"""Atomic, replayable report metadata and mention saves. All inputs are passive."""

from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from ...core import archives, evidence
from ...core.evidence_models import Citation, Document, Metadata, Observation, source_time
from ...core.indicators import canonical
from . import content, extractor

PARSER_VERSION = "report-save-1"


def digest_json(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


class ReportMetadata(Metadata):
    capture_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.-]+$")
    title: str = Field(min_length=1, max_length=1024)
    publisher: str = Field(min_length=1, max_length=256)
    source_url: str | None = Field(default=None, max_length=2048)
    source_published_at: str | None = None
    publication_unknown: bool = False
    source_modified_at: str | None = None
    observed_at: str | None = None
    sensitivity: Literal["unknown", "public", "sensitive"] = "unknown"
    tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] | None = None
    citations: tuple[str, ...] = Field(default=(), max_length=100)

    _dates = field_validator("source_published_at", "source_modified_at", "observed_at")(source_time)

    @model_validator(mode="after")
    def required_source(self):
        if self.source_published_at is None and not self.publication_unknown:
            raise ValueError("Supply the publication date or explicitly mark it unknown")
        if self.source_published_at and self.publication_unknown:
            raise ValueError("A publication date cannot also be unknown")
        for value in (self.source_url, *self.citations):
            if value and (len(value) > 2048 or archives.secret_material(value.encode())):
                raise ValueError("Source references must be bounded and credential-free")
            if value and any(word in value.lower() for word in ("token=", "api_key=", "password=", "secret=")):
                raise ValueError("Source references must be credential-free")
        if any(not value.strip() for value in self.citations):
            raise ValueError("Citation references cannot be blank")
        return self


def extract_report(document):
    content.prepare_text(document)
    return extractor.extract(document.indicator_text or "", report_mode=True, report_references=document.references)


def save(document, raw: bytes, metadata: ReportMetadata, *, origin: str,
         collected_at: str | None = None, media_type="application/octet-stream", job_run_id=None):
    """An unchanged form/capture replays original time and originating run.

    Changed bytes, metadata, parser output or citations create a new capture.
    A fresh capture_id deliberately records another acquisition of equal bytes.
    All document/mention/citation writes commit together before raw retention.
    """
    if origin not in ("report", "file", "paste") or not isinstance(raw, bytes) or len(raw) > 10*1024**2:
        raise ValueError("Use a bounded report, file or paste input")
    if len(document.text) > extractor.MAX_TEXT_CHARS:
        raise ValueError("Report exceeds the extraction character limit")
    if archives.secret_material(raw):
        raise ValueError("Credential-like content requires a separate private handling workflow")
    result = extract_report(document)
    if result.truncated or len(result.items) > 2000:
        raise ValueError("Split the report into bounded saves")
    references = list(metadata.citations)
    for ref in document.references:
        if ref.get("value") and ref["value"] not in references:
            references.append(ref["value"])
    if len(references) > 100:
        raise ValueError("Report citation limit exceeded")
    # Validate all citations before any write. Literal references are not
    # followed, normalized, or merged into a supposed primary source.
    citations = [Citation(document_id=1, citation_key=digest_json([i, ref]), target_reference=ref,
                          locator=f"report reference {i+1}") for i, ref in enumerate(references)]
    if any(archives.secret_material(c.target_reference.encode()) for c in citations):
        raise ValueError("Citation contains credential-like content")
    raw_digest = sha256(raw).hexdigest()
    if document.final_url and (archives.secret_material(document.final_url.encode()) or
                              any(word in document.final_url.lower() for word in ("token=", "api_key=", "password=", "secret="))):
        raise ValueError("Capture reference contains credential-like content")
    subjects = [{"type": i.type, "value": canonical(i.type, i.value), "count": i.count,
                 "excerpt": i.excerpt or ""} for i in result.items]
    manifest = digest_json({"metadata": metadata.model_dump(mode="json"), "raw": raw_digest,
                            "subjects": subjects, "references": references, "origin": origin,
                            "parser": PARSER_VERSION, "job_run_id": job_run_id, "captured_reference": document.final_url})
    source_identity = metadata.publisher
    if metadata.source_url:
        try:
            source_identity += ":" + (urlsplit(metadata.source_url).hostname or "")
        except ValueError:
            raise ValueError("Invalid source URL") from None
    source_id = "report." + sha256(source_identity.encode()).hexdigest()[:32]
    proposed = Document(source_id=source_id, external_id=document.final_url or metadata.source_url or metadata.title,
                        capture_key=manifest, title=metadata.title, publisher=metadata.publisher,
                        source_url=metadata.source_url, kind=origin,
                        collection_method={"report": "public_page", "file": "manual_file", "paste": "manual_paste"}[origin],
                        source_published_at=metadata.source_published_at, source_modified_at=metadata.source_modified_at,
                        collected_at=collected_at or datetime.now(timezone.utc).isoformat(),
                        content_sha256=raw_digest, sensitivity=metadata.sensitivity, tlp=metadata.tlp,
                        job_run_id=job_run_id)
    with evidence.connect() as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        previous = conn.execute("SELECT * FROM evidence_report_saves WHERE save_key=?", (manifest,)).fetchone()
        if previous:
            ident = previous["document_id"]
        else:
            evidence._ensure_source(conn, source_id)
            ident = evidence._snapshot(conn, "evidence_documents", proposed, ("source_id", "external_id", "capture_key"))
            for i, item in enumerate(subjects):
                mention = Observation(document_id=ident, observation_key=digest_json([item["type"], item["value"]]),
                                      subject_type=item["type"], subject_value=item["value"],
                                      observed_at=metadata.observed_at,
                                      excerpt=item["excerpt"] if metadata.sensitivity == "public" else "",
                                      locator=f"extracted mention {i+1}; occurrences={item['count']}")
                observation_id = evidence._snapshot(conn, "evidence_observations", mention, ("document_id", "observation_key"))
                from ...core.alerts import match_observation

                match_observation(conn, observation_id)
            for citation in citations:
                evidence._snapshot(conn, "evidence_citations", citation.model_copy(update={"document_id": ident}),
                                   ("document_id", "citation_key"))
            conn.execute("INSERT INTO evidence_report_saves VALUES (?,?,?,1,?,?)",
                         (manifest, ident, manifest, len(subjects), PARSER_VERSION))
    archives.retain(ident, raw, media_type=media_type,
                    representation="utf8_paste" if origin == "paste" else "uploaded_file" if origin == "file" else "entity_bytes")
    return ident


def list_reports(limit=100):
    evidence._page(limit, 0)
    with evidence.connect() as conn:
        return [dict(row) for row in conn.execute("""SELECT d.*,s.indicator_count,
            CASE WHEN a.state IN ('stored','pending') AND a.expires_at<=? THEN 'expired' ELSE a.state END AS archive_state,
            CASE WHEN a.state IN ('stored','pending') AND a.expires_at<=? THEN 'retention_elapsed' ELSE a.reason END AS archive_reason
            FROM evidence_report_saves s JOIN evidence_documents d ON d.id=s.document_id
            LEFT JOIN evidence_archives a ON a.document_id=d.id WHERE s.complete=1 ORDER BY d.id DESC LIMIT ?""",
            (archives.now().isoformat(timespec="microseconds"), archives.now().isoformat(timespec="microseconds"), limit))]


def detail(ident):
    with evidence.connect() as conn:
        row = conn.execute("SELECT * FROM evidence_report_saves WHERE document_id=? AND complete=1", (ident,)).fetchone()
        if row is None:
            return None
        observations = [dict(r) for r in conn.execute("SELECT * FROM evidence_observations WHERE document_id=? ORDER BY id LIMIT 2000", (ident,))]
        results = [dict(r) for r in conn.execute("SELECT * FROM evidence_bulk_results WHERE document_id=? ORDER BY job_id,unit_key LIMIT 200", (ident,))]
        jobs = [dict(r) for r in conn.execute("""SELECT id,state,progress_done,progress_total,error_code FROM durable_jobs
            WHERE task='reports.enrich' AND json_extract(params,'$.document_id')=? ORDER BY created_at DESC,id DESC LIMIT 200""", (ident,))]
    return {"document": evidence.get_document(ident), "observations": observations,
            "citations": evidence.citations_for_document(ident), "archive": archives.get(ident), "bulk_results": results, "jobs": jobs}
