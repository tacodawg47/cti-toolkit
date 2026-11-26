"""Validated metadata for the shared corpus. No fetching or content execution."""

import re
from datetime import date, datetime, time, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def source_time(value: str | None) -> str | None:
    """Keep date-only precision; normalize aware instants to UTC. Unknown is None."""
    if value is None:
        return None
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return date.fromisoformat(value).isoformat()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)", value):
        raise ValueError("Use YYYY-MM-DD or an ISO timestamp with seconds and timezone")
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc).isoformat(timespec="microseconds")
    except OverflowError as exc:
        raise ValueError("Timestamp is outside the supported UTC range") from exc


def instant(value: str) -> str:
    result = source_time(value)
    if result is None or len(result) == 10:
        raise ValueError("Collection time requires an aware timestamp")
    return result


def review_day(value: str | None) -> str | None:
    if value is not None:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            raise ValueError("Review dates require YYYY-MM-DD")
        return date.fromisoformat(value).isoformat()
    return None


def _bound(value: str, end: bool = False) -> datetime:
    if len(value) == 10:
        return datetime.combine(date.fromisoformat(value), time.max if end else time.min, timezone.utc)
    return datetime.fromisoformat(value)


class Metadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class Source(Metadata):
    source_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    name: str = Field(min_length=1, max_length=256)
    homepage: str | None = Field(default=None, max_length=2048)
    source_class: Literal["unknown", "publisher", "aggregator", "legitimate_platform", "criminal_operated", "local"] = "unknown"
    access_method: Literal["unknown", "api", "feed", "public_page", "manual"] = "unknown"
    reliability: Literal["A", "B", "C", "D", "E", "F"] = "F"
    terms_status: Literal["unreviewed", "approved", "restricted", "denied"] = "unreviewed"
    terms_reviewed_on: str | None = None
    terms_reference: str | None = Field(default=None, min_length=1, max_length=2048)
    collection_enabled: bool = False
    rate_limit_notes: str | None = Field(default=None, min_length=1, max_length=2048)
    license_name: str | None = Field(default=None, min_length=1, max_length=256)
    license_reference: str | None = Field(default=None, min_length=1, max_length=2048)
    license_recorded_on: str | None = None
    review_notes: str = Field(default="", max_length=4096)

    _review_dates = field_validator("terms_reviewed_on", "license_recorded_on")(review_day)

    @model_validator(mode="after")
    def review_contract(self):
        if self.terms_status != "unreviewed" and not (self.terms_reviewed_on and self.terms_reference):
            raise ValueError("A terms decision needs a date and reference")
        if self.license_name and not (self.license_reference and self.license_recorded_on):
            raise ValueError("A license finding needs a dated reference")
        if self.collection_enabled and not self.eligible:
            raise ValueError("Collection needs approved terms, known class/method and rate-limit notes")
        return self

    @property
    def eligible(self) -> bool:
        return bool(self.collection_enabled and self.terms_status == "approved"
                    and self.terms_reviewed_on and self.terms_reference
                    and self.source_class != "unknown" and self.access_method != "unknown"
                    and self.rate_limit_notes)


class Document(Metadata):
    source_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]*$")
    external_id: str = Field(min_length=1, max_length=2048)
    capture_key: str = Field(min_length=1, max_length=256)
    source_revision: str | None = Field(default=None, min_length=1, max_length=256)
    title: str = Field(min_length=1, max_length=1024)
    publisher: str | None = Field(default=None, max_length=256)
    source_url: str | None = Field(default=None, max_length=2048)
    kind: Literal["report", "post", "paste", "file", "api_response", "feed"] = "report"
    collection_method: Literal["api", "feed", "public_page", "manual_paste", "manual_file", "local_import"]
    source_published_at: str | None = None
    source_modified_at: str | None = None
    collected_at: str
    content_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    sensitivity: Literal["unknown", "public", "sensitive"] = "unknown"
    tlp: Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"] | None = None
    job_run_id: str | None = Field(default=None, min_length=1, max_length=128)

    _source_dates = field_validator("source_published_at", "source_modified_at")(source_time)
    _collection_date = field_validator("collected_at")(instant)


class Observation(Metadata):
    document_id: int = Field(gt=0)
    observation_key: str = Field(min_length=1, max_length=256)
    subject_type: str = Field(min_length=1, max_length=64)
    subject_value: str = Field(min_length=1, max_length=2048)
    assertion: Literal["mention", "reported", "direct_observation"] = "mention"
    observed_at: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    excerpt: str = Field(default="", max_length=4096)
    locator: str = Field(default="", max_length=1024)

    _dates = field_validator("observed_at", "first_seen", "last_seen")(source_time)

    @model_validator(mode="after")
    def ordered_interval(self):
        if self.first_seen and self.last_seen and _bound(self.first_seen) > _bound(self.last_seen, end=True):
            raise ValueError("first_seen must not follow last_seen")
        return self


class Citation(Metadata):
    document_id: int = Field(gt=0)
    citation_key: str = Field(min_length=1, max_length=256)
    target_reference: str = Field(min_length=1, max_length=2048)
    target_document_id: int | None = Field(default=None, gt=0)
    relationship: Literal["cites", "derived_from", "republishes"] = "cites"
    excerpt: str = Field(default="", max_length=4096)
    locator: str = Field(default="", max_length=1024)
    resolution_note: str = Field(default="", max_length=2048)

    @model_validator(mode="after")
    def resolved_target(self):
        if self.target_document_id == self.document_id:
            raise ValueError("A citation cannot target itself")
        if self.target_document_id and not self.resolution_note:
            raise ValueError("Resolving a citation needs an explicit note")
        return self


class SourceLink(Metadata):
    source_id: str = Field(min_length=1, max_length=128)
    upstream_source_id: str = Field(min_length=1, max_length=128)
    relationship: Literal["derived_from", "republishes"]
    scope: str = Field(min_length=1, max_length=1024)
    evidence_reference: str = Field(min_length=1, max_length=2048)
    recorded_on: str

    _day = field_validator("recorded_on")(review_day)

    @model_validator(mode="after")
    def different_sources(self):
        if self.source_id == self.upstream_source_id:
            raise ValueError("Source lineage needs distinct sources")
        return self
