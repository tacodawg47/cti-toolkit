"""Small normalized claim contract. Provider adapters must map explicit fields."""

from datetime import datetime
from hashlib import sha256
import json

from pydantic import ConfigDict, Field, field_validator

from ...core import alerts, archives
from ...core.evidence_models import Metadata, source_time


class Claim(Metadata):
    # Post lookup uses the literal title, including leading/trailing whitespace.
    # Watch normalization is separate from the provider's identity and citation.
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)
    group: str = Field(min_length=1, max_length=256)
    organization: str = Field(min_length=1, max_length=512)
    website: str = Field(default="", max_length=2048)
    reference: str = Field(default="", max_length=2048)
    discovered_literal: str = Field(default="", max_length=64)
    sector: str | None = Field(default=None, min_length=1, max_length=128)
    country: str | None = Field(default=None, min_length=2, max_length=2)

    @field_validator("group", "organization")
    @classmethod
    def named(cls, value):
        if not value.strip():
            raise ValueError("Use a nonblank source name")
        return value

    @field_validator("discovered_literal")
    @classmethod
    def date_valid(cls, value):
        if value:
            # A naive upstream value stays literal. Never invent its timezone.
            datetime.fromisoformat(value)
        return value

    @field_validator("sector", "country")
    @classmethod
    def typed_value(cls, value, info):
        return alerts.normalize_subject(info.field_name, value) if value is not None else None

    @property
    def discovered_at(self):
        try:
            return source_time(self.discovered_literal or None)
        except ValueError:
            return None

    @property
    def key(self):
        # RansomLook identifies a post by group and exact title. No domain or
        # corporate alias inference. Different groups remain separate claims.
        return sha256(json.dumps([self.group.casefold(), self.organization], ensure_ascii=True).encode()).hexdigest()

    def subjects(self):
        result = [("organization", self.organization)]
        result.extend((kind, getattr(self, kind)) for kind in ("sector", "country") if getattr(self, kind))
        return result


def parse_recent(raw):
    if len(raw) > 2 * 1024**2:
        raise ValueError("Response exceeds bounds")
    rows = json.loads(raw)
    if not isinstance(rows, list) or not rows or len(rows) > 100:
        raise ValueError("Expected one nonempty recent-post snapshot of at most 100 rows")
    claims = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid post")
        # Deliberate allowlist. No HTML, screenshot, description, credentials,
        # or undocumented sector/country fields enter normalized metadata.
        claim = Claim(group=row.get("group_name"), organization=row.get("post_title"),
                      website=row.get("website") or "", reference=row.get("link") or "",
                      discovered_literal=row.get("discovered") or "")
        if archives.secret_material(claim.model_dump_json().encode()):
            raise ValueError("Credential-like metadata refused")
        claims.append(claim)
    identities = [c.key for c in claims]
    if len(set(identities)) != len(identities):
        raise ValueError("Duplicate post identities in snapshot")
    return claims
