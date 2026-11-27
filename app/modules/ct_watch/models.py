"""Allowlisted provisional crt.sh JSON fields. No source service code."""

from datetime import datetime
import json
import re

from pydantic import ConfigDict, Field, field_validator

from ...core import archives
from ...core.evidence_models import Metadata
from .matching import hostname

MAX_BYTES = 2*1024**2
MAX_PAYLOAD = 512*1024
MAX_CANDIDATES = 1000


class Candidate(Metadata):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)
    certificate_id: str = Field(min_length=1, max_length=24, pattern=r"^[0-9]+$")
    name: str = Field(min_length=1, max_length=253)
    literal_name: str = Field(min_length=1, max_length=254)
    entry_timestamp: str | None = Field(default=None, max_length=64)
    not_before: str | None = Field(default=None, max_length=64)
    not_after: str | None = Field(default=None, max_length=64)

    @field_validator("entry_timestamp", "not_before", "not_after")
    @classmethod
    def literal_date(cls, value):
        if value is not None:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)?", value):
                raise ValueError("Unexpected provider date")
            datetime.fromisoformat(value)
        return value  # Naive dates remain literal, with no invented timezone.


def parse(raw):
    if len(raw) > MAX_BYTES:
        raise ValueError("CT response exceeds bounds")
    rows = json.loads(raw)
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError("Expected at most 200 certificate rows")
    result, seen, identities = [], set(), {}
    names_checked = 0
    for row in rows:
        if not isinstance(row, dict) or type(row.get("id")) is not int or row["id"] <= 0:
            raise ValueError("Expected a positive certificate id")
        names = row.get("name_value")
        if not isinstance(names, str) or not names or len(names) > 12800:
            raise ValueError("Expected bounded certificate names")
        names = names.split("\n")
        if len(names) > 50:
            raise ValueError("Too many certificate names")
        selected = {name: row.get(name) for name in ("entry_timestamp", "not_before", "not_after")}
        identity = json.dumps([names, selected], sort_keys=True)
        if row["id"] in identities and identities[row["id"]] != identity:
            raise ValueError("Conflicting certificate identity")
        identities[row["id"]] = identity
        for literal in names:
            names_checked += 1
            if names_checked > MAX_CANDIDATES:
                raise ValueError("Too many names in a bounded snapshot")
            item = Candidate(certificate_id=str(row["id"]), name=hostname(literal, wildcard=True),
                             literal_name=literal, **selected)
            if archives.secret_material(item.model_dump_json().encode()):
                raise ValueError("Unsafe certificate metadata")
            key = (item.certificate_id, item.name, item.literal_name)
            if key not in seen:
                result.append(item)
                seen.add(key)
    return result
