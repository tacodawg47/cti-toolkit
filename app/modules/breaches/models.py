"""Original allowlist parser from HIBP v3 docs. Never retain source records."""

import json
import re
from datetime import datetime

from pydantic import ConfigDict, Field, StrictBool, field_validator

from ...core import archives
from ...core.evidence_models import Metadata, source_time

MAX_BYTES = 1024**2


class Breach(Metadata):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    title: str = Field(min_length=1, max_length=256)
    breach_date: str | None = None
    added_date: str | None = None
    modified_date: str | None = None
    verified: StrictBool | None = None
    fabricated: StrictBool | None = None
    spam_list: StrictBool | None = None
    malware: StrictBool | None = None
    stealer_log: StrictBool | None = None
    disclosure: str = Field(default="", max_length=2048)
    attribution: str = Field(default="", max_length=2048)

    @field_validator("breach_date", "added_date", "modified_date")
    @classmethod
    def dates(cls, value, info):
        if value is None:
            return None
        if info.field_name == "breach_date":
            source_time(value)
        else:
            # The docs include minute-precision examples. Retain literal
            # precision/offset rather than manufacturing seconds or a timezone.
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:\d{2})", value):
                raise ValueError("Use an aware provider date")
            parsed = datetime.fromisoformat(value)
            if parsed.utcoffset() is None:
                raise ValueError("Timezone required")
        return value


def parse(raw, status):
    if len(raw) > MAX_BYTES:
        raise ValueError("Response exceeds bounds")
    if status == 404 and raw == b"":
        return []
    if status != 200:
        raise ValueError("Unexpected response")
    rows = json.loads(raw)
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        raise ValueError("Expected 1 to 100 associations")
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid association")
        # No descriptions, passwords, tokens, logos, account records or unknown
        # fields. Literal disclosure references stay passive, never fetched.
        selected = {target: row.get(source) for source, target in (
            ("Name", "name"), ("Title", "title"), ("BreachDate", "breach_date"),
            ("AddedDate", "added_date"), ("ModifiedDate", "modified_date"),
            ("IsVerified", "verified"), ("IsFabricated", "fabricated"),
            ("IsSpamList", "spam_list"), ("IsMalware", "malware"), ("IsStealerLog", "stealer_log"))}
        selected["disclosure"] = row.get("DisclosureUrl") or ""
        selected["attribution"] = row.get("Attribution") or ""
        for field in ("breach_date", "added_date", "modified_date"):
            if selected[field] == "":
                selected[field] = None
        if selected["breach_date"] and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", selected["breach_date"]):
            raise ValueError("Breach date must retain date precision")
        item = Breach(**selected)
        if not item.title.strip() or archives.secret_material(item.model_dump_json().encode()):
            raise ValueError("Unsafe metadata")
        result.append(item)
    if len({item.name for item in result}) != len(result):
        raise ValueError("Duplicate breach identity")
    return result
