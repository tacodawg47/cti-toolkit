"""CTLogs host metadata, with literal dates distinct from local capture time."""

from datetime import datetime
from hashlib import sha256
import json
import re

from pydantic import ConfigDict, Field, model_validator

from ...core.config import settings
from ...core.evidence_models import Metadata, instant
from ..ct_watch.matching import hostname

QUERY_VERSION = "ctlogs-hosts-window-v1"
API_VERSION = "v1"
API = "https://api.ctlogs.dev/v1/hosts"
MAX_BYTES = 2 * 1024**2
MAX_PAYLOAD = 256 * 1024
PER_PAGE = 100
MAX_PAGES = 2
TYPES = ("subdomain_domain",)


def selector(value, kind="subdomain_domain"):
    if kind not in TYPES:
        raise ValueError("Use an exact inventory domain")
    return hostname(value)


def within(name, seed):
    """Literal name/pattern membership. A wildcard never asserts its base."""
    seed = selector(seed)
    name = hostname(name, wildcard=True).removeprefix("*.")
    return name == seed or name.endswith("." + seed)


def order(name):
    return tuple(reversed(name.split(".")))


def query(value, kind="subdomain_domain"):
    return API + "/" + selector(value, kind)


def prerequisite():
    if not settings.ctlogs_api_key or settings.ctlogs_access_tier not in ("free_noncommercial", "paid"):
        return "A separately reviewed CTLogs key, plan and purpose are required"
    return ""


def credential_identity():
    return sha256(json.dumps([settings.ctlogs_api_key, settings.ctlogs_access_tier]).encode()).hexdigest()


def cursor(value):
    # An opaque parameter, never decoded, interpreted as a URL or executed.
    if not isinstance(value, str) or len(value) > 2048 or (value and not re.fullmatch(r"[A-Za-z0-9_+=/-]+", value)):
        raise ValueError("Invalid bounded cursor")
    return value


class Lead(Metadata):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, str_strip_whitespace=False)
    host: str = Field(min_length=1, max_length=254)  # literal provider spelling
    certs: int = Field(ge=1, le=2**63-1)
    # Provider names are misleading: these are validity starts, not SCT times.
    first_seen: str | None = Field(default=None, max_length=64)
    last_seen: str | None = Field(default=None, max_length=64)
    last_not_after: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def validate_host(self):
        hostname(self.host, wildcard=True)
        # Validate dates without rewriting their original spelling/precision.
        for value in (self.first_seen, self.last_seen, self.last_not_after):
            if value is not None:
                instant(value)
        if self.first_seen and self.last_seen and datetime.fromisoformat(instant(self.first_seen)) > datetime.fromisoformat(instant(self.last_seen)):
            raise ValueError("Reversed provider interval")
        return self

    @property
    def canonical(self):
        return hostname(self.host, wildcard=True)

    @property
    def event(self):
        return "ctlogs.host." + sha256(self.canonical.encode()).hexdigest()


class Page(Metadata):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    leads: tuple[Lead, ...] = Field(max_length=PER_PAGE)
    returned_count: int = Field(ge=0, le=PER_PAGE)
    partial: bool = False
    has_next: bool
    next_cursor: str
    history_window_days: int = Field(ge=90, le=90)

    @model_validator(mode="after")
    def pagination(self):
        cursor(self.next_cursor)
        if self.has_next != bool(self.next_cursor) or (self.has_next and not self.leads):
            raise ValueError("Inconsistent inventory pagination")
        return self


def parse(raw, seed):
    if len(raw) > MAX_BYTES:
        raise ValueError("Inventory exceeds bounds")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result
    body = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(body, dict) or "hosts" not in body:
        raise ValueError("Expected inventory envelope")
    rows = body["hosts"]
    if rows is None:  # Explicitly documented empty shape. Missing is not empty.
        rows = []
    if not isinstance(rows, list) or len(rows) > PER_PAGE:
        raise ValueError("Expected bounded hosts")
    hosts = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Expected host metadata")
        item = Lead(**{key: row[key] for key in Lead.model_fields if key in row})
        if not within(item.host, seed):
            raise ValueError("Provider name is outside the approved exact domain")
        hosts.append(item)
    partial = False
    for key in ("truncated", "incomplete_results", "history_truncated"):
        if key in body:
            if type(body[key]) is not bool:
                raise ValueError("Invalid completeness flag")
            partial = partial or body[key]
    page = Page(leads=tuple(hosts), returned_count=len(hosts), partial=partial,
                has_next=body.get("has_next"), next_cursor=body.get("next_cursor"),
                history_window_days=body.get("history_window_days"))
    if len(page.model_dump_json().encode()) > MAX_PAYLOAD:
        raise ValueError("Normalized inventory exceeds bounds")
    return page
