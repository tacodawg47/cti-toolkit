"""Bounded Shodan metadata. Literal provider values survive normalization."""

from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
import json
import re

from pydantic import ConfigDict, Field, model_validator

from ...core import archives
from ...core.config import settings
from ...core.evidence_models import Metadata, instant
from ..ct_watch.matching import hostname

QUERY_VERSION = "shodan-hostname-cloud-local-v1"
API_VERSION = "host-search-fields-v1"  # Local contract; no upstream version header exists.
API = "https://api.shodan.io/shodan/host/search"
MAX_BYTES = 2 * 1024**2
MAX_PAYLOAD = 512 * 1024
PER_PAGE = 100
MAX_PAGES = 2
TYPES = ("cloud_domain",)
FIELDS = "ip_str,port,transport,hostnames,domains,org,isp,asn,product,version,timestamp,cloud.provider,cloud.region,cloud.service"


def selector(value, kind="cloud_domain"):
    if kind not in TYPES:
        raise ValueError("Use an exact authorized cloud domain")
    return hostname(value)


def within(name, seed):
    name, seed = hostname(name), selector(seed)
    return name == seed or name.endswith("." + seed)


def query(value, kind="cloud_domain"):
    # No free-text, Boolean syntax, cloud wildcards or query expansion.
    return 'hostname:"' + selector(value, kind) + '"'


def prerequisite():
    if (not settings.shodan_api_key or not settings.shodan_cloud_access_reviewed
            or settings.shodan_cloud_access_tier not in ("membership", "freelancer", "small_business", "corporate", "enterprise")):
        return "Separately reviewed Shodan search access, terms, purpose and handling are required"
    return ""


def credential_identity():
    return sha256(json.dumps([settings.shodan_api_key, settings.shodan_cloud_access_tier,
                             settings.shodan_cloud_access_reviewed, settings.shodan_cloud_monthly_credits,
                             API, FIELDS, PER_PAGE, MAX_PAGES]).encode()).hexdigest()


def provider_time(value):
    """Datapedia explicitly defines naive banner timestamps as UTC."""
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)?", value):
        raise ValueError("Invalid provider banner timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return instant(parsed.replace(tzinfo=timezone.utc).isoformat() if parsed.tzinfo is None else value)


class Literal(Metadata):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, str_strip_whitespace=False)

    @model_validator(mode="after")
    def safe_text(self):
        raw = self.model_dump_json().encode()
        if archives.secret_material(raw):
            raise ValueError("Credential-like metadata refused")
        for value in self.model_dump().values():
            if isinstance(value, str) and any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError("Control characters in metadata")
        return self


class Cloud(Literal):
    provider: str = Field(min_length=1, max_length=128)
    region: str | None = Field(default=None, max_length=128)
    service: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def attribution(self):
        if not self.provider.strip():
            raise ValueError("Cloud provider must be explicit")
        return self


class Service(Literal):
    ip_str: str = Field(min_length=2, max_length=45)
    port: int = Field(ge=1, le=65535)
    transport: str = Field(pattern="^(tcp|udp)$")
    hostnames: tuple[str, ...] = Field(max_length=32)
    domains: tuple[str, ...] = Field(default=(), max_length=32)
    org: str | None = Field(default=None, max_length=256)
    isp: str | None = Field(default=None, max_length=256)
    asn: str | None = Field(default=None, pattern=r"^AS\d{1,10}$")
    product: str | None = Field(default=None, max_length=128)
    version: str | None = Field(default=None, max_length=128)
    timestamp: str | None = Field(default=None, max_length=64)
    cloud: Cloud | None = None

    @model_validator(mode="after")
    def validate_service(self):
        ip_address(self.ip_str)  # Parse locally, never resolve.
        if "%" in self.ip_str:
            raise ValueError("Scoped IP refused")
        for name in self.hostnames + self.domains:
            if len(name) > 254:
                raise ValueError("Oversized literal name")
            hostname(name)
        provider_time(self.timestamp)
        return self

    @property
    def event(self):
        # Review identity ignores changed timestamps/products/cloud labels.
        identity = [str(ip_address(self.ip_str)), self.port, self.transport]
        return "shodan.service." + sha256(json.dumps(identity).encode()).hexdigest()


class Lead(Service):
    row_position: int = Field(ge=0, lt=PER_PAGE)
    cloud: Cloud


class Page(Metadata):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    total: int = Field(ge=0, le=2**63-1)
    returned_count: int = Field(ge=0, le=PER_PAGE)
    partial: bool = False
    service_keys: tuple[str, ...] = Field(max_length=PER_PAGE)
    leads: tuple[Lead, ...] = Field(max_length=PER_PAGE)

    @model_validator(mode="after")
    def positions(self):
        if self.total < self.returned_count or len(self.service_keys) != self.returned_count:
            raise ValueError("Inconsistent search page counts")
        positions = [lead.row_position for lead in self.leads]
        if len(set(positions)) != len(positions) or any(position >= self.returned_count for position in positions):
            raise ValueError("Inconsistent original row positions")
        if any(self.service_keys[lead.row_position] != lead.event for lead in self.leads):
            raise ValueError("Staged service identity differs")
        return self


def parse(raw, seed):
    if len(raw) > MAX_BYTES:
        raise ValueError("Search response exceeds bounds")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON field")
            result[key] = value
        return result
    body = json.loads(raw, object_pairs_hook=pairs)
    if (not isinstance(body, dict) or any(key in body for key in ("error", "errors"))
            or not isinstance(body.get("matches"), list) or len(body["matches"]) > PER_PAGE):
        raise ValueError("Expected bounded search envelope")
    leads, keys, partial = [], [], False
    for index, row in enumerate(body["matches"]):
        if not isinstance(row, dict) or any(key in row for key in ("data", "http", "html", "ssl", "opts", "screenshot", "_shodan", "content", "credentials")):
            raise ValueError("Content-bearing result; metadata projection must be verified")
        metadata = row.get("metadata")
        if metadata is not None:
            if not isinstance(metadata, dict):
                raise ValueError("Invalid projection metadata")
            truncated = metadata.get("truncated", [])
            if (not isinstance(truncated, list) or len(truncated) > 100
                    or any(not isinstance(field, str) or len(field) > 128 for field in truncated)):
                raise ValueError("Invalid truncated-field list")
            partial = partial or bool(truncated)
        fields = {key: row[key] for key in Service.model_fields if key in row}
        for key in ("hostnames", "domains"):
            if key in fields:
                if not isinstance(fields[key], list):
                    raise ValueError("Expected literal name list")
                fields[key] = tuple(fields[key])
        if fields.get("cloud") is not None:
            if not isinstance(fields["cloud"], dict):
                raise ValueError("Expected structured cloud attribution")
            fields["cloud"] = Cloud(**{key: value for key, value in fields["cloud"].items() if key in Cloud.model_fields})
        service = Service(**fields)
        keys.append(service.event)
        if service.cloud and any(within(name, seed) for name in service.hostnames):
            leads.append(Lead(**fields, row_position=index))
    for key in ("truncated", "incomplete_results", "partial"):
        if key in body:
            if type(body[key]) is not bool:
                raise ValueError("Invalid completeness flag")
            partial = partial or body[key]
    page = Page(total=body.get("total"), returned_count=len(body["matches"]), partial=partial,
                service_keys=tuple(keys), leads=tuple(leads))
    if page.total < page.returned_count or len(page.model_dump_json().encode()) > MAX_PAYLOAD:
        raise ValueError("Inconsistent or oversized normalized search page")
    return page
