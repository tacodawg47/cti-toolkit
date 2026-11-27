"""Allowlisted references only. Never request snippets, blobs or file contents."""

from hashlib import sha256
import json
import re

from pydantic import ConfigDict, Field, model_validator

from ...core import archives
from ...core.config import settings
from ...core.evidence_models import Metadata
from ..ct_watch.matching import hostname

QUERY_VERSION = "github-legacy-file-v1"
API_VERSION = "2022-11-28"  # Still supported; leave existing Phase 2 clients unchanged.
MAX_BYTES = 2 * 1024**2
MAX_PAYLOAD = 256 * 1024
PER_PAGE = 50
MAX_PAGES = 2
TYPES = ("github_domain", "github_organization")


def selector(value, kind):
    if kind not in TYPES or not isinstance(value, str) or value != value.strip():
        raise ValueError("Use an explicit GitHub organization or domain selector")
    if kind == "github_domain":
        value = hostname(value)
    else:
        # Explicit organization text, not an inferred GitHub owner/account.
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9 -]{2,79}", value) or "  " in value:
            raise ValueError("Use 3 to 80 plain organization characters")
        if any(word.upper() in ("AND", "OR", "NOT") for word in value.split()):
            raise ValueError("Search operators are not selector text")
        value = value.lower()
    if len(value) > 200 or archives.secret_material(value.encode()) or re.search(r"(?i)(?:gh[pousr]_|github_pat_|AKIA)[a-z0-9_]{8,}", value):
        raise ValueError("Unsafe or oversized query selector")
    return value


def query(value, kind):
    return '"' + selector(value, kind) + '" in:file'


def credential_identity():
    return sha256(settings.github_exposure_token.encode()).hexdigest()


def prerequisite():
    if not settings.github_exposure_token or not settings.github_exposure_public_only:
        return "A separately reviewed public-only search token is required"
    return ""


class Lead(Metadata):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, str_strip_whitespace=False)
    repository_id: int = Field(gt=0, le=2**63-1)
    repository: str = Field(min_length=3, max_length=140)
    path: str = Field(min_length=1, max_length=512)
    blob_sha: str = Field(pattern=r"^[a-f0-9]{40}$")
    html_url: str = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def reference(self):
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}", self.repository):
            raise ValueError("Unexpected repository reference")
        if self.repository.split("/")[1] in (".", ".."):
            raise ValueError("Invalid repository")
        if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", part) or part in (".", "..") for part in self.path.split("/")):
            raise ValueError("Unexpected file reference")
        prefix = "https://github.com/" + self.repository + "/blob/"
        tail = self.html_url.removeprefix(prefix)
        ref, sep, path = tail.partition("/")
        if not self.html_url.startswith(prefix) or not sep or path != self.path or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", ref):
            raise ValueError("Inconsistent literal provider reference")
        raw = self.model_dump_json().encode()
        if archives.secret_material(raw) or re.search(rb"(?i)(?:gh[pousr]_|github_pat_|AKIA)[a-z0-9_]{8,}", raw):
            raise ValueError("Credential-like reference refused")
        return self

    @property
    def event(self):
        # New blob revisions retain review history for the same provider file.
        return "github.code." + sha256(json.dumps([self.repository_id, self.path]).encode()).hexdigest()


class Page(Metadata):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    total_count: int = Field(ge=0, le=2**63-1)
    incomplete_results: bool
    returned_count: int = Field(ge=0, le=PER_PAGE)
    leads: tuple[Lead, ...]


def parse(raw):
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
    if not isinstance(body, dict) or not isinstance(body.get("items"), list) or len(body["items"]) > PER_PAGE:
        raise ValueError("Expected a bounded code search page")
    leads, seen = [], {}
    for item in body["items"]:
        if not isinstance(item, dict) or any(field in item for field in ("text_matches", "content", "encoding")):
            raise ValueError("Unexpected content-bearing search result")
        repo = item.get("repository")
        if not isinstance(repo, dict) or repo.get("private") is not False or repo.get("visibility", "public") != "public":
            raise ValueError("Expected explicitly public repository metadata")
        lead = Lead(repository_id=repo.get("id"), repository=repo.get("full_name"), path=item.get("path"),
                    blob_sha=item.get("sha"), html_url=item.get("html_url"))
        identity = (lead.repository_id, lead.path)
        if identity in seen and seen[identity] != lead:
            raise ValueError("Conflicting file identity in search page")
        if identity not in seen:
            leads.append(lead)
            seen[identity] = lead
    # Tuple conversion is deliberate, after validating the provider list shape.
    page = Page(total_count=body.get("total_count"), incomplete_results=body.get("incomplete_results"),
                returned_count=len(body["items"]), leads=tuple(leads))
    if page.total_count < page.returned_count or len(page.model_dump_json().encode()) > MAX_PAYLOAD:
        raise ValueError("Inconsistent or oversized normalized search page")
    return page
