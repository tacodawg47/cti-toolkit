"""
Normalized data shapes shared across vendor clients.

Every vendor client returns a VendorResult, so the UI and export code never
need to know a vendor's native JSON. `raw` keeps the useful part of the
original response for drill-down.
"""

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Verdict vocabulary used across all vendors (the actual judgement).
Verdict = Literal["malicious", "suspicious", "clean", "unknown", "error"]

# Why a result has no verdict, so the UI can style each case without parsing
# the error text: ok = we got an answer; not_configured = no API key; quota =
# daily/minute cap reached; error = the lookup failed.
Status = Literal["ok", "not_configured", "quota", "error"]


class VendorResult(BaseModel):
    source: str                                   # e.g. "virustotal"
    indicator: str                                # the value looked up
    indicator_type: str                           # ip | domain | hash | url
    verdict: Verdict = "unknown"
    status: Status = "ok"
    detection_ratio: str | None = None            # e.g. "12/89"
    summary: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] | None = None
    error: str | None = None
    cached: bool = False
    query_time: str = Field(default_factory=now_iso)
