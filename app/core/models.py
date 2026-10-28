"""
Normalized data shapes shared across vendor clients.

Every vendor client returns a VendorResult, so the UI and export code never
need to know a vendor's native JSON. `raw` keeps the useful part of the
original response for drill-down.
"""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# Verdict vocabulary used across all vendors.
VERDICTS = ("malicious", "suspicious", "clean", "unknown", "error")


class VendorResult(BaseModel):
    source: str                                   # e.g. "virustotal"
    indicator: str                                # the value looked up
    indicator_type: str                           # ip | domain | hash | url
    verdict: str = "unknown"
    detection_ratio: str | None = None            # e.g. "12/89"
    summary: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] | None = None
    error: str | None = None
    cached: bool = False
    query_time: str = Field(default_factory=now_iso)
