"""
Settings loaded from the .env file.

pydantic-settings reads each field from an environment variable of the same
name, case-insensitively, falling back to .env. So `virustotal_api_key` is
filled from VIRUSTOTAL_API_KEY. Keys default to empty strings, which the
vendor clients treat as "not configured" rather than crashing.
"""

import ipaddress
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root is two levels up from this file (app/core/config.py -> project).
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # API keys (never logged or rendered; only their presence is shown).
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    shodan_api_key: str = ""
    urlscan_api_key: str = ""
    abusech_auth_key: str = ""
    greynoise_api_key: str = ""
    # Phase 2, both optional: NVD works without a key at a lower rate, and
    # GitHub search works without a token at 10 searches a minute.
    nvd_api_key: str = ""
    github_token: str = ""
    # ransomware.live PRO (free key from my.ransomware.live): group profiles
    # with the CVEs each group exploits. Phase 3 reuses it for victims.
    ransomwarelive_api_key: str = ""
    # HIBP direct-email API. Entitlement expiry is reviewed manually, never
    # inferred from the existence of a key or a locally watched address.
    hibp_api_key: str = ""
    hibp_subscription_until: str = ""
    # VulnCheck community token: VulnCheck KEV (broader than CISA's, with
    # citations) and the XDB exploit index. Feed wired once a key exists.
    vulncheck_api_key: str = ""

    # Server: local only by design.
    host: str = "127.0.0.1"
    port: int = 8000
    # A second explicit switch, in addition to per-source review and schedule.
    # Default startup creates metadata but dispatches no provider work.
    scheduled_feeds_enabled: bool = False
    bulk_enrichment_enabled: bool = False
    # No implicit raw retention policy. All five values are required to opt in.
    archive_enabled: bool = False
    archive_public_sources: tuple[str, ...] = Field(default=(), max_length=200)
    archive_root: Path | None = None
    archive_response_bytes: int | None = Field(default=None, gt=0, le=64*1024**2)
    archive_source_bytes: int | None = Field(default=None, gt=0, le=1024**4)
    archive_total_bytes: int | None = Field(default=None, gt=0, le=1024**4)
    archive_retention_seconds: int | None = Field(default=None, gt=0, le=366*86400)

    @field_validator("archive_root", "archive_response_bytes", "archive_source_bytes",
                     "archive_total_bytes", "archive_retention_seconds", mode="before")
    @classmethod
    def blank_archive_values(cls, value):
        return None if value == "" else value

    @model_validator(mode="after")
    def archive_policy(self):
        if self.archive_enabled:
            bounds = (self.archive_response_bytes, self.archive_source_bytes,
                      self.archive_total_bytes, self.archive_retention_seconds)
            if self.archive_root is None or any(v is None for v in bounds):
                raise ValueError("Archive enabling requires a local root and all finite limits")
            if not self.archive_response_bytes <= self.archive_source_bytes <= self.archive_total_bytes:
                raise ValueError("Archive limits must satisfy response <= source <= total")
        return self

    @field_validator("host")
    @classmethod
    def _host_must_be_loopback(cls, v: str) -> str:
        # The toolkit binds to localhost only, on purpose. Reject any
        # non-loopback host (e.g. 0.0.0.0) so a stray .env line or shell
        # variable cannot expose the app to the network without auth.
        if v == "localhost":
            return v
        try:
            if ipaddress.ip_address(v).is_loopback:
                return v
        except ValueError:
            pass
        raise ValueError(
            f"host must be loopback (127.0.0.1, ::1, or localhost); got {v!r}. "
            "The app is local-only by design."
        )

    # Where the SQLite database and other local data live (git-ignored).
    data_dir: Path = PROJECT_ROOT / "data"

    # How many rows of data/tranco.csv count as "popular enough to skip".
    # The full list is one million; the top 100k is the usual false-positive
    # suppression range. Raise or lower in .env as TRANCO_TOP_N.
    tranco_top_n: int = 100_000

    @property
    def db_path(self) -> Path:
        # The directory is created once in db.init_db(); don't mkdir on every
        # access (this property is read on every cache and quota query).
        return self.data_dir / "cti.db"


settings = Settings()
