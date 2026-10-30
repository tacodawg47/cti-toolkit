"""
Settings loaded from the .env file.

pydantic-settings reads each field from an environment variable of the same
name, case-insensitively, falling back to .env. So `virustotal_api_key` is
filled from VIRUSTOTAL_API_KEY. Keys default to empty strings, which the
vendor clients treat as "not configured" rather than crashing.
"""

import ipaddress
from pathlib import Path

from pydantic import field_validator
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

    # Server: local only by design.
    host: str = "127.0.0.1"
    port: int = 8000

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

    @property
    def db_path(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "cti.db"


settings = Settings()
