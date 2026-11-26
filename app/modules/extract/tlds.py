"""Offline TLD validation; optional runtime IANA snapshot, no lookup per IOC."""

from pathlib import Path
from functools import lru_cache
from ...core.config import settings

URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
# Independently keyed common delegated TLDs plus documented special-use names.
# The full official list is fetched at runtime, never a DNS probe of an IOC.
FALLBACK = frozenset("com org net edu gov mil int io ai app dev co uk us au ca de fr nl ru cn ch jp in br it es se no fi pl be at cz dk nz za kr tw hk sg me tv cc xyz info biz online site tech cloud shop top zip pro live name mobi museum travel asia eu club network systems solutions space world news digital security click link today store website agency social work download example test invalid onion local localhost".split())


def path() -> Path:
    return settings.data_dir / "iana-tlds.txt"


@lru_cache(maxsize=8)
def _labels(filename: str, modified: int) -> frozenset:
    try:
        labels = frozenset(line.strip().lower() for line in Path(filename).read_text(encoding="ascii").splitlines()
                           if line and not line.startswith("#"))
    except (OSError, UnicodeError):
        labels = frozenset()
    return labels | FALLBACK


def known(host: str) -> bool:
    filename = path()
    try:
        modified = filename.stat().st_mtime_ns
    except OSError:
        modified = 0
    return host.rsplit(".", 1)[-1].lower() in _labels(str(filename), modified)


async def refresh() -> str | None:
    from ..vulnerability_intelligence.http import fetch_bytes
    status, body, error = await fetch_bytes(URL, max_bytes=128000, follow_redirects=False)
    if error or status != 200:
        return "IANA TLD catalog: " + (error or f"HTTP {status}")
    try:
        text = body.decode("ascii")
        values = [line for line in text.splitlines() if line and not line.startswith("#")]
        if len(values) < 500 or any(not value.replace("-", "").isalnum() for value in values):
            raise ValueError("invalid TLD list")
        path().parent.mkdir(parents=True, exist_ok=True)
        path().write_text(text, encoding="ascii")
    except (ValueError, UnicodeError, OSError):
        return "IANA TLD catalog could not be saved; common-TLD fallback remains available"
    return None
