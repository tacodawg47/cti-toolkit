"""
Tranco domain allowlist.

Tranco (https://tranco-list.eu/) publishes a daily ranking of the top one
million websites. A domain near the top of that list is almost never worth
spending vendor quota on, so the registry skips the fan-out for an exact match
(or its "www." form) and shows one local card with the rank instead. The
"query anyway" checkbox overrides that.

Matching is deliberately EXACT, not by parent domain: "evil.github.io" must
not be allowlisted just because "github.io" is popular, since free hosting
and cloud subdomains are a favourite phishing home.

The list is a plain CSV of "rank,domain" (no header), downloaded by hand to
data/tranco.csv (see docs/runbooks/tranco-allowlist.md); nothing is fetched
automatically. If the file is missing the gate is simply off, and the health
page says so.
"""

import csv
from datetime import datetime, timezone
from pathlib import Path

from .config import settings


class Allowlist:
    def __init__(self) -> None:
        self._ranks: dict[str, int] = {}
        self.path: Path | None = None
        self.loaded_at: str | None = None
        self.file_modified: str | None = None
        self.top_n: int = 0
        self.error: str | None = None

    def load(self, path: Path | None = None, top_n: int | None = None) -> int:
        """Read the first top_n rows of the CSV. Returns the number loaded (0 if
        the file is missing or unreadable; the gate is then off and `error`
        says why, so the health page can show it). Never raises: this runs at
        startup, and a bad list file must not stop the app."""
        path = path or settings.data_dir / "tranco.csv"
        top_n = top_n if top_n is not None else settings.tranco_top_n
        self._ranks = {}
        self.path = path
        self.top_n = top_n
        self.loaded_at = None
        self.file_modified = None
        self.error = None
        if not path.is_file():
            return 0
        try:
            with path.open(newline="", encoding="utf-8") as fh:
                for row in csv.reader(fh):
                    if len(row) < 2:
                        continue
                    rank, domain = row[0].strip(), row[1].strip().lower()
                    if not rank.isdigit():
                        continue            # a header line, if one is ever added
                    self._ranks[domain] = int(rank)
                    if len(self._ranks) >= top_n:
                        break
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            self._ranks = {}
            self.error = f"could not read the list: {type(exc).__name__}"
            return 0
        self.loaded_at = datetime.now(timezone.utc).isoformat()
        self.file_modified = datetime.fromtimestamp(
            path.stat().st_mtime, timezone.utc).isoformat()
        return len(self._ranks)

    @property
    def loaded(self) -> bool:
        return bool(self._ranks)

    def rank(self, host: str) -> int | None:
        """Tranco rank for an exact host match (or its www. form), else None."""
        if not self._ranks:
            return None
        h = host.lower().rstrip(".")
        if h.startswith("www."):
            h = h[4:]
        return self._ranks.get(h)

    def status(self) -> dict:
        return {
            "loaded": self.loaded,
            "entries": len(self._ranks),
            "top_n": self.top_n,
            "path": str(self.path) if self.path else None,
            "file_modified": self.file_modified,
            "error": self.error,
        }


allowlist = Allowlist()
