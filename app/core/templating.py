"""
The one Jinja2 environment every route module renders with.

Lives in core (not app.main) so module routers can import it without a
circular import. The filters registered here are available in every template.
"""

from datetime import datetime, timezone
from pathlib import Path

from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def fmt(v):
    """Render a summary value: lists as 'a, b', dicts as 'k: v, ...', else as-is."""
    if isinstance(v, dict):
        return ", ".join(f"{k}: {val}" for k, val in v.items())
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    return v


def ago(iso: str | None) -> str:
    """Turn an ISO timestamp into a short relative age like '2h ago'."""
    try:
        t = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return ""
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    secs = (datetime.now(timezone.utc) - t).total_seconds()
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


def day(iso: str | None) -> str:
    """Just the date part of an ISO timestamp, or '—'."""
    return iso[:10] if iso else "—"


templates.env.filters["fmt"] = fmt
templates.env.filters["ago"] = ago
templates.env.filters["day"] = day
