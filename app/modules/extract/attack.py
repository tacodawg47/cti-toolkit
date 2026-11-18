"""Identify ATT&CK references and recover procedure evidence from HTML tables."""

import re
from collections import Counter

from .html import Document, Table

_ID = re.compile(r"(?<![\w.-])(?:T[0-9]{4}(?:[./][0-9]{3})?|[SG][0-9]{4})(?![\w]|[./][0-9])", re.I)
_SECTIONS = {"T": "techniques", "S": "software", "G": "groups"}
_PROCEDURE_HEADERS = {
    "use", "procedure", "example", "description", "evidence", "observed behavior", "observed activity",
    "annotation", "notes", "summary", "code behavior", "where it appears", "threat actor action",
}
_NAME_HEADERS = {"technique", "technique title", "technique name", "sub-technique", "name"}


def ids(text: str) -> list[str]:
    return [match[0].upper().replace("/", ".") for match in _ID.finditer(text)]


def _name(text: str) -> str:
    return text.strip(" *|`").casefold()


def _table_evidence(table: Table, objects: dict, tactics: dict) -> list[tuple[str, dict]]:
    id_matches = Counter()
    for row in table.rows:
        for col, value in enumerate(row):
            if any(ident.startswith("T") and ident in objects for ident in ids(value)):
                id_matches[col] += 1
    if not id_matches:
        return []
    id_col = id_matches.most_common(1)[0][0]
    header = next((row for row in table.rows[:3] if any(_name(v) in _PROCEDURE_HEADERS | _NAME_HEADERS for v in row)
                   and not any(ids(value) for value in row)), [])
    if id_matches[id_col] < 2 and not any(_name(value) in _PROCEDURE_HEADERS for value in header):
        return []

    tactic_labels = {_name(tactic["name"]): tactic for tactic in tactics.values()}
    tactic_labels.update({key.casefold(): tactic for key, tactic in tactics.items()})
    tactic_labels.setdefault("defense evasion", {"name": "Defense Evasion", "slug": "defense-evasion"})
    context = next((tactic for key, tactic in tactic_labels.items()
                    if re.search(r"(?<!\w)" + re.escape(key) + r"(?!\w)", table.caption.casefold())), None)
    name_hint = next((col for col, value in enumerate(header) if _name(value) in _NAME_HEADERS and col != id_col), None)
    use_hint = next((col for col, value in enumerate(header) if _name(value) in _PROCEDURE_HEADERS and col != id_col), None)

    result = []
    for row in table.rows:
        if row is header:
            continue
        tactic_cols = {col: tactic_labels[_name(value)] for col, value in enumerate(row)
                       if _name(value) in tactic_labels}
        if tactic_cols:
            context = next(iter(tactic_cols.values()))
        matches = list(dict.fromkeys(
            ident for ident in ids(row[id_col]) if ident.startswith("T") and ident in objects
        )) if id_col < len(row) else []
        if not matches:
            continue
        names = {_name(objects[ident]["name"]) for ident in matches}
        name_cols = {col for col, value in enumerate(row) if col != id_col and _name(value) in names}
        name_col = min(name_cols) if name_cols else name_hint
        remaining = [col for col, value in enumerate(row) if value and col != id_col
                     and col != name_col and col not in tactic_cols and col not in name_cols]
        use_col = use_hint if use_hint in remaining else max(remaining, key=lambda col: len(row[col]), default=None)
        published_name = row[name_col] if name_col is not None and name_col < len(row) else ""
        for ident in matches:
            official = objects[ident]
            slug = context["slug"] if context else ""
            valid_tactics = set(official["tactics"])
            if valid_tactics.intersection(("stealth", "defense-impairment")):
                valid_tactics.add("defense-evasion")
            result.append((ident, {
                "caption": table.caption, "procedure": row[use_col] if use_col is not None else "",
                "tactic": context["name"] if context else "", "shared": len(matches) > 1,
                "tactic_mismatch": bool(slug and valid_tactics and slug not in valid_tactics),
                "name_mismatch": published_name if published_name and not name_cols and _name(published_name) != _name(official["name"]) else "",
            }))
    return result


def extract(document: Document, catalog: dict) -> list[dict]:
    """Keep a syntactic ID hit even if the local catalog cannot verify it."""
    objects = catalog.get("objects", {})
    tactics = catalog.get("tactics", {})
    evidence = {}
    for table in document.tables:
        for ident, finding in _table_evidence(table, objects, tactics):
            rows = evidence.setdefault(ident, [])
            if finding not in rows and len(rows) < 20:
                rows.append(finding)
    output = []
    for ident, count in Counter(ids(document.text)).items():
        official = objects.get(ident, {})
        status = official.get("state") or ("In Catalog" if official else
                                           "Absent From Catalog" if objects else "Catalog Unavailable")
        url = f"https://attack.mitre.org/{_SECTIONS[ident[0]]}/{ident.replace('.', '/')}/" if official else ""
        output.append({"id": ident, "count": count, "name": official.get("name"), "status": status, "url": url,
                       "domains": official.get("domains", []), "replacement": official.get("replacement"),
                       "evidence": evidence.get(ident, [])})
    return output
