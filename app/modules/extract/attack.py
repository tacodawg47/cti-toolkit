"""Identify ATT&CK references and preserve explicitly aligned report evidence."""

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
    return re.sub(r"\s*::\s*", ": ", text.strip(" *|`")).casefold()


def _names(official: str) -> set[str]:
    return {_name(official), _name(official.rsplit(": ", 1)[-1])}


def _has_context(text: str, matches: list[str], objects: dict) -> bool:
    """A list of catalog labels alone is not an observed procedure."""
    remainder = _ID.sub(" ", text)
    names = set().union(*(_names(objects[ident]["name"]) for ident in matches))
    for name in sorted(names, key=len, reverse=True):
        remainder = re.sub(r"(?<!\w)" + re.escape(name) + r"(?!\w)", " ", remainder, flags=re.I)
    words = re.findall(r"\b\w+\b", remainder)
    return len(words) >= 2 and len(" ".join(words)) >= 8


def _inline(text: str, matches: list[str], objects: dict) -> str | None:
    """Split an explicit ID/name label using catalog names, not colon position."""
    if not matches:
        return None
    pattern = re.compile(re.escape(matches[0]).replace(r"\.", r"[./]"), re.I)
    found = pattern.search(text)
    if not found:
        return None
    prefix = text[:found.start()].strip(" *|`_[]():-–—")
    names = set().union(*(_names(objects[ident]["name"]) for ident in matches))
    if prefix and _name(prefix) not in names:
        return None
    remaining = text[found.end():].strip(" *|`_[]():-–—")
    for name in sorted(names, key=len, reverse=True):
        if remaining.casefold().startswith(name) and (len(remaining) == len(name) or not remaining[len(name)].isalnum()):
            remaining = remaining[len(name):].strip(" *|`_[]():-–—")
            break
    return remaining if _has_context(remaining, matches, objects) else ""


def _table_evidence(table: Table, objects: dict, tactics: dict) -> list[tuple[str, dict]]:
    id_matches = Counter()
    for row in table.rows:
        for col, value in enumerate(row):
            if any(ident.startswith("T") and ident in objects for ident in ids(value)):
                id_matches[col] += 1
    if not id_matches:
        return []
    id_col = max(id_matches, key=lambda col: (id_matches[col], -sum(len(row[col]) for row in table.rows if col < len(row))))
    header = next((row for row in table.rows[:3] if any(_name(v) in _PROCEDURE_HEADERS | _NAME_HEADERS for v in row)
                   and not any(ids(value) for value in row)), [])
    if id_matches[id_col] < 2 and table.kind == "HTML Table" and not any(_name(value) in _PROCEDURE_HEADERS for value in header):
        return []

    tactic_labels = {_name(tactic["name"]): tactic for tactic in tactics.values()}
    tactic_labels.update({key.casefold(): tactic for key, tactic in tactics.items()})
    tactic_labels.setdefault("defense evasion", {"name": "Defense Evasion", "slug": "defense-evasion"})

    def cell_role(value: str, names: set[str]) -> tuple[str, dict | None]:
        label = _name(value)
        if label in tactic_labels:
            return label, tactic_labels[label]
        # Some publishers combine "Tactic: Technique" in one cell. Match
        # the known tactic and catalog name before calling it procedure text.
        prefix, separator, suffix = label.partition(":")
        if separator and prefix in tactic_labels and suffix.strip() in names:
            return suffix.strip(), tactic_labels[prefix]
        return label, None
    context = next((tactic for key, tactic in tactic_labels.items()
                    if re.search(r"(?<!\w)" + re.escape(key) + r"(?!\w)", table.caption.casefold())), None)
    name_hint = next((col for col, value in enumerate(header) if _name(value) in _NAME_HEADERS and col != id_col), None)
    use_hint = next((col for col, value in enumerate(header) if _name(value) in _PROCEDURE_HEADERS and col != id_col), None)
    data_rows = [row for row in table.rows if id_col < len(row) and any(ident in objects for ident in ids(row[id_col]))]
    name_counts = Counter()
    tactic_counts = Counter()
    lengths = {}
    for row in data_rows:
        matches = [ident for ident in ids(row[id_col]) if ident in objects]
        names = set().union(*(_names(objects[ident]["name"]) for ident in matches))
        for col, value in enumerate(row):
            if col == id_col:
                continue
            label, tactic = cell_role(value, names)
            if label in names:
                name_counts[col] += 1
            if tactic:
                tactic_counts[col] += 1
            lengths.setdefault(col, []).append(len(value))
    averages = {col: sum(values) / len(values) for col, values in lengths.items()}
    inferred_name = name_counts.most_common(1)[0][0] if name_counts else None
    if inferred_name is None and name_hint is not None and any(length > averages.get(name_hint, 0) for col, length in averages.items() if col != name_hint):
        inferred_name = name_hint
    candidates = [col for col in averages if col != inferred_name and not tactic_counts[col]]
    procedure_col = max(candidates, key=lambda col: (averages[col], col == use_hint), default=None)

    result = []
    for row in table.rows:
        if row is header:
            continue
        matches = list(dict.fromkeys(
            ident for ident in ids(row[id_col]) if ident.startswith("T") and ident in objects
        )) if id_col < len(row) else []
        names = set().union(*(_names(objects[ident]["name"]) for ident in matches))
        roles = [cell_role(value, names) for value in row]
        tactic_cols = {col: tactic for col, (_, tactic) in enumerate(roles) if tactic}
        if tactic_cols:
            context = next(iter(tactic_cols.values()))
        if not matches:
            continue
        name_cols = {col for col, (label, _) in enumerate(roles) if col != id_col and label in names}
        name_col = min(name_cols) if name_cols else inferred_name
        remaining = [col for col, value in enumerate(row) if value and col != id_col
                     and col != name_col and col not in tactic_cols and col not in name_cols]
        use_col = procedure_col if procedure_col in remaining else max(remaining, key=lambda col: len(row[col]), default=None)
        procedure = row[use_col] if use_col is not None else (_inline(row[id_col], matches, objects) or "")
        if procedure and not _has_context(procedure, matches, objects):
            procedure = ""
        published_name = row[name_col] if name_col is not None and name_col < len(row) else ""
        for ident in matches:
            official = objects[ident]
            slug = context["slug"] if context else ""
            valid_tactics = set(official["tactics"])
            if valid_tactics.intersection(("stealth", "defense-impairment")):
                valid_tactics.add("defense-evasion")
            result.append((ident, {
                "caption": table.caption, "procedure": procedure,
                "kind": table.kind, "confidence": "Source Structure",
                "tactic": context["name"] if context else "", "shared": len(matches) > 1,
                "tactic_mismatch": bool(slug and valid_tactics and slug not in valid_tactics),
                "name_mismatch": published_name if published_name and not name_cols and _name(published_name) != _name(official["name"]) else "",
            }))
    return result


def _line_evidence(text: str, objects: dict, kind: str, caption: str = "", tactics: dict | None = None) -> list[tuple[str, dict]]:
    result = []
    context = next((tactic for key, tactic in (tactics or {}).items()
                    if any(re.search(r"(?<!\w)" + re.escape(label) + r"(?!\w)", caption, re.I)
                           for label in (key, tactic["name"]))), None)
    for block in re.split(r"\n\s*\n", text[:1000000]):
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        positions = [index for index, line in enumerate(lines) if any(ident.startswith("T") and ident in objects for ident in ids(line))]
        if not positions:
            continue
        # A flattened column of labels followed by a column of prose cannot
        # establish which paragraph belongs to which technique.
        if any(b == a + 1 for a, b in zip(positions, positions[1:])):
            if all(not _inline(lines[index], [ident for ident in ids(lines[index]) if ident in objects and ident.startswith("T")], objects) for index in positions):
                continue
        for number, position in enumerate(positions):
            matches = list(dict.fromkeys(ident for ident in ids(lines[position]) if ident in objects and ident.startswith("T")))
            if not matches or kind == "PDF Paragraph" and len(matches) != 1:
                continue
            inline = _inline(lines[position], matches, objects)
            end = positions[number + 1] if number + 1 < len(positions) else len(lines)
            following = " ".join(lines[position + 1:end])
            if inline is None:
                if len(positions) != 1:
                    continue
                procedure = " ".join(lines)
            else:
                procedure = " ".join(part for part in (inline, following) if part)
                if not inline:
                    for name in sorted(_names(objects[matches[0]]["name"]), key=len, reverse=True):
                        if procedure.casefold().startswith(name):
                            procedure = procedure[len(name):].lstrip(" :-–—")
                            break
            if not _has_context(procedure, matches, objects):
                continue
            for ident in matches:
                valid = set(objects[ident]["tactics"])
                if valid.intersection({"stealth", "defense-impairment"}):
                    valid.add("defense-evasion")
                result.append((ident, {"caption": caption, "procedure": procedure[:4000], "kind": kind,
                                       "confidence": "Paragraph Alignment", "shared": len(matches) > 1,
                                       "tactic": context["name"] if context else "",
                                       "tactic_mismatch": bool(context and valid and context["slug"] not in valid),
                                       "name_mismatch": ""}))
    return result


def extract(document: Document, catalog: dict) -> list[dict]:
    """Keep a syntactic ID hit even if the local catalog cannot verify it."""
    objects = catalog.get("objects", {})
    tactics = catalog.get("tactics", {})
    evidence = {}
    for table in document.tables:
        if table.kind in ("Preformatted Lines", "HTML Line Block"):
            findings = _line_evidence("\n".join(row[0] for row in table.rows if row), objects, table.kind, table.caption, tactics)
        else:
            findings = _table_evidence(table, objects, tactics)
        for ident, finding in findings:
            rows = evidence.setdefault(ident, [])
            if finding not in rows and len(rows) < 20:
                rows.append(finding)
    if document.format == "PDF":
        for page in document.pages:
            for ident, finding in _line_evidence(page, objects, "PDF Paragraph"):
                if len(evidence.setdefault(ident, [])) < 20:
                    evidence[ident].append(finding)
    else:
        prose = document.prose if document.prose is not None else [document.text]
        for paragraph in prose:
            for sentence in re.split(r"(?<=[.!?])\s+|\n", paragraph):
                matches = list(dict.fromkeys(ident for ident in ids(sentence) if ident.startswith("T") and ident in objects))
                if not matches or not _has_context(sentence, matches, objects):
                    continue
                for ident in matches:
                    if any(item["procedure"] for item in evidence.get(ident, [])):
                        continue
                    evidence.setdefault(ident, []).append({
                        "caption": "Prose Fallback", "procedure": sentence[:4000], "kind": "Prose Fallback",
                        "confidence": "Low" if len(matches) >= 3 else "Prose Context",
                        "shared": len(matches) > 1, "tactic": "", "tactic_mismatch": False, "name_mismatch": ""})
    occurrences = Counter(ids(document.text))
    # Adjacent inline spans in CSS grids have no plain-text separators.
    # Recover their explicitly bounded cells without double-counting normal text.
    for table in document.tables:
        for ident, count in Counter(ident for row in table.rows for cell in row for ident in ids(cell)).items():
            occurrences[ident] = max(occurrences[ident], count)
    output = []
    for ident, count in occurrences.items():
        official = objects.get(ident, {})
        status = official.get("state") or ("In Catalog" if official else
                                           "Absent From Catalog" if objects else "Catalog Unavailable")
        url = f"https://attack.mitre.org/{_SECTIONS[ident[0]]}/{ident.replace('.', '/')}/" if official else ""
        output.append({"id": ident, "count": count, "name": official.get("name"), "status": status, "url": url,
                       "domains": official.get("domains", []), "replacement": official.get("replacement"),
                       "evidence": evidence.get(ident, [])})
    return output
