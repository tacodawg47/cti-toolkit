"""Small local index of official MITRE ATT&CK STIX identifiers."""

import asyncio
import json
import re
from pathlib import Path
from tempfile import NamedTemporaryFile

from ...core.config import settings
from ..vulnerability_intelligence.http import fetch_bytes

VERSION = "20.1"
SOURCE = "https://github.com/mitre-attack/attack-stix-data"
_RAW = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
_DOMAINS = ("enterprise", "mobile", "ics")
_MAX_BYTES = 96 * 1024 * 1024
_EXTERNAL_ID = {
    "attack-pattern": re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?"),
    "intrusion-set": re.compile(r"G[0-9]{4}"),
    "malware": re.compile(r"S[0-9]{4}"),
    "tool": re.compile(r"S[0-9]{4}"),
    "x-mitre-tactic": re.compile(r"TA[0-9]{4}"),
}


def parse(body: bytes, domain: str) -> dict:
    bundle = json.loads(body)
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("expected a STIX bundle")
    objects, tactics, stix_ids, revoked_by = {}, {}, {}, {}
    for item in bundle["objects"]:
        kind = item.get("type")
        if kind == "relationship" and item.get("relationship_type") == "revoked-by":
            if not item.get("revoked"):
                revoked_by[item["source_ref"]] = item["target_ref"]
            continue
        pattern = _EXTERNAL_ID.get(kind)
        if not pattern:
            continue
        external_id = next((ref["external_id"] for ref in item.get("external_references", [])
                            if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
                            and pattern.fullmatch(ref.get("external_id", ""))), None)
        if not external_id:
            continue
        name = item["name"]
        if kind == "x-mitre-tactic":
            tactics[external_id] = {"name": name, "slug": item["x_mitre_shortname"]}
            continue
        state = "Revoked" if item.get("revoked") else "Deprecated" if item.get("x_mitre_deprecated") else ""
        stix_ids[item["id"]] = external_id
        objects[external_id] = {"name": name, "state": state, "domains": [domain],
                                "tactics": sorted({p["phase_name"] for p in item.get("kill_chain_phases", [])
                                                   if p.get("kill_chain_name", "").startswith("mitre-")})}
    if not objects or not tactics:
        raise ValueError("bundle is missing ATT&CK objects")
    for source, target in revoked_by.items():
        if source in stix_ids and target in stix_ids:
            objects[stix_ids[source]]["replacement"] = stix_ids[target]
    return {"objects": objects, "tactics": tactics}


def _path() -> Path:
    return settings.data_dir / "attack-index.json"


def load() -> dict:
    try:
        index = json.loads(_path().read_text(encoding="utf-8"))
        return index if isinstance(index, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(index: dict) -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        temp = Path(handle.name)
        try:
            json.dump(index, handle, ensure_ascii=False, separators=(",", ":"))
            handle.close()
            temp.replace(path)
        finally:
            temp.unlink(missing_ok=True)


async def refresh() -> str | None:
    index = {"version": VERSION, "objects": {}, "tactics": {}}
    for domain in _DOMAINS:
        url = f"{_RAW}/{domain}-attack/{domain}-attack-{VERSION}.json"
        status, body, error = await fetch_bytes(url, max_bytes=_MAX_BYTES, follow_redirects=False)
        if error or status != 200:
            return f"ATT&CK {domain}: {error or f'HTTP {status}'}"
        try:
            data = await asyncio.to_thread(parse, body, domain)
        except (AttributeError, KeyError, TypeError, ValueError):
            return f"ATT&CK {domain}: invalid STIX bundle"
        index["tactics"].update(data["tactics"])
        for key, item in data["objects"].items():
            existing = index["objects"].get(key)
            if existing is None:
                index["objects"][key] = item
            else:
                preferred = item if existing["state"] and not item["state"] else existing
                index["objects"][key] = {**preferred, "domains": existing["domains"] + item["domains"],
                                         "tactics": sorted(set(existing["tactics"] + item["tactics"]))}
    try:
        await asyncio.to_thread(_save, index)
    except OSError:
        return "Unable to save the local ATT&CK catalog"
    return None
