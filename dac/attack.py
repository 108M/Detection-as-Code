"""MITRE ATT&CK knowledge base (pinned STIX version, cached locally)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import requests

ATTACK_VERSION = os.environ.get("DAC_ATTACK_VERSION", "20.1")
DOMAINS = ("enterprise-attack", "ics-attack")
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "{domain}/{domain}-{version}.json"
)
CACHE_DIR = Path(os.environ.get("DAC_CACHE_DIR", ".cache")) / "attack"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    domain: str
    tactics: frozenset[str]
    deprecated: bool = False
    revoked: bool = False
    revoked_by: str | None = None  # replacement technique ID, if revoked


@dataclass
class AttackData:
    version: str
    techniques: dict[str, Technique] = field(default_factory=dict)  # "T1003.001" -> Technique
    tactics: dict[str, str] = field(default_factory=dict)  # "credential-access" -> "TA0006"
    other_ids: set[str] = field(default_factory=set)  # groups (G), software (S), campaigns (C)


def _ext_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack") and ref.get(
            "external_id"
        ):
            return ref["external_id"]
    return None


def _index_path(domain: str, version: str) -> Path:
    return CACHE_DIR / f"{domain}-{version}.index.json"


def _build_index(domain: str, version: str) -> dict:
    """Download the STIX bundle and keep a compact index (the bundle is ~50 MB)."""
    url = STIX_URL.format(domain=domain, version=version)
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    bundle = resp.json()

    techniques: dict[str, dict] = {}
    tactics: dict[str, str] = {}
    other: list[str] = []
    stix_to_ext = {o["id"]: _ext_id(o) for o in bundle["objects"] if _ext_id(o)}
    revoked_by = {
        o["source_ref"]: stix_to_ext.get(o["target_ref"])
        for o in bundle["objects"]
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by"
    }
    for obj in bundle["objects"]:
        ext = _ext_id(obj)
        if not ext:
            continue
        kind = obj.get("type")
        if kind == "attack-pattern":
            entry = {
                "name": obj.get("name", ""),
                "tactics": sorted(
                    p["phase_name"]
                    for p in obj.get("kill_chain_phases", [])
                    if p.get("kill_chain_name") in ("mitre-attack", "mitre-ics-attack")
                ),
                "deprecated": bool(obj.get("x_mitre_deprecated")),
                "revoked": bool(obj.get("revoked")),
                "revoked_by": revoked_by.get(obj["id"]),
            }
            current = techniques.get(ext)
            # An active object wins over a revoked/deprecated one with the same ID.
            if current is None or (current["revoked"] or current["deprecated"]):
                techniques[ext] = entry
        elif kind == "x-mitre-tactic":
            tactics[obj["x_mitre_shortname"]] = ext
        elif kind in ("intrusion-set", "malware", "tool", "campaign"):
            other.append(ext)

    index = {"version": version, "techniques": techniques, "tactics": tactics, "other": other}
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _index_path(domain, version).write_text(json.dumps(index), encoding="utf-8")
    return index


@cache
def load(version: str = ATTACK_VERSION) -> AttackData:
    data = AttackData(version=version)
    for domain in DOMAINS:
        path = _index_path(domain, version)
        if path.exists():
            index = json.loads(path.read_text(encoding="utf-8"))
        else:
            index = _build_index(domain, version)
        for tid, t in index["techniques"].items():
            data.techniques[tid] = Technique(
                id=tid,
                name=t["name"],
                domain=domain,
                tactics=frozenset(t["tactics"]),
                deprecated=t["deprecated"],
                revoked=t["revoked"],
                revoked_by=t.get("revoked_by"),
            )
        data.tactics.update(index["tactics"])
        data.other_ids.update(index["other"])
    return data
