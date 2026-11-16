"""Sigma -> Elastic Security detection rules (EQL, Detection Engine import format).

pySigma's EQL backend generates the query; the rule object around it is built here,
because the backend's `siem_rule` output targets the alerting saved-object schema
(camelCase params, generic rule type) and its ATT&CK names/licence are not ours.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import yaml
from sigma.backends.elasticsearch import EqlBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaRuleLocation
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

from dac import attack

PIPELINES_DIR = Path("pipelines")
CUSTOM_PIPELINE = PIPELINES_DIR / "dac_ecs_windows.yml"
TARGETS_FILE = PIPELINES_DIR / "elastic_targets.yml"
TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")

# pySigma prefixes case-insensitive regexes with "(?i)", which Elasticsearch regex
# (Lucene syntax) does not support: the query parses but never matches. `regex~`
# is already case-insensitive, so the flag is dropped.
INLINE_FLAG_RE = re.compile(r'"\(\?i\)')


@dataclass
class ConvertedRule:
    path: Path
    rule_id: str
    title: str
    query: str
    payload: dict[str, Any]


@dataclass
class ConversionResult:
    rules: list[ConvertedRule] = field(default_factory=list)
    errors: list[tuple[Path, str]] = field(default_factory=list)


@cache
def load_targets(path: Path = TARGETS_FILE) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def build_pipeline() -> ProcessingPipeline:
    custom = ProcessingPipeline.from_yaml(CUSTOM_PIPELINE.read_text(encoding="utf-8"))
    return ecs_windows() + custom


def _match_target(rule: SigmaRule, targets: list[dict]) -> dict:
    ls = {
        "product": rule.logsource.product,
        "category": rule.logsource.category,
        "service": rule.logsource.service,
    }
    for target in targets:
        if all(ls.get(k) == v for k, v in target["logsource"].items()):
            return target
    raise SigmaError(f"no Elastic target for logsource {ls} in {TARGETS_FILE}")


def _technique_ref(tid: str) -> str:
    return f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"


def build_threat(tags: list[str], data: attack.AttackData) -> list[dict]:
    """Elastic `threat` array: tactic -> technique -> sub-technique."""
    tactic_tags = {t.removeprefix("attack.") for t in tags if t.startswith("attack.")}
    by_tactic: dict[str, dict] = {}
    for tag in tags:
        m = TECHNIQUE_TAG_RE.match(tag)
        if not m:
            continue
        tech = data.techniques.get(m.group(1).upper())
        if tech is None:
            continue
        for short in sorted(tech.tactics & tactic_tags):
            tactic = data.tactic_info[(tech.domain, short)]
            entry = by_tactic.setdefault(
                tactic.id,
                {
                    "framework": "MITRE ATT&CK",
                    "tactic": {
                        "id": tactic.id,
                        "name": tactic.name,
                        "reference": f"https://attack.mitre.org/tactics/{tactic.id}/",
                    },
                    "technique": [],
                },
            )
            parent_id = tech.id.split(".")[0]
            parent = next((t for t in entry["technique"] if t["id"] == parent_id), None)
            if parent is None:
                parent_name = (
                    data.techniques[parent_id].name if parent_id in data.techniques else ""
                )
                parent = {
                    "id": parent_id,
                    "name": parent_name,
                    "reference": _technique_ref(parent_id),
                }
                entry["technique"].append(parent)
            if "." in tech.id:
                subs = parent.setdefault("subtechnique", [])
                if all(s["id"] != tech.id for s in subs):
                    subs.append(
                        {"id": tech.id, "name": tech.name, "reference": _technique_ref(tech.id)}
                    )
    return [by_tactic[k] for k in sorted(by_tactic)]


def _note(rule: SigmaRule, path: Path, repo_url: str) -> str:
    fps = "\n".join(f"- {fp}" for fp in rule.falsepositives) or "- None documented"
    src = path.as_posix()
    return (
        f"## Triage\n\n{(rule.description or '').strip()}\n\n"
        f"### Known false positives\n\n{fps}\n\n"
        f"### Source\n\nSigma rule [`{src}`]({repo_url}/{src}) (id `{rule.id}`), "
        f"managed by Detection-as-Code. Do not edit in Kibana: changes are overwritten "
        f"on the next deploy.\n"
    )


def build_rule(
    rule: SigmaRule,
    path: Path,
    query: str,
    data: attack.AttackData,
    index_override: list[str] | None = None,
) -> dict[str, Any]:
    cfg = load_targets()
    defaults = cfg["defaults"]
    target = _match_target(rule, cfg["targets"])
    level = rule.level.name.lower() if rule.level else "medium"
    severity, risk = cfg["severity"][level]
    status = rule.status.name.lower() if rule.status else "experimental"
    tags = [str(t) for t in rule.tags]
    threat = build_threat(tags, data)

    payload: dict[str, Any] = {
        "rule_id": str(rule.id),
        "name": rule.title,
        "description": (rule.description or "").strip(),
        "type": "eql",
        "language": "eql",
        "query": query,
        "index": index_override or target["index"],
        "severity": severity,
        "risk_score": risk,
        "interval": defaults["interval"],
        "from": defaults["from"],
        "max_signals": defaults["max_signals"],
        # Experimental rules are deployed disabled (staging) until promoted.
        "enabled": status != "experimental",
        "author": [rule.author] if rule.author else [],
        "license": "MIT",
        "false_positives": list(rule.falsepositives),
        "references": list(rule.references),
        "threat": threat,
        "tags": [
            "Detection-as-Code",
            "Sigma",
            f"Status: {status}",
            "OS: Windows",
            "Use Case: Threat Detection",
            *[f"Tactic: {t['tactic']['name']}" for t in threat],
            *target.get("tags", []),
        ],
        "note": _note(rule, path, defaults["repo_url"]),
    }
    content_hash = hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    payload["meta"] = {
        "dac": {"source": path.as_posix(), "sigma_status": status, "content_hash": content_hash}
    }
    return payload


def convert(
    paths: list[Path],
    index_override: list[str] | None = None,
    attack_data: attack.AttackData | None = None,
) -> ConversionResult:
    data = attack_data or attack.load()
    backend = EqlBackend(build_pipeline())
    result = ConversionResult()
    for path in paths:
        try:
            collection = SigmaCollection.from_yaml(
                path.read_text(encoding="utf-8"), source=SigmaRuleLocation(path)
            )
            for rule in collection.rules:
                if not isinstance(rule, SigmaRule):
                    raise SigmaError("correlation rules are not supported yet")
                queries = backend.convert_rule(rule)
                if len(queries) != 1:
                    raise SigmaError(f"expected 1 query, backend returned {len(queries)}")
                query = INLINE_FLAG_RE.sub('"', queries[0])
                payload = build_rule(rule, path, query, data, index_override)
                result.rules.append(ConvertedRule(path, str(rule.id), rule.title, query, payload))
        except (SigmaError, OSError, yaml.YAMLError) as exc:
            result.errors.append((path, str(exc)))
    return result


def write_ndjson(rules: list[ConvertedRule], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as fh:
        for r in sorted(rules, key=lambda r: r.rule_id):
            fh.write(json.dumps(r.payload, ensure_ascii=False, sort_keys=True) + "\n")
