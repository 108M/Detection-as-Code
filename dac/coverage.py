"""`dac coverage`: ATT&CK coverage from the rules + test results.

Outputs (default build/site/, ready for GitHub Pages):
  index.html             human report (metrics, matrix, rules, backlog, datasets)
  layer.json             ATT&CK Navigator layer, techniques coloured by test status
  coverage.json          machine-readable model
  badges/*.json          shields.io endpoint badges
  test-report.json       copy of the `dac test` report used
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml
from jinja2 import Environment, PackageLoader, select_autoescape

from dac import attack
from dac.validate import TECHNIQUE_TAG_RE, discover

DOMAIN = "enterprise-attack"
NAVIGATOR_URL = "https://mitre-attack.github.io/attack-navigator/"
DEFAULT_SITE_URL = "https://108m.github.io/Detection-as-Code"
REPO_URL = "https://github.com/108M/Detection-as-Code"

# Test state of a technique, worst first. Colours are used by both the HTML and Navigator.
STATES: dict[str, dict[str, str]] = {
    "failing": {"label": "Failing tests", "label_es": "Tests fallando", "color": "#d64545"},
    "untested": {"label": "Rule without tests", "label_es": "Regla sin tests", "color": "#e0a526"},
    "experimental": {
        "label": "Experimental rule",
        "label_es": "Regla experimental",
        "color": "#5b8def",
    },
    "tested": {"label": "Tested (passing)", "label_es": "Probada (pasa)", "color": "#2e9e5b"},
}


@dataclass
class RuleCoverage:
    rule_id: str
    title: str
    path: str
    level: str
    sigma_status: str
    test_status: str  # pass | fail | error | untested | not-run
    techniques: list[str]
    tactics: list[str]
    tp_hits: int = 0
    fp_hits: int = 0
    gaps: list[dict[str, str]] = field(default_factory=list)
    accepted_fps: list[dict[str, Any]] = field(default_factory=list)

    @property
    def state(self) -> str:
        if self.test_status in ("fail", "error"):
            return "failing"
        if self.sigma_status == "experimental":
            return "experimental"
        if self.test_status == "pass":
            return "tested"
        return "untested"


@dataclass
class TechniqueCoverage:
    id: str
    name: str
    tactics: list[str]
    rules: list[RuleCoverage]

    @property
    def state(self) -> str:
        states = {r.state for r in self.rules}
        for s in ("failing", "tested", "untested", "experimental"):
            if s in states:
                return s
        return "untested"


@dataclass
class TacticCoverage:
    shortname: str
    id: str
    name: str
    total: int  # parent techniques in the tactic
    covered: int  # parent techniques with >= 1 rule (directly or via a sub-technique)
    techniques: list[TechniqueCoverage]

    @property
    def percent(self) -> float:
        return round(100 * self.covered / self.total, 1) if self.total else 0.0


@dataclass
class CoverageModel:
    generated_at: str
    attack_version: str
    commit: str | None
    rules: list[RuleCoverage]
    techniques: list[TechniqueCoverage]
    tactics: list[TacticCoverage]
    test_summary: dict[str, Any] | None
    datasets: list[dict[str, Any]]

    @property
    def summary(self) -> dict[str, Any]:
        states = [t.state for t in self.techniques]
        return {
            "rules": len(self.rules),
            "rules_passing": sum(1 for r in self.rules if r.test_status == "pass"),
            "techniques": len(self.techniques),
            "techniques_tested": states.count("tested"),
            "tactics_covered": sum(1 for t in self.tactics if t.covered),
            "tactics_total": len(self.tactics),
            "parent_techniques_covered": sum(t.covered for t in self.tactics),
        }


def _load_rules(rules_dir: Path) -> list[tuple[Path, dict]]:
    out = []
    for path in discover(rules_dir):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            out.append((path, raw))
    return out


def build(
    rules_dir: Path,
    cases_dir: Path,
    report_path: Path | None,
    data: attack.AttackData | None = None,
) -> CoverageModel:
    data = data or attack.load()
    report = None
    if report_path and report_path.exists():
        report = json.loads(report_path.read_text(encoding="utf-8"))
    results = {r["path"]: r for r in (report or {}).get("rules", [])}

    rules: list[RuleCoverage] = []
    for path, raw in _load_rules(rules_dir):
        tags = [str(t) for t in raw.get("tags") or []]
        techniques = sorted(m.group(1).upper() for t in tags if (m := TECHNIQUE_TAG_RE.match(t)))
        tactics = [
            t.removeprefix("attack.") for t in tags if t.removeprefix("attack.") in data.tactics
        ]
        result = results.get(path.as_posix())
        if report is None:
            test_status = "not-run"
        else:
            test_status = result["status"] if result else "untested"
        rc = RuleCoverage(
            rule_id=str(raw.get("id", "")),
            title=str(raw.get("title", path.stem)),
            path=path.as_posix(),
            level=str(raw.get("level", "")),
            sigma_status=str(raw.get("status", "")),
            test_status=test_status,
            techniques=techniques,
            tactics=tactics,
        )
        if result:
            for d in result.get("results", []):
                if d["expected"] in ("detects", "also_detects"):
                    rc.tp_hits += d["hits"]
                elif d["expected"] in ("false_positive", "accepted_fp"):
                    rc.fp_hits += d["hits"]
        case_path = cases_dir / path.name
        if case_path.exists():
            case = yaml.safe_load(case_path.read_text(encoding="utf-8")) or {}
            rc.gaps = [
                {"dataset": g["dataset"], "reason": " ".join(str(g.get("reason", "")).split())}
                for g in case.get("known_gaps", [])
            ]
            hits_by_ds = {d["dataset"]: d["hits"] for d in (result or {}).get("results", [])}
            rc.accepted_fps = [
                {
                    "dataset": a["dataset"],
                    "max_hits": a["max_hits"],
                    "hits": hits_by_ds.get(a["dataset"]),
                    "reason": " ".join(str(a.get("reason", "")).split()),
                }
                for a in case.get("accepted_false_positives", [])
            ]
        rules.append(rc)

    # Technique -> rules; a technique is placed under the tactics the rule tags for it.
    by_tech: dict[str, TechniqueCoverage] = {}
    for rc in rules:
        for tid in rc.techniques:
            tech = data.techniques.get(tid)
            if tech is None:
                continue
            tc = by_tech.setdefault(
                tid,
                TechniqueCoverage(tid, tech.name, sorted(tech.tactics & set(rc.tactics)), []),
            )
            tc.tactics = sorted(set(tc.tactics) | (tech.tactics & set(rc.tactics)))
            tc.rules.append(rc)
    techniques = sorted(by_tech.values(), key=lambda t: t.id)

    tactics: list[TacticCoverage] = []
    for short in data.tactic_order.get(DOMAIN, []):
        tactic = data.tactic_info[(DOMAIN, short)]
        parents = {t.id for t in data.techniques_in(DOMAIN, short)}
        in_tactic = [t for t in techniques if short in t.tactics]
        covered_parents = {t.id.split(".")[0] for t in in_tactic} & parents
        tactics.append(
            TacticCoverage(
                short, tactic.id, tactic.name, len(parents), len(covered_parents), in_tactic
            )
        )

    return CoverageModel(
        generated_at=(report or {}).get("generated_at")
        or dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        attack_version=data.version,
        commit=os.environ.get("GITHUB_SHA"),
        rules=sorted(rules, key=lambda r: r.path),
        techniques=techniques,
        tactics=tactics,
        test_summary=(report or {}).get("summary"),
        datasets=(report or {}).get("datasets", []),
    )


# --- Writers ---------------------------------------------------------------------------


def navigator_layer(model: CoverageModel) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for tech in model.techniques:
        color = STATES[tech.state]["color"]
        comment = "; ".join(f"{r.title} [{r.test_status}]" for r in tech.rules)
        for tactic in tech.tactics or [None]:
            entry: dict[str, Any] = {
                "techniqueID": tech.id,
                "color": color,
                "score": len(tech.rules),
                "comment": comment,
                "enabled": True,
                "showSubtechniques": "." not in tech.id,
                "metadata": [{"name": "rule", "value": r.title} for r in tech.rules],
                "links": [
                    {"label": r.title, "url": f"{REPO_URL}/blob/main/{r.path}"} for r in tech.rules
                ],
            }
            if tactic:
                entry["tactic"] = tactic
            entries.append(entry)
            # Expand the parent so the sub-technique is visible in the matrix.
            if "." in tech.id:
                parent = {"techniqueID": tech.id.split(".")[0], "showSubtechniques": True}
                if tactic:
                    parent["tactic"] = tactic
                entries.append(parent)
    return {
        "name": "Detection-as-Code coverage",
        "versions": {
            "attack": model.attack_version.split(".")[0],
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": DOMAIN,
        "description": (
            f"Sigma rules in {REPO_URL}, coloured by `dac test` result ({model.generated_at})."
        ),
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showID": True,
            "showName": True,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": entries,
        "legendItems": [{"label": s["label"], "color": s["color"]} for s in STATES.values()],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def _badge(label: str, message: str, color: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "label": label, "message": message, "color": color}


def badges(model: CoverageModel) -> dict[str, dict[str, Any]]:
    s = model.summary
    ts = model.test_summary or {}
    rate = ts.get("detection_rate")
    out = {
        "rules": _badge(
            "detection rules",
            f"{s['rules_passing']}/{s['rules']} passing",
            "brightgreen" if s["rules_passing"] == s["rules"] else "red",
        ),
        "attack": _badge(
            f"ATT&CK v{model.attack_version}",
            f"{s['techniques']} techniques · {s['tactics_covered']} tactics",
            "blue",
        ),
    }
    if rate is not None:
        out["detection-rate"] = _badge(
            "detection rate",
            f"{rate * 100:.0f}%",
            "brightgreen" if rate == 1 else "orange" if rate >= 0.8 else "red",
        )
    return out


def markdown(model: CoverageModel, site_url: str | None = None) -> str:
    s = model.summary
    lines = [
        "## ATT&CK coverage",
        "",
        f"{s['techniques']} techniques ({s['techniques_tested']} tested) across "
        f"{s['tactics_covered']}/{s['tactics_total']} tactics · ATT&CK v{model.attack_version}",
        "",
        "| Tactic | Covered | Techniques |",
        "|---|---:|---|",
    ]
    for t in model.tactics:
        if t.covered:
            techs = ", ".join(f"{x.id} {x.name}" for x in t.techniques)
            lines.append(f"| {t.name} | {t.covered}/{t.total} | {techs} |")
    if site_url:
        lines += ["", f"Report: {site_url}/ · Navigator: {navigator_link(site_url)}"]
    return "\n".join(lines) + "\n"


def navigator_link(site_url: str) -> str:
    return f"{NAVIGATOR_URL}#layerURL={quote(site_url.rstrip('/') + '/layer.json', safe='')}"


def write_site(
    model: CoverageModel, output: Path, site_url: str, report_path: Path | None
) -> list[Path]:
    output.mkdir(parents=True, exist_ok=True)
    (output / "badges").mkdir(exist_ok=True)
    written: list[Path] = []

    def dump(path: Path, obj: Any) -> None:
        path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")
        written.append(path)

    dump(output / "layer.json", navigator_layer(model))
    dump(
        output / "coverage.json",
        {
            "generated_at": model.generated_at,
            "attack_version": model.attack_version,
            "summary": model.summary,
            "test_summary": model.test_summary,
            "rules": [asdict(r) | {"state": r.state} for r in model.rules],
            "techniques": [
                {
                    "id": t.id,
                    "name": t.name,
                    "tactics": t.tactics,
                    "state": t.state,
                    "rules": [r.rule_id for r in t.rules],
                }
                for t in model.techniques
            ],
        },
    )
    for name, badge in badges(model).items():
        dump(output / "badges" / f"{name}.json", badge)
    if report_path and report_path.exists():
        shutil.copyfile(report_path, output / "test-report.json")
        written.append(output / "test-report.json")

    env = Environment(
        loader=PackageLoader("dac", "templates"),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    html = env.get_template("report.html.j2").render(
        m=model,
        s=model.summary,
        ts=model.test_summary or {},
        states=STATES,
        repo_url=REPO_URL,
        navigator_link=navigator_link(site_url),
        has_report=report_path is not None and report_path.exists(),
    )
    (output / "index.html").write_text(html, encoding="utf-8")
    written.append(output / "index.html")
    return written
