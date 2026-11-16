"""Unit tests for `dac coverage` (fake ATT&CK data, no network)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dac.attack import AttackData, Tactic, Technique
from dac.coverage import badges, build, navigator_layer, navigator_link, write_site

ENT = "enterprise-attack"

RULE = """\
title: {title}
id: {id}
status: {status}
description: d
author: a
date: 2026-11-16
tags: [{tags}]
logsource: {{category: process_creation, product: windows}}
detection:
  sel: {{CommandLine|contains: x}}
  condition: sel
falsepositives: [none]
level: high
"""


@pytest.fixture
def data() -> AttackData:
    d = AttackData(version="20.1")
    d.techniques = {
        "T1003": Technique("T1003", "OS Credential Dumping", ENT, frozenset({"credential-access"})),
        "T1003.001": Technique("T1003.001", "LSASS Memory", ENT, frozenset({"credential-access"})),
        "T1555": Technique(
            "T1555", "Credentials from Password Stores", ENT, frozenset({"credential-access"})
        ),
        "T1059": Technique(
            "T1059", "Command and Scripting Interpreter", ENT, frozenset({"execution"})
        ),
        "T1059.001": Technique("T1059.001", "PowerShell", ENT, frozenset({"execution"})),
    }
    d.tactic_info = {
        (ENT, "execution"): Tactic("TA0002", "Execution", "execution", ENT),
        (ENT, "credential-access"): Tactic("TA0006", "Credential Access", "credential-access", ENT),
    }
    d.tactics = {"execution": "TA0002", "credential-access": "TA0006"}
    d.tactic_order = {ENT: ["execution", "credential-access"]}
    return d


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "lsass.yml").write_text(
        RULE.format(
            title="LSASS",
            id="11111111-1111-4111-8111-111111111111",
            status="test",
            tags="attack.credential-access, attack.t1003.001",
        ),
        encoding="utf-8",
    )
    (rules / "ps.yml").write_text(
        RULE.format(
            title="PS",
            id="22222222-2222-4222-8222-222222222222",
            status="experimental",
            tags="attack.execution, attack.t1059.001",
        ),
        encoding="utf-8",
    )
    cases = tmp_path / "cases"
    cases.mkdir()
    (cases / "lsass.yml").write_text(
        "detects: [{dataset: a}]\nknown_gaps: [{dataset: b, reason: variant}]\n", encoding="utf-8"
    )
    return tmp_path


def _report(tmp_path: Path, lsass_status: str = "pass") -> Path:
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps(
            {
                "generated_at": "2026-11-16T10:00:00+00:00",
                "summary": {
                    "detection_rate": 1.0,
                    "detected": 1,
                    "expected_detections": 1,
                    "alert_precision": 1.0,
                    "true_positive_hits": 2,
                    "false_positive_hits": 0,
                    "events": 10,
                    "datasets": 2,
                },
                "datasets": [
                    {"id": "a", "events": 10, "techniques": ["T1003.001"], "description": ""}
                ],
                "rules": [
                    {
                        "path": "rules/lsass.yml",
                        "status": lsass_status,
                        "results": [{"dataset": "a", "hits": 2, "expected": "detects"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _build(repo: Path, data: AttackData, report: Path | None):
    import os

    cwd = os.getcwd()
    os.chdir(repo)  # rule paths are reported relative to the repo root
    try:
        return build(Path("rules"), Path("cases"), report, data)
    finally:
        os.chdir(cwd)


def test_states_and_tactic_coverage(repo, data):
    report = _report(repo)
    model = _build(repo, data, report)
    states = {t.id: t.state for t in model.techniques}
    assert states == {"T1003.001": "tested", "T1059.001": "experimental"}
    cred = next(t for t in model.tactics if t.shortname == "credential-access")
    assert (cred.covered, cred.total) == (1, 2)  # T1003 via its sub-technique; T1555 not
    lsass = next(r for r in model.rules if r.title == "LSASS")
    assert lsass.tp_hits == 2 and lsass.gaps[0]["dataset"] == "b"


def test_without_report_rules_are_not_run(repo, data):
    model = _build(repo, data, None)
    assert {r.test_status for r in model.rules} == {"not-run"}
    assert {t.state for t in model.techniques} == {"untested", "experimental"}


def test_failing_rule_marks_technique_failing(repo, data):
    report = _report(repo, lsass_status="fail")
    model = _build(repo, data, report)
    assert next(t for t in model.techniques if t.id == "T1003.001").state == "failing"
    assert badges(model)["rules"]["color"] == "red"


def test_navigator_layer_expands_parents(repo, data):
    layer = navigator_layer(_build(repo, data, None))
    ids = {(t["techniqueID"], t.get("tactic")) for t in layer["techniques"]}
    assert ("T1003.001", "credential-access") in ids
    assert ("T1003", "credential-access") in ids  # parent entry so the sub-technique shows
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["attack"] == "20"


def test_write_site_outputs(repo, data, tmp_path):
    out = tmp_path / "site"
    written = write_site(_build(repo, data, None), out, "https://example.test/dac", None)
    names = {p.relative_to(out).as_posix() for p in written}
    assert {"index.html", "layer.json", "coverage.json", "badges/rules.json"} <= names
    html = (out / "index.html").read_text(encoding="utf-8")
    assert "T1003.001" in html and "Detection backlog" in html


def test_navigator_link_encodes_layer_url():
    link = navigator_link("https://example.test/dac/")
    assert link.endswith("#layerURL=https%3A%2F%2Fexample.test%2Fdac%2Flayer.json")
