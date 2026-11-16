"""Unit tests for `dac validate`: each broken rule must produce a specific, clear error."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from dac.attack import AttackData, Technique
from dac.validate import Severity, validate

VALID_RULE = """\
title: Test Rule
id: 0e9c2f53-6a3b-4c1e-9d0a-1b2c3d4e5f60
status: test
description: Test rule
author: tester
date: 2026-11-14
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'comsvcs'
  condition: selection
falsepositives:
  - Unlikely
level: high
"""


@pytest.fixture
def attack_data() -> AttackData:
    data = AttackData(version="test")
    data.tactics = {"credential-access": "TA0006", "execution": "TA0002", "stealth": "TA0005"}
    data.techniques = {
        "T1003.001": Technique(
            "T1003.001", "LSASS Memory", "enterprise-attack", frozenset({"credential-access"})
        ),
        "T1059.001": Technique(
            "T1059.001", "PowerShell", "enterprise-attack", frozenset({"execution"})
        ),
        "T1070.001": Technique(
            "T1070.001",
            "Clear Windows Event Logs",
            "enterprise-attack",
            frozenset({"stealth"}),
            revoked=True,
            revoked_by="T1685.005",
        ),
    }
    data.other_ids = {"G0016"}
    return data


def _run(tmp_path: Path, content: str, attack_data: AttackData, name: str = "test_rule.yml"):
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / name).write_text(textwrap.dedent(content), encoding="utf-8")
    issues, total = validate(rules, cases_dir=tmp_path / "cases", attack_data=attack_data)
    return issues, total


def _codes(issues, severity=Severity.ERROR) -> set[str]:
    return {i.code for i in issues if i.severity == severity}


def test_valid_rule_has_no_errors(tmp_path, attack_data):
    issues, total = _run(tmp_path, VALID_RULE, attack_data)
    assert total == 1
    assert _codes(issues) == set()
    assert _codes(issues, Severity.WARNING) == {"untested"}


def test_test_case_present_removes_warning(tmp_path, attack_data):
    (tmp_path / "cases").mkdir()
    (tmp_path / "cases" / "test_rule.yml").write_text("rule: test_rule\n", encoding="utf-8")
    issues, _ = _run(tmp_path, VALID_RULE, attack_data)
    assert issues == []


def test_missing_required_field(tmp_path, attack_data):
    issues, _ = _run(
        tmp_path, VALID_RULE.replace("falsepositives:\n  - Unlikely\n", ""), attack_data
    )
    assert "missing-field" in _codes(issues)
    assert any("falsepositives" in i.message for i in issues)


@pytest.mark.parametrize(
    ("old", "new", "code"),
    [
        ("status: test", "status: production", "invalid-status"),
        ("level: high", "level: urgent", "invalid-level"),
        ("date: 2026-11-14", "date: 14/11/2026", "invalid-date"),
    ],
)
def test_invalid_enum_values(tmp_path, attack_data, old, new, code):
    issues, _ = _run(tmp_path, VALID_RULE.replace(old, new), attack_data)
    assert code in _codes(issues)


def test_bad_filename(tmp_path, attack_data):
    issues, _ = _run(tmp_path, VALID_RULE, attack_data, name="Bad-Name.yml")
    assert "filename" in _codes(issues)


def test_unknown_technique(tmp_path, attack_data):
    issues, _ = _run(tmp_path, VALID_RULE.replace("t1003.001", "t9999.001"), attack_data)
    assert "attack-unknown" in _codes(issues)


def test_revoked_technique_suggests_replacement(tmp_path, attack_data):
    rule = VALID_RULE.replace("attack.credential-access", "attack.stealth").replace(
        "t1003.001", "t1070.001"
    )
    issues, _ = _run(tmp_path, rule, attack_data)
    revoked = [i for i in issues if i.code == "attack-revoked"]
    assert revoked and "T1685.005" in revoked[0].message


def test_unknown_tactic(tmp_path, attack_data):
    rule = VALID_RULE.replace("attack.credential-access", "attack.defense-evasion")
    issues, _ = _run(tmp_path, rule, attack_data)
    assert "attack-unknown" in _codes(issues)


def test_technique_tactic_mismatch(tmp_path, attack_data):
    rule = VALID_RULE.replace("attack.credential-access", "attack.execution")
    issues, _ = _run(tmp_path, rule, attack_data)
    assert "attack-tactic-mismatch" in _codes(issues)


def test_missing_technique_tag(tmp_path, attack_data):
    issues, _ = _run(tmp_path, VALID_RULE.replace("  - attack.t1003.001\n", ""), attack_data)
    assert "attack-missing" in _codes(issues)


def test_broken_detection_is_reported_by_pysigma(tmp_path, attack_data):
    rule = VALID_RULE.replace("condition: selection", "condition: selection and missing_one")
    issues, _ = _run(tmp_path, rule, attack_data)
    assert any(c.startswith("sigma-") for c in _codes(issues))


def test_duplicate_ids_across_rules(tmp_path, attack_data):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "rule_a.yml").write_text(VALID_RULE, encoding="utf-8")
    (rules / "rule_b.yml").write_text(VALID_RULE.replace("Test Rule", "Other"), encoding="utf-8")
    issues, _ = validate(rules, cases_dir=tmp_path / "cases", attack_data=attack_data)
    assert any(
        "Identifier" in i.code or "identifier" in i.message.lower()
        for i in issues
        if i.severity == Severity.ERROR
    )


def test_invalid_yaml(tmp_path, attack_data):
    issues, _ = _run(tmp_path, "title: [unclosed\n", attack_data)
    assert _codes(issues)  # reported as error, does not crash


def test_repository_rules_are_valid():
    """The real rule set must always pass (ATT&CK index needed: skipped if unavailable)."""
    try:
        from dac import attack

        data = attack.load()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"ATT&CK data unavailable: {exc}")
    issues, total = validate(Path("rules"), attack_data=data)
    assert total > 0
    assert [str(i) for i in issues if i.severity == Severity.ERROR] == []


@pytest.mark.parametrize("regex", ["^comsvcs.*", ".*comsvcs$", "(?i)comsvcs.*"])
def test_regex_incompatible_with_elasticsearch(tmp_path, attack_data, regex):
    rule = VALID_RULE.replace(
        "    CommandLine|contains: 'comsvcs'", f"    CommandLine|re: '{regex}'"
    )
    issues, _ = _run(tmp_path, rule, attack_data)
    assert "es-regex" in _codes(issues)
