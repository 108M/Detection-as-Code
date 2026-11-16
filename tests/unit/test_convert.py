"""Unit tests for `dac convert`.

EQL snapshots live in tests/unit/snapshots/eql/<rule>.eql so that any change to a rule,
the pySigma pipeline or the backend version shows up as a reviewable diff in the PR.
Regenerate them with:  DAC_UPDATE_SNAPSHOTS=1 pytest tests/unit/test_convert.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from dac.attack import AttackData, Tactic, Technique
from dac.convert import build_threat, convert
from dac.validate import discover

SNAPSHOTS = Path(__file__).parent / "snapshots" / "eql"
UPDATE = os.environ.get("DAC_UPDATE_SNAPSHOTS") == "1"

RULE = """\
title: Test Rule
id: 0e9c2f53-6a3b-4c1e-9d0a-1b2c3d4e5f60
status: {status}
description: Test rule
author: tester
date: 2026-11-14
tags:
  - attack.credential-access
  - attack.t1003.001
  - attack.stealth
  - attack.t1218.011
logsource:
  category: {category}
  product: windows
detection:
  selection:
    CommandLine|contains: 'comsvcs'
  regex:
    CommandLine|re|i: 'rundll32\\.exe.*'
  condition: selection and regex
falsepositives:
  - Unlikely
level: high
"""


@pytest.fixture
def attack_data() -> AttackData:
    data = AttackData(version="test")
    ent = "enterprise-attack"
    data.techniques = {
        "T1003": Technique("T1003", "OS Credential Dumping", ent, frozenset({"credential-access"})),
        "T1003.001": Technique("T1003.001", "LSASS Memory", ent, frozenset({"credential-access"})),
        "T1218": Technique("T1218", "System Binary Proxy Execution", ent, frozenset({"stealth"})),
        "T1218.011": Technique("T1218.011", "Rundll32", ent, frozenset({"stealth"})),
    }
    data.tactic_info = {
        (ent, "credential-access"): Tactic("TA0006", "Credential Access", "credential-access", ent),
        (ent, "stealth"): Tactic("TA0005", "Stealth", "stealth", ent),
    }
    data.tactics = {"credential-access": "TA0006", "stealth": "TA0005"}
    return data


def _convert(tmp_path, attack_data, status="test", category="process_creation", **kw):
    path = tmp_path / "rule.yml"
    path.write_text(RULE.format(status=status, category=category), encoding="utf-8")
    return convert([path], attack_data=attack_data, **kw)


def test_payload_is_detection_engine_eql_rule(tmp_path, attack_data):
    result = _convert(tmp_path, attack_data)
    assert result.errors == []
    p = result.rules[0].payload
    assert p["rule_id"] == "0e9c2f53-6a3b-4c1e-9d0a-1b2c3d4e5f60"
    assert (p["type"], p["language"]) == ("eql", "eql")
    assert (p["severity"], p["risk_score"]) == ("high", 73)
    assert p["enabled"] is True
    assert p["license"] == "MIT"
    assert "Tactic: Credential Access" in p["tags"]
    assert p["meta"]["dac"]["content_hash"]


def test_logsource_condition_added(tmp_path, attack_data):
    query = _convert(tmp_path, attack_data).rules[0].query
    assert 'event.category:"process"' in query and 'event.type:"start"' in query


def test_regex_inline_flag_removed(tmp_path, attack_data):
    query = _convert(tmp_path, attack_data).rules[0].query
    assert "regex~" in query
    assert "(?i)" not in query


def test_experimental_rules_are_disabled(tmp_path, attack_data):
    assert (
        _convert(tmp_path, attack_data, status="experimental").rules[0].payload["enabled"] is False
    )


def test_index_override(tmp_path, attack_data):
    p = _convert(tmp_path, attack_data, index_override=["dac-test-*"]).rules[0].payload
    assert p["index"] == ["dac-test-*"]


def test_unmapped_logsource_is_an_error(tmp_path, attack_data):
    path = tmp_path / "rule.yml"
    path.write_text(
        RULE.format(status="test", category="process_creation").replace(
            "product: windows", "product: macos"
        ),
        encoding="utf-8",
    )
    result = convert([path], attack_data=attack_data)
    assert result.rules == [] and result.errors


def test_content_hash_changes_with_query(tmp_path, attack_data):
    h1 = _convert(tmp_path, attack_data).rules[0].payload["meta"]["dac"]["content_hash"]
    h1_again = _convert(tmp_path, attack_data).rules[0].payload["meta"]["dac"]["content_hash"]
    path = tmp_path / "rule.yml"
    path.write_text(
        path.read_text(encoding="utf-8").replace("comsvcs", "comsvcs.dll"), encoding="utf-8"
    )
    h2 = convert([path], attack_data=attack_data).rules[0].payload["meta"]["dac"]["content_hash"]
    assert h1 == h1_again != h2


def test_threat_groups_subtechniques_under_parent(attack_data):
    tags = ["attack.credential-access", "attack.t1003.001", "attack.stealth", "attack.t1218.011"]
    threat = build_threat(tags, attack_data)
    assert [t["tactic"]["id"] for t in threat] == ["TA0005", "TA0006"]
    cred = threat[1]["technique"][0]
    assert cred["id"] == "T1003" and cred["name"] == "OS Credential Dumping"
    assert cred["subtechnique"][0]["id"] == "T1003.001"
    assert cred["subtechnique"][0]["reference"] == "https://attack.mitre.org/techniques/T1003/001/"


# --- Real rule set -------------------------------------------------------------------


@pytest.fixture(scope="module")
def repo_conversion():
    try:
        from dac import attack

        data = attack.load()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"ATT&CK data unavailable: {exc}")
    return convert(discover(Path("rules")), attack_data=data)


def test_all_repository_rules_convert(repo_conversion):
    assert [f"{p}: {m}" for p, m in repo_conversion.errors] == []
    assert len(repo_conversion.rules) == len(discover(Path("rules")))


def test_eql_snapshots(repo_conversion):
    SNAPSHOTS.mkdir(parents=True, exist_ok=True)
    seen = set()
    mismatches = []
    for rule in repo_conversion.rules:
        snap = SNAPSHOTS / f"{rule.path.stem}.eql"
        seen.add(snap.name)
        if not snap.exists() and os.environ.get("CI"):
            mismatches.append(f"{rule.path.as_posix()} (missing snapshot)")
            continue
        if UPDATE or not snap.exists():
            snap.write_text(rule.query + "\n", encoding="utf-8", newline="\n")
            continue
        if snap.read_text(encoding="utf-8").rstrip("\n") != rule.query:
            mismatches.append(rule.path.as_posix())
    stale = sorted(p.name for p in SNAPSHOTS.glob("*.eql") if p.name not in seen)
    assert not stale, f"snapshots without a rule (delete them): {stale}"
    assert not mismatches, (
        "EQL output changed for: "
        + ", ".join(mismatches)
        + ". If intended, run DAC_UPDATE_SNAPSHOTS=1 pytest tests/unit/test_convert.py"
    )
