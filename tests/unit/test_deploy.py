"""Unit tests for `dac deploy` planning and execution (fake Kibana, no network)."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from dac.convert import ConvertedRule
from dac.deploy import DeployError, apply, plan


def _rule(
    rule_id: str, title: str, query: str = "process where true", h: str = "h1"
) -> ConvertedRule:
    payload = {
        "rule_id": rule_id,
        "name": title,
        "type": "eql",
        "language": "eql",
        "query": query,
        "index": ["logs-*", "winlogbeat-*"],
        "severity": "high",
        "risk_score": 73,
        "interval": "5m",
        "from": "now-6m",
        "enabled": True,
        "max_signals": 100,
        "tags": ["Detection-as-Code"],
        "meta": {"dac": {"content_hash": h}},
    }
    return ConvertedRule(Path(f"rules/{rule_id}.yml"), rule_id, title, query, payload)


class FakeKibana:
    """In-memory Detection Engine with the same API surface as KibanaRulesApi."""

    def __init__(self, rules: list[dict[str, Any]] | None = None, fail_on: set[str] | None = None):
        self.rules = {r["rule_id"]: copy.deepcopy(r) for r in rules or []}
        self.fail_on = fail_on or set()
        self.calls: list[tuple[str, str]] = []

    def _check(self, op: str, rule_id: str) -> None:
        self.calls.append((op, rule_id))
        if rule_id in self.fail_on:
            raise DeployError(f"{op} rejected")

    def find_managed(self):
        return [copy.deepcopy(r) for r in self.rules.values()]

    def create(self, rule):
        self._check("create", rule["rule_id"])
        self.rules[rule["rule_id"]] = copy.deepcopy(rule)
        return rule

    def update(self, rule):
        self._check("update", rule["rule_id"])
        self.rules[rule["rule_id"]] = copy.deepcopy(rule)
        return rule

    def patch(self, rule_id, changes):
        self._check("patch", rule_id)
        self.rules[rule_id].update(changes)
        return self.rules[rule_id]

    def delete(self, rule_id):
        self._check("delete", rule_id)
        del self.rules[rule_id]


def _kinds(p) -> dict[str, str]:
    return {a.rule_id: a.kind for a in p.actions}


def test_first_deploy_creates_and_second_is_noop():
    desired = [_rule("a", "A"), _rule("b", "B")]
    kibana = FakeKibana()
    p1 = plan(desired, kibana.find_managed())
    assert _kinds(p1) == {"a": "create", "b": "create"}
    assert apply(p1, kibana, log=lambda _: None) == []
    p2 = plan(desired, kibana.find_managed())
    assert p2.changes == [] and _kinds(p2) == {"a": "unchanged", "b": "unchanged"}


def test_changed_hash_is_an_update():
    kibana = FakeKibana([_rule("a", "A", h="old").payload])
    assert _kinds(plan([_rule("a", "A", h="new")], kibana.find_managed())) == {"a": "update"}


def test_manual_edit_in_kibana_is_drift():
    deployed = _rule("a", "A").payload | {"severity": "low", "enabled": False}
    p = plan([_rule("a", "A")], [deployed])
    action = p.actions[0]
    assert action.kind == "drift"
    assert "severity" in action.detail and "enabled" in action.detail


def test_index_order_is_not_drift():
    deployed = _rule("a", "A").payload | {"index": ["winlogbeat-*", "logs-*"]}
    assert plan([_rule("a", "A")], [deployed]).changes == []


def test_orphans_are_disabled_or_pruned():
    current = [_rule("a", "A").payload, _rule("gone", "Gone").payload]
    assert _kinds(plan([_rule("a", "A")], current))["gone"] == "disable"
    assert _kinds(plan([_rule("a", "A")], current, prune=True))["gone"] == "delete"
    disabled = _rule("gone", "Gone").payload | {"enabled": False}
    assert (
        _kinds(plan([_rule("a", "A")], [_rule("a", "A").payload, disabled]))["gone"] == "unchanged"
    )


def test_force_redeploys_everything():
    kibana = FakeKibana([_rule("a", "A").payload])
    p = plan([_rule("a", "A")], kibana.find_managed(), force=True)
    assert _kinds(p) == {"a": "update"} and p.actions[0].detail == "forced"


def test_apply_continues_after_a_failure():
    kibana = FakeKibana(fail_on={"b"})
    p = plan([_rule("a", "A"), _rule("b", "B"), _rule("c", "C")], [])
    errors = apply(p, kibana, log=lambda _: None)
    assert len(errors) == 1 and "B" in errors[0]
    assert set(kibana.rules) == {"a", "c"}


def test_apply_uses_the_right_api_calls():
    kibana = FakeKibana([_rule("u", "U", h="old").payload, _rule("o", "O").payload])
    p = plan([_rule("n", "N"), _rule("u", "U", h="new")], kibana.find_managed())
    apply(p, kibana, log=lambda _: None)
    assert sorted(kibana.calls) == [("create", "n"), ("patch", "o"), ("update", "u")]
    assert kibana.rules["o"]["enabled"] is False
