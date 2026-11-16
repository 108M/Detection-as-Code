"""`dac deploy`: reconcile Kibana's Detection Engine with the rules in the repository.

The repository is the source of truth. Rules deployed by this tool carry the
`Detection-as-Code` tag and `meta.dac.content_hash`; only those are ever touched.

  create     rule in the repo, not in Kibana
  update     content hash changed (rule, pipeline or conversion changed)
  drift      same hash, but someone edited the rule in Kibana: restored from the repo
  disable    managed rule no longer in the repo (default: kept, but disabled)
  delete     same, with --prune
  unchanged  nothing to do (a second run after a deploy is all `unchanged`)
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Protocol

import requests

from dac.config import Settings
from dac.convert import ConvertedRule

MANAGED_TAG = "Detection-as-Code"
RULES_API = "/api/detection_engine/rules"

# Fields compared to detect manual edits in Kibana (beyond the content hash).
DRIFT_FIELDS = (
    "name",
    "query",
    "index",
    "severity",
    "risk_score",
    "interval",
    "from",
    "enabled",
    "max_signals",
    "type",
    "language",
)


class DeployError(RuntimeError):
    pass


class RulesApi(Protocol):
    def find_managed(self) -> list[dict[str, Any]]: ...
    def create(self, rule: dict[str, Any]) -> dict[str, Any]: ...
    def update(self, rule: dict[str, Any]) -> dict[str, Any]: ...
    def patch(self, rule_id: str, changes: dict[str, Any]) -> dict[str, Any]: ...
    def delete(self, rule_id: str) -> None: ...


class KibanaRulesApi:
    """Thin client for the Detection Engine rules API, authenticated with an API key."""

    def __init__(self, settings: Settings, timeout: int = 60) -> None:
        if not settings.api_key:
            raise DeployError("DAC_API_KEY not set (run `dac lab setup` or export it)")
        self.base = settings.kibana_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"ApiKey {settings.api_key}",
                "kbn-xsrf": "dac",
                "Content-Type": "application/json",
            }
        )
        self.timeout = timeout

    def _call(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        resp = self.session.request(method, f"{self.base}{path}", timeout=self.timeout, **kwargs)
        if not resp.ok:
            raise DeployError(f"{method} {path} -> {resp.status_code}: {resp.text[:400]}")
        return resp.json() if resp.content else {}

    def _pages(self) -> Iterator[dict[str, Any]]:
        page = 1
        while True:
            body = self._call(
                "GET",
                f"{RULES_API}/_find",
                params={
                    "page": page,
                    "per_page": 100,
                    "filter": f'alert.attributes.tags:"{MANAGED_TAG}"',
                },
            )
            yield from body.get("data", [])
            if page * body.get("per_page", 100) >= body.get("total", 0):
                return
            page += 1

    def find_managed(self) -> list[dict[str, Any]]:
        return list(self._pages())

    def create(self, rule: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", RULES_API, json=rule)

    def update(self, rule: dict[str, Any]) -> dict[str, Any]:
        return self._call("PUT", RULES_API, json=rule)

    def patch(self, rule_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        return self._call("PATCH", RULES_API, json={"rule_id": rule_id, **changes})

    def delete(self, rule_id: str) -> None:
        self._call("DELETE", RULES_API, params={"rule_id": rule_id})


@dataclass
class Action:
    kind: str  # create | update | drift | disable | delete | unchanged
    rule_id: str
    name: str
    detail: str = ""
    payload: dict[str, Any] | None = None


@dataclass
class Plan:
    actions: list[Action] = field(default_factory=list)

    @property
    def changes(self) -> list[Action]:
        return [a for a in self.actions if a.kind != "unchanged"]

    def count(self, kind: str) -> int:
        return sum(1 for a in self.actions if a.kind == kind)


def _hash(rule: dict[str, Any]) -> str | None:
    return ((rule.get("meta") or {}).get("dac") or {}).get("content_hash")


def _normalise(value: Any) -> Any:
    return (
        sorted(value)
        if isinstance(value, list) and all(isinstance(v, str) for v in value)
        else value
    )


def drifted_fields(desired: dict[str, Any], current: dict[str, Any]) -> list[str]:
    return [
        f
        for f in DRIFT_FIELDS
        if f in desired and _normalise(desired.get(f)) != _normalise(current.get(f))
    ]


def plan(
    desired: list[ConvertedRule],
    current: list[dict[str, Any]],
    prune: bool = False,
    force: bool = False,
) -> Plan:
    out = Plan()
    by_id = {r["rule_id"]: r for r in current}
    wanted = {r.rule_id for r in desired}

    for rule in sorted(desired, key=lambda r: r.title):
        existing = by_id.get(rule.rule_id)
        if existing is None:
            out.actions.append(Action("create", rule.rule_id, rule.title, payload=rule.payload))
        elif _hash(existing) != _hash(rule.payload) or force:
            reason = "content changed" if _hash(existing) != _hash(rule.payload) else "forced"
            out.actions.append(Action("update", rule.rule_id, rule.title, reason, rule.payload))
        elif fields := drifted_fields(rule.payload, existing):
            out.actions.append(
                Action(
                    "drift",
                    rule.rule_id,
                    rule.title,
                    "edited in Kibana: " + ", ".join(fields),
                    rule.payload,
                )
            )
        else:
            out.actions.append(Action("unchanged", rule.rule_id, rule.title))

    for existing in sorted(current, key=lambda r: r.get("name", "")):
        if existing["rule_id"] in wanted:
            continue
        name = existing.get("name", existing["rule_id"])
        if prune:
            out.actions.append(Action("delete", existing["rule_id"], name, "not in repository"))
        elif existing.get("enabled"):
            out.actions.append(Action("disable", existing["rule_id"], name, "not in repository"))
        else:
            out.actions.append(
                Action("unchanged", existing["rule_id"], name, "orphan, already disabled")
            )
    return out


def apply(plan_: Plan, api: RulesApi, log: Callable[[str], None] = print) -> list[str]:
    """Execute the plan; returns error messages (one failing rule does not stop the rest)."""
    errors: list[str] = []
    for action in plan_.changes:
        try:
            if action.kind == "create":
                api.create(action.payload or {})
            elif action.kind in ("update", "drift"):
                api.update(action.payload or {})
            elif action.kind == "disable":
                api.patch(action.rule_id, {"enabled": False})
            elif action.kind == "delete":
                api.delete(action.rule_id)
            log(f"  {action.kind:9} ok  {action.name}")
        except DeployError as exc:
            errors.append(f"{action.kind} {action.name}: {exc}")
            log(f"  {action.kind:9} ERR {action.name}: {exc}")
    return errors
