"""Rule validation: pySigma validators + project conventions + ATT&CK consistency."""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError, SigmaRuleLocation
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaValidationIssueSeverity
from sigma.validators.core import validators as core_validators

from dac import attack

CASES_DIR = Path("tests/cases")
FILENAME_RE = re.compile(r"^[a-z0-9]+(_[a-z0-9]+)*\.yml$")
TECHNIQUE_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
OTHER_TAG_RE = re.compile(r"^attack\.([gsc]\d{4})$")

REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "tags",
    "logsource",
    "detection",
    "falsepositives",
    "level",
)
ALLOWED_STATUS = {"stable", "test", "experimental"}
ALLOWED_LEVEL = {"informational", "low", "medium", "high", "critical"}

# Replaced by our own pinned-version ATT&CK check below.
EXCLUDED_CORE_VALIDATORS = {"attacktag"}


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Issue:
    path: Path
    severity: Severity
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.severity.value}: [{self.code}] {self.message}"


def discover(rules_dir: Path) -> list[Path]:
    return sorted(p for p in rules_dir.rglob("*.yml") if p.is_file())


def _sigma_issues(paths: list[Path]) -> tuple[list[Issue], dict[Path, SigmaRule]]:
    """Parse with pySigma and run its core validators."""
    issues: list[Issue] = []
    rules: dict[Path, SigmaRule] = {}
    for path in paths:
        try:
            collection = SigmaCollection.from_yaml(
                path.read_text(encoding="utf-8"),
                collect_errors=True,
                source=SigmaRuleLocation(path),
            )
        except Exception as exc:  # noqa: BLE001 - YAML errors are reported by _metadata step
            if not isinstance(exc, yaml.YAMLError):
                issues.append(Issue(path, Severity.ERROR, "sigma-parse", str(exc)))
            continue
        for rule in collection.rules:
            errors = list(rule.errors)
            if isinstance(rule, SigmaRule) and not errors:
                # pySigma resolves condition identifiers lazily (at conversion time);
                # force it here so a broken condition fails validation.
                for cond in rule.detection.parsed_condition:
                    try:
                        cond.parsed  # noqa: B018
                    except SigmaError as exc:
                        errors.append(exc)
            for err in errors:
                issues.append(Issue(path, Severity.ERROR, "sigma-parse", str(err)))
            if isinstance(rule, SigmaRule) and not errors:
                rules[path] = rule

    selected = [v for name, v in core_validators.items() if name not in EXCLUDED_CORE_VALIDATORS]
    validator = SigmaValidator(selected)
    for issue in validator.validate_rules(list(rules.values())):
        severity = (
            Severity.WARNING
            if issue.severity == SigmaValidationIssueSeverity.LOW
            else Severity.ERROR
        )
        for rule in issue.rules:
            path = Path(rule.source.path) if rule.source else Path("?")
            issues.append(Issue(path, severity, f"sigma-{type(issue).__name__}", issue.description))
    return issues, rules


def _metadata_issues(path: Path, raw: dict) -> list[Issue]:
    issues: list[Issue] = []

    def err(code: str, msg: str) -> None:
        issues.append(Issue(path, Severity.ERROR, code, msg))

    for name in REQUIRED_FIELDS:
        if raw.get(name) in (None, "", []):
            err("missing-field", f"required field '{name}' is missing or empty")

    if raw.get("status") and raw["status"] not in ALLOWED_STATUS:
        err("invalid-status", f"status '{raw['status']}' not in {sorted(ALLOWED_STATUS)}")
    if raw.get("level") and raw["level"] not in ALLOWED_LEVEL:
        err("invalid-level", f"level '{raw['level']}' not in {sorted(ALLOWED_LEVEL)}")

    date = raw.get("date")
    if date and not isinstance(date, dt.date):
        try:
            dt.date.fromisoformat(str(date))
        except ValueError:
            err("invalid-date", f"date '{date}' must be YYYY-MM-DD")

    if not FILENAME_RE.match(path.name):
        err("filename", "file name must be lowercase snake_case ending in .yml")

    title = str(raw.get("title", ""))
    if len(title) > 110:
        err("title-length", f"title is {len(title)} chars (max 110)")
    return issues


def _attack_issues(path: Path, tags: list[str], data: attack.AttackData) -> list[Issue]:
    issues: list[Issue] = []

    def err(code: str, msg: str) -> None:
        issues.append(Issue(path, Severity.ERROR, code, msg))

    attack_tags = [t for t in tags if isinstance(t, str) and t.startswith("attack.")]
    techniques: list[attack.Technique] = []
    tactics: set[str] = set()

    for tag in attack_tags:
        if m := TECHNIQUE_TAG_RE.match(tag):
            tid = m.group(1).upper()
            tech = data.techniques.get(tid)
            if tech is None:
                err("attack-unknown", f"{tag}: technique {tid} not found in ATT&CK v{data.version}")
            elif tech.revoked:
                hint = f", replaced by {tech.revoked_by}" if tech.revoked_by else ""
                err("attack-revoked", f"{tag}: technique {tid} is revoked in v{data.version}{hint}")
            elif tech.deprecated:
                err("attack-deprecated", f"{tag}: technique {tid} is deprecated in v{data.version}")
            else:
                techniques.append(tech)
        elif m := OTHER_TAG_RE.match(tag):
            if m.group(1).upper() not in data.other_ids:
                err("attack-unknown", f"{tag}: not found in ATT&CK v{data.version}")
        else:
            shortname = tag.removeprefix("attack.")
            if shortname in data.tactics:
                tactics.add(shortname)
            else:
                err("attack-unknown", f"{tag}: unknown tactic or malformed ATT&CK tag")

    if not techniques and not any(i.code.startswith("attack-") for i in issues):
        err("attack-missing", "at least one ATT&CK technique tag (attack.tXXXX) is required")
    if not tactics and not any(i.code == "attack-unknown" for i in issues):
        err("attack-missing", "at least one ATT&CK tactic tag (e.g. attack.execution) is required")

    # Each technique must belong to at least one of the tactics the rule declares.
    for tech in techniques:
        if tactics and not tech.tactics & tactics:
            err(
                "attack-tactic-mismatch",
                f"{tech.id} ({tech.name}) belongs to {sorted(tech.tactics)}, "
                f"none of which is tagged",
            )
    # Each declared tactic should be backed by at least one technique.
    for tactic in sorted(tactics):
        if techniques and not any(tactic in t.tactics for t in techniques):
            issues.append(
                Issue(
                    path,
                    Severity.WARNING,
                    "attack-orphan-tactic",
                    f"tactic '{tactic}' has no matching technique tag",
                )
            )
    return issues


def _test_case_issues(path: Path, cases_dir: Path) -> list[Issue]:
    if (cases_dir / path.name).exists():
        return []
    return [
        Issue(
            path,
            Severity.WARNING,
            "untested",
            f"no test case found at {(cases_dir / path.name).as_posix()}",
        )
    ]


def validate(
    rules_dir: Path,
    cases_dir: Path = CASES_DIR,
    attack_data: attack.AttackData | None = None,
) -> tuple[list[Issue], int]:
    """Validate every rule under rules_dir. Returns (issues, number_of_rules)."""
    paths = discover(rules_dir)
    if not paths:
        return [Issue(rules_dir, Severity.ERROR, "no-rules", "no .yml rules found")], 0

    data = attack_data or attack.load()
    issues, _ = _sigma_issues(paths)

    for path in paths:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            issues.append(Issue(path, Severity.ERROR, "yaml", str(exc).replace("\n", " ")))
            continue
        if not isinstance(raw, dict):
            issues.append(Issue(path, Severity.ERROR, "yaml", "rule must be a YAML mapping"))
            continue
        issues += _metadata_issues(path, raw)
        issues += _attack_issues(path, raw.get("tags") or [], data)
        issues += _test_case_issues(path, cases_dir)

    # Normalise paths so output is stable regardless of how pySigma reports them.
    def norm(p: Path) -> Path:
        try:
            return p.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            return p

    unique = {(norm(i.path), i.severity, i.code, i.message): None for i in issues}
    result = [Issue(*k) for k in unique]
    result.sort(key=lambda i: (str(i.path), i.severity != Severity.ERROR, i.code))
    return result, len(paths)
