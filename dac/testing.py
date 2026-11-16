"""`dac test`: run every converted rule against every dataset and grade the results.

For each rule, hits are attributed per dataset (one index per dataset) and compared
with the rule's test case (tests/cases/<rule-file-name>.yml):

  detects        datasets where the rule MUST fire (min_hits)      -> true positives
  also_detects   other datasets with real malicious activity it     -> not counted as FP
                 legitimately catches (documented with a reason)
  known_gaps     datasets with the technique the rule does NOT      -> documented misses
                 catch (variant / evasion), with a reason
  accepted_false_positives  documented benign noise with a hit budget -> FP (counted),
                 fails only if the budget (max_hits) is exceeded
  anything else  hits in any other dataset                          -> false positives

A rule fails if a `detects` dataset is missed or it exceeds `max_false_positives`.
"""

from __future__ import annotations

import datetime as dt
import json
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml
from elasticsearch import Elasticsearch, helpers

from dac import attack
from dac.config import Settings
from dac.convert import ConvertedRule, convert
from dac.datasets import Dataset, iter_events, load_manifest
from dac.lab import TEST_INDEX_PATTERN, TEST_INDEX_TEMPLATE, TEST_TEMPLATE_BODY
from dac.validate import discover

INDEX_PREFIX = "dac-test-"
MAX_HITS = 10_000


class TestSetupError(RuntimeError):
    pass


# --- Elasticsearch ---------------------------------------------------------------------


def es_client(settings: Settings) -> Elasticsearch:
    kwargs: dict[str, Any] = {"request_timeout": 120}
    if settings.api_key:
        kwargs["api_key"] = settings.api_key
    return Elasticsearch(settings.es_url, **kwargs)


def index_name(ds: Dataset) -> str:
    return f"{INDEX_PREFIX}{ds.id}".lower()


def load_datasets(
    es: Elasticsearch, datasets: list[Dataset], force: bool = False, log: Callable = print
) -> dict[str, int]:
    """Index each dataset into its own index; skip unchanged ones. Returns event counts."""
    es.indices.put_index_template(name=TEST_INDEX_TEMPLATE, **TEST_TEMPLATE_BODY)
    counts: dict[str, int] = {}
    for ds in datasets:
        name = index_name(ds)
        fingerprint = ds.fingerprint()
        if es.indices.exists(index=name) and not force:
            meta = es.indices.get_mapping(index=name)[name]["mappings"].get("_meta", {})
            if meta.get("dac_fingerprint") == fingerprint:
                counts[ds.id] = es.count(index=name)["count"]
                continue
        es.indices.delete(index=name, ignore_unavailable=True)
        es.indices.create(index=name)
        actions = ({"_index": name, "_source": doc} for doc in iter_events(ds, log))
        ok, errors = 0, []
        try:
            for success, info in helpers.streaming_bulk(
                es, actions, chunk_size=2000, raise_on_error=False, max_retries=2
            ):
                if success:
                    ok += 1
                elif len(errors) < 3:
                    errors.append(info)
            if errors:
                raise TestSetupError(f"{ds.id}: bulk indexing errors, e.g. {errors[0]}")
        except Exception:
            # Never leave a half-loaded index behind: it would be reused as valid.
            es.indices.delete(index=name, ignore_unavailable=True)
            raise
        es.indices.refresh(index=name)
        # The fingerprint marks the index as complete, so it is written last.
        es.indices.put_mapping(index=name, meta={"dac_fingerprint": fingerprint})
        counts[ds.id] = ok
        log(f"  indexed {ds.id}: {ok} events")
    return counts


def run_query(es: Elasticsearch, query: str) -> Counter:
    resp = es.eql.search(
        index=TEST_INDEX_PATTERN,
        query=query,
        size=MAX_HITS,
        filter_path=["hits.events._index"],
    )
    events = resp.get("hits", {}).get("events", [])
    return Counter(e["_index"].removeprefix(INDEX_PREFIX) for e in events)


# --- Test cases ------------------------------------------------------------------------


@dataclass
class DatasetResult:
    dataset: str
    hits: int
    expected: str  # detects | also_detects | known_gap | false_positive
    ok: bool
    note: str = ""


@dataclass
class RuleResult:
    rule_id: str
    title: str
    path: str
    status: str  # pass | fail | untested | error
    results: list[DatasetResult] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)

    @property
    def total_hits(self) -> int:
        return sum(r.hits for r in self.results)

    def hits_of(self, kind: str) -> int:
        return sum(r.hits for r in self.results if r.expected == kind)

    @property
    def tp_hits(self) -> int:
        return self.hits_of("detects") + self.hits_of("also_detects")

    @property
    def fp_hits(self) -> int:
        """Unexpected FPs plus documented (accepted) ones: both are noise for an analyst."""
        return self.hits_of("false_positive") + self.hits_of("accepted_fp")


def load_case(cases_dir: Path, rule: ConvertedRule) -> dict | None:
    path = cases_dir / rule.path.name
    if not path.exists():
        return None
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def grade(rule: ConvertedRule, case: dict | None, hits: Counter, known: set[str]) -> RuleResult:
    res = RuleResult(rule.rule_id, rule.title, rule.path.as_posix(), "pass")
    if case is None:
        res.status = "untested"
        res.results = [DatasetResult(d, n, "unlabeled", True) for d, n in sorted(hits.items())]
        return res

    labelled: set[str] = set()

    def check_known(dataset: str, section: str) -> bool:
        if dataset not in known:
            res.messages.append(f"{section}: unknown dataset '{dataset}'")
            res.status = "fail"
            return False
        labelled.add(dataset)
        return True

    for entry in case.get("detects", []):
        d = entry["dataset"]
        if not check_known(d, "detects"):
            continue
        n, minimum = hits.get(d, 0), int(entry.get("min_hits", 1))
        ok = n >= minimum
        res.results.append(DatasetResult(d, n, "detects", ok, f"min {minimum}"))
        if not ok:
            res.status = "fail"
            res.messages.append(f"MISSED {d}: {n} hits, expected >= {minimum}")

    for entry in case.get("also_detects", []):
        d = entry["dataset"]
        if not check_known(d, "also_detects"):
            continue
        n = hits.get(d, 0)
        res.results.append(DatasetResult(d, n, "also_detects", True, entry.get("reason", "")))
        if n == 0:
            res.messages.append(f"stale also_detects: no hits in {d} any more")

    for entry in case.get("known_gaps", []):
        d = entry["dataset"]
        if not check_known(d, "known_gaps"):
            continue
        n = hits.get(d, 0)
        res.results.append(DatasetResult(d, n, "known_gap", True, entry.get("reason", "")))
        if n:
            res.messages.append(f"gap closed? {n} hits in known gap {d}: move it to detects")

    for entry in case.get("accepted_false_positives", []):
        d = entry["dataset"]
        if not check_known(d, "accepted_false_positives"):
            continue
        n, cap = hits.get(d, 0), int(entry["max_hits"])
        ok = n <= cap
        res.results.append(DatasetResult(d, n, "accepted_fp", ok, entry.get("reason", "")))
        if not ok:
            res.status = "fail"
            res.messages.append(f"accepted FP budget exceeded in {d}: {n} hits (max {cap})")

    fp_total = 0
    for d, n in sorted(hits.items()):
        if d in labelled:
            continue
        fp_total += n
        res.results.append(DatasetResult(d, n, "false_positive", False))
    max_fp = int(case.get("max_false_positives", 0))
    if fp_total > max_fp:
        res.status = "fail"
        res.messages.append(f"{fp_total} false positive hits (max {max_fp})")
    return res


# --- Orchestration ---------------------------------------------------------------------


@dataclass
class TestReport:
    generated_at: str
    attack_version: str
    datasets: list[dict]
    rules: list[RuleResult]

    @property
    def summary(self) -> dict[str, Any]:
        statuses = Counter(r.status for r in self.rules)
        tested = [r for r in self.rules if r.status in ("pass", "fail")]
        expected = [x for r in tested for x in r.results if x.expected == "detects"]
        tp = sum(r.tp_hits for r in tested)
        fp = sum(r.fp_hits for r in tested)
        return {
            "rules": len(self.rules),
            "passed": statuses.get("pass", 0),
            "failed": statuses.get("fail", 0),
            "untested": statuses.get("untested", 0),
            "errors": statuses.get("error", 0),
            "datasets": len(self.datasets),
            "events": sum(d["events"] for d in self.datasets),
            "expected_detections": len(expected),
            "detected": sum(1 for x in expected if x.ok),
            "detection_rate": round(sum(1 for x in expected if x.ok) / len(expected), 4)
            if expected
            else None,
            "true_positive_hits": tp,
            "false_positive_hits": fp,
            "alert_precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
        }

    def to_json(self) -> str:
        return json.dumps(
            {
                "generated_at": self.generated_at,
                "attack_version": self.attack_version,
                "summary": self.summary,
                "datasets": self.datasets,
                "rules": [asdict(r) | {"total_hits": r.total_hits} for r in self.rules],
            },
            indent=2,
            ensure_ascii=False,
        )


def run(
    settings: Settings,
    rules_dir: Path,
    cases_dir: Path,
    force_reload: bool = False,
    log: Callable = print,
) -> TestReport:
    datasets = load_manifest()
    es = es_client(settings)
    if not es.ping():
        raise TestSetupError(f"Elasticsearch not reachable at {settings.es_url}")
    log(f"Loading {len(datasets)} datasets into {TEST_INDEX_PATTERN}")
    counts = load_datasets(es, datasets, force=force_reload, log=log)

    data = attack.load()
    conversion = convert(discover(rules_dir), index_override=[TEST_INDEX_PATTERN], attack_data=data)
    known = {d.id for d in datasets}
    results: list[RuleResult] = []
    for path, message in conversion.errors:
        results.append(RuleResult("?", path.name, path.as_posix(), "error", messages=[message]))
    for rule in conversion.rules:
        try:
            hits = run_query(es, rule.query)
        except Exception as exc:  # noqa: BLE001 - report as a rule error, keep going
            results.append(
                RuleResult(
                    rule.rule_id,
                    rule.title,
                    rule.path.as_posix(),
                    "error",
                    messages=[f"query failed: {exc}"],
                )
            )
            continue
        results.append(grade(rule, load_case(cases_dir, rule), hits, known))

    results.sort(key=lambda r: r.path)
    return TestReport(
        generated_at=dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
        attack_version=data.version,
        datasets=[
            {
                "id": d.id,
                "events": counts.get(d.id, 0),
                "techniques": d.techniques,
                "description": d.description,
            }
            for d in datasets
        ],
        rules=results,
    )


def markdown_summary(report: TestReport) -> str:
    s = report.summary
    icon = {"pass": "✅", "fail": "❌", "untested": "⚪", "error": "💥"}
    lines = [
        "## Detection tests",
        "",
        f"**{s['passed']}/{s['rules']} rules passed** · detection rate "
        f"{_pct(s['detection_rate'])} ({s['detected']}/{s['expected_detections']} expected "
        f"datasets) · {s['false_positive_hits']} false positive hits · alert precision "
        f"{_pct(s['alert_precision'])} · {s['events']:,} events in {s['datasets']} datasets",
        "",
        "| | Rule | TP hits | FP hits | Notes |",
        "|---|---|---:|---:|---|",
    ]
    for r in report.rules:
        tp = r.tp_hits
        notes = "; ".join(r.messages) or ""
        lines.append(f"| {icon.get(r.status, '?')} | {r.title} | {tp} | {r.fp_hits} | {notes} |")
    return "\n".join(lines) + "\n"


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x * 100:.1f}%"
