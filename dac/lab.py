"""Lab bootstrap: secrets, pipeline identity, API key and index templates."""

from __future__ import annotations

import secrets
import shutil
import string
import time
from collections.abc import Callable
from typing import Any

import requests

from dac.config import ENV_EXAMPLE, ENV_FILE, Settings, update_env_file

PIPELINE_USER = "dac_pipeline"
PIPELINE_ROLE = "dac_pipeline"
TEST_INDEX_TEMPLATE = "dac-test"
TEST_INDEX_PATTERN = "dac-test-*"

# Indices the pipeline reads/writes. Detection rules run with the privileges of
# the API key that created them, so it needs the source data and the alerts index.
PIPELINE_INDICES = [
    "dac-*",
    "logs-*",
    ".alerts-security*",
    ".siem-signals-*",
    ".lists-*",
    ".items-*",
    ".internal.alerts-security*",
    ".preview.alerts-security*",
    ".internal.preview.alerts-security*",
]

# Sigma matching is case-insensitive: keyword fields in test indices are
# lowercased so converted queries behave the same way in the lab.
TEST_TEMPLATE_BODY: dict[str, Any] = {
    "index_patterns": [TEST_INDEX_PATTERN],
    "priority": 200,
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "analysis": {
                "normalizer": {"dac_lowercase": {"type": "custom", "filter": ["lowercase"]}}
            },
        },
        "mappings": {
            "dynamic_templates": [
                {
                    "strings_as_keyword": {
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "keyword",
                            "normalizer": "dac_lowercase",
                            "ignore_above": 8191,
                        },
                    }
                }
            ],
            "properties": {"@timestamp": {"type": "date"}},
        },
    },
    "_meta": {"managed_by": "detection-as-code"},
}


class LabError(RuntimeError):
    pass


def _random_secret(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def init_env(force: bool = False) -> bool:
    """Create lab/.env from the example with random secrets. Returns True if created."""
    if ENV_FILE.exists() and not force:
        return False
    shutil.copyfile(ENV_EXAMPLE, ENV_FILE)
    update_env_file(
        {
            "ELASTIC_PASSWORD": _random_secret(24),
            "KIBANA_PASSWORD": _random_secret(24),
            "KIBANA_ENCRYPTION_KEY": _random_secret(48),
        }
    )
    return True


def _wait(check: Callable[[], bool], what: str, timeout: int, log: Callable[[str], None]) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():
                log(f"{what}: ready")
                return
        except requests.RequestException:
            pass
        time.sleep(5)
    raise LabError(f"{what} not ready after {timeout}s")


def _check(resp: requests.Response, action: str) -> dict[str, Any]:
    if not resp.ok:
        raise LabError(f"{action} failed ({resp.status_code}): {resp.text[:500]}")
    return resp.json() if resp.content else {}


def setup(settings: Settings, log: Callable[[str], None] = print, timeout: int = 300) -> None:
    """Idempotent bootstrap of the pipeline identity and test index template."""
    if not settings.elastic_password:
        raise LabError("ELASTIC_PASSWORD not set (run `dac lab init` first)")

    es = requests.Session()
    es.auth = ("elastic", settings.elastic_password)
    kb = requests.Session()
    kb.auth = ("elastic", settings.elastic_password)
    kb.headers.update({"kbn-xsrf": "dac", "Content-Type": "application/json"})

    _wait(
        lambda: (
            es.get(f"{settings.es_url}/_cluster/health", timeout=5).json().get("status")
            in ("green", "yellow")
        ),
        "Elasticsearch",
        timeout,
        log,
    )
    _wait(
        lambda: (
            kb.get(f"{settings.kibana_url}/api/status", timeout=5)
            .json()
            .get("status", {})
            .get("overall", {})
            .get("level")
            == "available"
        ),
        "Kibana",
        timeout,
        log,
    )

    # 1. Role with ES index privileges + Kibana Security (siem) feature.
    role = {
        "elasticsearch": {
            "cluster": ["monitor", "manage_index_templates", "manage_own_api_key"],
            "indices": [
                {
                    "names": PIPELINE_INDICES,
                    "privileges": ["all"],
                    "allow_restricted_indices": False,
                }
            ],
        },
        "kibana": [
            {
                "base": [],
                "feature": {"siem": ["all"], "actions": ["all"], "stackAlerts": ["all"]},
                "spaces": ["default"],
            }
        ],
    }
    _check(
        kb.put(f"{settings.kibana_url}/api/security/role/{PIPELINE_ROLE}", json=role, timeout=30),
        "create role",
    )
    log(f"role {PIPELINE_ROLE}: ok")

    # 2. Pipeline user (password persisted in lab/.env).
    password = settings.pipeline_password or _random_secret(24)
    _check(
        es.put(
            f"{settings.es_url}/_security/user/{PIPELINE_USER}",
            json={
                "password": password,
                "roles": [PIPELINE_ROLE],
                "full_name": "Detection-as-Code pipeline",
            },
            timeout=30,
        ),
        "create user",
    )
    update_env_file({"DAC_PIPELINE_PASSWORD": password})
    log(f"user {PIPELINE_USER}: ok")

    # 3. API key owned by the pipeline user (inherits its privileges).
    if settings.api_key and _api_key_valid(settings):
        log("API key: existing key still valid, keeping it")
    else:
        key = _check(
            requests.post(
                f"{settings.es_url}/_security/api_key",
                auth=(PIPELINE_USER, password),
                json={"name": "dac-pipeline", "metadata": {"managed_by": "detection-as-code"}},
                timeout=30,
            ),
            "create API key",
        )
        update_env_file({"DAC_API_KEY": key["encoded"]})
        log("API key: created and stored in lab/.env")

    # 4. Index template for test telemetry.
    _check(
        es.put(
            f"{settings.es_url}/_index_template/{TEST_INDEX_TEMPLATE}",
            json=TEST_TEMPLATE_BODY,
            timeout=30,
        ),
        "create index template",
    )
    log(f"index template {TEST_INDEX_TEMPLATE} ({TEST_INDEX_PATTERN}): ok")


def _api_key_valid(settings: Settings) -> bool:
    try:
        resp = requests.get(
            f"{settings.es_url}/_security/_authenticate",
            headers={"Authorization": f"ApiKey {settings.api_key}"},
            timeout=10,
        )
    except requests.RequestException:
        return False
    return resp.ok


def check(settings: Settings) -> list[tuple[str, bool, str]]:
    """Health checks using only the pipeline API key."""
    results: list[tuple[str, bool, str]] = []
    if not settings.api_key:
        return [("API key", False, "DAC_API_KEY not set (run `dac lab setup`)")]
    headers = {"Authorization": f"ApiKey {settings.api_key}", "kbn-xsrf": "dac"}

    def run(name: str, fn: Callable[[], str]) -> None:
        try:
            results.append((name, True, fn()))
        except Exception as exc:  # noqa: BLE001 - report any failure as a check result
            results.append((name, False, str(exc)[:300]))

    def es_auth() -> str:
        r = _check(
            requests.get(f"{settings.es_url}/_security/_authenticate", headers=headers, timeout=10),
            "authenticate",
        )
        return f"user={r['username']} via {r['authentication_type']}"

    def es_health() -> str:
        r = _check(
            requests.get(f"{settings.es_url}/_cluster/health", headers=headers, timeout=10),
            "cluster health",
        )
        return f"status={r['status']}"

    def template() -> str:
        _check(
            requests.get(
                f"{settings.es_url}/_index_template/{TEST_INDEX_TEMPLATE}",
                headers=headers,
                timeout=10,
            ),
            "index template",
        )
        return TEST_INDEX_PATTERN

    def kibana_status() -> str:
        r = _check(
            requests.get(f"{settings.kibana_url}/api/status", headers=headers, timeout=10),
            "kibana status",
        )
        return f"version={r['version']['number']} level={r['status']['overall']['level']}"

    def detection_engine() -> str:
        r = _check(
            requests.get(
                f"{settings.kibana_url}/api/detection_engine/rules/_find",
                params={"per_page": 1},
                headers=headers,
                timeout=30,
            ),
            "detection engine",
        )
        return f"rules installed={r.get('total', 0)}"

    run("Elasticsearch auth", es_auth)
    run("Elasticsearch health", es_health)
    run("Test index template", template)
    run("Kibana status", kibana_status)
    run("Detection Engine API", detection_engine)
    return results
