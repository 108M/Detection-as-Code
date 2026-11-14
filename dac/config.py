"""Configuration: environment variables override values from lab/.env."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

LAB_DIR = Path("lab")
ENV_FILE = LAB_DIR / ".env"
ENV_EXAMPLE = LAB_DIR / ".env.example"


def read_env_file(path: Path = ENV_FILE) -> dict[str, str]:
    """Parse a simple KEY=VALUE file (no interpolation, # comments)."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def update_env_file(updates: dict[str, str], path: Path = ENV_FILE) -> None:
    """Set keys in an env file, preserving order and comments."""
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    pending = dict(updates)
    out: list[str] = []
    for raw in lines:
        key = raw.split("=", 1)[0].strip()
        if "=" in raw and not raw.lstrip().startswith("#") and key in pending:
            out.append(f"{key}={pending.pop(key)}")
        else:
            out.append(raw)
    out.extend(f"{k}={v}" for k, v in pending.items())
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class Settings:
    es_url: str
    kibana_url: str
    api_key: str | None
    elastic_password: str | None
    pipeline_password: str | None

    @classmethod
    def load(cls) -> Settings:
        file_values = read_env_file()

        def get(key: str, default: str | None = None) -> str | None:
            value = os.environ.get(key) or file_values.get(key) or default
            return value or None

        return cls(
            es_url=get("DAC_ES_URL", "http://localhost:9200"),
            kibana_url=get("DAC_KIBANA_URL", "http://localhost:5601"),
            api_key=get("DAC_API_KEY"),
            elastic_password=get("ELASTIC_PASSWORD"),
            pipeline_password=get("DAC_PIPELINE_PASSWORD"),
        )
