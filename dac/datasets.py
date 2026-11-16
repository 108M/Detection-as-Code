"""Dataset manifest: download (pinned + sha256), extract and normalise to ECS ndjson."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import tarfile
import zipfile
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
import yaml

from dac.normalize import NORMALIZER_VERSION, iter_kv_events, normalize, parse_xml_event

SOURCES_FILE = Path("tests/datasets/sources.yml")
LOCAL_DIR = Path("tests/datasets")  # own captures (Phase 7) live here, already ECS
CACHE_DIR = Path(os.environ.get("DAC_CACHE_DIR", ".cache")) / "datasets"


class DatasetError(RuntimeError):
    pass


@dataclass
class Dataset:
    id: str
    format: str
    url: str | None = None
    local_path: Path | None = None
    sha256: str | None = None
    techniques: list[str] = field(default_factory=list)
    description: str = ""

    @property
    def raw_path(self) -> Path:
        suffix = "".join(Path(self.url or "x.bin").suffixes[-2:]) or ".bin"
        return CACHE_DIR / "raw" / f"{self.id}{suffix}"

    def fingerprint(self) -> str:
        """Identifies the normalised content: changes if the data or normaliser changes."""
        source = self.sha256 or (_sha256(self.local_path) if self.local_path else "unknown")
        return f"{source}:{self.format}:{NORMALIZER_VERSION}"


def load_manifest(path: Path = SOURCES_FILE) -> list[Dataset]:
    spec = yaml.safe_load(path.read_text(encoding="utf-8"))
    sources = spec.get("sources", {})
    out: list[Dataset] = []
    seen: set[str] = set()
    for entry in spec.get("datasets", []):
        ds_id = entry["id"]
        if ds_id in seen:
            raise DatasetError(f"duplicate dataset id {ds_id}")
        seen.add(ds_id)
        if "source" in entry:
            src = sources[entry["source"]]
            out.append(
                Dataset(
                    id=ds_id,
                    format=entry.get("format", src["format"]),
                    url=f"{src['base_url'].rstrip('/')}/{entry['path']}",
                    sha256=entry.get("sha256"),
                    techniques=entry.get("techniques", []),
                    description=entry.get("description", ""),
                )
            )
        else:
            out.append(
                Dataset(
                    id=ds_id,
                    format="ecs-ndjson",
                    local_path=LOCAL_DIR / entry["path"],
                    techniques=entry.get("techniques", []),
                    description=entry.get("description", ""),
                )
            )
    return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(ds: Dataset, log: Callable[[str], None] = print) -> str:
    """Download if needed and verify. Returns the sha256 of the raw file."""
    if ds.local_path:
        if not ds.local_path.exists():
            raise DatasetError(f"{ds.id}: local file {ds.local_path} not found")
        return _sha256(ds.local_path)
    if not ds.raw_path.exists():
        ds.raw_path.parent.mkdir(parents=True, exist_ok=True)
        log(f"  downloading {ds.id}")
        resp = requests.get(ds.url, timeout=300)
        resp.raise_for_status()
        if resp.content.startswith(b"version https://git-lfs"):
            raise DatasetError(f"{ds.id}: got a Git LFS pointer, not the file ({ds.url})")
        tmp = ds.raw_path.with_suffix(".part")
        tmp.write_bytes(resp.content)
        tmp.replace(ds.raw_path)
    digest = _sha256(ds.raw_path)
    if ds.sha256 and digest != ds.sha256:
        ds.raw_path.unlink()
        raise DatasetError(f"{ds.id}: sha256 mismatch (expected {ds.sha256}, got {digest})")
    return digest


def _is_data_file(name: str) -> bool:
    """JSON members only, ignoring macOS archive metadata (__MACOSX/, ._ files)."""
    base = name.rsplit("/", 1)[-1]
    return name.endswith(".json") and not name.startswith("__MACOSX/") and not base.startswith("._")


def _iter_raw(ds: Dataset) -> Iterator[dict[str, Any]]:
    path = ds.raw_path
    if ds.format == "otrf-json":
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                members = [(n, zf.read(n)) for n in zf.namelist() if _is_data_file(n)]
        else:
            with tarfile.open(path, "r:*") as tf:
                members = [
                    (m.name, tf.extractfile(m).read())  # type: ignore[union-attr]
                    for m in tf.getmembers()
                    if m.isfile() and _is_data_file(m.name)
                ]
        for _, blob in sorted(members):
            for line in io.TextIOWrapper(io.BytesIO(blob), encoding="utf-8-sig", errors="replace"):
                if line.strip():
                    yield json.loads(line)
    elif ds.format == "windows-xml":
        # One <Event> per record, but a record may span several lines (multi-line
        # command lines), so split on the closing tag rather than on newlines.
        buffer = ""
        with path.open(encoding="utf-8-sig", errors="replace") as fh:
            for line in fh:
                buffer += line
                while "</Event>" in buffer:
                    record, buffer = buffer.split("</Event>", 1)
                    event = parse_xml_event(record + "</Event>")
                    if event is not None:
                        yield event
    elif ds.format == "windows-kv":
        with path.open(encoding="utf-8-sig", errors="replace") as fh:
            yield from iter_kv_events(fh)
    else:
        raise DatasetError(f"{ds.id}: unknown format {ds.format}")


def iter_events(ds: Dataset, log: Callable[[str], None] = print) -> Iterator[dict[str, Any]]:
    """Fetch (cached, verified) and yield ECS documents.

    Normalised output is streamed, never written to disk: decoded attack telemetry
    (e.g. Empire's Base64 PowerShell stager) is flagged and quarantined by endpoint
    AV (Defender: Trojan:PowerShell/Boxter). Only the original archives are cached.
    """
    fetch(ds, log)
    if ds.local_path:
        yield from _iter_ndjson(ds.local_path)
        return
    for raw in _iter_raw(ds):
        yield normalize(raw, ds.id)


def _iter_ndjson(path: Path) -> Iterator[dict[str, Any]]:
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield json.loads(line)
