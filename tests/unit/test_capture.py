"""Unit tests for own captures: dataset registration and the windows-json format."""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest

from dac.capture import CaptureError, register, run_capture
from dac.datasets import iter_events, load_manifest

MANIFEST = """\
sources:
  otrf:
    base_url: https://example.test
    format: otrf-json

datasets:
  - id: otrf_x
    source: otrf
    path: x.zip
    sha256: abc
    techniques: [T1003.001]
    description: public dataset
"""

EVENT = {
    "EventID": 1,
    "Channel": "Microsoft-Windows-Sysmon/Operational",
    "SourceName": "Microsoft-Windows-Sysmon",
    "Hostname": "dac-win11",
    "TimeCreated": "2026-11-16T10:00:00.000Z",
    "RecordId": 42,
    "UtcTime": "2026-11-16 10:00:00.000",
    "Image": r"C:\Windows\System32\mshta.exe",
    "CommandLine": "mshta.exe vbscript:Execute(...)",
    "ParentImage": r"C:\Windows\System32\cmd.exe",
}


def _result(sha: str = "f" * 64) -> dict:
    return {
        "name": "mshta_vbscript",
        "technique": "T1218.005",
        "tests": "1",
        "events": 3,
        "sha256": sha,
    }


def test_register_appends_own_section_and_replaces(tmp_path: Path):
    path = tmp_path / "sources.yml"
    path.write_text(MANIFEST, encoding="utf-8")
    assert register(_result(), "first", path) == "dac_mshta_vbscript"
    register(_result("e" * 64), "second", path)
    text = path.read_text(encoding="utf-8")
    assert text.count("- id: dac_mshta_vbscript") == 1
    assert f'sha256: "{"e" * 64}"' in text and '"second"' in text
    assert text.count("Own captures") == 1
    assert "- id: otrf_x" in text  # existing entries untouched


def test_registered_capture_is_loaded_and_normalised(tmp_path: Path, monkeypatch):
    captures = tmp_path / "captures"
    captures.mkdir()
    blob = gzip.compress((json.dumps(EVENT) + "\n").encode("utf-8"))
    (captures / "mshta_vbscript.json.gz").write_bytes(blob)
    sha = hashlib.sha256(blob).hexdigest()
    path = tmp_path / "sources.yml"
    path.write_text(MANIFEST, encoding="utf-8")
    register(_result(sha), "mshta", path)

    monkeypatch.setattr("dac.datasets.LOCAL_DIR", tmp_path)
    ds = next(d for d in load_manifest(path) if d.id == "dac_mshta_vbscript")
    assert ds.format == "windows-json" and ds.techniques == ["T1218.005"]
    (doc,) = list(iter_events(ds, log=lambda _: None))
    assert doc["process"]["executable"].endswith("mshta.exe")
    assert doc["event"]["category"] == ["process"]
    assert doc["host"]["name"] == "dac-win11"


def test_tampered_capture_fails_verification(tmp_path: Path, monkeypatch):
    captures = tmp_path / "captures"
    captures.mkdir()
    (captures / "mshta_vbscript.json.gz").write_bytes(gzip.compress(b"{}\n"))
    path = tmp_path / "sources.yml"
    path.write_text(MANIFEST, encoding="utf-8")
    register(_result("0" * 64), "mshta", path)
    monkeypatch.setattr("dac.datasets.LOCAL_DIR", tmp_path)
    ds = next(d for d in load_manifest(path) if d.id == "dac_mshta_vbscript")
    with pytest.raises(Exception, match="sha256 mismatch"):
        list(iter_events(ds, log=lambda _: None))


def test_capture_name_must_be_snake_case():
    with pytest.raises(CaptureError):
        run_capture("T1218.005", "1", "Bad-Name")
