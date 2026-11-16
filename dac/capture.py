"""`dac lab capture`: run an Atomic Red Team test in the lab VM and register the capture.

Works with any Vagrant provider (Hyper-V or VirtualBox) and without shared folders:
  1. upload scripts/capture_atomic.ps1 to the VM (`vagrant upload`)
  2. run it elevated over WinRM; it writes C:\dac\captures\<name>.json.gz
  3. pull the file back base64-encoded over WinRM and verify its sha256
  4. save it as tests/datasets/captures/<name>.json.gz and register it in
     tests/datasets/sources.yml (pinned by sha256, like the public datasets)
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from dac.datasets import LOCAL_DIR, SOURCES_FILE

VM_DIR = Path("lab/vm")
LOCAL_SCRIPT = Path("scripts/capture_atomic.ps1")
VM_SCRIPT = r"C:\dac\capture_atomic.ps1"
VM_OUT_DIR = r"C:\dac\captures"
CAPTURES_DIR = LOCAL_DIR / "captures"
RESULT_MARKER = "DAC_CAPTURE_RESULT "
B64_BEGIN, B64_END = "DAC_B64_BEGIN", "DAC_B64_END"
OWN_SECTION = "  # --- Own captures (lab/vm, scripts/capture_atomic.ps1) ---"
NAME_RE = re.compile(r"^[a-z0-9_]+$")


class CaptureError(RuntimeError):
    pass


def vagrant_bin() -> str:
    found = shutil.which("vagrant")
    if found:
        return found
    for candidate in (
        Path(r"C:\Program Files\Vagrant\bin\vagrant.exe"),
        Path(r"C:\HashiCorp\Vagrant\bin\vagrant.exe"),
    ):
        if candidate.exists():
            return str(candidate)
    raise CaptureError("vagrant not found (install it and open a new terminal)")


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _vagrant(args: list[str], log: Callable[[str], None] | None = None) -> str:
    """Run a vagrant command in lab/vm, streaming output to `log`; returns stdout."""
    proc = subprocess.Popen(
        [vagrant_bin(), *args],
        cwd=VM_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    lines: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        lines.append(line)
        if log and line.strip() and RESULT_MARKER not in line:
            log(f"  vm> {line.rstrip()}")
    if proc.wait() != 0:
        raise CaptureError(f"vagrant {args[0]} failed (exit {proc.returncode})")
    return "".join(lines)


def _pull(vm_path: str) -> bytes:
    """Read a file from the VM over WinRM (base64 between markers)."""
    command = (
        f"Write-Output '{B64_BEGIN}'; "
        f"[Convert]::ToBase64String([IO.File]::ReadAllBytes({_ps_quote(vm_path)})); "
        f"Write-Output '{B64_END}'"
    )
    out = _vagrant(["winrm", "--shell", "powershell", "--command", command])
    if B64_BEGIN not in out or B64_END not in out:
        raise CaptureError(f"could not read {vm_path} from the VM")
    payload = out.split(B64_BEGIN, 1)[1].split(B64_END, 1)[0]
    return base64.b64decode("".join(payload.split()))


def run_capture(
    technique: str,
    tests: str,
    name: str,
    benign_command: str | None = None,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    if not NAME_RE.match(name):
        raise CaptureError("name must be lowercase snake_case")
    args = [f"-Name {_ps_quote(name)}", f"-OutDir {_ps_quote(VM_OUT_DIR)}"]
    if benign_command:
        args += [
            "-Benign",
            f"-Technique {_ps_quote(technique or 'benign')}",
            f"-Command {_ps_quote(benign_command)}",
        ]
    else:
        args.append(f"-Technique {_ps_quote(technique)}")
        if tests:
            args.append(f"-TestNumbers {_ps_quote(tests)}")

    _vagrant(["upload", str(LOCAL_SCRIPT.resolve()), VM_SCRIPT])
    out = _vagrant(
        [
            "winrm",
            "--elevated",
            "--shell",
            "powershell",
            "--command",
            f"& {VM_SCRIPT} " + " ".join(args),
        ],
        log=log,
    )
    marker = next((ln for ln in out.splitlines() if RESULT_MARKER in ln), None)
    if marker is None:
        raise CaptureError("capture script did not report a result; see the VM output above")
    result = json.loads(marker.split(RESULT_MARKER, 1)[1])

    blob = _pull(f"{VM_OUT_DIR}\\{name}.json.gz")
    digest = hashlib.sha256(blob).hexdigest()
    if digest != result["sha256"]:
        raise CaptureError(f"transfer corrupted: sha256 {digest} != {result['sha256']}")
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    (CAPTURES_DIR / f"{name}.json.gz").write_bytes(blob)
    (CAPTURES_DIR / f"{name}.meta.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return result


def register(result: dict[str, Any], description: str, path: Path = SOURCES_FILE) -> str:
    """Add (or replace) the capture in sources.yml. Returns the dataset id."""
    ds_id = f"dac_{result['name']}"
    technique = str(result.get("technique") or "")
    techniques = f"[{technique.upper()}]" if technique.upper().startswith("T") else "[]"
    block = (
        f"  - id: {ds_id}\n"
        f"    path: captures/{result['name']}.json.gz\n"
        f"    format: windows-json\n"
        f'    sha256: "{result["sha256"]}"\n'
        f"    techniques: {techniques}\n"
        f"    description: {json.dumps(description, ensure_ascii=False)}\n"
    )
    text = path.read_text(encoding="utf-8")
    existing = re.compile(rf"^  - id: {re.escape(ds_id)}\n(?:    .*\n)*", re.MULTILINE)
    if existing.search(text):
        text = existing.sub(block, text)
    else:
        if OWN_SECTION not in text:
            text = text.rstrip("\n") + f"\n\n{OWN_SECTION}\n"
        text = text.rstrip("\n") + "\n" + block
    path.write_text(text, encoding="utf-8")
    return ds_id
