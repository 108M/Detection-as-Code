"""Raw Windows events -> ECS documents, shaped like Elastic's Windows integrations.

Input is a flat dict per event (OTRF JSON already is; Windows XML is flattened by
`parse_xml_event`). Output keeps every original data field under
`winlog.event_data.*` (as winlogbeat does) and adds the ECS fields that the
`ecs_windows` Sigma pipeline queries, so converted rules see the same layout they
would see in production.
"""

from __future__ import annotations

import datetime as dt
import ntpath
import re
import xml.etree.ElementTree as ET
from typing import Any

NORMALIZER_VERSION = "2"  # bump to invalidate cached normalised datasets

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

# Fields describing the record itself (not event data) in OTRF / NXLog exports.
META_FIELDS = {
    "@timestamp",
    "@version",
    "TimeCreated",
    "EventTime",
    "EventReceivedTime",
    "Hostname",
    "host",
    "Computer",
    "Channel",
    "EventID",
    "SourceName",
    "ProviderName",
    "ProviderGuid",
    "Provider_Name",
    "Message",
    "Keywords",
    "Level",
    "Task",
    "Opcode",
    "RecordNumber",
    "EventRecordID",
    "ExecutionProcessID",
    "ThreadID",
    "Version",
    "SeverityValue",
    "Severity",
    "EventType",
    "SourceModuleName",
    "SourceModuleType",
    "RecordId",
    "Category",
    "OpcodeValue",
    "AccountType",
    "Domain",
    "UserID",
    "tags",
    "port",
    "type",
    "log_name",
    "event_original_message",
}

# Sysmon event id -> (event.category, event.type, {source field: ECS field})
SYSMON_ECS: dict[str, tuple[list[str], list[str], dict[str, str]]] = {
    "1": (
        ["process"],
        ["start"],
        {
            "Image": "process.executable",
            "CommandLine": "process.command_line",
            "OriginalFileName": "process.pe.original_file_name",
            "ProcessId": "process.pid",
            "CurrentDirectory": "process.working_directory",
            "ParentImage": "process.parent.executable",
            "ParentCommandLine": "process.parent.command_line",
            "ParentProcessId": "process.parent.pid",
            "User": "user.name",
        },
    ),
    "3": (
        ["network"],
        ["connection"],
        {
            "Image": "process.executable",
            "DestinationIp": "destination.ip",
            "DestinationPort": "destination.port",
            "SourceIp": "source.ip",
        },
    ),
    "5": (["process"], ["end"], {"Image": "process.executable"}),
    "7": (["process"], ["change"], {"Image": "process.executable", "ImageLoaded": "file.path"}),
    "8": (["process"], ["change"], {"SourceImage": "process.executable"}),
    "10": (
        ["process"],
        ["access"],
        {
            "SourceImage": "process.executable",
            "SourceProcessId": "process.pid",
        },
    ),
    "11": (["file"], ["creation"], {"Image": "process.executable", "TargetFilename": "file.path"}),
    "12": (
        ["registry"],
        ["change"],
        {"Image": "process.executable", "TargetObject": "registry.path"},
    ),
    "13": (
        ["registry"],
        ["change"],
        {"Image": "process.executable", "TargetObject": "registry.path"},
    ),
    "14": (
        ["registry"],
        ["change"],
        {"Image": "process.executable", "TargetObject": "registry.path"},
    ),
    "22": (
        ["network"],
        ["protocol"],
        {"Image": "process.executable", "QueryName": "dns.question.name"},
    ),
    "23": (["file"], ["deletion"], {"Image": "process.executable", "TargetFilename": "file.path"}),
}

# Windows Security log (Elastic `system.security` / `windows` integrations).
SECURITY_ECS: dict[str, tuple[list[str], list[str], dict[str, str]]] = {
    "4688": (
        ["process"],
        ["start"],
        {
            "NewProcessName": "process.executable",
            "CommandLine": "process.command_line",
            "ParentProcessName": "process.parent.executable",
        },
    ),
}


def _set(doc: dict, dotted: str, value: Any) -> None:
    node = doc
    *parents, leaf = dotted.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value


def _parse_time(raw: dict) -> str:
    for key in ("UtcTime", "@timestamp", "TimeCreated", "EventTime"):
        value = raw.get(key)
        if not value:
            continue
        text = str(value).strip().replace("Z", "+00:00")
        try:
            ts = dt.datetime.fromisoformat(text.replace(" ", "T", 1))
        except ValueError:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.UTC)
        return ts.astimezone(dt.UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return "1970-01-01T00:00:00.000Z"


# Exporters disagree on channel casing ("security" vs "Security").
CANONICAL_CHANNELS = {
    c.lower(): c
    for c in (
        SYSMON_CHANNEL,
        "Security",
        "System",
        "Application",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
    )
}


def normalize(raw: dict[str, Any], dataset: str) -> dict[str, Any]:
    channel = str(raw.get("Channel") or raw.get("log_name") or "")
    channel = CANONICAL_CHANNELS.get(channel.lower(), channel)
    event_id = str(raw.get("EventID", "")).strip()
    provider = raw.get("SourceName") or raw.get("ProviderName") or raw.get("Provider_Name") or ""
    host = raw.get("Hostname") or raw.get("Computer") or raw.get("host") or ""

    event_data = {
        k: (v if isinstance(v, str) else str(v))
        for k, v in raw.items()
        if k not in META_FIELDS and v is not None and not isinstance(v, (dict, list))
    }
    doc: dict[str, Any] = {
        "@timestamp": _parse_time(raw),
        "event": {"code": event_id, "provider": provider, "dataset": f"dac.{dataset}"},
        "host": {"name": host},
        "winlog": {
            "channel": channel,
            "event_id": event_id,
            "provider_name": provider,
            "computer_name": host,
            "event_data": event_data,
        },
        "dac": {"dataset": dataset},
    }

    table: dict[str, tuple[list[str], list[str], dict[str, str]]] = {}
    if channel == SYSMON_CHANNEL:
        table = SYSMON_ECS
    elif channel == "Security":
        table = SECURITY_ECS
    if event_id in table:
        category, etype, mapping = table[event_id]
        doc["event"]["category"] = category
        doc["event"]["type"] = etype
        for src, dst in mapping.items():
            if raw.get(src) not in (None, ""):
                _set(doc, dst, str(raw[src]))
        exe = raw.get("Image") or raw.get("NewProcessName")
        if exe and (category == ["process"] and etype == ["start"]):
            _set(doc, "process.name", ntpath.basename(str(exe)))
        if channel == SYSMON_CHANNEL and event_id == "13" and raw.get("Details"):
            _set(doc, "registry.data.strings", [str(raw["Details"])])
    if raw.get("Message"):
        doc["message"] = str(raw["Message"])
    return doc


_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def parse_xml_event(line: str) -> dict[str, Any] | None:
    """Flatten one <Event> (as exported by Splunk/WEF) into OTRF-like keys."""
    start = line.find("<Event")
    if start < 0:
        return None
    line = line[start:].strip()
    root = ET.fromstring(line)
    system = root.find(f"{_NS}System")
    out: dict[str, Any] = {}
    if system is not None:
        provider = system.find(f"{_NS}Provider")
        if provider is not None:
            out["SourceName"] = provider.get("Name", "")
        for tag in ("EventID", "Channel", "Computer", "EventRecordID"):
            el = system.find(f"{_NS}{tag}")
            if el is not None and el.text:
                out[tag] = el.text
        tc = system.find(f"{_NS}TimeCreated")
        if tc is not None:
            out["TimeCreated"] = tc.get("SystemTime", "")
    data_root = root.find(f"{_NS}EventData")
    if data_root is not None:
        for i, data in enumerate(data_root):
            name = data.get("Name") or f"param{i + 1}"
            out[name] = data.text or ""
    user_data = root.find(f"{_NS}UserData")
    if user_data is not None:
        for container in user_data:
            for child in container:
                out[child.tag.split("}")[-1]] = child.text or ""
    return out


# --- Splunk classic WinEventLog (multi-line key=value) ---------------------------------

_KV_RECORD_START = re.compile(r"^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M$")
_MSG_FIELD = re.compile(r"^\s*([A-Za-z][A-Za-z /()-]*?):\s+(\S.*?)\s*$")

# Fields only present inside the rendered Message: (EventID, label) -> event data name,
# the same extraction Splunk's Windows add-on performs.
MESSAGE_FIELDS: dict[str, dict[str, str]] = {
    "4688": {
        "New Process Name": "NewProcessName",
        "Process Command Line": "CommandLine",
        "Creator Process Name": "ParentProcessName",
        "New Process ID": "NewProcessId",
    },
    "7045": {
        "Service Name": "ServiceName",
        "Service File Name": "ImagePath",
        "Service Type": "ServiceType",
        "Service Start Type": "StartType",
        "Service Account": "AccountName",
    },
}


def _kv_record(lines: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    stamp = dt.datetime.strptime(lines[0].strip(), "%m/%d/%Y %I:%M:%S %p")
    out["TimeCreated"] = stamp.isoformat()
    message: list[str] = []
    in_message = False
    for line in lines[1:]:
        if in_message:
            message.append(line.rstrip("\r\n"))
            continue
        key, sep, value = line.rstrip("\r\n").partition("=")
        if not sep:
            continue
        if key == "Message":
            in_message = True
            message.append(value)
        else:
            out[key] = value
    out["Channel"] = out.pop("LogName", "")
    out["EventID"] = out.pop("EventCode", "")
    out["Hostname"] = out.pop("ComputerName", "")
    out["Message"] = "\n".join(message).strip()
    labels = MESSAGE_FIELDS.get(str(out["EventID"]), {})
    if labels:
        for msg_line in message:
            m = _MSG_FIELD.match(msg_line)
            if m and m.group(1) in labels and labels[m.group(1)] not in out:
                out[labels[m.group(1)]] = m.group(2)
    return out


def iter_kv_events(lines) -> Any:
    """Yield flat events from a Splunk classic WinEventLog export."""
    record: list[str] = []
    for line in lines:
        if _KV_RECORD_START.match(line.strip()) and record:
            yield _kv_record(record)
            record = []
        if record or _KV_RECORD_START.match(line.strip()):
            record.append(line)
    if record:
        yield _kv_record(record)
