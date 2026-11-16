"""Unit tests for dataset parsing/normalisation and test grading (no Elasticsearch needed)."""

from __future__ import annotations

import io
from collections import Counter
from pathlib import Path

from dac.convert import ConvertedRule
from dac.normalize import iter_kv_events, normalize, parse_xml_event
from dac.testing import grade

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def test_otrf_sysmon_process_creation_maps_to_ecs():
    raw = {
        "SourceName": "Microsoft-Windows-Sysmon",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventID": 1,
        "Hostname": "WORKSTATION5",
        "UtcTime": "2020-10-19 03:30:41.104",
        "TimeCreated": "2020-10-19 05:30:41.104",
        "Image": r"C:\Windows\System32\nltest.exe",
        "CommandLine": "nltest /domain_trusts",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "OriginalFileName": "nltestrk.exe",
        "Message": "Process Create: ...",
    }
    doc = normalize(raw, "ds")
    assert doc["@timestamp"] == "2020-10-19T03:30:41.104Z"  # UtcTime wins
    assert doc["event"]["category"] == ["process"] and doc["event"]["type"] == ["start"]
    assert doc["event"]["code"] == "1"
    assert doc["process"]["executable"].endswith("nltest.exe")
    assert doc["process"]["name"] == "nltest.exe"
    assert doc["process"]["parent"]["executable"].endswith("cmd.exe")
    assert doc["process"]["pe"]["original_file_name"] == "nltestrk.exe"
    # Original fields kept as winlogbeat does; record metadata is not event data.
    assert doc["winlog"]["event_data"]["CommandLine"] == "nltest /domain_trusts"
    assert "Hostname" not in doc["winlog"]["event_data"]
    assert "Message" not in doc["winlog"]["event_data"]


def test_channel_casing_is_canonical():
    doc = normalize({"Channel": "security", "EventID": "4688", "NewProcessName": "x.exe"}, "ds")
    assert doc["winlog"]["channel"] == "Security"
    assert doc["process"]["executable"] == "x.exe"


def test_sysmon_registry_and_process_access():
    reg = normalize(
        {
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": "13",
            "Image": r"C:\a.exe",
            "TargetObject": r"HKU\S-1\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x",
            "Details": r"C:\Users\Public\x.exe",
        },
        "ds",
    )
    assert reg["registry"]["path"].endswith(r"\Run\x")
    assert reg["registry"]["data"]["strings"] == [r"C:\Users\Public\x.exe"]
    access = normalize(
        {
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 10,
            "SourceImage": r"C:\tool.exe",
            "TargetImage": r"C:\Windows\system32\target.exe",
            "GrantedAccess": "0x1010",
        },
        "ds",
    )
    assert access["process"]["executable"] == r"C:\tool.exe"
    assert access["winlog"]["event_data"]["GrantedAccess"] == "0x1010"


def test_xml_event_with_multiline_data():
    xml = (
        f"<Event xmlns='{NS}'><System><Provider Name='Microsoft-Windows-Sysmon'/>"
        "<EventID>1</EventID><TimeCreated SystemTime='2021-01-25T15:56:40.577Z'/>"
        "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>dc</Computer>"
        "</System><EventData><Data Name='Image'>C:\\Windows\\System32\\cmd.exe</Data>"
        "<Data Name='CommandLine'>cmd /c echo one\necho two</Data></EventData></Event>"
    )
    raw = parse_xml_event(xml)
    assert raw["EventID"] == "1" and raw["Computer"] == "dc"
    assert raw["CommandLine"] == "cmd /c echo one\necho two"
    doc = normalize(raw, "ds")
    assert doc["process"]["command_line"].endswith("echo two")


def test_xml_userdata_is_flattened():
    xml = (
        f"<Event xmlns='{NS}'><System><EventID>1102</EventID><Channel>Security</Channel>"
        "</System><UserData><LogFileCleared xmlns='urn:x'><SubjectUserName>admin"
        "</SubjectUserName></LogFileCleared></UserData></Event>"
    )
    assert parse_xml_event(xml)["SubjectUserName"] == "admin"


KV_EXPORT = """\
06/15/2021 12:00:19 PM
LogName=Security
SourceName=Microsoft Windows security auditing.
EventCode=4688
ComputerName=dc.lab.local
Message=A new process has been created.

Process Information:
\tNew Process Name:\tC:\\Windows\\System32\\wevtutil.exe
\tCreator Process Name:\tC:\\Windows\\System32\\cmd.exe
\tProcess Command Line:\twevtutil  cl Application
04/05/2021 05:39:16 AM
LogName=System
SourceName=Service Control Manager
EventCode=7045
ComputerName=srv
Message=A service was installed in the system.

Service Name:  PSEXESVC
Service File Name:  %SystemRoot%\\PSEXESVC.exe
"""


def test_splunk_classic_kv_records():
    events = list(iter_kv_events(io.StringIO(KV_EXPORT)))
    assert len(events) == 2
    proc, svc = (normalize(e, "ds") for e in events)
    assert proc["winlog"]["channel"] == "Security" and proc["event"]["code"] == "4688"
    assert proc["process"]["command_line"] == "wevtutil  cl Application"
    assert proc["process"]["parent"]["executable"].endswith("cmd.exe")
    assert proc["@timestamp"] == "2021-06-15T12:00:19.000Z"
    assert svc["winlog"]["provider_name"] == "Service Control Manager"
    assert svc["winlog"]["event_data"]["ServiceName"] == "PSEXESVC"
    assert svc["winlog"]["event_data"]["ImagePath"] == r"%SystemRoot%\PSEXESVC.exe"


# --- grading ---------------------------------------------------------------------------


def _rule() -> ConvertedRule:
    return ConvertedRule(Path("rules/x/r.yml"), "id-1", "Rule", "any where true", {})


KNOWN = {"attack_a", "attack_b", "noise", "gap", "ansible"}


def test_grade_pass_with_all_labels():
    case = {
        "detects": [{"dataset": "attack_a", "min_hits": 2}],
        "also_detects": [{"dataset": "attack_b", "reason": "same stager"}],
        "known_gaps": [{"dataset": "gap", "reason": "variant"}],
        "accepted_false_positives": [{"dataset": "ansible", "max_hits": 5, "reason": "ops"}],
    }
    res = grade(_rule(), case, Counter(attack_a=3, attack_b=1, ansible=5), KNOWN)
    assert res.status == "pass"
    assert res.tp_hits == 4 and res.fp_hits == 5


def test_grade_missed_detection_fails():
    res = grade(_rule(), {"detects": [{"dataset": "attack_a"}]}, Counter(), KNOWN)
    assert res.status == "fail" and "MISSED attack_a" in res.messages[0]


def test_grade_unexpected_hits_are_false_positives():
    case = {"detects": [{"dataset": "attack_a"}]}
    res = grade(_rule(), case, Counter(attack_a=1, noise=4), KNOWN)
    assert res.status == "fail" and res.fp_hits == 4


def test_grade_accepted_fp_budget():
    case = {"accepted_false_positives": [{"dataset": "ansible", "max_hits": 2}]}
    assert grade(_rule(), case, Counter(ansible=3), KNOWN).status == "fail"


def test_grade_closed_gap_and_unknown_dataset():
    res = grade(_rule(), {"known_gaps": [{"dataset": "gap"}]}, Counter(gap=1), KNOWN)
    assert res.status == "pass" and "gap closed" in res.messages[0]
    res = grade(_rule(), {"detects": [{"dataset": "typo"}]}, Counter(), KNOWN)
    assert res.status == "fail" and "unknown dataset" in res.messages[0]


def test_grade_without_case_is_untested():
    res = grade(_rule(), None, Counter(noise=2), KNOWN)
    assert res.status == "untested" and res.hits_of("unlabeled") == 2
