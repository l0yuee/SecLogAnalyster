"""Coverage for the Microsoft-scheduled-task baseline comparison
(data/scheduled_tasks/known_microsoft_tasks.json + classify_against_baseline)
and its wiring into Case.suspicious_tasks()'s new `suspicion_reasons`
column."""

from __future__ import annotations

from pathlib import Path

from seclogx.case import Case
from seclogx.ingest.logsources.parsers.task_baseline import classify_against_baseline

FIXTURES = Path(__file__).parent.parent / "fixtures" / "logsources"

_HIJACKED_TASK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Scheduled Start</Description>
  </RegistrationInfo>
  <Settings><Enabled>true</Enabled><Hidden>false</Hidden></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Users\\Public\\update.exe</Command>
      <Arguments>-enc AAAA</Arguments>
    </Exec>
  </Actions>
</Task>
"""

_LEGIT_TASK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Microsoft Corporation</Author>
    <Description>Scheduled Start</Description>
  </RegistrationInfo>
  <Settings><Enabled>true</Enabled><Hidden>false</Hidden></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%windir%\\system32\\usoclient.exe</Command>
      <Arguments>StartScan</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def test_classify_against_baseline_flags_mismatched_action():
    reason = classify_against_baseline(
        r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
        r"C:\Users\Public\update.exe",
    )
    assert reason is not None
    assert "Scheduled Start" in reason


def test_classify_against_baseline_accepts_expected_action():
    reason = classify_against_baseline(
        r"\Microsoft\Windows\WindowsUpdate\Scheduled Start",
        r"%windir%\system32\usoclient.exe",
    )
    assert reason is None


def test_classify_against_baseline_unknown_path_is_not_flagged():
    reason = classify_against_baseline(r"\SomeVendor\CustomApp\Update", r"C:\Temp\evil.exe")
    assert reason is None


def test_classify_against_baseline_no_action_command_is_not_flagged():
    reason = classify_against_baseline(r"\Microsoft\Windows\WindowsUpdate\Scheduled Start", None)
    assert reason is None


def _make_task_file(evidence_root: Path, host_dir_name: str, filename: str, content: str) -> Path:
    tasks_dir = evidence_root / host_dir_name / "Tasks" / "Microsoft" / "Windows" / "WindowsUpdate"
    tasks_dir.mkdir(parents=True, exist_ok=True)
    (tasks_dir / filename).write_text(content)
    return evidence_root / host_dir_name


def test_suspicious_tasks_flags_hijacked_known_task_with_reason(tmp_path: Path):
    case = Case.create("baseline-hijack", case_root=tmp_path / "cases")
    host_dir = _make_task_file(tmp_path / "evidence", "WKS01", "Scheduled Start", _HIJACKED_TASK_XML)
    case.ingest([f"{host_dir}:WKS01"])

    df = case.suspicious_tasks()
    assert len(df) == 1
    reasons = df.iloc[0]["suspicion_reasons"]
    assert any("known Microsoft task path" in r for r in reasons)


def test_suspicious_tasks_does_not_flag_legitimate_known_task(tmp_path: Path):
    case = Case.create("baseline-legit", case_root=tmp_path / "cases")
    host_dir = _make_task_file(tmp_path / "evidence", "WKS01", "Scheduled Start", _LEGIT_TASK_XML)
    case.ingest([f"{host_dir}:WKS01"])

    df = case.suspicious_tasks()
    assert df.empty
