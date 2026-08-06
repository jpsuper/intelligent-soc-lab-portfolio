import re
from pathlib import Path

COLLECTOR_PATH = Path("scripts/windows/sysmon_event1/export_sysmon_event1_provider_json.ps1")


def collector_text() -> str:
    return COLLECTOR_PATH.read_text(encoding="utf-8")


def test_native_collector_has_required_event_log_and_xml_contract_markers() -> None:
    text = collector_text()
    required_markers = {
        "Get-WinEvent",
        ".ToXml()",
        "XmlNamespaceManager",
        "http://schemas.microsoft.com/win/2004/08/events/event",
        "Microsoft-Windows-Sysmon/Operational",
        "EventRecordID",
        "TimeCreated",
        "GetAttribute('Name')",
        "ConvertTo-Json",
        "UTF8Encoding",
    }

    assert COLLECTOR_PATH.is_file()
    for marker in required_markers:
        assert marker in text
    assert re.search(r"\bId\s*=\s*1\b", text)
    assert re.search(r"\[ValidateRange\(1,\s*999\)\]", text)
    assert "-ErrorAction Stop" in text
    assert "SilentlyContinue" not in text


def test_native_collector_avoids_position_dependent_or_executable_patterns() -> None:
    text = collector_text()
    forbidden_patterns = {
        r"Properties\[[0-9]+\]",
        r"\bInvoke-Expression\b",
        r"\bStart-Process\b",
        r"\bInvoke-WebRequest\b",
        r"(?i)\bscp\b",
        r"(?i)\bssh\b",
    }

    for pattern in forbidden_patterns:
        assert re.search(pattern, text) is None


def test_native_collector_contains_no_runtime_identity_or_secret_material() -> None:
    text = collector_text()
    forbidden_markers = {
        ".".join(("192", "168", "1", "31")),
        "".join(("WIN-", "VICTIM01")),
        "PRIVATE KEY",
        "password=",
        "credential=",
    }

    for marker in forbidden_markers:
        assert marker not in text


def test_native_collector_keeps_transfer_outside_the_script() -> None:
    text = collector_text()

    assert "OutputDirectory" in text
    assert "WriteAllText" in text
    assert "System.Text.UTF8Encoding($false)" in text
    assert "Invoke-RestMethod" not in text
    assert "System.Net." not in text


def test_native_collector_separates_query_and_no_record_errors() -> None:
    text = collector_text()

    query_error = "Failed to query Sysmon Event ID 1 from the configured channel."
    no_records_error = "No Sysmon Event ID 1 records found in the requested time window."
    assert query_error in text
    assert no_records_error in text
    assert query_error != no_records_error


def test_native_collector_derives_filename_from_three_digit_fixture_id() -> None:
    text = collector_text()

    assert re.search(r"\$SequenceText\s*=\s*'\{0:D3\}'", text)
    assert re.search(r'\$FixtureId\s*=\s*"sysmon-event1-\$FixtureSlug-\$SequenceText"', text)
    assert re.search(r'\$FileName\s*=\s*"\$FixtureId\.json"', text)
