import copy
import json
import sys
from pathlib import Path

import pytest

DOMAIN_MODULE_DIR = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "sysmon_event1"
sys.path.insert(0, str(DOMAIN_MODULE_DIR))

from parse_sysmon_event1_source import (  # noqa: E402
    SysmonEvent1ParseError,
    parse_sysmon_event1_source,
)

FIXTURE_DIR = Path("tests/fixtures/windows/sysmon_event1/source")
FIXTURE_A_PATH = FIXTURE_DIR / "sysmon-event1-ordinary-powershell-001.json"
FIXTURE_B_PATH = FIXTURE_DIR / "sysmon-event1-encoded-flag-001.json"
FIXTURE_C_PATH = FIXTURE_DIR / "sysmon-event1-ordinary-notepad-001.json"
SYNTHETIC_PROVIDER_GUID = "{44444444-4444-4444-4444-444444444444}"

FORBIDDEN_PARSED_FIELDS = {
    "event_id",
    "platform",
    "source",
    "host",
    "timestamp",
    "event_type",
    "pid",
    "ppid",
    "process_name",
    "exe",
    "cwd",
    "parent_process_name",
    "parent_exe",
    "raw_ref",
    "source_fields",
    "canonical_event_id",
    "expected_detection",
    "powershell_process_observed",
    "encoded_command_observed",
    "malicious",
    "verdict",
    "severity",
    "confidence",
    "response",
    "detection",
    "incident",
}


def load_fixture(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def minimum_source() -> dict:
    return {
        "fixture_contract_version": "1.0",
        "fixture_id": "sysmon-event1-minimum-source-001",
        "source_format": "sysmon_eventlog_json",
        "system": {
            "provider_name": "Microsoft-Windows-Sysmon",
            "provider_event_id": 1,
            "system_time": "2026-01-15T01:02:03.123Z",
            "event_record_id": 41010,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "WIN-FIXTURE01",
        },
        "event_data": {
            "UtcTime": "2026-01-15 01:02:03.123",
            "ProcessGuid": "{55555555-5555-5555-5555-555555555551}",
            "ProcessId": "5000",
            "Image": "C:\\Windows\\System32\\fixture.exe",
            "CommandLine": "fixture.exe --safe-text",
            "User": "LAB\\fixture-user",
            "ParentProcessId": "4900",
            "ParentImage": "C:\\Windows\\System32\\parent.exe",
        },
    }


def test_fixture_a_parse() -> None:
    parsed = parse_sysmon_event1_source(load_fixture(FIXTURE_A_PATH))

    assert parsed["fixture_contract_version"] == "1.0"
    assert parsed["fixture_id"] == "sysmon-event1-ordinary-powershell-001"
    assert parsed["source_format"] == "sysmon_eventlog_json"
    assert parsed["provider_name"] == "Microsoft-Windows-Sysmon"
    assert parsed["provider_guid"] == SYNTHETIC_PROVIDER_GUID
    assert parsed["provider_event_id"] == 1
    assert parsed["event_record_id"] == 41001
    assert parsed["computer"] == "WIN-FIXTURE01"
    assert parsed["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert parsed["system_time"] == "2026-01-15T01:02:03.123000Z"
    assert parsed["utc_time"] == "2026-01-15T01:02:03.123000Z"
    assert parsed["process_guid"] == "{11111111-1111-1111-1111-111111111111}"
    assert parsed["process_id"] == 4100
    assert parsed["parent_process_id"] == 4000
    assert parsed["terminal_session_id"] == 1
    assert parsed["image"] == ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    assert parsed["command_line"] == (
        'powershell.exe -NoProfile -Command "Write-Output fixture-ok"'
    )
    assert parsed["current_directory"] == "C:\\LabFixture\\"
    assert parsed["user"] == "LAB\\fixture-user"
    assert parsed["logon_id"] == "0x123ABC"
    assert parsed["hashes"] == {
        "SHA256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
    assert "rule_name" not in parsed


def test_fixture_b_parse() -> None:
    parsed = parse_sysmon_event1_source(load_fixture(FIXTURE_B_PATH))

    assert parsed["fixture_id"] == "sysmon-event1-encoded-flag-001"
    assert parsed["event_record_id"] == 41002
    assert parsed["system_time"] == "2026-01-15T01:03:03.123000Z"
    assert parsed["utc_time"] == "2026-01-15T01:03:03.123000Z"
    assert parsed["process_id"] == 4200
    assert parsed["parent_process_id"] == 4000
    assert parsed["image"] == ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    assert parsed["command_line"] == ("powershell.exe -NoProfile -EncodedCommand SAFE_PLACEHOLDER")
    assert parsed["hashes"] == {
        "SHA256": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    }
    assert parsed["parent_process_guid"] == ("{22222222-2222-2222-2222-222222222222}")
    assert parsed["parent_image"] == "C:\\Windows\\System32\\cmd.exe"
    assert parsed["parent_command_line"] == "cmd.exe"
    assert parsed["parent_user"] == "LAB\\fixture-user"
    assert "rule_name" not in parsed


def test_fixture_c_parse() -> None:
    parsed = parse_sysmon_event1_source(load_fixture(FIXTURE_C_PATH))

    assert parsed["fixture_id"] == "sysmon-event1-ordinary-notepad-001"
    assert parsed["provider_guid"] == SYNTHETIC_PROVIDER_GUID
    assert parsed["image"] == "C:\\Windows\\System32\\notepad.exe"
    assert parsed["process_id"] == 4300
    assert parsed["parent_process_id"] == 3900
    assert parsed["parent_process_guid"] == ("{33333333-3333-3333-3333-333333333332}")
    assert parsed["parent_image"] == "C:\\Windows\\explorer.exe"
    assert parsed["parent_command_line"] == "explorer.exe"
    assert parsed["parent_user"] == "LAB\\fixture-user"
    assert parsed["system_time"] == parsed["utc_time"]
    assert "rule_name" not in parsed


@pytest.mark.parametrize("path", [FIXTURE_A_PATH, FIXTURE_B_PATH, FIXTURE_C_PATH])
def test_parser_does_not_modify_source(path: Path) -> None:
    source = load_fixture(path)
    original = copy.deepcopy(source)

    parse_sysmon_event1_source(source)

    assert source == original


def test_missing_optional_source_fields_are_not_fabricated() -> None:
    parsed = parse_sysmon_event1_source(minimum_source())
    optional_fields = {
        "provider_guid",
        "event_version",
        "rule_name",
        "current_directory",
        "logon_guid",
        "terminal_session_id",
        "integrity_level",
        "hashes",
        "parent_process_guid",
        "parent_command_line",
        "parent_user",
    }

    assert parsed.keys().isdisjoint(optional_fields)


@pytest.mark.parametrize("sentinel", ["-", "N/A", ""])
def test_rule_name_sentinel_is_omitted(sentinel: str) -> None:
    source = minimum_source()
    source["event_data"]["RuleName"] = sentinel

    assert "rule_name" not in parse_sysmon_event1_source(source)


def test_non_sentinel_rule_name_is_preserved() -> None:
    source = minimum_source()
    source["event_data"]["RuleName"] = "technique_id=T1059.001"

    assert parse_sysmon_event1_source(source)["rule_name"] == "technique_id=T1059.001"


def test_rule_name_sentinels_are_not_applied_globally() -> None:
    source = minimum_source()
    source["event_data"]["Description"] = "-"

    assert parse_sysmon_event1_source(source)["description"] == "-"


def test_zero_integer_source_strings_are_valid() -> None:
    source = minimum_source()
    source["event_data"]["ProcessId"] = "0"
    source["event_data"]["ParentProcessId"] = "0"
    source["event_data"]["TerminalSessionId"] = "0"

    parsed = parse_sysmon_event1_source(source)

    assert parsed["process_id"] == 0
    assert parsed["parent_process_id"] == 0
    assert parsed["terminal_session_id"] == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ProcessId", 10),
        ("ProcessId", "not-a-pid"),
        ("ParentProcessId", "-1"),
        ("ParentProcessId", " 10"),
        ("TerminalSessionId", "+1"),
    ],
)
def test_invalid_integer_source_values_are_rejected(field: str, value: object) -> None:
    source = minimum_source()
    source["event_data"][field] = value

    with pytest.raises(SysmonEvent1ParseError, match=rf"event_data\.{field}"):
        parse_sysmon_event1_source(source)


@pytest.mark.parametrize(
    ("system_time", "expected"),
    [
        ("2026-01-15T01:02:03.123Z", "2026-01-15T01:02:03.123000Z"),
        ("2026-01-15T10:02:03.123+09:00", "2026-01-15T01:02:03.123000Z"),
        ("2026-01-14T20:02:03.123-05:00", "2026-01-15T01:02:03.123000Z"),
        ("2026-01-15T01:02:03.123456Z", "2026-01-15T01:02:03.123456Z"),
    ],
)
def test_system_time_is_normalized_to_utc(system_time: str, expected: str) -> None:
    source = minimum_source()
    source["system"]["system_time"] = system_time

    assert parse_sysmon_event1_source(source)["system_time"] == expected


@pytest.mark.parametrize(
    ("utc_time", "expected"),
    [
        ("2026-01-15 01:02:03.123", "2026-01-15T01:02:03.123000Z"),
        ("2026-01-15 01:02:03.123456", "2026-01-15T01:02:03.123456Z"),
        ("2026-01-15 01:02:03.1234567", "2026-01-15T01:02:03.123456Z"),
    ],
)
def test_sysmon_utc_time_fraction_is_normalized(utc_time: str, expected: str) -> None:
    source = minimum_source()
    source["event_data"]["UtcTime"] = utc_time

    assert parse_sysmon_event1_source(source)["utc_time"] == expected


@pytest.mark.parametrize(
    "system_time",
    [
        "2026-01-15T01:02:03.123",
        "2026-01-15 01:02:03.123+00:00",
        "2026-02-30T01:02:03.123Z",
    ],
)
def test_invalid_system_time_is_rejected(system_time: str) -> None:
    source = minimum_source()
    source["system"]["system_time"] = system_time

    with pytest.raises(SysmonEvent1ParseError, match=r"system\.system_time"):
        parse_sysmon_event1_source(source)


@pytest.mark.parametrize(
    "utc_time",
    [
        "2026-01-15T01:02:03.123",
        "2026-01-15 01:02:03.12",
        "2026-02-30 01:02:03.123",
    ],
)
def test_invalid_sysmon_utc_time_is_rejected(utc_time: str) -> None:
    source = minimum_source()
    source["event_data"]["UtcTime"] = utc_time

    with pytest.raises(SysmonEvent1ParseError, match=r"event_data\.UtcTime"):
        parse_sysmon_event1_source(source)


def test_timestamp_mismatch_is_preserved_without_canonical_timestamp() -> None:
    source = minimum_source()
    source["event_data"]["UtcTime"] = "2026-01-15 02:03:04.123"

    parsed = parse_sysmon_event1_source(source)

    assert parsed["system_time"] == "2026-01-15T01:02:03.123000Z"
    assert parsed["utc_time"] == "2026-01-15T02:03:04.123000Z"
    assert "timestamp" not in parsed


@pytest.mark.parametrize(
    ("source_hashes", "expected"),
    [
        ("SHA256=AAAA", {"SHA256": "AAAA"}),
        ("SHA256=AAAA,MD5=BBBB", {"SHA256": "AAAA", "MD5": "BBBB"}),
        ("sha256=AAAA", {"SHA256": "AAAA"}),
        ("sha3_256=CCCC", {"SHA3_256": "CCCC"}),
        (" SHA256 = AAAA , MD5 = BBBB ", {"SHA256": "AAAA", "MD5": "BBBB"}),
    ],
)
def test_hashes_are_parsed_by_algorithm(source_hashes: str, expected: dict) -> None:
    source = minimum_source()
    source["event_data"]["Hashes"] = source_hashes

    assert parse_sysmon_event1_source(source)["hashes"] == expected


@pytest.mark.parametrize(
    "source_hashes",
    [
        "SHA256AAAA",
        "=AAAA",
        "SHA256=",
        "SHA256=AAAA,sha256=BBBB",
        "SHA 256=AAAA",
        "SHA.256=AAAA",
        "_SHA256=AAAA",
    ],
)
def test_invalid_hashes_are_rejected(source_hashes: str) -> None:
    source = minimum_source()
    source["event_data"]["Hashes"] = source_hashes

    with pytest.raises(SysmonEvent1ParseError, match=r"event_data\.Hashes"):
        parse_sysmon_event1_source(source)


def test_absent_hashes_do_not_create_output_key() -> None:
    assert "hashes" not in parse_sysmon_event1_source(minimum_source())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_name", "Microsoft-Windows-Kernel-Process"),
        ("provider_event_id", 2),
        ("channel", "System"),
    ],
)
def test_wrong_provider_routing_is_rejected(field: str, value: object) -> None:
    source = minimum_source()
    source["system"][field] = value

    with pytest.raises(SysmonEvent1ParseError, match=rf"system\.{field}"):
        parse_sysmon_event1_source(source)


def test_non_mapping_source_is_rejected() -> None:
    with pytest.raises(SysmonEvent1ParseError, match="Sysmon Event ID 1.*source"):
        parse_sysmon_event1_source([])  # type: ignore[arg-type]


def test_schema_error_does_not_dump_source_values() -> None:
    source = minimum_source()
    source["system"]["provider_name"] = "wrong-provider"
    source["event_data"]["CommandLine"] = "sensitive-command-text"

    with pytest.raises(SysmonEvent1ParseError) as exc_info:
        parse_sysmon_event1_source(source)

    assert "system.provider_name" in str(exc_info.value)
    assert "wrong-provider" not in str(exc_info.value)
    assert "sensitive-command-text" not in str(exc_info.value)


@pytest.mark.parametrize("path", [FIXTURE_A_PATH, FIXTURE_B_PATH, FIXTURE_C_PATH])
def test_parsed_output_does_not_cross_canonical_or_detection_boundary(path: Path) -> None:
    parsed = parse_sysmon_event1_source(load_fixture(path))

    assert parsed.keys().isdisjoint(FORBIDDEN_PARSED_FIELDS)
    assert "event_id" not in parsed
    assert parsed["provider_event_id"] == 1
