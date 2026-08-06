import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = Path("schemas/sysmon_event1_source_fixture.schema.json")
DELETE = object()


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def validator() -> Draft202012Validator:
    return Draft202012Validator(
        load_schema(),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def assert_valid(instance: dict) -> None:
    validator().validate(instance)


def assert_invalid(instance: dict) -> None:
    with pytest.raises(ValidationError):
        validator().validate(instance)


def minimum_fixture() -> dict:
    return {
        "fixture_contract_version": "1.0",
        "fixture_id": "sysmon-event1-ordinary-powershell-001",
        "source_format": "sysmon_eventlog_json",
        "system": {
            "provider_name": "Microsoft-Windows-Sysmon",
            "provider_event_id": 1,
            "system_time": "2026-01-15T01:02:03.123Z",
            "event_record_id": 41001,
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": "WIN-FIXTURE01",
        },
        "event_data": {
            "UtcTime": "2026-01-15 01:02:03.123",
            "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
            "ProcessId": "4100",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": ('powershell.exe -NoProfile -Command "Write-Output fixture-ok"'),
            "User": "LAB\\fixture-user",
            "ParentProcessId": "4000",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        },
    }


def full_fixture() -> dict:
    fixture = copy.deepcopy(minimum_fixture())
    fixture["system"].update(
        {
            "provider_guid": "{44444444-4444-4444-4444-444444444444}",
            "event_version": 5,
            "event_level": 4,
            "event_task": 1,
            "event_opcode": 0,
            "event_keywords": "0x8000000000000000",
        }
    )
    fixture["event_data"].update(
        {
            "RuleName": "-",
            "FileVersion": "10.0.0.0",
            "Description": "Synthetic PowerShell fixture",
            "Product": "Synthetic Windows fixture",
            "Company": "Example Lab",
            "OriginalFileName": "PowerShell.EXE",
            "CurrentDirectory": "C:\\LabFixture\\",
            "LogonGuid": "{33333333-3333-3333-3333-333333333333}",
            "LogonId": "0x123ABC",
            "TerminalSessionId": "1",
            "IntegrityLevel": "Medium",
            "Hashes": ("SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "ParentProcessGuid": "{22222222-2222-2222-2222-222222222222}",
            "ParentCommandLine": "cmd.exe",
            "ParentUser": "LAB\\fixture-user",
        }
    )
    return fixture


def modified_fixture(path: tuple[str, ...], value: object) -> dict:
    fixture = copy.deepcopy(minimum_fixture())
    target = fixture
    for key in path[:-1]:
        target = target[key]

    if value is DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return fixture


def test_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(load_schema())


def test_minimum_required_fixture_is_valid() -> None:
    assert_valid(minimum_fixture())


def test_full_fixture_with_optional_fields_is_valid() -> None:
    assert_valid(full_fixture())


@pytest.mark.parametrize(
    "fixture_id",
    [
        "sysmon-event1-ordinary-powershell-001",
        "sysmon-event1-encoded-flag-001",
        "sysmon-event1-ordinary-notepad-001",
    ],
)
def test_supported_fixture_id_family_is_valid(fixture_id: str) -> None:
    fixture = minimum_fixture()
    fixture["fixture_id"] = fixture_id
    assert_valid(fixture)


@pytest.mark.parametrize("rule_name", ["-", "N/A", ""])
def test_source_rule_name_sentinels_are_preserved(rule_name: str) -> None:
    fixture = minimum_fixture()
    fixture["event_data"]["RuleName"] = rule_name
    assert_valid(fixture)


def test_synthetic_hash_source_string_is_valid() -> None:
    fixture = minimum_fixture()
    fixture["event_data"]["Hashes"] = (
        "SHA256=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    )
    assert_valid(fixture)


def test_optional_system_fields_may_be_absent() -> None:
    assert_valid(minimum_fixture())


def test_lowercase_hex_braced_guid_is_valid() -> None:
    fixture = minimum_fixture()
    fixture["event_data"]["ProcessGuid"] = "{abcdefab-cdef-abcd-efab-cdefabcdefab}"
    assert_valid(fixture)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ProcessId", "0"),
        ("ParentProcessId", "0"),
        ("TerminalSessionId", "0"),
    ],
)
def test_zero_integer_source_strings_are_valid(field: str, value: str) -> None:
    fixture = minimum_fixture()
    fixture["event_data"][field] = value
    assert_valid(fixture)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("fixture_id",), DELETE),
        (("unexpected",), True),
        (("fixture_contract_version",), "2.0"),
        (("source_format",), "raw_evtx"),
        (("fixture_id",), "ordinary-powershell-001"),
        (("system", "provider_name"), "Microsoft-Windows-Kernel-Process"),
        (("system", "provider_event_id"), 2),
        (("system", "provider_event_id"), "1"),
        (("system", "channel"), "System"),
        (("system", "provider_name"), DELETE),
        (("system", "unexpected"), "value"),
        (("system", "system_time"), "not-a-date-time"),
        (("system", "system_time"), "2026-01-15 01:02:03+00:00"),
        (("system", "event_record_id"), 0),
        (("event_data", "UtcTime"), DELETE),
        (("event_data", "unexpected"), "value"),
        (("event_data", "ProcessId"), 4100),
        (("event_data", "ProcessId"), "not-a-pid"),
        (("event_data", "ParentProcessId"), 4000),
        (("event_data", "ParentProcessId"), "not-a-pid"),
        (("event_data", "ProcessGuid"), "not-a-guid"),
        (("event_data", "ParentProcessGuid"), "not-a-guid"),
        (("event_data", "LogonGuid"), "not-a-guid"),
        (("event_data", "LogonId"), "123ABC"),
        (("event_data", "TerminalSessionId"), "not-a-session"),
        (("event_data", "UtcTime"), "2026/01/15 01:02:03"),
    ],
)
def test_invalid_source_fixture_is_rejected(path: tuple[str, ...], value: object) -> None:
    assert_invalid(modified_fixture(path, value))
