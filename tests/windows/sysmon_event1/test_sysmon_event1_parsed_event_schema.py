import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = Path("schemas/sysmon_event1_parsed_event.schema.json")
EXPECTED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_parsed")
DELETE = object()


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_schema() -> dict:
    return load_json(SCHEMA_PATH)


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


def minimum_parsed_event() -> dict:
    return {
        "fixture_contract_version": "1.0",
        "fixture_id": "sysmon-event1-minimum-parsed-001",
        "source_format": "sysmon_eventlog_json",
        "provider_name": "Microsoft-Windows-Sysmon",
        "provider_event_id": 1,
        "event_record_id": 41010,
        "computer": "WIN-FIXTURE01",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "system_time": "2026-01-15T01:02:03.123000Z",
        "utc_time": "2026-01-15T01:02:03.123000Z",
        "process_guid": "{55555555-5555-5555-5555-555555555551}",
        "process_id": 5000,
        "image": "C:\\Windows\\System32\\fixture.exe",
        "command_line": "fixture.exe --safe-text",
        "user": "LAB\\fixture-user",
        "parent_process_id": 4900,
        "parent_image": "C:\\Windows\\System32\\parent.exe",
    }


def full_parsed_event() -> dict:
    event = minimum_parsed_event()
    event.update(
        {
            "provider_guid": "{44444444-4444-4444-4444-444444444444}",
            "event_version": 5,
            "event_level": 4,
            "event_task": 1,
            "event_opcode": 0,
            "event_keywords": "0x8000000000000000",
            "rule_name": "technique_id=T1059.001",
            "file_version": "10.0.0.0",
            "description": "Synthetic fixture",
            "product": "Synthetic Windows fixture",
            "company": "Example Lab",
            "original_file_name": "FIXTURE.EXE",
            "current_directory": "C:\\LabFixture\\",
            "logon_guid": "{55555555-5555-5555-5555-555555555553}",
            "logon_id": "0x123ABC",
            "terminal_session_id": 1,
            "integrity_level": "Medium",
            "hashes": {"SHA256": "AAAA", "MD5": "BBBB"},
            "parent_process_guid": "{55555555-5555-5555-5555-555555555552}",
            "parent_command_line": "parent.exe",
            "parent_user": "LAB\\fixture-user",
        }
    )
    return event


def modified_event(path: tuple[str, ...], value: object) -> dict:
    event = copy.deepcopy(minimum_parsed_event())
    target = event
    for key in path[:-1]:
        target = target[key]
    if value is DELETE:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return event


def test_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(load_schema())


def test_minimum_required_parsed_event_is_valid() -> None:
    assert_valid(minimum_parsed_event())


def test_full_parsed_event_is_valid() -> None:
    assert_valid(full_parsed_event())


def test_current_expected_parsed_artifacts_are_valid() -> None:
    paths = sorted(EXPECTED_DIR.glob("*.json"))
    assert paths
    for path in paths:
        assert_valid(load_json(path))


def test_zero_parsed_integer_fields_are_valid() -> None:
    event = minimum_parsed_event()
    event["process_id"] = 0
    event["parent_process_id"] = 0
    event["terminal_session_id"] = 0
    assert_valid(event)


def test_lowercase_hex_braced_guids_are_valid() -> None:
    event = minimum_parsed_event()
    event["provider_guid"] = "{abcdefab-cdef-abcd-efab-cdefabcdefab}"
    event["process_guid"] = "{abcdefab-cdef-abcd-efab-cdefabcdefac}"
    event["logon_guid"] = "{abcdefab-cdef-abcd-efab-cdefabcdefad}"
    event["parent_process_guid"] = "{abcdefab-cdef-abcd-efab-cdefabcdefae}"
    assert_valid(event)


def test_multiple_uppercase_hash_algorithms_are_valid() -> None:
    event = minimum_parsed_event()
    event["hashes"] = {"SHA256": "AAAA", "MD5": "BBBB", "SHA3_256": "CCCC"}
    assert_valid(event)


@pytest.mark.parametrize(
    "field",
    [
        "file_version",
        "description",
        "product",
        "company",
        "original_file_name",
        "current_directory",
        "parent_command_line",
        "parent_user",
    ],
)
def test_optional_copied_strings_may_be_empty(field: str) -> None:
    event = minimum_parsed_event()
    event[field] = ""
    assert_valid(event)


def test_non_sentinel_rule_name_is_valid() -> None:
    event = minimum_parsed_event()
    event["rule_name"] = "technique_id=T1059.001"
    assert_valid(event)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("unknown",), True),
        (("fixture_id",), DELETE),
        (("fixture_contract_version",), "2.0"),
        (("source_format",), "raw_evtx"),
        (("provider_name",), "Microsoft-Windows-Kernel-Process"),
        (("provider_event_id",), 2),
        (("provider_event_id",), "1"),
        (("channel",), "System"),
        (("event_record_id",), 0),
        (("process_id",), "5000"),
        (("parent_process_id",), "4900"),
        (("terminal_session_id",), "1"),
        (("process_id",), -1),
        (("parent_process_id",), -1),
        (("terminal_session_id",), -1),
        (("process_guid",), "not-a-guid"),
        (("system_time",), "not-a-date-time"),
        (("system_time",), "2026-01-15T10:02:03.123000+09:00"),
        (("utc_time",), "2026-01-15T01:02:03.123Z"),
        (("utc_time",), "2026-01-15T01:02:03.1234567Z"),
        (("utc_time",), "2026-02-30T01:02:03.123000Z"),
        (("event_id",), "canonical-id"),
        (("rule_name",), "-"),
        (("rule_name",), "N/A"),
        (("rule_name",), ""),
        (("hashes",), {}),
        (("hashes",), {"sha256": "AAAA"}),
        (("hashes",), {"SHA256": ""}),
        (("hashes",), {"SHA 256": "AAAA"}),
    ],
)
def test_invalid_parsed_event_is_rejected(path: tuple[str, ...], value: object) -> None:
    assert_invalid(modified_event(path, value))
