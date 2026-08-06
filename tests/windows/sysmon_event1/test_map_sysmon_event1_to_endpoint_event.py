import copy
import json
import re
import sys
import traceback
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

DOMAIN_MODULE_DIR = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "sysmon_event1"
sys.path.insert(0, str(DOMAIN_MODULE_DIR))

import map_sysmon_event1_to_endpoint_event as mapper  # noqa: E402
from map_sysmon_event1_to_endpoint_event import (  # noqa: E402
    SysmonEvent1MappingError,
    build_source_fields,
    canonical_event_id,
    map_sysmon_event1_to_endpoint_event,
    validate_endpoint_event,
    windows_basename,
)
from parse_sysmon_event1_source import parse_sysmon_event1_source  # noqa: E402

SOURCE_DIR = Path("tests/fixtures/windows/sysmon_event1/source")
PARSED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_parsed")
FIXTURE_A_NAME = "sysmon-event1-ordinary-powershell-001.json"
FIXTURE_B_NAME = "sysmon-event1-encoded-flag-001.json"
FIXTURE_C_NAME = "sysmon-event1-ordinary-notepad-001.json"
FIXTURE_A_ID = "sysmon-event1:v1:54aa19e2ce68d8cf8f27f519992024f5338d6d9e65c6916912919465c538bcef"
FIXTURE_B_ID = "sysmon-event1:v1:4fc28bf961113fe8702ef58882f449a3928772fa5eec9fa0d34e2e033c134643"
FIXTURE_C_ID = "sysmon-event1:v1:0d71d2939ce94b4a27040fa570be53d1bf1913aa695d9545b92fd27143ab332f"
REQUIRED_SOURCE_FIELDS = {
    "provider_name",
    "provider_event_id",
    "event_record_id",
    "channel",
    "system_time",
    "utc_time",
    "timestamp_source",
    "timestamps_equal",
    "process_guid",
    "mapper_name",
    "mapper_version",
    "event_id_method",
    "event_identity_version",
}
OPTIONAL_SOURCE_FIELDS = set(mapper.OPTIONAL_SOURCE_FIELDS)
CANONICAL_DUPLICATES = {
    "computer",
    "user",
    "process_id",
    "parent_process_id",
    "image",
    "command_line",
    "current_directory",
    "parent_image",
    "parent_command_line",
    "fixture_id",
}
FORBIDDEN_OUTPUT_FIELDS = {
    "argv",
    "uid",
    "file_path",
    "file_action",
    "src_ip",
    "src_port",
    "dest_ip",
    "dest_port",
    "protocol",
    "collection_timestamp",
    "expected_detection",
    "powershell_process_observed",
    "encoded_command_observed",
    "malicious",
    "verdict",
    "severity",
    "confidence",
    "detection",
    "incident",
    "response",
}


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_parsed(name: str = FIXTURE_A_NAME) -> dict[str, object]:
    return load_json(PARSED_DIR / name)


def map_fixture(name: str = FIXTURE_A_NAME) -> dict[str, object]:
    return map_sysmon_event1_to_endpoint_event(
        load_parsed(name),
        source_artifact=(SOURCE_DIR / name).as_posix(),
    )


@pytest.mark.parametrize(
    ("name", "expected_id", "process_name", "parent_process_name"),
    [
        (FIXTURE_A_NAME, FIXTURE_A_ID, "powershell.exe", "cmd.exe"),
        (FIXTURE_B_NAME, FIXTURE_B_ID, "powershell.exe", "cmd.exe"),
        (FIXTURE_C_NAME, FIXTURE_C_ID, "notepad.exe", "explorer.exe"),
    ],
)
def test_fixture_mapping_and_golden_ids(
    name: str,
    expected_id: str,
    process_name: str,
    parent_process_name: str,
) -> None:
    parsed = load_parsed(name)
    event = map_fixture(name)

    assert event["event_id"] == expected_id
    assert re.fullmatch(r"sysmon-event1:v1:[0-9a-f]{64}", event["event_id"])
    assert event["source"] == "sysmon"
    assert event["platform"] == "windows"
    assert event["event_type"] == "process_exec"
    assert event["host"] == parsed["computer"]
    assert event["timestamp"] == parsed["utc_time"]
    assert event["user"] == parsed["user"]
    assert event["pid"] == parsed["process_id"]
    assert event["ppid"] == parsed["parent_process_id"]
    assert event["process_name"] == process_name
    assert event["exe"] == parsed["image"]
    assert event["command_line"] == parsed["command_line"]
    assert event["cwd"] == parsed["current_directory"]
    assert event["parent_process_name"] == parent_process_name
    assert event["parent_exe"] == parsed["parent_image"]
    assert event["parent_command_line"] == parsed["parent_command_line"]
    assert event.keys().isdisjoint(FORBIDDEN_OUTPUT_FIELDS)


@pytest.mark.parametrize("name", [FIXTURE_A_NAME, FIXTURE_B_NAME, FIXTURE_C_NAME])
def test_mapped_event_is_valid_in_minimal_endpoint_envelope(name: str) -> None:
    schema = load_json(Path("schemas/endpoint_events.schema.json"))
    envelope = {
        "schema_version": "endpoint_events.v1",
        "events": [map_fixture(name)],
    }

    Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(envelope)


def test_identity_policy_and_host_case_preservation() -> None:
    parsed = load_parsed()
    original_id = canonical_event_id(parsed)

    assert canonical_event_id(parsed) == original_id

    host_case_change = copy.deepcopy(parsed)
    host_case_change["computer"] = str(parsed["computer"]).lower()
    host_case_event = map_sysmon_event1_to_endpoint_event(
        host_case_change, source_artifact="tests/fixtures/synthetic.json"
    )
    assert host_case_event["event_id"] == original_id
    assert host_case_event["host"] == str(parsed["computer"]).lower()

    record_change = copy.deepcopy(parsed)
    record_change["event_record_id"] = int(parsed["event_record_id"]) + 1
    assert canonical_event_id(record_change) != original_id

    guid_change = copy.deepcopy(parsed)
    guid_change["process_guid"] = "{99999999-9999-9999-9999-999999999999}"
    assert canonical_event_id(guid_change) == original_id

    for source_identifier in (
        parsed["provider_event_id"],
        parsed["event_record_id"],
        parsed["process_guid"],
        parsed["fixture_id"],
    ):
        assert original_id != str(source_identifier)


def test_timestamp_policy_for_equal_and_unequal_values() -> None:
    equal_event = map_fixture()
    assert equal_event["source_fields"]["timestamps_equal"] is True

    parsed = load_parsed()
    parsed["system_time"] = "2026-01-15T01:02:03.124000Z"
    event = map_sysmon_event1_to_endpoint_event(
        parsed, source_artifact="tests/fixtures/synthetic.json"
    )

    assert event["timestamp"] == parsed["utc_time"]
    assert event["source_fields"]["system_time"] == parsed["system_time"]
    assert event["source_fields"]["utc_time"] == parsed["utc_time"]
    assert event["source_fields"]["timestamp_source"] == "utc_time"
    assert event["source_fields"]["timestamps_equal"] is False
    assert "timestamp_delta" not in event["source_fields"]


def test_raw_ref_and_source_fields_are_compact_allowlisted_provenance() -> None:
    parsed = load_parsed()
    event = map_fixture()
    source_fields = event["source_fields"]

    assert event["raw_ref"] == {
        "source_artifact": (SOURCE_DIR / FIXTURE_A_NAME).as_posix(),
        "fixture_id": parsed["fixture_id"],
    }
    assert set(source_fields) == REQUIRED_SOURCE_FIELDS | (OPTIONAL_SOURCE_FIELDS & set(parsed))
    assert source_fields["mapper_name"] == "sysmon_event1_endpoint_event_mapper"
    assert source_fields["mapper_version"] == "1.0"
    assert source_fields["event_id_method"] == "sha256-json-canonical-v1"
    assert source_fields["event_identity_version"] == "sysmon-event1-event-id.v1"
    assert set(source_fields).isdisjoint(CANONICAL_DUPLICATES)
    assert source_fields != parsed
    assert "fixture_id" not in source_fields


def test_missing_optional_fields_are_omitted() -> None:
    parsed = load_parsed()
    for field in OPTIONAL_SOURCE_FIELDS | {"current_directory", "parent_command_line"}:
        parsed.pop(field, None)

    event = map_sysmon_event1_to_endpoint_event(
        parsed, source_artifact="tests/fixtures/synthetic.json"
    )

    assert set(build_source_fields(parsed)) == REQUIRED_SOURCE_FIELDS
    assert "cwd" not in event
    assert "parent_command_line" not in event


def test_mapper_does_not_modify_input() -> None:
    parsed = load_parsed()
    original = copy.deepcopy(parsed)

    map_sysmon_event1_to_endpoint_event(parsed, source_artifact="tests/fixtures/synthetic.json")

    assert parsed == original


def test_mutating_mapped_hashes_does_not_mutate_parsed_input() -> None:
    parsed = load_parsed()
    original = copy.deepcopy(parsed)

    event = map_sysmon_event1_to_endpoint_event(
        parsed,
        source_artifact="tests/fixtures/synthetic.json",
    )
    event["source_fields"]["hashes"]["SHA256"] = "MUTATED"

    assert parsed == original

    parsed["hashes"]["SHA256"] = "CHANGED-AFTER-MAPPING"
    assert event["source_fields"]["hashes"]["SHA256"] != "CHANGED-AFTER-MAPPING"


def test_input_schema_failure_suppresses_sensitive_validation_context() -> None:
    parsed = load_parsed()
    parsed["command_line"] = {
        "secret": "sensitive-command-text",
    }

    with pytest.raises(
        SysmonEvent1MappingError,
        match=r"mapping failed at command_line$",
    ) as exc_info:
        map_sysmon_event1_to_endpoint_event(
            parsed,
            source_artifact="tests/fixtures/synthetic.json",
        )

    rendered = "".join(
        traceback.format_exception(
            exc_info.type,
            exc_info.value,
            exc_info.tb,
        )
    )
    assert exc_info.value.__cause__ is None
    assert "mapping failed at command_line" in rendered
    assert "sensitive-command-text" not in rendered


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_name", "Other-Provider"),
        ("provider_event_id", 3),
        ("channel", "Application"),
        ("utc_time", "not-a-timestamp"),
    ],
)
def test_invalid_parsed_values_fail_closed_without_dumping_values(
    field: str, value: object
) -> None:
    parsed = load_parsed()
    parsed[field] = value

    with pytest.raises(SysmonEvent1MappingError, match=field) as exc_info:
        map_sysmon_event1_to_endpoint_event(parsed, source_artifact="tests/fixtures/synthetic.json")

    assert str(value) not in str(exc_info.value)


def test_missing_required_and_unexpected_canonical_fields_fail_closed() -> None:
    missing = load_parsed()
    missing.pop("process_guid")
    with pytest.raises(SysmonEvent1MappingError, match=r"at process_guid$"):
        map_sysmon_event1_to_endpoint_event(
            missing, source_artifact="tests/fixtures/synthetic.json"
        )

    unexpected = load_parsed()
    unexpected["event_id"] = "must-not-be-accepted"
    with pytest.raises(SysmonEvent1MappingError, match=r"at event_id$") as exc_info:
        map_sysmon_event1_to_endpoint_event(
            unexpected, source_artifact="tests/fixtures/synthetic.json"
        )
    assert "must-not-be-accepted" not in str(exc_info.value)


@pytest.mark.parametrize("source_artifact", ["", "   "])
def test_empty_source_artifact_fails_closed(source_artifact: str) -> None:
    with pytest.raises(SysmonEvent1MappingError, match=r"at source_artifact$"):
        map_sysmon_event1_to_endpoint_event(load_parsed(), source_artifact=source_artifact)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("image", "C:\\Windows\\System32\\"),
        ("image", "C:/Windows/System32/"),
        ("parent_image", "C:\\Windows\\"),
        ("parent_image", "C:/Windows/"),
    ],
)
def test_paths_without_a_filename_fail_closed(field: str, value: str) -> None:
    parsed = load_parsed()
    parsed[field] = value

    with pytest.raises(SysmonEvent1MappingError, match=rf"at {field}$"):
        map_sysmon_event1_to_endpoint_event(parsed, source_artifact="tests/fixtures/synthetic.json")


def test_windows_basename_preserves_case_and_does_not_require_exe_suffix() -> None:
    assert windows_basename("C:\\Tools\\MixedCase.CMD", field="image") == "MixedCase.CMD"
    assert windows_basename("C:\\Tools\\script", field="image") == "script"


def test_output_schema_failure_is_wrapped_with_safe_path(monkeypatch) -> None:
    valid_event = map_fixture()
    monkeypatch.setattr(
        mapper,
        "windows_basename",
        lambda value, *, field: {"secret": "sensitive-output-text"},
    )

    with pytest.raises(
        SysmonEvent1MappingError,
        match=r"normalized output failed at events\.0\.process_name$",
    ) as exc_info:
        map_fixture()

    rendered = "".join(
        traceback.format_exception(
            exc_info.type,
            exc_info.value,
            exc_info.tb,
        )
    )
    assert exc_info.value.__cause__ is None
    assert "normalized output failed at events.0.process_name" in rendered
    assert "sensitive-output-text" not in rendered

    with pytest.raises(
        SysmonEvent1MappingError,
        match=r"normalized output failed at events\.0\.event_id$",
    ):
        validate_endpoint_event(
            {
                **valid_event,
                "event_id": "",
            }
        )


@pytest.mark.parametrize("name", [FIXTURE_A_NAME, FIXTURE_B_NAME, FIXTURE_C_NAME])
def test_source_parser_to_mapper_matches_expected_parsed_to_mapper(name: str) -> None:
    source_artifact = (SOURCE_DIR / name).as_posix()
    parsed_from_source = parse_sysmon_event1_source(load_json(SOURCE_DIR / name))

    from_source = map_sysmon_event1_to_endpoint_event(
        parsed_from_source,
        source_artifact=source_artifact,
    )
    from_expected_parsed = map_sysmon_event1_to_endpoint_event(
        load_parsed(name),
        source_artifact=source_artifact,
    )

    assert from_source == from_expected_parsed
