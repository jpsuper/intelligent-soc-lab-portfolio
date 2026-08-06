import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

DOMAIN_MODULE_DIR = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "sysmon_event1"
sys.path.insert(0, str(DOMAIN_MODULE_DIR))

from map_sysmon_event1_to_endpoint_event import (  # noqa: E402
    map_sysmon_event1_to_endpoint_event,
)
from parse_sysmon_event1_source import parse_sysmon_event1_source  # noqa: E402

SOURCE_DIR = Path("tests/fixtures/windows/sysmon_event1/source")
PARSED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_parsed")
EXPECTED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
ENDPOINT_SCHEMA_PATH = Path("schemas/endpoint_events.schema.json")

FIXTURE_A_ID = "sysmon-event1-ordinary-powershell-001"
FIXTURE_B_ID = "sysmon-event1-encoded-flag-001"
FIXTURE_C_ID = "sysmon-event1-ordinary-notepad-001"
EXPECTED_EVENT_IDS = {
    FIXTURE_A_ID: (
        "sysmon-event1:v1:54aa19e2ce68d8cf8f27f519992024f5338d6d9e65c6916912919465c538bcef"
    ),
    FIXTURE_B_ID: (
        "sysmon-event1:v1:4fc28bf961113fe8702ef58882f449a3928772fa5eec9fa0d34e2e033c134643"
    ),
    FIXTURE_C_ID: (
        "sysmon-event1:v1:0d71d2939ce94b4a27040fa570be53d1bf1913aa695d9545b92fd27143ab332f"
    ),
}
EXPECTED_PROCESS_NAMES = {
    FIXTURE_A_ID: ("powershell.exe", "cmd.exe"),
    FIXTURE_B_ID: ("powershell.exe", "cmd.exe"),
    FIXTURE_C_ID: ("notepad.exe", "explorer.exe"),
}
EXPECTED_TOP_LEVEL_FIELDS = {
    "event_id",
    "source",
    "platform",
    "host",
    "timestamp",
    "event_type",
    "user",
    "pid",
    "ppid",
    "process_name",
    "exe",
    "command_line",
    "cwd",
    "parent_process_name",
    "parent_exe",
    "parent_command_line",
    "raw_ref",
    "source_fields",
}
EXPECTED_SOURCE_FIELDS = {
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
    "provider_guid",
    "event_version",
    "event_level",
    "event_task",
    "event_opcode",
    "event_keywords",
    "file_version",
    "description",
    "product",
    "company",
    "original_file_name",
    "logon_guid",
    "logon_id",
    "terminal_session_id",
    "integrity_level",
    "hashes",
    "parent_process_guid",
    "parent_user",
}
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
FORBIDDEN_KEYS = {
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
    "malicious",
    "verdict",
    "severity",
    "confidence",
    "detection",
    "incident",
    "response",
    "expected_detection",
    "powershell_process_observed",
    "encoded_command_observed",
    "attack_id",
    "run_id",
}
FORBIDDEN_ENVELOPE_FIELDS = {
    "schema_version",
    "events",
    "generated_at",
    "source_run_id",
    "metadata",
}
FORBIDDEN_RUNTIME_VALUES = {
    "".join(("WIN-", "VICTIM01")),
    ".".join(("192", "168", "1", "31")),
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def json_paths(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.json"))


def expected_artifacts() -> list[tuple[Path, dict]]:
    return [(path, load_json(path)) for path in json_paths(EXPECTED_DIR)]


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def collect_string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for child in value.values() for text in collect_string_values(child)]
    if isinstance(value, list):
        return [text for child in value for text in collect_string_values(child)]
    return []


def endpoint_validator() -> Draft202012Validator:
    return Draft202012Validator(
        load_json(ENDPOINT_SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def test_current_expected_normalized_inventory_is_a_b_and_c() -> None:
    artifacts = expected_artifacts()
    assert artifacts
    assert {artifact["raw_ref"]["fixture_id"] for _, artifact in artifacts} == {
        FIXTURE_A_ID,
        FIXTURE_B_ID,
        FIXTURE_C_ID,
    }


def test_source_parsed_and_expected_normalized_filename_inventories_match() -> None:
    source_names = {path.name for path in json_paths(SOURCE_DIR)}
    parsed_names = {path.name for path in json_paths(PARSED_DIR)}
    expected_names = {path.name for path in json_paths(EXPECTED_DIR)}
    assert source_names == parsed_names == expected_names


def test_expected_normalized_filenames_match_raw_ref_fixture_ids() -> None:
    for path, artifact in expected_artifacts():
        assert path.stem == artifact["raw_ref"]["fixture_id"]


def test_all_expected_normalized_artifacts_are_endpoint_schema_valid() -> None:
    artifacts = expected_artifacts()
    assert artifacts
    validator = endpoint_validator()
    for _, artifact in artifacts:
        validator.validate(
            {
                "schema_version": "endpoint_events.v1",
                "events": [artifact],
            }
        )


def test_expected_parsed_mapper_output_exactly_matches_expected_normalized() -> None:
    for expected_path in json_paths(EXPECTED_DIR):
        source_path = SOURCE_DIR / expected_path.name
        actual = map_sysmon_event1_to_endpoint_event(
            load_json(PARSED_DIR / expected_path.name),
            source_artifact=source_path.as_posix(),
        )
        assert actual == load_json(expected_path)


def test_source_parser_and_mapper_output_exactly_matches_expected_normalized() -> None:
    for source_path in json_paths(SOURCE_DIR):
        parsed = parse_sysmon_event1_source(load_json(source_path))
        actual = map_sysmon_event1_to_endpoint_event(
            parsed,
            source_artifact=source_path.as_posix(),
        )
        assert actual == load_json(EXPECTED_DIR / source_path.name)


def test_expected_normalized_golden_event_ids() -> None:
    for _, artifact in expected_artifacts():
        fixture_id = artifact["raw_ref"]["fixture_id"]
        event_id = artifact["event_id"]
        assert event_id == EXPECTED_EVENT_IDS[fixture_id]
        assert re.fullmatch(r"sysmon-event1:v1:[0-9a-f]{64}", event_id)


def test_expected_normalized_raw_refs_point_to_sanitized_source_fixtures() -> None:
    for path, artifact in expected_artifacts():
        source_path = SOURCE_DIR / path.name
        raw_ref = artifact["raw_ref"]
        assert raw_ref == {
            "source_artifact": source_path.as_posix(),
            "fixture_id": path.stem,
        }
        assert source_path.is_file()
        assert not Path(raw_ref["source_artifact"]).is_absolute()
        assert "\\" not in raw_ref["source_artifact"]


def test_expected_normalized_artifacts_preserve_canonical_and_provenance_boundary() -> None:
    for _, artifact in expected_artifacts():
        fixture_id = artifact["raw_ref"]["fixture_id"]
        source_fields = artifact["source_fields"]
        process_name, parent_process_name = EXPECTED_PROCESS_NAMES[fixture_id]

        assert set(artifact) == EXPECTED_TOP_LEVEL_FIELDS
        assert artifact["source"] == "sysmon"
        assert artifact["platform"] == "windows"
        assert artifact["host"] == "WIN-FIXTURE01"
        assert artifact["event_type"] == "process_exec"
        assert artifact["process_name"] == process_name
        assert artifact["parent_process_name"] == parent_process_name
        assert set(source_fields) == EXPECTED_SOURCE_FIELDS
        assert source_fields["timestamp_source"] == "utc_time"
        assert source_fields["timestamps_equal"] is True
        assert source_fields["system_time"]
        assert source_fields["utc_time"]
        assert artifact["timestamp"] == source_fields["utc_time"]
        assert source_fields["mapper_name"] == "sysmon_event1_endpoint_event_mapper"
        assert source_fields["mapper_version"] == "1.0"
        assert source_fields["event_id_method"] == "sha256-json-canonical-v1"
        assert source_fields["event_identity_version"] == "sysmon-event1-event-id.v1"
        assert "fixture_id" not in source_fields
        assert set(source_fields).isdisjoint(CANONICAL_DUPLICATES)
        assert collect_keys(artifact).isdisjoint(FORBIDDEN_KEYS)


def test_expected_normalized_type_boundary() -> None:
    for _, artifact in expected_artifacts():
        source_fields = artifact["source_fields"]
        assert isinstance(artifact["event_id"], str)
        assert type(artifact["pid"]) is int
        assert type(artifact["ppid"]) is int
        assert isinstance(artifact["timestamp"], str)
        assert type(source_fields["provider_event_id"]) is int
        assert type(source_fields["event_record_id"]) is int
        assert type(source_fields["terminal_session_id"]) is int
        assert type(source_fields["timestamps_equal"]) is bool
        assert isinstance(source_fields["hashes"], dict)
        assert all(
            isinstance(algorithm, str) and isinstance(value, str)
            for algorithm, value in source_fields["hashes"].items()
        )
        assert isinstance(artifact["raw_ref"], dict)


def test_expected_normalized_artifacts_do_not_contain_runtime_identifiers() -> None:
    for _, artifact in expected_artifacts():
        values = collect_string_values(artifact)
        for forbidden_value in FORBIDDEN_RUNTIME_VALUES:
            assert all(forbidden_value not in value for value in values)


def test_expected_normalized_artifacts_are_event_objects_not_generated_envelopes() -> None:
    for _, artifact in expected_artifacts():
        assert set(artifact).isdisjoint(FORBIDDEN_ENVELOPE_FIELDS)
