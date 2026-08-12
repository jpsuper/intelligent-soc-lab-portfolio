import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

DOMAIN_MODULE_DIR = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "security_auth"
sys.path.insert(0, str(DOMAIN_MODULE_DIR))

from map_windows_security_auth_to_endpoint_event import (  # noqa: E402
    WindowsSecurityAuthMappingError,
    canonical_event_id,
    map_windows_security_auth_to_endpoint_event,
)

PARSED_DIR = Path("tests/fixtures/windows/security_auth/expected_parsed")
NORMALIZED_DIR = Path("tests/fixtures/windows/security_auth/expected_normalized")
ENDPOINT_SCHEMA_PATH = Path("schemas/endpoint_events.schema.json")
SUCCESS_NAME = "windows-security-4624-network-logon-success-001.json"
FAILURE_NAME = "windows-security-4625-network-logon-failure-001.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def parsed(name: str = SUCCESS_NAME) -> dict:
    return load_json(PARSED_DIR / name)


def expected(name: str = SUCCESS_NAME) -> dict:
    return load_json(NORMALIZED_DIR / name)


def source_artifact(name: str) -> str:
    return f"tests/fixtures/windows/security_auth/source/{name}"


def endpoint_validator() -> Draft202012Validator:
    return Draft202012Validator(
        load_json(ENDPOINT_SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def mapped(name: str = SUCCESS_NAME) -> dict:
    return map_windows_security_auth_to_endpoint_event(
        parsed(name),
        source_artifact=source_artifact(name),
    )


def test_parsed_and_expected_normalized_inventories_match() -> None:
    parsed_names = {path.name for path in PARSED_DIR.glob("*.json")}
    normalized_names = {path.name for path in NORMALIZED_DIR.glob("*.json")}
    assert parsed_names == normalized_names == {SUCCESS_NAME, FAILURE_NAME}


def test_expected_normalized_artifacts_are_endpoint_schema_valid() -> None:
    validator = endpoint_validator()
    for path in sorted(NORMALIZED_DIR.glob("*.json")):
        validator.validate(
            {
                "schema_version": "endpoint_events.v1",
                "events": [load_json(path)],
            }
        )


@pytest.mark.parametrize("name", [SUCCESS_NAME, FAILURE_NAME])
def test_mapper_exactly_matches_expected_normalized(name: str) -> None:
    assert mapped(name) == expected(name)


def test_success_maps_reviewed_canonical_fields() -> None:
    event = mapped(SUCCESS_NAME)

    assert event["source"] == "windows_security"
    assert event["platform"] == "windows"
    assert event["host"] == "WIN-FIXTURE01"
    assert event["timestamp"] == "2026-01-15T02:00:00.123000Z"
    assert event["event_type"] == "auth_success"
    assert event["user"] == "LAB\\fixture-user"
    assert event["src_ip"] == "198.51.100.24"
    assert event["src_port"] == 54432


def test_failure_maps_event_type_without_interpreting_provider_status() -> None:
    event = mapped(FAILURE_NAME)

    assert event["event_type"] == "auth_failure"
    assert event["user"] == "LAB\\fixture-user"
    assert event["source_fields"]["failure_reason"] == "%%2313"
    assert event["source_fields"]["status"] == "0xC000006D"
    assert event["source_fields"]["sub_status"] == "0xC000006A"
    assert "target_logon_id" not in event["source_fields"]


def test_success_and_failure_preserve_event_specific_provenance() -> None:
    success = mapped(SUCCESS_NAME)["source_fields"]
    failure = mapped(FAILURE_NAME)["source_fields"]

    assert success["target_logon_id"] == "0xABC001"
    assert "failure_reason" not in success
    assert failure["subject_user_sid"] == "S-1-0-0"
    assert "subject_user_name" not in failure
    assert "subject_domain_name" not in failure


def test_provenance_records_mapper_and_identity_policy() -> None:
    fields = mapped(SUCCESS_NAME)["source_fields"]

    assert fields["provider_name"] == "Microsoft-Windows-Security-Auditing"
    assert fields["provider_event_id"] == 4624
    assert fields["event_record_id"] == 42001
    assert fields["channel"] == "Security"
    assert fields["system_time"] == "2026-01-15T02:00:00.123000Z"
    assert fields["timestamp_source"] == "system_time"
    assert fields["mapper_name"] == "windows_security_auth_endpoint_event_mapper"
    assert fields["mapper_version"] == "1.0"
    assert fields["event_id_method"] == "sha256-json-canonical-v1"
    assert fields["event_identity_version"] == "windows-security-auth-event-id.v1"


def test_optional_network_fields_are_omitted_without_placeholder() -> None:
    value = parsed(FAILURE_NAME)
    del value["source_ip"]
    del value["source_port"]

    event = map_windows_security_auth_to_endpoint_event(
        value,
        source_artifact=source_artifact(FAILURE_NAME),
    )

    assert "src_ip" not in event
    assert "src_port" not in event


def test_event_id_is_deterministic_casefolded_and_not_fixture_bound() -> None:
    value = parsed()
    changed_provenance = copy.deepcopy(value)
    changed_provenance["computer"] = value["computer"].lower()
    changed_provenance["fixture_id"] = "windows-security-4624-alternate-case-999"

    assert canonical_event_id(value) == canonical_event_id(changed_provenance)


def test_event_record_identity_change_changes_event_id() -> None:
    value = parsed()
    changed = copy.deepcopy(value)
    changed["event_record_id"] += 1

    assert canonical_event_id(value) != canonical_event_id(changed)


def test_raw_reference_is_separate_from_windows_record_identity() -> None:
    event = mapped(SUCCESS_NAME)

    assert event["raw_ref"] == {
        "source_artifact": source_artifact(SUCCESS_NAME),
        "fixture_id": SUCCESS_NAME.removesuffix(".json"),
    }
    assert event["source_fields"]["event_record_id"] == 42001
    assert event["event_id"].startswith("windows-security-auth:v1:")


def test_mapper_does_not_modify_parsed_event() -> None:
    value = parsed()
    original = copy.deepcopy(value)

    map_windows_security_auth_to_endpoint_event(
        value,
        source_artifact=source_artifact(SUCCESS_NAME),
    )

    assert value == original


def test_non_mapping_parsed_event_fails_closed() -> None:
    with pytest.raises(
        WindowsSecurityAuthMappingError,
        match="mapping failed at parsed_event",
    ):
        map_windows_security_auth_to_endpoint_event(  # type: ignore[arg-type]
            [],
            source_artifact="fixture.json",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_name", "Microsoft-Windows-Sysmon"),
        ("provider_event_id", 4634),
        ("channel", "System"),
        ("system_time", "not-a-timestamp"),
        ("source_port", 65536),
    ],
)
def test_invalid_parsed_route_and_types_fail_at_safe_path(
    field: str,
    value: object,
) -> None:
    invalid = parsed()
    invalid[field] = value

    with pytest.raises(WindowsSecurityAuthMappingError, match=field):
        map_windows_security_auth_to_endpoint_event(
            invalid,
            source_artifact=source_artifact(SUCCESS_NAME),
        )


@pytest.mark.parametrize("source_reference", ["", "   ", None, 1])
def test_invalid_source_artifact_fails_closed(source_reference: object) -> None:
    with pytest.raises(
        WindowsSecurityAuthMappingError,
        match="mapping failed at source_artifact",
    ):
        map_windows_security_auth_to_endpoint_event(
            parsed(),
            source_artifact=source_reference,  # type: ignore[arg-type]
        )


def test_unreviewed_field_error_does_not_disclose_value() -> None:
    invalid = parsed()
    invalid["unexpected_field"] = "private-source-value"

    with pytest.raises(WindowsSecurityAuthMappingError) as exc_info:
        map_windows_security_auth_to_endpoint_event(
            invalid,
            source_artifact=source_artifact(SUCCESS_NAME),
        )

    message = str(exc_info.value)
    assert "unexpected_field" in message
    assert "private-source-value" not in message
