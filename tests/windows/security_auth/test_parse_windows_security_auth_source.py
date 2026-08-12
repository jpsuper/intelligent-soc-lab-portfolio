import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

DOMAIN_MODULE_DIR = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "security_auth"
sys.path.insert(0, str(DOMAIN_MODULE_DIR))

from parse_windows_security_auth_source import (  # noqa: E402
    WindowsSecurityAuthParseError,
    parse_windows_security_auth_source,
)

SOURCE_DIR = Path("tests/fixtures/windows/security_auth/source")
EXPECTED_DIR = Path("tests/fixtures/windows/security_auth/expected_parsed")
PARSED_SCHEMA_PATH = Path("schemas/windows_security_auth_parsed_event.schema.json")
SUCCESS_NAME = "windows-security-4624-network-logon-success-001.json"
FAILURE_NAME = "windows-security-4625-network-logon-failure-001.json"
FORBIDDEN_PARSED_FIELDS = {
    "event_id",
    "event_type",
    "source",
    "platform",
    "host",
    "timestamp",
    "user",
    "src_ip",
    "src_port",
    "auth_success",
    "auth_failure",
    "malicious",
    "verdict",
    "severity",
    "confidence",
    "detection",
    "incident",
    "response",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def source(name: str = SUCCESS_NAME) -> dict:
    return load_json(SOURCE_DIR / name)


def expected(name: str = SUCCESS_NAME) -> dict:
    return load_json(EXPECTED_DIR / name)


def parsed_validator() -> Draft202012Validator:
    return Draft202012Validator(
        load_json(PARSED_SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def test_parsed_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(load_json(PARSED_SCHEMA_PATH))


def test_source_and_expected_parsed_inventories_match() -> None:
    source_names = {path.name for path in SOURCE_DIR.glob("*.json")}
    expected_names = {path.name for path in EXPECTED_DIR.glob("*.json")}
    assert source_names == expected_names == {SUCCESS_NAME, FAILURE_NAME}


def test_expected_parsed_artifacts_are_schema_valid() -> None:
    validator = parsed_validator()
    for path in sorted(EXPECTED_DIR.glob("*.json")):
        validator.validate(load_json(path))


@pytest.mark.parametrize("name", [SUCCESS_NAME, FAILURE_NAME])
def test_source_parser_exactly_matches_expected_parsed(name: str) -> None:
    assert parse_windows_security_auth_source(source(name)) == expected(name)


def test_success_parsed_types_and_route_are_explicit() -> None:
    parsed = parse_windows_security_auth_source(source(SUCCESS_NAME))

    assert parsed["provider_name"] == "Microsoft-Windows-Security-Auditing"
    assert parsed["provider_event_id"] == 4624
    assert parsed["channel"] == "Security"
    assert parsed["system_time"] == "2026-01-15T02:00:00.123000Z"
    assert type(parsed["event_record_id"]) is int
    assert type(parsed["logon_type"]) is int
    assert type(parsed["source_port"]) is int
    assert parsed["target_logon_id"] == "0xABC001"
    assert "failure_reason" not in parsed
    assert "status" not in parsed
    assert "sub_status" not in parsed


def test_failure_sentinels_are_omitted_and_status_is_not_interpreted() -> None:
    parsed = parse_windows_security_auth_source(source(FAILURE_NAME))

    assert parsed["provider_event_id"] == 4625
    assert "subject_user_name" not in parsed
    assert "subject_domain_name" not in parsed
    assert "target_logon_id" not in parsed
    assert parsed["failure_reason"] == "%%2313"
    assert parsed["status"] == "0xC000006D"
    assert parsed["sub_status"] == "0xC000006A"


def test_optional_network_sentinels_are_omitted() -> None:
    value = source(FAILURE_NAME)
    value["event_data"].update(
        {
            "WorkstationName": "-",
            "IpAddress": "-",
            "IpPort": "-",
        }
    )

    parsed = parse_windows_security_auth_source(value)

    assert "workstation_name" not in parsed
    assert "source_ip" not in parsed
    assert "source_port" not in parsed


def test_system_time_is_normalized_to_utc_microseconds() -> None:
    value = source()
    value["system"]["system_time"] = "2026-01-15T03:00:00.123+01:00"

    parsed = parse_windows_security_auth_source(value)

    assert parsed["system_time"] == "2026-01-15T02:00:00.123000Z"


def test_parser_does_not_modify_source() -> None:
    value = source()
    original = copy.deepcopy(value)

    parse_windows_security_auth_source(value)

    assert value == original


def test_parsed_output_contains_no_canonical_or_downstream_fields() -> None:
    for name in (SUCCESS_NAME, FAILURE_NAME):
        parsed = parse_windows_security_auth_source(source(name))
        assert collect_keys(parsed).isdisjoint(FORBIDDEN_PARSED_FIELDS)


def test_non_mapping_source_fails_closed() -> None:
    with pytest.raises(
        WindowsSecurityAuthParseError,
        match="source validation failed at source",
    ):
        parse_windows_security_auth_source([])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("section", "field", "value", "path"),
    [
        (
            "system",
            "provider_name",
            "Microsoft-Windows-Sysmon",
            "system.provider_name",
        ),
        ("system", "provider_event_id", 4634, "system.provider_event_id"),
        ("system", "channel", "System", "system.channel"),
        ("event_data", "LogonType", "not-a-number", "event_data.LogonType"),
        ("event_data", "IpPort", "65536", "event_data.IpPort"),
    ],
)
def test_invalid_source_route_and_types_fail_at_safe_path(
    section: str,
    field: str,
    value: object,
    path: str,
) -> None:
    fixture = source()
    fixture[section][field] = value

    with pytest.raises(WindowsSecurityAuthParseError, match=path):
        parse_windows_security_auth_source(fixture)


def test_unreviewed_field_error_does_not_disclose_source_values() -> None:
    fixture = source()
    fixture["event_data"]["UnexpectedField"] = "private-source-value"

    with pytest.raises(WindowsSecurityAuthParseError) as exc_info:
        parse_windows_security_auth_source(fixture)

    message = str(exc_info.value)
    assert "event_data.UnexpectedField" in message
    assert "private-source-value" not in message


def test_parsed_schema_rejects_cross_route_fields() -> None:
    success = expected(SUCCESS_NAME)
    failure = expected(FAILURE_NAME)
    success["status"] = "0x0"
    failure["target_logon_id"] = "0xABC002"

    with pytest.raises(ValidationError):
        parsed_validator().validate(success)
    with pytest.raises(ValidationError):
        parsed_validator().validate(failure)
