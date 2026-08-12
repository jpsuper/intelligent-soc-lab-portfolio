import copy
import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = Path("schemas/windows_security_auth_source_fixture.schema.json")
FIXTURE_DIR = Path("tests/fixtures/windows/security_auth/source")
SUCCESS_ID = "windows-security-4624-network-logon-success-001"
FAILURE_ID = "windows-security-4625-network-logon-failure-001"
PROVIDER_GUID = "{54849625-5478-4994-a5ba-3e3b0328c30d}"
FORBIDDEN_DOWNSTREAM_KEYS = {
    "event_id",
    "event_type",
    "source",
    "platform",
    "host",
    "timestamp",
    "auth_success",
    "auth_failure",
    "malicious",
    "verdict",
    "severity",
    "confidence",
    "detection",
    "incident",
    "response",
    "expected_parsed",
    "expected_normalized",
    "expected_detection",
}
FORBIDDEN_RUNTIME_VALUES = {
    "PRIVATE-RUNTIME-HOST",
}
RFC1918_IPV4 = re.compile(
    r"^(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})$"
)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def fixture_paths() -> list[Path]:
    return sorted(FIXTURE_DIR.glob("*.json"))


def fixtures() -> list[tuple[Path, dict]]:
    return [(path, load_json(path)) for path in fixture_paths()]


def validator() -> Draft202012Validator:
    return Draft202012Validator(
        load_json(SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def fixture_by_id(fixture_id: str) -> dict:
    return next(value for _, value in fixtures() if value["fixture_id"] == fixture_id)


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


def test_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(load_json(SCHEMA_PATH))


def test_fixture_inventory_is_exactly_success_and_failure() -> None:
    assert {path.stem for path in fixture_paths()} == {SUCCESS_ID, FAILURE_ID}


def test_all_source_fixtures_are_schema_valid() -> None:
    source_validator = validator()
    for _, fixture in fixtures():
        source_validator.validate(fixture)


def test_filenames_and_fixture_ids_match() -> None:
    for path, fixture in fixtures():
        assert path.stem == fixture["fixture_id"]


def test_source_identities_are_distinct() -> None:
    loaded = [fixture for _, fixture in fixtures()]
    assert len({fixture["fixture_id"] for fixture in loaded}) == len(loaded)
    assert len({fixture["system"]["event_record_id"] for fixture in loaded}) == len(loaded)


def test_provider_and_route_invariants() -> None:
    for _, fixture in fixtures():
        system = fixture["system"]
        assert fixture["fixture_contract_version"] == "1.0"
        assert fixture["source_format"] == "windows_security_eventlog_json"
        assert system["provider_name"] == "Microsoft-Windows-Security-Auditing"
        assert system["provider_guid"] == PROVIDER_GUID
        assert system["provider_event_id"] in {4624, 4625}
        assert system["channel"] == "Security"


def test_success_fixture_represents_one_network_logon() -> None:
    fixture = fixture_by_id(SUCCESS_ID)
    event_data = fixture["event_data"]

    assert fixture["system"]["provider_event_id"] == 4624
    assert event_data["LogonType"] == "3"
    assert event_data["TargetLogonId"].startswith("0x")
    assert "FailureReason" not in event_data
    assert "Status" not in event_data
    assert "SubStatus" not in event_data


def test_failure_fixture_represents_one_failed_network_logon() -> None:
    fixture = fixture_by_id(FAILURE_ID)
    event_data = fixture["event_data"]

    assert fixture["system"]["provider_event_id"] == 4625
    assert event_data["LogonType"] == "3"
    assert event_data["FailureReason"] == "%%2313"
    assert event_data["Status"] == "0xC000006D"
    assert event_data["SubStatus"] == "0xC000006A"
    assert "TargetLogonId" not in event_data


def test_event_specific_fields_are_required() -> None:
    source_validator = validator()
    success = copy.deepcopy(fixture_by_id(SUCCESS_ID))
    failure = copy.deepcopy(fixture_by_id(FAILURE_ID))
    del success["event_data"]["TargetLogonId"]
    del failure["event_data"]["Status"]

    with pytest.raises(ValidationError):
        source_validator.validate(success)
    with pytest.raises(ValidationError):
        source_validator.validate(failure)


def test_event_specific_fields_cannot_cross_routes() -> None:
    source_validator = validator()
    success = copy.deepcopy(fixture_by_id(SUCCESS_ID))
    failure = copy.deepcopy(fixture_by_id(FAILURE_ID))
    success["event_data"]["Status"] = "0x0"
    failure["event_data"]["TargetLogonId"] = "0xABC002"

    with pytest.raises(ValidationError):
        source_validator.validate(success)
    with pytest.raises(ValidationError):
        source_validator.validate(failure)


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("system", "provider_name", "Microsoft-Windows-Sysmon"),
        ("system", "provider_event_id", 4634),
        ("system", "channel", "System"),
        ("system", "event_record_id", 0),
        ("event_data", "LogonType", 3),
        ("event_data", "SubjectLogonId", "3e7"),
        ("event_data", "IpAddress", "not-an-ip-address"),
        ("event_data", "IpPort", "65536"),
    ],
)
def test_invalid_source_values_fail_schema_validation(
    section: str,
    field: str,
    value: object,
) -> None:
    fixture = copy.deepcopy(fixture_by_id(SUCCESS_ID))
    fixture[section][field] = value

    with pytest.raises(ValidationError):
        validator().validate(fixture)


def test_unreviewed_source_field_fails_closed() -> None:
    fixture = copy.deepcopy(fixture_by_id(SUCCESS_ID))
    fixture["event_data"]["ElevatedToken"] = "%%1842"

    with pytest.raises(ValidationError):
        validator().validate(fixture)


def test_fixtures_do_not_contain_downstream_conclusions() -> None:
    for _, fixture in fixtures():
        assert collect_keys(fixture).isdisjoint(FORBIDDEN_DOWNSTREAM_KEYS)


def test_fixtures_use_documentation_addresses_and_no_runtime_identifiers() -> None:
    for _, fixture in fixtures():
        values = collect_string_values(fixture)
        assert "198.51.100.24" in values
        assert all(RFC1918_IPV4.fullmatch(value) is None for value in values)
        for forbidden_value in FORBIDDEN_RUNTIME_VALUES:
            assert all(forbidden_value not in value for value in values)
