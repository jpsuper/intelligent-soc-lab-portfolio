import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

DOMAIN_MODULE_DIR = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "security_auth"
sys.path.insert(0, str(DOMAIN_MODULE_DIR))

from adapt_wazuh_windows_security_auth_hit import (  # noqa: E402
    WazuhWindowsSecurityAuthAdaptError,
    adapt_wazuh_windows_security_auth_hit,
)
from map_windows_security_auth_to_endpoint_event import (  # noqa: E402
    map_windows_security_auth_to_endpoint_event,
)
from parse_windows_security_auth_source import (  # noqa: E402
    parse_windows_security_auth_source,
)

WAZUH_DIR = Path("tests/fixtures/windows/security_auth/wazuh_indexer")
SOURCE_DIR = Path("tests/fixtures/windows/security_auth/source")
SCHEMA_PATH = Path("schemas/wazuh_windows_security_auth_hit_projection.schema.json")
FIXTURE_NAMES = (
    "windows-security-4624-network-logon-success-001.json",
    "windows-security-4625-network-logon-failure-001.json",
)
OMITTABLE_SENTINEL_FIELDS = (
    ("subjectUserName", "SubjectUserName", "subject_user_name"),
    ("subjectDomainName", "SubjectDomainName", "subject_domain_name"),
    ("workstationName", "WorkstationName", "workstation_name"),
    ("ipAddress", "IpAddress", "source_ip"),
    ("ipPort", "IpPort", "source_port"),
)
EXPECTED_PROVENANCE_KEYS = {
    "source_product",
    "source_plane",
    "index",
    "document_id",
    "alert_timestamp",
    "retrieved_at",
    "query_ref",
    "query_window_start",
    "query_window_end",
    "agent_id",
    "agent_name",
    "manager_name",
    "adapter_name",
    "adapter_version",
    "validation_outcome",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def projection(name: str = FIXTURE_NAMES[0]) -> dict:
    return load_json(WAZUH_DIR / name)


def windows_system(value: dict) -> dict:
    return value["hit"]["_source"]["data"]["win"]["system"]


def windows_eventdata(value: dict) -> dict:
    return value["hit"]["_source"]["data"]["win"]["eventdata"]


def test_wazuh_projection_inventory_is_exactly_4624_and_4625() -> None:
    assert tuple(path.name for path in sorted(WAZUH_DIR.glob("*.json"))) == tuple(
        sorted(FIXTURE_NAMES)
    )


def test_all_wazuh_projections_are_schema_valid() -> None:
    validator = Draft202012Validator(
        load_json(SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    for name in FIXTURE_NAMES:
        validator.validate(projection(name))


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_wazuh_projection_converts_exactly_to_existing_source_fixture(name: str) -> None:
    adapted = adapt_wazuh_windows_security_auth_hit(projection(name))

    assert adapted["source_event"] == load_json(SOURCE_DIR / name)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_wazuh_and_direct_paths_have_normalized_semantic_parity(name: str) -> None:
    source_path = SOURCE_DIR / name
    wazuh_path = WAZUH_DIR / name
    direct_source = load_json(source_path)
    adapted_source = adapt_wazuh_windows_security_auth_hit(projection(name))["source_event"]

    direct = map_windows_security_auth_to_endpoint_event(
        parse_windows_security_auth_source(direct_source),
        source_artifact=source_path.as_posix(),
    )
    via_wazuh = map_windows_security_auth_to_endpoint_event(
        parse_windows_security_auth_source(adapted_source),
        source_artifact=wazuh_path.as_posix(),
    )

    direct_without_ref = {key: value for key, value in direct.items() if key != "raw_ref"}
    wazuh_without_ref = {key: value for key, value in via_wazuh.items() if key != "raw_ref"}
    assert wazuh_without_ref == direct_without_ref
    assert via_wazuh["event_id"] == direct["event_id"]
    assert via_wazuh["raw_ref"] == {
        "source_artifact": wazuh_path.as_posix(),
        "fixture_id": wazuh_path.stem,
    }


def test_retrieval_provenance_is_allowlisted_and_separate_from_source_event() -> None:
    adapted = adapt_wazuh_windows_security_auth_hit(projection())
    provenance = adapted["retrieval_provenance"]

    assert set(provenance) == EXPECTED_PROVENANCE_KEYS
    assert provenance["source_product"] == "wazuh_indexer"
    assert provenance["source_plane"] == "wazuh_alerts"
    assert provenance["document_id"] == "wazuh-auth-fixture-document-a"
    assert provenance["adapter_name"] == "wazuh_windows_security_auth_hit_adapter"
    assert provenance["adapter_version"] == "1.0"
    assert provenance["validation_outcome"] == "validated"
    assert adapted["source_event"].keys().isdisjoint(EXPECTED_PROVENANCE_KEYS)


@pytest.mark.parametrize(
    ("wazuh_field", "source_field", "parsed_field"),
    OMITTABLE_SENTINEL_FIELDS,
)
def test_wazuh_omitted_provider_sentinel_is_restored_as_unavailable(
    wazuh_field: str,
    source_field: str,
    parsed_field: str,
) -> None:
    value = projection(FIXTURE_NAMES[1])
    del windows_eventdata(value)[wazuh_field]

    source_event = adapt_wazuh_windows_security_auth_hit(value)["source_event"]
    parsed = parse_windows_security_auth_source(source_event)

    assert source_event["event_data"][source_field] == "-"
    assert parsed_field not in parsed


def test_backend_document_id_cannot_substitute_for_event_record_id() -> None:
    value = projection()
    value["hit"]["_id"] = "999999"
    del windows_system(value)["eventRecordID"]

    with pytest.raises(WazuhWindowsSecurityAuthAdaptError, match=r"system\.eventRecordID"):
        adapt_wazuh_windows_security_auth_hit(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("providerName", "Microsoft-Windows-Sysmon"),
        ("eventID", "4634"),
        ("channel", "System"),
    ],
)
def test_wrong_source_route_fails_closed(field: str, value: str) -> None:
    source = projection()
    windows_system(source)[field] = value

    with pytest.raises(WazuhWindowsSecurityAuthAdaptError, match=field):
        adapt_wazuh_windows_security_auth_hit(source)


def test_event_specific_fields_cannot_cross_routes() -> None:
    success = projection(FIXTURE_NAMES[0])
    failure = projection(FIXTURE_NAMES[1])
    windows_eventdata(success)["status"] = "0x0"
    windows_eventdata(failure)["targetLogonId"] = "0xABC002"

    with pytest.raises(WazuhWindowsSecurityAuthAdaptError):
        adapt_wazuh_windows_security_auth_hit(success)
    with pytest.raises(WazuhWindowsSecurityAuthAdaptError):
        adapt_wazuh_windows_security_auth_hit(failure)


@pytest.mark.parametrize("value", ["", "-1", " 42001", "backend-doc-id"])
def test_invalid_event_record_id_fails_closed(value: str) -> None:
    source = projection()
    windows_system(source)["eventRecordID"] = value

    with pytest.raises(WazuhWindowsSecurityAuthAdaptError, match=r"system\.eventRecordID"):
        adapt_wazuh_windows_security_auth_hit(source)


def test_alert_timestamp_must_be_inside_declared_query_window() -> None:
    source = projection()
    source["hit"]["_source"]["timestamp"] = "2026-01-15T03:00:00Z"

    with pytest.raises(WazuhWindowsSecurityAuthAdaptError, match=r"_source\.timestamp"):
        adapt_wazuh_windows_security_auth_hit(source)


def test_adapter_does_not_modify_projection() -> None:
    source = projection()
    original = copy.deepcopy(source)

    adapt_wazuh_windows_security_auth_hit(source)

    assert source == original


def test_validation_error_does_not_dump_source_values() -> None:
    source = projection()
    windows_eventdata(source)["targetUserName"] = "sensitive-user"
    source["hit"]["_source"]["unexpected"] = "private-value"

    with pytest.raises(WazuhWindowsSecurityAuthAdaptError) as exc_info:
        adapt_wazuh_windows_security_auth_hit(source)

    message = str(exc_info.value)
    assert "hit._source.unexpected" in message
    assert "sensitive-user" not in message
    assert "private-value" not in message
