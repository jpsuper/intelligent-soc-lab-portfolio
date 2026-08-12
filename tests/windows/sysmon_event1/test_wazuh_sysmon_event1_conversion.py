import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

DOMAIN_MODULE_DIR = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "sysmon_event1"
sys.path.insert(0, str(DOMAIN_MODULE_DIR))

from adapt_wazuh_sysmon_event1_hit import (  # noqa: E402
    WazuhSysmonEvent1AdaptError,
    adapt_wazuh_sysmon_event1_hit,
)
from map_sysmon_event1_to_endpoint_event import (  # noqa: E402
    map_sysmon_event1_to_endpoint_event,
)
from parse_sysmon_event1_source import parse_sysmon_event1_source  # noqa: E402

WAZUH_DIR = Path("tests/fixtures/windows/sysmon_event1/wazuh_indexer")
SOURCE_DIR = Path("tests/fixtures/windows/sysmon_event1/source")
SCHEMA_PATH = Path("schemas/wazuh_sysmon_event1_hit_projection.schema.json")
FIXTURE_NAMES = (
    "sysmon-event1-ordinary-powershell-001.json",
    "sysmon-event1-encoded-flag-001.json",
    "sysmon-event1-ordinary-notepad-001.json",
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


def test_wazuh_projection_inventory_is_exactly_fixture_a_b_and_c() -> None:
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
    adapted = adapt_wazuh_sysmon_event1_hit(projection(name))

    assert adapted["source_event"] == load_json(SOURCE_DIR / name)


@pytest.mark.parametrize("name", FIXTURE_NAMES)
def test_wazuh_and_direct_paths_have_normalized_semantic_parity(name: str) -> None:
    source_path = SOURCE_DIR / name
    wazuh_path = WAZUH_DIR / name
    direct_source = load_json(source_path)
    adapted_source = adapt_wazuh_sysmon_event1_hit(projection(name))["source_event"]

    direct = map_sysmon_event1_to_endpoint_event(
        parse_sysmon_event1_source(direct_source),
        source_artifact=source_path.as_posix(),
    )
    via_wazuh = map_sysmon_event1_to_endpoint_event(
        parse_sysmon_event1_source(adapted_source),
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
    adapted = adapt_wazuh_sysmon_event1_hit(projection())
    provenance = adapted["retrieval_provenance"]

    assert set(provenance) == EXPECTED_PROVENANCE_KEYS
    assert provenance["source_product"] == "wazuh_indexer"
    assert provenance["source_plane"] == "wazuh_alerts"
    assert provenance["document_id"] == "wazuh-fixture-document-a"
    assert provenance["adapter_name"] == "wazuh_sysmon_event1_hit_adapter"
    assert provenance["adapter_version"] == "1.0"
    assert provenance["validation_outcome"] == "validated"
    assert adapted["source_event"].keys().isdisjoint(EXPECTED_PROVENANCE_KEYS)


def test_backend_document_id_cannot_substitute_for_event_record_id() -> None:
    value = projection()
    value["hit"]["_id"] = "999999"
    del windows_system(value)["eventRecordID"]

    with pytest.raises(WazuhSysmonEvent1AdaptError, match=r"system\.eventRecordID"):
        adapt_wazuh_sysmon_event1_hit(value)


def test_non_mapping_projection_fails_closed() -> None:
    with pytest.raises(WazuhSysmonEvent1AdaptError, match="at projection"):
        adapt_wazuh_sysmon_event1_hit([])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("providerName", "Microsoft-Windows-Security-Auditing"),
        ("eventID", "3"),
        ("channel", "Security"),
    ],
)
def test_wrong_source_routing_fails_in_existing_parser(field: str, value: str) -> None:
    source = projection()
    windows_system(source)[field] = value
    adapted = adapt_wazuh_sysmon_event1_hit(source)

    with pytest.raises(
        ValueError,
        match={
            "providerName": "system.provider_name",
            "eventID": "system.provider_event_id",
            "channel": "system.channel",
        }[field],
    ):
        parse_sysmon_event1_source(adapted["source_event"])


@pytest.mark.parametrize("value", ["", "-1", " 41001", "backend-doc-id"])
def test_invalid_event_record_id_fails_closed(value: str) -> None:
    source = projection()
    windows_system(source)["eventRecordID"] = value

    with pytest.raises(WazuhSysmonEvent1AdaptError, match=r"system\.eventRecordID"):
        adapt_wazuh_sysmon_event1_hit(source)


def test_alert_timestamp_must_be_inside_declared_query_window() -> None:
    source = projection()
    source["hit"]["_source"]["timestamp"] = "2026-01-15T02:00:00Z"

    with pytest.raises(WazuhSysmonEvent1AdaptError, match=r"_source\.timestamp"):
        adapt_wazuh_sysmon_event1_hit(source)


def test_query_window_must_be_forward() -> None:
    source = projection()
    source["retrieval"]["query_window"] = {
        "start": "2026-01-15T01:05:00Z",
        "end": "2026-01-15T01:00:00Z",
    }

    with pytest.raises(WazuhSysmonEvent1AdaptError, match=r"retrieval\.query_window"):
        adapt_wazuh_sysmon_event1_hit(source)


def test_unreviewed_wazuh_fields_fail_closed() -> None:
    source = projection()
    source["hit"]["_source"]["rule"] = {"level": 12}

    with pytest.raises(WazuhSysmonEvent1AdaptError, match=r"_source\.rule"):
        adapt_wazuh_sysmon_event1_hit(source)


def test_adapter_does_not_modify_projection() -> None:
    source = projection()
    original = copy.deepcopy(source)

    adapt_wazuh_sysmon_event1_hit(source)

    assert source == original


def test_validation_error_does_not_dump_source_values() -> None:
    source = projection()
    source["hit"]["_source"]["data"]["win"]["eventdata"]["commandLine"] = "sensitive-command-text"
    source["hit"]["_source"]["unexpected"] = "private-value"

    with pytest.raises(WazuhSysmonEvent1AdaptError) as exc_info:
        adapt_wazuh_sysmon_event1_hit(source)

    message = str(exc_info.value)
    assert "hit._source.unexpected" in message
    assert "sensitive-command-text" not in message
    assert "private-value" not in message
