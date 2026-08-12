import copy
import json
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

MODULE_DIR = Path(__file__).resolve().parents[1] / "scripts" / "siem"
sys.path.insert(0, str(MODULE_DIR))

from wazuh_indexer_query_adapter import (  # noqa: E402
    SiemQueryAdapterError,
    build_wazuh_indexer_query_plan,
    load_source_registry,
    parse_wazuh_indexer_response,
)

REQUEST_PATH = Path("tests/fixtures/siem/wazuh_alerts_windows_security_auth/query_request.json")
REGISTRY_PATH = Path("config/siem_sources/wazuh_alerts_windows_security_auth.yaml")
WAZUH_FIXTURE_PATH = Path(
    "tests/fixtures/windows/security_auth/wazuh_indexer/"
    "windows-security-4625-network-logon-failure-001.json"
)
REQUEST_SCHEMA_PATH = Path("schemas/siem_query_request.schema.json")
REGISTRY_SCHEMA_PATH = Path("schemas/siem_source_registry_entry.schema.json")
RESPONSE_SCHEMA_PATH = Path("schemas/siem_query_response.schema.json")
EXECUTED_AT = "2026-01-15T02:06:00Z"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def request() -> dict:
    return load_json(REQUEST_PATH)


def backend_response() -> dict:
    hit = copy.deepcopy(load_json(WAZUH_FIXTURE_PATH)["hit"])
    hit["_source"]["id"] = "wazuh-auth-alert-001"
    hit["sort"] = [hit["_source"]["timestamp"], hit["_source"]["id"]]
    return {
        "took": 3,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "max_score": None,
            "hits": [hit],
        },
    }


def assert_schema_valid(value: dict, schema_path: Path) -> None:
    Draft202012Validator(
        load_json(schema_path),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(value)


def test_auth_request_and_registry_are_reviewed_and_schema_valid() -> None:
    assert_schema_valid(request(), REQUEST_SCHEMA_PATH)
    registry = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))
    assert_schema_valid(registry, REGISTRY_SCHEMA_PATH)
    assert load_source_registry(REGISTRY_PATH) == registry


def test_auth_query_plan_is_selected_by_logical_source_and_exactly_bounded() -> None:
    plan = build_wazuh_indexer_query_plan(request())
    filters = plan["body"]["query"]["bool"]["filter"]

    assert plan["method"] == "POST"
    assert plan["path"] == "/_search"
    assert plan["query_parameters"] == {"allow_partial_search_results": "false"}
    assert plan["pit_lifecycle"]["create_path"] == ("/wazuh-alerts-*/_search/point_in_time")
    assert plan["body"]["size"] == 2
    assert filters == [
        {
            "range": {
                "timestamp": {
                    "gte": "2026-01-15T02:00:00Z",
                    "lt": "2026-01-15T02:05:00Z",
                }
            }
        },
        {"term": {"data.win.system.providerName": "Microsoft-Windows-Security-Auditing"}},
        {"term": {"data.win.system.channel": "Security"}},
        {"term": {"agent.name": "WIN-FIXTURE01"}},
        {"term": {"data.win.system.eventID": "4625"}},
    ]


@pytest.mark.parametrize("event_id", ["4624", "4625"])
def test_both_reviewed_auth_event_ids_compile_as_required_request_filters(
    event_id: str,
) -> None:
    value = request()
    value["filters"][1]["value"] = event_id

    plan = build_wazuh_indexer_query_plan(value)

    assert {"term": {"data.win.system.eventID": event_id}} in (
        plan["body"]["query"]["bool"]["filter"]
    )


def test_auth_query_requires_both_host_and_event_id() -> None:
    for missing_field in ("agent.name", "data.win.system.eventID"):
        value = request()
        value["filters"] = [item for item in value["filters"] if item["field"] != missing_field]

        with pytest.raises(SiemQueryAdapterError) as exc_info:
            build_wazuh_indexer_query_plan(value)

        assert exc_info.value.category == "invalid_request"


def test_unreviewed_source_does_not_fall_back_to_sysmon_registry() -> None:
    value = request()
    value["source_names"] = ["wazuh-alerts-unreviewed-source"]

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        build_wazuh_indexer_query_plan(value)

    assert exc_info.value.category == "unknown_source"


def test_auth_backend_page_maps_to_provider_neutral_response() -> None:
    result = parse_wazuh_indexer_response(
        request(),
        backend_response(),
        executed_at=EXECUTED_AT,
    )

    assert_schema_valid(result, RESPONSE_SCHEMA_PATH)
    assert result["request_id"] == "query-windows-security-auth-4625-001"
    assert result["queried_sources"] == [
        {
            "logical_name": "wazuh-alerts-windows-security-auth",
            "physical_sources": ["wazuh-alerts-4.x-2026.01.15"],
        }
    ]
    assert result["returned_records"] == 1
    assert result["total_hits"] == 1
    assert result["truncated"] is False
    record = result["records"][0]
    assert record["logical_source"] == "wazuh-alerts-windows-security-auth"
    assert record["backend_record_id"] == "wazuh-auth-fixture-document-b"
    assert record["fields"]["data.win.system"]["eventID"] == "4625"
    assert record["fields"]["data.win.system"]["eventRecordID"] == "42002"


def test_auth_query_provenance_hashes_all_fixed_and_requested_values() -> None:
    result = parse_wazuh_indexer_response(
        request(),
        backend_response(),
        executed_at=EXECUTED_AT,
    )
    provenance = result["query_provenance"]
    serialized = json.dumps(provenance)

    assert len(provenance["filter_descriptors"]) == 4
    assert {item["origin"] for item in provenance["filter_descriptors"]} == {
        "registry",
        "request",
    }
    assert "WIN-FIXTURE01" not in serialized
    assert "4625" not in serialized
    assert "Microsoft-Windows-Security-Auditing" not in serialized


def test_explicit_wrong_registry_path_fails_closed() -> None:
    with pytest.raises(SiemQueryAdapterError) as exc_info:
        build_wazuh_indexer_query_plan(
            request(),
            registry_path="config/siem_sources/wazuh_alerts_sysmon_event1.yaml",
        )

    assert exc_info.value.category == "unknown_source"
