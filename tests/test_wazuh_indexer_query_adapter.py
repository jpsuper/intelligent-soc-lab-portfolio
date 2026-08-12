import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet
from jsonschema import Draft202012Validator

MODULE_DIR = Path(__file__).resolve().parents[1] / "scripts" / "siem"
sys.path.insert(0, str(MODULE_DIR))

from wazuh_indexer_cursor import (  # noqa: E402
    CURSOR_KEY_ENV,
    decode_wazuh_indexer_cursor,
    encode_wazuh_indexer_cursor,
)
from wazuh_indexer_query_adapter import (  # noqa: E402
    SiemQueryAdapterError,
    build_wazuh_indexer_query_plan,
    load_source_registry,
    parse_wazuh_indexer_response,
)

REQUEST_PATH = Path("tests/fixtures/siem/wazuh_alerts_sysmon_event1/query_request.json")
WAZUH_FIXTURE_DIR = Path("tests/fixtures/windows/sysmon_event1/wazuh_indexer")
REQUEST_SCHEMA_PATH = Path("schemas/siem_query_request.schema.json")
RESPONSE_SCHEMA_PATH = Path("schemas/siem_query_response.schema.json")
REGISTRY_SCHEMA_PATH = Path("schemas/siem_source_registry_entry.schema.json")
REGISTRY_PATH = Path("config/siem_sources/wazuh_alerts_sysmon_event1.yaml")
FIXTURE_NAMES = (
    "sysmon-event1-ordinary-powershell-001.json",
    "sysmon-event1-encoded-flag-001.json",
    "sysmon-event1-ordinary-notepad-001.json",
)
EXECUTED_AT = "2026-01-15T01:06:00Z"
CURSOR_NOW = datetime(2026, 1, 15, 1, 6, tzinfo=timezone.utc)
CURSOR_EXPIRES_AT = "2026-01-15T01:06:30Z"
PIT_ID = "private-existing-pit-id"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def request() -> dict:
    return load_json(REQUEST_PATH)


def cursor_environment() -> dict[str, str]:
    return {CURSOR_KEY_ENV: Fernet.generate_key().decode("ascii")}


def request_with_cursor(
    values: dict[str, str],
    *,
    search_after: list[str | int | float] | None = None,
    returned_records: int = 2,
    expires_at: str = CURSOR_EXPIRES_AT,
) -> tuple[dict, str]:
    query = request()
    token = encode_wazuh_indexer_cursor(
        query,
        pit_id=PIT_ID,
        search_after=search_after or ["2026-01-15T01:02:04.125Z", "wazuh-alert-002"],
        returned_records=returned_records,
        expires_at=expires_at,
        environment=values,
        now=CURSOR_NOW,
    )
    query["cursor"] = token
    return query, token


def backend_response(
    names: tuple[str, ...] = FIXTURE_NAMES[:2],
    *,
    total: int | None = None,
    relation: str = "eq",
) -> dict:
    hits = []
    for index, name in enumerate(names, start=1):
        fixture_hit = copy.deepcopy(load_json(WAZUH_FIXTURE_DIR / name)["hit"])
        alert_id = f"wazuh-alert-{index:03d}"
        fixture_hit["_source"]["id"] = alert_id
        fixture_hit["sort"] = [fixture_hit["_source"]["timestamp"], alert_id]
        hits.append(fixture_hit)
    return {
        "took": 3,
        "timed_out": False,
        "_shards": {
            "total": 1,
            "successful": 1,
            "skipped": 0,
            "failed": 0,
        },
        "hits": {
            "total": {
                "value": len(hits) if total is None else total,
                "relation": relation,
            },
            "max_score": None,
            "hits": hits,
        },
    }


def assert_schema_valid(value: dict, schema_path: Path) -> None:
    Draft202012Validator(
        load_json(schema_path),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(value)


def test_request_fixture_and_registry_are_schema_valid() -> None:
    assert_schema_valid(request(), REQUEST_SCHEMA_PATH)
    registry = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))
    assert_schema_valid(registry, REGISTRY_SCHEMA_PATH)
    assert load_source_registry() == registry


def test_query_plan_is_exactly_bounded_and_registry_controlled() -> None:
    plan = build_wazuh_indexer_query_plan(request())

    assert plan == {
        "method": "POST",
        "path": "/_search",
        "query_parameters": {
            "allow_partial_search_results": "false",
        },
        "connection_name": "wazuh_indexer_readonly",
        "transport_policy": {
            "read_only": True,
            "tls_verify": True,
            "connect_timeout_seconds": 3,
            "read_timeout_seconds": 10,
            "max_response_bytes": 5242880,
            "pit_keep_alive_seconds": 30,
        },
        "pit_lifecycle": {
            "create_method": "POST",
            "create_path": "/wazuh-alerts-*/_search/point_in_time",
            "create_query_parameters": {
                "keep_alive": "30s",
                "allow_partial_pit_creation": "false",
            },
            "keep_alive": "30s",
            "delete_method": "DELETE",
            "delete_path": "/_search/point_in_time",
        },
        "body": {
            "size": 2,
            "track_total_hits": True,
            "timeout": "10s",
            "_source": [
                "timestamp",
                "id",
                "agent.id",
                "agent.name",
                "manager.name",
                "data.win.system",
                "data.win.eventdata",
            ],
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "timestamp": {
                                    "gte": "2026-01-15T01:00:00Z",
                                    "lt": "2026-01-15T01:05:00Z",
                                }
                            }
                        },
                        {"term": {"data.win.system.providerName": ("Microsoft-Windows-Sysmon")}},
                        {"term": {"data.win.system.eventID": "1"}},
                        {
                            "term": {
                                "data.win.system.channel": ("Microsoft-Windows-Sysmon/Operational")
                            }
                        },
                        {"term": {"agent.name": "WIN-FIXTURE01"}},
                    ]
                }
            },
            "sort": [
                {"timestamp": {"order": "asc"}},
                {"id": {"order": "asc"}},
            ],
        },
    }


def test_query_plan_contains_no_credential_or_authorization_value() -> None:
    serialized = json.dumps(build_wazuh_indexer_query_plan(request())).lower()

    for forbidden in ("password", "authorization", "bearer", "api_key", "token"):
        assert forbidden not in serialized
    assert "wazuh_indexer_readonly" in serialized


def test_required_host_filter_cannot_be_omitted() -> None:
    value = request()
    value["filters"] = []

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        build_wazuh_indexer_query_plan(value)

    assert exc_info.value.category == "invalid_request"
    assert "host filter" in str(exc_info.value)


@pytest.mark.parametrize(
    ("mutation", "category"),
    [
        (lambda value: value.update(source_names=["wazuh-alerts"]), "unknown_source"),
        (lambda value: value.update(backend="elastic"), "unsupported_backend"),
        (lambda value: value.update(limit=101), "result_limit_exceeded"),
        (
            lambda value: value.update(aggregation_fields=["data.win.system.eventID"]),
            "invalid_request",
        ),
    ],
)
def test_unsupported_query_scope_fails_closed(mutation, category: str) -> None:
    value = request()
    mutation(value)

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        build_wazuh_indexer_query_plan(value)

    assert exc_info.value.category == category


def test_valid_cursor_compiles_stable_search_after_and_redacted_resume_state() -> None:
    values = cursor_environment()
    query, token = request_with_cursor(values)
    original = copy.deepcopy(query)

    plan = build_wazuh_indexer_query_plan(
        query,
        cursor_environment=values,
        cursor_now=CURSOR_NOW,
    )

    assert plan["body"]["search_after"] == [
        "2026-01-15T01:02:04.125Z",
        "wazuh-alert-002",
    ]
    cursor_state = plan["cursor_state"]
    assert cursor_state.pit_id == PIT_ID
    assert cursor_state.returned_records == 2
    assert repr(cursor_state).startswith("WazuhIndexerCursor(<redacted>")
    assert PIT_ID not in repr(plan)
    assert token not in repr(plan)
    assert query == original


def test_cursor_resume_page_size_is_bounded_by_remaining_volume() -> None:
    values = cursor_environment()
    query, _ = request_with_cursor(values, returned_records=99)

    plan = build_wazuh_indexer_query_plan(
        query,
        cursor_environment=values,
        cursor_now=CURSOR_NOW,
    )

    assert plan["body"]["size"] == 1


@pytest.mark.parametrize(
    ("search_after", "returned_records"),
    [
        (["2026-01-15T01:02:04.125Z"], 2),
        (["not-a-timestamp", "wazuh-alert-002"], 2),
        (["2026-01-15T01:02:04.125Z", 2], 2),
        (["2026-01-15T01:02:04.125Z", "wazuh-alert-002"], 100),
    ],
)
def test_cursor_resume_position_and_volume_fail_closed(
    search_after: list[str | int | float],
    returned_records: int,
) -> None:
    values = cursor_environment()
    query, token = request_with_cursor(
        values,
        search_after=search_after,
        returned_records=returned_records,
    )

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        build_wazuh_indexer_query_plan(
            query,
            cursor_environment=values,
            cursor_now=CURSOR_NOW,
        )

    assert exc_info.value.category == "cursor_invalid"
    assert token not in str(exc_info.value)
    assert PIT_ID not in str(exc_info.value)


def test_cursor_key_and_token_fail_closed_without_disclosure(monkeypatch) -> None:
    monkeypatch.delenv(CURSOR_KEY_ENV, raising=False)
    values = cursor_environment()
    query, token = request_with_cursor(values)

    with pytest.raises(SiemQueryAdapterError) as config_error:
        build_wazuh_indexer_query_plan(query, cursor_now=CURSOR_NOW)
    assert config_error.value.category == "cursor_config_error"

    query["cursor"] = "not-a-protected-cursor"
    with pytest.raises(SiemQueryAdapterError) as token_error:
        build_wazuh_indexer_query_plan(
            query,
            cursor_environment=values,
            cursor_now=CURSOR_NOW,
        )
    assert token_error.value.category == "cursor_invalid"
    assert token not in str(token_error.value)
    assert PIT_ID not in str(token_error.value)


def test_cursor_expiry_cannot_exceed_registered_pit_keep_alive() -> None:
    values = cursor_environment()
    query, token = request_with_cursor(
        values,
        expires_at="2026-01-15T01:06:31Z",
    )

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        build_wazuh_indexer_query_plan(
            query,
            cursor_environment=values,
            cursor_now=CURSOR_NOW,
        )

    assert exc_info.value.category == "cursor_invalid"
    assert token not in str(exc_info.value)
    assert PIT_ID not in str(exc_info.value)


def test_expired_or_request_mismatched_cursor_fails_closed() -> None:
    values = cursor_environment()
    expired_query, _ = request_with_cursor(values)
    with pytest.raises(SiemQueryAdapterError) as expired_error:
        build_wazuh_indexer_query_plan(
            expired_query,
            cursor_environment=values,
            cursor_now=datetime(2026, 1, 15, 1, 6, 30, tzinfo=timezone.utc),
        )
    assert expired_error.value.category == "cursor_invalid"

    mismatched_query, _ = request_with_cursor(values)
    mismatched_query["limit"] = 1
    with pytest.raises(SiemQueryAdapterError) as mismatch_error:
        build_wazuh_indexer_query_plan(
            mismatched_query,
            cursor_environment=values,
            cursor_now=CURSOR_NOW,
        )
    assert mismatch_error.value.category == "cursor_invalid"


def test_query_window_is_start_inclusive_end_exclusive_and_capped_at_30_minutes() -> None:
    value = request()
    value["time_range"] = {
        "start": "2026-01-15T01:00:00Z",
        "end": "2026-01-15T01:30:01Z",
    }

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        build_wazuh_indexer_query_plan(value)

    assert exc_info.value.category == "time_range_too_large"


def test_unknown_projection_and_non_eq_filter_fail_closed_without_values() -> None:
    projection_request = request()
    projection_request["projection_fields"] = ["rule.description"]
    with pytest.raises(SiemQueryAdapterError) as projection_error:
        build_wazuh_indexer_query_plan(projection_request)
    assert projection_error.value.category == "unknown_field"
    assert "rule.description" not in str(projection_error.value)

    filter_request = request()
    filter_request["filters"][0]["operator"] = "contains"
    with pytest.raises(SiemQueryAdapterError) as filter_error:
        build_wazuh_indexer_query_plan(filter_request)
    assert filter_error.value.category == "unsupported_filter"
    assert "WIN-FIXTURE01" not in str(filter_error.value)


def test_incomplete_projection_and_empty_host_fail_before_backend_execution() -> None:
    projection_request = request()
    projection_request["projection_fields"] = ["timestamp", "id"]
    with pytest.raises(SiemQueryAdapterError) as projection_error:
        build_wazuh_indexer_query_plan(projection_request)
    assert projection_error.value.category == "invalid_request"

    host_request = request()
    host_request["filters"][0]["value"] = " "
    with pytest.raises(SiemQueryAdapterError) as host_error:
        build_wazuh_indexer_query_plan(host_request)
    assert host_error.value.category == "field_type_mismatch"


def test_complete_backend_page_maps_to_provider_neutral_response() -> None:
    result = parse_wazuh_indexer_response(
        request(),
        backend_response(),
        executed_at=EXECUTED_AT,
    )

    assert_schema_valid(result, RESPONSE_SCHEMA_PATH)
    assert result["contract_version"] == "1.0"
    assert result["request_id"] == "query-windows-sysmon-event1-001"
    assert result["backend"] == "wazuh_indexer"
    assert result["total_hits"] == 2
    assert result["total_hits_relation"] == "eq"
    assert result["returned_records"] == 2
    assert result["truncated"] is False
    assert result["refinement_required"] is False
    assert result["partial"] is False
    assert result["next_cursor"] is None
    assert result["warnings"] == []
    assert result["source_statuses"] == [
        {
            "logical_name": "wazuh-alerts-sysmon-event1",
            "status": "complete",
            "error_category": None,
        }
    ]


def test_opensearch_epoch_millisecond_timestamp_sort_is_normalized() -> None:
    backend = backend_response(names=FIXTURE_NAMES[:1])
    hit = backend["hits"]["hits"][0]
    timestamp = datetime.fromisoformat(hit["_source"]["timestamp"].replace("Z", "+00:00"))
    hit["sort"][0] = int(timestamp.timestamp() * 1000)

    result = parse_wazuh_indexer_response(
        request(),
        backend,
        executed_at=EXECUTED_AT,
    )

    assert result["returned_records"] == 1


def test_wazuh_offset_without_colon_event_time_is_normalized_to_rfc3339() -> None:
    backend = backend_response(names=FIXTURE_NAMES[:1])
    hit = backend["hits"]["hits"][0]
    hit["_source"]["timestamp"] = "2026-01-15T10:02:04.125+0900"
    hit["sort"][0] = hit["_source"]["timestamp"]

    result = parse_wazuh_indexer_response(
        request(),
        backend,
        executed_at=EXECUTED_AT,
    )

    assert result["records"][0]["event_time"] == "2026-01-15T01:02:04.125000Z"
    assert result["records"][0]["fields"]["timestamp"] == ("2026-01-15T10:02:04.125+0900")


def test_response_records_keep_backend_and_windows_identity_distinct() -> None:
    result = parse_wazuh_indexer_response(
        request(),
        backend_response(),
        executed_at=EXECUTED_AT,
    )
    first = result["records"][0]

    assert first["backend_record_id"] == "wazuh-fixture-document-a"
    assert first["fields"]["id"] == "wazuh-alert-001"
    assert first["fields"]["data.win.system"]["eventRecordID"] == "41001"
    assert (
        len(
            {
                first["backend_record_id"],
                first["fields"]["id"],
                first["fields"]["data.win.system"]["eventRecordID"],
            }
        )
        == 3
    )


def test_projection_drops_unreviewed_backend_fields_before_response() -> None:
    backend = backend_response()
    backend["hits"]["hits"][0]["_source"]["rule"] = {
        "level": 12,
        "description": "native conclusion",
    }
    backend["hits"]["hits"][0]["_source"]["full_log"] = "untrusted raw payload"

    result = parse_wazuh_indexer_response(
        request(),
        backend,
        executed_at=EXECUTED_AT,
    )
    serialized = json.dumps(result)

    assert "native conclusion" not in serialized
    assert "untrusted raw payload" not in serialized
    assert result["records"][0]["raw_payload_available"] is False
    assert result["records"][0]["redacted_fields"] == []


def test_query_provenance_hashes_filter_values_and_records_executed_scope() -> None:
    result = parse_wazuh_indexer_response(
        request(),
        backend_response(),
        executed_at=EXECUTED_AT,
    )
    provenance = result["query_provenance"]
    serialized = json.dumps(provenance)

    assert provenance["executed_at"] == EXECUTED_AT
    assert provenance["adapter_name"] == "wazuh-indexer-query-adapter"
    assert provenance["adapter_version"] == "0.2.0"
    assert provenance["connection_name"] == "wazuh_indexer_readonly"
    assert provenance["pagination_mode"] == "refine_required"
    assert provenance["limit"] == 2
    assert len(provenance["filter_descriptors"]) == 4
    assert all(
        descriptor["value_sha256"].startswith("sha256:")
        for descriptor in provenance["filter_descriptors"]
    )
    assert "WIN-FIXTURE01" not in serialized
    assert "Microsoft-Windows-Sysmon" not in serialized


@pytest.mark.parametrize(("relation", "total"), [("eq", 3), ("gte", 2)])
def test_unpageable_volume_requires_refinement_without_cursor(
    relation: str,
    total: int,
) -> None:
    result = parse_wazuh_indexer_response(
        request(),
        backend_response(total=total, relation=relation),
        executed_at=EXECUTED_AT,
    )

    assert result["truncated"] is True
    assert result["refinement_required"] is True
    assert result["next_cursor"] is None
    assert result["warnings"] == ["result_volume_requires_refinement"]


def test_pit_page_returns_request_bound_cursor_without_requiring_refinement() -> None:
    values = cursor_environment()
    query = request()

    result = parse_wazuh_indexer_response(
        query,
        backend_response(total=3),
        executed_at=EXECUTED_AT,
        pit_id=PIT_ID,
        cursor_environment=values,
        cursor_now=CURSOR_NOW,
    )

    assert result["truncated"] is True
    assert result["refinement_required"] is False
    assert result["warnings"] == ["additional_results_available"]
    assert result["query_provenance"]["pagination_mode"] == "pit_search_after"
    token = result["next_cursor"]
    assert isinstance(token, str)
    decoded = decode_wazuh_indexer_cursor(
        token,
        query,
        environment=values,
        now=CURSOR_NOW,
    )
    assert decoded.pit_id == PIT_ID
    assert decoded.search_after == tuple(backend_response()["hits"]["hits"][-1]["sort"])
    assert decoded.returned_records == 2
    assert decoded.expires_at == CURSOR_EXPIRES_AT


def test_resumed_final_page_uses_cumulative_count_and_stable_fingerprint() -> None:
    values = cursor_environment()
    query, _ = request_with_cursor(values)
    backend = backend_response(names=FIXTURE_NAMES[2:3], total=3)
    hit = backend["hits"]["hits"][0]
    hit["_source"]["timestamp"] = "2026-01-15T01:03:04.125Z"
    hit["_source"]["id"] = "wazuh-alert-003"
    hit["sort"] = [hit["_source"]["timestamp"], hit["_source"]["id"]]

    result = parse_wazuh_indexer_response(
        query,
        backend,
        executed_at=EXECUTED_AT,
        pit_id=PIT_ID,
        cursor_environment=values,
        cursor_now=CURSOR_NOW,
    )
    initial = parse_wazuh_indexer_response(
        request(),
        backend_response(),
        executed_at=EXECUTED_AT,
    )

    assert result["returned_records"] == 1
    assert result["truncated"] is False
    assert result["refinement_required"] is False
    assert result["next_cursor"] is None
    assert result["warnings"] == []
    assert (
        result["query_provenance"]["request_fingerprint"]
        == initial["query_provenance"]["request_fingerprint"]
    )


def test_cursor_page_at_volume_cap_requires_refinement_without_new_cursor() -> None:
    values = cursor_environment()
    query, _ = request_with_cursor(values, returned_records=99)
    backend = backend_response(names=FIXTURE_NAMES[2:3], total=101)
    hit = backend["hits"]["hits"][0]
    hit["_source"]["timestamp"] = "2026-01-15T01:03:04.125Z"
    hit["_source"]["id"] = "wazuh-alert-100"
    hit["sort"] = [hit["_source"]["timestamp"], hit["_source"]["id"]]

    result = parse_wazuh_indexer_response(
        query,
        backend,
        executed_at=EXECUTED_AT,
        pit_id=PIT_ID,
        cursor_environment=values,
        cursor_now=CURSOR_NOW,
    )

    assert result["returned_records"] == 1
    assert result["truncated"] is True
    assert result["refinement_required"] is True
    assert result["next_cursor"] is None
    assert result["warnings"] == ["result_volume_requires_refinement"]


def test_lower_bound_total_requires_refinement_and_no_cursor() -> None:
    values = cursor_environment()

    result = parse_wazuh_indexer_response(
        request(),
        backend_response(total=2, relation="gte"),
        executed_at=EXECUTED_AT,
        pit_id=PIT_ID,
        cursor_environment=values,
        cursor_now=CURSOR_NOW,
    )

    assert result["truncated"] is True
    assert result["refinement_required"] is True
    assert result["next_cursor"] is None
    assert result["warnings"] == ["result_volume_requires_refinement"]


@pytest.mark.parametrize("failure", ["duplicate_resume_position", "empty_exact_page"])
def test_resumed_page_must_make_strict_progress(failure: str) -> None:
    values = cursor_environment()
    query, _ = request_with_cursor(values)
    if failure == "duplicate_resume_position":
        backend = backend_response(names=FIXTURE_NAMES[:1], total=3)
        hit = backend["hits"]["hits"][0]
        hit["_source"]["timestamp"] = "2026-01-15T01:02:04.125Z"
        hit["_source"]["id"] = "wazuh-alert-002"
        hit["sort"] = [hit["_source"]["timestamp"], hit["_source"]["id"]]
    else:
        backend = backend_response(names=(), total=3)

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        parse_wazuh_indexer_response(
            query,
            backend,
            executed_at=EXECUTED_AT,
            pit_id=PIT_ID,
            cursor_environment=values,
            cursor_now=CURSOR_NOW,
        )

    assert exc_info.value.category == "response_parse_error"


@pytest.mark.parametrize("partial_kind", ["timeout", "shard_failure"])
def test_partial_backend_page_is_never_returned_as_complete(partial_kind: str) -> None:
    backend = backend_response()
    if partial_kind == "timeout":
        backend["timed_out"] = True
    else:
        backend["_shards"]["failed"] = 1

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        parse_wazuh_indexer_response(
            request(),
            backend,
            executed_at=EXECUTED_AT,
        )

    assert exc_info.value.category == "partial_result"
    assert "incomplete" in str(exc_info.value)


@pytest.mark.parametrize(
    "broken_field",
    ["timestamp", "malformed_timestamp", "sort", "_id", "_index"],
)
def test_invalid_hit_identity_or_ordering_fails_closed(broken_field: str) -> None:
    backend = backend_response()
    hit = backend["hits"]["hits"][0]
    if broken_field == "timestamp":
        del hit["_source"]["timestamp"]
    elif broken_field == "malformed_timestamp":
        hit["_source"]["timestamp"] = "not-a-timestamp"
    elif broken_field == "sort":
        hit["sort"] = ["wrong", "order"]
    elif broken_field == "_id":
        hit["_id"] = ""
    else:
        hit["_index"] = "other-index"

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        parse_wazuh_indexer_response(
            request(),
            backend,
            executed_at=EXECUTED_AT,
        )

    assert exc_info.value.category == "response_parse_error"


def test_adapter_is_deterministic_and_does_not_modify_inputs() -> None:
    query = request()
    backend = backend_response()
    query_original = copy.deepcopy(query)
    backend_original = copy.deepcopy(backend)

    first = parse_wazuh_indexer_response(query, backend, executed_at=EXECUTED_AT)
    second = parse_wazuh_indexer_response(query, backend, executed_at=EXECUTED_AT)

    assert first == second
    assert query == query_original
    assert backend == backend_original


def test_adapter_errors_do_not_echo_filter_or_source_values() -> None:
    query = request()
    query["filters"][0]["field"] = "private-field"
    query["filters"][0]["value"] = "private-host-value"

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        build_wazuh_indexer_query_plan(query)

    message = str(exc_info.value)
    assert "private-field" not in message
    assert "private-host-value" not in message
