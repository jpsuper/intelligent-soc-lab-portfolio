import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

MODULE_DIR = Path(__file__).resolve().parents[1] / "scripts" / "siem"
sys.path.insert(0, str(MODULE_DIR))

import wazuh_indexer_live_smoke as live_smoke  # noqa: E402
from wazuh_indexer_live_smoke import (  # noqa: E402
    LiveSmokeError,
    build_live_smoke_request,
    build_live_smoke_summary,
)
from wazuh_indexer_query_adapter import parse_wazuh_indexer_response  # noqa: E402

WAZUH_FIXTURE_PATH = Path(
    "tests/fixtures/windows/sysmon_event1/wazuh_indexer/sysmon-event1-ordinary-powershell-001.json"
)
SUMMARY_SCHEMA_PATH = Path("schemas/wazuh_indexer_live_smoke_summary.schema.json")
RUN_ID = "windows-sysmon1-20260115T010203Z"
HOST = "WIN-FIXTURE01"
ANCHOR = "2026-01-15T01:02:03Z"
EXECUTED_AT = "2026-01-15T01:20:00Z"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def request() -> dict:
    return build_live_smoke_request(run_id=RUN_ID, host=HOST, anchor=ANCHOR, limit=1)


def backend_response() -> dict:
    hit = copy.deepcopy(load_json(WAZUH_FIXTURE_PATH)["hit"])
    hit["_source"]["id"] = "wazuh-alert-001"
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


def provider_neutral_response() -> dict:
    response = parse_wazuh_indexer_response(
        request(),
        backend_response(),
        executed_at=EXECUTED_AT,
    )
    response["query_provenance"]["pagination_mode"] = "pit_search_after"
    return response


def second_provider_neutral_record() -> dict:
    record = copy.deepcopy(provider_neutral_response()["records"][0])
    record["backend_record_id"] = "wazuh-fixture-document-b"
    record["event_time"] = "2026-01-15T01:02:05.002Z"
    record["fields"]["id"] = "wazuh-alert-002"
    record["fields"]["data.win.system"]["eventRecordID"] = "41002"
    record["fields"]["data.win.system"]["systemTime"] = "2026-01-15T01:02:04.125Z"
    record["fields"]["data.win.eventdata"]["utcTime"] = "2026-01-15 01:02:04.125"
    return record


def paginated_responses() -> list[dict]:
    first = provider_neutral_response()
    first.update(
        total_hits=2,
        truncated=True,
        next_cursor="opaque-cursor",
        warnings=["additional_results_available"],
    )
    second = copy.deepcopy(first)
    second.update(
        records=[second_provider_neutral_record()],
        truncated=False,
        next_cursor=None,
        warnings=[],
    )
    return [first, second]


def test_live_smoke_request_is_host_and_run_anchored_to_exact_30_minutes() -> None:
    value = request()

    assert value["request_id"] == f"live-smoke-{RUN_ID}"
    assert value["source_names"] == ["wazuh-alerts-sysmon-event1"]
    assert value["time_range"] == {
        "start": "2026-01-15T00:47:03Z",
        "end": "2026-01-15T01:17:03Z",
    }
    assert value["filters"] == [{"field": "agent.name", "operator": "eq", "value": HOST}]
    assert value["limit"] == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"run_id": "invalid run id"},
        {"host": " "},
        {"anchor": "not-a-time"},
        {"limit": 0},
        {"limit": 101},
    ],
)
def test_invalid_live_smoke_input_fails_before_transport(kwargs: dict) -> None:
    values = {"run_id": RUN_ID, "host": HOST, "anchor": ANCHOR, "limit": 1}
    values.update(kwargs)

    with pytest.raises(LiveSmokeError) as exc_info:
        build_live_smoke_request(**values)

    assert exc_info.value.category == "invalid_smoke_input"
    assert HOST not in str(exc_info.value)


def test_live_smoke_summary_is_schema_valid_sanitized_and_time_aligned() -> None:
    summary = build_live_smoke_summary(
        run_id=RUN_ID,
        host=HOST,
        response=provider_neutral_response(),
    )

    Draft202012Validator(
        load_json(SUMMARY_SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(summary)
    assert summary["status"] == "passed"
    assert summary["results"] == {
        "total_hits": 1,
        "total_hits_relation": "eq",
        "returned_records": 1,
        "truncated": False,
        "refinement_required": False,
        "partial": False,
    }
    assert summary["identity_presence"] == {
        "backend_record_id_records": 1,
        "wazuh_alert_id_records": 1,
        "windows_event_record_id_records": 1,
    }
    assert summary["time_alignment"] == {
        "records_with_system_time": 1,
        "records_with_utc_time": 1,
        "alert_to_system_delta_ms": {
            "minimum": 877.0,
            "maximum": 877.0,
            "maximum_absolute": 877.0,
        },
        "system_to_utc_delta_ms": {
            "minimum": 0.0,
            "maximum": 0.0,
            "maximum_absolute": 0.0,
        },
    }
    serialized = json.dumps(summary)
    for excluded in (
        HOST,
        "wazuh-fixture-document-a",
        "wazuh-alert-001",
        "41001",
        "powershell.exe",
        "fixture-user",
    ):
        assert excluded not in serialized


def test_live_smoke_resumes_cursor_and_returns_sanitized_multi_page_summary() -> None:
    responses = paginated_responses()
    observed_cursors: list[object] = []

    def execute_query(query):
        observed_cursors.append(query["cursor"])
        return responses.pop(0)

    summary = live_smoke.run_live_smoke(
        run_id=RUN_ID,
        host=HOST,
        anchor=ANCHOR,
        limit=1,
        require_multiple_pages=True,
        execute_query=execute_query,
    )

    assert observed_cursors == [None, "opaque-cursor"]
    assert summary["results"]["returned_records"] == 2
    assert summary["pagination"] == {
        "mode": "pit_search_after",
        "requested_page_size": 1,
        "pages_returned": 2,
        "cursor_resumptions": 1,
        "page_record_counts": [1, 1],
        "stable_request_fingerprint": True,
        "stable_search_after_progression": True,
        "final_page_cleanup_confirmed": True,
    }
    serialized = json.dumps(summary)
    assert "opaque-cursor" not in serialized
    assert "wazuh-fixture-document-b" not in serialized
    assert "wazuh-alert-002" not in serialized


def test_required_multi_page_smoke_fails_when_query_fits_one_page() -> None:
    with pytest.raises(LiveSmokeError) as exc_info:
        live_smoke.run_live_smoke(
            run_id=RUN_ID,
            host=HOST,
            anchor=ANCHOR,
            limit=1,
            require_multiple_pages=True,
            execute_query=lambda _query: provider_neutral_response(),
        )

    assert exc_info.value.category == "pagination_not_exercised"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda response: response[1]["query_provenance"].update(
            request_fingerprint="sha256:" + "0" * 64
        ),
        lambda response: response[1].update(total_hits=3),
        lambda response: response[1].update(
            executed_time_range={
                "start": "2026-01-15T00:47:04Z",
                "end": "2026-01-15T01:17:04Z",
                "time_field": "timestamp",
            }
        ),
    ],
)
def test_multi_page_smoke_requires_stable_query_alignment(mutation) -> None:
    responses = paginated_responses()
    mutation(responses)

    with pytest.raises(LiveSmokeError) as exc_info:
        live_smoke.run_live_smoke(
            run_id=RUN_ID,
            host=HOST,
            anchor=ANCHOR,
            limit=1,
            execute_query=lambda _query: responses.pop(0),
        )

    assert exc_info.value.category == "pagination_alignment_failed"


def test_multi_page_smoke_rejects_repeated_cursor_without_disclosing_it() -> None:
    responses = paginated_responses()
    responses[1].update(truncated=True, next_cursor="opaque-cursor")

    with pytest.raises(LiveSmokeError) as exc_info:
        live_smoke.run_live_smoke(
            run_id=RUN_ID,
            host=HOST,
            anchor=ANCHOR,
            limit=1,
            execute_query=lambda _query: responses.pop(0),
        )

    assert exc_info.value.category == "pagination_alignment_failed"
    assert "opaque-cursor" not in str(exc_info.value)


def test_zero_results_are_inconclusive_not_passing_live_evidence() -> None:
    value = provider_neutral_response()
    value["total_hits"] = 0
    value["returned_records"] = 0
    value["records"] = []

    with pytest.raises(LiveSmokeError) as exc_info:
        build_live_smoke_summary(run_id=RUN_ID, host=HOST, response=value)

    assert exc_info.value.category == "no_matching_record"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(truncated=True, refinement_required=True),
        lambda value: value.update(partial=True),
        lambda value: value.update(total_hits_relation="gte"),
        lambda value: value.update(total_hits=2),
    ],
)
def test_incomplete_or_unbounded_results_do_not_pass_live_smoke(mutation) -> None:
    value = provider_neutral_response()
    mutation(value)

    with pytest.raises(LiveSmokeError) as exc_info:
        build_live_smoke_summary(run_id=RUN_ID, host=HOST, response=value)

    assert exc_info.value.category == "incomplete_live_result"


@pytest.mark.parametrize(
    ("field", "value", "category"),
    [
        ("agent.name", "OTHER-HOST", "filter_alignment_failed"),
        ("id", "", "identity_alignment_failed"),
        ("backend_record_id", "", "identity_alignment_failed"),
    ],
)
def test_filter_and_identity_mismatch_fail_closed(
    field: str,
    value: str,
    category: str,
) -> None:
    response = provider_neutral_response()
    record = response["records"][0]
    if field == "backend_record_id":
        record[field] = value
    else:
        record["fields"][field] = value

    with pytest.raises(LiveSmokeError) as exc_info:
        build_live_smoke_summary(run_id=RUN_ID, host=HOST, response=response)

    assert exc_info.value.category == category


@pytest.mark.parametrize(
    ("container", "field"),
    [
        ("system", "providerName"),
        ("system", "eventID"),
        ("system", "channel"),
        ("system", "systemTime"),
        ("eventdata", "utcTime"),
    ],
)
def test_fixed_filter_and_time_field_mismatch_fail_closed(container: str, field: str) -> None:
    response = provider_neutral_response()
    fields = response["records"][0]["fields"]
    target = fields["data.win.system" if container == "system" else "data.win.eventdata"]
    target[field] = "invalid"

    with pytest.raises(LiveSmokeError) as exc_info:
        build_live_smoke_summary(run_id=RUN_ID, host=HOST, response=response)

    expected = (
        "filter_alignment_failed"
        if field in {"providerName", "eventID", "channel"}
        else "time_alignment_failed"
    )
    assert exc_info.value.category == expected


def test_cli_failure_prints_only_stable_category(monkeypatch, capsys) -> None:
    def fail(**_kwargs):
        raise LiveSmokeError("safe_category", "must not be printed")

    monkeypatch.setattr(live_smoke, "run_live_smoke", fail)

    exit_code = live_smoke.main(["--run-id", RUN_ID, "--host", HOST, "--anchor", ANCHOR])

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "failed",
        "error_category": "safe_category",
    }


def test_cli_accepts_page_size_alias_and_requires_pagination(monkeypatch, capsys) -> None:
    observed = {}

    def pass_smoke(**kwargs):
        observed.update(kwargs)
        return {"status": "passed"}

    monkeypatch.setattr(live_smoke, "run_live_smoke", pass_smoke)

    exit_code = live_smoke.main(
        [
            "--run-id",
            RUN_ID,
            "--host",
            HOST,
            "--anchor",
            ANCHOR,
            "--page-size",
            "5",
            "--require-multiple-pages",
        ]
    )

    assert exit_code == 0
    assert observed == {
        "run_id": RUN_ID,
        "host": HOST,
        "anchor": ANCHOR,
        "limit": 5,
        "require_multiple_pages": True,
    }
    assert json.loads(capsys.readouterr().out) == {"status": "passed"}
