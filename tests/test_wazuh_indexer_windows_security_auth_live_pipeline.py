import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

MODULE_DIR = Path(__file__).resolve().parents[1] / "scripts" / "siem"
sys.path.insert(0, str(MODULE_DIR))

import wazuh_indexer_windows_security_auth_live_pipeline as live_pipeline  # noqa: E402
from wazuh_indexer_query_adapter import parse_wazuh_indexer_response  # noqa: E402
from wazuh_indexer_windows_security_auth_live_pipeline import (  # noqa: E402
    WindowsSecurityAuthLivePipelineError,
    build_live_wazuh_auth_projection,
    build_windows_security_auth_live_pipeline_summary,
    run_windows_security_auth_live_pipeline,
)
from wazuh_indexer_windows_security_auth_live_smoke import (  # noqa: E402
    WindowsSecurityAuthLiveSmokeError,
    build_windows_security_auth_live_smoke_request,
)

FIXTURE_PATH = Path(
    "tests/fixtures/windows/security_auth/wazuh_indexer/"
    "windows-security-4625-network-logon-failure-001.json"
)
SUMMARY_SCHEMA_PATH = Path(
    "schemas/wazuh_indexer_windows_security_auth_live_pipeline_summary.schema.json"
)
RUN_ID = "windows-security-auth-live-pipeline-20260115T020600Z"
HOST = "WIN-FIXTURE01"
ANCHOR = "2026-01-15T02:01:00Z"
EXECUTED_AT = "2026-01-15T02:06:00Z"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def request() -> dict:
    return build_windows_security_auth_live_smoke_request(
        run_id=RUN_ID,
        host=HOST,
        event_id="4625",
        anchor=ANCHOR,
    )


def backend_response(record_count: int = 1) -> dict:
    template = load_json(FIXTURE_PATH)["hit"]
    hits = []
    for index in range(record_count):
        hit = copy.deepcopy(template)
        second = index + 1
        hit["_id"] = f"private-backend-document-{index + 1}"
        hit["_source"]["id"] = f"private-wazuh-alert-{index + 1}"
        hit["_source"]["timestamp"] = f"2026-01-15T02:01:{second:02d}Z"
        hit["_source"]["data"]["win"]["system"]["systemTime"] = f"2026-01-15T02:01:{index:02d}.123Z"
        hit["_source"]["data"]["win"]["system"]["eventRecordID"] = str(42002 + index)
        system = hit["_source"]["data"]["win"]["system"]
        system["message"] = "private localized message"
        system["processID"] = "123"
        system["severityValue"] = "AUDIT_FAILURE"
        system["threadID"] = "456"
        event_data = hit["_source"]["data"]["win"]["eventdata"]
        event_data["keyLength"] = "0"
        event_data["processId"] = "0x123"
        del event_data["subjectUserName"]
        del event_data["subjectDomainName"]
        hit["sort"] = [hit["_source"]["timestamp"], hit["_source"]["id"]]
        hits.append(hit)
    return {
        "took": 3,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": record_count, "relation": "eq"},
            "max_score": None,
            "hits": hits,
        },
    }


def provider_neutral_response(record_count: int = 1) -> dict:
    return parse_wazuh_indexer_response(
        request(),
        backend_response(record_count),
        executed_at=EXECUTED_AT,
    )


def test_live_projection_reconstructs_only_reviewed_in_memory_shape() -> None:
    response = provider_neutral_response()
    record = response["records"][0]
    original_response = copy.deepcopy(response)

    projection = build_live_wazuh_auth_projection(
        response=response,
        record=record,
        record_number=1,
    )

    assert projection["fixture_id"] == "windows-security-4625-live-record-001"
    assert projection["retrieval"]["query_ref"] == response["request_id"]
    assert projection["hit"]["_index"] == record["physical_source"]
    assert projection["hit"]["_id"] == record["backend_record_id"]
    projected_windows = projection["hit"]["_source"]["data"]["win"]
    assert projected_windows["system"]["eventID"] == "4625"
    for unreviewed_field in ("message", "processID", "severityValue", "threadID"):
        assert unreviewed_field not in projected_windows["system"]
    for unreviewed_field in ("keyLength", "processId"):
        assert unreviewed_field not in projected_windows["eventdata"]
    assert response == original_response


def test_live_pipeline_summary_is_schema_valid_and_sanitized() -> None:
    summary = build_windows_security_auth_live_pipeline_summary(
        run_id=RUN_ID,
        host=HOST,
        response=provider_neutral_response(),
    )

    Draft202012Validator(
        load_json(SUMMARY_SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(summary)
    assert summary["status"] == "passed"
    assert summary["stage_counts"] == {
        "retrieved_records": 1,
        "adapted_records": 1,
        "normalized_events": 1,
        "represented_detection_events": 1,
        "deduped_detections": 1,
        "correlations": 0,
        "incidents": 1,
        "triage_results": 1,
        "investigation_results": 1,
    }
    assert all(summary["pipeline_alignment"].values())

    serialized = json.dumps(summary)
    for excluded in (
        HOST,
        "fixture-user",
        "198.51.100.24",
        "private-backend-document-1",
        "private-wazuh-alert-1",
        "42002",
    ):
        assert excluded not in serialized


def test_multiple_live_records_remain_covered_after_dedupe() -> None:
    summary = build_windows_security_auth_live_pipeline_summary(
        run_id=RUN_ID,
        host=HOST,
        response=provider_neutral_response(2),
    )

    assert summary["stage_counts"] == {
        "retrieved_records": 2,
        "adapted_records": 2,
        "normalized_events": 2,
        "represented_detection_events": 2,
        "deduped_detections": 1,
        "correlations": 0,
        "incidents": 1,
        "triage_results": 1,
        "investigation_results": 1,
    }


def test_live_pipeline_executes_one_bounded_4625_query() -> None:
    observed = []

    def execute_query(value):
        observed.append(copy.deepcopy(value))
        return provider_neutral_response()

    summary = run_windows_security_auth_live_pipeline(
        run_id=RUN_ID,
        host=HOST,
        anchor=ANCHOR,
        execute_query=execute_query,
    )

    assert observed == [request()]
    assert summary["status"] == "passed"


def test_required_target_evidence_still_fails_closed() -> None:
    response = provider_neutral_response()
    del response["records"][0]["fields"]["data.win.eventdata"]["targetUserName"]

    with pytest.raises(WindowsSecurityAuthLiveSmokeError) as exc_info:
        build_windows_security_auth_live_pipeline_summary(
            run_id=RUN_ID,
            host=HOST,
            response=response,
        )

    assert exc_info.value.category == "conversion_projection_failed"


def test_pipeline_alignment_rejects_lost_raw_event_reference() -> None:
    bundle = {
        "deduped_detections": [
            {
                "duplicate_count": 1,
                "raw_event_refs": [],
            }
        ],
        "correlations": [],
        "incidents": [{}],
        "triage_results": [{}],
        "investigation_results": [{}],
    }

    with pytest.raises(WindowsSecurityAuthLivePipelineError) as exc_info:
        live_pipeline._validate_pipeline_coverage(record_count=1, bundle=bundle)

    assert exc_info.value.category == "pipeline_alignment_failed"


def test_cli_failure_prints_only_stable_category(monkeypatch, capsys) -> None:
    def fail(**_kwargs):
        raise WindowsSecurityAuthLivePipelineError(
            "safe_category",
            "private failure details",
        )

    monkeypatch.setattr(live_pipeline, "run_windows_security_auth_live_pipeline", fail)

    exit_code = live_pipeline.main(
        [
            "--run-id",
            RUN_ID,
            "--host",
            HOST,
            "--anchor",
            ANCHOR,
        ]
    )

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "failed",
        "error_category": "safe_category",
    }


def test_invalid_projection_record_number_fails_without_values() -> None:
    response = provider_neutral_response()

    with pytest.raises(WindowsSecurityAuthLivePipelineError) as exc_info:
        build_live_wazuh_auth_projection(
            response=response,
            record=response["records"][0],
            record_number=0,
        )

    assert exc_info.value.category == "projection_build_failed"
    assert HOST not in str(exc_info.value)
