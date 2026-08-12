import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

MODULE_DIR = Path(__file__).resolve().parents[1] / "scripts" / "siem"
sys.path.insert(0, str(MODULE_DIR))

import wazuh_indexer_windows_security_auth_live_smoke as auth_smoke  # noqa: E402
from wazuh_indexer_query_adapter import parse_wazuh_indexer_response  # noqa: E402
from wazuh_indexer_windows_security_auth_live_smoke import (  # noqa: E402
    WindowsSecurityAuthLiveSmokeError,
    build_windows_security_auth_live_smoke_request,
    build_windows_security_auth_live_smoke_summary,
)

WAZUH_DIR = Path("tests/fixtures/windows/security_auth/wazuh_indexer")
SUMMARY_SCHEMA_PATH = Path(
    "schemas/wazuh_indexer_windows_security_auth_live_smoke_summary.schema.json"
)
RUN_ID = "windows-security-auth-20260115T020100Z"
HOST = "WIN-FIXTURE01"
ANCHOR = "2026-01-15T02:01:00Z"
EXECUTED_AT = "2026-01-15T02:06:00Z"
FIXTURES = {
    "4624": "windows-security-4624-network-logon-success-001.json",
    "4625": "windows-security-4625-network-logon-failure-001.json",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def request(event_id: str = "4625") -> dict:
    return build_windows_security_auth_live_smoke_request(
        run_id=RUN_ID,
        host=HOST,
        event_id=event_id,
        anchor=ANCHOR,
    )


def backend_response(event_id: str = "4625") -> dict:
    hit = copy.deepcopy(load_json(WAZUH_DIR / FIXTURES[event_id])["hit"])
    hit["_source"]["id"] = f"wazuh-auth-alert-{event_id}"
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


def provider_neutral_response(event_id: str = "4625") -> dict:
    return parse_wazuh_indexer_response(
        request(event_id),
        backend_response(event_id),
        executed_at=EXECUTED_AT,
    )


def test_auth_smoke_request_is_event_host_and_five_minute_window_bounded() -> None:
    value = request()

    assert value["request_id"] == f"live-smoke-{RUN_ID}-4625"
    assert value["source_names"] == ["wazuh-alerts-windows-security-auth"]
    assert value["time_range"] == {
        "start": "2026-01-15T01:58:30Z",
        "end": "2026-01-15T02:03:30Z",
    }
    assert value["filters"] == [
        {"field": "agent.name", "operator": "eq", "value": HOST},
        {"field": "data.win.system.eventID", "operator": "eq", "value": "4625"},
    ]
    assert value["limit"] == 100
    assert value["cursor"] is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"run_id": "invalid run id"},
        {"host": " "},
        {"event_id": "4634"},
        {"anchor": "not-a-time"},
        {"window_seconds": 0},
        {"window_seconds": 1801},
    ],
)
def test_invalid_auth_smoke_input_fails_before_transport(kwargs: dict) -> None:
    values = {
        "run_id": RUN_ID,
        "host": HOST,
        "event_id": "4625",
        "anchor": ANCHOR,
        "window_seconds": 300,
    }
    values.update(kwargs)

    with pytest.raises(WindowsSecurityAuthLiveSmokeError) as exc_info:
        build_windows_security_auth_live_smoke_request(**values)

    assert exc_info.value.category == "invalid_smoke_input"
    assert HOST not in str(exc_info.value)


@pytest.mark.parametrize("event_id", ["4624", "4625"])
def test_auth_smoke_summary_is_schema_valid_and_conversion_ready(event_id: str) -> None:
    summary = build_windows_security_auth_live_smoke_summary(
        run_id=RUN_ID,
        host=HOST,
        event_id=event_id,
        response=provider_neutral_response(event_id),
    )

    Draft202012Validator(
        load_json(SUMMARY_SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(summary)
    assert summary["status"] == "passed"
    assert summary["event_id"] == event_id
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
    assert summary["conversion_projection_alignment"] == {
        "system": True,
        "eventdata_common": True,
        "eventdata_event_specific": True,
    }

    serialized = json.dumps(summary)
    for excluded in (
        HOST,
        f"wazuh-auth-alert-{event_id}",
        "42001",
        "42002",
        "fixture-user",
        "198.51.100.24",
    ):
        assert excluded not in serialized


@pytest.mark.parametrize(
    "field",
    [
        "subjectUserName",
        "subjectDomainName",
        "workstationName",
        "ipAddress",
        "ipPort",
    ],
)
def test_omitted_wazuh_provider_sentinel_remains_conversion_ready(
    field: str,
) -> None:
    response = provider_neutral_response("4625")
    del response["records"][0]["fields"]["data.win.eventdata"][field]

    summary = build_windows_security_auth_live_smoke_summary(
        run_id=RUN_ID,
        host=HOST,
        event_id="4625",
        response=response,
    )

    assert summary["conversion_projection_alignment"] == {
        "system": True,
        "eventdata_common": True,
        "eventdata_event_specific": True,
    }


def test_auth_smoke_executes_one_read_only_query_and_returns_summary() -> None:
    observed = []

    def execute_query(query):
        observed.append(copy.deepcopy(query))
        return provider_neutral_response("4625")

    summary = auth_smoke.run_windows_security_auth_live_smoke(
        run_id=RUN_ID,
        host=HOST,
        event_id="4625",
        anchor=ANCHOR,
        execute_query=execute_query,
    )

    assert len(observed) == 1
    assert observed[0] == request("4625")
    assert summary["status"] == "passed"


def test_zero_results_are_inconclusive() -> None:
    value = provider_neutral_response()
    value.update(total_hits=0, returned_records=0, records=[])

    with pytest.raises(WindowsSecurityAuthLiveSmokeError) as exc_info:
        build_windows_security_auth_live_smoke_summary(
            run_id=RUN_ID,
            host=HOST,
            event_id="4625",
            response=value,
        )

    assert exc_info.value.category == "no_matching_record"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(truncated=True, refinement_required=True),
        lambda value: value.update(partial=True),
        lambda value: value.update(total_hits_relation="gte"),
        lambda value: value.update(total_hits=2),
        lambda value: value.update(next_cursor="opaque-cursor"),
    ],
)
def test_incomplete_result_requires_a_narrower_window(mutation) -> None:
    value = provider_neutral_response()
    mutation(value)

    with pytest.raises(WindowsSecurityAuthLiveSmokeError) as exc_info:
        build_windows_security_auth_live_smoke_summary(
            run_id=RUN_ID,
            host=HOST,
            event_id="4625",
            response=value,
        )

    assert exc_info.value.category == "incomplete_live_result"
    assert "opaque-cursor" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("target", "field"),
    [
        ("system", "providerGuid"),
        ("system", "eventRecordID"),
        ("eventdata", "targetUserName"),
        ("eventdata", "failureReason"),
    ],
)
def test_missing_conversion_field_fails_closed(target: str, field: str) -> None:
    response = provider_neutral_response()
    fields = response["records"][0]["fields"]
    container = fields[f"data.win.{target}"]
    del container[field]

    with pytest.raises(WindowsSecurityAuthLiveSmokeError) as exc_info:
        build_windows_security_auth_live_smoke_summary(
            run_id=RUN_ID,
            host=HOST,
            event_id="4625",
            response=response,
        )

    assert exc_info.value.category == "conversion_projection_failed"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent.name", "OTHER-HOST"),
        ("providerName", "Microsoft-Windows-Sysmon"),
        ("eventID", "4624"),
        ("channel", "System"),
    ],
)
def test_filter_mismatch_fails_closed(field: str, value: str) -> None:
    response = provider_neutral_response()
    fields = response["records"][0]["fields"]
    if field == "agent.name":
        fields[field] = value
    else:
        fields["data.win.system"][field] = value

    with pytest.raises(WindowsSecurityAuthLiveSmokeError) as exc_info:
        build_windows_security_auth_live_smoke_summary(
            run_id=RUN_ID,
            host=HOST,
            event_id="4625",
            response=response,
        )

    assert exc_info.value.category == "filter_alignment_failed"


def test_cli_failure_prints_only_stable_category(monkeypatch, capsys) -> None:
    def fail(**_kwargs):
        raise WindowsSecurityAuthLiveSmokeError("safe_category", "must not be printed")

    monkeypatch.setattr(auth_smoke, "run_windows_security_auth_live_smoke", fail)

    exit_code = auth_smoke.main(
        [
            "--run-id",
            RUN_ID,
            "--host",
            HOST,
            "--event-id",
            "4625",
            "--anchor",
            ANCHOR,
        ]
    )

    assert exit_code == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "failed",
        "error_category": "safe_category",
    }


def test_cli_passes_only_bounded_arguments(monkeypatch, capsys) -> None:
    observed = {}

    def pass_smoke(**kwargs):
        observed.update(kwargs)
        return {"status": "passed"}

    monkeypatch.setattr(auth_smoke, "run_windows_security_auth_live_smoke", pass_smoke)

    exit_code = auth_smoke.main(
        [
            "--run-id",
            RUN_ID,
            "--host",
            HOST,
            "--event-id",
            "4624",
            "--anchor",
            ANCHOR,
            "--window-seconds",
            "120",
        ]
    )

    assert exit_code == 0
    assert observed == {
        "run_id": RUN_ID,
        "host": HOST,
        "event_id": "4624",
        "anchor": ANCHOR,
        "window_seconds": 120,
    }
    assert json.loads(capsys.readouterr().out) == {"status": "passed"}
