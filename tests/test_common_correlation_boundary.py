import json
from copy import deepcopy
from pathlib import Path

import pytest

from detection.compiler.correlation import (
    correlate_auth_then_authorized_keys,
    correlate_key_login_then_process_exec,
)
from detection.compiler.loader import load_rule
from detection.compiler.pipeline import (
    CommonPipelineValidationError,
    run_common_correlation_stage,
    run_common_detection_pipeline,
)

LINUX_FIXTURE_PATH = Path(
    "tests/fixtures/scenario_009_suspicious_archive_staging/endpoint_events.json"
)
LINUX_RULE_PATH = Path("detection/dsl/suspicious_archive_staging.yaml")
WINDOWS_NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
WINDOWS_RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def endpoint_envelope(event: dict) -> dict:
    return {"schema_version": "endpoint_events.v1", "events": [event]}


def canonical_detection(
    detection_id: str,
    artifact: str,
    timestamp: str | None,
    *,
    host: str = "fixture-host",
    user: str | None = "fixture-user",
    src_ip: str | None = "192.0.2.10",
    rule_id: str | None = None,
) -> dict:
    return {
        "id": detection_id,
        "rule_id": rule_id or f"test.{artifact}",
        "title": f"Test {artifact}",
        "log_source": {"product": "linux"},
        "event_type": artifact,
        "artifact": artifact,
        "severity": "low",
        "host": host,
        "user": user,
        "src_ip": src_ip,
        "path": "/home/fixture-user/.ssh/authorized_keys"
        if artifact == "authorized_keys_modification"
        else None,
        "command_line": "/bin/id" if artifact == "process_exec" else None,
        "behavior_features": {f"{artifact}_observed": True},
        "evidence_refs": [f"evidence.json#{detection_id}"],
        "raw_event_refs": [f"input[{detection_id}]"],
        "time_window_start": timestamp,
        "time_window_end": timestamp,
    }


def test_existing_auth_then_authorized_keys_policy_shape() -> None:
    detections = [
        canonical_detection("det-failed", "ssh_failed_login", "2026-08-01T00:00:00Z"),
        canonical_detection("det-success", "ssh_success_login", "2026-08-01T00:00:10Z"),
        canonical_detection(
            "det-authorized-keys",
            "authorized_keys_modification",
            "2026-08-01T00:00:20Z",
            src_ip=None,
        ),
    ]

    result = correlate_auth_then_authorized_keys(detections)

    assert len(result) == 1
    assert result[0]["correlation_type"] == "auth_then_authorized_keys"
    assert result[0]["title"] == "SSH authentication followed by authorized_keys persistence"
    assert result[0]["severity"] == "high"
    assert result[0]["artifacts"] == [
        "ssh_failed_login",
        "ssh_success_login",
        "authorized_keys_modification",
    ]
    assert result[0]["behavior_features"] == {
        "ssh_auth_failure_observed": True,
        "ssh_success_observed": True,
        "password_authentication": True,
        "ssh_authorized_keys_targeted": True,
        "persistence_related_path": True,
    }


def test_existing_key_login_then_process_execution_policy_shape() -> None:
    detections = [
        canonical_detection("det-key", "ssh_key_login", "2026-08-01T00:00:00Z"),
        canonical_detection("det-exec", "process_exec", "2026-08-01T00:00:10Z"),
    ]

    result = correlate_key_login_then_process_exec(detections)

    assert len(result) == 1
    assert result[0]["correlation_type"] == "key_login_then_process_exec"
    assert result[0]["title"] == "SSH key login followed by command execution"
    assert result[0]["severity"] == "high"
    assert result[0]["artifacts"] == ["ssh_key_login", "process_exec"]
    assert result[0]["behavior_features"] == {
        "ssh_success_observed": True,
        "publickey_authentication": True,
        "post_login_execution_observed": True,
    }


def auth_sequence(
    *,
    failed_timestamp: str | None = "2026-08-01T00:00:00Z",
    success_timestamp: str | None = "2026-08-01T00:00:10Z",
    authorized_keys_timestamp: str | None = "2026-08-01T00:00:20Z",
) -> list[dict]:
    return [
        canonical_detection("det-failed", "ssh_failed_login", failed_timestamp),
        canonical_detection("det-success", "ssh_success_login", success_timestamp),
        canonical_detection(
            "det-authorized-keys",
            "authorized_keys_modification",
            authorized_keys_timestamp,
            src_ip=None,
        ),
    ]


def key_exec_sequence(
    *,
    key_timestamp: str | None = "2026-08-01T00:00:00Z",
    exec_timestamp: str | None = "2026-08-01T00:00:10Z",
) -> list[dict]:
    return [
        canonical_detection("det-key", "ssh_key_login", key_timestamp),
        canonical_detection("det-exec", "process_exec", exec_timestamp),
    ]


def test_empty_input_returns_empty_without_calling_correlation_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_policy(*args: object, **kwargs: object) -> list[dict]:
        raise AssertionError("correlation helpers must not be called for empty input")

    monkeypatch.setattr(
        "detection.compiler.pipeline.correlate_auth_then_authorized_keys",
        unexpected_policy,
    )
    monkeypatch.setattr(
        "detection.compiler.pipeline.correlate_key_login_then_process_exec",
        unexpected_policy,
    )

    assert run_common_correlation_stage([]) == ([], [])


@pytest.mark.parametrize(
    ("detections", "message"),
    [
        ({}, "canonical detection output must be a list"),
        ([{"id": "incomplete"}], "missing canonical fields"),
        (
            [
                canonical_detection("det-duplicate", "process_exec", "2026-08-01T00:00:00Z"),
                canonical_detection("det-duplicate", "process_exec", "2026-08-01T00:00:01Z"),
            ],
            "duplicate detection id: det-duplicate",
        ),
        (
            [canonical_detection("det-invalid", "process_exec", "not-a-timestamp")],
            "time_window_start must be a valid ISO-8601 timestamp or null",
        ),
    ],
)
def test_invalid_canonical_input_fails_closed(detections: object, message: str) -> None:
    with pytest.raises(CommonPipelineValidationError, match=message):
        run_common_correlation_stage(detections)


def test_dedupe_runs_before_correlation_and_preserves_merged_support() -> None:
    duplicate_failed = canonical_detection(
        "det-failed-b",
        "ssh_failed_login",
        "2026-08-01T00:00:05Z",
    )
    duplicate_failed["evidence_refs"] = ["evidence.json#failed-b", "evidence.json#shared"]
    duplicate_failed["raw_event_refs"] = ["raw-failed-b", "raw-shared"]
    detections = auth_sequence()
    detections[0]["id"] = "det-failed-a"
    detections[0]["evidence_refs"] = ["evidence.json#failed-a", "evidence.json#shared"]
    detections[0]["raw_event_refs"] = ["raw-failed-a", "raw-shared"]
    detections.insert(1, duplicate_failed)

    deduped, correlations = run_common_correlation_stage(detections)

    assert len(deduped) == 3
    merged_failed = next(item for item in deduped if item["artifact"] == "ssh_failed_login")
    assert merged_failed["id"] == "det-failed-a"
    assert merged_failed["duplicate_count"] == 2
    assert merged_failed["evidence_refs"] == [
        "evidence.json#failed-a",
        "evidence.json#failed-b",
        "evidence.json#shared",
    ]
    assert len(correlations) == 1
    assert correlations[0]["supporting_detections"]["ssh_failed_login"] == [merged_failed]
    assert set(correlations[0]["evidence_refs"]) >= set(merged_failed["evidence_refs"])


def test_auth_policy_inclusive_window_boundaries_correlate() -> None:
    detections = auth_sequence(
        failed_timestamp="2026-08-01T00:00:00Z",
        success_timestamp="2026-08-01T00:05:00Z",
        authorized_keys_timestamp="2026-08-01T00:20:00Z",
    )

    _, correlations = run_common_correlation_stage(detections)

    assert [item["correlation_type"] for item in correlations] == ["auth_then_authorized_keys"]


@pytest.mark.parametrize(
    "mutation",
    [
        "auth_window_outside",
        "failed_host",
        "failed_user",
        "failed_src_ip",
        "authorized_keys_host",
        "authorized_keys_before_success",
    ],
)
def test_auth_policy_identity_and_window_mismatches_do_not_correlate(mutation: str) -> None:
    detections = auth_sequence()
    if mutation == "auth_window_outside":
        detections[0]["time_window_start"] = "2026-07-31T23:55:09Z"
        detections[0]["time_window_end"] = "2026-07-31T23:55:09Z"
    elif mutation == "failed_host":
        detections[0]["host"] = "other-host"
    elif mutation == "failed_user":
        detections[0]["user"] = "other-user"
    elif mutation == "failed_src_ip":
        detections[0]["src_ip"] = "198.51.100.20"
    elif mutation == "authorized_keys_host":
        detections[2]["host"] = "other-host"
    elif mutation == "authorized_keys_before_success":
        detections[2]["time_window_start"] = "2026-08-01T00:00:09Z"
        detections[2]["time_window_end"] = "2026-08-01T00:00:09Z"

    _, correlations = run_common_correlation_stage(detections)

    assert correlations == []


def test_key_exec_policy_inclusive_window_boundary_correlates() -> None:
    detections = key_exec_sequence(exec_timestamp="2026-08-01T00:05:00Z")

    _, correlations = run_common_correlation_stage(detections)

    assert [item["correlation_type"] for item in correlations] == ["key_login_then_process_exec"]


@pytest.mark.parametrize(
    "mutation",
    ["execution_window_outside", "key_host", "key_user", "execution_before_key"],
)
def test_key_exec_policy_identity_and_window_mismatches_do_not_correlate(
    mutation: str,
) -> None:
    detections = key_exec_sequence()
    if mutation == "execution_window_outside":
        detections[1]["time_window_start"] = "2026-08-01T00:05:01Z"
        detections[1]["time_window_end"] = "2026-08-01T00:05:01Z"
    elif mutation == "key_host":
        detections[0]["host"] = "other-host"
    elif mutation == "key_user":
        detections[0]["user"] = "other-user"
    elif mutation == "execution_before_key":
        detections[1]["time_window_start"] = "2026-07-31T23:59:59Z"
        detections[1]["time_window_end"] = "2026-07-31T23:59:59Z"

    _, correlations = run_common_correlation_stage(detections)

    assert correlations == []


def test_missing_timestamps_do_not_correlate_or_raise_comparison_errors() -> None:
    detections = [
        *auth_sequence(failed_timestamp=None),
        *key_exec_sequence(key_timestamp=None),
    ]

    _, correlations = run_common_correlation_stage(detections)

    assert correlations == []


def test_input_order_equal_timestamps_and_timezone_forms_are_deterministic() -> None:
    detections = [
        *auth_sequence(
            failed_timestamp="2026-08-01T00:00:00Z",
            success_timestamp="2026-08-01T00:00:00+00:00",
            authorized_keys_timestamp="2026-07-31T20:00:00-04:00",
        ),
        *key_exec_sequence(
            key_timestamp="2026-08-01T00:00:00+00:00",
            exec_timestamp="2026-08-01T09:00:00+09:00",
        ),
    ]
    original = deepcopy(detections)

    forward = run_common_correlation_stage(detections)
    reversed_result = run_common_correlation_stage(list(reversed(detections)))

    assert forward == reversed_result
    assert detections == original
    assert [item["correlation_id"] for item in forward[1]] == [
        "corr-auth-persistence-000001",
        "corr-key-exec-000001",
    ]
    for correlation in forward[1]:
        assert correlation["evidence_refs"] == sorted(correlation["evidence_refs"])
        assert correlation["raw_event_refs"] == sorted(correlation["raw_event_refs"])
        for detections_by_artifact in correlation["supporting_detections"].values():
            assert detections_by_artifact == sorted(
                detections_by_artifact,
                key=lambda detection: (detection["rule_id"], detection["id"]),
            )


def valid_auth_correlation() -> tuple[list[dict], dict]:
    deduped, correlations = run_common_correlation_stage(auth_sequence())
    assert len(correlations) == 1
    return deduped, correlations[0]


def test_non_list_policy_output_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "detection.compiler.pipeline.correlate_auth_then_authorized_keys",
        lambda detections: {},
    )

    with pytest.raises(
        CommonPipelineValidationError,
        match="auth_then_authorized_keys output must be a list",
    ):
        run_common_correlation_stage(auth_sequence())


def test_policy_error_is_wrapped_with_policy_name(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken_policy(detections: list[dict]) -> list[dict]:
        raise TypeError("synthetic policy failure")

    monkeypatch.setattr(
        "detection.compiler.pipeline.correlate_key_login_then_process_exec",
        broken_policy,
    )

    with pytest.raises(
        CommonPipelineValidationError,
        match="policy key_login_then_process_exec failed: synthetic policy failure",
    ):
        run_common_correlation_stage(key_exec_sequence())


@pytest.mark.parametrize(
    ("malformation", "message"),
    [
        ("unknown_type", "correlation_type is not supported"),
        ("unknown_support", "references unknown detection id"),
        ("changed_support", "supporting detection differs from input"),
        ("invented_evidence", "evidence_refs must equal supporting detection refs"),
        ("missing_evidence", "evidence_refs must equal supporting detection refs"),
        ("invalid_timestamp", "time window must contain valid timestamps"),
        ("reversed_window", "time_window_start must not be after time_window_end"),
    ],
)
def test_malformed_correlation_result_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    malformation: str,
    message: str,
) -> None:
    _, valid = valid_auth_correlation()
    malformed = deepcopy(valid)
    if malformation == "unknown_type":
        malformed["correlation_type"] = "unknown_policy"
    elif malformation == "unknown_support":
        malformed["supporting_detections"]["ssh_failed_login"][0]["id"] = "det-unknown"
    elif malformation == "changed_support":
        malformed["supporting_detections"]["ssh_failed_login"][0]["title"] = "Changed"
    elif malformation == "invented_evidence":
        malformed["evidence_refs"].append("invented-evidence")
        malformed["evidence_refs"].sort()
    elif malformation == "missing_evidence":
        malformed["evidence_refs"] = malformed["evidence_refs"][1:]
    elif malformation == "invalid_timestamp":
        malformed["time_window_start"] = "not-a-timestamp"
    elif malformation == "reversed_window":
        malformed["time_window_start"] = "2026-08-01T00:01:00Z"

    monkeypatch.setattr(
        "detection.compiler.pipeline.correlate_auth_then_authorized_keys",
        lambda detections: [malformed],
    )
    monkeypatch.setattr(
        "detection.compiler.pipeline.correlate_key_login_then_process_exec",
        lambda detections: [],
    )

    with pytest.raises(CommonPipelineValidationError, match=message):
        run_common_correlation_stage(auth_sequence())


def test_duplicate_correlation_id_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _, valid = valid_auth_correlation()
    monkeypatch.setattr(
        "detection.compiler.pipeline.correlate_auth_then_authorized_keys",
        lambda detections: [deepcopy(valid)],
    )
    monkeypatch.setattr(
        "detection.compiler.pipeline.correlate_key_login_then_process_exec",
        lambda detections: [deepcopy(valid)],
    )

    with pytest.raises(CommonPipelineValidationError, match="duplicate correlation id"):
        run_common_correlation_stage(auth_sequence())


def test_scenario_009_detection_is_preserved_without_correlation() -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    detections = run_common_detection_pipeline(endpoint_events, [load_rule(LINUX_RULE_PATH)])

    deduped, correlations = run_common_correlation_stage(detections)

    assert len(deduped) == 1
    assert deduped[0]["rule_id"] == "collection.suspicious_archive_staging"
    assert deduped[0]["artifact"] == detections[0]["artifact"]
    assert deduped[0]["behavior_features"] == detections[0]["behavior_features"]
    assert deduped[0]["evidence_refs"] == detections[0]["evidence_refs"]
    assert correlations == []


@pytest.mark.parametrize(
    ("fixture_name", "expected_rule_ids"),
    [
        (
            "sysmon-event1-ordinary-powershell-001.json",
            ["execution.windows_powershell_process_observed"],
        ),
        (
            "sysmon-event1-encoded-flag-001.json",
            [
                "execution.windows_powershell_encoded_command_observed",
                "execution.windows_powershell_process_observed",
            ],
        ),
        ("sysmon-event1-ordinary-notepad-001.json", []),
    ],
)
def test_windows_fixtures_preserve_dedupe_counts_without_correlation(
    fixture_name: str,
    expected_rule_ids: list[str],
) -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / fixture_name)
    rules = [load_rule(path) for path in WINDOWS_RULE_PATHS]
    detections = run_common_detection_pipeline(endpoint_envelope(event), rules)

    deduped, correlations = run_common_correlation_stage(detections)

    assert [detection["rule_id"] for detection in deduped] == expected_rule_ids
    assert correlations == []
