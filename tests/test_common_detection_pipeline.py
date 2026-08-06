import json
from pathlib import Path

import pytest

from detection.compiler.evaluator import evaluate_rules_against_events
from detection.compiler.loader import load_rule
from detection.compiler.pipeline import (
    CommonPipelineValidationError,
    run_common_detection_pipeline,
)

LINUX_FIXTURE_PATH = Path(
    "tests/fixtures/scenario_009_suspicious_archive_staging/endpoint_events.json"
)
LINUX_RULE_PATH = Path("detection/dsl/suspicious_archive_staging.yaml")
WINDOWS_NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
WINDOWS_EXPECTED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_detection")
WINDOWS_RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def endpoint_envelope(event: dict) -> dict:
    return {
        "schema_version": "endpoint_events.v1",
        "events": [event],
    }


def windows_summary(event: dict, detections: list[dict]) -> dict:
    return {
        "schema_version": "sysmon_event1_expected_detection.v1",
        "fixture_id": event["raw_ref"]["fixture_id"],
        "normalized_event_id": event["event_id"],
        "matched_rule_ids": sorted(detection["rule_id"] for detection in detections),
        "behavior_features": {
            key: True
            for detection in detections
            for key, value in detection["behavior_features"].items()
            if value is True
        },
    }


def canonical_detection() -> dict:
    return {
        "id": "det-000001",
        "rule_id": "test.rule",
        "title": "Test rule",
        "log_source": {"product": "linux"},
        "event_type": "process_exec",
        "artifact": "test_artifact",
        "severity": "low",
        "host": "fixture-host",
        "user": None,
        "src_ip": None,
        "path": None,
        "process_name": "test",
        "file_path": None,
        "command_line": None,
        "auth_method": None,
        "result": None,
        "behavior_features": {},
        "evidence_refs": [],
        "raw_event_refs": ["input[0]"],
        "time_window_start": "2026-07-10T22:00:00Z",
        "time_window_end": "2026-07-10T22:00:00Z",
    }


def test_normalized_linux_endpoint_events_preserve_existing_evaluator_output() -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    rules = [load_rule(LINUX_RULE_PATH)]

    actual = run_common_detection_pipeline(endpoint_events, rules)
    legacy = evaluate_rules_against_events(endpoint_events["events"], rules)

    assert actual == legacy
    assert [detection["rule_id"] for detection in actual] == [
        "collection.suspicious_archive_staging"
    ]


@pytest.mark.parametrize(
    "fixture_name",
    [
        "sysmon-event1-ordinary-powershell-001.json",
        "sysmon-event1-encoded-flag-001.json",
        "sysmon-event1-ordinary-notepad-001.json",
    ],
)
def test_windows_fixture_detection_parity_through_common_pipeline(
    fixture_name: str,
) -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / fixture_name)
    rules = [load_rule(path) for path in reversed(WINDOWS_RULE_PATHS)]

    detections = run_common_detection_pipeline(endpoint_envelope(event), rules)

    assert windows_summary(event, detections) == load_json(WINDOWS_EXPECTED_DIR / fixture_name)


def test_linux_and_windows_use_the_same_atomic_evaluator(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[dict], list[str]]] = []

    def record_evaluation(
        events: list[dict],
        rules: list[dict],
        time_min: object = None,
        time_max: object = None,
    ) -> list[dict]:
        calls.append((events, [rule["id"] for rule in rules]))
        return []

    monkeypatch.setattr(
        "detection.compiler.pipeline.evaluate_rules_against_events",
        record_evaluation,
    )

    linux = load_json(LINUX_FIXTURE_PATH)
    windows_event = load_json(WINDOWS_NORMALIZED_DIR / "sysmon-event1-ordinary-powershell-001.json")
    run_common_detection_pipeline(linux, [load_rule(LINUX_RULE_PATH)])
    run_common_detection_pipeline(
        endpoint_envelope(windows_event),
        [load_rule(WINDOWS_RULE_PATHS[0])],
    )

    assert len(calls) == 2
    assert calls[0][0] == linux["events"]
    assert calls[1][0] == [windows_event]


def test_rule_order_does_not_change_common_pipeline_output() -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / "sysmon-event1-encoded-flag-001.json")
    rules = [load_rule(path) for path in WINDOWS_RULE_PATHS]

    forward = run_common_detection_pipeline(endpoint_envelope(event), rules)
    reversed_order = run_common_detection_pipeline(endpoint_envelope(event), list(reversed(rules)))

    assert forward == reversed_order
    assert [detection["rule_id"] for detection in forward] == [
        "execution.windows_powershell_encoded_command_observed",
        "execution.windows_powershell_process_observed",
    ]


def test_no_match_is_a_successful_empty_result() -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / "sysmon-event1-ordinary-notepad-001.json")
    rules = [load_rule(path) for path in WINDOWS_RULE_PATHS]

    assert run_common_detection_pipeline(endpoint_envelope(event), rules) == []


@pytest.mark.parametrize(
    "endpoint_events",
    [
        [],
        {"schema_version": "endpoint_events.v1"},
        {
            "schema_version": "endpoint_events.v1",
            "events": [
                {
                    "event_id": "malformed",
                    "source": "auditd",
                    "platform": "linux",
                    "host": "fixture-host",
                    "timestamp": "not-a-timestamp",
                    "event_type": "process_exec",
                }
            ],
        },
    ],
)
def test_malformed_endpoint_contract_fails_closed(endpoint_events: object) -> None:
    with pytest.raises(CommonPipelineValidationError, match="endpoint_events.v1 validation"):
        run_common_detection_pipeline(endpoint_events, [load_rule(LINUX_RULE_PATH)])


def test_unknown_match_operator_remains_fail_closed() -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    rule = load_rule(LINUX_RULE_PATH)
    rule["match"]["unknown_operator"] = True

    assert run_common_detection_pipeline(endpoint_events, [rule]) == []


def test_invalid_rule_contract_fails_closed() -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    rule = load_rule(LINUX_RULE_PATH)
    del rule["artifact"]

    with pytest.raises(CommonPipelineValidationError, match="missing required keys: artifact"):
        run_common_detection_pipeline(endpoint_events, [rule])


@pytest.mark.parametrize(
    "behavior_features",
    [
        {"encoded_command_observed": "true"},
        {1: True},
    ],
)
def test_no_match_with_invalid_rule_behavior_features_fails_before_evaluation(
    monkeypatch: pytest.MonkeyPatch,
    behavior_features: dict,
) -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / "sysmon-event1-ordinary-notepad-001.json")
    rule = load_rule(WINDOWS_RULE_PATHS[0])
    rule["behavior_features"] = behavior_features
    evaluator_called = False

    def unexpected_evaluation(*args: object, **kwargs: object) -> list[dict]:
        nonlocal evaluator_called
        evaluator_called = True
        return []

    monkeypatch.setattr(
        "detection.compiler.pipeline.evaluate_rules_against_events",
        unexpected_evaluation,
    )

    with pytest.raises(
        CommonPipelineValidationError,
        match="'behavior_features' must be an object of booleans",
    ):
        run_common_detection_pipeline(endpoint_envelope(event), [rule])
    assert evaluator_called is False


def test_canonical_output_missing_host_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    detection = canonical_detection()
    del detection["host"]
    monkeypatch.setattr(
        "detection.compiler.pipeline.evaluate_rules_against_events",
        lambda *args, **kwargs: [detection],
    )

    with pytest.raises(CommonPipelineValidationError, match="missing canonical fields: host"):
        run_common_detection_pipeline(endpoint_events, [load_rule(LINUX_RULE_PATH)])


@pytest.mark.parametrize(
    ("field", "invalid_value", "message"),
    [
        ("host", None, "host must be a non-empty string"),
        ("host", "", "host must be a non-empty string"),
        ("host", " ", "host must be a non-empty string"),
        ("user", 1000, "user must be a string or null"),
        ("src_ip", ["192.0.2.1"], "src_ip must be a string or null"),
        ("path", {"value": "/tmp"}, "path must be a string or null"),
        ("command_line", True, "command_line must be a string or null"),
    ],
)
def test_canonical_output_common_field_types_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    invalid_value: object,
    message: str,
) -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    detection = canonical_detection()
    detection[field] = invalid_value
    monkeypatch.setattr(
        "detection.compiler.pipeline.evaluate_rules_against_events",
        lambda *args, **kwargs: [detection],
    )

    with pytest.raises(CommonPipelineValidationError, match=message):
        run_common_detection_pipeline(endpoint_events, [load_rule(LINUX_RULE_PATH)])


def test_malformed_canonical_output_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    monkeypatch.setattr(
        "detection.compiler.pipeline.evaluate_rules_against_events",
        lambda *args, **kwargs: [{"id": "incomplete"}],
    )

    with pytest.raises(CommonPipelineValidationError, match="missing canonical fields"):
        run_common_detection_pipeline(endpoint_events, [load_rule(LINUX_RULE_PATH)])
