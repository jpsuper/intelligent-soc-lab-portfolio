import json
from copy import deepcopy
from pathlib import Path

import pytest

from detection.compiler.dedupe import dedupe_detections
from detection.compiler.loader import load_rule
from detection.compiler.pipeline import (
    CommonPipelineValidationError,
    dedupe_canonical_detections,
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
    *,
    rule_id: str = "test.rule",
    artifact: str = "process_exec",
    timestamp: str | None = "2026-07-31T00:00:00Z",
) -> dict:
    return {
        "id": detection_id,
        "rule_id": rule_id,
        "title": "Test rule",
        "log_source": {"product": "linux"},
        "event_type": "process_exec",
        "artifact": artifact,
        "severity": "low",
        "host": "fixture-host",
        "user": "fixture-user",
        "src_ip": None,
        "path": "/tmp/fixture.sh",
        "command_line": "/bin/bash /tmp/fixture.sh",
        "behavior_features": {"process_execution_observed": True},
        "evidence_refs": [f"evidence.json#{detection_id}"],
        "raw_event_refs": [f"input[{detection_id}]"],
        "time_window_start": timestamp,
        "time_window_end": timestamp,
    }


def test_existing_dedupe_merges_same_identity_within_artifact_window() -> None:
    first = canonical_detection("det-a", timestamp="2026-07-31T00:00:00Z")
    second = canonical_detection("det-b", timestamp="2026-07-31T00:00:30Z")

    result = dedupe_detections([first, second])

    assert len(result) == 1
    assert result[0]["id"] == "det-a"
    assert result[0]["duplicate_count"] == 2
    assert result[0]["time_window_start"] == "2026-07-31T00:00:00+00:00"
    assert result[0]["time_window_end"] == "2026-07-31T00:00:30+00:00"


def test_empty_canonical_list_returns_empty_without_calling_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_dedupe(*args: object, **kwargs: object) -> list[dict]:
        raise AssertionError("dedupe helper must not be called for an empty input")

    monkeypatch.setattr("detection.compiler.pipeline.dedupe_detections", unexpected_dedupe)

    assert dedupe_canonical_detections([]) == []


def test_input_duplicate_count_is_not_a_dedupe_authority() -> None:
    detection = canonical_detection("det-self-reported")
    detection["duplicate_count"] = 999

    result = dedupe_canonical_detections([detection])

    assert result[0]["duplicate_count"] == 1


@pytest.mark.parametrize(
    ("detections", "message"),
    [
        ({}, "canonical detection output must be a list"),
        ([{"id": "incomplete"}], "missing canonical fields"),
        (
            [canonical_detection("det-duplicate"), canonical_detection("det-duplicate")],
            "duplicate detection id: det-duplicate",
        ),
        (
            [canonical_detection("det-invalid-ts", timestamp="not-a-timestamp")],
            "time_window_start must be a valid ISO-8601 timestamp or null",
        ),
    ],
)
def test_invalid_canonical_dedupe_input_fails_closed(
    detections: object,
    message: str,
) -> None:
    with pytest.raises(CommonPipelineValidationError, match=message):
        dedupe_canonical_detections(detections)


def test_duplicate_merge_preserves_canonical_information_deterministically() -> None:
    first = canonical_detection("det-a", timestamp="2026-07-31T00:00:00Z")
    first["time_window_end"] = "2026-07-31T00:00:05Z"
    first["evidence_refs"] = ["evidence.json#shared", "evidence.json#a"]
    first["raw_event_refs"] = ["raw-z", "raw-shared"]
    first["behavior_features"] = {"feature_a": True, "feature_b": False}

    second = canonical_detection("det-b", timestamp="2026-07-31T00:00:20Z")
    second["time_window_end"] = "2026-07-31T00:00:30Z"
    second["evidence_refs"] = ["evidence.json#b", "evidence.json#shared"]
    second["raw_event_refs"] = ["raw-a", "raw-shared"]
    second["behavior_features"] = {"feature_a": False, "feature_b": True}

    result = dedupe_canonical_detections([second, first])

    assert len(result) == 1
    assert result[0]["id"] == "det-a"
    assert result[0]["duplicate_count"] == 2
    assert result[0]["time_window_start"] == "2026-07-31T00:00:00+00:00"
    assert result[0]["time_window_end"] == "2026-07-31T00:00:30+00:00"
    assert result[0]["evidence_refs"] == [
        "evidence.json#a",
        "evidence.json#b",
        "evidence.json#shared",
    ]
    assert result[0]["raw_event_refs"] == ["raw-a", "raw-shared", "raw-z"]
    assert result[0]["behavior_features"] == {"feature_a": True, "feature_b": True}


def test_same_identity_outside_window_remains_separate() -> None:
    first = canonical_detection("det-a", timestamp="2026-07-31T00:00:00Z")
    second = canonical_detection("det-b", timestamp="2026-07-31T00:01:01Z")

    result = dedupe_canonical_detections([second, first])

    assert [item["id"] for item in result] == ["det-a", "det-b"]
    assert [item["duplicate_count"] for item in result] == [1, 1]


def test_different_rule_ids_are_not_merged() -> None:
    first = canonical_detection("det-a", rule_id="test.rule.a")
    second = canonical_detection("det-b", rule_id="test.rule.b")

    result = dedupe_canonical_detections([second, first])

    assert [item["rule_id"] for item in result] == ["test.rule.a", "test.rule.b"]
    assert [item["duplicate_count"] for item in result] == [1, 1]


def test_input_order_and_equal_timestamps_do_not_change_output() -> None:
    first = canonical_detection("det-b")
    first["evidence_refs"] = ["evidence-z", "evidence-shared"]
    first["raw_event_refs"] = ["raw-z", "raw-shared"]
    second = canonical_detection("det-a")
    second["evidence_refs"] = ["evidence-a", "evidence-shared"]
    second["raw_event_refs"] = ["raw-a", "raw-shared"]
    detections = [first, second]
    original = deepcopy(detections)

    forward = dedupe_canonical_detections(detections)
    reversed_result = dedupe_canonical_detections(list(reversed(detections)))

    assert forward == reversed_result
    assert forward[0]["id"] == "det-a"
    assert forward[0]["evidence_refs"] == ["evidence-a", "evidence-shared", "evidence-z"]
    assert forward[0]["raw_event_refs"] == ["raw-a", "raw-shared", "raw-z"]
    assert detections == original


def test_missing_timestamps_are_not_merged_by_input_order() -> None:
    first = canonical_detection("det-b", timestamp=None)
    second = canonical_detection("det-a", timestamp=None)

    forward = dedupe_canonical_detections([first, second])
    reversed_result = dedupe_canonical_detections([second, first])

    assert forward == reversed_result
    assert [item["id"] for item in forward] == ["det-a", "det-b"]
    assert [item["duplicate_count"] for item in forward] == [1, 1]


def test_linux_scenario_009_detection_preserves_canonical_evidence() -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    detections = run_common_detection_pipeline(endpoint_events, [load_rule(LINUX_RULE_PATH)])

    result = dedupe_canonical_detections(detections)

    assert len(result) == 1
    for field in ("rule_id", "artifact", "behavior_features", "evidence_refs", "raw_event_refs"):
        assert result[0][field] == detections[0][field]


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
def test_windows_fixture_detection_counts_and_rule_ids_are_preserved(
    fixture_name: str,
    expected_rule_ids: list[str],
) -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / fixture_name)
    rules = [load_rule(path) for path in WINDOWS_RULE_PATHS]
    detections = run_common_detection_pipeline(endpoint_envelope(event), rules)

    result = dedupe_canonical_detections(detections)

    assert [detection["rule_id"] for detection in result] == expected_rule_ids


def test_invalid_dedupe_helper_output_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "detection.compiler.pipeline.dedupe_detections",
        lambda detections: [{"id": "malformed"}],
    )

    with pytest.raises(CommonPipelineValidationError, match="missing canonical fields"):
        dedupe_canonical_detections([canonical_detection("det-a")])
