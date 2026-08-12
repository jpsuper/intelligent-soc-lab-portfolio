import json
from copy import deepcopy
from pathlib import Path

import pytest

from common import defender_pipeline
from detection.compiler.loader import load_rule
from detection.compiler.pipeline import (
    CommonPipelineValidationError,
    run_common_correlation_stage,
    run_common_detection_pipeline,
)

FIXTURE_PATH = Path(
    "tests/fixtures/windows/sysmon_event1/slice2/powershell_parent_child_encoded_command.json"
)
RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]


def load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def fixture_detections() -> list[dict]:
    return run_common_detection_pipeline(
        load_fixture(),
        [load_rule(path) for path in RULE_PATHS],
    )


def detection_by_id(detections: list[dict], detection_id: str) -> dict:
    return next(detection for detection in detections if detection["id"] == detection_id)


def test_slice2_fixture_builds_one_parent_child_correlation() -> None:
    detections = fixture_detections()

    assert [detection["rule_id"] for detection in detections] == [
        "execution.windows_powershell_process_observed",
        "execution.windows_powershell_encoded_command_observed",
        "execution.windows_powershell_process_observed",
    ]
    assert [detection["event_id"] for detection in detections] == [
        "windows-slice2:parent:001",
        "windows-slice2:child:001",
        "windows-slice2:child:001",
    ]
    assert [(detection["pid"], detection["ppid"]) for detection in detections] == [
        (5100, 5000),
        (5200, 5100),
        (5200, 5100),
    ]

    deduped, correlations = run_common_correlation_stage(detections)

    assert len(deduped) == 3
    assert len(correlations) == 1
    correlation = correlations[0]
    assert correlation["correlation_id"] == "corr-windows-ps-parent-child-000001"
    assert correlation["correlation_type"] == "windows_powershell_parent_child_encoded_command"
    assert correlation["severity"] == "medium"
    assert correlation["host"] == "WIN-SLICE2-01"
    assert correlation["user"] == "LAB\\fixture-user"
    assert correlation["artifacts"] == [
        "powershell_process_observed",
        "encoded_command_observed",
    ]
    assert correlation["behavior_features"] == {
        "powershell_parent_child_observed": True,
        "encoded_command_observed": True,
    }
    assert [
        detection["id"]
        for detection in correlation["supporting_detections"]["powershell_process_observed"]
    ] == ["det-000001", "det-000003"]
    assert [
        detection["id"]
        for detection in correlation["supporting_detections"]["encoded_command_observed"]
    ] == ["det-000002"]
    assert correlation["raw_event_refs"] == ["input[0]", "input[1]"]
    assert correlation["time_window_start"] == "2026-08-01T00:00:00+00:00"
    assert correlation["time_window_end"] == "2026-08-01T00:00:30+00:00"


def test_slice2_correlation_is_input_order_deterministic() -> None:
    detections = fixture_detections()
    original = deepcopy(detections)

    forward = run_common_correlation_stage(detections)
    reversed_result = run_common_correlation_stage(list(reversed(detections)))

    assert forward == reversed_result
    assert detections == original


def test_slice2_exact_ids_flow_through_shared_investigation_boundary() -> None:
    bundle = defender_pipeline.run_common_endpoint_to_investigation(
        load_fixture(),
        [load_rule(path) for path in RULE_PATHS],
        endpoint_events_source=str(FIXTURE_PATH),
    )

    assert {key: len(value) for key, value in bundle.items()} == {
        "deduped_detections": 3,
        "correlations": 1,
        "incidents": 1,
        "triage_results": 1,
        "investigation_results": 1,
    }
    incident = bundle["incidents"][0]
    assert incident["incident_id"] == "inc-corr-windows-ps-parent-child-000001"
    assert incident["matched_detection_ids"] == [
        "det-000001",
        "det-000002",
        "det-000003",
    ]
    assert bundle["triage_results"][0]["incident_id"] == incident["incident_id"]
    assert bundle["investigation_results"][0]["incident_id"] == incident["incident_id"]


@pytest.mark.parametrize(
    "mutation",
    [
        "different_host",
        "different_user",
        "wrong_parent_pid",
        "child_before_parent",
        "outside_window",
        "missing_child_event_id",
        "mismatched_child_event_id",
        "same_event_parent",
    ],
)
def test_slice2_identity_and_time_mismatches_do_not_correlate(mutation: str) -> None:
    detections = fixture_detections()
    parent = detection_by_id(detections, "det-000001")
    encoded_child = detection_by_id(detections, "det-000002")
    process_child = detection_by_id(detections, "det-000003")

    if mutation == "different_host":
        parent["host"] = "OTHER-HOST"
    elif mutation == "different_user":
        parent["user"] = "LAB\\other-user"
    elif mutation == "wrong_parent_pid":
        parent["pid"] = 9999
    elif mutation == "child_before_parent":
        parent["time_window_start"] = "2026-08-01T00:00:31Z"
        parent["time_window_end"] = "2026-08-01T00:00:31Z"
    elif mutation == "outside_window":
        parent["time_window_start"] = "2026-07-31T23:58:59Z"
        parent["time_window_end"] = "2026-07-31T23:58:59Z"
    elif mutation == "missing_child_event_id":
        encoded_child["event_id"] = None
    elif mutation == "mismatched_child_event_id":
        encoded_child["event_id"] = "windows-slice2:other-child:001"
    elif mutation == "same_event_parent":
        parent["event_id"] = process_child["event_id"]

    _, correlations = run_common_correlation_stage(detections)

    assert correlations == []


def test_slice2_window_boundary_is_inclusive() -> None:
    detections = fixture_detections()
    parent = detection_by_id(detections, "det-000001")
    parent["time_window_start"] = "2026-07-31T23:59:30Z"
    parent["time_window_end"] = "2026-07-31T23:59:30Z"

    _, correlations = run_common_correlation_stage(detections)

    assert len(correlations) == 1


def test_process_identity_prevents_parent_child_dedupe_collapse() -> None:
    detections = fixture_detections()

    deduped, _ = run_common_correlation_stage(detections)

    process_detections = [
        detection for detection in deduped if detection["artifact"] == "powershell_process_observed"
    ]
    assert [detection["event_id"] for detection in process_detections] == [
        "windows-slice2:parent:001",
        "windows-slice2:child:001",
    ]
    assert [detection["duplicate_count"] for detection in process_detections] == [1, 1]


@pytest.mark.parametrize(
    ("field", "invalid_value", "message"),
    [
        ("event_id", 10, "event_id must be a string or null"),
        ("pid", {}, "pid must be a string, number, or null"),
        ("ppid", True, "ppid must be a string, number, or null"),
    ],
)
def test_process_identity_fields_fail_closed(
    field: str,
    invalid_value: object,
    message: str,
) -> None:
    detections = fixture_detections()
    detections[0][field] = invalid_value

    with pytest.raises(CommonPipelineValidationError, match=message):
        run_common_correlation_stage(detections)
