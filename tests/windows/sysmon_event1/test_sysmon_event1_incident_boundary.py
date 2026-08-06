import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from detection.compiler.loader import load_rule
from detection.compiler.pipeline import run_common_detection_pipeline

NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
INCIDENT_BUILDER_PATH = Path("agents/incident-builder-agent/src/main.py")
INCIDENT_SCHEMA_PATH = Path("schemas/incident_schema.json")
RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]
FIXTURE_EXPECTATIONS = {
    "sysmon-event1-ordinary-powershell-001.json": [
        (
            "execution.windows_powershell_process_observed",
            "powershell_process_observed",
        )
    ],
    "sysmon-event1-encoded-flag-001.json": [
        (
            "execution.windows_powershell_encoded_command_observed",
            "encoded_command_observed",
        ),
        (
            "execution.windows_powershell_process_observed",
            "powershell_process_observed",
        ),
    ],
    "sysmon-event1-ordinary-notepad-001.json": [],
}
FORBIDDEN_INCIDENT_KEYS = {
    "EventData",
    "ProcessGuid",
    "Image",
    "CommandLine",
    "fixture_id",
    "provider_name",
    "source_fields",
    "malicious",
    "compromise",
    "attack_success",
    "containment",
    "approval",
    "response_action",
}
FORBIDDEN_ATTACKER_MARKERS = {
    "ATTACK_EVENT_JSON",
    "staging_directory_created",
    "archive_created",
    "payload_execution_succeeded",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_incident_builder():
    spec = importlib.util.spec_from_file_location(
        "windows_slice1_incident_builder",
        INCIDENT_BUILDER_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def endpoint_envelope(event: dict) -> dict:
    return {
        "schema_version": "endpoint_events.v1",
        "events": [event],
    }


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def detections_for_fixture(fixture_name: str) -> tuple[dict, list[dict]]:
    event = load_json(NORMALIZED_DIR / fixture_name)
    rules = [load_rule(path) for path in reversed(RULE_PATHS)]
    detections = run_common_detection_pipeline(endpoint_envelope(event), rules)
    return event, detections


@pytest.mark.parametrize("fixture_name", FIXTURE_EXPECTATIONS)
def test_windows_slice1_reaches_observation_incident_boundary(
    fixture_name: str,
) -> None:
    event, detections = detections_for_fixture(fixture_name)
    bridge = load_incident_builder()

    incidents = bridge.build_observation_incidents_from_detections(
        detections,
        incident_severity="low",
    )

    expected = FIXTURE_EXPECTATIONS[fixture_name]
    assert len(detections) == len(expected)
    assert len(incidents) == len(expected)
    assert [incident["incident_id"] for incident in incidents] == [
        f"inc-{index:06d}" for index in range(1, len(expected) + 1)
    ]
    assert [incident["matched_rules"][0] for incident in incidents] == [
        rule_id for rule_id, _feature in expected
    ]

    validator = Draft7Validator(load_json(INCIDENT_SCHEMA_PATH))
    detections_by_id = {detection["id"]: detection for detection in detections}
    for incident, (rule_id, feature) in zip(incidents, expected, strict=True):
        validator.validate(incident)
        detection = detections_by_id[incident["matched_detection_ids"][0]]
        timeline = incident["timeline"][0]

        assert incident["severity"] == "low"
        assert incident["matched_rules"] == [rule_id]
        assert incident["matched_detection_ids"] == [detection["id"]]
        assert incident["primary_artifact"] == detection["artifact"]
        assert incident["behavior_features"] == {feature: True}
        assert incident["source_hosts"] == [event["host"]]
        assert incident["source_ips"] == []
        assert incident["evidence_refs"] == detection["evidence_refs"]
        assert incident["raw_event_refs"] == detection["raw_event_refs"]
        assert incident["time_window_start"] == event["timestamp"]
        assert incident["time_window_end"] == event["timestamp"]

        assert timeline["rule_id"] == rule_id
        assert timeline["artifact"] == detection["artifact"]
        assert timeline["event_type"] == event["event_type"]
        assert timeline["host"] == event["host"]
        assert timeline["command_line"] == event["command_line"]
        assert timeline["evidence_refs"] == detection["evidence_refs"]
        assert timeline["raw_event_refs"] == detection["raw_event_refs"]

        summary_and_notes = " ".join([incident["summary"], *incident["notes"]])
        assert "observed behavior only" in summary_and_notes
        assert "does not infer compromise" in summary_and_notes
        assert "No live auditd, Wazuh, or SIEM collection is proven" in summary_and_notes
        assert collect_keys(incident).isdisjoint(FORBIDDEN_INCIDENT_KEYS)
        serialized = json.dumps(incident)
        assert all(marker not in serialized for marker in FORBIDDEN_ATTACKER_MARKERS)

    assert event["command_line"] == load_json(NORMALIZED_DIR / fixture_name)["command_line"]
    if "SAFE_PLACEHOLDER" in event["command_line"]:
        assert all(
            incident["timeline"][0]["command_line"] == event["command_line"]
            for incident in incidents
        )


def test_incident_order_and_ids_do_not_depend_on_detection_input_order() -> None:
    _event, detections = detections_for_fixture("sysmon-event1-encoded-flag-001.json")
    bridge = load_incident_builder()

    forward = bridge.build_observation_incidents_from_detections(
        detections,
        incident_severity="low",
    )
    reversed_input = bridge.build_observation_incidents_from_detections(
        list(reversed(detections)),
        incident_severity="low",
    )

    assert forward == reversed_input


def test_bounded_incident_severity_is_an_explicit_adapter_policy() -> None:
    _event, detections = detections_for_fixture("sysmon-event1-ordinary-powershell-001.json")
    detections[0]["severity"] = "medium"
    bridge = load_incident_builder()

    incidents = bridge.build_observation_incidents_from_detections(
        detections,
        incident_severity="low",
    )

    assert incidents[0]["severity"] == "low"
    assert incidents[0]["timeline"][0]["severity"] == "low"


@pytest.mark.parametrize(
    "detections",
    [
        {},
        ["not-an-object"],
        [{"id": "incomplete"}],
    ],
)
def test_invalid_canonical_detection_input_fails_closed(detections: object) -> None:
    bridge = load_incident_builder()

    with pytest.raises(bridge.IncidentBoundaryValidationError):
        bridge.build_observation_incidents_from_detections(detections)


def test_duplicate_detection_ids_fail_closed() -> None:
    _event, detections = detections_for_fixture("sysmon-event1-encoded-flag-001.json")
    duplicate_ids = deepcopy(detections)
    duplicate_ids[1]["id"] = duplicate_ids[0]["id"]
    bridge = load_incident_builder()

    with pytest.raises(
        bridge.IncidentBoundaryValidationError,
        match="canonical detection ids must be unique",
    ):
        bridge.build_observation_incidents_from_detections(duplicate_ids)


def test_schema_invalid_incident_output_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _event, detections = detections_for_fixture("sysmon-event1-ordinary-powershell-001.json")
    bridge = load_incident_builder()
    monkeypatch.setattr(
        bridge,
        "build_detection_hit_incident",
        lambda *args, **kwargs: {"incident_id": "invalid"},
    )

    with pytest.raises(
        bridge.IncidentBoundaryValidationError,
        match="schema validation failed",
    ):
        bridge.build_observation_incidents_from_detections(
            detections,
            incident_severity="low",
        )


@pytest.mark.parametrize("invalid_item", [1, {"ref": "evidence.json"}, None])
@pytest.mark.parametrize("location", ["top_level", "timeline"])
def test_invalid_incident_evidence_ref_items_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    location: str,
    invalid_item: object,
) -> None:
    _event, detections = detections_for_fixture("sysmon-event1-ordinary-powershell-001.json")
    bridge = load_incident_builder()
    original_builder = bridge.build_detection_hit_incident

    def build_with_invalid_evidence_ref(*args: object, **kwargs: object) -> dict:
        incident = original_builder(*args, **kwargs)
        if location == "top_level":
            incident["evidence_refs"] = [invalid_item]
        else:
            incident["timeline"][0]["evidence_refs"] = [invalid_item]
        return incident

    monkeypatch.setattr(
        bridge,
        "build_detection_hit_incident",
        build_with_invalid_evidence_ref,
    )

    with pytest.raises(
        bridge.IncidentBoundaryValidationError,
        match="schema validation failed",
    ):
        bridge.build_observation_incidents_from_detections(
            detections,
            incident_severity="low",
        )


def test_non_deterministic_incident_id_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _event, detections = detections_for_fixture("sysmon-event1-ordinary-powershell-001.json")
    bridge = load_incident_builder()
    original_builder = bridge.build_detection_hit_incident

    def build_with_wrong_id(*args: object, **kwargs: object) -> dict:
        incident = original_builder(*args, **kwargs)
        incident["incident_id"] = "inc-random"
        return incident

    monkeypatch.setattr(bridge, "build_detection_hit_incident", build_with_wrong_id)

    with pytest.raises(
        bridge.IncidentBoundaryValidationError,
        match=r"incident_id must be inc-000001",
    ):
        bridge.build_observation_incidents_from_detections(
            detections,
            incident_severity="low",
        )
