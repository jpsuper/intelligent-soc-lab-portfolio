import importlib.util
import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from detection.compiler.loader import load_rule
from detection.compiler.pipeline import (
    run_common_correlation_stage,
    run_common_detection_pipeline,
)

INCIDENT_BUILDER_PATH = Path("agents/incident-builder-agent/src/main.py")
INCIDENT_SCHEMA_PATH = Path("schemas/incident_schema.json")
LINUX_FIXTURE_PATH = Path(
    "tests/fixtures/scenario_009_suspicious_archive_staging/endpoint_events.json"
)
LINUX_RULE_PATH = Path("detection/dsl/suspicious_archive_staging.yaml")
WINDOWS_NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
WINDOWS_RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]
FORBIDDEN_ATTACKER_MARKERS = {
    "ATTACK_EVENT_JSON",
    "attack_observed_effects",
    "staging_directory_created",
    "payload_execution_succeeded",
}
FORBIDDEN_INCIDENT_KEYS = {
    "malicious",
    "compromise",
    "attack_success",
    "containment",
    "approval",
    "response_action",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_incident_builder():
    spec = importlib.util.spec_from_file_location(
        "common_incident_selection_builder",
        INCIDENT_BUILDER_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_detection(
    detection_id: str,
    artifact: str,
    timestamp: str,
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


def auth_sequence() -> list[dict]:
    return [
        canonical_detection("det-failed", "ssh_failed_login", "2026-08-01T00:00:00Z"),
        canonical_detection("det-success", "ssh_success_login", "2026-08-01T00:00:10Z"),
        canonical_detection(
            "det-authorized-keys",
            "authorized_keys_modification",
            "2026-08-01T00:00:20Z",
            src_ip=None,
        ),
    ]


def key_exec_sequence() -> list[dict]:
    return [
        canonical_detection("det-key", "ssh_key_login", "2026-08-01T00:01:00Z"),
        canonical_detection("det-exec", "process_exec", "2026-08-01T00:01:10Z"),
    ]


def uncovered_detection() -> dict:
    return canonical_detection(
        "det-uncovered",
        "process_exec",
        "2026-08-01T00:02:00Z",
        host="other-host",
        user="other-user",
        src_ip=None,
        rule_id="test.uncovered-process",
    )


def selection_inputs(detections: list[dict]) -> tuple[list[dict], list[dict]]:
    return run_common_correlation_stage(detections)


def assert_schema_valid(incidents: list[dict]) -> None:
    validator = Draft7Validator(load_json(INCIDENT_SCHEMA_PATH))
    for incident in incidents:
        validator.validate(incident)


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def represented_detection_ids(incidents: list[dict]) -> set[str]:
    return {
        detection_id for incident in incidents for detection_id in incident["matched_detection_ids"]
    }


def test_empty_selection_returns_empty() -> None:
    bridge = load_incident_builder()

    assert bridge.build_selected_incidents_from_results([], []) == []


def test_no_correlation_falls_back_to_one_observation_incident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deduped, correlations = selection_inputs([uncovered_detection()])
    assert correlations == []
    bridge = load_incident_builder()
    original_builder = bridge.build_correlation_incidents_from_results
    calls = 0

    def tracked_builder(*args: object, **kwargs: object) -> list[dict]:
        nonlocal calls
        calls += 1
        return original_builder(*args, **kwargs)

    monkeypatch.setattr(bridge, "build_correlation_incidents_from_results", tracked_builder)

    incidents = bridge.build_selected_incidents_from_results(correlations, deduped)

    assert calls == 1
    assert [incident["incident_id"] for incident in incidents] == ["inc-000001"]
    assert incidents[0]["matched_detection_ids"] == ["det-uncovered"]
    assert_schema_valid(incidents)


@pytest.mark.parametrize(
    ("detections", "expected_incident_id", "expected_detection_ids"),
    [
        (
            auth_sequence(),
            "inc-corr-auth-persistence-000001",
            {"det-failed", "det-success", "det-authorized-keys"},
        ),
        (
            key_exec_sequence(),
            "inc-corr-key-exec-000001",
            {"det-key", "det-exec"},
        ),
    ],
)
def test_full_correlation_coverage_suppresses_observation_incidents(
    detections: list[dict],
    expected_incident_id: str,
    expected_detection_ids: set[str],
) -> None:
    deduped, correlations = selection_inputs(detections)
    bridge = load_incident_builder()

    incidents = bridge.build_selected_incidents_from_results(correlations, deduped)

    assert len(correlations) == 1
    assert [incident["incident_id"] for incident in incidents] == [expected_incident_id]
    assert represented_detection_ids(incidents) == expected_detection_ids
    assert all(not incident["incident_id"].startswith("inc-0") for incident in incidents)


def test_partial_coverage_builds_correlation_then_uncovered_observation() -> None:
    detections = [*auth_sequence(), uncovered_detection()]
    deduped, correlations = selection_inputs(detections)
    bridge = load_incident_builder()

    incidents = bridge.build_selected_incidents_from_results(correlations, deduped)

    assert [incident["incident_id"] for incident in incidents] == [
        "inc-corr-auth-persistence-000001",
        "inc-000001",
    ]
    assert incidents[1]["matched_detection_ids"] == ["det-uncovered"]
    assert set(incidents[0]["matched_detection_ids"]).isdisjoint(
        incidents[1]["matched_detection_ids"]
    )
    assert represented_detection_ids(incidents) == {item["id"] for item in deduped}


def test_multiple_independent_correlations_preserve_existing_order() -> None:
    deduped, correlations = selection_inputs([*auth_sequence(), *key_exec_sequence()])
    bridge = load_incident_builder()

    incidents = bridge.build_selected_incidents_from_results(correlations, deduped)

    assert [incident["incident_id"] for incident in incidents] == [
        "inc-corr-auth-persistence-000001",
        "inc-corr-key-exec-000001",
    ]
    assert len({incident["incident_id"] for incident in incidents}) == 2
    assert represented_detection_ids(incidents) == {item["id"] for item in deduped}


def test_overlapping_correlations_keep_both_and_suppress_shared_observation() -> None:
    detections = [
        canonical_detection("det-key", "ssh_key_login", "2026-08-01T00:00:00Z"),
        canonical_detection("det-exec-one", "process_exec", "2026-08-01T00:01:10Z"),
        canonical_detection("det-exec-two", "process_exec", "2026-08-01T00:02:20Z"),
    ]
    deduped, correlations = selection_inputs(detections)
    bridge = load_incident_builder()

    incidents = bridge.build_selected_incidents_from_results(correlations, deduped)

    assert len(correlations) == 2
    assert len(incidents) == 2
    assert [incident["incident_id"] for incident in incidents] == [
        "inc-corr-key-exec-000001",
        "inc-corr-key-exec-000002",
    ]
    assert all("det-key" in incident["matched_detection_ids"] for incident in incidents)
    assert all(incident["incident_id"].startswith("inc-corr-") for incident in incidents)


def test_selection_is_independent_of_raw_and_correlation_input_order() -> None:
    detections = [*auth_sequence(), *key_exec_sequence(), uncovered_detection()]
    bridge = load_incident_builder()
    forward_deduped, forward_correlations = selection_inputs(detections)
    reverse_deduped, reverse_correlations = selection_inputs(list(reversed(detections)))

    forward = bridge.build_selected_incidents_from_results(
        forward_correlations,
        forward_deduped,
    )
    reversed_raw = bridge.build_selected_incidents_from_results(
        reverse_correlations,
        reverse_deduped,
    )
    reversed_correlations = bridge.build_selected_incidents_from_results(
        list(reversed(forward_correlations)),
        forward_deduped,
    )

    assert forward == reversed_raw == reversed_correlations


def test_observation_adapter_parameters_apply_only_to_fallback() -> None:
    deduped, correlations = selection_inputs([*auth_sequence(), uncovered_detection()])
    bridge = load_incident_builder()

    incidents = bridge.build_selected_incidents_from_results(
        correlations,
        deduped,
        observation_scenario_name="bounded-selection-test",
        observation_incident_severity="low",
    )

    correlation_incident, observation_incident = incidents
    assert correlation_incident["scenario_name"] == "auth_then_authorized_keys"
    assert correlation_incident["severity"] == "high"
    assert observation_incident["scenario_name"] == "bounded-selection-test"
    assert observation_incident["severity"] == "low"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"observation_scenario_name": " "},
        {"observation_incident_severity": "unknown"},
    ],
)
@pytest.mark.parametrize("detections", [[], auth_sequence()])
def test_observation_adapter_parameters_are_validated_without_fallback(
    detections: list[dict],
    kwargs: dict,
) -> None:
    deduped, correlations = selection_inputs(detections)
    bridge = load_incident_builder()

    with pytest.raises(bridge.IncidentBoundaryValidationError):
        bridge.build_selected_incidents_from_results(correlations, deduped, **kwargs)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("detections_not_list", "canonical detection output must be a list"),
        ("incomplete_detection", "missing canonical fields"),
        ("duplicate_detection", "duplicate detection id"),
        ("invalid_timestamp", "valid ISO-8601 timestamp"),
        ("semantic_duplicate", "do not match deterministic dedupe output"),
        ("nondeterministic_order", "do not match deterministic dedupe output"),
        ("correlations_not_list", "correlation output must be a list"),
        ("malformed_correlation", "missing correlation fields"),
        ("unknown_support", "references unknown detection id"),
        ("changed_support", "supporting detection differs from input"),
        ("invented_evidence", "evidence_refs must equal supporting detection refs"),
        ("missing_raw", "raw_event_refs must equal supporting detection refs"),
        ("invalid_window", "time window must contain valid timestamps"),
    ],
)
def test_invalid_selection_inputs_fail_closed(mutation: str, message: str) -> None:
    deduped, correlations = selection_inputs(auth_sequence())
    invalid_deduped: object = deepcopy(deduped)
    invalid_correlations: object = deepcopy(correlations)
    if mutation == "detections_not_list":
        invalid_deduped = {}
    elif mutation == "incomplete_detection":
        invalid_deduped = [{"id": "incomplete"}]
    elif mutation == "duplicate_detection":
        invalid_deduped[1]["id"] = invalid_deduped[0]["id"]
    elif mutation == "invalid_timestamp":
        invalid_deduped[0]["time_window_start"] = "not-a-timestamp"
    elif mutation == "semantic_duplicate":
        duplicate = deepcopy(invalid_deduped[0])
        duplicate["id"] = "det-semantic-duplicate"
        duplicate.pop("duplicate_count")
        invalid_deduped[0].pop("duplicate_count")
        invalid_deduped.insert(1, duplicate)
    elif mutation == "nondeterministic_order":
        invalid_deduped.reverse()
    elif mutation == "correlations_not_list":
        invalid_correlations = {}
    elif mutation == "malformed_correlation":
        invalid_correlations = [{"correlation_id": "incomplete"}]
    elif mutation == "unknown_support":
        invalid_correlations[0]["supporting_detections"]["ssh_failed_login"][0]["id"] = (
            "det-unknown"
        )
    elif mutation == "changed_support":
        invalid_correlations[0]["supporting_detections"]["ssh_failed_login"][0]["title"] = "Changed"
    elif mutation == "invented_evidence":
        invalid_correlations[0]["evidence_refs"].append("invented")
        invalid_correlations[0]["evidence_refs"].sort()
    elif mutation == "missing_raw":
        invalid_correlations[0]["raw_event_refs"] = invalid_correlations[0]["raw_event_refs"][1:]
    elif mutation == "invalid_window":
        invalid_correlations[0]["time_window_start"] = "not-a-timestamp"
    bridge = load_incident_builder()

    with pytest.raises(bridge.IncidentBoundaryValidationError, match=message):
        bridge.build_selected_incidents_from_results(
            invalid_correlations,
            invalid_deduped,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_correlation",
        "missing_observation",
        "covered_observation",
        "unknown_observation",
        "duplicate_incident_id",
        "schema_invalid",
        "swapped_order",
        "changed_correlation_id",
        "changed_correlation_type",
        "observation_count",
    ],
)
def test_combined_semantic_validation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    deduped, correlations = selection_inputs([*auth_sequence(), uncovered_detection()])
    bridge = load_incident_builder()
    valid_correlations = bridge.build_correlation_incidents_from_results(correlations, deduped)
    uncovered = [item for item in deduped if item["id"] == "det-uncovered"]
    valid_observations = bridge.build_observation_incidents_from_detections(uncovered)
    correlation_incidents = deepcopy(valid_correlations)
    observation_incidents = deepcopy(valid_observations)
    if mutation == "missing_correlation":
        correlation_incidents = []
    elif mutation == "missing_observation":
        observation_incidents = []
    elif mutation == "covered_observation":
        observation_incidents[0]["matched_detection_ids"] = ["det-failed"]
    elif mutation == "unknown_observation":
        observation_incidents[0]["matched_detection_ids"] = ["det-unknown"]
    elif mutation == "duplicate_incident_id":
        observation_incidents[0]["incident_id"] = correlation_incidents[0]["incident_id"]
    elif mutation == "schema_invalid":
        observation_incidents = [{"incident_id": "inc-000001"}]
    elif mutation == "swapped_order":
        correlation_incidents = deepcopy(valid_observations)
        observation_incidents = deepcopy(valid_correlations)
    elif mutation == "changed_correlation_id":
        correlation_incidents[0]["incident_id"] = "inc-corr-changed"
    elif mutation == "changed_correlation_type":
        correlation_incidents[0]["correlation_type"] = "changed"
    elif mutation == "observation_count":
        observation_incidents.append(deepcopy(observation_incidents[0]))

    monkeypatch.setattr(
        bridge,
        "build_correlation_incidents_from_results",
        lambda *args, **kwargs: correlation_incidents,
    )
    monkeypatch.setattr(
        bridge,
        "build_observation_incidents_from_detections",
        lambda *args, **kwargs: observation_incidents,
    )

    with pytest.raises(bridge.IncidentBoundaryValidationError):
        bridge.build_selected_incidents_from_results(correlations, deduped)


def test_selection_does_not_modify_inputs_or_add_attacker_evidence() -> None:
    deduped, correlations = selection_inputs(
        [*auth_sequence(), *key_exec_sequence(), uncovered_detection()]
    )
    original_deduped = deepcopy(deduped)
    original_correlations = deepcopy(correlations)
    bridge = load_incident_builder()

    incidents = bridge.build_selected_incidents_from_results(correlations, deduped)

    assert deduped == original_deduped
    assert correlations == original_correlations
    assert collect_keys(incidents).isdisjoint(FORBIDDEN_INCIDENT_KEYS)
    serialized = json.dumps(incidents)
    assert all(marker not in serialized for marker in FORBIDDEN_ATTACKER_MARKERS)


def test_linux_scenario_009_falls_back_without_detection_loss() -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    detections = run_common_detection_pipeline(endpoint_events, [load_rule(LINUX_RULE_PATH)])
    deduped, correlations = selection_inputs(detections)
    bridge = load_incident_builder()

    incidents = bridge.build_selected_incidents_from_results(correlations, deduped)

    assert len(deduped) == 1
    assert correlations == []
    assert [incident["incident_id"] for incident in incidents] == ["inc-000001"]
    assert incidents[0]["matched_detection_ids"] == [deduped[0]["id"]]


@pytest.mark.parametrize(
    ("fixture_name", "expected_count"),
    [
        ("sysmon-event1-ordinary-powershell-001.json", 1),
        ("sysmon-event1-encoded-flag-001.json", 2),
        ("sysmon-event1-ordinary-notepad-001.json", 0),
    ],
)
def test_windows_fixture_selection_preserves_observation_policy(
    fixture_name: str,
    expected_count: int,
) -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / fixture_name)
    endpoint_events = {"schema_version": "endpoint_events.v1", "events": [event]}
    rules = [load_rule(path) for path in WINDOWS_RULE_PATHS]
    detections = run_common_detection_pipeline(endpoint_events, rules)
    deduped, correlations = selection_inputs(detections)
    bridge = load_incident_builder()

    incidents = bridge.build_selected_incidents_from_results(
        correlations,
        deduped,
        observation_incident_severity="low",
    )

    assert len(deduped) == expected_count
    assert correlations == []
    assert [incident["incident_id"] for incident in incidents] == [
        f"inc-{index:06d}" for index in range(1, expected_count + 1)
    ]
    assert all(incident["severity"] == "low" for incident in incidents)
    assert represented_detection_ids(incidents) == {item["id"] for item in deduped}


def test_existing_builders_retain_their_identity_policies() -> None:
    deduped, correlations = selection_inputs([*auth_sequence(), uncovered_detection()])
    bridge = load_incident_builder()

    correlation_incidents = bridge.build_correlation_incidents_from_results(
        correlations,
        deduped,
    )
    observation_incidents = bridge.build_observation_incidents_from_detections(
        deduped,
        incident_severity="low",
    )

    assert correlation_incidents[0]["incident_id"] == "inc-corr-auth-persistence-000001"
    assert [incident["incident_id"] for incident in observation_incidents] == [
        "inc-000001",
        "inc-000002",
        "inc-000003",
        "inc-000004",
    ]
