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
        "common_correlation_incident_builder",
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


def auth_sequence(
    *,
    failed_timestamp: str = "2026-08-01T00:00:00Z",
    success_timestamp: str = "2026-08-01T00:00:10Z",
    authorized_keys_timestamp: str = "2026-08-01T00:00:20Z",
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
    key_timestamp: str = "2026-08-01T00:01:00Z",
    exec_timestamp: str = "2026-08-01T00:01:10Z",
) -> list[dict]:
    return [
        canonical_detection("det-key", "ssh_key_login", key_timestamp),
        canonical_detection("det-exec", "process_exec", exec_timestamp),
    ]


def correlation_inputs(detections: list[dict]) -> tuple[list[dict], list[dict]]:
    deduped, correlations = run_common_correlation_stage(detections)
    assert correlations
    return deduped, correlations


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


def test_auth_correlation_builds_one_schema_valid_incident() -> None:
    deduped, correlations = correlation_inputs(auth_sequence())
    bridge = load_incident_builder()

    incidents = bridge.build_correlation_incidents_from_results(correlations, deduped)

    assert len(incidents) == 1
    incident = incidents[0]
    correlation = correlations[0]
    assert incident["incident_id"] == "inc-corr-auth-persistence-000001"
    for field in (
        "correlation_id",
        "correlation_type",
        "title",
        "severity",
        "primary_artifact",
        "behavior_features",
        "evidence_refs",
        "raw_event_refs",
    ):
        assert incident[field] == correlation[field]
    assert incident["matched_detection_ids"] == [
        "det-failed",
        "det-success",
        "det-authorized-keys",
    ]
    assert incident["matched_rules"] == [
        "test.ssh_failed_login",
        "test.ssh_success_login",
        "test.authorized_keys_modification",
    ]
    assert [entry["detection_id"] for entry in incident["timeline"]] == incident[
        "matched_detection_ids"
    ]
    assert_schema_valid(incidents)


def test_key_login_process_execution_builds_ordered_incident() -> None:
    deduped, correlations = correlation_inputs(key_exec_sequence())
    bridge = load_incident_builder()

    incidents = bridge.build_correlation_incidents_from_results(correlations, deduped)

    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["incident_id"] == "inc-corr-key-exec-000001"
    assert incident["correlation_type"] == "key_login_then_process_exec"
    assert [entry["artifact"] for entry in incident["timeline"]] == [
        "ssh_key_login",
        "process_exec",
    ]
    assert incident["matched_detection_ids"] == ["det-key", "det-exec"]
    assert_schema_valid(incidents)


def test_multiple_correlations_and_all_input_orders_are_deterministic() -> None:
    detections = [
        *auth_sequence(
            failed_timestamp="2026-08-01T00:00:00Z",
            success_timestamp="2026-08-01T00:00:00+00:00",
            authorized_keys_timestamp="2026-07-31T20:00:00-04:00",
        ),
        *key_exec_sequence(
            key_timestamp="2026-08-01T00:00:00",
            exec_timestamp="2026-08-01T09:00:00+09:00",
        ),
    ]
    bridge = load_incident_builder()
    forward_deduped, forward_correlations = correlation_inputs(detections)
    reverse_deduped, reverse_correlations = correlation_inputs(list(reversed(detections)))

    forward = bridge.build_correlation_incidents_from_results(
        forward_correlations,
        forward_deduped,
    )
    reversed_detections = bridge.build_correlation_incidents_from_results(
        reverse_correlations,
        reverse_deduped,
    )
    reversed_correlations = bridge.build_correlation_incidents_from_results(
        list(reversed(forward_correlations)),
        forward_deduped,
    )

    assert forward == reversed_detections == reversed_correlations
    assert [incident["incident_id"] for incident in forward] == [
        "inc-corr-auth-persistence-000001",
        "inc-corr-key-exec-000001",
    ]
    assert len({incident["incident_id"] for incident in forward}) == 2


def test_empty_correlation_does_not_build_fallback_incident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deduped, _correlations = run_common_correlation_stage(
        [canonical_detection("det-only", "process_exec", "2026-08-01T00:00:00Z")]
    )
    bridge = load_incident_builder()
    monkeypatch.setattr(
        bridge,
        "build_correlation_incident",
        lambda correlation: pytest.fail("single-correlation builder must not be called"),
    )

    assert bridge.build_correlation_incidents_from_results([], deduped) == []


def test_merged_dedupe_output_is_accepted_without_losing_duplicate_count() -> None:
    detections = auth_sequence()
    duplicate = deepcopy(detections[0])
    duplicate["id"] = "det-failed-second-observation"
    duplicate["time_window_start"] = "2026-08-01T00:00:05Z"
    duplicate["time_window_end"] = "2026-08-01T00:00:05Z"
    duplicate["evidence_refs"] = ["evidence.json#det-failed-second-observation"]
    duplicate["raw_event_refs"] = ["input[det-failed-second-observation]"]
    detections.append(duplicate)
    deduped, correlations = correlation_inputs(detections)
    bridge = load_incident_builder()

    incidents = bridge.build_correlation_incidents_from_results(correlations, deduped)

    merged = next(item for item in deduped if item["artifact"] == "ssh_failed_login")
    assert merged["duplicate_count"] == 2
    assert len(incidents) == 1
    assert incidents[0]["timeline"][0]["detection_id"] == merged["id"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("not_list", "canonical detection output must be a list"),
        ("incomplete", "missing canonical fields"),
        ("duplicate_id", "duplicate detection id"),
        ("invalid_timestamp", "valid ISO-8601 timestamp"),
        ("semantic_duplicate", "do not match deterministic dedupe output"),
        ("wrong_order", "do not match deterministic dedupe output"),
    ],
)
def test_deduped_detection_input_validation_fails_closed(
    mutation: str,
    message: str,
) -> None:
    deduped, correlations = correlation_inputs(auth_sequence())
    invalid: object = deepcopy(deduped)
    if mutation == "not_list":
        invalid = {}
    elif mutation == "incomplete":
        invalid = [{"id": "incomplete"}]
    elif mutation == "duplicate_id":
        invalid[1]["id"] = invalid[0]["id"]
    elif mutation == "invalid_timestamp":
        invalid[0]["time_window_start"] = "not-a-timestamp"
    elif mutation == "semantic_duplicate":
        duplicate = deepcopy(invalid[0])
        duplicate["id"] = "det-semantic-duplicate"
        duplicate.pop("duplicate_count")
        invalid[0].pop("duplicate_count")
        invalid.insert(1, duplicate)
    elif mutation == "wrong_order":
        invalid.reverse()
    bridge = load_incident_builder()

    with pytest.raises(
        bridge.IncidentBoundaryValidationError,
        match=f"deduped canonical detection validation failed:.*{message}",
    ):
        bridge.build_correlation_incidents_from_results(correlations, invalid)


@pytest.mark.parametrize("duplicate_count", [True, False, 0, -1, "2", 2.0, None])
def test_invalid_duplicate_count_fails_closed(duplicate_count: object) -> None:
    deduped, correlations = correlation_inputs(auth_sequence())
    deduped[0]["duplicate_count"] = duplicate_count
    bridge = load_incident_builder()

    with pytest.raises(
        bridge.IncidentBoundaryValidationError,
        match=(
            "deduped canonical detection validation failed:.*"
            "duplicate_count must be a positive integer"
        ),
    ):
        bridge.build_correlation_incidents_from_results(correlations, deduped)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("not_list", "correlation output must be a list"),
        ("malformed", "missing correlation fields"),
        ("duplicate_id", "duplicate correlation id"),
        ("unknown_type", "correlation_type is not supported"),
        ("unknown_support", "references unknown detection id"),
        ("changed_support", "supporting detection differs from input"),
        ("invented_evidence", "evidence_refs must equal supporting detection refs"),
        ("missing_raw", "raw_event_refs must equal supporting detection refs"),
        ("invalid_window", "time window must contain valid timestamps"),
        ("reversed_window", "time_window_start must not be after time_window_end"),
    ],
)
def test_correlation_result_validation_is_reused_and_wrapped(
    mutation: str,
    message: str,
) -> None:
    deduped, correlations = correlation_inputs(auth_sequence())
    invalid: object = deepcopy(correlations)
    if mutation == "not_list":
        invalid = {}
    elif mutation == "malformed":
        invalid = [{"correlation_id": "corr-incomplete"}]
    elif mutation == "duplicate_id":
        invalid.append(deepcopy(invalid[0]))
    elif mutation == "unknown_type":
        invalid[0]["correlation_type"] = "unknown"
    elif mutation == "unknown_support":
        invalid[0]["supporting_detections"]["ssh_failed_login"][0]["id"] = "det-unknown"
    elif mutation == "changed_support":
        invalid[0]["supporting_detections"]["ssh_failed_login"][0]["title"] = "Changed"
    elif mutation == "invented_evidence":
        invalid[0]["evidence_refs"].append("invented")
        invalid[0]["evidence_refs"].sort()
    elif mutation == "missing_raw":
        invalid[0]["raw_event_refs"] = invalid[0]["raw_event_refs"][1:]
    elif mutation == "invalid_window":
        invalid[0]["time_window_start"] = "not-a-timestamp"
    elif mutation == "reversed_window":
        invalid[0]["time_window_start"] = "2026-08-02T00:00:00Z"
    bridge = load_incident_builder()

    with pytest.raises(
        bridge.IncidentBoundaryValidationError,
        match=f"correlation result validation failed:.*{message}",
    ):
        bridge.build_correlation_incidents_from_results(invalid, deduped)


@pytest.mark.parametrize(
    "mutation",
    [
        "schema_invalid",
        "incident_id",
        "correlation_id",
        "correlation_type",
        "missing_support",
        "duplicate_timeline_id",
        "invented_evidence",
        "behavior_features",
        "empty_timeline",
    ],
)
def test_incident_output_validation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    deduped, correlations = correlation_inputs(auth_sequence())
    bridge = load_incident_builder()
    original_builder = bridge.build_correlation_incident

    def broken_builder(correlation: dict) -> dict:
        if mutation == "schema_invalid":
            return {"incident_id": "invalid"}
        incident = original_builder(correlation)
        if mutation == "incident_id":
            incident["incident_id"] = "inc-random"
        elif mutation == "correlation_id":
            incident["correlation_id"] = "corr-changed"
        elif mutation == "correlation_type":
            incident["correlation_type"] = "changed"
        elif mutation == "missing_support":
            incident["matched_detection_ids"] = incident["matched_detection_ids"][1:]
        elif mutation == "duplicate_timeline_id":
            incident["timeline"][1]["detection_id"] = incident["timeline"][0]["detection_id"]
        elif mutation == "invented_evidence":
            incident["evidence_refs"].append("invented")
        elif mutation == "behavior_features":
            incident["behavior_features"]["invented"] = True
        elif mutation == "empty_timeline":
            incident["timeline"] = []
        return incident

    monkeypatch.setattr(bridge, "build_correlation_incident", broken_builder)

    with pytest.raises(bridge.IncidentBoundaryValidationError):
        bridge.build_correlation_incidents_from_results(correlations, deduped)


def test_inputs_are_not_modified_and_evidence_boundary_is_bounded() -> None:
    deduped, correlations = correlation_inputs([*auth_sequence(), *key_exec_sequence()])
    original_deduped = deepcopy(deduped)
    original_correlations = deepcopy(correlations)
    bridge = load_incident_builder()

    incidents = bridge.build_correlation_incidents_from_results(correlations, deduped)

    assert deduped == original_deduped
    assert correlations == original_correlations
    serialized = json.dumps(incidents)
    summary_and_notes = " ".join([incidents[0]["summary"], *incidents[0]["notes"]]).lower()
    assert "defender-side correlation" in summary_and_notes
    assert "does not prove compromise" in summary_and_notes
    assert "no response action" in summary_and_notes
    assert collect_keys(incidents).isdisjoint(FORBIDDEN_INCIDENT_KEYS)
    assert all(marker not in serialized for marker in FORBIDDEN_ATTACKER_MARKERS)
    assert all(incident["mitre_attack"] == [] for incident in incidents)


def test_linux_scenario_009_has_no_correlation_incident() -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    detections = run_common_detection_pipeline(endpoint_events, [load_rule(LINUX_RULE_PATH)])
    deduped, correlations = run_common_correlation_stage(detections)
    bridge = load_incident_builder()

    incidents = bridge.build_correlation_incidents_from_results(correlations, deduped)

    assert len(deduped) == 1
    assert correlations == []
    assert incidents == []


@pytest.mark.parametrize(
    ("fixture_name", "expected_count"),
    [
        ("sysmon-event1-ordinary-powershell-001.json", 1),
        ("sysmon-event1-encoded-flag-001.json", 2),
        ("sysmon-event1-ordinary-notepad-001.json", 0),
    ],
)
def test_windows_fixtures_have_no_correlation_incidents(
    fixture_name: str,
    expected_count: int,
) -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / fixture_name)
    endpoint_events = {"schema_version": "endpoint_events.v1", "events": [event]}
    rules = [load_rule(path) for path in WINDOWS_RULE_PATHS]
    detections = run_common_detection_pipeline(endpoint_events, rules)
    deduped, correlations = run_common_correlation_stage(detections)
    bridge = load_incident_builder()

    incidents = bridge.build_correlation_incidents_from_results(correlations, deduped)

    assert len(deduped) == expected_count
    assert correlations == []
    assert incidents == []


def test_existing_observation_incident_policy_is_unchanged() -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / "sysmon-event1-encoded-flag-001.json")
    endpoint_events = {"schema_version": "endpoint_events.v1", "events": [event]}
    rules = [load_rule(path) for path in WINDOWS_RULE_PATHS]
    detections = run_common_detection_pipeline(endpoint_events, rules)
    bridge = load_incident_builder()

    incidents = bridge.build_observation_incidents_from_detections(
        detections,
        incident_severity="low",
    )

    assert [incident["incident_id"] for incident in incidents] == [
        "inc-000001",
        "inc-000002",
    ]
    assert all(incident["severity"] == "low" for incident in incidents)
