import importlib.util
from copy import deepcopy
from pathlib import Path

import pytest

from detection.compiler.pipeline import run_common_correlation_stage

INCIDENT_BUILDER_PATH = Path("agents/incident-builder-agent/src/main.py")


def load_incident_builder():
    spec = importlib.util.spec_from_file_location(
        "common_incident_selection_trust_builder",
        INCIDENT_BUILDER_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def detection(
    detection_id: str,
    artifact: str,
    timestamp: str,
    *,
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
        "host": "fixture-host",
        "user": "fixture-user",
        "src_ip": "192.0.2.10",
        "path": None,
        "command_line": "/bin/id" if artifact == "process_exec" else None,
        "behavior_features": {f"{artifact}_observed": True},
        "evidence_refs": [f"evidence.json#{detection_id}"],
        "raw_event_refs": [f"input[{detection_id}]"],
        "time_window_start": timestamp,
        "time_window_end": timestamp,
    }


def auth_sequence() -> list[dict]:
    failed = detection("det-failed", "ssh_failed_login", "2026-08-01T00:00:00Z")
    success = detection("det-success", "ssh_success_login", "2026-08-01T00:00:10Z")
    authorized = detection(
        "det-authorized-keys",
        "authorized_keys_modification",
        "2026-08-01T00:00:20Z",
    )
    authorized["src_ip"] = None
    authorized["path"] = "/home/fixture-user/.ssh/authorized_keys"
    return [failed, success, authorized]


def fake_auth_correlation(power_shell_detection: dict) -> dict:
    return {
        "correlation_id": "corr-auth-persistence-999999",
        "correlation_type": "auth_then_authorized_keys",
        "title": "Fabricated auth persistence correlation",
        "primary_artifact": power_shell_detection["artifact"],
        "severity": "high",
        "host": power_shell_detection["host"],
        "user": power_shell_detection["user"],
        "src_ip": power_shell_detection["src_ip"],
        "artifacts": [power_shell_detection["artifact"]],
        "behavior_features": deepcopy(power_shell_detection["behavior_features"]),
        "supporting_detections": {
            power_shell_detection["artifact"]: [deepcopy(power_shell_detection)]
        },
        "evidence_refs": sorted(power_shell_detection["evidence_refs"]),
        "raw_event_refs": sorted(power_shell_detection["raw_event_refs"]),
        "time_window_start": power_shell_detection["time_window_start"],
        "time_window_end": power_shell_detection["time_window_end"],
    }


@pytest.mark.parametrize(
    "api_name",
    [
        "build_correlation_incidents_from_results",
        "build_selected_incidents_from_results",
    ],
)
def test_structurally_valid_fabricated_correlation_is_rejected(api_name: str) -> None:
    power_shell = detection(
        "det-powershell",
        "powershell_process",
        "2026-08-01T00:00:00Z",
    )
    deduped, correlations = run_common_correlation_stage([power_shell])
    assert correlations == []
    bridge = load_incident_builder()

    with pytest.raises(
        bridge.IncidentBoundaryValidationError,
        match="do not match deterministic fixed-policy output",
    ):
        getattr(bridge, api_name)([fake_auth_correlation(deduped[0])], deduped)


@pytest.mark.parametrize(
    "mutation",
    [
        "host",
        "evidence_refs",
        "raw_event_refs",
        "timeline_evidence_refs",
        "matched_rules",
        "behavior_features",
    ],
)
def test_selected_observation_evidence_mutation_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    deduped, correlations = run_common_correlation_stage(
        [detection("det-uncovered", "process_exec", "2026-08-01T00:02:00Z")]
    )
    bridge = load_incident_builder()
    original_builder = bridge.build_observation_incidents_from_detections

    def broken_builder(*args: object, **kwargs: object) -> list[dict]:
        incidents = original_builder(*args, **kwargs)
        incident = incidents[0]
        if mutation == "host":
            incident["host"] = "other-host"
        elif mutation == "evidence_refs":
            incident["evidence_refs"] = ["invented#evidence"]
        elif mutation == "raw_event_refs":
            incident["raw_event_refs"] = ["invented#raw"]
        elif mutation == "timeline_evidence_refs":
            incident["timeline"][0]["evidence_refs"] = ["invented#timeline"]
        elif mutation == "matched_rules":
            incident["matched_rules"] = ["invented.rule"]
        elif mutation == "behavior_features":
            incident["behavior_features"] = {"invented": True}
        return incidents

    monkeypatch.setattr(
        bridge,
        "build_observation_incidents_from_detections",
        broken_builder,
    )

    with pytest.raises(bridge.IncidentBoundaryValidationError):
        bridge.build_selected_incidents_from_results(correlations, deduped)


@pytest.mark.parametrize(
    "mutation",
    ["host", "evidence_refs", "timeline_evidence_refs", "matched_rules", "behavior_features"],
)
def test_observation_builder_semantic_validation_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    bridge = load_incident_builder()
    original_builder = bridge.build_detection_hit_incident

    def broken_builder(*args: object, **kwargs: object) -> dict:
        incident = original_builder(*args, **kwargs)
        if mutation == "host":
            incident["host"] = "other-host"
        elif mutation == "evidence_refs":
            incident["evidence_refs"] = ["invented#evidence"]
        elif mutation == "timeline_evidence_refs":
            incident["timeline"][0]["evidence_refs"] = ["invented#timeline"]
        elif mutation == "matched_rules":
            incident["matched_rules"] = ["invented.rule"]
        elif mutation == "behavior_features":
            incident["behavior_features"] = {"invented": True}
        return incident

    monkeypatch.setattr(bridge, "build_detection_hit_incident", broken_builder)

    with pytest.raises(bridge.IncidentBoundaryValidationError):
        bridge.build_observation_incidents_from_detections(
            [detection("det-only", "process_exec", "2026-08-01T00:02:00Z")]
        )
