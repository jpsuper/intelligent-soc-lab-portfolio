import importlib.util
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from detection.compiler.evaluator import evaluate_rules_against_events
from detection.compiler.loader import load_rule

FIXTURE_PATH = Path("tests/fixtures/scenario_009_suspicious_archive_staging/endpoint_events.json")
RULE_PATH = Path("detection/dsl/suspicious_archive_staging.yaml")
INCIDENT_BUILDER_PATH = Path("agents/incident-builder-agent/src/main.py")
INCIDENT_SCHEMA_PATH = Path("schemas/incident_schema.json")

FORBIDDEN_INCIDENT_FIELDS = {
    "containment_approved",
    "action_approval",
    "apply_approved",
    "deployment_approved",
    "baseline_update_approved",
    "prompt_update_approved",
    "parser_update_approved",
    "telemetry_update_approved",
    "correlation_update_approved",
    "promotion_approved",
    "promotion_allowed",
    "rule_improvement_candidate_generated",
    "auto_promote",
    "mutates_state",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_incident_builder():
    spec = importlib.util.spec_from_file_location(
        "incident_builder_main",
        INCIDENT_BUILDER_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_scenario009_detection_hit_builds_observation_level_incident() -> None:
    fixture = load_json(FIXTURE_PATH)
    rule = load_rule(RULE_PATH)
    detections = evaluate_rules_against_events(fixture["events"], [rule])
    assert len(detections) == 1

    bridge = load_incident_builder()
    incident = bridge.build_detection_hit_incident(
        detections[0],
        idx=1,
        scenario_name="scenario_009_suspicious_archive_staging",
    )

    Draft202012Validator(load_json(INCIDENT_SCHEMA_PATH)).validate(incident)

    assert incident["scenario_name"] == "scenario_009_suspicious_archive_staging"
    assert incident["primary_artifact"] == "suspicious_archive_staging"
    assert incident["severity"] == "medium"
    assert incident["matched_rules"] == ["collection.suspicious_archive_staging"]
    assert incident["matched_detection_ids"] == ["det-000001"]
    assert incident["raw_event_refs"] == ["input[3]"]
    assert incident["timeline"][0]["raw_event_refs"] == ["input[3]"]
    assert incident["timeline"][0]["event_type"] == "process_exec"
    assert "tar -czf" in incident["timeline"][0]["command_line"]

    assert incident["behavior_features"] == {
        "local_staging_path": True,
        "synthetic_file_staging": True,
        "archive_creation": True,
        "archive_permission_change_observed": False,
        "exfiltration_observed": False,
        "credential_access_observed": False,
        "ransomware_behavior_observed": False,
    }

    serialized = json.dumps(incident)
    assert "staging_directory_created" not in serialized
    assert "staged_file_written" not in serialized
    assert "archive_created" not in serialized
    assert "archive_permission_changed" not in serialized
    assert "ATTACK_EVENT_JSON" not in serialized
    assert not FORBIDDEN_INCIDENT_FIELDS.intersection(incident)

    summary_and_notes = " ".join([incident["summary"], *incident["notes"]])
    assert "does not infer compromise" in summary_and_notes
    assert "No file content inspection" in summary_and_notes
    assert "No network transfer observed" in summary_and_notes
    assert "No exfiltration observed" in summary_and_notes
    assert "No live auditd, Wazuh, or SIEM collection is proven" in summary_and_notes
    assert "ransomware behavior" in summary_and_notes
    assert "credential access" in summary_and_notes
    assert "real data collection" in summary_and_notes
