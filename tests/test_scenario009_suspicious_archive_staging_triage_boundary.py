import importlib.util
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

from detection.compiler.evaluator import evaluate_rules_against_events
from detection.compiler.loader import load_rule

FIXTURE_PATH = Path("tests/fixtures/scenario_009_suspicious_archive_staging/endpoint_events.json")
RULE_PATH = Path("detection/dsl/suspicious_archive_staging.yaml")
INCIDENT_BUILDER_PATH = Path("agents/incident-builder-agent/src/main.py")
RULE_TRIAGE_PATH = Path("agents/rule-triage-agent/src/main.py")
AI_TRIAGE_PATH = Path("agents/ai-triage-agent/src/main.py")
TRIAGE_SCHEMA_PATH = Path("agents/ai-triage-agent/schemas/triage_schema.json")

FORBIDDEN_TRIAGE_FIELDS = {
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

ATTACKER_SIDE_EFFECTS = {
    "staging_directory_created",
    "staged_file_written",
    "archive_created",
    "archive_permission_changed",
    "ATTACK_EVENT_JSON",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_module(name: str, path: Path, import_path: Path | None = None):
    if import_path is not None:
        sys.path.insert(0, str(import_path))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if import_path is not None:
            sys.path.remove(str(import_path))


def build_scenario009_incident() -> dict:
    fixture = load_json(FIXTURE_PATH)
    rule = load_rule(RULE_PATH)
    detections = evaluate_rules_against_events(fixture["events"], [rule])
    assert len(detections) == 1

    bridge = load_module("incident_builder_main", INCIDENT_BUILDER_PATH)
    return bridge.build_detection_hit_incident(
        detections[0],
        idx=1,
        scenario_name="scenario_009_suspicious_archive_staging",
    )


def test_scenario009_triage_prompt_keeps_archive_staging_evidence_bounded() -> None:
    incident = build_scenario009_incident()
    ai_triage = load_module(
        "ai_triage_main",
        AI_TRIAGE_PATH,
        import_path=AI_TRIAGE_PATH.parent,
    )

    prompt = ai_triage.build_messages(incident, prompt_file=None)

    assert "Observed suspicious archive staging behavior" in prompt
    assert '"archive_creation": true' in prompt
    assert '"exfiltration_observed": false' in prompt
    assert '"credential_access_observed": false' in prompt
    assert '"ransomware_behavior_observed": false' in prompt
    assert "No file content inspection is represented by this incident." in prompt
    assert "No network transfer observed." in prompt
    assert "No exfiltration observed." in prompt
    assert "No live auditd, Wazuh, or SIEM collection is proven by this fixture." in prompt
    assert "archive_permission_change_observed" in prompt
    assert '"raw_event_refs": [\n    "input[3]"\n  ]' in prompt

    for attacker_side_effect in ATTACKER_SIDE_EFFECTS:
        assert attacker_side_effect not in prompt
    for forbidden_field in FORBIDDEN_TRIAGE_FIELDS:
        assert forbidden_field not in prompt


def test_scenario009_rule_triage_does_not_escalate_to_download_execute_claims() -> None:
    incident = build_scenario009_incident()
    rule_triage = load_module(
        "rule_triage_main",
        RULE_TRIAGE_PATH,
        import_path=RULE_TRIAGE_PATH.parent,
    )

    triage = rule_triage.build_output(incident)

    Draft202012Validator(load_json(TRIAGE_SCHEMA_PATH)).validate(triage)

    assert triage["incident_id"] == incident["incident_id"]
    assert triage["attack_id"] is None
    assert triage["verdict"] == "benign"
    assert triage["confidence"] == "low"
    assert triage["priority"] == "P3"
    assert triage["risk_score"] == 10
    assert triage["derived_features"] == {
        "download_and_execute_chain": False,
        "high_risk_execution_flow": False,
        "external_payload_source": False,
    }
    assert triage["derived_features_extra"] == []
    assert triage["recommended_actions"] == []

    serialized = json.dumps(triage).lower()

    for attacker_side_effect in ATTACKER_SIDE_EFFECTS:
        assert attacker_side_effect.lower() not in serialized
    for forbidden_field in FORBIDDEN_TRIAGE_FIELDS:
        assert forbidden_field not in triage

    unsupported_positive_claims = [
        "exfiltration confirmed",
        "confirmed exfiltration",
        "ransomware behavior observed",
        "credential access observed",
        "confirmed compromise",
        "live auditd coverage",
        "live wazuh coverage",
        "live siem coverage",
    ]

    for claim in unsupported_positive_claims:
        assert claim not in serialized
