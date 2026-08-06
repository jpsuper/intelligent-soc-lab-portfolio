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
INVESTIGATION_PATH = Path("agents/investigation-agent/src/main.py")
INVESTIGATION_SCHEMA_PATH = Path("schemas/investigation_result_schema.json")

FORBIDDEN_INVESTIGATION_FIELDS = {
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


def scenario009_triage_result(incident: dict) -> dict:
    return {
        "triage_id": f"triage-{incident['incident_id']}",
        "incident_id": incident["incident_id"],
        "attack_id": None,
        "verdict": "benign",
        "confidence": "low",
        "priority": "P3",
        "risk_score": 10,
        "summary": "Boundary triage did not escalate archive staging into a confirmed outcome.",
        "attack_story": [],
        "key_observations": [],
        "derived_features": {
            "download_and_execute_chain": False,
            "high_risk_execution_flow": False,
            "external_payload_source": False,
        },
        "derived_features_extra": [],
        "mitre_attack": [],
        "recommended_actions": [],
    }


def test_scenario009_investigation_stays_evidence_bounded() -> None:
    fixture = load_json(FIXTURE_PATH)
    incident = build_scenario009_incident()
    investigation = load_module(
        "investigation_main_scenario009",
        INVESTIGATION_PATH,
        import_path=INVESTIGATION_PATH.parent,
    )

    result = investigation.build_investigation_result(
        incident=incident,
        triage_result=scenario009_triage_result(incident),
        endpoint_events=fixture,
        endpoint_events_source=str(FIXTURE_PATH),
    )

    Draft202012Validator(load_json(INVESTIGATION_SCHEMA_PATH)).validate(result)

    assert result["incident_id"] == incident["incident_id"]
    assert result["triage_id"] == f"triage-{incident['incident_id']}"
    assert result["attack_id"] is None
    assert result["source_inputs"]["endpoint_events_json"] == str(FIXTURE_PATH)
    assert result["evidence"]["endpoint_event_count"] == len(fixture["events"])
    assert result["evidence"]["archive_staging_rule"] == ("collection.suspicious_archive_staging")
    assert result["evidence"]["archive_creation_observed"] is True
    assert result["evidence"]["local_staging_path_observed"] is True
    assert result["evidence"]["synthetic_file_staging_observed"] is True
    assert result["evidence"]["chmod_event_present_in_fixture"] is True
    assert result["evidence"]["chmod_correlated_by_detection_rule"] is False
    assert "archive_staging_behavior_observed" in result["enriched_features"]
    assert "archive_creation_observed" in result["enriched_features"]
    assert "local_archive_staging_path_observed" in result["enriched_features"]

    summary_and_story = f"{result['summary']} {result['attack_story']}"
    assert "suspicious local archive staging" in summary_and_story
    assert "Archive creation was observed" in summary_and_story
    assert "Possible preparation for collection remains a hypothesis" in summary_and_story
    assert "collection.suspicious_archive_staging" in summary_and_story
    assert "does not correlate that permission change" in summary_and_story

    observed_facts = result["evidence_summary"]["observed_facts"]
    supporting_signals = result["evidence_summary"]["supporting_signals"]
    evidence_gaps = result["evidence_summary"]["evidence_gaps"]
    assert any("tar -czf" in fact for fact in observed_facts)
    assert any("staged_synthetic_files.tar.gz" in fact for fact in observed_facts)
    assert (
        "Suspicious local archive staging was observed from defender-side evidence."
        in observed_facts
    )
    assert "Matched detection rule: collection.suspicious_archive_staging." in supporting_signals
    assert any("chmod event is present" in signal for signal in supporting_signals)
    assert "No file content inspection was present in evidence." in evidence_gaps
    assert "No network transfer was observed." in evidence_gaps
    assert "No exfiltration was observed." in evidence_gaps
    assert "No destination host or external endpoint was observed." in evidence_gaps
    assert (
        "No live auditd, Wazuh, or SIEM telemetry source is proven by this synthetic fixture."
        in evidence_gaps
    )

    timeline = "\n".join(result["timeline_notes"])
    assert "mkdir -p" in timeline
    assert "staging/note.txt" in timeline
    assert "staging/metadata.json" in timeline
    assert "tar -czf" in timeline
    assert "chmod 0640" in timeline

    unsupported = json.dumps(result["unsupported_claims"]).lower()
    assert "exfiltration" in unsupported
    assert "file contents" in unsupported
    assert "live auditd, wazuh, or siem" in unsupported
    assert "current evidence supports suspicious archive staging only" in unsupported

    serialized = json.dumps(result).lower()
    for attacker_side_effect in ATTACKER_SIDE_EFFECTS:
        assert attacker_side_effect.lower() not in serialized
    for forbidden_field in FORBIDDEN_INVESTIGATION_FIELDS:
        assert forbidden_field not in result

    unsupported_positive_claims = [
        "confirmed exfiltration",
        "exfiltration occurred",
        "ransomware behavior observed",
        "credential access observed",
        "confirmed compromise",
        "real data collection",
        "live auditd coverage",
        "live wazuh coverage",
        "live siem coverage",
        "containment approval",
        "action approval",
    ]
    for claim in unsupported_positive_claims:
        assert claim not in serialized
