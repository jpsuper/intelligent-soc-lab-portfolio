import json
from pathlib import Path

from jsonschema import validate

from detection.compiler.evaluator import evaluate_rules_against_events
from detection.compiler.loader import load_rule

FIXTURE_PATH = Path("tests/fixtures/scenario_009_suspicious_archive_staging/endpoint_events.json")
SCHEMA_PATH = Path("schemas/endpoint_events.schema.json")
RULE_PATH = Path("detection/dsl/suspicious_archive_staging.yaml")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_scenario009_endpoint_fixture_is_schema_valid_defender_telemetry() -> None:
    fixture = load_json(FIXTURE_PATH)
    schema = load_json(SCHEMA_PATH)

    validate(instance=fixture, schema=schema)

    assert fixture["metadata"]["defender_side"] is True
    serialized = json.dumps(fixture)
    assert "ATTACK_EVENT_JSON" not in serialized
    assert "staging_directory_created" not in serialized
    assert "archive_created" not in serialized


def test_scenario009_fixture_represents_archive_staging_observations() -> None:
    fixture = load_json(FIXTURE_PATH)
    events = fixture["events"]

    process_names = {event.get("process_name") for event in events}
    file_paths = {event.get("file_path") for event in events if event.get("file_path")}
    command_lines = [event.get("command_line", "") for event in events]
    process_command_lines = [
        event.get("command_line", "")
        for event in events
        if event.get("event_type") == "process_exec"
    ]

    assert {"mkdir", "tar", "chmod"}.issubset(process_names)
    assert any(path.endswith("/staging/note.txt") for path in file_paths)
    assert any(path.endswith("/staging/metadata.json") for path in file_paths)
    assert any(path.endswith("/staged_synthetic_files.tar.gz") for path in file_paths)
    assert any("tar -czf" in command for command in command_lines)
    assert any("chmod 0640" in command for command in command_lines)
    assert all(
        "/tmp/ai_soc_lab_scenario_009_suspicious_archive_staging" in command
        for command in process_command_lines
    )
    assert not Path("data/runs/scenario_009_suspicious_archive_staging").exists()


def test_scenario009_dsl_detects_archive_creation_from_defender_fixture_only() -> None:
    fixture = load_json(FIXTURE_PATH)
    rule = load_rule(RULE_PATH)

    detections = evaluate_rules_against_events(fixture["events"], [rule])

    assert len(detections) == 1
    detection = detections[0]
    assert detection["rule_id"] == "collection.suspicious_archive_staging"
    assert detection["artifact"] == "suspicious_archive_staging"
    assert detection["event_type"] == "process_exec"
    assert detection["command_line"].startswith("tar -czf ")
    assert detection["behavior_features"] == {
        "local_staging_path": True,
        "synthetic_file_staging": True,
        "archive_creation": True,
        "archive_permission_change_observed": False,
        "exfiltration_observed": False,
        "credential_access_observed": False,
        "ransomware_behavior_observed": False,
    }
    assert detection["raw_event_refs"] == ["input[3]"]
