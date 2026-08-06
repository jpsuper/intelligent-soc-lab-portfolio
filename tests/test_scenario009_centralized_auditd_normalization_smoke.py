import json
import sys
from pathlib import Path

from jsonschema import validate

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agents/parser-agent/src"))

from auditd_endpoint_event_converter import convert_auditd_events  # noqa: E402
from auditd_parser import parse_auditd_log  # noqa: E402

FIXTURE_DIR = Path("tests/fixtures/scenario_009_suspicious_archive_staging")
RAW_AUDITD_FIXTURE = FIXTURE_DIR / "centralized_auditd_smoke.txt"
SYNTHETIC_ENDPOINT_FIXTURE = FIXTURE_DIR / "endpoint_events.json"
ENDPOINT_SCHEMA_PATH = Path("schemas/endpoint_events.schema.json")
SOURCE_ARTIFACT = "/var/log/remote/ubuntu-victim01/auditd.log"
SCENARIO_AUDIT_KEY = "scenario009_audit_smoke"
GENERATED_AT = "2026-07-10T22:00:00Z"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def scenario_evidence_events(auditd_events: list[dict]) -> list[dict]:
    return [
        event
        for event in auditd_events
        if event.get("audit_key") == SCENARIO_AUDIT_KEY
        and event.get("success") is True
        and event.get("event_type") == "file_write"
    ]


def by_serial(events: list[dict]) -> dict[str, dict]:
    return {str(event["audit_serial"]): event for event in events}


def event_by_suffix(events: list[dict], suffix: str) -> dict:
    matches = [event for event in events if str(event.get("file_path", "")).endswith(suffix)]
    assert len(matches) == 1
    return matches[0]


def assert_path_record(event: dict, suffix: str, nametype: str) -> None:
    paths = event["source_fields"]["paths"]
    assert any(
        str(path.get("name", "")).endswith(suffix) and path.get("nametype") == nametype
        for path in paths
    )


def test_scenario009_centralized_auditd_normalizes_to_endpoint_events() -> None:
    auditd_events = parse_auditd_log(RAW_AUDITD_FIXTURE)
    auditd_by_serial = by_serial(auditd_events)

    assert {"10309", "10310", "10311", "10313", "10317"}.issubset(auditd_by_serial)
    assert auditd_by_serial["10310"]["raw_record_count"] == 5
    assert len(auditd_by_serial["10310"]["paths"]) == 2
    assert {path["nametype"] for path in auditd_by_serial["10310"]["paths"]} == {
        "PARENT",
        "CREATE",
    }

    grep_events = [event for event in auditd_events if event.get("comm") == "grep"]
    assert len(grep_events) == 1
    assert grep_events[0]["event_type"] == "process_exec"

    scenario_events = scenario_evidence_events(auditd_events)
    assert [event["audit_serial"] for event in scenario_events] == [
        "10309",
        "10310",
        "10311",
        "10313",
        "10317",
    ]
    assert "10400" not in {event["audit_serial"] for event in scenario_events}
    assert "10401" not in {event["audit_serial"] for event in scenario_events}
    assert "10403" not in {event["audit_serial"] for event in scenario_events}

    envelope = convert_auditd_events(
        scenario_events,
        source_artifact=SOURCE_ARTIFACT,
        source_run_id="scenario-009-centralized-auditd-smoke",
        generated_at=GENERATED_AT,
    )
    validate(instance=envelope, schema=load_json(ENDPOINT_SCHEMA_PATH))

    assert envelope["metadata"]["input_event_count"] == 5
    assert envelope["metadata"]["output_event_count"] == 5
    assert {event["event_type"] for event in envelope["events"]} == {"file_write"}

    serialized = json.dumps(envelope)
    assert "ATTACK_EVENT_JSON" not in serialized
    assert "staging_directory_created" not in serialized
    assert "staged_file_written" not in serialized
    assert "archive_created" not in serialized
    assert "archive_permission_changed" not in serialized

    mkdir_event = event_by_suffix(envelope["events"], "/staging")
    note_event = event_by_suffix(envelope["events"], "/staging/note.txt")
    metadata_event = event_by_suffix(envelope["events"], "/staging/metadata.json")
    tar_event = [
        event
        for event in envelope["events"]
        if event.get("process_name") == "tar"
        and str(event.get("file_path", "")).endswith("/staged_synthetic_files.tar.gz")
    ][0]
    chmod_event = [
        event
        for event in envelope["events"]
        if event.get("process_name") == "chmod"
        and str(event.get("file_path", "")).endswith("/staged_synthetic_files.tar.gz")
    ][0]

    assert mkdir_event["file_action"] == "directory_create"
    assert note_event["file_action"] == "write_create_truncate"
    assert metadata_event["file_action"] == "write_create_truncate"
    assert tar_event["file_action"] == "write_create"
    assert chmod_event["file_action"] == "attribute_change"

    assert tar_event["process_name"] == "tar"
    assert tar_event["exe"] == "/usr/bin/tar"
    assert "tar" in tar_event["command_line"]
    assert "-czf" in tar_event["command_line"]
    assert "-C" in tar_event["command_line"]
    assert "staged_synthetic_files.tar.gz" in tar_event["command_line"]
    assert tar_event["command_line"].endswith("-C /tmp/ai_soc_lab_scenario_009_audit_smoke/stag")
    assert "note.txt" not in tar_event["command_line"]

    assert chmod_event["process_name"] == "chmod"
    assert chmod_event["exe"] == "/usr/bin/chmod"
    assert "chmod" in chmod_event["command_line"]
    assert "0640" in chmod_event["command_line"]
    assert "staged_synthetic_files.tar.gz" in chmod_event["command_line"]

    assert_path_record(note_event, "/staging", "PARENT")
    assert_path_record(note_event, "/staging/note.txt", "CREATE")
    assert_path_record(metadata_event, "/staging/metadata.json", "CREATE")
    assert_path_record(tar_event, "/staged_synthetic_files.tar.gz", "CREATE")
    assert_path_record(chmod_event, "/staged_synthetic_files.tar.gz", "NORMAL")

    for event in envelope["events"]:
        assert event["host"] == "ubuntu-victim01"
        assert event["user"] == "victim01"
        assert event["uid"] == "1000"
        assert event["raw_ref"]["source_artifact"] == SOURCE_ARTIFACT
        assert event["source_fields"]["program"] == "auditd"
        assert event["source_fields"]["audit_key"] == SCENARIO_AUDIT_KEY

    synthetic = load_json(SYNTHETIC_ENDPOINT_FIXTURE)
    synthetic_paths = {
        Path(event["file_path"]).name for event in synthetic["events"] if event.get("file_path")
    }
    live_paths = {
        Path(event["file_path"]).name for event in envelope["events"] if event.get("file_path")
    }
    assert {"note.txt", "metadata.json", "staged_synthetic_files.tar.gz"}.issubset(live_paths)
    assert {"note.txt", "metadata.json", "staged_synthetic_files.tar.gz"}.issubset(synthetic_paths)
    assert any(event["process_name"] == "tar" for event in synthetic["events"])
    assert tar_event["process_name"] == "tar"
    assert any(event["process_name"] == "chmod" for event in synthetic["events"])
    assert chmod_event["process_name"] == "chmod"
