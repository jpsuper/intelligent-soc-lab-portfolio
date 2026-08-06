import json
import sys
from pathlib import Path

from jsonschema import validate

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agents/parser-agent/src"))

from auditd_endpoint_event_converter import (  # noqa: E402
    convert_auditd_events,
    filter_auditd_events,
    filter_metadata,
    main,
)

SCHEMA_PATH = Path("schemas/endpoint_events.schema.json")
GENERATED_AT = "2026-06-14T00:00:00Z"


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def assert_valid_endpoint_events(envelope: dict) -> None:
    validate(instance=envelope, schema=load_schema())


def process_exec_event(**overrides: object) -> dict:
    event = {
        "source": "auditd",
        "host": "ubuntu-victim01",
        "audit_serial": "3389",
        "collector_timestamp": "2026-06-14T00:18:34+00:00",
        "audit_epoch_raw": "1781396314.485",
        "audit_timestamp": "2026-06-14T00:18:34.485Z",
        "record_types": ["SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"],
        "audit_key": "isl_execve",
        "event_type": "process_exec",
        "syscall": "execve",
        "success": True,
        "pid": 35974,
        "ppid": 34304,
        "session": "128",
        "tty": "pts0",
        "auid": "victim01",
        "auid_num": "1000",
        "uid": "victim01",
        "uid_num": "1000",
        "gid": "victim01",
        "euid": "victim01",
        "comm": "bash",
        "exe": "/usr/bin/bash",
        "cwd": "/home/victim01",
        "argv": ["bash", "-c", "whoami"],
        "argv_raw": ["bash", "2D63", "77686F616D69"],
        "proctitle": "bash -c whoami",
        "paths": [{"item": 0, "name": "/usr/bin/bash", "nametype": "NORMAL"}],
        "file_path": None,
        "file_action": None,
        "raw_record_count": 5,
    }
    event.update(overrides)
    return event


def file_write_event(**overrides: object) -> dict:
    event = process_exec_event(
        audit_serial="3390",
        audit_key="isl_tmp_marker",
        event_type="file_write",
        syscall="openat",
        comm="bash",
        exe="/usr/bin/bash",
        argv=["bash", "-c", "echo marker > /tmp/ai_soc_lab_scenario_007_marker.txt"],
        proctitle="bash -c echo marker > /tmp/ai_soc_lab_scenario_007_marker.txt",
        paths=[
            {
                "item": 1,
                "name": "/tmp/ai_soc_lab_scenario_007_marker.txt",
                "nametype": "NORMAL",
            }
        ],
        file_path="/tmp/ai_soc_lab_scenario_007_marker.txt",
        file_action="file_change",
    )
    event.update(overrides)
    return event


def persistence_event(**overrides: object) -> dict:
    event = file_write_event(
        audit_serial="3391",
        audit_key="isl_ssh_persistence",
        event_type="persistence_file_change",
        file_path="/home/victim01/.ssh/authorized_keys",
        file_action="attribute_change",
        paths=[
            {
                "item": 1,
                "name": "/home/victim01/.ssh/authorized_keys",
                "nametype": "NORMAL",
            }
        ],
    )
    event.update(overrides)
    return event


def convert_one(event: dict, source_artifact: str = "auditd_events.json") -> dict:
    envelope = convert_auditd_events(
        [event],
        source_artifact=source_artifact,
        source_run_id="run-001",
        generated_at=GENERATED_AT,
    )
    assert_valid_endpoint_events(envelope)
    return envelope


def test_convert_minimal_process_exec_to_valid_endpoint_envelope() -> None:
    envelope = convert_one(process_exec_event())
    event = envelope["events"][0]

    assert envelope["schema_version"] == "endpoint_events.v1"
    assert envelope["generated_at"] == GENERATED_AT
    assert envelope["source_artifact"] == "auditd_events.json"
    assert envelope["source_run_id"] == "run-001"
    assert envelope["metadata"] == {
        "converter": "auditd_endpoint_event_converter",
        "input_event_count": 1,
        "output_event_count": 1,
    }
    assert event["event_id"] == "auditd:ubuntu-victim01:3389"
    assert event["source"] == "auditd"
    assert event["platform"] == "linux"
    assert event["host"] == "ubuntu-victim01"
    assert event["timestamp"] == "2026-06-14T00:18:34.485Z"
    assert event["event_type"] == "process_exec"
    assert event["user"] == "victim01"
    assert event["uid"] == "1000"
    assert event["pid"] == 35974
    assert event["ppid"] == 34304
    assert event["process_name"] == "bash"
    assert event["exe"] == "/usr/bin/bash"
    assert event["argv"] == ["bash", "-c", "whoami"]
    assert event["command_line"] == "bash -c whoami"
    assert event["cwd"] == "/home/victim01"
    assert "file_path" not in event


def test_convert_file_write_preserves_file_path_and_action() -> None:
    envelope = convert_one(file_write_event())
    event = envelope["events"][0]

    assert event["event_type"] == "file_write"
    assert event["file_path"] == "/tmp/ai_soc_lab_scenario_007_marker.txt"
    assert event["file_action"] == "file_change"


def test_convert_persistence_file_change_event() -> None:
    envelope = convert_one(persistence_event(file_action=None))
    event = envelope["events"][0]

    assert event["event_type"] == "persistence_file_change"
    assert event["file_path"] == "/home/victim01/.ssh/authorized_keys"
    assert event["file_action"] == "modify"


def test_unknown_auditd_event_type_maps_to_unknown() -> None:
    envelope = convert_one(process_exec_event(event_type="audit_event"))

    assert envelope["events"][0]["event_type"] == "unknown"


def test_missing_audit_serial_produces_deterministic_non_empty_event_id() -> None:
    event = process_exec_event(audit_serial=None)
    first = convert_one(event)["events"][0]["event_id"]
    second = convert_one(event)["events"][0]["event_id"]

    assert first
    assert first == second
    assert first.startswith("auditd:ubuntu-victim01:derived:")


def test_collector_timestamp_maps_to_collection_timestamp() -> None:
    envelope = convert_one(process_exec_event())

    assert envelope["events"][0]["collection_timestamp"] == "2026-06-14T00:18:34+00:00"


def test_auditd_specific_fields_are_preserved_under_source_fields() -> None:
    envelope = convert_one(process_exec_event())
    source_fields = envelope["events"][0]["source_fields"]

    assert source_fields["audit_serial"] == "3389"
    assert source_fields["audit_key"] == "isl_execve"
    assert source_fields["syscall"] == "execve"
    assert source_fields["success"] is True
    assert source_fields["session"] == "128"
    assert source_fields["tty"] == "pts0"
    assert source_fields["auid"] == "victim01"
    assert source_fields["uid"] == "victim01"
    assert source_fields["gid"] == "victim01"
    assert source_fields["euid"] == "victim01"
    assert source_fields["proctitle"] == "bash -c whoami"
    assert source_fields["paths"] == [{"item": 0, "name": "/usr/bin/bash", "nametype": "NORMAL"}]
    assert source_fields["raw_record_count"] == 5
    assert source_fields["audit_epoch_raw"] == "1781396314.485"
    assert source_fields["audit_timestamp"] == "2026-06-14T00:18:34.485Z"
    assert source_fields["collector_timestamp"] == "2026-06-14T00:18:34+00:00"


def test_output_validates_against_endpoint_events_schema() -> None:
    envelope = convert_auditd_events(
        [process_exec_event(), file_write_event(), persistence_event()],
        source_artifact="auditd_events.json",
        generated_at=GENERATED_AT,
    )

    assert_valid_endpoint_events(envelope)


def test_cli_writes_valid_output_file(tmp_path: Path) -> None:
    input_path = tmp_path / "auditd_events.json"
    output_path = tmp_path / "endpoint_events.json"
    input_path.write_text(
        json.dumps([process_exec_event(), file_write_event()]),
        encoding="utf-8",
    )

    main(
        [
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--source-artifact",
            "auditd_events.json",
            "--source-run-id",
            "run-cli-001",
        ]
    )

    envelope = json.loads(output_path.read_text(encoding="utf-8"))
    assert envelope["source_run_id"] == "run-cli-001"
    assert envelope["metadata"]["input_event_count"] == 2
    assert envelope["metadata"]["output_event_count"] == 2
    assert_valid_endpoint_events(envelope)


def test_converter_does_not_add_assessment_like_fields() -> None:
    envelope = convert_one(process_exec_event())
    forbidden = {
        "severity",
        "confidence",
        "detected",
        "overall_result",
        "recommended_actions",
        "rule_candidates",
        "attack_story",
    }

    assert forbidden.isdisjoint(envelope)
    assert forbidden.isdisjoint(envelope["metadata"])
    for event in envelope["events"]:
        assert forbidden.isdisjoint(event)
        assert forbidden.isdisjoint(event["source_fields"])


def test_filter_auditd_events_by_include_keyword() -> None:
    events = [
        process_exec_event(
            audit_serial="1",
            argv=["whoami"],
            proctitle="whoami",
        ),
        process_exec_event(
            audit_serial="2",
            argv=["curl", "-fsS", "-o", "/tmp/scenario_006_payload.sh"],
            proctitle="curl -fsS -o /tmp/scenario_006_payload.sh",
        ),
    ]

    filtered = filter_auditd_events(
        events,
        include_keywords=["scenario_006_payload.sh"],
    )

    assert len(filtered) == 1
    assert filtered[0]["audit_serial"] == "2"


def test_filter_auditd_events_by_exclude_keyword() -> None:
    events = [
        process_exec_event(
            audit_serial="1",
            argv=["grep", "payload"],
            proctitle="grep payload",
        ),
        process_exec_event(
            audit_serial="2",
            argv=["curl", "-fsS", "-o", "/tmp/scenario_006_payload.sh"],
            proctitle="curl -fsS -o /tmp/scenario_006_payload.sh",
        ),
    ]

    filtered = filter_auditd_events(events, exclude_keywords=["grep"])

    assert len(filtered) == 1
    assert filtered[0]["audit_serial"] == "2"


def test_filter_auditd_events_by_event_type_and_audit_key() -> None:
    events = [
        process_exec_event(audit_serial="1", audit_key="isl_execve"),
        file_write_event(audit_serial="2", audit_key="isl_tmp_marker"),
        persistence_event(audit_serial="3", audit_key="isl_ssh_persistence"),
    ]

    filtered = filter_auditd_events(
        events,
        event_types=["file_write"],
        audit_keys=["isl_tmp_marker"],
    )

    assert len(filtered) == 1
    assert filtered[0]["audit_serial"] == "2"


def test_filter_auditd_events_by_since_until() -> None:
    events = [
        process_exec_event(
            audit_serial="1",
            audit_timestamp="2026-06-14T00:00:00Z",
        ),
        process_exec_event(
            audit_serial="2",
            audit_timestamp="2026-06-14T00:10:00Z",
        ),
        process_exec_event(
            audit_serial="3",
            audit_timestamp="2026-06-14T00:20:00Z",
        ),
    ]

    filtered = filter_auditd_events(
        events,
        since="2026-06-14T00:05:00Z",
        until="2026-06-14T00:15:00Z",
    )

    assert [event["audit_serial"] for event in filtered] == ["2"]


def test_filter_metadata_records_filter_criteria() -> None:
    metadata = filter_metadata(
        source_event_count=2,
        filtered_event_count=1,
        since="2026-06-14T00:00:00Z",
        until="2026-06-14T00:30:00Z",
        include_keywords=["scenario_006_payload.sh"],
        exclude_keywords=["grep"],
        event_types=["process_exec"],
        audit_keys=["isl_execve"],
    )

    assert metadata["source_event_count"] == 2
    assert metadata["filtered_event_count"] == 1
    assert metadata["filter"] == {
        "since": "2026-06-14T00:00:00Z",
        "until": "2026-06-14T00:30:00Z",
        "include_keywords": ["scenario_006_payload.sh"],
        "exclude_keywords": ["grep"],
        "event_types": ["process_exec"],
        "audit_keys": ["isl_execve"],
    }


def test_cli_applies_filters_and_records_metadata(tmp_path: Path) -> None:
    input_path = tmp_path / "auditd_events.json"
    output_path = tmp_path / "endpoint_events.json"
    input_path.write_text(
        json.dumps(
            [
                process_exec_event(
                    audit_serial="1",
                    argv=["grep", "payload"],
                    proctitle="grep payload",
                ),
                process_exec_event(
                    audit_serial="2",
                    argv=["curl", "-fsS", "-o", "/tmp/scenario_006_payload.sh"],
                    proctitle="curl -fsS -o /tmp/scenario_006_payload.sh",
                ),
            ]
        ),
        encoding="utf-8",
    )

    main(
        [
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--source-artifact",
            "auditd_events.json",
            "--include-keyword",
            "scenario_006_payload.sh",
            "--exclude-keyword",
            "grep",
            "--event-type",
            "process_exec",
            "--audit-key",
            "isl_execve",
        ]
    )

    envelope = json.loads(output_path.read_text(encoding="utf-8"))
    assert envelope["metadata"]["source_event_count"] == 2
    assert envelope["metadata"]["filtered_event_count"] == 1
    assert envelope["metadata"]["input_event_count"] == 1
    assert envelope["metadata"]["output_event_count"] == 1
    assert envelope["metadata"]["filter"]["include_keywords"] == ["scenario_006_payload.sh"]
    assert envelope["metadata"]["filter"]["exclude_keywords"] == ["grep"]
    assert envelope["events"][0]["event_id"] == "auditd:ubuntu-victim01:2"
    assert_valid_endpoint_events(envelope)
