import copy
import json
from pathlib import Path

import pytest

from detection.compiler.loader import load_rule
from detection.compiler.pipeline import run_common_detection_pipeline

NORMALIZED_DIR = Path("tests/fixtures/windows/security_auth/expected_normalized")
EXPECTED_DIR = Path("tests/fixtures/windows/security_auth/expected_detection")
RULE_PATH = Path("detection/dsl/windows_security_auth_failure_observed.yaml")
SUCCESS_NAME = "windows-security-4624-network-logon-success-001.json"
FAILURE_NAME = "windows-security-4625-network-logon-failure-001.json"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def normalized(name: str) -> dict:
    return load_json(NORMALIZED_DIR / name)


def expected(name: str) -> dict:
    return load_json(EXPECTED_DIR / name)


def endpoint_envelope(event: dict) -> dict:
    return {
        "schema_version": "endpoint_events.v1",
        "events": [event],
    }


def detection_summary(event: dict, detections: list[dict]) -> dict:
    return {
        "schema_version": "windows_security_auth_expected_detection.v1",
        "fixture_id": event["raw_ref"]["fixture_id"],
        "normalized_event_id": event["event_id"],
        "matched_rule_ids": sorted(detection["rule_id"] for detection in detections),
        "behavior_features": {
            key: True
            for detection in detections
            for key, value in detection["behavior_features"].items()
            if value is True
        },
    }


def evaluate(event: dict) -> list[dict]:
    return run_common_detection_pipeline(
        endpoint_envelope(event),
        [load_rule(RULE_PATH)],
    )


def test_normalized_and_expected_detection_inventories_match() -> None:
    normalized_names = {path.name for path in NORMALIZED_DIR.glob("*.json")}
    detection_names = {path.name for path in EXPECTED_DIR.glob("*.json")}
    assert normalized_names == detection_names == {SUCCESS_NAME, FAILURE_NAME}


def test_rule_is_one_observation_only_auth_failure_route() -> None:
    rule = load_rule(RULE_PATH)

    assert rule["match"] == {
        "source": "windows_security",
        "platform": "windows",
        "event_type": "auth_failure",
    }
    assert rule["artifact"] == "windows_security_auth_failure_observed"
    assert rule["severity"] == "low"
    assert rule["behavior_features"] == {
        "windows_security_auth_failure_observed": True,
    }
    assert rule["metadata"]["mitre"] == []


@pytest.mark.parametrize("name", [SUCCESS_NAME, FAILURE_NAME])
def test_detection_exactly_matches_static_expectation(name: str) -> None:
    event = normalized(name)
    detections = evaluate(event)

    assert detection_summary(event, detections) == expected(name)


def test_success_is_an_explicit_no_match_control() -> None:
    assert evaluate(normalized(SUCCESS_NAME)) == []


def test_failure_emits_one_canonical_atomic_observation() -> None:
    event = normalized(FAILURE_NAME)

    assert evaluate(event) == [
        {
            "id": "det-000001",
            "rule_id": "authentication.windows_security_failure_observed",
            "title": "Windows Security authentication failure observed",
            "log_source": {
                "product": "windows",
                "service": "security",
            },
            "event_type": "auth_failure",
            "artifact": "windows_security_auth_failure_observed",
            "severity": "low",
            "host": "WIN-FIXTURE01",
            "user": "LAB\\fixture-user",
            "src_ip": "198.51.100.24",
            "path": None,
            "event_id": event["event_id"],
            "pid": None,
            "ppid": None,
            "process_name": None,
            "file_path": None,
            "command_line": None,
            "auth_method": None,
            "result": None,
            "behavior_features": {
                "windows_security_auth_failure_observed": True,
            },
            "evidence_refs": [],
            "raw_event_refs": ["input[0]"],
            "time_window_start": "2026-01-15T02:01:00.123000Z",
            "time_window_end": "2026-01-15T02:01:00.123000Z",
        }
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source", "sysmon"),
        ("platform", "linux"),
        ("event_type", "auth_success"),
    ],
)
def test_route_mismatch_is_a_clean_no_match(field: str, value: str) -> None:
    event = normalized(FAILURE_NAME)
    event[field] = value

    assert evaluate(event) == []


def test_provider_status_is_not_a_rule_input() -> None:
    event = normalized(FAILURE_NAME)
    without_provider_details = copy.deepcopy(event)
    del without_provider_details["source_fields"]

    assert detection_summary(event, evaluate(event)) == detection_summary(
        without_provider_details,
        evaluate(without_provider_details),
    )


def test_detection_does_not_modify_normalized_input() -> None:
    event = normalized(FAILURE_NAME)
    original = copy.deepcopy(event)

    evaluate(event)

    assert event == original


def test_rule_contains_no_attack_or_incident_conclusion() -> None:
    rule = load_rule(RULE_PATH)
    serialized = json.dumps(rule, sort_keys=True).casefold()

    for forbidden in (
        "malicious",
        "compromised",
        "invalid_credentials",
        "attack_success",
        "incident",
        "response",
    ):
        assert forbidden not in serialized
