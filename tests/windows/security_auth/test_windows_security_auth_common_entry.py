import json
from copy import deepcopy
from pathlib import Path

import pytest

from common import defender_pipeline
from detection.compiler.loader import load_rule

NORMALIZED_DIR = Path("tests/fixtures/windows/security_auth/expected_normalized")
RULE_PATH = Path("detection/dsl/windows_security_auth_failure_observed.yaml")
SUCCESS_NAME = "windows-security-4624-network-logon-success-001.json"
FAILURE_NAME = "windows-security-4625-network-logon-failure-001.json"
STAGE_KEYS = (
    "deduped_detections",
    "correlations",
    "incidents",
    "triage_results",
    "investigation_results",
)
FORBIDDEN_DOWNSTREAM_KEYS = {
    "containment",
    "approval",
    "response_action",
    "action_plan",
    "case_id",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def normalized(name: str) -> dict:
    return load_json(NORMALIZED_DIR / name)


def endpoint_envelope(event: dict) -> dict:
    return {
        "schema_version": "endpoint_events.v1",
        "events": [event],
    }


def run_fixture(name: str) -> tuple[dict, dict, dict]:
    event = normalized(name)
    endpoint_events = endpoint_envelope(event)
    rule = load_rule(RULE_PATH)
    bundle = defender_pipeline.run_common_endpoint_to_investigation(
        endpoint_events,
        [rule],
        endpoint_events_source=str(NORMALIZED_DIR / name),
        observation_incident_severity="low",
    )
    return event, rule, bundle


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


@pytest.mark.parametrize(
    ("name", "expected_counts"),
    [
        (SUCCESS_NAME, [0, 0, 0, 0, 0]),
        (FAILURE_NAME, [1, 0, 1, 1, 1]),
    ],
)
def test_authentication_common_entry_stage_matrix(
    name: str,
    expected_counts: list[int],
) -> None:
    _, _, bundle = run_fixture(name)

    assert list(bundle) == list(STAGE_KEYS)
    assert [len(bundle[key]) for key in STAGE_KEYS] == expected_counts


def test_success_no_match_stays_empty_through_every_stage() -> None:
    _, _, bundle = run_fixture(SUCCESS_NAME)

    assert bundle == {key: [] for key in STAGE_KEYS}


def test_failure_preserves_exact_identity_linkage_through_all_stages() -> None:
    _, _, bundle = run_fixture(FAILURE_NAME)
    detection = bundle["deduped_detections"][0]
    incident = bundle["incidents"][0]
    triage = bundle["triage_results"][0]
    investigation = bundle["investigation_results"][0]

    assert detection["id"] == "det-000001"
    assert detection["rule_id"] == "authentication.windows_security_failure_observed"
    assert detection["duplicate_count"] == 1
    assert incident["incident_id"] == "inc-000001"
    assert incident["matched_detection_ids"] == [detection["id"]]
    assert triage["incident_id"] == incident["incident_id"]
    assert triage["triage_id"] == "triage-inc-000001"
    assert investigation["incident_id"] == incident["incident_id"]
    assert investigation["triage_id"] == triage["triage_id"]
    assert investigation["investigation_id"] == "investigation-inc-000001"


def test_failure_remains_one_uncorrelated_low_severity_observation() -> None:
    _, _, bundle = run_fixture(FAILURE_NAME)
    incident = bundle["incidents"][0]

    assert bundle["correlations"] == []
    assert incident["scenario_name"] == "windows_security_auth_failure_observed"
    assert incident["primary_artifact"] == "windows_security_auth_failure_observed"
    assert incident["severity"] == "low"
    assert incident["confidence"] == "medium"
    assert incident["mitre_attack"] == []
    assert incident["attack_id"] is None
    assert "does not infer compromise" in incident["summary"]
    assert incident["behavior_features"] == {
        "windows_security_auth_failure_observed": True,
    }


def test_failure_investigation_retains_the_exact_endpoint_event() -> None:
    event, _, bundle = run_fixture(FAILURE_NAME)
    investigation = bundle["investigation_results"][0]
    evidence = investigation["evidence"]

    assert evidence["endpoint_event_count"] == 1
    assert evidence["endpoint_events"] == [event]
    assert investigation["source_inputs"]["endpoint_events_json"] == str(
        NORMALIZED_DIR / FAILURE_NAME
    )
    assert any(
        "endpoint telemetry observed failed authentication" in fact
        for fact in investigation["evidence_summary"]["observed_facts"]
    )


def test_failure_timeline_retains_canonical_event_context() -> None:
    event, _, bundle = run_fixture(FAILURE_NAME)
    detection = bundle["deduped_detections"][0]
    incident = bundle["incidents"][0]
    timeline = incident["timeline"]

    assert detection["event_id"] == event["event_id"]
    assert detection["host"] == event["host"]
    assert detection["user"] == event["user"]
    assert detection["src_ip"] == event["src_ip"]
    assert detection["raw_event_refs"] == ["input[0]"]
    assert len(timeline) == 1
    assert timeline[0]["event_ref"] == "input[0]"
    assert timeline[0]["event_type"] == "auth_failure"
    assert timeline[0]["artifact"] == "windows_security_auth_failure_observed"


@pytest.mark.parametrize("name", [SUCCESS_NAME, FAILURE_NAME])
def test_common_entry_does_not_modify_event_or_rule(name: str) -> None:
    event = normalized(name)
    endpoint_events = endpoint_envelope(event)
    rules = [load_rule(RULE_PATH)]
    original_endpoint_events = deepcopy(endpoint_events)
    original_rules = deepcopy(rules)

    defender_pipeline.run_common_endpoint_to_investigation(
        endpoint_events,
        rules,
        endpoint_events_source=str(NORMALIZED_DIR / name),
        observation_incident_severity="low",
    )

    assert endpoint_events == original_endpoint_events
    assert rules == original_rules


def test_common_entry_adds_no_response_or_case_artifact() -> None:
    _, _, bundle = run_fixture(FAILURE_NAME)

    assert collect_keys(bundle).isdisjoint(FORBIDDEN_DOWNSTREAM_KEYS)
    assert all(
        item["attack_id"] is None
        for key in ("incidents", "triage_results", "investigation_results")
        for item in bundle[key]
    )
