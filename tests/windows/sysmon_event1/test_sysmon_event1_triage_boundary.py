import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from detection.compiler.loader import load_rule
from detection.compiler.pipeline import run_common_detection_pipeline

NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
INCIDENT_BUILDER_PATH = Path("agents/incident-builder-agent/src/main.py")
RULE_TRIAGE_PATH = Path("agents/rule-triage-agent/src/main.py")
TRIAGE_SCHEMA_PATH = Path("agents/ai-triage-agent/schemas/triage_schema.json")
RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]
FIXTURE_EXPECTATIONS = {
    "sysmon-event1-ordinary-powershell-001.json": ["execution.windows_powershell_process_observed"],
    "sysmon-event1-encoded-flag-001.json": [
        "execution.windows_powershell_encoded_command_observed",
        "execution.windows_powershell_process_observed",
    ],
    "sysmon-event1-ordinary-notepad-001.json": [],
}
FORBIDDEN_TRIAGE_KEYS = {
    "EventData",
    "ProcessGuid",
    "Image",
    "CommandLine",
    "fixture_id",
    "provider_name",
    "source_fields",
    "containment",
    "approval",
    "execution",
    "live_coverage",
}
FORBIDDEN_CLAIMS = {
    "confirmed compromise",
    "attack success",
    "malicious powershell",
    "live wazuh coverage",
    "live siem coverage",
}
FORBIDDEN_ATTACKER_MARKERS = {
    "ATTACK_EVENT_JSON",
    "staging_directory_created",
    "archive_created",
    "payload_execution_succeeded",
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


def endpoint_envelope(event: dict) -> dict:
    return {
        "schema_version": "endpoint_events.v1",
        "events": [event],
    }


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def incidents_for_fixture(fixture_name: str) -> tuple[list[dict], list[dict]]:
    event = load_json(NORMALIZED_DIR / fixture_name)
    rules = [load_rule(path) for path in reversed(RULE_PATHS)]
    detections = run_common_detection_pipeline(endpoint_envelope(event), rules)
    incident_builder = load_module(
        "windows_triage_incident_builder",
        INCIDENT_BUILDER_PATH,
    )
    incidents = incident_builder.build_observation_incidents_from_detections(
        detections,
        incident_severity="low",
    )
    return detections, incidents


def load_rule_triage():
    return load_module(
        "windows_slice1_rule_triage",
        RULE_TRIAGE_PATH,
        import_path=RULE_TRIAGE_PATH.parent,
    )


@pytest.mark.parametrize("fixture_name", FIXTURE_EXPECTATIONS)
def test_windows_slice1_reaches_deterministic_rule_triage_boundary(
    fixture_name: str,
) -> None:
    detections, incidents = incidents_for_fixture(fixture_name)
    rule_triage = load_rule_triage()

    triages = rule_triage.build_triage_results_from_incidents(incidents)

    expected_rule_ids = FIXTURE_EXPECTATIONS[fixture_name]
    assert len(detections) == len(expected_rule_ids)
    assert len(incidents) == len(expected_rule_ids)
    assert len(triages) == len(expected_rule_ids)
    assert [incident["matched_rules"][0] for incident in incidents] == expected_rule_ids
    assert [triage["incident_id"] for triage in triages] == [
        incident["incident_id"] for incident in incidents
    ]
    assert [triage["triage_id"] for triage in triages] == [
        f"triage-{incident['incident_id']}" for incident in incidents
    ]
    assert len({triage["triage_id"] for triage in triages}) == len(triages)

    validator = Draft7Validator(load_json(TRIAGE_SCHEMA_PATH))
    for incident, triage in zip(incidents, triages, strict=True):
        validator.validate(triage)
        assert triage["attack_id"] == incident.get("attack_id")
        assert set(triage["derived_features"]) == {
            "download_and_execute_chain",
            "high_risk_execution_flow",
            "external_payload_source",
        }
        assert isinstance(triage["derived_features_extra"], list)
        assert isinstance(triage["mitre_attack"], list)
        assert isinstance(triage["recommended_actions"], list)
        assert collect_keys(triage).isdisjoint(FORBIDDEN_TRIAGE_KEYS)

        serialized = json.dumps(triage).lower()
        assert all(claim not in serialized for claim in FORBIDDEN_CLAIMS)
        assert all(marker.lower() not in serialized for marker in FORBIDDEN_ATTACKER_MARKERS)

        # These values only record the current Linux-oriented Rule Triage fallback.
        # They are not approval of Windows verdict or risk-scoring quality.
        assert triage["verdict"] == "benign"
        assert triage["confidence"] == "low"
        assert triage["priority"] == "P3"
        assert triage["risk_score"] == 10


def test_triage_order_and_ids_do_not_depend_on_incident_input_order() -> None:
    _detections, incidents = incidents_for_fixture("sysmon-event1-encoded-flag-001.json")
    rule_triage = load_rule_triage()

    forward = rule_triage.build_triage_results_from_incidents(incidents)
    reversed_input = rule_triage.build_triage_results_from_incidents(list(reversed(incidents)))

    assert forward == reversed_input


def test_empty_incident_list_does_not_call_single_incident_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rule_triage = load_rule_triage()

    def unexpected_build_output(*args: object, **kwargs: object) -> dict:
        pytest.fail("build_output must not be called for an empty Incident list")

    monkeypatch.setattr(rule_triage, "build_output", unexpected_build_output)

    assert rule_triage.build_triage_results_from_incidents([]) == []


@pytest.mark.parametrize(
    "incidents",
    [
        {},
        ["not-an-object"],
        [{"incident_id": "inc-000001"}],
    ],
)
def test_invalid_incident_list_or_item_fails_closed(incidents: object) -> None:
    rule_triage = load_rule_triage()

    with pytest.raises(rule_triage.TriageBoundaryValidationError):
        rule_triage.build_triage_results_from_incidents(incidents)


@pytest.mark.parametrize(
    ("invalid_id", "error_match"),
    [
        ("", "non-empty string"),
        ("   ", "non-empty string"),
        (1, "schema validation failed"),
        (None, "schema validation failed"),
    ],
)
def test_invalid_incident_id_fails_closed(
    invalid_id: object,
    error_match: str,
) -> None:
    _detections, incidents = incidents_for_fixture("sysmon-event1-ordinary-powershell-001.json")
    invalid_incidents = deepcopy(incidents)
    invalid_incidents[0]["incident_id"] = invalid_id
    rule_triage = load_rule_triage()

    with pytest.raises(
        rule_triage.TriageBoundaryValidationError,
        match=error_match,
    ):
        rule_triage.build_triage_results_from_incidents(invalid_incidents)


def test_missing_incident_id_fails_closed() -> None:
    _detections, incidents = incidents_for_fixture("sysmon-event1-ordinary-powershell-001.json")
    invalid_incidents = deepcopy(incidents)
    del invalid_incidents[0]["incident_id"]
    rule_triage = load_rule_triage()

    with pytest.raises(
        rule_triage.TriageBoundaryValidationError,
        match="schema validation failed",
    ):
        rule_triage.build_triage_results_from_incidents(invalid_incidents)


def test_duplicate_incident_id_fails_closed() -> None:
    _detections, incidents = incidents_for_fixture("sysmon-event1-encoded-flag-001.json")
    duplicate_ids = deepcopy(incidents)
    duplicate_ids[1]["incident_id"] = duplicate_ids[0]["incident_id"]
    rule_triage = load_rule_triage()

    with pytest.raises(
        rule_triage.TriageBoundaryValidationError,
        match="incident_id values must be unique",
    ):
        rule_triage.build_triage_results_from_incidents(duplicate_ids)


def test_schema_invalid_triage_output_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _detections, incidents = incidents_for_fixture("sysmon-event1-ordinary-powershell-001.json")
    rule_triage = load_rule_triage()
    monkeypatch.setattr(
        rule_triage,
        "build_output",
        lambda *args, **kwargs: {"triage_id": "invalid"},
    )

    with pytest.raises(
        rule_triage.TriageBoundaryValidationError,
        match="triage_results\\[0\\] schema validation failed",
    ):
        rule_triage.build_triage_results_from_incidents(incidents)


def test_mismatched_output_incident_id_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _detections, incidents = incidents_for_fixture("sysmon-event1-ordinary-powershell-001.json")
    rule_triage = load_rule_triage()
    original_builder = rule_triage.build_output

    def build_with_wrong_incident_id(*args: object, **kwargs: object) -> dict:
        triage = original_builder(*args, **kwargs)
        triage["incident_id"] = "inc-wrong"
        return triage

    monkeypatch.setattr(rule_triage, "build_output", build_with_wrong_incident_id)

    with pytest.raises(
        rule_triage.TriageBoundaryValidationError,
        match="incident_id must match input incident_id",
    ):
        rule_triage.build_triage_results_from_incidents(incidents)


def test_duplicate_triage_id_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _detections, incidents = incidents_for_fixture("sysmon-event1-encoded-flag-001.json")
    rule_triage = load_rule_triage()
    original_builder = rule_triage.build_output

    def build_with_duplicate_triage_id(*args: object, **kwargs: object) -> dict:
        triage = original_builder(*args, **kwargs)
        triage["triage_id"] = "triage-duplicate"
        return triage

    monkeypatch.setattr(rule_triage, "build_output", build_with_duplicate_triage_id)

    with pytest.raises(
        rule_triage.TriageBoundaryValidationError,
        match="triage_id values must be unique",
    ):
        rule_triage.build_triage_results_from_incidents(incidents)


def test_non_deterministic_triage_id_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _detections, incidents = incidents_for_fixture("sysmon-event1-ordinary-powershell-001.json")
    rule_triage = load_rule_triage()
    original_builder = rule_triage.build_output

    def build_with_non_deterministic_triage_id(*args: object, **kwargs: object) -> dict:
        triage = original_builder(*args, **kwargs)
        triage["triage_id"] = "triage-random"
        return triage

    monkeypatch.setattr(
        rule_triage,
        "build_output",
        build_with_non_deterministic_triage_id,
    )

    with pytest.raises(
        rule_triage.TriageBoundaryValidationError,
        match="triage_id must be triage-inc-000001",
    ):
        rule_triage.build_triage_results_from_incidents(incidents)
