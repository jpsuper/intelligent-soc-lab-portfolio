import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from detection.compiler.loader import load_rule
from detection.compiler.pipeline import run_common_detection_pipeline

NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
INCIDENT_BUILDER_PATH = Path("agents/incident-builder-agent/src/main.py")
RULE_TRIAGE_PATH = Path("agents/rule-triage-agent/src/main.py")
INVESTIGATION_PATH = Path("agents/investigation-agent/src/main.py")
INVESTIGATION_SCHEMA_PATH = Path("schemas/investigation_result_schema.json")
RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]
FIXTURE_EXPECTATIONS = {
    "sysmon-event1-ordinary-powershell-001.json": 1,
    "sysmon-event1-encoded-flag-001.json": 2,
    "sysmon-event1-ordinary-notepad-001.json": 0,
}
FORBIDDEN_KEYS = {
    "EventData",
    "ProcessGuid",
    "Image",
    "CommandLine",
    "fixture_id",
    "source_fields",
    "containment",
    "approval",
    "execution_state",
    "apply_approved",
    "deployment_approved",
    "promotion_approved",
    "promotion_allowed",
}
FORBIDDEN_TOP_LEVEL_KEYS = {
    "verdict",
    "severity",
    "confidence",
    "priority",
    "risk_score",
    "post_action_dfir_investigation_result",
}
FORBIDDEN_MARKERS = {
    "ATTACK_EVENT_JSON",
    "staging_directory_created",
    "archive_created",
    "payload_execution_succeeded",
}
FORBIDDEN_CLAIMS = {
    "confirmed compromise",
    "attack success",
    "malicious powershell",
    "live windows coverage",
    "live wazuh coverage",
    "live siem coverage",
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


def boundary_inputs(fixture_name: str) -> tuple[list[dict], list[dict], list[dict]]:
    event = load_json(NORMALIZED_DIR / fixture_name)
    rules = [load_rule(path) for path in reversed(RULE_PATHS)]
    detections = run_common_detection_pipeline(endpoint_envelope(event), rules)

    incident_builder = load_module(
        "windows_investigation_incident_builder",
        INCIDENT_BUILDER_PATH,
    )
    incidents = incident_builder.build_observation_incidents_from_detections(
        detections,
        incident_severity="low",
    )

    rule_triage = load_module(
        "windows_investigation_rule_triage",
        RULE_TRIAGE_PATH,
        import_path=RULE_TRIAGE_PATH.parent,
    )
    triage_results = rule_triage.build_triage_results_from_incidents(incidents)
    return detections, incidents, triage_results


def load_investigation():
    return load_module(
        "windows_slice1_investigation",
        INVESTIGATION_PATH,
        import_path=INVESTIGATION_PATH.parent,
    )


@pytest.mark.parametrize("fixture_name", FIXTURE_EXPECTATIONS)
def test_windows_slice1_reaches_pre_case_investigation_boundary(
    fixture_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detections, incidents, triage_results = boundary_inputs(fixture_name)
    original_incidents = deepcopy(incidents)
    original_triages = deepcopy(triage_results)
    investigation = load_investigation()
    original_builder = investigation.build_investigation_result
    builder_calls: list[tuple[str, str]] = []

    def tracking_builder(*args: object, **kwargs: object) -> dict:
        incident = kwargs["incident"]
        triage_result = kwargs["triage_result"]
        builder_calls.append((incident["incident_id"], triage_result["triage_id"]))
        return original_builder(*args, **kwargs)

    monkeypatch.setattr(investigation, "build_investigation_result", tracking_builder)

    results = investigation.build_investigation_results_from_incidents_and_triages(
        incidents,
        triage_results,
    )

    expected_count = FIXTURE_EXPECTATIONS[fixture_name]
    assert len(detections) == expected_count
    assert len(incidents) == expected_count
    assert len(triage_results) == expected_count
    assert len(results) == expected_count
    assert len(builder_calls) == expected_count
    assert builder_calls == [
        (incident["incident_id"], triage_result["triage_id"])
        for incident, triage_result in zip(incidents, triage_results, strict=True)
    ]
    assert incidents == original_incidents
    assert triage_results == original_triages

    validator = Draft202012Validator(load_json(INVESTIGATION_SCHEMA_PATH))
    for incident, triage_result, result in zip(
        incidents,
        triage_results,
        results,
        strict=True,
    ):
        validator.validate(result)
        assert result["incident_id"] == incident["incident_id"]
        assert result["triage_id"] == triage_result["triage_id"]
        assert result["investigation_id"] == (f"investigation-{incident['incident_id']}")
        assert result["source_inputs"]["incident_json"] is True
        assert result["source_inputs"]["triage_result_json"] is True
        assert set(result).isdisjoint(FORBIDDEN_TOP_LEVEL_KEYS)
        assert collect_keys(result).isdisjoint(FORBIDDEN_KEYS)

        serialized = json.dumps(result).lower()
        assert all(marker.lower() not in serialized for marker in FORBIDDEN_MARKERS)
        assert all(claim not in serialized for claim in FORBIDDEN_CLAIMS)


def test_investigation_order_is_independent_of_both_input_orders() -> None:
    _detections, incidents, triage_results = boundary_inputs("sysmon-event1-encoded-flag-001.json")
    investigation = load_investigation()

    forward = investigation.build_investigation_results_from_incidents_and_triages(
        incidents,
        triage_results,
    )
    reversed_inputs = investigation.build_investigation_results_from_incidents_and_triages(
        list(reversed(incidents)),
        list(reversed(triage_results)),
    )
    independently_reversed = investigation.build_investigation_results_from_incidents_and_triages(
        list(reversed(incidents)),
        triage_results,
    )

    assert forward == reversed_inputs == independently_reversed
    assert [result["incident_id"] for result in forward] == [
        "inc-000001",
        "inc-000002",
    ]
    assert [result["triage_id"] for result in forward] == [
        "triage-inc-000001",
        "triage-inc-000002",
    ]


def test_empty_inputs_do_not_call_single_result_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    investigation = load_investigation()

    def unexpected_builder(*args: object, **kwargs: object) -> dict:
        pytest.fail("single-result builder must not be called for empty inputs")

    monkeypatch.setattr(investigation, "build_investigation_result", unexpected_builder)

    assert investigation.build_investigation_results_from_incidents_and_triages([], []) == []


@pytest.mark.parametrize(
    ("incidents", "triage_results", "error_match"),
    [
        ({}, [], "incidents must be a list"),
        ([], {}, "triage_results must be a list"),
        (["not-an-object"], [], "incidents\\[0\\] schema validation failed"),
        ([], ["not-an-object"], "triage_results\\[0\\] schema validation failed"),
        (
            [{"incident_id": "inc-000001"}],
            [],
            "incidents\\[0\\] schema validation failed",
        ),
        (
            [],
            [{"triage_id": "triage-inc-000001"}],
            "triage_results\\[0\\] schema validation failed",
        ),
    ],
)
def test_malformed_boundary_input_fails_closed(
    incidents: object,
    triage_results: object,
    error_match: str,
) -> None:
    investigation = load_investigation()

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match=error_match,
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            triage_results,
        )


@pytest.mark.parametrize("invalid_id", ["", "   "])
def test_blank_incident_id_fails_closed(invalid_id: str) -> None:
    _detections, incidents, triage_results = boundary_inputs(
        "sysmon-event1-ordinary-powershell-001.json"
    )
    invalid_incidents = deepcopy(incidents)
    invalid_incidents[0]["incident_id"] = invalid_id
    investigation = load_investigation()

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match="incident_id must be a non-empty string",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            invalid_incidents,
            triage_results,
        )


def test_missing_incident_id_fails_closed() -> None:
    _detections, incidents, triage_results = boundary_inputs(
        "sysmon-event1-ordinary-powershell-001.json"
    )
    invalid_incidents = deepcopy(incidents)
    del invalid_incidents[0]["incident_id"]
    investigation = load_investigation()

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match="incidents\\[0\\] schema validation failed",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            invalid_incidents,
            triage_results,
        )


@pytest.mark.parametrize("field", ["triage_id", "incident_id"])
@pytest.mark.parametrize("invalid_id", ["", "   "])
def test_blank_triage_identifiers_fail_closed(
    field: str,
    invalid_id: str,
) -> None:
    _detections, incidents, triage_results = boundary_inputs(
        "sysmon-event1-ordinary-powershell-001.json"
    )
    invalid_triages = deepcopy(triage_results)
    invalid_triages[0][field] = invalid_id
    investigation = load_investigation()

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match=rf"{field} must be a non-empty string",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            invalid_triages,
        )


@pytest.mark.parametrize("field", ["triage_id", "incident_id"])
def test_missing_triage_identifiers_fail_closed(field: str) -> None:
    _detections, incidents, triage_results = boundary_inputs(
        "sysmon-event1-ordinary-powershell-001.json"
    )
    invalid_triages = deepcopy(triage_results)
    del invalid_triages[0][field]
    investigation = load_investigation()

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match="triage_results\\[0\\] schema validation failed",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            invalid_triages,
        )


def test_duplicate_incident_id_fails_closed() -> None:
    _detections, incidents, triage_results = boundary_inputs("sysmon-event1-encoded-flag-001.json")
    duplicate_incidents = deepcopy(incidents)
    duplicate_incidents[1]["incident_id"] = duplicate_incidents[0]["incident_id"]
    investigation = load_investigation()

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match="incident_id values must be unique",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            duplicate_incidents,
            triage_results,
        )


def test_duplicate_triage_id_fails_closed() -> None:
    _detections, incidents, triage_results = boundary_inputs("sysmon-event1-encoded-flag-001.json")
    duplicate_triages = deepcopy(triage_results)
    duplicate_triages[1]["triage_id"] = duplicate_triages[0]["triage_id"]
    investigation = load_investigation()

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match="triage_id values must be unique",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            duplicate_triages,
        )


def test_duplicate_triage_linkage_fails_closed() -> None:
    _detections, incidents, triage_results = boundary_inputs("sysmon-event1-encoded-flag-001.json")
    duplicate_linkage = deepcopy(triage_results)
    duplicate_linkage[1]["incident_id"] = duplicate_linkage[0]["incident_id"]
    investigation = load_investigation()

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match="triage result incident_id values must be unique",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            duplicate_linkage,
        )


@pytest.mark.parametrize(
    ("mutation", "error_match"),
    [
        ("missing", "missing triage"),
        ("orphan", "orphan triage"),
        ("mismatch", "sets must match exactly"),
    ],
)
def test_incident_and_triage_id_set_mismatch_fails_closed(
    mutation: str,
    error_match: str,
) -> None:
    _detections, incidents, triage_results = boundary_inputs("sysmon-event1-encoded-flag-001.json")
    invalid_incidents = deepcopy(incidents)
    invalid_triages = deepcopy(triage_results)
    if mutation == "missing":
        invalid_triages.pop()
    elif mutation == "orphan":
        invalid_incidents.pop()
    else:
        invalid_triages[1]["incident_id"] = "inc-orphan"
    investigation = load_investigation()

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match=error_match,
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            invalid_incidents,
            invalid_triages,
        )


def test_later_invalid_input_prevents_all_builder_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _detections, incidents, triage_results = boundary_inputs("sysmon-event1-encoded-flag-001.json")
    invalid_triages = deepcopy(triage_results)
    del invalid_triages[1]["triage_id"]
    investigation = load_investigation()
    builder_calls = 0

    def tracking_builder(*args: object, **kwargs: object) -> dict:
        nonlocal builder_calls
        builder_calls += 1
        return {}

    monkeypatch.setattr(investigation, "build_investigation_result", tracking_builder)

    with pytest.raises(investigation.InvestigationBoundaryValidationError):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            invalid_triages,
        )

    assert builder_calls == 0


def test_schema_invalid_investigation_output_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _detections, incidents, triage_results = boundary_inputs(
        "sysmon-event1-ordinary-powershell-001.json"
    )
    investigation = load_investigation()
    monkeypatch.setattr(
        investigation,
        "build_investigation_result",
        lambda *args, **kwargs: {"investigation_id": "invalid"},
    )

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match="investigation_results\\[0\\] schema validation failed",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            triage_results,
        )


@pytest.mark.parametrize(
    ("field", "invalid_value", "error_match"),
    [
        ("incident_id", "inc-wrong", "incident_id must match input incident_id"),
        ("triage_id", "triage-wrong", "triage_id must match input triage_id"),
        ("investigation_id", "", "investigation_id must be a non-empty string"),
    ],
)
def test_invalid_investigation_identity_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    invalid_value: str,
    error_match: str,
) -> None:
    _detections, incidents, triage_results = boundary_inputs(
        "sysmon-event1-ordinary-powershell-001.json"
    )
    investigation = load_investigation()
    original_builder = investigation.build_investigation_result

    def build_with_invalid_identity(*args: object, **kwargs: object) -> dict:
        result = original_builder(*args, **kwargs)
        result[field] = invalid_value
        return result

    monkeypatch.setattr(
        investigation,
        "build_investigation_result",
        build_with_invalid_identity,
    )

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match=error_match,
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            triage_results,
        )


def test_duplicate_investigation_id_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _detections, incidents, triage_results = boundary_inputs("sysmon-event1-encoded-flag-001.json")
    investigation = load_investigation()
    original_builder = investigation.build_investigation_result

    def build_with_duplicate_id(*args: object, **kwargs: object) -> dict:
        result = original_builder(*args, **kwargs)
        result["investigation_id"] = "investigation-duplicate"
        return result

    monkeypatch.setattr(
        investigation,
        "build_investigation_result",
        build_with_duplicate_id,
    )

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match="investigation_id values must be unique",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            triage_results,
        )


def test_non_deterministic_investigation_id_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _detections, incidents, triage_results = boundary_inputs(
        "sysmon-event1-ordinary-powershell-001.json"
    )
    investigation = load_investigation()
    original_builder = investigation.build_investigation_result

    def build_with_non_deterministic_id(*args: object, **kwargs: object) -> dict:
        result = original_builder(*args, **kwargs)
        result["investigation_id"] = "investigation-random"
        return result

    monkeypatch.setattr(
        investigation,
        "build_investigation_result",
        build_with_non_deterministic_id,
    )

    with pytest.raises(
        investigation.InvestigationBoundaryValidationError,
        match="investigation_id must be investigation-inc-000001",
    ):
        investigation.build_investigation_results_from_incidents_and_triages(
            incidents,
            triage_results,
        )
