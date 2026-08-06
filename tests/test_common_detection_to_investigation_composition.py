import inspect
import json
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from common import defender_pipeline
from detection.compiler.loader import load_rule
from detection.compiler.pipeline import (
    CommonPipelineValidationError,
    run_common_detection_pipeline,
)

LINUX_FIXTURE_PATH = Path(
    "tests/fixtures/scenario_009_suspicious_archive_staging/endpoint_events.json"
)
LINUX_RULE_PATH = Path("detection/dsl/suspicious_archive_staging.yaml")
WINDOWS_NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
WINDOWS_RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]
FORBIDDEN_MARKERS = {
    "ATTACK_EVENT_JSON",
    "attack_observed_effects",
    "staging_directory_created",
    "payload_execution_succeeded",
    "post_action_dfir",
}
FORBIDDEN_KEYS = {
    "containment",
    "approval",
    "response_action",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def endpoint_envelope(event: dict) -> dict:
    return {"schema_version": "endpoint_events.v1", "events": [event]}


def canonical_detection(
    detection_id: str,
    artifact: str,
    timestamp: str,
    *,
    host: str = "fixture-host",
    user: str | None = "fixture-user",
    src_ip: str | None = "192.0.2.10",
    rule_id: str | None = None,
) -> dict:
    return {
        "id": detection_id,
        "rule_id": rule_id or f"test.{artifact}",
        "title": f"Test {artifact}",
        "log_source": {"product": "linux"},
        "event_type": artifact,
        "artifact": artifact,
        "severity": "low",
        "host": host,
        "user": user,
        "src_ip": src_ip,
        "path": "/home/fixture-user/.ssh/authorized_keys"
        if artifact == "authorized_keys_modification"
        else None,
        "command_line": "/bin/id" if artifact == "process_exec" else None,
        "behavior_features": {f"{artifact}_observed": True},
        "evidence_refs": [f"evidence.json#{detection_id}"],
        "raw_event_refs": [f"input[{detection_id}]"],
        "time_window_start": timestamp,
        "time_window_end": timestamp,
    }


def auth_sequence() -> list[dict]:
    return [
        canonical_detection("det-failed", "ssh_failed_login", "2026-08-01T00:00:00Z"),
        canonical_detection("det-success", "ssh_success_login", "2026-08-01T00:00:10Z"),
        canonical_detection(
            "det-authorized-keys",
            "authorized_keys_modification",
            "2026-08-01T00:00:20Z",
            src_ip=None,
        ),
    ]


def key_exec_sequence() -> list[dict]:
    return [
        canonical_detection("det-key", "ssh_key_login", "2026-08-01T00:01:00Z"),
        canonical_detection("det-exec", "process_exec", "2026-08-01T00:01:10Z"),
    ]


def uncovered_detection() -> dict:
    return canonical_detection(
        "det-uncovered",
        "process_exec",
        "2026-08-01T00:02:00Z",
        host="other-host",
        user="other-user",
        src_ip=None,
        rule_id="test.uncovered-process",
    )


def assert_linkage(bundle: dict) -> None:
    incident_ids = {item["incident_id"] for item in bundle["incidents"]}
    assert (
        incident_ids
        == {item["incident_id"] for item in bundle["triage_results"]}
        == {item["incident_id"] for item in bundle["investigation_results"]}
    )
    triages = {item["incident_id"]: item for item in bundle["triage_results"]}
    for investigation in bundle["investigation_results"]:
        incident_id = investigation["incident_id"]
        assert triages[incident_id]["triage_id"] == f"triage-{incident_id}"
        assert investigation["investigation_id"] == f"investigation-{incident_id}"
        assert investigation["triage_id"] == triages[incident_id]["triage_id"]


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def test_empty_composition_calls_each_list_boundary_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = {"incident": 0, "triage": 0, "investigation": 0}

    def incidents(*args: object, **kwargs: object) -> list[dict]:
        calls["incident"] += 1
        return []

    def triages(*args: object, **kwargs: object) -> list[dict]:
        calls["triage"] += 1
        return []

    def investigations(*args: object, **kwargs: object) -> list[dict]:
        calls["investigation"] += 1
        return []

    monkeypatch.setattr(
        defender_pipeline,
        "_load_incident_builder_module",
        lambda: SimpleNamespace(
            IncidentBoundaryValidationError=ValueError,
            build_selected_incidents_from_results=incidents,
            build_detection_hit_incident=lambda *args, **kwargs: pytest.fail(
                "single Incident builder must not be called"
            ),
        ),
    )
    monkeypatch.setattr(
        defender_pipeline,
        "_load_rule_triage_module",
        lambda: SimpleNamespace(
            TriageBoundaryValidationError=ValueError,
            build_triage_results_from_incidents=triages,
            build_output=lambda *args, **kwargs: pytest.fail(
                "single Triage builder must not be called"
            ),
        ),
    )
    monkeypatch.setattr(
        defender_pipeline,
        "_load_investigation_module",
        lambda: SimpleNamespace(
            InvestigationBoundaryValidationError=ValueError,
            build_investigation_results_from_incidents_and_triages=investigations,
            build_investigation_result=lambda *args, **kwargs: pytest.fail(
                "single Investigation builder must not be called"
            ),
        ),
    )

    result = defender_pipeline.run_common_detection_to_investigation([])

    assert result == {
        "deduped_detections": [],
        "correlations": [],
        "incidents": [],
        "triage_results": [],
        "investigation_results": [],
    }
    assert calls == {"incident": 1, "triage": 1, "investigation": 1}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"observation_scenario_name": " "},
        {"observation_incident_severity": "unknown"},
    ],
)
def test_empty_composition_preserves_observation_parameter_validation(kwargs: dict) -> None:
    with pytest.raises(
        defender_pipeline.CommonPipelineCompositionError,
        match="incident selection stage failed",
    ):
        defender_pipeline.run_common_detection_to_investigation([], **kwargs)


def test_no_correlation_falls_back_through_all_stages() -> None:
    bundle = defender_pipeline.run_common_detection_to_investigation(
        [uncovered_detection()],
        observation_incident_severity="low",
    )

    assert [len(bundle[key]) for key in bundle] == [1, 0, 1, 1, 1]
    assert bundle["incidents"][0]["incident_id"] == "inc-000001"
    assert bundle["triage_results"][0]["triage_id"] == "triage-inc-000001"
    assert bundle["investigation_results"][0]["investigation_id"] == "investigation-inc-000001"
    assert_linkage(bundle)


@pytest.mark.parametrize(
    ("detections", "expected_incident_id"),
    [
        (auth_sequence(), "inc-corr-auth-persistence-000001"),
        (key_exec_sequence(), "inc-corr-key-exec-000001"),
    ],
)
def test_full_correlation_coverage_reaches_one_investigation(
    detections: list[dict],
    expected_incident_id: str,
) -> None:
    bundle = defender_pipeline.run_common_detection_to_investigation(detections)

    assert len(bundle["correlations"]) == 1
    assert [item["incident_id"] for item in bundle["incidents"]] == [expected_incident_id]
    assert len(bundle["triage_results"]) == 1
    assert len(bundle["investigation_results"]) == 1
    assert_linkage(bundle)


def test_partial_coverage_preserves_stage_specific_order_and_id_linkage() -> None:
    bundle = defender_pipeline.run_common_detection_to_investigation(
        [*auth_sequence(), uncovered_detection()]
    )

    assert [item["incident_id"] for item in bundle["incidents"]] == [
        "inc-corr-auth-persistence-000001",
        "inc-000001",
    ]
    expected_downstream = ["inc-000001", "inc-corr-auth-persistence-000001"]
    assert [item["incident_id"] for item in bundle["triage_results"]] == expected_downstream
    assert [item["incident_id"] for item in bundle["investigation_results"]] == (
        expected_downstream
    )
    assert_linkage(bundle)


def test_multiple_independent_correlations_remain_distinct() -> None:
    bundle = defender_pipeline.run_common_detection_to_investigation(
        [*auth_sequence(), *key_exec_sequence()]
    )

    assert len(bundle["correlations"]) == 2
    assert len(bundle["incidents"]) == 2
    assert len(bundle["triage_results"]) == 2
    assert len(bundle["investigation_results"]) == 2
    assert_linkage(bundle)


def test_overlapping_correlations_are_not_merged() -> None:
    detections = [
        canonical_detection("det-key", "ssh_key_login", "2026-08-01T00:00:00Z"),
        canonical_detection("det-exec-one", "process_exec", "2026-08-01T00:01:10Z"),
        canonical_detection("det-exec-two", "process_exec", "2026-08-01T00:02:20Z"),
    ]

    bundle = defender_pipeline.run_common_detection_to_investigation(detections)

    assert len(bundle["correlations"]) == 2
    assert [item["incident_id"] for item in bundle["incidents"]] == [
        "inc-corr-key-exec-000001",
        "inc-corr-key-exec-000002",
    ]
    assert len(bundle["triage_results"]) == len(bundle["investigation_results"]) == 2


def test_composition_is_independent_of_detection_input_order() -> None:
    detections = [*auth_sequence(), *key_exec_sequence(), uncovered_detection()]

    forward = defender_pipeline.run_common_detection_to_investigation(detections)
    reversed_result = defender_pipeline.run_common_detection_to_investigation(
        list(reversed(detections))
    )

    assert forward == reversed_result


@pytest.mark.parametrize(
    ("detections", "message"),
    [
        ({}, "canonical detection output must be a list"),
        ([{"id": "incomplete"}], "missing canonical fields"),
        (
            [
                uncovered_detection(),
                deepcopy(uncovered_detection()),
            ],
            "duplicate detection id",
        ),
        (
            [
                {
                    **uncovered_detection(),
                    "time_window_start": "not-a-timestamp",
                }
            ],
            "valid ISO-8601 timestamp",
        ),
    ],
)
def test_invalid_canonical_detection_stops_before_downstream(
    monkeypatch: pytest.MonkeyPatch,
    detections: object,
    message: str,
) -> None:
    downstream_loaded = False

    def unexpected_loader() -> object:
        nonlocal downstream_loaded
        downstream_loaded = True
        return object()

    monkeypatch.setattr(
        defender_pipeline,
        "_load_incident_builder_module",
        unexpected_loader,
    )

    with pytest.raises(
        defender_pipeline.CommonPipelineCompositionError,
        match=rf"correlation stage failed: .*{message}",
    ) as error:
        defender_pipeline.run_common_detection_to_investigation(detections)
    assert isinstance(error.value.__cause__, CommonPipelineValidationError)
    assert downstream_loaded is False


def test_semantic_duplicates_are_deduped_by_the_existing_boundary() -> None:
    first = uncovered_detection()
    second = deepcopy(first)
    second["id"] = "det-uncovered-duplicate"
    second["evidence_refs"] = ["evidence.json#duplicate"]

    bundle = defender_pipeline.run_common_detection_to_investigation([second, first])

    assert len(bundle["deduped_detections"]) == 1
    assert bundle["deduped_detections"][0]["duplicate_count"] == 2


def test_public_api_has_no_caller_supplied_correlation_parameter() -> None:
    signature = inspect.signature(defender_pipeline.run_common_detection_to_investigation)

    assert "correlations" not in signature.parameters
    with pytest.raises(TypeError):
        defender_pipeline.run_common_detection_to_investigation([], correlations=[])


def test_agent_loader_restores_import_state() -> None:
    import_path = str(defender_pipeline.RULE_TRIAGE_PATH.parent)
    original_path = list(sys.path)
    original_modules = {
        name: sys.modules.get(name) for name in ("evaluator", "rule_loader", "rule_validator")
    }

    module = defender_pipeline._load_rule_triage_module()

    assert callable(module.build_triage_results_from_incidents)
    assert sys.path == original_path
    assert {
        name: sys.modules.get(name) for name in ("evaluator", "rule_loader", "rule_validator")
    } == original_modules
    assert sys.path.count(import_path) == original_path.count(import_path)


def test_correlation_failure_stops_all_downstream_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downstream_loaded = False

    def fail_correlation(detections: object) -> tuple[list[dict], list[dict]]:
        raise CommonPipelineValidationError("synthetic correlation failure")

    def unexpected_loader() -> object:
        nonlocal downstream_loaded
        downstream_loaded = True
        return object()

    monkeypatch.setattr(
        defender_pipeline,
        "run_common_correlation_stage",
        fail_correlation,
    )
    monkeypatch.setattr(
        defender_pipeline,
        "_load_incident_builder_module",
        unexpected_loader,
    )

    with pytest.raises(
        defender_pipeline.CommonPipelineCompositionError,
        match="correlation stage failed: synthetic correlation failure",
    ) as error:
        defender_pipeline.run_common_detection_to_investigation([])
    assert isinstance(error.value.__cause__, CommonPipelineValidationError)
    assert downstream_loaded is False


def test_incident_selection_failure_stops_later_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    later_loaded = False

    def fail_selection(*args: object, **kwargs: object) -> list[dict]:
        raise ValueError("synthetic selection failure")

    def unexpected_loader() -> object:
        nonlocal later_loaded
        later_loaded = True
        return object()

    monkeypatch.setattr(
        defender_pipeline,
        "_load_incident_builder_module",
        lambda: SimpleNamespace(
            IncidentBoundaryValidationError=ValueError,
            build_selected_incidents_from_results=fail_selection,
        ),
    )
    monkeypatch.setattr(defender_pipeline, "_load_rule_triage_module", unexpected_loader)

    with pytest.raises(
        defender_pipeline.CommonPipelineCompositionError,
        match="incident selection stage failed: synthetic selection failure",
    ):
        defender_pipeline.run_common_detection_to_investigation([uncovered_detection()])
    assert later_loaded is False


def test_triage_failure_stops_investigation(monkeypatch: pytest.MonkeyPatch) -> None:
    investigation_loaded = False

    def fail_triage(*args: object, **kwargs: object) -> list[dict]:
        raise ValueError("synthetic triage failure")

    def unexpected_investigation() -> object:
        nonlocal investigation_loaded
        investigation_loaded = True
        return object()

    triage = SimpleNamespace(
        TriageBoundaryValidationError=ValueError,
        build_triage_results_from_incidents=fail_triage,
    )
    monkeypatch.setattr(defender_pipeline, "_load_rule_triage_module", lambda: triage)
    monkeypatch.setattr(
        defender_pipeline,
        "_load_investigation_module",
        unexpected_investigation,
    )

    with pytest.raises(
        defender_pipeline.CommonPipelineCompositionError,
        match="rule triage stage failed: synthetic triage failure",
    ):
        defender_pipeline.run_common_detection_to_investigation([uncovered_detection()])
    assert investigation_loaded is False


def test_investigation_failure_returns_no_partial_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    investigation = SimpleNamespace(
        InvestigationBoundaryValidationError=ValueError,
        build_investigation_results_from_incidents_and_triages=lambda *args, **kwargs: (
            _ for _ in ()
        ).throw(ValueError("synthetic investigation failure")),
    )
    monkeypatch.setattr(
        defender_pipeline,
        "_load_investigation_module",
        lambda: investigation,
    )

    with pytest.raises(
        defender_pipeline.CommonPipelineCompositionError,
        match="investigation stage failed: synthetic investigation failure",
    ):
        defender_pipeline.run_common_detection_to_investigation([uncovered_detection()])


def _run_with_mutated_downstream(
    monkeypatch: pytest.MonkeyPatch,
    valid: dict,
    *,
    triage_results: object,
    investigation_results: object,
) -> None:
    monkeypatch.setattr(
        defender_pipeline,
        "run_common_correlation_stage",
        lambda detections: (
            deepcopy(valid["deduped_detections"]),
            deepcopy(valid["correlations"]),
        ),
    )
    monkeypatch.setattr(
        defender_pipeline,
        "_load_incident_builder_module",
        lambda: SimpleNamespace(
            IncidentBoundaryValidationError=ValueError,
            build_selected_incidents_from_results=lambda *args, **kwargs: deepcopy(
                valid["incidents"]
            ),
        ),
    )
    monkeypatch.setattr(
        defender_pipeline,
        "_load_rule_triage_module",
        lambda: SimpleNamespace(
            TriageBoundaryValidationError=ValueError,
            build_triage_results_from_incidents=lambda *args, **kwargs: deepcopy(triage_results),
        ),
    )
    monkeypatch.setattr(
        defender_pipeline,
        "_load_investigation_module",
        lambda: SimpleNamespace(
            InvestigationBoundaryValidationError=ValueError,
            build_investigation_results_from_incidents_and_triages=(
                lambda *args, **kwargs: deepcopy(investigation_results)
            ),
        ),
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "triage_not_list",
        "investigation_not_list",
        "missing_triage",
        "orphan_triage",
        "duplicate_triage_id",
        "wrong_triage_incident",
        "missing_investigation",
        "orphan_investigation",
        "duplicate_investigation_id",
        "wrong_investigation_incident",
        "wrong_investigation_triage",
        "wrong_derived_triage_id",
        "wrong_derived_investigation_id",
        "triage_order",
        "investigation_order",
    ],
)
def test_composition_semantic_validation_rejects_invalid_downstream_output(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    valid = defender_pipeline.run_common_detection_to_investigation(
        [*auth_sequence(), uncovered_detection()]
    )
    triages: object = deepcopy(valid["triage_results"])
    investigations: object = deepcopy(valid["investigation_results"])
    if mutation == "triage_not_list":
        triages = {}
    elif mutation == "investigation_not_list":
        investigations = {}
    elif mutation == "missing_triage":
        triages.pop()
    elif mutation == "orphan_triage":
        triages[0]["incident_id"] = "inc-orphan"
        triages[0]["triage_id"] = "triage-inc-orphan"
    elif mutation == "duplicate_triage_id":
        triages[1]["triage_id"] = triages[0]["triage_id"]
    elif mutation == "wrong_triage_incident":
        triages[0]["incident_id"] = "inc-wrong"
    elif mutation == "missing_investigation":
        investigations.pop()
    elif mutation == "orphan_investigation":
        investigations[0]["incident_id"] = "inc-orphan"
        investigations[0]["investigation_id"] = "investigation-inc-orphan"
    elif mutation == "duplicate_investigation_id":
        investigations[1]["investigation_id"] = investigations[0]["investigation_id"]
    elif mutation == "wrong_investigation_incident":
        investigations[0]["incident_id"] = "inc-wrong"
    elif mutation == "wrong_investigation_triage":
        investigations[0]["triage_id"] = "triage-wrong"
    elif mutation == "wrong_derived_triage_id":
        triages[0]["triage_id"] = "triage-wrong"
    elif mutation == "wrong_derived_investigation_id":
        investigations[0]["investigation_id"] = "investigation-wrong"
    elif mutation == "triage_order":
        triages.reverse()
    elif mutation == "investigation_order":
        investigations.reverse()

    _run_with_mutated_downstream(
        monkeypatch,
        valid,
        triage_results=triages,
        investigation_results=investigations,
    )

    with pytest.raises(
        defender_pipeline.CommonPipelineCompositionError,
        match="composition output validation failed",
    ):
        defender_pipeline.run_common_detection_to_investigation([])


def test_all_external_inputs_are_immutable() -> None:
    inputs = {
        "detections": [uncovered_detection()],
        "attack_result": {"attack_id": "attack-fixture"},
        "process_events": [],
        "auditd_events": [],
        "endpoint_events": None,
        "process_chain_hits": [],
        "zeek_enrichment": [],
        "wazuh_fim_alerts": [],
        "wazuh_sudo_alerts": [],
        "ssh_auth_events": [],
    }
    original = deepcopy(inputs)

    defender_pipeline.run_common_detection_to_investigation(**inputs)

    assert inputs == original


def test_bundle_does_not_add_attacker_or_response_evidence() -> None:
    bundle = defender_pipeline.run_common_detection_to_investigation(
        [*auth_sequence(), uncovered_detection()]
    )

    serialized = json.dumps(bundle)
    assert all(marker not in serialized for marker in FORBIDDEN_MARKERS)
    assert collect_keys(bundle).isdisjoint(FORBIDDEN_KEYS)


def test_linux_scenario_009_reaches_investigation_without_detection_loss() -> None:
    endpoint_events = load_json(LINUX_FIXTURE_PATH)
    detections = run_common_detection_pipeline(endpoint_events, [load_rule(LINUX_RULE_PATH)])

    bundle = defender_pipeline.run_common_detection_to_investigation(
        detections,
        endpoint_events=endpoint_events,
        endpoint_events_source=str(LINUX_FIXTURE_PATH),
    )

    assert [len(bundle[key]) for key in bundle] == [1, 0, 1, 1, 1]
    assert bundle["deduped_detections"][0]["id"] == detections[0]["id"]
    assert_linkage(bundle)


@pytest.mark.parametrize(
    ("fixture_name", "expected_count"),
    [
        ("sysmon-event1-ordinary-powershell-001.json", 1),
        ("sysmon-event1-encoded-flag-001.json", 2),
        ("sysmon-event1-ordinary-notepad-001.json", 0),
    ],
)
def test_windows_fixtures_reach_investigation_through_composition(
    fixture_name: str,
    expected_count: int,
) -> None:
    event = load_json(WINDOWS_NORMALIZED_DIR / fixture_name)
    endpoint_events = endpoint_envelope(event)
    detections = run_common_detection_pipeline(
        endpoint_events,
        [load_rule(path) for path in WINDOWS_RULE_PATHS],
    )

    bundle = defender_pipeline.run_common_detection_to_investigation(
        detections,
        endpoint_events=endpoint_events,
        endpoint_events_source=str(WINDOWS_NORMALIZED_DIR / fixture_name),
        observation_incident_severity="low",
    )

    assert [len(bundle[key]) for key in bundle] == [
        expected_count,
        0,
        expected_count,
        expected_count,
        expected_count,
    ]
    assert all(incident["severity"] == "low" for incident in bundle["incidents"])
    assert_linkage(bundle)
