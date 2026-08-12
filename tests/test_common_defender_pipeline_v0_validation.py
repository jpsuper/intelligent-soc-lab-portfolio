import json
from copy import deepcopy
from pathlib import Path

import pytest

from common import defender_pipeline
from detection.compiler.loader import load_rule
from detection.compiler.pipeline import CommonPipelineValidationError

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


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def assert_bundle_linkage(bundle: dict) -> None:
    incident_ids = {item["incident_id"] for item in bundle["incidents"]}
    assert incident_ids == {item["incident_id"] for item in bundle["triage_results"]}
    assert incident_ids == {item["incident_id"] for item in bundle["investigation_results"]}
    triages = {item["incident_id"]: item for item in bundle["triage_results"]}
    for investigation in bundle["investigation_results"]:
        incident_id = investigation["incident_id"]
        assert triages[incident_id]["triage_id"] == f"triage-{incident_id}"
        assert investigation["investigation_id"] == f"investigation-{incident_id}"
        assert investigation["triage_id"] == triages[incident_id]["triage_id"]


def test_common_defender_pipeline_v0_cross_platform_execution_matrix() -> None:
    linux_endpoint_events = load_json(LINUX_FIXTURE_PATH)
    windows_fixtures = [
        ("sysmon-event1-ordinary-powershell-001.json", 1),
        ("sysmon-event1-encoded-flag-001.json", 2),
        ("sysmon-event1-ordinary-notepad-001.json", 0),
    ]
    cases = [
        (
            "linux-scenario-009",
            linux_endpoint_events,
            [load_rule(LINUX_RULE_PATH)],
            str(LINUX_FIXTURE_PATH),
            1,
            "medium",
        ),
        *[
            (
                fixture_name,
                endpoint_envelope(load_json(WINDOWS_NORMALIZED_DIR / fixture_name)),
                [load_rule(path) for path in WINDOWS_RULE_PATHS],
                str(WINDOWS_NORMALIZED_DIR / fixture_name),
                expected_count,
                "low",
            )
            for fixture_name, expected_count in windows_fixtures
        ],
    ]

    observed_platforms: set[str] = set()
    for case_name, endpoint_events, rules, source, expected_count, expected_severity in cases:
        original_endpoint_events = deepcopy(endpoint_events)
        original_rules = deepcopy(rules)

        bundle = defender_pipeline.run_common_endpoint_to_investigation(
            endpoint_events,
            rules,
            endpoint_events_source=source,
        )

        observed_platforms.update(event["platform"] for event in endpoint_events["events"])
        assert endpoint_events == original_endpoint_events, case_name
        assert rules == original_rules, case_name
        assert [len(bundle[key]) for key in bundle] == [
            expected_count,
            0,
            expected_count,
            expected_count,
            expected_count,
        ], case_name
        assert all(incident["severity"] == expected_severity for incident in bundle["incidents"])
        assert_bundle_linkage(bundle)

        serialized = json.dumps(bundle)
        assert all(marker not in serialized for marker in FORBIDDEN_MARKERS), case_name
        assert collect_keys(bundle).isdisjoint(FORBIDDEN_KEYS), case_name

    assert observed_platforms == {"linux", "windows"}


def test_endpoint_validation_failure_stops_before_downstream_composition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    downstream_called = False

    def unexpected_downstream(*args: object, **kwargs: object) -> dict:
        nonlocal downstream_called
        downstream_called = True
        return {}

    monkeypatch.setattr(
        defender_pipeline,
        "run_common_detection_to_investigation",
        unexpected_downstream,
    )

    with pytest.raises(
        defender_pipeline.CommonPipelineCompositionError,
        match="detection stage failed: .*endpoint_events.v1 validation",
    ) as error:
        defender_pipeline.run_common_endpoint_to_investigation(
            {"schema_version": "endpoint_events.v1"},
            [load_rule(LINUX_RULE_PATH)],
        )

    assert isinstance(error.value.__cause__, CommonPipelineValidationError)
    assert downstream_called is False
