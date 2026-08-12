import inspect
import json
from copy import deepcopy
from pathlib import Path

import pytest

from common import defender_pipeline
from detection.compiler.loader import load_rule
from detection.compiler.pipeline import REQUIRED_DETECTION_KEYS

LINUX_FIXTURE_PATH = Path(
    "tests/fixtures/scenario_009_suspicious_archive_staging/endpoint_events.json"
)
LINUX_RULE_PATH = Path("detection/dsl/suspicious_archive_staging.yaml")
WINDOWS_NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
WINDOWS_SLICE2_FIXTURE_PATH = Path(
    "tests/fixtures/windows/sysmon_event1/slice2/powershell_parent_child_encoded_command.json"
)
WINDOWS_RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]
EXPECTED_BUNDLE_KEYS = [
    "deduped_detections",
    "correlations",
    "incidents",
    "triage_results",
    "investigation_results",
]
FORBIDDEN_NATIVE_INPUTS = {
    "auditd_events",
    "process_events",
    "process_chain_hits",
    "ssh_auth_events",
    "wazuh_fim_alerts",
    "wazuh_sudo_alerts",
    "zeek_enrichment",
}
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


def windows_rules() -> list[dict]:
    return [load_rule(path) for path in WINDOWS_RULE_PATHS]


def validation_cases() -> list[dict]:
    windows_fixtures = [
        ("windows-slice1-fixture-a", "sysmon-event1-ordinary-powershell-001.json", 1),
        ("windows-slice1-fixture-b", "sysmon-event1-encoded-flag-001.json", 2),
        ("windows-slice1-fixture-c", "sysmon-event1-ordinary-notepad-001.json", 0),
    ]
    return [
        {
            "name": "linux-scenario-009",
            "endpoint_events": load_json(LINUX_FIXTURE_PATH),
            "rules": [load_rule(LINUX_RULE_PATH)],
            "source": str(LINUX_FIXTURE_PATH),
            "counts": [1, 0, 1, 1, 1],
            "correlation_types": [],
            "severity": "medium",
        },
        *[
            {
                "name": name,
                "endpoint_events": endpoint_envelope(
                    load_json(WINDOWS_NORMALIZED_DIR / fixture_name)
                ),
                "rules": windows_rules(),
                "source": str(WINDOWS_NORMALIZED_DIR / fixture_name),
                "counts": [expected_count, 0, expected_count, expected_count, expected_count],
                "correlation_types": [],
                "severity": "low",
            }
            for name, fixture_name, expected_count in windows_fixtures
        ],
        {
            "name": "windows-slice2-parent-child-correlation",
            "endpoint_events": load_json(WINDOWS_SLICE2_FIXTURE_PATH),
            "rules": windows_rules(),
            "source": str(WINDOWS_SLICE2_FIXTURE_PATH),
            "counts": [3, 1, 1, 1, 1],
            "correlation_types": ["windows_powershell_parent_child_encoded_command"],
            "severity": "medium",
        },
    ]


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def assert_bundle_linkage(bundle: dict) -> None:
    incident_ids = {incident["incident_id"] for incident in bundle["incidents"]}
    assert incident_ids == {triage["incident_id"] for triage in bundle["triage_results"]}
    assert incident_ids == {
        investigation["incident_id"] for investigation in bundle["investigation_results"]
    }

    triages = {triage["incident_id"]: triage for triage in bundle["triage_results"]}
    for investigation in bundle["investigation_results"]:
        incident_id = investigation["incident_id"]
        assert triages[incident_id]["triage_id"] == f"triage-{incident_id}"
        assert investigation["investigation_id"] == f"investigation-{incident_id}"
        assert investigation["triage_id"] == triages[incident_id]["triage_id"]


def test_common_pipeline_v1_entry_cross_platform_regression_matrix() -> None:
    observed_platforms: set[str] = set()

    for case in validation_cases():
        endpoint_events = case["endpoint_events"]
        rules = case["rules"]
        original_endpoint_events = deepcopy(endpoint_events)
        original_rules = deepcopy(rules)

        bundle = defender_pipeline.run_common_endpoint_to_investigation(
            endpoint_events,
            rules,
            endpoint_events_source=case["source"],
        )
        replay = defender_pipeline.run_common_endpoint_to_investigation(
            endpoint_events,
            rules,
            endpoint_events_source=case["source"],
        )

        assert bundle == replay, case["name"]
        assert endpoint_events == original_endpoint_events, case["name"]
        assert rules == original_rules, case["name"]
        assert list(bundle) == EXPECTED_BUNDLE_KEYS, case["name"]
        assert [len(bundle[key]) for key in EXPECTED_BUNDLE_KEYS] == case["counts"], case["name"]
        assert [correlation["correlation_type"] for correlation in bundle["correlations"]] == case[
            "correlation_types"
        ], case["name"]
        assert all(incident["severity"] == case["severity"] for incident in bundle["incidents"]), (
            case["name"]
        )

        represented_detection_ids = [
            detection_id
            for incident in bundle["incidents"]
            for detection_id in incident["matched_detection_ids"]
        ]
        deduped_detection_ids = [detection["id"] for detection in bundle["deduped_detections"]]
        assert sorted(represented_detection_ids) == sorted(deduped_detection_ids), case["name"]
        assert len(represented_detection_ids) == len(set(represented_detection_ids)), case["name"]

        assert_bundle_linkage(bundle)
        serialized = json.dumps(bundle)
        assert all(marker not in serialized for marker in FORBIDDEN_MARKERS), case["name"]
        assert collect_keys(bundle).isdisjoint(FORBIDDEN_KEYS), case["name"]
        observed_platforms.update(event["platform"] for event in endpoint_events["events"])

    assert observed_platforms == {"linux", "windows"}


@pytest.mark.parametrize("case_index", [0, 1, 4])
def test_common_endpoint_entry_uses_canonical_handoff_without_native_inputs(
    monkeypatch: pytest.MonkeyPatch,
    case_index: int,
) -> None:
    case = validation_cases()[case_index]
    captured: dict = {}

    def capture_handoff(detections: list[dict], **kwargs: object) -> dict[str, list]:
        captured["detections"] = detections
        captured["kwargs"] = kwargs
        return {key: [] for key in EXPECTED_BUNDLE_KEYS}

    monkeypatch.setattr(
        defender_pipeline,
        "run_common_detection_to_investigation",
        capture_handoff,
    )

    result = defender_pipeline.run_common_endpoint_to_investigation(
        case["endpoint_events"],
        case["rules"],
        endpoint_events_source=case["source"],
    )

    assert result == {key: [] for key in EXPECTED_BUNDLE_KEYS}
    assert FORBIDDEN_NATIVE_INPUTS.isdisjoint(captured["kwargs"])
    assert captured["kwargs"]["endpoint_events"]["schema_version"] == "endpoint_events.v1"
    assert all(REQUIRED_DETECTION_KEYS <= detection.keys() for detection in captured["detections"])
    assert all("raw" not in detection for detection in captured["detections"])


def test_common_endpoint_entry_has_no_platform_or_scenario_dispatch_parameter() -> None:
    parameters = inspect.signature(
        defender_pipeline.run_common_endpoint_to_investigation
    ).parameters

    assert "platform" not in parameters
    assert "scenario_id" not in parameters
    assert "source_parser" not in parameters
    assert "normalized_mapper" not in parameters
