import importlib.util
import json
import sys
from pathlib import Path

import pytest

from common import defender_pipeline
from detection.compiler.loader import load_rule

NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
SLICE2_FIXTURE_PATH = Path(
    "tests/fixtures/windows/sysmon_event1/slice2/powershell_parent_child_encoded_command.json"
)
INVESTIGATION_PATH = Path("agents/investigation-agent/src/main.py")
HARNESS_PATH = Path("scripts/run_triage_harness.py")
RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def windows_rules() -> list[dict]:
    return [load_rule(path) for path in RULE_PATHS]


def test_rule_triage_grounds_unknown_rules_in_canonical_incident_artifacts() -> None:
    notepad = load_json(NORMALIZED_DIR / "sysmon-event1-ordinary-notepad-001.json")
    powershell = load_json(NORMALIZED_DIR / "sysmon-event1-ordinary-powershell-001.json")
    endpoint_events = {
        "schema_version": "endpoint_events.v1",
        "events": [notepad, powershell],
    }

    bundle = defender_pipeline.run_common_endpoint_to_investigation(
        endpoint_events,
        windows_rules(),
    )

    assert len(bundle["incidents"]) == 1
    triage = bundle["triage_results"][0]
    assert triage["key_observations"] == ["powershell process observed"]
    assert triage["attack_story"] == triage["key_observations"]
    assert triage["summary"] == (
        "Rule-based triage observed canonical artifact(s): powershell process observed."
    )
    assert triage["recommended_actions"] == []

    # Artifact grounding does not tune the existing assessment fallback.
    assert (triage["verdict"], triage["confidence"], triage["priority"]) == (
        "benign",
        "low",
        "P3",
    )
    assert triage["risk_score"] == 10


def test_investigation_binds_correlation_evidence_to_incident_input_refs() -> None:
    endpoint_events = load_json(SLICE2_FIXTURE_PATH)
    unrelated = load_json(NORMALIZED_DIR / "sysmon-event1-ordinary-notepad-001.json")
    endpoint_events["events"].append(unrelated)

    result = defender_pipeline.run_common_endpoint_to_investigation(
        endpoint_events,
        windows_rules(),
    )["investigation_results"][0]

    assert result["evidence"]["endpoint_event_refs"] == ["input[0]", "input[1]"]
    assert result["evidence"]["endpoint_event_count"] == 2
    assert [event["event_id"] for event in result["evidence"]["endpoint_events"]] == [
        event["event_id"] for event in endpoint_events["events"][:2]
    ]

    observed_facts = result["evidence_summary"]["observed_facts"]
    assert all(
        any(event["command_line"] in fact for fact in observed_facts)
        for event in endpoint_events["events"][:2]
    )
    assert all(unrelated["command_line"] not in fact for fact in observed_facts)


def test_slice2_triage_and_investigation_preserve_correlation_evidence_boundary() -> None:
    bundle = defender_pipeline.run_common_endpoint_to_investigation(
        load_json(SLICE2_FIXTURE_PATH),
        windows_rules(),
    )

    triage = bundle["triage_results"][0]
    assert triage["key_observations"] == [
        "powershell process observed",
        "encoded command observed",
    ]
    assert triage["verdict"] == "benign"
    assert triage["confidence"] == "low"

    investigation = bundle["investigation_results"][0]
    assert investigation["evidence"]["endpoint_event_refs"] == [
        "input[0]",
        "input[1]",
    ]
    assert investigation["evidence"]["endpoint_event_count"] == 2
    assert investigation["evidence_summary"]["evidence_gaps"]
    assert investigation["unsupported_claims"]

    serialized = json.dumps(investigation).lower()
    assert "confirmed compromise" not in serialized
    assert "attack success" not in serialized
    assert "malicious powershell" not in serialized


def test_windows_investigation_output_reaches_existing_harness_specificity_axis() -> None:
    result = defender_pipeline.run_common_endpoint_to_investigation(
        load_json(SLICE2_FIXTURE_PATH),
        windows_rules(),
    )["investigation_results"][0]
    harness = load_module("windows_downstream_harness", HARNESS_PATH)
    compare_result = {
        "agent_only_items": {
            "rule_investigation": {
                "evidence_present": True,
            }
        }
    }

    score, reason = harness.score_evidence_specificity(
        compare_result,
        result,
        "rule_investigation",
    )

    assert score > 0.4
    assert "command/path/url evidence from endpoint telemetry" in reason


@pytest.mark.parametrize(
    "raw_event_refs",
    [
        ["input[2]"],
        ["input[0]", "source-native-ref"],
    ],
)
def test_ambiguous_or_out_of_range_endpoint_evidence_binding_fails_closed(
    raw_event_refs: list[str],
) -> None:
    investigation = load_module(
        "windows_downstream_investigation",
        INVESTIGATION_PATH,
    )
    endpoint_events = {
        "schema_version": "endpoint_events.v1",
        "events": [load_json(NORMALIZED_DIR / "sysmon-event1-ordinary-powershell-001.json")],
    }

    with pytest.raises(investigation.InvestigationBoundaryValidationError):
        investigation.build_investigation_result(
            incident={
                "incident_id": "inc-evidence-binding",
                "correlation_id": "corr-evidence-binding",
                "timeline": [],
                "raw_event_refs": raw_event_refs,
            },
            triage_result={"triage_id": "triage-inc-evidence-binding"},
            endpoint_events=endpoint_events,
        )
