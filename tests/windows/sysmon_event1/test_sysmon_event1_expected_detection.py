import json
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator

from detection.compiler.evaluator import evaluate_rules_against_events
from detection.compiler.loader import load_rule

SOURCE_DIR = Path("tests/fixtures/windows/sysmon_event1/source")
PARSED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_parsed")
NORMALIZED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_normalized")
EXPECTED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_detection")
SCHEMA_PATH = Path("schemas/sysmon_event1_expected_detection.schema.json")
RULE_PATHS = [
    Path("detection/dsl/windows_powershell_encoded_command_observed.yaml"),
    Path("detection/dsl/windows_powershell_process_observed.yaml"),
]

FIXTURE_A_ID = "sysmon-event1-ordinary-powershell-001"
FIXTURE_B_ID = "sysmon-event1-encoded-flag-001"
FIXTURE_C_ID = "sysmon-event1-ordinary-notepad-001"
EXPECTED_OUTCOMES = {
    FIXTURE_A_ID: {
        "matched_rule_ids": ["execution.windows_powershell_process_observed"],
        "behavior_features": {"powershell_process_observed": True},
    },
    FIXTURE_B_ID: {
        "matched_rule_ids": [
            "execution.windows_powershell_encoded_command_observed",
            "execution.windows_powershell_process_observed",
        ],
        "behavior_features": {
            "encoded_command_observed": True,
            "powershell_process_observed": True,
        },
    },
    FIXTURE_C_ID: {
        "matched_rule_ids": [],
        "behavior_features": {},
    },
}
FORBIDDEN_EXPECTED_KEYS = {
    "severity",
    "confidence",
    "verdict",
    "malicious",
    "assessment",
    "incident",
    "response",
    "approval",
}
FORBIDDEN_RUNTIME_VALUES = {
    "".join(("WIN-", "VICTIM01")),
    ".".join(("192", "168", "1", "31")),
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def json_paths(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.json"))


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def collect_string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for child in value.values() for text in collect_string_values(child)]
    if isinstance(value, list):
        return [text for child in value for text in collect_string_values(child)]
    return []


def load_windows_rules() -> list[dict]:
    return [load_rule(path) for path in RULE_PATHS]


def build_actual_summary(event: dict, rules: list[dict]) -> tuple[dict, list[dict]]:
    detections = evaluate_rules_against_events([event], rules)
    behavior_features = {
        key: True
        for detection in detections
        for key, value in detection["behavior_features"].items()
        if value is True
    }
    fixture_id = event["raw_ref"]["fixture_id"]
    return (
        {
            "schema_version": "sysmon_event1_expected_detection.v1",
            "fixture_id": fixture_id,
            "normalized_event_id": event["event_id"],
            "matched_rule_ids": sorted(detection["rule_id"] for detection in detections),
            "behavior_features": behavior_features,
        },
        detections,
    )


def test_source_parsed_normalized_and_detection_filename_inventories_match() -> None:
    inventories = [
        {path.name for path in json_paths(directory)}
        for directory in [SOURCE_DIR, PARSED_DIR, NORMALIZED_DIR, EXPECTED_DIR]
    ]

    assert inventories[0]
    assert all(inventory == inventories[0] for inventory in inventories[1:])


def test_expected_detection_identity_links_match_normalized_artifacts() -> None:
    for expected_path in json_paths(EXPECTED_DIR):
        expected = load_json(expected_path)
        normalized = load_json(NORMALIZED_DIR / expected_path.name)

        assert expected_path.stem == expected["fixture_id"]
        assert expected["normalized_event_id"] == normalized["event_id"]
        assert expected["fixture_id"] == normalized["raw_ref"]["fixture_id"]


def test_expected_detection_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(load_json(SCHEMA_PATH))


def test_expected_detection_artifacts_are_schema_valid() -> None:
    validator = Draft202012Validator(load_json(SCHEMA_PATH))

    for expected_path in json_paths(EXPECTED_DIR):
        validator.validate(load_json(expected_path))


def test_windows_rule_files_load_with_existing_dsl_loader() -> None:
    rules = load_windows_rules()

    assert {rule["id"] for rule in rules} == {
        "execution.windows_powershell_encoded_command_observed",
        "execution.windows_powershell_process_observed",
    }


def test_expected_normalized_evaluation_exactly_matches_expected_detection() -> None:
    rules = load_windows_rules()

    for normalized_path in json_paths(NORMALIZED_DIR):
        event = load_json(normalized_path)
        actual, _ = build_actual_summary(event, rules)

        assert actual == load_json(EXPECTED_DIR / normalized_path.name)


def test_fixture_a_b_and_c_have_reviewed_positive_and_negative_outcomes() -> None:
    for fixture_id, outcome in EXPECTED_OUTCOMES.items():
        expected = load_json(EXPECTED_DIR / f"{fixture_id}.json")

        assert expected["matched_rule_ids"] == outcome["matched_rule_ids"]
        assert expected["behavior_features"] == outcome["behavior_features"]


def test_expected_artifacts_exclude_assessment_and_response_fields() -> None:
    for expected_path in json_paths(EXPECTED_DIR):
        expected = load_json(expected_path)

        assert collect_keys(expected).isdisjoint(FORBIDDEN_EXPECTED_KEYS)
        assert expected["matched_rule_ids"] == sorted(expected["matched_rule_ids"])


def test_expected_artifacts_contain_only_sanitized_fixture_values() -> None:
    for expected_path in json_paths(EXPECTED_DIR):
        expected = load_json(expected_path)
        string_values = collect_string_values(expected)

        assert not any(
            forbidden in value for forbidden in FORBIDDEN_RUNTIME_VALUES for value in string_values
        )
        assert not any("://" in value for value in string_values)


def test_canonical_outputs_preserve_untrusted_event_fields_without_assessment() -> None:
    rules = load_windows_rules()
    forbidden_output_keys = {
        "malicious",
        "verdict",
        "confidence",
        "assessment",
        "incident",
        "response",
        "approval",
    }

    for normalized_path in json_paths(NORMALIZED_DIR):
        event = load_json(normalized_path)
        original_event = deepcopy(event)
        _, detections = build_actual_summary(event, rules)

        for detection in detections:
            assert detection["host"] == event["host"]
            assert detection["user"] == event["user"]
            assert detection["command_line"] == event["command_line"]
            assert set(detection).isdisjoint(forbidden_output_keys)
        assert event == original_event


def test_rule_artifact_and_behavior_feature_contracts_match() -> None:
    expected_contracts = {
        "execution.windows_powershell_encoded_command_observed": (
            "encoded_command_observed",
            {"encoded_command_observed": True},
        ),
        "execution.windows_powershell_process_observed": (
            "powershell_process_observed",
            {"powershell_process_observed": True},
        ),
    }

    for rule in load_windows_rules():
        artifact, behavior_features = expected_contracts[rule["id"]]
        assert rule["artifact"] == artifact
        assert rule["behavior_features"] == behavior_features
        assert rule["severity"] == "low"


def test_safe_placeholder_is_preserved_and_not_transformed() -> None:
    path = NORMALIZED_DIR / f"{FIXTURE_B_ID}.json"
    event = load_json(path)
    original_command_line = event["command_line"]
    _, detections = build_actual_summary(event, load_windows_rules())

    assert "SAFE_PLACEHOLDER" in original_command_line
    assert event["command_line"] == original_command_line
    assert all(detection["command_line"] == original_command_line for detection in detections)


def test_parity_inputs_are_not_generated_or_overwritten() -> None:
    input_paths = [
        path
        for directory in [
            SOURCE_DIR,
            PARSED_DIR,
            NORMALIZED_DIR,
            EXPECTED_DIR,
        ]
        for path in json_paths(directory)
    ]
    before = {path: path.read_bytes() for path in input_paths}

    rules = load_windows_rules()
    for normalized_path in json_paths(NORMALIZED_DIR):
        build_actual_summary(load_json(normalized_path), rules)

    assert {path: path.read_bytes() for path in input_paths} == before
