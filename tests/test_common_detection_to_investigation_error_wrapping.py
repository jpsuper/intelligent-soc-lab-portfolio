from pathlib import Path

import pytest

from common.defender_pipeline import (
    CommonPipelineCompositionError,
    run_common_detection_to_investigation,
)


def canonical_detection() -> dict:
    timestamp = "2026-08-01T00:00:00Z"
    return {
        "id": "det-rule-input-error",
        "rule_id": "test.process-exec",
        "title": "Test process execution",
        "log_source": {"product": "linux"},
        "event_type": "process_exec",
        "artifact": "process_exec",
        "severity": "low",
        "host": "fixture-host",
        "user": "fixture-user",
        "src_ip": None,
        "path": None,
        "command_line": "/bin/id",
        "behavior_features": {"process_exec_observed": True},
        "evidence_refs": ["evidence.json#det-rule-input-error"],
        "raw_event_refs": ["input[det-rule-input-error]"],
        "time_window_start": timestamp,
        "time_window_end": timestamp,
    }


def assert_wrapped_rule_error(
    exc_info: pytest.ExceptionInfo[CommonPipelineCompositionError],
) -> BaseException:
    composition_error = exc_info.value
    assert "rule triage stage failed:" in str(composition_error)

    boundary_error = composition_error.__cause__
    assert boundary_error is not None
    assert boundary_error.__class__.__name__ == "TriageBoundaryValidationError"
    assert "triage_results[0] rule evaluation failed:" in str(boundary_error)

    root_cause = boundary_error.__cause__
    assert root_cause is not None
    return root_cause


@pytest.mark.parametrize(
    "path_argument",
    [
        "derived_rules_path",
        "assessment_rules_path",
    ],
)
def test_missing_rule_file_is_wrapped_by_composition(
    tmp_path: Path,
    path_argument: str,
) -> None:
    missing_path = tmp_path / f"missing-{path_argument}.yaml"

    with pytest.raises(CommonPipelineCompositionError) as exc_info:
        run_common_detection_to_investigation(
            [canonical_detection()],
            **{path_argument: str(missing_path)},
        )

    root_cause = assert_wrapped_rule_error(exc_info)
    assert isinstance(root_cause, FileNotFoundError)


@pytest.mark.parametrize(
    ("rule_content", "expected_root_cause"),
    [
        ("rules: {}\n", "ValueError"),
        (
            "rules:\n"
            "  - id: invalid-rule\n"
            "    name: Invalid rule\n"
            "    when:\n"
            "      all:\n"
            "        - feature: process_exec_observed\n"
            "          equals: true\n",
            "ValueError",
        ),
        (
            "rules:\n  - id: [unterminated\n",
            "ParserError",
        ),
    ],
)
def test_invalid_rule_file_is_wrapped_by_composition(
    tmp_path: Path,
    rule_content: str,
    expected_root_cause: str,
) -> None:
    rule_path = tmp_path / "invalid-derived-rules.yaml"
    rule_path.write_text(rule_content, encoding="utf-8")

    with pytest.raises(CommonPipelineCompositionError) as exc_info:
        run_common_detection_to_investigation(
            [canonical_detection()],
            derived_rules_path=str(rule_path),
        )

    root_cause = assert_wrapped_rule_error(exc_info)
    assert root_cause.__class__.__name__ == expected_root_cause
