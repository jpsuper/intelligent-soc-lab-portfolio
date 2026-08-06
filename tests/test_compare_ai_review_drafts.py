import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = Path("scripts/compare_ai_review_drafts.py")
FIXTURE_DIR = Path("tests/fixtures/rule_improvement_ai_review_draft_comparison")
MOCK_PATH = FIXTURE_DIR / "mock_draft.json"
OPENAI_PATH = FIXTURE_DIR / "openai_draft.json"
LMSTUDIO_PATH = FIXTURE_DIR / "lmstudio_draft.json"
INVALID_PATH = FIXTURE_DIR / "invalid_draft.json"
SOURCE_REVIEW_INPUT_ID = "ri-review-comparison-001"
SOURCE_REVIEW_INPUT_REF = "data/runs/run-comparison/rule_improvement_review_input.json"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "compare_ai_review_drafts",
        MODULE_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compare_default(comparer, output_path: Path) -> dict:
    return comparer.compare_ai_review_drafts(
        [
            f"mock={MOCK_PATH}",
            f"openai={OPENAI_PATH}",
            f"lmstudio={LMSTUDIO_PATH}",
        ],
        output_path,
        comparison_id="ai-review-draft-comparison-test",
    )


def test_valid_candidates_produce_deterministic_comparison_json(
    tmp_path: Path,
) -> None:
    comparer = load_module()
    output_path = tmp_path / "ai_review_draft_comparison.json"

    result = compare_default(comparer, output_path)

    assert result == load_json(output_path)
    assert result["comparison_id"] == "ai-review-draft-comparison-test"
    assert result["source_review_input_id"] == SOURCE_REVIEW_INPUT_ID
    assert result["source_review_input_ref"] == SOURCE_REVIEW_INPUT_REF
    assert result["candidate_count"] == 3
    assert result["valid_candidate_count"] == 3
    assert result["invalid_candidate_count"] == 0
    assert result["summary"]["schema_pass_rate"] == 1.0
    assert result["summary"]["candidate_names_by_validity"] == {
        "valid": ["mock", "openai", "lmstudio"],
        "invalid": [],
    }
    assert result["candidates"][0] == {
        "name": "mock",
        "path": str(MOCK_PATH),
        "schema_valid": True,
        "validation_error": None,
        "draft_id": "ri-ai-review-draft-mock-comparison-001",
        "suggestion_count": 3,
        "label_counts": {
            "insufficient_evidence": 1,
            "parser_gap": 1,
            "telemetry_gap": 1,
        },
        "signal_refs": [
            "/supporting_signals/0",
            "/supporting_signals/1",
            "/supporting_signals/2",
        ],
        "empty_evidence_caveat_count": 0,
        "empty_review_question_count": 0,
        "missing_confidence_rationale_count": 0,
        "warning_count": 1,
        "error_count": 0,
    }


def test_invalid_candidate_is_recorded_with_validation_error(
    tmp_path: Path,
) -> None:
    comparer = load_module()
    output_path = tmp_path / "comparison.json"

    result = comparer.compare_ai_review_drafts(
        [f"mock={MOCK_PATH}", f"invalid={INVALID_PATH}"],
        output_path,
    )

    assert result["candidate_count"] == 2
    assert result["valid_candidate_count"] == 1
    assert result["invalid_candidate_count"] == 1
    assert result["summary"]["schema_pass_rate"] == 0.5
    invalid = result["candidates"][1]
    assert invalid["name"] == "invalid"
    assert invalid["schema_valid"] is False
    assert invalid["validation_error"]
    assert invalid["draft_id"] is None
    assert result["summary"]["candidate_names_by_validity"] == {
        "valid": ["mock"],
        "invalid": ["invalid"],
    }


def test_no_valid_candidates_fails_closed(tmp_path: Path) -> None:
    comparer = load_module()
    output_path = tmp_path / "comparison.json"

    with pytest.raises(ValueError, match="schema-valid candidate"):
        comparer.compare_ai_review_drafts([f"invalid={INVALID_PATH}"], output_path)

    assert not output_path.exists()


def test_duplicate_candidate_names_fail_closed(tmp_path: Path) -> None:
    comparer = load_module()
    output_path = tmp_path / "comparison.json"

    with pytest.raises(ValueError, match="Duplicate candidate names"):
        comparer.compare_ai_review_drafts(
            [f"mock={MOCK_PATH}", f"mock={OPENAI_PATH}"],
            output_path,
        )

    assert not output_path.exists()


@pytest.mark.parametrize("candidate_arg", ["missing-equals", "=path.json", "name="])
def test_malformed_candidate_argument_fails_closed(
    candidate_arg: str,
    tmp_path: Path,
) -> None:
    comparer = load_module()
    output_path = tmp_path / "comparison.json"

    with pytest.raises(ValueError):
        comparer.compare_ai_review_drafts([candidate_arg], output_path)

    assert not output_path.exists()


def test_mismatched_source_review_input_id_fails_closed(tmp_path: Path) -> None:
    comparer = load_module()
    mismatched = load_json(OPENAI_PATH)
    mismatched["source_review_input_id"] = "ri-review-other-001"
    mismatched_path = tmp_path / "mismatched_id.json"
    write_json(mismatched_path, mismatched)
    output_path = tmp_path / "comparison.json"

    with pytest.raises(ValueError, match="source_review_input_id"):
        comparer.compare_ai_review_drafts(
            [f"mock={MOCK_PATH}", f"other={mismatched_path}"],
            output_path,
        )

    assert not output_path.exists()


def test_mismatched_source_review_input_ref_fails_closed(tmp_path: Path) -> None:
    comparer = load_module()
    mismatched = load_json(OPENAI_PATH)
    mismatched["source_review_input_ref"] = "data/runs/other/rule_improvement_review_input.json"
    mismatched_path = tmp_path / "mismatched_ref.json"
    write_json(mismatched_path, mismatched)
    output_path = tmp_path / "comparison.json"

    with pytest.raises(ValueError, match="source_review_input_ref"):
        comparer.compare_ai_review_drafts(
            [f"mock={MOCK_PATH}", f"other={mismatched_path}"],
            output_path,
        )

    assert not output_path.exists()


def test_explicit_source_metadata_must_match_valid_candidates(
    tmp_path: Path,
) -> None:
    comparer = load_module()
    output_path = tmp_path / "comparison.json"

    with pytest.raises(ValueError, match="--source-review-input-id"):
        comparer.compare_ai_review_drafts(
            [f"mock={MOCK_PATH}", f"openai={OPENAI_PATH}"],
            output_path,
            source_review_input_id="ri-review-explicit-other",
        )

    assert not output_path.exists()


def test_signal_matrix_captures_disagreement_and_missing_coverage(
    tmp_path: Path,
) -> None:
    comparer = load_module()
    result = compare_default(comparer, tmp_path / "comparison.json")
    by_ref = {item["source_signal_ref"]: item for item in result["signal_matrix"]}

    assert by_ref["/supporting_signals/0"] == {
        "source_signal_ref": "/supporting_signals/0",
        "labels_by_candidate": {
            "mock": "insufficient_evidence",
            "openai": "timing_or_scope_limit",
            "lmstudio": "detection_gap",
        },
        "label_disagreement": True,
        "present_in_candidates": ["mock", "openai", "lmstudio"],
        "missing_from_candidates": [],
    }
    assert by_ref["/supporting_signals/2"] == {
        "source_signal_ref": "/supporting_signals/2",
        "labels_by_candidate": {
            "mock": "telemetry_gap",
            "lmstudio": "telemetry_gap",
        },
        "label_disagreement": False,
        "present_in_candidates": ["mock", "lmstudio"],
        "missing_from_candidates": ["openai"],
    }
    assert result["summary"]["signals_with_label_disagreement"] == 1
    assert result["summary"]["signals_missing_from_any_valid_candidate"] == 1


def test_empty_and_missing_field_counters_work_on_candidate_metrics() -> None:
    comparer = load_module()
    metrics = comparer._candidate_metrics(
        {
            "draft_id": "synthetic",
            "suggestions": [
                {
                    "source_signal_ref": "/supporting_signals/0",
                    "suggested_label": "insufficient_evidence",
                    "evidence_caveats": [],
                    "review_questions": ["What is missing?"],
                    "confidence_rationale": "",
                },
                {
                    "source_signal_ref": "/supporting_signals/1",
                    "suggested_label": "parser_gap",
                    "evidence_caveats": ["Parser extraction is limited."],
                    "review_questions": [],
                },
            ],
            "warnings": ["warning"],
            "errors": ["error"],
        }
    )

    assert metrics["empty_evidence_caveat_count"] == 1
    assert metrics["empty_review_question_count"] == 1
    assert metrics["missing_confidence_rationale_count"] == 2
    assert metrics["warning_count"] == 1
    assert metrics["error_count"] == 1


def test_output_is_byte_stable_across_repeated_runs(tmp_path: Path) -> None:
    comparer = load_module()
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"

    compare_default(comparer, first_path)
    compare_default(comparer, second_path)

    assert first_path.read_bytes() == second_path.read_bytes()


def test_comparison_creates_no_downstream_artifacts(tmp_path: Path) -> None:
    comparer = load_module()
    compare_default(comparer, tmp_path / "ai_review_draft_comparison.json")

    for name in (
        "rule_improvement_signal_classification.json",
        "human_decisions_template.json",
        "rule_candidates.yaml",
        "prompt_candidates.yaml",
        "promotion_recommendation.yaml",
    ):
        assert not (tmp_path / name).exists()


def test_refuses_downstream_artifact_output_name(tmp_path: Path) -> None:
    comparer = load_module()
    output_path = tmp_path / "rule_candidates.yaml"

    with pytest.raises(ValueError, match="downstream artifact"):
        comparer.compare_ai_review_drafts([f"mock={MOCK_PATH}"], output_path)

    assert not output_path.exists()


def test_script_source_does_not_execute_models_or_call_importer() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8").lower()

    for forbidden in (
        "openai",
        "lmstudio",
        "urlopen",
        "requests",
        "httpx",
        "subprocess",
        "import_ai_review_draft_model_output",
        "generate_mock_ai_review_draft",
    ):
        assert forbidden not in source
