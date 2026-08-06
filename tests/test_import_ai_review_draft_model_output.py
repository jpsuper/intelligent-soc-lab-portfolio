import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

MODULE_PATH = Path("scripts/import_ai_review_draft_model_output.py")
FIXTURE_DIR = Path("tests/fixtures/rule_improvement_ai_review_draft_model_output")
BUNDLE_PATH = FIXTURE_DIR / "prompt_bundle.json"
VALID_MODEL_OUTPUT_PATH = FIXTURE_DIR / "valid_model_output.json"
EXPECTED_PATH = FIXTURE_DIR / "expected_imported_draft.json"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "import_ai_review_draft_model_output",
        MODULE_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def import_valid(importer, output_path: Path, *, draft_id: str | None = None) -> dict:
    return importer.import_ai_review_draft_model_output(
        BUNDLE_PATH,
        VALID_MODEL_OUTPUT_PATH,
        output_path,
        draft_id=draft_id,
    )


def test_valid_model_output_imports_deterministically(tmp_path: Path) -> None:
    importer = load_module()
    output_path = tmp_path / "rule_improvement_ai_review_draft.json"

    result = import_valid(importer, output_path)

    assert result == load_json(EXPECTED_PATH)
    assert load_json(output_path) == load_json(EXPECTED_PATH)
    assert output_path.read_bytes() == EXPECTED_PATH.read_bytes()


def test_repeated_imports_are_byte_identical(tmp_path: Path) -> None:
    importer = load_module()
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"

    import_valid(importer, first_path)
    import_valid(importer, second_path)

    assert first_path.read_bytes() == second_path.read_bytes()


def test_invalid_schema_fails_closed(tmp_path: Path) -> None:
    importer = load_module()
    output_path = tmp_path / "draft.json"

    with pytest.raises(ValidationError):
        importer.import_ai_review_draft_model_output(
            BUNDLE_PATH,
            FIXTURE_DIR / "invalid_schema_model_output.json",
            output_path,
        )

    assert not output_path.exists()


@pytest.mark.parametrize(
    ("fixture_name", "error_match"),
    [
        (
            "invalid_source_review_input_id.json",
            "source_review_input_id does not match",
        ),
        ("invalid_unknown_signal_ref.json", "unknown source_signal_ref"),
        ("invalid_forbidden_field.json", "forbidden fields"),
    ],
)
def test_inconsistent_or_forbidden_output_fails_closed(
    fixture_name: str,
    error_match: str,
    tmp_path: Path,
) -> None:
    importer = load_module()
    output_path = tmp_path / "draft.json"

    with pytest.raises(ValueError, match=error_match):
        importer.import_ai_review_draft_model_output(
            BUNDLE_PATH,
            FIXTURE_DIR / fixture_name,
            output_path,
        )

    assert not output_path.exists()


def test_invalid_boundary_flags_fail_closed(tmp_path: Path) -> None:
    importer = load_module()
    output_path = tmp_path / "draft.json"

    with pytest.raises((ValidationError, ValueError)):
        importer.import_ai_review_draft_model_output(
            BUNDLE_PATH,
            FIXTURE_DIR / "invalid_boundary_flags.json",
            output_path,
        )

    assert not output_path.exists()


def test_inconsistent_source_review_input_ref_fails_closed(tmp_path: Path) -> None:
    importer = load_module()
    bundle = load_json(BUNDLE_PATH)
    bundle["source_review_input_ref"] = "data/runs/wrong/review_input.json"
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    output_path = tmp_path / "draft.json"

    with pytest.raises(ValueError, match="source_review_input_ref does not match"):
        importer.import_ai_review_draft_model_output(
            bundle_path,
            VALID_MODEL_OUTPUT_PATH,
            output_path,
        )

    assert not output_path.exists()


def test_malformed_json_fails_closed(tmp_path: Path) -> None:
    importer = load_module()
    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text('{"draft_id":', encoding="utf-8")
    output_path = tmp_path / "draft.json"

    with pytest.raises(json.JSONDecodeError):
        importer.import_ai_review_draft_model_output(
            BUNDLE_PATH,
            malformed_path,
            output_path,
        )

    assert not output_path.exists()


def test_optional_draft_id_override_is_validated_and_deterministic(
    tmp_path: Path,
) -> None:
    importer = load_module()
    output_path = tmp_path / "draft.json"

    result = import_valid(
        importer,
        output_path,
        draft_id="ri-ai-review-draft-imported-custom-001",
    )

    assert result["draft_id"] == "ri-ai-review-draft-imported-custom-001"
    assert load_json(output_path)["draft_id"] == result["draft_id"]


def test_import_reads_only_bundle_output_and_schemas(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    importer = load_module()
    original_load_json = importer.load_json
    loaded_paths: list[Path] = []

    def tracking_load_json(path: Path) -> dict:
        loaded_paths.append(path)
        return original_load_json(path)

    monkeypatch.setattr(importer, "load_json", tracking_load_json)
    output_path = tmp_path / "rule_improvement_ai_review_draft.json"
    import_valid(importer, output_path)

    assert set(loaded_paths) == {
        BUNDLE_PATH,
        VALID_MODEL_OUTPUT_PATH,
        importer.OUTPUT_SCHEMA_PATH,
        importer.PROMPT_INPUT_SCHEMA_PATH,
    }
    for name in (
        "human_review_worksheet.md",
        "human_decisions_template.json",
        "rule_improvement_signal_classification.json",
        "rule_candidates.yaml",
        "prompt_candidates.yaml",
        "promotion_recommendation.yaml",
    ):
        assert not (tmp_path / name).exists()


def test_importer_has_no_model_runner_or_network_integration() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8").lower()

    for forbidden in (
        "openai",
        "ollama",
        "requests",
        "httpx",
        "urllib",
        "socket",
        "subprocess",
    ):
        assert forbidden not in source
