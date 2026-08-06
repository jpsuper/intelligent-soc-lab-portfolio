import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

MODULE_PATH = Path("scripts/export_ai_review_draft_prompt_bundle.py")
FIXTURE_DIR = Path("tests/fixtures/rule_improvement_ai_review_draft_prompt_bundle")
SOURCE_PATH = FIXTURE_DIR / "valid_prompt_input.json"
INVALID_SOURCE_PATH = FIXTURE_DIR / "invalid_prompt_input.json"
RUN_ID = "run-prompt-bundle"
PROMPT_INPUT_FILENAME = "rule_improvement_ai_review_draft_prompt_input.json"
EXPECTED_DRAFT_ID = "ri-ai-review-draft-ri-review-prompt-bundle-001"
EXPECTED_REVIEW_INPUT_REF = f"data/runs/{RUN_ID}/rule_improvement_review_input.json"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "export_ai_review_draft_prompt_bundle",
        MODULE_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def create_run_local_source(base_path: Path) -> Path:
    source_path = base_path / "data" / "runs" / RUN_ID / PROMPT_INPUT_FILENAME
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(SOURCE_PATH.read_bytes())
    return source_path


def export(exporter, output_path: Path) -> dict:
    return exporter.export_ai_review_draft_prompt_bundle(
        create_run_local_source(output_path.parent),
        output_path,
    )


def test_valid_input_produces_deterministic_prompt_bundle(tmp_path: Path) -> None:
    exporter = load_module()
    output_path = tmp_path / "rule_improvement_ai_review_draft_prompt_bundle.json"
    source_path = create_run_local_source(tmp_path)

    result = exporter.export_ai_review_draft_prompt_bundle(source_path, output_path)

    assert load_json(output_path) == result
    assert result["bundle_id"] == ("ri-ai-review-draft-prompt-bundle-ri-review-prompt-bundle-001")
    assert result["source_stage"] == "post_action_dfir"
    assert result["source_prompt_input_id"] == (
        "ri-ai-review-draft-prompt-input-ri-review-prompt-bundle-001"
    )
    assert result["source_prompt_input_ref"] == str(source_path)
    assert result["draft_id"] == EXPECTED_DRAFT_ID
    assert result["source_review_input_id"] == "ri-review-prompt-bundle-001"
    assert result["source_review_input_ref"] == EXPECTED_REVIEW_INPUT_REF
    assert result["prompt_template_ref"] == ("prompts/rule-improvement/ai_review_draft_v1.md")
    assert result["expected_response_schema_ref"] == (
        "schemas/rule_improvement_ai_review_draft.schema.json"
    )
    assert result["prompt_input"] == load_json(SOURCE_PATH)


def test_repeated_exports_are_byte_identical(tmp_path: Path) -> None:
    exporter = load_module()
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"

    export(exporter, first_path)
    export(exporter, second_path)

    assert first_path.read_bytes() == second_path.read_bytes()


def test_bundle_locks_execution_and_decision_boundaries(tmp_path: Path) -> None:
    exporter = load_module()
    result = export(exporter, tmp_path / "bundle.json")

    assert result["model_execution_allowed"] is False
    assert result["model_execution_performed"] is False
    assert result["network_allowed"] is False
    assert result["human_review_required"] is True
    assert result["classification_decision_allowed"] is False
    assert result["candidate_generation_started"] is False
    assert result["promotion_allowed"] is False
    assert result["response_instructions"]
    assert result["safety_boundaries"]


def test_prompt_text_contains_exact_provenance_and_safety_language(
    tmp_path: Path,
) -> None:
    exporter = load_module()
    result = export(exporter, tmp_path / "bundle.json")
    prompt_text = result["prompt_text"]

    for expected in (
        "AI suggestions are not human decisions.",
        "schemas/rule_improvement_ai_review_draft.schema.json",
        "Do not approve candidates or promote anything.",
        "Do not mutate case, action, investigation, containment",
        "Linux.BashHistory as weak, user-controlled, timing-sensitive evidence",
        "Linux.ProcessList as point-in-time evidence",
        "Missing telemetry is a reviewable gap",
        "Do not read, open, fetch, or infer the contents of evidence refs.",
        "Copy these output provenance values exactly:",
        f"draft_id: {EXPECTED_DRAFT_ID}",
        "source_review_input_id: ri-review-prompt-bundle-001",
        f"source_review_input_ref: {EXPECTED_REVIEW_INPUT_REF}",
        "Do not use MISSING_REQUIRED_PROVENANCE.",
        "Do not invent provenance.",
        "If provenance is missing, fail by returning errors",
        '"source_review_input_id": "ri-review-prompt-bundle-001"',
        '"source_signal_ref": "/supporting_signals/0"',
    ):
        assert expected in prompt_text
    assert "# AI-Assisted Rule Improvement Review Draft Prompt v1" in prompt_text
    assert "raw_log" not in prompt_text


def test_non_run_local_source_prompt_input_ref_fails_closed(tmp_path: Path) -> None:
    exporter = load_module()
    output_path = tmp_path / "bundle.json"

    with pytest.raises(ValueError, match="run-local prompt input"):
        exporter.export_ai_review_draft_prompt_bundle(SOURCE_PATH, output_path)

    assert not output_path.exists()


def test_invalid_prompt_input_fails_closed(tmp_path: Path) -> None:
    exporter = load_module()
    output_path = tmp_path / "bundle.json"

    with pytest.raises(ValidationError):
        exporter.export_ai_review_draft_prompt_bundle(
            INVALID_SOURCE_PATH,
            output_path,
        )

    assert not output_path.exists()


def test_export_reads_only_input_schema_and_prompt_template(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exporter = load_module()
    original_load_json = exporter.load_json
    original_load_text = exporter.load_text
    loaded_json_paths: list[Path] = []
    loaded_text_paths: list[Path] = []

    def tracking_load_json(path: Path) -> dict:
        loaded_json_paths.append(path)
        return original_load_json(path)

    def tracking_load_text(path: Path) -> str:
        loaded_text_paths.append(path)
        return original_load_text(path)

    monkeypatch.setattr(exporter, "load_json", tracking_load_json)
    monkeypatch.setattr(exporter, "load_text", tracking_load_text)
    source_path = create_run_local_source(tmp_path)
    output_path = tmp_path / "bundle.json"
    exporter.export_ai_review_draft_prompt_bundle(source_path, output_path)

    assert set(loaded_json_paths) == {source_path, exporter.SOURCE_SCHEMA_PATH}
    assert loaded_text_paths == [exporter.DEFAULT_PROMPT_TEMPLATE_PATH]
    for name in (
        "rule_improvement_ai_review_draft.json",
        "human_review_worksheet.md",
        "human_decisions_template.json",
        "rule_improvement_signal_classification.json",
        "rule_candidates.yaml",
        "prompt_candidates.yaml",
        "promotion_recommendation.yaml",
    ):
        assert not (tmp_path / name).exists()


def test_exporter_contains_no_model_runner_or_network_integration() -> None:
    source = MODULE_PATH.read_text(encoding="utf-8")

    for forbidden_import in (
        "import openai",
        "import ollama",
        "import requests",
        "import httpx",
        "import urllib",
        "import socket",
        "import subprocess",
        "from openai",
        "from ollama",
        "from requests",
        "from httpx",
        "from urllib",
        "from socket",
    ):
        assert forbidden_import not in source


def test_custom_bundle_id_and_prompt_template_are_supported(tmp_path: Path) -> None:
    exporter = load_module()
    custom_template = tmp_path / "custom_prompt.md"
    custom_template.write_text("Custom prompt instructions.", encoding="utf-8")
    output_path = tmp_path / "bundle.json"
    source_path = create_run_local_source(tmp_path)

    result = exporter.export_ai_review_draft_prompt_bundle(
        source_path,
        output_path,
        bundle_id="ri-ai-review-draft-prompt-bundle-custom-001",
        prompt_template_path=custom_template,
    )

    assert result["bundle_id"] == "ri-ai-review-draft-prompt-bundle-custom-001"
    assert result["draft_id"] == EXPECTED_DRAFT_ID
    assert result["source_review_input_ref"] == EXPECTED_REVIEW_INPUT_REF
    assert result["prompt_template_ref"] == str(custom_template)
    assert "Custom prompt instructions." in result["prompt_text"]
