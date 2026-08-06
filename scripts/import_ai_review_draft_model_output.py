from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from jsonschema import validate

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_SCHEMA_PATH = REPO_ROOT / "schemas/rule_improvement_ai_review_draft.schema.json"
PROMPT_INPUT_SCHEMA_PATH = (
    REPO_ROOT / "schemas/rule_improvement_ai_review_draft_prompt_input.schema.json"
)
EXPECTED_RESPONSE_SCHEMA_REF = "schemas/rule_improvement_ai_review_draft.schema.json"

LOCKED_OUTPUT_FLAGS = {
    "ai_assistance_only": True,
    "human_review_required": True,
    "classification_decision_allowed": False,
    "candidate_generation_started": False,
    "promotion_allowed": False,
}

LOCKED_BUNDLE_FLAGS = {
    "model_execution_allowed": False,
    "model_execution_performed": False,
    "network_allowed": False,
    "human_review_required": True,
    "classification_decision_allowed": False,
    "candidate_generation_started": False,
    "promotion_allowed": False,
}

FORBIDDEN_FIELDS = {
    "label",
    "candidate_generation_eligible",
    "decision_id",
    "reviewer",
    "reviewed_at",
    "review_status",
    "human_review_completed",
    "classification_decision",
    "rule_candidates",
    "prompt_candidates",
    "promotion_recommendation",
    "candidate_approved",
    "candidate_promoted",
    "case_status",
    "case_severity",
    "action_approval",
    "containment_state",
    "verdict",
    "confidence",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and import an already-produced AI review draft model output "
            "without executing a model"
        )
    )
    parser.add_argument(
        "--prompt-bundle",
        required=True,
        type=Path,
        help="Path to rule_improvement_ai_review_draft_prompt_bundle.json",
    )
    parser.add_argument(
        "--model-output",
        required=True,
        type=Path,
        help="Path to candidate rule_improvement_ai_review_draft.json",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write canonical rule_improvement_ai_review_draft.json",
    )
    parser.add_argument(
        "--draft-id",
        help="Optional deterministic replacement draft ID",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for child in value.values():
            keys.update(_all_keys(child))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for child in value:
            keys.update(_all_keys(child))
        return keys
    return set()


def _validate_locked_flags(
    value: dict[str, Any],
    expected: dict[str, bool],
    *,
    artifact_name: str,
) -> None:
    for field, expected_value in expected.items():
        if value.get(field) is not expected_value:
            raise ValueError(f"{artifact_name} must keep {field}={str(expected_value).lower()}")


def _bundle_signal_refs(bundle: dict[str, Any]) -> set[str]:
    if bundle.get("source_stage") != "post_action_dfir":
        raise ValueError("Prompt bundle source_stage must be post_action_dfir")
    if bundle.get("expected_response_schema_ref") != EXPECTED_RESPONSE_SCHEMA_REF:
        raise ValueError("Prompt bundle has an unexpected response schema ref")
    _validate_locked_flags(
        bundle,
        LOCKED_BUNDLE_FLAGS,
        artifact_name="Prompt bundle",
    )

    prompt_input = bundle.get("prompt_input")
    if not isinstance(prompt_input, dict):
        raise ValueError("Prompt bundle must contain normalized prompt_input")
    validate(instance=prompt_input, schema=load_json(PROMPT_INPUT_SCHEMA_PATH))

    bundle_review_input_id = bundle.get("source_review_input_id")
    prompt_review_input_id = prompt_input["source_context"]["source_review_input_id"]
    if bundle_review_input_id != prompt_review_input_id:
        raise ValueError("Prompt bundle source_review_input_id does not match prompt_input")

    return {signal["source_signal_ref"] for signal in prompt_input["signals"]}


def build_imported_ai_review_draft(
    bundle: dict[str, Any],
    model_output: dict[str, Any],
    *,
    draft_id: str | None = None,
) -> dict[str, Any]:
    forbidden = _all_keys(model_output).intersection(FORBIDDEN_FIELDS)
    if forbidden:
        names = ", ".join(sorted(forbidden))
        raise ValueError(f"Model output contains forbidden fields: {names}")

    validate(instance=model_output, schema=load_json(OUTPUT_SCHEMA_PATH))
    _validate_locked_flags(
        model_output,
        LOCKED_OUTPUT_FLAGS,
        artifact_name="Model output",
    )
    allowed_signal_refs = _bundle_signal_refs(bundle)

    if model_output["source_stage"] != bundle["source_stage"]:
        raise ValueError("Model output source_stage does not match prompt bundle")
    if model_output["source_review_input_id"] != bundle["source_review_input_id"]:
        raise ValueError("Model output source_review_input_id does not match prompt bundle")
    bundle_review_input_ref = bundle.get("source_review_input_ref")
    if (
        bundle_review_input_ref is not None
        and model_output["source_review_input_ref"] != bundle_review_input_ref
    ):
        raise ValueError("Model output source_review_input_ref does not match prompt bundle")

    unknown_signal_refs = sorted(
        {suggestion["source_signal_ref"] for suggestion in model_output["suggestions"]}
        - allowed_signal_refs
    )
    if unknown_signal_refs:
        raise ValueError(
            f"Model output contains unknown source_signal_ref values: {unknown_signal_refs}"
        )

    result = copy.deepcopy(model_output)
    if draft_id is not None:
        result["draft_id"] = draft_id
        validate(instance=result, schema=load_json(OUTPUT_SCHEMA_PATH))
    return result


def import_ai_review_draft_model_output(
    prompt_bundle_path: Path,
    model_output_path: Path,
    output_path: Path,
    *,
    draft_id: str | None = None,
) -> dict[str, Any]:
    bundle = load_json(prompt_bundle_path)
    model_output = load_json(model_output_path)
    result = build_imported_ai_review_draft(
        bundle,
        model_output,
        draft_id=draft_id,
    )
    write_json(output_path, result)
    return result


def main() -> None:
    args = parse_args()
    result = import_ai_review_draft_model_output(
        args.prompt_bundle,
        args.model_output,
        args.output,
        draft_id=args.draft_id,
    )
    print(f"AI review draft model output imported: {args.output}")
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
