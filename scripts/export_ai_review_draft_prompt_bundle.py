from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from jsonschema import validate

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_SCHEMA_PATH = REPO_ROOT / "schemas/rule_improvement_ai_review_draft_prompt_input.schema.json"
DEFAULT_PROMPT_TEMPLATE_REF = "prompts/rule-improvement/ai_review_draft_v1.md"
DEFAULT_PROMPT_TEMPLATE_PATH = REPO_ROOT / DEFAULT_PROMPT_TEMPLATE_REF
EXPECTED_RESPONSE_SCHEMA_REF = "schemas/rule_improvement_ai_review_draft.schema.json"
PROMPT_INPUT_FILENAME = "rule_improvement_ai_review_draft_prompt_input.json"
REVIEW_INPUT_FILENAME = "rule_improvement_review_input.json"

RESPONSE_INSTRUCTIONS = [
    "Return one JSON object that validates against the expected response schema.",
    "Produce suggestions only; AI suggestions are not human decisions.",
    "Use only normalized context contained in this bundle.",
    "Preserve evidence caveats and keep review questions non-empty.",
]

SAFETY_BOUNDARIES = [
    "Do not approve candidates or promote anything.",
    (
        "Do not mutate case, action, investigation, containment, approval, verdict, "
        "severity, confidence, or Rule Improvement state."
    ),
    (
        "Treat Linux.BashHistory as weak, user-controlled, timing-sensitive evidence; "
        "an entry does not confirm execution and absence does not prove non-execution."
    ),
    (
        "Treat Linux.ProcessList as point-in-time evidence; presence applies only at "
        "collection time and absence does not prove non-execution."
    ),
    (
        "Missing telemetry is a reviewable gap, not automatic proof of benign, clean, "
        "or non-execution and not an automatic candidate."
    ),
    "Do not read, open, fetch, or infer the contents of evidence refs.",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export a deterministic local AI review draft prompt bundle without "
            "executing a prompt or model"
        )
    )
    parser.add_argument(
        "--prompt-input",
        required=True,
        type=Path,
        help="Path to rule_improvement_ai_review_draft_prompt_input.json",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write rule_improvement_ai_review_draft_prompt_bundle.json",
    )
    parser.add_argument("--bundle-id", help="Optional stable bundle identifier")
    parser.add_argument(
        "--prompt-template",
        type=Path,
        help=(
            f"Optional versioned prompt template path; defaults to {DEFAULT_PROMPT_TEMPLATE_REF}"
        ),
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _derive_source_review_input_ref(source_prompt_input_ref: str) -> str:
    source_path = Path(source_prompt_input_ref)
    parts = source_path.parts
    if (
        ".." in parts
        or len(parts) < 4
        or parts[-4] != "data"
        or parts[-3] != "runs"
        or parts[-2] in {"", ".", ".."}
        or parts[-1] != PROMPT_INPUT_FILENAME
    ):
        raise ValueError(
            "source_prompt_input_ref must be a run-local prompt input under data/runs/<run-id>"
        )
    return str(Path("data") / "runs" / parts[-2] / REVIEW_INPUT_FILENAME)


def _prompt_text(
    template_text: str,
    prompt_input: dict[str, Any],
    *,
    draft_id: str,
    source_review_input_id: str,
    source_review_input_ref: str,
) -> str:
    normalized_input = json.dumps(
        prompt_input,
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    )
    safety_preamble = "\n".join(
        [
            "# Prompt bundle safety preamble",
            "",
            "AI suggestions are not human decisions.",
            f"Model output must conform to {EXPECTED_RESPONSE_SCHEMA_REF}.",
            *SAFETY_BOUNDARIES,
        ]
    )
    provenance = "\n".join(
        [
            "# Required output provenance",
            "",
            "Copy these output provenance values exactly:",
            f"draft_id: {draft_id}",
            f"source_review_input_id: {source_review_input_id}",
            f"source_review_input_ref: {source_review_input_ref}",
            "Do not use MISSING_REQUIRED_PROVENANCE.",
            "Do not invent provenance.",
            (
                "If provenance is missing, fail by returning errors instead of "
                "inventing it; this exporter provides all required provenance."
            ),
        ]
    )
    return (
        f"{safety_preamble}\n\n"
        f"{provenance}\n\n"
        "# Versioned prompt template\n\n"
        f"{template_text.rstrip()}\n\n"
        "# Normalized prompt input JSON\n\n"
        "```json\n"
        f"{normalized_input}\n"
        "```\n"
    )


def build_ai_review_draft_prompt_bundle(
    prompt_input: dict[str, Any],
    *,
    source_prompt_input_ref: str,
    prompt_template_ref: str,
    prompt_template_text: str,
    bundle_id: str | None = None,
) -> dict[str, Any]:
    source_review_input_id = prompt_input["source_context"]["source_review_input_id"]
    if not isinstance(source_review_input_id, str) or not source_review_input_id.strip():
        raise ValueError("source_review_input_id must be a non-empty string")
    draft_id = f"ri-ai-review-draft-{source_review_input_id}"
    source_review_input_ref = _derive_source_review_input_ref(source_prompt_input_ref)
    resolved_bundle_id = bundle_id or (f"ri-ai-review-draft-prompt-bundle-{source_review_input_id}")
    if not isinstance(resolved_bundle_id, str) or not resolved_bundle_id.strip():
        raise ValueError("bundle_id must be a non-empty string")

    return {
        "bundle_id": resolved_bundle_id,
        "source_stage": "post_action_dfir",
        "source_prompt_input_id": (f"ri-ai-review-draft-prompt-input-{source_review_input_id}"),
        "source_prompt_input_ref": source_prompt_input_ref,
        "draft_id": draft_id,
        "source_review_input_id": source_review_input_id,
        "source_review_input_ref": source_review_input_ref,
        "prompt_template_ref": prompt_template_ref,
        "expected_response_schema_ref": EXPECTED_RESPONSE_SCHEMA_REF,
        "model_execution_allowed": False,
        "model_execution_performed": False,
        "network_allowed": False,
        "human_review_required": True,
        "classification_decision_allowed": False,
        "candidate_generation_started": False,
        "promotion_allowed": False,
        "prompt_input": copy.deepcopy(prompt_input),
        "prompt_text": _prompt_text(
            prompt_template_text,
            prompt_input,
            draft_id=draft_id,
            source_review_input_id=source_review_input_id,
            source_review_input_ref=source_review_input_ref,
        ),
        "response_instructions": list(RESPONSE_INSTRUCTIONS),
        "safety_boundaries": list(SAFETY_BOUNDARIES),
    }


def export_ai_review_draft_prompt_bundle(
    prompt_input_path: Path,
    output_path: Path,
    *,
    bundle_id: str | None = None,
    prompt_template_path: Path | None = None,
) -> dict[str, Any]:
    prompt_input = load_json(prompt_input_path)
    validate(instance=prompt_input, schema=load_json(SOURCE_SCHEMA_PATH))

    resolved_template_path = prompt_template_path or DEFAULT_PROMPT_TEMPLATE_PATH
    prompt_template_ref = (
        str(prompt_template_path)
        if prompt_template_path is not None
        else DEFAULT_PROMPT_TEMPLATE_REF
    )
    result = build_ai_review_draft_prompt_bundle(
        prompt_input,
        source_prompt_input_ref=str(prompt_input_path),
        prompt_template_ref=prompt_template_ref,
        prompt_template_text=load_text(resolved_template_path),
        bundle_id=bundle_id,
    )
    write_json(output_path, result)
    return result


def main() -> None:
    args = parse_args()
    result = export_ai_review_draft_prompt_bundle(
        args.prompt_input,
        args.output,
        bundle_id=args.bundle_id,
        prompt_template_path=args.prompt_template,
    )
    print(f"AI review draft prompt bundle created: {args.output}")
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
