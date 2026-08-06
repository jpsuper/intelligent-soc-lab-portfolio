from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import ValidationError, validate

REPO_ROOT = Path(__file__).resolve().parents[1]
AI_REVIEW_DRAFT_SCHEMA_PATH = REPO_ROOT / "schemas/rule_improvement_ai_review_draft.schema.json"

DOWNSTREAM_ARTIFACT_NAMES = {
    "rule_improvement_signal_classification.json",
    "human_decisions_template.json",
    "rule_candidates.yaml",
    "prompt_candidates.yaml",
    "promotion_recommendation.yaml",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare already-produced Rule Improvement AI review draft artifacts "
            "without executing models or selecting a winner"
        )
    )
    parser.add_argument(
        "--candidate",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="Candidate name and path. May be repeated.",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--comparison-id")
    parser.add_argument("--source-review-input-id")
    parser.add_argument("--source-review-input-ref")
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


def parse_candidate_spec(spec: str) -> tuple[str, Path]:
    if "=" not in spec:
        raise ValueError("Candidate must use NAME=PATH format")
    name, path = spec.split("=", maxsplit=1)
    if not name.strip():
        raise ValueError("Candidate name must be non-empty")
    if not path.strip():
        raise ValueError("Candidate path must be non-empty")
    return name.strip(), Path(path)


def parse_candidate_specs(specs: list[str]) -> list[tuple[str, Path]]:
    candidates = [parse_candidate_spec(spec) for spec in specs]
    names = [name for name, _path in candidates]
    duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
    if duplicates:
        raise ValueError(f"Duplicate candidate names are not allowed: {duplicates}")
    if not candidates:
        raise ValueError("At least one --candidate is required")
    return candidates


def _validation_error_message(exc: BaseException) -> str:
    if isinstance(exc, ValidationError):
        return exc.message
    return str(exc)


def _suggestions(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    suggestions = candidate.get("suggestions", [])
    return suggestions if isinstance(suggestions, list) else []


def _suggestion_label(suggestion: dict[str, Any]) -> str | None:
    label = suggestion.get("suggested_label")
    return label if isinstance(label, str) else None


def _suggestion_signal_ref(suggestion: dict[str, Any]) -> str | None:
    signal_ref = suggestion.get("source_signal_ref")
    return signal_ref if isinstance(signal_ref, str) else None


def _empty_list_field_count(
    suggestions: list[dict[str, Any]],
    field_name: str,
) -> int:
    return sum(
        1
        for suggestion in suggestions
        if not isinstance(suggestion.get(field_name), list) or not suggestion[field_name]
    )


def _missing_string_field_count(
    suggestions: list[dict[str, Any]],
    field_name: str,
) -> int:
    return sum(
        1
        for suggestion in suggestions
        if not isinstance(suggestion.get(field_name), str) or not suggestion[field_name].strip()
    )


def _candidate_metrics(candidate: dict[str, Any]) -> dict[str, Any]:
    suggestions = _suggestions(candidate)
    labels = [
        label for suggestion in suggestions if (label := _suggestion_label(suggestion)) is not None
    ]
    signal_refs = [
        signal_ref
        for suggestion in suggestions
        if (signal_ref := _suggestion_signal_ref(suggestion)) is not None
    ]
    return {
        "draft_id": candidate.get("draft_id"),
        "suggestion_count": len(suggestions),
        "label_counts": dict(sorted(Counter(labels).items())),
        "signal_refs": signal_refs,
        "empty_evidence_caveat_count": _empty_list_field_count(
            suggestions,
            "evidence_caveats",
        ),
        "empty_review_question_count": _empty_list_field_count(
            suggestions,
            "review_questions",
        ),
        "missing_confidence_rationale_count": _missing_string_field_count(
            suggestions,
            "confidence_rationale",
        ),
        "warning_count": len(candidate.get("warnings", [])),
        "error_count": len(candidate.get("errors", [])),
    }


def _invalid_candidate_summary(
    *,
    name: str,
    path: Path,
    validation_error: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "path": str(path),
        "schema_valid": False,
        "validation_error": validation_error,
        "draft_id": None,
        "suggestion_count": 0,
        "label_counts": {},
        "signal_refs": [],
        "empty_evidence_caveat_count": 0,
        "empty_review_question_count": 0,
        "missing_confidence_rationale_count": 0,
        "warning_count": 0,
        "error_count": 0,
    }


def _valid_candidate_summary(
    *,
    name: str,
    path: Path,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": name,
        "path": str(path),
        "schema_valid": True,
        "validation_error": None,
        **_candidate_metrics(candidate),
    }


def _validate_source_metadata(
    valid_candidates: list[tuple[str, dict[str, Any]]],
    *,
    source_review_input_id: str | None,
    source_review_input_ref: str | None,
) -> tuple[str, str]:
    ids = {candidate["source_review_input_id"] for _name, candidate in valid_candidates}
    refs = {candidate["source_review_input_ref"] for _name, candidate in valid_candidates}

    if source_review_input_id is not None:
        if ids != {source_review_input_id}:
            raise ValueError("Valid candidates do not match --source-review-input-id")
        resolved_id = source_review_input_id
    elif len(ids) == 1:
        resolved_id = next(iter(ids))
    else:
        raise ValueError("Valid candidates disagree on source_review_input_id")

    if source_review_input_ref is not None:
        if refs != {source_review_input_ref}:
            raise ValueError("Valid candidates do not match --source-review-input-ref")
        resolved_ref = source_review_input_ref
    elif len(refs) == 1:
        resolved_ref = next(iter(refs))
    else:
        raise ValueError("Valid candidates disagree on source_review_input_ref")

    return resolved_id, resolved_ref


def _signal_matrix(
    summaries: list[dict[str, Any]],
    candidates_by_name: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    valid_names = [summary["name"] for summary in summaries if summary["schema_valid"] is True]
    labels_by_signal: dict[str, dict[str, str]] = {}
    for name in valid_names:
        candidate = candidates_by_name[name]
        for suggestion in _suggestions(candidate):
            signal_ref = _suggestion_signal_ref(suggestion)
            label = _suggestion_label(suggestion)
            if signal_ref is not None and label is not None:
                labels_by_signal.setdefault(signal_ref, {})[name] = label

    matrix: list[dict[str, Any]] = []
    for signal_ref in sorted(labels_by_signal):
        labels_by_candidate = labels_by_signal[signal_ref]
        present = [name for name in valid_names if name in labels_by_candidate]
        missing = [name for name in valid_names if name not in labels_by_candidate]
        matrix.append(
            {
                "source_signal_ref": signal_ref,
                "labels_by_candidate": {name: labels_by_candidate[name] for name in present},
                "label_disagreement": len(set(labels_by_candidate.values())) > 1,
                "present_in_candidates": present,
                "missing_from_candidates": missing,
            }
        )
    return matrix


def build_ai_review_draft_comparison(
    candidate_specs: list[tuple[str, Path]],
    *,
    comparison_id: str | None = None,
    source_review_input_id: str | None = None,
    source_review_input_ref: str | None = None,
) -> dict[str, Any]:
    schema = load_json(AI_REVIEW_DRAFT_SCHEMA_PATH)
    summaries: list[dict[str, Any]] = []
    valid_candidates: list[tuple[str, dict[str, Any]]] = []
    candidates_by_name: dict[str, dict[str, Any]] = {}

    for name, path in candidate_specs:
        try:
            candidate = load_json(path)
            validate(instance=candidate, schema=schema)
        except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
            summaries.append(
                _invalid_candidate_summary(
                    name=name,
                    path=path,
                    validation_error=_validation_error_message(exc),
                )
            )
            continue

        valid_candidates.append((name, candidate))
        candidates_by_name[name] = candidate
        summaries.append(_valid_candidate_summary(name=name, path=path, candidate=candidate))

    if not valid_candidates:
        raise ValueError("At least one schema-valid candidate is required")

    resolved_source_id, resolved_source_ref = _validate_source_metadata(
        valid_candidates,
        source_review_input_id=source_review_input_id,
        source_review_input_ref=source_review_input_ref,
    )
    matrix = _signal_matrix(summaries, candidates_by_name)
    valid_names = [summary["name"] for summary in summaries if summary["schema_valid"] is True]
    invalid_names = [summary["name"] for summary in summaries if summary["schema_valid"] is False]
    candidate_count = len(summaries)
    valid_candidate_count = len(valid_names)

    return {
        "comparison_id": comparison_id or f"ai-review-draft-comparison-{resolved_source_id}",
        "source_review_input_id": resolved_source_id,
        "source_review_input_ref": resolved_source_ref,
        "candidate_count": candidate_count,
        "valid_candidate_count": valid_candidate_count,
        "invalid_candidate_count": len(invalid_names),
        "candidates": summaries,
        "signal_matrix": matrix,
        "summary": {
            "schema_pass_rate": round(valid_candidate_count / candidate_count, 2),
            "signals_with_label_disagreement": sum(
                1 for signal in matrix if signal["label_disagreement"]
            ),
            "signals_missing_from_any_valid_candidate": sum(
                1 for signal in matrix if signal["missing_from_candidates"]
            ),
            "candidate_names_by_validity": {
                "valid": valid_names,
                "invalid": invalid_names,
            },
        },
    }


def compare_ai_review_drafts(
    candidate_args: list[str],
    output_path: Path,
    *,
    comparison_id: str | None = None,
    source_review_input_id: str | None = None,
    source_review_input_ref: str | None = None,
) -> dict[str, Any]:
    candidate_specs = parse_candidate_specs(candidate_args)
    result = build_ai_review_draft_comparison(
        candidate_specs,
        comparison_id=comparison_id,
        source_review_input_id=source_review_input_id,
        source_review_input_ref=source_review_input_ref,
    )
    if output_path.name in DOWNSTREAM_ARTIFACT_NAMES:
        raise ValueError(f"Refusing to write downstream artifact name: {output_path.name}")
    write_json(output_path, result)
    return result


def main() -> None:
    args = parse_args()
    result = compare_ai_review_drafts(
        args.candidate,
        args.output,
        comparison_id=args.comparison_id,
        source_review_input_id=args.source_review_input_id,
        source_review_input_ref=args.source_review_input_ref,
    )
    print(f"AI review draft comparison written: {args.output}")
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
