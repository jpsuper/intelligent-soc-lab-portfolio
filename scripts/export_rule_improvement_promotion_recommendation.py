from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[1]
CONCRETE_CANDIDATE_BUNDLE_V1_SCHEMA_PATH = (
    REPO_ROOT / "schemas/rule_improvement_concrete_candidate_bundle_v1.schema.json"
)
PROMOTION_RECOMMENDATION_SCHEMA_PATH = REPO_ROOT / "schemas/promotion_recommendation_schema.json"

UNSAFE_OUTPUT_NAMES = {"rule_candidates.yaml", "prompt_candidates.yaml"}

APPROVAL_LIKE_FIELDS = {
    "approved",
    "candidate_approved",
    "apply_approved",
    "deployment_approved",
    "baseline_update_approved",
    "promotion_approved",
    "auto_apply_allowed",
    "promotion_allowed",
    "applies_changes",
    "promoted",
    "updates_baseline",
    "mutates_state",
    "apply",
    "deploy",
    "promote",
}

SCHEMA_REQUIRED_PROMOTION_FIELDS = {"promote"}

REQUIRED_PAYLOAD_FIELDS = {
    "promotion_recommended",
    "current_agent",
    "challenger_agent",
    "next_baseline_agent",
    "score_delta",
    "gates",
    "blocking_gaps",
}

REQUIRED_GATES = {
    "score_improvement",
    "primary_artifact_coverage",
    "overclaim_control",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export a recommendation-only promotion_recommendation.yaml "
            "from a non-applying Rule Improvement concrete candidate bundle"
        )
    )
    parser.add_argument(
        "--bundle",
        required=True,
        type=Path,
        help="Path to rule_improvement_concrete_candidate_bundle_v1.json",
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path to write recommendation-only promotion_recommendation.yaml",
    )
    parser.add_argument(
        "--diagnostics-output",
        type=Path,
        help="Optional path to write non-recommendation export diagnostics JSON",
    )
    parser.add_argument(
        "--bundle-schema",
        type=Path,
        default=CONCRETE_CANDIDATE_BUNDLE_V1_SCHEMA_PATH,
        help=(
            "Path to rule_improvement_concrete_candidate_bundle_v1.schema.json "
            f"(default: {CONCRETE_CANDIDATE_BUNDLE_V1_SCHEMA_PATH})"
        ),
    )
    parser.add_argument(
        "--output-schema",
        type=Path,
        default=PROMOTION_RECOMMENDATION_SCHEMA_PATH,
        help=(
            "Path to promotion_recommendation_schema.json "
            f"(default: {PROMOTION_RECOMMENDATION_SCHEMA_PATH})"
        ),
    )
    return parser.parse_args()


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def validate_json(instance: Any, schema_path: Path) -> None:
    schema = load_json(schema_path)
    Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(instance)


def _require_object(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{description} must be a JSON object")
    return value


def _read_bundle_bytes(path: Path) -> tuple[dict[str, Any], str]:
    raw_bytes = path.read_bytes()
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    return _require_object(json.loads(raw_bytes), "Concrete candidate bundle"), sha256


def _refuse_unsafe_output_paths(
    bundle_path: Path,
    output_path: Path,
    diagnostics_output_path: Path | None,
) -> None:
    resolved_bundle = bundle_path.resolve()
    resolved_output = output_path.resolve()

    if resolved_output == resolved_bundle:
        raise ValueError("Refusing to overwrite input bundle artifact")
    if output_path.name in UNSAFE_OUTPUT_NAMES:
        raise ValueError(f"Refusing to write unsupported output: {output_path.name}")

    if diagnostics_output_path is None:
        return

    resolved_diagnostics = diagnostics_output_path.resolve()
    if diagnostics_output_path.name in UNSAFE_OUTPUT_NAMES:
        raise ValueError(f"Refusing to write unsupported output: {diagnostics_output_path.name}")
    if resolved_diagnostics == resolved_bundle:
        raise ValueError("Refusing to overwrite input bundle artifact")
    if resolved_diagnostics == resolved_output:
        raise ValueError("Diagnostics output and recommendation output paths must be different")


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


def _verify_no_unsafe_fields(value: dict[str, Any]) -> None:
    unsafe_fields = sorted(
        _all_keys(value).intersection(APPROVAL_LIKE_FIELDS - SCHEMA_REQUIRED_PROMOTION_FIELDS)
    )
    if unsafe_fields:
        names = ", ".join(unsafe_fields)
        raise ValueError(f"Promotion recommendation output contains unsafe fields: {names}")


def _diagnostic(
    candidate: dict[str, Any],
    *,
    reason: str,
) -> dict[str, Any]:
    return {
        "candidate_id": candidate["candidate_id"],
        "candidate_type": candidate["candidate_type"],
        "target_artifact_type": candidate["target_artifact_type"],
        "proposal_ref": candidate["proposal_ref"],
        "reason": reason,
    }


def _verify_promotion_review_candidate(candidate: dict[str, Any]) -> None:
    expected = {
        "candidate_type": "promotion_review",
        "allowed_next_artifact_type": "promotion_review_recommendation",
        "target_artifact_type": "promotion_review_bundle_item",
    }
    for field, expected_value in expected.items():
        if candidate[field] != expected_value:
            raise ValueError(f"{field} mismatch for promotion recommendation export")


def _require_payload(candidate: dict[str, Any]) -> dict[str, Any]:
    payload = candidate["candidate_payload"]["payload"]
    if not isinstance(payload, dict):
        raise ValueError(f"{candidate['candidate_id']} candidate payload must be an object")

    missing = sorted(REQUIRED_PAYLOAD_FIELDS - set(payload))
    if missing:
        names = ", ".join(missing)
        raise ValueError(f"{candidate['candidate_id']} missing promotion payload fields: {names}")

    if not isinstance(payload["promotion_recommended"], bool):
        raise ValueError("promotion_recommended must be a boolean recommendation value")

    for field in [
        "current_agent",
        "challenger_agent",
        "next_baseline_agent",
    ]:
        if not isinstance(payload[field], str) or not payload[field].strip():
            raise ValueError(f"{field} must be a non-empty string")

    if "from_agent" in payload and not isinstance(payload["from_agent"], str | type(None)):
        raise ValueError("from_agent must be a string or null")
    if "to_agent" in payload and not isinstance(payload["to_agent"], str | type(None)):
        raise ValueError("to_agent must be a string or null")

    if not isinstance(payload["score_delta"], int | float) or isinstance(
        payload["score_delta"], bool
    ):
        raise ValueError("score_delta must be numeric")

    gates = payload["gates"]
    if not isinstance(gates, dict):
        raise ValueError("gates must be an object")
    if set(gates) != REQUIRED_GATES:
        raise ValueError("gates must include exactly the legacy promotion gate fields")
    for gate_name, gate_value in gates.items():
        if gate_value not in {"pass", "fail"}:
            raise ValueError(f"{gate_name} gate must be pass or fail")

    blocking_gaps = payload["blocking_gaps"]
    if not isinstance(blocking_gaps, list) or not all(
        isinstance(item, str) for item in blocking_gaps
    ):
        raise ValueError("blocking_gaps must be an array of strings")

    return payload


def _reason(
    candidate: dict[str, Any],
    bundle: dict[str, Any],
    *,
    bundle_path: Path,
    bundle_sha256: str,
) -> str:
    source = bundle["source"]
    provenance = candidate["source_human_decision_provenance"]
    return (
        f"{candidate['candidate_payload']['summary']} "
        f"{candidate['candidate_payload']['proposed_change']} "
        f"Conversion rationale: {candidate['conversion_decision_rationale']} "
        "Recommendation-only artifact; not promotion approval. "
        f"source_bundle:{bundle_path}; "
        f"source_bundle_sha256:{bundle_sha256}; "
        f"source_proposal_review_decisions_ref:{source['source_proposal_review_decisions_ref']}; "
        f"source_proposal_review_decisions_sha256:"
        f"{source['source_proposal_review_decisions_sha256']}; "
        f"source_proposals_ref:{source['source_proposals_ref']}; "
        f"source_proposals_sha256:{source['source_proposals_sha256']}; "
        f"candidate_id:{candidate['candidate_id']}; "
        f"candidate_type:{candidate['candidate_type']}; "
        f"target_artifact_type:{candidate['target_artifact_type']}; "
        f"allowed_next_artifact_type:{candidate['allowed_next_artifact_type']}; "
        f"proposal_ref:{candidate['proposal_ref']}; "
        f"proposal_review_decision_ref:{candidate['proposal_review_decision_ref']}; "
        f"human_decision_ref:{provenance['decision_ref']}; "
        f"human_decision_id:{provenance['decision_id']}; "
        f"human_decision_status:{provenance['decision_status']}; "
        f"limitations:{' | '.join(candidate['limitations'])}; "
        f"required_follow_up_evidence_refs:"
        f"{' | '.join(candidate['required_follow_up_evidence_refs']) or 'none'}; "
        f"expected_effect:{' | '.join(candidate['candidate_payload']['expected_effect'])}"
    )


def _recommendation_from_candidate(
    candidate: dict[str, Any],
    bundle: dict[str, Any],
    *,
    bundle_path: Path,
    bundle_sha256: str,
) -> dict[str, Any]:
    _verify_promotion_review_candidate(candidate)
    payload = _require_payload(candidate)
    return {
        "promotion_recommendation": {
            "promote": payload["promotion_recommended"],
            "from_agent": payload.get("from_agent"),
            "to_agent": payload.get("to_agent"),
            "current_agent": payload["current_agent"],
            "challenger_agent": payload["challenger_agent"],
            "next_baseline_agent": payload["next_baseline_agent"],
            "score_delta": payload["score_delta"],
            "reason": _reason(
                candidate,
                bundle,
                bundle_path=bundle_path,
                bundle_sha256=bundle_sha256,
            ),
            "blocking_gaps": list(payload["blocking_gaps"]),
            "gates": dict(payload["gates"]),
        }
    }


def _empty_recommendation(
    bundle: dict[str, Any],
    *,
    bundle_path: Path,
    bundle_sha256: str,
) -> dict[str, Any]:
    source = bundle["source"]
    return {
        "promotion_recommendation": {
            "promote": False,
            "from_agent": None,
            "to_agent": None,
            "current_agent": "not_applicable",
            "challenger_agent": "not_applicable",
            "next_baseline_agent": "not_applicable",
            "score_delta": 0.0,
            "reason": (
                "No eligible promotion_review bundle candidate was present. "
                "Recommendation-only artifact; not promotion approval. "
                f"source_bundle:{bundle_path}; "
                f"source_bundle_sha256:{bundle_sha256}; "
                f"source_proposal_review_decisions_ref:"
                f"{source['source_proposal_review_decisions_ref']}; "
                f"source_proposal_review_decisions_sha256:"
                f"{source['source_proposal_review_decisions_sha256']}; "
                f"source_proposals_ref:{source['source_proposals_ref']}; "
                f"source_proposals_sha256:{source['source_proposals_sha256']}"
            ),
            "blocking_gaps": ["no_eligible_promotion_review_candidates"],
            "gates": {
                "score_improvement": "fail",
                "primary_artifact_coverage": "fail",
                "overclaim_control": "fail",
            },
        }
    }


def build_promotion_recommendation(
    bundle: dict[str, Any],
    *,
    bundle_path: Path,
    bundle_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    eligible_candidates = []
    skipped_items = []

    for candidate in bundle["converted_candidates"]:
        if candidate["candidate_type"] != "promotion_review":
            skipped_items.append(
                _diagnostic(
                    candidate,
                    reason="unsupported_candidate_type_for_promotion_recommendation_export",
                )
            )
            continue
        if (
            candidate["allowed_next_artifact_type"] != "promotion_review_recommendation"
            or candidate["target_artifact_type"] != "promotion_review_bundle_item"
        ):
            raise ValueError("promotion_review candidate has mismatched export mapping")
        eligible_candidates.append(candidate)

    for skipped_decision in bundle["skipped_decisions"]:
        skipped_items.append(
            {
                "candidate_id": skipped_decision["candidate_id"],
                "candidate_type": "skipped_decision",
                "target_artifact_type": "not_exportable",
                "proposal_ref": skipped_decision["proposal_ref"],
                "reason": "skipped_decision_not_exportable",
            }
        )

    if len(eligible_candidates) > 1:
        raise ValueError("Multiple promotion_review candidates require separate human handling")

    if eligible_candidates:
        output = _recommendation_from_candidate(
            eligible_candidates[0],
            bundle,
            bundle_path=bundle_path,
            bundle_sha256=bundle_sha256,
        )
    else:
        output = _empty_recommendation(
            bundle,
            bundle_path=bundle_path,
            bundle_sha256=bundle_sha256,
        )

    diagnostics = {
        "version": 1,
        "artifact_type": "rule_improvement_promotion_recommendation_export_diagnostics",
        "source_concrete_candidate_bundle_ref": str(bundle_path),
        "source_concrete_candidate_bundle_sha256": bundle_sha256,
        "promotion_review_candidate_count": len(eligible_candidates),
        "skipped_count": len(skipped_items),
        "skipped_items": skipped_items,
    }
    return output, diagnostics


def write_yaml(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(value, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def export_rule_improvement_promotion_recommendation(
    bundle_path: Path,
    output_path: Path,
    *,
    bundle_schema_path: Path = CONCRETE_CANDIDATE_BUNDLE_V1_SCHEMA_PATH,
    output_schema_path: Path = PROMOTION_RECOMMENDATION_SCHEMA_PATH,
    diagnostics_output_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _refuse_unsafe_output_paths(bundle_path, output_path, diagnostics_output_path)

    bundle, bundle_sha256 = _read_bundle_bytes(bundle_path)
    validate_json(bundle, bundle_schema_path)
    output, diagnostics = build_promotion_recommendation(
        bundle,
        bundle_path=bundle_path,
        bundle_sha256=bundle_sha256,
    )
    _verify_no_unsafe_fields(output)
    validate_json(output, output_schema_path)

    write_yaml(output_path, output)
    if diagnostics_output_path is not None:
        write_json(diagnostics_output_path, diagnostics)
    return output, diagnostics


def main() -> None:
    args = parse_args()
    output, diagnostics = export_rule_improvement_promotion_recommendation(
        args.bundle,
        args.output,
        bundle_schema_path=args.bundle_schema,
        output_schema_path=args.output_schema,
        diagnostics_output_path=args.diagnostics_output,
    )
    recommendation = output["promotion_recommendation"]
    print(
        "Rule Improvement promotion recommendation exported: "
        f"{diagnostics['promotion_review_candidate_count']} promotion_review candidates, "
        f"promote={str(recommendation['promote']).lower()}, "
        f"{diagnostics['skipped_count']} skipped, "
        f"output={args.output}"
    )


if __name__ == "__main__":
    main()
