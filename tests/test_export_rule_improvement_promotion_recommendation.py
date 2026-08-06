import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator, ValidationError

MODULE_PATH = Path("scripts/export_rule_improvement_promotion_recommendation.py")
BUNDLE_SCHEMA_PATH = Path("schemas/rule_improvement_concrete_candidate_bundle_v1.schema.json")
OUTPUT_SCHEMA_PATH = Path("schemas/promotion_recommendation_schema.json")

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

CANDIDATE_TYPE_MAPPING = {
    "rule": ("rule_candidate_proposal", "rule_candidate_bundle_item"),
    "prompt": ("prompt_candidate_proposal", "prompt_candidate_bundle_item"),
    "parser": ("parser_candidate_proposal", "parser_candidate_bundle_item"),
    "telemetry": ("telemetry_candidate_proposal", "telemetry_candidate_bundle_item"),
    "correlation": ("correlation_candidate_proposal", "correlation_candidate_bundle_item"),
    "promotion_review": (
        "promotion_review_recommendation",
        "promotion_review_bundle_item",
    ),
}


def load_module():
    spec = importlib.util.spec_from_file_location(
        "export_rule_improvement_promotion_recommendation",
        MODULE_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_yaml(path: Path) -> dict:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validator(schema_path: Path) -> Draft202012Validator:
    return Draft202012Validator(load_json(schema_path))


def collect_keys(value: object) -> set[str]:
    result = set()

    def visit(nested_value: object) -> None:
        if isinstance(nested_value, dict):
            result.update(nested_value)
            for item in nested_value.values():
                visit(item)
        elif isinstance(nested_value, list):
            for item in nested_value:
                visit(item)

    visit(value)
    return result


def converted_candidate(
    *,
    candidate_id: str = "ri-promotion-review-001",
    candidate_type: str = "promotion_review",
    index: int = 0,
    target: str = "agent-comparison-review",
) -> dict:
    allowed_next_artifact_type, target_artifact_type = CANDIDATE_TYPE_MAPPING[candidate_type]
    payload = {
        "target": target,
        "source_signal_ref": f"/supporting_signals/{index}",
        "source_label": "promotion_review",
        "source_fact_ids": [f"{candidate_id}-fact"],
        "required_evidence_refs": ["judge_result.json"],
        "priority": "medium",
        "review_status": "human_review_required",
    }
    if candidate_type == "promotion_review":
        payload.update(
            {
                "promotion_recommended": True,
                "from_agent": "triage_ai_variant",
                "to_agent": "triage_ai_current",
                "current_agent": "triage_ai_current",
                "challenger_agent": "triage_ai_variant",
                "next_baseline_agent": "triage_ai_variant",
                "score_delta": 0.125,
                "blocking_gaps": [],
                "gates": {
                    "score_improvement": "pass",
                    "primary_artifact_coverage": "pass",
                    "overclaim_control": "pass",
                },
            }
        )

    return {
        "candidate_id": candidate_id,
        "candidate_type": candidate_type,
        "allowed_next_artifact_type": allowed_next_artifact_type,
        "proposal_ref": f"/proposals/{index}",
        "proposal_review_decision_ref": f"/decisions/{index}",
        "conversion_decision_rationale": (
            f"Human reviewer accepted {candidate_id} for recommendation export only."
        ),
        "source_candidate_creation_input_ref": (
            "data/runs/run-001/rule_improvement_candidate_creation_input.json"
        ),
        "source_candidate_creation_input_sha256": "a" * 64,
        "source_human_decision_provenance": {
            "decision_ref": f"/decisions/{index}",
            "decision_id": f"candidate-review.json#/decisions/{index}",
            "decision_status": "accepted_for_candidate_creation",
        },
        "limitations": ["Legacy promotion recommendation narrows provenance to reason text."],
        "required_follow_up_evidence_refs": ["judge_result.json"],
        "target_artifact_type": target_artifact_type,
        "candidate_payload": {
            "summary": f"Summary for {candidate_id}.",
            "proposed_change": f"Recommend reviewer consideration for {candidate_id}.",
            "expected_effect": ["Surface recommendation-only promotion review context."],
            "payload": payload,
        },
    }


def skipped_decision() -> dict:
    return {
        "candidate_id": "ri-candidate-skipped",
        "proposal_ref": "/proposals/99",
        "proposal_review_decision_ref": "/decisions/99",
        "decision": "defer",
        "reason": "deferred_by_reviewer",
        "source_human_decision_provenance": {
            "decision_ref": "/decisions/99",
            "decision_id": "candidate-review.json#/decisions/99",
            "decision_status": "accepted_for_candidate_creation",
        },
    }


def bundle(candidates: list[dict] | None = None, skipped: list[dict] | None = None) -> dict:
    if candidates is None:
        candidates = [converted_candidate()]
    if skipped is None:
        skipped = []
    return {
        "version": 1,
        "artifact_type": "rule_improvement_concrete_candidate_bundle",
        "artifact_semantics": "candidate_bundle_only",
        "source": {
            "source_proposal_review_decisions_ref": (
                "data/runs/run-001/rule_improvement_proposal_review_decisions.json"
            ),
            "source_proposal_review_decisions_sha256": "b" * 64,
            "source_proposals_ref": (
                "data/runs/run-001/rule_improvement_candidate_proposals_v2.json"
            ),
            "source_proposals_sha256": "c" * 64,
        },
        "converted_candidates": candidates,
        "skipped_decisions": skipped,
    }


def write_bundle(tmp_path: Path, source: dict) -> tuple[Path, Path, Path]:
    bundle_path = tmp_path / "rule_improvement_concrete_candidate_bundle_v1.json"
    output_path = tmp_path / "nested" / "promotion_recommendation.yaml"
    diagnostics_output_path = tmp_path / "nested" / "promotion_diagnostics.json"
    write_json(bundle_path, source)
    return bundle_path, output_path, diagnostics_output_path


def export_from_bundle(
    tmp_path: Path,
    source: dict,
    *,
    diagnostics: bool = False,
) -> tuple[dict, dict, Path, Path, Path]:
    exporter = load_module()
    bundle_path, output_path, diagnostics_output_path = write_bundle(tmp_path, source)
    output, export_diagnostics = exporter.export_rule_improvement_promotion_recommendation(
        bundle_path,
        output_path,
        diagnostics_output_path=diagnostics_output_path if diagnostics else None,
    )

    assert load_yaml(output_path) == output
    if diagnostics:
        assert load_json(diagnostics_output_path) == export_diagnostics
    else:
        assert not diagnostics_output_path.exists()
    return output, export_diagnostics, bundle_path, output_path, diagnostics_output_path


def test_valid_promotion_review_candidate_exports_schema_valid_recommendation(
    tmp_path: Path,
) -> None:
    output, diagnostics, bundle_path, output_path, _diagnostics_path = export_from_bundle(
        tmp_path,
        bundle(),
        diagnostics=True,
    )

    assert output_path.exists()
    validator(OUTPUT_SCHEMA_PATH).validate(output)
    recommendation = output["promotion_recommendation"]
    assert recommendation["promote"] is True
    assert recommendation["current_agent"] == "triage_ai_current"
    assert recommendation["challenger_agent"] == "triage_ai_variant"
    assert recommendation["next_baseline_agent"] == "triage_ai_variant"
    assert recommendation["score_delta"] == 0.125
    assert recommendation["blocking_gaps"] == []
    assert recommendation["gates"] == {
        "score_improvement": "pass",
        "primary_artifact_coverage": "pass",
        "overclaim_control": "pass",
    }
    assert f"source_bundle:{bundle_path}" in recommendation["reason"]
    assert f"source_bundle_sha256:{sha256(bundle_path)}" in recommendation["reason"]
    assert "candidate_id:ri-promotion-review-001" in recommendation["reason"]
    assert "proposal_ref:/proposals/0" in recommendation["reason"]
    assert diagnostics["promotion_review_candidate_count"] == 1
    assert diagnostics["skipped_count"] == 0


def test_non_promotion_candidates_are_not_included_in_recommendation_output(
    tmp_path: Path,
) -> None:
    candidates = [
        converted_candidate(candidate_id="ri-candidate-rule", candidate_type="rule", index=0),
        converted_candidate(candidate_id="ri-candidate-prompt", candidate_type="prompt", index=1),
        converted_candidate(candidate_id="ri-candidate-parser", candidate_type="parser", index=2),
        converted_candidate(
            candidate_id="ri-candidate-telemetry",
            candidate_type="telemetry",
            index=3,
        ),
        converted_candidate(
            candidate_id="ri-candidate-correlation",
            candidate_type="correlation",
            index=4,
        ),
        converted_candidate(candidate_id="ri-candidate-promotion", index=5),
    ]
    output, diagnostics, *_paths = export_from_bundle(
        tmp_path,
        bundle(candidates),
        diagnostics=True,
    )

    rendered = json.dumps(output, sort_keys=True)
    assert "ri-candidate-promotion" in rendered
    for candidate_id in [
        "ri-candidate-rule",
        "ri-candidate-prompt",
        "ri-candidate-parser",
        "ri-candidate-telemetry",
        "ri-candidate-correlation",
    ]:
        assert candidate_id not in rendered
    assert diagnostics["skipped_count"] == 5
    assert [item["reason"] for item in diagnostics["skipped_items"]] == [
        "unsupported_candidate_type_for_promotion_recommendation_export"
    ] * 5


def test_skipped_decisions_are_never_exported(tmp_path: Path) -> None:
    output, diagnostics, *_paths = export_from_bundle(
        tmp_path,
        bundle([], [skipped_decision()]),
        diagnostics=True,
    )

    assert output["promotion_recommendation"]["promote"] is False
    assert "ri-candidate-skipped" not in json.dumps(output, sort_keys=True)
    assert diagnostics["skipped_items"] == [
        {
            "candidate_id": "ri-candidate-skipped",
            "candidate_type": "skipped_decision",
            "target_artifact_type": "not_exportable",
            "proposal_ref": "/proposals/99",
            "reason": "skipped_decision_not_exportable",
        }
    ]


def test_empty_bundle_exports_schema_valid_noop_recommendation(tmp_path: Path) -> None:
    output, diagnostics, *_paths = export_from_bundle(tmp_path, bundle([]), diagnostics=True)

    recommendation = output["promotion_recommendation"]
    assert recommendation["promote"] is False
    assert recommendation["current_agent"] == "not_applicable"
    assert recommendation["challenger_agent"] == "not_applicable"
    assert recommendation["next_baseline_agent"] == "not_applicable"
    assert recommendation["blocking_gaps"] == ["no_eligible_promotion_review_candidates"]
    assert diagnostics["promotion_review_candidate_count"] == 0
    validator(OUTPUT_SCHEMA_PATH).validate(output)


def test_invalid_bundle_schema_fails_closed_and_writes_no_output(tmp_path: Path) -> None:
    exporter = load_module()
    bundle_path, output_path, _diagnostics_output_path = write_bundle(tmp_path, bundle())
    source = load_json(bundle_path)
    source["artifact_semantics"] = "approval"
    write_json(bundle_path, source)

    with pytest.raises(ValidationError):
        exporter.export_rule_improvement_promotion_recommendation(
            bundle_path,
            output_path,
        )

    assert not output_path.exists()


def test_invalid_output_schema_fails_closed_and_writes_no_output(tmp_path: Path) -> None:
    exporter = load_module()
    bundle_path, output_path, diagnostics_output_path = write_bundle(tmp_path, bundle())
    strict_schema_path = tmp_path / "strict_promotion_schema.json"
    strict_schema = copy.deepcopy(load_json(OUTPUT_SCHEMA_PATH))
    strict_schema["properties"]["promotion_recommendation"]["properties"]["promote"]["const"] = (
        False
    )
    write_json(strict_schema_path, strict_schema)

    with pytest.raises(ValidationError):
        exporter.export_rule_improvement_promotion_recommendation(
            bundle_path,
            output_path,
            output_schema_path=strict_schema_path,
            diagnostics_output_path=diagnostics_output_path,
        )

    assert not output_path.exists()
    assert not diagnostics_output_path.exists()


def test_output_refuses_to_overwrite_input_bundle(tmp_path: Path) -> None:
    exporter = load_module()
    bundle_path, _output_path, _diagnostics_output_path = write_bundle(tmp_path, bundle())

    with pytest.raises(ValueError, match="overwrite input bundle"):
        exporter.export_rule_improvement_promotion_recommendation(
            bundle_path,
            bundle_path,
        )


def test_diagnostics_output_path_collision_is_refused(tmp_path: Path) -> None:
    exporter = load_module()
    bundle_path, output_path, _diagnostics_output_path = write_bundle(tmp_path, bundle())

    with pytest.raises(ValueError, match="Diagnostics output"):
        exporter.export_rule_improvement_promotion_recommendation(
            bundle_path,
            output_path,
            diagnostics_output_path=output_path,
        )

    assert not output_path.exists()


@pytest.mark.parametrize(
    "unsafe_name",
    ["rule_candidates.yaml", "prompt_candidates.yaml"],
)
def test_diagnostics_output_rule_prompt_names_are_refused(
    tmp_path: Path,
    unsafe_name: str,
) -> None:
    exporter = load_module()
    bundle_path, output_path, _diagnostics_output_path = write_bundle(tmp_path, bundle())
    diagnostics_output_path = output_path.with_name(unsafe_name)

    with pytest.raises(ValueError, match="unsupported output"):
        exporter.export_rule_improvement_promotion_recommendation(
            bundle_path,
            output_path,
            diagnostics_output_path=diagnostics_output_path,
        )

    assert not output_path.exists()
    assert not diagnostics_output_path.exists()


def test_generated_output_does_not_contain_unsafe_fields_beyond_schema_promote(
    tmp_path: Path,
) -> None:
    output, diagnostics, *_paths = export_from_bundle(
        tmp_path,
        bundle([converted_candidate(), converted_candidate(candidate_type="rule", index=1)]),
        diagnostics=True,
    )

    assert collect_keys(output).isdisjoint(APPROVAL_LIKE_FIELDS - SCHEMA_REQUIRED_PROMOTION_FIELDS)
    assert collect_keys(diagnostics).isdisjoint(APPROVAL_LIKE_FIELDS)


def test_exporter_does_not_create_rule_or_prompt_candidates(tmp_path: Path) -> None:
    output, _diagnostics, _bundle_path, output_path, _diagnostics_path = export_from_bundle(
        tmp_path,
        bundle(),
    )

    assert output_path.exists()
    assert not (output_path.parent / "rule_candidates.yaml").exists()
    assert not (output_path.parent / "prompt_candidates.yaml").exists()
    assert "rule_candidates" not in collect_keys(output)
    assert "prompt_candidates" not in collect_keys(output)


def test_exporter_does_not_call_or_imply_promotion_workflow(tmp_path: Path) -> None:
    output, _diagnostics, *_paths = export_from_bundle(tmp_path, bundle())

    reason = output["promotion_recommendation"]["reason"]
    assert "Recommendation-only artifact; not promotion approval." in reason
    assert "promotion_workflow" not in collect_keys(output)
    assert "deployment_approved" not in collect_keys(output)


def test_missing_promotion_payload_fails_closed_and_writes_no_output(tmp_path: Path) -> None:
    exporter = load_module()
    candidate = converted_candidate()
    for field in exporter.REQUIRED_PAYLOAD_FIELDS:
        del candidate["candidate_payload"]["payload"][field]
    bundle_path, output_path, _diagnostics_output_path = write_bundle(
        tmp_path,
        bundle([candidate]),
    )

    with pytest.raises(ValueError, match="missing promotion payload fields"):
        exporter.export_rule_improvement_promotion_recommendation(
            bundle_path,
            output_path,
        )

    assert not output_path.exists()


def test_rule_prompt_output_paths_are_refused(tmp_path: Path) -> None:
    exporter = load_module()
    bundle_path, output_path, _diagnostics_output_path = write_bundle(tmp_path, bundle())

    with pytest.raises(ValueError, match="unsupported output"):
        exporter.export_rule_improvement_promotion_recommendation(
            bundle_path,
            output_path.with_name("rule_candidates.yaml"),
        )

    with pytest.raises(ValueError, match="unsupported output"):
        exporter.export_rule_improvement_promotion_recommendation(
            bundle_path,
            output_path.with_name("prompt_candidates.yaml"),
        )
