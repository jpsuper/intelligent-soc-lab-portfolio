# Rule Improvement Promotion Recommendation Export Contract

## 1. Purpose

This document defines the export boundary from non-applying Rule
Improvement concrete candidate bundles into a legacy-compatible promotion
recommendation artifact.

The export artifact validation summary boundary is defined separately in
`docs/design/rule-improvement/rule_improvement_export_artifact_validation_summary_contract.md`.

Promotion recommendation export is implemented as a standalone deterministic
exporter at `scripts/export_rule_improvement_promotion_recommendation.py`.
The exporter consumes schema-valid
`rule_improvement_concrete_candidate_bundle_v1.json` and considers only
`converted_candidates` with the required schema-compatible promotion payload
fields and:

- `candidate_type: promotion_review`
- `target_artifact_type: promotion_review_bundle_item`
- `allowed_next_artifact_type: promotion_review_recommendation`

The required promotion payload fields are `promotion_recommended`,
`current_agent`, `challenger_agent`, `next_baseline_agent`, `score_delta`,
`gates`, and `blocking_gaps`. The exporter must not infer promotion decisions
from incomplete payloads.

The exporter may produce `promotion_recommendation.yaml`. That artifact remains
recommendation-only. It must not promote anything by itself.

Integration-style smoke coverage is implemented at
`tests/test_rule_improvement_promotion_recommendation_export_chain_smoke.py`.
The smoke uses synthetic schema-valid fixtures under `tmp_path` to verify that
proposal v2 plus canonical proposal review decisions can be converted into a
concrete candidate bundle, that schema-safe promotion payload fields are
preserved into the bundle payload, and that the exporter produces schema-valid
recommendation-only `promotion_recommendation.yaml`. Non-promotion candidates
and non-accept/skipped decisions are excluded from the recommendation output,
diagnostics report them deterministically, and the exporter does not create
`rule_candidates.yaml` or `prompt_candidates.yaml`.

## 2. Flow Position

The intended flow is:

```text
rule_improvement_proposal_review_decisions.json
  -> scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py
  -> rule_improvement_concrete_candidate_bundle_v1.json
  -> scripts/export_rule_improvement_legacy_rule_prompt_candidates.py, if rule/prompt export is needed
  -> rule_candidates.yaml / prompt_candidates.yaml
  -> scripts/export_rule_improvement_promotion_recommendation.py, if promotion_review export is needed
  -> promotion_recommendation.yaml
  -> separate human review / promotion workflow
```

Rule and prompt narrowing is handled by
`scripts/export_rule_improvement_legacy_rule_prompt_candidates.py`.
Promotion-recommendation narrowing remains a separate exporter so that
candidate generation cannot be conflated with promotion review or execution.

## 3. Eligibility

Only schema-valid bundle `converted_candidates` may be considered.

The exporter must not export:

- `skipped_decisions`
- diagnostics
- `rule`
- `prompt`
- `parser`
- `telemetry`
- `correlation`
- unsupported candidate types
- candidates with mismatched `candidate_type` / `allowed_next_artifact_type` /
  `target_artifact_type`
- candidates with unsafe approval/apply/deploy/promote-like fields

`accept_for_conversion` remains conversion-review-only. `promotion_review`
means the candidate may be considered for a recommendation artifact; it is not
promotion approval.

## 4. Recommendation-Only Semantics

`promotion_recommendation.yaml` is a recommendation artifact only.

It is not:

- promotion approval
- automatic promotion
- deployment approval
- baseline update approval
- apply approval

It must not:

- mutate active agents
- select a champion by itself
- update production state

The recommendation artifact requires explicit human review and a separate
promotion workflow before any state-changing promotion can occur.

## 5. Required Provenance

The exporter should preserve or link back to:

- source concrete candidate bundle ref
- source concrete candidate bundle SHA-256
- source proposal review decisions ref
- source proposal review decisions SHA-256
- source proposals ref
- source proposals SHA-256
- `candidate_id`
- `candidate_type`
- `target_artifact_type`
- `allowed_next_artifact_type`
- `proposal_ref`
- `proposal_review_decision_ref`
- `source_human_decision_provenance`
- `conversion_decision_rationale`
- `limitations`
- `required_follow_up_evidence_refs`
- `candidate_payload.summary`
- `candidate_payload.proposed_change`
- `candidate_payload.expected_effect`
- `candidate_payload.payload` fields where schema-compatible

If legacy `promotion_recommendation.yaml` cannot carry some provenance fields,
the source concrete candidate bundle remains the authoritative provenance
artifact.

## 6. Output Strategy

The output name is:

```text
promotion_recommendation.yaml
```

The exporter should:

- refuse unsafe paths
- refuse to overwrite the source concrete candidate bundle
- refuse to overwrite rule/prompt outputs unless explicitly allowed by
  separate safe path handling
- validate output against `schemas/promotion_recommendation_schema.json`
- write output only after validation succeeds

## 7. Safety Boundaries

The exporter must not:

- apply changes
- deploy changes
- update baselines
- update prompt templates
- update parser code
- update telemetry collection
- update correlation logic
- promote candidates or agents
- mutate active agents
- mutate case state
- mutate action state
- mutate investigation state
- mutate approval state
- mutate verdict, severity, or confidence
- treat `accept_for_conversion` as promotion approval
- treat `promotion_review` as promotion approval
- treat `promotion_recommendation.yaml` as promotion approval

## 8. Failure Behavior

The exporter must fail closed on:

- invalid bundle schema
- invalid promotion recommendation output schema
- unsafe approval/apply/deploy/promote-like fields
- unsupported candidate type
- missing candidate payload
- missing provenance or backrefs
- unsafe output path
- overwrite attempt
- attempts to export skipped decisions
- attempts to export diagnostics as recommendations
- attempts to include rule/prompt/parser/telemetry/correlation candidates
- attempts to mutate state or call a promotion workflow

## 9. Relationship to Phase 1 Rule/Prompt Exporter

`scripts/export_rule_improvement_legacy_rule_prompt_candidates.py`
intentionally does not create `promotion_recommendation.yaml`.

Promotion recommendation export remains a separate exporter.
Rule/prompt export and promotion recommendation export remain separable so
candidate generation and promotion recommendation do not get conflated.

## 10. Status And Evidence Ownership

This document owns promotion-review eligibility, required payload fields,
recommendation-only semantics, provenance handling, output validation, and
fail-closed behavior. The exporter, output schema, diagnostics, validation
summary contract, and focused chain smoke named here are evidence for those
boundaries.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, validation depth, priorities, and sequencing.
A recommendation artifact must never be treated as evidence that promotion
execution exists or has been approved.

---

## 11. Boundary Acceptance Criteria

The promotion-recommendation export boundary remains valid when:

- only eligible `promotion_review` converted candidates are considered
- every required promotion payload field is present and schema-compatible
- non-promotion candidates, skipped decisions, and diagnostics are excluded
- source bundle and human review provenance remain traceable
- output is validated before it is written
- the recommendation requires separate human review and cannot execute
  promotion

---

## 12. One-Line Summary

```text
Promotion recommendation export narrows eligible non-applying bundle candidates into recommendation-only promotion_recommendation.yaml; it must not apply, deploy, update baselines, or promote.
```
