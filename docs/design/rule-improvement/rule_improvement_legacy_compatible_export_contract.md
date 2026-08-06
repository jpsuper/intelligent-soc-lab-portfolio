# Rule Improvement Legacy-Compatible Export Contract

## 1. Purpose

This document defines the export boundary from non-applying Rule
Improvement concrete candidate bundles into legacy-compatible candidate
artifacts.

The promotion recommendation export boundary is defined separately in
`docs/design/rule-improvement/rule_improvement_promotion_recommendation_export_contract.md`.
The parser legacy export boundary is defined separately in
`docs/design/rule-improvement/rule_improvement_parser_legacy_export_contract.md`.
The export artifact validation summary boundary is defined separately in
`docs/design/rule-improvement/rule_improvement_export_artifact_validation_summary_contract.md`.

The Phase 1 legacy-compatible exporter is implemented at
`scripts/export_rule_improvement_legacy_rule_prompt_candidates.py`. It consumes
schema-valid `rule_improvement_concrete_candidate_bundle_v1.json` and may
produce legacy-compatible rule and prompt candidate artifacts only. It must not
apply changes, deploy changes, update baselines, update prompt templates,
update parser code, update telemetry collection, update correlation logic,
promote candidates or agents, or mutate operational state.

## 2. Flow Position

The standalone export flow is:

```text
rule_improvement_proposal_review_decisions.json
  -> scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py
  -> rule_improvement_concrete_candidate_bundle_v1.json
  -> scripts/export_rule_improvement_legacy_rule_prompt_candidates.py
  -> rule_candidates.yaml / prompt_candidates.yaml
  -> scripts/export_rule_improvement_promotion_recommendation.py, if needed
  -> promotion_recommendation.yaml
  -> scripts/export_rule_improvement_parser_candidates.py, if needed
  -> parser_candidates.yaml
  -> scripts/summarize_rule_improvement_export_artifacts.py
  -> rule_improvement_export_artifact_validation_summary.json
  -> separate human review and any state-changing workflows
```

Rule and prompt narrowing is handled by the Phase 1 exporter. Promotion-review
and parser narrowing use separate recommendation-only and candidate-only
exporters. Telemetry and correlation are outside this contract and require
dedicated schemas and export contracts.

## 3. Export Eligibility

Only `converted_candidates` from a schema-valid concrete candidate bundle may
be considered for export.

The exporter must not export:

- `skipped_decisions`
- diagnostics
- non-accept decisions
- candidates with unsupported `candidate_type`
- candidates with mismatched `candidate_type` / `target_artifact_type`
- candidates with unsafe approval/apply/promotion-like fields

`accept_for_conversion` remains conversion-review-only. It is not approval to
apply, deploy, update baselines, update prompts, update parser code, update
telemetry collection, update correlation logic, or promote.

## 4. Candidate Type Support

Rule and prompt exporter support:

| Bundle `candidate_type` | Legacy-compatible output |
|---|---|
| `rule` | `rule_candidates.yaml` |
| `prompt` | `prompt_candidates.yaml` |

Separate exporter support:

| Bundle `candidate_type` | Legacy-compatible output |
|---|---|
| `promotion_review` | `promotion_recommendation.yaml` |
| `parser` | `parser_candidates.yaml` |

`promotion_review` export must remain recommendation-only. It must not promote
anything by itself and requires separate human review.
Parser export must remain candidate-only. It must not update parser code,
parser configuration, active agents, or production state.

Outside this contract:

- `telemetry`
- `correlation`

Telemetry and correlation export require dedicated legacy-compatible schemas
and separate artifact contracts. The parser legacy export contract
defines the `parser_candidates.yaml` and parser diagnostics boundaries.

## 5. Legacy Artifact Relationship

Legacy comparison-harness artifacts include:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`
- `parser_candidates.yaml`

These artifacts are narrower than the v2 provenance-preserving concrete
candidate bundle. Exporting to a legacy format is a narrowing step.

Exporter output should preserve enough backreferences to the
bundle/proposal/review provenance where the legacy schema permits. Any
provenance that cannot fit into the legacy schema must remain available through
the source bundle and documented source refs.

Legacy-compatible artifacts are candidate artifacts only. They are not apply
approval, deployment approval, baseline update approval, prompt update
approval, parser update approval, telemetry update approval, correlation update
approval, or promotion approval.

## 6. Required Source and Provenance Handling

Each exporter should preserve or link back to:

- source concrete candidate bundle ref
- source concrete candidate bundle SHA-256
- source proposal review decisions ref
- source proposal review decisions SHA-256
- source proposals ref
- source proposals SHA-256
- `candidate_id`
- `candidate_type`
- `target_artifact_type`
- `proposal_ref`
- `proposal_review_decision_ref`
- `source_human_decision_provenance`
- conversion decision rationale
- limitations
- `required_follow_up_evidence_refs`

The exporter must not fabricate proposal, review, human decision, bundle, or
legacy artifact identity. If a legacy schema cannot carry a provenance field,
the exporter should keep the source bundle as the authoritative provenance
artifact.

## 7. Output Path Strategy

Rule and prompt output names:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`

Separate exporter output names:

- `promotion_recommendation.yaml`
- `parser_candidates.yaml`

Promotion recommendation output is produced by the separate
recommendation-only exporter. Exporters should refuse unsafe paths and must
refuse to overwrite the source concrete candidate bundle.
Parser candidate output is produced by the separate candidate-only exporter
and must remain candidate-only.

## 8. Safety Boundaries

Exporters must not:

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
- treat bundle output as approval
- treat `promotion_review` export as promotion

Legacy-compatible export is not apply approval, deployment approval, baseline
update approval, or promotion approval.

## 9. Failure Behavior

Exporters must fail closed on:

- invalid bundle schema
- unsafe approval/apply/promotion-like fields
- unsupported candidate type
- missing candidate payload
- missing provenance or backrefs
- unsafe output path
- overwrite attempt
- output schema validation failure
- attempts to export skipped decisions
- attempts to export diagnostics as candidates

The exporter must write outputs only after successful input validation, safety
checks, provenance checks, and output schema validation.

## 10. Status And Evidence Ownership

This document owns eligibility for rule and prompt narrowing, the separation of
promotion-review and parser exporters, provenance handling, safe output paths,
schema validation, and fail-closed behavior. The bundle schema, dedicated
exporters, output schemas, diagnostics, and focused tests named here are
evidence for those boundaries.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, validation depth, priorities, and sequencing.
Telemetry or correlation support must arrive through dedicated contracts rather
than being inferred from this exporter.

---

## 11. Boundary Acceptance Criteria

The legacy-compatible export boundary remains valid when:

- only converted candidates of supported types are eligible
- skipped decisions and diagnostics cannot become candidate artifacts
- source bundle and review provenance remain traceable
- every exporter validates input, output, and safe path handling before write
- rule, prompt, and parser outputs remain candidate-only
- promotion output remains recommendation-only
- narrowing artifacts cannot authorize apply, deployment, mutation, or
  promotion

---

## 12. One-Line Summary

```text
Legacy-compatible export narrows non-applying bundle artifacts into schema-valid candidate or recommendation artifacts; it must not apply, deploy, update baselines, or promote.
```
