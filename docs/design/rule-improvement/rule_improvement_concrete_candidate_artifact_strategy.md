# Rule Improvement Concrete Candidate Artifact Strategy

## 1. Purpose

This document defines the concrete candidate artifact strategy
for Rule Improvement proposal conversion.

It is a strategy document for the non-applying bundle shape now defined by
`schemas/rule_improvement_concrete_candidate_bundle_v1.schema.json`. The
standalone converter exists, but it does not emit legacy artifacts, apply
changes, deploy changes, update baselines, update prompts, update parser code,
update telemetry collection, update correlation logic, or promote anything.

The converter boundary is defined in
`docs/design/rule-improvement/rule_improvement_proposal_conversion_contract.md`.
The standalone deterministic converter is implemented at
`scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py`.
This strategy narrows the first output shape for that converter.

## 2. Recommendation

The bundle converter intentionally does not convert directly from canonical
`rule_improvement_proposal_review_decisions.json` into legacy artifacts.

Instead, it should emit a provenance-preserving v1 concrete candidate bundle:

```text
rule_improvement_concrete_candidate_bundle_v1.json
```

Legacy-compatible export is a later, separate step after bundle conversion.
Rule/prompt export is implemented, schema-validated, separately reviewed, and
still non-applying. The legacy-compatible export boundary is defined in
`docs/design/rule-improvement/rule_improvement_legacy_compatible_export_contract.md`.
The promotion recommendation export boundary is defined in
`docs/design/rule-improvement/rule_improvement_promotion_recommendation_export_contract.md`.
The parser legacy export boundary is defined in
`docs/design/rule-improvement/rule_improvement_parser_legacy_export_contract.md`.
The export artifact validation summary boundary is defined in
`docs/design/rule-improvement/rule_improvement_export_artifact_validation_summary_contract.md`.

Current export MVP flow:

```text
rule_improvement_proposal_review_decisions.json
  -> scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py
  -> rule_improvement_concrete_candidate_bundle_v1.json
  -> scripts/export_rule_improvement_legacy_rule_prompt_candidates.py, if needed
  -> rule_candidates.yaml / prompt_candidates.yaml
  -> scripts/export_rule_improvement_promotion_recommendation.py, if needed
  -> promotion_recommendation.yaml
  -> scripts/export_rule_improvement_parser_candidates.py, if needed
  -> parser_candidates.yaml
  -> scripts/summarize_rule_improvement_export_artifacts.py
  -> rule_improvement_export_artifact_validation_summary.json
  -> future apply / deployment / update / promotion workflows
```

This Rule Improvement export MVP is complete for the current
candidate-generation boundary. It remains non-applying, non-deploying,
non-mutating, review-oriented, and does not implement baseline updates, prompt
updates, parser updates, telemetry updates, correlation updates, a promotion
workflow, or automatic promotion.

## 3. Rationale

The v2 proposal and proposal-review flow carries richer provenance than the
legacy comparison-harness artifacts. That provenance includes source proposal
refs, source hashes, human candidate-review decision provenance, limitations,
required follow-up evidence, and human proposal review rationale.

Direct legacy emission risks losing:

- source proposal refs
- source proposal hashes
- source candidate-creation input refs and hashes
- human candidate-review decision provenance
- proposal review rationale
- limitations
- required follow-up evidence refs
- skipped decision context

A concrete candidate bundle can preserve the full conversion context while
remaining a non-applying review artifact. Legacy-compatible export can then be
implemented later as an explicit narrowing step, with clear schema validation
and separate review.

## 4. Preferred Bundle Shape

The v1 bundle schema is defined at
`schemas/rule_improvement_concrete_candidate_bundle_v1.schema.json`. At a high
level, the root artifact includes:

- `version`
- `artifact_type`
- `artifact_semantics`, such as `candidate_bundle_only`
- source proposal review decisions ref
- source proposal review decisions SHA-256
- source proposals ref
- source proposals SHA-256
- converted candidates array
- skipped decisions array

Each converted candidate should preserve:

- `candidate_id`
- `candidate_type`
- `allowed_next_artifact_type`
- `proposal_ref`
- conversion decision rationale
- `source_human_decision_provenance`
- source candidate creation input ref
- source candidate creation input SHA-256
- limitations
- `required_follow_up_evidence_refs`
- candidate payload area
- target legacy artifact type, if applicable

The candidate payload area should remain specific to the candidate type. It
should not smuggle approval, apply, deployment, baseline update, or promotion
semantics into the bundle. Optional schema-safe proposal `payload` fields may
be preserved into this area for later narrowing exporters, but they must not
override converter-owned base metadata such as `target`, `source_signal_ref`,
`source_label`, `source_fact_ids`, `required_evidence_refs`, `priority`, or
`review_status`.

## 5. Candidate Type Strategy

Current bundle handling:

| `candidate_type` | Bundle strategy |
|---|---|
| `rule` | A bundle candidate may export to candidate-only `rule_candidates.yaml`; direct legacy export remains separate from conversion. |
| `prompt` | A bundle candidate may export to candidate-only `prompt_candidates.yaml`; direct legacy export remains separate from conversion. |
| `promotion_review` | A bundle candidate may export to recommendation-only `promotion_recommendation.yaml`; it must not promote anything by itself. |
| `parser` | A bundle candidate may export to candidate-only `parser_candidates.yaml`; it must not update parser code or configuration. |
| `telemetry` | Needs a dedicated schema before conversion or export. |
| `correlation` | Needs a dedicated schema before conversion or export. |

Known `candidate_type` / `allowed_next_artifact_type` mismatches must fail
closed before bundle output is written.

## 6. Skipped Decisions

Only `accept_for_conversion` decisions may be considered for future conversion.
All other decisions should be represented as skipped, not converted:

- `reject`
- `defer`
- `split_required`
- `needs_more_evidence`

Skipped decision records should include:

- decision
- reason
- `candidate_id`
- `proposal_ref`
- provenance pointer where available

Skipped records are audit context. They must not be emitted as converted
candidates, proposal items, approvals, or recommendations to apply, deploy,
update baselines, or promote.

## 7. Legacy Artifact Relationship

Legacy comparison-harness artifacts remain separate:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`
- `parser_candidates.yaml`

The legacy schemas are intentionally compact and strict. They do not preserve
the full v2 proposal and proposal-review provenance. That is useful for the
existing comparison-harness flow, but it makes them a poor first output for the
future v2 proposal conversion path.

Legacy-compatible exports are candidate or recommendation artifacts only. They
must be schema-validated and separately reviewed. They must not apply changes,
deploy changes, update baselines, update prompts, update parser code, update
telemetry collection, update correlation logic, or promote anything.

## 8. Safety Boundaries

The future concrete candidate bundle is not:

- apply approval
- deployment approval
- baseline update approval
- prompt update approval
- parser update approval
- telemetry update approval
- correlation update approval
- promotion approval

The future bundle must not mutate:

- rules
- prompts
- parsers
- telemetry collection
- correlation logic
- baselines
- active agents
- case state
- action state
- pre-case investigation state
- post-action DFIR investigation state
- approval state
- verdict
- severity
- confidence
- Rule Improvement promotion state

Legacy-compatible exports, if implemented later, remain candidate artifacts only
and must not apply or promote.

## 9. Future Failure Behavior

A future converter should fail closed on:

- invalid proposal review decisions
- missing source hashes
- missing provenance
- unsupported candidate type
- mismatched `candidate_type` / `allowed_next_artifact_type`
- unsafe approval/apply/promotion-like fields
- unsafe output path
- overwrite attempt
- attempts to treat diagnostics as proposals

The converter should write a bundle only after input validation, provenance
checks, candidate type checks, safety checks, and output validation succeed.

## 10. Implementation Status

Implemented:

- proposal v2 schema and generator
- proposal review decisions schema
- proposal review decisions template exporter
- proposal review decisions importer / validator
- proposal conversion contract
- concrete candidate artifact strategy document
- concrete candidate bundle v1 schema
- standalone deterministic concrete candidate bundle converter
- legacy-compatible export contract document
- Phase 1 legacy-compatible rule/prompt exporter
- promotion recommendation export contract document
- promotion recommendation exporter
- direct generation of recommendation-only `promotion_recommendation.yaml`
- optional schema-safe proposal payload preservation into bundle payloads
- promotion recommendation export-chain smoke test
- parser legacy export contract document
- parser candidate schema
- parser candidate schema tests
- parser legacy exporter
- parser legacy exporter tests
- parser export chain smoke test
- export artifact validation summary contract document
- export artifact validation summary script

Not implemented:

- telemetry legacy exporter
- telemetry candidate schema
- telemetry export chain smoke
- correlation legacy exporter
- correlation candidate schema
- correlation export chain smoke
- parser/telemetry/correlation export process-pipeline wiring
- apply workflow
- deployment workflow
- baseline update workflow
- prompt update workflow
- parser update workflow
- telemetry update workflow
- correlation update workflow
- promotion workflow
- automatic promotion

## 11. One-Line Summary

```text
Future proposal conversion should first preserve review provenance in a non-applying concrete candidate bundle, then optionally narrow to legacy-compatible candidate artifacts in a later reviewed step.
```
