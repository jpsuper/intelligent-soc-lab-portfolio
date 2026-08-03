# Rule Improvement Proposal Conversion Contract

## 1. Purpose

This document defines the future conversion boundary from canonical
`rule_improvement_proposal_review_decisions.json` into concrete Rule
Improvement candidate artifacts.

The standalone converter is implemented at
`scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py`.
It consumes canonical `rule_improvement_proposal_review_decisions.json` produced by
`scripts/import_rule_improvement_proposal_review_decisions.py`. It may only
consider decisions whose `decision` is `accept_for_conversion`.

The converter may create concrete candidate artifacts only. It must not apply
changes, deploy changes, update baselines, update prompts, update parser code,
update telemetry collection, update correlation logic, promote candidates or
agents, or mutate operational state. Conversion is separate from importer
behavior.

The preferred future concrete candidate artifact strategy is defined in
`docs/design/rule-improvement/rule_improvement_concrete_candidate_artifact_strategy.md`.
That strategy recommends a provenance-preserving
`rule_improvement_concrete_candidate_bundle_v1.json` as the first future
converter output, with legacy-compatible export handled later as a separate
reviewed step.
The non-applying bundle shape is defined by
`schemas/rule_improvement_concrete_candidate_bundle_v1.schema.json`.
The future legacy-compatible export boundary from that bundle into legacy
candidate artifacts is defined in
`docs/design/rule-improvement/rule_improvement_legacy_compatible_export_contract.md`.
The promotion recommendation export boundary is defined in
`docs/design/rule-improvement/rule_improvement_promotion_recommendation_export_contract.md`.

## 2. Flow Position

The intended future conversion flow is:

```text
rule_improvement_candidate_proposals_v2.json
  -> rule_improvement_proposal_review_decisions_template.json
  -> human-completed proposal review decisions JSON
  -> rule_improvement_proposal_review_decisions.json
  -> scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py
  -> rule_improvement_concrete_candidate_bundle_v1.json
  -> scripts/export_rule_improvement_legacy_rule_prompt_candidates.py, if needed
  -> rule_candidates.yaml / prompt_candidates.yaml
  -> scripts/export_rule_improvement_promotion_recommendation.py, if needed
  -> promotion_recommendation.yaml
  -> future apply / deployment / promotion workflows
```

The concrete candidate bundle schema and standalone converter are implemented,
and the Phase 1 legacy-compatible rule/prompt exporter is implemented.
Promotion recommendation export is implemented as a separate recommendation-only
exporter. The process pipeline is not wired to this converter or exporter.

## 3. Conversion Eligibility

A proposal review decision may be eligible for future conversion only when all
of these are true:

- the artifact has `artifact_semantics: conversion_review_only`
- the review decision artifact validates against
  `schemas/rule_improvement_proposal_review_decisions_v1.schema.json`
- the source proposal artifact is schema-valid
- the decision is `accept_for_conversion`
- the decision rationale is completed and not a template placeholder
- required source and human decision provenance fields are present
- `candidate_type` and `allowed_next_artifact_type` are a valid pair

All other decisions must remain unconverted:

- `reject`
- `defer`
- `split_required`
- `needs_more_evidence`

`accept_for_conversion` means only that the reviewed proposal may be eligible
for a future converter. It is not apply approval, deployment approval,
baseline update approval, prompt update approval, parser update approval,
telemetry update approval, correlation update approval, or promotion approval.

## 4. Candidate Type Mapping

Expected future conversion directions are:

| `candidate_type` | `allowed_next_artifact_type` | Future output area |
|---|---|---|
| `rule` | `rule_candidate_proposal` | future rule candidate artifact |
| `prompt` | `prompt_candidate_proposal` | future prompt candidate artifact |
| `parser` | `parser_candidate_proposal` | future parser candidate artifact |
| `telemetry` | `telemetry_candidate_proposal` | future telemetry candidate artifact |
| `correlation` | `correlation_candidate_proposal` | future correlation candidate artifact |
| `promotion_review` | `promotion_review_recommendation` | future promotion review recommendation artifact |

Known `candidate_type` / `allowed_next_artifact_type` mismatches must fail
closed.

## 5. Legacy Artifact Relationship

Legacy comparison-harness artifacts currently include:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`

Canonical v2 proposal review decisions are not directly equivalent to those
legacy artifacts. The legacy schemas are smaller and do not preserve the full
v2 proposal and review provenance.

A future converter may emit legacy-compatible artifacts only if a later
reviewed implementation explicitly preserves provenance, validates output
schemas, and keeps the safety boundaries in this contract. Parser, telemetry,
and correlation candidate artifact shapes may need separate schemas before
conversion.

The recommended first conversion output is not a legacy artifact. It is a
future `rule_improvement_concrete_candidate_bundle_v1.json` that preserves
conversion context, skipped decisions, source hashes, proposal refs, human
decision provenance, limitations, and review rationale. Legacy-compatible
exports should be a later explicit narrowing step.

## 6. Required Provenance Preservation

Future converter output should preserve or link back to:

- source proposal review decisions ref
- source proposal review decisions SHA-256
- source proposals ref
- source proposals SHA-256
- source candidate creation input ref
- source candidate creation input SHA-256
- `proposal_ref`
- `candidate_id`
- `candidate_type`
- `allowed_next_artifact_type`
- `source_human_decision_provenance`
- conversion decision rationale
- limitations
- `required_follow_up_evidence_refs`
- schema-compatible proposal `payload` fields needed by later narrowing
  exporters

The converter must not fabricate proposal, review, or human decision
identity. It should carry reviewed provenance forward, or reference it
explicitly, in any concrete candidate artifact shape a later contract defines.
It must not infer promotion decisions from missing or incomplete proposal
payload. It must fail closed if optional proposal payload attempts to override
converter-owned base payload metadata such as `target`, `source_signal_ref`,
`source_label`, `source_fact_ids`, `required_evidence_refs`, `priority`, or
`review_status`.

## 7. Safety Boundaries

The future converter must not:

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
- treat diagnostics as proposals
- treat `accept_for_conversion` as apply, deployment, baseline update, or
  promotion approval

Concrete candidate artifacts remain review artifacts unless a later apply,
deployment, baseline update, or promotion workflow separately validates and
authorizes state changes.

## 8. Failure Behavior

The future converter must fail closed on:

- invalid review decisions schema
- missing source hashes
- missing provenance
- unsupported candidate type
- mismatched `candidate_type` / `allowed_next_artifact_type`
- non-accept decisions
- placeholder rationale
- unsafe approval/apply/promotion-like fields
- attempts to overwrite source artifacts
- unsafe output paths

The converter must write outputs only after successful validation and safety
checks.

## 9. Implementation Status

Implemented:

- v2 proposal schema
- v2 proposal generator
- generator diagnostics
- proposal review decisions schema
- proposal review decisions template exporter
- proposal review decisions importer / validator
- concrete candidate artifact strategy document
- concrete candidate bundle v1 schema
- standalone deterministic concrete candidate bundle converter
- legacy-compatible export contract document
- Phase 1 legacy-compatible rule/prompt exporter
- promotion recommendation export contract document
- promotion recommendation exporter
- direct generation of recommendation-only `promotion_recommendation.yaml`

Not implemented:

- concrete candidate artifact schemas for parser, telemetry, and correlation
  if absent
- process-pipeline wiring
- apply workflow
- deployment workflow
- baseline update workflow
- prompt update workflow
- parser update workflow
- telemetry update workflow
- correlation update workflow
- promotion workflow

## 10. One-Line Summary

```text
Canonical proposal review decisions may feed the standalone bundle converter, but conversion still does not authorize apply, deployment, baseline update, or promotion.
```
