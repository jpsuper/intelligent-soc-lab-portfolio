# Rule Improvement Candidate Proposal v2 Contract

## 1. Purpose

`rule_improvement_candidate_proposals_v2.schema.json` defines the v2
proposal artifact contract for AI-assisted Rule Improvement candidate creation.

The standalone generator is implemented at
`scripts/generate_rule_improvement_candidate_proposals_v2.py`. This contract
does not implement an apply workflow, deployment workflow, baseline update,
prompt update, parser update, telemetry update, correlation update, or
promotion workflow.

Generator behavior is defined separately in
`docs/design/rule-improvement/rule_improvement_candidate_proposal_generator_contract.md`.
Future human review and conversion after proposal generation are defined in
`docs/design/rule-improvement/rule_improvement_candidate_proposal_review_conversion_contract.md`.
The future proposal human review decision artifact shape is defined by
`schemas/rule_improvement_proposal_review_decisions_v1.schema.json`.
The future conversion boundary from canonical review decisions into concrete
candidate artifacts is defined in
`docs/design/rule-improvement/rule_improvement_proposal_conversion_contract.md`.
The preferred future concrete candidate artifact strategy is defined in
`docs/design/rule-improvement/rule_improvement_concrete_candidate_artifact_strategy.md`.

The AI-assisted Rule Improvement flow may now produce proposal-only v2 output
from:

```text
rule_improvement_candidate_creation_input.json
```

## 2. Flow position

The standalone generator position is:

```text
rule_improvement_candidate_creation_input.json
  ↓ scripts/generate_rule_improvement_candidate_proposals_v2.py
rule_improvement_candidate_proposals_v2.json   (proposal-only)
  ↓ future human proposal review decisions
  ↓ future proposal converter
  ↓ future concrete candidate artifacts
  ↓ future apply / deployment / promotion workflows
```

The v2 artifact is a proposal artifact only. It is not candidate approval,
deployment approval, promotion approval, or authority to mutate rule, prompt,
parser, telemetry, correlation, baseline, active-agent, case, action, or
investigation state.

The follow-on proposal review decisions artifact has
`artifact_semantics: conversion_review_only`. Its `accept_for_conversion`
decision means only future conversion eligibility; it is not apply,
deployment, baseline update, prompt update, parser update, telemetry update,
correlation update, or promotion approval.

## 3. Schema identity

Schema:

```text
schemas/rule_improvement_candidate_proposals_v2.schema.json
```

Root invariants:

```json
{
  "version": 2,
  "artifact_type": "rule_improvement_candidate_proposals",
  "artifact_semantics": "proposal_only"
}
```

The schema rejects unknown fields at the root, source object,
`human_decision_provenance`, and proposal item levels. This is intentional:
approval, apply, deployment, baseline update, and promotion semantics must not
be smuggled into proposal artifacts.

## 4. Required source provenance

The root `source` object preserves provenance from the accepted
candidate-creation input:

```json
{
  "source_candidate_creation_input_ref": "data/runs/run-001/rule_improvement_candidate_creation_input.json",
  "source_candidate_creation_input_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```

The SHA-256 value must be lowercase hexadecimal. The schema does not define how
the hash is calculated or checked at runtime; that remains future generator and
reviewer validation work.

## 5. Proposal item requirements

Each proposal preserves:

- `candidate_id`
- `candidate_type`
- `allowed_next_artifact_type`
- `source_signal_ref`
- `source_label`
- `source_fact_ids`
- `required_evidence_refs`
- `limitations`
- `human_decision_provenance`
- `target`
- `rationale`
- `proposed_change`
- `expected_effect`
- `priority`
- `review_status`
- optional `payload`

`review_status` is always:

```json
"human_review_required"
```

This status means the proposal still requires later review. It does not mean
the candidate has been approved, deployed, applied, or promoted.

The optional `payload` object carries schema-compatible, non-authorizing
details that a later reviewed converter/exporter may need. For example,
`promotion_review` proposals that are intended for recommendation-only export
may include `promotion_recommended`, `current_agent`, `challenger_agent`,
`next_baseline_agent`, `score_delta`, `gates`, and `blocking_gaps` in
`payload`. Unsafe approval/apply/deploy/promote-like payload field names are
rejected. Payload fields do not authorize apply, deployment, baseline update,
prompt update, parser update, telemetry update, correlation update, or
promotion.

When proposal payload is later preserved into concrete candidate bundle
payload, it must not override converter-owned base metadata such as `target`,
`source_signal_ref`, `source_label`, `source_fact_ids`,
`required_evidence_refs`, `priority`, or `review_status`.

## 6. Human decision provenance

Each proposal must preserve human candidate-review decision provenance:

```json
{
  "decision_ref": "/decisions/0",
  "decision_id": "decision-001",
  "decision_status": "accepted_for_candidate_creation"
}
```

For proposals generated from `rule_improvement_candidate_creation_input.json`,
the generator must populate these fields from item-level
`human_decision_ref`, `human_decision_id`, and `human_decision_status`. It must
not derive `decision_id` from `candidate_id`.

`accepted_for_candidate_creation` means only that the reviewed draft item may
become a proposal. It is not rule approval, prompt approval, parser approval,
telemetry approval, correlation approval, deployment approval, baseline update
approval, or promotion approval.

## 7. Candidate and next-artifact types

The v2 proposal schema supports these candidate types:

- `rule`
- `prompt`
- `parser`
- `telemetry`
- `correlation`
- `promotion_review`

It supports these next-artifact proposal types:

- `rule_candidate_proposal`
- `prompt_candidate_proposal`
- `parser_candidate_proposal`
- `telemetry_candidate_proposal`
- `correlation_candidate_proposal`
- `promotion_review_recommendation`

`candidate_type` and `allowed_next_artifact_type` are coupled. The schema
requires this exact mapping:

| `candidate_type` | Required `allowed_next_artifact_type` |
|---|---|
| `rule` | `rule_candidate_proposal` |
| `prompt` | `prompt_candidate_proposal` |
| `parser` | `parser_candidate_proposal` |
| `telemetry` | `telemetry_candidate_proposal` |
| `correlation` | `correlation_candidate_proposal` |
| `promotion_review` | `promotion_review_recommendation` |

`promotion_review_recommendation` is recommendation-only. It must not be
treated as approval to promote, deploy, update the baseline, or change active
agents.

## 8. Relationship to legacy schemas

The v2 proposal contract intentionally differs from the legacy
comparison-harness schemas:

- `schemas/rule_candidates_schema.json`
- `schemas/prompt_candidates_schema.json`
- `schemas/promotion_recommendation_schema.json`

Those legacy schemas remain intact and continue to describe lightweight
comparison-harness proposal/recommendation artifacts. They are too small to
preserve the richer provenance needed by the AI-assisted candidate-creation
flow, such as source candidate-creation input refs and hashes, source signal
refs, source fact IDs, required evidence refs, limitations, and human
candidate-review decision provenance.

Generator work targets the v2 proposal schema rather than directly emitting the
legacy schema shape. Any future conversion from v2 proposals into
concrete rule, prompt, parser, telemetry, correlation, or promotion-review
artifacts must be a separate reviewed workflow. The future review and
conversion boundary is documented in
`docs/design/rule-improvement/rule_improvement_candidate_proposal_review_conversion_contract.md`.
The concrete candidate artifact strategy recommends that a future converter
first emit a provenance-preserving
`rule_improvement_concrete_candidate_bundle_v1.json`, with any
legacy-compatible export handled later as a separate schema-validated step.

## 9. Prohibited semantics

The v2 proposal artifact must not contain or imply:

- `approved`
- `candidate_approved`
- `promotion_approved`
- `deployment_approved`
- `baseline_update_approved`
- `auto_apply_allowed`
- `promotion_allowed`
- `applies_changes`
- `promoted`

It must not:

- apply rule changes
- update prompt templates
- enable detection rules
- modify parser code
- modify telemetry collection behavior
- modify correlation logic
- update baselines
- change active agents
- mutate case, action, pre-case investigation, post-action DFIR, containment,
  approval, verdict, severity, confidence, or Rule Improvement promotion state

## 10. Implementation status

Implemented:

- v2 proposal JSON Schema
- standalone generator from `rule_improvement_candidate_creation_input.json`
- v1 proposal human review decision schema
- proposal review decisions template exporter
- proposal review decisions importer / validator
- concrete candidate artifact strategy document
- focused schema tests for valid rule and prompt proposals
- tests rejecting unknown, approval-like, malformed provenance, and unsafe
  semantic fields

Not implemented:

- process-pipeline integration
- candidate YAML generation
- proposal review worksheet
- converter from v2 proposals to concrete candidate artifacts
- concrete candidate bundle schema
- legacy-compatible exporter
- conversion into legacy artifacts
- apply, deployment, baseline update, prompt update, parser update, telemetry
  update, correlation update, or promotion behavior

## 11. One-line summary

```text
v2 candidate proposals preserve reviewed provenance for future work, but remain proposal-only and non-applying.
```
