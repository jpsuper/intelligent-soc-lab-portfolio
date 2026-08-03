# Rule Improvement Candidate Proposal Review and Conversion Contract

## 1. Purpose

This document defines the future human review and conversion boundary after
`rule_improvement_candidate_proposals_v2.json`.

`rule_improvement_candidate_proposals_v2.json` is proposal-only. It requires a
future human review step before any conversion into concrete candidate
artifacts. Human review and conversion are separate from standalone generator
behavior.

This contract is supported by the v1 proposal review decisions schema at
`schemas/rule_improvement_proposal_review_decisions_v1.schema.json`. The
schema defines a conversion-review-only human decision artifact. The local
template exporter is implemented at
`scripts/export_rule_improvement_proposal_review_decisions_template.py`; it
creates an incomplete human-review template and defaults every decision to
`defer`. The local importer is implemented at
`scripts/import_rule_improvement_proposal_review_decisions.py`; it validates
human-completed decisions and writes canonical
`rule_improvement_proposal_review_decisions.json`. These scripts do not add a
review worksheet, converter, pipeline step, apply workflow, deployment
workflow, baseline update workflow, prompt update workflow, parser update
workflow, telemetry update workflow, correlation update workflow, or promotion
workflow.

The future converter boundary from canonical proposal review decisions to
concrete candidate artifacts is defined separately in
`docs/design/rule-improvement/rule_improvement_proposal_conversion_contract.md`.

## 2. Flow Position

The intended review and conversion position is:

```text
rule_improvement_candidate_creation_input.json
  -> rule_improvement_candidate_proposals_v2.json
  -> future human proposal review decisions
  -> future proposal converter
  -> future concrete candidate artifacts
  -> future apply / deployment / promotion workflows
```

The first two artifacts in this flow are currently implemented, and the future
human proposal review decision artifact shape is defined by schema. The
standalone generator can create proposal-only v2 artifacts from reviewed
candidate-creation input, and the template exporter can create an incomplete
human-review template from those proposals. The importer can validate a
human-completed version of that template and write canonical decisions. No
review worksheet, conversion artifact, concrete candidate artifact, apply
workflow, deployment workflow, baseline update workflow, or promotion workflow
is implemented by this contract.

## 3. Review Decision Schema

The future human proposal review decision artifact validates against:

```text
schemas/rule_improvement_proposal_review_decisions_v1.schema.json
```

Its root invariants are:

```json
{
  "version": 1,
  "artifact_type": "rule_improvement_proposal_review_decisions",
  "artifact_semantics": "conversion_review_only"
}
```

The artifact records human review decisions over
`rule_improvement_candidate_proposals_v2.json` items. It authorizes only future
conversion eligibility. It is not apply approval, deployment approval,
baseline update approval, prompt update approval, parser update approval,
telemetry update approval, correlation update approval, or promotion approval.

`scripts/export_rule_improvement_proposal_review_decisions_template.py`
exports a schema-valid starting template for this artifact. The template is
incomplete human-review input: each decision defaults to `defer`, uses a
placeholder rationale, omits reviewer identity, and is not imported
automatically.

`scripts/import_rule_improvement_proposal_review_decisions.py` validates a
human-completed review decisions artifact, rejects the TODO rationale
placeholder, and writes canonical JSON only after schema validation and
invariant checks pass. The importer canonicalizes decisions only; it does not
convert proposals into concrete candidate artifacts.

## 4. Human Review Decision Semantics

A future proposal review decision artifact should use explicit decision values
with narrow meanings. Expected decision values are:

| Decision | Meaning |
|---|---|
| `accept_for_conversion` | The reviewer allows the proposal to proceed to a later converter for a concrete candidate artifact. |
| `reject` | The reviewer rejects the proposal for conversion. |
| `defer` | The reviewer postpones the decision without authorizing conversion. |
| `split_required` | The reviewer requires the proposal to be split before conversion. |
| `needs_more_evidence` | The reviewer requires additional evidence or context before conversion. |

`accept_for_conversion` is not apply approval. It is not deployment approval.
It is not baseline update approval. It is not prompt update approval, parser
update approval, telemetry update approval, correlation update approval, or
promotion approval.

A future converter must treat any decision other than `accept_for_conversion`
as not eligible for conversion unless a later reviewed contract explicitly
defines a narrower flow.

## 5. Required Review Decision Provenance

Future human proposal review decisions should preserve enough provenance to
trace the decision back to both the proposal and the accepted
candidate-creation input.

At minimum, each decision should preserve:

- `candidate_id`, or a future `proposal_id` if a later schema introduces one
- `proposal_ref`, such as `/proposals/0`
- `source_candidate_creation_input_ref`
- `source_candidate_creation_input_sha256`
- the proposal's `human_decision_provenance`
- reviewer identity or reviewer ref, if the future review artifact supports it
- reviewer rationale
- limitations, unresolved evidence gaps, or required follow-up evidence when
  applicable

The review artifact must not fabricate human candidate-review decision
identity. It should carry forward the proposal's
`human_decision_provenance.decision_ref`,
`human_decision_provenance.decision_id`, and
`human_decision_provenance.decision_status` exactly unless a later reviewed
schema defines an explicit transformation.

## 6. Conversion Boundary

Future conversion may create concrete candidate artifacts only after a
schema-valid proposal artifact and explicit human proposal review decision
authorize conversion.

The detailed future conversion contract is
`docs/design/rule-improvement/rule_improvement_proposal_conversion_contract.md`.
That contract consumes canonical
`rule_improvement_proposal_review_decisions.json` and may consider only
`accept_for_conversion` decisions.

Expected future conversion directions are:

| v2 proposal area | Future concrete artifact area |
|---|---|
| `rule` proposal | rule candidate artifact |
| `prompt` proposal | prompt candidate artifact |
| `parser` proposal | parser candidate artifact |
| `telemetry` proposal | telemetry candidate artifact |
| `correlation` proposal | correlation candidate artifact |
| `promotion_review` proposal | promotion review recommendation artifact |

Legacy comparison-harness artifacts remain separate:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`

Current v2 proposals are not directly equivalent to those legacy artifacts.
The legacy schemas are smaller and do not preserve the full v2 provenance
shape. Any future converter that emits legacy artifact names must be a
separate reviewed implementation with explicit schema validation, provenance
preservation rules, tests, and safety boundaries.

## 7. Safety Boundaries

Future proposal review and conversion must not:

- automatically apply changes
- automatically deploy changes
- automatically update baselines
- automatically update prompt templates
- automatically update parser code
- automatically update telemetry collection
- automatically update correlation logic
- automatically promote candidates or agents
- mutate active agents
- mutate case state
- mutate action state
- mutate pre-case investigation state
- mutate post-action DFIR investigation state
- mutate containment state
- mutate approval state
- mutate verdict, severity, or confidence
- treat generator diagnostics as proposals
- treat proposal review decisions as apply, deployment, baseline update, or
  promotion approvals

Generator diagnostics are non-proposal metadata. They may explain skipped
unsupported future schema-valid candidate types, but they do not create,
approve, convert, apply, deploy, update, or promote anything.

## 8. Failure and Unresolved Cases

Future proposal review and conversion tooling must fail closed on:

- invalid `rule_improvement_candidate_proposals_v2.json` schema
- missing proposal provenance
- missing `source_candidate_creation_input_sha256`
- malformed or missing `human_decision_provenance`
- unsupported `candidate_type`
- mismatched `candidate_type` / `allowed_next_artifact_type`
- missing human proposal review decision
- proposal review decision that is not `accept_for_conversion`
- unsafe conversion semantics
- attempts to treat diagnostics as proposal items
- attempts to treat conversion as apply, deployment, baseline update, or
  promotion

Unsupported, ambiguous, split-required, deferred, or evidence-insufficient
items must remain unconverted unless a later reviewed contract defines a safe
next step.

## 9. Implementation Status

Implemented:

- v2 proposal JSON Schema
- standalone deterministic v2 proposal generator
- generator diagnostics for skipped unsupported future schema-valid candidate
  types
- runbook usage documentation for v2 proposal generation and diagnostics
- v1 proposal human review decisions JSON Schema
- deterministic proposal review decisions template exporter
- deterministic proposal review decisions importer / validator
- focused schema tests for conversion-review-only semantics, provenance,
  unsafe-field rejection, and candidate type mapping
- focused exporter tests for exact source hashing, safe default decisions,
  provenance preservation, and fail-closed behavior
- focused importer tests for completed rationale validation, canonical output,
  provenance preservation, and fail-closed behavior

Not implemented:

- proposal review worksheet
- converter from v2 proposals to concrete candidate artifacts
- pipeline wiring
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
Proposal v2 artifacts may later be reviewed for conversion, but review and conversion are separate future boundaries and still do not authorize apply, deployment, baseline update, or promotion.
```
