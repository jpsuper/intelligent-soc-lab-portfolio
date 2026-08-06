# Rule Improvement Proposal Conversion Contract

## 1. Purpose

This document defines conversion from canonical
`rule_improvement_proposal_review_decisions.json` into the
provenance-preserving concrete candidate bundle.

The standalone converter is implemented at
`scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py`.
It consumes canonical review decisions produced by
`scripts/import_rule_improvement_proposal_review_decisions.py` together with
their source v2 proposal artifact. It may convert only decisions whose value is
`accept_for_conversion`.

The converter writes candidate artifacts only. It must not apply or deploy
changes, update baselines, prompts, parser code, telemetry, or correlation
logic, promote candidates or agents, or mutate operational state.

The concrete artifact shape and downstream narrowing boundaries are defined by:

- `docs/design/rule-improvement/rule_improvement_concrete_candidate_artifact_strategy.md`
- `schemas/rule_improvement_concrete_candidate_bundle_v1.schema.json`
- `docs/design/rule-improvement/rule_improvement_legacy_compatible_export_contract.md`
- `docs/design/rule-improvement/rule_improvement_parser_legacy_export_contract.md`
- `docs/design/rule-improvement/rule_improvement_promotion_recommendation_export_contract.md`

---

## 2. Flow Position

The implemented standalone conversion and narrowing path is:

```text
rule_improvement_candidate_proposals_v2.json
  -> rule_improvement_proposal_review_decisions_template.json
  -> human-completed proposal review decisions
  -> rule_improvement_proposal_review_decisions.json
  -> scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py
  -> rule_improvement_concrete_candidate_bundle_v1.json
  -> optional schema-validated narrowing exporters
  -> rule_candidates.yaml / prompt_candidates.yaml / parser_candidates.yaml
  -> promotion_recommendation.yaml
```

The converter and exporters remain standalone and non-applying. State-changing
apply, deployment, baseline-update, runtime-mutation, and promotion workflows
are separate and outside this contract.

---

## 3. Conversion Eligibility

A proposal review decision is eligible for conversion only when:

- the review artifact has `artifact_semantics: conversion_review_only`
- review decisions and source proposals are schema-valid
- the decision is `accept_for_conversion`
- the rationale is complete and not a template placeholder
- required source and human decision provenance is present
- `candidate_type` and `allowed_next_artifact_type` form a valid pair

Every other decision remains unconverted and is recorded in
`skipped_decisions`:

- `reject`
- `defer`
- `split_required`
- `needs_more_evidence`

`accept_for_conversion` authorizes only conversion into the non-applying
bundle. It is not apply, deployment, baseline-update, runtime-mutation, or
promotion approval.

---

## 4. Candidate Type Mapping

The converter enforces this mapping:

| `candidate_type` | `allowed_next_artifact_type` | Bundle candidate area |
|---|---|---|
| `rule` | `rule_candidate_proposal` | rule candidate |
| `prompt` | `prompt_candidate_proposal` | prompt candidate |
| `parser` | `parser_candidate_proposal` | parser candidate |
| `telemetry` | `telemetry_candidate_proposal` | telemetry candidate |
| `correlation` | `correlation_candidate_proposal` | correlation candidate |
| `promotion_review` | `promotion_review_recommendation` | recommendation-only promotion review |

Known mismatches fail closed.

---

## 5. Legacy Artifact Relationship

The concrete candidate bundle is the provenance-preserving conversion output;
it is not a legacy candidate artifact. Dedicated exporters narrow eligible
bundle items into smaller schema-valid outputs:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `parser_candidates.yaml`
- `promotion_recommendation.yaml`

The narrower schemas do not preserve every v2 field. Exporters therefore
validate source and output schemas, preserve bundle, candidate, proposal, and
review backreferences wherever the target schema permits, and emit diagnostics
for unsupported or skipped items.

Telemetry and correlation narrowing exports remain separate contract work.
None of the legacy-compatible outputs is apply, deployment, baseline-update,
runtime-mutation, or promotion authority.

---

## 6. Required Provenance Preservation

Converter output preserves or links back to:

- source proposal review decisions ref and SHA-256
- source proposals ref and SHA-256
- source candidate-creation input ref and SHA-256
- `proposal_ref`
- `candidate_id`
- `candidate_type`
- `allowed_next_artifact_type`
- source human decision provenance
- conversion decision rationale
- limitations and required follow-up evidence refs
- schema-compatible proposal `payload` fields used by narrowing exporters

The converter must not fabricate proposal, review, or human decision identity.
Optional proposal payload cannot override converter-owned metadata such as
`target`, `source_signal_ref`, `source_label`, `source_fact_ids`,
`required_evidence_refs`, `priority`, or `review_status`.

---

## 7. Safety Boundaries

The converter must not:

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

Concrete candidate artifacts remain review artifacts unless a separate apply,
deployment, baseline update, or promotion workflow separately validates and
authorizes state changes.

## 8. Failure Behavior

The converter fails closed on:

- invalid proposal or review-decision schemas
- missing source hashes or provenance
- unsupported candidate types
- mismatched `candidate_type` / `allowed_next_artifact_type`
- non-accept decisions entering the conversion path
- placeholder rationale
- unsafe approval, apply, deployment, mutation, or promotion-like fields
- attempts to overwrite source artifacts
- unsafe output paths

Output is written only after source consistency, schema validation, and safety
checks succeed.

---

## 9. Status And Evidence Ownership

This document owns conversion eligibility, candidate-type mapping, bundle
provenance, payload merge constraints, skipped-decision handling, and
fail-closed conversion behavior. The schema, converter, narrowing contracts,
and focused tests named here are evidence for those boundaries.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, validation depth, priorities, and sequencing.
Availability of a narrowing exporter must not change conversion-review-only or
non-applying semantics.

---

## 10. Boundary Acceptance Criteria

The conversion boundary remains valid when:

- only canonical `accept_for_conversion` decisions become converted candidates
- all other decisions remain explicit skipped decisions
- source refs, hashes, and human decision provenance remain traceable
- candidate-type mapping and payload ownership fail closed on mismatch
- output is validated before it is written
- conversion and narrowing cannot authorize state changes

---

## 11. One-Line Summary

```text
Canonical proposal review decisions may feed the standalone bundle converter, but conversion and narrowing never authorize apply, deployment, mutation, or promotion.
```
