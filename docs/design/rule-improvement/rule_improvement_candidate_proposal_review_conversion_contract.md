# Rule Improvement Candidate Proposal Review and Conversion Contract

## 1. Purpose

This document defines the human proposal-review boundary after
`rule_improvement_candidate_proposals_v2.json` and its handoff to the
standalone concrete-bundle converter.

The proposal artifact is proposal-only. A human reviewer records explicit
conversion-review decisions before any proposal can enter the converter.
Review and conversion remain separate from proposal generation.

The review-decision shape is defined by
`schemas/rule_improvement_proposal_review_decisions_v1.schema.json`.
`scripts/export_rule_improvement_proposal_review_decisions_template.py`
creates an incomplete template with safe `defer` defaults, and
`scripts/import_rule_improvement_proposal_review_decisions.py` validates
human-completed decisions before writing canonical
`rule_improvement_proposal_review_decisions.json`.

These review tools do not convert proposals or authorize state changes. The
standalone conversion boundary is defined separately in
`docs/design/rule-improvement/rule_improvement_proposal_conversion_contract.md`.

---

## 2. Flow Position

The implemented standalone review and conversion path is:

```text
rule_improvement_candidate_creation_input.json
  -> rule_improvement_candidate_proposals_v2.json
  -> rule_improvement_proposal_review_decisions_template.json
  -> human-completed proposal review decisions
  -> rule_improvement_proposal_review_decisions.json
  -> rule_improvement_concrete_candidate_bundle_v1.json
  -> optional schema-validated narrowing exporters
```

Proposal review records conversion eligibility only. Conversion creates a
non-applying concrete bundle only. Apply, deployment, baseline update, runtime
mutation, and promotion require separate workflows.

---

## 3. Review Decision Schema

Canonical human proposal-review decisions validate against:

```text
schemas/rule_improvement_proposal_review_decisions_v1.schema.json
```

Root invariants are:

```json
{
  "version": 1,
  "artifact_type": "rule_improvement_proposal_review_decisions",
  "artifact_semantics": "conversion_review_only"
}
```

The artifact records human decisions over v2 proposals. It authorizes only
conversion eligibility and cannot authorize apply, deployment, baseline
update, prompt update, parser update, telemetry update, correlation update, or
promotion.

The template exporter writes incomplete human-review input: each decision
defaults to `defer`, uses a placeholder rationale, and omits reviewer
identity. The importer rejects placeholder rationale and writes canonical JSON
only after schema and invariant validation. Neither tool performs conversion.

---

## 4. Human Review Decision Semantics

The decision values have narrow meanings:

| Decision | Meaning |
|---|---|
| `accept_for_conversion` | The proposal may enter the standalone converter for a concrete candidate bundle item. |
| `reject` | The proposal is rejected for conversion. |
| `defer` | The decision is postponed without authorizing conversion. |
| `split_required` | The proposal must be split before conversion. |
| `needs_more_evidence` | More evidence or context is required before conversion. |

`accept_for_conversion` is not apply, deployment, baseline-update,
runtime-mutation, or promotion approval. The converter treats every other
decision as ineligible and records it as a skipped decision rather than a
converted candidate.

---

## 5. Required Review Decision Provenance

Each human proposal-review decision preserves enough provenance to trace the
decision to both the proposal and the accepted candidate-creation input:

- `candidate_id`
- `proposal_ref`
- `source_candidate_creation_input_ref`
- `source_candidate_creation_input_sha256`
- the proposal's `human_decision_provenance`
- reviewer identity or reviewer ref
- reviewer rationale
- limitations, unresolved evidence gaps, or required follow-up evidence

The review artifact must not fabricate human candidate-review identity. It
carries forward
`human_decision_provenance.decision_ref`,
`human_decision_provenance.decision_id`, and
`human_decision_provenance.decision_status` exactly.

---

## 6. Conversion Boundary

Conversion requires both a schema-valid proposal artifact and canonical human
review decisions. The standalone converter consumes only
`accept_for_conversion` decisions and writes
`rule_improvement_concrete_candidate_bundle_v1.json`.

| v2 proposal area | Concrete bundle candidate area |
|---|---|
| `rule` | rule candidate |
| `prompt` | prompt candidate |
| `parser` | parser candidate |
| `telemetry` | telemetry candidate |
| `correlation` | correlation candidate |
| `promotion_review` | promotion-review recommendation candidate |

Legacy-compatible rule, prompt, parser, and recommendation artifacts are
separate narrowed exports from the concrete bundle. Their smaller schemas do
not replace the v2 proposal or bundle as the provenance-preserving source.

---

## 7. Safety Boundaries

Proposal review and conversion must not:

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

Review import and conversion fail closed on:

- invalid proposal or review-decision schemas
- missing source refs, hashes, or human decision provenance
- unsupported candidate types or mismatched next-artifact types
- missing decisions or placeholder rationale
- unsafe conversion semantics
- attempts to treat diagnostics as proposals
- attempts to treat conversion review as state-change approval

Only `accept_for_conversion` decisions may become converted candidates.
Rejected, deferred, split-required, evidence-insufficient, unsupported, or
ambiguous items remain explicit skipped decisions.

---

## 9. Status And Evidence Ownership

This document owns human proposal-review semantics, decision provenance,
conversion eligibility, the review-to-converter handoff, and fail-closed
handling of unresolved items. The schemas, template exporter, importer,
converter contract, and focused tests named here are evidence for those
boundaries.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, validation depth, priorities, and sequencing.
Converter and exporter availability must not broaden
`accept_for_conversion` beyond conversion-review-only semantics.

---

## 10. Boundary Acceptance Criteria

The review and conversion boundary remains valid when:

- templates default safely and require explicit human completion
- canonical decisions preserve source and human-review provenance
- only `accept_for_conversion` enters the converter
- every other decision remains explicit and unconverted
- review decisions cannot authorize apply, deployment, mutation, or promotion
- invalid or unsafe input fails closed before output is written

---

## 11. One-Line Summary

```text
Human proposal review may authorize conversion into a non-applying concrete bundle; it never authorizes apply, deployment, mutation, or promotion.
```
