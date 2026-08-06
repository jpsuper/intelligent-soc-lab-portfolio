# Rule Improvement Candidate Creation Workflow Contract

## 1. Purpose

This document defines the Rule Improvement candidate creation workflow boundary
after `rule_improvement_candidate_creation_input.json`.

It documents the standalone path through proposal generation, human proposal
review, concrete bundle conversion, narrow candidate export, and export
validation. It does not itself wire candidate generation or export into the
process pipeline, apply changes, approve deployment, or promote anything.

A Japanese overview of the broader Rule Improvement artifact chain is available
at `docs/design/rule-improvement/rule_improvement_overview_ja.md`.

The AI-assisted post-action Rule Improvement flow begins its candidate-creation
boundary from:

```text
rule_improvement_candidate_creation_input.json
```

That artifact and any generated v2 proposal artifact are not candidate
approval, deployment approval, promotion approval, or an instruction to edit
rules, prompts, parsers, telemetry, or correlation logic.

## 2. Workflow position

The implemented standalone path is:

```text
rule_improvement_candidate_creation_input.json
  ↓ scripts/generate_rule_improvement_candidate_proposals_v2.py
rule_improvement_candidate_proposals_v2.json
  ↓ proposal review template export and human completion
rule_improvement_proposal_review_decisions.json
  ↓ scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py
rule_improvement_concrete_candidate_bundle_v1.json
  ↓ narrow schema-validated exporters
rule_candidates.yaml / prompt_candidates.yaml / parser_candidates.yaml
promotion_recommendation.yaml
  ↓ optional validation summary reporter
rule_improvement_export_artifact_validation_summary.json
```

Every artifact in this path remains review-oriented and non-applying. The
generation, conversion, and export tools are standalone; candidate-generation
pipeline wiring and apply, deployment, baseline-update, runtime-mutation, and
promotion workflows are outside this contract.

The proposal review boundary is documented in
`docs/design/rule-improvement/rule_improvement_candidate_proposal_review_conversion_contract.md`.
The conversion boundary is documented in
`docs/design/rule-improvement/rule_improvement_proposal_conversion_contract.md`.
Narrow export contracts define the rule, prompt, parser, promotion-review, and
validation-summary boundaries.

---

## 3. Source of authority

The generators, converters, and exporters in this chain must derive authority
only from schema-valid canonical artifacts beginning with
`rule_improvement_candidate_creation_input.json`.

They must not use any of these as sources of authority:

- `rule_improvement_ai_review_draft.json`
- `ai_review_draft_comparison.json`
- `human_review_worksheet.md`
- `human_review_packet_ja.md`
- `rule_improvement_candidate_review_worksheet.md`
- `rule_improvement_candidate_review_worksheet_ja_rewritten.md`
- Japanese rewrites
- worksheets
- AI drafts
- comparison output
- untranslated or translated prose notes
- raw post-action evidence without the reviewed candidate-creation path

Those artifacts may help a human reviewer understand context earlier in the
flow, but they must not authorize candidate creation, approval, deployment, or
promotion.

## 4. Generator requirements

The standalone generator, converter, and exporters are deterministic and local.
Each downstream step must preserve the same boundary.

Generators in this flow must:

- validate `rule_improvement_candidate_creation_input.json` before producing
  output
- preserve candidate IDs, candidate refs, source signal refs, source labels,
  source fact IDs, evidence refs, requested changes, and limitations
- preserve item-level human candidate-review decision provenance, including
  `human_decision_ref`, `human_decision_id`, and `human_decision_status`
- preserve the distinction between detection-rule, prompt, parser, telemetry,
  and correlation proposal areas
- fail closed on invalid input, known `candidate_type` /
  `allowed_next_artifact_type` mismatches, inconsistent refs, or missing
  provenance
- skip only unsupported future schema-valid candidate types when the v2
  generator contract allows it
- optionally write diagnostics for skipped unsupported future schema-valid
  candidate types as non-proposal metadata
- write only proposal artifacts
- avoid network, model, or external service execution unless a later contract
  explicitly introduces a separate, gated mode

They must not:

- infer eligibility from AI output
- infer approval from completed review text
- infer promotion from candidate acceptance
- read raw evidence refs to strengthen or rewrite the decision
- mutate any source artifact

## 5. Legacy artifact relationship

The repository contains comparison-harness candidate artifact names and
schemas:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`

It also contains older tooling such as `tools/generate_rule_candidates.py`
and `scripts/review_improvement_candidates.py`.
`tools/generate_rule_candidates.py` remains a distinct triage-diff helper; it
is not the canonical bridge from
`rule_improvement_candidate_creation_input.json`.

The implemented AI-assisted path preserves rich provenance in the v2 proposal
and concrete bundle, then uses dedicated schema-validated exporters to narrow
eligible items into legacy-compatible artifacts.

| Artifact | Current role | Required boundary |
|---|---|---|
| `rule_candidates.yaml` | Review-required rule candidate artifact. | Must not apply or enable detection rules. |
| `prompt_candidates.yaml` | Review-required prompt candidate artifact. | Must not edit prompt templates automatically. |
| `parser_candidates.yaml` | Optional review-required parser candidate artifact. | Must not update parser code automatically. |
| `promotion_recommendation.yaml` | Recommendation artifact for reviewer consideration. | Must not become promotion approval or baseline-update authority. |

Reuse of these artifacts must preserve:

- non-applying and human-review-required semantics
- source provenance and schema validation
- no automatic deployment, baseline update, runtime mutation, or promotion
- no mutation of case, action, investigation, verdict, severity, or confidence
  state

Strict schemas are part of the boundary. Fields that imply apply, approval,
deployment, mutation, or promotion must not be smuggled into candidate or
recommendation artifacts.

---

## 6. Schema compatibility and narrowing strategy

The v2 proposal and concrete bundle schemas preserve richer provenance than the
legacy comparison-harness schemas. The canonical chain therefore does not emit
legacy shapes directly from candidate-creation input.

The chain uses:

- `schemas/rule_improvement_candidate_proposals_v2.schema.json` for
  proposal-only items
- `schemas/rule_improvement_proposal_review_decisions_v1.schema.json` for
  conversion-review-only human decisions
- `schemas/rule_improvement_concrete_candidate_bundle_v1.schema.json` for
  provenance-preserving converted candidates and skipped decisions
- dedicated legacy-compatible exporters for rule, prompt, parser, and
  promotion-review outputs
- `schemas/rule_improvement_export_artifact_validation_summary.schema.json`
  for non-mutating export validation results

The narrowing exporters must validate their input and output schemas, preserve
backreferences wherever the target schema permits, and write only after all
checks pass. The smaller legacy shapes must never become authority for apply,
deployment, baseline update, runtime mutation, or promotion.

Detailed generator behavior is documented in
`docs/design/rule-improvement/rule_improvement_candidate_proposal_generator_contract.md`.
Conversion and export behavior remains owned by their dedicated contracts.

---

## 7. Output semantics

Generated `rule_candidates.yaml`, `prompt_candidates.yaml`, and
`parser_candidates.yaml` are candidate artifacts only. They must not:

- apply rule changes
- update prompt templates
- enable detection rules
- modify parser code
- modify telemetry collection behavior
- modify correlation logic
- approve deployment or update baselines
- mutate case, action, investigation, containment, approval, verdict, severity,
  confidence, or Rule Improvement promotion state

`promotion_recommendation.yaml` remains recommendation-only. It may express
that promotion is worth reviewer consideration, but it must not approve
promotion, change the active baseline, deploy a prompt variant, or update Rule
Improvement promotion state.

`rule_improvement_export_artifact_validation_summary.json` reports validation
results only. It does not invoke exporters, rewrite candidates, or authorize
state changes.

---

## 8. Human review and state-changing workflow boundary

Human proposal review is separate from proposal generation, and conversion is
separate from review. `accept_for_conversion` authorizes only conversion into
a non-applying concrete candidate bundle.

Any apply, deployment, baseline-update, runtime-mutation, or promotion workflow
must remain separately reviewed and must:

- require explicit human approval
- validate candidate artifacts and end-to-end provenance
- run appropriate single-scenario and regression checks
- keep state changes outside proposal, conversion, export, and validation tools
- record reviewer intent and rationale

An accepted candidate-creation item, accepted proposal review decision,
candidate artifact, recommendation, or passing validation summary does not
authorize any downstream state change.

---

## 9. Prohibited automation

This contract explicitly prohibits:

- treating proposal v2 artifacts as approval, apply, deployment, baseline
  update, or promotion authority
- process-pipeline integration for candidate artifact creation
- automatic apply
- automatic promotion
- baseline update
- prompt template update
- detection rule enablement
- parser mutation
- telemetry mutation
- correlation mutation
- mutation of `case.json`
- mutation of `action_result.json`
- mutation of pre-case `investigation_result.json`
- mutation of `post_action_dfir_investigation_result.json`
- mutation of verdict, severity, confidence, containment, approval, or Rule
  Improvement promotion state

## 10. Status And Evidence Ownership

This document owns the artifact-chain boundary from reviewed
candidate-creation input through proposal, human conversion review, concrete
bundle, narrow export, and export validation. Dedicated contracts own the
schema and tool behavior of each step.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, validation depth, priorities, and sequencing.
This workflow remains non-applying, non-deploying, non-mutating, and
non-promoting.

---

## 11. Boundary Acceptance Criteria

The candidate-creation boundary remains valid when:

- every transition consumes schema-valid canonical input
- human review provenance and source hashes remain traceable
- proposal, conversion, export, recommendation, and validation semantics remain
  distinct
- unsupported or unsafe items fail closed or remain explicit diagnostics
- candidate and recommendation artifacts cannot authorize state changes
- apply, deployment, mutation, and promotion require separate workflows

---

## 12. One-line summary

```text
Reviewed candidate-creation input may progress through proposal, human conversion review, concrete bundle, and narrow exports, but none of those artifacts authorizes apply, deployment, mutation, or promotion.
```
