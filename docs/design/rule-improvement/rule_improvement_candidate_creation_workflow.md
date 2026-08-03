# Rule Improvement Candidate Creation Workflow Contract

## 1. Purpose

This document defines the Rule Improvement candidate creation workflow boundary
after `rule_improvement_candidate_creation_input.json`.

It documents the current standalone v2 proposal-generation boundary and the
later implementation boundaries. It does not wire a pipeline step, generate
legacy candidate artifacts, apply changes, approve deployment, or promote
anything.

A Japanese overview of the broader Rule Improvement artifact chain is available
at `docs/design/rule-improvement/rule_improvement_overview_ja.md`.

The current AI-assisted post-action Rule Improvement flow can now produce
proposal-only v2 artifacts from:

```text
rule_improvement_candidate_creation_input.json
```

That artifact and any generated v2 proposal artifact are not candidate
approval, deployment approval, promotion approval, or an instruction to edit
rules, prompts, parsers, telemetry, or correlation logic.

## 2. Workflow position

The current implemented proposal-only path is:

```text
rule_improvement_candidate_creation_input.json
  ↓ scripts/generate_rule_improvement_candidate_proposals_v2.py
rule_improvement_candidate_proposals_v2.json   (proposal-only)
  ↓ future human review / conversion
concrete candidate artifacts or apply workflows (not implemented)
```

The implemented generator is standalone and deterministic. It is not wired into
`run_process_pipeline.py`, and there is still no automatic apply, deployment,
baseline update, or promotion path.

The future human review and conversion boundary after
`rule_improvement_candidate_proposals_v2.json` is documented in
`docs/design/rule-improvement/rule_improvement_candidate_proposal_review_conversion_contract.md`.
The future conversion boundary from canonical proposal review decisions into
concrete candidate artifacts is documented in
`docs/design/rule-improvement/rule_improvement_proposal_conversion_contract.md`.

## 3. Source of authority

The standalone v2 proposal generator and any future candidate artifact
generator must consume only a schema-valid
`rule_improvement_candidate_creation_input.json`.

It must not use any of these as source of authority:

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

The standalone v2 proposal generator is deterministic and local. Any future
concrete candidate artifact generator must preserve the same boundary.

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

## 5. Existing legacy artifact evaluation

The repository already contains comparison-harness candidate artifact names and
schemas:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`

It also contains supporting legacy tooling such as
`tools/generate_rule_candidates.py` and
`scripts/review_improvement_candidates.py`.

`tools/generate_rule_candidates.py` is specifically a legacy
triage-diff-based helper: it reads `triage_diff.json` and `incident.json`, then
emits disabled, review-required proposals from `diff.extra_ai_only` and
`incident.behavior_features`. It is intentionally not the future bridge from
`rule_improvement_candidate_creation_input.json` to concrete candidate
artifacts unless a later reviewed implementation explicitly adapts or replaces
it. A future bridge should likely be separate if it needs stricter provenance
from human candidate-review decisions.

These existing artifact names and schemas may be reused by a future
candidate-creation workflow only if the workflow preserves the safety boundary
below.

| Artifact | Current role | Future reuse condition |
|---|---|---|
| `rule_candidates.yaml` | Proposal artifact for deterministic rule / rule-triage improvement candidates. | Must remain a proposal only and must not apply or enable detection rules. |
| `prompt_candidates.yaml` | Proposal artifact for prompt variant improvement candidates. | Must remain a proposal only and must not edit prompt templates automatically. |
| `promotion_recommendation.yaml` | Recommendation artifact for reviewer consideration. | Must remain recommendation-only and must not become promotion approval or baseline update authority. |

Future reuse must preserve:

- non-applying semantics
- human-review-required semantics
- source provenance
- no auto-apply
- no auto-promotion
- no deployment approval
- no mutation of case/action/investigation/verdict/severity/confidence state

The existing candidate artifact schemas reject unknown fields at the root and
inside candidate or recommendation objects. That strictness is part of the
boundary: fields that imply apply, approval, deployment, or promotion must not
be smuggled into these artifacts.

## 6. Existing schema compatibility assessment

`schemas/rule_candidates_schema.json`,
`schemas/prompt_candidates_schema.json`, and
`schemas/promotion_recommendation_schema.json` are legacy comparison-harness
schemas. They are intentionally strict because they reject unknown fields at the
root and inside nested candidate or recommendation objects.

That strictness makes the legacy schemas suitable for lightweight proposal and
recommendation artifacts in the comparison-harness flow. It also means they are
not sufficient as-is for the newer AI-assisted Rule Improvement
candidate-creation flow: the legacy rule and prompt candidate shapes cannot
preserve the richer provenance carried by
`rule_improvement_candidate_creation_input.json`.

A future v2 proposal schema for AI-assisted candidate creation should preserve
fields such as:

- `source_candidate_creation_input_ref`
- `source_candidate_creation_input_sha256`
- `candidate_id`
- `candidate_type`
- `source_signal_ref`
- `source_label`
- `source_fact_ids`
- `required_evidence_refs`
- `allowed_next_artifact_type`
- `limitations`
- human candidate-review decision provenance
  (`human_decision_ref`, `human_decision_id`, and `human_decision_status`)

`schemas/promotion_recommendation_schema.json` also contains the legacy
`promote` boolean. Any future v2 promotion-review artifact must make clear that
it is recommendation-only and not approval, deployment, baseline update, or
promotion authority.

The future candidate-creation bridge should not emit the legacy schema shape
directly unless a later reviewed design explicitly adapts it. The recommended
direction is to keep the legacy schemas intact and use the v2 proposal schema
for AI-assisted Rule Improvement candidate creation.

The v2 proposal contract is documented in
`docs/design/rule-improvement/rule_improvement_candidate_proposal_v2_contract.md`
and implemented by
`schemas/rule_improvement_candidate_proposals_v2.schema.json`. The standalone
deterministic generator for converting
`rule_improvement_candidate_creation_input.json` into
`rule_improvement_candidate_proposals_v2.json` is implemented at
`scripts/generate_rule_improvement_candidate_proposals_v2.py` and documented in
`docs/design/rule-improvement/rule_improvement_candidate_proposal_generator_contract.md`.
The output remains proposal-only and does not add process-pipeline integration,
apply workflow, deployment workflow, baseline update, or promotion workflow.

## 7. Output semantics

Any future `rule_candidates.yaml` or `prompt_candidates.yaml` produced from
`rule_improvement_candidate_creation_input.json` must be a proposal artifact
only.

Candidate artifacts must not:

- apply rule changes
- update prompt templates
- enable detection rules
- modify parser code
- modify telemetry collection behavior
- modify correlation logic
- approve deployment
- update baselines
- mutate case, action, investigation, containment, approval, verdict, severity,
  confidence, or Rule Improvement promotion state

`promotion_recommendation.yaml` must remain recommendation-only. It may express
that promotion is worth reviewer consideration, but it must not itself approve
promotion, change the active baseline, deploy a prompt variant, or update any
Rule Improvement promotion state.

## 8. Future human review and apply boundary

Future candidate artifact review must be separate from candidate artifact
proposal generation.

At minimum, a future apply or promotion workflow must:

- require explicit human approval
- validate candidate artifacts against their schemas
- validate provenance back to `rule_improvement_candidate_creation_input.json`
- use the candidate-creation input's human decision provenance instead of
  fabricating decision identity from `candidate_id`
- run appropriate single-scenario and regression checks before promotion
- keep apply/deploy/promotion state changes in a separate workflow
- record reviewer intent and rationale

An accepted candidate-creation input item does not by itself authorize any of
those downstream actions.

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

## 10. Implementation status

Implemented today:

- `rule_improvement_candidate_creation_input.json` schema and exporter
- human candidate-review decision validation before candidate-creation input
- explicit human decision provenance in
  `rule_improvement_candidate_creation_input.json`
- existing comparison-harness schemas for `rule_candidates.yaml`,
  `prompt_candidates.yaml`, and `promotion_recommendation.yaml`
- schema tests that lock down non-smuggling behavior for existing candidate
  artifact schemas
- v2 proposal schema and contract for AI-assisted candidate proposal artifacts
- enforced `candidate_type` / `allowed_next_artifact_type` mapping in the v2
  proposal schema tests
- standalone deterministic proposal v2 generator:
  `scripts/generate_rule_improvement_candidate_proposals_v2.py`
- optional generator diagnostics for skipped unsupported future schema-valid
  candidate types
- runbook usage documentation for proposal v2 generation and diagnostics
- v1 proposal human review decisions schema for future conversion-review-only
  decisions
- deterministic proposal review decisions template exporter and importer /
  validator

Not implemented by this contract:

- generator from `rule_improvement_candidate_creation_input.json` to concrete
  candidate artifacts
- process-pipeline integration
- proposal review worksheet
- converter from canonical proposal review decisions to concrete candidate
  artifacts
- candidate apply workflow
- deployment workflow
- baseline update workflow
- prompt update workflow
- parser, telemetry, or correlation mutation workflow
- promotion workflow

## 11. One-line summary

```text
rule_improvement_candidate_creation_input.json may feed a standalone proposal-only v2 generator, but neither artifact is approval, deployment, baseline update, apply authority, or promotion.
```
