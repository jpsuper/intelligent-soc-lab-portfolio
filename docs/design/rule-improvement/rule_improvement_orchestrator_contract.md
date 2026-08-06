# Rule Improvement Orchestrator Contract

## 1. Purpose

This document defines the stable responsibility and artifact boundaries for
orchestrating Rule Improvement work.

The orchestrator coordinates validated stages and artifacts. The Rule
Improvement Agent produces reviewable analysis and candidate proposals. Neither
component applies, deploys, enables, promotes, or otherwise mutates active
detection, prompt, parser, telemetry, correlation, policy, or runtime state.

The shared compare and judge behavior for Triage, Investigation, and Action is
defined in the
[Comparison Harness Contract](comparison_harness_contract.md).

---

## 2. Contract And Status Ownership

This document owns:

- orchestrator and Rule Improvement Agent responsibilities;
- artifact authority and handoff boundaries;
- validation, provenance, failure, and skip behavior;
- the separation between AI assistance, human decisions, candidate creation,
  export, and state mutation; and
- extension conditions for new Rule Improvement stages.

The [Main Roadmap](../../roadmap/roadmap.md) and
[Phase 6](../../roadmap/phase6.md) own current implementation status, active
priority, sequencing, validation depth, and Done Criteria. Detailed artifact
shape and stage semantics belong in the dedicated contracts listed in
[Section 13](#13-related-contracts). Operational commands belong in the
[AI-Assisted Rule Improvement Review Handoff Runbook](../../runbooks/ai_assisted_rule_improvement_review_handoff.md).

The previous combined orchestrator and harness planning document is retained as
[historical context](../archive/rule-improvement-orchestrator-and-harness-plan.md).
It is non-canonical.

---

## 3. Core Invariants

### 3.1 Artifact-First Coordination

Each stage consumes explicit, validated artifacts and produces explicit,
reviewable artifacts. Hidden conversational state, model memory, Markdown
prose, or an operator's implicit intent must not become pipeline authority.

### 3.2 Deterministic Control

Stage selection, input resolution, schema validation, output placement, failure
handling, and metadata recording must be deterministic. Model-generated content
remains untrusted until it crosses its dedicated importer and review boundary.

### 3.3 Human Decisions Are Explicit

Human classification, candidate-review, and proposal-conversion decisions must
be represented by their schema-defined decision artifacts. The orchestrator
must not infer acceptance, approval, or promotion from edited worksheets,
review comments, filenames, or an AI suggestion.

### 3.4 Candidate Does Not Mean Applied

A candidate, accepted conversion decision, concrete bundle, export artifact,
validation pass, or promotion recommendation is not authorization to modify
active state.

### 3.5 Fail Closed

Invalid required input, unsupported schema version, missing provenance,
contradictory review state, unsafe field, or invalid output must stop the
affected stage before the primary artifact is written. Optional absence may
produce an explicit skip only when the consumer contract permits it.

---

## 4. Orchestrator Responsibility

### 4.1 The Orchestrator Must

- load an explicit workflow or stage configuration;
- resolve run-local input and output paths;
- validate required inputs before invoking a stage;
- invoke only registered deterministic components or explicitly enabled
  manual/model boundaries;
- keep current, challenger, and baseline artifacts isolated;
- validate stage outputs before downstream handoff;
- preserve run, source, schema, tool, prompt, model, and reviewer provenance as
  required by the relevant artifact contract;
- record completed, skipped, and failed stages explicitly;
- prevent partial or invalid output from becoming downstream authority; and
- keep generated artifacts inside the intended run boundary.

### 4.2 The Orchestrator Must Not

- decide whether a security finding is true;
- invent missing evidence, labels, reviewer intent, or candidate payloads;
- copy AI suggestions into human decision fields;
- treat a comparison score as promotion approval;
- apply a rule, prompt, parser, policy, telemetry, or correlation change;
- deploy or enable a candidate;
- update an active baseline;
- execute a response action; or
- bypass approval and regression gates.

One-line definition:

```text
orchestrator = deterministic stage coordination + validation + provenance
```

---

## 5. Rule Improvement Agent Responsibility

### 5.1 The Agent May

- consume schema-valid comparison, judge, evaluation, observed-effects, DFIR,
  or human-classification inputs admitted by a dedicated contract;
- identify evidence-backed gaps, regressions, or review questions;
- create review-only candidate drafts or proposals;
- preserve source facts, evidence references, limitations, and human decisions;
- produce deterministic diagnostics; and
- prepare candidate artifacts for a separate human review or export boundary.

### 5.2 The Agent Must Not

- treat attacker-side observations as defender detections;
- treat missing evidence as proof of absence;
- fabricate telemetry, correlations, facts, or reviewer decisions;
- modify canonical Incident, Triage, Investigation, Case, Action, or evaluation
  verdicts;
- enable, apply, deploy, or promote a candidate;
- authorize a production or lab configuration change; or
- convert a recommendation into state mutation.

One-line definition:

```text
Rule Improvement Agent = evidence-bounded proposal generation for human review
```

---

## 6. Artifact Authority Chain

Rule Improvement uses multiple review and conversion boundaries. The exact
artifact set varies by source, but authority must progress explicitly:

```text
validated evaluation or review signals
  -> deterministic review input
  -> optional untrusted AI-assisted draft
  -> explicit human signal classification
  -> candidate-generation input and candidate draft
  -> explicit human candidate-review decisions
  -> candidate-creation input and proposal
  -> explicit proposal-conversion decisions
  -> non-applying concrete candidate bundle
  -> candidate-only or recommendation-only exports
  -> non-mutating export validation summary
  -> future apply / deployment / promotion workflow (not defined here)
```

Not every workflow must use every optional aid. It must, however, preserve all
required authority transitions for the artifacts it consumes.

### 6.1 Authoritative Inputs

Depending on the stage, authority may come from:

- schema-valid deterministic evaluation or review-input artifacts;
- schema-valid human classification decisions;
- schema-valid human candidate-review decisions;
- schema-valid proposal review or conversion decisions; and
- separately reviewed workflow configuration.

### 6.2 Non-Authoritative Aids

The following are context or review aids unless another contract explicitly
states otherwise:

- AI-generated model output before import;
- imported AI review drafts;
- descriptive AI-draft comparisons;
- Markdown worksheets and reports;
- Japanese review packets or rewrites;
- judge scores by themselves;
- candidate hints;
- diagnostics; and
- promotion recommendations.

These artifacts must not authorize candidate creation, apply, deployment,
baseline update, prompt update, parser update, or promotion.

---

## 7. AI-Assisted Boundary

AI assistance is optional and default-off unless an explicit workflow enables
it. A model runner may produce only the untrusted output permitted by its
prompt bundle and runner contract.

An importer must:

- validate the candidate output against the canonical schema;
- verify prompt-bundle and source-input provenance;
- preserve locked safety fields;
- reject unknown, missing, contradictory, or unsafe content;
- avoid reading evidence outside the allowed bundle; and
- write the canonical draft only after all checks pass.

An imported AI draft remains a suggestion artifact. A human reviewer must make
independent decisions from the canonical review input and retained evidence.

See the
[AI-Assisted Review Draft Contract](ai_assisted_review_draft_contract.md) and
[AI Review Draft Prompt/Input Contract](ai_review_draft_prompt_input_contract.md).

---

## 8. Human Review Boundaries

### 8.1 Signal Classification

A reviewer classifies each review signal with explicit identity, timestamp,
rationale, source references, and evidence limits. Classification may determine
whether later candidate intake is eligible; it does not create or approve a
candidate.

See the
[Signal Classification Contract](rule_improvement_signal_classification_contract.md).

### 8.2 Candidate Review

Candidate-review decisions must be explicit, schema-valid, and tied to the
candidate draft and source review provenance. An accepted candidate-review item
may enter candidate-creation input. It does not authorize apply or deployment.

See the
[Candidate Draft Contract](rule_improvement_candidate_draft_contract.md) and
[Candidate Creation Workflow](rule_improvement_candidate_creation_workflow.md).

### 8.3 Proposal Conversion Review

Proposal conversion must use explicit review decisions. Acceptance means that a
proposal may be converted into a non-applying concrete candidate representation.
It does not mean that the candidate is safe to apply, deploy, enable, or promote.

See the
[Proposal Review Conversion Contract](rule_improvement_candidate_proposal_review_conversion_contract.md) and
[Proposal Conversion Contract](rule_improvement_proposal_conversion_contract.md).

---

## 9. Candidate And Export Boundaries

### 9.1 Proposal And Concrete Bundle

Candidate proposals and concrete bundles must preserve source review, human
decision, proposal, and conversion provenance. They must reject fields that
imply apply, deployment, update, enablement, or promotion authority.

See the
[Proposal v2 Contract](rule_improvement_candidate_proposal_v2_contract.md) and
[Concrete Candidate Artifact Strategy](rule_improvement_concrete_candidate_artifact_strategy.md).

### 9.2 Candidate-Only Exports

Legacy-compatible rule, prompt, and parser exports are narrowing steps from
reviewed concrete candidates. They remain disabled or review-required candidate
artifacts and must not update active implementations.

See the
[Legacy-Compatible Export Contract](rule_improvement_legacy_compatible_export_contract.md) and
[Parser Candidate Export Contract](rule_improvement_parser_legacy_export_contract.md).

### 9.3 Promotion Recommendation

`promotion_recommendation.yaml` is recommendation-only. It may identify a
reviewed candidate as worth further consideration, but it does not approve
promotion, select an active champion, update a baseline, or deploy a variant.

See the
[Promotion Recommendation Export Contract](rule_improvement_promotion_recommendation_export_contract.md).

### 9.4 Export Validation Summary

An export validation summary reports schema, safety, and consistency results
for artifacts that already exist. It must not invoke exporters, repair
candidates, approve them, or mutate state.

See the
[Export Artifact Validation Summary Contract](rule_improvement_export_artifact_validation_summary_contract.md).

---

## 10. Provenance And Run Isolation

Every generated artifact must preserve the provenance required to reconstruct
why it exists and which authority transition produced it. Depending on the
artifact, this includes:

- `run_id` and source run references;
- source artifact paths and hashes;
- schema and tool versions;
- prompt and model identity where AI assistance was used;
- reviewer identity and review timestamp;
- classification, candidate-review, and conversion decision references;
- proposal and concrete-bundle identifiers;
- export diagnostics; and
- validation outcomes and limitations.

Run artifacts must be append-only or written to unique validated paths. A stage
must not overwrite source evidence, human decisions, active rules, prompt
templates, parser code, deployment configuration, or promotion state.

---

## 11. Failure And Skip Semantics

A stage must fail before writing its primary output when:

- a required source artifact is missing or invalid;
- schema or version compatibility is unsupported;
- provenance cannot be verified;
- a referenced signal, candidate, proposal, or decision cannot be resolved;
- review is incomplete or contradictory;
- unsafe authority-like fields are present;
- an output path violates run isolation; or
- generated output fails schema or invariant validation.

Optional stages may be skipped only when:

- the workflow marks them optional;
- downstream consumers allow their absence;
- the skip reason is recorded; and
- no success, review, or promotion state is inferred from the absence.

Diagnostics may be written only when their contract permits safe failure
reporting. Diagnostics are never substitutes for a valid primary artifact.

---

## 12. Non-Goals

This contract does not define or authorize:

- automatic rule, prompt, parser, policy, telemetry, or correlation changes;
- automatic candidate apply or deployment;
- automatic baseline or champion replacement;
- automatic promotion;
- state-changing response execution;
- bypass of approval or regression testing;
- AI-authored human decisions;
- evidence fabrication or automatic gap repair;
- production deployment management; or
- a planner that can add unregistered stages or tools.

Any future apply, deployment, update, or promotion workflow requires a separate
contract, explicit reviewer intent, before-and-after artifacts, rollback
semantics, regression gates, and audit logging.

---

## 13. Related Contracts

| Boundary | Contract |
|---|---|
| Triage, Investigation, and Action comparison | [Comparison Harness Contract](comparison_harness_contract.md) |
| Observed-effects review signal | [Observed Effects Alignment Signal](observed_effects_alignment_signal_contract.md) |
| Post-action DFIR review input | [Post-Action DFIR Review Input](post_action_dfir_review_input_contract.md) |
| AI-assisted draft | [AI-Assisted Review Draft](ai_assisted_review_draft_contract.md) |
| AI prompt/input | [AI Review Draft Prompt/Input](ai_review_draft_prompt_input_contract.md) |
| Human signal classification | [Signal Classification](rule_improvement_signal_classification_contract.md) |
| Candidate draft | [Candidate Draft](rule_improvement_candidate_draft_contract.md) |
| Candidate creation | [Candidate Creation Workflow](rule_improvement_candidate_creation_workflow.md) |
| Proposal v2 | [Candidate Proposal v2](rule_improvement_candidate_proposal_v2_contract.md) |
| Proposal review | [Conversion contract](rule_improvement_candidate_proposal_review_conversion_contract.md) |
| Concrete candidate bundle | [Concrete Candidate Strategy](rule_improvement_concrete_candidate_artifact_strategy.md) |
| Rule and prompt export | [Legacy-Compatible Export](rule_improvement_legacy_compatible_export_contract.md) |
| Parser export | [Parser Candidate Export](rule_improvement_parser_legacy_export_contract.md) |
| Promotion export | [Recommendation export](rule_improvement_promotion_recommendation_export_contract.md) |
| Export validation | [Export Validation Summary](rule_improvement_export_artifact_validation_summary_contract.md) |

---

## 14. Contract Acceptance Criteria

The orchestrator contract remains valid when:

- every stage has explicit validated inputs and outputs;
- control flow and artifact placement are deterministic;
- AI output remains untrusted until import and human review;
- human authority is represented only by explicit decision artifacts;
- candidate and conversion acceptance remain separate from apply approval;
- all proposals, bundles, exports, and recommendations remain non-applying;
- provenance remains traceable across every authority transition;
- invalid required input fails closed before primary output is written;
- optional absence is recorded without being treated as success;
- run artifacts cannot overwrite active or source state; and
- state mutation remains outside this contract.

---

## 15. Extension Conditions

Add a new Rule Improvement stage, signal source, candidate type, exporter, or
consumer only when a concrete need identifies:

1. the source-of-authority artifact;
2. the schema and provenance requirements;
3. deterministic validation and failure behavior;
4. the required human decision boundary;
5. safe run-local output placement;
6. focused valid, invalid, and unsafe fixtures or tests;
7. compatibility and migration behavior;
8. diagnostics that cannot become authority; and
9. explicit confirmation that apply, deployment, update, and promotion remain
   outside the change unless separately approved.

Status and priority updates belong in the Main Roadmap or Phase 6 rather than
this contract.

---

## 16. One-Line Summary

```text
The Rule Improvement orchestrator coordinates validated, reviewable artifacts;
it never converts analysis, AI output, human review aids, candidates, or
recommendations into active-state mutation.
```
