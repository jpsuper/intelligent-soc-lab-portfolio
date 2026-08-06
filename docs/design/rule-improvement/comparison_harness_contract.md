# Comparison Harness Contract

## 1. Purpose

This document defines the shared comparison and judge contract for Triage,
Investigation, and Action variants.

A comparison harness executes bounded stage variants against the same validated
inputs, preserves each output independently, compares explicit dimensions, and
applies a deterministic rubric. It produces reviewable evidence for human
analysis and Rule Improvement; it does not apply changes or select an active
champion by itself.

---

## 2. Contract And Status Ownership

This document owns:

- common harness inputs, outputs, and run isolation;
- current, challenger, and baseline execution boundaries;
- compare versus judge responsibilities;
- stage-specific comparison dimensions;
- metadata, provenance, failure, and batch behavior;
- recommendation and human-review boundaries; and
- extension conditions for new comparison stages.

The [Rule Improvement Orchestrator Contract](rule_improvement_orchestrator_contract.md)
owns orchestration and downstream Rule Improvement authority transitions. The
[Main Roadmap](../../roadmap/roadmap.md) and
[Phase 6](../../roadmap/phase6.md) own implementation status, scenario
coverage, validation depth, priority, and sequencing.

The archived combined planning document is retained as
[historical context](../archive/rule-improvement-orchestrator-and-harness-plan.md)
and is non-canonical.

---

## 3. Core Model

```text
validated stage inputs
  -> execute current variant
  -> execute challenger variant
  -> execute deterministic baseline when applicable
  -> validate and preserve every stage output
  -> compare explicit facts and differences
  -> judge against a versioned rubric
  -> write summary and metadata
  -> human review / Rule Improvement intake
```

The harness compares outputs from a single stage. It must not collapse Triage,
Investigation, Action, execution, collection, or post-action DFIR into one
undifferentiated score.

---

## 4. Shared Invariants

### 4.1 Same Input Boundary

Current, challenger, and baseline variants must receive the same canonical
required inputs. Optional evidence must be resolved consistently and its
presence, absence, or validation failure recorded per run.

### 4.2 Output Isolation

Each variant writes to a separate run-local location. A variant must not read
another variant's output, overwrite a shared baseline, or mutate source
artifacts.

### 4.3 Schema-Valid Outputs

Each stage result must validate against its canonical schema before comparison.
Invalid output is a failed candidate result, not a partially successful result
to be repaired by compare or judge logic.

### 4.4 Evidence-Bounded Evaluation

Compare and judge stages may use only validated inputs, outputs, expected
artifacts, evidence references, scenario policy, and rubric data explicitly
admitted by the workflow. They must not infer unrecorded facts.

### 4.5 Deterministic Judge

The judge applies a versioned rubric and deterministic scoring or decision
rules. An AI-generated narrative may be a separate review aid, but it must not
replace the canonical deterministic judge result.

### 4.6 No State Mutation

A passing score, challenger win, or promotion recommendation is review
evidence only. The harness must not update a prompt, rule, parser, policy,
baseline, active champion, deployment, or promotion state.

---

## 5. Harness Inputs

A harness run must identify:

- stage: `triage`, `investigation`, or `action`;
- run and scenario identity;
- canonical required input artifacts;
- optional evidence artifacts admitted by the stage contract;
- expected and primary artifacts when scenario evaluation uses them;
- current variant configuration;
- challenger variant configuration;
- deterministic baseline configuration when applicable;
- compare configuration;
- judge rubric and version;
- output root; and
- timeout or other bounded execution controls.

Variant configuration must be explicit enough to reproduce the run. Depending
on the stage, it may include tool version, prompt version, model identifier,
temperature or deterministic settings, policy version, and registered agent
entrypoint.

Credentials and secrets must remain in approved runtime configuration and must
not be copied into harness metadata or outputs.

---

## 6. Harness Outputs

Each run must preserve:

- one validated result or explicit failure record per variant;
- `compare.json`;
- `judge_result.json`;
- `summary.md`; and
- `metadata.json`.

Additional diagnostics are permitted only when they are clearly non-authoritative
and cannot replace a required primary output.

### 6.1 `compare.json`

`compare.json` records factual similarities, differences, missing values,
artifact alignment, and candidate-specific validation outcomes. It must not
declare promotion approval or mutate the compared results.

### 6.2 `judge_result.json`

`judge_result.json` records the rubric version, criterion-level results,
evidence references, hard-gate results, limitations, and overall judge outcome.

A criterion result must remain distinguishable from source evidence. The judge
must not convert absence of optional evidence into a fabricated fact.

### 6.3 `summary.md`

`summary.md` is a human-readable rendering of validated compare and judge
artifacts. It is not a source-of-authority artifact.

### 6.4 `metadata.json`

`metadata.json` must preserve enough information to reproduce and audit the
comparison, including:

- harness run ID;
- source run and scenario IDs;
- stage;
- required and optional input references and hashes where required;
- current, challenger, and baseline identities;
- agent, prompt, model, policy, and rubric versions as applicable;
- schema versions;
- execution timestamps and statuses;
- output references;
- compare and judge tool versions;
- timeout or bounded execution settings;
- skip and failure reasons; and
- known evidence or environment limitations.

Metadata must not contain credentials, raw private evidence, or hidden model
reasoning.

---

## 7. Compare Responsibility

Compare logic must:

- validate that candidate results belong to the same input boundary;
- preserve candidate identity;
- compare explicit schema fields and derived comparison dimensions;
- distinguish missing, null, unsupported, invalid, and unequal values;
- preserve primary-artifact and expected-artifact semantics;
- identify candidate-only and shared findings;
- expose regressions and evidence gaps without repairing them;
- remain independent of promotion decisions; and
- produce deterministic output for the same validated inputs.

Compare logic must not:

- execute a candidate;
- re-run an agent implicitly;
- rewrite a candidate result;
- infer attacker success as defender detection;
- collapse evidence strength into a binary result when the source contract
  preserves uncertainty; or
- decide that a candidate is safe to deploy.

---

## 8. Judge Responsibility

Judge logic must:

- consume schema-valid candidate results and `compare.json`;
- apply a named, versioned rubric;
- record criterion-level evidence and results;
- enforce hard gates separately from weighted quality scores;
- preserve scenario-specific expectations admitted by the workflow;
- distinguish insufficient evidence from a negative finding;
- report ties, indeterminate outcomes, and all-candidate failures explicitly;
- keep safety and approval failures visible; and
- produce deterministic output.

Judge logic must not:

- use hidden criteria;
- silently change weights by scenario;
- reward unsupported specificity;
- infer reviewer approval;
- turn a score into apply or promotion authority; or
- conceal a hard-gate failure inside an average score.

---

## 9. Triage Harness Contract

### 9.1 Boundary

```text
incident.json
  -> triage variant
  -> triage_result.json
  -> compare
  -> judge
```

The Triage harness evaluates stage output only. It does not perform
Investigation, Case construction, Action planning, or response execution.

### 9.2 Minimum Comparison Dimensions

- severity and assessment alignment;
- behavior and derived feature coverage;
- detected and missing artifact handling;
- primary-artifact awareness;
- confidence and uncertainty handling;
- rationale grounding in Incident facts;
- recommended investigation pivots;
- unsupported or fabricated claims; and
- schema and contract compliance.

### 9.3 Minimum Judge Concerns

- detection and artifact coverage;
- assessment correctness;
- evidence grounding;
- false specificity;
- confidence calibration;
- missing-pivot usefulness; and
- safety or policy violations.

---

## 10. Investigation Harness Contract

### 10.1 Boundary

```text
incident.json + triage_result.json + optional validated evidence
  -> Investigation variant
  -> investigation_result.json
  -> compare
  -> judge
```

Optional evidence may include normalized endpoint events, process events,
process-chain results, network evidence, or other source-specific artifacts
admitted by the Investigation contract. Missing optional evidence must remain
explicit.

The harness evaluates pre-case Investigation output. It does not merge
post-action DFIR collection or change the Case timeline.

### 10.2 Minimum Comparison Dimensions

- evidence coverage and source diversity;
- evidence specificity;
- finding and hypothesis quality;
- enriched-feature quality;
- factual observed facts versus interpretation;
- missing and recommended pivots;
- limitations and uncertainty;
- source provenance;
- unsupported claims; and
- schema and contract compliance.

### 10.3 Minimum Judge Concerns

- whether findings are grounded in cited evidence;
- whether the output preserves source limitations;
- whether enriched features add defensible context;
- whether missing pivots are identified;
- whether recommended pivots are actionable and bounded;
- whether absent evidence is misrepresented; and
- whether pre-case and post-action boundaries remain separate.

---

## 11. Action Harness Contract

### 11.1 Boundary

```text
case.json + optional policy and capability context
  -> Action variant
  -> action_result.json
  -> compare
  -> judge
```

The Action harness evaluates planning output only. It must not invoke an
executor, perform containment, change credentials, collect evidence, or compare
execution results.

An executor or post-action result comparison requires a separate contract
because environment state, capability, approval, and execution evidence differ
from Action planning quality.

### 11.2 Minimum Comparison Dimensions

- action coverage;
- grounding in Case facts and evidence;
- playbook specificity;
- approval fitness;
- auto-executable versus approval-required classification;
- safety controls;
- prerequisites and target clarity;
- unsupported or excessive actions;
- rollback or validation guidance where applicable; and
- schema and policy compliance.

### 11.3 Minimum Judge Concerns

- whether every proposed action is evidence-grounded;
- whether high-risk actions require approval;
- whether the plan stays within registered capabilities;
- whether targets, parameters, prerequisites, and validation are specific;
- whether the plan avoids automatic destructive or irreversible behavior;
- whether monitor-only or no-action outcomes remain representable; and
- whether planning is kept separate from execution.

---

## 12. Champion, Challenger, And Baseline Semantics

`current`, `challenger`, and `baseline` identify compared variants. They do not
encode approval, trust, or deployment state.

A challenger may be recommended for further review only when:

- all required inputs and outputs validate;
- hard safety and contract gates pass;
- primary and expected artifacts are handled correctly;
- criterion-level evidence supports the result;
- regression coverage is sufficient for the claimed scope;
- limitations are recorded; and
- a human reviewer can inspect the complete comparison.

If current and challenger both miss a primary artifact or fail a hard gate, the
result is a shared gap or indeterminate comparison. The judge must not select a
winner merely because one numeric score is higher.

A deterministic baseline provides a reference point when the stage supports
one. It is not automatically inferior to an AI variant and must be evaluated
under the same evidence and schema boundaries.

---

## 13. Promotion Recommendation Boundary

A harness may produce data that supports a later recommendation-only artifact.
It must not directly modify `promotion_recommendation.yaml` unless a dedicated
export contract explicitly consumes validated review decisions.

Any recommendation must preserve:

- source harness and candidate identities;
- compare and judge references;
- rubric and regression context;
- hard-gate results;
- reviewer-required status;
- limitations; and
- recommendation-only semantics.

A recommendation is not promotion approval, active-baseline selection, prompt
deployment, or state mutation.

---

## 14. Batch Comparison Contract

A batch runner may execute the same versioned harness definition across multiple
scenarios or runs.

The batch runner must:

- preserve one independently reviewable result per scenario;
- keep scenario inputs and outputs isolated;
- record partial failures and skips;
- preserve primary-artifact expectations per scenario;
- prevent one strong result from hiding another scenario's hard-gate failure;
- aggregate only comparable rubric versions and dimensions;
- keep candidate identity stable across the batch;
- produce deterministic aggregate summaries; and
- avoid automatic promotion.

Batch success does not mean universal coverage. The summary must state the
tested scenario set, evidence type, validation depth, failures, skips, and
uncovered scope.

---

## 15. Failure And Skip Semantics

A candidate execution fails when required input is invalid, execution exceeds
its bounded controls, output is missing or invalid, provenance is inconsistent,
or an unregistered stage behavior occurs.

The harness must:

- preserve the failure without fabricating a result;
- allow other isolated candidates to finish when safe;
- make comparison limitations explicit;
- prevent judge success when required candidate evidence is invalid;
- distinguish candidate failure from harness infrastructure failure; and
- avoid writing a promotion recommendation from incomplete required evidence.

An optional candidate or baseline may be skipped only when the workflow permits
it and the skip is recorded. A skip is not a pass.

---

## 16. Security And Approval Boundaries

The harness must not:

- execute Action plans;
- apply or deploy rules, prompts, parsers, policies, or configuration;
- enable a candidate;
- update an active baseline;
- approve or perform promotion;
- weaken approval requirements;
- expose credentials or sensitive raw evidence in summaries;
- call unregistered tools or endpoints;
- use model output as a human decision; or
- write outside the validated run boundary.

State-changing execution, candidate application, deployment, and promotion
require separate approval-gated workflows.

---

## 17. Contract Acceptance Criteria

The comparison harness contract remains valid when:

- all variants receive the same validated required inputs;
- outputs and metadata remain isolated and reproducible;
- each stage result validates before comparison;
- compare remains factual and separate from judge;
- judge behavior is deterministic and rubric-versioned;
- hard gates cannot be hidden by aggregate scores;
- Triage, Investigation, Action, and execution boundaries remain distinct;
- optional evidence absence stays explicit;
- batch aggregation preserves per-scenario failures and scope;
- recommendations remain human-review-only; and
- no harness result mutates active state.

---

## 18. Extension Conditions

Add a new stage, candidate type, rubric criterion, optional evidence source, or
batch dimension only when a concrete need identifies:

1. canonical required and optional inputs;
2. stage output schema and validation behavior;
3. source and candidate provenance;
4. compare dimensions;
5. deterministic rubric criteria and hard gates;
6. missing, invalid, timeout, and skip semantics;
7. focused valid, invalid, regression, and unsafe coverage;
8. batch compatibility rules where applicable; and
9. an explicit boundary preventing apply, execution, deployment, and automatic
   promotion.

Implementation status and scenario coverage belong in the Main Roadmap or
Phase 6 rather than this contract.

---

## 19. One-Line Summary

```text
A comparison harness isolates stage variants, compares validated facts, and
applies a deterministic rubric; its results inform human review and never
authorize execution, apply, deployment, or promotion.
```
