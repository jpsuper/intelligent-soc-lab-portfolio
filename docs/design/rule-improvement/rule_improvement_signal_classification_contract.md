# Rule Improvement Signal Classification Contract

## 1. Purpose

This document defines the human review boundary between
`rule_improvement_review_input.json` and any later Rule Improvement candidate
work.

Signal classification is a human decision-recording step. It is not candidate
generation, candidate approval, rule promotion, or state mutation.

The artifact contract is implemented by
`schemas/rule_improvement_signal_classification.schema.json`, with valid and
invalid fixtures under
`tests/fixtures/rule_improvement_signal_classification/` and focused schema
tests in `tests/test_rule_improvement_signal_classification_schema.py`.

The human-operated helper is implemented at
`scripts/create_rule_improvement_signal_classification.py`. It is a
deterministic CLI, not AI integration, candidate generation, or promotion.

The optional deterministic
`scripts/export_ai_review_draft_human_worksheet.py` exporter creates only a
Markdown aid from a schema-valid AI review draft. A reviewer must still inspect
the source review input and manually author decisions JSON. The exporter does
not create classification output or invoke this helper. Its optional,
default-off process-pipeline flag only exports the worksheet and does not author
or submit decisions.

The deterministic
`scripts/export_ri_signal_classification_decisions_template.py` exporter creates
an incomplete JSON template from a schema-valid AI review draft. It preserves
draft/review provenance and signal refs but replaces every AI suggestion with
explicit human-edit placeholders. The template is not completed decisions JSON,
is rejected by the classification helper until a human extracts and completes
its `decisions` array. The optional, default-off
`--export-ri-signal-classification-decisions-template` process-pipeline flag
invokes only this local exporter, requires an existing AI review draft, and
fails closed without fabricating a source or output.

---

## 2. Canonical flow

```text
post_action_dfir_investigation_result.json
  ↓ deterministic review-input export
rule_improvement_review_input.json
  ↓ human signal classification
rule_improvement_signal_classification.json    (schema-defined review decision record)
  ↓ only eligible, completed classifications
separate candidate-generation intake (when authorized)
  ↓ candidate review + regression gates
human-approved rule or prompt update
```

There is no direct edge from a review signal or classification label to a rule
candidate or promotion decision.

An optional human-authoring aid follows this separate path:

```text
rule_improvement_ai_review_draft.json
  ↓ scripts/export_ri_signal_classification_decisions_template.py
human_decisions_template.json                 (incomplete placeholders only)
  ↓ independent human review and editing
completed decisions array in a separate JSON file
  ↓ scripts/create_rule_improvement_signal_classification.py
rule_improvement_signal_classification.json   (human decision record)
```

The exporter validates the AI draft schema and writes deterministic sorted,
pretty JSON. It does not copy suggested labels or rationales into human fields,
derive eligibility, populate reviewer metadata, invoke the helper, read evidence
refs, generate candidates or promotion, or mutate state.

The optional AI suggestion boundary is defined in
[`ai_assisted_review_draft_contract.md`](ai_assisted_review_draft_contract.md),
with minimized prompt context defined in
[`ai_review_draft_prompt_input_contract.md`](ai_review_draft_prompt_input_contract.md).
Its deterministic exporters, explicit manual model runners, and fail-closed
importer can produce a schema-valid suggestions-only draft. That artifact is
not a decision record and cannot replace or invoke the human-operated
classification helper.

---

## 3. Source and output artifacts

### 3.1 Source

The classification source is:

```text
data/runs/<run_id>/rule_improvement_review_input.json
```

The reviewer must use the schema-valid review input, including its observed
facts, supporting signals, evidence gaps, collection limitations, recommended
review questions, candidate hints, and risk notes.

Candidate hints remain hypotheses with `candidate_generation_allowed: false`.
They do not preselect the classification label.

### 3.2 Schema-defined output

The classification artifact is:

```text
data/runs/<run_id>/rule_improvement_signal_classification.json
```

Its Draft 2020-12 schema is implemented at
`schemas/rule_improvement_signal_classification.schema.json`. The artifact is a
provenance-preserving human review decision record. It is not:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`
- a rule or prompt update
- an approval or containment decision

### 3.3 Human-operated helper

The helper reads:

- a schema-valid `rule_improvement_review_input.json`
- a human-authored decisions JSON file
- a reviewer ID
- an RFC 3339 review timestamp

It writes a schema-valid `rule_improvement_signal_classification.json`:

```bash
uv run python scripts/create_rule_improvement_signal_classification.py \
  --review-input data/runs/<run_id>/rule_improvement_review_input.json \
  --decisions-json /tmp/ri_classification_decisions.json \
  --reviewer-id analyst-001 \
  --reviewed-at 2026-06-21T12:00:00Z \
  --output data/runs/<run_id>/rule_improvement_signal_classification.json
```

The decisions file is a non-empty JSON array. Human-provided fields are
`source_signal_ref`, `label`, `rationale`, `recommended_next_step`, and optional
`missing_requirements`. For example:

```json
[
  {
    "source_signal_ref": "/supporting_signals/0",
    "label": "detection_gap",
    "rationale": "Reviewed telemetry indicates a possible detection coverage gap.",
    "recommended_next_step": "Retain for a separate candidate intake review."
  }
]
```

The helper validates the source against
`schemas/rule_improvement_review_input.schema.json`, resolves each
`source_signal_ref`, and copies the source signal type, source fact IDs, and
evidence refs. It also copies optional case and scenario IDs. It derives
`candidate_generation_eligible` from the fixed mapping, validates the result
against `schemas/rule_improvement_signal_classification.schema.json`, and then
writes deterministic pretty JSON.

---

## 4. Hard boundaries

Classification must not modify or overwrite:

- `case.json`
- `action_result.json`
- pre-case `investigation_result.json`
- `post_action_dfir_investigation_result.json`
- `rule_improvement_review_input.json`
- containment or approval state
- verdict, severity, or confidence
- Rule Improvement candidate approval or promotion state

Classification must not generate:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`

The schema requires these safety invariants:

```json
{
  "human_review_completed": true,
  "candidate_generation_started": false,
  "promotion_allowed": false
}
```

A reviewer records a classification; the reviewer does not toggle promotion or
candidate generation in this artifact.

Root `additionalProperties: false` also rejects candidate, promotion, and
state-mutation fields such as `rule_candidates`, `prompt_candidates`,
`promotion_recommendation`, `candidate_approved`, `candidate_promoted`, case or
action state, containment state, verdict, severity, and confidence.

---

## 5. Unit of classification

A reviewer classifies each `supporting_signals[]` item independently. Multiple
signals may receive different labels.

Because the current review-input contract does not assign a dedicated signal
ID, the classification artifact references each source signal by:

- `source_signal_ref`, using a JSON Pointer such as `/supporting_signals/0`
- `source_signal_type`
- `source_fact_ids`
- `evidence_refs`

The source review input is deterministic and should be treated as immutable, so
the JSON Pointer remains auditable. A future review-input schema revision may
add a stable `signal_id`; this contract does not require that change now.

---

## 6. Schema-defined classification artifact shape

The human-operated helper emits this schema-valid shape:

```json
{
  "classification_id": "ri-classification-run-0033-001",
  "source_stage": "post_action_dfir",
  "source_review_input_ref": "data/runs/run-0033/rule_improvement_review_input.json",
  "source_review_input_id": "ri-review-post-dfir-run-0033-001",
  "case_id": "case-run-0033",
  "scenario_id": "scenario_006",
  "review_status": "completed",
  "reviewer": {
    "reviewer_id": "analyst-001",
    "reviewed_at": "2026-06-21T12:00:00Z"
  },
  "decisions": [
    {
      "decision_id": "ri-decision-run-0033-001",
      "source_signal_ref": "/supporting_signals/0",
      "source_signal_type": "post_action_observation_for_review",
      "source_fact_ids": [
        "process-snapshot-example"
      ],
      "evidence_refs": [
        "forensics/mock/Linux.ProcessList.json"
      ],
      "label": "correlation_gap",
      "rationale": "The process and authentication facts are present, but the intended temporal correlation is not represented.",
      "candidate_generation_eligible": true,
      "recommended_next_step": "Prepare a separately reviewed correlation-candidate proposal."
    }
  ],
  "human_review_completed": true,
  "candidate_generation_started": false,
  "promotion_allowed": false
}
```

### 6.1 Required provenance

Each decision should preserve:

| Field | Meaning |
|---|---|
| `source_review_input_ref` | Path to the exact review input used by the reviewer. |
| `source_review_input_id` | Stable ID from the review input. |
| `source_signal_ref` | JSON Pointer or future stable signal ID. |
| `source_signal_type` | Signal type copied from the review input. |
| `source_fact_ids` | Exact observed-fact IDs supporting the decision. |
| `evidence_refs` | Evidence references carried by the source signal and facts. |
| `reviewer.reviewer_id` | Human identity or approved reviewer principal. |
| `reviewer.reviewed_at` | Review timestamp. |
| `label` | Human classification decision. |
| `rationale` | Evidence-aware explanation for the decision. |

A label without reviewer identity, rationale, source fact IDs, and evidence
references is not eligible for downstream use.

### 6.2 Missing requirements

A decision may include `missing_requirements` as descriptive review context.
The schema recognizes these requirement types:

- `telemetry`
- `parser`
- `correlation`
- `collection_scope`
- `collection_timing`
- `evidence`
- `review`

Each entry preserves a summary and may name recommended sources. Missing
requirements do not change label eligibility, start candidate generation, or
allow promotion.

---

## 7. Classification labels

The allowed labels are:

```text
detection_gap
telemetry_gap
parser_gap
correlation_gap
timing_or_scope_limit
insufficient_evidence
expected_or_authorized_behavior
no_rule_change
```

### 7.1 `detection_gap`

Evidence suggests relevant defender telemetry exists and the behavior is
sufficiently corroborated, but current detection logic may not cover it.

This label does not mean a rule candidate is correct. It permits later,
separate candidate work after provenance and rationale review.

### 7.2 `telemetry_gap`

Needed telemetry is absent, unavailable, outside retention, or not collected at
the required fidelity.

The usual next step is a collection, sensor, retention, or logging improvement
task. It is not a detection-rule candidate.

### 7.3 `parser_gap`

A collected artifact exists, but parser support, normalization, or required
field extraction is missing or insufficient.

This may become eligible for later parser or normalization candidate work. It
does not prove the underlying behavior occurred.

### 7.4 `correlation_gap`

Individual observed facts exist, but cross-artifact, entity, sequence, or
temporal correlation needed for the intended behavior is missing.

This may become eligible for later correlation-candidate work.

### 7.5 `timing_or_scope_limit`

Collection timing, point-in-time scope, retention, user scope, host scope, or
artifact semantics prevent a reliable conclusion.

This label is not eligible for candidate generation.

### 7.6 `insufficient_evidence`

Available evidence is too weak, incomplete, ambiguous, or uncorroborated to
justify candidate work.

This label is not eligible for candidate generation.

### 7.7 `expected_or_authorized_behavior`

After human review, the behavior represented by the signal appears expected or
authorized in the reviewed context.

This is a scoped review decision, not a host-clean or benign verdict. It does
not change case verdict, severity, status, or confidence and is not eligible for
candidate generation.

### 7.8 `no_rule_change`

The reviewer explicitly decides that no rule or prompt change is needed for the
signal. The rationale should explain whether existing coverage is adequate, the
signal is out of scope, or another non-rule task is more appropriate.

This label is not eligible for candidate generation.

---

## 8. Eligibility mapping

Eligibility is derived from the reviewed label; it is not an independent human
approval switch. The schema enforces this mapping with conditional constraints.

| Label | `candidate_generation_eligible` | Typical downstream handling |
|---|---:|---|
| `detection_gap` | `true` | Possible future detection-candidate input after separate intake validation. |
| `parser_gap` | `true` | Possible future parser/normalization-candidate input after separate intake validation. |
| `correlation_gap` | `true` | Possible future correlation-candidate input after separate intake validation. |
| `telemetry_gap` | `false` | Collection, logging, sensor, or retention improvement task. |
| `timing_or_scope_limit` | `false` | Improve collection timing/scope or retain as a limitation. |
| `insufficient_evidence` | `false` | Gather corroborating evidence or close without candidate work. |
| `expected_or_authorized_behavior` | `false` | Close as reviewed context; do not infer global benign status. |
| `no_rule_change` | `false` | Close with reviewer rationale. |

Only a completed human review with `detection_gap`, `parser_gap`, or
`correlation_gap` may become input to a later candidate-generation workflow.
Eligibility does not create a candidate and never permits automatic promotion.

---

## 9. Evidence rules

### 9.1 BashHistory

`Linux.BashHistory` remains weak, user-controlled, timing-sensitive evidence.

- A history entry does not confirm command execution.
- An absent history entry does not prove non-execution.
- BashHistory alone should not justify `detection_gap` without independent
  corroboration.
- The classification decision must retain `evidence_strength: weak`,
  `user_controlled`, `timing_sensitive`, and
  `shell_history_entry_not_confirmed_execution` context through its provenance
  or rationale.

### 9.2 ProcessList

`Linux.ProcessList` remains a point-in-time snapshot.

- A matching process supports presence only at collection time.
- An absent process does not prove non-execution.
- A timing mismatch should normally be classified as `timing_or_scope_limit`,
  not as proof of adequate detection or clean-host status.

### 9.3 Missing or limited evidence

Missing, unreadable, unparseable, unsupported, or scoped evidence remains a
gap or limitation. It must not become:

- proof of non-execution
- a host-clean or benign conclusion
- a reason to lower verdict, severity, or confidence
- a positive or negative promotion decision

---

## 10. Review procedure

The reviewer should:

1. Verify the review input schema and source reference.
2. Read the signal, linked observed facts, evidence refs, gaps, limitations, and
   risk notes together.
3. Confirm that cited fact IDs and evidence refs exist in the source review
   input.
4. Check whether independent evidence is required, especially for BashHistory
   or point-in-time ProcessList observations.
5. Select exactly one allowed label for each reviewed signal.
6. Record reviewer identity, timestamp, rationale, and recommended next step.
7. Derive `candidate_generation_eligible` from the label mapping.
8. Leave `candidate_generation_started` and `promotion_allowed` as `false`.

A partial review may be saved with `review_status: partial`, but unclassified or
partially reviewed signals are never eligible for downstream candidate work.

---

## 11. Corrections and auditability

Classification artifacts should be append-only review records.

- Do not rewrite `rule_improvement_review_input.json`.
- Do not silently edit a completed classification.
- A correction should create a new classification artifact or revision with a
  new ID and `supersedes_classification_ref`.
- Preserve the original reviewer identity, timestamp, decision, and rationale.
- Downstream consumers must use only the latest non-superseded, completed
  classification.

---

## 12. Failure and incomplete-review behavior

The implemented schema rejects unknown labels, label/eligibility mismatches,
missing required provenance, unsafe flags, and root mutation fields. The
implemented human-operated helper fails closed:

- missing or invalid review input: do not write output
- unknown signal reference: do not write output
- missing rationale or recommended next step: do not write output
- unknown label: do not write output
- missing fact or evidence provenance: output validation fails before writing
- label/eligibility mismatch: reject the classification artifact
- schema-invalid output: do not write output

A classification failure must not modify any source artifact or existing state.
The helper cannot accept overrides for `candidate_generation_started`,
`promotion_allowed`, or `candidate_generation_eligible`.

---

## 13. Relationship to candidate generation

The classification artifact is upstream review context only.

A later candidate-generation adapter may consume only decisions that are:

- from a schema-valid classification artifact
- `review_status: completed`
- human reviewed with identity and rationale
- labeled `detection_gap`, `parser_gap`, or `correlation_gap`
- marked eligible according to the fixed mapping
- not superseded

Even then, generated candidates remain reviewable proposals. They must pass the
existing candidate-review and regression gates, and they must never be
auto-applied or auto-promoted.

---

## 14. Status And Evidence Ownership

This document owns human classification semantics, provenance, the fixed
label-to-eligibility mapping, and the locked candidate and promotion
invariants. The schema, fixtures, deterministic helper, authoring aids, and
focused tests named in this contract are evidence references for those
boundaries.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, validation depth, priorities, and sequencing.
A completed classification may become reviewed intake for a separately
authorized candidate-generation adapter, but this schema neither implements nor
authorizes candidate creation, apply, deployment, or promotion.

Revision and supersession support must preserve an auditable decision history
and cannot silently replace a human-reviewed record.

---

## 15. Boundary Acceptance Criteria

The classification boundary remains valid when:

- all labels and meanings are fixed
- provenance requirements are schema-testable
- label-to-eligibility mapping cannot be overridden
- incomplete reviews cannot become eligible
- weak and point-in-time evidence semantics survive classification
- classification cannot generate candidates or promotion recommendations
- correction and supersession behavior is auditable
- all mutation boundaries remain explicit

---

## 16. One-line summary

```text
Human classification records what a review signal means; it does not create, approve, apply, or promote a Rule Improvement candidate.
```
