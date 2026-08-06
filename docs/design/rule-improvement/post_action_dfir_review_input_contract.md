# Post-Action DFIR Rule Improvement Review Input Contract

## 1. Purpose

This document defines a safe, one-way handoff from
`post_action_dfir_investigation_result.json` to Rule Improvement review.

Post-action DFIR findings may inform a reviewer about possible detection,
telemetry, parser, or correlation gaps. They are not rule changes, promotion
decisions, case reassessments, or instructions to take response action.

This contract is implemented through `schemas/rule_improvement_review_input.schema.json` and the deterministic exporter `scripts/export_rule_improvement_review_input.py`. It still does not add candidate generation, promotion, or state mutation.

---

## 2. Canonical flow

```text
collection_result.json + collected outputs
  ↓
post_action_dfir_investigation_result.json
  ↓ deterministic, provenance-preserving projection
rule_improvement_review_input.json          (implemented, review-only)
  ↓
human signal classification
  ↓ optional, separately reviewed candidate generation
rule_candidates.yaml / prompt_candidates.yaml
  ↓ existing review and regression gates
human-approved rule or prompt update
```

The handoff is one-way. Neither `collection_result.json` nor
`post_action_dfir_investigation_result.json` is fed back into the pre-case
`investigation_result.json` stage.

---

## 3. Hard boundaries

The review input and exporter must not directly or indirectly overwrite:

- pre-case `investigation_result.json`
- `case.json`, including status, severity, verdict, or confidence
- `action_result.json`
- action approval or containment state
- Rule Improvement candidate approval or promotion state
- current/variant selection or detector enablement

The review input must not:

- auto-create `rule_candidates.yaml`, `prompt_candidates.yaml`, or a promotion
  recommendation
- mark any candidate as accepted or promotable
- trigger a rule, prompt, policy, containment, isolation, or external-case update
- convert missing evidence into a negative security conclusion

Post-action findings may only create or enrich a human-reviewable Rule
Improvement input signal.

---

## 4. Exported artifact

The implemented output artifact is:

```text
data/runs/<run_id>/rule_improvement_review_input.json
```

`rule_improvement_review_input.json` is a review artifact. It is not a candidate
artifact and not a promotion artifact.

Invariant fields are:

```json
{
  "source_stage": "post_action_dfir",
  "human_review_required": true,
  "promotion_allowed": false
}
```

`promotion_allowed` must default to `false`. A later reviewer decision must not
rewrite this source artifact to `true`; accepted signals should move into the
existing, separately auditable candidate-review flow.

The exporter is invoked explicitly:

```bash
uv run python scripts/export_rule_improvement_review_input.py \
  --input data/runs/<run_id>/post_action_dfir_investigation_result.json \
  --output data/runs/<run_id>/rule_improvement_review_input.json
```

It validates the source against `schemas/post_action_dfir_investigation_result.schema.json`, validates the projected output against `schemas/rule_improvement_review_input.schema.json`, and writes deterministic pretty JSON with sorted keys.

### 4.1 Optional process-pipeline integration

`scripts/run_process_pipeline.py --export-ri-review-input` is implemented and remains off by default. When combined with `--run-post-action-dfir`, the pipeline runs post-action DFIR first and then invokes the exporter for the same run. When used alone, `--export-ri-review-input` requires an existing `data/runs/<run_id>/post_action_dfir_investigation_result.json`.

If the source result is missing, the pipeline fails closed with a clear error and does not fabricate `rule_improvement_review_input.json`. Successful export writes `data/runs/<run_id>/rule_improvement_review_input.json` with the same review-only invariants as the standalone exporter. The integration does not generate candidate or promotion YAML and does not mutate investigation, case, action, approval, containment, assessment, or Rule Improvement promotion state.

---

## 5. Source requirements

The direct source is a schema-valid
`post_action_dfir_investigation_result.json`. The review input references the
source result and selected evidence references rather than embedding raw
collector output.

Eligible source sections are:

- `evidence_inventory`
- `artifact_parse_results`
- `observed_facts`
- `evidence_gaps`
- `collection_limitations`
- `recommended_followups`

`collection_result.json` remains evidence transport. It is not itself a Rule
Improvement conclusion or a pre-case investigation input.

If `detection_type` is not present in the post-action result, the review-input
producer may copy it from already-associated run metadata. It must remain null
or omitted when unavailable; it must not be inferred from weak evidence.

---

## 6. Exported content

The exporter emits this shape:

```json
{
  "review_input_id": "ri-review-post-dfir-run-0033-001",
  "source_stage": "post_action_dfir",
  "source_result_ref": "data/runs/run-0033/post_action_dfir_investigation_result.json",
  "case_id": "case-run-0033",
  "scenario_id": "scenario_006",
  "detection_type": "ssh_key_login_then_process_exec",
  "observed_facts": [
    {
      "fact_id": "shell-history-example",
      "fact_type": "shell_history_observation",
      "summary": "A relevant command appeared in collected shell history; this does not establish execution.",
      "evidence_refs": [
        "forensics/mock/Linux.BashHistory.json"
      ],
      "evidence_strength": "weak",
      "evidence_characteristics": [
        "user_controlled",
        "timing_sensitive"
      ],
      "interpretation_scope": "shell_history_entry_not_confirmed_execution"
    }
  ],
  "supporting_signals": [
    {
      "signal_type": "post_action_observation_for_review",
      "summary": "Review whether existing detection coverage represents the collected observations.",
      "source_fact_ids": [
        "shell-history-example"
      ],
      "review_status": "unreviewed"
    }
  ],
  "evidence_gaps": [],
  "collection_limitations": [],
  "recommended_review_questions": [
    "Does independent telemetry corroborate command execution?",
    "Is any apparent gap a detection, telemetry, parser, correlation, or timing gap?"
  ],
  "candidate_hints": [
    {
      "hint_type": "review_hypothesis",
      "summary": "Consider whether a reviewed detection gap exists after independent corroboration.",
      "candidate_generation_allowed": false
    }
  ],
  "risk_notes": [
    "BashHistory is weak, user-controlled, timing-sensitive evidence and does not confirm execution."
  ],
  "human_review_required": true,
  "promotion_allowed": false
}
```

### 6.1 Field semantics

| Field | Meaning |
|---|---|
| `source_stage` | Must be `post_action_dfir`. |
| `source_result_ref` | Run-relative or canonical path to the source post-action result. |
| `case_id` | Traceability only; it does not authorize case mutation. |
| `scenario_id` | Scenario context for review and later regression selection. |
| `detection_type` | Existing run context when available; never inferred from missing or weak evidence. |
| `observed_facts` | Sanitized, provenance-preserving facts from the post-action result. |
| `supporting_signals` | Review context derived from facts; not conclusions or candidate approvals. |
| `evidence_gaps` | Preserved source gaps, including missing, failed, unreadable, or unparseable evidence. |
| `collection_limitations` | Preserved scope, timing, retention, and evidence-strength limitations. |
| `recommended_review_questions` | Specific questions a reviewer should resolve before candidate generation. |
| `candidate_hints` | Non-executable hypotheses. They are not `rule_candidates.yaml` entries. |
| `risk_notes` | Overclaim, evidence-strength, privacy, and operational-risk notes. |
| `human_review_required` | Must be `true`. |
| `promotion_allowed` | Must be `false` in this artifact. |

---

## 7. Evidence semantics

### 7.1 `Linux.Syslog.SSHLogin`

An SSH login fact means the represented authentication event was recorded. It
does not independently establish payload execution, persistence, privilege
escalation, or malicious intent.

### 7.2 `Linux.ProcessList`

`Linux.ProcessList` is a point-in-time snapshot. A matching process may support
only the fact that the process was present at collection time.

A missing process must not be transformed into:

- proof that a payload did not execute
- proof that a process never existed
- a host-clean or benign conclusion
- a negative Rule Improvement signal

### 7.3 `Linux.BashHistory`

`Linux.BashHistory` is weak, user-controlled, timing-sensitive evidence.
`shell_history_observation` means only that a command appeared in collected
shell history. It does not confirm execution.

The handoff must preserve:

```text
evidence_strength: weak
user_controlled
timing_sensitive
shell_history_entry_not_confirmed_execution
```

A missing history entry must not be transformed into proof of non-execution, a
host-clean conclusion, or a reason to suppress a candidate review.

### 7.4 Absence is a limitation, not a finding

Missing, unsupported, unreadable, unparseable, or non-matching evidence remains
in `evidence_gaps`, `collection_limitations`, or `risk_notes`. It must not be
promoted into an observed fact or a benign conclusion.

---

## 8. Review policy

### 8.1 First gate: signal classification

The canonical decision-record contract is `docs/design/rule-improvement/rule_improvement_signal_classification_contract.md`. Its implemented schema, `schemas/rule_improvement_signal_classification.schema.json`, defines the human-created `data/runs/<run_id>/rule_improvement_signal_classification.json` artifact, reviewer provenance, rationale, label semantics, and fixed eligibility mapping. The implemented human-operated CLI is `scripts/create_rule_improvement_signal_classification.py`.

A human reviewer classifies each review signal before any candidate-generation
step. The classifications are:

An optional `rule_improvement_ai_review_draft.json` may provide suggestions
before this human step. Per
`docs/design/rule-improvement/ai_assisted_review_draft_contract.md`, it cannot
make a classification decision, derive eligibility, invoke candidate
generation, or bypass the human-operated helper.

| Classification | Meaning |
|---|---|
| `detection_gap` | Adequate telemetry and corroborated behavior exist, but detection coverage appears absent or insufficient. |
| `telemetry_gap` | Required defender telemetry is absent, incomplete, or outside retention. |
| `parser_gap` | Collected data exists, but parsing or normalization is insufficient. |
| `correlation_gap` | Relevant facts exist but are not joined into the intended behavior. |
| `timing_or_scope_limit` | Point-in-time, retention, or collection scope prevents a conclusion. |
| `insufficient_evidence` | Evidence strength is too weak for candidate generation. |
| `expected_or_authorized_behavior` | Review finds no rule change is currently justified. |
| `no_rule_change` | The signal is closed without candidate generation. |

Only a reviewer-classified `detection_gap`, `parser_gap`, or `correlation_gap`
may proceed to optional candidate generation. Classification does not itself
approve or promote a candidate.

### 8.2 Second gate: candidate and promotion review

Any later candidate remains subject to the existing Rule Improvement contract:

```text
reviewed signal
  ↓ optional candidate generation
candidate_review.md
  ↓ human review
single-scenario validation
  ↓
batch regression validation
  ↓
human-approved promotion decision
```

There is no direct edge from a post-action DFIR fact to promotion.

---

## 9. Candidate hint rules

`candidate_hints` help reviewers frame possible follow-up work. They must:

- be phrased as hypotheses or review questions
- cite source fact IDs or evidence references when applicable
- preserve evidence strength and limitations
- require independent corroboration for weak evidence
- set `candidate_generation_allowed` to `false` before review

They must not contain:

- ready-to-apply rule content
- a promotion recommendation
- an automatic severity, verdict, confidence, approval, or containment change
- a negative conclusion derived from missing evidence

---

## 10. Data minimization and provenance

The handoff should copy the minimum review context needed.

- Prefer evidence references and sanitized summaries over raw collector output.
- Do not copy secrets, credentials, private keys, tokens, raw payload bodies, or
  arbitrary shell-history contents into the review artifact.
- Preserve source fact IDs, artifact names, and evidence references.
- Do not upgrade qualitative evidence strength during projection.
- Preserve gaps and limitations adjacent to the facts they constrain.

---

## 11. Failure behavior

The exporter fails closed:

- a missing or invalid post-action result fails before output is written
- an output that fails the review-input schema is not written
- source facts without required provenance fail source validation
- raw parser details are not copied; only schema-approved fact and semantic fields are projected

Failure to produce a review input must not fail or rewrite the completed
pre-case, case, action, collection, or post-action DFIR artifacts.

---

## 12. Relationship to existing Rule Improvement artifacts

Existing outputs remain unchanged:

```text
rule_candidates.yaml
prompt_candidates.yaml
promotion_recommendation.yaml
candidate_review.md
observed_effects_alignment_signals.json
```

`rule_improvement_review_input.json` is upstream review context. It does not
replace or populate these outputs automatically. It may eventually be rendered
as an optional section in `candidate_review.md` after a reviewer classifies the
signal.

---

## 13. Status And Evidence Ownership

This document owns the one-way DFIR-to-review projection, evidence semantics,
data minimization, provenance, candidate-hint boundaries, and fail-closed
export behavior. The schema, exporter, human classification helper, fixtures,
and focused tests named in this contract are evidence for those boundaries.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, validation depth, priorities, and sequencing.
Downstream proposal, conversion, export, validation-summary, apply, deployment,
and promotion state must not be inferred from this review-input contract.

Revision or supersession support must preserve an auditable decision history
and cannot silently replace a human-reviewed record.

---

## 14. Exporter guarantees

The implemented exporter guarantees:

- the source and target artifact roles are unambiguous
- weak and point-in-time evidence semantics survive projection
- gaps and limitations cannot become negative conclusions
- `human_review_required` is always `true`
- `promotion_allowed` is always `false`
- no existing investigation, case, action, approval, containment, or promotion
  state is mutated
- candidate generation requires explicit reviewer classification
- promotion remains governed by existing human review and regression gates

---

## 15. One-line summary

```text
Post-action DFIR may inform Rule Improvement through a provenance-preserving, review-only signal; it never directly creates or promotes a rule change.
```
