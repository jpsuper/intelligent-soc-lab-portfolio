# Observed Effects Alignment Signal Contract

## 1. Purpose

This document defines how `observed_effects_alignment` gaps should be surfaced to the Rule Improvement workflow as reviewable signals.

The goal is to connect attacker-side observed effects with the improvement loop without confusing attacker-side evidence with defender-side detection.

This contract governs the additive signal path used by the Rule Improvement
Agent and its human-review artifacts.

---

## 2. Scope

This contract covers signals derived from:

```text
attack_observed_effects.json
  ↓
observed_effects_alignment in evaluation_result.json
  ↓
Rule Improvement review signal
  ↓
human review
  ↓
optional candidate generation
```

The initial target is `attacker_observed_defender_missing`.

Future signal types may include:

- `defender_observed_attacker_missing`
- `expected_but_not_observed`

---

## 3. Key Boundaries

### 3.1 Attacker-side evidence is not defender telemetry

```text
ATTACK_EVENT_JSON != defender-side telemetry
ATTACK_EVENT_JSON != defender-side detection
attack_observed_effects.json != defender-side observed artifacts
```

A structured runner event may support an attacker-side observed effect.
It must not be treated as proof that the defender detected the behavior.

### 3.2 Alignment signal is not an automatically promotable rule candidate

```text
observed_effects_alignment signal != automatically promotable rule candidate
```

An alignment gap is a review signal. It may indicate a detection gap, but it may also indicate a collection gap, parser gap, correlation gap, mapping issue, or weak attacker-side evidence.

### 3.3 Existing evaluation verdict behavior must not change

This contract must not change:

- `overall_result`
- `detected`
- existing evaluation pass/fail semantics
- existing observed-effects alignment behavior

The Rule Improvement signal is additive.

---

## 4. Source Artifact

The source artifact is `evaluation_result.json`.

Expected source field:

```text
evaluation_result.observed_effects_alignment
```

The signal should reference the relevant alignment item rather than duplicating all source evidence.

---

## 5. Eligible Alignment Statuses

### 5.1 Initial status

```text
attacker_observed_defender_missing
```

Meaning:

- the attacker-agent observed or inferred that an intended effect occurred
- the effect maps to an expected defender-side artifact
- the defender-side artifact was not observed in the current evaluation

This should be treated as a reviewable improvement signal, not as a direct rule candidate.

### 5.2 Future statuses

```text
defender_observed_attacker_missing
expected_but_not_observed
```

These may be introduced later once their review semantics are documented and tested.

---

## 6. Signal Semantics

`attacker_observed_defender_missing` may indicate one of several causes.

Reviewers should classify the signal before any candidate is generated.

Recommended review categories:

| Category | Meaning |
|---|---|
| `detection_gap` | Defender telemetry exists, but no detection or rule captured the expected artifact. |
| `collection_gap` | The expected telemetry was not collected or was unavailable. |
| `parser_gap` | Raw telemetry likely exists, but parsing or normalization missed it. |
| `correlation_gap` | Atomic observations exist, but correlation did not connect them to the scenario. |
| `scenario_mapping_issue` | The attacker-side effect maps to the wrong or too-broad defender artifact. |
| `insufficient_attacker_evidence` | The attacker-side evidence is too weak to justify a defender-side expectation. |
| `expected_noise_or_out_of_scope` | The gap is known, acceptable, or outside the current scenario scope. |

---

## 7. Review Signal Shape

The additive review signal uses this shape:

```json
{
  "signal_type": "observed_effects_alignment_gap",
  "alignment_status": "attacker_observed_defender_missing",
  "source_artifact": "evaluation_result.observed_effects_alignment",
  "scenario_id": "scenario_006",
  "effect_type": "payload_execution_succeeded",
  "expected_defender_artifact": "process_exec",
  "technique": "T1059",
  "attacker_evidence_type": "structured_runner_event",
  "attacker_evidence_confidence": "medium",
  "review_required": true,
  "auto_generate_rule_candidate": false,
  "recommended_review_categories": [
    "detection_gap",
    "collection_gap",
    "parser_gap",
    "correlation_gap",
    "scenario_mapping_issue",
    "insufficient_attacker_evidence"
  ]
}
```

### 7.1 Required fields

| Field | Meaning |
|---|---|
| `signal_type` | Stable signal type. Initial value: `observed_effects_alignment_gap`. |
| `alignment_status` | Alignment status that triggered the signal. |
| `source_artifact` | Source artifact path or logical field. |
| `scenario_id` | Scenario that produced the alignment result. |
| `effect_type` | Attacker-side observed effect type. |
| `expected_defender_artifact` | Defender-side artifact expected by the mapping. |
| `review_required` | Must be `true` for this contract. |
| `auto_generate_rule_candidate` | Must be `false` under this contract. |

### 7.2 Recommended fields

| Field | Meaning |
|---|---|
| `technique` | MITRE ATT&CK technique ID if available. |
| `attacker_evidence_type` | Evidence source such as `structured_runner_event`, `legacy_stdout_marker`, or `exit_code_fallback`. |
| `attacker_evidence_confidence` | Confidence from `attack_observed_effects.json`. |
| `recommended_review_categories` | Suggested human review categories. |
| `notes` | Short non-sensitive explanation. |

---

## 8. Rule Improvement Handling Policy

### 8.1 Review behavior

The Rule Improvement workflow treats these signals as human-reviewable context.

Review behavior:

```text
observed_effects_alignment gap
  ↓
review signal
  ↓
candidate_review.md or equivalent review artifact
  ↓
human classification
  ↓
optional candidate generation after a separate review gate
```

### 8.2 Candidate generation gate

Rule or prompt candidates may be proposed only when review classifies the signal as one of:

- `detection_gap`
- `parser_gap`
- `correlation_gap`

Even then, the candidate should remain reviewable and should not be auto-applied.

### 8.3 No auto-promotion

Signals from this contract must not directly trigger:

- rule promotion
- prompt promotion
- policy promotion
- current / variant replacement
- detector enablement
- containment or executor actions

---

## 9. Relationship to Existing Artifacts

### 9.1 `attack_observed_effects.json`

`attack_observed_effects.json` records attacker-side observed effects.

It may derive effects from:

```text
structured runner events
  ↓ fallback
legacy stdout marker parsing
  ↓ fallback
exit_code-based weak inference
```

### 9.2 `evaluation_result.json`

`evaluation_result.json` may include additive `observed_effects_alignment` results.

This contract only consumes alignment results as improvement signals.
It does not redefine the alignment algorithm.

### 9.3 Rule Improvement outputs

Relevant Rule Improvement review outputs include:

```text
observed_effects_alignment_signals.json
candidate_review.md
```

The signal artifact and review rendering remain additive and review-only. They
must not populate candidate or recommendation artifacts automatically.

---

## 10. Safety and Robustness Rules

Signals must not include:

- secrets
- passwords
- private keys
- full token values
- sensitive file contents
- raw payload bodies
- large stdout blobs

Signals may include:

- artifact names
- effect names
- technique IDs
- scenario IDs
- host or user labels
- sanitized evidence summaries
- evidence confidence
- review categories

---

## 11. Status And Evidence Ownership

This document owns alignment-gap signal semantics, the separation between
attacker-side and defender-side evidence, human-review requirements, and the
non-candidate boundary. Implemented signal generation, review rendering, and
focused tests are evidence for those boundaries.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, validation depth, priorities, and sequencing.
New alignment statuses require documented review semantics and focused tests
before they may enter this contract.

---

## 12. Boundary Acceptance Criteria

The alignment-signal boundary remains valid when:

- `attacker_observed_defender_missing` remains a reviewable signal
- attacker-side evidence remains separate from defender-side detection
- alignment signals do not change `overall_result` or `detected`
- alignment gaps do not auto-generate rule candidates
- review categories remain explicit
- new signal types are introduced additively with documented semantics and
  focused tests

---

## 13. One-Line Summary

```text
observed_effects_alignment gaps can inform Rule Improvement, but only as human-reviewable signals until a reviewer classifies the likely gap type.
```
