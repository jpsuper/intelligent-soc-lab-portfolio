# Attack Observed Effects Contract

## 1. Purpose

This document defines the current contract for `attack_observed_effects.json`.

`attack_observed_effects.json` represents attacker-side observed facts about what the attacker runner believes happened during execution.

It is intentionally separate from:

- `attack_result.json`
- `attack_execution_log.json`
- `evaluation_result.json`
- `incident.json`
- `triage_result.json`
- `investigation_result.json`

The core purpose is to make attacker-side observations explicit without treating them as defender-confirmed truth.

One-line definition:

```text
attack_observed_effects.json = attacker-side observed effects, not defender-side detection evidence
```

---

## 2. Current Status

Current Phase C observed-effects artifact work is implemented for the
scenario_004 / 005 / 006 / 007 shell-runner path.

Implemented:

- `attack_result.schema.json`
- `attack_execution_log.schema.json`
- `attack_observed_effects.schema.json`
- attacker-agent output validation
- process pipeline `attack_result.json` schema alignment
- attack artifact contract
- attacker artifact catalog for scenario family / event / artifact mappings
- shell backend contract
- attacker-agent runtime generation of `attack_observed_effects.json`
- shell backend stdout / stderr preservation in `attack_execution_log.json`
- additive `structured_events` in `attack_execution_log.json` when valid
  `ATTACK_EVENT_JSON:` lines are present
- scenario_004 / 005 / 006 / 007 structured runner events for current observed-effect
  mappings
- observed-effects generation that prefers valid `execution_log.structured_events`
  before stdout structured-event parsing, legacy stdout marker fallback, and
  exit-code fallback
- additive `observed_effects_alignment` in `evaluation_result.json`
- Rule Improvement review signals from observed-effects alignment gaps

Still future / follow-on:

- richer observed-effect sources beyond the current shell-runner evidence path
- reviewer-approved conversion from observed-effects signals into concrete rule
  or prompt candidates

The runtime behavior remains bounded by this contract: attacker-side observed
effects are useful context, but they are not defender-side telemetry or
detections.

---

## 3. Why This Artifact Exists

The lab currently has two major views of the same attack run.

```text
attacker side:
  what was attempted
  what appeared to succeed
  what the runner observed

defender side:
  what telemetry was collected
  what detections fired
  what investigation confirmed
```

Without a separate artifact, these can become mixed together.

For example:

```text
SSH command returned exit code 0
```

does not mean:

```text
defender observed ssh_key_login
```

Similarly:

```text
payload printed an execution marker
```

does not mean:

```text
defender observed process_exec
```

`attack_observed_effects.json` exists to preserve this distinction.

---

## 4. Relationship to Existing Artifacts

### 4.1 `attack_result.json`

`attack_result.json` summarizes the run.

It answers:

- which scenario ran
- which backend was used
- whether execution completed
- which artifacts were expected
- which scenario metadata applied

It should not store detailed observed effects.

### 4.2 `attack_execution_log.json`

`attack_execution_log.json` records backend execution events.

It answers:

- which runner executed
- what exit code occurred
- what event sequence occurred
- what stdout / stderr was captured or referenced
- which additive `structured_events` were parsed from valid `ATTACK_EVENT_JSON:`
  lines, when present

It is raw execution evidence, not interpreted observed effects. Parsed
`structured_events` do not replace `events`, stdout, or stderr.

### 4.3 `attack_observed_effects.json`

`attack_observed_effects.json` interprets attacker-side execution evidence into structured observations.

It answers:

- what attacker-side effect was observed
- how it was observed
- what evidence supports it
- whether the effect is confirmed, partial, missing, or unknown from the attacker side
- how it maps to expected artifacts

### 4.4 `evaluation_result.json`

`evaluation_result.json` remains defender-side evaluation.

It compares expected artifacts against defender-side observations and may include
additive `observed_effects_alignment` for attacker/defender comparison.

Observed-effects alignment does not change `overall_result`, `detected`, or
existing verdict behavior. It must not treat attacker-side observations as
ground truth.

---

## 5. Key Boundary

The most important design boundary is:

```text
attacker-side observed effect != defender-side observed artifact
```

Examples:

| Attacker-side observed effect | Defender-side artifact |
|---|---|
| `ssh_login_succeeded` | `ssh_key_login` |
| `payload_command_returned_zero` | `process_exec` |
| `authorized_keys_append_attempted` | `authorized_keys_modification` |
| `suspicious_file_write_succeeded` | `suspicious_file_write` |
| `payload_stdout_marker_seen` | may support `process_exec`, but does not prove defender observed it |

This distinction is critical for fair evaluation.

---

## 6. Producer Responsibility

Current expected producer:

- attacker-agent

Current producer components:

- shell backend execution evidence
- structured runner event parser for `ATTACK_EVENT_JSON:` stdout lines
- attacker-agent observed-effects builder

Future possible producers:

- richer TTP backend evidence
- Atomic backend evidence
- autonomous backend evidence, after scenario and safety contracts are stable

The process pipeline should not normally produce `attack_observed_effects.json`, because it is primarily a defender-side orchestration pipeline.

Policy:

```text
attacker-agent may produce attack_observed_effects.json;
process pipeline may consume it later, but should not synthesize it from defender telemetry.
```

---

## 7. Consumer Responsibility

Current consumers:

- evaluation pipeline through additive `observed_effects_alignment`
- Rule Improvement review signal generation through
  `observed_effects_alignment_signals.json`

Potential future consumers:

- comparison harness
- attack/defense consistency checker
- case enrichment
- reporting layer

Consumers must treat this artifact as attacker-side context.

They should not directly convert observed effects into detection coverage.

Correct usage:

```text
attacker observed payload execution
  +
defender observed process_exec
  =
stronger end-to-end confirmation
```

Incorrect usage:

```text
attacker observed payload execution
  =
defender detected process_exec
```

---

## 8. Minimal Schema Shape

The implemented `attack_observed_effects.schema.json` intentionally stays small.

Current top-level shape:

```json
{
  "attack_id": "run-attack-schema-check",
  "scenario_id": "scenario-006",
  "backend": "shell",
  "generated_at": "2026-06-06T05:00:00Z",
  "effects": []
}
```

Current effect shape:

```json
{
  "effect_id": "effect-001",
  "effect_type": "ssh_login_succeeded",
  "status": "observed",
  "confidence": "medium",
  "maps_to_artifact": "ssh_key_login",
  "evidence": [
    {
      "type": "exit_code",
      "value": "0",
      "source": "attack_execution_log.events[1]"
    }
  ],
  "notes": "SSH command returned exit code 0."
}
```

---

## 9. Suggested Top-Level Fields

Current required fields:

- `attack_id`
- `scenario_id`
- `backend`
- `generated_at`
- `effects`

Current optional fields:

- `schema_version`
- `run_id`
- `scenario_name`
- `source_artifacts`
- `summary`
- `limitations`

Example:

```json
{
  "schema_version": "attack_observed_effects_v1",
  "attack_id": "run-attack-schema-check",
  "scenario_id": "scenario-006",
  "scenario_name": "SSH key login followed by command execution",
  "backend": "shell",
  "generated_at": "2026-06-06T05:00:00Z",
  "source_artifacts": [
    "attack_execution_log.json"
  ],
  "effects": [],
  "limitations": [
    "Attacker-side observations do not prove defender-side detection."
  ]
}
```

---

## 10. Suggested Effect Fields

Current required fields:

- `effect_id`
- `effect_type`
- `status`
- `confidence`

Current optional fields:

- `maps_to_artifact`
- `maps_to_technique`
- `target`
- `evidence`
- `timestamp`
- `notes`
- `limitations`

### 10.1 `effect_type`

Examples:

- `ssh_login_succeeded`
- `ssh_login_failed`
- `authorized_keys_write_attempted`
- `authorized_keys_write_succeeded`
- `payload_download_attempted`
- `payload_download_succeeded`
- `chmod_attempted`
- `chmod_succeeded`
- `payload_execution_attempted`
- `payload_execution_succeeded`
- `stdout_marker_observed`

### 10.2 `status`

Current enum:

- `observed`
- `not_observed`
- `partial`
- `unknown`

### 10.3 `confidence`

Current enum:

- `low`
- `medium`
- `high`

Confidence should be based on attacker-side evidence only.

---

## 11. Evidence Model

Observed effects should carry evidence references.

Recommended evidence fields:

- `type`
- `value`
- `source`
- `timestamp`
- `notes`

Example evidence types:

- `exit_code`
- `stdout`
- `stderr`
- `runner_marker`
- `generated_file`
- `command_output`
- `structured_runner_event`

Example:

```json
{
  "type": "stdout",
  "value": "[payload] executed at 2026-06-06T04:59:43Z",
  "source": "attack_execution_log.events[1].stdout",
  "timestamp": "2026-06-06T04:59:43Z"
}
```

Large stdout / stderr should eventually be referenced rather than embedded.

---

## 12. Mapping to Expected Artifacts

`maps_to_artifact` should be optional.

It links attacker-side effects to expected defender-side artifact names.

Example:

```json
{
  "effect_type": "ssh_login_succeeded",
  "maps_to_artifact": "ssh_key_login"
}
```

Important:

```text
maps_to_artifact means the attacker-side effect is related to that defender artifact.
It does not mean the defender observed that artifact.
```

---

## 13. Scenario Examples

### 13.1 scenario_005

Scenario:

```text
SSH authorized_keys persistence reuse
```

Expected artifact:

```text
ssh_key_login
```

Possible observed effect:

```json
{
  "effect_id": "effect-001",
  "effect_type": "ssh_login_succeeded",
  "status": "observed",
  "confidence": "medium",
  "maps_to_artifact": "ssh_key_login",
  "evidence": [
    {
      "type": "exit_code",
      "value": "0",
      "source": "attack_execution_log.events"
    }
  ]
}
```

### 13.2 scenario_006

Scenario:

```text
SSH key login followed by command execution
```

Expected artifacts:

```text
ssh_key_login
process_exec
```

Possible observed effects:

```json
[
  {
    "effect_id": "effect-001",
    "effect_type": "ssh_login_succeeded",
    "status": "observed",
    "confidence": "medium",
    "maps_to_artifact": "ssh_key_login"
  },
  {
    "effect_id": "effect-002",
    "effect_type": "payload_execution_succeeded",
    "status": "observed",
    "confidence": "medium",
    "maps_to_artifact": "process_exec",
    "evidence": [
      {
        "type": "stdout",
        "value": "[payload] executed",
        "source": "attack_execution_log.events"
      }
    ]
  }
]
```

---

## 14. Relationship to Shell Backend

The shell backend should not directly overinterpret every stdout line.

Current flow:

```text
shell runner
  ↓
attack_execution_log.json
  ↓
observed-effects extractor
  ↓
attack_observed_effects.json
```

This keeps raw execution capture separate from interpreted attacker-side observations.

Current observed-effects extraction precedence is:

```text
valid execution_log.structured_events
  ↓ fallback
structured runner events parsed from ATTACK_EVENT_JSON stdout lines
  ↓ fallback
legacy stdout marker parsing
  ↓ fallback
exit-code-based weak inference
```

`attack_execution_log.json` keeps `structured_events` additive. Direct
structured-event preference does not replace raw execution events, stdout, or
stderr.

---

## 15. Relationship to Evaluation

Evaluation can compare three layers through additive `observed_effects_alignment`:

```text
expected artifacts
  vs
attacker-side observed effects
  vs
defender-side observed artifacts
```

Example matrix:

| Layer | Example |
|---|---|
| Expected | `process_exec` |
| Attacker observed | `payload_execution_succeeded` |
| Defender observed | `process_exec` |

This allows more nuanced results:

- attack failed and detection absent
- attack succeeded but detection absent
- attack succeeded and detection present
- attack unclear but detection present
- attacker claimed success but defender evidence contradicts or lacks support

The alignment section is additive. It does not change `overall_result`,
`detected`, or existing verdict behavior.

---

## 16. Validation Policy

`attack_observed_effects.json` validates against:

```text
schemas/attack_observed_effects.schema.json
```

Validation is intentionally limited to:

- top-level required fields
- effect list shape
- allowed status values
- allowed confidence values
- evidence list shape

Do not overfit the first schema to scenario_006 only.

---

## 17. Out of Scope

The following remain out of scope for the observed-effects contract:

- autonomous planning
- attacker-side scoring
- guaranteed defender-side coverage
- automatic claim truth validation
- multi-host effect graphs
- long-term attacker memory
- exploit success grading
- automatic promotion decisions
- direct case timeline modification

---

## 18. Implementation Status and Follow-Ons

Completed:

1. Add this contract document
2. Add `schemas/attack_observed_effects.schema.json`
3. Add unit tests with synthetic scenario_005 / 006 examples
4. Add observed-effects generation for attacker-agent shell execution evidence
5. Keep process pipeline verdict behavior unchanged
6. Add additive `observed_effects_alignment` to `evaluation_result.json`
7. Add Rule Improvement review signals without auto-populating
   `rule_candidates.yaml`

Follow-ons:

1. Add richer observed-effect sources only when new scenario families need them
2. Convert observed-effects signals to rule or prompt candidates only through a
   reviewer-approved workflow

---

## 19. Current Done Criteria

Current implementation is done for the scenario_004 / 005 / 006 / 007 shell-runner
path when:

- `attack_observed_effects.schema.json` exists
- synthetic examples validate
- attacker-agent can generate `attack_observed_effects.json`
- scenario_004 / 005 / 006 / 007 shell execution can produce or derive observed
  effects
- structured runner events are supported while legacy stdout marker / exit-code
  fallback remains compatible
- observed effects remain separate from defender-side artifacts
- evaluation alignment remains additive and does not change `overall_result` or
  `detected`
- Rule Improvement signals remain review-only and do not auto-populate
  `rule_candidates.yaml`
- docs clarify the attacker-side / defender-side boundary

---

## 20. One-Line Summary

```text
`attack_observed_effects.json` records what the attacker side observed, while `evaluation_result.json` decides whether the defender side observed the expected artifacts.
```
