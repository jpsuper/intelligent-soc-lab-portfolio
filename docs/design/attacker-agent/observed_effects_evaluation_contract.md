# Observed Effects Evaluation Contract

## 1. Purpose

This document defines how `attack_observed_effects.json` should be used by future evaluation logic.

The goal is to compare attacker-side observed effects with defender-side observed artifacts without confusing the two.

The key rule is:

```text
attacker-side observed effect != defender-side observed artifact
```

This document originally defined the design contract. The first additive implementation is now present in the minimal process-pipeline evaluation result.

The implementation adds `observed_effects_alignment` without changing existing evaluation verdict behavior.

---

## 2. Background

The attacker-agent can now produce:

```text
attack_result.json
attack_execution_log.json
attack_observed_effects.json
```

`attack_observed_effects.json` records what the attacker side observed during execution.

Examples:

```text
ssh_bruteforce_attempted        -> ssh_failed_login
ssh_login_succeeded             -> ssh_success_login / ssh_key_login
authorized_keys_write_succeeded -> authorized_keys_modification
payload_execution_succeeded     -> process_exec
```

These observations are useful for evaluation, but they are not defender-side detections.

---

## 3. Current Coverage

Current observed-effects runtime coverage exists for scenario_004 / 005 / 006.

### scenario_004

```text
ssh_bruteforce_attempted        -> ssh_failed_login
ssh_login_succeeded             -> ssh_success_login
authorized_keys_write_succeeded -> authorized_keys_modification
```

### scenario_005

```text
ssh_login_succeeded             -> ssh_key_login
```

### scenario_006

```text
ssh_login_succeeded             -> ssh_key_login
payload_execution_succeeded     -> process_exec
```

---

## 4. Three-Layer Evaluation Model

Evaluation should compare three distinct layers.

```text
expected artifacts
  vs
attacker-side observed effects
  vs
defender-side observed artifacts
```

### 4.1 Expected artifacts

Expected artifacts come from the scenario / attack result.

Examples:

```text
attack_result.expected_artifacts
attack_result.artifacts_expected
```

These represent what the scenario expects the defense pipeline to observe.

### 4.2 Attacker-side observed effects

Attacker-side observed effects come from:

```text
attack_observed_effects.json
```

They represent what the attacker runner believes happened.

### 4.3 Defender-side observed artifacts

Defender-side observed artifacts come from detection, correlation, incident, investigation, or case artifacts.

Examples:

```text
dsl_detection_outputs_*.json
dsl_correlations.json
incident.json
investigation_result.json
case.json
```

These represent what the defense pipeline actually observed.

---

## 5. Correct Interpretation

Correct interpretation:

```text
attacker observed payload execution
  +
defender observed process_exec
  =
strong end-to-end confirmation
```

Incorrect interpretation:

```text
attacker observed payload execution
  =
defender detected process_exec
```

Attacker-side observed effects can support evaluation context, but they must not be counted as defender-side coverage.

---

## 6. Implemented Evaluation Output Shape

The minimal process-pipeline evaluation now adds an `observed_effects_alignment` section.

Example:

```json
{
  "observed_effects_alignment": {
    "status": "complete",
    "items": [
      {
        "expected_artifact": "process_exec",
        "attacker_effect": "payload_execution_succeeded",
        "attacker_status": "observed",
        "defender_observed": true,
        "defender_sources": [
          "dsl_detection_outputs_process.json",
          "process_chain_hits.json"
        ],
        "alignment": "attacker_and_defender_observed"
      }
    ]
  }
}
```

This section is additive.

It does not replace existing evaluation result fields and does not change `overall_result`, `detected`, or existing coverage fields.

---

## 7. Alignment States

Recommended alignment states:

| State | Meaning |
|---|---|
| `attacker_and_defender_observed` | Attacker observed the effect and defender observed the mapped artifact |
| `attacker_observed_defender_missing` | Attacker observed the effect but defender did not observe the mapped artifact |
| `defender_observed_attacker_missing` | Defender observed the artifact but attacker-side observed effect is missing |
| `expected_but_not_observed` | Expected artifact was not observed by either side |
| `not_applicable` | No mapping is available or artifact is not part of this comparison |

---

## 8. Example Matrix

### scenario_006

```text
expected_artifact: ssh_key_login
attacker_effect:   ssh_login_succeeded
defender_artifact: ssh_key_login
alignment:         attacker_and_defender_observed

expected_artifact: process_exec
attacker_effect:   payload_execution_succeeded
defender_artifact: process_exec
alignment:         attacker_and_defender_observed
```

### defender gap example

```text
expected_artifact: process_exec
attacker_effect:   payload_execution_succeeded
defender_artifact: missing
alignment:         attacker_observed_defender_missing
```

This is the most useful gap state for detection engineering.

It means:

```text
the attack appears to have succeeded,
but the defender pipeline did not observe the expected artifact.
```

---

## 9. Source Priority

### 9.1 Attacker-side sources

Attacker-side sources may include:

- `attack_observed_effects.json`
- `attack_execution_log.json`
- `attack_result.json`

### 9.2 Defender-side sources

Defender-side sources may include:

- `dsl_detection_outputs_*.json`
- `dsl_correlations.json`
- `incident.json`
- `investigation_result.json`
- `case.json`
- `evaluation_result.json`

The evaluation layer should clearly label which side each source belongs to.

---

## 10. Mapping Policy

Mappings should be based on `maps_to_artifact` in each observed effect.

Example:

```json
{
  "effect_type": "payload_execution_succeeded",
  "maps_to_artifact": "process_exec"
}
```

The evaluation should use this as a relationship hint, not proof of defender coverage.

Policy:

```text
maps_to_artifact links an attacker-side effect to an expected defender-side artifact.
It does not mean the defender observed that artifact.
```

---

## 11. Confidence Policy

Attacker-side confidence and defender-side confidence should remain separate.

Example:

```text
attacker confidence: medium
defender confidence: high
```

Do not collapse these into a single score too early.

A future evaluator may compute an alignment confidence, but it should preserve source-specific confidence.

---

## 12. First Implementation Status

The first implementation is complete for the minimal process-pipeline evaluation path.

Implemented scope:

1. Load `attack_result.json`
2. Load `attack_observed_effects.json` if present in the run directory
3. Use existing defender-side observed artifacts from current evaluation inputs
4. Build an additive `observed_effects_alignment` section
5. Preserve existing pass/fail behavior

Still out of scope:

- changing final evaluation verdict
- modifying case timeline
- treating attacker observations as defender detections
- autonomous remediation
- TTP scoring
- multi-host effect graphs

---

## 13. Initial Algorithm

Pseudo-flow:

```text
expected_artifacts = attack_result.expected_artifacts

attacker_effects_by_artifact =
  group attack_observed_effects.effects by maps_to_artifact

defender_observed_artifacts =
  derive from existing detection / correlation / investigation artifacts

for each expected_artifact:
  attacker_effect = attacker_effects_by_artifact.get(expected_artifact)
  defender_observed = expected_artifact in defender_observed_artifacts

  classify alignment
```

Classification:

```text
if attacker observed and defender observed:
  attacker_and_defender_observed

if attacker observed and defender missing:
  attacker_observed_defender_missing

if attacker missing and defender observed:
  defender_observed_attacker_missing

if both missing:
  expected_but_not_observed
```

---

## 14. Relationship to Rule Improvement

The most important value is detection gap discovery.

Useful improvement signals:

```text
attacker_observed_defender_missing
```

This state may indicate:

- missing detection rule
- insufficient telemetry
- parser gap
- correlation gap
- investigation enrichment gap
- expected artifact mismatch

This should feed Rule Improvement Agent only after human-reviewable evidence is preserved.

---

## 15. Relationship to Case and Action

`case.json` and `action_result.json` may use observed-effects alignment as context later.

However:

```text
action planning should remain grounded in defender-side evidence.
```

Attacker-side effects can support reasoning, but action should not be triggered solely by attacker-side claims.

---

## 16. Relationship to Harness / Judge

Future harness comparisons may use observed-effects alignment to judge whether a candidate pipeline improves coverage.

Possible rubric dimensions:

- expected artifact coverage
- attacker / defender alignment
- gap explanation quality
- overclaim control
- evidence grounding

The judge should penalize any candidate that treats attacker-side observations as defender-side detections.

---

## 17. Failure Modes to Avoid

Avoid these failure modes:

1. Counting `attack_observed_effects.json` as detection evidence
2. Treating `maps_to_artifact` as proof of defender coverage
3. Collapsing attacker and defender confidence into one untraceable score
4. Adding observed effects directly into case timeline as defender events
5. Triggering response action solely from attacker-side observations
6. Hiding missing defender telemetry behind successful attacker execution

---

## 18. Done Criteria for First Implementation

Completed:

- evaluation can load `attack_observed_effects.json`
- evaluation can produce `observed_effects_alignment`
- scenario_004 / 005 / 006 can be represented
- attacker-only observations do not count as defender coverage
- defender-only observations remain distinguishable
- existing evaluation behavior remains backward compatible
- tests cover:
  - attacker and defender both observed
  - attacker observed but defender missing
  - defender observed but attacker missing
  - neither side observed
  - scenario_004 all-observed alignment

Confirmed runtime smoke check:

```text
scenario_004:
  ssh_failed_login             -> attacker_and_defender_observed
  ssh_success_login            -> attacker_and_defender_observed
  authorized_keys_modification -> attacker_and_defender_observed

scenario_005:
  ssh_key_login                -> attacker_and_defender_observed

scenario_006:
  ssh_key_login -> attacker_and_defender_observed
  process_exec  -> attacker_and_defender_observed
```

---

## 19. Recommended Next PR

The additive `observed_effects_alignment` implementation is complete.

Recommended next PR:

```text
docs: update observed effects evaluation alignment progress
```

Possible future implementation follow-ups:

```text
- add structured runner output convention if stdout parsing becomes fragile
- feed attacker_observed_defender_missing into Rule Improvement Agent as a reviewable signal
- keep case/action integration out of scope until alignment semantics are stable
- extend smoke checks only when new scenario families introduce new artifact mappings
```

---

## 20. One-Line Summary

```text
Evaluation may compare attacker-side observed effects with defender-side observed artifacts, but it must never treat attacker observations as defender detections.
```
