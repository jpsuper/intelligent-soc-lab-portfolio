# Attack Artifact Contract

## 1. Purpose

This document defines the current attacker-side artifact contract used by the lab.

The immediate goal is to make attacker-side outputs schema-backed and comparable without prematurely introducing autonomous attack behavior or rich observed-effects modeling.

Current scope:

- `attack_result.json`
- `attack_execution_log.json`

Future scope:

- `attack_observed_effects.json`
- `attack_request.json`
- `attack_plan.json`

The key design rule is:

```text
stabilize current artifacts first
  ↓
validate existing outputs
  ↓
then introduce richer observed effects
```

---

## 2. Current Status

The current Phase C-1 status is complete.

Implemented:

- `schemas/attack_result.schema.json`
- `schemas/attack_execution_log.schema.json`
- attacker-agent `attack_result.json` validation
- attacker-agent `attack_execution_log.json` validation
- process pipeline minimal `attack_result.json` alignment with `attack_result.schema.json`

Not implemented yet:

- `attack_observed_effects.json`
- `attack_request.json`
- `attack_plan.json`
- shell backend formal contract
- TTP catalog
- autonomous planner / supervisor

---

## 3. Artifact Overview

### 3.1 `attack_result.json`

`attack_result.json` is the canonical summary of an attack run or attack-like scenario execution.

It answers:

- which scenario was run
- which backend produced the result
- whether the run completed
- what artifacts were expected
- what scenario metadata was attached
- what steps were attempted at a high level

Current producers:

- attacker-agent
- process pipeline minimal artifact generation

### 3.2 `attack_execution_log.json`

`attack_execution_log.json` is the execution-oriented log for attacker-agent runs.

It answers:

- which backend executed the scenario
- which runner or step was invoked
- what event sequence occurred
- whether the runner completed
- what exit code was observed

Current producers:

- attacker-agent

The process pipeline does not need to generate `attack_execution_log.json` at this stage.

### 3.3 Future `attack_observed_effects.json`

`attack_observed_effects.json` will eventually represent attacker-side observed facts.

It should answer:

- what the attacker side believes succeeded
- what evidence supports that belief
- which expected effects were observed
- which expected effects were not observed
- how attacker-side observations compare with defender telemetry

This artifact is intentionally not introduced in Phase C-1.

---

## 4. `attack_result.json` Responsibility

`attack_result.json` is a run-level summary artifact.

It should be stable enough for downstream components to reference without knowing which attacker backend or pipeline produced it.

Minimum fields are defined by:

```text
schemas/attack_result.schema.json
```

Current important fields:

- `attack_id`
- `scenario_id`
- `scenario_name`
- `schema_version`
- `backend`
- `status`
- `started_at`
- `ended_at`
- `primary_artifact`
- `artifacts_expected`
- `expected_artifacts`
- `techniques`
- `state_changing`
- `steps`

Compatibility fields may exist:

- `attack_status`
- `target`

These remain for compatibility with older evaluation and pipeline logic.

### 4.1 `status` vs `attack_status`

`status` is the preferred canonical field.

`attack_status` is a compatibility field retained for older code paths.

Current policy:

```text
new readers should prefer status
old readers may still use attack_status
```

A later cleanup may deprecate `attack_status` once all readers have moved to `status`.

### 4.2 `artifacts_expected` vs `expected_artifacts`

Both fields currently exist.

- `artifacts_expected` follows `attack_scenario_v1`
- `expected_artifacts` is retained for older downstream compatibility

Current policy:

```text
write both fields
keep values aligned
```

A later cleanup can choose one canonical name, but not during Phase C-1.

---

## 5. `attack_execution_log.json` Responsibility

`attack_execution_log.json` records attacker-agent execution events.

It is not a replacement for `attack_result.json`.

It should contain execution-specific information that does not belong in the summary artifact.

Minimum fields are defined by:

```text
schemas/attack_execution_log.schema.json
```

Current important fields:

- `attack_id`
- `scenario_id`
- `backend`
- `started_at`
- `ended_at`
- `status`
- `events`

Event records may include:

- `event_type`
- `timestamp`
- `step_id`
- `runner_path`
- `command`
- `exit_code`
- `status`
- `message`

### 5.1 Process pipeline relationship

The process pipeline is primarily a defense-side orchestration pipeline.

It may create a minimal `attack_result.json` because downstream evaluation and case generation expect an attack summary.

It does not need to create `attack_execution_log.json` unless it starts executing attacker-side actions directly.

Current policy:

```text
attacker-agent:
  writes attack_result.json
  writes attack_execution_log.json

process pipeline:
  writes schema-compatible attack_result.json
  does not need attack_execution_log.json
```

---

## 6. Relationship to `attack_scenario_v1`

`attack_scenario_v1` is the scenario input contract.

`attack_result.json` is the run output contract.

The following fields should flow from scenario to result when available:

```text
attack_scenario_v1.schema_version -> attack_result.schema_version
scenario_id                       -> scenario_id
scenario_name                     -> scenario_name
primary_artifact                  -> primary_artifact
artifacts_expected                -> artifacts_expected / expected_artifacts
techniques                        -> techniques
runner.state_changing             -> state_changing
```

This keeps attack-side scenario metadata available to evaluation, case generation, action planning, and future compare logic.

---

## 7. Relationship to Defender-Side Artifacts

`attack_result.json` should remain useful to defender-side artifacts, but it should not duplicate their responsibilities.

### 7.1 `evaluation_result.json`

`evaluation_result.json` evaluates whether the expected artifacts were observed by the defender-side pipeline.

It should compare:

```text
attack_result.expected_artifacts
  vs
observed detection / correlation / investigation artifacts
```

### 7.2 `incident.json`

`incident.json` represents defender-side detection and correlation output.

It should not depend on attacker-agent internals.

### 7.3 `case.json`

`case.json` can reference attack metadata, but case timeline should remain defender-side canonical timeline.

### 7.4 `action_result.json`

`action_result.json` should plan response based on case, investigation, and evidence.

It may use attack metadata for context, but it should not treat attacker-side claims as confirmed defender-side facts.

---

## 8. Why `attack_observed_effects.json` Is Not First

`attack_observed_effects.json` is useful, but introducing it too early creates ambiguity.

Potential ambiguity:

- attacker-side observed success
- defender-side observed detection
- scenario expected artifact
- evaluation coverage
- process pipeline synthetic artifact

Phase C-1 intentionally avoids this ambiguity by first stabilizing:

```text
attack_result.json
attack_execution_log.json
```

Only after those are stable should the project introduce:

```text
attack_observed_effects.json
```

---

## 9. Validation Policy

Current validation policy:

```text
attack_result.schema.json
  validates attacker-agent output
  validates process pipeline minimal output

attack_execution_log.schema.json
  validates attacker-agent output
  process pipeline output is out of scope
```

Validation should remain part of attacker-agent tests.

Manual validation of generated artifacts is useful during development, but tests should remain the primary guardrail.

---

## 10. Out of Scope

The following are out of scope for the current contract:

- autonomous attack planning
- automatic TTP composition
- Atomic Red Team backend
- Caldera backend
- attack-side success scoring
- first-class observed effects
- multi-host attacker orchestration
- approval workflow for offensive actions
- shell runner environment contract

These should be introduced only after the current artifact contracts remain stable.

---

## 11. Next Steps

Recommended next steps:

1. Keep validating current `attack_result.json` and `attack_execution_log.json`
2. Add more tests only if scenario_004 / 005 / 006 expose schema gaps
3. Decide whether the next implementation target is:
   - shell backend contract, or
   - first-class `attack_observed_effects.json`
4. Add `attack_observed_effects.schema.json` only after its contract is clear
5. Avoid autonomous planning until scenario, artifact, and safety contracts are stable

---

## 12. One-Line Summary

```text
attack_result.json summarizes the attack run;
attack_execution_log.json records attacker-agent execution;
attack_observed_effects.json remains a future attacker-side evidence artifact.
```
