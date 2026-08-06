# Attack Artifact Contract

## 1. Purpose

This document defines the common attacker-side run artifact boundaries used by
the lab:

- `attack_result.json` summarizes the run outcome;
- `attack_execution_log.json` records execution activity and provenance; and
- `attack_observed_effects.json` records attacker-side observations without
  becoming defender telemetry or detection evidence.

`attack_request.json`, `attack_plan.json`, TTP catalogs, and autonomous
planning require separate contracts before they can enter this boundary.

The key design rule is:

```text
execute a bounded scenario
  ↓
record traceable attacker-side artifacts
  ↓
compare attacker observations with independent defender evidence
```

---

## 2. Contract And Status Ownership

This document owns the shared identity, status, traceability, and separation
rules for attacker-side run artifacts. Detailed observed-effects semantics
belong in
[`attack_observed_effects_contract.md`](attack_observed_effects_contract.md),
and shell execution boundaries belong in
[`shell_backend_contract.md`](shell_backend_contract.md).

The [Main Roadmap](../../roadmap/roadmap.md) and
[Phase 6](../../roadmap/phase6.md) own current implementation status, validation
depth, priorities, and sequencing. The presence of an artifact in this contract
does not authorize autonomous planning or make attacker-side evidence a
defender-side result.

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

Defined producers:

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

Defined producers:

- attacker-agent

`attack_execution_log.json` is owned by the execution boundary. Other pipeline
stages must not synthesize it unless a separate producer contract defines
equivalent provenance and validation.

### 3.3 `attack_observed_effects.json`

`attack_observed_effects.json` represents attacker-side observed facts.

It records:

- what the attacker side believes succeeded;
- what attacker-side evidence supports that belief;
- which expected effects were or were not observed; and
- stable references used for later comparison with independent defender
  evidence.

It does not record defender detection, evaluation coverage, or an Incident
conclusion. Detailed fields and derivation rules belong in the dedicated
observed-effects contract.

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

## 8. Observed-Effects Separation

The artifact model must keep these meanings distinct:

- attacker-side observed success;
- defender-side telemetry and detection;
- scenario expected artifacts;
- evaluation coverage; and
- synthetic or fixture-generated evidence.

`attack_result.json`, `attack_execution_log.json`, and
`attack_observed_effects.json` therefore remain separate artifacts with
separate schemas and provenance. No attacker-side artifact proves that a
defender observed or detected an effect.

---

## 9. Validation Policy

The validation boundary is:

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

## 10. Out Of Scope

This contract does not define or authorize:

- autonomous attack planning;
- automatic TTP composition;
- Atomic Red Team or Caldera backends;
- attack-side security scoring;
- multi-host attacker orchestration;
- approval workflows for offensive actions;
- defender detection or Incident conclusions;
- detailed observed-effects evaluation; or
- shell-runner environment and execution policy.

The final two responsibilities remain in their dedicated attacker-agent
contracts rather than being duplicated here.

---

## 11. Extension Conditions

Extend the common artifact boundary only when a new attacker-side artifact:

1. has a dedicated schema or explicit validation contract;
2. preserves run, scenario, and execution provenance;
3. remains distinguishable from defender telemetry and detection;
4. has bounded fixture and runner validation;
5. does not authorize planning, execution, or state change by its presence; and
6. has its priority and completion tracked in the Roadmap.

---

## 12. One-Line Summary

```text
attack_result.json summarizes the run;
attack_execution_log.json records attacker-agent execution;
attack_observed_effects.json records attacker-side observations only.
```
