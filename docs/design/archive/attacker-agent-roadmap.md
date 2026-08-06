# Attacker Agent Roadmap

> [!IMPORTANT]
> This document is an archived attacker-agent planning snapshot from an earlier
> stage of the project. It is retained for historical design context and is not
> the current source of truth for implementation status, priorities, sequencing,
> or Done Criteria.
>
> Refer to [the main Roadmap](../../roadmap/roadmap.md) for current status and
> priorities, and to [the current attacker-agent design documents](../attacker-agent/)
> for current contracts and design boundaries.
>
> The Phase A-I labels in this document are historical attacker-subsystem phases,
> not the canonical project-wide Phase 0-8 roadmap.
>
> Archived: 2026-08-03

## 1. Goal

The attacker-agent evolves the lab from manually triggered scenario execution into a common attack execution foundation that can support:

1. reproducible scenario-based evaluation
2. richer attack artifacts
3. TTP composition
4. future autonomous recon-to-action experiments
5. assessment-mode safety boundaries

The primary goal is not autonomy first. The primary goal is to keep Scenario Mode, TTP Composition Mode, and future Autonomous Mode comparable through the same attack contracts and run artifacts.

```text
scenario / objective
  ↓
attacker-agent
  ↓
attack_result / attack_execution_log / attack_observed_effects
  ↓
observed_effects_alignment
  ↓
defense pipeline
  ↓
evaluation / compare / judge
```

---

## 2. Current State

The attacker-agent is no longer only a legacy step executor.

Current implementation status:

- Phase A dispatcher skeleton is implemented
- scenario loader / validator / backend selector are separated
- step backend and shell backend are available
- shell runner scenarios are first-class
- scenario contract tests exist
- `attack_scenario.schema.json` exists
- `docs/design/attacker-agent/scenario_schema.md` exists
- scenario_004 / 005 / 006 have been migrated to `attack_scenario_v1`
- schema-v1 scenarios are validated at load time
- legacy scenarios without `schema_version` remain compatible
- `attack_result.json` includes schema-derived metadata

Current schema-v1 scenarios:

- `scenario_004`: SSH brute force to authorized_keys persistence
- `scenario_005`: SSH authorized_keys persistence reuse
- `scenario_006`: SSH key login followed by command execution

Current `attack_result.json` bridge fields:

- `scenario_name`
- `schema_version`
- `primary_artifact`
- `artifacts_expected`
- `expected_artifacts`
- `techniques`
- `state_changing`

Current Phase C artifact schema status:

- `attack_result.schema.json` exists
- `attack_execution_log.schema.json` exists
- `attack_observed_effects.schema.json` exists
- attacker-agent `attack_result.json` validates against `attack_result.schema.json`
- attacker-agent `attack_execution_log.json` validates against `attack_execution_log.schema.json`
- synthetic scenario_005 / scenario_006 observed-effects examples validate against `attack_observed_effects.schema.json`
- process pipeline minimal `attack_result.json` is aligned with `attack_result.schema.json`
- attacker-agent generates `attack_observed_effects.json`
- shell backend preserves `stdout` / `stderr` in `attack_execution_log.json`
- `attack_execution_log.json` includes additive `structured_events` when valid
  `ATTACK_EVENT_JSON:` lines are present
- scenario_004 execute confirms observed effects for:
  - `ssh_bruteforce_attempted` -> `ssh_failed_login`
  - `ssh_login_succeeded` -> `ssh_success_login`
  - `authorized_keys_write_succeeded` -> `authorized_keys_modification`
- scenario_005 execute confirms:
  - `ssh_login_succeeded` -> `ssh_key_login`
- scenario_006 execute confirms:
  - `ssh_login_succeeded` -> `ssh_key_login`
  - `payload_execution_succeeded` -> `process_exec`
- evaluation_result includes additive `observed_effects_alignment`
- scenario_004 evaluation alignment confirms:
  - `ssh_failed_login` -> `attacker_and_defender_observed`
  - `ssh_success_login` -> `attacker_and_defender_observed`
  - `authorized_keys_modification` -> `attacker_and_defender_observed`
- scenario_005 evaluation alignment confirms:
  - `ssh_key_login` -> `attacker_and_defender_observed`
- scenario_006 evaluation alignment confirms:
  - `ssh_key_login` -> `attacker_and_defender_observed`
  - `process_exec` -> `attacker_and_defender_observed`
- observed-effects alignment does not change `overall_result` or `detected`
- structured runner output contract exists
- attacker artifact catalog documents scenario family / event / artifact mappings
- defender coverage matrix maps scenario_004 through scenario_008 artifacts to telemetry, pivots, and gaps
- endpoint telemetry coverage design identifies auditd, Wazuh, osquery, and Velociraptor needs for post-login artifacts
- auditd minimal coverage design scopes the first endpoint telemetry collection layer for current post-login artifacts
- auditd smoke checklist defines future manual validation for auditd endpoint telemetry
- lab-scoped auditd minimal rules exist for first-pass endpoint telemetry validation
- artifact catalog documents implemented `scenario_008_ssh_key_system_discovery` coverage
- structured runner event parser exists
- scenario_004 / 005 / 006 / 007 / 008 runners emit `ATTACK_EVENT_JSON:` events
- `attack_observed_effects.json` prefers structured runner events when present
- legacy stdout marker / exit-code fallback remains compatible
- shell backend static contract tests enforce runner path shape, executable bit,
  positive integer `timeout_seconds`, boolean `state_changing`, and inline shell
  field boundaries
- `docs/operations/smoke_runbook.md` documents structured runner and
  observed-effects smoke checks
- scenario_006 suppresses the repeated SSH known-host warning in stderr
- Rule Improvement review signal contract exists for observed-effects alignment gaps
- Rule Improvement Agent can generate `observed_effects_alignment_signals.json`
  from `evaluation_result.observed_effects_alignment`
- `candidate_review.md` surfaces observed-effects alignment signals for human review
- observed-effects alignment signals do not automatically populate `rule_candidates.yaml`
  or change `promotion_recommendation.yaml`
- observed-effects signal generation does not change `overall_result` or `detected`

---

## 3. Design Principles

### 3.1 Scenario-first, then autonomy

Static, reproducible scenarios remain the foundation.

Autonomous modes should reuse the same contract and artifacts rather than bypassing them.

### 3.2 Compare-ready artifacts first

The attacker-agent should produce artifacts that can be compared with defender-side detections, incidents, evaluations, investigations, and action plans.

### 3.3 One contract, multiple modes

Scenario Mode, TTP Composition Mode, and Autonomous Mode should share the same artifact model.

### 3.4 Planner and executor separation

Future planners must not directly execute dangerous actions.

Planning, supervision, approval, and execution should remain separable.

### 3.5 Optional external tools

Atomic Red Team and Caldera are optional backends or comparison targets. They should not become the core contract.

---

## 4. Target Architecture

```text
attack_request
  ↓
scenario / objective loader
  ↓
planner or scenario resolver
  ↓
attack_plan
  ↓
backend selector
    ├─ step_backend
    ├─ shell_backend
    ├─ atomic_backend      optional
    ├─ caldera_backend     later / optional
    └─ autonomous_backend  later
  ↓
execution supervisor
  ↓
attack_result
  ↓
attack_execution_log
  ↓
attack_observed_effects
  ↓
run artifacts / evaluation / compare
```

---

## 5. Current Artifact Set

Implemented:

```text
attack_result.json
attack_execution_log.json
attack_observed_effects.json
```

Partially enriched:

```text
attack_result.json
  scenario_name
  schema_version
  primary_artifact
  artifacts_expected
  expected_artifacts
  techniques
  state_changing
```

Future:

```text
attack_request.json
attack_plan.json
```

`attack_observed_effects.json` now represents attacker-side observed facts for shell-backed scenario execution. It prefers structured runner events when present and falls back to legacy stdout / exit-code evidence for scenarios that have not migrated yet.

---

## 6. Phase Plan

## Phase A — Dispatcher

### Status

Complete.

### Implemented

- `main.py` dispatcher skeleton
- `scenario_loader.py`
- `scenario_validator.py`
- `backend_selector.py`
- `backends/step_backend.py`
- `backends/shell_backend.py`
- runner-based shell backend execution
- deterministic backend selection
- scenario contract tests
- `attack_result.json`
- `attack_execution_log.json`

### Notes

Phase A intentionally did not introduce autonomy, planner logic, or rich artifacts. It created the stable execution boundary.

---

## Phase B — Scenario Schema Unification

### Status

Complete for scenario_004 / 005 / 006.

### Implemented

- `schemas/attack_scenario.schema.json`
- `docs/design/attacker-agent/scenario_schema.md`
- migration of scenario_004 / 005 / 006 to `attack_scenario_v1`
- runtime schema validation for `schema_version: attack_scenario_v1`
- compatibility mapping:
  - `scenario_name` → runtime `name`
  - `techniques` → runtime `mitre_attack`
  - `artifacts_expected` → runtime `expected_artifacts`
- legacy scenarios without `schema_version` remain supported

### Done Criteria

Completed:

- new scenario schema exists
- canonical fields are documented
- scenario_004 / 005 / 006 are migrated
- schema-v1 scenarios fail early on invalid YAML shape
- old-style scenarios remain compatible through loader normalization

---

## Phase C — Rich Attack Artifacts

### Status

In progress. Phase C-1, Phase C-2 runtime generation, observed-effects alignment, scenario_004 / 005 / 006 structured runner event coverage, execution-log `structured_events`, shell backend static contract tests, smoke runbook documentation, and Rule Improvement review signal integration are complete.

### Goal

Make attack artifacts compare-ready and schema-validated.

Completed Phase C-1 scope:

1. added `attack_result.schema.json`
2. added `attack_execution_log.schema.json`
3. validated current attacker-agent outputs
4. aligned process pipeline minimal `attack_result.json` with `attack_result.schema.json`

Completed initial Phase C-2 schema scope:

1. added `attack_observed_effects.schema.json`
2. added synthetic scenario_005 / scenario_006 validation tests

Completed Phase C-2 runtime scope:

1. attacker-agent generates `attack_observed_effects.json`
2. shell backend preserves `stdout` / `stderr` in execution events
3. scenario_004 execute confirms:
   - `ssh_bruteforce_attempted` maps to `ssh_failed_login`
   - `ssh_login_succeeded` maps to `ssh_success_login`
   - `authorized_keys_write_succeeded` maps to `authorized_keys_modification`
4. scenario_005 execute confirms:
   - `ssh_login_succeeded` maps to `ssh_key_login`
5. scenario_006 execute confirms:
   - `ssh_login_succeeded` maps to `ssh_key_login`
   - `payload_execution_succeeded` maps to `process_exec`
6. additive `observed_effects_alignment` is integrated into `evaluation_result.json`
7. scenario_004 evaluation alignment confirms:
   - `ssh_failed_login` maps to `attacker_and_defender_observed`
   - `ssh_success_login` maps to `attacker_and_defender_observed`
   - `authorized_keys_modification` maps to `attacker_and_defender_observed`
8. scenario_005 evaluation alignment confirms:
   - `ssh_key_login` maps to `attacker_and_defender_observed`
9. scenario_006 evaluation alignment confirms:
   - `ssh_key_login` maps to `attacker_and_defender_observed`
   - `process_exec` maps to `attacker_and_defender_observed`
10. existing evaluation verdict behavior remains unchanged
11. structured runner output contract is documented
12. parser helper and parser tests exist for `ATTACK_EVENT_JSON:` lines
13. scenario_004 / 005 / 006 emit structured runner events for current observed-effect mappings
14. attacker-agent prefers structured runner events when building `attack_observed_effects.json`
15. legacy stdout marker / exit-code fallback remains available
16. scenario_006 suppresses repeated SSH known-host warning noise in stderr
17. Rule Improvement Agent can generate `observed_effects_alignment_signals.json`
    from `evaluation_result.observed_effects_alignment`
18. `candidate_review.md` surfaces observed-effects alignment signals for human review
19. observed-effects signals remain separate from automatic rule candidate generation
20. `attack_execution_log.json` includes additive `structured_events` while preserving raw stdout / stderr and execution events
21. shell backend static contract tests enforce runner path, executable bit, timeout / `state_changing` shape, and inline shell field boundaries
22. smoke runbook documents structured runner and observed-effects checks

Next Phase C scope:

1. keep observed-effects alignment signals human-reviewable and avoid automatic candidate promotion
2. maintain scenario_004 / 005 / 006 structured runner event coverage and extend only for new scenario families if useful
3. keep shell backend safety and runner output policies aligned with observed-effects design
4. avoid expanding into autonomous planning before artifact contracts are stable

### Candidate `attack_result.json` fields

Already present or partially present:

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

Future fields:

- `mode`
- `selected_techniques`
- `attempted_steps`
- `observed_effects_ref`
- `evidence_level`
- `blocked_actions`
- `safety_decisions`
- `coverage_claim`
- `novelty_flags`
- `failure_reason`

### Current `attack_execution_log.json` fields

Current schema-backed output supports:

- `attack_id`
- `scenario_id`
- `backend`
- `started_at`
- `ended_at`
- `status`
- `events`
- additive `structured_events` when valid `ATTACK_EVENT_JSON:` lines are present
- per-event `event_type`
- per-event `runner_path`
- per-event `exit_code`
- per-event raw `stdout`
- per-event raw `stderr`

Future runtime enrichments may add per-event `failure_reason` and stdout / stderr
file references for very large streams.

### Done Criteria

Completed for Phase C-1:

- `attack_result.schema.json` exists
- `attack_execution_log.schema.json` exists
- current shell backend output validates
- process pipeline minimal `attack_result.json` validates
- compatibility with downstream pipeline is preserved

Completed for initial Phase C-2 schema step:

- `attack_observed_effects.schema.json` exists
- synthetic scenario_005 observed-effects example validates
- synthetic scenario_006 observed-effects example validates
- invalid observed-effect status is rejected

Completed for Phase C-2 runtime generation:

- attacker-agent generates `attack_observed_effects.json`
- shell backend includes `stdout` and `stderr` in execution events
- generated observed effects remain schema-compatible
- scenario_004 execution derives:
  - `ssh_bruteforce_attempted` from Hydra / brute-force stdout evidence
  - `ssh_login_succeeded` from valid-credential stdout evidence
  - `authorized_keys_write_succeeded` from authorized_keys persistence stdout evidence
- scenario_005 execution derives:
  - `ssh_login_succeeded` from SSH key reuse execution evidence
- scenario_006 execution derives:
  - `ssh_login_succeeded` from shell execution evidence
  - `payload_execution_succeeded` from payload stdout marker

Completed for observed-effects evaluation alignment:

- `evaluation_result.json` includes additive `observed_effects_alignment`
- attacker-side observed effects are compared with defender-side observed artifacts
- attacker-side observations are not treated as defender-side detections
- existing `overall_result`, `detected`, and coverage behavior remains backward compatible
- scenario_004 smoke check confirms:
  - `ssh_failed_login` -> `attacker_and_defender_observed`
  - `ssh_success_login` -> `attacker_and_defender_observed`
  - `authorized_keys_modification` -> `attacker_and_defender_observed`
- scenario_005 smoke check confirms:
  - `ssh_key_login` -> `attacker_and_defender_observed`
- scenario_006 smoke check confirms:
  - `ssh_key_login` -> `attacker_and_defender_observed`
  - `process_exec` -> `attacker_and_defender_observed`


Completed for structured runner output coverage:

- `docs/design/attacker-agent/structured_runner_output_contract.md` exists
- `scripts/structured_runner_events.py` parses `ATTACK_EVENT_JSON:` stdout lines
- parser tests cover valid / invalid / mixed stdout cases
- scenario_004 / 005 / 006 / 007 / 008 emit structured runner events for current observed-effect mappings
- `attack_observed_effects.json` prefers structured runner events when present
- legacy stdout marker / exit-code fallback remains compatible
- shell backend static contract tests enforce runner path shape, executable bit,
  positive integer `timeout_seconds`, boolean `state_changing`, and inline shell
  field boundaries
- `docs/operations/smoke_runbook.md` documents structured runner and
  observed-effects smoke checks
- scenario_006 suppresses repeated SSH known-host warning noise in stderr

Completed for observed-effects Rule Improvement review signal:

- `docs/design/rule-improvement/observed_effects_alignment_signal_contract.md` exists
- Rule Improvement Agent can generate `observed_effects_alignment_signals.json`
  from `evaluation_result.observed_effects_alignment`
- `candidate_review.md` includes observed-effects alignment signals for human review
- observed-effects signals are review inputs and not automatically promotable rule candidates
- `rule_candidates.yaml`, `promotion_recommendation.yaml`, `overall_result`, and `detected`
  behavior remain unchanged by observed-effects signal generation

Still future:

- runtime shell backend allowlist / approval enforcement beyond the current static tests
- structured event emission is extended to additional scenario families only when useful
- reviewer-approved conversion from observed-effects signals to concrete rule or prompt candidates

---

## Phase D — Shell Backend Formalization

### Status

Future for runtime safety and approval formalization. Static contract enforcement
for scenario_004 / 005 / 006 is already in place.

### Goal

Make shell runner execution a formal runtime backend contract.

Scope:

- stdout / stderr capture policy
- runner env contract
- output file contract
- retry policy
- timeout policy
- state-changing classification
- shell backend safety policy

This phase should come after attack artifact schemas are stable.

---

## Phase E — TTP Catalog

### Status

Future.

### Goal

Extract reusable attack building blocks from existing scenarios.

Initial catalog candidates:

- `bruteforce_ssh`
- `ssh_password_login`
- `authorized_keys_persistence`
- `ssh_key_login_reuse`
- `post_login_command_execution`

Each TTP should define:

- preconditions
- required tools
- safety level
- expected artifacts
- success evidence

---

## Phase F — Atomic Backend

### Status

Optional future.

Atomic Red Team can be introduced as an optional backend after the lab's own contracts are stable.

---

## Phase G — TTP Composition Mode

### Status

Future.

Generate an `attack_plan.json` from objectives and constraints.

Planner can be rule-based initially.

---

## Phase H — Autonomous Planner + Supervisor

### Status

Later.

Autonomous mode should not be introduced until scenario / artifact / safety contracts are stable.

---

## Phase I — Assessment Mode

### Status

Later.

Assessment Mode should support:

- read-only
- validation-only
- approval-required
- blocked actions
- budget limits
- operator override
- reporting-first mode

---

## 7. File / Doc Plan

Existing:

```text
docs/design/archive/attacker-agent-roadmap.md
docs/design/attacker-agent/scenario_schema.md
docs/design/attacker-agent/attack_artifact_contract.md
docs/design/attacker-agent/attack_observed_effects_contract.md
docs/design/attacker-agent/observed_effects_evaluation_contract.md
docs/design/attacker-agent/shell_backend_contract.md
docs/design/attacker-agent/structured_runner_output_contract.md
docs/design/rule-improvement/observed_effects_alignment_signal_contract.md
schemas/attack_scenario.schema.json
schemas/attack_result.schema.json
schemas/attack_execution_log.schema.json
schemas/attack_observed_effects.schema.json
```

Recommended next:

```text
Structured event coverage maintenance for scenario_004 / 005 / 006 / 007 / 008
Shell backend safety and runner output policy refinement
Reviewer-approved use of observed-effects signals for future candidate generation
```

Future:

```text
schemas/attack_request.schema.json
schemas/attack_plan.schema.json
docs/design/attacker-agent/ttp_catalog.md
docs/design/attacker-agent/atomic_backend_integration.md
docs/design/attacker-agent/ttp_composition_mode.md
docs/design/attacker-agent/autonomous_mode.md
docs/design/attacker-agent/assessment_mode.md
```

---

## 8. Recommended Priority

### Immediate

1. Keep observed-effects alignment signals review-only unless a human classifies the gap
2. Keep shell backend safety and runner output policies aligned with observed-effects design
3. Maintain structured event coverage for scenario_004 / 005 / 006 / 007 / 008 and extend only for new scenario families if useful

### Next

4. Extend observed-effects runtime / alignment coverage only when new scenarios introduce new artifact families
5. Define TTP catalog candidates only after artifact contracts remain stable
6. Keep autonomous planning out of scope until scenario, artifact, and safety contracts are stable

### Later

7. TTP catalog
8. TTP composition mode
9. Atomic backend if useful
10. Autonomous planner / supervisor
11. Assessment mode

---

## 9. Final Recommendation

The attacker-agent has completed the important transition from ad hoc scenario execution to schema-backed scenario execution.

The next step should not be autonomy.

The next step should build on the current artifact contracts:

```text
attack_scenario_v1
  ↓
attack_result.schema.json              complete
  ↓
attack_execution_log.schema.json       complete
  ↓
attack_observed_effects.schema.json    complete
  ↓
attack_observed_effects.json runtime   complete
  ↓
observed_effects_alignment             complete
  ↓
scenario-wide alignment smoke checks   complete
  ↓
structured runner event coverage       complete
  ↓
execution-log structured_events        complete
  ↓
shell backend static contract tests    complete
  ↓
RI review signal                       complete
  ↓
shell backend runtime formalization    future
```

Only after these artifacts are stable should the project move toward TTP cataloging, composition, or autonomous execution.
