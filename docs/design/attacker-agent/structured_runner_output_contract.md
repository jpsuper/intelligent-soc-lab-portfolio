# Structured Runner Output Contract

## 1. Purpose

This document defines a minimal structured output convention for attacker-agent shell runners.

The goal is to reduce fragile stdout marker parsing while preserving the current shell-runner simplicity.

Observed effects are now derived from structured runner events when present, with legacy stdout marker parsing retained as a fallback.

Examples:

```text
[payload] executed
valid credential found
persistence execution finished
authorized_keys
```

This works for the current scenario_004 / 005 / 006 / 007 set, but it becomes fragile as scenarios grow.

The structured runner output convention introduces a small machine-readable event stream that shell runners may emit without requiring a full backend redesign.

---


## Implementation Status

Current implementation status:

- `docs/design/attacker-agent/structured_runner_output_contract.md` exists
- `docs/design/attacker-agent/artifact_catalog.md` documents canonical event / artifact mappings
- `scripts/structured_runner_events.py` parses `ATTACK_EVENT_JSON:` stdout lines
- parser tests cover valid, invalid, and mixed stdout cases
- scenario_004 / 005 / 006 / 007 emit structured events for current observed-effect mappings:
  - scenario_004: `ssh_bruteforce_attempted` -> `ssh_failed_login`
  - scenario_004: `ssh_login_succeeded` -> `ssh_success_login`
  - scenario_004: `authorized_keys_write_succeeded` -> `authorized_keys_modification`
  - scenario_005: `ssh_login_succeeded` -> `ssh_key_login`
  - scenario_006: `ssh_login_succeeded` -> `ssh_key_login`
  - scenario_006: `payload_execution_succeeded` -> `process_exec`
  - scenario_007: `ssh_login_succeeded` -> `ssh_key_login`
  - scenario_007: `suspicious_file_write_succeeded` -> `suspicious_file_write`
- attacker-agent `attack_observed_effects.json` generation prefers structured runner events when present
- attacker-agent `attack_execution_log.json` includes parsed `structured_events` as an
  additive top-level field when valid `ATTACK_EVENT_JSON:` lines are present
- `structured_events` preserves, and does not replace, raw `events[].stdout` /
  `events[].stderr` execution evidence
- legacy stdout marker / exit-code fallback remains for runners without structured events
- static shell backend contract tests enforce scenario runner path shape,
  executable runner files, timeout / `state_changing` field shape, and the
  boundary against inline shell fields in scenario YAML
- `docs/operations/smoke_runbook.md` documents structured runner and
  observed-effects smoke checks
- scenario_006 runner suppresses the noisy SSH known-host warning while preserving error-level SSH output

---

## 2. Design Goals

The convention should be:

1. incrementally adoptable
2. backward compatible with current stdout parsing
3. line-oriented and easy to emit from shell scripts
4. safe to parse without executing content
5. suitable for observed-effects generation
6. stable across scenario mode and future TTP composition mode

Non-goals:

- replacing `attack_execution_log.json`
- replacing human-readable stdout
- introducing autonomous planning
- changing evaluation verdict behavior
- coupling runner output directly to defender detections

---

## 3. Key Boundary

Structured runner output is attacker-side evidence.

```text
structured runner event != defender-side detection
```

A runner event may support `attack_observed_effects.json`.

It must not be treated as defender telemetry.

---

## 4. Recommended Format

Shell runners may emit line-delimited JSON events prefixed with a stable marker.

Recommended prefix:

```text
ATTACK_EVENT_JSON:
```

Each event line should be valid JSON after the prefix.

Example:

```text
ATTACK_EVENT_JSON: {"event_type":"ssh_login_succeeded","artifact":"ssh_key_login","status":"observed","confidence":"medium"}
```

Why prefix instead of raw JSON:

- keeps human-readable stdout possible
- makes extraction simple
- avoids parsing every stdout line as JSON
- keeps current runner style intact

---

## 5. Minimal Event Schema

Recommended fields:

```json
{
  "event_type": "ssh_login_succeeded",
  "artifact": "ssh_key_login",
  "status": "observed",
  "confidence": "medium",
  "technique": "T1078",
  "message": "SSH key login succeeded"
}
```

### Required fields

| Field | Type | Meaning |
|---|---|---|
| `event_type` | string | Attacker-side effect/event name |
| `artifact` | string | Expected defender-side artifact this maps to |
| `status` | string | `observed`, `not_observed`, `partial`, or `unknown` |

### Recommended fields

| Field | Type | Meaning |
|---|---|---|
| `confidence` | string | `low`, `medium`, or `high` |
| `technique` | string | MITRE ATT&CK technique ID |
| `message` | string | Human-readable short message |
| `target` | object | Optional target context |
| `evidence` | object | Optional compact evidence context |

---

## 6. Status Values

Recommended status values:

| Status | Meaning |
|---|---|
| `observed` | Runner observed the intended effect |
| `not_observed` | Runner attempted but did not observe the effect |
| `partial` | Runner completed partially or inferred a weak signal |
| `unknown` | Runner cannot determine the effect |

`failed` is not a structured runner event status. Runner failures should be represented as `not_observed`, `partial`, or `unknown` depending on attacker-side evidence.

---

## 7. Confidence Values

Recommended confidence values:

| Confidence | Meaning |
|---|---|
| `high` | Strong structured confirmation |
| `medium` | Expected runner output or command success supports the effect |
| `low` | Weak inference from successful runner exit or indirect marker |

Initial implementation can keep current `medium` confidence behavior.

---

## 8. Scenario Examples

### scenario_004

```text
ATTACK_EVENT_JSON: {"event_type":"ssh_bruteforce_attempted","artifact":"ssh_failed_login","status":"observed","confidence":"medium","technique":"T1110","message":"Hydra brute force attempt started"}
ATTACK_EVENT_JSON: {"event_type":"ssh_login_succeeded","artifact":"ssh_success_login","status":"observed","confidence":"medium","technique":"T1078","message":"Hydra found a valid SSH credential"}
ATTACK_EVENT_JSON: {"event_type":"authorized_keys_write_succeeded","artifact":"authorized_keys_modification","status":"observed","confidence":"medium","technique":"T1098","message":"authorized_keys persistence write completed"}
```

### scenario_005

```text
ATTACK_EVENT_JSON: {"event_type":"ssh_login_succeeded","artifact":"ssh_key_login","status":"observed","confidence":"medium","technique":"T1078","message":"SSH key persistence reuse succeeded"}
```

### scenario_006

```text
ATTACK_EVENT_JSON: {"event_type":"ssh_login_succeeded","artifact":"ssh_key_login","status":"observed","confidence":"medium","technique":"T1078","message":"SSH key login succeeded"}
ATTACK_EVENT_JSON: {"event_type":"payload_execution_succeeded","artifact":"process_exec","status":"observed","confidence":"medium","technique":"T1059","message":"Payload execution marker observed"}
```

### scenario_007

```text
ATTACK_EVENT_JSON: {"event_type":"ssh_login_succeeded","artifact":"ssh_key_login","status":"observed","confidence":"medium","technique":"T1078","message":"SSH key login succeeded"}
ATTACK_EVENT_JSON: {"event_type":"suspicious_file_write_succeeded","artifact":"suspicious_file_write","status":"observed","confidence":"medium","technique":"T1059","message":"Benign marker file write under /tmp succeeded"}
```

---

## 9. Relationship to attack_execution_log.json

The shell backend preserves raw stdout / stderr in execution events.

When valid `ATTACK_EVENT_JSON:` lines are present in stdout, attacker-agent also
adds parsed runner events to `attack_execution_log.json` as a top-level
`structured_events` field. This field is additive: it does not replace
`events`, does not remove raw stdout / stderr, and does not change
`attack_result.json` behavior.

Current execution-log shape:

```json
{
  "attack_id": "run-0033",
  "scenario_id": "scenario-006",
  "backend": "shell",
  "status": "completed",
  "events": [
    {
      "event_type": "runner_executed",
      "backend": "shell",
      "runner_path": "attacks/runners/scenario_006_ssh_key_login_then_command_execution.sh",
      "status": "success",
      "exit_code": 0,
      "stdout": "... ATTACK_EVENT_JSON: {...}",
      "stderr": "..."
    }
  ],
  "structured_events": [
    {
      "event_type": "payload_execution_succeeded",
      "artifact": "process_exec",
      "status": "observed",
      "confidence": "medium",
      "technique": "T1059"
    }
  ]
}
```

Invalid structured event lines are ignored for extraction and do not break
execution-log generation.

---

## 10. Relationship to attack_observed_effects.json

`attack_observed_effects.json` now prefers structured runner events over natural-language stdout markers when structured events are present.

Recommended precedence:

```text
structured runner events
  ↓ fallback
legacy stdout marker parsing
  ↓ fallback
exit_code-based weak inference
```

This keeps backward compatibility while making future scenarios less fragile.

---

## 11. Mapping Policy

Structured runner event field mapping:

| Runner event field | Observed effect field |
|---|---|
| `event_type` | `effect_type` |
| `artifact` | `maps_to_artifact` |
| `status` | `status` |
| `confidence` | `confidence` |
| `technique` | `maps_to_technique` |
| `message` | `notes` |

The mapping remains attacker-side only.

```text
artifact in runner event = expected defender-side artifact relationship
artifact in runner event != defender observed artifact
```

---

## 12. Safety and Robustness

Structured runner events are captured through shell runner stdout and may be preserved in attack artifacts. They should therefore be treated as durable attacker-side evidence.

Structured runner events should not include:

- secrets
- passwords
- private keys
- full token values
- sensitive file contents
- raw payload bodies
- large stdout blobs

They may include:

- artifact names
- technique IDs
- host/user labels
- boolean status
- short non-sensitive messages
- sanitized evidence summaries

Runner output policy:

- stdout may contain human-readable progress and `ATTACK_EVENT_JSON:` lines
- stderr may contain tool warnings or errors
- repeated non-actionable warning noise should be suppressed where safe
- exit code remains the runner completion signal
- structured events remain attacker-side effect evidence only

Related contract:

- `docs/design/attacker-agent/shell_backend_contract.md`

---


## 13. Backward Compatibility

Current runners remain valid.

Legacy stdout marker and exit-code fallback remain valid.

The current precedence is:

```text
structured runner events
  ↓ fallback
legacy stdout marker parsing
  ↓ fallback
exit_code-based weak inference
```

This means:

- scenario_004 / 005 / 006 can use structured runner events for current observed-effect mappings
- runners without structured events can continue using legacy stdout / exit-code fallback
- existing observed-effects alignment behavior remains backward compatible
- attacker-side structured events remain separate from defender-side detections

---


## 14. Implementation History

Completed implementation sequence:

```text
#141 docs: add structured runner output contract
#142 feat: parse structured runner events
#143 feat: emit structured events from scenario006 runner
#144 feat: prefer structured runner events in observed effects
#145 chore: suppress ssh known-host warning in scenario006 runner
#153 feat: add structured runner events to scenario004 and scenario005
#157 test: enforce shell backend structured event contract
```

Completed implementation scope:

- parser helper for `ATTACK_EVENT_JSON:` lines
- tests for valid / invalid / mixed stdout lines
- scenario_004 / 005 / 006 runners emit structured events for their current observed-effect mappings
- `attack_observed_effects.json` prefers structured events when present
- `attack_execution_log.json` includes additive `structured_events` when valid structured event lines are present
- raw `events[].stdout` / `events[].stderr` are preserved and are not replaced by `structured_events`
- legacy stdout marker fallback is preserved for runners without structured events
- static shell backend contract tests enforce runner path, executable bit, timeout / `state_changing` shape, and inline shell field boundaries
- `docs/operations/smoke_runbook.md` documents structured runner and observed-effects smoke checks
- scenario_006 keeps stderr cleaner by suppressing the repeated SSH known-host warning

Remaining implementation should be incremental:

- maintain scenario_004 / 005 / 006 structured event coverage
- extend structured event emission only when new scenario families introduce useful mappings
- keep fallback behavior for runners without structured events
- keep shell backend safety and runner output policy aligned
- avoid turning attacker-side structured events into defender-side detections

---

## 15. Failure Modes to Avoid

Avoid:

1. requiring all runners to migrate at once
2. breaking existing stdout marker parsing
3. treating structured attacker events as defender detections
4. embedding secrets in structured events
5. making shell scripts complex or hard to read
6. changing evaluation verdict behavior during parser introduction

---


## 16. Done Criteria

Completed:

- the contract exists
- a parser helper exists
- parser tests exist
- scenario_004 / 005 / 006 runners emit structured events for current observed-effect mappings
- `attack_observed_effects.json` can use structured events
- `attack_execution_log.json` includes additive `structured_events` for valid `ATTACK_EVENT_JSON:` lines
- raw stdout / stderr behavior remains preserved
- legacy stdout fallback still works
- scenario_004 / 005 / 006 smoke checks confirm `structured_runner_event` evidence in `attack_observed_effects.json`
- shell backend static contract tests enforce runner path, executable bit, timeout / `state_changing` shape, and inline shell field boundaries
- attacker-side structured events remain separate from defender-side detections

Follow-on work:

- extend structured event emission only when new scenario families introduce useful mappings
- add runtime shell backend allowlist / approval enforcement when assessment mode requires it

---

## 17. One-Line Summary

```text
Shell runners may emit ATTACK_EVENT_JSON lines so attacker-side observed effects can be derived from stable machine-readable events instead of fragile stdout markers.
```
