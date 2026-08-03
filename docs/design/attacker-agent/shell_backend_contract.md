# Shell Backend Contract

## 1. Purpose

This document defines the contract for the attacker-agent shell backend.

The shell backend exists to execute existing scenario runner scripts in a controlled, reproducible, and artifact-compatible way.

The goal is not to make shell scripts the long-term attack planner. The goal is to make shell runner execution stable enough to support:

- reproducible scenario execution
- schema-compatible `attack_result.json`
- schema-compatible `attack_execution_log.json`
- schema-compatible `attack_observed_effects.json`
- structured runner output for stable attacker-side observed effects
- later migration toward TTP catalog and composition mode

---

## 2. Current Status

The shell backend is already implemented as part of attacker-agent Phase A.

Current capabilities:

- scenario loader can read `runner` blocks
- backend selector can choose `shell`
- shell backend can execute scenario runner scripts
- shell backend records execution results
- shell backend preserves stdout / stderr for review and observed-effects extraction
- `attack_execution_log.json` includes additive `structured_events` when valid
  `ATTACK_EVENT_JSON:` lines are present
- attacker-agent writes:
  - `attack_result.json`
  - `attack_execution_log.json`
  - `attack_observed_effects.json`
- attacker-agent observed-effects generation prefers structured runner events when present
- legacy stdout marker / exit-code fallback remains compatible
- scenario_004 / 005 / 006 emit `ATTACK_EVENT_JSON:` events for current observed-effect mappings
- shell backend static contract tests enforce runner path shape, executable
  runner files, positive integer `timeout_seconds`, boolean `state_changing`,
  and no inline shell fields in runner blocks
- shell backend runtime validation rejects unsafe runner paths, missing or
  non-executable runner files, invalid timeout values, and inline shell fields
  before execution
- `docs/operations/smoke_runbook.md` documents structured runner and
  observed-effects smoke checks
- core attack artifacts validate against current schemas

Current schema-backed artifacts:

- `schemas/attack_result.schema.json`
- `schemas/attack_execution_log.schema.json`
- `schemas/attack_observed_effects.schema.json`

Still future / optional:

- shared shell runner wrapper
- rich stdout / stderr artifact references
- retry policy
- human approval workflow for state-changing runners
- signed runner allowlist or manifest-based runner approval
- assessment-mode approval enforcement for state-changing runners

---

## 3. Scope

This contract covers:

- shell backend responsibility
- shell runner responsibility
- input contract
- execution contract
- output contract
- timeout handling
- stdout / stderr handling
- structured runner output handling
- exit code handling
- state-changing classification
- relationship to attack artifacts
- relationship to observed effects

This contract does not cover:

- autonomous planning
- TTP composition
- Atomic Red Team backend
- Caldera backend
- actual exploitation outside the lab
- approval workflow for offensive actions
- production red-team operation management

---

## 4. Backend Responsibility

The shell backend is responsible for executing a shell runner script and converting the execution result into attacker-agent artifacts.

The shell backend should:

- validate runner path
- enforce timeout
- execute the runner
- capture exit code
- capture stdout / stderr
- record start / end timestamps
- produce structured step results
- contribute to `attack_result.json`
- contribute to `attack_execution_log.json`
- preserve scenario metadata
- preserve raw stdout / stderr for review and observed-effects extraction
- avoid interpreting attacker-side success beyond what the runner, structured events, and exit code support

The shell backend should not:

- perform planning
- infer complex observed effects
- directly modify defender-side artifacts
- treat stdout claims as defender-confirmed evidence
- make autonomous decisions outside the scenario contract

One-line definition:

```text
shell backend = controlled runner execution + structured artifact recording
```

---

## 5. Shell Runner Responsibility

A shell runner is a scenario-specific executable script.

The runner is responsible for performing the concrete attack action for the scenario.

A runner may:

- call tools such as `ssh`, `hydra`, `curl`, `wget`, or local helper scripts
- print human-readable progress to stdout
- print tool warnings or errors to stderr
- emit structured attacker-side events using `ATTACK_EVENT_JSON:` lines
- exit with a meaningful exit code

A runner should:

- be executable
- be deterministic enough for lab evaluation
- stay within scenario constraints
- avoid destructive behavior outside lab scope
- avoid writing directly into defender-side run artifacts
- keep environment assumptions explicit
- return non-zero when the attack action cannot be completed
- keep structured events compact and non-sensitive

A runner should not:

- generate `incident.json`
- generate `triage_result.json`
- generate `case.json`
- generate `action_result.json`
- bypass attacker-agent artifact generation
- perform unrelated cleanup or destructive actions
- silently ignore failed attack steps
- print secrets, private keys, passwords, or raw payload bodies to stdout / stderr

---

## 6. Scenario Input Contract

The shell backend is selected from an `attack_scenario_v1` runner block.

Example:

```yaml
runner:
  type: shell
  path: attacks/runners/scenario_006_ssh_key_login_then_command_execution.sh
  timeout_seconds: 120
  state_changing: true
```

Required runner fields:

- `type`
- `path`

Optional runner fields:

- `timeout_seconds`
- `state_changing`

The backend selector should choose the shell backend when:

```text
runner.type == shell
```

---

## 7. Runner Path Policy

Runner paths should be repository-relative paths.

Recommended path pattern:

```text
attacks/runners/<scenario_runner>.sh
```

The shell backend should prefer an allowlist-style path policy.

Allowed:

- paths under `attacks/runners/`
- executable files
- repository-relative paths

Not allowed:

- absolute paths outside the repository
- paths using traversal such as `../`
- non-executable runner files
- arbitrary shell fragments in scenario YAML

Policy:

```text
scenario YAML points to a runner file;
scenario YAML must not contain arbitrary inline shell code.
```

Static contract tests currently enforce that scenario_004 / 005 / 006 runner
paths are repository-relative, avoid `../` traversal, live under
`attacks/runners/`, point to executable files, and avoid inline shell fields such
as `command`, `shell`, `script`, or `inline`.

Runtime validation now applies the same safety boundary before execution. The
shell backend rejects runner paths that are absolute, contain `..`, escape the
repository root or `attacks/runners/`, point outside `attacks/runners/`, do not
exist, are not regular files, or are not executable. It also rejects inline shell
fields such as `command`, `shell`, `script`, or `inline`.

Implemented now:

- runtime runner path validation
- runtime runner file existence, regular-file, and executable-bit validation
- runtime `timeout_seconds` validation
- runtime inline-shell field rejection

Still future:

- human approval workflow for state-changing runners
- signed runner allowlist
- manifest-based runner approval

---

## 8. Execution Contract

The shell backend should execute exactly one runner invocation per scenario execution.

Minimum execution record:

- runner path
- backend name
- start timestamp
- end timestamp
- timeout seconds
- exit code
- status
- stdout
- stderr

Runner stdout may include line-oriented structured events prefixed with:

```text
ATTACK_EVENT_JSON:
```

Those events are attacker-side execution evidence only. They can support `attack_observed_effects.json`, but they must not be treated as defender-side telemetry or detection.

Recommended execution status mapping:

| Condition | Status |
|---|---|
| exit code 0 | `completed` |
| non-zero exit code | `failed` |
| timeout | `failed` |
| skipped by dry-run | `skipped` |

The shell backend should not mark a run as `completed` if the runner exits non-zero.

---

## 9. Timeout Policy

Timeout is part of the runner contract.

Source of timeout:

1. `runner.timeout_seconds`
2. backend default timeout

Recommended default:

```text
120 seconds
```

Timeout validation:

- missing `timeout_seconds` uses the backend default timeout
- provided `timeout_seconds` must be a positive integer

Timeout behavior:

- terminate runner execution
- mark status as `failed`
- record timeout in execution log
- preserve stdout / stderr captured before timeout
- include a clear failure reason if supported

Future field:

```json
{
  "failure_reason": "timeout"
}
```

---

## 10. Exit Code Policy

Exit code is the primary machine-readable runner result.

Policy:

```text
exit_code == 0
  → runner completed

exit_code != 0
  → runner failed
```

The shell backend should record `exit_code` in:

- step result
- `attack_execution_log.json` event
- optionally `attack_result.json.steps[]`

The shell backend should not infer partial success solely from stdout if exit code is non-zero.

Structured runner events may describe individual attacker-side effects, but exit code remains the primary runner completion signal.

---

## 11. stdout / stderr Policy

stdout and stderr are useful for human review and observed-effects extraction.

Current policy:

- capture stdout
- capture stderr
- print them during interactive execution
- include enough information in execution events to debug the run
- allow observed-effects extraction from structured runner output when available

Runner output policy:

- stdout may contain human-readable progress
- stdout may contain `ATTACK_EVENT_JSON:` lines
- stderr may contain tool errors or warnings
- repeated non-actionable warning noise should be suppressed where safe
- output must not include secrets, private keys, passwords, token values, or raw payload bodies
- large stdout / stderr should eventually be stored as file references rather than embedded directly in JSON

Important boundary:

```text
stdout/stderr are attacker-side execution evidence;
structured runner events are attacker-side structured evidence;
neither is defender-side detection evidence.
```

---

## 12. Dry-Run Policy

Dry-run should not execute the runner.

Dry-run should show:

- scenario ID
- scenario name
- description
- MITRE ATT&CK techniques
- selected backend
- runner path
- timeout
- expected artifacts
- expected output files if any

Dry-run may validate:

- scenario schema
- runner path presence
- backend selection

Dry-run should not create attack execution evidence unless explicitly designed to do so.

---

## 13. State-Changing Classification

`runner.state_changing` describes whether the runner is expected to change target state.

Examples:

```yaml
state_changing: true
```

State-changing examples:

- writing `authorized_keys`
- executing a payload
- creating a file
- modifying services
- changing credentials

Non-state-changing examples:

- read-only validation
- login check
- metadata lookup

Current policy:

- record `state_changing` in `attack_result.json`
- do not enforce approval workflow yet

Future policy:

- require approval for state-changing actions in assessment mode
- block state-changing actions in read-only mode
- record safety decisions in attack artifacts

---

## 14. Output Artifacts

The shell backend currently contributes to core attacker-side artifacts.

### 14.1 `attack_result.json`

`attack_result.json` summarizes the run.

Important fields:

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

### 14.2 `attack_execution_log.json`

`attack_execution_log.json` records execution events.

Important fields:

- `attack_id`
- `scenario_id`
- `backend`
- `started_at`
- `ended_at`
- `status`
- `events`
- `structured_events` when valid `ATTACK_EVENT_JSON:` lines are present

Example event types:

- `runner_started`
- `runner_completed`
- `runner_failed`
- `runner_timeout`

The shell backend preserves stdout / stderr in execution events. Parsed
`structured_events` are additive and do not replace raw execution events,
stdout, or stderr.

### 14.3 `attack_observed_effects.json`

`attack_observed_effects.json` represents attacker-side observed effects derived from shell execution evidence.

Current extraction precedence:

```text
structured runner events
  ↓ fallback
legacy stdout marker parsing
  ↓ fallback
exit_code-based weak inference
```

The artifact remains attacker-side only. It does not prove that defender-side telemetry or detections observed the mapped artifact.

---

## 15. Relationship to `attack_observed_effects.json`

`attack_observed_effects.json` is now part of the attacker-agent artifact set.

Observed effects may be derived from:

- structured runner output
- legacy stdout markers
- exit code
- generated files
- explicit runner-produced JSON in the future

Current direction:

```text
runner execution
  ↓
attack_execution_log.json
  ↓
observed-effects extractor
  ↓
attack_observed_effects.json
```

This keeps raw execution logging separate from interpreted attacker-side observations.

Important boundary:

```text
attack_observed_effects.json = attacker-side observed effects
attack_observed_effects.json != defender-side observed artifacts
attack_observed_effects.json != detections
```

---

## 16. Structured Runner Output Policy

Shell runners may optionally emit line-oriented structured events using the `ATTACK_EVENT_JSON:` prefix.

Example:

```text
ATTACK_EVENT_JSON: {"event_type":"ssh_login_succeeded","artifact":"ssh_key_login","status":"observed","confidence":"medium"}
```

Required event fields:

- `event_type`
- `artifact`
- `status`

Recommended event fields:

- `confidence`
- `technique`
- `message`
- `target`
- `evidence`

Policy:

```text
runner exit code = runner completion signal
ATTACK_EVENT_JSON = attacker-side effect evidence
attack_observed_effects.json = interpreted attacker-side observation
evaluation_result.json = defender-side coverage comparison
```

Structured runner output is optional and additive. Runners without structured events remain valid through legacy stdout marker / exit-code fallback.

Details:

- `docs/design/attacker-agent/structured_runner_output_contract.md`

---

## 17. Relationship to Evaluation

Evaluation should compare expected artifacts with defender-side observations.

The shell backend provides attack-side execution context, but it does not decide defender-side detection success.

Correct boundary:

```text
shell backend:
  records what was attempted and whether runner execution completed

evaluation:
  checks whether expected artifacts were observed by defender pipeline
```

The runner completing successfully does not automatically mean the defender observed the expected artifacts.

---

## 18. Safety Boundary

The shell backend is powerful because it can execute arbitrary runner scripts.

Therefore, safety must be handled through constraints and path controls.

Current safety boundary:

- repository-controlled runner scripts
- schema-defined runner path
- no inline shell code in scenario YAML
- timeout
- state-changing metadata
- lab-only scenarios
- no autonomous planning
- no secrets in structured runner events
- no defender-side artifact writes from shell runners

Future safety boundary:

- runtime allowlist / denylist policy
- approval-required state-changing actions
- assessment mode
- read-only mode
- budget limits
- operator override
- safety decisions in artifacts

---

## 19. Current Done Criteria

The shell backend contract is considered established when:

- shell runner scenarios can be selected deterministically
- runner path is explicit in scenario YAML
- timeout is explicit or defaulted
- execution produces schema-compatible `attack_result.json`
- execution produces schema-compatible `attack_execution_log.json`
- valid `ATTACK_EVENT_JSON:` lines are captured as additive `structured_events`
- dry-run does not execute runner actions
- exit code is recorded
- stdout / stderr are available for review
- `state_changing` is preserved in `attack_result.json`
- static contract tests enforce runner path, executable bit,
  `timeout_seconds`, `state_changing`, and inline shell field boundaries
- `attack_observed_effects.json` can be derived from shell execution evidence
- structured runner output is documented and optional
- scenario_004 / 005 / 006 emit structured runner events for current observed-effect mappings
- legacy stdout marker / exit-code fallback remains compatible

---

## 20. Next Steps

Recommended next steps:

1. Keep current shell backend behavior stable
2. Add tests only for concrete schema, runner-path, or output-regression risks
3. Maintain scenario_004 / 005 / 006 structured runner event coverage
4. Extend structured runner events only when new scenario families introduce useful mappings
5. Maintain additive `structured_events` in `attack_execution_log.json` without replacing raw stdout / stderr
6. Introduce runtime path allowlist / safety policy when assessment mode becomes relevant
7. Avoid autonomous execution or TTP composition until artifact contracts remain stable

---

## 21. One-Line Summary

```text
The shell backend executes repository-controlled scenario runners, preserves attacker-side execution evidence, and records schema-compatible attack artifacts; it does not perform planning or defender-side evaluation.
```
