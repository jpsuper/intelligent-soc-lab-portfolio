# Attacker Scenario Schema v1

## 1. Purpose

`attack_scenario.schema.json` defines the first explicit scenario contract for attacker-agent Phase B.

The goal is not to migrate every existing scenario immediately. The goal is to fix the contract that future scenario YAMLs and migration work should converge on.

This schema follows the attacker-agent roadmap direction:

```text
Scenario Mode
  ↓
unified scenario contract
  ↓
backend selection
  ↓
attack_result / attack_execution_log
  ↓
future rich attack artifacts
```

The schema is designed to preserve the current Scenario-first approach while making attacker-side artifacts easier to compare with detection, triage, investigation, action, and evaluation artifacts.

---

## 2. Background

The attacker-agent currently supports two scenario styles.

### 2.1 Legacy step-based scenario

The older scenario style is step-based.

Typical fields:

```yaml
name: SSH brute force privilege escalation
mitre_attack:
  - T1110
  - T1078
expected_artifacts:
  - ssh_failed_login
  - ssh_success_login
steps:
  - id: step-1
    type: bruteforce_ssh
    command: hydra ...
```

This style is useful for small local command sequences and compatibility with early lab scenarios.

### 2.2 Shell runner-based scenario

The newer operational style uses shell runners.

Typical fields:

```yaml
scenario_id: scenario_006
name: SSH key login followed by command execution
description: SSH public-key login followed by post-login command execution.
expected_artifacts:
  - ssh_key_login
  - process_exec
runner:
  type: shell
  path: attacks/runners/scenario_006_ssh_key_login_then_command_execution.sh
  timeout_seconds: 120
```

In this style, the attack logic lives in a shell script and the scenario YAML acts as execution metadata.

### 2.3 Why schema v1 is needed

The current attacker-agent Phase A dispatcher can already normalize, validate, and select a backend for step-based or shell runner-based scenarios.

However, before introducing richer attack artifacts, TTP catalogs, or autonomous modes, the scenario contract should be fixed.

Schema v1 provides that contract.

---

## 3. Scope

### In scope

* Define `attack_scenario_schema_v1`
* Define canonical attacker scenario fields
* Preserve compatibility with current step-based and shell runner-based scenarios
* Make Phase B migration direction explicit
* Prepare for future rich attack artifacts
* Prepare for future `attack_observed_effects.json`
* Prepare for future TTP catalog and autonomous modes without implementing them yet

### Out of scope

* Immediate rewrite of all existing scenarios
* Runtime schema validation in attacker-agent
* Rich `attack_result.json`
* `attack_observed_effects.json`
* TTP catalog
* Atomic Red Team backend
* Caldera backend
* TTP Composition Mode
* Autonomous Recon-to-Action Mode
* Assessment Mode

---

## 4. Design Principles

## 4.1 Scenario-first, not autonomy-first

The schema is designed for reproducible scenario execution first.

Autonomous planning is a later extension. It should reuse the same attack contract rather than replacing it.

## 4.2 One contract, multiple execution styles

The schema supports both:

* shell runner-based scenarios
* legacy step-based scenarios

This makes migration incremental.

## 4.3 Compare-ready artifacts first

Scenario metadata should make it easier to compare attacker intent, expected artifacts, observed defender artifacts, and evaluation results.

The schema therefore includes fields such as:

* `primary_artifact`
* `artifacts_expected`
* `observed_effects_contract`
* `success_conditions`

## 4.4 Safety and constraints are first-class

Scenario metadata should describe execution boundaries.

The schema therefore includes:

* `constraints`
* `runner.timeout_seconds`
* `runner.state_changing`
* future-compatible `requires_approval`

## 4.5 Runtime behavior should not change in the schema PR

The first schema PR should only add the schema and documentation.

Scenario migration and runtime validation should be done in follow-up PRs.

---

## 5. Schema Version

Schema v1 uses:

```yaml
schema_version: attack_scenario_v1
```

This field is recommended for all new or migrated scenarios.

During migration, legacy scenarios may omit `schema_version`, but schema-v1 scenarios should include it.

---

## 6. Canonical Fields

## 6.1 Required fields

Schema v1 requires the following logical fields:

* `scenario_id`
* `description`
* `scenario_name` or legacy `name`
* `runner` or legacy `steps`
* `artifacts_expected` or legacy `expected_artifacts`

## 6.2 Recommended fields

New scenarios should also include:

* `schema_version`
* `attacker`
* `target`
* `techniques`
* `primary_artifact`
* `observed_effects_contract`
* `constraints`
* `success_conditions`

## 6.3 Compatibility fields

For migration safety, schema v1 still accepts:

* `name`
* `mitre_attack`
* `expected_artifacts`
* `steps`

The long-term canonical fields are:

* `scenario_name`
* `techniques`
* `artifacts_expected`

---

## 7. Field Reference

## 7.1 `schema_version`

Identifies the scenario schema version.

Example:

```yaml
schema_version: attack_scenario_v1
```

Policy:

* Recommended for new scenarios
* Required for scenarios that claim schema-v1 compatibility
* Future versions should use new values such as `attack_scenario_v2`

---

## 7.2 `scenario_id`

Stable scenario identifier.

Example:

```yaml
scenario_id: scenario_006
```

Accepted format:

```text
scenario_006
scenario-006
```

Repository-local convention should prefer underscore form:

```text
scenario_006
```

Policy:

* Required by schema v1
* Current loader may still infer it for legacy scenarios
* Migrated scenarios should declare it explicitly

---

## 7.3 `scenario_name`

Human-readable scenario name.

Example:

```yaml
scenario_name: SSH key login followed by command execution
```

Policy:

* Preferred canonical field
* Legacy `name` remains accepted during migration
* New scenarios should use `scenario_name`

---

## 7.4 `name`

Legacy human-readable scenario name.

Example:

```yaml
name: SSH key login followed by command execution
```

Policy:

* Accepted for compatibility
* Should be migrated to `scenario_name` over time

---

## 7.5 `description`

Short scenario explanation.

Example:

```yaml
description: SSH public-key login followed by post-login command execution.
```

Policy:

* Required
* Should describe what the scenario does, not only the expected detection result

---

## 7.6 `attacker`

Describes the attacker-side execution context.

Example:

```yaml
attacker:
  host: kali-attacker
  ip: 192.0.2.40
  user: attacker
```

Supported fields:

* `host`
* `ip`
* `user`

Policy:

* Recommended
* Used for traceability and future attack artifact enrichment
* Should not be treated as a replacement for actual telemetry

---

## 7.7 `target`

Describes the target-side execution context.

Example:

```yaml
target:
  host: ubuntu-victim01
  ip: 192.0.2.30
  user: victim01
```

Supported fields:

* `host`
* `ip`
* `user`

Policy:

* Recommended
* Useful for expected log correlation and later evaluation
* Should match lab inventory naming where possible

---

## 7.8 `techniques`

Canonical ATT&CK / TTP metadata.

Examples:

```yaml
techniques:
  - id: T1078
    name: Valid Accounts
    tactic: Defense Evasion
  - id: T1059
    name: Command and Scripting Interpreter
    tactic: Execution
```

Simple string form is also allowed:

```yaml
techniques:
  - T1078
  - T1059
```

Policy:

* Preferred over legacy `mitre_attack`
* Object form is recommended for new scenarios
* String form is acceptable for simple metadata

---

## 7.9 `mitre_attack`

Legacy ATT&CK metadata.

Example:

```yaml
mitre_attack:
  - T1078
  - T1059
```

Policy:

* Accepted for compatibility
* New scenarios should prefer `techniques`
* Loader may map `mitre_attack` to `techniques` in future

---

## 7.10 `primary_artifact`

Main defensive artifact expected from the scenario.

Example:

```yaml
primary_artifact: ssh_key_login
```

Policy:

* Recommended
* Should represent the scenario's primary evaluation target
* Helps evaluation and harness logic avoid process-first bias

Examples:

```yaml
primary_artifact: authorized_keys_modification
primary_artifact: ssh_key_login
primary_artifact: process_exec
```

---

## 7.11 `artifacts_expected`

Canonical list of expected defensive artifacts.

Example:

```yaml
artifacts_expected:
  - ssh_key_login
  - process_exec
```

Policy:

* Preferred over `expected_artifacts`
* Should align with detection / evaluation artifact vocabulary
* Used by future attack / detection / evaluation comparison

---

## 7.12 `expected_artifacts`

Legacy expected artifact list.

Example:

```yaml
expected_artifacts:
  - ssh_key_login
  - process_exec
```

Policy:

* Accepted for compatibility
* New scenarios should prefer `artifacts_expected`

---

## 7.13 `runner`

Shell runner execution contract.

Example:

```yaml
runner:
  type: shell
  path: attacks/runners/scenario_006_ssh_key_login_then_command_execution.sh
  timeout_seconds: 120
  state_changing: true
```

Fields:

* `type`
* `path`
* `timeout_seconds`
* `state_changing`

### `runner.type`

Currently supported value:

```yaml
type: shell
```

Policy:

* Defaults to `shell` in the current loader when runner path is present
* Future backend types may be added separately

### `runner.path`

Path to shell runner.

Example:

```yaml
path: attacks/runners/scenario_006_ssh_key_login_then_command_execution.sh
```

Policy:

* Required for shell runner scenarios
* Runtime validator should enforce allowlisted paths
* Current implementation allows runners under `attacks/runners`

### `runner.timeout_seconds`

Execution timeout.

Example:

```yaml
timeout_seconds: 120
```

Policy:

* Must be greater than 0
* Current validator caps it at 3600 seconds
* Default should remain conservative

### `runner.state_changing`

Whether the scenario is expected to modify target state.

Example:

```yaml
state_changing: true
```

Policy:

* Recommended
* Useful for future assessment / approval modes
* Examples:

  * `authorized_keys` modification: `true`
  * public key login only: may be `false` or `true` depending on side effects
  * payload download + execute: `true`

---

## 7.14 `steps`

Legacy step-based execution contract.

Example:

```yaml
steps:
  - id: step-1
    type: bruteforce_ssh
    command: hydra ...
```

Policy:

* Accepted for compatibility
* If `runner` is present, backend selection should prefer runner-based execution
* New shell-based scenarios should prefer `runner`

---

## 7.15 `observed_effects_contract`

Future-facing contract for attacker-observed effects.

Example:

```yaml
observed_effects_contract:
  expected_effects:
    - public key login succeeds
    - post-login command execution occurs
  evidence_sources:
    - runner stdout
    - ssh exit code
    - runner exit code
  notes: >
    Full attack_observed_effects.json is introduced in Phase C.
```

Fields:

* `expected_effects`
* `evidence_sources`
* `notes`

Policy:

* Optional in schema v1
* Intended as a placeholder for Phase C
* Does not require `attack_observed_effects.json` yet
* Helps define what the attacker side expects to observe

---

## 7.16 `constraints`

Execution constraints and safety hints.

Example:

```yaml
constraints:
  allowed_hosts:
    - ubuntu-victim01
  allowed_networks:
    - 192.0.2.0/24
  forbidden_actions:
    - destructive_file_deletion
    - privilege_persistence_outside_lab
  requires_approval: false
```

Supported fields:

* `allowed_hosts`
* `allowed_networks`
* `forbidden_actions`
* `requires_approval`

Policy:

* Optional in schema v1
* Should become more important in Assessment Mode
* Does not replace runtime safety checks

---

## 7.17 `success_conditions`

Expected success conditions.

String form:

```yaml
success_conditions:
  - SSH public-key login succeeds
  - post-login command execution returns exit code 0
```

Object form:

```yaml
success_conditions:
  - type: artifact_observed
    artifact: ssh_key_login
    description: Defender side observes SSH public-key login
  - type: command_success
    description: Runner exits with code 0
```

Policy:

* Recommended for new scenarios
* Future evaluation can compare success conditions with attack and defense artifacts
* Should avoid claiming more than the scenario can actually observe

---

## 8. Backend Model

Schema v1 intentionally supports two execution styles during migration.

## 8.1 Shell runner-based scenario

```yaml
schema_version: attack_scenario_v1
scenario_id: scenario_006
scenario_name: SSH key login followed by command execution
description: SSH public-key login followed by post-login command execution.

attacker:
  host: kali-attacker
  ip: 192.0.2.40
  user: attacker

target:
  host: ubuntu-victim01
  ip: 192.0.2.30
  user: victim01

techniques:
  - id: T1078
    name: Valid Accounts
    tactic: Defense Evasion
  - id: T1059
    name: Command and Scripting Interpreter
    tactic: Execution

primary_artifact: ssh_key_login

artifacts_expected:
  - ssh_key_login
  - process_exec

runner:
  type: shell
  path: attacks/runners/scenario_006_ssh_key_login_then_command_execution.sh
  timeout_seconds: 120
  state_changing: true

observed_effects_contract:
  expected_effects:
    - SSH public-key login succeeds
    - post-login command execution occurs
  evidence_sources:
    - runner stdout
    - ssh exit code
    - runner exit code

constraints:
  allowed_hosts:
    - ubuntu-victim01
  allowed_networks:
    - 192.0.2.0/24
  forbidden_actions:
    - destructive_file_deletion
  requires_approval: false

success_conditions:
  - type: artifact_observed
    artifact: ssh_key_login
    description: Defender side observes SSH public-key login
  - type: artifact_observed
    artifact: process_exec
    description: Defender side observes post-login process execution
```

## 8.2 Step-based scenario

```yaml
schema_version: attack_scenario_v1
scenario_id: scenario_001
scenario_name: SSH brute force privilege escalation
description: Legacy step-based SSH brute force scenario.

expected_artifacts:
  - ssh_failed_login
  - ssh_success_login

steps:
  - id: step-1
    type: bruteforce_ssh
    command: hydra ...
  - id: step-2
    type: ssh_login_and_sudo
    command: ssh ...
```

---

## 9. Backend Selection Policy

Backend selection should remain deterministic.

During migration, the policy is:

```text
1. If runner.path exists, use shell backend.
2. Else if steps exists, use step backend.
3. Else validation error.
```

This matches the current attacker-agent dispatcher behavior.

If both `runner` and `steps` are present, shell runner should take precedence.

Reason:

* `runner` represents the newer scenario execution style
* shell runner scenarios are the current operational path for scenario_004 / 005 / 006
* deterministic priority avoids ambiguous backend selection

---

## 10. Scenario ID Policy

`scenario_id` is required by schema v1.

Current attacker-agent loader can still infer scenario IDs for legacy paths, but migrated schema-v1 scenarios should declare `scenario_id` explicitly.

Recommended format:

```text
scenario_001
scenario_004
scenario_006
```

Compatibility format:

```text
scenario-001
scenario-004
scenario-006
```

Migration rule:

```text
legacy inferred scenario_id
  ↓
explicit scenario_id in schema-v1 YAML
```

---

## 11. Artifact Vocabulary Policy

New scenarios should use defensive artifact vocabulary that matches detection and evaluation outputs.

Recommended examples:

```text
ssh_failed_login
ssh_success_login
ssh_key_login
authorized_keys_modification
process_exec
suspicious_file_write
```

For scenario_006:

```yaml
primary_artifact: ssh_key_login
artifacts_expected:
  - ssh_key_login
  - process_exec
```

For scenario_007:

```yaml
primary_artifact: suspicious_file_write
artifacts_expected:
  - ssh_key_login
  - suspicious_file_write
```

For scenario_005:

```yaml
primary_artifact: ssh_key_login
artifacts_expected:
  - ssh_key_login
```

For scenario_004:

```yaml
primary_artifact: authorized_keys_modification
artifacts_expected:
  - ssh_failed_login
  - ssh_success_login
  - authorized_keys_modification
```

Policy:

* `primary_artifact` should be one main artifact
* `artifacts_expected` may contain multiple expected artifacts
* `artifacts_expected` should not include every possible side effect
* Avoid scenario name or attack name as artifact names

---

## 12. Relationship to Attack Artifacts

Schema v1 does not make rich attack artifacts mandatory.

However, it prepares for them.

Future artifacts:

```text
attack_request.json
attack_plan.json
attack_result.json
attack_execution_log.json
attack_observed_effects.json
```

Current Phase A / early Phase B artifacts:

```text
attack_result.json
attack_execution_log.json
```

Future Phase C will make `attack_observed_effects.json` first-class.

Schema v1 supports that future by introducing:

* `primary_artifact`
* `artifacts_expected`
* `observed_effects_contract`
* `success_conditions`

---

## 13. Relationship to Defensive Pipeline

The scenario schema should connect cleanly to the defensive pipeline.

```text
attack_scenario.yaml
  ↓
attacker-agent
  ↓
attack_result.json
  ↓
logs / telemetry
  ↓
detection
  ↓
evaluation_result.json
```

The scenario schema should not duplicate defensive results, but it should define attacker-side intent and expected defensive artifacts.

Examples:

```yaml
artifacts_expected:
  - ssh_key_login
  - process_exec
```

These are expectations, not proof.

Defensive proof still comes from:

* logs
* detection outputs
* incident.json
* evaluation_result.json
* investigation_result.json

---

## 14. Compatibility and Migration

## 14.1 Compatibility policy

Schema v1 intentionally accepts both canonical and legacy fields.

Canonical:

```yaml
scenario_name:
artifacts_expected:
techniques:
```

Legacy:

```yaml
name:
expected_artifacts:
mitre_attack:
```

This allows incremental migration.

## 14.2 Migration target

Long-term target:

```yaml
schema_version: attack_scenario_v1
scenario_id: scenario_006
scenario_name: SSH key login followed by command execution
description: ...
attacker: ...
target: ...
techniques: ...
primary_artifact: ssh_key_login
artifacts_expected:
  - ssh_key_login
  - process_exec
runner: ...
observed_effects_contract: ...
constraints: ...
success_conditions: ...
```

## 14.3 Recommended migration order

1. Add schema and documentation
2. Add schema validation helper or test
3. Migrate `scenario_006`
4. Migrate `scenario_005`
5. Migrate `scenario_004`
6. Keep legacy step scenarios compatible through loader normalization

Reason:

* `scenario_006` exercises both SSH key login and post-login process execution
* `scenario_005` is simpler and validates key reuse only
* `scenario_004` includes installation / persistence context and is slightly broader
* Step-based scenarios can remain legacy until needed

## 14.4 What not to do in the schema PR

Do not migrate all scenarios in the same PR as schema introduction.

Do not add runtime validation and scenario migration in the same PR.

Do not introduce rich attack artifacts in the schema PR.

---

## 15. Validation Strategy

## 15.1 Schema syntax validation

Use:

```bash
python3 -m json.tool schemas/attack_scenario.schema.json >/tmp/attack_scenario.schema.pretty.json
```

## 15.2 Sample schema validation

Use:

```bash
PYTHONPATH=. uv run python - <<'PY'
import json
from jsonschema import Draft202012Validator

schema = json.load(open("schemas/attack_scenario.schema.json", encoding="utf-8"))
Draft202012Validator.check_schema(schema)

sample = {
    "schema_version": "attack_scenario_v1",
    "scenario_id": "scenario_006",
    "scenario_name": "SSH key login followed by command execution",
    "description": "SSH public-key login followed by post-login command execution.",
    "artifacts_expected": ["ssh_key_login", "process_exec"],
    "primary_artifact": "ssh_key_login",
    "runner": {
        "type": "shell",
        "path": "attacks/runners/scenario_006_ssh_key_login_then_command_execution.sh",
        "timeout_seconds": 120,
        "state_changing": True,
    },
}

Draft202012Validator(schema).validate(sample)
print("attack_scenario schema validation: OK")
PY
```

## 15.3 Runtime validation

Runtime validation is a follow-up.

Recommended follow-up:

```text
feat: validate attack scenario schema
```

That PR can add:

* schema validation helper
* tests for schema-v1 scenario YAMLs
* clearer validation errors
* compatibility handling for legacy fields

---

## 16. Example: scenario_006 Migration Target

```yaml
schema_version: attack_scenario_v1
scenario_id: scenario_006
scenario_name: SSH key login followed by command execution
description: >
  Reuse an existing SSH public key to authenticate to the victim host, then
  execute a post-login command chain that downloads, marks executable, and runs
  a payload.

attacker:
  host: kali-attacker
  ip: 192.0.2.40
  user: attacker

target:
  host: ubuntu-victim01
  ip: 192.0.2.30
  user: victim01

techniques:
  - id: T1078
    name: Valid Accounts
    tactic: Defense Evasion
  - id: T1059
    name: Command and Scripting Interpreter
    tactic: Execution

primary_artifact: ssh_key_login

artifacts_expected:
  - ssh_key_login
  - process_exec

runner:
  type: shell
  path: attacks/runners/scenario_006_ssh_key_login_then_command_execution.sh
  timeout_seconds: 120
  state_changing: true

observed_effects_contract:
  expected_effects:
    - SSH public-key login succeeds
    - payload download command is attempted
    - post-login command execution occurs
  evidence_sources:
    - runner stdout
    - ssh exit code
    - runner exit code

constraints:
  allowed_hosts:
    - ubuntu-victim01
  allowed_networks:
    - 192.0.2.0/24
  forbidden_actions:
    - destructive_file_deletion
    - persistence_outside_lab_scope
  requires_approval: false

success_conditions:
  - type: runner_exit_code
    description: Shell runner exits with code 0
  - type: artifact_observed
    artifact: ssh_key_login
    description: Defender side observes SSH public-key login
  - type: artifact_observed
    artifact: process_exec
    description: Defender side observes post-login process execution
```

---

## 17. Example: scenario_005 Migration Target

```yaml
schema_version: attack_scenario_v1
scenario_id: scenario_005
scenario_name: SSH authorized_keys persistence reuse
description: >
  Reuse a previously installed SSH public key to authenticate to the victim host.

attacker:
  host: kali-attacker
  ip: 192.0.2.40
  user: attacker

target:
  host: ubuntu-victim01
  ip: 192.0.2.30
  user: victim01

techniques:
  - id: T1078
    name: Valid Accounts
    tactic: Defense Evasion

primary_artifact: ssh_key_login

artifacts_expected:
  - ssh_key_login

runner:
  type: shell
  path: attacks/runners/scenario_005_ssh_authorized_keys_persistence_reuse.sh
  timeout_seconds: 120
  state_changing: false

observed_effects_contract:
  expected_effects:
    - SSH public-key login succeeds
  evidence_sources:
    - runner stdout
    - ssh exit code

constraints:
  allowed_hosts:
    - ubuntu-victim01
  allowed_networks:
    - 192.0.2.0/24
  forbidden_actions:
    - destructive_file_deletion
  requires_approval: false

success_conditions:
  - type: runner_exit_code
    description: Shell runner exits with code 0
  - type: artifact_observed
    artifact: ssh_key_login
    description: Defender side observes SSH public-key login
```

---

## 18. Example: scenario_004 Migration Target

```yaml
schema_version: attack_scenario_v1
scenario_id: scenario_004
scenario_name: SSH brute force to authorized_keys persistence
description: >
  Attempt SSH brute force, authenticate with discovered credentials, and install
  an attacker public key into authorized_keys for persistence.

attacker:
  host: kali-attacker
  ip: 192.0.2.40
  user: attacker

target:
  host: ubuntu-victim01
  ip: 192.0.2.30
  user: victim01

techniques:
  - id: T1110
    name: Brute Force
    tactic: Credential Access
  - id: T1078
    name: Valid Accounts
    tactic: Defense Evasion
  - id: T1098
    name: Account Manipulation
    tactic: Persistence

primary_artifact: authorized_keys_modification

artifacts_expected:
  - ssh_failed_login
  - ssh_success_login
  - authorized_keys_modification

runner:
  type: shell
  path: attacks/runners/scenario_004_ssh_bruteforce_authorized_keys_persistence.sh
  timeout_seconds: 300
  state_changing: true

observed_effects_contract:
  expected_effects:
    - SSH brute force attempts occur
    - password login succeeds
    - authorized_keys is modified
  evidence_sources:
    - runner stdout
    - ssh exit code
    - runner exit code

constraints:
  allowed_hosts:
    - ubuntu-victim01
  allowed_networks:
    - 192.0.2.0/24
  forbidden_actions:
    - destructive_file_deletion
    - persistence_outside_lab_scope
  requires_approval: false

success_conditions:
  - type: runner_exit_code
    description: Shell runner exits with code 0
  - type: artifact_observed
    artifact: ssh_failed_login
    description: Defender side observes SSH failed login attempts
  - type: artifact_observed
    artifact: ssh_success_login
    description: Defender side observes successful SSH login
  - type: artifact_observed
    artifact: authorized_keys_modification
    description: Defender side observes authorized_keys modification
```

---

## 19. Relationship to Future Phases

## 19.1 Phase C: Rich Attack Artifacts

This schema prepares for Phase C but does not implement it.

Phase C will introduce richer artifacts such as:

* `attack_result.schema.json`
* `attack_execution_log.schema.json`
* `attack_observed_effects.schema.json`

The most important future artifact is:

```text
attack_observed_effects.json
```

This will represent attacker-side observed facts and help compare attack-side claims against defensive telemetry.

## 19.2 Phase D: Shell Backend Formalization

The schema already has a `runner` contract. Phase D can formalize:

* shell runner environment variables
* stdout / stderr capture
* observed effects output path
* runner wrapper behavior
* shell backend safety policy

## 19.3 Phase E: TTP Catalog

The `techniques` field is intentionally compatible with future TTP catalog work.

Later scenarios may reference catalog entries instead of embedding all details.

## 19.4 Phase G and later

Autonomous and composition modes should not bypass this scenario contract.

They should generate or consume compatible attack plans and attack artifacts.

---

## 20. Done Criteria for This Contract

This contract is considered established when:

* `schemas/attack_scenario.schema.json` exists
* `docs/design/attacker-agent/scenario_schema.md` exists
* schema itself is syntactically valid JSON
* a minimal shell runner scenario sample can validate against the schema
* compatibility with legacy `name`, `mitre_attack`, `expected_artifacts`, and `steps` is documented
* runtime behavior is unchanged

---

## 21. One-line Summary

```text
attack_scenario_schema_v1 fixes the attacker-side scenario contract so static
scenario execution, future rich attack artifacts, and later autonomous modes can
share the same evaluation pipeline.
```
