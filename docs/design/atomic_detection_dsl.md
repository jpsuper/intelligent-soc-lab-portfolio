# Atomic Detection DSL

## 1. Purpose

This document defines the canonical design for the AI SOC Lab atomic detection
DSL.

The DSL has five goals:

1. define a backend-independent canonical detection-output contract;
2. reduce scenario-specific hard-coding;
3. define stable `artifact`, `behavior_features`, and `evidence` contracts
   for downstream triage, investigation, case, and action stages;
4. provide one source of truth for Python detection, Wazuh deployment, and
   future export targets; and
5. support correlation-first Incident entry from Phase 6 onward.

---

## 2. Why The Atomic Detection DSL Comes First

The stable input contract must exist before investigation is generalized into
packs. Investigation packs depend on predictable `artifact`,
`behavior_features`, and `evidence` fields.

The dependency order is:

```text
atomic detection DSL
  ↓
artifact / behavior_features / evidence contract
  ↓
investigation packs
  ↓
workflow / policy
```

Introducing packs first would make their inputs more likely to change and would
reintroduce scenario-specific assumptions.

---

## 3. Source Of Truth And System View

The lab uses this relationship:

```text
atomic detection DSL
  ↓
canonical detection output
  ↓
target adapter / compiler
  ├─ Python detection target
  ├─ Wazuh deployment target
  └─ future export target
```

### 3.1 Source Of Truth

- The DSL is the detection-rule source of truth.
- Canonical detection output is the shared internal contract.
- Wazuh is a deployment, alert, and search target.

Downstream agents therefore depend on canonical detection output rather than
backend-specific fields.

### 3.2 DSL Responsibilities

The atomic detection DSL expresses:

- the expected input source;
- the conditions that produce a hit;
- the emitted `artifact`;
- the attached `behavior_features`; and
- the targets for which the rule may be compiled or adapted.

---

## 4. Responsibilities In The Feature Lifecycle

The lab separates features into these layers:

- `behavior_features`: observed facts attached by detection;
- `derived_features`: meaning derived during triage;
- `enriched_features`: context added during investigation; and
- `assessment`: the final judgment.

### 4.1 Key Rule

Detection and the DSL should attach only observation-based
`behavior_features`. Interpretive or conclusion-oriented meaning belongs to
triage or investigation.

### 4.2 Detection And DSL Examples

- `remote_download`
- `temporary_path_execution`
- `execution_after_download`
- `direct_ip_download`
- `permission_change_before_execution`

### 4.3 Triage And Investigation Examples

- `download_and_execute_chain`
- `high_risk_execution_flow`
- `same_parent_process_chain`
- `payload_path_confirmed`

The DSL therefore defines observation-based `behavior_features`; it is not the
definition point for every feature used by the pipeline.

---

## 5. Initial Scope

Keep the initial artifact vocabulary intentionally small:

- `ssh_failed_login`
- `ssh_success_login`
- `ssh_key_login`
- `authorized_keys_modification`
- `process_exec`

Possible later additions include:

- `sudo_command`
- `user_creation`

This initial vocabulary is sufficient to represent the artifacts required by
`scenario_003`, `scenario_004`, `scenario_005`, and `scenario_006`
without embedding scenario-specific output contracts.

---

## 6. Minimal Schema Shape

The minimal rule shape is:

```yaml
id: auth.ssh_success_password
title: SSH successful password login
status: experimental

log_source:
  product: linux
  service: sshd

match:
  event_type: ssh_success_login
  auth_method: password

artifact: ssh_success_login
severity: medium

behavior_features:
  ssh_success: true
  password_authentication: true

metadata:
  mitre:
    - T1078
  references: []
  tags: []

targets:
  - python
  - wazuh
```

### 6.1 Required Fields

- `id`
- `title`
- `log_source`
- `match`
- `artifact`
- `severity`
- `behavior_features`
- `targets`

### 6.2 Optional Fields

- `status`
- `metadata`
- `metadata.mitre`
- `metadata.references`
- `metadata.tags`

---

## 7. Canonical Detection Output

Canonical detection output passed downstream from the DSL contains at least
the following fields:

```yaml
id: det-000001
rule_id: auth.ssh_success_password
title: SSH successful password login

log_source:
  product: linux
  service: sshd

event_type: ssh_success_login
artifact: ssh_success_login
severity: medium

host: ubuntu-victim01
user: victim01
src_ip: 192.0.2.40
path: null
command_line: null
auth_method: password
result: success

behavior_features:
  ssh_success: true
  password_authentication: true

evidence_refs:
  - ssh_auth_events.json#event-10

raw_event_refs:
  - sshd.log:1234

time_window_start: 2026-04-11T04:06:55Z
time_window_end: 2026-04-11T04:06:55Z
```

### 7.1 Required Common Fields

- `id`
- `rule_id`
- `title`
- `log_source`
- `event_type`
- `artifact`
- `severity`
- `host`
- `user`
- `src_ip`
- `path`
- `command_line`
- `behavior_features`
- `evidence_refs`
- `raw_event_refs`
- time-window fields
  - `time_window_start`
  - `time_window_end`

### 7.2 Notes

- `auth_method` and `result` are optional because they do not apply to every
  artifact.
- `path` and `command_line` may be null when they do not apply.
- Canonical output remains backend-independent.

---

## 8. Initial Rule Templates

### 8.1 ssh_failed_login

```yaml
id: auth.ssh_failed_login
title: SSH failed login
status: experimental

log_source:
  product: linux
  service: sshd

match:
  event_type: ssh_auth_failure

artifact: ssh_failed_login
severity: low

behavior_features:
  ssh_auth_failure: true
  password_authentication: true

metadata:
  mitre:
    - T1110
  references: []
  tags:
    - auth
    - ssh

targets:
  - python
  - wazuh
```

### 8.2 ssh_success_login

```yaml
id: auth.ssh_success_password
title: SSH successful password login
status: experimental

log_source:
  product: linux
  service: sshd

match:
  event_type: ssh_success_login
  auth_method: password

artifact: ssh_success_login
severity: medium

behavior_features:
  ssh_success: true
  password_authentication: true

metadata:
  mitre:
    - T1078
  references: []
  tags:
    - auth
    - ssh

targets:
  - python
  - wazuh
```

### 8.3 ssh_key_login

```yaml
id: auth.ssh_success_publickey
title: SSH successful public key login
status: experimental

log_source:
  product: linux
  service: sshd

match:
  event_type: ssh_key_login
  auth_method: publickey

artifact: ssh_key_login
severity: medium

behavior_features:
  ssh_success: true
  publickey_authentication: true

metadata:
  mitre:
    - T1078
    - T1021
  references: []
  tags:
    - auth
    - ssh
    - persistence-reuse

targets:
  - python
  - wazuh
```

### 8.4 authorized_keys_modification

```yaml
id: persistence.authorized_keys_modification
title: authorized_keys modification
status: experimental

log_source:
  product: linux
  service: wazuh_fim

match:
  path_suffix: /.ssh/authorized_keys
  event: modified

artifact: authorized_keys_modification
severity: high

behavior_features:
  file_modification: true
  ssh_authorized_keys_targeted: true
  persistence_related_path: true

metadata:
  mitre:
    - T1098
  references: []
  tags:
    - persistence
    - fim
    - ssh

targets:
  - python
  - wazuh
```

### 8.5 process_exec

```yaml
id: execution.process_exec
title: Suspicious process execution chain
status: experimental

log_source:
  product: linux
  service: auditd

match:
  detection_type: suspicious_download_chmod_execute

artifact: process_exec
severity: high

behavior_features:
  remote_download: true
  temporary_path_execution: true
  execution_after_download: true
  permission_change_before_execution: true

metadata:
  mitre:
    - T1105
    - T1059
  references: []
  tags:
    - execution
    - process
    - auditd

targets:
  - python
```

---

## 9. Implementation Boundaries

The implementation should preserve these responsibilities:

- the loader reads YAML and validates required fields;
- the evaluator applies `match` conditions to normalized input;
- the evaluator emits canonical `artifact` and `behavior_features` fields;
- target adapters translate the canonical rule without becoming a second source
  of truth; and
- scenario runners and orchestration code do not embed replacement copies of
  DSL match logic.

A complete Wazuh XML generator is not required for the DSL to serve as the
lab-local source of truth. Target expansion must preserve canonical output and
be validated independently.

---

## 10. Relationship To Wazuh

Wazuh is a deployment, alert, and search target rather than the rule source of
truth:

- DSL: source of truth;
- canonical detection output: shared lab contract; and
- Wazuh: baseline collection, decoding, basic detection, and search backend.

Downstream agents must not depend directly on Wazuh-specific fields. An adapter
or normalizer should map required source fields into the canonical model.

---

## 11. Reference Directory Layout

```text
detection/
  dsl/
    ssh_failed_login.yaml
    ssh_success_login.yaml
    ssh_key_login.yaml
    authorized_keys_modification.yaml
    process_exec.yaml
  compiler/
    loader.py
    evaluator.py
    targets/
      python.py
      wazuh.py
```

---

## 12. Non-Goals

This contract does not require:

- converting every rule to Sigma;
- complete Sigma-to-Wazuh generation;
- rewriting the investigation agent;
- introducing queue or Redis Stream event delivery;
- introducing a workflow engine;
- implementing multi-host or external-intelligence support; or
- decoding or executing untrusted command content.

---

## 13. Contract Acceptance Criteria

The contract is usable when:

1. the rule schema and required fields are explicit;
2. the initial artifact vocabulary can be represented in DSL rules;
3. a loader and evaluator can validate and apply those rules;
4. scenarios can emit canonical artifacts without scenario-only downstream
   assumptions;
5. canonical detection output is backend-independent; and
6. `artifact`, `behavior_features`, and `evidence` remain stable inputs for
   downstream stages.

These are contract criteria, not a live implementation checklist. Current
completion and validation evidence belong in the
[Main Roadmap](../roadmap/roadmap.md) and
[Phase 6](../roadmap/phase6.md).

---

## 14. Summary

The atomic detection DSL stabilizes the observation contract before
investigation packs, policies, or workflows are generalized. This ordering
keeps downstream stages backend-independent and reduces scenario-specific
coupling.

---

## 15. Status And Evidence Ownership

This document owns the DSL rule shape, feature lifecycle boundary, canonical
detection-output semantics, and target-adapter responsibilities. The
[Main Roadmap](../roadmap/roadmap.md) and
[Phase 6](../roadmap/phase6.md) own current implementation status, validation
depth, priorities, and sequencing.

The following descriptions are contract semantics and must not be interpreted
as a claim that every source, target, scenario, or deployment path is complete.

### 15.1 Windows Match Operator Semantics

Windows rule content and match conditions remain source- and domain-specific
while using the shared DSL loader, evaluator, and canonical output.

The defined Windows operators are:

- `process_name_casefold`: case-insensitive exact process-name comparison;
- `command_token_casefold_any`: case-insensitive exact-token comparison
  against an explicit non-empty token list.

Windows rules require exact `source: sysmon`, `platform: windows`, and
`event_type: process_exec` routing. Substrings such as
`-EncodedCommandSuffix` and `prefix-enc` do not match. Unknown match
operators fail closed. Command text remains untrusted data and is never decoded
or executed.

### 15.2 Severity Boundary

The Windows rules use `severity: low` because `severity` is a required global
DSL field and `low` is the lowest existing value. This is rule metadata, not a
malicious verdict, Incident severity, confidence, assessment, or response
approval.

### 15.3 Extension Conditions

Add rules, operators, or export targets only when required by an evidence-backed
scenario or backend integration. Each extension must preserve canonical output,
fail closed for unknown operators, keep untrusted source content inert, and add
focused validation. Project priority and delivery order remain Roadmap-owned.
