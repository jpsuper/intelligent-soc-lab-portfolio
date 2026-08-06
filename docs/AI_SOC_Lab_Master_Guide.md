# AI SOC Lab Master Guide

[日本語](AI_SOC_Lab_Master_Guide_ja.md)

An integrated guide for progressing phase by phase through an AI SOC research lab built across two physical hosts.

> Canonical current-status source:
> [Main Roadmap](roadmap/roadmap.md)
>
> This guide owns stable architecture, artifact boundaries, evidence rules, and
> operating policy. It does not own active priorities, incomplete-work queues,
> or frequently changing Done Criteria.

---

# 1. Lab Goal

The purpose of this lab is to support continuous learning and improvement of the following capabilities in one environment.

- Adversary Simulation
- Detection Engineering
- Correlation
- AI Triage
- Investigation Analysis
- Case Management
- Action Planning / Approval
- Investigation / DFIR / External Integrations
- Deception
- Automated Improvement Loop

The target research loop is:

```text
Attack / Noise / Deception
        ↓
Telemetry Collection
        ↓
Detection
        ↓
Correlation
        ↓
Incident Builder
        ↓
Triage
        ↓
Investigation
        ↓
Case
        ↓
Action
        ↓
Execution / Approval
        ↓
DFIR / External Integrations
        ↓
Rule Improvement
        ↓
Attack Again
```

For detailed responsibilities and trust boundaries in the defender-side
telemetry → parser → normalization → detection → correlation → triage → investigation flow, see the
[Defender Event Processing Flow](architecture/defender-event-processing-flow.md)
document.

Design principles:

- Detection is deterministic.
- AI supports analyst, triage, investigation, and planning work.
- Deception creates high-confidence detection signals.
- Normal activity and noise make the SOC environment more realistic.
- Risky operations remain behind an approval gate.
- Automation advances incrementally while preserving comparability.

---

## 1.1 Scenario-aware Artifact Selection
Rather than merely listing detected events, this lab determines
which artifact should be primary for each scenario.

Examples:
- scenario_003: `process_exec` is primary (execution).
- scenario_004: `authorized_keys_modification` is primary (persistence installation).
- scenario_005: `ssh_key_login` is primary (persistence reuse).
- scenario_006: `process_exec` is primary (post-login action after key reuse).

This approach:
- accurately represents distinct attack domains such as execution, persistence, and privilege escalation; and
- improves consistency across Case, Investigation, and response artifacts.

This design is an important architectural step in Phase6.

---

## 1.2 Atomic Detection DSL and Correlation-First Entry

This lab avoids scenario-specific hardcoding for detection, investigation, and Case creation by defining backend-independent atomic detection output as a common contract.

The basic flow is:

```text
atomic detection DSL
  ↓
canonical detection output
  ↓
dedupe
  ↓
correlation
  ↓
incident / triage / investigation / case
```

### Source of truth

- DSL = source of truth
- canonical detection output = the common contract within the lab
- Wazuh = deploy / search target

### Feature layers

- `behavior_features` = observed facts assigned by Detection
- `derived_features` = interpretations produced by Triage
- `enriched_features` = contextual enrichment produced by Investigation
- `assessment` = final analytical judgment

Detection should assign only `behavior_features` in principle and leave conclusion-oriented interpretation to downstream stages.

### Correlation-first incident entry

A process-first Incident construction path alone does not represent persistence-focused scenarios well.
The architecture therefore supports deduplicating and correlating atomic detections before constructing an Incident from the result.

Examples:
- `ssh_failed_login`
- `ssh_success_login`
- `authorized_keys_modification`

These three detections are correlated to construct an Incident with `authorized_keys_modification` as the primary artifact.

### Why it matters

This design makes it easier to handle distinct attack domains, including persistence and persistence reuse as well as execution, on a common foundation.


## 1.3 Attacker-side Artifact Contracts

The Attacker Agent separates attack execution results into the following artifacts.

```text
attack_result.json
  Summary of the attack run

attack_execution_log.json
  Execution log for the shell backend / runner

attack_observed_effects.json
  Effects observed on the attacker side
```

Key boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

Examples:

- `ssh_login_succeeded` is the attacker-side observation corresponding to `ssh_key_login`.
- `payload_execution_succeeded` is the attacker-side observation corresponding to `process_exec`.
- An effect observed by the attacker side does not prove that the defender side detected it.

The attacker-agent can currently derive the following artifacts from shell execution evidence.

```text
scenario_004:
  ssh_bruteforce_attempted        -> ssh_failed_login
  ssh_login_succeeded             -> ssh_success_login
  authorized_keys_write_succeeded -> authorized_keys_modification

scenario_005:
  ssh_login_succeeded             -> ssh_key_login

scenario_006:
  ssh_login_succeeded             -> ssh_key_login
  payload_execution_succeeded     -> process_exec
```

These artifacts can be compared with defender-side observed artifacts through `observed_effects_alignment`.


## 1.4 Structured Runner Output and Observed Effects Alignment

To avoid excessive dependence on shell runner stdout markers, the attacker-agent uses a structured runner output convention.

Basic form:

```text
ATTACK_EVENT_JSON: {"event_type":"ssh_login_succeeded","artifact":"ssh_key_login","status":"observed","confidence":"medium"}
```

Key boundary:

```text
ATTACK_EVENT_JSON = attacker-side structured evidence
ATTACK_EVENT_JSON != defender-side telemetry
ATTACK_EVENT_JSON != defender-side detection
```

The following capabilities are available:

- An `ATTACK_EVENT_JSON:` parser helper and focused tests exist.
- The scenario_004 / 005 / 006 runners emit structured events.
- `attack_observed_effects.json` prefers structured runner events when they are available.
- `attack_execution_log.json` includes additive `structured_events` when valid `ATTACK_EVENT_JSON:` lines are present.
- `structured_events` do not replace raw `stdout`, `stderr`, or execution events.
- The legacy stdout-marker and `exit_code` fallback remains available when structured events are absent.
- Structured runner events have been smoke-validated for scenario_004 / 005 / 006:
  - scenario_004: `ssh_bruteforce_attempted` → `ssh_failed_login`
  - scenario_004: `ssh_login_succeeded` → `ssh_success_login`
  - scenario_004: `authorized_keys_write_succeeded` → `authorized_keys_modification`
  - scenario_005: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_006: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_006: `payload_execution_succeeded` → `process_exec`
- `observed_effects_alignment` is an additive signal that compares attacker-side observed effects with defender-side observed artifacts.
- It does not change existing `overall_result`, `detected`, or verdict behavior.
- The Rule Improvement Agent can produce
  `observed_effects_alignment_signals.json` from `evaluation_result.observed_effects_alignment`.
- `candidate_review.md` presents observed-effects alignment signals for human review.
- Observed-effects signals remain review inputs and are not automatically inserted into `rule_candidates.yaml`.
- Shell backend contract static tests verify runner-path, executable-bit, timeout, `state_changing`, and inline-shell-field boundaries.
- `docs/operations/smoke_runbook.md` records structured-runner and observed-effects smoke checks.


## 1.5 Comparison Harness and Improvement Cycle

The Phase6 extended MVP adds a **comparable improvement loop** alongside the single-run pipeline.

The comparison spine extends beyond Triage to Investigation and action planning.

```text
triage_result comparison
  ↓
investigation_result comparison
  ↓
action_result comparison
```

The basic flow is:

```text
current / champion
        +
variant / challenger
        +
rule baseline
        ↓
compare.json
        ↓
judge_result.json
        ↓
Rule Improvement Agent
        ↓
rule_candidates.yaml
prompt_candidates.yaml
promotion_recommendation.yaml
parser_candidates.yaml
rule_improvement_export_artifact_validation_summary.json
observed_effects_alignment_signals.json
candidate_review.md
        ↓
batch validation
        ↓
human review
```

The current and variant outputs serve as champion and challenger.

```text
triage_ai_current = current adopted version / baseline / champion
triage_ai_variant = improvement candidate / challenger
triage_ai_variant_next = next improvement candidate
```

Promotion is not determined from a single winner.
Multiple scenarios such as `scenario_004 / 005 / 006` are batch-compared so that primary-artifact coverage, overclaim control, evidence grounding, and response fitness can be assessed across the set during human review.

The following foundation is available:

- triage comparison harness
- investigation comparison harness
- action comparison harness
- compare / judge schema
- generic rubric
- must-have / nice-to-have evaluation of response keywords
- evidence-aware compare / judge refinement
- action compare / judge refinement
- minimal Rule Improvement Agent
- promotion recommendation
- batch compare runner
- connection from `action_result` to `collection_request`
- `collection_result.json` contract downstream of `collection_request.json`
- generation of observed-effects alignment signals and presentation in candidate review

## 1.6 Durable Capability and Evidence Boundaries

Current implementation status, validation depth, incomplete work, and active
priority are maintained in the [Main Roadmap](roadmap/roadmap.md). This section
defines the stable pipeline shape and the boundaries that later implementation
must preserve.

```text
attack / scenario
  ↓
logs / telemetry
  ↓
normalization
  ↓
canonical detection
  ↓
dedupe / correlation / Incident selection
  ↓
triage
  ↓
pre-case investigation
  ↓
initial case
  ↓
action planning
  ↓
collection request / approval / execution
  ↓
collection_result.json
  ↓
post-action DFIR / external integration
  ↓
evaluation / comparison / reviewed improvement
```

Stable boundaries:

- Source parsing and normalization may remain platform- or provider-specific.
  Downstream stages consume canonical artifacts rather than raw source formats.
- Atomic detections remain reviewable observations. Dedupe, correlation, and
  exact Incident selection form a separate boundary before downstream case
  processing.
- Fixture parity, schema validation, manual observation, live collection, and
  end-to-end execution are different evidence levels and must not be conflated.
- Attacker-side observed effects are execution evidence, not defender telemetry
  or proof that a detection occurred.
- Pre-case `investigation_result.json` remains separate from post-action DFIR.
  Collection results must not be fed back into the pre-case artifact.
- Case enrichment from collection outcomes is append-only and must not silently
  rewrite assessment, verdict, confidence, severity, or approval state.
- Rule Improvement proposals, candidates, exports, and promotion
  recommendations remain review artifacts. They do not authorize apply,
  deployment, mutation, or promotion.
- Deception hits require deterministic defender-side trap observations.
  Attacker-side runner claims alone do not establish a deception hit.
- State-changing response, containment, collection, apply, deployment, and
  promotion actions remain approval-gated.

Detailed ownership:

- current status, priority, incomplete work, and Done Criteria:
  [Main Roadmap](roadmap/roadmap.md)
- Phase6 history and validation evidence:
  [Phase6 Roadmap](roadmap/phase6.md)
- Phase7 history and deferred scenario boundary:
  [Phase7 Roadmap](roadmap/phase7.md)
- cross-platform defender flow:
  [Defender Event Processing Flow](architecture/defender-event-processing-flow.md)
- post-action evidence boundary:
  [Post-action DFIR Investigation](design/dfir/post_action_dfir_investigation.md)
- reviewed Rule Improvement artifact flow:
  [Rule Improvement Candidate Creation Workflow](design/rule-improvement/rule_improvement_candidate_creation_workflow.md)

# 2. Hardware Layout

## Node1: Attack / Victim Lab

Existing host:
- TRIGKEY Speed S5 Pro
- Ryzen 7 5800H
- 32GB RAM
- 1TB NVMe

Roles:
- attacker
- victim hosts
- AD / Windows / Linux
- honeypot / deception targets
- background activity generation

## Node2: SOC Core Host

Second host:
- GMKtec NucBox K8 Plus
- Ryzen 7 8845HS
- 64GB RAM
- 1TB NVMe

Roles:
- log pipeline
- detection engine
- correlation engine
- Wazuh
- TheHive
- Velociraptor
- triage / investigation
- action / orchestration
- rule improvement
- AI deception

## Node3: Future AI Engine (optional)

An optional future node dedicated to AI workloads.

Roles:
- Ollama
- Qwen
- embeddings
- local AI SOC analyst
- future enrichment / RAG / memory workloads

---

# 3. Recommended VM Layout

## Node1 (Attack / Victim)

| VM | Role | Suggested Spec |
|---|---|---|
| kali-attacker | attacker / tooling | 4 vCPU / 8GB / 80-100GB |
| ubuntu-victim01 | SSH target / auth.log | 2 vCPU / 4GB / 50GB |
| ubuntu-victim02 | persistence / lateral | 2 vCPU / 4GB / 50GB |
| windows-victim01 | Windows telemetry | 4 vCPU / 8GB / 100GB |
| dc01 | AD / identity lab | 4 vCPU / 8GB / 100GB |
| honeypot01 | fake service / share | 2 vCPU / 2-4GB / 40GB |

## Node2: SOC Core VM Layout

| VM | Role | Suggested Spec |
|---|---|---|
| soc-analyzer | detection / correlation / incident builder | 6 vCPU / 16GB / 200GB |
| wazuh | SIEM / EDR platform | 4 vCPU / 8GB / 200GB |
| log-pipeline | Vector / Fluent Bit | 2 vCPU / 4GB / 80GB |
| thehive | case management | 2 vCPU / 6GB / 100GB |
| velociraptor | investigation / DFIR | 2 vCPU / 4GB / 80GB |
| ai-soc | AI triage / investigation / planning client | 4 vCPU / 8GB / 100GB |

---

# 4. Final Architecture

```text
Attack Simulation + Background Activity + Deception
                        │
                        ▼
                 Victim Network
          (Linux / Windows / AD / Honeypot)
                        │
                        ▼
                 Telemetry Collection
      (auth.log / Sysmon / auditd / Wazuh agent)
                        │
                        ▼
                   Log Pipeline
              (Vector / Fluent Bit)
                        │
                        ▼
                 Detection Engine
     (Python / Sigma-like rules / future Wazuh)
                        │
                        ▼
                Correlation Engine
                        │
                        ▼
                 Incident Builder
                        │
                        ▼
                   Triage Agent
                        │
                        ▼
              Investigation Analysis
                        │
                        ▼
                     Case Agent
                        │
                        ▼
                   Action Agent
                        │
                        ▼
             Executor Agent / Approval Gate
                        │
                        ▼
      DFIR / External Integrations / Case Systems
         (Velociraptor / TheHive / future adapters)
                        │
                        ▼
                 Rule Improvement
                        │
                        ▼
                      Attack Again
```

> Note:
> The offensive side starts with Scenario and Attacker components.
> It can later evolve toward an offensive architecture with an objective-driven planner, specialist delegation, tool selection, and memory / graph capabilities.

---

# 5. Agent Architecture

Agents introduced incrementally in the lab.

| Agent | Role | Main Phase |
|---|---|---|
| Telemetry Agent | Acquire raw and forwarded logs | Phase0 |
| Log Parser Agent | Normalize sources such as auth.log, sshd, sudo, and auditd into canonical events | Phase0 / Phase5 |
| Detection Agent | Perform deterministic detection and assign `behavior_features` | Phase1 / Phase6 |
| Correlation Agent | Deduplicate and correlate atomic detections to form the Incident entry boundary | Phase1 / Phase6 |
| Incident Builder Agent | Generate `incident.json` from correlated detections | Phase1 |
| Triage Agent | Perform SOC analysis and initial judgment; produce `risk_score`, `derived_features`, and `assessment` | Phase2 / Phase6 |
| Rule Triage Baseline | Provide a deterministic baseline for comparison with AI Triage | Phase6 |
| Investigation Agent (pre-case) | Perform evidence-aware investigation using Incident, Triage, and defender-side telemetry; produce `investigation_result.json`, enriched features, evidence gaps, and pivots | Phase4 / Phase6 |
| Case Agent | Normalize run results into `case.json` as the action-planning input boundary; append only dedicated DFIR fields when a collection result is available | Phase4 / Phase6 |
| Post-action DFIR / Integration Workflow | Handle outcomes and collected outputs after Action / collection; perform DFIR evidence review, reviewed finding-based Case enrichment, and optional external Case updates; remain separate from the pre-case Investigation Agent | Follow-on |
| TheHive Agent | Create external Case and observable records from the initial `case.json`; later append reviewed post-action DFIR findings | Phase4 / Phase5 / Follow-on |
| Velociraptor Agent | Generate DFIR collection requests, integrate collection outcomes, and support future actual collection execution | Phase4 / Phase5 / Follow-on |
| Action Agent | Generate response policy and playbooks grounded in Case and evidence | Phase2 extension / Phase5 / Phase6 |
| Executor Agent | Execute playbooks, enforce approval gates, and record `decision_log` | Phase5 / future extension |
| Scenario Agent | Define attack scenarios | Phase3 |
| Attacker Agent | Execute attacks and generate `attack_result`, `attack_execution_log`, and `attack_observed_effects` | Phase3 / Phase6 |
| Attack Planner Agent | Decompose objectives into subtasks and select tools or specialists (future extension) | Phase3 extension / future |
| Rule Improvement Agent | Generate rule, prompt, and promotion candidates plus review artifacts from compare / judge outputs | Phase6 |
| Scenario Orchestrator / Harness Runner | Orchestrate the process pipeline, Triage / Investigation / Action harnesses, and batch comparison | Phase6 |
| Deception Agent | Generate honeytokens, honey shares, and decoys | Phase7 |
| Trap Detection Agent | Detect deception hits | Phase7 |
| Background Activity Agent | Generate normal-activity noise | Phase8 |

## 5.1 Agent Dependency

```text
Telemetry Agent
   ↓
Log Parser Agent
   ↓
Detection Agent
   ↓
Correlation Agent
   ↓
Incident Builder Agent
   ↓
Triage Agent
   ↓
Pre-case Investigation Agent
   ↓
Case Agent (initial case)
   ↓
Action Agent
   ↓
Executor Agent / Approval Gate
   ├─ initial TheHive / Case integrations
   ├─ Collection / Velociraptor execution (after approval when required)
   │    ↓
   │  Post-action DFIR / Integration Workflow
   │    ├─ reviewed finding-based case enrichment
   │    ├─ optional external case update
   │    └─ human-reviewable follow-up signal
   └─ Rule Improvement Agent

Scenario Agent
   ↓
Attacker Agent
   ↓
Scenario Orchestrator

Deception Agent
   ↓
Trap Detection Agent

Background Activity Agent
   ↓
Telemetry / Detection realism
```

## 5.2 Historical Minimum Viable Agent Order

The original minimum build-up order was:

1. Telemetry Agent
2. Detection Agent
3. Incident Builder Agent
4. Triage Agent
5. Correlation Agent
6. Scenario Agent / Attacker Agent
7. Case Agent / Investigation Agent
8. Action Agent / Executor Agent
9. Deception Agent
10. Background Activity Agent
11. Rule Improvement Agent / Orchestrator

This list records architectural sequencing only. It does not represent current
implementation status or active priority; use the
[Main Roadmap](roadmap/roadmap.md) for both.

---

# 6. Durable Phase Architecture Map

This chapter records the stable architectural role of each phase. It does not
duplicate current status, incomplete work, priority, or Done Criteria from the
[Main Roadmap](roadmap/roadmap.md).

| Phase | Stable architectural role | Detailed history and evidence |
|---|---|---|
| Phase0 | Establish the minimal Attack → Log → Parse → Detect → Incident baseline. | [phase0.md](roadmap/phase0.md) |
| Phase1 | Add deterministic correlation and Incident construction. | [phase1.md](roadmap/phase1.md) |
| Phase2 | Add triage, initial assessment, and approval-aware action planning. | [phase2.md](roadmap/phase2.md) |
| Phase3 | Add reproducible attacker scenarios, isolated runs, and evaluation inputs. | [phase3.md](roadmap/phase3.md) |
| Phase4 | Add Case ownership, timeline, and external integration boundaries. | [phase4.md](roadmap/phase4.md) |
| Phase5 | Add endpoint telemetry and process-focused detection while preserving canonical events. | [phase5.md](roadmap/phase5.md) |
| Phase6 | Add feature ownership, comparison harnesses, post-action evidence, and reviewed improvement artifacts. | [phase6.md](roadmap/phase6.md) |
| Phase7 | Add deterministic local-lab deception artifacts while preserving defender-side source-of-truth and approval boundaries. | [phase7.md](roadmap/phase7.md) |
| Phase8 | Increase background activity and telemetry realism for false-positive and tuning work. Phase8 is maintained as a section in the Main Roadmap; no separate `phase8.md` exists. | [Main Roadmap](roadmap/roadmap.md) |

Cross-phase rules:

- A later phase extends the artifact pipeline; it does not silently redefine an
  earlier artifact or evidence boundary.
- Phase documents preserve phase-specific history, validation evidence, and
  scoped decisions.
- The Main Roadmap is authoritative for current Implemented, Validated,
  Planned, Deferred, and Unverified status.
- Design documents remain authoritative for individual contracts and technical
  decisions.
- A phase label is organizational context, not evidence that a capability has
  been implemented or validated.

# 7. Repository Organization Boundary

The current physical layout is governed by the
[Repository Structure Policy](development/repository_structure.md),
[ADR 0001](adr/0001-repository-organization-policy.md), and
[ADR 0002](adr/0002-domain-oriented-scripts-and-tests-layout.md).
This guide does not define a competing target tree.

The stable top-level roots are:

```text
agents/
attacks/
common/
configs/
detection/
docs/
rubrics/
schemas/
scripts/
scenarios/
tests/
tools/
workflows/
```

Durable placement rules:

- keep stage-specific agents and integration adapters under `agents/` until a
  reviewed architecture decision changes that boundary
- keep runnable attack support under `attacks/` and scenario intent under
  `scenarios/`
- keep deterministic detection logic under `detection/`
- keep schemas centralized under `schemas/`
- keep shared utilities under `common/` and avoid moving stage-specific
  business logic there without demonstrated reuse
- keep orchestration, export, harness, and utility entry points under
  `scripts/`; cohesive domains may use reviewed subdirectories
- keep fixtures under `tests/fixtures/` and generated run artifacts outside
  version-controlled source paths
- keep documentation purpose-oriented under `docs/architecture/`,
  `docs/design/`, `docs/development/`, `docs/adr/`,
  `docs/operations/`, `docs/runbooks/`, and `docs/roadmap/`

Do not create new top-level roots or reorganize the repository from an
aspirational tree in this guide. A new root or cross-domain move requires the
repository-structure review process and, when appropriate, an ADR.

---

# 8. Documentation Ownership and Maintenance

Follow the
[Documentation Language Policy](development/documentation-language-policy.md)
and update the smallest authoritative document set required by the change.

- `README.md` owns the first-reader overview and concise current snapshot.
- This Master Guide owns stable architecture, artifact boundaries, evidence
  rules, and operating policy.
- `docs/roadmap/roadmap.md` owns current status, active priorities,
  incomplete work, sequencing, and Done Criteria.
- `docs/roadmap/phase0.md` through `phase7.md` preserve phase-specific
  history, validation evidence, and scoped decisions. Phase8 remains a section
  in the Main Roadmap.
- `docs/design/` owns individual contracts and technical decisions.
- `docs/operations/` and `docs/runbooks/` own executable operational and
  handoff procedures.
- `docs/development/` and `docs/adr/` own repository-wide policy and
  architectural decisions.

Do not create placeholder documents solely because an older planning list
named them. Add a document only when it has a clear owner, durable purpose, and
reviewed location.

---

# 9. Key Schemas / Artifact Contracts

This lab prioritizes **artifact contracts** over Agent implementation details.
Each stage emits a JSON or YAML artifact that downstream stages consume as input.

## 9.1 Normalized Event

```json
{
  "timestamp": "2026-03-16T10:00:00Z",
  "host": "ubuntu-victim01",
  "event_type": "ssh_failed_login",
  "src_ip": "192.0.2.40",
  "user": "root",
  "raw_log": "...",
  "rule": null,
  "severity": null
}
```

Process telemetry uses normalized process events such as the following.

```json
{
  "event_type": "process_exec",
  "timestamp": "2026-03-24T08:08:09Z",
  "host": "ubuntu-victim01",
  "pid": 1234,
  "ppid": 1200,
  "user": "victim01",
  "exe": "/usr/bin/curl",
  "command_line": "curl ...",
  "cwd": "/home/victim01",
  "source": "auditd"
}
```

## 9.2 Detection / Atomic Artifact

Detection is deterministic and should assign only observation-level `behavior_features` in principle.

Primary artifact examples:
- `ssh_failed_login`
- `ssh_success_login`
- `ssh_key_login`
- `authorized_keys_modification`
- `sudo_command`
- `process_exec`
- `suspicious_download_chmod_execute`

## 9.3 Incident JSON

```json
{
  "incident_id": "INC-0001",
  "scenario_name": "ssh_bruteforce_priv_esc",
  "severity": "high",
  "host": "ubuntu-victim01",
  "src_ip": "192.0.2.40",
  "timeline": [],
  "matched_rules": [
    "ssh_failed_login",
    "ssh_success_login",
    "sudo_command"
  ],
  "behavior_features": {
    "credential_access": true,
    "privilege_escalation": true
  }
}
```

## 9.4 Triage Result

```json
{
  "incident_id": "INC-0001",
  "verdict": "malicious",
  "confidence": "high",
  "priority": "P1",
  "risk_score": 85,
  "summary": "Possible brute force followed by privilege escalation.",
  "attack_story": "The source IP attempted multiple SSH logins...",
  "key_observations": [],
  "mitre_attack": [],
  "recommended_actions": []
}
```

## 9.5 Feature Lifecycle

```json
{
  "behavior_features": {},
  "derived_features": {},
  "assessment": {},
  "enriched_features": {}
}
```

Responsibility boundaries:
- `behavior_features`: observed facts assigned by Detection
- `derived_features`: interpretations produced by Triage
- `assessment`: judgments such as verdict, confidence, priority, and `risk_score`
- `enriched_features`: context and evidence added by Investigation

## 9.6 Investigation Result

`investigation_result.json` is an artifact separate from Triage.

Key fields:
- `evidence_level`
- `evidence_summary`
- `unsupported_claims`
- `missing_pivots`
- `recommended_pivots`
- `enriched_features`

Optional inputs:
- `process_events.json`
- `process_chain_hits.json`
- `zeek_enrichment.json`

## 9.7 Case JSON

`case.json` is the input boundary for action planning and the source of truth for external integrations.

Required fields:
- `case_id`
- `attack_id`
- `scenario_id`
- `title`
- `status`
- `severity`
- `summary`
- `attack_result`
- `detection_result`
- `coverage`

Recommended fields:
- `triage_result`
- `key_artifacts`
- `timeline`
- `recommended_actions`
- `process_summary`
- `process_timeline`
- `investigation_notes`

## 9.8 Action Result / Approval Boundary

`action_result.json` represents response plans and playbooks in machine-readable form.

Key boundary:
- safe steps may be auto-executable
- sensitive steps require an approval gate
- containment actions remain pending approval by default
- actions must be grounded in the Case and evidence

Example action types:
- `request_dfir_collection`
- `collect_payload_or_process_evidence`
- `alert_soc_team`
- `review_payload_execution`
- `consider_host_isolation`

## 9.9 Collection Request

`collection_request.json` is a DFIR request artifact generated from `action_result`.

Current trigger types:
- `request_dfir_collection`
- `collect_payload_or_process_evidence`

Design notes:
- retain action-driven context in `collection_request.context.action_types`
- treat Velociraptor as follow-on DFIR rather than continuous collection

## 9.10 Collection Result

`collection_result.json` is a DFIR outcome artifact that records the execution result of `collection_request.json`, a manual collection result, or a mock collection result.

```text
action_result.json
  ↓
collection_request.json
  ↓
collection_result.json
  ├─ outcome-only case enrichment: `dfir_collection_summary` / `dfir_evidence_refs` (implemented)
  └─ post-action DFIR run workflow MVP / future external integration workflow
       ↓
     future executor / DFIR result comparison
```

Primary responsibilities:

- record collection status such as requested, completed, partial, failed, skipped, or cancelled
- keep `collected_artifacts`, `failed_artifacts`, and `skipped_artifacts` separate
- preserve traceability to `collection_request.json`, `action_result.json`, and `case.json`
- normalize Velociraptor, manual, mock, and future collector outcomes into a common result model
- retain references to collected evidence in `output_refs`
- for run-based mock collection, write controlled `Linux.Syslog.SSHLogin` output to `forensics/mock/Linux.Syslog.SSHLogin.json` and reference it from the collected artifact's `output_refs`

Key boundary:

- a collection result is an evidence-transport artifact, not a conclusion in the pre-case `investigation_result.json`
- the post-action DFIR workflow is separate from the pre-case Investigation Agent and does not overwrite the existing `investigation_result.json`
- a collection outcome alone does not change verdict, severity, confidence, `overall_result`, or `detected`
- it does not change action approval or containment decisions
- it does not automatically generate Rule Improvement candidates or promotion

Detailed design:

- `docs/design/dfir/collection_result_contract.md`
- `docs/design/dfir/collection_result_ingestion.md`

## 9.11 Attacker-side Artifact Contracts

The Attacker Agent emits the following artifacts separately.

```text
attack_result.json
  Summary of the attack run

attack_execution_log.json
  Execution log for the shell backend / runner

attack_observed_effects.json
  Effects observed on the attacker side
```

Key boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

This separation allows an attacker-side success that is not detected by the defender side to be represented as an `observed_effects_alignment` gap.

## 9.12 Evaluation Result / Observed Effects Alignment

In addition to expected and observed coverage, `evaluation_result.json` carries `observed_effects_alignment` as an additive Phase6 signal.

Key policy:
- keep attacker-side observations separate from defender-side detections
- `observed_effects_alignment` does not change existing `overall_result`, `detected`, or verdict behavior
- `observed_effects_alignment_signals.json` is a human-reviewable Rule Improvement signal artifact
- treat `attacker_observed_defender_missing` as a review signal and do not automatically convert it into a rule candidate

## 9.13 Harness Artifacts

A harness run uses the following base artifacts.

```text
data/harness_runs/<harness_run_id>/
  input/
  optional_inputs/
  agents/
  compare.json
  judge_result.json
  summary.md
  metadata.json
```

Triage and Rule Improvement flows additionally generate the following artifacts.

```text
rule_candidates.yaml
prompt_candidates.yaml
promotion_recommendation.yaml
parser_candidates.yaml
rule_improvement_export_artifact_validation_summary.json
observed_effects_alignment_signals.json
candidate_review.md
```

---

# 10. Durable Build and Validation Order

Active sequencing and the next implementation priority are maintained in the
[Main Roadmap](roadmap/roadmap.md). This guide retains only the durable order
needed to preserve artifact and evidence boundaries.

## 10.1 Build order

1. Acquire logs or telemetry without changing their source meaning.
2. Normalize source-specific events into canonical event contracts.
3. Produce deterministic atomic detections and factual behavior features.
4. Apply dedupe and correlation without hiding the underlying detections.
5. Select the exact Incident inputs and preserve deterministic linkage.
6. Run triage and pre-case investigation as separate reviewable stages.
7. Build the initial case and approval-aware action plan.
8. Generate collection requests and keep collection results traceable.
9. Run post-action DFIR without rewriting the pre-case Investigation artifact.
10. Compare outputs and create review-only improvement artifacts.
11. Apply, deploy, update, contain, or promote only through an explicit approval
    boundary.

## 10.2 Validation order

Use increasingly strong evidence without treating one level as another:

1. schema and structural validation
2. deterministic fixtures and exact parity
3. focused component and contract tests
4. cross-platform or cross-scenario regression
5. manual or live collection validation
6. bounded end-to-end execution validation

Fixture-backed success must not be described as live parity. Attacker-side
runner success must not be described as defender-side observation.

## 10.3 Change ownership

- active priority and Done Criteria:
  [Main Roadmap](roadmap/roadmap.md)
- source-to-common defender stage boundaries:
  [Defender Event Processing Flow](architecture/defender-event-processing-flow.md)
- Phase6 implementation history:
  [Phase6 Roadmap](roadmap/phase6.md)
- Phase7 implementation history:
  [Phase7 Roadmap](roadmap/phase7.md)
- Rule Improvement review and export boundaries:
  [Rule Improvement Candidate Creation Workflow](design/rule-improvement/rule_improvement_candidate_creation_workflow.md)

# 11. What Not to Overbuild Early

Avoid overbuilding early.

- complex multi-agent coordination
- completing local LLM migration first
- attempting to complete Windows, Linux, and AD support simultaneously
- starting with TheHive or Velociraptor integration
- completing Deception first
- completing an offensive planner or autonomous attacker first

The initial success criterion was:

```text
One attack scenario
→ logs collected
→ one detection chain
→ incident.json
→ AI triage report
```

---

# 12. Current Documentation Index

This index points to current owner documents. It is navigational and does not
replace the Main Roadmap as the current-status source.

## Architecture and repository policy

- [Agent Architecture](architecture/agent-architecture.md)
- [Lab Architecture](architecture/lab-architecture.md)
- [SOC Lab System Diagram](architecture/soc-lab-system-diagram.md)
- [Defender Event Processing Flow](architecture/defender-event-processing-flow.md)
- [Repository Structure Policy](development/repository_structure.md)
- [Documentation Language Policy](development/documentation-language-policy.md)

## Phase and status ownership

- [Main Roadmap](roadmap/roadmap.md)
- [Phase0 history and evidence](roadmap/phase0.md)
- [Phase1 history and evidence](roadmap/phase1.md)
- [Phase2 history and evidence](roadmap/phase2.md)
- [Phase3 history and evidence](roadmap/phase3.md)
- [Phase4 history and evidence](roadmap/phase4.md)
- [Phase5 history and evidence](roadmap/phase5.md)
- [Phase6 history and evidence](roadmap/phase6.md)
- [Phase7 history and evidence](roadmap/phase7.md)

## Core contracts and operational handoffs

- [Atomic Detection DSL](design/atomic_detection_dsl.md)
- [Normalized Endpoint Event Contract](design/defender/normalized_endpoint_event_contract.md)
- [Windows Telemetry Contract](design/windows/windows_telemetry_contract.md)
- [Scenario Family Expansion Policy](design/scenario_family_expansion_policy.md)
- [Post-action DFIR Investigation](design/dfir/post_action_dfir_investigation.md)
- [Rule Improvement Candidate Creation Workflow](design/rule-improvement/rule_improvement_candidate_creation_workflow.md)
- [AI-assisted Rule Improvement Review Handoff](runbooks/ai_assisted_rule_improvement_review_handoff.md)
- [Smoke Runbook](operations/smoke_runbook.md)

When a new contract or runbook becomes authoritative, add it to the most
specific owner document first. Update this index only when the reference is
stable and useful across workstreams.
