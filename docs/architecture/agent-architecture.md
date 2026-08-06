# Agent Architecture

This document defines the AI SOC Lab's stable target architecture, agent
responsibilities, dependencies, artifact boundaries, and trust boundaries.

It does not own volatile implementation status, active priorities, unfinished
work, or Done Criteria. The
[Main Roadmap](../roadmap/roadmap.md) is the authoritative source for current
status.

---

## 1. Design Principle

This document separates the following two concerns.

1. **Target Architecture**
   - the intended end-state architecture of the lab
   - responsibilities for implemented and future agents
   - stable artifact and trust boundaries between stages

2. **Current Implementation Status**
   - maintained in the Main Roadmap
   - updated from code, tests, schemas, fixtures, and validation evidence
   - never inferred from this document's component list or dependency diagrams

Unimplemented agents remain in the target architecture as explicit future
responsibilities. Their presence in this document does not mean that they are
Implemented, Validated, live, or runtime-validated.

---

## 2. Naming Convention

- Workflow / responsibility descriptions use conceptual stage names without "Agent" (for example: Triage, Investigation, Case, Action, Execution).
- Component inventories and implementation references use concrete implementation names with "Agent" (for example: Triage Agent, Investigation Agent, Case Agent, Action Agent, Executor Agent).

### Examples

#### Workflow / responsibility description
```text
Detection
→ Triage
→ Investigation
→ Case
→ Action
→ Execution / Approval
```

#### Component / implementation description
```text
Detection Agent
→ Triage Agent
→ Investigation Agent
→ Case Agent
→ Action Agent
→ Executor Agent
```

---

## 3. Full Agent List

| Agent | Purpose | Input | Output | Main Phase |
|---|---|---|---|---|
| Telemetry Agent | Log collection | raw logs | collected raw logs / forwarded logs | Phase0 |
| Log Parser Agent | Normalization | raw log | normalized events | Phase0 |
| Detection Agent | Atomic detection / initial feature assignment | normalized events | detection hits | Phase1 |
| Correlation Agent | Correlation | detection hits | correlated incident candidates | Phase1 |
| Incident Builder Agent | Incident construction | correlated incidents + refs + features | incident.json | Phase1 |
| Triage Agent | SOC analysis / initial judgment / risk assessment | incident + optional context | triage_result.json | Phase2 |
| Action Agent | Response planning / playbook generation | triage / investigation / case | action_result.json | Phase2 extension |
| Executor Agent | Playbook execution / approval control | action_result / playbook | execution result / external execution | Phase2 extension |
| Scenario Agent | Attack scenario definition | scenario YAML / templates | runnable scenario definitions | Phase3 |
| Attacker Agent | Attack execution | scenario | attack_result.json / attack execution | Phase3 |
| Attack Planner Agent | Decompose objectives into subtasks and select tools, specialists, and executors (future extension) | objective / constraints / memory | attack plan | Phase3 extension / future |
| Case Agent | Normalize run results into case.json as the source of truth | incident / triage / investigation / evaluation | case.json | Phase4 |
| Investigation Agent | Pre-case context acquisition / attack story / evidence-gap analysis | incident / triage / defender-side context | `investigation_result.json` / evidence refs | Phase4 |
| Endpoint Telemetry Agent | Process telemetry enhancement | endpoint telemetry | enriched endpoint events | Phase5 |
| Rule Improvement Agent | Detection, correlation, and workflow improvement proposals | attack results + incidents + triage + actions + gaps | rule suggestions / improvement notes | Phase6 |
| Scenario Orchestrator | Control of the attack→detect→triage→investigate→improve loop | scenario + config | loop run / orchestration result | Phase6 |
| Deception Agent | Decoy / honeytoken generation | attacker intent / config | deception assets | Phase7 |
| Trap Detection Agent | Deception-hit detection | auth / access / endpoint logs | trap alert | Phase7 |
| Background Activity Agent | Benign-noise generation | schedule / templates | normal activity logs | Phase8 |

---

## 4. Full Dependency Order

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
Investigation Agent
  ↓
Case Agent
  ├─ TheHive / case integration
  ↓
Action Agent
  ↓
Executor Agent / approval gate
  ↓
collection request / execution
  ↓
collection_result.json
  ↓
post-action DFIR investigation / external integration
  ↓
human-reviewed handoff

reviewed run artifacts
  ↓
Rule Improvement Agent
  ↓
review / apply / deploy / promotion gates

Scenario Agent
  ↓
Attacker Agent
  ↓
Scenario Orchestrator

Endpoint Telemetry Agent
  ↓
Telemetry / Detection / Correlation enrichment

Deception Agent
  ↓
Trap Detection Agent

Background Activity Agent
  ↓
Telemetry realism / false positive evaluation
```

The pre-case Investigation Agent produces `investigation_result.json` before
Case and Action. It does not consume `collection_result.json`. Collected output
is handled by the separate post-action DFIR workflow.

---

## 5. Core Data Flow

### 5.1 Defensive Workflow

```text
Raw Log
→ Normalized Event
→ Detection Hit
→ Correlated Incident
→ Incident
→ Triage
→ pre-case Investigation
→ Initial Case
→ Action
→ Approval / Execution
→ Collection Request
→ Collection Result
→ post-action DFIR / External Integration
→ Human-reviewed Handoff
```

Pre-case Investigation and post-action DFIR are separate stages with separate
inputs, outputs, and authority. Neither collection outcome metadata nor
post-action findings automatically overwrite the earlier assessment or action
state.

### 5.2 Offensive / Validation Workflow

```text
Scenario
→ Attacker Agent
→ shell runner
→ attack_result.json
→ attack_execution_log.json
→ attack_observed_effects.json
→ defender-side logs / telemetry / fixtures
→ defensive workflow when implemented
```

Important boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

Attacker-side structured runner events and `attack_observed_effects.json` are
useful for auditability and alignment. They are not defender-side telemetry,
detection evidence, or alerts.

### 5.3 Improvement Loop

```text
attack_result.json
+ incident.json
+ triage_result.json
+ investigation_result.json
+ case.json
+ action_result.json
+ reviewed execution / integration evidence
        ↓
Rule Improvement Agent
        ↓
proposal / candidate / recommendation artifacts
        ↓
human review and explicit apply / deploy / promotion gates
        ↓
Scenario Orchestrator
        ↓
attack again
```

A recommendation artifact is not approval or execution. Rule Improvement must
not auto-apply, auto-deploy, or auto-promote a candidate.

### 5.4 Feature Lifecycle

```text
Detection
  ↓
behavior_features
  ↓
Triage
  ↓
derived_features
  ↓
Investigation
  ↓
enriched_features
  ↓
Case
```

---

## 6. Stable Responsibility and Trust Boundaries

Current implementation status, priorities, incomplete work, sequencing, and
Done Criteria are maintained in the
[Main Roadmap](../roadmap/roadmap.md). The boundaries below remain valid
regardless of which optional backend, model, or integration is selected.

### 6.1 Pre-case Investigation

The Investigation Agent operates before the initial Case and Action stages.

Primary inputs:

- `incident.json`
- `triage_result.json`
- defender-side telemetry and optional defender enrichment

Primary output:

- `investigation_result.json`

Responsibilities:

- build an evidence-referenced attack story
- add surrounding context and `enriched_features`
- identify evidence gaps and recommended pivots
- preserve fixture, controlled, live, and runtime evidence labels

It does not execute a DFIR collection request and must not consume
`collection_result.json`.

### 6.2 Post-action DFIR

Post-action DFIR is a separate workflow after Action, approval, and collection.

Primary inputs:

- `case.json`
- `action_result.json`
- `collection_request.json`
- `collection_result.json`
- collected outputs referenced by the collection result

Primary output:

- `post_action_dfir_investigation_result.json`

The workflow records evidence availability, factual parsed observations,
limitations, and review proposals. It must not overwrite
`investigation_result.json` or automatically change Case assessment, Action
state, containment, external Case state, or Rule Improvement promotion state.

See
[Post-action DFIR Investigation Design](../design/dfir/post_action_dfir_investigation.md)
for the canonical post-action contract.

### 6.3 Triage Processing Contract

Triage is a processing contract, not a required model choice. Deterministic and
AI-assisted implementations may consume the same bounded inputs and produce the
same structured artifact contract. Model use does not relax evidence,
validation, or comparison boundaries.

### 6.4 Action, Execution, and Integration

Action planning, approval, execution, collection, and external integration are
separate responsibilities.

- `action_result.json` records the proposed response plan and policy context.
- approval artifacts record reviewer intent where required.
- the Executor Agent records execution state; it does not interpret collected evidence.
- `collection_request.json` describes requested evidence.
- `collection_result.json` records collection outcome and output references; completion is not a security conclusion.
- TheHive updates, Velociraptor API execution, and other external integrations
  remain explicit integration boundaries.
- post-action findings require human review before Case reassessment, external
  update, or follow-up Action.

### 6.5 Scenario and Evidence Boundaries

Attacker-side results and observed effects never prove defender-side telemetry,
detection, or Incident coverage.

A bounded fixture path may validate artifact composition without establishing
live or continuous integration. For example, Scenario 009 fixture-backed
Incident-to-Action coverage does not establish canonical live Wazuh source
integration. Consult the Main Roadmap for the current Scenario 009 status.

---

## 7. Reference Pipeline

The following flow shows the intended artifact order. It is a responsibility
map, not a claim that every stage is live-integrated or runtime-validated.

```text
scenario
→ attacker execution
→ attacker-side result / execution log / observed effects
→ defender-side logs, telemetry, or bounded fixtures
→ source parsing and normalization
→ deterministic detection
→ correlation
→ incident.json
→ triage_result.json
→ investigation_result.json
→ case.json
→ action_result.json
→ approval / execution
→ collection_request.json
→ collection_result.json
→ post_action_dfir_investigation_result.json
→ human-reviewed Case / external integration handoff
→ evaluation / Rule Improvement review artifacts
```

Each implementation claim must retain its evidence qualifier, such as fixture,
controlled, manual, live, or runtime-validated.

---

## 8. Artifact Ownership

| Artifact / boundary | Primary owner | Boundary |
|---|---|---|
| normalized events | source parser / normalized mapper | Telemetry shaping only; not detection or assessment. |
| detection hits | Detection | Defender-side detection output; attacker claims are not substitutes. |
| `incident.json` | Incident Builder | Structured Incident entry for downstream processing. |
| `triage_result.json` | Triage | Initial bounded analysis; deterministic or AI-assisted implementation may be used. |
| `investigation_result.json` | pre-case Investigation | Context, evidence gaps, pivots, and enriched features before Case/Action. |
| `case.json` | Case | Internal source of truth for the reviewed workflow state. |
| `action_result.json` | Action | Proposed response plan; not proof of approval or execution. |
| `collection_request.json` | Action / Executor boundary | Evidence request; not collection success. |
| `collection_result.json` | collection backend | Outcome and output-reference metadata; not evidence interpretation. |
| `post_action_dfir_investigation_result.json` | post-action DFIR workflow | Factual follow-on analysis and review proposal; no automatic reassessment. |
| candidate / recommendation artifacts | Rule Improvement | Review inputs only until explicit apply, deploy, or promotion approval. |

`decision_log.json` may record decisions across stages, but it does not transfer
authority between the owners above.

---

## 9. Cross-Cutting Design

### 9.1 Run Isolation

- separate artifacts by `run_id`
- preserve run-level reproducibility and comparison
- maintain one run as one experimental unit

### 9.2 Traceability

Use `run_id`, `attack_id`, event references, Incident references, Case
references, and artifact paths according to each contract. Do not fabricate
cross-stage linkage when the source artifact does not provide it.

Traceability supports:

- run-level evaluation
- missed-detection analysis
- evidence review
- Rule Improvement input construction

### 9.3 Case as Source of Truth

- use the Case as the internal record of facts and judgments
- connect external integrations to the reviewed Case state
- distinguish outcome-only collection metadata from reviewed post-action findings
- do not let post-action evidence overwrite the Case assessment without review

### 9.4 Feature-Based Design

- Detection records observed behavior as `behavior_features`
- Triage produces `derived_features` from bounded inputs
- pre-case Investigation adds `enriched_features` from defender-side evidence
- Action uses features and policy as its primary basis
- post-action DFIR findings do not flow backward into the pre-case feature lifecycle

### 9.5 Approval and Promotion Gates

- state-changing Actions such as containment, isolation, blocking, and
  credential revocation retain their approval boundaries
- collection success does not imply evidence interpretation or Case reassessment
- a Rule Improvement recommendation does not imply apply, deploy, runtime
  update, or promotion execution

---

## 10. Agent Responsibility Details

### 10.1 Case Agent
- integrate Incident, Triage, and Investigation into `case.json`
- maintain the Case lifecycle
- provide the source of truth for external integrations

### 10.2 Investigation Agent
- expand the surrounding context, timeline, and attack story for Incident and Triage
- relate defender-side evidence, evidence gaps, and recommended pivots
- produce `investigation_result.json` before Case and Action
- do not own collection execution or post-action DFIR interpretation

### 10.3 Endpoint Telemetry Agent
- integrate process, file, and network telemetry
- provide the defensive workflow with signals beyond Linux authentication events
- enable richer correlation

### 10.4 Rule Improvement Agent
- compare results across attack runs
- classify outcomes as detected, missed, or noisy
- generate rule-improvement suggestions
- also handle correlation and workflow improvement suggestions

### 10.5 Scenario Orchestrator
- control the execution of multiple scenarios
- coordinate rerun loops with the defensive workflow
- act as the hub of the improvement loop
- provide a future execution point for workflow definitions

### 10.6 Deception / Trap Detection
- the Deception Agent generates bounded local-lab assets
- the Trap Detection Agent produces hits from defender-side trap observations
- do not derive deception hits from attacker-side claims
- even when a confirmed deception hit is treated as a high-confidence signal,
  preserve evidence, approval, containment, and Rule Improvement review boundaries
- maintain the current status of the scenario runner, deployment, and live
  validation in the Main Roadmap

### 10.7 Background Activity Agent
- generate benign background noise
- support false-positive measurement
- reproduce observation conditions closer to a production SOC

### 10.8 Attack Planner Agent
- decompose objectives into subtasks
- select tools, executors, and specialists
- provide an extension point for an offensive planner, memory, and graph

---

## 11. MVP Order (Recommended)

Although the target architecture is broad, the recommended MVP order is:

1. Telemetry / Parser
2. Detection
3. Correlation
4. Incident Builder
5. Triage
6. Scenario / Attacker
7. Case / Investigation
8. Action / Executor
9. Endpoint Telemetry
10. Rule Improvement / Orchestrator
11. Deception
12. Background Activity

---

## 12. Key Design Principles

- **Modular**: separate responsibilities by agent
- **Traceable**: trace activity through `attack_id`, `event_ref`, `incident_id`, and `run_id`
- **Reproducible**: make scenarios and runs reproducible
- **Phase-based**: support incremental implementation by phase
- **Future-compatible**: retain unimplemented agents in the target architecture
- **Feature-oriented**: generalize processing around behavior features
- **Evidence-first**: make evidence and decision boundaries more visible than AI judgments

---

## 13. Summary

This architecture defines target agent responsibilities and artifact and trust
boundaries. It does not duplicate current implementation status; the Main
Roadmap remains authoritative.

In particular, preserve the boundaries between:

- attacker-side evidence and defender-side evidence
- the Triage processing contract and model choice
- pre-case `investigation_result.json` and post-action
  `post_action_dfir_investigation_result.json`
- Action planning, approval, execution, collection outcome, and evidence interpretation
- Rule Improvement recommendations and apply, deploy, or promotion operations

Retain unimplemented agents in the target architecture, but do not treat their
presence in this document as evidence that they are Implemented or Validated.
