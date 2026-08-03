# Phase 4 — Case Agent and Integration Preparation

## Overview

Phase 4 focuses on converting the outputs of the attack simulation and evaluation pipeline into a structured SOC-style case record.

By the end of Phase 4, the lab should be able to take a single isolated run and produce a normalized `case.json` that can later be used for:

In the current lab implementation, a minimal TheHive integration has also been implemented,
allowing case creation and observable attachment based on the generated `case.json`.

- analyst review
- reporting
- case management
- external platform integration
- automated response preparation

This phase does **not** aim to fully automate enterprise-grade case management yet.  
Instead, it establishes the internal data model and agent flow required for future integrations such as TheHive and Velociraptor.

---

## Background

Current state before Phase 4:

- attack → evaluation pipeline is implemented
- `attack_id` exists
- run isolation exists
- coverage evaluation exists
- expected vs observed artifacts can be compared

This means the system can already execute a scenario and evaluate whether the expected attack behavior was successfully observed and detected.

The next missing layer is a component that transforms these machine-oriented outputs into a case-oriented representation suitable for SOC workflows.

---

## Goals

Phase 4 goals:

1. Define a normalized case data model
2. Implement a Case Agent that generates `case.json`
3. Preserve traceability from scenario and run outputs into case records
4. Make the case model integration-ready for future TheHive and Velociraptor support
5. Implement a minimal TheHive adapter for case creation and observable ingestion
6. Implement a minimal Velociraptor adapter for DFIR request generation
7. Keep the first implementation deterministic and easy to test

---

## Non-Goals

The following are out of scope for the initial implementation of Phase 4:

- full production-grade TheHive deployment/operation
- full production-grade Velociraptor deployment/operation
- multi-case correlation across runs
- SOAR-grade automated containment
- analyst UI/dashboard
- bi-directional sync with external case management systems
- complex LLM-driven reasoning as the primary decision engine

---

## Main Concept

The Case Agent takes the outputs of a single run and produces a normalized SOC-style case.

### Input sources

- `scenario.json`
- `attack_result.json`
- `triage_result.json` (if available)
- `evaluation_result.json`

### Output

- `case.json`

This output becomes the canonical case record for that run.

---

## Expected Pipeline After Phase 4

```text
scenario
  ↓
attack
  ↓
detection / triage
  ↓
evaluation
  ↓
case-agent
  ↓
case.json
```

---

## Current Inputs / Assumptions

Phase 4 assumes the following artifacts already exist per isolated run:

- `scenario.json`
- `attack_result.json`
- `evaluation_result.json`
- `triage_result.json` (optional in the first iteration)
- `incident.json` is not required for the initial Case Agent MVP.

Minimum required fields:

### scenario.json
- `scenario_id`
- `title`

### attack_result.json
- `attack_id`
- `scenario_id`
- `attack_status`
- `overall_result`

### evaluation_result.json
- `detected`
- `incident_created`
- `triage_completed`
- `coverage`

### triage_result.json
- optional in initial implementation

---

## Phase 4 Deliverables

The initial implementation of Phase 4 should produce:

- `agents/case-agent/src/main.py`
- `agents/case-agent/src/models.py`
- `agents/case-agent/src/builder.py`
- `agents/case-agent/src/rules.py`
- `schemas/case_schema.json`
- `data/cases/case.json`
- `agents/thehive-agent/src/main.py`
- `agents/thehive-agent/src/client.py`
- `agents/thehive-agent/src/mapper.py`
- `agents/thehive-agent/README.md`
- `.env.example`
- `agents/velociraptor-agent/src/main.py`
- `agents/velociraptor-agent/src/mapper.py`
- `agents/velociraptor-agent/src/rules.py`
- `data/forensics/collection_request.json`
- unit tests for core builder/rule logic

---

## Proposed Directory Layout

```text
.
├── agents
│   ├── action-agent
│   ├── ai-triage-agent
│   ├── attacker-agent
│   ├── case-agent
│   │   ├── README.md
│   │   └── src
│   │       ├── main.py
│   │       ├── models.py
│   │       ├── builder.py
│   │       └── rules.py
│   ├── correlation-agent
│   ├── detection-agent
│   ├── incident-builder-agent
│   ├── parser-agent
│   ├── rule-improvement-agent
│   ├── telemetry-agent
│   └── trap-detection-agent
├── data
│   ├── actions
│   ├── attacks
│   ├── cases
│   │   └── case.json
│   ├── correlation
│   ├── detections
│   ├── evaluation
│   ├── incidents
│   ├── normalized
│   └── triage
├── detection
│   └── rules
├── docs
│   └── roadmap
│       └── phase4.md
├── schema
│   ├── detection_hit_schema.json
│   ├── incident_schema.json
│   ├── triage_report_schema.json
│   └── case_schema.json
├── scenarios
└── main.py
```

---

## Case Model

### Required fields
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

### Recommended fields
- `triage_result`
- `key_artifacts`
- `timeline`
- `recommended_actions`

### Optional fields
- `analyst_notes`
- `external_refs`
- `tags`

### detection_result minimum fields
- `detected`
- `incident_created`
- `triage_completed`

### Rule inputs
- `attack_result.attack_status`
- `attack_result.overall_result`
- `evaluation_result.detected`
- `evaluation_result.triage_completed`
- `evaluation_result.coverage`

---

## Milestones

### Milestone 1 — Schema definition
- define `case_schema.json`
- define minimum required fields
- validate sample output manually

### Milestone 2 — Case Agent MVP
- load input artifacts
- derive status/severity
- generate `case.json`

### Milestone 3 — Validation and tests
- add schema validation
- add builder/rules unit tests

### Milestone 4 — Integration preparation
implement TheHive adapter MVP
validate case creation and observable ingestion
document observable type mapping
implement Velociraptor DFIR request generator (no execution)

---

## Done Criteria

Phase 4 MVP is complete when:

- a single isolated run can generate `case.json`
- generated `case.json` passes `case_schema.json` validation
- `attack_id` and `scenario_id` are preserved
- coverage information is preserved
- status is automatically derived
- severity is automatically derived
- the output can be produced without TheHive or Velociraptor
- one sample case is stored under `data/cases/`

## Implementation Notes (Lab Findings)

During TheHive integration, the following behaviors were observed:

- Case creation returns both `_id` and `number`
- Observable attachment requires `_id`, not `number`
- Observable `dataType` must match UI-supported values

Validated observable types:
- ip
- hostname
- other

Rejected / unsupported in this lab:
- host
- username

These constraints should be considered when designing future integrations.

During Velociraptor integration, the following design decisions were made:

- Velociraptor is used as a follow-on DFIR adapter, not a primary pipeline component
- Initial implementation only generates collection requests (no direct API execution)
- DFIR is triggered only when triage verdict is "malicious"
- Artifact selection is intentionally minimal and fixed in the MVP

This keeps the system loosely coupled and allows future extension to:
- API-driven collection execution
- dynamic artifact selection
- multi-host investigations