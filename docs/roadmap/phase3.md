# Phase 3: Attacker Agent & Scenario Execution

## Overview
Phase 3 introduces an attacker simulation layer to the SOC automation lab.
This phase enables controlled execution of attack scenarios and produces structured, traceable attack results.

---

## Objectives
- Define attack scenarios using YAML
- Execute attacks via attacker-agent
- Support remote execution (Kali attacker host)
- Output machine-readable attack results
- Enable run-level isolation
- Enable attack traceability across pipeline

---

## Architecture

scenario.yaml
   ↓
attacker-agent
   ↓ (ssh)
kali-attacker
   ↓
target (victim)
   ↓
SOC pipeline (parser → detection → correlation → incident → triage → action)

---

## Scenario Definition

Example: scenario_001_ssh_bruteforce_priv_esc.yaml

- step1: SSH brute force (Hydra)
- step2: SSH login + sudo execution

---

## Attacker Agent

Location:
agents/attacker-agent/src/main.py

### Features
- dry-run mode
- step filtering (--step)
- full execution (--execute)
- remote execution support
- structured result output
- attack_id generation
- started_at / ended_at timestamps

---

## Execution

### Recommended (End-to-End)

make attack-run

### Manual

uv run python agents/attacker-agent/src/main.py --execute

---

## Output: attack_result.json

Location:
data/attacks/attack_result.json

Example:

{
  "attack_id": "attack-000001",
  "scenario_id": "scenario-001",
  "status": "completed",
  "started_at": "...",
  "ended_at": "...",
  "expected_artifacts": [
    "ssh_failed_login",
    "ssh_success_login",
    "sudo_command"
  ],
  "steps": [...]
}

---

## Run Isolation

Parser filters logs using:

started_at (from attack_result.json)

This ensures:
- Only current attack logs are processed
- One run → one incident

---

## attack_id Traceability

All pipeline stages include:

"attack_id": "attack-000001"

Applies to:
- normalized_events.json
- detection_hits.json
- correlated_incidents.json
- incident.json
- triage_result.json
- action_result.json

---

## Data Structure

data/
  ├── attacks/
  ├── normalized/
  ├── detections/
  ├── correlation/
  ├── incidents/
  ├── triage/
  ├── actions/
  └── evaluation/   ← 追加

---

## Expected Artifacts

- ssh_failed_login
- ssh_success_login
- sudo_command

---

## Expected Pipeline Outputs

- data/detections/detection_hits.json
- data/correlation/correlated_incidents.json
- data/incidents/incident.json
- data/triage/triage_result.json
- data/actions/action_result.json
- data/evaluation/evaluation_result.json

---

## Evaluation & Coverage Validation

Phase 3 introduces a minimal evaluation layer to validate detection outcomes.

### Purpose

- Verify whether the attack was successfully detected
- Ensure all expected attack behaviors are observed
- Enable run-level evaluation using attack_id

### Input

- data/attacks/attack_result.json
- data/detections/detection_hits.json
- data/incidents/incident.json
- data/triage/triage_result.json
- data/actions/action_result.json

### Output

- data/evaluation/evaluation_result.json

### Example

{
  "attack_id": "attack-000001",
  "scenario_id": "scenario-001",
  "overall_result": "success",
  "coverage": {
    "expected_artifacts": [
      "ssh_failed_login",
      "ssh_success_login",
      "sudo_command"
    ],
    "observed_artifacts": [
      "ssh_failed_login",
      "ssh_success_login",
      "sudo_command"
    ],
    "missing_artifacts": [],
    "unexpected_artifacts": []
  },
  "analysis": {
    "missed_detection": false,
    "false_positive": false
  }
}

### Capabilities

- attack_id-based validation
- detection coverage validation
- missed detection identification
- basic false positive detection

---

## Key Achievements

- End-to-end attack simulation
- Remote execution integration
- Run-level isolation
- attack_id traceability
- Makefile-based orchestration
- Evaluation capability (success / partial / failed)
- Detection coverage validation

---

## Next Steps

### Phase3 Scope (Completed / In Progress)

- Evaluation enhancement (analysis layer)
- Detection coverage validation

### Deferred

- Multi-scenario execution
- Orchestrator Agent (Phase6)

---

## Summary

Phase 3 establishes a fully executable and traceable SOC pipeline from attack to response.
