# Phase1 — Detection, Correlation, and Incident Builder

> [!NOTE]
> This document preserves Phase1-specific implementation history and
> validation context. The [main Roadmap](roadmap.md) is authoritative for current
> status, active priority, incomplete work, and Done Criteria.

## 🎯 Goal
Correlate individual detections and **generate incident.json for investigation and analysis**.

---

## 🏗 Architecture

```
attack
  ↓
log (auth.log / sshd.log / sudo.log)
  ↓
log forwarding (rsyslog)
  ↓
parser-agent
  ↓
normalized_events.json
  ↓
detection-agent
  ↓
detection_hits.json
  ↓
correlation-agent
  ↓
correlated_incidents.json
  ↓
incident-builder-agent
  ↓
incident.json
```

---

## ⚙️ Implemented Agents

### 1. parser-agent
- Normalize logs
- Assign event_type
  - ssh_failed_login
  - ssh_success_login
  - sudo_command

---

### 2. detection-agent
- Generate detections from normalized events
- Map detections to MITRE ATT&CK
  - ssh_failed_login → T1110
  - ssh_success_login → T1078
  - sudo_command → T1548

---

### 3. correlation-agent
- Perform scenario-based correlation
- Connect detections into an incident

#### Implemented Scenario
```
ssh_failed_login
  ↓
ssh_success_login
  ↓
sudo_command
```

#### Conditions
- failed occurs before success (within 15 minutes)
- sudo occurs after success (within 10 minutes)
- host and username match

#### Improvements
- Use sudo as the correlation starting point (to eliminate duplicates)
- Use only the closest success event

---

### 4. incident-builder-agent
- Format correlation results for human and AI consumption

#### Additional Information
- timeline
- source_ips
- mitre_attack
- summary
- severity / confidence

---

## 📦 Output Files

### normalized_events.json
- Normalized events

### detection_hits.json
- Detection results

### correlated_incidents.json
- Correlation results

### incident.json
- Final incident for analysis

---

## 🔍 Example Incident

- Source IP: 192.0.2.40
- User: victim01
- Sequence:
  - SSH brute force (multiple failed events)
  - Successful authentication (success)
  - Privilege escalation (sudo)

### MITRE ATT&CK
- T1110: Brute Force
- T1078: Valid Accounts
- T1548: Privilege Escalation

---

## 🧠 Key Design Principles

### 1. Separation of Responsibilities
```
parser → log interpretation
detection → semantic classification
correlation → attack-story construction
incident builder → presentation
```

---

### 2. Log-Format-Independent Design
- detection uses only event_type
- Does not depend on log format

---

### 3. Scenario-Based Correlation
- Capture the attack sequence instead of isolated detections

---

## 🚧 Known Limitations

- Too many failed events create noise
- confidence is fixed
- Assumes a single host
- Does not support lateral movement

---

## 🚀 Historical Next Phase

### Phase2 — AI Triage Agent

Using incident.json as input:

- Explain the attack
- Estimate the scope of impact
- Recommend initial response actions
- Present investigation steps

👉 Implement AI that supports SOC analyst decision-making
