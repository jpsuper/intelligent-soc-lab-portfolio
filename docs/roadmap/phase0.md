# Phase0 — Lab Stabilization and SOC Pipeline Baseline

> [!NOTE]
> This document preserves Phase0-specific implementation history and
> validation context. The [main Roadmap](roadmap.md) is authoritative for current
> status, active priority, incomplete work, and Done Criteria.

## Goal
Build the minimal Attack → Log → Forward → Parse → Detect → Incident pipeline

## What was implemented

### Attack
- Run an SSH brute-force attack from Kali (Hydra)

### Log Collection
- Collect auth.log from the victim (Ubuntu)

### Log Forwarding
- Forward the logs to soc-analyzer with rsyslog

### Parsing
- Normalize sshd logs with parser-agent
- Generate normalized_events.json

### Detection
- Implement the ssh_failed_login rule
- Generate detection_hits.json

### Incident
- Build an incident from detections with incident-builder-agent
- Generate INC-0001.json

## Data Flow

```text
Kali
↓
SSH brute force
↓
Ubuntu auth.log
↓
rsyslog forward
↓
soc-analyzer
↓
parser-agent
↓
detection-agent
↓
incident-builder-agent
```

## Output

- data/normalized/normalized_events.json
- data/detections/detection_hits.json
- data/incidents/INC-0001.json

## Result

- Completed the minimal SOC pipeline
- Successfully automated the flow from attack execution to incident generation

## Historical Next

- Phase1: Correlation Agent
