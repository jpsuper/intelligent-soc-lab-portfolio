# AI SOC Lab Architecture

This document describes the practical node layout and VM placement for the AI SOC research lab.

It reflects the current confirmed hardware:

- **Node1**: existing mini PC / Attack-Victim Lab
- **Node2**: GMKtec NucBox K8 Plus / SOC Core
- **Node3**: future optional AI node

Goal:

Attack -> Collect -> Detect -> Correlate -> Build Incident -> Triage -> Investigate -> Improve -> Attack Again

---

# 1. Final Node Roles

## Node1 — Attack / Victim Lab

Current example hardware:
- Ryzen 7 5800H class
- 32GB RAM
- 1TB NVMe
- Proxmox recommended

Role:
- adversary simulation
- victim systems
- telemetry source
- deception target hosting
- background activity generation
- optional small AD lab

This node is the place where attacks happen and where logs are generated.

### Typical VMs over time

Phase0-2
- kali-attacker
- ubuntu-victim01

Phase3+
- ubuntu-victim02
- windows-victim01

Phase4+
- dc01 (optional when AD phase starts)

Phase7+
- honeypot01 / deception target

---

## Node2 — SOC Core

Confirmed hardware:
- **GMKtec NucBox K8 Plus**
- **AMD Ryzen 7 8845HS**
- **64GB RAM**
- **1TB NVMe**
- **Radeon 780M iGPU**
- Proxmox recommended

Role:
- log pipeline
- parser / normalization
- detection engine
- correlation engine
- incident builder
- AI triage
- case management
- investigation platform
- rule improvement workflows
- deception control
- orchestration

This node is the central SOC platform.

### Typical VMs over time

Phase0-2
- soc-analyzer

Phase1+
- log-pipeline (optional split later)

Phase4+
- thehive
- velociraptor

Phase5+
- wazuh

Phase6+
- orchestrator

Phase7+
- deception-controller (can share soc-analyzer early)

### AI usage on Node2

Node2 can run **lightweight local AI workloads** for:
- triage
- incident summarization
- report generation
- rule suggestion experiments

Examples:
- Ollama
- Qwen 7B class
- small local embeddings

However, Node2 should still be treated primarily as **SOC Core**, not as a dedicated heavy inference node.

---

## Node3 — Future AI Engine (Optional)

Future optional node.

Role:
- local LLM inference
- Ollama / Qwen
- embeddings / rerankers
- heavier report generation
- future AI-vs-AI experiments

This node is not required for Phase0-Phase4.

---

# 2. Hypervisor Strategy

## Recommended
- Node1: Proxmox
- Node2: Proxmox

## Not recommended for now
- Proxmox cluster
- HA / Ceph / shared storage

Reason:
- adds complexity
- not needed for current lab goals
- can introduce quorum / network troubleshooting overhead

The lab should prioritize **clear role separation**, not cluster features.

---

# 3. Network Strategy

## Initial recommendation
Start simple.

- Node1 and Node2 are connected on the same management / lab network
- use a single bridge first (`vmbr0`)
- segment later only when needed

## Role-based IP convention

The lab uses a simple role-based IP convention: Proxmox nodes use
`192.0.2.1X`, defence/SOC hosts use `192.0.2.2X`, victim hosts use
`192.0.2.3X`, and offence hosts use `192.0.2.4X`.

Current confirmed IP plan:

| Role | Host | IP |
|---|---|---|
| Proxmox / hypervisor | `proxmox-node1` | `192.0.2.10` |
| Proxmox / hypervisor | `proxmox-node2` | `192.0.2.11` |
| Defence / SOC | `soc-analyzer` | `192.0.2.20` |
| Defence / SOC | `thehive-vm` | `192.0.2.21` |
| Defence / SOC | `velociraptor-server` | `192.0.2.22` |
| Defence / SOC | `wazuh-server` | `192.0.2.23` |
| Victim | `ubuntu-victim01` | `192.0.2.30` |
| Victim | `windows-victim01` | `192.0.2.31` |
| Offence | `kali-attacker` | `192.0.2.40` |

`windows-victim01` is currently a manually provisioned runtime VM with hostname
`WIN-VICTIM01`, Windows 11 Enterprise Evaluation, and UTC timezone.
Sysmon process-creation telemetry for Event ID 1 has been manually validated,
but the Wazuh agent is not installed. This inventory entry does not mean
that repository automation for provisioning the VM is implemented.

### Initial Lab Layout

```text
home-router / switch
      │
 ┌────┴────┐
 │         │
Node1     Node2
```

### Initial Proxmox bridge usage

- `vmbr0`: management + shared lab traffic

Later phases can add:
- attack segment
- server segment
- AD segment
- deception segment

But this is **not required for Phase0**.

---

# 4. VM Build Plan by Phase

## Phase0 — Minimum Viable Lab

### Node1
#### kali-attacker
- 2 vCPU
- 4GB RAM
- 40GB Disk

#### ubuntu-victim01
- 2 vCPU
- 2GB RAM
- 20GB Disk

### Node2
#### soc-analyzer
- 4 vCPU
- 8GB RAM
- 60GB Disk

Purpose:
- parser-agent
- detection-agent
- basic incident output
- optional early triage experiments

Data flow:

```text
Kali
 ↓ SSH brute force
Ubuntu victim
 ↓ auth.log
SOC analyzer
 ↓ parser
normalized events
 ↓ detection
detection hits
```

---

## Phase1 — Detection / Correlation

### Node1
- kali-attacker
- ubuntu-victim01

### Node2
- soc-analyzer

Functions added:
- correlation-agent
- incident-builder-agent

---

## Phase2 — AI Triage

### Node2
- soc-analyzer (same VM at first)
- optional split: ai-triage VM later if needed

Functions added:
- AI triage
- report generation

---

## Phase3 — Adversary Simulation Expansion

### Node1
- ubuntu-victim02
- windows-victim01 (optional, if capacity allows)

Functions added:
- scenario-agent
- attacker-agent
- repeatable multi-host scenarios

---

## Phase4 — Incident Response / Case Workflow

### Node2
- thehive
- velociraptor

### Node1
- windows-victim01 recommended by this stage

Functions added:
- case workflow
- artifact collection
- Linux / Windows investigation

---

## Phase5 — Endpoint Telemetry

### Node2
- wazuh

### Node1
- windows-victim01
- optional dc01

Functions added:
- Sysmon
- Wazuh agent
- auditd
- endpoint telemetry detections

---

## Phase6 — Automated Improvement Loop

### Node2
- orchestrator
- rule improvement workflows

Functions added:
- scenario-to-triage automation
- improvement loop experiments
- Rule Improvement export MVP for reviewed candidate-generation outputs
- Rule Improvement apply / deploy / promotion remains review-gated and is not
  automatic

---

## Phase7 — Deception

### Node1
- honeypot01 / deception target

### Node2
- deception controller (may stay inside SOC analyzer early)

Functions added:
- Phase7 deception artifact foundation is complete through schemas, local asset
  generation, trap hit generation, incident bridge, and chain smoke coverage
- Phase7 deception scenario YAML / runner implementation is intentionally
  deferred
- future honeytoken deployment, trap detection, and high-confidence deception
  alerting remain later implementation work

Current scenario expansion status:

- Scenario family expansion policy governs scenario growth after `scenario_008`.
- Linux scenario family candidates selected `suspicious_archive_staging` as the
  first broader Linux candidate.
- `scenario_009_suspicious_archive_staging` is implemented as a local scenario
  YAML + shell runner slice.
- `scenario_009` emits attacker-side structured events and observed effects for
  staging directory creation, synthetic file writing, archive creation, and
  archive permission change.
- `scenario_009` has an initial synthetic defender-side endpoint fixture and DSL
  detection expectation for `suspicious_archive_staging`.
- `scenario_009` has an initial helper-level observation incident bridge for
  `suspicious_archive_staging` detection hits.
- Live auditd / Wazuh / SIEM telemetry collection for `scenario_009` is not
  complete, and triage / investigation / action coverage for `scenario_009` is
  not complete.

External framework stance:

- Atomic Red Team is a reference / mapping source only; no Atomic adapter is
  implemented.
- CALDERA is later optional integration; no CALDERA integration is implemented.

---

## Phase8 — Background Activity

### Node1
- background activity generation on Linux / Windows victims

Functions added:
- normal SSH login noise
- sudo noise
- apt / cron noise
- Windows admin-like noise
- false positive pressure for tuning

---

# 5. Recommended Starting Point

Do **not** build the final lab all at once.

Start with only:

## Node1
- kali-attacker
- ubuntu-victim01

## Node2
- soc-analyzer

This is enough to begin:
- attack reproduction
- auth.log parsing
- detection hits
- incident generation

---

# 6. Final Guidance

To avoid drift:

- Node1 = Attack / Victim
- Node2 = SOC Core
- Node3 = future dedicated AI

And:

- build by phase
- keep cluster features out for now
- keep networking simple first
- only split more VMs when a phase truly needs them

This architecture is intentionally practical rather than overengineered.
