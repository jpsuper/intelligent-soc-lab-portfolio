# AI SOC Lab Architecture

This document describes the practical node layout, VM lifecycle, and logical
component placement for the AI SOC research lab.

> Document responsibility:
> This document owns physical node roles, hardware placement, VM lifecycle, and
> logical component placement. The [Main Roadmap](../roadmap/roadmap.md) owns
> current implementation status, priorities, validation depth, and Done
> Criteria. Component or phase placement in this document does not establish
> that an item is implemented or live-validated.

It reflects the current confirmed hardware:

- **Node1**: existing mini PC / Attack-Victim Lab
- **Node2**: GMKtec NucBox K8 Plus / SOC Core
- **Node3**: future optional AI node

Target flow:

```text
Attack -> Collect -> Detect -> Correlate -> Build Incident -> Triage
  -> pre-case Investigation -> Case -> Action -> Approval / Execution
  -> Collection Result -> post-action DFIR -> Review / Improve -> Attack Again
```

See the [System Diagram](soc-lab-system-diagram.md) and
[Agent Architecture](agent-architecture.md) for stable processing and trust
boundaries.

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

### Node1 VM Evolution

Phase0-2
- kali-attacker
- ubuntu-victim01

Phase3+
- ubuntu-victim02
- windows-victim01

Phase5+
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

### Node2 Deployment Evolution

Phase0-2
- VM: `soc-analyzer`

Phase1+
- optional VM: `log-pipeline`

Phase4+
- VMs: `thehive-vm`, `velociraptor-server`

Phase5+
- VM: `wazuh-server`

Phase6+
- logical component: `orchestrator`; no dedicated VM is required by the phase
  plan

Phase7+
- logical component: `deception-controller`; it can share `soc-analyzer`
  initially

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

# 4. Infrastructure and Capability Plan by Phase

This section describes both VM lifecycle changes and capability placement. It
is not a list of dedicated VMs to create for every item shown under a node.

- **New VMs** are guests first introduced in that phase.
- **Reused VMs** are existing guests used by that phase and do not require a
  new build.
- **Logical components** identify node placement but do not imply a dedicated
  VM unless explicitly stated.
- **Capability scope** describes intended functional placement rather than
  implementation status.

Phase placement describes the intended architecture and does not by itself
prove that a VM has been provisioned or live-validated.

## Phase0 — Minimum Viable Lab

### Phase0 New VMs

#### Phase0 Node1

##### kali-attacker
- 2 vCPU
- 4GB RAM
- 40GB Disk

##### ubuntu-victim01
- 2 vCPU
- 2GB RAM
- 20GB Disk

#### Phase0 Node2

##### soc-analyzer
- 4 vCPU
- 8GB RAM
- 60GB Disk

### Phase0 Capability Scope

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

### Phase1 VM Changes

- New VMs: none
- Reused VMs:
  - Node1: `kali-attacker`, `ubuntu-victim01`
  - Node2: `soc-analyzer`

### Phase1 Capability Scope

- correlation-agent
- incident-builder-agent

---

## Phase2 — AI Triage

### Phase2 VM Changes

- Required new VMs: none
- Reused VM:
  - Node2: `soc-analyzer`
- Optional future VM:
  - Node2: `ai-soc`, if resource or isolation requirements justify a split

### Phase2 Capability Scope

- AI triage
- report generation

---

## Phase3 — Adversary Simulation Expansion

### Phase3 VM Changes

- New VM:
  - Node1: `ubuntu-victim02`
- Optional new VM:
  - Node1: `windows-victim01`, if capacity allows

### Phase3 Capability Scope

- scenario-agent
- attacker-agent
- repeatable multi-host scenarios

---

## Phase4 — Incident Response / Case Workflow

### Phase4 VM Changes

- Planned new VMs:
  - Node2: `thehive-vm`, `velociraptor-server`
- Required availability:
  - Node1: `windows-victim01` should be available by this phase; add it here if
    it was deferred in Phase3

### Phase4 Capability Scope

- pre-case Investigation and internal Case workflow
- evidence-gap analysis and collection-request preparation
- separate external Case and collection integration boundaries

---

## Phase5 — Endpoint Telemetry

### Phase5 VM Changes

- Planned new VM:
  - Node2: `wazuh-server`
- Reused VM:
  - Node1: `windows-victim01`
- Optional new VM:
  - Node1: `dc01`

### Phase5 Capability Scope

- Sysmon
- Wazuh agent
- auditd
- endpoint telemetry detections

---

## Phase6 — Automated Improvement Loop

### Phase6 VM Changes

- Dedicated new VMs: none in the current plan
- Logical components on Node2:
  - orchestrator
  - rule improvement workflows
- The current architecture does not yet assign these components to a dedicated
  VM. A separate VM may be introduced later if isolation or capacity requires
  one.

### Phase6 Capability Scope

- scenario-to-analysis and evaluation-loop orchestration
- reviewed Rule Improvement proposal, candidate, recommendation, and export
  artifact flow
- explicit review and approval gates for Rule Improvement apply, deploy, and
  promotion operations

---

## Phase7 — Deception

### Phase7 VM Changes

- Planned new VM:
  - Node1: `honeypot01` / deception target
- Logical component on Node2:
  - deception controller; it may remain inside `soc-analyzer` initially and
    does not require a dedicated VM

### Phase7 Capability Scope

- deception inventory and bounded local-lab asset generation
- defender-side trap observations and deterministic deception-hit generation
- deception-hit-to-Incident bridging
- future high-confidence alerting from validated defender-side trap evidence
- preservation of the boundary that attacker-side observed effects do not prove
  defender-side deception hits

Current implementation and validation status are maintained in the
[Main Roadmap](../roadmap/roadmap.md) and
[Phase7 Roadmap](../roadmap/phase7.md).

---

## Phase8 — Background Activity

### Phase8 VM Changes

- Dedicated new VMs: none in the current plan
- Reused VMs:
  - Node1: existing Linux and Windows victim VMs

### Phase8 Capability Scope

- background activity generation on Linux / Windows victims
- normal SSH login noise
- sudo noise
- apt / cron noise
- Windows admin-like noise
- false positive pressure for tuning

---

# 5. Recommended Starting Point

Do **not** build the final lab all at once.

Start with only:

## Starting Node1
- kali-attacker
- ubuntu-victim01

## Starting Node2
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
- keep current status, priorities, validation depth, and Done Criteria in the
  Main Roadmap and phase documents

This architecture is intentionally practical rather than overengineered.
