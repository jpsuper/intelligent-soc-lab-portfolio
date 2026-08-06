# Endpoint Telemetry Coverage Design

## Purpose

Attacker-side structured events show what an attack runner did or attempted. Defender-side telemetry shows what the SOC pipeline can actually observe. For post-login behavior, the lab needs endpoint telemetry that can explain command execution, file writes, persistence-path changes, and read-only discovery commands.

This document defines durable coverage goals and source-positioning boundaries
for Wazuh, auditd, osquery, Velociraptor, and other endpoint telemetry. It does
not change detection verdicts, `overall_result`, or `detected`, and it does not
auto-generate rule candidates. Current implementation status, validation depth,
and delivery order belong in the
[Main Roadmap](../../roadmap/roadmap.md) and its phase documents.

Key boundaries:

- Do not treat attacker-side structured events as defender evidence.
- Do not mark `detected=true` only because attacker-side observed effects exist.
- Do not auto-promote observed-effects gaps into rule candidates.
- Defender telemetry gaps should first become explicit investigation or telemetry backlog items.
- Scenario additions should wait until current telemetry gaps are understood.

## Coverage And Evidence Ownership

This document owns the telemetry objectives for each artifact family, the
relative role of candidate telemetry sources, and the boundary between attacker
claims and defender evidence. The
[normalized endpoint event contract](normalized_endpoint_event_contract.md)
owns the common event shape.

Implementation inventories, scenario results, harness scores, completion claims,
and current priorities are intentionally kept in the
[Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents. A source
listed in the coverage matrix is a candidate evidence source, not proof that its
collection, normalization, or end-to-end path is implemented.

## Telemetry Goals By Artifact

| Artifact | Scenarios | Desired defender evidence | Candidate telemetry source | Priority | Notes |
|---|---|---|---|---|---|
| `process_exec` | `scenario_006` | Command line, process name, parent process, user, working directory, timestamp | auditd `execve`, osquery process events, Velociraptor process collection, EDR | High | Needed to validate payload or command execution beyond attacker-side stdout. |
| `suspicious_file_write` | `scenario_007` | Path, file action, writing user, process, timestamp | auditd file watch, Wazuh FIM, Velociraptor file collection, EDR | High | `/tmp` marker writes are lab-safe, but defender evidence still needs file telemetry. |
| `system_discovery` | `scenario_008` | Commands such as `whoami`, `id`, `hostname`, `uname -a`; user; parent SSH session; timestamp | auditd `execve`, osquery process events, Velociraptor process collection, EDR | Medium to High | Read-only discovery is benign-looking, so correlation with SSH session matters. |
| `suspicious_archive_staging` | `scenario_009` | `mkdir`, synthetic file write, `tar` / archive creation, and `chmod` observations under a runner-controlled temp path | auditd `execve`, auditd file watch, normalized endpoint events, EDR | Medium | Fixture coverage exists through the bounded incident-to-action chain. Wazuh `alerts.json` produced no matching documents, while a bounded temporary raw-archive run confirmed manager receipt and all five operations. The result is Outcome C because each core serial retained only `SYSCALL` and complete multi-record grouping was not preserved. `archives.json` is supporting evidence, not canonical; source selection, parity, normalization, detection, and incident consumption remain pending. |
| `authorized_keys_modification` | `scenario_004` | Modified path, file change, user, process, timestamp | Wazuh FIM, auditd file watch, EDR | High | Persistence-specific artifact that should remain distinct from generic suspicious file writes. |

## Source Selection Principles

- Use auditd when low-level Linux execution or selected file-change evidence is
  required.
- Use Wazuh when centrally collected auth, auditd, FIM, or alert evidence is
  required.
- Use Velociraptor or osquery for bounded investigation and state-oriented
  pivots, while accounting for collection timing and short-lived processes.
- Select a source from the evidence required by a scenario or investigation
  question; do not infer implementation priority from the order in this
  document.
- Preserve existing auth and endpoint evidence paths when adding a new source.

This design does not itself add auditd rules, Wazuh configuration, osquery
packs, Velociraptor artifacts, parser logic, or detections.

## Minimal Auditd Proposal

Future auditd coverage should start small and be tuned to avoid excessive noise.

Proposed coverage areas:

- Process execution
  - `execve`
  - command line
  - UID and AUID
  - executable path
- Persistence path file watch
  - `/home/*/.ssh/authorized_keys`
- Lab suspicious file paths
  - selected `/tmp` marker paths only
  - avoid broad noisy `/tmp` monitoring
- Discovery command execution
  - `whoami`
  - `id`
  - `hostname`
  - `uname`

Auditd rules should be scoped to lab scenarios and adjusted after observing event volume, field quality, and correlation usefulness.

## Tool Positioning

### Wazuh

- Auth log detection.
- auditd ingestion.
- FIM for important paths.
- Alert generation.

### auditd

- Low-level Linux execution and file-change telemetry.
- Useful for structured process and file evidence.
- Good first step for `process_exec`, `suspicious_file_write`, `system_discovery`, and `authorized_keys_modification` evidence.

### osquery

- Lightweight query-based state and process/file inspection.
- Useful for enrichment depending on deployment model and schedule.
- Helpful for confirming state after an alert, but may miss short-lived processes without eventing.

### Velociraptor

- Investigation and collection after alert.
- Useful for deeper endpoint pivots.
- Strong fit for collecting process, file, user, persistence, and timeline context during review.

## Decision Boundaries

- Attacker-side structured events remain attacker-side evidence.
- Defender-side telemetry must come from logs, endpoint sensors, or collection tools.
- Observed-effects alignment gaps are review signals, not automatic rule candidates.
- Rule candidates require reviewer approval and separate rule/prompt work.
- Endpoint telemetry backlog items should be explicit before adding new attacker scenarios.

## Coverage Extension Conditions

Extend this coverage design only when a scenario family or investigation
question requires defender evidence that the current matrix cannot represent.
Each extension should:

1. name the required defender-observable fact;
2. identify a candidate source without treating source availability as proof;
3. preserve a reviewable reference to raw or source-specific evidence;
4. define bounded fixtures or validation evidence;
5. remain additive to existing telemetry paths; and
6. update current priority and completion claims only in the
   [Main Roadmap](../../roadmap/roadmap.md).
