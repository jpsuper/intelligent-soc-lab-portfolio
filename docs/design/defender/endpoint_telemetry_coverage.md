# Endpoint Telemetry Coverage Design

## Purpose

Attacker-side structured events show what an attack runner did or attempted. Defender-side telemetry shows what the SOC pipeline can actually observe. For post-login behavior, the lab needs endpoint telemetry that can explain command execution, file writes, persistence-path changes, and read-only discovery commands.

This document is a planning design for future Wazuh, auditd, osquery, and Velociraptor integration. It does not change detection verdicts, does not change `overall_result` or `detected`, and does not auto-generate rule candidates.

Key boundaries:

- Do not treat attacker-side structured events as defender evidence.
- Do not mark `detected=true` only because attacker-side observed effects exist.
- Do not auto-promote observed-effects gaps into rule candidates.
- Defender telemetry gaps should first become explicit investigation or telemetry backlog items.
- Scenario additions should wait until current telemetry gaps are understood.

## Current Implementation Status

The first endpoint telemetry path is now implemented through auditd-backed normalized endpoint events.

Implemented:

- `schemas/endpoint_events.schema.json`
- auditd to `endpoint_events.json` conversion
- optional `endpoint_events.json` input for investigation and investigation harness
- endpoint telemetry observed facts and supporting signals
- endpoint-derived enriched features for command / path / URL evidence
- endpoint-derived investigation pivots for payload and command context
- deterministic judge support for:
  - `evidence_specificity`
  - `enriched_feature_quality`
  - `missing_pivot_detection`

Confirmed scenario_006 harness behavior:

```text
endpoint_events.json
  -> observed_facts / supporting_signals
  -> endpoint-derived enriched_features
  -> endpoint-derived missing_pivots / recommended_pivots
  -> judge scoring improvements
```

Representative smoke result:

```text
evidence_specificity      = 0.8
enriched_feature_quality  = 0.85 / 0.9
missing_pivot_detection   = 1.0
```


## Telemetry Goals By Artifact

| Artifact | Scenarios | Desired defender evidence | Candidate telemetry source | Priority | Notes |
|---|---|---|---|---|---|
| `process_exec` | `scenario_006` | Command line, process name, parent process, user, working directory, timestamp | auditd `execve`, osquery process events, Velociraptor process collection, EDR | High | Needed to validate payload or command execution beyond attacker-side stdout. |
| `suspicious_file_write` | `scenario_007` | Path, file action, writing user, process, timestamp | auditd file watch, Wazuh FIM, Velociraptor file collection, EDR | High | `/tmp` marker writes are lab-safe, but defender evidence still needs file telemetry. |
| `system_discovery` | `scenario_008` | Commands such as `whoami`, `id`, `hostname`, `uname -a`; user; parent SSH session; timestamp | auditd `execve`, osquery process events, Velociraptor process collection, EDR | Medium to High | Read-only discovery is benign-looking, so correlation with SSH session matters. |
| `suspicious_archive_staging` | `scenario_009` | `mkdir`, synthetic file write, `tar` / archive creation, and `chmod` observations under a runner-controlled temp path | auditd `execve`, auditd file watch, normalized endpoint events, EDR | Medium | Fixture coverage exists through the bounded incident-to-action chain. Wazuh `alerts.json` produced no matching documents, while a bounded temporary raw-archive run confirmed manager receipt and all five operations. The result is Outcome C because each core serial retained only `SYSCALL` and complete multi-record grouping was not preserved. `archives.json` is supporting evidence, not canonical; source selection, parity, normalization, detection, and incident consumption remain pending. |
| `authorized_keys_modification` | `scenario_004` | Modified path, file change, user, process, timestamp | Wazuh FIM, auditd file watch, EDR | High | Persistence-specific artifact that should remain distinct from generic suspicious file writes. |

## Recommended Implementation Order

1. auditd minimal telemetry design
   - Covers `execve`.
   - Covers selected file writes.
   - Works well for process and file evidence.
   - Can be ingested by Wazuh later.
2. Wazuh integration
   - Ingest auditd logs.
   - Use Wazuh FIM for persistence paths.
   - Keep auth coverage stable.
3. Velociraptor or osquery
   - Provide investigation pivots.
   - Provide process, file, user, and network context.
   - Support post-alert enrichment and investigation.

This document is only the design. It does not add auditd rules, Wazuh config, osquery packs, Velociraptor artifacts, parser logic, or detections.

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

## Recommended Next PRs

Completed first-pass items:

1. `docs: design auditd minimal coverage`
2. `feat/docs: define normalized endpoint event contract`
3. `feat: add endpoint events schema`
4. `feat: convert auditd telemetry to endpoint_events.json`
5. `feat: wire endpoint_events.json into investigation and harness`
6. `feat: derive endpoint enriched features from telemetry`
7. `feat: derive endpoint investigation pivots from telemetry`

Recommended next work:

1. Keep endpoint telemetry signals human-reviewable and additive.
2. Add Wazuh FIM coverage for persistence paths when persistence telemetry becomes the next focus.
3. Add Velociraptor or osquery collection only after endpoint event contract usage remains stable.
4. Extend telemetry mapping only when new scenario families require new defender evidence.
