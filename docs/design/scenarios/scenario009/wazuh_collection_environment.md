# Scenario 009 Wazuh Collection Environment

Status: Environment Confirmed / Behavioral Validation Pending

## Purpose

This document records the observed Wazuh and auditd environment supporting a
future `scenario_009_suspicious_archive_staging` Wazuh / SIEM validation.

It confirms deployment, agent connectivity, and collection configuration. It
does not prove that the complete scenario is retained, normalized, detected, or
consumed by the downstream pipeline through Wazuh.

Core boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

## Observation Date And Provenance

The environment was observed interactively on `2026-07-11`. Commands were run
on `wazuh-server` and `ubuntu-victim01`.

File sizes, service state, process state, backlog, and similar values are
point-in-time observations. This record does not commit raw logs, complete
command output, secrets, credentials, enrollment tokens, agent keys,
certificates, or registration material.

## Lab Topology

The authoritative host and IP table is maintained in
[Lab Architecture](../../../architecture/lab-architecture.md#role-based-ip-convention).
The confirmed topology at observation time was:

| Role | Host | IP |
|---|---|---|
| Proxmox / hypervisor | `proxmox-node1` | `192.0.2.10` |
| Proxmox / hypervisor | `proxmox-node2` | `192.0.2.11` |
| Defence / SOC | `soc-analyzer` | `192.0.2.20` |
| Defence / SOC | `thehive-vm` | `192.0.2.21` |
| Defence / SOC | `velociraptor-server` | `192.0.2.22` |
| Defence / SOC | `wazuh-server` | `192.0.2.23` |
| Victim | `ubuntu-victim01` | `192.0.2.30` |
| Offence | `kali-attacker` | `192.0.2.40` |

This scenario-specific record references rather than replaces the architecture
inventory.

## Wazuh Server Deployment

`wazuh-server` uses native Ubuntu packages. Docker was not installed and was not
the deployment mechanism.

| Component | Observed version |
|---|---|
| `wazuh-manager` | `4.14.4-1` |
| `wazuh-indexer` | `4.14.4-1` |
| `wazuh-dashboard` | `4.14.4-1` |

Wazuh control output reported version `v4.14.4`, revision `rc2`, and type
`server`. Cluster information reported node `node01` with type `master`.

Registered agents included:

| ID | Name | State | Registered IP policy |
|---|---|---|---|
| `000` | `wazuh-server` | Active / Local | Local |
| `001` | `ubuntu-victim01` | Active | `any` |

## Victim Agent Configuration

`ubuntu-victim01` had `wazuh-agent` package `4.14.4-1`. Wazuh control output
reported version `v4.14.4`, revision `rc2`, and type `agent`.

The agent was configured for manager address `192.0.2.23`, port `1514`, and
TCP. Its profile was `ubuntu, ubuntu22, ubuntu22.04`. The `wazuh-agent` service
was enabled and active, and the `wazuh-logcollector` process was running.

The agent-local `ossec.conf` contained:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

The shared `/var/ossec/etc/shared/agent.conf` existed. The inspection found no
matching `audit.log` or `log_format=audit` directive in that file. This proves
only that the inspected pattern was absent; it does not establish that the
shared configuration was otherwise empty. The confirmed audit collection
directive was agent-local.

## Auditd Configuration And Health

`ubuntu-victim01` had auditd package `1:3.0.7-1build1`. The service was enabled
and active, and auditd reported version `3.0.7`.

The audit log was `/var/log/audit/audit.log` and was approximately 5.6 MB at
inspection time. Audit status reported enabled `1`, lost events `0`, and backlog
`0`.

Observed active rules were:

- 64-bit `execve` for `auid >= 1000`, key `isl_execve`
- 32-bit `execve` for `auid >= 1000`, key `isl_execve`
- watch on `/home/victim01/.ssh`, key `isl_ssh_persistence`
- watch on `/tmp/ai_soc_lab_scenario_007_marker.txt`, key `isl_tmp_marker`

No rule with key `scenario009_audit_smoke` was present in the observed
`auditctl -l` output. Current `execve` rules may capture tar or chmod execution,
but they do not prove collection of the five file-operation observations needed
for scenario parity.

The auditd message `No plugins found, not dispatching events` does not establish
that Wazuh collection is unavailable. In this configuration,
`wazuh-logcollector` reads `/var/log/audit/audit.log` directly.

## Confirmed Collection Path

The confirmed configured path is:

```text
auditd
  -> /var/log/audit/audit.log
  -> wazuh-logcollector
  -> TCP 1514
  -> wazuh-server
```

Active agent registration and connectivity were observed. This confirms
configuration and connectivity, not that every scenario record is retained or
that any scenario alert is generated.

## Manager-Side Artifact Availability

At inspection time:

- `/var/ossec/logs/alerts/alerts.json` existed and was approximately 23 KB
- `/var/ossec/logs/archives/archives.json` did not exist
- manager `logall` was `no`
- manager `logall_json` was `no`

Alert storage is available. `alerts.json` contains alert-producing records and
may omit records that do not alert. It is a candidate supporting artifact, but
has not been shown to retain enough original fields for deterministic audit
grouping or existing endpoint normalization.

Raw JSON archive storage was not enabled, so `archives.json` is not currently
available as a candidate source artifact.

## Follow-On Alerts Inspection

A controlled follow-on run is recorded in
[Scenario 009 Wazuh Alerts Inspection](wazuh_alerts_inspection.md).
The safe runner executed from `kali-attacker`, local auditd confirmed all five
expected file-operation observations, and audit health reported zero lost events.
During the same window, `alerts.json` gained `31` lines but contained `0`
matching scenario documents.

This establishes that the current alert output does not expose Scenario 009
evidence. It does not prove or disprove that Wazuh received the underlying audit
records.

## Follow-On Raw Archive Validation

A bounded temporary `logall_json` observation is recorded in
[Scenario 009 Wazuh Raw Archive Validation Result](wazuh_raw_archive_validation.md).
The manager archive window contained `1026` new JSON documents, including `55`
strong Scenario 009 documents for agent `001:ubuntu-victim01`. All five expected
operations reached the manager with the same core serials observed locally.

Each inspected core serial was classified in the retained summary as one
`/var/log/audit/audit.log` document with structured `audit.type=SYSCALL`. The
summary did not demonstrate separate serial-linked `CWD`, `PATH`, `EXECVE`, or
`PROCTITLE` documents and did not retain the exact `full_log` values. An
additional `34`
strong documents came through `journald` without an extractable original audit
serial.

This confirms Wazuh receipt and supporting observability, but not deterministic
complete grouping or canonical source suitability. The temporary configuration
was restored with matching checksums, the manager returned active, and the
specific temporary audit rule and controlled artifacts were removed.

## Current Scenario 009 Evidence Gap

The Wazuh path has now confirmed:

- manager receipt of staging directory creation
- manager receipt of `note.txt` creation
- manager receipt of `metadata.json` creation
- manager receipt of tar archive creation
- manager receipt of archive permission change
- preservation of core audit serials, keys, syscalls, executables, and `full_log`

The Wazuh path has not yet validated:

- complete `SYSCALL`, `EXECVE`, `CWD`, `PATH`, `PROCTITLE`, and `EOE` retention
- deterministic grouping across `/var/log/audit/audit.log` and `journald`-located
  documents whose representation type remains unresolved
- exact-record deduplication after Wazuh transport
- canonical five-event semantic parity
- exactly one canonical `suspicious_archive_staging` DSL detection
- incident or downstream pipeline consumption

## Source Artifact Decision

Primary canonical source artifact: unresolved.

`alerts.json` is not canonical under the observed configuration. Temporary
`archives.json` observation confirmed supporting observability and manager
receipt, but the retained Outcome C evidence did not demonstrate complete serial-linked audit groups.
Therefore `archives.json` is not selected as canonical from this observation.

A later read-only inspection recorded in
[Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md)
confirmed separate agent-local audit-log and journald inputs, strongly localized
the raw archive to the analysisd output boundary, and found Filebeat archive
ingestion disabled. Version-matched source verification recorded in
[Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md)
confirms agent-side audit grouping and archive `full_log` preservation of the
incoming payload as the expected product path. A separate Stage 4 controlled
comparison recorded in
[Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md)
confirmed exact grouped-payload identity for one controlled event. The
exact historical Scenario 009 `full_log` remains unavailable.

## Configuration-Change Boundary

The environment-record PR changed no Wazuh or auditd configuration. A later
bounded operational validation temporarily enabled `logall_json`, used the
specific Scenario 009 audit watch, and restored the original configuration with
matching checksums. No persistent audit rule, decoder, Wazuh rule, or rsyslog
configuration was changed.

## Confirmed Versus Pending

| Capability | Status | Meaning |
|---|---|---|
| Wazuh server deployed | Confirmed | Native packages observed |
| Manager, indexer, and dashboard versions | Confirmed | `4.14.4-1` packages observed |
| `ubuntu-victim01` agent enrolled | Confirmed | Agent ID `001` active |
| Agent connectivity | Confirmed | Active registration and configured TCP path observed |
| auditd running | Confirmed | Service and health state observed |
| Agent configured to collect `audit.log` | Confirmed | Agent-local directive observed |
| `alerts.json` available | Confirmed | File existed at inspection time |
| `archives.json` available | Temporarily observed | Bounded `logall_json` run produced `1026` new documents |
| `scenario009_audit_smoke` rule active | Absent after cleanup | Specific temporary rule removal confirmed |
| Scenario evidence in `alerts.json` | Not observed | Controlled run produced `0` matching documents despite complete local auditd evidence |
| `alerts.json` canonical source suitability | Rejected under observed configuration | No scenario evidence was exposed for grouping or normalization |
| Wazuh receipt of all five operations | Confirmed | Core local serials were present manager-side |
| `archives.json` supporting observability | Confirmed | `55` strong scenario documents retained envelope and `full_log` |
| `archives.json` canonical source suitability | Not established | Retained structured summaries exposed `SYSCALL` per core serial; exact grouped `full_log` values were not retained |
| Five-event Wazuh semantic parity | Pending | Semantic presence confirmed; deterministic complete grouping is not established from retained evidence |
| Wazuh-path DSL detection | Pending | No canonical hit produced from Wazuh evidence |
| Wazuh-path incident consumption | Pending | No Wazuh-derived hit consumed |

## Recommended Next Validation

The no-manager-configuration-change `alerts.json` inspection is complete and
found no matching scenario evidence.

The bounded temporary `logall_json` validation has been executed and recorded
as Outcome C in
[Scenario 009 Wazuh Raw Archive Validation Result](wazuh_raw_archive_validation.md).
Stages 2 and 3 confirmed the deployed input topology and expected Wazuh
`v4.14.4` grouping/archive path. Stage 4 then confirmed
`EXACT_CONTENT_PRESERVED` / T1-equivalent controlled evidence through exact
grouped-payload identity for one separate event. The original T3/Outcome C evidence remains unchanged. Canonical source
selection, parity, normalization, detection, and incident consumption remain
pending.

## Explicit Non-Goals

The original environment-record observation did not:

- validate scenario_009 through Wazuh or validate Wazuh-native rules
- install or configure Wazuh
- enable `logall` or `logall_json`
- add audit rules or restart services
- export raw production logs
- define an adapter, fixture, source-code change, or test
- validate Velociraptor or direct continuous production-log ingestion
- execute containment or response
- claim exfiltration, ransomware, credential access, compromise, or real-data
  collection

## Relationship To The Validation Plan

The contract is defined in
[Scenario 009 Wazuh / SIEM Validation Plan](wazuh_siem_validation_plan.md).

This observation confirms deployment, component versions, agent topology,
connectivity, and agent-local audit collection configuration. The alert
inspection excludes `alerts.json` as canonical input. The raw-archive observation
confirms manager receipt and supporting observability but records Outcome C
because complete grouping was not demonstrated by the retained summaries. The
primary canonical Wazuh source and downstream behavioral validation remain
unresolved. The existing sanitized
auditd fixture remains canonical.
