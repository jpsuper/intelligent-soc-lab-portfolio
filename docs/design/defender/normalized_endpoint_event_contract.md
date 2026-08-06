# Normalized Endpoint Event Contract

## Purpose

The lab should avoid passing every source-specific endpoint format directly into investigation. auditd, Sysmon, osquery, Velociraptor, Wazuh, macOS telemetry, Splunk, and ELK each expose different field names, nesting, identifiers, and event semantics. If investigation logic consumes each native format directly, every new telemetry source creates source-specific branching in evidence review, prompt inputs, tests, and future enrichment.

Source-specific collectors and parsers should instead normalize stable, useful endpoint telemetry into a common event model. The normalized model gives investigation a predictable factual input while preserving the original source record for review and troubleshooting.

Normalization is telemetry shaping only. It is not detection, triage, assessment, response recommendation, or Rule Improvement promotion.

## Intended Flow

```text
auditd_events.json
Sysmon events
osquery rows
Velociraptor artifacts
Wazuh alerts
macOS telemetry
        |
        v
normalized endpoint event contract
        |
        v
endpoint_events.json
        |
        v
investigation evidence
        |
        v
observed_facts / supporting_signals
        |
        v
endpoint-derived enriched_features
        |
        v
missing_pivots / recommended_pivots
```

`endpoint_events.json` is an optional investigation input. When absent, existing investigation behavior should remain unchanged.

## Design Principles

- Preserve raw or source-specific events for reviewer inspection.
- Normalize only stable fields that are useful across endpoint sources.
- Keep source-specific fields under `source_fields` or in a sidecar object referenced by `raw_ref`.
- Do not infer maliciousness during normalization.
- Do not change detection, triage, investigation assessment, action generation, or Rule Improvement behavior.
- Treat normalized endpoint events as factual telemetry, not conclusions.
- Allow sparse events; not every source can populate every field.
- Prefer consistent field names over source-native naming when a field has a clear cross-source meaning.
- Keep attacker-side structured runner events separate from defender-side endpoint telemetry.

## Contract Scope And Status Ownership

This document owns the stable `endpoint_events.json` envelope, common event
vocabulary, source-mapping requirements, provenance rules, and downstream trust
boundaries. Source-specific mapper contracts and fixtures own evidence that a
particular source satisfies this contract.

The [Main Roadmap](../../roadmap/roadmap.md) and its phase documents own current
implementation status, validation depth, priorities, and sequencing. A source
being listed in an example or extension condition below does not mean that its
mapper, collection path, or end-to-end validation is complete.

## Implemented Event Shape

[`endpoint_events.schema.json`](../../../schemas/endpoint_events.schema.json)
defines the canonical object envelope with required `schema_version` and
`events` fields. The envelope can also contain `generated_at`,
`source_artifact`, `source_run_id`, and `metadata`. Current converters and
source mappers validate mapped event objects through this envelope. The event
object shape below is the implemented canonical contract.

Required fields:

| Field | Type | Description |
|---|---|---|
| `event_id` | string | Stable event identifier within the normalized artifact. This may be derived from source, host, timestamp, and source event ID when no native ID exists. |
| `source` | string | Telemetry source, such as `auditd`, `sysmon`, `osquery`, `velociraptor`, `wazuh`, `macos`, `splunk`, or `elk`. |
| `platform` | string | Endpoint platform, such as `linux`, `windows`, `macos`, or `unknown`. |
| `host` | string | Endpoint hostname or asset identifier. |
| `timestamp` | string | Event timestamp in ISO 8601 format when available. |
| `event_type` | string | Normalized event type from the vocabulary below. |

Optional common fields:

| Field | Type | Description |
|---|---|---|
| `user` | string or null | User name, account name, or best available user identity. |
| `uid` | string, number, or null | Numeric or source-native user identifier. |
| `pid` | string, number, or null | Process ID. |
| `ppid` | string, number, or null | Parent process ID. |
| `process_name` | string or null | Process image or command name. |
| `exe` | string or null | Executable path. |
| `argv` | array of strings or null | Process arguments when available as structured values. |
| `command_line` | string or null | Full command line when available. |
| `cwd` | string or null | Current working directory. |
| `file_path` | string or null | Primary file path for file-oriented events. For process execution, prefer `exe` and leave `file_path` empty unless the source explicitly describes a separate file target. |
| `file_action` | string or null | File action, such as `write`, `create`, `delete`, `rename`, `modify`, or a source-specific normalized value. |
| `src_ip` | string or null | Source IP address for network or auth events. |
| `src_port` | number or null | Source port for network events. |
| `dest_ip` | string or null | Destination IP address. |
| `dest_port` | number or null | Destination port. |
| `protocol` | string or null | Network protocol, such as `tcp`, `udp`, `icmp`, `dns`, or `unknown`. |
| `parent_process_name` | string or null | Parent process name when known. |
| `parent_exe` | string or null | Parent executable path. |
| `parent_command_line` | string or null | Parent command line when known. |
| `raw_ref` | string or object or null | Pointer to preserved raw/source-specific data, such as source file path, event offset, source event ID, artifact name, or sidecar record ID. |
| `source_fields` | object | Source-specific fields that should be preserved but not promoted to common top-level fields. |
| `collection_timestamp` | string or null | Telemetry collection time when it differs from event timestamp or when true event time is unavailable. |

Guidance:

- Required fields should be present for every normalized event. If the source cannot provide a trustworthy value, use a conservative value such as `unknown` only where the future schema allows it.
- Optional fields should be omitted or set to null when unavailable.
- `source_fields` should not become a dumping ground for every raw byte if a separate raw artifact is available. Prefer a compact set of useful source-native fields plus `raw_ref`.
- Normalizers should not add assessment labels such as `malicious`, `compromised`, `attack_success`, or `severity`.

## Common Event Types

| `event_type` | Meaning |
|---|---|
| `process_exec` | Process execution or command invocation. |
| `file_write` | File creation, write, truncate, or content modification. |
| `file_delete` | File deletion. |
| `file_rename` | File rename or move. |
| `persistence_file_change` | Change to a path commonly used for persistence, such as SSH `authorized_keys`, launch agents, startup folders, or similar platform-specific paths. |
| `network_connection` | Network connection attempt or established connection. |
| `dns_query` | DNS lookup or resolver event. |
| `auth_success` | Successful authentication event. |
| `auth_failure` | Failed authentication event. |
| `privilege_change` | Privilege escalation, token change, sudo/admin transition, or equivalent source event. |
| `service_change` | Service creation, modification, start, stop, or removal. |
| `scheduled_task_change` | Scheduled task, cron, launchd, or equivalent schedule modification. |
| `registry_change` | Windows registry change. |
| `unknown` | Event could not be safely mapped to a more specific normalized type. |

This vocabulary is intentionally small. Future PRs may add event types when they are needed by tests, schemas, and investigation use cases.

## Source Mapping Examples

| Source event | Normalized `event_type` | Mapping notes |
|---|---|---|
| Linux auditd `execve` records | `process_exec` | Map `exe`, reconstructed `argv`, `comm`, `pid`, `ppid`, `cwd`, user IDs, audit key, and timestamp. Preserve audit serial and record types in `source_fields`. |
| Linux auditd PATH write event | `file_write` | Map selected target path to `file_path`, write/create/truncate semantics to `file_action`, and preserve all PATH records in `source_fields` or raw sidecar data. |
| Linux auditd `.ssh/authorized_keys` watch | `persistence_file_change` | Map authorized keys path to `file_path`; keep audit key and syscall details in `source_fields`. Do not infer persistence success. |
| Windows Sysmon Event ID 1 | `process_exec` | Map image to `exe`, command line to `command_line`, process GUID/ID to `source_fields` or `pid`, user to `user`, and parent image/command line to parent fields. |
| Windows Sysmon Event ID 3 | `network_connection` | Map source/destination IP and port, protocol, process image, process ID, and user. Preserve Sysmon-specific GUIDs in `source_fields`. |
| Windows Security Event 4624 | `auth_success` | Map account, host, logon type, source IP, and timestamp. Preserve event ID and logon ID in `source_fields`. |
| Windows Security Event 4625 | `auth_failure` | Map failed account, host, source IP, failure reason if available, and timestamp. Preserve source-native status/substatus in `source_fields`. |
| osquery process row | `process_exec` or process inventory evidence | If row represents an execution event, map to `process_exec`. If it is a periodic snapshot, preserve it as endpoint inventory evidence or use `unknown` until a dedicated inventory contract exists. |
| Velociraptor artifact row | Source-specific endpoint evidence | Map clear process, file, network, auth, or persistence rows to the corresponding normalized type. Preserve artifact name, query, and collection metadata in `source_fields`. |
| Wazuh alert | Alert evidence or normalized endpoint event | If original endpoint telemetry is available in the alert payload, map that telemetry to a normalized endpoint event. If only the alert conclusion is available, keep it as alert evidence rather than pretending it is raw endpoint telemetry. |

## Relationship To Current Auditd Work

Current `auditd_events.json` is a source-specific normalized artifact. It already gives investigation factual endpoint evidence for process execution, selected file writes, and persistence-path changes. It should be considered a stepping stone toward the future common `endpoint_events.json` contract.

Current auditd behavior should not be broken:

- The auditd parser can continue to emit `auditd_events.json`.
- auditd signal enrichment should continue to populate factual `observed_facts` and `supporting_signals`.
- Raw audit logs and source-specific normalized fields should remain available for review where current workflows expect them.

Future implementation can take either path:

1. Add an `auditd_events.json` to `endpoint_events.json` converter.
2. Update the auditd parser to emit the common endpoint event shape directly, while preserving current compatibility as needed.

Either path should preserve existing auditd tests and investigation behavior until callers are intentionally migrated.

## Relationship To SIEM

A SIEM can provide indexed and searchable normalized records. Wazuh, Splunk, ELK, and similar platforms may eventually become the source of endpoint events for the lab. This contract is still useful in that future because it defines what downstream lab components expect, regardless of whether the upstream source is:

- a local parser,
- a Wazuh alert or archive query,
- a Splunk or ELK search result,
- a Velociraptor collection,
- an osquery result, or
- another endpoint telemetry collector.

When a SIEM already provides a normalized schema, the lab importer should map that schema into this contract rather than making investigation depend directly on SIEM-specific field names.

## Investigation Boundaries

Normalized endpoint events may support investigation evidence by contributing to:

- `evidence_summary.observed_facts`
- `evidence_summary.supporting_signals`
- preserved raw/source evidence references
- evidence-grounded endpoint-derived `enriched_features`
- endpoint-derived `missing_pivots`
- endpoint-derived `recommended_pivots`

They must not directly modify:

- confidence,
- severity,
- `attack_story`,
- recommended actions,
- final assessment,
- `overall_result`,
- `detected`, or
- Rule Improvement promotion behavior.

The existing separation should remain intact:

```text
source telemetry
  -> normalized endpoint events
  -> observed facts / supporting signals
  -> endpoint-derived features / pivots
  -> assessment logic owned elsewhere
```

## Non-Goals

This document does not:

- Implement the wider Windows telemetry or detection pipeline beyond the
  focused Sysmon Event ID 1 mapper.
- Implement macOS support.
- Implement osquery, Velociraptor, Wazuh, Splunk, or ELK ingestion.
- Replace Wazuh, Splunk, ELK, or any SIEM.
- Define detection logic.
- Change scoring, confidence, severity, or assessment behavior.
- Create or promote rule candidates.
- Require all fields to be present for all telemetry sources.
- Change current auditd parser or investigation behavior.
- Treat endpoint-derived enriched features or pivots as automatically promotable rule candidates.

## Extension Conditions

A new source mapping or consumer should be added only when it:

1. has a source-specific contract or documented mapping boundary;
2. validates mapped events through
   [`endpoint_events.schema.json`](../../../schemas/endpoint_events.schema.json);
3. preserves source identity, timestamp semantics, and reviewable provenance;
4. uses deterministic fixtures or bounded validation evidence;
5. remains additive when `endpoint_events.json` is absent; and
6. does not move detection, assessment, response, or promotion decisions into
   normalization.

Priorities and implementation order for additional sources belong in the
[Main Roadmap](../../roadmap/roadmap.md), not in this contract.
