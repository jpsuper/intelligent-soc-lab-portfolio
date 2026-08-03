# Sysmon Event ID 1 Normalized Mapper Contract

Status: Implemented / Fixture A/B/C Expected Normalized Parity Implemented

## Purpose And Boundary

The versioned mapper in
[`map_sysmon_event1_to_endpoint_event.py`](../../../scripts/windows/sysmon_event1/map_sysmon_event1_to_endpoint_event.py)
projects one schema-valid Sysmon Event ID 1 source-specific parsed event into
one normalized endpoint event:

```text
provider-like source JSON
  -> Sysmon Event ID 1 source parser
  -> source-specific parsed event
  -> Sysmon Event ID 1 normalized mapper
  -> one endpoint event object
```

This is telemetry shaping only. The mapper does not generate detection,
verdict, severity, confidence, incident, or response state. The canonical
field authority is
[`endpoint_events.schema.json`](../../../schemas/endpoint_events.schema.json);
the input authority is
[`sysmon_event1_parsed_event.schema.json`](../../../schemas/sysmon_event1_parsed_event.schema.json).

## Public API And Versions

```python
def map_sysmon_event1_to_endpoint_event(
    parsed_event: dict[str, object],
    *,
    source_artifact: str,
) -> dict[str, object]:
    ...
```

The mapper is a pure mapping module. It has no CLI, file write, network,
subprocess, command execution, decoding, environment, clock, or randomness
behavior. It does not mutate `parsed_event`.

Versioned constants:

```text
mapper_name: sysmon_event1_endpoint_event_mapper
mapper_version: "1.0"
event_identity_version: "sysmon-event1-event-id.v1"
event_id_prefix: "sysmon-event1:v1:"
event_id_method: "sha256-json-canonical-v1"
```

## Canonical Event Identity

The first mapper slice uses only the preferred identity set because
`event_record_id` is required by the parsed-event schema:

```json
{
  "identity_version": "sysmon-event1-event-id.v1",
  "provider_name": "Microsoft-Windows-Sysmon",
  "computer_casefold": "win-fixture01",
  "channel": "Microsoft-Windows-Sysmon/Operational",
  "event_record_id": 41001
}
```

The object is serialized with `sort_keys=True`, separators `(",", ":")`, and
`ensure_ascii=False`. The UTF-8 bytes are hashed with SHA-256, and the full
64-character lowercase hex digest is appended to `sysmon-event1:v1:`.

Host case is folded only for identity. The original `computer` value and case
are preserved as top-level `host`. `process_guid` remains provenance but is not
an identity input while the preferred set is available. No fallback or
fixture-only identity is implemented.

The canonical ID is a deterministic lab identifier. It is not the provider
Event ID, EventRecordID, ProcessGuid, fixture ID, or a native Windows ID.

## Timestamp Policy

Top-level `timestamp` is exactly the parsed `utc_time`, the Sysmon EventData
process-observation time. Both `system_time` and `utc_time` remain independent
values in `source_fields`.

```text
timestamp_source: utc_time
timestamps_equal: system_time == utc_time
```

Unequal schema-valid timestamps are accepted. The mapper applies no tolerance,
computes no delta, and does not use `system_time` as
`collection_timestamp`. There is no timestamp fallback because both values are
required by the parsed-event schema.

## Windows Path Policy

`process_name` and `parent_process_name` are derived from `image` and
`parent_image` with `pathlib.PureWindowsPath`. Original path and filename case
are preserved, and no executable suffix is required. A path ending in `/` or
`\`, or any value with no basename, is rejected. Full Windows paths remain
unchanged in `exe` and `parent_exe`; they are not translated to Linux paths.

## Top-Level Mapping

| Parsed input or rule | Normalized field |
|---|---|
| versioned canonical ID | `event_id` |
| constant `sysmon` | `source` |
| constant `windows` | `platform` |
| `computer` | `host` |
| `utc_time` | `timestamp` |
| constant `process_exec` | `event_type` |
| `user` | `user` |
| `process_id` | `pid` |
| `parent_process_id` | `ppid` |
| Windows basename of `image` | `process_name` |
| `image` | `exe` |
| `command_line` | `command_line` |
| optional `current_directory` | `cwd` |
| Windows basename of `parent_image` | `parent_process_name` |
| `parent_image` | `parent_exe` |
| optional `parent_command_line` | `parent_command_line` |

Unavailable optional fields are omitted rather than populated with null.
Fields that cannot be truthfully derived, including `argv`, `uid`, file,
network, protocol, and collection-time fields, are omitted.

## Provenance

`raw_ref` is a locator, not embedded raw content:

```json
{
  "source_artifact": "<non-empty caller-supplied locator>",
  "fixture_id": "<parsed fixture_id>"
}
```

Required `source_fields` are:

```text
provider_name
provider_event_id
event_record_id
channel
system_time
utc_time
timestamp_source
timestamps_equal
process_guid
mapper_name
mapper_version
event_id_method
event_identity_version
```

The optional allowlist is:

```text
provider_guid
event_version
event_level
event_task
event_opcode
event_keywords
file_version
description
product
company
original_file_name
logon_guid
logon_id
terminal_session_id
integrity_level
hashes
parent_process_guid
parent_user
rule_name
```

Optional provenance is included only when present. Canonical top-level values
are not duplicated, `fixture_id` appears only in `raw_ref`, and the parsed
event is not copied wholesale.

## Validation And Rejection

Before mapping, the input is validated with a Draft 2020-12 validator and
format checker against the parsed-event schema. This fails closed on missing
or additional fields, invalid timestamps, and incorrect provider, provider
Event ID, or channel. `source_artifact` must be a non-empty string.

The mapped event is wrapped in this minimal envelope and validated with the
same validator draft and format checking:

```json
{
  "schema_version": "endpoint_events.v1",
  "events": [
    {
      "event_id": "sysmon-event1:v1:54aa19e2ce68d8cf8f27f519992024f5338d6d9e65c6916912919465c538bcef",
      "source": "sysmon",
      "platform": "windows",
      "host": "WIN-FIXTURE01",
      "timestamp": "2026-01-15T01:02:03.123000Z",
      "event_type": "process_exec"
    }
  ]
}
```

Only the validated event object is returned. Failures raise
`SysmonEvent1MappingError` with a safe field path and without dumping the
source value.

## Expected Normalized Parity

Fixture A/B/C static `expected_normalized` artifacts preserve the mapper return
value as one endpoint event object rather than an artifact envelope. Focused
tests wrap each object in the minimal `endpoint_events.v1` envelope for schema
validation and enforce both exact deterministic paths:

```text
expected_parsed -> mapper -> expected_normalized
source -> parser -> mapper -> expected_normalized
```

This parity is repository-fixture evidence only. It does not claim live
normalized parity or add detection semantics to the mapper. The separately
implemented deterministic detector consumes these normalized events and has
its own Fixture A/B/C `expected_detection` parity.

## Security And Trust Boundaries

Command lines and all source text remain untrusted data. The mapper never
executes, tokenizes, or decodes them. Normalization does not establish
maliciousness, attack success, a detection, an incident, or permission for any
state-changing response. It does not alter pre-case investigation or
post-action DFIR behavior.

## Downstream Status And Non-Responsibilities

- the mapper does not generate PowerShell observable features or detections
- downstream deterministic PowerShell observation and Fixture A/B/C
  `expected_detection` parity are implemented separately
- Common Defender Pipeline v0 invocation/spine
- incident bridging
- Wazuh Windows integration or live collector changes
- fallback event identity
- CLI or artifact writing

The next focused slice implements Common Pipeline v0 without changing this
mapper boundary.
