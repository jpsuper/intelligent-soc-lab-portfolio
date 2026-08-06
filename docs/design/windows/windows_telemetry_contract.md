# Windows Telemetry MVP Contract

Status: Design contract. See the [Main Roadmap](../../roadmap/roadmap.md) for
current implementation and validation status.

## 1. Purpose

This document defines the provider and source boundaries for a standalone
Windows endpoint telemetry MVP. It describes how Windows Event Log and Sysmon
source events can be parsed and mapped into the existing
[`normalized_endpoint_event`](../defender/normalized_endpoint_event_contract.md)
contract and consumed by deterministic detection.

> Document responsibility:
> This document owns stable Windows source semantics, identity, normalization,
> provenance, trust boundaries, and MVP scope. The
> [Main Roadmap](../../roadmap/roadmap.md) owns implementation status,
> priorities, sequencing, validation depth, and Done Criteria. Detailed fixture,
> mapper, and native-parity evidence remains with the linked contracts and
> runbook.

The intended flow is:

```text
Windows Event Log / Sysmon source event
  -> Windows source parser / mapper
  -> normalized_endpoint_event
  -> deterministic DSL detection
  -> correlation
  -> incident pipeline
```

Windows source documents, Sysmon XML, and Wazuh documents are not canonical
semantic events. Acquisition format and canonical meaning remain separate so a
future implementation can replace a direct fixture with Windows Event
Forwarding or a Wazuh Indexer query without changing downstream event semantics.

The MVP starts with standalone Windows process telemetry, centered on Sysmon
Event ID 1. Active Directory and Domain Controller telemetry are deferred.
Detection remains deterministic under the existing lab policy.

### Implementation And Evidence References

Current Windows and cross-platform implementation status is maintained in the
[Main Roadmap](../../roadmap/roadmap.md), including the distinction among
fixture parity, bounded native observation, focused-test validation, live
runtime validation, and complete cross-platform execution.

Detailed evidence for this contract remains close to the relevant boundary:

- the [Sysmon Event ID 1 Fixture Contract](sysmon_event1_fixture_contract.md)
  owns fixture, parser, expected-output, and bounded native-observation evidence;
- the [Sysmon Event ID 1 Normalized Mapper Contract](sysmon_event1_normalized_mapper_contract.md)
  owns mapper identity, timestamp, field-mapping, and parity behavior; and
- the [native parity runbook](../../runbooks/windows/sysmon_event1_native_parity.md)
  owns the operator procedure and observed-run evidence.

The sections below define required behavior and scope. Describing a boundary or
validation slice here does not by itself claim that it is implemented, live, or
complete.

## 2. MVP Scope

The initial scope is intentionally narrow:

```text
Primary
  Sysmon Event ID 1 - Process creation

Secondary / later in the same Windows MVP
  Security Event ID 4624 - Successful logon
  Security Event ID 4625 - Failed logon
```

The MVP scope permits a Sysmon Event ID 1-only initial slice. Event IDs 4624
and 4625 require their own source-field mapping and fixtures before they are
added.

The first MVP does not cover:

- Active Directory correlation;
- Domain Controller-specific events;
- PowerShell Script Block Logging Event ID 4104;
- Sysmon network connection Event ID 3;
- Sysmon file creation Event ID 11;
- registry modification;
- scheduled task detection;
- Windows Defender or Microsoft Defender for Endpoint telemetry;
- broad Windows event coverage;
- live Wazuh ingestion;
- native Wazuh rules; or
- automatic containment.

These are future candidates, not implied capabilities of this design.

## 3. Responsibility Boundaries

### Acquisition

Acquisition retrieves a bounded representation such as EVTX-derived data, XML,
JSON, or a Wazuh query record. It records where the representation came from
but does not assign canonical event meaning.

### Source Parser

The source parser interprets the Windows event structure, provider, Event ID,
system fields, and provider-specific event fields. It validates source types and
normalizes source sentinels. It does not emit a detection verdict.

### Source Mapper

The source mapper converts one source-specific parsed event into the existing
`normalized_endpoint_event` shape. It applies explicit identity, typing, and
field-mapping policy without inventing missing evidence.

### Normalized Event Contract

The normalized event contract supplies backend- and source-independent endpoint
semantics. It remains the downstream source of truth; this document does not
create a Windows-specific canonical schema.

### Detection DSL

The detection DSL applies deterministic conditions to normalized events. It
does not parse XML or depend directly on Wazuh field paths.

### Correlation

Correlation handles relationships among multiple events, sources, identities,
and timestamps. A parser or mapper does not infer those relationships from one
record.

### Incident Pipeline

The incident pipeline creates an incident artifact from detection and
correlation results. A Windows source event or normalized process observation
alone is not an incident.

Acquisition, parsing, mapping, detection, correlation, and incident creation
remain independently testable boundaries.

## 4. Supported Acquisition Representations

The MVP anticipates these representations:

1. Sanitized JSON fixture.
2. Windows Event Log XML export.
3. Future Windows Event Forwarding representation.
4. Future Wazuh Indexer query record.

The sanitized fixture is the initial validated test path. Wazuh is a
future operational query path, not the source of canonical semantics. Windows
XML and EVTX-derived events are source evidence that must be parsed and mapped
before reaching the DSL. Raw EVTX binary parsing is not a prerequisite for the
first MVP.

A representation adapter may vary by acquisition path, but it must produce the
same source-specific parsed event contract for equivalent source evidence.

## 5. Initial Source-Event Contract: Sysmon Event ID 1

The source-specific parsed event can retain these Sysmon process-creation
fields when present:

```text
provider_name
provider_event_id
event_record_id
computer
channel
system_time
utc_time
process_guid
process_id
image
file_version
description
product
company
original_file_name
command_line
current_directory
user
logon_guid
logon_id
terminal_session_id
integrity_level
hashes
parent_process_guid
parent_process_id
parent_image
parent_command_line
parent_user
rule_name
```

The two parsed timestamp fields retain different source authorities:

```text
system_time
  timezone-aware timestamp derived from Windows Event Log System / TimeCreated

utc_time
  timezone-aware timestamp derived from Sysmon EventData / UtcTime
```

Both remain independently traceable. The parser must not silently overwrite
one with the other.

The source parser classifies them as follows.

Identifier meanings remain distinct throughout parsing, mapping, and
provenance:

```text
source system.provider_event_id -> parsed provider_event_id
  Sysmon or Windows provider event type, such as 1, 4624, or 4625

event_record_id
  Windows Event Log record identity; required by the current parsed-event
  schema and first-slice mapper

canonical event_id
  lab-generated deterministic normalized event identifier; absent from the
  source-specific parsed event and generated by the versioned mapper

backend record ID
  Wazuh or SIEM retrieval document identifier

fixture record ID
  test-only fixture provenance
```

None of these identifiers substitutes for another. In particular, a backend
record ID is not a Windows `event_record_id`, and a fixture record ID is not a
live record identity.

### Required Parsed Input For The Sysmon Event ID 1 Mapper

The complete authority is
[`sysmon_event1_parsed_event.schema.json`](../../../schemas/sysmon_event1_parsed_event.schema.json).
The Sysmon Event ID 1 mapper requires these parsed fields:

```text
fixture_contract_version
fixture_id
source_format
provider_name
provider_event_id
event_record_id
computer
channel
system_time
utc_time
process_guid
process_id
image
command_line
user
parent_process_id
parent_image
```

`event_record_id` and `channel` are canonical identity inputs. `channel` is
also routing authority. `utc_time` is the canonical process-observation
timestamp, while `system_time` is required independent provenance.
`process_guid`, `command_line`, `user`, `parent_process_id`, and
`parent_image` are also schema-required inputs, not partial-mapping quality
hints.

The Sysmon Event ID 1 mapper fails closed with
`SysmonEvent1MappingError` when the parsed-event schema, provider route,
identity inputs, timestamp inputs, Windows basename requirements, or endpoint
output schema are invalid. A wrong provider, provider Event ID, or channel is
rejected. The mapper does not emit a partial event or a quarantine artifact.
Missing optional context is omitted without fabricating an empty string, zero,
`unknown`, or another placeholder.

### Optional Source Context

- `current_directory`
- `provider_guid`
- `event_version`
- `event_level`
- `event_task`
- `event_opcode`
- `event_keywords`
- `file_version`
- `description`
- `product`
- `company`
- `original_file_name`
- `logon_guid`
- `logon_id`
- `terminal_session_id`
- `integrity_level`
- `hashes`
- `parent_process_guid`
- `parent_command_line`
- `parent_user`
- `rule_name`

These fields are included only when present. Selected values remain under the
documented top-level mapping or `source_fields` allowlist. Verbose or complete
source content belongs behind `raw_ref`; `source_fields` must not become an
unrestricted copy of the raw event.

## 6. Mapping To `normalized_endpoint_event`

The
[`endpoint_events.schema.json`](../../../schemas/endpoint_events.schema.json)
is the canonical field authority. The Sysmon Event ID 1 mapping uses its
existing names.

The exact mapping policy is defined in the
[`Sysmon Event ID 1 Normalized Mapper Contract`](sysmon_event1_normalized_mapper_contract.md).

### Canonical Event ID Generation

Canonical `event_id` is a deterministic lab identifier. It must not be
presented as a native Windows identifier. This first mapper slice uses exactly:

```text
identity_version
provider_name
computer casefolded for identity only
channel
event_record_id
```

The identity object is serialized as sorted compact JSON with UTF-8, hashed
with SHA-256, and emitted as `sysmon-event1:v1:` plus the full lowercase
64-character digest. The method is `sha256-json-canonical-v1`, and the identity
version is `sysmon-event1-event-id.v1`. Original host case is preserved in
`host`. `process_guid` remains provenance but is not an identity input while
required `event_record_id` is present. Fallback and fixture-only identity are
outside this contract.

| Sysmon parsed value | Canonical field | Mapping rule |
|---|---|---|
| approved deterministic identity input set | `event_id` | Apply the versioned canonical event ID generation policy; do not imply a native Windows ID |
| constant `sysmon` | `source` | Identifies original telemetry semantics, even when retrieval later passes through Wazuh |
| constant `windows` | `platform` | Sysmon Event ID 1 is Windows endpoint telemetry |
| `computer` | `host` | Preserve the source value; apply documented comparison policy separately |
| `utc_time` | `timestamp` | Preserve the Sysmon EventData process-observation timestamp exactly |
| constant `process_exec` | `event_type` | Event ID 1 records process creation |
| `user` | `user` | Preserve Windows account form |
| `process_id` | `pid` | Parse as an integer when valid |
| `parent_process_id` | `ppid` | Parse as an integer when valid |
| basename of `image` | `process_name` | Derive with Windows path semantics |
| `image` | `exe` | Preserve the Windows executable path |
| `command_line` | `command_line` | Preserve as untrusted source text |
| `current_directory` | `cwd` | Preserve the Windows path when present |
| basename of `parent_image` | `parent_process_name` | Derive with Windows path semantics |
| `parent_image` | `parent_exe` | Preserve the Windows executable path |
| `parent_command_line` | `parent_command_line` | Preserve as untrusted source text when present |
| fixture or retrieval locator | `raw_ref` | Reference source evidence without embedding it |
| remaining selected source context | `source_fields` | Preserve compact provider-specific identifiers and details |

The mapper retains both timestamps in `source_fields`, records
`timestamp_source: utc_time`, and records exact equality as
`timestamps_equal`. Unequal schema-valid values map successfully. The mapper
does not apply tolerance, calculate a delta, reject a mismatch, or place
`system_time` in `collection_timestamp`.

`process_guid`, `parent_process_guid`, `provider_name`, `provider_event_id`,
`event_record_id`, `channel`, logon identifiers, integrity level, hashes, and
other selected source context belong in `source_fields` unless a current
canonical field explicitly applies. No new Windows-only canonical top-level
fields are introduced here.

The reviewed canonical vocabulary already contains `auth_success` and
`auth_failure`, so future Security Event ID 4624 and 4625 mappings can use those
existing event types. Their detailed account, logon, network, status, and
provenance mapping is deferred to the later fixture slice. This document does
not introduce a new canonical `event_type`.

## 7. Identity And Typing Rules

- Windows process IDs are parsed as integers when valid. Invalid values do not
  become zero or another placeholder.
- `ProcessGuid` is retained as a source-specific stable identifier in
  `source_fields`; it is not treated as a cross-provider universal ID.
- `LogonId` can remain a hexadecimal source string. The mapper does not force
  it into decimal and lose its original representation.
- Windows users can retain `DOMAIN\user` form.
- Computer-name comparison uses a documented mapper policy. The recommended MVP
  compares names case-insensitively while preserving the original source value.
- Windows paths remain Windows paths. The mapper does not translate them into
  Linux path syntax.
- Command lines and parent command lines are untrusted text.
- Hashes are parsed by algorithm into separate source fields rather than kept
  as one ambiguous value. Unsupported or malformed entries remain source
  parsing errors or omitted context.
- Missing fields are not replaced with empty strings.
- Source sentinels such as `N/A` and `-` should be normalized to missing only
  when the provider/field contract defines them as sentinels. They must not be
  treated blindly as real evidence.
- Timestamps are converted to timezone-aware ISO 8601. The original source
  timestamp can remain in provenance or `source_fields`.

Type conversion failures are explicit parser or mapper outcomes, not reasons to
silently coerce a different value.

## 8. Provenance

A normalized event or its evidence reference must allow a reviewer to trace:

```text
source_type: sysmon
provider_name
provider_event_id
channel
computer
event_record_id
system_time when available
utc_time when available
fixture or retrieval reference
mapper name/version
canonical event ID generation method/version
```

Provenance traces a source event; it is not a detection verdict. A fixture ID is
test provenance and must not be represented as a live Windows record ID. The
canonical `event_id` remains a lab-generated identifier and does not replace
the retained `provider_event_id` or `event_record_id`. When available,
`system_time` and `utc_time` must both remain traceable as distinct source
timestamps.

When acquisition uses Wazuh, preserve Wazuh retrieval metadata separately from
the original Windows provider metadata wherever the retrieved representation
allows it. The provenance model must not rewrite a Wazuh document ID as a
Sysmon `EventRecordID`, or replace the original provider with Wazuh.

## 9. Initial Deterministic Detection

The initial deterministic detection contract is a PowerShell process
observation derived from normalized `process_exec` events. Process creation is
an atomic observation, not a malicious verdict.

```text
Atomic observation
  source == sysmon
  platform == windows
  event_type == process_exec
  process_name case-insensitive exact match == powershell.exe

Observable behavior features
  powershell_process_observed
  encoded_command_observed
```

The encoded-command observation additionally requires one case-insensitive
exact command token:

```text
-encodedcommand
-enc
```

Substring forms such as `-EncodedCommandSuffix` and `prefix-enc` do not match.
The evaluator does not decode or execute command text. Name matching cannot
identify a renamed binary and does not establish maliciousness. `pwsh.exe`,
additional aliases, hidden-window flags, execution-policy bypass, and download
expressions require later dedicated fixtures and rules.

The detector may emit observable behavior features. Conclusion-oriented
interpretation remains with triage and investigation. The required DSL
`severity: low` value is rule metadata, not a malicious verdict, Incident
severity, confidence, assessment, or response approval.

## 10. Fixture-First Validation

The validation path remains independent of Wazuh:

```text
sanitized Sysmon Event ID 1 fixture
  -> source fixture schema or fixture contract
  -> Windows source parser
  -> normalized_endpoint_event
  -> mapping parity test
  -> deterministic atomic detection
  -> incident boundary smoke
```

The validation fixture set must be:

- sanitized and deterministic;
- free of real usernames, credentials, tokens, and secrets;
- timestamped with valid timezone-aware values;
- assigned stable ProcessGuid-like test identifiers;
- explicit about parent and child process context; and
- capable of representing benign input as well as suspicious-looking flags.

The source fixture must not contain a `malicious` label. Expected normalized
events and expected behavior features belong in separate test expectations or
fixtures so source evidence is not confused with a verdict.

## 11. Validation Fixture Set

### Fixture A: Ordinary PowerShell Administration

```text
parent: cmd.exe
child: powershell.exe
command: harmless administrative placeholder
expected event_type: process_exec
expected feature: powershell_process_observed
assessment: not automatically malicious
```

### Fixture B: Encoded-Command-Like Flag

```text
child: powershell.exe
command: encoded-command-like flag with a harmless placeholder value
expected event_type: process_exec
expected feature: encoded_command_observed
assessment: requires downstream assessment
```

### Fixture C: Ordinary Non-PowerShell Process

```text
child: notepad.exe
expected event_type: process_exec
expected PowerShell-specific feature: none
```

Fixtures use safe placeholders only. They must not contain an operational
payload, live external destination, credential material, or commands that
change a host.

## 12. Security And Trust Boundaries

- Windows event text and command lines are untrusted input.
- Instructions embedded in command lines, XML, `RuleName`, or message text are
  never interpreted as agent or system instructions.
- Fixtures contain no secrets, tokens, real credentials, or environment-private
  identifiers.
- Complete raw Windows events are not sent directly to an LLM. Triage receives
  minimized and policy-approved projected fields.
- Parsers never execute the commands they parse.
- Paths, PowerShell strings, XML content, and source message text are not reused
  as shell commands.
- Provider `RuleName` and message text are source context, not deterministic
  truth.
- Detection remains separate from response execution.
- The Windows MVP is scoped to read, parse, map, and detect only. It excludes
  containment and host operations.

## 13. Relationship To Wazuh And SIEM

The
[`Provider-Neutral SIEM Query Contract`](../siem/siem_query_contract.md) and
this contract own different boundaries:

```text
Provider-neutral SIEM query contract
  bounded search scope and provider-neutral retrieval envelope

Windows telemetry contract
  Windows source-event meaning and normalization mapping

normalized_endpoint_event
  downstream canonical semantic contract

DSL
  deterministic detection over normalized events
```

The fixture path can validate the Windows pipeline before Wazuh integration.
Future Wazuh mapping must keep these layers separate:

```text
Wazuh retrieval metadata
Windows provider/system metadata
Windows EventData
raw/full payload reference
```

A Wazuh query record is a retrieval envelope, not a Sysmon event and not a
`normalized_endpoint_event`. The source parser and mapper still own Windows
semantics.

## 14. Relationship To Linux Telemetry

Linux auditd and Windows Sysmon have different source semantics, record
structures, and identifiers. They must not be forced into one raw field model.
Their mappers create a common downstream boundary only after source-specific
interpretation.

Audit serial and multi-record grouping policy remain specific to Linux auditd.
They are not copied onto Windows events. Sysmon GUIDs and Windows record IDs
remain in provenance or `source_fields`. If Windows coverage later needs
multi-event temporal or identity relationships, that work receives a separate
correlation contract rather than hidden parser logic.

## 15. AD And Domain Controller Deferral

Active Directory and Domain Controller telemetry are deferred because they add
domain, SID, logon-session, authentication-package, and cross-host identity
semantics. Their correlation model differs from standalone endpoint process
telemetry. Adding them before standalone mapping is stable would expand the
contract before its first boundary is validated.

An AD/DC design must preserve these entry conditions:

```text
Sysmon Event ID 1 fixture parser is stable
normalized_endpoint_event parity is demonstrated
Windows process detection smoke is complete
source provenance is stable
a Wazuh-independent fixture path is complete
```

These are entry criteria for later design, not completion claims in this
document.

## 16. Status And Planning References

The [Main Roadmap](../../roadmap/roadmap.md) is the source of truth for the
active sequence, Common Defender Pipeline completion boundary, and incomplete
Windows work:

- [Active Sequence](../../roadmap/roadmap.md#4-active-sequence)
- [Common Defender Pipeline v0](../../roadmap/roadmap.md#5-common-defender-pipeline-v0)
- [Windows and cross-platform defender flow](../../roadmap/roadmap.md#61-windows-and-cross-platform-defender-flow)

This contract intentionally carries no independent Completed, Next, or Future
implementation list. Contract changes still require focused review and must
preserve the source, identity, provenance, safety, runtime, and retrieval
boundaries defined here.

## 17. Non-Goals

This design does not:

- reimplement a Windows EDR;
- support every Sysmon Event ID;
- implement AD detection;
- create Wazuh native rules;
- perform live containment or autonomous response;
- execute malware;
- collect real credentials;
- force Windows telemetry into Linux source semantics;
- make Wazuh the canonical semantic contract;
- add live detection-to-Incident integration, downstream Windows scenarios, or
  runtime artifacts; or
- change Windows, Sysmon, Wazuh, or lab runtime configuration.

Observed product behavior must be labeled separately from this contract.
Product behavior does not override lab policy.
