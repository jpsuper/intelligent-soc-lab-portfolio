# Sysmon Event ID 1 Fixture Contract

Evidence scope: Fixture A/B/C source-to-detection parity and bounded native
source/parser parity. See the [Main Roadmap](../../roadmap/roadmap.md) for
overall Windows and common-pipeline status.

## 1. Purpose

This document defines the first sanitized fixture boundary for Sysmon Event ID
1 process-creation telemetry. It narrows the broader
[`Windows Telemetry MVP Contract`](windows_telemetry_contract.md) into three
deterministic fixture cases and their separately reviewed expectations.

> Document responsibility:
> This document owns the sanitized Fixture A/B/C source, parsed, normalized, and
> detection expectations; their separation, identity, safety, and parity
> evidence; and the bounded native source/parser observation. The
> [Main Roadmap](../../roadmap/roadmap.md) owns overall Windows and common-pipeline
> implementation status, priorities, sequencing, validation depth, and Done
> Criteria. Downstream Incident, Triage, and Investigation composition does not
> determine whether this fixture contract is satisfied.

The intended validation path is:

```text
raw/live Sysmon event (runtime evidence; not a repository fixture)
  -> explicit sanitization and review
  -> provider-like source fixture
  -> source-specific parsed event
  -> normalized_endpoint_event
  -> deterministic source-observation detection expectation
```

Each arrow is a contract boundary. A downstream expectation must not be copied
into an upstream source fixture, and successful manual runtime observation does
not by itself establish repository implementation status.

## 2. Scope And Evidence Claims

This contract covers only Sysmon Event ID 1 and these fixture cases:

| Case name | `fixture_id` | Source observation represented | Safety intent |
|---|---|---|---|
| `ordinary_powershell` | `sysmon-event1-ordinary-powershell-001` | Ordinary `powershell.exe` process creation | Exercise PowerShell process observation without suspicious flags |
| `encoded_flag` | `sysmon-event1-encoded-flag-001` | `powershell.exe` process creation with an encoded-command-like flag and inert placeholder | Exercise flag observation without an operational payload |
| `ordinary_notepad` | `sysmon-event1-ordinary-notepad-001` | Ordinary `notepad.exe` process creation | Negative control for PowerShell-specific observation |

### Fixture And Boundary Evidence

Repository evidence:

- source fixture JSON Schema:
  [`sysmon_event1_source_fixture.schema.json`](../../../schemas/sysmon_event1_source_fixture.schema.json);
  and
- focused source fixture schema validation tests:
  [`test_sysmon_event1_source_fixture_schema.py`](../../../tests/windows/sysmon_event1/test_sysmon_event1_source_fixture_schema.py);
- Fixture A/B/C source JSON; and
- focused source fixture inventory and consistency tests:
  [`test_sysmon_event1_source_fixtures.py`](../../../tests/windows/sysmon_event1/test_sysmon_event1_source_fixtures.py);
- Sysmon Event ID 1 source parser; and
- focused source parser tests:
  [`test_parse_sysmon_event1_source.py`](../../../tests/windows/sysmon_event1/test_parse_sysmon_event1_source.py);
- parsed-event JSON Schema:
  [`sysmon_event1_parsed_event.schema.json`](../../../schemas/sysmon_event1_parsed_event.schema.json);
- Fixture A/B/C `expected_parsed` artifacts;
- focused parsed-event schema tests:
  [`test_sysmon_event1_parsed_event_schema.py`](../../../tests/windows/sysmon_event1/test_sysmon_event1_parsed_event_schema.py); and
- exact parser parity tests:
  [`test_sysmon_event1_expected_parsed.py`](../../../tests/windows/sysmon_event1/test_sysmon_event1_expected_parsed.py);
- native Event ID 1 collector adapter tooling:
  [`export_sysmon_event1_provider_json.ps1`](../../../scripts/windows/sysmon_event1/export_sysmon_event1_provider_json.ps1);
- local-only source/parser/parsed-schema parity validator:
  [`validate_sysmon_event1_native_parity.py`](../../../scripts/windows/sysmon_event1/validate_sysmon_event1_native_parity.py);
- focused collector and validator tooling tests; and
- native parity
  [`runbook`](../../runbooks/windows/sysmon_event1_native_parity.md); and
- normalized endpoint mapper and focused tests:
  [`map_sysmon_event1_to_endpoint_event.py`](../../../scripts/windows/sysmon_event1/map_sysmon_event1_to_endpoint_event.py),
  [`test_map_sysmon_event1_to_endpoint_event.py`](../../../tests/windows/sysmon_event1/test_map_sysmon_event1_to_endpoint_event.py),
  and the
  [`normalized mapper contract`](sysmon_event1_normalized_mapper_contract.md);
- Fixture A/B/C static `expected_normalized` endpoint event objects; and
- focused endpoint-envelope schema validation, expected-parsed-to-mapper exact
  parity, and source-to-parser-to-mapper exact parity tests:
  [`test_sysmon_event1_expected_normalized.py`](../../../tests/windows/sysmon_event1/test_sysmon_event1_expected_normalized.py);
- deterministic PowerShell process and encoded-command observation rules using
  the existing atomic DSL/evaluator;
- expected-detection JSON Schema:
  [`sysmon_event1_expected_detection.schema.json`](../../../schemas/sysmon_event1_expected_detection.schema.json);
- Fixture A/B/C static `expected_detection` artifacts; and
- focused schema, rule-loader, exact positive/negative parity, safety-boundary,
  and no-overwrite tests:
  [`test_sysmon_event1_expected_detection.py`](../../../tests/windows/sysmon_event1/test_sysmon_event1_expected_detection.py).

Downstream use of these fixtures by the common pipeline is tracked in the
[Main Roadmap](../../roadmap/roadmap.md) and the
[Defender Event Processing Flow](../../architecture/defender-event-processing-flow.md).
This contract does not own completion claims for Incident, Triage,
Investigation, live integration, or cross-platform execution.

Observed manually on 2026-07-26:

- bounded `windows-victim01` native collection;
- source-shape validation for 2/2 records;
- source parser live parity for 2/2 records;
- parsed-event schema live parity for 2/2 records;
- no unknown EventData warnings observed; and
- no live artifacts committed.

The mapper produces one normalized endpoint event from one parsed event.
Fixture A/B/C expected normalized and detection parity is fixed by separate
static artifacts. This contract defines no expected Incident, Triage, or
Investigation artifact and makes no claim about downstream analytical quality.

## 3. Required Boundary Model

### 3.1 Raw Or Live Event Versus Sanitized Fixture

A raw/live Sysmon event is runtime evidence produced by Windows and Sysmon. It
may contain real hostnames, users, paths, identifiers, timestamps, network
details, or other environment-specific values. It is not suitable for direct
commit as a fixture.

A sanitized fixture is a deliberately curated, deterministic representation.
It uses synthetic identities and safe command text, removes environment-private
values, and retains only fields required to exercise Event ID 1 semantics. It
must not claim to be the byte-for-byte raw event. Raw XML, EVTX, provider JSON,
and live exports remain outside this fixture contract and committed fixture set.

Sanitization must preserve the semantic relationships needed by the case:

- the provider is Sysmon;
- the provider event type is process creation;
- parent and child process context remain internally consistent;
- identifiers remain distinct and stable within the fixture set; and
- the command line contains only the inert behavior needed by that case.

### 3.2 Provider-Like Source Fixture Versus Parsed Event

The provider-like source fixture models selected Sysmon System and EventData
values using reviewed source names such as `EventRecordID`, `ProcessGuid`,
`ProcessId`, `Image`, and `CommandLine`. Its values remain source-shaped; for
example, source process IDs may still be strings. The fixture does not contain
parser conclusions, canonical fields, or detection labels.

The source-specific parsed event is the output of the Sysmon source parser. It
uses the parsed field vocabulary from the Windows telemetry contract,
including `provider_event_id`, `event_record_id`, `process_guid`,
`process_id`, `image`, and `command_line`. Type conversion, source sentinel
handling, and provider validation happen at this boundary.

Each `expected_parsed` artifact is stored separately from its provider-like
source fixture. Parser expectations are not embedded in the source record.

### 3.3 Parsed Event Versus `normalized_endpoint_event`

The parsed event retains Sysmon-specific meaning. The mapper then projects that
event into the existing `normalized_endpoint_event` contract. Mapping derives
canonical names such as `event_type`, `process_name`, `exe`, and `pid` while
retaining selected Sysmon context under `source_fields`.

An `expected_normalized` definition must be separate from both the source
fixture and `expected_parsed`. Normalization is telemetry shaping only; it must
not add `malicious`, severity, verdict, confidence, or response fields.

### 3.4 Source Observation Versus Detection Expectation

Sysmon Event ID 1 states that process creation was observed. It does not state
that execution was malicious, successful in a broader attacker objective, or
worthy of containment.

An `expected_detection` definition may describe deterministic observable
features expected from a normalized event. It is a reviewed test oracle for
the detector under test, not source evidence, a runtime canonical detection
result, or a fixture label. Detection
expectations must therefore be stored separately and must not be copied into
the source fixture, parsed event, or normalized event.

### 3.5 Identifier Boundaries

The identifiers have different authorities and must never substitute for one
another:

| Identifier | Authority and meaning | Allowed use |
|---|---|---|
| `provider_event_id` | Sysmon provider event type; exactly integer `1` for this contract | Validate and route a process-creation source event |
| `event_record_id` | Sanitized representation of Windows Event Log record identity when present | Source provenance and preferred canonical identity input |
| `ProcessGuid` / `process_guid` | Sysmon process identity, synthetic in fixtures | Source-specific process correlation and fallback canonical identity input |
| `fixture_id` | Repository test-case identity such as `sysmon-event1-ordinary-powershell-001` | Locate and relate a fixture to separate expectations |
| canonical `event_id` | Lab-generated deterministic normalized event identifier | Identify one normalized event within the canonical artifact |
| future Wazuh document ID | Retrieval-backend record identity | Retrieval provenance only |

`fixture_id` is not an `event_record_id`. It must not be written into
`event_record_id` to compensate for missing source identity. Conversely,
`event_record_id` does not select a fixture case.

Source `system.provider_event_id` maps to parsed `provider_event_id`, which
remains integer `1` and represents the provider event type. The parsed event
does not contain canonical `event_id`; the mapper generates it
with identity version `sysmon-event1-event-id.v1` from:

```text
provider_name
computer casefolded for identity only
channel
event_record_id
```

The sorted compact canonical JSON is SHA-256 hashed, and the full digest is
prefixed with `sysmon-event1:v1:`. `process_guid` remains provenance and
`fixture_id` remains only in `raw_ref`; neither is an identity input in this
slice. Fallback and fixture-only identity are outside this contract.

## 4. Provider-Like Source Fixture Contract

### 4.1 Fixed Top-Level Envelope

Every provider-like source fixture must use this top-level envelope:

```json
{
  "fixture_contract_version": "1.0",
  "fixture_id": "sysmon-event1-ordinary-powershell-001",
  "source_format": "sysmon_eventlog_json",
  "system": {},
  "event_data": {}
}
```

The top-level names, nesting, `fixture_contract_version`, and `source_format`
value are fixed by this contract. The source fixture schema,
[`sysmon_event1_source_fixture.schema.json`](../../../schemas/sysmon_event1_source_fixture.schema.json),
enforces this envelope and its machine-readable constraints. A breaking change
requires a separately reviewed contract version. Parser expectations,
normalized fields, and detection expectations do not belong in this envelope.

### 4.2 `system` Field Contract

The provider-like `system` object covers these keys:

```text
provider_name
provider_guid
provider_event_id
event_version
event_level
event_task
event_opcode
event_keywords
system_time
event_record_id
channel
computer
```

MVP minimum required fields are:

- `provider_name`;
- `provider_event_id`;
- `system_time`;
- `event_record_id`;
- `channel`; and
- `computer`.

The provider-routing values are exact:

```text
provider_name = Microsoft-Windows-Sysmon
provider_event_id = 1
channel = Microsoft-Windows-Sysmon/Operational
```

The other System fields are optional source context. Absence of only
`provider_guid`, `event_version`, `event_level`, `event_task`, `event_opcode`,
or `event_keywords` must not make an otherwise valid MVP record invalid.

### 4.3 `event_data` Field Contract

The provider-like `event_data` object covers these source keys:

```text
RuleName
UtcTime
ProcessGuid
ProcessId
Image
FileVersion
Description
Product
Company
OriginalFileName
CommandLine
CurrentDirectory
User
LogonGuid
LogonId
TerminalSessionId
IntegrityLevel
Hashes
ParentProcessGuid
ParentProcessId
ParentImage
ParentCommandLine
ParentUser
```

MVP minimum required fields are:

- `UtcTime`;
- `ProcessGuid`;
- `ProcessId`;
- `Image`;
- `CommandLine`;
- `User`;
- `ParentProcessId`; and
- `ParentImage`.

The first-fixture quality target additionally includes:

- `ParentProcessGuid`;
- `ParentCommandLine`;
- `ParentUser`;
- `IntegrityLevel`; and
- `Hashes`.

Minimum required fields determine whether the first parser path has enough
source evidence for the contracted process observation. Quality-target fields
improve parity and provenance, but absence of only a quality-target field must
not automatically reject the whole record. The parser omits the corresponding
optional output field when that source context is absent.

`system.system_time` and `event_data.UtcTime` are distinct source fields and the
fixture must be able to represent both. The mapper uses parsed `utc_time` as
canonical `timestamp`, retains both values, and records exact equality without
tolerance or delta logic. The parser must not silently collapse or overwrite
one with the other.

### 4.4 Source Fidelity And Parser Responsibilities

The provider-like fixture preserves these source-shaped representations:

- `ProcessId` and `ParentProcessId` are integer-like JSON strings;
- `UtcTime` is a Sysmon EventData-form UTC string;
- `LogonId` is a hexadecimal string; and
- `Hashes` is a source string containing `algorithm=value` entries.

The source parser owns PID/PPID integer conversion, timestamp conversion, and
hash algorithm splitting. The fixture must not pre-convert these fields merely
to resemble canonical output. Unsupported or malformed values produce an
explicit `SysmonEvent1ParseError` outcome.

### 4.5 Field-Specific Sentinel Handling

The source values `"-"`, `"N/A"`, and `""` may be normalized to missing only
under a field-, provider-, and Event ID-specific sentinel rule. There is no
global rule that treats `-` or another token as missing in every field.

For example, a provider-like fixture may preserve:

```text
RuleName: "-"
```

The corresponding `expected_parsed` value may omit `rule_name` because the
reviewed Sysmon Event ID 1 rule defines `-` as a sentinel for that field. The
same token in an unrelated field must remain source text unless that field's
contract explicitly defines it as a sentinel.

### 4.6 Synthetic Values

The first fixture set uses a synthetic hostname such as `WIN-FIXTURE01` and a
synthetic account such as `LAB\\fixture-user`. GUID fields must contain
syntactically valid synthetic GUIDs, for example:

```text
ProcessGuid:       {11111111-1111-1111-1111-111111111111}
ParentProcessGuid: {22222222-2222-2222-2222-222222222222}
LogonGuid:         {33333333-3333-3333-3333-333333333333}
```

Each fixture uses stable GUID values that do not unintentionally overlap with
another fixture. `Hashes` values must also be synthetic and must not be copied
from a runtime host. Fixtures must not include a runtime IP address, real user
identity, credential, token, secret, reachable URL, or live environment path.

The fixture must not grow into an unrestricted copy of a raw event.

## 5. Source-Specific Parsed Event Contract

For each valid source fixture, `expected_parsed` describes the parser output
with these target values. Values derived from optional or quality-target source
fields are present only when their source field is present:

| Parsed field | Expected rule |
|---|---|
| `provider_name` | Identifies the reviewed Sysmon provider |
| `provider_event_id` | Integer `1` mapped from source `system.provider_event_id`; not a canonical event identity |
| `event_record_id` | Preserves the sanitized source record identity |
| `computer` | Preserves the synthetic source hostname |
| `channel` | Preserves the source channel |
| `system_time` | Timezone-aware timestamp |
| `utc_time` | Timezone-aware value parsed independently from source `UtcTime` |
| `process_guid` | Preserves the source `ProcessGuid` value |
| `process_id` | Integer parsed from `ProcessId` |
| `image` | Preserves the Windows image path |
| `command_line` | Preserves inert source text as untrusted text |
| `current_directory` | Preserves the Windows path |
| `user` | Preserves the synthetic Windows account form |
| `parent_process_id` | Integer parsed from `ParentProcessId` |
| `parent_process_guid` | Preserves the source `ParentProcessGuid` when present |
| `parent_image` | Preserves the parent image path |
| `parent_command_line` | Preserves untrusted text when present |
| `parent_user` | Preserves the source `ParentUser` when present |
| `integrity_level` | Preserves the reviewed source value when present |
| `hashes` | Splits supported source `Hashes` entries by algorithm when present |

The parser emits `hashes` as an object with uppercase algorithm keys and source
values. The parsed-event schema enforces this machine-readable shape without an
algorithm whitelist or fixed hash length.

Provider validation occurs before this output is accepted. A source record with
the wrong provider or a `provider_event_id` other than `1` is not a valid
Sysmon Event ID 1 parsed event, and the source parser rejects it.

Missing fields are not fabricated as empty strings, zero, `unknown`, or source
sentinels. A type conversion failure is an explicit parser outcome, not a
silently coerced value.

`system_time` and `utc_time` remain independently traceable through parsing.
The parser does not decide which value becomes canonical. The mapper applies
the explicit `utc_time` precedence and accepts unequal schema-valid timestamps.

## 6. Normalized Mapping Expectations

For each valid `expected_parsed` event, the mapper returns one
event conforming to the tracked
[`endpoint_events.schema.json`](../../../schemas/endpoint_events.schema.json).
Its exact policy is defined in the
[`Sysmon Event ID 1 Normalized Mapper Contract`](sysmon_event1_normalized_mapper_contract.md).
Fixture A/B/C static `expected_normalized` artifacts fix exact parity for both
expected-parsed-to-mapper and source-to-parser-to-mapper paths. Tests wrap each
event object in the minimal endpoint envelope for schema validation.
The mapping expectations are:

| Parsed input | Normalized field | Expected rule |
|---|---|---|
| versioned identity inputs | `event_id` | Generate a deterministic lab identifier distinct from all source IDs |
| Sysmon source semantics | `source` | Constant `sysmon`, including when retrieval is later performed through Wazuh |
| Event ID 1 platform | `platform` | Constant `windows` |
| `computer` | `host` | Preserve the source value |
| `utc_time` | `timestamp` | Preserve the Sysmon EventData process-observation timestamp |
| Event ID 1 meaning | `event_type` | Constant `process_exec` |
| `user` | `user` | Preserve Windows account form |
| `process_id` | `pid` | Emit parsed integer |
| `parent_process_id` | `ppid` | Emit parsed integer |
| basename of `image` | `process_name` | Derive using Windows path semantics |
| `image` | `exe` | Preserve the Windows path |
| `command_line` | `command_line` | Preserve as untrusted text |
| `current_directory` | `cwd` | Preserve the Windows path |
| basename of `parent_image` | `parent_process_name` | Derive using Windows path semantics |
| `parent_image` | `parent_exe` | Preserve the Windows path |
| `parent_command_line` | `parent_command_line` | Preserve when present |
| fixture source/reference | `raw_ref` | Point to sanitized source evidence; do not imply raw/live evidence |
| selected Sysmon context | `source_fields` | Retain `provider_name`, `provider_event_id`, `event_record_id`, `process_guid`, and `channel` |

The normalized event must not retain `fixture_id` as though it were provider
identity. If retained for test traceability, it belongs in fixture expectation
metadata or a clearly named fixture-only provenance value, not
`event_record_id` or canonical `event_id`.

## 7. Fixture Case Expectations

All paths, identifiers, hosts, users, times, and commands below are sanitized
values that describe semantic parity. The committed JSON artifacts and schemas
remain authoritative for the exact machine-readable format.

### 7.1 `ordinary_powershell`

Provider-like source observation:

```text
fixture_id: sysmon-event1-ordinary-powershell-001
fixture_contract_version: "1.0"
source_format: sysmon_eventlog_json
system.provider_name: Microsoft-Windows-Sysmon
system.provider_event_id: 1
system.channel: Microsoft-Windows-Sysmon/Operational
system.event_record_id: 41001
system.computer: WIN-FIXTURE01
system.system_time: 2026-01-15T01:02:03.123000Z
event_data.RuleName: "-"
event_data.UtcTime: 2026-01-15 01:02:03.123
event_data.ProcessGuid: {11111111-1111-1111-1111-111111111111}
event_data.ParentProcessGuid: {11111111-1111-1111-1111-111111111112}
event_data.LogonGuid: {11111111-1111-1111-1111-111111111113}
event_data.ProcessId: "4100"
event_data.Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
event_data.CommandLine: powershell.exe -NoProfile -Command "Write-Output fixture-ok"
event_data.CurrentDirectory: C:\LabFixture\
event_data.User: LAB\fixture-user
event_data.IntegrityLevel: Medium
event_data.ParentProcessId: "4000"
event_data.ParentImage: C:\Windows\System32\cmd.exe
event_data.ParentCommandLine: cmd.exe
event_data.ParentUser: LAB\fixture-user
event_data.Hashes: SHA256=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

`expected_parsed`:

- `provider_event_id` is integer `1` mapped from source
  `system.provider_event_id`; canonical `event_id` is absent;
- `event_record_id` and `process_guid` preserve their distinct source values;
- `image`, `command_line`, and parent context preserve the sanitized source
  observation; and
- no detection feature or assessment field is added.

`expected_normalized`:

- `source: sysmon`, `platform: windows`, and `event_type: process_exec`;
- `process_name: powershell.exe` and the corresponding Windows `exe` path;
- parsed `pid` and `ppid`, preserved command line, parent fields, and user;
- a generated canonical `event_id` distinct from `provider_event_id`,
  `event_record_id`, `ProcessGuid`, and `fixture_id`; and
- compact Sysmon provenance in `source_fields`.

`expected_detection`:

- `powershell_process_observed`: present;
- `encoded_command_observed`: absent; and
- no malicious verdict, severity, confidence, or response implication.

### 7.2 `encoded_flag`

Provider-like source observation:

```text
fixture_id: sysmon-event1-encoded-flag-001
fixture_contract_version: "1.0"
source_format: sysmon_eventlog_json
system.provider_name: Microsoft-Windows-Sysmon
system.provider_event_id: 1
system.channel: Microsoft-Windows-Sysmon/Operational
system.event_record_id: 41002
system.computer: WIN-FIXTURE01
system.system_time: 2026-01-15T01:03:03.123000Z
event_data.UtcTime: 2026-01-15 01:03:03.123
event_data.ProcessGuid: {22222222-2222-2222-2222-222222222221}
event_data.ParentProcessGuid: {22222222-2222-2222-2222-222222222222}
event_data.LogonGuid: {22222222-2222-2222-2222-222222222223}
event_data.ProcessId: "4200"
event_data.Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
event_data.CommandLine: powershell.exe -NoProfile -EncodedCommand SAFE_PLACEHOLDER
event_data.CurrentDirectory: C:\LabFixture\
event_data.User: LAB\fixture-user
event_data.IntegrityLevel: Medium
event_data.ParentProcessId: "4000"
event_data.ParentImage: C:\Windows\System32\cmd.exe
event_data.ParentCommandLine: cmd.exe
event_data.ParentUser: LAB\fixture-user
event_data.Hashes: SHA256=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
```

`SAFE_PLACEHOLDER` is intentionally not an operational encoded payload. The
case validates deterministic preservation and observation of an
encoded-command-like flag as untrusted telemetry, not decoding, execution,
attacker success, or maliciousness.

`expected_parsed`:

- the same provider, identity, type, and preservation rules as
  `ordinary_powershell`; and
- the inert `CommandLine` remains untrusted source text without execution or
  decoding.

`expected_normalized`:

- the same process mapping boundary as `ordinary_powershell`;
- a case-specific canonical `event_id` generated from this record's identity
  inputs; and
- no detection expectation embedded in the normalized event.

`expected_detection`:

- `powershell_process_observed`: present;
- `encoded_command_observed`: present; and
- the feature remains an observation requiring downstream assessment, not a
  malicious verdict.

### 7.3 `ordinary_notepad`

Provider-like source observation:

```text
fixture_id: sysmon-event1-ordinary-notepad-001
fixture_contract_version: "1.0"
source_format: sysmon_eventlog_json
system.provider_name: Microsoft-Windows-Sysmon
system.provider_event_id: 1
system.channel: Microsoft-Windows-Sysmon/Operational
system.event_record_id: 41003
system.computer: WIN-FIXTURE01
system.system_time: 2026-01-15T01:04:03.123000Z
event_data.UtcTime: 2026-01-15 01:04:03.123
event_data.ProcessGuid: {33333333-3333-3333-3333-333333333331}
event_data.ParentProcessGuid: {33333333-3333-3333-3333-333333333332}
event_data.LogonGuid: {33333333-3333-3333-3333-333333333333}
event_data.ProcessId: "4300"
event_data.Image: C:\Windows\System32\notepad.exe
event_data.CommandLine: notepad.exe C:\LabFixture\readme.txt
event_data.CurrentDirectory: C:\LabFixture\
event_data.User: LAB\fixture-user
event_data.IntegrityLevel: Medium
event_data.ParentProcessId: "3900"
event_data.ParentImage: C:\Windows\explorer.exe
event_data.ParentCommandLine: explorer.exe
event_data.ParentUser: LAB\fixture-user
event_data.Hashes: SHA256=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

`expected_parsed`:

- valid Sysmon Event ID 1 parsing with distinct provider, record, process, and
  fixture identifiers; and
- the notepad image, command line, and parent context preserved without a
  PowerShell classification.

`expected_normalized`:

- `source: sysmon`, `platform: windows`, and `event_type: process_exec`;
- `process_name: notepad.exe` with the corresponding `exe` path;
- a distinct generated canonical `event_id`; and
- no PowerShell-specific or assessment fields.

`expected_detection`:

- `powershell_process_observed`: absent;
- `encoded_command_observed`: absent; and
- no positive PowerShell-specific detection result.

## 8. Separation Of Artifacts

The following concerns remain logically separate even if a test
loader later packages references in one manifest:

```text
provider-like source fixture
  fixture_id + sanitized Sysmon-shaped evidence only

expected_parsed
  parser output and parser acceptance only

expected_normalized
  mapper output conforming to endpoint_events.schema.json only

expected_detection
  deterministic observable-feature expectations only
```

The source fixture must not contain expected fields, behavior labels, a
malicious flag, severity, confidence, verdict, or response recommendation.
Expected outputs must refer back to the case by `fixture_id` without rewriting
that ID as Windows source identity.

The source fixture and parsed-event schemas define machine-readable constraints
for their separate shapes. Expected normalized artifacts are validated through
the existing `endpoint_events.schema.json` envelope. Expected detection
artifacts are validated through
`sysmon_event1_expected_detection.schema.json`. The latter is a reviewed test
oracle and is not the runtime canonical detection output itself.

### 8.1 Grouped File Layout

This contract uses the following grouped layout:

```text
tests/fixtures/windows/sysmon_event1/
├── source/
│   ├── sysmon-event1-ordinary-powershell-001.json
│   ├── sysmon-event1-encoded-flag-001.json
│   └── sysmon-event1-ordinary-notepad-001.json
├── expected_parsed/
│   ├── sysmon-event1-ordinary-powershell-001.json
│   ├── sysmon-event1-encoded-flag-001.json
│   └── sysmon-event1-ordinary-notepad-001.json
├── expected_normalized/
│   ├── sysmon-event1-ordinary-powershell-001.json
│   ├── sysmon-event1-encoded-flag-001.json
│   └── sysmon-event1-ordinary-notepad-001.json
└── expected_detection/
    ├── sysmon-event1-ordinary-powershell-001.json
    ├── sysmon-event1-encoded-flag-001.json
    └── sysmon-event1-ordinary-notepad-001.json
```

This layout makes the source/parsed/normalized/detection boundaries visible and
lets each expectation refer to the same stable `fixture_id`. Tests compare the
detector summary with the static golden artifacts and do not generate or
overwrite them.

## 9. Runtime Evidence Boundary

The bounded native observation recorded in the
[native parity runbook](../../runbooks/windows/sysmon_event1_native_parity.md)
confirms that Sysmon Event ID 1 source records can cross the documented source
shape, parser, and parsed-schema boundaries under the recorded lab conditions.
It is runtime evidence, not a committed fixture or a claim of continuous
collection, live normalized parity, downstream analytical quality, or
end-to-end Windows telemetry ingestion.

Native observation and repository fixture evidence remain separate. A manual
run must not be used by itself to claim automated VM provisioning, deterministic
detection coverage, Wazuh retrieval, or any later pipeline stage.

Runtime inventory details belong in architecture documentation. They must not
be copied into sanitized fixture values or expected outputs.

## 10. Sysmon Semantics And Future Wazuh Retrieval

Sysmon remains the semantic source for Event ID 1 regardless of acquisition
path. A future Wazuh integration may retrieve an indexed representation, but
Wazuh retrieval metadata is a separate envelope:

```text
future Wazuh document / query metadata
  -> Windows/Sysmon representation adapter
  -> the same source-specific parsed event boundary
  -> the same normalized mapping boundary
```

A Wazuh document ID is not `event_record_id`, `ProcessGuid`, `fixture_id`, or
canonical `event_id`. Wazuh rule output is not raw Sysmon evidence, and a Wazuh
alert conclusion must not be presented as a process-creation source event when
the underlying provider fields are unavailable.

The normalized `source` remains `sysmon` when the normalized semantics come
from recoverable Sysmon provider data. Wazuh query scope, retrieval provenance,
and backend identity remain separate metadata governed by the provider-neutral
SIEM query contract. Wazuh Windows integration is outside this fixture
contract. Its status belongs in the Main Roadmap.

## 11. Sanitization And Safety Requirements

- Use only synthetic hostnames, users, record IDs, syntactically valid synthetic
  GUIDs, and deterministic timestamps.
- Do not include runtime inventory addresses or other environment-private
  identifiers.
- Do not include real credentials, tokens, secrets, hashes of sensitive data,
  reachable external destinations, or user documents.
- Do not include a functional encoded payload. `encoded_flag` uses an inert
  placeholder solely to exercise flag recognition.
- Do not execute or decode any fixture command text.
- Treat all command lines, paths, and source text as untrusted input.
- Do not infer host compromise, attack success, or benignness from one Event
  ID 1 record.
- Do not commit raw XML, EVTX, provider JSON, live Wazuh output, or generated
  runtime artifacts as part of this design slice.

## 12. Fixture-Parity Acceptance Evidence

The focused source, parser, mapper, and detector fixture-parity slices
collectively provide:

1. source fixture schema validation for the fixed envelope;
2. exact `fixture_contract_version` validation;
3. all three sanitized source fixtures;
4. exact `provider_name == Microsoft-Windows-Sysmon` validation;
5. exact `provider_event_id == 1` validation;
6. exact `channel == Microsoft-Windows-Sysmon/Operational` validation;
7. independent `system_time` / `UtcTime` conversion and documented consistency
   handling;
8. `ProcessId` / `ParentProcessId` integer conversion;
9. Windows path preservation and Windows basename extraction;
10. field-specific sentinel normalization, including a negative check against a
    global `-` rule;
11. `Hashes` algorithm parsing from synthetic source strings;
12. separately asserted `expected_parsed` outputs;
13. a mapper whose outputs pass canonical `endpoint_events.schema.json`
    validation;
14. stable, versioned canonical `event_id` generation;
15. fixture/source/canonical identity separation checks;
16. separately asserted `expected_normalized` outputs;
17. deterministic observation logic with separate `expected_detection` results;
18. expected positive behavior for the two PowerShell cases and negative
    PowerShell-specific behavior for the notepad case;
19. negative checks for source/expectation leakage;
20. confirmation that no real identifier, secret, or runtime inventory value
    appears in source fixtures or expected outputs; and
21. a test boundary guaranteeing that fixture command strings are never
    executed or decoded.

Bounded native live source-shape and parser parity was observed as the
pre-mapper validation step and is recorded in the dedicated runbook. Raw or
live runtime evidence is not committed.

## 13. Status And Planning References

The [Main Roadmap](../../roadmap/roadmap.md) is the source of truth for
downstream Windows work, Common Defender Pipeline completion, live integration,
and Wazuh sequencing. This contract intentionally carries no independent
Completed, Next, or Later implementation list.

Changes to the fixture set or its schemas still require focused review and must
preserve artifact separation, identity, safety, runtime-evidence, and retrieval
boundaries.

## 14. Non-Goals

This fixture contract does not:

- add live Windows detection-to-Incident execution;
- add Windows-specific Incident builders or schemas;
- add generated runtime data;
- add raw XML, EVTX, provider JSON, or Wazuh records;
- configure Sysmon, Windows, Wazuh, or a VM;
- define a maliciousness verdict or incident policy;
- claim repository automation from manual runtime validation; or
- make future Wazuh retrieval authoritative for Sysmon semantics.
