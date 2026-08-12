# Windows Security Authentication Parser Contract

Evidence scope: deterministic source-to-parsed parity for the two sanitized
Windows Security Event ID 4624/4625 fixtures. See the
[Main Roadmap](../../roadmap/roadmap.md) for overall Windows and common-pipeline
status.

## 1. Purpose And Boundary

The parser converts the reviewed provider-like source fixture into a
source-specific parsed event:

```text
sanitized Windows Security provider-like fixture
  -> source schema validation
  -> Windows Security authentication parser
  -> parsed-event schema validation
  -> source-specific parsed event
```

The parser interprets source types and sentinels only. The separately reviewed
[normalized mapper](windows_security_auth_normalized_mapper_contract.md)
creates the canonical endpoint event and chooses `auth_success` or
`auth_failure`; that behavior is not evidence produced by this parser. The
parser does not emit a detection or infer whether an account or credential was
compromised.

The input authority is
[`windows_security_auth_source_fixture.schema.json`](../../../schemas/windows_security_auth_source_fixture.schema.json).
The output authority is
[`windows_security_auth_parsed_event.schema.json`](../../../schemas/windows_security_auth_parsed_event.schema.json).

## 2. Public API

```python
def parse_windows_security_auth_source(
    source: Mapping[str, object],
) -> dict[str, object]:
    ...
```

The parser is deterministic and does not mutate its input. It has no network,
subprocess, file-write, environment, clock, decoding, or command-execution
behavior. Schema files are read from the repository only for validation.

Failures raise `WindowsSecurityAuthParseError` with a safe field path. Source
values, usernames, addresses, status text, and exception details are not copied
into the stable error message.

## 3. Route And Type Policy

The accepted route is fixed:

```text
provider_name: Microsoft-Windows-Security-Auditing
provider_event_id: 4624 or 4625
channel: Security
```

The parser applies these conversions:

| Source field | Parsed field | Policy |
|---|---|---|
| `system_time` | `system_time` | Normalize a timezone-aware source timestamp to UTC with six fractional digits |
| `LogonType` | `logon_type` | Convert the decimal source string to a non-negative integer |
| `IpPort` | `source_port` | Convert a non-sentinel decimal source string to an integer from 0 through 65535 |
| `IpAddress` | `source_ip` | Preserve a schema-valid IPv4 or IPv6 string; omit source sentinel `-` |
| subject and target identifiers | snake-case parsed names | Preserve source identity without combining or reinterpreting it |
| hexadecimal logon/status identifiers | snake-case parsed names | Preserve their source string representation |

`event_record_id` is already an integer at the fixture boundary and remains the
Windows Event Log record identity represented by the fixture. It is not a
canonical event ID or backend document ID.

## 4. Sentinel Policy

The source fixture retains `-` where the provider reports unavailable optional
text. The parser omits that sentinel only for:

```text
SubjectUserName
SubjectDomainName
WorkstationName
IpAddress
IpPort
```

It does not replace a sentinel with an empty string, `unknown`, zero, localhost,
or another invented value. Required target-account and authentication fields
must survive parsed-output validation and therefore cannot silently become
missing evidence.

`FailureReason` remains the provider token such as `%%2313`. The parser does not
translate localized text or convert Status/SubStatus into a verdict. The mapper
also retains these values as source provenance without interpreting them.

## 5. Event-Specific Output

Common parsed fields retain provider, record, host, subject, target, logon,
authentication, workstation, and network evidence.

Event-specific output remains exclusive:

- Event ID 4624 requires `target_logon_id` and rejects failure fields.
- Event ID 4625 requires `failure_reason`, `status`, and `sub_status` and rejects
  `target_logon_id`.

This distinction is provider semantics, not detection logic. The parser does
not emit top-level `event_type`, `user`, `src_ip`, or `src_port`; those names and
their provenance policy belong to the separately reviewed normalized mapper.

## 6. Expected Parsed Parity

The two static `expected_parsed` objects are separate from their source
fixtures:

```text
source/windows-security-4624-network-logon-success-001.json
  -> parser
  -> expected_parsed/windows-security-4624-network-logon-success-001.json

source/windows-security-4625-network-logon-failure-001.json
  -> parser
  -> expected_parsed/windows-security-4625-network-logon-failure-001.json
```

Tests require exact object equality, schema validity, matching filenames,
explicit integer conversions, UTC timestamp normalization, sentinel omission,
input immutability, route separation, and safe failures.

## 7. Done Criteria

This parser boundary is complete when:

- the source and expected-parsed inventories match exactly;
- both expected objects validate against the parsed-event schema;
- both source fixtures parse to their exact static expected objects;
- timestamp, Logon Type, and port conversions are deterministic;
- optional provider sentinels are omitted without invented values;
- 4624 and 4625 event-specific fields cannot cross routes;
- invalid routes, types, additional fields, and output shapes fail closed;
- the parser does not mutate or disclose source values; and
- formatter, lint, focused tests, full tests, and whitespace checks pass.

## 8. Does Not Establish

This parser contract by itself does not establish:

- the separately reviewed mapping parity as parser evidence;
- detection, correlation, Incident, Triage, or Investigation;
- Wazuh conversion, query, or live transport support;
- native Windows collection or source/parser parity;
- Active Directory or Domain Controller coverage; or
- account compromise, credential validity, attack success, or user intent.

## 9. Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest \
  tests/windows/security_auth/test_parse_windows_security_auth_source.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
```
