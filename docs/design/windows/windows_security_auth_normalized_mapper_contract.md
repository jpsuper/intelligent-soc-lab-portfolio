# Windows Security Authentication Normalized Mapper Contract

Evidence scope: deterministic parsed-to-normalized parity for the two sanitized
Windows Security Event ID 4624/4625 fixtures. See the
[Main Roadmap](../../roadmap/roadmap.md) for overall Windows and common-pipeline
status.

## 1. Purpose And Boundary

The mapper converts one validated source-specific authentication event into the
existing canonical endpoint vocabulary:

```text
source-specific Windows Security parsed event
  -> parsed-event schema validation
  -> Windows Security authentication mapper
  -> endpoint_events.v1 validation
  -> normalized authentication event
```

The mapper assigns the already-supported `auth_success` or `auth_failure`
event type and preserves reviewed provenance. It does not decide whether an
authentication was authorized, malicious, successful for an attacker, or
evidence of compromised credentials.

The separately reviewed
[deterministic detection contract](windows_security_auth_detection_contract.md)
uses `auth_failure` only as an observation rule and keeps `auth_success` as a
no-match control. That result is not evidence produced by this mapper.

The input authority is
[`windows_security_auth_parsed_event.schema.json`](../../../schemas/windows_security_auth_parsed_event.schema.json).
The output authority is
[`endpoint_events.schema.json`](../../../schemas/endpoint_events.schema.json).
This slice does not add a Windows-only canonical schema.

## 2. Public API

```python
def map_windows_security_auth_to_endpoint_event(
    parsed_event: dict[str, object],
    *,
    source_artifact: str,
) -> dict[str, object]:
    ...
```

The mapper is deterministic and does not mutate its input. It has no network,
subprocess, file-write, environment, clock, decoding, credential-validation, or
command-execution behavior. Schema files are read from the repository only for
validation.

Failures raise `WindowsSecurityAuthMappingError` with a stable field path.
Source values and exception details are not copied into error messages.

## 3. Mapping Policy

| Parsed value | Canonical field | Policy |
|---|---|---|
| approved identity input set | `event_id` | Generate a versioned deterministic lab ID |
| constant `windows_security` | `source` | Preserve the original Windows Security telemetry family; retrieval through Wazuh would not change it |
| constant `windows` | `platform` | This is Windows endpoint telemetry |
| `computer` | `host` | Preserve original case |
| `system_time` | `timestamp` | Use the parsed Windows Event Log System/TimeCreated value |
| Event ID 4624 | `event_type: auth_success` | Provider success semantics only; not an authorization or benign verdict |
| Event ID 4625 | `event_type: auth_failure` | Provider failure semantics only; not proof of invalid credentials or malicious intent |
| `target_domain_name` + `target_user_name` | `user` | Join exactly as `DOMAIN\user` without replacing either source identity |
| `source_ip` | `src_ip` | Preserve only when present |
| `source_port` | `src_port` | Preserve the parsed integer only when present |
| source locator + `fixture_id` | `raw_ref` | Reference fixture evidence without embedding it |
| reviewed provider context | `source_fields` | Preserve compact allowlisted provenance |

The mapper does not populate `collection_timestamp`, process fields, destination
network fields, a verdict, severity, confidence, or an Incident field. Missing
optional network evidence is omitted; it is not replaced with localhost, zero,
an empty string, `unknown`, or another placeholder.

## 4. Canonical Event Identity

Canonical `event_id` is a lab-generated identifier, not a Windows Event Log,
Wazuh, fixture, account, or logon-session identifier. Version 1 uses exactly:

```text
identity_version
provider_name
computer casefolded for identity only
channel
event_record_id
```

The object is serialized as sorted compact JSON with UTF-8, hashed with
SHA-256, and emitted as `windows-security-auth:v1:` plus the full lowercase
digest.

```text
method: sha256-json-canonical-v1
identity version: windows-security-auth-event-id.v1
```

Original computer case remains in `host`. Fixture ID, source-artifact path,
provider event type, account, address, status, and timestamp are not identity
inputs. The Windows `event_record_id` remains separately traceable under
`source_fields`; no fallback identity is defined by this slice.

## 5. Provenance And Failure Evidence

`source_fields` retains the provider route, record ID, System timestamp,
subject and target identifiers, Logon Type, logon process, authentication
package, mapper/version metadata, and reviewed optional provider fields.

For Event ID 4624, `target_logon_id` remains provider provenance. For Event ID
4625, `failure_reason`, `status`, and `sub_status` remain their source tokens.
The mapper does not translate `%%2313`, decode NTSTATUS values, assert a root
cause, or turn those fields into a detection verdict.

The subject account and target account remain distinct. Canonical `user`
represents the target account involved in the authentication observation;
subject identity remains in `source_fields`. This does not establish that the
target account owns the source address or that the subject initiated the
activity.

## 6. Exact Expected-Normalized Parity

The static expectations remain separate from their parsed inputs:

```text
expected_parsed/windows-security-4624-network-logon-success-001.json
  -> mapper
  -> expected_normalized/windows-security-4624-network-logon-success-001.json

expected_parsed/windows-security-4625-network-logon-failure-001.json
  -> mapper
  -> expected_normalized/windows-security-4625-network-logon-failure-001.json
```

Tests require exact object equality, endpoint-schema validity, deterministic
identity, explicit route-to-event-type mapping, optional network omission,
event-specific provenance, input immutability, and safe failures.

## 7. Done Criteria

This mapper boundary is complete when:

- parsed and expected-normalized inventories match exactly;
- both expected events validate inside an `endpoint_events.v1` envelope;
- both parsed fixtures map to their exact static expected events;
- Event IDs 4624/4625 map only to `auth_success`/`auth_failure` respectively;
- target-account, timestamp, host, and optional network policies are explicit;
- canonical event identity is deterministic, versioned, casefolded only for
  host identity, and independent of fixture provenance;
- provider failure fields remain uninterpreted source evidence;
- invalid input, route, types, source references, and output fail closed;
- the mapper does not mutate or disclose source values; and
- formatter, lint, focused tests, full tests, and whitespace checks pass.

## 8. Does Not Establish

This mapper contract by itself does not establish:

- the separately reviewed atomic detection parity as mapper evidence;
- correlation, Incident, Triage, or Investigation;
- that a 4624 event is authorized or benign;
- that a 4625 event proves invalid credentials, malicious intent, or compromise;
- account ownership of an address or workstation;
- Wazuh conversion, query, alert coverage, or live transport support;
- native Windows collection or source/parser/mapper parity;
- Active Directory or Domain Controller coverage; or
- live cross-platform pipeline execution.

## 9. Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest \
  tests/windows/security_auth/test_map_windows_security_auth_to_endpoint_event.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
```
