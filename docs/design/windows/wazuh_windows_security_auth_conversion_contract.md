# Wazuh Windows Security Authentication Bounded Conversion Contract

Evidence scope: sanitized `wazuh-alerts-*` hit-projection conversion parity for
the existing Windows Security 4624/4625 authentication fixtures. Overall status
and sequencing remain owned by the [Main Roadmap](../../roadmap/roadmap.md).

## 1. Purpose

This slice validates one representation adapter in front of the existing
Windows Security authentication parser and mapper:

```text
sanitized Wazuh Indexer alert-hit projection
  -> Wazuh representation adapter
  -> existing windows_security_eventlog_json source contract
  -> existing Windows Security parser
  -> existing normalized endpoint mapper
  -> endpoint_events.v1 event
```

The adapter resolves Wazuh retrieval nesting, lower-camel EventData names, and
string-encoded System integers only. Windows provider semantics remain owned by
the existing parser, and canonical endpoint semantics remain owned by the
existing mapper.

## 2. Included Scope

The bounded implementation includes:

- one strict schema for a sanitized Wazuh Indexer alert-hit projection;
- one synthetic 4624 projection and one synthetic 4625 projection;
- allowlisted `data.win.system` and `data.win.eventdata` fields;
- explicit normalization of five Wazuh-omittable provider sentinel fields;
- strict decimal conversion for Wazuh string-encoded System integers;
- separate retrieval provenance and source-event outputs;
- exact parity with the two existing provider-like source fixtures; and
- normalized semantic and deterministic event-identity parity between the
  direct and Wazuh fixture paths.

The committed projections are synthetic and sanitized. They are not runtime
exports and do not contain the lab host, address, credentials, PIT state, or raw
event payload.

## 3. Conversion Boundary

Representative mappings are:

| Wazuh projection | Existing source contract | Rule |
|---|---|---|
| `providerName` | `provider_name` | fixed Security-Auditing provider |
| `eventID` | `provider_event_id` | ASCII decimal; `4624` or `4625` |
| `eventRecordID` | `event_record_id` | required Windows record identity |
| `systemTime` | `system_time` | provider time retained |
| `targetUserName` | `TargetUserName` | copied without identity inference |
| `failureReason` | `FailureReason` | 4625 provider evidence only |

Event-specific fields remain exclusive: 4624 requires `targetLogonId`, while
4625 requires `failureReason`, `status`, and `subStatus`. Unexpected fields fail
closed. The Wazuh hit `_id` never substitutes for Windows `eventRecordID`.

Wazuh may omit EventData fields whose provider value is the unavailable
sentinel `-`. Only `subjectUserName`, `subjectDomainName`,
`workstationName`, `ipAddress`, and `ipPort` may be absent at this
projection boundary. The adapter restores the existing source-contract
sentinel before parsing. Missing target identity, logon, authentication, or
event-specific failure evidence continues to fail closed.

The output contains sibling `source_event` and `retrieval_provenance` objects.
Backend index/document identity remains retrieval provenance and does not enter
the provider source or canonical event identity.

## 4. Done Criteria

This conversion boundary is complete when:

- both projections validate with Draft 2020-12 format checking;
- both adapt exactly to the existing 4624/4625 source fixtures;
- each allowlisted omitted sentinel field restores `-` and is omitted by the
  existing parser without inventing an identity or network value;
- direct and Wazuh paths have normalized parity apart from `raw_ref` location;
- routing, event-specific fields, record identity, query-window, unexpected
  fields, and input immutability fail safely or remain fixed as tested;
- stable errors disclose neither event values nor retrieval values; and
- formatter, lint, focused tests, full tests, and whitespace checks pass.

## 5. Does Not Establish

This boundary does not establish:

- that a live Wazuh 4.14.4 document uses every projected field exactly as
  represented; that remains the next bounded lab check;
- source-registry, query-plan, transport, pagination, or live-smoke behavior;
- `wazuh-archives-*`, raw archive completeness, or unalerted-event coverage;
- continuous collection, alert-rule coverage, detection quality, credential
  validity, account compromise, or attack success;
- whether an omitted Wazuh field was present as a literal `-` in native
  Windows export evidence;
- native Windows export parity, AD/DC coverage, or cross-platform execution.

## 6. Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest \
  tests/windows/security_auth/test_wazuh_windows_security_auth_conversion.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
```
