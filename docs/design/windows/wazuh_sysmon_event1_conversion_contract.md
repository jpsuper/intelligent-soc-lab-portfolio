# Wazuh Sysmon Event ID 1 Bounded Conversion Contract

Evidence scope: sanitized `wazuh-alerts-*` hit-projection conversion parity for
the existing Sysmon Event ID 1 Fixture A/B/C set. Overall status and sequencing
remain owned by the [Main Roadmap](../../roadmap/roadmap.md).

## 1. Purpose

This slice validates one representation adapter in front of the existing
Sysmon Event ID 1 source parser and normalized endpoint mapper:

```text
sanitized Wazuh Indexer alert-hit projection
  -> Wazuh representation adapter
  -> existing sysmon_eventlog_json source contract
  -> existing Sysmon Event ID 1 parser
  -> existing Sysmon Event ID 1 normalized mapper
  -> endpoint_events.v1 event
```

The adapter resolves Wazuh retrieval nesting and string typing only. Windows
provider semantics remain owned by the existing source parser, and canonical
endpoint semantics remain owned by the existing mapper.

## 2. Included Scope

The bounded implementation includes:

- one strict JSON Schema for a sanitized Wazuh Indexer alert-hit projection;
- fixed alert-plane retrieval metadata: index, backend document ID, query
  reference, query window, retrieval time, agent identity, and manager name;
- allowlisted `data.win.system` and `data.win.eventdata` fields;
- conversion of Wazuh string-encoded System integers into the existing
  provider-like source types;
- separate retrieval provenance and source-event outputs;
- exact source-event parity for Fixture A/B/C; and
- normalized semantic and deterministic event-identity parity between the
  direct fixture path and the Wazuh projection path.

The committed projections are synthetic, sanitized, and deterministic. They
are not raw runtime exports.

## 3. Explicit Non-Goals

This slice does not implement or validate:

- a live Wazuh API or Indexer connection;
- credentials, TLS, authorization, retries, timeouts, pagination, or
  `search_after` behavior;
- source-registry translation or a reusable SIEM query client;
- `wazuh-archives-*`, unalerted raw events, or alert/archive parity;
- Wazuh rule quality, alert level, verdict, risk, or native detection parity;
- continuous collection, live Windows parity, or runtime artifact retention;
- additional Windows Event IDs; or
- any Incident, Triage, Investigation, Case, Action, or scoring change.

Because the fixed input is from `wazuh-alerts-*`, the evidence applies only to
the alert plane. Absence of a hit does not prove absence of collection or
source activity.

## 4. Input Projection

Each fixture uses
`source_format = wazuh_indexer_alert_hit_projection` and contains:

```text
fixture_contract_version
fixture_id
source_format
retrieval
  query_ref
  retrieved_at
  query_window.start
  query_window.end
hit
  _index
  _id
  _source.timestamp
  _source.agent
  _source.manager
  _source.data.win.system
  _source.data.win.eventdata
```

The projection is a reviewed allowlist, not an unrestricted Wazuh document.
Unexpected fields fail closed so Wazuh rule conclusions, raw payloads, and
unreviewed product fields cannot cross this fixture boundary silently.

The declared query window must be forward-moving, and the projected alert
timestamp must be inside it. This validates fixture mechanics only; it does
not establish operational query enforcement.

## 5. Source Conversion

The adapter converts Wazuh field names to the already-reviewed provider-like
source names. Representative mappings are:

| Wazuh projection | Existing source contract | Rule |
|---|---|---|
| `providerName` | `provider_name` | copied; parser validates exact provider |
| `eventID` | `provider_event_id` | strict ASCII decimal conversion; parser requires `1` |
| `eventRecordID` | `event_record_id` | strict ASCII decimal conversion; required |
| `systemTime` | `system_time` | copied; parser validates and normalizes |
| `utcTime` | `UtcTime` | copied independently from `systemTime` |
| `processId` | `ProcessId` | source string retained for the parser |
| `parentProcessId` | `ParentProcessId` | source string retained for the parser |

All reviewed EventData names are renamed from lower camel case to the existing
Sysmon source vocabulary without analytical interpretation.

Provider, Event ID, and channel routing are intentionally validated by the
existing source parser after adaptation. The adapter must not duplicate or
replace that source-specific authority.

## 6. Identity And Provenance Boundaries

The following identities remain distinct:

| Identifier | Authority | Use in this slice |
|---|---|---|
| Wazuh hit `_id` | retrieval backend | retrieval provenance only |
| Wazuh `_index` | retrieval backend | alert-plane provenance only |
| Windows `eventRecordID` | Windows provider record | required source identity and canonical event-identity input |
| `fixture_id` | repository fixture | fixture inventory and `raw_ref` only |
| canonical `event_id` | lab mapper | deterministic endpoint event identity |

The adapter never substitutes `_id` for a missing Windows `eventRecordID`.
Removing `eventRecordID` must fail even when `_id` looks numeric.

The output has two siblings:

```text
source_event
retrieval_provenance
```

`source_event` exactly matches the existing provider-like Fixture A/B/C
contract. `retrieval_provenance` retains only reviewed retrieval facts and is
not copied into Sysmon System/EventData or canonical endpoint fields. The
normalized event's `raw_ref.source_artifact` points to the Wazuh fixture when
that path is used, keeping the separate provenance reviewable.

## 7. Failure Semantics

The adapter fails closed for:

- a non-object projection;
- missing or unexpected projected fields;
- an index outside `wazuh-alerts-*`;
- malformed timestamps or query-window ordering;
- an alert timestamp outside the declared window;
- missing or non-decimal System integer values;
- missing Windows `eventRecordID`; and
- unreviewed Wazuh fields at the contracted boundary.

The existing Sysmon parser then fails closed for wrong provider, Event ID,
channel, malformed timestamps, invalid process identifiers, and other source
contract violations. Error messages identify a field path without echoing
source values or command text.

## 8. Done Criteria

This bounded slice is done when:

1. all three Wazuh projections validate against the new schema;
2. each projection adapts exactly to its existing Fixture A/B/C source JSON;
3. direct and Wazuh paths produce identical normalized semantics and canonical
   `event_id`, with only the acquisition-specific `raw_ref.source_artifact`
   differing;
4. retrieval provenance remains allowlisted and separate;
5. `_id` cannot replace `eventRecordID`;
6. invalid routing, typing, query bounds, and unexpected fields fail closed;
7. inputs remain unchanged and errors do not disclose source values;
8. existing Sysmon and common-pipeline regressions remain green; and
9. lint, the full test suite, and whitespace validation pass.

## 9. Validation

```bash
uv run pytest tests/windows/sysmon_event1/test_wazuh_sysmon_event1_conversion.py -q
uv run pytest tests/windows/sysmon_event1 -q
uv run pytest tests -q
uv run ruff check .
git diff --check origin/main...HEAD
```

Passing these commands establishes fixed-fixture conversion mechanics and
parity only. It does not satisfy the live Wazuh integration acceptance
conditions in the SIEM query or Wazuh integration contracts.

## 10. References

- [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/index.html)
- [Wazuh Indexer API search use cases](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html)
- [SIEM Query Contract](../siem/siem_query_contract.md)
- [Wazuh Integration Contract](../wazuh_integration_design.md)
- [Windows Telemetry MVP Contract](windows_telemetry_contract.md)
- [Sysmon Event ID 1 Fixture Contract](sysmon_event1_fixture_contract.md)
