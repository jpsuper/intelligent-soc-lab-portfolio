# Provider-Neutral SIEM Query Contract

## 1. Purpose

This document defines a provider-neutral contract for bounded, read-only
searches across SIEM and investigation backends. A SIEM is an operational query
plane over multiple log sources. Backend adapters translate the common request
into Wazuh Indexer, Elastic, Splunk, or another supported search mechanism.

The contract keeps four responsibilities distinct:

```text
Evidence source
  Manager-local archives.json.full_log

Operational query source
  Wazuh Indexer API / Elastic / Splunk

Canonical semantic contract
  normalized_endpoint_event

Detection result source
  wazuh-alerts-* / alerts.json
```

Manager-local `archives.json.full_log` can support controlled evidence
validation. It is not fixed as the normal persistent read path for agents or
workflows. An indexed SIEM document is likewise not the lab's canonical event
schema. Search results pass through a source-specific mapper before they can
become `normalized_endpoint_event` artifacts.

Raw-event searches and alert searches have different meanings and remain
separate interfaces even when one backend stores both kinds of document.

## 2. Responsibility Boundaries

### SIEM Query Contract

The query contract records:

- which logical sources were searched;
- the bounded time range used;
- the structured conditions applied;
- the projected and aggregated fields requested; and
- the limit, pagination state, and result-volume status.

It does not interpret backend-specific fields or assign canonical event
semantics.

### Source Mapper Or Parser

The source mapper or parser owns:

- interpretation of backend- and source-specific fields;
- preservation of source provenance;
- parsing of any retained source payload; and
- conversion into `normalized_endpoint_event` when sufficient evidence exists.

### Detection DSL

The detection DSL evaluates normalized events. It does not depend directly on
Wazuh, Elastic, or Splunk field names.

### Correlation

Correlation owns temporal relationships and relationships across multiple
sources. A query filter can narrow retrieval, but it is not a correlation
result.

### Incident Pipeline

The incident pipeline creates incident artifacts from detection results. A
query hit alone is neither a detection nor an incident.

## 3. Query Input Contract

The following JSON is the version `1.0` contract shape. This document does not
by itself create a repository JSON Schema or runtime artifact. The
[Main Roadmap](../../roadmap/roadmap.md) owns current implementation and
validation status.

```json
{
  "contract_version": "1.0",
  "request_id": "query-...",
  "backend": "wazuh_indexer",
  "source_names": ["wazuh-archives"],
  "time_range": {
    "start": "2026-07-13T12:00:00Z",
    "end": "2026-07-13T12:10:00Z"
  },
  "filters": [
    {
      "field": "agent.name",
      "operator": "eq",
      "value": "ubuntu-victim01"
    }
  ],
  "projection_fields": [
    "timestamp",
    "agent.id",
    "agent.name",
    "location",
    "full_log"
  ],
  "aggregation_fields": [],
  "sort": [
    {
      "field": "timestamp",
      "direction": "asc"
    }
  ],
  "limit": 100,
  "cursor": null
}
```

### Input Semantics

- `contract_version` identifies the request and response contract revision.
- `request_id` is caller-generated and supports audit correlation and retries.
- `backend` selects a configured adapter. It must agree with every selected
  source registry entry.
- `source_names` contains logical registry names, not physical index patterns.
- `time_range.start` and `time_range.end` are required timezone-aware ISO 8601
  timestamps.
- The recommended interval is start-inclusive and end-exclusive: `[start, end)`.
- The physical `time_field` is resolved from the source registry. A permitted
  caller override must be validated against the registry field definition.
- `filters` is the standard structured filter interface.
- `projection_fields` limits returned fields. An empty list uses the source's
  configured default projection.
- `aggregation_fields` requests bounded summaries over registry-approved
  fields.
- `sort` must use known, compatible fields and a stable tie-breaker when needed
  for cursor pagination.
- `limit` is positive and capped by policy and source configuration.
- `cursor` is opaque to callers and bound to the original request parameters.

Wildcard searches across all physical indexes are not part of the standard
contract. Pagination uses cursors rather than caller-managed backend offsets.
Backend-native query languages are exposed, if at all, through the separate
interface in Section 11.

## 4. Supported Structured Operators

The MVP structured interface supports these operators:

| Operator | Accepted value | Meaning | Compatibility checks |
|---|---|---|---|
| `eq` | One non-null scalar | Exact equality | Value must match the registered field type |
| `in` | Non-empty array of scalar values of one compatible type | Match any listed value | Every member must be compatible; adapters preserve OR semantics |
| `exists` | Boolean | `true` requires field presence; `false` requires absence | Field must be registered; value must be Boolean |
| `range` | Object containing one or more of `gt`, `gte`, `lt`, `lte` | Conjunctive lower and upper bounds | Allowed for ordered numeric, timestamp, and explicitly ordered keyword fields |
| `contains` | One string | Source field contains the literal string | Allowed only for registered searchable string fields |
| `prefix` | One string | Source field begins with the literal prefix | Allowed only for registered prefix-capable string fields |

Multiple values are accepted only where the operator defines them. In
particular, `in` means OR within one filter. Multiple filter objects are ANDed
in the MVP unless a later contract version adds an explicit Boolean expression
shape.

Field absence is expressed with `exists` set to `false`, not `eq` with a null
value. The MVP does not normalize backend-specific differences among null,
missing, and empty-string semantics.

The adapter translates these semantic operators into backend syntax without
changing their meaning. The registry supplies field types and searchable
capabilities; validation must reject incompatible combinations before query
execution. Backend coercion must not silently turn a type mismatch into a
different search.

Regular expressions, arbitrary scripts, and arbitrary backend functions are
outside the MVP structured interface.

## 5. Source Registry

The source registry resolves logical sources into controlled physical search
targets and source-specific processing metadata. For example:

```yaml
name: wazuh-archives
backend: wazuh_indexer
physical_source: wazuh-archives-*
time_field: timestamp
source_kind: raw_event
default_projection:
  - timestamp
  - agent.id
  - agent.name
  - location
  - full_log
key_fields:
  - agent.id
  - agent.name
  - location
data_classification: sensitive
raw_payload_fields:
  - full_log
```

The pattern above is registry-controlled. Its presence does not permit callers
to submit arbitrary physical patterns.

A registry entry should manage:

- logical source name;
- backend and configured connection identity;
- physical index, dataset, or source pattern;
- time field and timestamp semantics;
- source kind, such as `raw_event` or `alert`;
- default projection and key fields;
- field definitions, types, and supported operations;
- raw payload fields;
- data classification and projection policy;
- maximum query window and default result limit;
- retention metadata; and
- source mapper identifier and compatible version.

Candidate logical sources include:

- `wazuh-archives`
- `wazuh-alerts`
- `wazuh-alerts-sysmon-event1` for the bounded registered Windows alert slice
- `splunk-endpoint`
- `elastic-network`
- `timesketch-timeline`

Timesketch is not a SIEM in the same sense as Wazuh, Elastic, or Splunk. It is a
future investigation backend that could connect to the same bounded query
abstraction while retaining its own source semantics.

## 6. Query Output Contract

The version `1.0` response design is:

```json
{
  "contract_version": "1.0",
  "request_id": "query-...",
  "backend": "wazuh_indexer",
  "queried_sources": [
    {
      "logical_name": "wazuh-archives",
      "physical_sources": ["wazuh-archives-2026.07.13"]
    }
  ],
  "executed_time_range": {
    "start": "2026-07-13T12:00:00Z",
    "end": "2026-07-13T12:10:00Z",
    "time_field": "timestamp"
  },
  "total_hits": 1,
  "total_hits_relation": "eq",
  "returned_records": 1,
  "truncated": false,
  "refinement_required": false,
  "partial": false,
  "source_statuses": [
    {
      "logical_name": "wazuh-archives",
      "status": "complete",
      "error_category": null
    }
  ],
  "warnings": [],
  "records": [
    {
      "logical_source": "wazuh-archives",
      "physical_source": "wazuh-archives-2026.07.13",
      "backend_record_id": "record-...",
      "event_time": "2026-07-13T12:05:27Z",
      "fields": {
        "timestamp": "2026-07-13T12:05:27Z",
        "agent.id": "001",
        "agent.name": "ubuntu-victim01",
        "location": "/var/log/audit/audit.log"
      },
      "redacted_fields": ["full_log"],
      "raw_payload_available": true
    }
  ],
  "aggregations": [],
  "next_cursor": null,
  "query_provenance": {
    "executed_at": "2026-07-13T12:20:00Z",
    "adapter_name": "wazuh-indexer-query-adapter",
    "adapter_version": "0.2.0"
  }
}
```

`total_hits_relation` qualifies `total_hits` and accepts only:

- `eq`: `total_hits` is the exact matching count;
- `gte`: at least `total_hits` records matched; or
- `unknown`: the backend or policy did not provide a total count.

`total_hits` is a non-negative integer when the relation is `eq` or `gte`, and
is `null` when the relation is `unknown`.

`returned_records` is the number included in this response and is distinct from
`total_hits`. `truncated` means that some matching records are not included in
the response. `refinement_required` means cursor pagination cannot resolve the
volume condition and the caller must narrow the time range, sources, filters,
or aggregations. Ordinary page truncation that can be continued safely with
`next_cursor` does not necessarily set `refinement_required` to `true`.

`partial` indicates that timeout, shard failure, or failure of one selected
source prevented a complete query result. Each `source_statuses` entry names a
logical source and assigns `status` as `complete`, `partial`, or `failed`.
`error_category` is either an Error Model category or `null`. When `partial` is
`true`, consumers must be able to identify every incomplete source through
`source_statuses`; any `partial` or `failed` source status requires response-level
`partial` to be `true`. `warnings` may contain safe structured warnings; raw
backend exception text must not be copied into them.

Evidence-completeness validation, parity validation, and automatic incident
promotion must reject partial consumption. Investigation and hunt callers may
consume a partial response only when they explicitly opt in. If the caller or
workflow does not allow partial consumption, the adapter returns a
`partial_result` error instead of a response for downstream consumption.

### Record Envelope

Each item in `records` uses a provider-neutral retrieval envelope:

- `logical_source` is the source registry entry name.
- `physical_source` is the actual index, dataset, or source that produced the
  hit.
- `backend_record_id` is the backend-native document identifier when one is
  available; its absence must not be replaced with an invented identifier.
- `event_time` is common retrieval metadata extracted from the registry's time
  field. It does not yet assert canonical event-time semantics.
- `fields` contains projected source-native fields.
- `redacted_fields` names fields that existed but were withheld by policy.
- `raw_payload_available: true` means a separate controlled retrieval may be
  available. It does not mean the response contains the raw payload.

The executed projection, `fields`, and `redacted_fields` are interpreted
together: a field outside the executed projection was not requested; a
projected field absent from both `fields` and `redacted_fields` was not present
in the source record; and a field named in `redacted_fields` existed but was
withheld. The envelope is not necessarily a complete copy of the backend-native
document, and it is not a `normalized_endpoint_event`.

The query adapter must not send an entire backend `_source` document or raw
payload to an LLM by default. A workflow needing raw evidence uses a separate,
controlled retrieval with authorization, audit logging, and volume bounds.

## 7. Result Volume Policy

Agents and LLMs must not receive large result sets directly. Exact thresholds
are configurable, but implementations preserve these behavior classes:

```text
small result set (example: 0-100 hits)
  return policy-approved projected records

larger result set (example: 101 hits or more)
  return total count, bounded aggregations, a small sample, and
  refinement_required=true

hard limit exceeded
  set refinement_required=true and require query refinement; do not return
  the full matching set
```

The source registry and deployment policy may set stricter limits based on data
classification, source cost, or retention tier. Pagination does not bypass a
hard query or workflow volume limit. A normal truncated page with a valid
`next_cursor` can leave `refinement_required` as `false` when pagination remains
within those policy limits.

## 8. Query Provenance And Auditability

Every execution record must include or reference:

- request ID;
- logical source names;
- resolved physical sources;
- backend;
- executed query window and time field;
- structured filter fields and operators;
- projection and aggregation fields;
- limit and sort;
- execution timestamp;
- adapter name and version;
- total and returned result counts; and
- truncated and partial status.

Filter values are retained as full values, redacted values, or hashes according
to their data classification and audit purpose. Sensitive filter values must
not be persisted unconditionally. A hash is an audit correlation aid, not a
claim that the original value can be recovered or safely disclosed.

If a rendered backend-native query is retained for troubleshooting, it must be
sanitized and must not contain credentials, authorization headers, session
tokens, or other secrets. Retention and redaction policy must also prevent
sensitive indicators of compromise, personal information, and secret-equivalent
values from surviving in a nominally sanitized query. Query provenance records
what was executed; it does not establish that returned content is canonical,
detected, or incident-worthy.

## 9. Error Model

Errors use a stable category plus a safe message, retry guidance, request ID,
and optional backend correlation identifier. Backend exception text is not
copied blindly because it may contain sensitive query or infrastructure data.

| Category | Typical handling | Retry class |
|---|---|---|
| `invalid_request` | Correct malformed or contradictory input | Caller correction |
| `invalid_time_range` | Supply valid timezone-aware start and end values | Caller correction |
| `time_range_too_large` | Narrow the requested window | Caller correction |
| `unknown_source` | Select a registered logical source | Caller correction |
| `unsupported_backend` | Configure or choose a supported adapter | Configuration change |
| `unsupported_filter` | Use an operator supported by the field and adapter | Caller correction |
| `unknown_field` | Use a registered field | Caller correction |
| `field_type_mismatch` | Supply a compatible value or field | Caller correction |
| `authentication_error` | Refresh or repair the read credential | Credential repair; no blind retry |
| `authorization_error` | Request access or reduce source/field scope | Policy or caller correction |
| `backend_unavailable` | Retry with bounded backoff when policy permits | Retryable |
| `query_timeout` | Narrow or refine; a bounded retry may be permitted | Conditionally retryable |
| `result_limit_exceeded` | Refine filters, window, or aggregation | Caller correction |
| `partial_result` | Inspect failed sources and decide whether to retry | Conditionally retryable |
| `cursor_invalid` | Restart the bounded query with the original inputs | Caller restart |
| `response_parse_error` | Preserve safe diagnostics and investigate adapter compatibility | Adapter investigation |

Partial data must not be silently returned as complete. A response may carry
records with `partial: true`, incomplete `source_statuses`, and safe structured
`warnings` only when both policy and the caller explicitly permit partial
consumption. Evidence-completeness validation, parity validation, and automatic
incident promotion do not permit it. Otherwise the adapter returns the
`partial_result` error.

## 10. Security Boundaries

- Every query requires a bounded time range.
- Registry and policy enforce a maximum query window.
- Registry and policy enforce default and maximum result limits.
- Callers select registered logical sources; arbitrary physical-source
  wildcards are rejected.
- Structured and backend-native query interfaces are separate.
- Sensitive fields require explicit, policy-approved projection.
- Raw payload fields receive stricter retrieval, retention, and disclosure
  controls than ordinary projected metadata.
- Credentials and secrets never appear in requests, responses, provenance, or
  committed artifacts.
- Query activity is audited with caller, purpose, scope, and result status.
- Filter fields and operators are audited. Filter values are retained as full,
  redacted, or hashed values according to classification; sensitive values are
  not persisted unconditionally.
- Sanitized backend-native queries remain subject to retention and redaction
  controls for sensitive indicators, personal information, and
  secret-equivalent values.
- Field projection and redaction occur before records are provided to an LLM.
- Log text is untrusted data. Instructions embedded in log content, alerts, or
  raw payloads are not interpreted as agent or system instructions.
- Backend write, update, delete, rule-deployment, and configuration operations
  are outside this contract.
- Backend adapters use read-only credentials by default and least-privilege
  source and field access.

## 11. Structured Query And Raw Query Separation

### Structured Query Interface

The structured interface is the normal interface for agents, workflows, and
pipelines. It accepts registry-backed sources, structured filters, projections,
aggregations, sorting, limits, and cursors. Its semantic validation is portable
across providers.

### Backend-Native Raw Query Interface

The backend-native interface accepts languages such as SPL, ES|QL, or
Elasticsearch Query DSL. It is reserved for analysts or explicitly authorized
advanced workflows and requires:

- explicit opt-in;
- stricter authorization;
- a mandatory bounded time range enforced outside the native expression;
- a policy-enforced result limit;
- complete query audit logging;
- backend-specific syntax and safety validation; and
- a policy gate before any LLM-generated expression can be executed.

Native expressions do not inherit trust merely because they were generated by
an agent. They cannot invoke backend write operations through this read-only
contract.

## 12. Alerts Versus Raw Events

Raw-event and alert sources represent different evidence planes:

```text
raw event source
  may include events that produced no SIEM-native alert
  supports investigation, hunting, and candidate input for the lab DSL

alert source
  contains events or findings that passed SIEM-native detection
  supports triage, case creation, and native-rule parity assessment
```

For Wazuh:

```text
wazuh-archives-*
  raw event plane

wazuh-alerts-*
  native alert plane
```

The absence of a matching Scenario 009 alert in `alerts.json` describes the
native alert result under the observed configuration. It does not establish
whether the underlying event was collected. Raw-event receipt must be evaluated
through an appropriate raw-event evidence or query path.

## 13. Relationship To `normalized_endpoint_event`

The intended flow is:

```text
SIEM query response record
  -> source-specific mapper
  -> source-specific parsed event
  -> normalized_endpoint_event
  -> DSL detection
  -> correlation
  -> incident pipeline
```

A query response record is not a `normalized_endpoint_event`. Wazuh, Splunk,
Elastic, and other sources use different field names, typing, nesting, and raw
payload representations. The mapper resolves those differences and preserves
source provenance. It must not invent missing endpoint evidence merely to
satisfy the canonical shape.

The canonical event contract defines downstream semantic expectations. The
source registry defines where physical data is queried. Neither replaces the
other.

## 14. Scenario 009 Evidence Boundary

The controlled Scenario 009 Stage 4 validation established exact grouped-payload
identity for manager-local `archives.json.full_log`: completed local record
bodies were newline-stripped, joined with single ASCII spaces, and matched the
manager `full_log` by byte length and SHA-256. That is evidence-plane
validation, not validation of an operational SIEM query path.

The manager-local result must not be generalized into persistent operational
query architecture. An indexed Wazuh path requires separate evidence for source
registration, field representation, bounded retrieval, provenance, pagination,
and mapper parity. Detailed Scenario 009 evidence remains in the
[Scenario 009 design documents](../scenarios/scenario009/); current status and
priority remain Roadmap-owned.

## 15. Implementation Acceptance Conditions

A backend path satisfies this contract only when it provides independently
reviewable evidence for:

1. bounded read-only query translation;
2. a reviewed source-registry entry;
3. deterministic backend-field mapping with provenance;
4. `normalized_endpoint_event` parity where normalization is applicable;
5. explicit truncation, pagination, timeout, and partial-result behavior;
6. separation of raw-event and alert semantics;
7. multi-source bounds where a request spans logical sources; and
8. downstream detection and Incident handoffs that do not treat a query hit as
   a detection result.

Native backend-rule translation and parity comparison are separate target
concerns. They are not prerequisites for validating the provider-neutral query
contract itself. Current implementation order and completion claims belong in
the [Main Roadmap](../../roadmap/roadmap.md).

## 16. Bounded Wazuh Query Adapter Record

The first executable subset is recorded in the
[Wazuh Alerts Sysmon Event ID 1 Query Adapter Contract](wazuh_alerts_sysmon_event1_query_adapter_contract.md).
It adds machine-readable request, response, and registry schemas; one reviewed
single-source registry entry; bounded offline Wazuh search-plan compilation;
complete-page response parsing; hashed filter provenance; explicit refinement
for unpageable volume; and fail-closed timeout and shard-failure behavior.

That subset does not by itself provide credential resolution, an HTTPS
transport, live index mapping evidence, a Wazuh Indexer PIT lifecycle, live
query evidence, raw archive retrieval, or multi-source execution. The bounded
alert-hit conversion contract remains the separately reviewed
source-representation mapping boundary.

## 17. Bounded Wazuh Live Transport Record

The follow-on implementation is recorded in the
[Wazuh Indexer Live Transport and Smoke Contract](wazuh_indexer_live_transport_contract.md).
It resolves one read-only connection from runtime-only values, requires HTTPS
and certificate verification, executes only the registered bounded plan, caps
the response body, rejects redirects and partial/error responses, and produces
a sanitized smoke summary with identity-presence and time-alignment counts.

Implementation and deterministic tests do not by themselves establish live
retrieval. The separately recorded 2026-08-10 read-only lab run satisfied that
bounded gate for one run-correlated host/time window. A follow-on bounded Wazuh
Indexer PIT lifecycle now creates a 30-second snapshot, performs the same
single-page search, and confirms deletion. A separately recorded 2026-08-10
rerun through that lifecycle returned the same 14 exact records and confirmed
PIT deletion with the existing read-only account. The deterministic transport
now retains that PIT across protected cursor calls, resumes with stable
`search_after`, caps cumulative results at 100, and deletes on final page,
policy stop, or known failure. Live multi-page completeness, raw archive
retrieval, multi-source execution, and downstream pipeline ingestion remain
deferred.

The next foundation is recorded in the
[Wazuh Indexer Cursor Envelope Contract](wazuh_indexer_cursor_envelope_contract.md).
It adds an encrypted, request-bound, expiring container for the PIT ID, stable
`search_after` values, and cumulative count. The adapter and transport now use
that container for deterministic continuation. No live second-page result or
multi-page completeness claim is established yet.

## Non-Goals

This contract does not:

- implement a backend adapter or source mapper;
- create a JSON Schema, fixture, or runtime artifact;
- change Wazuh, Filebeat, Elastic, Splunk, or Timesketch configuration;
- approve raw payload disclosure to agents or LLMs;
- make a SIEM document the canonical semantic contract;
- replace the existing detection DSL or correlation boundary;
- treat local file access as operational SIEM search; or
- depend on Agentic SOC Platform, Vigil, AI_SOC, or another external design.

Those projects may inform future comparison, but they are not dependencies or
authoritative implementations of this lab policy.
