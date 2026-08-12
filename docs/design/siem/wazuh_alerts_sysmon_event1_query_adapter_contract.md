# Wazuh Alerts Sysmon Event ID 1 Query Adapter Contract

Evidence scope: offline, fixed-fixture validation of one bounded read-only
Wazuh Indexer query plan and one complete backend response page. Overall status
and sequencing remain owned by the [Main Roadmap](../../roadmap/roadmap.md).

## 1. Purpose

This slice implements the first executable boundary from the
[Provider-Neutral SIEM Query Contract](siem_query_contract.md):

```text
siem_query_request.v1
  -> reviewed single-source registry entry
  -> bounded Wazuh Indexer search plan
  -> future credential-resolving HTTPS transport
  -> Wazuh Indexer search response page
  -> siem_query_response.v1
  -> existing source-specific representation adapter
```

The implementation compiles and parses deterministic objects. It deliberately
does not open a network connection or resolve credentials. This keeps query
semantics reviewable before a live transport receives authority to contact the
Indexer.

The separately reviewed
[Wazuh Indexer Live Transport and Smoke Contract](wazuh_indexer_live_transport_contract.md)
now implements that follow-on transport and smoke harness. The documented
2026-08-10 read-only smoke satisfied the bounded alert-plane retrieval gate.

## 2. Included Scope

The slice includes:

- machine-readable provider-neutral request and response schemas;
- a machine-readable source-registry entry schema;
- one registered logical source, `wazuh-alerts-sysmon-event1`;
- fixed mapping to the registry-controlled physical source
  `wazuh-alerts-*`;
- a start-inclusive, end-exclusive time range capped at 30 minutes;
- one required exact `agent.name` host filter;
- fixed Sysmon provider, Event ID 1, and channel predicates supplied by the
  registry rather than the caller;
- a fixed allowlisted projection and stable `timestamp`, `id` sort;
- a positive limit capped at 100 records;
- exact total-hit tracking and explicit result-volume refinement;
- fail-closed timeout and shard-failure handling; and
- safe query provenance with hashed filter values.

The prior sanitized Wazuh Fixture A/B/C projections provide the backend hit
evidence used by the tests. No additional runtime export is committed.

## 3. Source Registry Boundary

Callers select the logical name `wazuh-alerts-sysmon-event1`. They cannot submit
an index pattern. The registry owns:

```text
backend
connection identity
physical source pattern
source kind
time field
fixed predicates
required caller filters
field capabilities
default projection
stable sort
query-window and result limits
transport policy
adapter identity and version
```

The source kind is `alert`. Therefore the result set covers only events present
in the Wazuh alert plane. Zero results do not prove that Windows or Sysmon
failed to produce an event, that the Wazuh agent failed to collect it, or that
the manager/raw archive lacks it.

The current 30-minute maximum supports the previously selected short
incident-anchored window of plus/minus 15 minutes. A 24-hour fallback or other
wider query requires a separately reviewed policy and must not be obtained by
silently increasing this registry value.

The registered query time field is the Wazuh alert `timestamp`. This adapter
does not correct clock skew or equate that retrieval field with Sysmon
`systemTime` or `utcTime`. The bounded 2026-08-10 live run recorded the first
observed relationship among the incident anchor, alert timestamp, and provider
times; it did not approve a general clock-skew tolerance or broader
completeness claim.

## 4. Compiled Search Plan

The compiler returns a plan with:

```text
POST /wazuh-alerts-*/_search
allow_partial_search_results=false
track_total_hits=true
timeout=10s
TLS verification required
read-only connection identity
connect timeout=3s
read timeout=10s
```

The query body contains:

1. the bounded `[start, end)` timestamp range;
2. exact registry-owned Sysmon provider, Event ID, and channel terms;
3. the required caller-owned `agent.name` term;
4. the fixed projection; and
5. the stable `timestamp`, `id` ascending sort.

The plan contains a connection name, not a username, password, bearer token,
authorization header, base URL, or certificate secret. A future transport must
resolve that connection through approved runtime configuration, retain TLS
verification, and use read-only least-privilege credentials.

## 5. Response Mapping

One complete OpenSearch/Wazuh response page maps to
`siem_query_response.v1`. The adapter retains:

- logical and physical source identity;
- backend document ID;
- event time from the registered time field;
- only the executed allowlisted projection;
- exact or lower-bound total-hit semantics;
- returned-record count;
- truncation, refinement, and partial status;
- source status; and
- adapter, connection, scope, and hashed-filter provenance.

Backend `_id`, Wazuh alert `id`, and Windows `eventRecordID` remain separate.
The query response is a retrieval envelope, not a Sysmon parsed event,
`normalized_endpoint_event`, detection, or Incident.

Unrequested `_source` values, including `rule` conclusions and `full_log`, are
not copied into the provider-neutral response. `raw_payload_available` remains
false for this source entry because no controlled raw-payload retrieval is
implemented by this slice.

## 6. Pagination And Volume Semantics

The adapter now accepts one non-null cursor only after the reviewed cursor
codec authenticates, decrypts, checks expiry, and confirms binding to the same
bounded request. It then validates the cumulative count and the two registered
stable sort positions, and rejects an expiry beyond the registered 30-second
PIT keep-alive before compiling the protected position as `search_after`.

The compiled resume plan retains the decoded cursor only as a redacted internal
state object. Its representation does not expose the PIT ID. The transport now
uses that state to search the same PIT without creating a replacement PIT.

If exact total hits exceed the cumulative returned count and the 100-record
policy still has room, the response uses:

```text
truncated = true
refinement_required = false
next_cursor = <opaque protected cursor>
warning = additional_results_available
```

The next request is capped to the smaller of the original page limit and the
remaining 100-record allowance. Sort order must progress strictly beyond the
protected prior position. The request fingerprint remains stable because only
the opaque cursor value is cleared before hashing.

If the cumulative count reaches 100 while exact hits remain, or the backend
reports a `gte` total relation, the response instead uses:

```text
truncated = true
refinement_required = true
next_cursor = null
warning = result_volume_requires_refinement
```

This behavior is intentional. OpenSearch restricts `_id` sorting, and ordinary
`search_after` is not snapshot-consistent. The transport therefore retains the
same 30-second PIT across cursor calls and deletes it on the final page, policy
cap, or known failure. A caller that abandons a cursor does not prove explicit
cleanup; the registered PIT and cursor expiry only bound that condition.

## 7. Partial And Failure Semantics

The compiled plan sets `allow_partial_search_results=false`. The parser also
checks the response independently.

The adapter raises a stable `partial_result` error when:

- `timed_out` is not exactly false; or
- any shard failed.

It does not return the collected subset as complete. This slice has no caller
opt-in for partial consumption.

Other failures use stable SIEM categories such as `invalid_request`,
`invalid_time_range`, `time_range_too_large`, `unknown_source`,
`unsupported_backend`, `unsupported_filter`, `unknown_field`,
`field_type_mismatch`, `result_limit_exceeded`, `cursor_invalid`, and
`response_parse_error`. Error messages name a safe boundary without echoing
host names, filter values, source text, backend exception text, or credentials.

## 8. Done Criteria

This bounded slice is done when:

1. the request, response, and registry artifacts validate against their
   schemas;
2. callers cannot select an arbitrary physical index or omit the host filter;
3. the 30-minute window, 100-record cap, fixed projection, and stable sort fail
   closed when exceeded or changed;
4. the compiled plan is read-only, TLS-verifying, partial-disallowing, bounded,
   and free of credential values;
5. complete Fixture A/B/C-derived pages map deterministically into the
   provider-neutral response;
6. backend, Wazuh alert, and Windows record identities remain distinct;
7. unreviewed Wazuh fields do not leak into the response;
8. filter values are hashed in retained provenance;
9. a valid request-bound cursor compiles only the registered two-position
   `search_after`, while malformed, expired, overlong, over-limit, or
   mismatched cursor state fails without disclosure;
10. continuation pages cannot exceed the cumulative 100-record policy;
11. exact remaining volume returns a protected cursor without requiring
    refinement, while unknown or over-limit volume requires refinement without
    inventing a cursor;
12. resumed pages must progress strictly beyond the protected sort position and
    preserve a cursor-independent request fingerprint;
13. timeout and shard failure produce `partial_result` rather than complete
    evidence;
14. malformed hit identity, time, source, or ordering fails closed, while an
    OpenSearch epoch-millisecond date sort value must normalize to the projected
    timestamp before it is accepted;
15. inputs remain immutable and errors do not disclose values; and
16. formatter, lint, focused tests, full tests, and whitespace checks pass.

## 9. Explicit Non-Goals And Evidence Limits

This slice does not establish:

- a live Wazuh Indexer connection or successful authentication;
- credential-store, environment-variable, secret-manager, CA-bundle, or base
  URL resolution;
- HTTP status, retry, backoff, connection failure, or authorization behavior;
- live multi-page execution or completeness and explicit cleanup of a cursor
  abandoned by its caller;
- live index mappings for `timestamp` and `id`;
- live manager/Indexer clock alignment or alert/provider time-skew behavior;
- raw archive or unalerted-event retrieval;
- query completeness outside the fixed response fixtures;
- live Sysmon/Wazuh source parity;
- Wazuh native rule quality or alert absence interpretation;
- automatic source-event conversion or canonical detection execution from a
  query response; or
- any Incident, Triage, Investigation, Case, Action, verdict, risk, or scoring
  change.

## 10. Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest tests/test_wazuh_indexer_query_adapter.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
```

## 11. Primary References

- [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/index.html)
- [Wazuh Indexer API configuration](https://documentation.wazuh.com/current/user-manual/indexer-api/configuration.html)
- [Wazuh Indexer API security](https://documentation.wazuh.com/current/user-manual/indexer-api/securing-indexer-api.html)
- [OpenSearch Search API](https://docs.opensearch.org/latest/api-reference/search-apis/search/)
- [OpenSearch pagination](https://docs.opensearch.org/latest/search-plugins/searching-data/paginate/)
- [OpenSearch Point in Time](https://docs.opensearch.org/latest/search-plugins/searching-data/point-in-time/)
- [OpenSearch `_id` limitations](https://docs.opensearch.org/latest/field-types/metadata-fields/id/)
