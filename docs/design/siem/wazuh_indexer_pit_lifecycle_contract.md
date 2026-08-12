# Wazuh Indexer PIT Lifecycle Contract

Evidence scope: implementation, deterministic tests, and one bounded live lab
run for a read-only Wazuh Indexer Point in Time (PIT) create/search/delete
lifecycle. Overall status and sequencing remain owned by the
[Main Roadmap](../../roadmap/roadmap.md).

## 1. Terminology And Purpose

Wazuh Indexer exposes an OpenSearch-compatible API. This contract therefore
uses **Wazuh Indexer** for the product boundary and names OpenSearch only when
describing the compatible PIT wire protocol.

The lifecycle adds snapshot consistency to the bounded query across calls:

```text
registered Wazuh alert source
  -> create 30-second Wazuh Indexer PIT
  -> search one page through the PIT
  -> return a protected cursor while exact bounded results remain
  -> resume the same PIT with stable search_after
  -> confirm PIT deletion on the final page or policy boundary
```

The transport executes the adapter's protected resume plan, and the live-smoke
runner can now continue pages in one process while retaining only sanitized
counts and assertions. Deterministic tests cover the orchestration, and one
bounded multi-page lab run now covers the observed lifecycle described in
Section 5.2. Broader operational behavior remains outside this contract.

## 2. Registered Lifecycle

The source registry fixes `pit_keep_alive_seconds` at 30 seconds. A first-page
request compiles create and search operations. A resumed request skips create:

```text
POST /wazuh-alerts-*/_search/point_in_time
  keep_alive=30s
  allow_partial_pit_creation=false

POST /_search
  allow_partial_search_results=false
  pit.id=<runtime-only PIT ID>
  pit.keep_alive=30s

DELETE /_search/point_in_time
  pit_id=[<runtime-only PIT ID>]
```

Deletion is issued after the final page, a cumulative 100-record policy stop,
or a known failure after a PIT ID exists. It is not issued when a successful
page returns a protected continuation cursor.

The caller cannot select an index, PIT endpoint, keep-alive value, PIT ID, or
cleanup behavior. The PIT ID exists only in transport memory or inside the
encrypted cursor and is not copied into the provider-neutral response, smoke
summary, provenance, stable error, or committed fixture.

## 3. Cleanup And Failure Semantics

Once a create response or validated cursor supplies a PIT ID, cleanup is
attempted after:

- a successful final page or policy-bound response parse;
- a search transport or HTTP failure;
- a partial PIT creation response; or
- a search response parse or partial-result failure.

When cleanup is required, the transport returns success only when deletion
reports exactly one matching PIT with `successful = true`. An unconfirmed
deletion fails closed with `pit_cleanup_failed`. Partial creation fails with
`pit_creation_failed`.
Authentication, authorization, TLS, timeout, connection, response-size, and
response-format failures retain the existing stable transport categories.

If both the primary operation and cleanup fail, the primary failure remains the
raised category and receives only a safe cleanup-failure note. Neither backend
text nor the PIT ID is disclosed. The 30-second keep-alive bounds an otherwise
unreleased PIT, but expiry is not treated as evidence that explicit cleanup
succeeded.

A successful non-final page intentionally returns before deletion so the same
PIT can be resumed. If the caller abandons that cursor, the 30-second expiry
bounds the PIT lifetime but does not prove explicit cleanup. Cursor validation
and issuance use one transport-start timestamp so the returned cursor cannot be
extended by response-transfer or parsing time beyond the reviewed bound.

## 4. Least-Privilege Boundary

The read-only runtime identity needs only the index-scoped capabilities needed
to:

```text
create a PIT
search through that PIT
delete that PIT by ID
```

For the current OpenSearch-compatible API these map to:

```text
indices:data/read/point_in_time/create
indices:data/read/search
indices:data/read/point_in_time/delete
```

The implementation does not list all PITs, delete all PITs, write documents,
manage indices, or use an administrative identity.

## 5. Done Criteria

This foundation is reviewable when deterministic tests establish that:

1. the registry bounds PIT lifetime to 30 seconds;
2. partial PIT creation is disabled using wire-compatible lowercase boolean
   spelling;
3. the first search creates a PIT, while a resumed search reuses the protected
   PIT ID and registered `search_after` without another create;
4. every response is TLS-verified, size-capped, non-redirecting, and closed;
5. a non-final page returns a protected cursor without deletion;
6. cleanup is attempted on the final page, policy cap, failed search/parse, and
   partial creation paths whenever a PIT ID exists;
7. required cleanup succeeds only after a confirmed matching deletion;
8. cumulative results cannot exceed 100 and resumed ordering must progress;
9. PIT identifiers and backend text do not survive in stable outputs; and
10. formatter, lint, focused tests, full tests, and whitespace checks pass.

The live evidence gate is separate from deterministic tests. The prior
2026-08-10 14-record smoke predates this lifecycle and is not PIT evidence; the
PIT-enabled rerun recorded below satisfies the bounded lifecycle gate.

### 5.1 Observed lab evidence

One PIT-enabled rerun completed on 2026-08-10 with the existing read-only lab
account and TLS verification:

- run ID: `windows-sysmon1-20260810T221534Z`;
- request fingerprint:
  `sha256:560c5f1b83feda84a9fef74786f35506b1aae69d5eb72bd5483b73cbceb2fd76`;
- 14 exact hits from one physical alert source, all returned, non-partial, and
  non-truncated;
- process exit code 0, which is emitted only after the matching PIT deletion is
  confirmed successful;
- no role change, TLS bypass, administrative credential, retry, or wider query
  window for the rerun; and
- sanitized summary SHA-256:
  `b75402666a153f150f4413528cc15a8260f2c44932bd300f6afed703d7534c62`.

The rerun intentionally reused the earlier controlled event and bounded query
window. It validates the new PIT transport lifecycle, not new event generation,
collection recency, or continuous availability. The summary remains outside
the repository and contains no PIT ID.

### 5.2 Observed multi-page lifecycle evidence

One bounded rerun on 2026-08-11 used page size 5 and the existing read-only,
TLS-verifying connection to return the exact 14-record result as pages
`[5, 5, 4]`. Two protected cursor resumptions retained the same request
fingerprint and registered stable ordering. The final page completed without
partial, truncation, or refinement state and confirmed deletion of the same
PIT. The sanitized summary SHA-256 is
`04dbe0a9c818307a70a1582cc189413ef96ce9df0b71dbf82fb481c172cf2ce3`.

The runtime cursor key, cursor, PIT ID, `search_after`, host value, record
identifiers, and event contents were not retained. The run reused the earlier
event/window and does not establish event-generation recency or continuous
collection.

## 6. Evidence Boundary

The passing multi-page lab run establishes that one bounded Wazuh Indexer PIT
was created, resumed twice through protected cursor state, used to return the
exact 14-record result in three ordered pages, and explicitly deleted through
the TLS-verified read-only transport.

This foundation does not establish:

- live pagination or completeness outside the one reviewed query/window;
- cleanup of a PIT abandoned by a caller holding a future cursor;
- pagination beyond the registered 100-record policy limit;
- raw archive or unalerted-event completeness;
- continuous runtime collection or operational availability;
- detection, Incident, Triage, Investigation, or verdict correctness; or
- full Common Defender Pipeline cross-platform validation.

## 7. Primary References

- [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/index.html)
- [OpenSearch-compatible Point in Time API](https://docs.opensearch.org/latest/api-reference/search-apis/point-in-time-api/)
