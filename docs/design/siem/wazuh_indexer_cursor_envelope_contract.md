# Wazuh Indexer Cursor Envelope Contract

Evidence scope: implementation and deterministic tests for one encrypted,
request-bound, short-lived cursor envelope. Overall status and sequencing
remain owned by the [Main Roadmap](../../roadmap/roadmap.md).

## 1. Purpose

The existing Wazuh Indexer transport creates a 30-second Point in Time (PIT),
reads one page, and confirms deletion. A future caller needs a cursor to ask for
the next page without receiving the PIT ID or constructing `search_after`
values itself.

This PR introduces only the safe envelope needed for that future handoff:

```text
original bounded query
  + runtime-only PIT ID
  + last accepted stable sort values
  + cumulative returned-record count
  + expiry
  -> authenticated encryption
  -> opaque caller cursor
```

The Wazuh Indexer product boundary remains primary. OpenSearch is named only
where its compatible PIT and `search_after` wire behavior explains the need for
the envelope.

## 2. Protected Envelope

The decrypted version `1.0` envelope is defined by
`schemas/wazuh_indexer_cursor_envelope.schema.json` and contains exactly:

- the original request fingerprint;
- the runtime PIT ID;
- the last accepted hit's stable sort values;
- the cumulative number of records already returned; and
- an RFC 3339 expiry timestamp.

The fingerprint is SHA-256 over canonical JSON after replacing only the
request's `cursor` value with `null`. All other request values, including the
request ID, logical source, window, filters, projection, sort, and limit, remain
bound. A cursor therefore cannot be moved to a different request while still
being accepted.

The current source policy bounds cumulative returned records to 100. The schema
does not admit arbitrary objects, null sort values, empty PIT IDs, or additional
properties. A Wazuh wildcard can resolve across many dated indexes and shards,
so its OpenSearch-compatible PIT ID is not assumed to be short. The reviewed
capacity accepts a protected PIT ID up to 128 KiB and an encrypted cursor up to
256 KiB. Both limits remain fail-closed bounds rather than unbounded input.

## 3. Confidentiality And Runtime Key

The serialized cursor uses Fernet authenticated encryption. The protected
payload cannot be read or modified without the key. Fernet framing exposes the
token issuance time, but the PIT ID, request fingerprint, sort values, count,
and explicit expiry remain encrypted.

The key is resolved only from the runtime environment variable:

```text
WAZUH_INDEXER_CURSOR_FERNET_KEY
```

It is not accepted in the provider-neutral request, query plan, response,
provenance, fixture, or committed configuration. Missing or malformed key
material fails with `cursor_config_error`; the key value is never echoed.
Production key storage and rotation remain deployment concerns. Losing or
rotating the only active key invalidates outstanding short-lived cursors, which
callers handle by restarting the original bounded query.

## 4. Validation And Failure Semantics

Decode succeeds only when all of the following are true:

1. the token is non-empty and within the fixed input-size cap;
2. authenticated decryption succeeds with the runtime key;
3. the decrypted object validates against the envelope schema;
4. the explicit expiry is later than the validation time; and
5. the protected request fingerprint matches the supplied request after only
   its cursor is cleared.

Tampering, a wrong key, malformed content, expiry, or request mismatch all
collapse to the same safe `cursor_invalid` category and message. Stable errors
do not echo the token, PIT ID, sort values, request values, decrypted content,
or cryptography exception text. The decoded object also uses a redacted
representation.

## 5. Done Criteria

This foundation is reviewable when deterministic tests establish that:

1. encode/decode preserves the protected PIT ID, sort values, cumulative count,
   and expiry;
2. the serialized token and decoded-object representation do not expose the PIT
   ID or sort values;
3. only the request cursor value is excluded from request binding;
4. tampered, malformed, wrong-key, wrong-request, and expired tokens fail
   closed with safe categories;
5. missing or malformed runtime key material fails without disclosure;
6. invalid envelope fields and volume above 100 are rejected;
7. a bounded 64 KiB multi-shard-style PIT ID survives encrypted round-trip while
   a PIT ID above 128 KiB fails without disclosure;
8. caller inputs remain immutable;
9. the new direct dependency and generated lockfile remain consistent; and
10. formatter, lint, focused tests, full tests, and whitespace checks pass.

## 6. Evidence Boundary

Passing deterministic tests establishes that this process can create and
validate the reviewed protected cursor envelope, compile its stable position,
and use it to resume the same PIT through the bounded transport. The adapter
also rejects an envelope whose remaining expiry exceeds the registered
30-second PIT keep-alive.

It does not establish:

- a live second-page Wazuh Indexer query or live multi-page completeness;
- explicit cleanup of a PIT after its caller abandons a returned cursor;
- cursor persistence across a key rotation or deployment boundary;
- pagination beyond the registered 100-record policy limit;
- raw archive or unalerted-event completeness;
- continuous runtime collection or operational availability;
- detection, Incident, Triage, Investigation, or verdict correctness; or
- full Common Defender Pipeline cross-platform validation.

The deterministic transport retains the PIT when it returns a cursor, reuses it
for a resumed search, and requests deletion after the final page, policy cap, or
known search/parse failure. A returned cursor that is never presented again is
bounded only by the registered PIT and cursor expiry; expiry is not evidence of
confirmed deletion.

## 7. Primary References

- [Wazuh Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/index.html)
- [OpenSearch-compatible Point in Time API](https://docs.opensearch.org/latest/api-reference/search-apis/point-in-time-api/)
- [Fernet authenticated encryption](https://cryptography.io/en/latest/fernet/)
