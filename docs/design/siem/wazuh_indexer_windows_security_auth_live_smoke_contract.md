# Wazuh Windows Security Authentication Live Smoke Contract

Evidence scope: one bounded, read-only `wazuh-alerts-*` query for one Windows
Security authentication Event ID on one host and one short time window. This
contract defines the harness and records one sanitized 2026-08-11 lab result.

## 1. Purpose

The harness is the first point in this workstream that requires the user's
Wazuh 4.14.4 and Windows lab:

```text
reviewed source registry and query adapter
  -> existing TLS-verifying read-only PIT transport
  -> one exact Event ID: 4624 or 4625
  -> sanitized summary only
```

It confirms that the alert-plane hit contains the System and EventData fields
needed by the separately reviewed conversion contract. It does not write raw
records or backend state to disk.

## 2. Bounds

- one logical source: `wazuh-alerts-windows-security-auth`;
- one exact `agent.name`;
- one exact Event ID, `4624` or `4625`;
- centered window: 300 seconds by default, configurable from 1 to 1800 seconds;
- maximum 100 exact records;
- no retry, redirect, TLS bypass, administrative credential, or archive query;
- one PIT-backed transport call with confirmed cleanup before success;
- only the five reviewed Wazuh-omittable provider sentinel fields may be absent;
  all target identity, logon, authentication, and event-specific fields remain
  required; and
- zero, partial, lower-bound, truncated, cursor-bearing, or over-limit results
  cannot pass.

The harness intentionally does not add multi-page authentication evidence. The
existing Sysmon smoke already validates the shared PIT/cursor transport across
multiple pages. If this source exceeds 100 hits, narrow the window instead of
widening the evidence or result cap.

## 3. Sanitized Summary

The public schema is
[`wazuh_indexer_windows_security_auth_live_smoke_summary.schema.json`](../../../schemas/wazuh_indexer_windows_security_auth_live_smoke_summary.schema.json).
The summary retains only:

- run label, requested Event ID, request fingerprint, and hashed host;
- exact result and physical-source counts;
- presence counts for backend, Wazuh-alert, and Windows-record identities;
- Boolean host/provider/Event-ID/channel alignment;
- Boolean common and event-specific conversion-projection alignment; and
- alert-to-Windows-System time-delta bounds.

It excludes the host value, account, address, record IDs, Wazuh alert IDs,
backend document IDs, EventData values, URL, username, password, CA path, PIT
ID, and raw event.

## 4. Lab Procedure

Use the existing read-only account and external CA bundle. Do not change the
Wazuh role, switch to `admin`, or disable TLS verification for this smoke.

On Windows, first select a recent Security event and print its UTC anchor:

```powershell
$eventId = 4625
$event = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$eventId} -MaxEvents 1
$event | Select-Object Id, RecordId, TimeCreated
$anchor = $event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$anchor
$env:COMPUTERNAME
```

If the lab has no recent 4625, a bounded failed authentication can be generated
with a nonexistent lab-only account and a non-secret placeholder. Confirm the
target is the local lab host before running it:

```powershell
cmd /c 'net use \\127.0.0.1\IPC$ /user:.\intelligent-soc-smoke-nonexistent placeholder'
```

Failure is expected. This must not use a real account or password. Re-run the
`Get-WinEvent` block afterward and record the new anchor. Do not treat command
failure itself as defender evidence; the Security event and Wazuh hit are the
relevant observations.

After allowing the event to reach the Indexer, run on the repository host:

```bash
SMOKE_RUN_ID="windows-security-auth-$(date -u +%Y%m%dT%H%M%SZ)"
SMOKE_RESULT=/tmp/wazuh-indexer-windows-security-auth-live-smoke-summary.json

uv run python \
  scripts/siem/wazuh_indexer_windows_security_auth_live_smoke.py \
  --run-id "$SMOKE_RUN_ID" \
  --host WIN-VICTIM01 \
  --event-id 4625 \
  --anchor WINDOWS_EVENT_UTC_ANCHOR \
  --window-seconds 300 \
  > "$SMOKE_RESULT"

SMOKE_EXIT=$?
printf 'exit code: %s\n' "$SMOKE_EXIT"
uv run python -m json.tool "$SMOKE_RESULT"
sha256sum "$SMOKE_RESULT"
```

If more than 100 matching alerts exist, rerun with a smaller
`--window-seconds`. Do not move the anchor to a different event merely to make a
failed check pass. A 4624 run uses the same command with `--event-id 4624` and
that event's own anchor. A zero-hit 4624 alert-plane result is inconclusive; it
may reflect Wazuh alert-rule behavior rather than missing Windows collection.

## 5. Reviewed Live Evidence

A 2026-08-11 Wazuh 4.14.4 lab execution used the existing TLS-verifying
read-only account and the controlled 4625 anchor without changing the role,
disabling TLS verification, retrying, or retaining raw records.

The sanitized summary recorded:

- run ID `windows-security-auth-20260811T074933Z`;
- five exact records from one physical source;
- `eq` total-hit relation with no partial, truncated, refinement, or cursor
  result;
- matching host, provider, Event ID, and Security channel for every record;
- complete required common and 4625-specific conversion projection after the
  reviewed provider-sentinel omission policy;
- backend, Wazuh-alert, and Windows-record identities for all five records;
- alert-to-System deltas from `3686.874` through
  `3700.8109999999997` milliseconds; and
- summary SHA-256
  `41f6a7a11e94b1cad7a5890f9cf6f0550894409860c2e275996ab56c6018c3b2`.

This is bounded alert-plane retrieval evidence. It does not upgrade the result
to live conversion, normalized parity, detection, downstream pipeline, or
cross-platform execution evidence. The separately reviewed
[live common-pipeline contract](wazuh_indexer_windows_security_auth_live_pipeline_contract.md)
owns the next in-memory conversion and common-entry gate.

## 6. Done Criteria

The offline harness is ready when its schema, query selection, filter and field
alignment, sanitization, incomplete-result, and CLI tests pass alongside the
existing Sysmon transport regressions.

The live gate is complete only when a reviewed summary has exit code 0 and:

- at least one exact, complete, non-partial, non-truncated hit;
- matching host, provider, requested Event ID, and Security channel;
- all required common and event-specific conversion fields, with absence
  accepted only for the five reviewed provider-sentinel fields normalized by
  the conversion adapter;
- all three identity kinds present for every returned record;
- alert/System time deltas for every returned record; and
- no TLS bypass, role widening, admin credential, retry, or raw artifact
  retention.

## 7. Does Not Establish

Even a passing summary does not establish raw archive or unalerted-event
completeness, continuous collection, Wazuh alert or lab detection coverage,
credential validity, authorized or malicious activity, account compromise,
whether an omitted alert field was a literal provider `-`, native EVTX/export
parity, AD/DC behavior, downstream Incident correctness, or full cross-platform
execution.

## 8. Offline Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest \
  tests/test_wazuh_indexer_windows_security_auth_query.py \
  tests/test_wazuh_indexer_windows_security_auth_live_smoke.py \
  tests/test_wazuh_indexer_query_adapter.py \
  tests/test_wazuh_indexer_transport.py \
  tests/test_wazuh_indexer_live_smoke.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
```
