# Wazuh Windows Security Authentication Query Adapter Contract

Evidence scope: deterministic source-registry selection, bounded query-plan
compilation, and provider-neutral response parsing for one reviewed Windows
Security authentication alert source. Overall status remains owned by the
[Main Roadmap](../../roadmap/roadmap.md).

## 1. Purpose

This contract registers the Wazuh alert-plane source needed before a live
Windows Security 4624/4625 check:

```text
siem_query_request.v1
  -> logical source selection
  -> reviewed source registry
  -> read-only Wazuh Indexer PIT/search plan
  -> siem_query_response.v1
```

The logical source is `wazuh-alerts-windows-security-auth`. It reuses the
existing TLS-verifying read-only connection, PIT lifecycle, protected cursor,
stable timestamp-plus-alert-ID sort, 30-minute window, and cumulative 100-record
limit. This PR does not execute a live request.

## 2. Bounded Filters

The registry fixes:

- `data.win.system.providerName = Microsoft-Windows-Security-Auditing`; and
- `data.win.system.channel = Security`.

Every request must additionally provide exact string filters for:

- `agent.name`; and
- `data.win.system.eventID`.

Event ID remains a request filter so 4624 and 4625 can be checked independently
without adding a broader OR/terms operator. Both reviewed values compile, while
the live smoke owns the explicit `4624`/`4625` allowlist.

The projection remains limited to alert timestamp/ID, agent/manager identity,
and the two reviewed Windows objects. Raw payload, Wazuh rule conclusions, and
unreviewed fields do not enter the provider-neutral response.

## 3. Registry Selection And Compatibility

The adapter selects one registry from the single requested logical source:

| Logical source | Registry |
|---|---|
| `wazuh-alerts-sysmon-event1` | existing Sysmon Event ID 1 registry |
| `wazuh-alerts-windows-security-auth` | Windows Security authentication registry |

Unknown sources fail closed and never fall back to Sysmon. An explicitly passed
registry path must still match the request source. Existing Sysmon request,
cursor, response, and transport tests remain unchanged and green.

## 4. Done Criteria

- both registry and request fixture pass their public schemas;
- 4624 and 4625 compile only with exact host and Event ID filters;
- source selection cannot silently use another reviewed registry;
- query method, PIT path, TLS/read-only policy, projection, sort, window, and
  result bounds remain fixed;
- a sanitized authentication hit maps to `siem_query_response.v1` with Wazuh,
  alert, and Windows record identities kept distinct;
- provenance hashes every fixed and request filter value; and
- formatter, lint, focused tests, full tests, and whitespace checks pass.

## 5. Does Not Establish

This contract does not establish live connectivity, authorization, event
generation, alert delivery, field availability, pagination for this source,
raw archive completeness, native Windows parity, detection quality, account
compromise, or cross-platform pipeline execution.

The separately reviewed
[live smoke contract](wazuh_indexer_windows_security_auth_live_smoke_contract.md)
defines the bounded operator gate without upgrading these deterministic query
tests into live evidence.

## 6. Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest \
  tests/test_wazuh_indexer_windows_security_auth_query.py \
  tests/test_wazuh_indexer_query_adapter.py \
  tests/test_wazuh_indexer_transport.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
```
