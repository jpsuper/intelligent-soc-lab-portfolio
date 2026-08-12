# Wazuh Indexer Live Transport, PIT Lifecycle, And Smoke Contract

Evidence scope: implementation and deterministic tests for a credential-
resolving, TLS-verifying, read-only Wazuh Indexer transport with bounded PIT
cursor pagination, a deterministic multi-page smoke runner, and bounded live
lab runs for its single-page behavior. The results establish only the alert-
plane retrieval and lifecycle claims defined below. Overall status and
sequencing remain owned by the
[Main Roadmap](../../roadmap/roadmap.md).

## 1. Purpose

This slice connects the reviewed query adapter to one real Wazuh Indexer:

```text
run ID + host + RFC 3339 anchor
  -> fixed plus/minus 15-minute query request
  -> registered Wazuh search plan
  -> runtime-only read-only connection resolution
  -> create a bounded Wazuh Indexer PIT
  -> TLS-verifying PIT search without redirects or retries
  -> optional protected cursor and same-PIT search_after resume
  -> bounded JSON response
  -> provider-neutral response parser
  -> confirm PIT deletion on final page, policy stop, or known failure
  -> sanitized live-smoke summary
```

The transport executes only the plan produced by
`wazuh_indexer_query_adapter.py`. It does not accept an arbitrary URL, method,
index, query body, hostless request, or wider time window from the caller.

## 2. Included Scope

The implementation includes:

- one connection identity, `wazuh_indexer_readonly`;
- runtime-only HTTPS origin, username, password, and optional CA-bundle
  resolution;
- HTTP Basic authentication for the current lab boundary;
- mandatory server-certificate and hostname verification;
- no redirects and no automatic retries;
- registered 3-second connect and 10-second read timeouts;
- a 5 MiB decoded response-body limit;
- exact HTTP, media-type, UTF-8 JSON, and backend-response validation;
- a registered 30-second Wazuh Indexer PIT create/search/delete lifecycle;
- protected same-PIT continuation with stable `search_after`;
- a cumulative 100-record limit across cursor calls;
- final-page, policy-stop, and known-failure PIT cleanup;
- partial PIT creation rejection and confirmed cleanup;
- safe error categories that do not retain connection values, backend error
  text, or exception text;
- one run-correlated live smoke request fixed to host and plus/minus 15 minutes;
- immediate same-process cursor continuation until the exact final page;
- an opt-in requirement that fails unless at least two pages are observed;
- page-count, cursor-resumption, request-fingerprint, stable-order, and final-
  cleanup assertions without retaining a cursor or PIT ID;
- a successful-smoke requirement of at least one complete, non-truncated,
  exact-total result;
- returned host, provider, Event ID, and channel alignment checks;
- backend record, Wazuh alert, and Windows event-record identity-presence
  checks; and
- sanitized alert-to-`systemTime` and `systemTime`-to-`utcTime` delta summaries.

Retries, token authentication, secret-manager plugins, raw archive retrieval,
pipeline ingestion, and broader live multi-page coverage remain separate work.
Detailed PIT semantics are recorded in the
[Wazuh Indexer PIT Lifecycle Contract](wazuh_indexer_pit_lifecycle_contract.md).

## 3. Runtime Connection Boundary

The committed source registry contains only a logical connection name and
transport policy. The following values exist only in the process environment:

```text
WAZUH_INDEXER_READONLY_URL
WAZUH_INDEXER_READONLY_USERNAME
WAZUH_INDEXER_READONLY_PASSWORD
WAZUH_INDEXER_READONLY_CA_BUNDLE  # optional when the system trust store is sufficient
WAZUH_INDEXER_CURSOR_FERNET_KEY   # required only when a continuation cursor is issued or used
```

The URL must be an HTTPS origin with no user information, path, query, or
fragment. The optional CA bundle must resolve to a file. There is no switch to
disable TLS verification.

Do not pass a password as a command-line argument, commit it to a dotenv file,
paste it into test fixtures, or include it in shell tracing. The runtime account
must have only the index-scoped permissions needed to create a PIT, search the
PIT, and delete that PIT by ID for `wazuh-alerts-*`; an administrative account
is outside this evidence boundary.

## 4. HTTP And Failure Semantics

The initial complete-page path issues the existing create, search, and delete
requests:

```text
POST https://<runtime-origin>/wazuh-alerts-*/_search/point_in_time
  keep_alive=30s
  allow_partial_pit_creation=false

POST https://<runtime-origin>/_search
  allow_partial_search_results=false
  pit.id=<runtime-only PIT ID>
  pit.keep_alive=30s

DELETE https://<runtime-origin>/_search/point_in_time
  pit_id=[<runtime-only PIT ID>]

redirects=false
TLS verification=true or an explicit CA-bundle path
timeout=(3 seconds connect, 10 seconds read)
```

When exact bounded results remain, the successful page returns an encrypted
cursor and omits delete. The next call authenticates that cursor and issues:

```text
POST https://<runtime-origin>/_search
  allow_partial_search_results=false
  pit.id=<protected existing PIT ID>
  pit.keep_alive=30s
  search_after=<protected stable timestamp and alert ID>

DELETE https://<runtime-origin>/_search/point_in_time
  pit_id=[<protected existing PIT ID>]
```

The resumed call never creates a replacement PIT. Delete is required after the
final page, cumulative 100-record stop, or a known failure after the PIT ID is
available. A caller-abandoned cursor is bounded by 30-second expiry; that expiry
does not confirm explicit deletion. Cursor validation and issuance share one
transport-start timestamp so response-transfer and parsing time do not extend
the returned cursor lifetime.

It does not retry. A later retry policy would need to define request identity,
attempt provenance, and the conditions under which a read-only POST can be
replayed.

Stable transport categories are:

```text
connection_config_error
transport_policy_error
tls_verification_failed
transport_timeout
connection_failed
transport_failed
authentication_failed
authorization_failed
backend_request_failed
backend_unavailable
response_too_large
response_parse_error
pit_creation_failed
pit_cleanup_failed
```

HTTP response bodies and underlying exception strings are not copied into
errors. A 401 is authentication failure, a 403 is authorization failure, other
4xx responses are rejected requests, and other statuses are backend
unavailability. Only HTTP 200 with an `application/json` UTF-8 object proceeds
to the existing response parser. Parser timeout and shard-failure semantics
remain fail closed.

Once a create response or validated cursor supplies a PIT ID, cleanup is
attempted after final-page success, policy stop, search failure, partial
creation, or parse failure. When cleanup is required, success is returned only
after deletion confirms the matching PIT. The PIT ID is never retained in a
stable output.

## 5. Live Smoke Procedure

### 5.1 Prerequisites

1. The Windows lab endpoint is enrolled in Wazuh and Sysmon Event ID 1 reaches
   the Wazuh alert plane.
2. The runner host can reach the Wazuh Indexer HTTPS origin.
3. A read-only Indexer account can create a PIT, search through it, and delete
   that PIT by ID for only the required alert indices.
4. The Indexer CA is trusted by the system or available as an external PEM
   bundle.
5. Shell command tracing is disabled.

### 5.2 Generate one controlled event

Run on the Windows lab endpoint:

```powershell
$runAnchor = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
Start-Process "$env:SystemRoot\System32\notepad.exe"
$runAnchor
$env:COMPUTERNAME
```

Record the printed UTC anchor and host for this run. They must not be replaced
with a time or host from another test run.

### 5.3 Load runtime values without command-line secrets

Run on the repository host. These prompts avoid placing credentials in shell
history:

```bash
read -r -p "Wazuh Indexer HTTPS origin: " WAZUH_INDEXER_READONLY_URL
read -r -p "Wazuh read-only username: " WAZUH_INDEXER_READONLY_USERNAME
read -r -s -p "Wazuh read-only password: " WAZUH_INDEXER_READONLY_PASSWORD
printf '\n'
read -r -p "CA bundle path (blank for system trust): " WAZUH_INDEXER_READONLY_CA_BUNDLE
export WAZUH_INDEXER_READONLY_URL
export WAZUH_INDEXER_READONLY_USERNAME
export WAZUH_INDEXER_READONLY_PASSWORD
export WAZUH_INDEXER_READONLY_CA_BUNDLE
```

Do not use `curl -k`, `verify=False`, or a committed environment file to make a
failing certificate check pass.

### 5.4 Execute the bounded smoke

After allowing the controlled event to reach the alert index, run:

```bash
uv run python scripts/siem/wazuh_indexer_live_smoke.py \
  --run-id windows-sysmon1-YYYYMMDDTHHMMSSZ \
  --host WINDOWS-HOSTNAME \
  --anchor 2026-01-15T01:02:03.123Z \
  > /tmp/wazuh-indexer-live-smoke-summary.json
```

The runner uses the maximum registered limit of 100 so an otherwise complete
30-minute query is less likely to require refinement. If the result still
exceeds 100, the smoke fails with `incomplete_live_result`; it must not be
treated as successful by ignoring the remaining events.

The output contains no base URL, username, password, CA path, host value, raw
event, process command line, or event identifiers. It contains a host hash,
counts, executed window, fixed-filter alignment, identity-presence counts, and
time-delta summaries. The full provider-neutral response remains in memory and
is not written by the runner.

### 5.5 Execute the bounded multi-page smoke

The multi-page smoke deliberately lowers the page size so the known 14-record
window cannot fit in one page. Generate one ephemeral Fernet key in process
memory, then require the runner to resume at least one protected cursor:

```bash
WAZUH_INDEXER_CURSOR_FERNET_KEY="$(
  uv run python -c \
    'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
)"
export WAZUH_INDEXER_CURSOR_FERNET_KEY

uv run python scripts/siem/wazuh_indexer_live_smoke.py \
  --run-id windows-sysmon1-20260810T221534Z \
  --host WIN-VICTIM01 \
  --anchor 2026-08-10T22:15:34.804Z \
  --page-size 5 \
  --require-multiple-pages \
  > /tmp/wazuh-indexer-live-multi-page-smoke-summary.json
```

The command reuses the previously reviewed run/window; it does not claim new
event generation or collection recency. A page size of 5 should produce three
pages for the observed exact total of 14. The smoke fails rather than passing
if the query fits one page, any page changes the exact total, request
fingerprint, or executed range, a continuation repeats, the cumulative result
exceeds 100, the final page remains incomplete, or final PIT deletion is not
confirmed by the transport.

The summary retains only page sizes and counts plus Boolean alignment results.
It never retains the runtime cursor key, protected cursor, `search_after`, PIT
ID, host value, record identifiers, or event contents.

The cursor capacity is deliberately larger than a single-index test token
because `wazuh-alerts-*` can resolve across many dated indexes and shards. A
bounded 128 KiB PIT ID and 256 KiB encrypted cursor are accepted; larger values
still fail closed and are never printed.

Clear runtime values after the run:

```bash
unset WAZUH_INDEXER_READONLY_URL
unset WAZUH_INDEXER_READONLY_USERNAME
unset WAZUH_INDEXER_READONLY_PASSWORD
unset WAZUH_INDEXER_READONLY_CA_BUNDLE
unset WAZUH_INDEXER_CURSOR_FERNET_KEY
```

## 6. Live Done Criteria

The transport implementation is reviewable when formatter, lint, focused
tests, full tests, and whitespace checks pass. The live evidence portion is done
only when one summary from the user's lab shows:

1. `status = passed`;
2. one or more exact, complete, non-partial, non-truncated hits;
3. host, provider, Event ID 1, and channel alignment;
4. all returned records contain the three separately counted identity fields;
5. alert/`systemTime` and `systemTime`/`utcTime` deltas are present for every
   returned record;
6. no TLS bypass, administrative credential, retry, wider window, or different-
   run event was used; and
7. the result remains labeled as bounded alert-plane retrieval evidence.

For the separate multi-page gate, the sanitized summary must additionally
show at least two pages, at least one cursor resumption, stable request-
fingerprint and `search_after` progression assertions, an exact cumulative
record count, and confirmed final-page cleanup. Deterministic tests alone do
not satisfy this live gate.

The first observed time-delta summary establishes the lab baseline; this PR
does not silently invent a generally acceptable clock-skew threshold. A
reviewed tolerance can be added only after the observed manager/Indexer and
provider-time relationship is understood.

### 6.1 Observed lab evidence

One read-only lab run completed on 2026-08-10 with an explicit external CA
bundle and no TLS bypass, retry, wider window, or administrative credential:

- run ID: `windows-sysmon1-20260810T221534Z`;
- request fingerprint:
  `sha256:560c5f1b83feda84a9fef74786f35506b1aae69d5eb72bd5483b73cbceb2fd76`;
- 14 exact hits from one physical alert source, all returned, non-partial, and
  non-truncated;
- host, provider, Event ID 1, and channel alignment for every record;
- backend-record, Wazuh-alert, and Windows-event-record identity presence for
  all 14 records;
- alert-to-`systemTime` delta range: 251.415 to 1239.179 milliseconds;
- `systemTime`-to-`utcTime` delta range: 1.244 to 4.648 milliseconds; and
- sanitized summary SHA-256:
  `35c98e83b98df1c57437efaef293436d088c313d8f15179a28538b3838b0a744`.

These values are the first observed lab baseline, not a generally approved
clock-skew tolerance. The summary remains outside the repository; no
credential, CA bundle, host value, raw event, command line, or record identifier
is committed.

This observed run used the pre-PIT one-request transport. It remains valid
bounded alert-plane retrieval evidence, but it does not establish live PIT
creation, PIT-backed search, or confirmed PIT deletion.

### 6.2 Observed PIT lifecycle evidence

The same bounded request was rerun through the PIT-enabled transport on
2026-08-10 with the existing read-only account and TLS verification:

- all 14 exact records were returned again, non-partial and non-truncated;
- no role change, TLS bypass, administrative credential, retry, or wider query
  window was used;
- process exit code 0 confirms that PIT creation, PIT-backed search, response
  parsing, and matching PIT deletion all succeeded; and
- sanitized summary SHA-256:
  `b75402666a153f150f4413528cc15a8260f2c44932bd300f6afed703d7534c62`.

The rerun reused the earlier controlled event and window. It establishes the
PIT transport lifecycle only; it does not establish new event generation,
collection recency, or continuous availability. The summary remains outside
the repository and contains no PIT ID.

### 6.3 Observed bounded multi-page evidence

The same bounded 14-record request was executed through the multi-page runner
on 2026-08-11 with the existing read-only account, TLS verification, and one
runtime-only cursor key:

- run ID: `windows-sysmon1-20260810T221534Z`;
- executed at: `2026-08-11T02:15:03.813398Z`;
- request fingerprint:
  `sha256:9864d0a5465825fd20a84f2c372cbc502e9e312807183874668e68f0a2ea596d`;
- page size 5 produced three pages with record counts `[5, 5, 4]` and two
  protected cursor resumptions;
- all 14 exact hits were returned from one physical alert source, non-partial,
  non-truncated, and without refinement;
- the request fingerprint and registered stable `search_after` progression
  remained aligned across pages;
- all 14 records retained backend-record, Wazuh-alert, and Windows-event-record
  identity presence plus the registered host/provider/Event ID/channel fields;
- the prior alert/provider time-delta ranges were reproduced for all 14
  records;
- process exit code 0 and `final_page_cleanup_confirmed = true` establish
  confirmed deletion after the final page; and
- sanitized summary SHA-256:
  `04dbe0a9c818307a70a1582cc189413ef96ce9df0b71dbf82fb481c172cf2ce3`.

The run intentionally reused the prior event and 30-minute window. It
establishes bounded live continuation through one Wazuh alert-plane PIT, not
new event generation, collection recency, raw archive completeness, or
continuous availability. The summary remains outside the repository and
contains no cursor key, cursor, `search_after`, PIT ID, host value, record
identifier, or event content.

## 7. Evidence Boundary

A passing summary establishes only that one run-correlated, host-bounded query
was authenticated, executed with TLS verification, returned a complete Wazuh
alert-plane response, passed the registered parser, and exposed an observable
time relationship.

It does not establish:

- raw archive or unalerted-event completeness;
- continuous collection or operational availability;
- detection coverage or rule quality;
- compromise, Incident, Triage, Investigation, or verdict correctness;
- live Windows downstream parity;
- Linux Scenario 009 live integration;
- full Common Defender Pipeline cross-platform validation; or
- an approved general clock-skew tolerance.

The observed multi-page result establishes live cursor reuse, stable
`search_after` progression, exact completion, and confirmed final-page deletion
only for this one bounded Wazuh alert-plane PIT query. It does not generalize
that result to other windows, sources, index mappings, result volumes, or an
abandoned cursor.

Zero hits are inconclusive and fail the smoke. They do not prove that Windows,
Sysmon, the Wazuh agent, the manager, or the raw archive lacked the event.

## 8. Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest tests/test_wazuh_indexer_query_adapter.py \
  tests/test_wazuh_indexer_transport.py \
  tests/test_wazuh_indexer_live_smoke.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
```

## 9. Primary References

- [Wazuh Indexer API getting started](https://documentation.wazuh.com/current/user-manual/indexer-api/getting-started.html)
- [Wazuh Indexer API security](https://documentation.wazuh.com/current/user-manual/indexer-api/securing-indexer-api.html)
- [Wazuh Indexer alert-query use cases](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html)
- [Requests SSL certificate verification](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification)
- [OpenSearch sort results](https://docs.opensearch.org/latest/search-plugins/searching-data/sort/)
- [OpenSearch date field](https://docs.opensearch.org/latest/mappings/supported-field-types/date/)
- [OpenSearch-compatible Point in Time API](https://docs.opensearch.org/latest/api-reference/search-apis/point-in-time-api/)
