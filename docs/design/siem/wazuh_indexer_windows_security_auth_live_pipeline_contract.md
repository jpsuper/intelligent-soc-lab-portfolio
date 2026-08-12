# Wazuh Windows Security Authentication Live Common-Pipeline Contract

Evidence scope: one bounded, read-only Windows Security 4625 alert query whose
complete results are converted and executed in memory through the existing
common endpoint-to-Investigation entry. This contract defines the harness and
records one reviewed 2026-08-11 live result at that bounded evidence level.

## 1. Purpose

The preceding live smoke established that exact Windows Security 4625 alerts
can be retrieved from Wazuh 4.14.4 with TLS verification and the existing
read-only account. This slice connects that reviewed result to the already
implemented Windows and common boundaries:

~~~text
bounded Wazuh 4625 response
  -> ephemeral in-memory hit projection
  -> reviewed Wazuh representation adapter
  -> Windows Security source parser
  -> endpoint_events.v1 mapper
  -> authentication failure observation rule
  -> common dedupe and fixed correlation policies
  -> Incident
  -> Rule Triage
  -> pre-case Investigation
  -> sanitized counts and alignment summary
~~~

The raw Wazuh response, adapted source events, normalized endpoint events,
detections, Incidents, Triage results, and Investigation results remain in
memory and are not written by this runner.

## 2. Bounds

- one logical source: `wazuh-alerts-windows-security-auth`;
- one exact host and Event ID 4625;
- centered query window from 1 through 1800 seconds, with 300 seconds as the
  default;
- one complete exact result containing 1 through 100 records;
- existing TLS-verifying read-only PIT transport with confirmed cleanup;
- one reviewed atomic rule:
  `authentication.windows_security_failure_observed`;
- no retry, redirect, TLS bypass, role widening, admin credential, cursor,
  archive query, Case, Action, approval, containment, or response; and
- one sanitized summary written to standard output only.

Event ID 4624 is excluded because a success alert may not exist on the Wazuh
alert plane and the current rule intentionally produces no Detection. Broader
authentication semantics belong to separate work.

## 3. In-Memory Projection

Each provider-neutral response record is reconstructed into the existing
allowlisted Wazuh hit-projection shape. Only fields owned by the reviewed
system and EventData mappings enter the strict projection. Additional Wazuh
enrichment fields are discarded before validation; missing required reviewed
fields still fail closed. The ephemeral identifier has the form:

~~~text
windows-security-4625-live-record-NNN
~~~

It is a run-local conversion label, not backend identity, persistent identity,
or evidence that a fixture was collected. Backend document ID, Wazuh alert ID,
Windows record ID, account, host, address, EventData values, and the complete
projection never enter the public summary.

The projection reuses the reviewed sentinel-omission policy. Only
`subjectUserName`, `subjectDomainName`, `workstationName`, `ipAddress`,
and `ipPort` may be absent and normalized to the source sentinel `-`.
Required target identity, logon, authentication, and 4625 failure fields remain
fail-closed.

## 4. Common-Entry Alignment

Every retrieved record must:

1. adapt to the Windows Security source contract;
2. parse and map to one `auth_failure` endpoint event;
3. match the reviewed failure-observation rule; and
4. remain represented by the deduped Detection raw-event references.

The existing dedupe boundary may merge adjacent observations. Therefore the
summary records both normalized-event count and represented-detection-event
count. These counts must remain equal even when the deduped Detection count is
smaller.

The current fixed correlation policies do not correlate this standalone
authentication observation. Correlation count must remain zero. Every deduped
Detection must produce one low-severity Incident, one Triage result, and one
Investigation result through the existing common composition validator.

## 5. Sanitized Summary

The public schema is
[`wazuh_indexer_windows_security_auth_live_pipeline_summary.schema.json`](../../../schemas/wazuh_indexer_windows_security_auth_live_pipeline_summary.schema.json).

It retains only:

- run label, Event ID, request fingerprint, and hashed host;
- bounded retrieval result and physical-source counts;
- adapted, normalized, represented, deduped, and downstream stage counts;
- Boolean conversion, raw-reference, linkage, and in-memory alignment; and
- the fixed rule ID and evidence boundary.

It excludes credentials, URL, CA path, PIT ID, backend/Wazuh/Windows record
identities, host value, account, address, source fields, endpoint events,
detections, Incidents, Triage, Investigation, and raw data.

## 6. Done Criteria

The offline harness is ready when:

- one and multiple sanitized fixture hits execute through every named boundary;
- Wazuh-omitted sentinels remain supported without weakening required fields;
- all normalized events are represented after dedupe;
- the exact 4625 rule and zero-correlation boundary remain fixed;
- stage linkage remains valid;
- the input response is not modified;
- stable CLI failures disclose no event or credential values;
- the summary passes its public schema and sanitization tests; and
- formatter, lint, focused tests, full tests, and whitespace checks pass.

The live gate is complete only when the existing controlled 4625 anchor produces
exit code 0 and a reviewed sanitized summary with equal retrieved, adapted,
normalized, and represented-event counts plus valid downstream linkage.

### 6.1 Reviewed live validation record

The first live common-pipeline attempt failed closed with
`representation_conversion_failed` because unreviewed Wazuh enrichment fields
entered the strict hit projection. The correction allowlists only fields owned
by the reviewed system and EventData mappings; it does not weaken the schema,
TLS verification, read-only role, or required-field handling.

The corrected runner passed on 2026-08-11:

- exit code and status: `0` / `passed`;
- retrieved, adapted, normalized, and represented records: `5 / 5 / 5 / 5`;
- deduped Detections and linked Incidents, Triage results, and Investigations:
  `4 / 4 / 4 / 4`;
- correlations: `0`;
- all pipeline-alignment checks: `true`;
- partial, refinement-required, and truncated flags: `false`; and
- sanitized summary SHA-256:
  `e4751c5af21ed7af17f841efa1b8226037fe67614d4c004b22fb600fc8bb9666`.

The five represented records and four deduped paths are consistent: the
existing dedupe boundary combined one adjacent observation while preserving
raw-event reference coverage for all five records. The summary retains no raw
response, native record, account, address, credential, Detection, Incident,
Triage, or Investigation artifact.

## 7. Does Not Establish

Even a passing result does not establish:

- raw archive or unalerted-event completeness;
- continuous runtime collection or Wazuh alert/detection coverage;
- credential validity, malicious intent, account compromise, or attack success;
- authentication-specific Triage or Investigation quality;
- brute force, password spraying, repeated-failure thresholds, or correlation;
- native EVTX/export parity or Active Directory/Domain Controller behavior;
- persistent identity, Case, Action, approval, containment, or response; or
- full Linux-and-Windows cross-platform pipeline validation.

## 8. Lab Procedure

Use the #465 environment and the same controlled anchor. Do not regenerate the
event merely to make a failed execution pass.

~~~bash
PIPELINE_RUN_ID="windows-security-auth-live-pipeline-$(date -u +%Y%m%dT%H%M%SZ)"
PIPELINE_RESULT=/tmp/wazuh-indexer-windows-security-auth-live-pipeline-summary.json

uv run python \
  scripts/siem/wazuh_indexer_windows_security_auth_live_pipeline.py \
  --run-id "$PIPELINE_RUN_ID" \
  --host WIN-VICTIM01 \
  --anchor 2026-08-11T07:15:59.218Z \
  --window-seconds 300 \
  > "$PIPELINE_RESULT"

PIPELINE_EXIT=$?
printf 'exit code: %s\n' "$PIPELINE_EXIT"
uv run python -m json.tool "$PIPELINE_RESULT"
sha256sum "$PIPELINE_RESULT"
~~~

## 9. Offline Validation

~~~bash
uv run ruff format --check .
uv run ruff check .
uv run pytest \
  tests/test_wazuh_indexer_windows_security_auth_live_pipeline.py \
  tests/test_wazuh_indexer_windows_security_auth_live_smoke.py \
  tests/windows/security_auth/test_wazuh_windows_security_auth_conversion.py \
  tests/windows/security_auth/test_windows_security_auth_common_entry.py \
  tests/test_wazuh_indexer_transport.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
~~~
