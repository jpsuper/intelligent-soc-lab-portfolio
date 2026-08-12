# Windows Security Authentication Detection Contract

Evidence scope: deterministic atomic-rule evaluation for the two sanitized
Windows Security Event ID 4624/4625 normalized fixtures. See the
[Main Roadmap](../../roadmap/roadmap.md) for overall Windows and common-pipeline
status.

## 1. Purpose And Boundary

This contract adds one observation-only rule to the existing common atomic
detector:

```text
endpoint_events.v1 authentication event
  -> endpoint schema validation
  -> deterministic DSL evaluation
  -> canonical detection-list validation
  -> one auth-failure observation or a clean no-match
```

The rule observes a normalized authentication failure. It does not diagnose
the provider status, decide credential validity, label an attacker, or create
an Incident by itself. The Event ID 4624 success fixture is an explicit
no-match control; ordinary successful logons are not turned into atomic
detections by this slice. The separately reviewed
[common-entry contract](windows_security_auth_common_entry_contract.md)
validates how both results pass through the existing composition without
changing this rule.

The normalized input authority is
[`endpoint_events.schema.json`](../../../schemas/endpoint_events.schema.json).
The mapper policy remains in the
[Windows Security Authentication Normalized Mapper Contract](windows_security_auth_normalized_mapper_contract.md).

## 2. Rule Contract

The only new rule is:

```text
rule_id: authentication.windows_security_failure_observed
artifact: windows_security_auth_failure_observed
severity: low
```

Its complete match boundary is:

```text
source == windows_security
platform == windows
event_type == auth_failure
```

All three conditions must match exactly. A different source, platform, or event
type is a successful no-match, not an evaluation error. The rule does not
inspect `source_fields`, `failure_reason`, `status`, `sub_status`, username,
address, port, workstation, Logon Type, or authentication package.

The required DSL `severity: low` value is rule metadata. It is not an Incident
severity, malicious verdict, confidence, response priority, or claim that every
failed authentication is security-relevant.

## 3. Why Success Is A No-Match

Event ID 4624 has useful authentication semantics, but a single successful
logon is normal endpoint activity in many environments. This slice therefore
uses the 4624 fixture to prove that the failure-observation rule does not match
`auth_success`.

Future correlation may review success in relation to preceding failures or
other evidence. That would require a separate multi-event policy and fixture
set. It is not hidden inside this atomic rule.

## 4. Failure Evidence Boundary

Event ID 4625 means Windows recorded a failed logon. A single normalized
`auth_failure` can result from an operator mistake, stale credentials, service
configuration, background noise, testing, or malicious activity. This rule
does not distinguish among those explanations.

The provider `FailureReason`, `Status`, and `SubStatus` remain mapper
provenance. Omitting `source_fields` from an otherwise schema-valid normalized
event does not change rule matching. No NTSTATUS decoding, localization,
threshold, sequence, baseline, enrichment, or account-state lookup occurs.

No MITRE technique is assigned because this fixture proves only one provider
failure observation, not valid-account abuse, password guessing, credential
access, or another attacker behavior.

## 5. Canonical Detection Output

For the 4625 fixture, the existing common evaluator emits one canonical
detection containing the normalized event identity, host, target user, source
address, timestamp window, rule identity, observation artifact, and
`input[0]` evidence reference.

For the 4624 fixture, the evaluator returns an empty list. Empty output is a
valid no-match result and is recorded separately from evaluation failure.

The detector does not copy raw provider status into canonical detection fields.
The normalized event and its `raw_ref` remain the evidence boundary for source
review.

## 6. Exact Expected-Detection Parity

Static summaries keep normalized evidence separate from expected behavior:

```text
expected_normalized/windows-security-4624-network-logon-success-001.json
  -> common atomic detector
  -> expected_detection/windows-security-4624-network-logon-success-001.json
     matched_rule_ids: []

expected_normalized/windows-security-4625-network-logon-failure-001.json
  -> common atomic detector
  -> expected_detection/windows-security-4625-network-logon-failure-001.json
     matched_rule_ids:
       - authentication.windows_security_failure_observed
```

Tests require exact summary parity and also assert the full canonical detection
object for the failure case.

## 7. Done Criteria

This detection boundary is complete when:

- one rule matches only `windows_security` / `windows` / `auth_failure`;
- the 4624 success fixture is a clean no-match;
- the 4625 failure fixture emits exactly one canonical observation;
- normalized and expected-detection inventories match exactly;
- static expected summaries match deterministic evaluator output;
- the canonical detection preserves event identity and bounded evidence refs;
- rule matching is independent of provider status fields;
- route mismatches do not match;
- rule and evaluator do not mutate normalized input;
- rule metadata contains no attack, compromise, Incident, or response claim;
  and
- formatter, lint, focused tests, full tests, and whitespace checks pass.

## 8. Does Not Establish

This atomic detection contract by itself does not establish:

- repeated-failure thresholds, password spraying, brute force, or correlation;
- that a failed logon used an invalid password or credential;
- that a successful logon is authorized, benign, or linked to a failure;
- malicious intent, account compromise, attacker identity, or attack success;
- the separately reviewed common-entry result as detection-rule evidence;
- authentication-specific Triage or Investigation quality;
- Case, Action, or response behavior;
- Wazuh conversion, query, alert coverage, or live transport support;
- native Windows collection or end-to-end parity;
- Active Directory or Domain Controller coverage; or
- live cross-platform validation.

## 9. Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest \
  tests/windows/security_auth/test_windows_security_auth_detection.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
```
