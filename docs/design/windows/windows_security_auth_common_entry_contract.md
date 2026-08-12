# Windows Security Authentication Common-Entry Contract

Evidence scope: bounded fixture execution from normalized Windows Security
authentication events through the existing common endpoint-to-Investigation
entry. See the [Main Roadmap](../../roadmap/roadmap.md) for overall Windows and
live-integration status.

## 1. Purpose And Boundary

This validation uses the existing public composition without changing its
implementation:

```text
endpoint_events.v1
  -> deterministic atomic detector
  -> canonical detection dedupe and fixed correlation policies
  -> Incident selection
  -> deterministic Rule Triage
  -> pre-case Investigation
```

The two authentication fixtures exercise different control paths:

```text
4624 auth_success
  -> no rule match
  -> five empty stage lists

4625 auth_failure
  -> one low-severity failure observation
  -> no correlation
  -> one Incident
  -> one Triage
  -> one Investigation
```

This is structural common-entry validation. It does not upgrade one failed
authentication into proof of an attack or claim that the existing generic
Triage and Investigation outputs provide authentication-specific analytical
quality.

The atomic rule boundary is represented by the public
[rule](../../../detection/dsl/windows_security_auth_failure_observed.yaml) and
[focused detection test](../../../tests/windows/security_auth/test_windows_security_auth_detection.py).
The public
[bounded live pipeline](../../../scripts/siem/wazuh_indexer_windows_security_auth_live_pipeline.py)
reuses this entry after Wazuh retrieval and conversion without changing the
common composition.

## 2. Public Entry

Both fixtures use the existing platform-neutral API:

```python
run_common_endpoint_to_investigation(
    endpoint_events,
    rules,
    endpoint_events_source=source,
    observation_incident_severity="low",
)
```

No Windows Security branch is added to `common/defender_pipeline.py`. The same
endpoint schema validation, deterministic rule ordering, detection validation,
dedupe, correlation, Incident selection, Triage, Investigation, and composition
validation used by existing Linux and Sysmon fixtures remain authoritative.

Input endpoint events and rule objects remain unchanged.

## 3. Stage Matrix

| Fixture | Detections | Correlations | Incidents | Triages | Investigations |
|---|---:|---:|---:|---:|---:|
| 4624 network-logon success | 0 | 0 | 0 | 0 | 0 |
| 4625 network-logon failure | 1 | 0 | 1 | 1 | 1 |

An empty success bundle is a valid no-match result. It is not a pipeline error,
missing telemetry claim, benign verdict, or proof that the successful logon was
authorized.

The failure observation does not satisfy any current multi-event correlation
policy. The Incident therefore uses the existing uncorrelated-observation
selection path rather than inventing an authentication correlation.

## 4. Identity And Linkage

For the failure fixture, run-local identities remain deterministic:

```text
det-000001
  -> inc-000001
  -> triage-inc-000001
  -> investigation-inc-000001
```

The Incident retains the matched detection ID, rule ID, primary observation
artifact, one `input[0]` timeline reference, host, target user, source address,
and normalized time window. It has no correlation ID or attacker-side attack
identity.

These identities are deterministic within the bounded execution only. This
slice does not define persistent identity across reruns, selection changes,
fixture changes, or runtime ingestion.

## 5. Endpoint Evidence Linkage

The Investigation retains exactly one normalized endpoint event for the 4625
fixture and records the curated expected-normalized path as its endpoint input.
The evidence summary can state the bounded observed fact that endpoint
telemetry recorded failed authentication for the fixture host and target user.

The retained endpoint event remains the source for provider route, Event ID,
record ID, timestamp, account, source address, Logon Type, authentication
package, and failure tokens. The common composition does not reinterpret those
provider fields.

The 4624 no-match path produces no Incident or Investigation and therefore does
not attach the successful event to a downstream case artifact.

## 6. Existing Downstream Behavior

The selected failure observation reaches the existing generic Rule Triage and
pre-case Investigation implementations. This PR validates their list APIs,
identity linkage, endpoint-event retention, and evidence-boundary behavior only.

It does not add authentication-specific triage scoring, failure-code analysis,
thresholding, account enrichment, recommended actions, or investigation pivots.
Generic fallback language about absent process, SSH, or network context is not
treated as authentication-analysis quality evidence by this contract.

No Case, Action, approval, containment, or response artifact is produced.

## 7. Done Criteria

This common-entry slice is complete when:

- both fixtures enter the same public endpoint-to-Investigation API;
- the 4624 success fixture returns exactly five empty stage lists;
- the 4625 failure fixture returns stage counts `[1, 0, 1, 1, 1]`;
- the failure remains one uncorrelated low-severity observation;
- Detection, Incident, Triage, and Investigation identities link exactly;
- the Incident timeline retains the canonical event context and `input[0]`;
- the Investigation retains the exact normalized endpoint event and source path;
- the composition adds no attacker evidence, response, approval, containment,
  Action, or Case artifact;
- endpoint events and rules remain immutable; and
- formatter, lint, focused tests, full tests, and whitespace checks pass.

## 8. Does Not Establish

This bounded common-entry validation does not establish:

- authentication-specific Triage or Investigation analytical quality;
- that the existing Triage verdict is ground truth about the source event;
- malicious intent, credential validity, account compromise, or attack success;
- repeated-failure thresholds, password spraying, brute force, or correlation;
- a relationship between the 4624 and 4625 fixtures;
- persistent identity, Case creation, Action planning, or response execution;
- Wazuh alert coverage or native Windows collection completeness;
- that fixture execution alone establishes the separately reviewed live Wazuh
  common-entry result;
- native Windows export parity;
- Active Directory or Domain Controller coverage; or
- live cross-platform pipeline execution.

## 9. Validation

```bash
uv run ruff format --check .
uv run ruff check .
uv run pytest \
  tests/windows/security_auth/test_windows_security_auth_common_entry.py -q
uv run pytest tests -q
git diff --check origin/main...HEAD
```
