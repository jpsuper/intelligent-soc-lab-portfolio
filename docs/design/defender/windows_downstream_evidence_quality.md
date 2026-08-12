# Windows Downstream Evidence-Quality Slice

## Purpose

This slice validates that the existing common Triage, pre-case Investigation,
and deterministic Investigation-harness boundaries can retain useful Windows
fixture evidence without introducing a Windows-specific downstream contract.

It is intentionally smaller than a Windows analytical-quality or live-runtime
claim. The slice changes evidence grounding and linkage only; it does not tune
verdict, confidence, priority, risk, correlation severity, prompts, or models.

## Implemented Boundary

The shared downstream flow now provides three bounded mechanics.

1. Rule Triage projects otherwise-unknown canonical Incident `artifacts` or
   `primary_artifact` values into `summary`, `attack_story`, and
   `key_observations`. Existing assessment rules remain authoritative and
   unchanged.
2. Investigation binds an `endpoint_events.v1` envelope for a correlation
   Incident to its complete canonical `input[N]` `raw_event_refs`. Evidence
   records the selected refs and events; unrelated events in the same envelope
   do not become Investigation facts. Observation-level Incidents keep their
   established surrounding-context behavior because one detection ref is not
   necessarily an exhaustive Investigation evidence set.
3. The deterministic Investigation harness treats a non-empty command detail
   from a normalized endpoint command-execution fact as concrete specificity.
   The common rubric therefore does not require a Linux- or Windows-executable
   allowlist.

Legacy/direct Investigation callers and observation-level Incidents retain
their existing all-events behavior. For correlation Incidents, a mixed
`input[N]`/source-native reference set or an out-of-range `input[N]` reference
fails closed.

## Fixture Validation

The focused matrix covers:

- Windows Fixture A with an unrelated no-match event in the same endpoint
  envelope;
- Windows Fixture B through the existing Slice 1 Triage and Investigation
  regressions;
- Windows Fixture C through the existing no-match regression;
- Windows Slice 2 with both parent and child refs retained by its correlation
  Incident; and
- the existing deterministic Investigation `evidence_specificity` scoring
  function using normalized PowerShell command facts.

The matrix confirms canonical artifact grounding, exact event selection,
concrete observed facts, schema-valid downstream artifacts, deterministic
assessment preservation, correlation evidence preservation, and fail-closed
ambiguous linkage.

## Done Criteria

This bounded slice is done when:

- Rule Triage exposes canonical Windows artifacts without rule-ID, platform, or
  native-source dispatch;
- `verdict`, `confidence`, `priority`, and `risk_score` remain unchanged by the
  grounding change;
- each correlation Investigation includes only endpoint events selected by its
  Incident's complete canonical `input[N]` refs;
- missing, mixed, and out-of-range linkage behavior is explicit and covered;
- Windows Slice 2 retains both supporting endpoint events without turning the
  correlation into a compromise or maliciousness claim;
- normalized Windows command facts satisfy the existing deterministic harness
  specificity axis without a platform-specific executable list; and
- Linux/Windows common-pipeline and existing Triage/Investigation regressions
  continue to pass.

## Evidence Boundary

- A canonical artifact is an observed defender-side artifact, not proof of
  malicious intent, compromise, attack success, or response necessity.
- A correlation is a bounded time/identity relationship; it does not make every
  supporting event malicious.
- `endpoint_event_refs` identify selected events inside the provided canonical
  envelope. They are run-local linkage, not persistent evidence identity.
- Fixture output proves deterministic fixture behavior only. It does not prove
  source parity, live Sysmon/Wazuh/SIEM collection, or continuous execution.
- Missing network, HTTP, authentication, payload, and other pivots remain
  explicit in Investigation output.
- Pre-case Investigation remains separate from post-action DFIR evidence.
- Harness scores remain comparison evidence for human review. They do not
  approve apply, deployment, promotion, containment, or execution.

## Validation Commands

```bash
uv run pytest \
  tests/windows/sysmon_event1/test_windows_downstream_evidence_quality.py \
  tests/test_investigation_judge_endpoint_specificity.py -q
uv run pytest \
  tests/windows/sysmon_event1/test_sysmon_event1_triage_boundary.py \
  tests/windows/sysmon_event1/test_sysmon_event1_investigation_boundary.py \
  tests/windows/sysmon_event1/test_windows_slice2_correlation.py \
  tests/test_common_defender_pipeline_v0_validation.py \
  tests/test_common_defender_pipeline_v1_entry_validation.py \
  tests/test_common_detection_to_investigation_composition.py \
  tests/test_endpoint_events_investigation_enrichment.py -q
uv run ruff check .
uv run pytest tests -q
git diff --check origin/main...HEAD
```
