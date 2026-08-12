# Common Pipeline v1 Entry Validation

## Purpose

This record fixes the bounded evidence required to begin Common Pipeline v1.
It does not introduce a new wire schema, persistent identity model, collector,
parser, mapper, or platform-specific downstream path.

The validated common entry remains:

```text
endpoint_events.v1 + explicitly selected deterministic rules
  -> canonical detections
  -> deterministic dedupe and fixed correlation policies
  -> exact-ID Incident selection
  -> deterministic Rule Triage
  -> evidence-aware pre-case Investigation
```

## Regression matrix

| Case | Dedupe | Correlation | Incident | Triage | Investigation |
|---|---:|---:|---:|---:|---:|
| Linux Scenario 009 bounded fixture | 1 | 0 | 1 | 1 | 1 |
| Windows Slice 1 Fixture A | 1 | 0 | 1 | 1 | 1 |
| Windows Slice 1 Fixture B | 2 | 0 | 2 | 2 | 2 |
| Windows Slice 1 Fixture C | 0 | 0 | 0 | 0 | 0 |
| Windows Slice 2 PID/PPID and time correlation | 3 | 1 | 1 | 1 | 1 |

The matrix uses the same `run_common_endpoint_to_investigation()` entry for all
cases. The Slice 2 correlation covers all three canonical detection IDs in one
Incident. Slice 1 observation detections remain separate when no correlation
policy covers them.

## Fixed v1 entry boundary

The validation fixes the following properties:

- Linux and Windows endpoint inputs use `endpoint_events.v1`.
- Detection output crosses the common boundary as canonical detections.
- The endpoint entry does not accept platform, scenario ID, source parser, or
  normalized mapper dispatch parameters.
- The endpoint entry passes canonical detections and the validated
  `endpoint_events.v1` envelope without synthesizing or routing optional auditd,
  Sysmon, Wazuh, SSH, Zeek, or process source-family evidence inputs.
- Dedupe and correlation remain deterministic and run-local.
- Incident selection represents every deduped detection ID exactly once.
- Triage and pre-case Investigation preserve exact Incident linkage.
- The common result remains the established five-list in-memory bundle.
- Required input and output validation remains fail closed.

Source-specific collectors, parsers, mappers, and rule content remain outside
this fixed spine. The generic Detection-to-Investigation composition retains its
existing optional evidence-enrichment inputs; existing retained source-family
paths are not migrated or removed by this validation.

## Evidence boundary

This record is supported by sanitized repository fixtures and deterministic
tests. It establishes bounded cross-platform structural validation only.

It does not establish:

- live Linux or Windows telemetry collection;
- live Wazuh retrieval or conversion;
- source-fixture parity for the curated Windows Slice 2 sequence;
- malicious intent, successful execution, compromise, or impact;
- persistent identity across runs or reprocessing;
- Windows Triage, Investigation, or AI-model analytical quality;
- containment, candidate application, deployment, update, or promotion approval.

Attacker-side artifacts remain outside this defender evidence path. Pre-case
Investigation remains separate from post-action DFIR.

## Done Criteria

The v1 entry boundary is validated when:

- the five-case regression matrix passes through one common entry;
- results are deterministic and inputs remain immutable;
- Slice 2 exact-ID coverage produces one correlation Incident without duplicate
  observation Incidents;
- the common handoff exposes no native-source or scenario-dispatch parameter;
- the established bundle, linkage, fail-closed, and evidence boundaries remain
  valid; and
- the complete repository test and lint suites pass.

## Validation commands

```bash
uv run pytest tests/test_common_defender_pipeline_v1_entry_validation.py -q
uv run pytest tests/test_common_defender_pipeline_v0_validation.py \
  tests/windows/sysmon_event1/test_windows_slice2_correlation.py \
  tests/test_common_detection_to_investigation_composition.py -q
uv run ruff check .
uv run pytest tests -q
git diff --check origin/main...HEAD
```
