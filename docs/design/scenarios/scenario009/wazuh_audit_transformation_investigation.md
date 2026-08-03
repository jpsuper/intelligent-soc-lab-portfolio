# Scenario 009 Wazuh Audit Transformation Investigation

Status: Stages 1-4 Completed / Controlled Content Preservation Confirmed

## Purpose

This plan defines an investigation to locate the transformation boundary between
the complete local Linux audit event groups and the observed Wazuh manager-side
representations for `scenario_009_suspicious_archive_staging`.

Core boundaries:

```text
attacker-side observed effect != defender-side observed artifact
semantic presence != deterministic grouping completeness
```

The investigation must distinguish missing collection from filtering, merging,
alternate representation, omitted identity, duplicate paths, and limitations in
the prior summary method.

## Status And Scope

Stage 1 existing bounded-evidence analysis is completed and recorded in
[Scenario 009 Wazuh Bounded Evidence Analysis](wazuh_bounded_evidence_analysis.md).
Stage 2 read-only deployed inspection is completed and recorded in
[Scenario 009 Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md).
Stage 3 version-matched source verification is completed and recorded in
[Scenario 009 Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md).
Stage 4 controlled validation is completed and recorded in
[Scenario 009 Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md).
It confirmed exact grouped-payload identity between one completed controlled
local event and manager `full_log`, plus successful manager rollback.

The existing Outcome C classification and canonical-source decision remain
unchanged.

## Current Evidence Summary

| Evidence property | Local auditd | Wazuh raw archive |
|---|---|---|
| Five expected operations | Confirmed | Confirmed |
| Audit serial | Confirmed | Confirmed for `SYSCALL` documents |
| `SYSCALL` | Confirmed | Confirmed |
| `CWD` | Confirmed | Not confirmed as serial-linked |
| `PATH` | Confirmed | Not confirmed as serial-linked |
| `EXECVE` | Confirmed where applicable | Not confirmed as serial-linked |
| `PROCTITLE` | Confirmed | Not confirmed as serial-linked |
| `EOE` or equivalent boundary | Not separately assessed; serial-based local grouping was confirmed | Not confirmed |
| Deterministic grouping | Confirmed | Not established from retained evidence; exact `full_log` values were not retained |
| Canonical source suitability | Sanitized centralized-auditd fixture is the baseline | Not established |

The bounded archive window contained `1026` valid JSON Lines documents and no
invalid lines. Fifty-five documents had strong scenario indicators; all
identified agent `001` / `ubuntu-victim01` and retained `full_log`. Locations
were `/var/log/audit/audit.log` (`21` documents) and `journald` (`34` documents).

Core local serials were `12174`, `12175`, `12176`, `12178`, and `12182`.
Supporting execution serials were `12173`, `12177`, and `12181`. The retained
structured summary contained one serial-linked document per known serial
classified as `audit.type=SYSCALL`. Exact `full_log` values were not retained,
so this does not prove `full_log` was `SYSCALL`-only. No separate serial-linked
`CWD`, `PATH`, `EXECVE`, or `PROCTITLE` document was confirmed in the retained
summary. Audit health remained enabled `1`, lost `0`, and backlog `0`.

## Problem Statement

The observed Wazuh path proves manager receipt and semantic presence of all five
operations. It does not yet preserve or expose enough serial-linked records to
reconstruct the deterministic event groups consumed by the existing auditd
parser.

Absence from the previous serial-linked archive summary does not prove permanent
record loss. Related records may never have been collected, may have been
filtered or merged, may be represented through `journald`, may omit serial
identity, may exist in another manager/indexer artifact, or may have been missed
by the summary method.

## Working Transformation Model

| Boundary | Current status | What is known or unknown |
|---|---|---|
| `ubuntu-victim01` auditd | Confirmed | Complete local multi-record groups were observed |
| `/var/log/audit/audit.log` | Confirmed | Controlled local source contained the expected records |
| Wazuh agent localfile collection | Product path confirmed; runtime parity pending | `v4.14.4` logcollector groups consecutive audit lines sharing a timestamp and serial before queue submission; exact Scenario-window grouped payload was not retained |
| Agent transport | Partially confirmed | The grouped message is the expected queue payload and manager receipt is confirmed; Scenario-window payload completeness is unknown |
| Manager remoted path | Partially confirmed | Current post-restart counters show no discard, but no Scenario-window transport trace exists |
| Decoder/analysis processing | Product path confirmed; runtime parity pending | `OS_CleanMSG()` initializes `full_log` from the incoming payload before decoding; structured fields remain lossy for repeated PATH and PROCTITLE |
| `archives.json` representation | Product serialization confirmed; exact retained values unavailable | JSON archive serialization forces `Eventinfo.full_log`; the retained summaries still lack exact Scenario 009 `full_log` values |
| Indexer/dashboard representation | Inspected for active archive path | Filebeat alerts are enabled and archives are disabled; no active Filebeat archive ingestion path was identified, and existing or historical indexer archive data was not inspected |

This model is conceptual. Component behavior must not be promoted from unknown to
confirmed without lab evidence or version-matched primary documentation/source.

## Investigation Questions

- Did the Wazuh agent read every audit record type from the local audit file?
- Were `CWD`, `PATH`, `EXECVE`, `PROCTITLE`, and `EOE` transported separately?
- Did decoder or analysis processing merge records into a `SYSCALL`-centered
  document?
- Are missing record types retained inside `full_log` or another field?
- Across the confirmed separate audit-log and journald inputs, are documents
  exact duplicates, semantic duplicates, or independent records?
- Can journald documents be deterministically associated with audit serials?
- Does each `full_log` contain one source record or a reconstructed event?
- Is the audit key retained across audit-log and journald representations?
- Is an earlier manager-side artifact available before decoder transformation?
- Does the indexer expose fields absent from the bounded archive summary?
- Can an existing adapter consume the representation without inventing grouping?
- Could a Wazuh-envelope adapter preserve semantics while explicitly marking
  group completeness as unverified?
- Is another collection mode required to preserve complete raw audit lines?

## Hypothesis Matrix

| ID | Hypothesis | Supporting evidence | Contradicting evidence | Evidence needed | Investigation method | Decision impact |
|---|---|---|---|---|---|---|
| H1 | Wazuh audit decoding produces one `SYSCALL`-centered archive document and omits associated record text | Historical structured summaries reported `audit.type=SYSCALL` | Stage 4 found six ordered record types in one controlled `full_log` despite structured `audit.type=SYSCALL` | Historical Scenario 009 `full_log` remains unavailable | Controlled test completed | Rejects a structured-field-only loss inference |
| H2 | Associated records are retained in `full_log` but the summary missed them | Source forces the incoming grouped payload into archive `full_log` | Stage 4 confirmed this behavior for one controlled event only | Do not generalize to the historical run | Controlled test completed | Establishes a bounded content-preserving archive path |
| H3 | The separate journald input preserves associated context without original audit serial identity | 34 historical journald-located documents retained scenario context | Stage 4 found no matching journald document and did not validate journald ingestion | Historical cross-input relationships remain unresolved | Not exercised by Stage 4 | Keeps journald supporting-only and non-additive |
| H4 | The agent failed to collect, group, or deliver every audit record | Historical retained summaries did not demonstrate complete groups | Stage 4 preserved all six controlled records once and in order | Historical Scenario 009 payload remains unavailable | Controlled test found no loss | Does not support a universal or historical no-loss claim |
| H5 | Grouped text was filtered or transformed before archive output | The initial harness snapshot appeared shorter than manager output | The completed local group and manager `full_log` had identical bytes and SHA-256 | Initial snapshot was incomplete | Controlled test completed | Rejects a Wazuh-transformation inference for the controlled event |
| H6 | Another manager, indexer, or export artifact preserves higher-fidelity content | The existing manager archive boundary preserved controlled content | Filebeat archive ingestion remains downstream; indexer data was not inspected | Canonical source suitability remains open | Existing archive boundary tested | Avoids treating indexing as a fidelity improvement |
| H7 | Separate audit-log and journald inputs create duplicate or overlapping representations | Both inputs are configured independently | Stage 4 found no matching journald document | Historical duplication remains unresolved | Not exercised by Stage 4 | Retains non-additive handling |

Stage 3 resolves the expected product grouping and archive path but does not
select a final observed lab mechanism. Current product assessments are recorded
in
[Scenario 009 Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md).

## Investigation Stages

### Stage 1: Existing Bounded Evidence Analysis

Status: Completed. Result: [Scenario 009 Wazuh Bounded Evidence Analysis](wazuh_bounded_evidence_analysis.md).

Use only retained bounded summaries and approved temporary analysis material. Do
not change the environment or commit raw windows.

- inventory JSON field names and document shapes
- compare every document associated with the eight known serials
- determine whether `full_log` is single-record, merged, or generated content
- classify journald documents by executable, syscall, path, command, timestamp,
  agent, and process identity where present
- identify exact duplicates within each source representation
- record limits where the retained material cannot answer a question

### Stage 2: Read-Only Deployed Configuration Inspection

Status: Completed. Result:
[Scenario 009 Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md).

- confirm active agent localfile entries
- determine whether journald collection is separately enabled
- discover relevant decoder and rule files from the deployment
- inspect active configuration and definitions read-only
- identify the component responsible for archive output
- determine whether archive output is before or after decoding
- confirm manager and agent versions

Do not edit configuration or restart services. Do not prescribe paths before
live discovery confirms them.

### Stage 3: Product Behavior Verification

Status: Completed. Result:
[Scenario 009 Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md).

The version-matched source establishes agent-side grouping by audit timestamp
and serial, manager `full_log` initialization from the incoming payload, and
forced `full_log` serialization into JSON archives. It also establishes lossy
structured-field coverage for repeated PATH records and PROCTITLE.

### Stage 4: Controlled Comparison

Status: Completed. Result:
[Scenario 009 Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md).

The controlled comparison matched six ordered local records to one manager
`full_log` by exact serial and unique target path. Original content was
contiguous and newline terminated. After newline removal and single-space
joining, the grouped representation matched the manager value by byte length
and SHA-256. The final classification is `EXACT_CONTENT_PRESERVED`; journald was
not validated, and rollback completed.

## Existing-Evidence Analysis Matrix

The completed eight-serial matrix, `full_log` limits, journald field boundary,
and duplicate classification are recorded in
[Scenario 009 Wazuh Bounded Evidence Analysis](wazuh_bounded_evidence_analysis.md).
The retained summaries support high-confidence correlation for the serial-bearing
audit-log documents, but they do not retain enough raw content to classify exact
`full_log` form or cross-location duplicates.

## Journald Investigation Boundary

Assess the 34 journald documents separately:

- whether they originate from the same commands as audit records
- retained syscall, executable, path, and command information
- audit serial in another field or format
- exact or semantic duplication of documents with Wazuh `location` `/var/log/audit/audit.log`
- independent detection value
- whether combination would inflate event counts

Matching timestamps and executables alone are not deterministic serial-level
correlation. Do not join representations on those fields alone.

## Full Log Assessment

Classify each relevant `full_log` as one of:

- original single audit line
- reconstructed multi-record event
- decoder-generated summary
- journald message
- other transformed content

Inspect record type marker, audit epoch and serial, raw key, syscall, `PATH`,
`CWD`, `EXECVE`, `PROCTITLE`, field ordering and escaping, and one-line versus
multi-line form. Record ambiguous cases rather than forcing a classification.

## Decoder And Collection-Path Inspection

Read-only discovery must identify:

- the active agent configuration responsible for audit-log collection
- separately active journald collection, if any
- relevant Wazuh decoder and rule definitions
- the manager component responsible for archive output
- whether decoded and raw archive representations are separate
- whether an original message exists before analysis
- version-specific behavior

No decoder name, deployed path, or processing sequence is assumed until
repository evidence, live discovery, or version-matched primary sources confirm
it.

## Duplicate Model

Classify candidate overlap as:

- exact raw-record duplicate
- same-serial and same-record-type duplicate
- transformed duplicate
- semantic duplicate across audit-log and journald representations
- unrelated concurrent administrative record

Cross-path evidence is parity or supporting evidence, not additive evidence.
Duplicate paths must not inflate canonical events or detections. Do not implement
a deduplication rule before stable identity fields are confirmed.

## Decision Criteria

### T1: Complete Multi-Record Representation Found

Wazuh may become a candidate canonical source. Proceed separately to sanitized
fixture and adapter design; normalization and detection remain separate work.

### T2: Transformed Records With Deterministic Identity

Define a narrow Wazuh adapter contract, preserve provenance, and verify semantic
parity before canonical selection.

### T3: Semantic Evidence Without Deterministic Grouping

Keep Wazuh as supporting observability, retain the centralized auditd fixture as
canonical, and do not infer grouping.

### T4: Collection Loss Confirmed

Document the exact loss boundary. Decide whether a configuration change or
alternative collection path is justified, and require a separate operational
design before changing the environment.

Stages 1 through 3 retain T3 as the best-supported classification for the
original Scenario 009 run, and Outcome C remains unchanged. Stage 4 provides
separate T1-equivalent controlled evidence that one bounded archive `full_log`
had exact grouped-payload identity with the completed local event after the
source-defined newline-to-space framing. It does not
recover the historical value or select a canonical Wazuh source.

## Canonical-Source Decision Boundary

Canonical source selection requires:

- stable host identity
- audit serial or equivalent stable event identity
- complete required record set
- deterministic grouping
- preserved `PATH` and command evidence
- reproducible extraction
- bounded duplicate handling
- feasible fixture sanitization

Semantic presence alone is insufficient.

## Planned Artifacts

Stage 1 produced the bounded evidence matrix, retained field limits, duplicate
classification, and T1-T4 narrowing in
[Scenario 009 Wazuh Bounded Evidence Analysis](wazuh_bounded_evidence_analysis.md).
Stage 2 produced the deployed collection and decoder-path record in
[Scenario 009 Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md).
Stage 3 produced the version-matched product behavior record in
[Scenario 009 Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md).
Stage 4 produced the controlled result in
[Scenario 009 Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md).
Later PRs may record a final source decision and downstream validation.

## Follow-On PR Sequence

1. `docs`: define this investigation. Completed.
2. `docs`: record offline bounded-evidence analysis. Completed.
3. `docs`: record read-only collection and decoder-path inspection. Completed.
4. `docs`: record version-matched primary-source product research. Completed.
5. `docs`: record the controlled-comparison result. Completed.
6. `docs`: record the final source decision. Future.
7. `test`: add a sanitized Wazuh fixture only if deterministic evidence is
   sufficient.
8. `feat/test`: implement a narrow adapter only after its contract is approved.

Do not combine those stages into this PR.

## Explicit Non-Goals

This plan does not modify Wazuh or auditd configuration, enable `logall_json`,
restart services, execute Scenario 009, create a raw archive or fixture,
implement inferred grouping or an adapter, modify parsers, add rules, or validate
Wazuh normalization, DSL detection, incident consumption, continuous ingestion,
Velociraptor, response, or containment.

It does not change Outcome C or the current canonical fixture decision and makes
no exfiltration, ransomware, credential-access, compromise, or real-data claim.

## Relationship To Existing Documents

- [Scenario 009 Overview](overview.md)
- [Wazuh / SIEM Validation Plan](wazuh_siem_validation_plan.md)
- [Wazuh Collection Environment](wazuh_collection_environment.md)
- [Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md)
- [Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md)
- [Wazuh Alerts Inspection](wazuh_alerts_inspection.md)
- [Wazuh Raw Archive Validation](wazuh_raw_archive_validation.md)
- [Centralized Rsyslog Auditd Collection](centralized_rsyslog_auditd_collection_validation.md)
- [Live Auditd Telemetry Smoke](live_auditd_telemetry_smoke_validation.md)
- [Temporary Wazuh Raw Archive Runbook](../../../operations/scenarios/scenario009/temporary_wazuh_raw_archive_validation.md)
- [Auditd Parser Contract](../../defender/auditd_parser_contract.md)
- [Wazuh Integration Design](../../wazuh_integration_design.md)

The environment, alert inspection, and Outcome C raw-archive record remain
unchanged. Stages 1 through 4 are complete; canonical source selection and
downstream validation remain separate future work.
