# Scenario 009 Wazuh / SIEM Validation Plan

Status: In Progress

## Purpose

This document defines the future validation contract for carrying real
`scenario_009_suspicious_archive_staging` auditd evidence through a Wazuh / SIEM
path and back into the existing canonical defender pipeline.

The validation must not introduce a second detection meaning. Wazuh may collect,
store, search, alert on, or enrich evidence, but the existing auditd parser,
endpoint converter, `suspicious_archive_staging` DSL rule, and incident builder
remain the comparison baseline.

Core boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

This plan now includes a confirmed environment record, a controlled
`alerts.json` inspection, and a bounded temporary raw-archive observation.
Manager receipt of all five Scenario 009 operations is confirmed, but complete
serial-linked multi-record grouping, canonical source selection, normalization,
detection, and live pipeline consumption remain unvalidated.

## Current Validated Baseline

The following fixture-driven ladder is complete:

1. Runner-only execution and target artifact creation.
2. Local auditd raw telemetry generation.
3. Centralized rsyslog collection and duplicate-forwarding correction.
4. Defensive exact-record deduplication and audit event grouping.
5. Conversion into schema-valid canonical endpoint events.
6. Exactly one DSL detection for archive creation.
7. One bounded, schema-valid incident.
8. Bounded triage, investigation, and advisory action planning.

These stages use a sanitized minimal live-derived centralized auditd fixture.
They do not use direct Wazuh ingestion or continuous production-log ingestion.

## Confirmed And Unresolved Infrastructure

The point-in-time environment record in
[Scenario 009 Wazuh Collection Environment](wazuh_collection_environment.md)
confirms a native-package Wazuh 4.14.4 manager, indexer, and dashboard on
`wazuh-server`, plus an active Wazuh 4.14.4 agent on `ubuntu-victim01`. The agent
is configured to collect `/var/log/audit/audit.log` and connect to the manager
over TCP 1514.

Manager `alerts.json` existed, while raw JSON archives were disabled through
`logall: no` and `logall_json: no`; `archives.json` was unavailable.

A controlled follow-on inspection is recorded in
[Scenario 009 Wazuh Alerts Inspection](wazuh_alerts_inspection.md).
The same run produced all five expected local auditd observations, but `31` new
`alerts.json` lines contained `0` matching scenario documents. Under the observed
configuration, `alerts.json` is not suitable as the canonical source artifact.
This result does not prove or disprove receipt of the underlying audit records.
A bounded raw-archive result is recorded in
[Scenario 009 Wazuh Raw Archive Validation Result](wazuh_raw_archive_validation.md).
Temporary `logall_json` enablement produced `1026` new archive documents and `55`
strong Scenario 009 documents. All five operations reached the manager with
stable core serials. The retained structured summary contained one serial-linked
document per known serial classified as `audit.type=SYSCALL`, but exact
`full_log` values were not retained; this does not prove `full_log` was
`SYSCALL`-only. `journald`-located documents lacked an extractable original
audit serial in the retained summary. Receipt is confirmed; complete grouping,
primary canonical source selection, parallel
rsyslog/Wazuh duplicate behavior, export strategy, and downstream behavioral
coverage remain unresolved.

A read-only deployed-path inspection is recorded in
[Scenario 009 Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md).
It confirmed separate agent-local audit-log and journald inputs, found the
deployed default audit decoder capable of parsing associated record text when
co-located in one input, strongly localized `archives.json` to the analysisd
output boundary, and found Filebeat archive ingestion disabled.

Version-matched product verification is recorded in
[Scenario 009 Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md).
It confirms agent-side grouping of consecutive records that share one audit
timestamp and serial, followed by archive `full_log` serialization of the
incoming grouped payload. A separate Stage 4 controlled comparison is recorded
in
[Scenario 009 Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md).
It confirmed `EXACT_CONTENT_PRESERVED` / T1-equivalent controlled evidence for
one six-record event while leaving the historical Scenario 009 T3 and Outcome C
unchanged.

## Validation Questions

The implementation must answer:

- Does `ubuntu-victim01` send the relevant auditd records through Wazuh, and
  which component collects them?
- Are original audit messages retained, or only decoded fields and alerts?
- Does transport split one audit event, duplicate records, or combine records?
- Are host, original timestamp, audit serial, audit key, syscall, success, UID,
  executable, `PROCTITLE`, `PATH`, and `CWD` retained?
- Can records from one audit event still be grouped deterministically?
- Can exact transport duplicates be removed without collapsing distinct `PATH`
  records?
- Can output satisfy the existing endpoint-events schema?
- Does the existing DSL still produce exactly one archive-creation detection?
- Are administrative, validation, failed, and unrelated events excluded?
- Can the existing incident and downstream boundary chain consume the result
  unchanged?

## Architectural Options

### Option A: Preserve Raw Auditd Records

Wazuh retains or exports original auditd message text. The existing auditd parser
remains the canonical semantic parser.

This gives the strongest parity with the current fixture and preserves grouping,
deduplication, `PATH`, and truncated `PROCTITLE` behavior. Its feasibility
depends on confirming that the selected Wazuh artifact retains complete original
messages and stable source identity.

### Option B: Add A Narrow Wazuh JSON Adapter

A generic adapter converts Wazuh archived events, stored documents, or alerts
into grouped auditd-equivalent objects accepted by the existing converter, or
directly into canonical endpoint events.

This supports Wazuh-native exports but adds a mapping boundary that must retain
original identity, expose parser warnings, and prove semantic parity. Direct
endpoint output is the fallback when reconstructing auditd-equivalent records is
not reliable.

### Option C: Use Wazuh Rule Output As Detection

Wazuh decoder or rule output becomes the primary detection source.

This may support operational alerting, but it creates parallel detection
semantics and makes fixture, Wazuh, and DSL results harder to compare. It is not
the recommended first implementation. Any later Wazuh-native rule must be
compared with the canonical DSL result rather than silently replacing it.

### Recommended Direction

Prefer Option A when complete original audit messages and event identity are
retained. The observed `archives.json` path does not yet satisfy that condition:
the retained structured summary classified serial-linked documents as
`audit.type=SYSCALL`, but exact `full_log` values were not retained and complete
grouping remains unverified. Do not implement Option B from this Outcome C sample alone. First
investigate another source or collection boundary that preserves the required
records, then decide whether a narrow generic adapter is justified. Preserve the
existing parser, endpoint converter, DSL rule, and incident builder as
canonical.

## Recommended Collection Boundary

Preferred conceptual flow:

```text
auditd on ubuntu-victim01
  -> confirmed Wazuh collection mechanism
  -> confirmed Wazuh manager or indexer storage
  -> sanitized minimal Wazuh export
  -> generic Wazuh extraction adapter
  -> grouped auditd-equivalent events
  -> existing convert_auditd_events()
  -> endpoint_events schema validation
  -> existing suspicious_archive_staging DSL
  -> existing incident and downstream boundary chain
```

If raw audit reconstruction is not reliable, the adapter may emit canonical
endpoint events directly. That decision requires evidence and must not add
scenario-specific semantics to a generic adapter.

## Source Artifact Contract

The source artifact is not yet selected.

| Candidate | Original message retention | Grouping potential | Administrative records | Intended role |
|---|---|---|---|---|
| Wazuh archives JSON | Historical run observed temporarily; all strong documents retained `full_log`, but exact values were not retained. Stage 4 separately retained one controlled value. | Historical group completeness unverified; controlled event had exact grouped-payload identity after newline removal and single-space joining | Historical run includes both audit-log and journald locations; Stage 4 validated audit-log only | Supporting observability; canonical selection remains open |
| Manager-side raw storage | Must be verified | Potentially strong if records are not rewritten | Likely; verify | Primary fallback candidate |
| Indexer-exported document | Depends on indexed fields and raw-message retention | Must be proven across split documents | Depends on query/export | Adapter input or supporting observability |
| Wazuh alerts JSON | Available, but a controlled run produced zero matching scenario documents | No grouping assessment possible for this scenario | Filtered by rule behavior | Not canonical under the observed configuration; supporting observability not confirmed |
| Agent-side audit log collected by Wazuh | Strong only if exported without loss | Strong before transport rewriting | Includes administrative records | Comparison source, not proof of manager-side SIEM storage |

The completed alert-file inspection excludes `alerts.json` as canonical input.
The bounded raw-archive observation confirms manager receipt but does not select
`archives.json` as canonical because complete multi-record grouping was not
preserved. Choose one primary source and one fallback only after a later source
observation proves stable original identity across all required audit records.
Example Wazuh filenames and paths must be verified against the deployed version
and configuration before being recorded as operational facts.

## Required Scenario Evidence

The Wazuh path must retain enough evidence to represent:

- staging directory creation
- `note.txt` creation
- `metadata.json` creation
- tar archive creation
- archive permission change

The current DSL remains archive-creation-focused. The tar evidence should retain,
where available:

- host `ubuntu-victim01` and user `victim01`
- process `tar` and executable `/usr/bin/tar`
- archive path ending in `staged_synthetic_files.tar.gz`
- command evidence containing `tar`, `-czf`, and `.tar.gz`
- original event timestamp
- audit serial or equivalent grouping reference
- audit key `scenario009_audit_smoke`
- source artifact and raw or normalized record reference

Directory creation, individual file creation, and `chmod` remain supporting
observations and must not independently trigger the current rule.

## Grouping And Deduplication Contract

One Linux audit event may contain `SYSCALL`, `EXECVE`, `CWD`, `PATH`,
`PROCTITLE`, and `EOE` records. Group records with stable original identity such
as host, audit timestamp, and serial. Wazuh transport or index identifiers must
not replace that identity.

Remove exact duplicate records defensively while preserving distinct `PATH`
records. Record both original and deduplicated counts. Potential duplicates may
come from parallel rsyslog and Wazuh collection, manager archives and alerts,
indexer re-export, repeated extraction, or fixture assembly.

One tar archive operation must yield one canonical event and one detection hit,
even if multiple transport copies exist.

## Wazuh Decoder And Rule Responsibility

Wazuh decoders and rules may support collection health, raw-event visibility,
operational alerting, troubleshooting, and metadata enrichment. The first
validation must not require them to replace auditd grouping, endpoint
normalization, the `suspicious_archive_staging` DSL rule, or canonical incident
construction.

A future Wazuh-native rule requires an explicit parity comparison covering
matched evidence, exclusions, severity, identity, and duplicate behavior.

## Administrative And Negative-Event Boundary

The Wazuh path must not create a scenario detection, incident, or downstream
chain from:

- `auditctl` administration or `CONFIG_CHANGE`
- validation-time `grep`
- failed stale cleanup
- `mkdir` alone
- either synthetic file creation alone
- `chmod` alone
- duplicate copies of the tar records

Administrative selection belongs to explicit scenario-evidence extraction; the
generic parser must not be described as globally removing administrative events.
Attacker-side `ATTACK_EVENT_JSON` names remain attacker-side observed effects,
not defender telemetry or Wazuh evidence.

## Schema And Adapter Boundary

Adapter output preference:

1. Grouped auditd-equivalent event objects accepted by the existing converter.
2. Canonical endpoint events accepted by the existing endpoint-events schema.

Do not add a scenario-specific Wazuh schema. If a generic ingestion envelope is
later justified, it should preserve source product, source artifact, source event
identifier, collection and original timestamps, host, raw or normalized
references, parser warnings, and deduplication metadata. Schema design remains a
future decision and is not part of this PR.

## Validation Artifacts

A future implementation should create only the minimal curated artifacts:

- sanitized minimal Wazuh-exported fixture
- fixture provenance and sanitization record
- generic Wazuh extraction adapter
- focused adapter normalization and semantic-parity smoke tests
- Wazuh-path DSL detection smoke
- optional Wazuh-path incident bridge smoke if not transitively covered
- operational validation notes with commands, counts, and limitations

Do not commit full logs, large indexer exports, credentials, agent keys,
registration or enrollment tokens, certificates, secrets, or generated
`data/runs/**` artifacts.

## Provenance And Sanitization

Document the source host and component, collection window, Wazuh components and
versions, extraction method, original and deduplicated record counts, retained
audit serials or equivalent identifiers, sanitization steps, removed fields,
whether values are synthetic or real, and a checksum when repository conventions
support it.

The fixture must contain only lab-generated synthetic scenario evidence. Remove
secrets and unrelated host activity without reconstructing missing command text
or other unobserved values.

## Acceptance Criteria

Wazuh / SIEM validation is complete only when:

- `scenario_009` executes on `ubuntu-victim01`
- relevant defender records reach the selected Wazuh component
- a sanitized minimal fixture with provenance is exported
- grouping and exact-record deduplication are deterministic
- five scenario endpoint observations, or documented equivalent coverage, are
  normalized
- endpoint-events schema validation passes
- the existing DSL produces exactly one archive-staging detection for tar
- administrative, failed, unrelated, and duplicate records produce no extra hit
- the existing incident builder accepts the canonical hit
- existing fixture tests remain green
- no unsupported exfiltration, ransomware, credential-access, compromise,
  real-data collection, containment, or response-execution claim is introduced

## Explicit Non-Goals

This plan does not validate or implement:

- Velociraptor collection
- direct continuous production-log ingestion into the current parser
- replacement of the canonical DSL with Wazuh-native detection
- production retention, index sizing, high availability, or agent enrollment
- secrets distribution or certificate lifecycle
- real containment, auto-remediation, or destructive response
- Rule Improvement apply, deploy, update, or promotion
- malicious or real user-data collection, exfiltration, ransomware, or
  credential theft

## Proposed Implementation PR Sequence

1. `docs`: define this validation contract. Completed.
2. `docs`: record confirmed environment, versions, topology, and current artifact
   availability. Completed.
3. `docs`: record the controlled `alerts.json` inspection. Completed; no matching
   scenario evidence was observed.
4. `docs/operations`: define a bounded temporary `logall_json` validation with
   backup, duration, volume, rollback, sanitization, and cleanup boundaries.
   Completed in
   [Scenario 009 Temporary Wazuh Raw Archive Validation](../../../operations/scenarios/scenario009/temporary_wazuh_raw_archive_validation.md).
5. `docs`: execute and record the bounded raw-archive observation. Completed as
   Outcome C in
   [Scenario 009 Wazuh Raw Archive Validation Result](wazuh_raw_archive_validation.md).
6. `docs/design`: investigate the Wazuh collection and decoding boundary that
   retained serial-bearing structured `SYSCALL` evidence without retained proof
   of complete serial-linked groups. Stages 1 through 3 are completed in
   [Scenario 009 Wazuh Audit Transformation Investigation](wazuh_audit_transformation_investigation.md).
7. `docs`: record the controlled comparison of one exact local audit group and
   archive `full_log`. Completed as `EXACT_CONTENT_PRESERVED` in
   [Scenario 009 Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md).
8. `docs`: decide canonical Wazuh source suitability. Future.
9. `test`: add a sanitized minimal Wazuh parity fixture only after an Outcome
   D-quality source preserves deterministic complete grouping.
10. `feat/test`: add a generic extraction adapter with grouping, deduplication,
   schema validation, and negative administrative coverage only after source
   suitability is established.
11. `test`: add Wazuh normalization and semantic-parity smoke coverage.
12. `test`: add Wazuh-path DSL detection with exactly one tar hit.
13. `test`: add Wazuh-path incident consumption only if not already covered
    transitively.
14. `docs`: record final live validation commands, counts, limitations, and gaps.

Keep continuous ingestion, Velociraptor, and response execution in separate
plans.

## Decision Log

| Decision | Status | Evidence needed |
|---|---|---|
| Primary source: archives, manager raw storage, or indexer export | Open; `archives.json` is supporting only | Outcome C retained structured `SYSCALL` evidence for all five operations, but exact `full_log` values were not retained for parity assessment |
| Role of alerts JSON | Insufficient under observed configuration | Controlled run produced all five local auditd observations but zero matching alert documents |
| Role of archives JSON | Supporting observability confirmed; canonical suitability not established | `1026` new documents and `55` strong scenario documents; retained summaries did not preserve exact `full_log` values |
| Parallel rsyslog and Wazuh collection | Open | Compare source representations without additive event counting |
| Manager and indexer location | Confirmed on `wazuh-server` | Environment observation recorded |
| Adapter output level | Open | Field-loss comparison for auditd-equivalent versus endpoint output |
| Need for a generic Wazuh envelope | Open | Demonstrated metadata that existing contracts cannot preserve |
| Wazuh version handling | Deployed version confirmed as 4.14.4; compatibility policy open | Export-shape comparison across supported versions |
| Wazuh-native alerts as secondary evidence | Open | Parity results against canonical DSL detections |

## Validation Ladder After This Plan

1. Runner-only execution: completed.
2. Local auditd raw telemetry: completed.
3. Centralized rsyslog collection: completed.
4. Sanitized auditd normalization: completed.
5. DSL detection from normalized live-derived fixture: completed.
6. Detection-to-incident bridge: completed.
7. Incident-to-action boundary chain: completed.
8. Wazuh / SIEM validation plan: defined by this document.
9. Wazuh environment confirmation: completed.
10. Controlled `alerts.json` inspection: completed; local auditd had all five
    expected observations, while the manager alert file had zero matching
    scenario documents.
11. Temporary raw-archive validation procedure: defined and executed once.
12. Temporary raw-archive observation: completed as Outcome C; manager receipt
    and all five operations confirmed, while retained summaries did not
    demonstrate complete grouping and omitted exact `full_log` values.
13. Collection-path inspection and version-matched product verification: Stages
    1 through 3 completed; product source predicts agent-side grouping and
    archive preservation of the incoming grouped payload.
14. Controlled exact local-group to archive-`full_log` comparison: completed;
    exact grouped-payload identity confirmed for one controlled event.
15. Canonical Wazuh source selection: future; Stage 4 alone does not select it.
16. Sanitized Wazuh parity fixture extraction: future and blocked on an Outcome
    D-quality source.
17. Wazuh adapter normalization: future.
18. Wazuh-path DSL detection: future.
19. Wazuh-path incident consumption: future.
20. Velociraptor validation: future.
21. Direct continuous production-log ingestion: future.
22. Approved containment execution: future and separate.
