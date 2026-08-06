# Wazuh Integration Contract

## 1. Purpose

This document defines the architectural contract for using Wazuh as an
additional collection, alert, search, and evidence source in the lab.

Wazuh may provide endpoint collection, source-native decoding, basic native
alerts, File Integrity Monitoring (FIM), vulnerability information, and
bounded search through its API or indexer. It does not replace the lab-owned
deterministic detection, canonical artifact, Triage, Investigation, Case,
Action, or Rule Improvement boundaries.

The intended relationship is:

```text
Wazuh = collection, source-native processing, alerting, and search capability
Lab pipeline = canonical semantics, deterministic decisions, and reviewable handoffs
```

---

## 2. Contract And Status Ownership

This document owns:

- the role boundary between Wazuh and the lab pipeline;
- admissible collection, alert, and investigation-enrichment paths;
- adapter, validation, provenance, and fail-closed requirements;
- the boundary between Wazuh-native data and canonical lab artifacts; and
- the conditions for adding a new Wazuh-backed source or mapping.

The [Main Roadmap](../roadmap/roadmap.md) and
[Phase 6](../roadmap/phase6.md) own current implementation status, priorities,
sequencing, and validation depth. The
[Defender Event Processing Flow](../architecture/defender-event-processing-flow.md)
owns the common detector and downstream pipeline architecture.

Scenario-specific evidence and source-selection decisions belong in the
corresponding scenario documents. A deployed Wazuh component, searchable
record, native alert, or successful manager receipt does not by itself prove
canonical-source suitability, source parity, deterministic detection, or
Incident consumption.

---

## 3. Design Principles

### 3.1 Additive Integration

Wazuh is an additional source and operational capability. Existing parsers,
source-family artifacts, deterministic rules, and canonical downstream
contracts remain valid unless an intentional migration preserves their
semantics and provenance.

### 3.2 Lab-Owned Semantics

Wazuh fields and native alerts describe source-native observations. The lab
owns the canonical interpretation used by deterministic detection, deduplication,
correlation, Incident creation, Triage, Investigation, Case, and Action.

### 3.3 Explicit Canonicalization

Wazuh-native payloads must cross an explicit adapter or evidence-reference
boundary before downstream use. Product-specific field shapes must not spread
through shared pipeline stages.

### 3.4 Evidence-Bounded Claims

Every claim must stay within the retained evidence. Manager receipt is not
equivalent to complete record grouping. A native alert is not automatically a
canonical detection. Absence from an alert store does not prove collection
loss.

### 3.5 Fail-Closed Processing

Unsupported schemas, incomplete required fields, invalid mappings, ambiguous
source identity, or invalid adapter output must produce an explicit skip or
failure. They must not be silently repaired into a successful detection.

---

## 4. Responsibility Boundaries

### 4.1 Wazuh Responsibilities

Wazuh may provide:

- endpoint and log collection;
- source-native decoding and field extraction;
- native rules and alerts;
- FIM observations;
- vulnerability information;
- dashboard and bounded search capability;
- API or indexer retrieval; and
- source-specific operational metadata.

These capabilities are evidence sources. They do not define the lab's
canonical semantic model.

### 4.2 Lab Pipeline Responsibilities

The lab retains responsibility for:

- source adapters and schema validation;
- canonical or retained source-family artifacts;
- behavior-feature and detection semantics;
- deterministic rule execution;
- canonical detection results;
- deduplication and fixed correlation policy;
- Incident, Triage, and pre-case Investigation handoffs;
- Case and Action artifacts;
- approval and execution boundaries; and
- review-only Rule Improvement candidate workflows.

### 4.3 Prohibited Boundary Collapse

The integration must not:

- make Wazuh the lab detection DSL or semantic source of truth;
- forward product-native fields throughout downstream agents;
- treat a Wazuh alert as sufficient evidence for a Case or Action;
- treat a dashboard view as a reproducible pipeline artifact;
- let optional Wazuh evidence change an existing verdict without a separate
  reviewed contract; or
- bypass human approval for state-changing actions or candidate application.

---

## 5. Supported Integration Paths

### 5.1 Collection And Adaptation

A source-specific collector or adapter may retrieve Wazuh data and write a
bounded run artifact. The adapter must preserve source identity, retrieval
context, timestamps, and limitations.

Endpoint telemetry may map to `endpoint_events.v1` only when the mapping
preserves source meaning and satisfies the normalized endpoint event contract.
Existing SSH and Wazuh FIM paths may retain source-family artifacts until an
intentional migration is justified. Not every Wazuh source must map to
`endpoint_events.v1`.

### 5.2 Native Alert Path

A Wazuh-native alert may become lab evidence or a canonical detection input
only through an explicit mapping:

```text
Wazuh alert or source record
  -> source-specific adapter
  -> validated lab artifact or evidence reference
  -> registered deterministic detector or reviewed alert mapping
  -> canonical detection result
  -> common downstream pipeline
```

An alert must not be forwarded unchanged as a canonical detection. Mapping
logic must state which source fields support each lab-owned observation and
which source limitations remain.

### 5.3 Investigation Enrichment Path

Wazuh search may be added as optional, bounded evidence enrichment after
Incident and Triage:

```text
incident.json + triage_result.json
  -> bounded query request
  -> Wazuh API or indexer search
  -> validated evidence references and limitations
  -> investigation_result.json
```

A Wazuh query result may support factual pivots such as host, user, address,
path, hash, process, or source event identity. It must not independently
change detection, severity, approval, containment, or promotion state.

Missing optional Wazuh input must remain an explicit absence or skip. It must
not invalidate an otherwise supported non-Wazuh path.

---

## 6. Feature And Assessment Boundary

Detection and source adapters own observable facts. Triage and Investigation
own progressively richer interpretation.

```text
source observation
  -> behavior feature or source-family fact
  -> derived feature in Triage
  -> enriched feature in Investigation
  -> evidence-grounded assessment
```

Wazuh-native fields, rule IDs, groups, and alert levels may contribute source
context, but they are not substitutes for lab-owned behavior semantics.
Source adapters must not infer intent, campaign attribution, compromise, or
response priority from a product field alone.

Specific feature mappings belong in the relevant source, detector, or scenario
contract rather than this integration-wide document.

---

## 7. Search And Evidence Boundary

### 7.1 Alert Search

Alert data may be used when the retained alert fields support the intended
query or evidence claim. An alert-store search must record the query window,
pivots, source identity, and result limitations.

No matching alert means only that no matching retained alert was found under
the stated configuration and query. It does not prove that the agent or manager
failed to receive the underlying source event.

### 7.2 Raw Archive Search

Raw archive collection is an operationally sensitive, source-specific option,
not a universal prerequisite. Enabling archive storage may change data volume,
retention, and exposure. It requires a bounded operational plan and explicit
cleanup or restoration checks.

An archive representation must not be selected as canonical merely because it
contains more text than an alert. Canonical selection requires deterministic
identity, complete semantics for the use case, stable retrieval, provenance,
deduplication policy, and focused validation.

### 7.3 Scenario 009 Evidence Constraint

Scenario 009 currently provides a bounded evidence constraint for this
contract:

- the inspected `alerts.json` path exposed no matching Scenario 009 alert
  evidence under the observed configuration;
- a temporary `archives.json` validation confirmed manager receipt and semantic
  presence of all five expected operations;
- the retained historical summaries did not establish deterministic complete
  multi-record grouping or canonical-source suitability;
- a later controlled `full_log` experiment demonstrated preservation for one
  separate bounded event but did not recover or upgrade the historical run;
  and
- the centralized auditd fixture remains canonical until source selection,
  parity, normalization, detection, and Incident consumption are separately
  reviewed and implemented.

See:

- [Wazuh Alerts Inspection](scenarios/scenario009/wazuh_alerts_inspection.md)
- [Wazuh Raw Archive Validation](scenarios/scenario009/wazuh_raw_archive_validation.md)
- [Wazuh Audit Transformation Investigation](scenarios/scenario009/wazuh_audit_transformation_investigation.md)

Cross-path Wazuh and auditd observations are parity or supporting evidence, not
automatically additive evidence. Duplicate paths must not inflate event,
detection, or Incident counts.

---

## 8. Adapter And Provenance Requirements

A Wazuh adapter or search-export artifact must preserve enough metadata to
review the transformation. At minimum, the design must account for:

- source product and version when relevant;
- manager, agent, or source identity;
- source artifact or query reference;
- event time and retrieval time;
- query window and pivots for search results;
- source-native identifiers used for grouping or deduplication;
- adapter or mapper version;
- output schema version;
- validation outcome; and
- known omissions, transformations, or confidence limitations.

Raw or source-native evidence should remain separately reviewable when safe and
necessary. Canonical output must not overwrite the only retained source
representation.

Credentials, API tokens, private keys, passwords, and sensitive raw payloads
must not appear in generated evidence, logs, fixtures, or documentation.

---

## 9. Deduplication And Identity

Wazuh may expose the same underlying activity through alert, archive, indexer,
FIM, journald, syslog, or other paths. These records must not be counted as
independent facts without an evidence-backed identity policy.

A deduplication design must identify:

- stable source identifiers;
- event or group boundaries;
- timestamp precision and clock assumptions;
- transformations between collection stages;
- cross-path equivalence rules; and
- the behavior when identity is incomplete.

Do not invent a deduplication key before stable identity fields are confirmed.
Ambiguous records remain separate, explicitly limited evidence rather than
being silently merged.

---

## 10. FIM Boundary

Wazuh FIM may provide source-family observations about file creation, change,
permission, ownership, or deletion. The watched paths and operational settings
belong in environment-specific configuration and runbooks, not this general
contract.

A FIM observation establishes the recorded file-system fact only. It does not
by itself establish persistence, maliciousness, actor intent, or incident
severity. Those interpretations require deterministic rules and downstream
evidence.

---

## 11. Operational And Security Requirements

Wazuh-backed retrieval and validation must:

- use read-only, least-privilege access where possible;
- obtain credentials from approved runtime configuration rather than artifacts;
- bound queries by time, host, agent, or another explicit pivot;
- avoid unbounded raw-log export;
- record partial results, timeouts, and retrieval failures explicitly;
- validate outputs before downstream consumption;
- isolate run artifacts and avoid overwriting canonical evidence;
- require a separate operational change for persistent manager, agent, decoder,
  rule, archive, or indexer configuration; and
- preserve approval boundaries for any state-changing response.

Documentation or fixture work does not authorize a live configuration change.
A temporary collection change must define exact scope, restoration, and
verification before execution.

---

## 12. Non-Goals

This contract does not require or authorize:

- replacing the lab's Python detection or canonical artifacts with Wazuh;
- treating Wazuh as a universal parser or event schema;
- direct Wazuh-alert-to-Case or Wazuh-alert-to-Action automation;
- continuous ingestion as a Common Pipeline v0 requirement;
- full EDR behavior, automatic containment, or autonomous response;
- simultaneous Linux, Windows, Active Directory, and every Event ID rollout;
- a Wazuh parity claim without a selected canonical source and focused
  evidence;
- creation of a parity fixture from incomplete historical evidence; or
- automatic Rule Improvement application, deployment, or promotion.

---

## 13. Contract Acceptance Criteria

The Wazuh integration contract remains valid when:

- Wazuh and lab-owned responsibilities remain explicit;
- every consumed Wazuh input crosses a documented adapter or evidence boundary;
- product-native fields do not leak into common downstream stages;
- source provenance and transformation limitations remain reviewable;
- unsupported or invalid input fails closed or produces an explicit skip;
- optional Wazuh evidence cannot silently change an existing verdict;
- alert absence is not misrepresented as collection loss;
- canonical-source and parity claims remain evidence-backed;
- duplicate source paths cannot inflate canonical results;
- generated artifacts exclude credentials and sensitive payloads; and
- Action, containment, and Rule Improvement application retain separate
  approval boundaries.

---

## 14. Extension Conditions

Add a Wazuh source, adapter, native-alert mapping, or investigation query only
when a concrete evidence or operational need identifies:

1. the source artifact and retrieval boundary;
2. the canonical or retained source-family output contract;
3. provenance and source-identity fields;
4. deterministic mapping and validation behavior;
5. deduplication or ambiguity handling;
6. focused fixtures or bounded live evidence;
7. failure, absence, timeout, and partial-result semantics;
8. credential, retention, and data-volume controls; and
9. downstream consumers that remain within existing approval boundaries.

Implementation and validation status must be recorded in the Main Roadmap or
the relevant phase and scenario documents rather than duplicated here.

---

## 15. One-Line Summary

```text
Wazuh supplies bounded source evidence and search capability; explicit adapters,
lab-owned deterministic semantics, canonical handoffs, and approval boundaries
control how that evidence enters the SOC pipeline.
```
