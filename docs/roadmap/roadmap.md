# AI SOC Lab Roadmap

[日本語](roadmap_ja.md)

This document is the English canonical source for current implementation status,
active priorities, incomplete work, sequencing, and Done Criteria.

For stable architecture, artifact contracts, evidence boundaries, and operating
policy, see the [AI SOC Lab Master Guide](../AI_SOC_Lab_Master_Guide.md).
For source-to-common defender processing responsibilities, see the
[Defender Event Processing Flow](../architecture/defender-event-processing-flow.md).
Phase-specific implementation history and validation evidence are retained in
[phase0.md](phase0.md) through [phase7.md](phase7.md).

---

# 1. Status Semantics and Non-Negotiable Boundaries

The following status terms are used deliberately.

- **Implemented**: repository code, schema, fixture, or documentation exists for
  the stated boundary.
- **Validated**: the stated boundary has supporting tests, fixture parity,
  controlled observation, or other explicitly named evidence.
- **Planned**: the work is intended but not implemented.
- **Deferred**: the work is intentionally outside the current sequence.
- **Unverified**: the implementation or behavior has not been demonstrated at
  the claimed evidence level.

Evidence and approval boundaries must not be upgraded during documentation work.

```text
fixture validation != live or runtime validation
manual observation != automated execution
attacker-side observed effect != defender-side telemetry or detection evidence
collection request generation != collector API execution or live result ingestion
pre-case investigation != post-action DFIR
candidate / export / recommendation != apply / deploy / update / promotion approval
```

Current safety and state boundaries:

- State-changing response and containment actions remain approval-gated.
- `investigation_result.json` remains separate from post-action DFIR outputs.
- `collection_result.json` may provide append-only Case enrichment but does not
  overwrite verdict, severity, confidence, approval, or detection state.
- Rule Improvement candidates and export artifacts remain review-oriented and
  do not authorize apply, deployment, runtime mutation, or promotion.
- Deception hits require deterministic defender-side trap observations.

---

# 2. Current State Summary

## 2.1 Implemented foundation

The repository contains a run-scoped, artifact-driven SOC research pipeline.

```text
scenario / attack
  ↓
telemetry / normalized events
  ↓
canonical detections
  ↓
dedupe / correlation / Incident selection
  ↓
triage
  ↓
pre-case investigation
  ↓
case
  ↓
action planning / approval boundary
  ↓
collection request
  ↓
mock, manual, or future collector result boundary
  ↓
post-action DFIR / reviewed enrichment
  ↓
comparison / Rule Improvement review artifacts
```

Implemented capabilities include:

- deterministic Linux detection and correlation foundations
- run-scoped Incident, Triage, Investigation, Case, and Action artifacts
- evidence-aware pre-case Investigation
- approval-aware playbook representation and Executor Agent boundaries
- TheHive Case and observable adapter MVP
- schema-validated Velociraptor `collection_request.json` generation
- `collection_result.json` contract, schema, controlled mock generation, and
  post-action DFIR workflow foundation
- Triage, Investigation, Action, and post-action DFIR comparison harnesses
- attacker execution, observed-effects, and structured runner artifact contracts
- additive attacker/defender observed-effects alignment signals
- Rule Improvement review, proposal, concrete candidate, narrow export, and
  validation-summary artifacts
- deterministic local-lab Deception inventory, hit, and Incident-bridge artifacts
- normalized endpoint event and Windows Sysmon Event ID 1 fixture contracts
- the Common Defender Pipeline v0 detector and bounded downstream composition

## 2.2 Current active workstream

The active workstream is **Windows cross-platform expansion**, extending the
Phase5 endpoint-telemetry and Phase6 common-pipeline foundations.

The current bounded implementation supports:

- Sysmon Event ID 1 source fixture parsing and normalized parity
- deterministic PowerShell process / encoded-command observation rules
- canonical detection-list validation and deterministic ordering
- platform-neutral dedupe-to-correlation execution using existing policies
- correlation-result-to-Incident construction
- exact supporting-detection-ID Incident selection and observation suppression
- deterministic Rule Triage per selected Incident
- evidence-aware pre-case Investigation per linked Incident/Triage pair
- Linux Scenario 009 and Windows Fixture A/B/C focused regression at the stated
  fixture boundary

This does **not** establish complete cross-platform execution validation,
Windows downstream analytical quality, or live Windows telemetry parity.

## 2.3 Current status baseline

| Area | Current status |
|---|---|
| Phase0–5 | Completed bounded MVPs |
| Phase6 | Extended MVP complete |
| Phase7 | Artifact-only MVP foundation complete; scenario YAML and runner deferred |
| Phase8 | Later; maintained in this Roadmap rather than a separate `phase8.md` |
| Common Pipeline v0 overall | Not complete |
| Full cross-platform execution validation | Not complete |
| Live Windows Detection-to-Incident/Investigation validation | Unverified / future |
| Rule Improvement export MVP | Complete for the current candidate-generation boundary |
| Rule Improvement apply, deploy, runtime update, and promotion | Unimplemented |
| Scenario 009 fixture path | Implemented and bounded |
| Scenario 009 canonical live-source selection and live integration | Deferred |

---

# 3. Phase Status and Ownership

Phase details below are summaries only. The linked phase documents retain
implementation history, scoped decisions, and validation evidence.

| Phase | Current status | Summary and authoritative detail |
|---|---|---|
| Phase0 | Completed bounded MVP | Minimal Attack → Log → Parse → Detect → Incident baseline. See [phase0.md](phase0.md). |
| Phase1 | Completed bounded MVP | Deterministic detection, correlation, and Incident construction. See [phase1.md](phase1.md). |
| Phase2 | Completed bounded MVP | AI-assisted Triage and machine-readable action planning with later approval-aware extensions. See [phase2.md](phase2.md). |
| Phase3 | Completed bounded MVP | Reproducible attacker scenarios, run isolation, traceable attack artifacts, and evaluation foundations. See [phase3.md](phase3.md). |
| Phase4 | Completed MVP + integration adapters | Case ownership, schema validation, TheHive adapter MVP, Investigation boundary, and DFIR request preparation. See [phase4.md](phase4.md). |
| Phase5 | Completed bounded MVP | Process telemetry, process-focused detection, action/execution boundary, and schema-validated collection-request generation. Direct Velociraptor API execution and live result ingestion are not claimed. See [phase5.md](phase5.md). |
| Phase6 | Extended MVP complete | Feature lifecycle, comparison harnesses, post-action evidence transport, attacker/defender alignment, and reviewed Rule Improvement export artifacts. Apply and promotion workflows remain unimplemented. See [phase6.md](phase6.md). |
| Phase7 | Artifact-only MVP foundation complete | Local-lab deception inventory, deterministic hit generation, and Incident bridge. Scenario YAML and safe runner remain deferred. See [phase7.md](phase7.md). |
| Phase8 | Later | Background activity and telemetry realism are defined in [Phase8](#7-phase8--background-activity-and-telemetry-realism). No separate `phase8.md` exists. |

---

# 4. Active Sequence

## 4.1 Completed prerequisites

The following workstreams are complete at their stated bounded evidence level.

```text
Phase6 extended MVP
  ↓
Triage / Investigation / Action comparison harness foundations
  ↓
Action → collection request boundary
  ↓
collection result contract and controlled post-action DFIR workflow
  ↓
attacker artifact contracts and observed-effects alignment
  ↓
Rule Improvement review and export MVP
  ↓
scenario-family policy, broader Linux mapping, and bounded Scenario 009 fixture path
  ↓
Windows Sysmon Event ID 1 fixture, parser, mapper, detection, and bounded common pipeline slice
```

## 4.2 Current work

1. Complete full Common Defender Pipeline v0 cross-platform execution validation.
2. Reconfirm Linux and Windows fixture regressions through the shared boundaries.
3. Keep identity run-local unless a separately reviewed persistent identity
   contract is introduced.
4. Preserve exact-ID Incident selection and the existing correlation-policy
   semantics during validation.

## 4.3 Next after Common Pipeline v0

1. Add Windows Slice 2 using a distinct multi-event Correlation shape based on
   PID/PPID and temporal relationships.
2. Run Linux and Windows Slice 1/2 regression through the same boundaries.
3. Fix the common execution spine as Common Pipeline v1 after the second slice
   validates the abstraction.
4. Improve Windows Triage, Investigation, and harness evidence quality without
   introducing Windows-specific downstream contracts.

## 4.4 Later work

- live Windows collection and Wazuh retrieval/conversion integration
- additional Windows telemetry sources such as Security 4624/4625 and Sysmon
  Event ID 3
- AD/DC coverage after standalone Windows telemetry stabilizes
- remaining Scenario 009 canonical-source and live-integration work
- additional post-action DFIR artifact parsers and collector mappings
- more practical attacker-agent behavior and optional SIEM integration
- Phase7 deception scenario YAML and safe runner
- Rule Improvement apply, deployment, runtime update, and promotion workflows

---

# 5. Common Defender Pipeline v0

## 5.1 Implemented subset

The implemented in-memory composition accepts canonical detections and executes
these boundaries in deterministic order.

```text
canonical detections
  ↓
validation and deterministic ordering
  ↓
dedupe
  ↓
existing fixed correlation policies
  ↓
correlation-result Incident construction
  ↓
exact-ID Incident selection / observation suppression
  ↓
deterministic Rule Triage
  ↓
evidence-aware pre-case Investigation
```

Implemented and focused-test validated:

- canonical detection-list input and output validation
- fail-closed duplicate detection ID and timestamp handling
- rule-distinct deterministic dedupe behavior
- fixed-order execution of the existing correlation policies
- correlation-result-to-Incident linkage
- exact supporting-detection-ID precedence for observation suppression
- one-to-one Incident/Triage linkage validation
- one-to-one Incident/Triage/Investigation execution
- Linux Scenario 009 and Windows Fixture A/B/C bounded fixture regression

Not implemented as a v0 requirement:

- correlation-to-correlation merge or suppression
- persistent aggregate artifacts
- stable identity across reprocessing or selection changes
- live Wazuh Windows integration

## 5.2 Remaining v0 work

- full cross-platform execution validation through the shared boundaries
- confirmation that the established Linux flow remains intact under the full
  validation sequence
- verification that all v0 Done Criteria below are satisfied together rather
  than only as isolated focused tests

## 5.3 Full Common Pipeline v0 Done Criteria

Common Pipeline v0 is complete only when all of the following are true.

- Linux and Windows `endpoint_events.v1` inputs can enter the common detector
  boundary where applicable.
- The shared spine covers detector invocation, dedupe/correlation, Incident,
  deterministic Rule Triage, and pre-case Investigation.
- Windows Slice 1 reaches the Incident boundary through common contracts.
- Existing Linux behavior remains regression-validated.
- Source-specific parsers, mappers, and rules are not forced into one
  implementation.
- Downstream stages consume canonical detections and common artifacts rather
  than native auditd or Sysmon shapes.
- Fixture, runtime, and attacker/defender evidence boundaries remain explicit.
- Live Wazuh Windows integration is not required for v0 completion.
- No Windows-specific Incident, Triage, or Investigation contract is introduced.
- Full cross-platform execution validation is recorded as complete with the
  exact commands and evidence used.

Current result: **not complete**.

## 5.4 Common Pipeline v1 entry conditions

Common Pipeline v1 begins only after:

- Windows Slice 2 validates a different multi-event Correlation shape
- Linux/Windows cross-platform regression passes
- post-Incident stages remain independent of native source formats
- the common run and harness artifact boundaries remain valid

---

# 6. Incomplete Work by Domain

## 6.1 Windows and cross-platform defender flow

Current:

- complete full v0 execution validation
- preserve bounded fixture evidence claims
- keep Windows analytical quality separate from structural parity

Next:

- Windows Slice 2
- cross-platform regression
- Common Pipeline v1
- downstream quality tuning

Later:

- live collection, Wazuh integration, additional telemetry, and AD/DC

## 6.2 Linux Scenario 009

Implemented:

- bounded fixture path
- controlled Wazuh evidence records and supporting documentation
- Scenario 009 advisory action-planning boundary

Remaining or deferred:

- canonical source selection
- source parity and normalization
- DSL detection and Incident consumption from the canonical source
- live integration

The fixture pipeline remains canonical until those steps are reviewed and
implemented. Historical Scenario 009 evidence must not be upgraded by later
controlled experiments.

## 6.3 Rule Improvement

Implemented current boundary:

- human-review input and classification artifacts
- proposal and concrete candidate bundle artifacts
- rule, prompt, parser, and promotion-recommendation export artifacts
- export-artifact validation summary
- deterministic local chain smoke coverage

Unimplemented:

- parser process-pipeline wiring
- telemetry and correlation candidate artifact export
- candidate apply
- rule, prompt, parser, telemetry, or correlation runtime update
- deployment and baseline update workflows
- promotion workflow and automatic promotion
- attack-to-detection-to-Rule-Improvement live E2E validation

`promotion_recommendation.yaml` remains recommendation-only.

Additional non-blocking Phase6 follow-ons, including multi-host correlation,
external intelligence enrichment, richer attack artifacts, and attacker
planning extensions, remain Deferred. See
[Phase6 Current Open Items](phase6.md#9-current-open-items).

## 6.4 Post-action DFIR and integrations

Implemented:

- collection request generation
- collection result schema and controlled mock outputs
- post-action DFIR parsing for the currently supported artifact set
- reviewed, boundary-preserving handoff artifacts

Remaining:

- actual Velociraptor API execution integration
- broader collector-output mappings
- additional artifact parsers
- explicit executor / collector result comparison where justified
- reviewed external Case updates beyond the current bounded integration

## 6.5 Deception

Implemented:

- artifact schemas and deterministic fixtures
- local-lab asset and hit generation
- deterministic Incident bridge

Deferred:

- scenario YAML
- safe scenario runner
- canonical detection output integration
- live/runtime deception validation
- automatic containment or Rule Improvement promotion

---

# 7. Phase8 — Background Activity and Telemetry Realism

Phase8 remains in this Roadmap because no separate `phase8.md` exists.

## 7.1 Goal

Generate controlled normal activity and noise so that detection, correlation,
triage, and Rule Improvement can be evaluated against realistic false-positive
pressure rather than attack-only telemetry.

## 7.2 Planned scope

Potential activity families include:

- periodic administrative SSH logins
- routine `sudo` operations
- package updates and backup scripts
- cron and scheduled-task activity
- Windows administrative PowerShell
- file-share access
- benign process chains that resemble isolated suspicious steps

## 7.3 Planned artifacts

```text
background_activity/
  linux_activity.yaml
  windows_activity.yaml
  background_activity_results.json
```

The exact schema and execution contract remain planned and must be introduced in
a focused contract PR before implementation.

## 7.4 Entry conditions

Phase8 implementation should begin only after:

- the common defender pipeline is stable enough to compare noisy and attack runs
- scenario/run identity and evidence linkage remain deterministic
- false-positive and tuning metrics are defined
- activity generation is bounded to the approved lab environment

## 7.5 Safety and evidence boundaries

- Background activity must remain deterministic and lab-scoped.
- Generated activity is not proof that defender telemetry was collected.
- Noise generation must not change approval or containment state.
- Tuning recommendations remain review-only until a separate apply workflow is
  approved and implemented.

## 7.6 Done Criteria

Phase8 is complete only when:

- Linux and Windows activity definitions have reviewed schemas
- execution produces traceable run-scoped result artifacts
- normal-activity telemetry can enter the same canonical defender boundaries
- attack and noise runs can be compared without identity collisions
- false-positive resilience and tuning effects are measured with explicit
  evidence
- no production, public, or unauthorized target is used

Current status: **Planned / later**.

---

# 8. Historical Planning Context

The original time-horizon plan grouped Phase0–2 into the first three months,
Phase3–5 into six months, and Phase5–8 into a twelve-month horizon. That plan is
retained only as historical context; it is not the current schedule.

Current sequencing is governed by [Active Sequence](#4-active-sequence) and the
Common Pipeline v0 Done Criteria.

Historical architecture, tool selection, and philosophy are retained in the
[Master Guide](../AI_SOC_Lab_Master_Guide.md) and phase documents rather than
duplicated here.

---

# 9. Completion and Review Checklist

Before changing a status or closing a Roadmap work item, confirm:

- the exact implementation boundary exists in code, schema, fixture, or docs
- the claimed validation level is named and supported
- attacker-side and defender-side evidence remain separate
- pre-case and post-action Investigation artifacts remain separate
- request, execution, and result-ingestion boundaries are explicit
- approval, apply, deployment, update, and promotion are not inferred from a
  candidate or recommendation artifact
- generated run artifacts are not committed as source unless deliberately
  curated as fixtures
- the relevant phase or design document retains detailed evidence and history
- English canonical status is updated before any Japanese synchronization
- links, anchors, code fences, and protected technical identifiers remain valid

Minimum docs-only validation:

```bash
git diff --check
! rg -n \
  'docs/roadmap/attacker-agent-roadmap\.md|\]\([^)]*phase8\.md(?:#[^)]*)?\)' \
  README.md README_ja.md AGENTS.md docs
```

The absence of a separate `phase8.md` is intentional.
