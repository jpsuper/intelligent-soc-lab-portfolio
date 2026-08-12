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
- bounded Common Pipeline v1 entry validation across Linux and Windows Slice 1/2

## 2.2 Current active workstream

The active workstream is **Common Pipeline v1 stabilization and Windows
downstream evidence quality**, extending the Phase5 endpoint-telemetry and
Phase6 common-pipeline foundations.

The current bounded implementation supports:

- Sysmon Event ID 1 source fixture parsing and normalized parity
- deterministic PowerShell process / encoded-command observation rules
- canonical detection-list validation and deterministic ordering
- platform-neutral dedupe-to-correlation execution using existing policies
- a bounded Windows Slice 2 PID/PPID and 60-second parent/child Correlation
  fixture and policy
- correlation-result-to-Incident construction
- exact supporting-detection-ID Incident selection and observation suppression
- deterministic Rule Triage per selected Incident
- evidence-aware pre-case Investigation per linked Incident/Triage pair
- one shared endpoint-to-Investigation execution entry for Linux Scenario 009
  and Windows Fixture A/B/C at the stated fixture boundary
- one combined Linux Scenario 009 and Windows Slice 1/2 regression matrix
  through the same endpoint-to-Investigation entry
- a canonical handoff that adds no native-source or scenario-dispatch parameter
- canonical Incident artifact grounding in deterministic Rule Triage without
  changing its assessment rules
- correlation-Incident-scoped `input[N]` endpoint evidence binding in pre-case
  Investigation

This satisfies the Common Pipeline v1 entry conditions only at the bounded
fixture level. It does **not** establish Windows downstream analytical quality,
live Windows telemetry parity, or continuous runtime automation.

## 2.3 Current status baseline

| Area | Current status |
|---|---|
| Phase0–5 | Completed bounded MVPs |
| Phase6 | Extended MVP complete |
| Phase7 | Artifact-only MVP foundation complete; scenario YAML and runner deferred |
| Phase8 | Later; maintained in this Roadmap rather than a separate `phase8.md` |
| Common Pipeline v0 overall | Complete at the bounded fixture execution level |
| Full cross-platform execution validation | Validated for Linux Scenario 009 and Windows Slice 1/2 |
| Windows Slice 2 correlation boundary | Validated through the shared endpoint-to-Investigation regression |
| Common Pipeline v1 entry conditions | Satisfied at the bounded fixture level |
| Windows downstream evidence-quality slice | Publicly validated for canonical artifact grounding and correlation endpoint evidence binding; private-lab harness scoring is not published |
| Bounded live Windows 4625 Detection-to-Incident/Investigation validation | Validated for one complete five-record Wazuh alert-plane query; all five records remained represented after dedupe produced four linked Detection/Incident/Triage/Investigation paths |
| Bounded Wazuh Indexer live multi-page cursor smoke | Validated for one 14-record alert-plane PIT query across pages `[5, 5, 4]` with confirmed final deletion |
| Windows Security 4624/4625 bounded common-entry boundary | Validated from sanitized source through the existing endpoint-to-Investigation entry: 4624 remains empty and 4625 preserves one uncorrelated low-severity observation with exact downstream linkage |
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
  ↓
Windows Slice 2 PID/PPID and temporal Correlation
  ↓
Linux and Windows Slice 1/2 common-entry regression
```

## 4.2 Current work

1. Maintain the Linux and Windows Slice 1/2 regression through the fixed common
   entry boundary.
2. Maintain the bounded Windows Triage and Investigation evidence-quality
   regression without introducing Windows-specific downstream contracts.
3. Maintain the bounded Wazuh Sysmon Event ID 1 alert-hit conversion parity
   regression while keeping its fixture claim distinct from the separately
   completed alert-plane transport evidence and still-unverified native parity.
4. Maintain the bounded `wazuh-alerts-sysmon-event1` query-plan and
   complete-page response regression, including host/time/result bounds,
   refinement, partial-result rejection, and hashed provenance.
5. Maintain the bounded Wazuh Indexer PIT create/search/resume/delete lifecycle,
   including final-page, policy-stop, and known-failure cleanup semantics.
6. Maintain the encrypted, request-bound, 30-second Wazuh Indexer cursor,
   cumulative 100-record cap, and strict stable `search_after` progression while
   maintaining the deterministic runner and the bounded 2026-08-11 live
   three-page/final-deletion evidence.
7. Maintain the bounded Windows Security 4624/4625 source-fixture, parser,
   normalized-mapper, sanitized Wazuh alert-hit conversion parity, source
   registry/query regression, atomic-detection, and common-entry matrix together
   with the completed five-record 4625 live common-pipeline evidence, without
   inferring authentication-specific analysis, repeated-failure correlation,
   native parity, or continuous live integration.
8. Keep identity run-local unless a separately reviewed persistent identity
   contract is introduced.
9. Preserve exact-ID Incident selection and the existing correlation-policy
   semantics during validation.

## 4.3 Next after v1 entry validation

1. Review any further Windows downstream quality change against a concrete
   shared-contract or shared-rubric gap before implementation.
2. Maintain the completed live evidence gate for the credential-resolving,
   TLS-verifying, read-only Wazuh HTTPS transport and bounded smoke harness. The
   2026-08-10 lab run returned 14 exact, complete alert-plane records and
   established the first manager/Indexer and alert/provider time-field baseline
   without widening the evidence claim. A PIT-enabled rerun returned the same
   14 records and confirmed the bounded create/search/delete lifecycle with the
   existing read-only account. A 2026-08-11 bounded multi-page rerun returned
   pages `[5, 5, 4]`, resumed two protected cursors with stable ordering, and
   confirmed final-page deletion without retaining runtime state or raw events.
3. Maintain the completed bounded Windows Security 4625 live common-pipeline
   gate. The 2026-08-11 controlled query retrieved, adapted, normalized, and
   represented all five records; dedupe produced four linked
   Detection/Incident/Triage/Investigation paths, and the sanitized summary
   SHA-256 was
   `e4751c5af21ed7af17f841efa1b8226037fe67614d4c004b22fb600fc8bb9666`.
4. Prepare the remaining Linux Scenario 009 canonical live-source selection and
   bounded live common-pipeline integration without converting the existing
   fixture evidence into a live claim.

## 4.4 Later work

- live Windows collection and operational Wazuh retrieval integration
- Windows Security 4624/4625 native parity and broader live integration after
  the bounded alert-plane smoke is reviewed
- additional Windows telemetry sources such as Sysmon Event ID 3
- AD/DC coverage after standalone Windows telemetry stabilizes
- additional post-action DFIR artifact parsers and collector mappings
- more practical attacker-agent behavior and optional SIEM integration
- Phase7 deception scenario YAML and safe runner
- Rule Improvement apply, deployment, runtime update, and promotion workflows

---

# 5. Common Defender Pipeline v0 and v1 Entry

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

- one endpoint-fixture entry that invokes deterministic detection before the
  existing Detection-to-Investigation composition
- canonical detection-list input and output validation
- fail-closed duplicate detection ID and timestamp handling
- rule-distinct deterministic dedupe behavior
- fixed-order execution of the existing correlation policies
- correlation-result-to-Incident linkage
- exact supporting-detection-ID precedence for observation suppression
- one-to-one Incident/Triage linkage validation
- one-to-one Incident/Triage/Investigation execution
- Linux Scenario 009 and Windows Fixture A/B/C bounded fixture regression
- Linux Scenario 009 and Windows Slice 1/2 combined common-entry regression

Not implemented as a v0 requirement:

- correlation-to-correlation merge or suppression
- persistent aggregate artifacts
- stable identity across reprocessing or selection changes
- generalized or continuous live Wazuh Windows integration beyond the bounded 4625 gate

## 5.2 v0 validation record

The cross-platform validation matrix executes Linux Scenario 009 and Windows
Fixture A/B/C through the same endpoint-to-Investigation entry. It confirms the
established Linux flow, Windows match and no-match behavior, deterministic
Incident/Triage/Investigation linkage, input immutability, fail-closed endpoint
validation, and the bounded evidence exclusions together.

Exact validation commands:

```bash
uv run pytest tests/test_common_defender_pipeline_v0_validation.py -q
uv run pytest tests/test_common_detection_pipeline.py \
  tests/test_common_detection_to_investigation_composition.py \
  tests/windows/sysmon_event1/test_sysmon_event1_investigation_boundary.py -q
uv run ruff check common/defender_pipeline.py \
  tests/test_common_defender_pipeline_v0_validation.py
uv run pytest tests -q
```

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

Current result: **complete at the bounded fixture execution level**.

## 5.4 Common Pipeline v1 entry conditions

Common Pipeline v1 begins only after:

- Windows Slice 2 validates a different multi-event Correlation shape
  (validated at the bounded fixture level)
- Linux/Windows cross-platform regression passes (validated at the bounded
  fixture level)
- post-Incident stages remain independent of native source formats (validated
  for the common endpoint entry)
- the common run and harness artifact boundaries remain valid (validated for
  the established five-list in-memory bundle)

Current result: **entry conditions satisfied at the bounded fixture level**.

## 5.5 v1 entry validation record

The five-case matrix, fixed handoff properties, Done Criteria, evidence limits,
and exact validation commands are recorded in the
[Common Pipeline v1 Entry Validation](../design/defender/common_pipeline_v1_entry_validation.md).

This status begins v1 stabilization. It does not define v1 as a new wire schema,
persistent identity model, runtime service, or live cross-platform integration.

## 5.6 Windows downstream evidence-quality validation record

The bounded artifact-grounding and correlation-Incident-scoped endpoint
evidence-linkage mechanics, including Done Criteria and evidence limits, are
recorded in the
[Windows Downstream Evidence-Quality Slice](../design/defender/windows_downstream_evidence_quality.md).

The broader private lab's deterministic comparison-harness scoring is not part
of this public snapshot.

This validation does not establish Windows verdict or risk quality, model
quality, live collection, source parity, or post-action DFIR coverage.

## 5.7 Bounded Wazuh Sysmon Event ID 1 conversion record

The strict sanitized alert-hit projection, separate retrieval provenance,
Fixture A/B/C source conversion, and normalized semantic parity are represented
by the public
[Wazuh hit adapter](../../scripts/windows/sysmon_event1/adapt_wazuh_sysmon_event1_hit.py)
and its
[focused conversion test](../../tests/windows/sysmon_event1/test_wazuh_sysmon_event1_conversion.py).

This validation does not establish a live Wazuh connection, operational query
behavior, raw archive coverage, Wazuh rule quality, unalerted event coverage,
or live Windows parity.

## 5.8 Bounded Wazuh query-adapter record

The reviewed single-source registry entry, request/response schemas, offline
search-plan compiler, complete-page response parser, refinement behavior,
partial-result rejection, and hashed provenance are represented by the public
[query adapter](../../scripts/siem/wazuh_indexer_query_adapter.py) and its
[focused tests](../../tests/test_wazuh_indexer_query_adapter.py).

This validation does not establish credential resolution, HTTPS execution,
live index mappings, PIT pagination, live query success, raw archive coverage,
or end-to-end live source parity.

---

# 6. Incomplete Work by Domain

## 6.1 Windows and cross-platform defender flow

Current:

- maintain the bounded Common Pipeline v1 entry regression
- preserve the Windows Slice 2 PID/PPID and temporal Correlation behavior
- preserve bounded fixture evidence claims
- keep Windows analytical quality separate from structural parity
- maintain bounded Wazuh Sysmon Event ID 1 alert-hit conversion parity
- maintain the bounded Wazuh query-plan and response-parser regression
- maintain the deterministic runner and completed bounded live multi-page
  alert-plane evidence
- maintain exact Windows Security 4624/4625 source-to-normalized-to-common-entry
  fixture parity
- maintain the bounded Windows Security Wazuh conversion, source-registry,
  query/response, and offline live-smoke regressions
- maintain the bounded 2026-08-11 Windows Security 4625 live alert-plane
  evidence: five exact complete records, reviewed sentinel normalization, and
  sanitized summary SHA-256 only

Next:

- downstream quality tuning
- maintain the completed credential-backed Wazuh HTTPS and single-page PIT live
  smoke evidence plus the three-page cursor/final-deletion evidence
- review the observed manager/Indexer clock and alert/provider time-field
  alignment before noise cleanup
- validate the bounded in-memory Windows Security authentication live
  common-pipeline runner through the reviewed Wazuh representation adapter,
  normalized mapper, detection, and Common Pipeline entry, then execute it
  against the retained controlled 4625 anchor and keep only sanitized summary
  evidence

Later:

- Windows Security authentication native parity, broader live integration,
  additional telemetry, correlation policies, and AD/DC

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
