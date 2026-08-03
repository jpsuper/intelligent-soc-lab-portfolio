# DFIR Collection Result Ingestion Design

## 1. Purpose

This document defines how `collection_result.json` is consumed after a DFIR collection request has been executed.

The goal is to make collection outcomes and evidence availability visible while preserving the separation between:

```text
pre-case Investigation Agent
  → investigation_result.json

post-action DFIR / external integration workflow
  → collection_result.json and collected outputs
  → reviewed finding-based case enrichment / optional external case update
```

The canonical follow-on flow is:

```text
collection_request.json
  ↓
approval gate (when required)
  ↓
collection execution or manual collection
  ↓
collection_result.json
  ├─ outcome-only case enrichment: collection summary / evidence refs
  └─ post-action DFIR investigation workflow
       ↓
     factual observations, evidence gaps, follow-up pivots
       ↓
     optional reviewed finding-based case enrichment / external integration update
```

`collection_result.json` remains an evidence transport artifact. It records what was collected, failed, skipped, and where output is stored. It does not decide whether the host is compromised, whether severity should change, whether containment should be approved, or whether a rule should be promoted.

> **Boundary:** The post-action DFIR workflow is distinct from the pre-case Investigation Agent. It must not overwrite `investigation_result.json`, retroactively change pre-case investigation conclusions, or make collection status itself a security conclusion.

---

## 2. Current state and contracts

### 2.1 Pre-case investigation result

`investigation_result.json` is the output of the pre-case Investigation Agent. It is strict at the top level and currently requires core investigation fields such as `incident_id`, `summary`, `attack_story`, `evidence`, `enriched_features`, `evidence_level`, `evidence_summary`, `investigation_notes`, `timeline_notes`, and `recommended_next_steps`.

Its existing optional inputs are defender-side telemetry and enrichment artifacts, including `process_events.json`, `process_chain_hits.json`, `zeek_enrichment.json`, and `endpoint_events.json`.

`collection_result.json` is **not** an optional input to this pre-case artifact. Adding it there would invert the intended stage order:

```text
incorrect:
collection_result.json → investigation_result.json

correct:
investigation_result.json → case.json → action / collection
collection_result.json → post-action DFIR workflow
```

### 2.2 Case result

`case.json` allows additional top-level properties, so collection outcome facts can be appended without changing required case fields.

The following append-only enrichment is implemented:

```text
dfir_collection_summary
dfir_evidence_refs
```

These additions must not replace `summary`, `severity`, `status`, `coverage`, `detection_result`, `triage_result`, or `recommended_actions`.

### 2.3 Collection result

`collection_result.json` is implemented as a schema-backed outcome artifact with mock generation support.

It preserves:

- collection request / case / attack / scenario traceability
- collector and target context
- requested, collected, failed, and skipped artifact outcomes
- top-level and per-collected-artifact `output_refs`
- warnings and errors

The contract is collector-neutral: `mock`, `manual`, `velociraptor`, and future collectors can publish the same outcome model.

---

## 3. Ingestion principles

1. **Append only.**
   - Do not overwrite pre-case investigation or case conclusions.
   - Add collection status and evidence references as supplemental context only.

2. **Preserve request/result traceability.**
   - Keep links to `collection_request.json`, `case_id`, `attack_id`, `scenario_id`, `target`, and `collector`.

3. **Treat output references as evidence availability, not evidence interpretation.**
   - A collected `Linux.ProcessList` output means the artifact is available for review.
   - It does not by itself prove compromise, absence of compromise, or execution.

4. **Separate collection outcome from assessment.**
   - A completed collection can coexist with a limited pre-case evidence level.
   - A failed or partial collection is an evidence-availability limitation, not an automatic negative conclusion.
   - A collection result never changes verdict, severity, confidence, `overall_result`, `detected`, approval, or containment on its own.

5. **Keep the two investigation stages separate.**
   - Pre-case Investigation Agent: works from incident, triage, and defender-side telemetry to produce `investigation_result.json`.
   - Post-action DFIR workflow: works from `collection_result.json` and actual collected outputs to produce factual follow-on analysis.
   - The latter does not overwrite the former.

6. **Do not trigger automatic Rule Improvement promotion.**
   - Post-action DFIR findings may later support human-reviewable signals.
   - They must not directly populate `rule_candidates.yaml` or promotion recommendations.

---

## 4. Implemented case append-only ingestion

### 4.1 Optional run-based input

The case agent loads `collection_result.json` when it exists in the run directory:

```text
data/runs/<run_id>/collection_result.json
```

Absence of the file preserves existing case-agent behavior.

### 4.2 Case output additions

The implemented append-only fields are:

```json
{
  "dfir_collection_summary": {
    "collection_result_id": "collection-result-case-attack-proc-run-0033",
    "status": "completed",
    "collector_type": "mock",
    "requested_artifact_count": 3,
    "collected_artifact_count": 3,
    "failed_artifact_count": 0,
    "skipped_artifact_count": 0,
    "output_refs": [
      "data/runs/run-0033/forensics/mock/Linux.ProcessList.json",
      "data/runs/run-0033/forensics/mock/Linux.BashHistory.json",
      "data/runs/run-0033/forensics/mock/Linux.Syslog.SSHLogin.json"
    ]
  },
  "dfir_evidence_refs": [
    "data/runs/run-0033/forensics/mock/Linux.ProcessList.json",
    "data/runs/run-0033/forensics/mock/Linux.BashHistory.json",
    "data/runs/run-0033/forensics/mock/Linux.Syslog.SSHLogin.json"
  ]
}
```

`output_refs` are collected from both the top-level result and individual collected-artifact entries, with duplicate references removed.

### 4.3 Case fields that must not be changed

Collection result ingestion must not directly change:

```text
case.status
case.severity
case.summary
case.attack_result.overall_result
case.detection_result.detected
case.coverage
case.triage_result
case.recommended_actions
```

The current implementation adds only the two dedicated DFIR fields above. Analyst-note generation remains outside this ingestion step.

---

## 5. Post-action DFIR investigation workflow

### 5.1 Scope

The run-based MVP is a dedicated **post-action DFIR investigation workflow**, not an extension of the pre-case Investigation Agent.

Required run input:

```text
data/runs/<run_id>/collection_result.json
```

Collected inputs are files referenced by `collected_artifacts[*].output_refs`. Case, action, and collection-request paths are traceability references only.

Minimum responsibilities:

```text
1. Verify collection outcome and evidence inventory.
2. Check referenced outputs for availability and parseability.
3. Parse selected collected artifacts into factual observations.
4. Record collection limitations and evidence gaps.
5. Compare DFIR facts with pre-case evidence without overwriting it.
6. Propose follow-up pivots, human review, or optional external case updates.
```

### 5.2 Dedicated output artifact contract

The dedicated output contract is defined in `docs/design/dfir/post_action_dfir_investigation.md`. The artifact is named `post_action_dfir_investigation_result.json` and remains separate from `investigation_result.json`.

Its minimum content should cover:

```text
collection summary
evidence inventory
artifact parse results
observed facts with evidence refs
evidence gaps and collection limitations
recommended follow-ups / pivots
review-required state
optional reassessment proposal for human review
```

It must not automatically alter:

```text
pre-case investigation_result.json
case verdict / severity / status
action approval or containment decisions
Rule Improvement candidate / promotion state
```

### 5.3 Interpretation rules

- A collected artifact is an available evidence source, not a conclusion.
- Missing data from `Linux.BashHistory`, `Linux.ProcessList`, or other point-in-time artifacts is not proof that no activity occurred.
- Parsed findings may support or challenge the existing narrative, but any case reassessment remains proposal-only until reviewed.
- Actual content parsing, not collection status alone, is required before evidence-level or assessment changes are considered.

### 5.4 External integration behavior

TheHive or other case systems may be updated in two phases:

```text
initial case / observables
  ← case.json

post-action DFIR enrichment
  ← reviewed DFIR findings and evidence refs
```

The post-action workflow may propose an external update, but automatic updates should not be introduced before the output contract, review boundary, and test strategy are established.

---

### 5.5 Run-based MVP usage

```bash
uv run python agents/post-action-dfir-agent/src/main.py --run-id <run_id>
```

The required input is `data/runs/<run_id>/collection_result.json`; the output is `data/runs/<run_id>/post_action_dfir_investigation_result.json`. Current parser support is limited to `Linux.Syslog.SSHLogin`. Unsupported, missing, unreadable, or unparseable outputs are represented as gaps or limitations, never security conclusions. The workflow does not modify pre-case investigation, case, approval, containment, or Rule Improvement state.

The process pipeline keeps this stage off by default. Pass `--run-post-action-dfir` to opt in; the pipeline generates a mock collection result when a collection request exists and no result has been produced, then invokes the same run-based post-action workflow. A requested post-action stage fails clearly when `collection_result.json` is unavailable.

---

## 6. Status handling

| `collection_result.status` | Case append-only behavior | Current post-action DFIR workflow behavior |
|---|---|---|
| `requested` | Add summary with requested status when a placeholder result exists. | Do not parse; the workflow is not ready until an execution outcome exists. |
| `completed` | Add summary and evidence refs. | Inventory available outputs and parse selected outputs when present. |
| `partial` | Add summary with partial status and all available refs. | Preserve available outputs; record failed/skipped artifacts as collection limitations. |
| `failed` | Add summary with failure status. | Record the failure reason and produce no negative security conclusion from absence of outputs. |
| `skipped` | Add summary with skipped status. | Record the skip reason as an evidence-availability limitation. |
| `cancelled` | Add summary with cancelled status. | Record the cancellation and identify whether a new approved request is needed. |

---

## 7. Implementation phases

### Phase A — Contract and mock outcome generation — completed

- Define `collection_result.json` contract and schema.
- Provide sample-compatible mock result generation.
- Keep collection outcome generation separate from interpretation.

### Phase B — Case append-only enrichment — completed

- Use `RunPaths.collection_result` in case-agent.
- Load `collection_result.json` when present.
- Append `dfir_collection_summary` and `dfir_evidence_refs`.
- Preserve assessment and case decision fields.
- Test top-level and per-artifact output-reference collection.

### Phase C — Post-action DFIR workflow contract — completed

- Define the dedicated `post_action_dfir_investigation_result.json` artifact contract.
- Define input/output ownership and the human-review boundary.
- Specify how initial TheHive case creation differs from post-action enrichment.
- Keep `collection_result.json` out of the pre-case Investigation Agent.

### Phase D — Collected-output fixtures and limited parsing — MVP completed

- A controlled `Linux.Syslog.SSHLogin` fixture and factual parser are implemented.
- Run-based mock collection writes `forensics/mock/Linux.Syslog.SSHLogin.json`, references it through the collected artifact's `output_refs`, and can be consumed by the post-action workflow.
- Parse failures and collection limitations are recorded explicitly.
- Evidence level and assessment are not automatically upgraded.
- Broader mock output generation, additional parsers, and real Velociraptor collection ingestion remain follow-on work.

### Phase E — Collector integration and result comparison

- Add Velociraptor-native output mapping after the generic fixture/parser contract is stable.
- Define executor / DFIR result comparison only after post-action artifact semantics are stable.

---

## 8. Validation direction

Completed case-ingestion coverage:

```text
- collection_result completed or partial -> case has dfir_collection_summary
- output_refs are copied to dfir_evidence_refs
- top-level and collected-artifact output refs are deduplicated
- case severity/status/coverage and other assessment fields are unchanged
- absent collection_result preserves the previous case output
```

Post-action workflow coverage:

```text
- collection_result alone does not alter investigation_result.json
- missing output files are reported as evidence availability limitations
- parsed output produces factual observations tied to evidence refs
- partial/failed collection produces gaps, not negative security conclusions
- reassessment remains a human-review proposal
- Rule Improvement artifacts are unchanged by collection outcome alone
```

---

## 9. Non-goals

This design does not implement:

- direct modification of `investigation_result.json` from `collection_result.json`
- actual Velociraptor API execution
- parsing Velociraptor collection zip contents
- malware analysis of collected payloads
- automatic severity changes from collection status
- automatic containment approval
- automatic Rule Improvement candidate generation
- executor / DFIR result comparison harness

Those remain follow-on work after the documented post-action DFIR workflow contract is implemented and the limited parsing boundary is stable.
