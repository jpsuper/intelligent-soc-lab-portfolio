# Post-action DFIR Investigation Design

## 1. Purpose

This document defines the dedicated **post-action DFIR investigation workflow** that follows a DFIR collection request and its recorded outcome.

The workflow consumes `collection_result.json` and the collected output files referenced by it. Its purpose is to produce factual, evidence-referenced follow-on analysis without modifying the earlier pre-case investigation or automatically changing operational decisions.

```text
pre-case Investigation Agent
  → investigation_result.json
  ↓
initial case / action planning / approval / collection
  ↓
collection_result.json
  ↓
post-action DFIR investigation workflow
  → post_action_dfir_investigation_result.json
  ↓
human review
  ↓
reviewed finding-based case enrichment / optional external case update
```

This document is the source of truth for the post-action workflow's artifact ownership and initial output contract.

---

## 2. Positioning and boundaries

### 2.1 Two investigation stages

The lab has two distinct investigation stages.

| Stage | Primary inputs | Primary output | Purpose |
|---|---|---|---|
| Pre-case Investigation Agent | incident, triage, defender-side telemetry, optional defender enrichment | `investigation_result.json` | Produce an attack story, evidence-aware context, enriched features, evidence gaps, and pivots before case and action planning. |
| Post-action DFIR investigation workflow | case, action, collection request/result, actual collected outputs | `post_action_dfir_investigation_result.json` | Verify availability of collected outputs, parse selected artifacts, record factual observations and limitations, and propose review-gated follow-up. |

The post-action workflow is **not** an execution mode or optional input of the pre-case Investigation Agent.

```text
incorrect:
collection_result.json → investigation_result.json

correct:
investigation_result.json → case.json → action / collection
collection_result.json + collected outputs → post_action_dfir_investigation_result.json
```

### 2.2 Assessment and action boundary

`collection_result.json` and `post_action_dfir_investigation_result.json` do not automatically change:

```text
investigation_result.json
case.status
case.severity
case.summary
case.attack_result.overall_result
case.detection_result.detected
case.coverage
case.triage_result
case.recommended_actions
action approval or containment state
Rule Improvement candidate or promotion state
```

Post-action findings can support a **review proposal**. A human review is required before any case reassessment, external case update, or follow-up action is accepted.

### 2.3 Collection outcome is not evidence interpretation

A collection outcome is only evidence availability metadata.

- `completed` means the collector reported completion; it does not prove that all referenced files exist, are readable, or contain relevant evidence.
- `partial`, `failed`, `skipped`, and `cancelled` are evidence-availability limitations. They are not evidence that no suspicious activity occurred.
- An output reference becomes investigation evidence only after the referenced content is available and a parser produces a factual observation tied to that reference.
- A missing item in a point-in-time artifact, such as `Linux.ProcessList`, is not proof of absence at the suspected execution time.

---

## 3. Canonical flow and ownership

```text
case.json
  ↓
action_result.json
  ↓
collection_request.json
  ↓
approval gate (when required)
  ↓
collection execution or manual collection
  ↓
collection_result.json
  ├─ outcome-only case enrichment (implemented)
  │    └─ dfir_collection_summary / dfir_evidence_refs
  ↓
post-action DFIR investigation workflow
  ├─ evidence inventory
  ├─ output availability and parseability checks
  ├─ selected artifact parsing
  ├─ factual observations and collection limitations
  └─ review proposal
  ↓
human review
  ├─ reviewed finding-based case enrichment
  ├─ optional external case update
  └─ optional follow-up action request
```

| Component | Owns | Does not own |
|---|---|---|
| Case Agent | Initial `case.json`; outcome-only `dfir_collection_summary` and `dfir_evidence_refs` when `collection_result.json` is present. | Parsing collected outputs; deciding post-action findings; changing assessment from collection metadata. |
| Action Agent / Executor Agent | Collection request generation, execution state, approval boundary, and execution record. | Interpreting collected evidence; reassessing a case. |
| Collection backend | Collection execution and `collection_result.json` outcome metadata. | Security conclusions; case reassessment; parser interpretation. |
| Post-action DFIR workflow | Evidence inventory, parsed factual observations, evidence gaps, recommended pivots, and review proposals. | Overwriting pre-case investigation; applying case/action/external changes automatically. |
| Human reviewer | Acceptance or rejection of reassessment, follow-up action, and external-update proposals. | Rewriting raw collection outcome history. |

---

## 4. Inputs and prerequisites

### 4.1 Required inputs

The run-based MVP requires `data/runs/<run_id>/collection_result.json`. If it is missing, the command exits non-zero with the expected path. Case, action, and collection-request paths are recorded for traceability but are not loaded or modified.

### 4.2 Run the MVP

```bash
uv run python agents/post-action-dfir-agent/src/main.py --run-id <run_id>
```

```text
input:
data/runs/<run_id>/collection_result.json

output:
data/runs/<run_id>/post_action_dfir_investigation_result.json
```

The output is validated against `schemas/post_action_dfir_investigation_result.schema.json` before it is written.

#### Optional process-pipeline integration

`scripts/run_process_pipeline.py` exposes `--run-post-action-dfir` as an explicit opt-in flag. It remains off by default. When enabled, the normal process pipeline completes its pre-case investigation, case/action generation, collection-request generation, and mock collection-result generation when needed before invoking the post-action DFIR workflow for the same `run_id`.

The integrated output is written to `data/runs/<run_id>/post_action_dfir_investigation_result.json`. The pipeline preserves repository-local imports for itself and its Python subprocesses, so callers do not need to set `PYTHONPATH=.` manually.

The separate `--export-ri-review-input` flag is also explicit opt-in and default-off. With both flags, post-action DFIR runs before review-input export. Without `--run-post-action-dfir`, export requires an existing post-action result; a missing source fails closed and no review input is fabricated. The review-only output is `data/runs/<run_id>/rule_improvement_review_input.json`.

### 4.3 Collected output references

The MVP resolves `collected_artifacts[*].output_refs`. Each requested, collected, failed, or skipped artifact is represented in `evidence_inventory`, and referenced outputs are classified as one of:

```text
available
missing
unreadable
unsupported
unparseable
not_collected
```

A parser must treat output data as untrusted input. It must not execute files, shell snippets, payloads, or commands found within collected output.

### 4.4 Optional inputs

The following artifacts may be read only for cross-reference and traceability; they do not become sources of new conclusions by themselves.

```text
investigation_result.json
process_events.json
process_chain_hits.json
endpoint_events.json
zeek_enrichment.json
decision_log.json
```

The workflow may state that a parsed fact is consistent with pre-case evidence, but it must preserve the source-specific evidence references for both sides.

---

## 5. Output artifact contract

### 5.1 Artifact name and path

The dedicated artifact is named:

```text
post_action_dfir_investigation_result.json
```

It is written under the run directory:

```text
data/runs/<run_id>/post_action_dfir_investigation_result.json
```

The MVP validates the output against `schemas/post_action_dfir_investigation_result.schema.json`.

### 5.2 Required top-level fields

The v1 contract should require the following fields.

| Field | Meaning |
|---|---|
| `post_action_dfir_investigation_id` | Stable ID for this post-action analysis run. |
| `schema_version` | Contract version, initially `post_action_dfir_investigation_v1`. |
| `run_id` | Run isolation key. |
| `case_id` / `attack_id` / `scenario_id` | Traceability to the original scenario and case. |
| `source_inputs` | References to the case, action, request, result, and optional pre-case evidence. |
| `collection_summary` | Normalized collection outcome metadata; not an assessment. |
| `evidence_inventory` | Per-artifact availability and output-reference inventory. |
| `artifact_parse_results` | Result of attempting to parse supported referenced outputs. |
| `observed_facts` | Parser-derived factual observations with exact evidence refs. |
| `evidence_gaps` | Missing, failed, unreadable, unparseable, or time-limited evidence. |
| `recommended_followups` | Review-gated next pivots or collection proposals. |
| `review` | Explicit human-review state and reasons. |
| `reassessment_proposal` | Optional, non-binding proposal for human review. |

### 5.3 Example shape

```json
{
  "post_action_dfir_investigation_id": "post-dfir-run-0033-001",
  "schema_version": "post_action_dfir_investigation_v1",
  "run_id": "run-0033",
  "case_id": "case-attack-proc-run-0033",
  "attack_id": "attack-proc-run-0033",
  "scenario_id": "scenario_006",
  "source_inputs": {
    "case_json": "data/runs/run-0033/case.json",
    "action_result_json": "data/runs/run-0033/action_result.json",
    "collection_request_json": "data/runs/run-0033/collection_request.json",
    "collection_result_json": "data/runs/run-0033/collection_result.json",
    "pre_case_investigation_json": "data/runs/run-0033/investigation_result.json"
  },
  "collection_summary": {
    "collection_result_id": "collection-result-case-attack-proc-run-0033",
    "status": "partial",
    "collector_type": "mock",
    "target": {"host": "ubuntu-victim01"},
    "requested_artifact_count": 3,
    "collected_artifact_count": 1,
    "failed_artifact_count": 1,
    "skipped_artifact_count": 1
  },
  "evidence_inventory": [
    {
      "artifact": "Linux.Syslog.SSHLogin",
      "collection_status": "collected",
      "output_refs": [
        "data/runs/run-0033/forensics/mock/Linux.Syslog.SSHLogin.json"
      ],
      "availability": "available"
    },
    {
      "artifact": "Linux.BashHistory",
      "collection_status": "failed",
      "output_refs": [],
      "availability": "not_collected"
    }
  ],
  "artifact_parse_results": [
    {
      "artifact": "Linux.Syslog.SSHLogin",
      "output_ref": "data/runs/run-0033/forensics/mock/Linux.Syslog.SSHLogin.json",
      "parser_id": "mock_linux_syslog_ssh_login_v1",
      "parse_status": "parsed",
      "record_count": 1,
      "warnings": []
    }
  ],
  "observed_facts": [
    {
      "fact_id": "fact-ssh-key-login-001",
      "fact_type": "ssh_key_login",
      "summary": "A public-key SSH login for victim01 was recorded on ubuntu-victim01.",
      "timestamp": "2026-06-19T00:00:01Z",
      "host": "ubuntu-victim01",
      "user": "victim01",
      "source_ip": "192.0.2.40",
      "evidence_refs": [
        "data/runs/run-0033/forensics/mock/Linux.Syslog.SSHLogin.json"
      ]
    }
  ],
  "evidence_gaps": [
    {
      "gap_type": "collection_failed",
      "summary": "Linux.BashHistory was requested but was not collected.",
      "related_artifacts": ["Linux.BashHistory"],
      "evidence_refs": []
    }
  ],
  "recommended_followups": [
    {
      "kind": "collect_artifact",
      "summary": "Collect file metadata or filesystem timeline evidence for /tmp/payload.sh when available.",
      "requires_human_review": true,
      "evidence_refs": []
    }
  ],
  "review": {
    "status": "not_reviewed",
    "required": true,
    "reasons": [
      "Collection was partial.",
      "Follow-up collection is proposed."
    ]
  },
  "reassessment_proposal": {
    "status": "insufficient_evidence",
    "summary": "The parsed SSH login supports the pre-case timeline, but the collected outputs do not independently establish post-login command execution.",
    "evidence_refs": [
      "data/runs/run-0033/forensics/mock/Linux.Syslog.SSHLogin.json"
    ],
    "requires_human_review": true
  }
}
```

### 5.4 Field rules

#### `source_inputs`

- Must reference the concrete run artifacts used for the workflow.
- May include `pre_case_investigation_json` only as a cross-reference.
- Must not imply that `investigation_result.json` was mutated.

#### `evidence_inventory`

- Must distinguish collection status from output availability.
- Must retain all relevant `output_refs`, even when a parser does not support them.
- Must not classify an artifact as `available` merely because the collection result says `completed`; the reference must be resolvable and readable.

#### `artifact_parse_results`

Allowed `parse_status` values in v1:

```text
parsed
unsupported
missing_output
unreadable_output
invalid_format
parse_error
not_attempted
```

A parse failure is recorded as an evidence limitation, not suppressed.

#### `observed_facts`

- Every fact must contain one or more `evidence_refs`.
- Facts must describe directly parsed content, not a generalized security verdict.
- Facts may be consistent with or challenge pre-case evidence, but they must not alter that artifact.
- No fact may claim that activity did not occur solely because it is absent from one collected artifact.

#### `evidence_gaps`

Recommended `gap_type` values:

```text
collection_failed
collection_skipped
collection_cancelled
missing_output
unreadable_output
unsupported_artifact
invalid_format
parse_error
time_scope_limit
retention_limit
```

#### `reassessment_proposal`

Allowed `status` values in v1:

```text
not_proposed
supports_existing_assessment
challenges_existing_assessment
insufficient_evidence
```

This is a review artifact only. It does not modify case assessment fields or cause an Action Agent invocation.

---

## 6. MVP parsing scope

### 6.1 Supported artifacts

Post-action DFIR parser coverage currently includes:

- `Linux.Syslog.SSHLogin`
- `Linux.ProcessList`
- `Linux.BashHistory`

Rationale:

- It maps directly to existing scenario_005 and scenario_006 SSH public-key login context.
- Timestamp, host, user, source IP, and authentication method can be expressed as factual observations.
- `Linux.ProcessList` is interpreted only as a point-in-time process snapshot. A matching command line may support a factual observation that the process was present at collection time.

The parser must emit only facts directly represented by the output, for example:

```text
public-key SSH authentication was recorded
host/user/source IP/timestamp were recorded
```

It must not infer payload execution, persistence, privilege escalation, or compromise from an SSH login alone.

The ProcessList parser must not turn a missing process into proof that a payload did not run. A process may have exited before collection or started afterward. Process absence therefore remains a timing limitation and must not support a host-clean or benign conclusion.

`Linux.BashHistory` is weak, user-controlled, timing-sensitive evidence. A matching entry may support only the factual observation that a relevant command appeared in collected shell history; it does not confirm execution. An absent entry does not prove non-execution and must not support a host-clean or benign conclusion.

The emitted fact uses `fact_type: shell_history_observation`. Its details record `evidence_strength: weak`, the `user_controlled` and `timing_sensitive` evidence characteristics, and `interpretation_scope: shell_history_entry_not_confirmed_execution`.

### 6.2 Deferred artifacts

The following artifacts are intentionally deferred until the fixture format and review behavior are stable:

```text
file metadata / filesystem timeline
payload file contents
Velociraptor-native collection ZIP output
```

Unavailable or unreadable BashHistory output remains an evidence gap or collection limitation, not a security conclusion. Future parsers must record time scope, collection timing, and coverage limitations before producing any negative statement.

### 6.3 Generic mock fixture envelope

Run-based mock collection now writes controlled output files for the supported artifacts at:

```text
data/runs/<run_id>/forensics/mock/Linux.Syslog.SSHLogin.json
data/runs/<run_id>/forensics/mock/Linux.ProcessList.json
data/runs/<run_id>/forensics/mock/Linux.BashHistory.json
```

Each corresponding collected-artifact entry in `collection_result.json` references its file with a run-relative `output_ref`. The generated envelope is collector-neutral:

```json
{
  "artifact": "Linux.Syslog.SSHLogin",
  "target": {"host": "ubuntu-victim01"},
  "collector": {"type": "mock", "name": "mock-result-generator"},
  "collected_at": "2026-06-19T00:00:01Z",
  "records": []
}
```

The envelope does not replace native collector output. It provides controlled input for the supported parsers. Broader mock output generation, additional artifact parsers, and ingestion of real Velociraptor collection output remain follow-on work.

---

## 7. Review and external integration policy

### 7.1 Review is required for finding-based updates

The workflow must set `review.required` to `true` when any of the following applies:

```text
parsed facts support or challenge a prior assessment
collection is partial, failed, skipped, or cancelled
an external case update is proposed
a follow-up collection or response action is proposed
parser limitations materially affect interpretation
```

A completed collection with no parsed findings may still have `review.required: false` only when the workflow makes no proposal and records no materially relevant limitation.

### 7.2 Case enrichment phases

```text
outcome-only case enrichment (implemented)
  - dfir_collection_summary
  - dfir_evidence_refs

reviewed finding-based case enrichment (future)
  - accepted factual findings
  - accepted evidence gaps
  - accepted investigation notes or timeline additions
```

The future finding-based enrichment must be append-only. It must preserve the original case assessment and record reviewer identity/time or an equivalent audit reference when accepted.

### 7.3 External case systems

TheHive or a future case system can receive:

```text
initial case / observables
  ← initial case.json

reviewed post-action enrichment
  ← accepted findings and evidence refs only
```

Automatic external updates are out of scope for the MVP. The first integration should produce an explicit update proposal or dry-run payload for review.

---

## 8. Pipeline and invocation boundary

The normal process pipeline produces the pre-case sequence through `collection_request.json`. It must not assume a `collection_result.json` exists.

The post-action workflow runs only after a collection backend or mock generator has produced `collection_result.json` and referenced outputs.

Current invocation:

```bash
uv run python agents/post-action-dfir-agent/src/main.py --run-id <run_id>
```

Future implementation may also support explicit file arguments for isolated tests, but the run-based path remains the primary contract.

The command does not rerun the pre-case Investigation Agent or replace any initial case artifact. `requested`, `failed`, `skipped`, and `cancelled` results produce no observed facts or security conclusions. Unsupported, missing, unreadable, or unparseable outputs are recorded as gaps or limitations.

---

## 9. Validation strategy

### 9.1 Contract tests

- `post_action_dfir_investigation_result.json` validates against its schema.
- Required traceability fields match `case.json`, `action_result.json`, `collection_request.json`, and `collection_result.json`.
- Output references are deduplicated and represented in the inventory.

### 9.2 Parser tests

- Run-based mock generation writes `collection_result.json` and the referenced controlled `Linux.Syslog.SSHLogin` output.
- A valid `Linux.Syslog.SSHLogin` mock fixture produces evidence-referenced `ssh_key_login` facts.
- Missing referenced output is recorded as `missing_output`, not as a negative security conclusion.
- Invalid output is recorded as `invalid_format` or `parse_error`.
- Unsupported output is retained in the inventory with `unsupported` status.
- Parser input is treated as data; no command, payload, or script is executed.

### 9.3 Boundary tests

- Running the post-action workflow does not change `investigation_result.json`.
- Running the post-action workflow does not change case assessment fields.
- A partial or failed collection generates evidence gaps but does not create a benign or negative conclusion.
- `reassessment_proposal` remains non-binding and requires human review.
- Rule Improvement artifacts are unchanged by collection outcome alone.

### 9.4 Scenario smoke target

Use scenario_006 as the initial smoke target.

```text
pre-case evidence:
ssh_key_login + process execution telemetry

post-action DFIR MVP:
Linux.Syslog.SSHLogin fixture
  → factual SSH public-key login observation
  → no automatic claim about payload execution
```

### 9.5 Result harness MVP

The deterministic result harness at `scripts/run_post_action_dfir_harness.py` evaluates one `post_action_dfir_investigation_result.json` against its source `collection_result.json`. The example entry point is `workflows/post_action_dfir_harness_example.yaml`, using `rubrics/post_action_dfir_generic_v1.yaml`:

```bash
uv run python scripts/run_post_action_dfir_harness.py \
  --workflow workflows/post_action_dfir_harness_example.yaml \
  --output-dir /tmp/post-action-dfir-harness
```

It writes `judge_input.json`, a schema-valid `judge_result.json`, `summary.md`, and `metadata.json`. The rubric scores:

- evidence inventory coverage
- observed fact grounding
- limitation and gap clarity
- post-action boundary safety
- recommended pivot quality

The harness is evaluation-only: it does not mutate pre-case investigation, case, action approval, containment, or Rule Improvement promotion state, and it does not generate promotion candidates. Its support classification now treats available, parsed `Linux.Syslog.SSHLogin`, `Linux.ProcessList`, and `Linux.BashHistory` outputs as supported. Unavailable outputs remain gap/limitation cases.

### 9.6 Rule Improvement review input exporter

`scripts/export_rule_improvement_review_input.py` deterministically projects a schema-valid post-action result into a schema-valid `rule_improvement_review_input.json`. It validates both schemas and preserves observed-fact provenance, evidence gaps, collection limitations, BashHistory weak-evidence markers, and ProcessList point-in-time scope. The output is review-only: `source_stage` is `post_action_dfir`, `human_review_required` is `true`, `promotion_allowed` is `false`, and emitted candidate hints keep `candidate_generation_allowed: false`.

The exporter does not feed either DFIR artifact into pre-case `investigation_result.json`, mutate case or action state, generate candidate or promotion YAML, or bypass existing candidate review and regression gates. The full contract is `docs/design/rule-improvement/post_action_dfir_review_input_contract.md`.

---

## 10. Implementation phases

### Phase A — Contract documentation — completed by this document

- Define output artifact name, ownership, required fields, and safety boundaries.
- Fix the separation from `investigation_result.json`.
- Define the first parser scope and review requirement.

### Phase B — Schema and mock output fixtures — MVP complete

- `post_action_dfir_investigation_result.schema.json` is implemented.
- Controlled `Linux.Syslog.SSHLogin`, point-in-time `Linux.ProcessList`, and weak-evidence `Linux.BashHistory` fixtures and parser tests are implemented.
- Run-based mock collection writes controlled outputs for all three supported artifacts under `forensics/mock/` and records their relative paths in the collected artifacts' `output_refs`.
- Broader mock collector output generation, additional artifact parsers, and real Velociraptor output ingestion remain deferred.

### Phase C — Workflow MVP — complete

- The run-based workflow builds evidence inventory and checks output availability.
- `Linux.Syslog.SSHLogin`, `Linux.ProcessList`, and `Linux.BashHistory` outputs produce evidence-referenced factual observations; ProcessList observations are limited to collection time, and BashHistory observations do not confirm execution.
- The workflow writes only the dedicated, schema-valid result artifact.

### Phase D — Case / external update proposal

- Generate append-only, reviewable finding-based case-enrichment proposals.
- Generate a dry-run external-case update proposal.
- Do not auto-apply either proposal.

### Phase E — Additional artifact parsers and comparison

- Add file-metadata parsers only with explicit limitation handling.
- Map actual Velociraptor output into the generic input boundary.
- Define executor / DFIR result comparison after post-action semantics stabilize.

---

## 11. Non-goals

This design does not implement:

- modification of pre-case `investigation_result.json`
- modification of `case.json`, including automatic reassessment or severity change
- automatic follow-up action execution
- action approval or containment-state changes
- automatic TheHive or external case updates
- Velociraptor API execution
- malware analysis or execution of collected payloads
- parsing arbitrary Velociraptor collection archives in the MVP
- Rule Improvement candidate generation or promotion
- executor / DFIR execution-result comparison harness; the post-action result-quality harness is implemented separately

---

## 12. Related documents

- `docs/design/dfir/collection_result_contract.md`
- `docs/design/dfir/collection_result_ingestion.md`
- `docs/design/rule-improvement/post_action_dfir_review_input_contract.md`
- `docs/roadmap/phase6.md`
- `docs/AI_SOC_Lab_Master_Guide.md`
