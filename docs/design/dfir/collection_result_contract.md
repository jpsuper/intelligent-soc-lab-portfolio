# DFIR Collection Result Contract

## 1. Purpose

This document defines the contract for `collection_result.json`, the artifact that records the outcome of a DFIR collection request.

The lab already connects action planning to DFIR request generation:

```text
case.json
  ↓
action_result.json
  ↓
collection_request.json
```

The next contract boundary is:

```text
collection_request.json
  ↓
DFIR collection execution or manual collection
  ↓
collection_result.json
```

The goal is to make DFIR collection outcomes explicit, reviewable, and reusable without mixing collection execution with investigation conclusions.

`collection_result.json` answers:

```text
What was requested, what was collected, what failed, what was skipped, and where is the collected evidence?
```

It must not answer by itself:

```text
Is the host compromised?
How severe is the case?
Should the host be isolated?
Should a detection rule be promoted?
```

---

## 2. Positioning

`collection_result.json` sits after `collection_request.json` and before any future investigation or case enrichment.

```text
action_result.json
  ↓
collection_request.json
  ↓
collection_result.json
  ↓
future investigation / case enrichment
  ↓
future executor / DFIR result comparison
```

This keeps three responsibilities separate:

| Artifact | Responsibility |
|---|---|
| `action_result.json` | Defines response intent and playbook steps. |
| `collection_request.json` | Defines what DFIR evidence should be collected. |
| `collection_result.json` | Records the outcome of a collection attempt. |

---

## 3. Design Principles

- Collection results are evidence transport artifacts, not investigation conclusions.
- Preserve request traceability back to `collection_request.json`, `action_result.json`, and `case.json`.
- Record successful, partial, failed, and skipped collection outcomes explicitly.
- Keep tool-specific fields under source-specific metadata.
- Support Velociraptor, manual collection, mock collection, and future collectors with the same contract.
- Do not modify verdict, severity, confidence, `overall_result`, `detected`, action approval, or Rule Improvement promotion behavior.
- Allow sparse results. A failed or skipped collection should still produce a valid result artifact.
- Keep collected evidence references explicit and reviewable.
- Treat this as a post-action / DFIR boundary, not a replacement for investigation.

---

## 4. Scope

### In scope

- Define `collection_result.json` as a first-class artifact.
- Define collection-level status.
- Define per-artifact result entries.
- Preserve source action / request / case references.
- Represent collected artifacts, failed artifacts, and skipped artifacts.
- Support Velociraptor, manual, mock, and future collection backends.
- Define what may be fed back to investigation or case enrichment.

### Out of scope

- Executing Velociraptor collections.
- Implementing a Velociraptor API client.
- Parsing full forensic artifacts.
- Scoring forensic findings.
- Updating case severity or investigation verdict.
- Comparing executor or DFIR result quality.
- Automatically generating Rule Improvement candidates.
- Automatically approving containment or credential actions.

---

## 5. Status Model

### Collection-level status

`collection_result.status` should use one of:

| Status | Meaning |
|---|---|
| `requested` | Request was accepted but collection has not completed. |
| `completed` | All requested collection items completed successfully. |
| `partial` | At least one item completed and at least one item failed or was skipped. |
| `failed` | No requested collection item completed successfully. |
| `skipped` | Collection was intentionally not attempted. |
| `cancelled` | Collection was stopped before completion. |
| `unknown` | State cannot be determined from available data. |

### Per-item status

Each item in `collected_artifacts`, `failed_artifacts`, and `skipped_artifacts` should also have an item-level status.

Recommended values:

```text
collected
failed
skipped
cancelled
not_found
timeout
permission_denied
unsupported
unknown
```

---

## 6. Required Top-Level Fields

Minimum required fields:

| Field | Type | Description |
|---|---|---|
| `collection_result_id` | string | Stable ID for this result artifact. |
| `collection_request_id` | string | ID of the request this result answers. |
| `case_id` | string or null | Case ID when available. |
| `action_id` | string or null | Action ID when available. |
| `scenario_id` | string or null | Scenario ID when available. |
| `source_run_id` | string or null | Source run ID when available. |
| `status` | string | Collection-level status. |
| `collector` | object | Collector identity and execution mode. |
| `started_at` | string or null | ISO 8601 start timestamp. |
| `ended_at` | string or null | ISO 8601 end timestamp. |
| `summary` | string | Short factual collection outcome summary. |
| `collected_artifacts` | array | Successfully collected item results. |
| `failed_artifacts` | array | Failed item results. |
| `skipped_artifacts` | array | Skipped item results. |
| `request_refs` | object | References back to request/action/case artifacts. |
| `safety_notes` | array | Safety or approval-related notes. |
| `metadata` | object | Versioning and backend-specific metadata. |

---

## 7. Collector Model

The `collector` object identifies how the collection was attempted.

Example:

```json
{
  "type": "velociraptor",
  "name": "Velociraptor",
  "mode": "request_only",
  "target_host": "ubuntu-victim01",
  "target_user": "victim01",
  "backend_result_ref": "velociraptor-flow-placeholder"
}
```

Recommended collector fields:

| Field | Type | Description |
|---|---|---|
| `type` | string | `velociraptor`, `manual`, `mock`, `osquery`, `wazuh`, `script`, or `unknown`. |
| `name` | string | Human-readable collector name. |
| `mode` | string | `request_only`, `executed`, `manual`, `mock`, or `unknown`. |
| `target_host` | string or null | Target host. |
| `target_user` | string or null | Target user when relevant. |
| `backend_result_ref` | string or null | Tool-native flow ID, job ID, ticket ID, or manual evidence reference. |

Notes:

- `request_only` is valid when the lab generates a request but does not execute the tool.
- `mock` is valid for deterministic tests and harnesses.
- Backend-specific identifiers should remain references, not conclusions.

---

## 8. Artifact Result Model

Each collected, failed, or skipped item should use a common shape.

### Common fields

| Field | Type | Description |
|---|---|---|
| `artifact_id` | string | Stable item ID within this result. |
| `request_item_id` | string or null | ID of the requested item when available. |
| `artifact_type` | string | Type of evidence or requested collection. |
| `status` | string | Item-level status. |
| `target` | object | Host, user, path, process, or other target. |
| `requested_by_action` | string or null | Action playbook step or action type that led to the request. |
| `evidence_refs` | array | References to case/investigation/action evidence that justified the request. |
| `output_refs` | array | References to collected files, flow IDs, logs, or storage paths. |
| `summary` | string | Factual summary of the result. |
| `errors` | array | Error entries when failed or partial. |
| `metadata` | object | Backend-specific metadata. |

### Example collected item

```json
{
  "artifact_id": "collected-artifact-001",
  "request_item_id": "request-item-001",
  "artifact_type": "process_list",
  "status": "collected",
  "target": {
    "host": "ubuntu-victim01",
    "user": null,
    "path": null,
    "process": null
  },
  "requested_by_action": "request_dfir_collection",
  "evidence_refs": [
    "action_result.playbook[1].evidence_refs[0]",
    "case.timeline[2]"
  ],
  "output_refs": [
    {
      "type": "file",
      "path": "data/dfir/run-0032/process_list.json",
      "sha256": null,
      "size_bytes": null
    }
  ],
  "summary": "Collected process list from ubuntu-victim01.",
  "errors": [],
  "metadata": {
    "collector_artifact": "Linux.ProcessList"
  }
}
```

### Example failed item

```json
{
  "artifact_id": "failed-artifact-001",
  "request_item_id": "request-item-002",
  "artifact_type": "payload_file",
  "status": "not_found",
  "target": {
    "host": "ubuntu-victim01",
    "user": "victim01",
    "path": "/tmp/payload.sh",
    "process": null
  },
  "requested_by_action": "collect_payload_or_process_evidence",
  "evidence_refs": [
    "investigation_result.evidence[2]"
  ],
  "output_refs": [],
  "summary": "Requested payload path was not found at collection time.",
  "errors": [
    {
      "code": "file_not_found",
      "message": "The target path was absent during collection.",
      "retryable": false
    }
  ],
  "metadata": {
    "collector_artifact": "Generic.Client.FileFinder"
  }
}
```

---

## 9. Output Reference Model

`output_refs` should point to collected evidence without requiring downstream components to understand the collector backend.

Recommended shape:

```json
{
  "type": "file",
  "path": "data/dfir/run-0032/process_list.json",
  "sha256": "optional-sha256",
  "size_bytes": 12345,
  "content_type": "application/json",
  "description": "Velociraptor process list export"
}
```

Allowed `type` values:

```text
file
directory
flow
ticket
url
log
hash
manual_note
unknown
```

Notes:

- Prefer local artifact paths when evidence is stored inside the lab.
- For external tools, use a stable flow ID, ticket ID, URL, or exported file path.
- Do not store secrets, credentials, or large raw binary blobs directly inside `collection_result.json`.
- Store hashes and metadata where available.

---

## 10. Traceability

`collection_result.json` should preserve references back to the request and the original decision chain.

Example:

```json
{
  "request_refs": {
    "collection_request": "data/runs/run-0032/collection_request.json",
    "action_result": "data/runs/run-0032/action_result.json",
    "case": "data/runs/run-0032/case.json",
    "investigation_result": "data/runs/run-0032/investigation_result.json"
  },
  "source_action_refs": [
    "action_result.playbook[1]",
    "action_result.playbook[2]"
  ],
  "case_refs": [
    "case.timeline[2]",
    "case.key_artifacts.process_exec"
  ]
}
```

Traceability is important because `collection_result.json` should be reviewable even when the collection itself is partial or failed.

---

## 11. Relationship To Investigation

Collection results may feed future investigation or case enrichment, but only as evidence availability and collection outcome.

Allowed investigation contributions:

- Add factual evidence availability notes.
- Add references to collected files or tool outputs.
- Add missing evidence notes when collection failed.
- Add recommended follow-up pivots when an important artifact was unavailable.
- Add raw artifact references for human review.

Not allowed directly from `collection_result.json`:

- Change `verdict`.
- Change `confidence`.
- Change `severity`.
- Mark `detected=true`.
- Mark `overall_result=success`.
- Declare attacker intent.
- Approve containment.
- Promote a rule candidate.
- Replace existing investigation evidence with unreviewed collector output.

Recommended boundary:

```text
collection_result.json
  -> evidence availability / raw artifact refs / collection gaps
  -> future investigation or case enrichment
  -> human or judge review
  -> no direct assessment mutation
```

---

## 12. Relationship To Action And Executor

`action_result.json` defines what should be done. `collection_request.json` translates relevant playbook steps into collection tasks. `collection_result.json` records what actually happened.

```text
action_result.json
  -> collection_request.json
  -> collection_result.json
```

This contract does not define executor comparison. A future executor / DFIR result comparison harness may compare:

- Did the executor attempt the right collections?
- Were approval boundaries respected?
- Did the collection result match the request?
- Were failures represented clearly?
- Were output artifacts traceable and reviewable?

That future harness should consume `collection_request.json` and `collection_result.json`, not overload action harness.

---

## 13. Relationship To Rule Improvement

`collection_result.json` may reveal evidence gaps, but those gaps are not automatically rule candidates.

Allowed:

- Surface failed or skipped collection as human-reviewable gaps.
- Use repeated collection failures as backlog or runbook improvement signals.
- Use missing artifacts as future investigation prompt or collection policy candidates after review.

Not allowed:

- Automatically add detection rules because a collection failed.
- Automatically promote Rule Improvement candidates.
- Treat collection success as proof that a detection was correct.
- Treat collection failure as proof that a detection was false.

Recommended boundary:

```text
collection result gap
  -> human-reviewable signal
  -> optional candidate after reviewer approval
```

---

## 14. Example `collection_result.json`

```json
{
  "collection_result_id": "collection-result-run-0032-001",
  "collection_request_id": "collection-request-run-0032-001",
  "case_id": "case-run-0032",
  "action_id": "action-run-0032",
  "scenario_id": "scenario-006",
  "source_run_id": "run-0032",
  "status": "partial",
  "collector": {
    "type": "velociraptor",
    "name": "Velociraptor",
    "mode": "mock",
    "target_host": "ubuntu-victim01",
    "target_user": "victim01",
    "backend_result_ref": "mock-flow-run-0032"
  },
  "started_at": "2026-06-15T12:00:00Z",
  "ended_at": "2026-06-15T12:01:00Z",
  "summary": "Collected process list and bash history; payload file was not found at collection time.",
  "collected_artifacts": [
    {
      "artifact_id": "collected-artifact-001",
      "request_item_id": "request-item-001",
      "artifact_type": "process_list",
      "status": "collected",
      "target": {
        "host": "ubuntu-victim01",
        "user": null,
        "path": null,
        "process": null
      },
      "requested_by_action": "request_dfir_collection",
      "evidence_refs": [
        "case.timeline[2]"
      ],
      "output_refs": [
        {
          "type": "file",
          "path": "data/dfir/run-0032/process_list.json",
          "sha256": null,
          "size_bytes": null,
          "content_type": "application/json",
          "description": "Mock process list export"
        }
      ],
      "summary": "Collected process list from ubuntu-victim01.",
      "errors": [],
      "metadata": {
        "collector_artifact": "Linux.ProcessList"
      }
    },
    {
      "artifact_id": "collected-artifact-002",
      "request_item_id": "request-item-002",
      "artifact_type": "bash_history",
      "status": "collected",
      "target": {
        "host": "ubuntu-victim01",
        "user": "victim01",
        "path": "/home/victim01/.bash_history",
        "process": null
      },
      "requested_by_action": "request_dfir_collection",
      "evidence_refs": [
        "case.timeline[1]"
      ],
      "output_refs": [
        {
          "type": "file",
          "path": "data/dfir/run-0032/bash_history.txt",
          "sha256": null,
          "size_bytes": null,
          "content_type": "text/plain",
          "description": "Mock bash history export"
        }
      ],
      "summary": "Collected bash history for victim01.",
      "errors": [],
      "metadata": {
        "collector_artifact": "Linux.BashHistory"
      }
    }
  ],
  "failed_artifacts": [
    {
      "artifact_id": "failed-artifact-001",
      "request_item_id": "request-item-003",
      "artifact_type": "payload_file",
      "status": "not_found",
      "target": {
        "host": "ubuntu-victim01",
        "user": "victim01",
        "path": "/tmp/payload.sh",
        "process": null
      },
      "requested_by_action": "collect_payload_or_process_evidence",
      "evidence_refs": [
        "investigation_result.evidence[2]"
      ],
      "output_refs": [],
      "summary": "Requested payload path was not found at collection time.",
      "errors": [
        {
          "code": "file_not_found",
          "message": "The target path was absent during collection.",
          "retryable": false
        }
      ],
      "metadata": {
        "collector_artifact": "Generic.Client.FileFinder"
      }
    }
  ],
  "skipped_artifacts": [],
  "request_refs": {
    "collection_request": "data/runs/run-0032/collection_request.json",
    "action_result": "data/runs/run-0032/action_result.json",
    "case": "data/runs/run-0032/case.json",
    "investigation_result": "data/runs/run-0032/investigation_result.json"
  },
  "source_action_refs": [
    "action_result.playbook[1]",
    "action_result.playbook[2]"
  ],
  "case_refs": [
    "case.timeline[1]",
    "case.timeline[2]"
  ],
  "safety_notes": [
    "Collection result records evidence availability only; it does not approve containment or change severity."
  ],
  "metadata": {
    "schema_version": "collection_result_v1",
    "collector_profile": "velociraptor-mock-v1",
    "generated_by": "dfir-collection-adapter",
    "generated_at": "2026-06-15T12:01:05Z"
  }
}
```

---

## 15. Future Schema Direction

A future schema should validate:

- top-level required fields
- `status` enum
- item-level status enum
- collector type enum
- `collected_artifacts` / `failed_artifacts` / `skipped_artifacts` array item shape
- `output_refs` item shape
- error item shape
- traceability fields
- metadata fields

Candidate schema path:

```text
schemas/collection_result.schema.json
```

Candidate tests:

```text
tests/test_collection_result_schema.py
tests/test_collection_request_to_result_contract.py
```

---

## 16. Future Implementation Path

Recommended implementation order:

1. Add this design document.
2. Add `schemas/collection_result.schema.json`.
3. Add schema tests with:
   - completed result
   - partial result
   - failed result
   - skipped result
4. Add mock collection result generator from `collection_request.json`.
5. Add Velociraptor adapter output mapping.
6. Add optional case / investigation enrichment from collection result.
7. Add executor / DFIR result comparison harness only after collection result contract is stable.

---

## 17. Done Criteria

This contract is ready when:

- `collection_result.json` responsibility is separated from `collection_request.json`.
- Top-level status and per-item status are defined.
- Collected, failed, and skipped artifacts can be represented.
- Tool-specific collector metadata can be preserved without leaking into assessment fields.
- Traceability to request, action, case, and investigation artifacts is preserved.
- Boundaries against verdict / severity / detection / Rule Improvement mutation are explicit.
- Future schema and implementation paths are documented.

---

## 18. One-line Summary

```text
collection_result.json records what DFIR collection actually produced or failed to produce;
it is evidence availability and traceability, not an investigation verdict.
```
