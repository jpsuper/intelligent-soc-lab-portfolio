# Rule Improvement Candidate Proposal Generator Contract

## 1. Purpose

This document defines the contract for the standalone deterministic generator
from:

```text
rule_improvement_candidate_creation_input.json
```

to:

```text
rule_improvement_candidate_proposals_v2.json
```

The generator is implemented at:

```text
scripts/generate_rule_improvement_candidate_proposals_v2.py
```

This contract does not wire the process pipeline, create generated sample
artifacts, apply changes, deploy changes, update baselines, update prompts,
update parser code, update telemetry collection, update correlation logic, or
promote anything.

The generator produces proposal-only v2 artifacts. Its output is not
approval to apply, deploy, promote, update baselines, or mutate any rule,
prompt, parser, telemetry, correlation, active-agent, case, action,
investigation, containment, approval, verdict, severity, confidence, or Rule
Improvement promotion state.

## 2. Inputs

The required input is:

```text
rule_improvement_candidate_creation_input.json
```

The input must be canonical JSON from the human-reviewed candidate creation
flow and must validate against
`schemas/rule_improvement_candidate_creation_input.schema.json`.

The generator must not use any of these as source of authority:

- Japanese rewrites
- worksheets
- AI draft text
- AI draft comparison summaries
- human-readable handoff prose
- untranslated or translated prose notes
- raw post-action evidence outside the reviewed candidate-creation path

Those artifacts may help a human understand earlier review context, but they
must not authorize proposal generation, approval, deployment, baseline update,
or promotion.

## 3. Output

The output artifact is:

```text
rule_improvement_candidate_proposals_v2.json
```

The output must validate against:

```text
schemas/rule_improvement_candidate_proposals_v2.schema.json
```

The output root must preserve:

- `version: 2`
- `artifact_type: rule_improvement_candidate_proposals`
- `artifact_semantics: proposal_only`
- `source.source_candidate_creation_input_ref`
- `source.source_candidate_creation_input_sha256`
- `proposals`

The output must remain a proposal-only artifact. It must not become a legacy
`rule_candidates.yaml`, `prompt_candidates.yaml`, or
`promotion_recommendation.yaml` artifact, and it must not update those
artifacts.

## 4. Source Hash

`source.source_candidate_creation_input_sha256` must be calculated over the
exact input bytes read by the generator.

Generator tests should use deterministic fixture bytes so the expected SHA-256
value is stable and reviewable.

## 5. Proposal Mapping

Each accepted candidate creation input item should map to one or more v2
proposal items only when it has enough reviewed information to create a safe
proposal. The generator must not invent evidence, rationale, source refs,
limitations, targets, or expected effects to fill gaps.

The current `rule_improvement_candidate_creation_input.json` item shape uses
candidate-creation names such as `detection_rule_candidate` and
`prompt_candidate`. The generator normalizes those source names into the v2
proposal schema's `candidate_type` values only through explicit, deterministic
mapping. Any future addition of promotion-review input must be
handled through the same reviewed, schema-valid input path.

The v2 proposal output must use this required mapping:

| v2 `candidate_type` | Required v2 `allowed_next_artifact_type` |
|---|---|
| `rule` | `rule_candidate_proposal` |
| `prompt` | `prompt_candidate_proposal` |
| `parser` | `parser_candidate_proposal` |
| `telemetry` | `telemetry_candidate_proposal` |
| `correlation` | `correlation_candidate_proposal` |
| `promotion_review` | `promotion_review_recommendation` |

`promotion_review_recommendation` is recommendation-only. It must not be
treated as promotion approval, deployment approval, baseline update approval,
or authority to change active agents.

## 6. Human Decision Provenance

Each generated proposal must preserve human candidate-review decision
provenance from the accepted candidate-creation input path.

`rule_improvement_candidate_creation_input.json` item objects preserve:

- `human_decision_ref`
- `human_decision_id`
- `human_decision_status`

The generator must use those fields to populate v2
`human_decision_provenance.decision_ref`,
`human_decision_provenance.decision_id`, and
`human_decision_provenance.decision_status`.

The source candidate-review decisions artifact currently uses the decision
value `accept_for_candidate_creation`. The candidate-creation input normalizes
that accepted value into `accepted_for_candidate_creation` for downstream v2
proposal provenance. The generator must not fabricate decision identity
from `candidate_id`.

If the input path does not provide enough reviewed provenance to populate
`decision_ref` and `decision_id` safely, the generator must skip the item, emit
a non-proposal diagnostic, or fail closed.

The generated proposal's `human_decision_provenance.decision_status` must
remain:

```json
"accepted_for_candidate_creation"
```

That status means only that the reviewed item may become a proposal. It is not
approval to apply a rule, update a prompt, update a parser, update telemetry,
update correlation logic, deploy anything, update a baseline, or promote
anything.

## 7. Skip Behavior

If an accepted input item has an unsupported future schema-valid candidate type,
the generator may skip that item.

Known `candidate_type` / `allowed_next_artifact_type` mismatches must fail
closed. Diagnostics must not be emitted as proposal items unless they satisfy
the v2 proposal schema and the safety requirements in this contract.

When `--diagnostics-output` is provided, the generator writes non-proposal
diagnostics metadata for skipped unsupported future schema-valid candidate
types after successful input and output validation. Diagnostics do not
authorize apply, deployment, baseline update, or promotion.

The generator must fail closed on invalid input, invalid output, known
candidate type mismatches, inconsistent refs, missing provenance, or unsafe
proposal semantics.

## 8. Safety Boundaries

The generator must not add fields such as:

- `approved`
- `candidate_approved`
- `promotion_approved`
- `deployment_approved`
- `baseline_update_approved`
- `auto_apply_allowed`
- `promotion_allowed`
- `applies_changes`
- `promoted`

The generator must not update any active artifact or baseline. It must not
mutate detection rules, prompts, parser code, telemetry collection,
correlation logic, case artifacts, action artifacts, pre-case investigation
artifacts, post-action DFIR artifacts, containment state, approval state,
verdict, severity, confidence, or Rule Improvement promotion state.

The generator must not be wired into `scripts/run_process_pipeline.py`.
Pipeline integration, apply workflows, deployment workflows, baseline updates,
and promotion workflows require separate reviewed contracts and tests.

## 9. CLI

The generator supports this CLI shape:

```bash
uv run python scripts/generate_rule_improvement_candidate_proposals_v2.py \
  --input data/runs/run-001/rule_improvement_candidate_creation_input.json \
  --output data/runs/run-001/rule_improvement_candidate_proposals_v2.json \
  --diagnostics-output data/runs/run-001/rule_improvement_candidate_proposal_generator_diagnostics.json
```

Optional flags:

```text
--input-schema
--output-schema
--diagnostics-output
```

The generator fails closed on invalid input or invalid output. It validates the
input before generating proposals and validates the output before writing or
reporting success. Diagnostics output does not turn fail-closed errors into
success.

## 10. Implementation Status

Implemented:

- standalone generator script
- focused generator tests
- v2 proposal JSON Schema
- generator contract and cross-references from existing Rule Improvement design
  docs

Not implemented:

- process-pipeline wiring
- apply, deployment, baseline update, prompt update, parser update, telemetry
  update, correlation update, or promotion behavior
- generated sample artifacts

## 11. One-line Summary

```text
The standalone generator converts reviewed candidate-creation input into v2 proposal-only artifacts, but it must not apply, deploy, promote, or mutate state.
```
