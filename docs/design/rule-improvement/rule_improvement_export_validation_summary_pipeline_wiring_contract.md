# Rule Improvement Export Validation Summary Pipeline Wiring Contract

## 1. Purpose

This document defines the wiring contract for adding the Rule Improvement
export artifact validation summary reporter to `scripts/run_process_pipeline.py`.

The implemented pipeline wiring allows an explicit pipeline run to generate:

```text
rule_improvement_export_artifact_validation_summary.json
```

after the Rule Improvement export artifacts it inspects already exist. This is
a validation/reporting step only. It is implemented as a disabled-by-default
opt-in path in `scripts/run_process_pipeline.py`.

## 2. Default Behavior

Pipeline wiring is disabled by default.

Existing process pipeline behavior must remain unchanged unless an explicit
flag or config option enables the RI export validation summary step. No
existing pipeline scenario should start producing
`rule_improvement_export_artifact_validation_summary.json` implicitly.

If the summary step is disabled:

- no summary artifact is required
- no existing pipeline behavior changes
- no RI export artifacts are created by the summary step

## 3. Trigger Shape

The implemented trigger is an explicit opt-in flag:

```text
--enable-ri-export-validation-summary
```

This flag must remain explicit and opt-in. It must not be enabled by default,
inferred from scenario identity, or silently activated by unrelated pipeline
options.

## 4. Expected Ordering

When explicitly enabled, the summary step runs after the existing RI export
steps in `scripts/run_process_pipeline.py`, so artifacts it inspects must
already have been generated:

```text
proposal/review artifacts
  -> concrete candidate bundle
  -> rule/prompt export
  -> promotion recommendation export
  -> RI export validation summary
```

The validation summary reporter must not invoke exporter scripts itself. It
must not create `rule_candidates.yaml`, `prompt_candidates.yaml`, or
`promotion_recommendation.yaml`.

## 5. Inputs and Outputs

The reporter may inspect these inputs when present:

- `rule_improvement_concrete_candidate_bundle_v1.json`
- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`
- `rule_improvement_legacy_rule_prompt_export_diagnostics.json`
- `rule_improvement_promotion_recommendation_export_diagnostics.json`
- other diagnostics JSON files discovered by the reporter

The output is:

- `rule_improvement_export_artifact_validation_summary.json`

The output must validate against:

```text
schemas/rule_improvement_export_artifact_validation_summary.schema.json
```

The reporter validates its own summary output against that schema before
writing.

## 6. Fail-Closed Behavior

Pipeline wiring must preserve the reporter's fail-closed behavior.

If summary schema validation fails:

- do not write `rule_improvement_export_artifact_validation_summary.json`
- fail the summary step
- do not rewrite inspected RI artifacts

If inspected artifact validation, consistency, or safety checks fail:

- the summary artifact may be written with `overall_status: fail`
- the pipeline surfaces this as a validation failure for the RI export chain
- the pipeline must not apply, deploy, update, or promote anything

If the summary step is disabled:

- no summary artifact is required
- existing pipeline behavior remains unchanged

## 7. Safety Boundaries

The validation summary is not human review.

It is not:

- apply approval
- deployment approval
- baseline update approval
- prompt update approval
- parser update approval
- telemetry update approval
- correlation update approval
- promotion approval
- automatic promotion

It does not:

- update active agents or production state
- invoke exporters
- create rule candidates, prompt candidates, parser candidates, or promotion
  recommendations
- mutate inspected RI artifacts

## 8. Non-Goals

This contract does not implement:

- attack-to-detection-to-RI E2E smoke
- parser process-pipeline wiring
- telemetry legacy export
- correlation legacy export
- apply workflow
- deployment workflow
- baseline update workflow
- prompt update workflow
- parser update workflow
- telemetry update workflow
- correlation update workflow
- promotion workflow
- automatic promotion

## 9. Implementation Status

Implemented:

- explicit opt-in `--enable-ri-export-validation-summary`
- disabled-by-default process-pipeline behavior
- summary reporter call after existing RI export steps
- canonical `rule_improvement_export_artifact_validation_summary.json` output
- reporter-managed summary schema validation before write
- fail-closed propagation of reporter failures and `overall_status: fail`
- focused tests for disabled default behavior, enabled generation, and surfaced
  reporter failure

Still not implemented:

- attack-to-detection-to-RI E2E smoke
- parser process-pipeline wiring
- telemetry legacy export
- correlation legacy export
- apply workflow
- deployment workflow
- baseline update workflow
- prompt update workflow
- parser update workflow
- telemetry update workflow
- correlation update workflow
- promotion workflow
- automatic promotion

## 10. One-Line Summary

RI export validation summary pipeline wiring is explicit, disabled by default,
ordered after export artifacts already exist, and limited to non-mutating
validation/reporting.
