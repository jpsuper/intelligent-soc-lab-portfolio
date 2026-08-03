# Rule Improvement Parser Legacy Export Contract

## 1. Purpose

This document defines the contract for exporting Rule Improvement parser
concrete candidates into a legacy-compatible parser candidate artifact.

The parser legacy exporter converts accepted parser-type concrete candidates
from `rule_improvement_concrete_candidate_bundle_v1.json` into parser candidate
proposals. This is candidate/recommendation-only. It must not modify parser
code, deploy parser changes, update production parser behavior, update active
agents, or mutate production state.

The parser candidate schema is implemented at:

```text
schemas/parser_candidates_schema.json
```

Focused schema tests are implemented at:

```text
tests/test_parser_candidates_schema.py
```

The standalone parser legacy exporter is implemented at:

```text
scripts/export_rule_improvement_parser_candidates.py
```

Focused exporter tests are implemented at:

```text
tests/test_export_rule_improvement_parser_candidates.py
```

## 2. Input

Primary input:

```text
rule_improvement_concrete_candidate_bundle_v1.json
```

Only `converted_candidates` from a schema-valid concrete candidate bundle may
be considered. Skipped decisions, diagnostics, and non-accept decisions must
not be exported.

Parser export requires explicit parser candidate semantics:

- `candidate_type: parser`
- `allowed_next_artifact_type: parser_candidate_proposal`
- `target_artifact_type: parser_candidate_bundle_item`

The exporter must not infer parser candidates from `rule`, `prompt`,
`promotion_review`, `telemetry`, or `correlation` candidates.

## 3. Output

Canonical output artifact:

```text
parser_candidates.yaml
```

This artifact should contain parser candidate proposals only. It is not applied
parser code and is not active parser configuration.

Suggested shape:

```yaml
parser_candidates:
  - id: ri-parser-001
    target: parsers/example_parser.py
    reason: Reviewed parser improvement candidate.
    proposed_change: Add parsing support for a bounded lab artifact shape.
    expected_effect:
      - Improve parser coverage for reviewed lab telemetry.
    supporting_signals:
      - source_bundle:data/runs/example/rule_improvement_concrete_candidate_bundle_v1.json
      - candidate_id:ri-parser-001
      - proposal_ref:/proposals/0
    priority: medium
```

The implemented parser candidate schema fixes this candidate-only shape for
`parser_candidates.yaml` artifacts. It does not add parser update, apply,
deployment, promotion, active parser configuration, or production parser state.

## 4. Diagnostics

Optional diagnostics output:

```text
rule_improvement_parser_legacy_export_diagnostics.json
```

Diagnostics should report:

- unsupported candidate types
- skipped or non-accept candidates
- missing required parser payload fields
- candidate IDs excluded from export
- schema or contract violations
- parser candidates excluded because their `candidate_type`,
  `allowed_next_artifact_type`, or `target_artifact_type` does not match parser
  export expectations

Diagnostics are metadata only. They must not be treated as candidate artifacts,
parser update approval, deployment approval, or promotion approval.

## 5. Safety Boundaries

`parser_candidates.yaml` is not:

- parser update approval
- apply approval
- deployment approval
- automatic parser update
- active parser configuration
- production parser state
- promotion approval

The exporter must not:

- write parser source files
- modify parser configuration
- run parser deployment
- call apply workflows
- call deployment workflows
- call promotion workflows
- update active agents
- update production state

The exporter may write only its candidate artifact and optional diagnostics
artifact after validation succeeds.

## 6. Fail-Closed Behavior

The parser exporter fails closed when:

- the input bundle is invalid
- the output path collides with the input bundle
- the output path is a known non-parser RI artifact, including
  `rule_candidates.yaml`, `prompt_candidates.yaml`,
  `promotion_recommendation.yaml`, or
  `rule_improvement_export_artifact_validation_summary.json`
- parser candidate payload is missing required fields
- parser candidate payload tries to override base metadata unsafely
- `candidate_type`, `allowed_next_artifact_type`, or `target_artifact_type`
  does not match parser export expectations
- skipped or non-accept candidate IDs appear in output
- unsafe approval/apply/deploy/promote-like fields appear
- diagnostics output collides with the parser candidate output or source bundle
- output schema validation fails

The exporter should write output only after input validation, candidate type
checks, payload checks, safety checks, and output validation succeed.

## 7. Relationship to Validation Summary

The implemented validation summary reporter currently inspects already
generated concrete bundle, rule, prompt, promotion recommendation, parser, and
diagnostics artifacts. It does not require `parser_candidates.yaml` today, but
when `parser_candidates.yaml` is present it validates the artifact and checks
that visible IDs come only from converted `candidate_type: parser` candidates.

Parser diagnostics remain diagnostics only. The validation summary must not
create parser candidates and must not invoke parser exporters.

## 8. Non-Goals

Implemented:

- parser legacy export future contract
- parser candidate schema at `schemas/parser_candidates_schema.json`
- focused parser candidate schema tests at
  `tests/test_parser_candidates_schema.py`
- parser legacy exporter at
  `scripts/export_rule_improvement_parser_candidates.py`
- focused parser legacy exporter tests at
  `tests/test_export_rule_improvement_parser_candidates.py`
- parser export chain smoke at
  `tests/test_rule_improvement_parser_export_chain_smoke.py`

Not implemented:

- parser process-pipeline wiring
- parser apply workflow
- parser deployment workflow
- automatic parser update
- telemetry legacy export
- correlation legacy export
- attack-to-detection-to-Rule-Improvement E2E smoke
- apply workflow
- deployment workflow
- baseline update workflow
- prompt update workflow
- parser update workflow
- telemetry update workflow
- correlation update workflow
- promotion workflow
- automatic promotion

## 9. Future Implementation Checklist

Future parser export follow-up work should:

- update docs/status after implementation
- keep process-pipeline wiring disabled by default if added later

## 10. One-Line Summary

```text
Parser legacy export may produce parser_candidates.yaml from accepted parser concrete candidates, but it remains candidate-only and must not update parser code, parser configuration, active agents, or production state.
```
