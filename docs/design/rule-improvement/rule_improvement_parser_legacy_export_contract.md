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

The validation summary reporter inspects already-generated concrete bundle,
rule, prompt, promotion recommendation, parser, and diagnostics artifacts.
`parser_candidates.yaml` is optional in the base reporting mode. When present,
the reporter validates it and checks that visible IDs come only from converted
`candidate_type: parser` candidates.

Parser diagnostics remain diagnostics only. The validation summary must not
create parser candidates or invoke parser exporters.

---

## 8. Non-Goals

This contract does not define or authorize:

- parser process-pipeline wiring
- parser apply or deployment workflows
- automatic parser updates
- telemetry or correlation legacy export
- attack-to-detection-to-Rule-Improvement E2E validation
- baseline, prompt, parser, telemetry, or correlation mutation
- promotion workflow or automatic promotion

---

## 9. Status And Evidence Ownership

This document owns parser-export eligibility, candidate-only output semantics,
diagnostics, safe output paths, schema validation, and fail-closed behavior.
The parser candidate schema, exporter, focused tests, and export-chain smoke
named here are evidence for those boundaries.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, pipeline integration, validation depth,
priorities, and sequencing. Telemetry or correlation export must arrive
through dedicated contracts rather than being inferred from this parser
exporter.

---

## 10. Boundary Acceptance Criteria

The parser export boundary remains valid when:

- only eligible converted parser candidates are considered
- skipped decisions, diagnostics, and other candidate types are excluded
- source bundle and review provenance remain traceable
- unsafe paths, payload overrides, or schema violations fail closed
- output is validated before it is written
- `parser_candidates.yaml` remains candidate-only and cannot update parser
  code, configuration, active agents, or production state

---

## 11. One-Line Summary

```text
Parser legacy export produces parser_candidates.yaml from eligible converted parser candidates, but remains candidate-only and cannot update parser code, configuration, active agents, or production state.
```
