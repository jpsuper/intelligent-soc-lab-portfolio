# Rule Improvement Export Artifact Validation Summary Contract

## 1. Purpose

This document defines the contract for a Rule Improvement export artifact
validation summary.

The summary command is implemented at:

```text
scripts/summarize_rule_improvement_export_artifacts.py
```

The command inspects already-generated Rule Improvement export artifacts and
writes a machine-readable validation/reporting summary. It must be
non-mutating, non-applying, non-deploying, non-promoting, and non-authorizing.

It must not replace human review. It must not apply rules, deploy changes,
update baselines, update prompts, update parsers, update telemetry, update
correlation logic, update active agents, or promote anything.

## 2. CLI Shape

Command shape:

```bash
uv run python scripts/summarize_rule_improvement_export_artifacts.py \
  --run-dir "$RUN_DIR" \
  --output "$RUN_DIR/rule_improvement_export_artifact_validation_summary.json"
```

The command should be safe to run against:

- synthetic `tmp_path` fixtures in tests
- a completed `data/runs/<run_id>/` directory

It should be local-development / WSL-friendly. It is not an
attack/victim-log end-to-end test and should not require victim logs, Wazuh,
rsyslog, Hydra output, Proxmox, Kali, Ubuntu victim, or existing external lab
state.

## 3. Candidate Inputs

The summary command may inspect these artifacts when present:

- `rule_improvement_concrete_candidate_bundle_v1.json`
- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`
- `parser_candidates.yaml`
- `rule_improvement_legacy_rule_prompt_export_diagnostics.json`
- `rule_improvement_promotion_recommendation_export_diagnostics.json`
- `rule_improvement_parser_legacy_export_diagnostics.json`
- other Rule Improvement export diagnostics JSON files, if present

Artifacts may be present or absent depending on which export steps were run.
`parser_candidates.yaml` is optional in the base reporting mode. The command
distinguishes absent optional artifacts from artifacts required by the selected
mode.

## 4. Checks

The summary should report artifact presence:

- present
- absent
- optional
- required, when the selected mode marks an artifact as required

It should report schema validation status for:

- concrete candidate bundle schema
- rule candidates schema
- prompt candidates schema
- promotion recommendation schema
- parser candidates schema, when `parser_candidates.yaml` is present

It should report cross-artifact consistency where feasible:

- rule candidates correspond only to `rule` converted candidates
- prompt candidates correspond only to `prompt` converted candidates
- promotion recommendations correspond only to `promotion_review` converted
  candidates
- parser candidates correspond only to `parser` converted candidates
- skipped decisions are not exported as rule candidates, prompt candidates, or
  promotion recommendations, or parser candidates

It should report diagnostics consistency:

- unsupported/skipped items are reported deterministically
- diagnostics are not candidate artifacts
- diagnostics are not recommendations

It should report safety boundary checks:

- no apply/deploy/promote-like fields beyond schema-required legacy fields
- `promotion_recommendation.yaml` remains recommendation-only
- `rule_candidates.yaml`, `prompt_candidates.yaml`, and
  `parser_candidates.yaml` remain candidate artifacts only

It should report provenance/backreference checks where schemas permit:

- source bundle refs and SHA-256 hashes
- proposal refs
- proposal review decision refs
- source human decision provenance

## 5. Output Shape

The summary artifact uses a small JSON shape such as:

```json
{
  "version": 1,
  "artifact_type": "rule_improvement_export_artifact_validation_summary",
  "source_run_dir": "data/runs/example",
  "checked_artifacts": [],
  "schema_validation": [],
  "consistency_checks": [],
  "safety_checks": [],
  "warnings": [],
  "errors": [],
  "overall_status": "pass"
}
```

Recommended `overall_status` values:

- `pass`
- `pass_with_warnings`
- `fail`

The summary schema is implemented at:

```text
schemas/rule_improvement_export_artifact_validation_summary.schema.json
```

Focused schema coverage is implemented at:

```text
tests/test_rule_improvement_export_artifact_validation_summary_schema.py
```

The schema fixes the contract for
`rule_improvement_export_artifact_validation_summary.json`. The reporter
validates the summary object against this schema before writing output. If
schema validation fails, it fails closed and does not write the summary output.
This does not change safety semantics, invoke exporters, create rule
candidates, prompt candidates, parser candidates, or promotion recommendations,
update active agents or production state, or add apply, deployment, baseline
update, prompt update, parser update, telemetry update, correlation update,
promotion workflow, or automatic promotion behavior.

Process-pipeline wiring is documented separately at:

```text
docs/design/rule-improvement/rule_improvement_export_validation_summary_pipeline_wiring_contract.md
```

`scripts/run_process_pipeline.py` can generate the RI export validation summary
only when explicitly enabled with `--enable-ri-export-validation-summary`.
Default pipeline behavior is unchanged.

## 6. Safety Boundaries

The validation summary output must not be treated as:

- apply approval
- deployment approval
- baseline update approval
- prompt update approval
- parser update approval
- telemetry update approval
- correlation update approval
- promotion approval
- automatic promotion decision

The summary may report that artifacts are schema-valid or internally
consistent. That is not authorization to apply, deploy, update baselines,
update prompts, update parsers, update telemetry, update correlation logic, or
promote.

## 7. Relationship to Existing Export Work

Existing export-chain smoke tests prove focused artifact paths:

- `tests/test_rule_improvement_phase1_legacy_export_chain_smoke.py` covers the
  concrete bundle to rule/prompt legacy export chain.
- `tests/test_rule_improvement_promotion_recommendation_export_chain_smoke.py`
  covers the concrete bundle to recommendation-only promotion recommendation
  export chain.
- `tests/test_rule_improvement_export_validation_summary_chain_smoke.py` covers
  the supported export chain through validation summary reporting with
  synthetic schema-valid `tmp_path` fixtures:
  `rule_improvement_candidate_proposals_v2.json` plus
  `rule_improvement_proposal_review_decisions.json` to
  `rule_improvement_concrete_candidate_bundle_v1.json`,
  `rule_candidates.yaml`, `prompt_candidates.yaml`,
  `promotion_recommendation.yaml`, optional `parser_candidates.yaml`, and
  `rule_improvement_export_artifact_validation_summary.json`.

The validation summary is a reporting layer over artifacts already produced by
those flows. It must not invoke exporters as an apply workflow and must not
create candidate or recommendation semantics beyond reporting what is already
present.

The reporting boundary covers reviewed proposal decisions converted into a
concrete candidate bundle and narrowed into rule, prompt, promotion-review, and
parser artifacts. Reporting remains non-applying, non-deploying, non-mutating,
and non-promoting; state-changing behavior requires separate workflows.

The chain smoke verifies that proposal v2 artifacts plus proposal review
decisions can flow through concrete bundle conversion; the rule/prompt exporter
produces schema-valid `rule_candidates.yaml` and `prompt_candidates.yaml`; the
promotion exporter produces schema-valid recommendation-only
`promotion_recommendation.yaml`; the parser exporter produces schema-valid
candidate-only `parser_candidates.yaml`; and the summary reporter reads those
already-generated artifacts, reports `overall_status: pass` with no errors,
lists the concrete bundle, rule candidates, prompt candidates, promotion
recommendation, and parser candidates as present when generated, passes schema
validation, safety checks, and consistency checks, treats diagnostics as
diagnostics only, excludes skipped/non-accept candidate IDs from
rule/prompt/promotion/parser outputs, and does not rewrite primary export
artifacts.

This smoke is local-development / WSL-friendly. It is not an
attack/victim-log end-to-end smoke and does not require victim logs, Wazuh,
rsyslog, Hydra output, Proxmox, Kali, Ubuntu victim, or existing
`data/runs/**` artifacts.

## 8. Status And Evidence Ownership

This document owns artifact presence, schema validation, cross-artifact
consistency, diagnostics, safety, provenance checks, and the machine-readable
summary shape. The reporter, schema, pipeline-wiring contract, and focused
tests named here are evidence for those boundaries.

The [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents own
current implementation status, validation depth, priorities, and sequencing.
Changes to supported exporters must not turn validation results into approval
or state-change authority.

---

## 9. Boundary Acceptance Criteria

The validation-summary boundary remains valid when:

- the reporter only inspects already-generated artifacts
- optional and required presence are distinguished explicitly
- source and output schemas are checked before success is reported
- skipped items and diagnostics cannot become candidates or recommendations
- provenance and cross-artifact consistency remain reviewable
- the reporter cannot invoke exporters, rewrite artifacts, or authorize state
  changes

---

## 10. One-Line Summary

```text
The RI export artifact validation summary is a non-mutating reporter over already-generated export artifacts; it is not approval to apply, deploy, update baselines, or promote.
```
