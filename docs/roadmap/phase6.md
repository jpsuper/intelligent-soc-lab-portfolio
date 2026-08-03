# Phase6: Behavior Feature + Automated Improvement Loop

## 1. Purpose

Phase6 establishes a behavior-feature-centered, compare-ready SOC improvement loop.

The core goal is to move from scenario-specific detection and one-off AI judgment to a pipeline where each stage produces explicit artifacts that can be compared, judged, reviewed, and improved.

```text
attack
  ↓
detection
  ↓
incident
  ↓
triage
  ↓
pre-case investigation
  └─ investigation_result.json
  ↓
case
  ↓
action
  ↓
DFIR request / approval (when required) / collection execution
  ↓
collection_result.json
  ↓
post-action DFIR run workflow MVP
  ↓
comparison / judge / improvement loop
```

Phase6 is not a single feature implementation phase. It is the integration phase that connects deterministic detection, AI interpretation, evidence-aware investigation, action planning, and reviewable improvement candidates.

---

## 2. Current Status

Phase6 extended MVP is complete.

The defense-side comparison spine now reaches action planning.

```text
triage_result comparison
  ↓
investigation_result comparison
  ↓
action_result comparison
```

Action output is also connected to DFIR request generation.

```text
case.json
  ↓
action_result.json
  ↓
collection_request.json
```

The DFIR collection-result boundary is implemented through a schema, mock result generation, and append-only case enrichment.

```text
collection_request.json
  ↓
DFIR collection execution or manual collection
  ↓
collection_result.json
  ├─ outcome-only case enrichment: collection summary / evidence refs (implemented)
  └─ post-action DFIR run workflow MVP
```

`collection_result.json` is an evidence transport artifact. It records collection outcomes and evidence references, but it does not change verdicts, severity, action approval, `overall_result`, `detected`, or Rule Improvement promotion behavior. It is not an optional input to the pre-case `investigation_result.json`.

The attacker-agent side has progressed from Phase A/B into Phase C artifact contracts, observed-effects runtime generation, and additive observed-effects evaluation alignment.

```text
attacker-agent Phase A
  dispatcher / loader / validator / backend selector
  ↓
attacker-agent Phase B
  attack_scenario_v1 schema
  scenario_004 / 005 / 006 migration
  runtime schema validation
  ↓
attacker-agent Phase C
  attack_result / attack_execution_log schemas
  attack_observed_effects schema
  attack_observed_effects runtime generation
  observed_effects_alignment in evaluation_result
  structured runner event coverage for scenario_004 / 005 / 006
```

---

## 3. Core Design

Phase6 uses a layered feature lifecycle.

```text
detection
  ↓
behavior_features
  ↓
triage
  ↓
derived_features
  ↓
assessment
  ↓
investigation
  ↓
enriched_features / evidence
  ↓
case / action / DFIR
```

### 3.1 behavior_features

Observation-level facts added by deterministic detection.

Examples:

```json
{
  "remote_download": true,
  "temporary_path_execution": true,
  "execution_after_download": true,
  "permission_change_before_execution": true
}
```

### 3.2 derived_features

Interpretations generated during triage.

Examples:

```json
{
  "download_and_execute_chain": true,
  "high_risk_execution_flow": true
}
```

### 3.3 assessment

Operational judgment.

Examples:

```json
{
  "verdict": "suspicious",
  "confidence": "medium",
  "priority": "P2",
  "risk_score": 63
}
```

### 3.4 enriched_features / evidence

Investigation-stage context and evidence.

Examples:

```json
{
  "public_key_login_to_execution_observed": true,
  "process_chain_hit_present": true,
  "network_context_observed": true
}
```

---

## 4. Implemented Capabilities

### 4.1 Detection / DSL

Implemented:

- Atomic detection DSL foundation
- Canonical detection output model
- Initial artifact coverage for:
  - `ssh_failed_login`
  - `ssh_success_login`
  - `ssh_key_login`
  - `authorized_keys_modification`
  - `process_exec`
- Correlation-first incident entry
- DSL evaluator / dedupe / correlation boundary cleanup

Details:

- `docs/design/atomic_detection_dsl.md`

### 4.2 Triage

Implemented:

- AI triage output
- rule-triage baseline
- `derived_features`
- `assessment`
- `triage_diff.json`
- triage comparison harness
- batch comparison across scenario_004 / 005 / 006

### 4.3 Pre-case Investigation

Implemented:

- `investigation_result.json` as an independent pre-case artifact
- evidence-aware investigation fields:
  - `evidence_level`
  - `evidence_summary`
  - `unsupported_claims`
  - `missing_pivots`
  - `recommended_pivots`
- optional evidence inputs:
  - `process_events.json`
  - `process_chain_hits.json`
  - `zeek_enrichment.json`
- investigation harness MVP
- evidence-aware compare / judge refinement

### 4.4 Case

Implemented:

- case generation from incident / triage / investigation
- canonical `case.timeline`
- investigation notes integrated append-only
- case as the input boundary for action planning

### 4.5 Action

Implemented:

- action-agent planning from case
- action policy registry
- canonical action types
- typed targets
- `evidence_refs`
- approval / auto-executable boundary
- action comparison harness MVP
- action compare / judge refinement
- scenario_006 action harness score reaching full score in current test set

### 4.6 DFIR Request and Collection Outcome

Implemented:

- `action_result.json` to `collection_request.json` connection
- collection request trigger from:
  - `request_dfir_collection`
  - `collect_payload_or_process_evidence`
- schema validation for `collection_request.json`
- preservation of action-driven context in `collection_request.context.action_types`
- `collection_result.json` contract and schema
- mock collection result generation
- collected / failed / skipped artifact result model
- source request / action / case traceability
- top-level and per-artifact `output_refs`
- case-agent append-only `dfir_collection_summary` / `dfir_evidence_refs`
- explicit boundary that collection results are evidence transport artifacts, not investigation conclusions
- `post_action_dfir_investigation_result.json` schema and run-based workflow MVP
- limited `Linux.Syslog.SSHLogin` parsing, point-in-time `Linux.ProcessList` parsing, and weak-evidence `Linux.BashHistory` parsing with explicit gaps and limitations
- controlled run-based mock output generation for all three supported artifacts with relative collected-artifact `output_refs` entries
- optional, default-off `scripts/run_process_pipeline.py --run-post-action-dfir` integration
- repository-root `PYTHONPATH` propagation for process-pipeline Python subprocesses; no manual `PYTHONPATH=.` is required

Current boundary:

```text
pre-case Investigation Agent
  → investigation_result.json

collection_result.json
  ├─ outcome-only case enrichment (implemented)
  └─ post-action DFIR run workflow MVP
```

Implemented post-action work:

- dedicated result schema and `--run-id` workflow
- limited `Linux.Syslog.SSHLogin` factual parsing, conservative `Linux.ProcessList` snapshot parsing, and weak `Linux.BashHistory` history-entry parsing
- mock collection output generation for all three supported artifacts under `forensics/mock/`
- optional pipeline generation of `post_action_dfir_investigation_result.json` when `--run-post-action-dfir` is set
- available `Linux.ProcessList` outputs are parsed as point-in-time snapshots; process absence cannot prove non-execution or support host-clean / benign conclusions
- available `Linux.BashHistory` outputs are parsed as weak, user-controlled, timing-sensitive evidence; entries do not confirm execution, and missing entries do not prove non-execution or support host-clean / benign conclusions
- BashHistory facts use `shell_history_observation` with `evidence_strength: weak`, `user_controlled`, `timing_sensitive`, and `shell_history_entry_not_confirmed_execution` details
- deterministic post-action result harness at `scripts/run_post_action_dfir_harness.py`
- example workflow `workflows/post_action_dfir_harness_example.yaml` and rubric `rubrics/post_action_dfir_generic_v1.yaml`
- harness outputs: `judge_input.json`, schema-valid `judge_result.json`, `summary.md`, and `metadata.json`
- harness criteria: evidence inventory coverage, observed fact grounding, limitation and gap clarity, post-action boundary safety, and recommended pivot quality
- harness support classification treats available, parsed `Linux.ProcessList` and `Linux.BashHistory` as supported
- explicit gaps and limitations for unsupported or unavailable outputs
- schema and deterministic `scripts/export_rule_improvement_review_input.py` exporter for review-only `rule_improvement_review_input.json`; source and output are validated, `human_review_required` is `true`, `promotion_allowed` is `false`, and candidate hints keep `candidate_generation_allowed: false`
- optional, default-off `scripts/run_process_pipeline.py --export-ri-review-input` integration; with `--run-post-action-dfir` it runs second, and without that flag it requires an existing post-action result or fails closed
- Draft 2020-12 `schemas/rule_improvement_signal_classification.schema.json`, synthetic fixtures, and boundary tests are implemented; the artifact preserves review provenance, locks candidate generation and promotion off, and enforces label-to-eligibility mapping
- human-operated `scripts/create_rule_improvement_signal_classification.py` helper is implemented; it validates the review input and classification schemas, resolves source signals, copies provenance, and derives eligibility from human labels without AI, candidate generation, or promotion
- Draft 2020-12 `schemas/rule_improvement_ai_review_draft.schema.json`, valid/unsafe fixtures, and boundary tests are implemented for suggestion-only labels, rationales, missing requirements, caveats, questions, and next steps; human-decision, eligibility, candidate, promotion, and state fields are rejected
- docs-first AI review draft prompt/input contract defines normalized context, raw-log/secret exclusion, untrusted-evidence handling, required evidence caveats, schema validation, and evaluation dimensions without adding a prompt file or model integration
- Draft 2020-12 `schemas/rule_improvement_ai_review_draft_prompt_input.schema.json`, minimized ProcessList/BashHistory fixtures, and unsafe-boundary tests are implemented; the prompt input is normalized context, not raw evidence transport or a decision artifact
- versioned `prompts/rule-improvement/ai_review_draft_v1.md` and lightweight boundary tests are implemented; the prompt is suggestions-only, treats evidence text as untrusted, preserves conservative artifact semantics, and has no runtime/model/pipeline behavior
- deterministic prompt-evaluation fixture pairs and focused offline tests are implemented under `tests/fixtures/rule_improvement_ai_review_draft_prompt_eval/`; they cover ProcessList, BashHistory, untrusted instructions, and missing evidence without executing a model
- deterministic `scripts/export_ai_review_draft_prompt_input.py` is implemented; it validates source/output schemas, writes sorted pretty JSON, preserves grounded refs, gaps, limitations, questions, hypotheses with `candidate_generation_allowed: false`, and conservative ProcessList/BashHistory semantics, while excluding raw content and never reading evidence refs; it does not execute a prompt/model, produce an AI review draft or decisions, invoke classification, or mutate state
- deterministic `scripts/export_ai_review_draft_prompt_bundle.py` is implemented as the local future-model handoff boundary; it validates normalized prompt input, embeds the versioned prompt and schema refs, locks model/network execution off, includes exact output provenance (`draft_id`, `source_review_input_id`, `source_review_input_ref`) in `prompt_text`, has no pipeline integration, and creates no response or downstream review artifact
- deterministic `scripts/import_ai_review_draft_model_output.py` is implemented as the local model-output acceptance boundary; it executes no model, validates canonical schema/provenance/locked flags/known signal refs, rejects unsafe output without repair, and has no pipeline or downstream candidate/promotion behavior
- manual-only `scripts/run_ai_review_draft_lmstudio_model.py` is implemented as a local/private-lab challenger runner for explicitly opted-in loopback or private-LAN LM Studio execution; public/cloud endpoints are rejected, private LAN requires a second opt-in, no pipeline integration exists, and untrusted output must pass through the deterministic importer
- manual-only `scripts/run_ai_review_draft_openai_model.py` is implemented as the stable external runner with separate `--allow-model-execution` and `--allow-external-api` opt-ins; it uses the OpenAI Responses API and strict AI review draft Structured Outputs with a deterministic OpenAI-compatible projection of the canonical schema, reads only bundle prompt text plus the schema, and produces untrusted importer input without pipeline, candidate, promotion, or state behavior
- deterministic mock `scripts/generate_mock_ai_review_draft.py` is implemented as the baseline for schema and downstream-review validation; it produces one conservative suggestion per signal, preserves evidence caveats and untrusted-text warnings, and performs no prompt/model/API/network execution, classification, candidate generation, promotion, or state mutation
- deterministic `scripts/compare_ai_review_drafts.py` is implemented for comparing already-produced canonical or candidate AI review drafts. It validates candidates, records invalid inputs, reports schema pass rate, label disagreement, and missing signal coverage, but is descriptive only: it does not execute models, call the importer, read raw logs or evidence refs, select a winner, classify signals, generate candidates, recommend promotion, or mutate state
- a mock-vs-OpenAI smoke comparison succeeded with both candidates schema-valid, schema pass rate 1.0, no missing signal coverage, and one signal label disagreement surfaced for human review; no generated `data/runs/**` artifacts are committed, and the result demonstrates comparison visibility rather than a decision
- optional, default-off `--export-ai-review-draft-prompt-input` and `--generate-mock-ai-review-draft` process-pipeline integration invokes only the deterministic local exporter and mock generator in order; missing sources fail closed, and no decisions, classification, candidate, or promotion artifacts are created

- candidate-review downstream handoff is implemented through deterministic local artifacts: `rule_improvement_candidate_generation_input.json`, `rule_improvement_candidate_draft.json`, `rule_improvement_candidate_review_worksheet.md`, `rule_improvement_candidate_review_decisions_template.json`, completed `rule_improvement_candidate_review_decisions.json`, `rule_improvement_candidate_creation_input.json`, proposal-only `rule_improvement_candidate_proposals_v2.json`, `rule_improvement_proposal_review_decisions_template.json`, canonical `rule_improvement_proposal_review_decisions.json`, non-applying `rule_improvement_concrete_candidate_bundle_v1.json`, and optional generator diagnostics. These artifacts preserve IDs/refs/English enums/evidence refs/limitations and explicit human decision provenance while keeping approval, deployment, baseline update, apply, and promotion out of scope
- optional Japanese candidate review worksheet rewrite is implemented as a read-only human aid. Prompt-bundle generation produces `rule_improvement_candidate_review_worksheet_ja_prompt_bundle.json`; the local LM Studio API runner writes only untrusted `rule_improvement_candidate_review_worksheet_ja_model_output.json`; the existing importer/invariant checker is the only path to `rule_improvement_candidate_review_worksheet_ja_rewritten.md`. Canonical JSON artifacts must not be translated, and IDs, refs, enum values, file paths, safety flags, and backtick-enclosed values must be preserved exactly
- the v2 proposal schema is implemented, including enforced `candidate_type` / `allowed_next_artifact_type` mapping. Standalone deterministic `scripts/generate_rule_improvement_candidate_proposals_v2.py` can produce proposal-only v2 artifacts from reviewed candidate-creation input and optional non-proposal diagnostics for skipped unsupported future schema-valid candidate types. Proposal v2 artifacts and diagnostics are not approval to apply, deploy, update baselines, or promote
- the proposal review decisions schema is implemented, along with deterministic template export and importer/validator scripts. Human-completed proposal review decisions can now be canonicalized into `rule_improvement_proposal_review_decisions.json`; `accept_for_conversion` remains conversion-review-only and is not approval to apply, deploy, update baselines, or promote
- the concrete candidate bundle v1 schema is implemented at `schemas/rule_improvement_concrete_candidate_bundle_v1.schema.json`, and standalone deterministic `scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py` converts canonical `rule_improvement_proposal_review_decisions.json` plus source `rule_improvement_candidate_proposals_v2.json` into non-applying `rule_improvement_concrete_candidate_bundle_v1.json`. The converter validates decisions, proposals, and output bundle schemas, checks source proposal SHA and decision/proposal consistency before writing output, converts only `accept_for_conversion` decisions into `converted_candidates`, and records `reject`, `defer`, `split_required`, and `needs_more_evidence` decisions as `skipped_decisions`
- the concrete candidate bundle is not a legacy candidate artifact and is not apply approval, deployment approval, baseline update approval, or promotion approval. `accept_for_conversion` remains conversion-review-only; it is not approval to apply, deploy, update baselines, or promote
- the standalone deterministic Phase 1 legacy-compatible rule/prompt exporter is implemented at `scripts/export_rule_improvement_legacy_rule_prompt_candidates.py`, with focused tests at `tests/test_export_rule_improvement_legacy_rule_prompt_candidates.py`. It reads `rule_improvement_concrete_candidate_bundle_v1.json`, exports only `candidate_type: rule` and `candidate_type: prompt` into `rule_candidates.yaml` and `prompt_candidates.yaml`, validates the concrete candidate bundle input schema plus legacy rule and prompt candidate output schemas, writes outputs only after validation succeeds, can optionally write non-candidate diagnostics for skipped or unsupported candidates, refuses unsafe output paths and output path collisions, and preserves source bundle/candidate/proposal/review backreferences where legacy schemas permit
- deterministic tmp-path integration smoke coverage is implemented at `tests/test_rule_improvement_phase1_legacy_export_chain_smoke.py`. It creates synthetic schema-valid fixtures under `tmp_path` and proves the artifact chain from `rule_improvement_candidate_proposals_v2.json` plus `rule_improvement_proposal_review_decisions.json` through `rule_improvement_concrete_candidate_bundle_v1.json` to `rule_candidates.yaml` / `prompt_candidates.yaml`; rule candidates appear only in rule output, prompt candidates appear only in prompt output, `promotion_review` and non-accept decisions are reported in diagnostics rather than exported, `promotion_recommendation.yaml` is not created, and generated rule/prompt outputs do not contain apply/deploy/promote-like fields. This is a local-development / WSL-friendly artifact-chain smoke test, not an attack/victim-log end-to-end test, and it does not require victim logs, Wazuh, rsyslog, Hydra output, Proxmox, Kali, Ubuntu victim, or existing `data/runs/**` artifacts
- the Phase 1 exporter is non-applying, non-deploying, and non-promoting. `rule_candidates.yaml` and `prompt_candidates.yaml` are candidate artifacts only; they are not apply approval, deployment approval, baseline update approval, prompt update approval, or promotion approval. `promotion_review`, `parser`, `telemetry`, and `correlation` remain out of Phase 1 export. Diagnostics are not candidate artifacts. Generated `data/runs/**` artifacts remain run outputs and should not be committed
- the parser legacy export contract is documented at `docs/design/rule-improvement/rule_improvement_parser_legacy_export_contract.md`. The parser candidate schema is implemented at `schemas/parser_candidates_schema.json`, with focused tests at `tests/test_parser_candidates_schema.py`; standalone deterministic `scripts/export_rule_improvement_parser_candidates.py` exports accepted `candidate_type: parser` concrete candidates into schema-valid candidate-only `parser_candidates.yaml`, can optionally write diagnostics, rejects approval/apply/deploy/promote-like fields, refuses unsafe output paths, and writes only after validation succeeds. Deterministic tmp-path parser export chain smoke coverage is implemented at `tests/test_rule_improvement_parser_export_chain_smoke.py`; it proves the local artifact chain from proposal/review decisions through the concrete bundle to schema-valid `parser_candidates.yaml`, requires no victim logs, Wazuh, rsyslog, Hydra output, Proxmox, Kali, Ubuntu victim, or existing `data/runs/**` artifacts, and remains candidate-only. Parser process-pipeline wiring, parser apply workflow, parser deployment workflow, and automatic parser update are not implemented
- the standalone deterministic promotion recommendation exporter is implemented at `scripts/export_rule_improvement_promotion_recommendation.py`, with focused tests at `tests/test_export_rule_improvement_promotion_recommendation.py`. It reads `rule_improvement_concrete_candidate_bundle_v1.json`, considers only converted `candidate_type: promotion_review` items with `allowed_next_artifact_type: promotion_review_recommendation`, validates bundle input and legacy promotion recommendation output schemas, writes recommendation-only `promotion_recommendation.yaml` only after validation succeeds, can optionally write non-recommendation diagnostics for skipped items, refuses unsafe paths and output collisions, and preserves bundle/candidate/proposal/review backreferences where the legacy schema permits
- deterministic tmp-path promotion recommendation export-chain smoke coverage is implemented at `tests/test_rule_improvement_promotion_recommendation_export_chain_smoke.py`. It creates synthetic schema-valid fixtures under `tmp_path` and proves `rule_improvement_candidate_proposals_v2.json` plus `rule_improvement_proposal_review_decisions.json` can convert into `rule_improvement_concrete_candidate_bundle_v1.json`, preserve schema-safe promotion-review proposal payload fields into concrete bundle payloads, and export schema-valid recommendation-only `promotion_recommendation.yaml`. Non-promotion candidates and non-accept/skipped decisions are not included in the recommendation output, diagnostics report unsupported/skipped items deterministically, and the promotion exporter does not create `rule_candidates.yaml` or `prompt_candidates.yaml`. This is local-development / WSL-friendly and does not require victim logs, Wazuh, rsyslog, Hydra output, Proxmox, Kali, Ubuntu victim, or existing `data/runs/**` artifacts
- proposal v2 supports optional schema-safe `payload` fields for later narrowing exporters. The bundle converter preserves those optional payload fields into concrete candidate bundle payloads, but fails closed if optional payload attempts to override base metadata such as `target`, `source_signal_ref`, `source_label`, `source_fact_ids`, `required_evidence_refs`, `priority`, or `review_status`
- deterministic validation summary reporter is implemented at `scripts/summarize_rule_improvement_export_artifacts.py`, with focused tests at `tests/test_summarize_rule_improvement_export_artifacts.py`. It inspects already-generated RI export artifacts such as the concrete bundle, `rule_candidates.yaml`, `prompt_candidates.yaml`, `promotion_recommendation.yaml`, optional `parser_candidates.yaml`, and export diagnostics, then writes `rule_improvement_export_artifact_validation_summary.json` with presence, schema validation, cross-artifact consistency, diagnostics consistency, safety checks, and provenance/backreference checks. `parser_candidates.yaml` remains optional and is validated only when present; parser diagnostics remain diagnostics only. It is non-mutating validation/reporting only, not human review, and not apply, deployment, baseline update, prompt update, parser update, telemetry update, correlation update, or promotion approval
- the validation summary schema is implemented at `schemas/rule_improvement_export_artifact_validation_summary.schema.json`, with focused schema tests at `tests/test_rule_improvement_export_artifact_validation_summary_schema.py`. The reporter validates `rule_improvement_export_artifact_validation_summary.json` against this schema before writing; schema validation failure is fail-closed and does not write the summary output. This does not change safety semantics, invoke exporters, create rule candidates, prompt candidates, parser candidates, or promotion recommendations, update active agents or production state, or add apply, deployment, baseline update, prompt update, parser update, telemetry update, correlation update, promotion workflow, or automatic promotion behavior
- disabled-by-default process-pipeline wiring is implemented in `scripts/run_process_pipeline.py` behind `--enable-ri-export-validation-summary`, as defined by `docs/design/rule-improvement/rule_improvement_export_validation_summary_pipeline_wiring_contract.md`. When explicitly enabled, it runs after existing RI export steps, calls the summary reporter for the current run directory, writes only `rule_improvement_export_artifact_validation_summary.json`, preserves reporter schema validation before write and fail-closed failure propagation, does not invoke exporters, and does not create `rule_candidates.yaml`, `prompt_candidates.yaml`, `promotion_recommendation.yaml`, or `parser_candidates.yaml`. Default pipeline behavior is unchanged
- the Rule Improvement export MVP is complete for the current candidate-generation boundary: reviewed proposal decisions can be converted into a concrete candidate bundle, narrowed into rule, prompt, promotion-review, and parser export artifacts, and checked by the export artifact validation summary. This MVP remains non-applying, non-deploying, non-mutating, review-oriented, and does not implement baseline updates, prompt updates, parser updates, telemetry updates, correlation updates, a promotion workflow, or automatic promotion
- deterministic tmp-path export validation summary chain smoke coverage is implemented at `tests/test_rule_improvement_export_validation_summary_chain_smoke.py`. It uses synthetic schema-valid fixtures under `tmp_path` and proves the implemented chain from `rule_improvement_candidate_proposals_v2.json` plus `rule_improvement_proposal_review_decisions.json` through `rule_improvement_concrete_candidate_bundle_v1.json`, schema-valid `rule_candidates.yaml` / `prompt_candidates.yaml`, schema-valid recommendation-only `promotion_recommendation.yaml`, optional schema-valid `parser_candidates.yaml`, and `rule_improvement_export_artifact_validation_summary.json`. The smoke verifies the validation summary reporter reads already-generated artifacts, reports `overall_status: pass` with no errors, lists the concrete bundle, rule candidates, prompt candidates, promotion recommendation, and parser candidates as present when generated, passes schema validation, safety checks, and consistency checks, treats diagnostics as diagnostics only, excludes skipped/non-accept candidate IDs from rule/prompt/promotion/parser outputs, and does not rewrite primary export artifacts. It is local-development / WSL-friendly, not an attack/victim-log end-to-end smoke, and requires no victim logs, Wazuh, rsyslog, Hydra output, Proxmox, Kali, Ubuntu victim, or existing `data/runs/**` artifacts
- the validation summary reporter does not invoke exporter scripts and does not create `rule_candidates.yaml`, `prompt_candidates.yaml`, `promotion_recommendation.yaml`, or `parser_candidates.yaml`; those artifacts are created only by their exporters. `promotion_recommendation.yaml` remains recommendation-only, `parser_candidates.yaml` remains candidate-only and optional, and no apply, deployment, baseline update, prompt update, parser update, telemetry update, correlation update, promotion workflow, or automatic promotion is implemented
- `promotion_recommendation.yaml` is recommendation-only. It is not apply approval, deployment approval, baseline update approval, prompt update approval, or promotion approval; the exporter is non-applying, non-deploying, and non-promoting, no active-agent or production state is changed, and later explicit human review plus a separate promotion workflow is required before any state-changing promotion
- still not implemented: parser process-pipeline wiring, telemetry legacy export, correlation legacy export, attack-to-detection-to-RI E2E smoke, apply workflow, deployment workflow, baseline update workflow, prompt update workflow, parser update workflow, telemetry update workflow, correlation update workflow, promotion workflow, or automatic promotion
Current intended AI-assisted Rule Improvement review flow:

```text
rule_improvement_review_input.json
  -> rule_improvement_ai_review_draft_prompt_input.json
  -> rule_improvement_ai_review_draft_prompt_bundle.json
  -> manual model/mock/OpenAI/LM Studio execution
  -> untrusted rule_improvement_ai_review_draft_model_output.json
  -> importer acceptance boundary
  -> canonical rule_improvement_ai_review_draft.json / named draft artifacts
  -> optional compare_ai_review_drafts.py descriptive comparison
  -> human_review_worksheet.md
  -> optional human_review_packet_ja.md
  -> human_decisions_template.json
  -> human-completed decisions JSON
  -> rule_improvement_signal_classification.json
  -> rule_improvement_candidate_generation_input.json
  -> rule_improvement_candidate_draft.json
  -> rule_improvement_candidate_review_worksheet.md
  -> optional rule_improvement_candidate_review_worksheet_ja_prompt_bundle.json
  -> optional LM Studio API runner
  -> untrusted rule_improvement_candidate_review_worksheet_ja_model_output.json
  -> importer invariant check
  -> optional rule_improvement_candidate_review_worksheet_ja_rewritten.md
  -> rule_improvement_candidate_review_decisions_template.json
  -> human-completed candidate review decisions JSON
  -> rule_improvement_candidate_review_decisions.json
  -> rule_improvement_candidate_creation_input.json
  -> optional standalone rule_improvement_candidate_proposals_v2.json
     plus optional generator diagnostics
  -> optional rule_improvement_proposal_review_decisions_template.json
  -> human-completed proposal review decisions JSON
  -> rule_improvement_proposal_review_decisions.json
  -> scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py
  -> rule_improvement_concrete_candidate_bundle_v1.json
  -> optional scripts/export_rule_improvement_legacy_rule_prompt_candidates.py
  -> optional rule_candidates.yaml / prompt_candidates.yaml
  -> optional scripts/export_rule_improvement_promotion_recommendation.py
  -> optional promotion_recommendation.yaml
  -> optional scripts/export_rule_improvement_parser_candidates.py
  -> optional parser_candidates.yaml
  -> optional scripts/summarize_rule_improvement_export_artifacts.py
  -> optional rule_improvement_export_artifact_validation_summary.json
```
- deterministic local `scripts/export_ai_review_draft_human_worksheet.py` is implemented for schema-valid draft-to-Markdown review handoff; optional, default-off `--export-ai-review-draft-human-worksheet` pipeline integration requires an existing draft, runs after mock generation when combined, and creates no decisions, classification, candidates, promotion recommendation, state mutation, or prompt/model execution
- deterministic `scripts/export_ri_signal_classification_decisions_template.py` is implemented for schema-valid draft-to-human-authoring handoff; optional, default-off `--export-ri-signal-classification-decisions-template` pipeline integration requires an existing draft and runs after worksheet export when combined without depending on it. The output remains an incomplete template, with no completed decisions, classification, eligibility, helper invocation, candidates, promotion, or state mutation
- `docs/runbooks/ai_assisted_rule_improvement_review_handoff.md` documents the deterministic/local artifact flow, default-off flags, human handoff, prohibited automation, evidence caveats, and smoke checks

Remaining post-action work:

- broader mock outputs, additional artifact parsers, and real Velociraptor collection ingestion
- review-gated case or external update proposals
- default-on or pipeline-integrated real model execution remains later; current model runners are manual-only and outputs remain untrusted until imported
- parser process-pipeline wiring remains future work, telemetry/correlation candidate artifacts remain future work, promotion recommendations are recommendation-only artifacts, and no automatic apply, update, or promotion exists

### 4.7 Rule Improvement Loop

Implemented:

- Rule Improvement Agent
- artifact-aware candidate generation
- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`
- `parser_candidates.yaml`
- `rule_improvement_export_artifact_validation_summary.json`
- `candidate_review.md`
- `observed_effects_alignment_signals.json`
- observed-effects alignment signals surfaced in `candidate_review.md`
- Rule Improvement export MVP for the current candidate-generation boundary
- batch validation support

Details:

- `docs/design/rule-improvement/rule_improvement_orchestrator_contract.md`
- `docs/design/rule-improvement/observed_effects_alignment_signal_contract.md`
- `docs/design/rule-improvement/post_action_dfir_review_input_contract.md`
- `docs/design/rule-improvement/rule_improvement_legacy_compatible_export_contract.md`
- `docs/design/rule-improvement/rule_improvement_parser_legacy_export_contract.md`
- `docs/design/rule-improvement/rule_improvement_export_artifact_validation_summary_contract.md`

### 4.8 Attacker Agent

Implemented:

- Phase A dispatcher skeleton
- scenario loader / validator / backend selector
- step backend and shell backend
- scenario contract tests
- `attack_scenario.schema.json`
- `attacker_scenario_schema.md`
- scenario_004 / 005 / 006 migration to `attack_scenario_v1`
- runtime schema validation for schema-v1 scenarios
- schema metadata bridge into `attack_result.json`
- `attack_result.schema.json`
- `attack_execution_log.schema.json`
- `attack_observed_effects.schema.json`
- attacker-agent `attack_result.json` validation
- attacker-agent `attack_execution_log.json` validation
- synthetic observed-effects validation tests for scenario_005 / scenario_006
- process pipeline `attack_result.json` alignment with `attack_result.schema.json`
- attacker-agent runtime generation of `attack_observed_effects.json`
- shell backend `stdout` / `stderr` preservation in `attack_execution_log.json`
- additive `structured_events` in `attack_execution_log.json` when valid
  `ATTACK_EVENT_JSON:` lines are present
- scenario_004 execute confirmation for observed effects:
  - `ssh_bruteforce_attempted` → `ssh_failed_login`
  - `ssh_login_succeeded` → `ssh_success_login`
  - `authorized_keys_write_succeeded` → `authorized_keys_modification`
- scenario_005 execute confirmation for observed effects:
  - `ssh_login_succeeded` → `ssh_key_login`
- scenario_006 execute confirmation for observed effects:
  - `ssh_login_succeeded` → `ssh_key_login`
  - `payload_execution_succeeded` → `process_exec`
- additive `observed_effects_alignment` in `evaluation_result.json`
- scenario_004 alignment smoke check:
  - `ssh_failed_login` → `attacker_and_defender_observed`
  - `ssh_success_login` → `attacker_and_defender_observed`
  - `authorized_keys_modification` → `attacker_and_defender_observed`
- scenario_005 alignment smoke check:
  - `ssh_key_login` → `attacker_and_defender_observed`
- scenario_006 alignment smoke check:
  - `ssh_key_login` → `attacker_and_defender_observed`
  - `process_exec` → `attacker_and_defender_observed`
- observed-effects alignment keeps attacker-side observations separate from defender-side detections
- structured runner output contract
- attacker artifact catalog for scenario family / event / artifact mappings
- defender coverage matrix for scenario_004 through scenario_008 artifact telemetry, pivots, and gaps
- endpoint telemetry coverage design for post-login artifacts (`process_exec`, `suspicious_file_write`, `system_discovery`, `authorized_keys_modification`)
- auditd minimal coverage design for first-pass endpoint telemetry collection of current post-login artifacts
- auditd smoke checklist for future manual validation of auditd endpoint telemetry
- lab-scoped auditd minimal rules for first-pass endpoint telemetry validation
- structured runner event parser for `ATTACK_EVENT_JSON:` stdout lines
- parser tests for valid / invalid / mixed stdout cases
- scenario_004 / 005 / 006 / 007 / 008 runners emit structured events for current observed-effect mappings:
  - scenario_004: `ssh_bruteforce_attempted` → `ssh_failed_login`
  - scenario_004: `ssh_login_succeeded` → `ssh_success_login`
  - scenario_004: `authorized_keys_write_succeeded` → `authorized_keys_modification`
  - scenario_005: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_006: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_006: `payload_execution_succeeded` → `process_exec`
  - scenario_007: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_007: `suspicious_file_write_succeeded` → `suspicious_file_write`
  - scenario_008: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_008: `system_discovery_succeeded` → `system_discovery`
- attacker-agent `attack_observed_effects.json` generation prefers structured runner events when present
- legacy stdout marker / exit-code fallback remains compatible
- shell backend static contract tests enforce runner path shape, executable bit,
  timeout / `state_changing` shape, and inline shell field boundaries
- `docs/operations/smoke_runbook.md` documents structured runner and
  observed-effects smoke checks
- scenario_006 suppresses repeated SSH known-host warning noise in stderr
- Rule Improvement Agent can generate `observed_effects_alignment_signals.json`
  from `evaluation_result.observed_effects_alignment`
- `candidate_review.md` surfaces observed-effects alignment signals for human review
- observed-effects alignment signals remain separate from automatic rule candidate generation

Details:

- `docs/roadmap/attacker-agent-roadmap.md`
- `docs/design/attacker-agent/scenario_schema.md`

---

## 5. Run Artifacts

Typical run directory:

```text
data/runs/<run_id>/
  process_events.json
  interesting_process_events.json
  process_chain_hits.json
  ssh_auth_events.json
  dsl_detection_outputs_auth_runlocal.json
  dsl_detection_outputs_process.json
  dsl_auth_deduped_detections.json
  dsl_deduped_detections.json
  dsl_correlations.json
  incident.json
  triage_result.json
  investigation_result.json
  triage_rule.json
  triage_diff.json
  attack_result.json
  attack_execution_log.json
  attack_observed_effects.json
  evaluation_result.json
  case.json
  action_result.json
  collection_request.json
  # Optional: produced only after collection execution or mock generation
  collection_result.json
  decision_log.json
  zeek_conn_events.json
  zeek_http_events.json
  zeek_enrichment.json
```

Post-action DFIR follow-on artifacts:

```text
data/runs/<run_id>/
  collection_result.json
  post_action_dfir_investigation_result.json
```

The dedicated workflow reads `collection_result.json` and supported collected outputs without feeding either artifact back into `investigation_result.json`.

Typical harness run directory:

```text
data/harness_runs/<harness_run_id>/
  input/
  optional_inputs/
  agents/
  compare.json
  judge_result.json
  summary.md
  metadata.json
```

Triage harness may also produce:

```text
rule_candidates.yaml
prompt_candidates.yaml
promotion_recommendation.yaml
parser_candidates.yaml
rule_improvement_export_artifact_validation_summary.json
observed_effects_alignment_signals.json
candidate_review.md
```

---

## 6. Scenario Coverage

### scenario_004

SSH brute force followed by authorized_keys persistence installation.

Primary artifacts:

```text
ssh_failed_login
ssh_success_login
authorized_keys_modification
```

### scenario_005

SSH public-key persistence reuse.

Primary artifact:

```text
ssh_key_login
```

### scenario_006

SSH public-key login followed by post-login command execution.

Primary artifacts:

```text
ssh_key_login
process_exec
```

Scenario details are intentionally not expanded in this roadmap document. The scenario contracts are now maintained through `attack_scenario_v1` YAML files and the attacker-agent roadmap.

---

## 7. Related Design Documents

Use this document as the Phase6 index. Detailed contracts live in dedicated design docs.

| Topic | Document |
|---|---|
| Atomic Detection DSL | `docs/design/atomic_detection_dsl.md` |
| Rule Improvement / Orchestrator / Harness contracts | `docs/design/rule-improvement/rule_improvement_orchestrator_contract.md` |
| Observed effects Rule Improvement signal | `docs/design/rule-improvement/observed_effects_alignment_signal_contract.md` |
| Post-action DFIR Rule Improvement review input | `docs/design/rule-improvement/post_action_dfir_review_input_contract.md` |
| Rule Improvement human signal classification | `docs/design/rule-improvement/rule_improvement_signal_classification_contract.md` |
| AI-assisted Rule Improvement review draft | `docs/design/rule-improvement/ai_assisted_review_draft_contract.md` |
| AI review draft prompt/input | `docs/design/rule-improvement/ai_review_draft_prompt_input_contract.md` |
| Wazuh integration direction | `docs/design/wazuh_integration_design.md` |
| DFIR collection result contract | `docs/design/dfir/collection_result_contract.md` |
| DFIR collection result ingestion | `docs/design/dfir/collection_result_ingestion.md` |
| Post-action DFIR investigation | `docs/design/dfir/post_action_dfir_investigation.md` |
| Normalized endpoint event contract | `docs/design/defender/normalized_endpoint_event_contract.md` |
| Endpoint telemetry coverage | `docs/design/defender/endpoint_telemetry_coverage.md` |
| Auditd investigation signal enrichment | `docs/design/investigation/auditd_signal_enrichment.md` |
| Attacker scenario schema | `docs/design/attacker-agent/scenario_schema.md` |
| Attack artifact contract | `docs/design/attacker-agent/attack_artifact_contract.md` |
| Attack observed effects contract | `docs/design/attacker-agent/attack_observed_effects_contract.md` |
| Observed effects evaluation contract | `docs/design/attacker-agent/observed_effects_evaluation_contract.md` |
| Shell backend contract | `docs/design/attacker-agent/shell_backend_contract.md` |
| Structured runner output contract | `docs/design/attacker-agent/structured_runner_output_contract.md` |
| Attacker-agent roadmap | `docs/roadmap/attacker-agent-roadmap.md` |
| Rule Improvement candidate creation workflow | `docs/design/rule-improvement/rule_improvement_candidate_creation_workflow.md` |

---

## 8. Definition of Done

Phase6 extended MVP is considered complete when the following are true.

Completed:

- behavior / derived / assessment / enriched feature boundaries are defined
- detection emits behavior features and canonical artifacts
- triage and rule-triage are comparable
- investigation is an independent artifact
- case timeline is canonical
- action planning is grounded in case / evidence
- triage harness is implemented
- investigation harness is implemented
- action harness is implemented
- Rule Improvement Agent produces reviewable candidates
- batch validation works across scenario_004 / 005 / 006
- Action output can trigger DFIR collection request
- collection request schema validation exists
- `collection_result.json` contract, schema, and mock generation exist
- case-agent can append collection summary and evidence references without changing assessment fields
- pre-case Investigation Agent and post-action DFIR workflow are explicitly separate
- post-action DFIR result schema, run workflow, and `Linux.Syslog.SSHLogin` parser are implemented
- mock collection writes the controlled `Linux.Syslog.SSHLogin` output and links it through `output_refs`
- attacker-agent Phase A dispatcher is implemented
- attacker-agent Phase B scenario schema unification is implemented for scenario_004 / 005 / 006
- schema-v1 scenarios are runtime-validated
- attack_result includes schema-derived metadata
- attack artifact schemas exist for result, execution log, and observed effects
- attacker-agent generates schema-compatible `attack_observed_effects.json`
- shell backend preserves stdout / stderr for observed-effects derivation
- attack_execution_log includes additive `structured_events` without replacing
  raw execution events or streams
- scenario_004 / 005 / 006 observed-effects runtime coverage is confirmed
- evaluation_result includes additive `observed_effects_alignment`
- scenario_004 / 005 / 006 observed-effects alignment smoke checks are confirmed
- observed-effects alignment was confirmed without changing existing verdict behavior
- normalized endpoint event schema exists
- auditd telemetry can be converted into `endpoint_events.json`
- investigation can consume optional `endpoint_events.json`
- endpoint telemetry contributes factual observed facts and supporting signals
- endpoint telemetry can derive evidence-grounded enriched features
- endpoint telemetry can derive missing / recommended pivots for payload and command context
- investigation endpoint-events harness reaches:
  - `evidence_specificity = 0.8`
  - `enriched_feature_quality = 0.85 / 0.9`
  - `missing_pivot_detection = 1.0`
- structured runner output contract exists
- structured runner event parser and tests exist
- scenario_004 / 005 / 006 / 007 / 008 emit structured runner events for their current observed-effect mappings
- attacker-agent observed-effects generation prefers structured runner events when present
- legacy stdout marker / exit-code fallback remains compatible
- shell backend static contract tests enforce runner path, executable bit,
  timeout / `state_changing` shape, and inline shell field boundaries
- structured runner and observed-effects smoke checks are documented in
  `docs/operations/smoke_runbook.md`
- Rule Improvement Agent can generate `observed_effects_alignment_signals.json`
  from `evaluation_result.observed_effects_alignment`
- `candidate_review.md` surfaces observed-effects alignment signals for human review
- observed-effects alignment signals do not automatically populate `rule_candidates.yaml`
- observed-effects signal generation does not change `overall_result` or `detected`
- reviewed proposal decisions can be converted into a concrete candidate bundle
- rule / prompt / promotion-review / parser export artifacts are implemented for the current candidate-generation boundary
- export artifact validation summary can inspect the implemented export artifact set
- Rule Improvement export MVP remains non-applying, non-deploying, non-mutating, and review-oriented

---

## 9. Current Open Items

Remaining work should be treated as follow-on work, not Phase6 blocker work.

### Defense-side follow-ons

- candidate apply / promotion apply with human approval
- Wazuh integration as a baseline collection / alert / search source
- broader mock or collector output generation and additional artifact parsers
- Velociraptor actual collection result ingestion
- executor / DFIR execution-result comparison harness after post-action artifact semantics stabilize; the result-quality harness MVP is complete
- process execution beyond current SSH / persistence scenarios
- multi-host correlation
- external intelligence enrichment

### Offense-side follow-ons

- reviewer-approved conversion from observed-effects signals to concrete rule or prompt candidates
- richer attack artifacts beyond the current scenario_004 / 005 / 006 / 007 / 008 coverage
- extend observed-effects alignment smoke checks only when new scenario families introduce new artifact mappings
- maintain structured runner event coverage for scenario_004 / 005 / 006 / 007 / 008 and extend it only when new scenario families require new mappings
- shell backend formalization follow-ons
- TTP catalog
- TTP composition mode
- autonomous planner / supervisor
- assessment mode

---

## 10. Next Priorities

Recommended next implementation order after Phase6 / Rule Improvement export MVP completion:

1. Define Phase7 Deception MVP scope before implementation
   - deception inventory
   - deception hit event contract
   - trap detection boundary
   - incident / triage handoff
2. Add a small Linux deception path first
   - honey credential or decoy file
   - high-confidence trap hit
   - no automatic containment
3. Define scenario family expansion policy
   - attacker-side observed effects
   - defender-side observed artifacts
   - primary artifact selection
   - alignment smoke requirements
4. Add Windows telemetry MVP after the scenario policy
   - Windows process / PowerShell / logon fixtures
   - canonical endpoint event mapping
   - minimal detection and incident smoke
5. Add Wazuh / SIEM integration as optional alert/search/evidence source
   - keep DSL / canonical detection output as source of truth
   - normalize Wazuh alerts into lab artifacts or evidence refs
6. Continue DFIR follow-ons only where they improve evidence quality
   - broader collector outputs
   - real Velociraptor ingestion
   - executor / DFIR result comparison after artifact semantics stabilize
7. Keep Rule Improvement apply / deploy / update / promotion workflows as separate future work
   - explicit human approval required
   - no automatic promotion

---

## 11. Success Summary

Phase6 established a compare-ready SOC pipeline.

```text
behavior_features
  ↓
derived_features
  ↓
assessment
  ↓
investigation evidence / enriched_features
  ↓
AI / rule / action compare
  ↓
judge
  ↓
artifact-aware improvement candidates
  ↓
human review
  ↓
batch validation
```

The most important outcome is not one specific detector or agent. The outcome is that the lab now has a structured improvement loop where stage outputs are explicit, comparable, reviewable, and incrementally improvable.
