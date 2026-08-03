# Rule Improvement Agent / Orchestrator Contract

## 1. Purpose

次の段階では、いきなり planner + specialist の本格マルチエージェントに進むのではなく、
**contract / compare / judge を持つ multi-agent comparison harness** の土台を作る。

そのために、まず以下の責務を明確に分離する。

- Orchestrator
- Rule Improvement Agent
- Triage Harness（compare / judge を含む）
- Investigation Harness
- Action Harness

この整理の目的は、将来の triage harness / investigation harness / action harness / judge / batch compare runner を無理なく載せられる形にすることにある。

---

## 2. Current Position

Phase6 is now beyond the initial comparison-harness MVP. The comparison spine has reached triage, investigation, and action, and action output is connected to DFIR request generation.

Already established:

- scenario_004: authorized_keys persistence installation
- scenario_005: persistence reuse
- scenario_006: key reuse followed by command execution
- atomic detection DSL foundation
- correlation-first incident entry
- DSL boundary cleanup
- case canonical timeline
- scenario_006 investigation enrichment
- run-based artifact isolation
- `incident / triage / investigation / case / action / evaluation` artifacts
- triage comparison harness foundation
- investigation harness MVP and evidence-aware refinement
- action comparison harness MVP and compare / judge refinement
- compare / judge schemas and generic rubrics
- AI current / AI variant / deterministic baseline comparison where applicable
- artifact synonym handling and primary-artifact-aware evaluation
- minimal Rule Improvement Agent
- artifact-aware candidate generation
- `rule_candidates.yaml` / `prompt_candidates.yaml` / `promotion_recommendation.yaml`
- `candidate_review.md` human review report
- scenario_004 / 005 / 006 batch validation
- action-agent coverage / grounding / specificity improvements
- action policy registry
- action_result to DFIR collection request connection
- `collection_request.json` schema validation
- attacker-agent Phase A dispatcher skeleton
- attacker-agent scenario contract tests
- attacker-agent Phase B scenario schema unification for scenario_004 / 005 / 006
- runtime validation for `attack_scenario_v1`
- attack_result metadata bridge from scenario schema
- normalized endpoint event contract / schema
- auditd to `endpoint_events.json` converter
- `endpoint_events.json` optional investigation harness input
- endpoint-derived investigation `enriched_features`
- endpoint-derived `missing_pivots` / `recommended_pivots`
- deterministic judge scoring improvements for:
  - `evidence_specificity`
  - `enriched_feature_quality`
  - `missing_pivot_detection`
- stale roadmap archive cleanup

Current level:

```text
Level 1: single pipeline harness         = complete
Level 2: multi-agent comparison harness  = established through action
Level 3: planner + specialist harness    = future
```

Current comparison spine:

```text
triage_result comparison
  ↓
investigation_result comparison
  ↓
action_result comparison
```

Action / DFIR connection:

```text
case.json
  ↓
action_result.json
  ↓
collection_request.json
```

Attacker-agent bridge:

```text
attack_scenario_v1
  ↓
runtime schema validation
  ↓
attack_result metadata bridge
```

Next priority is no longer more harness expansion. The comparison spine is stable through action, and endpoint telemetry is now connected through investigation evidence, enriched features, and pivots.

Current near-term priority is documentation and selective follow-on stabilization:

```text
endpoint_events.json
  ↓
observed_facts / supporting_signals
  ↓
endpoint-derived enriched_features
  ↓
missing_pivots / recommended_pivots
  ↓
deterministic judge evaluation
```

Attacker-side artifact contracts remain important, but `attack_result.schema.json`,
`attack_execution_log.schema.json`, and `attack_observed_effects.json` are now implemented
and should be maintained rather than treated as the next initial design target.

## 3. Guiding Principle

今やるべきことは agent を増やすことではなく、**比較可能な実験枠組みを固定すること** である。

```text
single pipeline
  ↓
compare-capable pipeline
  ↓
judge-capable pipeline
```

まだやらないこと:

- planner + specialist の全面導入
- shared memory / graph の本格導入
- autonomous agent society
- executor / actual execution の本格比較
- cross-stage global optimization
- candidate の自動適用
- current / variant の自動ファイル置換

---

## 4. Orchestrator Responsibility

### 4.1 Positioning

Orchestrator は **判断主体ではなく、実験実行主体** である。

役割は、

- どの入力を
- どの agent に
- どの順番で流し
- compare / judge / archive まで接続するか

を固定することにある。

### 4.2 Orchestrator does

- stage の実行順序を管理する
- input artifact / output artifact を接続する
- 同一入力を複数 agent に配布する
- compare を呼び出す
- judge を呼び出す
- rerun / batch 実行を扱う
- harness run の保存先を管理する
- experiment 定義に従って runner を実行する
- 各 agent の結果を比較実験用ディレクトリへ保存する

### 4.3 Orchestrator does not

- 改善案の意味付け
- prompt / rule / policy の改善提案生成
- root cause 分析そのもの
- rule promotion 判断
- compare 結果の運用的解釈そのもの

### 4.4 Output model

Orchestrator 自体は単一の業務 artifact を返す agent ではなく、
**harness run ディレクトリ全体** を成果物とする。

```text
data/
  harness_runs/
    <harness_run_id>/
      input/
      optional_inputs/
      agents/
      compare.json
      judge_result.json
      summary.md
      metadata.json
      rule_candidates.yaml
      prompt_candidates.yaml
      promotion_recommendation.yaml
      candidate_review.md
```

### 4.5 One-line definition

```text
Orchestrator = flow control + artifact routing + compare/judge execution + experiment persistence
```

---

## 5. Rule Improvement Agent Responsibility

### 5.1 Positioning

Rule Improvement Agent は **改善候補生成主体** である。

Orchestrator が土台を担い、Rule Improvement Agent が compare / judge を読み、差分を improvement candidate に変換する。

### 5.2 Rule Improvement Agent does

- compare 結果を読む
- judge 結果を読む
- 差分の意味を整理する
- feature lifecycle 上の gap を抽出する
- rule candidate を生成する
- prompt candidate を生成する
- policy candidate を生成する（future）
- promotion recommendation を生成する
- primary artifact に応じた artifact-aware candidate を生成する
- improvement hint を review 可能な形に正規化する

### 5.3 Rule Improvement Agent does not

- pipeline 全体の実行順管理
- run ディレクトリ管理
- batch rerun 制御
- artifact routing
- compare / judge の実行制御そのもの

### 5.4 Initial inputs

最初は以下で十分。

```text
compare.json
judge_result.json
```

The implemented deterministic exporter produces `rule_improvement_review_input.json` as review context for a future human signal-classification gate. It validates both source and output, is not an initial candidate input, does not auto-populate candidate YAML, and always carries `human_review_required: true` and `promotion_allowed: false`. See `docs/design/rule-improvement/post_action_dfir_review_input_contract.md`.

The human classification boundary is defined in `docs/design/rule-improvement/rule_improvement_signal_classification_contract.md`, and its Draft 2020-12 artifact schema is implemented at `schemas/rule_improvement_signal_classification.schema.json`. The human-operated `scripts/create_rule_improvement_signal_classification.py` helper validates a review input and human decisions, resolves signal provenance, derives eligibility, and writes `rule_improvement_signal_classification.json`. This remains a reviewer decision record, not AI integration, a Rule Improvement Agent candidate, or promotion output; `candidate_generation_started` and `promotion_allowed` remain false.

The optional future AI drafting boundary is defined in `docs/design/rule-improvement/ai_assisted_review_draft_contract.md`, and its suggestions-only schema and versioned prompt are implemented. No prompt execution or runtime model integration exists. `rule_improvement_ai_review_draft.json` is not an orchestrator input for candidate generation, cannot create a classification, and cannot mutate Rule Improvement or response state.

The minimized prompt/input envelope is defined in `docs/design/rule-improvement/ai_review_draft_prompt_input_contract.md`, and its schema and deterministic `scripts/export_ai_review_draft_prompt_input.py` exporter are implemented. The exporter validates source and output, preserves normalized provenance and evidence caveats, excludes raw logs and secrets, and treats retained evidence text as untrusted data. It reads no evidence refs and adds no prompt execution, classification, candidate, promotion, or model behavior.

The deterministic mock `scripts/generate_mock_ai_review_draft.py` generator is implemented for artifact-shape and downstream-review testing. Optional, default-off process-pipeline flags invoke the local exporter and mock generator in order and fail closed when a source is absent. They execute no prompt or model, call no classification helper, and create no decisions, candidates, or promotion recommendation. The mock output remains suggestions only and cannot mutate state.

The deterministic local `scripts/export_ai_review_draft_human_worksheet.py` exporter renders a schema-valid AI review draft as a Markdown worksheet with blank human review fields. The optional, default-off process-pipeline flag invokes only this exporter after draft generation, requires an existing draft, and fails closed otherwise. It executes no prompt or model and does not create decisions JSON, classification output, candidates, promotion recommendations, or state changes. Human decisions remain separately authored input to the human-operated classification helper.

The deterministic `scripts/export_ri_signal_classification_decisions_template.py` exporter creates only an incomplete human-editable JSON template from a schema-valid AI review draft. It preserves signal refs while replacing AI suggestions with placeholders, derives no eligibility or reviewer metadata, and invokes no helper. Its optional, default-off process-pipeline flag requires an existing draft, runs after mock draft and worksheet stages when combined, and fails closed otherwise; it does not require worksheet output. A human must independently complete and extract the decisions array before using the classification helper; no classification, candidate, promotion, or state change is created by the exporter.

Operational execution and human handoff are documented in `docs/runbooks/ai_assisted_rule_improvement_review_handoff.md`.

### 5.5 Initial outputs

最初の MVP では、Rule Improvement Agent 自体は以下の3つを出力する。

```text
rule_candidates.yaml
prompt_candidates.yaml
promotion_recommendation.yaml
```

`policy_candidates.yaml` は将来拡張とし、初期実装では対象外とする。

- `rule_candidates.yaml`: deterministic rule / rule-triage 側の改善候補
- `prompt_candidates.yaml`: AI triage prompt の次 variant 候補
- `promotion_recommendation.yaml`: current / variant の昇格判断

`candidate_review.md` は Rule Improvement Agent の直接出力ではなく、後段の review report generator が生成する human review artifact とする。

### 5.6 One-line definition

```text
Rule Improvement Agent = compare + judge を読み、差分を improvement candidate に変換する層
```

---

## 6. Contract Overview

最初に固定すべき contract は以下。

### 6.1 Triage contract

**input**

- `incident.json`

**output**

- `triage_result.json`

### 6.2 Investigation contract

**required input**

- `incident.json`
- `triage_result.json`

**optional input**

- `process_events.json`
- `process_chain_hits.json`
- `zeek_enrichment.json`
- `auditd_events.json`
- `endpoint_events.json`

`endpoint_events.json` is defender-side normalized endpoint telemetry. It can add factual
observed facts, supporting signals, evidence-grounded endpoint-derived enriched features,
and endpoint-derived investigation pivots. It must not change verdicts, severity,
`overall_result`, `detected`, action decisions, or Rule Improvement promotion behavior.

**output**

- `investigation_result.json`

最低限、investigation contract では以下の evidence-aware field を first-class に扱う。

- `evidence`
- `enriched_features`
- `evidence_level`
- `evidence_summary`
- `unsupported_claims`
- `missing_pivots`
- `recommended_pivots`
- `investigation_notes`
- `timeline_notes`
- `summary`
- `attack_story`
- `recommended_next_steps`

### 6.3 Action contract

**required input**

- `case.json`

**optional input**

- `incident.json`
- `triage_result.json`
- `investigation_result.json`
- `evaluation_result.json`
- `scenario_metadata.json`
- `execution_policy.json`
- `executor_capability_profile.json`

**output**

- `action_result.json`

### 6.4 Compare contract

**input**

- 複数 agent の同一 stage output

**output**

- `compare.json`

### 6.5 Judge contract

**core input**

- `compare.json`
- `rubric`

**optional assist**

- `expected`
- `evaluation_result.json`
- scenario metadata
- stage-specific policy / capability profile

**output**

- `judge_result.json`

### 6.6 Improvement contract

**input**

- `compare.json`
- `judge_result.json`

**output**

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`

**future output**

- `policy_candidates.yaml`

### 6.7 Review contract

**input**

- `judge_result.json`
- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`

**output**

- `candidate_review.md`

---

## 7. Triage Harness MVP Scope

最初の対象は **triage harness** に限定する。

理由:

- すでに `triage_result.json` がある
- `triage_rule.json` がある
- `triage_diff.json` がある
- compare / judge 基盤へ最も接続しやすい

### 7.1 Inputs

- `incident.json`

### 7.2 Agents

- `triage_ai_current`
- `triage_ai_variant`
- `triage_rule`

### 7.3 Outputs

- `agents/triage_ai_current.json`
- `agents/triage_ai_variant.json`
- `agents/triage_rule_agent.json`
- `compare.json`
- `judge_result.json`
- `summary.md`
- `metadata.json`

### 7.4 Suggested directory shape

```text
data/
  harness_runs/
    <harness_run_id>/
      input/
        incident.json
      optional_inputs/
        evaluation_result.json
        scenario_metadata.json
      agents/
        triage_ai_current.json
        triage_ai_variant.json
        triage_rule_agent.json
      compare.json
      judge_result.json
      summary.md
      metadata.json
      rule_candidates.yaml
      prompt_candidates.yaml
      promotion_recommendation.yaml
      candidate_review.md
```

### 7.5 Notes

- `input/` には harness の required input を置く
- `optional_inputs/` には judge の optional assist を置く
- `optional_inputs/` は存在しなくてもよい
- harness の rule agent 出力は、既存 run artifact の `triage_rule.json` と混同しないよう `triage_rule_agent.json` とする

---

## 8. Triage Harness Run Contract

```yaml
harness_run_id: harness-0001
stage: triage
source_run_id: run-0032
scenario_id: scenario-006

input_artifacts:
  incident: data/runs/run-0032/incident.json

agents:
  - name: triage_ai_current
    profile: current
    agent_version: v1
    prompt_version: prompt-v3
    output: agents/triage_ai_current.json

  - name: triage_ai_variant
    profile: variant
    agent_version: v2
    prompt_version: prompt-v4
    output: agents/triage_ai_variant.json

  - name: triage_rule
    profile: default
    agent_version: rule-agent-v1
    rule_version: rule-set-2026-04-18
    output: agents/triage_rule_agent.json

compare:
  output: compare.json
  schema: schemas/compare_schema.json
  artifact_synonyms:
    ssh_key_login:
      - ssh key login
      - ssh public key login
      - public key authentication
      - successful ssh public-key login
    process_exec:
      - process execution
      - command execution
      - post-login command execution

judge:
  rubric_id: triage_generic_v1
  rubric_file: rubrics/triage_generic_v1.yaml
  schema: schemas/judge_result_schema.json
  output: judge_result.json
  expected_response_keywords:
    must_have:
      - isolate
      - revoke
      - rotate
    nice_to_have:
      - review command
      - validate source ip
  optional_assist:
    evaluation_result: data/runs/run-0032/evaluation_result.json
    scenario_metadata:
      scenario_id: scenario-006
      primary_artifacts:
        - ssh_key_login
        - process_exec

artifacts:
  summary: summary.md
  metadata: metadata.json
```

### 8.1 Notes

- `triage_ai_current` は現行採用版 / baseline / champion を表す
- `triage_ai_variant` は改善候補 / challenger を表す
- `triage_rule` は deterministic baseline として比較に含める
- generic rubric を基本とし、scenario 固有性は `optional_assist.scenario_metadata` で補助する
- promotion は単発 harness の winner だけでは決めず、batch validation で横断確認する

---

## 9. metadata.json Contract

metadata は比較実験の再現性のために **必須** とする。

### 9.1 Required metadata fields

- `harness_run_id`
- `stage`
- `source_run_id`
- `scenario_id`
- `workflow_path`
- `rubric_id`
- `agent_versions`
- `prompt_versions`
- `rule_versions`
- `schema_versions`

### 9.2 metadata example

```json
{
  "harness_run_id": "harness-0001",
  "stage": "triage",
  "source_run_id": "run-0032",
  "scenario_id": "scenario-006",
  "workflow_path": "workflows/triage_harness_example.yaml",
  "rubric_id": "triage_scenario006_v1",
  "schema_versions": {
    "compare": "compare_schema_v1",
    "judge_result": "judge_result_schema_v1"
  },
  "agent_versions": {
    "triage_ai_current": "v1",
    "triage_ai_variant": "v2",
    "triage_rule": "rule-agent-v1"
  },
  "prompt_versions": {
    "triage_ai_current": "prompt-v3",
    "triage_ai_variant": "prompt-v4"
  },
  "rule_versions": {
    "triage_rule": "rule-set-2026-04-18"
  }
}
```

---

## 10. Compare Contract

compare は単なる diff ではなく、**judge の前処理** として扱う。

### 10.1 Compare responsibility

- 共通項を抽出する
- agent ごとの差分を抽出する
- 欠落項目を抽出する
- overclaim の可能性を抽出する
- stage-specific risk を抽出する
- judge が見やすい形に正規化する

### 10.2 Minimum comparison dimensions for triage

- verdict
- confidence
- priority
- summary
- attack_story
- recommended_response
- derived_features
- assessment
- scenario 主役 artifact の説明有無
- evidence / timeline に基づかない主張の有無

### 10.3 Minimum comparison dimensions for investigation

- summary
- attack_story
- evidence
- enriched_features
- evidence_level
- evidence_summary
- unsupported_claims
- missing_pivots
- recommended_pivots
- investigation_notes
- timeline_notes
- recommended_next_steps
- scenario 主役 artifact に対応する evidence の有無
- evidence / timeline に基づかない主張の有無

### 10.4 Minimum comparison dimensions for action

- summary
- response_strategy
- playbook steps
- action type coverage
- target specificity
- approval / auto-executable setting
- evidence grounding
- missing information
- safety notes
- scenario 主役 artifact に対応する action の有無
- case / evidence に基づかない action の有無
- dangerous / over-broad action の有無

---

## 11. Judge Contract

judge は「どれが勝ちか」を決めるだけでなく、**改善案生成のための評価信号** を出す。

### 11.1 Judge should output

- score
- strengths
- weaknesses
- pass / fail
- candidate_hints
- optional winner / summary

### 11.2 Judge input model

judge の core input は以下に固定する。

- `compare.json`
- `rubric`

judge の optional assist は以下を許可する。

- `expected`
- `evaluation_result.json`
- scenario metadata
- stage-specific policy / capability profile

つまり設計としては以下。

```text
core: compare + rubric
optional assist: expected / evaluation / scenario metadata / policy
```

この形により、

- harness の本質である agent 間比較を保てる
- ground truth がある scenario では judge を補強できる
- ground truth が薄いケースでも judge を動かせる
- action stage では approval / executor capability を補助情報として扱える

### 11.3 Rules

- `compare` と `rubric` は必須
- `optional_assist` は任意
- `optional_assist` が存在しない場合でも judge は動作可能である

---

## 12. Judge Rubric

### 12.1 Minimum triage criteria

1. `artifact_coverage`
   - expected artifact と scenario 主役 artifact を説明できているか
2. `verdict_quality`
   - verdict / priority / confidence が妥当か
3. `overclaim_control`
   - incident / evidence から言えないことを断定していないか
4. `response_fitness`
   - recommended response が scenario の性質に合っているか

### 12.2 Minimum investigation criteria

1. `evidence_coverage`
   - scenario 主役 artifact と investigation に必要な証拠を拾えているか
2. `evidence_quality`
   - `evidence_level` / `evidence_summary` が、観測事実と解釈の境界を明確にできているか
3. `timeline_grounding`
   - attack story / timeline notes が timeline / evidence に grounded しているか
4. `unsupported_claim_control`
   - incident / triage / evidence から言えないことを断定していないか
5. `missing_pivot_detection`
   - conclusion 前に確認すべき pivot / follow-up が残っていることを適切に認識できているか
6. `evidence_specificity`
   - command / path / URL / endpoint telemetry など、具体的な証拠粒度を拾えているか
7. `enriched_feature_quality`
   - process / network / endpoint telemetry 由来の enriched features を evidence-grounded に生成できているか
8. `next_step_fitness`
   - missing / recommended pivots と recommended next steps が evidence gap に対応しているか

### 12.3 Minimum action criteria

1. `action_coverage`
   - scenario 主役 artifact に対して必要な対応が playbook に含まれているか
2. `action_grounding`
   - case / incident / investigation / evidence から言える範囲に grounded しているか
3. `approval_fitness`
   - auto-executable / approval required の境界が適切か
4. `playbook_specificity`
   - step type / target / params / priority が具体的で、実行または human review しやすいか
5. `safety_control`
   - unsupported / dangerous / over-broad action を安易に提案していないか

### 12.4 Rubric naming convention

rubric は generic と scenario-specific の2層で管理する。

Generic:

- `triage_generic_v1`
- `investigation_generic_v1`
- `action_generic_v1`

Scenario-specific:

- `triage_scenario004_v1`
- `triage_scenario005_v1`
- `triage_scenario006_v1`
- `investigation_scenario006_v1`
- `action_scenario006_v1`

Policy:

- まず generic rubric を基本とする
- scenario 特有の judge 観点が必要な場合のみ scenario-specific rubric を追加する
- `rubric_id` と `rubric_file` は同じ命名規則に従う

---

## 13. Champion / Challenger Promotion Cycle

triage harness の AI 比較は champion / challenger 形式で運用する。

```text
triage_ai_current = 現在の採用版 / baseline / champion
triage_ai_variant = 改善候補 / challenger
triage_ai_variant_next = Rule Improvement Agent が作る次の改善候補
```

### 13.1 Basic cycle

```text
current と variant を比較
  ↓
compare.json / judge_result.json を生成
  ↓
Rule Improvement Agent が promotion と candidate を生成
  ↓
variant が promotion gate を通過した場合のみ current に昇格
  ↓
昇格後の current を base に next_variant を作成
  ↓
次の compare へ進む
```

### 13.2 Promotion gates

variant の昇格は、単純な score 勝ちではなく gate で判断する。

- current より score が明確に高い
- primary artifact coverage に regression がない
- overclaim control に regression がない
- verdict / priority が大きく悪化していない
- 必要に応じて複数 scenario で安定している

### 13.3 Both current and variant miss primary artifacts

current も variant も primary artifact を落とす場合は、どちらも昇格不可とする。

```text
promote: false
current stays
next_variant based_on current
goal: fix primary artifact coverage
```

この場合、current を直接変更せず、current をベースにした `triage_ai_variant_next` を作る。

---

## 14. Rule Improvement Agent Output Contract

The outputs in this section are the existing comparison-harness Rule
Improvement artifacts. They are separate from the newer AI-assisted post-action
review flow, which currently reaches `rule_improvement_candidate_creation_input.json`
and then stops.

`rule_improvement_candidate_creation_input.json` must not be treated as
`rule_candidates.yaml`, `prompt_candidates.yaml`, `promotion_recommendation.yaml`,
or approval to edit rules, prompts, parsers, telemetry, or correlation logic.
Any future connection from candidate-creation input to these concrete candidate
artifacts must be a separate, explicit, reviewed workflow.

The schemas for the three harness artifacts intentionally reject unknown fields,
including fields that could smuggle auto-apply, approval, deployment, or
promotion semantics. `promotion_recommendation.yaml` may recommend a promotion
for review, but it is not the promotion decision itself and must not auto-apply
or update the baseline.

### 14.1 rule_candidates.yaml

`rule_candidates.yaml` は deterministic rule / rule-triage 側の改善候補を表す。  
現在は `compare.rubric_context.primary_artifacts_expected` を参照し、primary artifact に応じた artifact-aware candidate を生成する。

例: scenario_004 / `authorized_keys_modification`

```yaml
rule_candidates:
  - id: rule-candidate-001
    target: triage_rule
    reason: rule-based triage has actionable judge weaknesses
    proposed_change: >-
      Add deterministic recommended-action mapping for primary artifacts
      (authorized_keys_modification): verify the modified authorized_keys file and
      identify the added key; remove unauthorized SSH public keys from the affected
      account; rotate credentials for the affected user; search for the same public
      key or source IP across other hosts.
    expected_effect:
      - improve response_fitness
    supporting_signals:
      - missing:response:expected_keywords
      - weakness:response_fitness
    priority: medium
```

例: scenario_006 / `ssh_key_login` + `process_exec`

```yaml
rule_candidates:
  - id: rule-candidate-001
    target: triage_rule
    reason: rule-based triage has actionable judge weaknesses
    proposed_change: >-
      Add deterministic recommended-action mapping for primary artifacts
      (ssh_key_login, process_exec): revoke or rotate the suspicious SSH key;
      validate whether the public key login was expected for the user; review the
      executed command line and parent login context; collect suspicious payload
      files and related process evidence; contain the host if post-login command
      execution is confirmed malicious.
    expected_effect:
      - improve response_fitness
    supporting_signals:
      - missing:response:expected_keywords
      - weakness:response_fitness
    priority: medium
```

### 14.2 prompt_candidates.yaml

`prompt_candidates.yaml` は AI triage prompt の次 variant 候補を表す。  
response specificity が main gap の場合、primary artifact に応じた containment / verification step を suggested change に含める。

```yaml
prompt_candidates:
  - id: prompt-candidate-001
    target: triage_ai_variant_next
    based_on: triage_ai_current
    reason: response specificity remains the main improvement gap
    proposed_change: >-
      Strengthen recommended_actions with artifact-specific containment and
      verification steps: revoke or rotate the suspicious SSH key; review the
      executed command line and parent login context; collect suspicious payload
      files and related process evidence.
    expected_effect:
      - improve response_fitness
    supporting_signals:
      - judge_summary.main_gap:response specificity
      - winner:triage_ai_current
      - next_baseline_agent:triage_ai_current
    priority: medium
```

### 14.3 promotion_recommendation.yaml

```yaml
promotion_recommendation:
  promote: true
  from_agent: triage_ai_variant
  to_agent: triage_ai_current
  current_agent: triage_ai_current
  challenger_agent: triage_ai_variant
  next_baseline_agent: triage_ai_variant
  score_delta: 0.1067
  reason: triage_ai_variant outperformed triage_ai_current without primary artifact or overclaim regression.
  blocking_gaps: []
  gates:
    score_improvement: pass
    primary_artifact_coverage: pass
    overclaim_control: pass
```

### 14.4 candidate_review.md

`candidate_review.md` は自動適用のための artifact ではなく、human review のための report である。  
`judge_result.json` / `promotion_recommendation.yaml` / `rule_candidates.yaml` / `prompt_candidates.yaml` を読み、reviewer が判断しやすい形にまとめる。

含める内容:

- judge score summary
- promotion recommendation
- promotion gates
- rule candidates
- prompt candidates
- manual apply checklist
- final human decision section

基本判断:

```text
candidate yaml
  ↓
candidate_review.md
  ↓
human review
  ↓
manual apply if accepted
  ↓
single harness rerun
  ↓
batch harness regression check
  ↓
human-approved promotion decision
```

---

## 15. Batch Compare Runner Contract

単発の promotion は candidate であり、自動リリース判断ではない。  
current / variant の入れ替え判断は、複数 scenario を横断して確認する。

### 15.1 Batch input

```yaml
batch_run_id: batch-phase6-0001
base_workflow: workflows/triage_harness_example.yaml
cases:
  - scenario_id: scenario-004
    source_run_id: run-0030
  - scenario_id: scenario-005
    source_run_id: run-0031
  - scenario_id: scenario-006
    source_run_id: run-0032
```

### 15.2 Batch outputs

```text
data/
  batch_harness_runs/
    <batch_run_id>/
      generated_workflows/
      logs/
      batch_summary.json
      batch_summary.md
```

各 case の harness run は従来通り以下に保存する。

```text
data/harness_runs/<batch_run_id>-<scenario_id>-<source_run_id>/
```

### 15.3 Batch decision rule

```text
single-scenario promotion = candidate
cross-scenario promotion  = release decision input
```

現段階では、batch runner は promotion を自動反映しない。  
一方で、各 harness run の `candidate_review.md` は batch 実行中に自動生成され、`batch_summary.json` / `batch_summary.md` には `candidate_review_path` が記録される。  
human reviewer は batch summary と各 review artifact を見て、current を昇格するか判断する。

---

## 16. MVP Boundary

この段階ではまだ対象外であることを明記する。

- planner + specialist の導入
- shared memory / graph
- executor / actual execution の比較
- cross-stage global optimization
- multi-host orchestration
- autonomous self-improvement
- candidate の自動適用
- current / variant の自動ファイル置換

---

## 17. Done Criteria

この整理フェーズの Done は以下。

- Orchestrator の責務が文章で固定されている
- Rule Improvement Agent の責務が文章で固定されている
- compare / judge / improvement の contract が固定されている
- judge の core input と optional assist の境界が固定されている
- metadata.json の version 契約が固定されている
- triage harness MVP の最小スコープが決まっている
- triage comparison harness が end-to-end で動作する
- `compare.json` / `judge_result.json` / `metadata.json` が出力される
- Rule Improvement Agent が `rule_candidates.yaml` / `prompt_candidates.yaml` / `promotion_recommendation.yaml` を出力する
- Rule Improvement Agent が primary artifact に応じた artifact-aware candidate を生成できる
- `candidate_review.md` により candidate / promotion gate / manual checklist / human decision を確認できる
- batch compare runner が scenario_004 / 005 / 006 を横断実行できる
- batch runner が各 harness run の `candidate_review.md` を自動生成し、`candidate_review_path` を batch summary に記録できる
- generated workflow 名が scenario ごとに補正され、summary title の整合性を保てる
- investigation harness が evidence-aware compare / judge / rubric refinement まで到達している
- action harness は設計対象として追加され、executor comparison はまだ対象外と明記されている

---

## 18. One-line Summary

```text
今やるべきは agent society ではなく、
contract / compare / judge / promotion / candidate review / batch validation を持つ
multi-agent comparison harness の土台作り
```

---

## 19. Investigation Harness MVP Scope

次の実装対象は **investigation harness** とする。  
ただし、triage harness と同様に、最初から多機能化せず **single-stage / compare-capable / judge-capable** な最小構成に限定する。

### 19.1 Positioning

investigation harness は triage harness の別系統ではなく、**同じ comparison harness 系列の stage-specific sibling** として扱う。

```text
triage harness
  = incident -> triage_result comparison

investigation harness
  = incident + triage_result -> investigation_result comparison
```

目的は investigation agent を増やすことではなく、**investigation の比較可能な実験枠組みを固定すること** にある。

### 19.2 Initial MVP Boundary

MVP では以下に限定する。

- single-scenario 実行
- AI current / AI variant の 2-agent 比較
- compare / judge / summary / metadata 出力
- human review 前提
- automatic promotion なし
- candidate auto-apply なし
- batch runner 対応は後続

この段階ではまだ対象外:

- deterministic investigation baseline の本格導入
- investigation rule candidate 自動生成
- investigation prompt candidate 自動生成
- investigation 用 promotion recommendation の自動運用
- cross-scenario batch validation
- multi-host investigation
- external intel / DFIR result の本格取り込み

### 19.3 Investigation contract

**required input**

- `incident.json`
- `triage_result.json`

**optional input**

- `process_events.json`
- `process_chain_hits.json`
- `zeek_enrichment.json`

**output**

- `investigation_result.json`

### 19.4 Compare contract for investigation

**input**

- 複数 agent の `investigation_result.json`

**output**

- `compare.json`

investigation compare は単なる diff ではなく、judge の前処理として扱う。  
最低限、以下の観点を比較対象に含める。

- summary
- attack_story
- evidence
- enriched_features
- evidence_level
- evidence_summary
- unsupported_claims
- missing_pivots
- recommended_pivots
- investigation_notes
- timeline_notes
- recommended_next_steps
- scenario 主役 artifact に対応する evidence の有無
- evidence / timeline に基づかない主張の有無

### 19.5 Judge contract for investigation

**core input**

- `compare.json`
- `rubric`

**optional assist**

- `evaluation_result.json`
- scenario metadata
- expected evidence
- expected enriched features

**output**

- `judge_result.json`

### 19.6 Initial investigation agents

MVP の agent は以下の 2 つでよい。

- `investigation_ai_current`
- `investigation_ai_variant`

この段階では `investigation_rule` のような deterministic baseline は無理に追加しない。  
まずは AI current / variant の比較実験枠組みを固定することを優先する。

### 19.7 Suggested rubric for investigation

最小 rubric は以下の 5 観点でよい。

1. `evidence_coverage`
2. `evidence_quality`
3. `timeline_grounding`
4. `unsupported_claim_control`
5. `missing_pivot_detection`

必要に応じて将来以下を追加できる。

- `next_step_fitness`
- `evidence_specificity`

### 19.8 Suggested directory shape

```text
data/
  harness_runs/
    <harness_run_id>/
      input/
        incident.json
        triage_result.json
      optional_inputs/
        process_events.json
        process_chain_hits.json
        zeek_enrichment.json
        evaluation_result.json
        scenario_metadata.json
      agents/
        investigation_ai_current.json
        investigation_ai_variant.json
      compare.json
      judge_result.json
      summary.md
      metadata.json
```

### 19.9 Investigation harness run example

```yaml
harness_run_id: investigation-harness-0001
stage: investigation
source_run_id: run-0032
scenario_id: scenario-006

input_artifacts:
  incident: data/runs/run-0032/incident.json
  triage_result: data/runs/run-0032/triage_result.json

optional_inputs:
  process_events: data/runs/run-0032/process_events.json
  process_chain_hits: data/runs/run-0032/process_chain_hits.json
  endpoint_events: data/runs/run-0032/endpoint_events.json
  zeek_enrichment: data/runs/run-0032/zeek_enrichment.json

agents:
  - name: investigation_ai_current
    profile: current
    agent_version: v1
    prompt_version: prompt-v1
    output: agents/investigation_ai_current.json

  - name: investigation_ai_variant
    profile: variant
    agent_version: v2
    prompt_version: prompt-v2
    output: agents/investigation_ai_variant.json

judge:
  rubric_id: investigation_generic_v1
  rubric_file: rubrics/investigation_generic_v1.yaml
  output: judge_result.json
  optional_assist:
    evaluation_result: data/runs/run-0032/evaluation_result.json
    scenario_metadata:
      scenario_id: scenario-006
      primary_artifacts:
        - ssh_key_login
        - process_exec
      expected_enriched_features:
        - network_context_observed
        - http_context_observed
        - payload_request_observed

artifacts:
  summary: summary.md
  metadata: metadata.json
```

### 19.10 Recommended first scenario

最初の investigation harness は `scenario_006` を対象にする。

理由:

- `incident.json`
- `triage_result.json`
- `investigation_result.json`
- `process_events.json`
- `process_chain_hits.json`
- `zeek_enrichment.json`

が既に揃っており、post-login command execution と network / HTTP context を含むため、investigation 比較の最初の題材として最も情報量が多い。

### 19.11 metadata.json additions

investigation harness でも metadata は必須とする。

最低限必要な項目:

- `harness_run_id`
- `stage`
- `source_run_id`
- `scenario_id`
- `workflow_path`
- `rubric_id`
- `agent_versions`
- `prompt_versions`
- `schema_versions`

加えて、investigation では以下も保持するのが望ましい。

- `input_artifact_refs`
- `optional_input_refs`
- `judge_optional_assist_refs`

### 19.12 Done criteria for investigation harness MVP

- investigation harness の責務が文章で固定されている
- required input / optional input / output contract が固定されている
- `scenario_006` で end-to-end に比較実行できる
- `compare.json` / `judge_result.json` / `summary.md` / `metadata.json` が出力される
- judge が `evidence_coverage` / `evidence_quality` / `timeline_grounding` / `unsupported_claim_control` / `missing_pivot_detection` を最低限評価できる
- batch compare / candidate apply / automatic promotion はまだ対象外と明記されている

### 19.13 One-line summary

```text
investigation harness は、
incident + triage_result を入力に investigation_result を比較・評価する
stage-specific comparison harness の MVP である
```

### 19.14 Investigation Harness Current Status

investigation harness は initial MVP を超えて、**endpoint-aware evidence / feature / pivot refinement** まで到達済みと整理する。

- `scenario_006` を対象にした single-scenario compare
- `investigation_ai_current` / `investigation_ai_variant` の 2-agent 比較
- `compare.json` / `judge_result.json` / `summary.md` / `metadata.json` の出力
- `process_events.json` / `process_chain_hits.json` / `zeek_enrichment.json` / `endpoint_events.json` を使った evidence wiring
- evidence-aware investigation field の compare 正規化
  - `evidence_level`
  - `evidence_summary`
  - `unsupported_claims`
  - `missing_pivots`
  - `recommended_pivots`
- endpoint telemetry 由来の additive enrichment
  - `observed_facts`
  - `supporting_signals`
  - endpoint-derived `enriched_features`
  - endpoint-derived `missing_pivots`
  - endpoint-derived `recommended_pivots`
- investigation judge の evidence-aware criteria 対応
  - `evidence_quality`
  - `unsupported_claim_control`
  - `missing_pivot_detection`
  - `evidence_specificity`
  - `enriched_feature_quality`
  - `next_step_fitness`

Current smoke result after endpoint-aware refinement:

```text
investigation_ai_current score  = 0.96
investigation_ai_variant score  = 0.965
evidence_specificity            = 0.8
enriched_feature_quality        = 0.85 / 0.9
missing_pivot_detection         = 1.0
```

この時点で、investigation harness は **MVP + evidence-aware + endpoint-aware compare/judge refinement** として成立している。

### 19.15 Current stopping point

現時点では以下を current stopping point とする。

- `investigation_ai_variant` を best balance として識別可能
- `endpoint_events.json` から observed facts / supporting signals / enriched features / pivots まで接続済み
- `missing_pivot_detection` は endpoint payload / command context まで認識できる
- evidence-aware investigation field は compare / judge / rubric まで接続済み
- `main_gap` は残差の大きい criterion を示すものとして扱い、単独で追加実装を急がない
- candidate_hints / weaknesses の deficit-aware 改善や、更なる judge 識別力改善は必要に応じて後続で継続する

### 19.16 Near-term priority after investigation harness

完了済み:

1. `investigation_result.json` に `evidence_level` と `evidence_summary` を導入
2. harness rubric に `evidence_quality` を追加
3. judge に `unsupported_claim_control` / `missing_pivot_detection` を追加
4. scoring refinement により current / variant の score saturation を緩和
5. `main_gap` を criterion-deficit から推定できるよう改善

次段候補:

- action comparison harness の設計
- attacker-agent Phase A
  - dispatcher 化
  - loader / validator / selector 分離
  - step / shell backend の最小導入
- attacker-agent Phase B / C は Phase A 完了後に再判断
- `candidate_hints` / `weaknesses` の deficit-aware 改善
- process execution 以外のドメイン展開
- supervisor-style correction は review/check として限定導入
- full swarm / offensive execution supervision はまだ先とする

### 19.17 Relationship to attacker-agent roadmap

investigation harness 後の lab-wide next step は、defense-side と offense-side を分けて考える。

- defense-side では action comparison harness の設計を先に行う
- offense-side では attacker-agent roadmap に沿って Phase A を次の実装対象とする
- attacker-agent の Phase B / C
  - scenario schema 統一
  - rich attack artifacts
  は Phase A 完了後に、triage / investigation / evaluation への波及を見て再判断する

この整理により、comparison harness の spine を action stage へ自然に伸ばしつつ、attacker-agent の基盤整理も roadmap の immediate priority に沿って前倒しできる。

---

## 20. Action Harness MVP Scope

次の設計対象は **action comparison harness** とする。  
ただし、最初から executor / approval / actual execution まで比較対象に含めず、MVP では **action planning output である `action_result.json` の比較** に限定する。

### 20.1 Positioning

action harness は triage harness / investigation harness と同じ comparison harness 系列の **stage-specific sibling** として扱う。

```text
triage harness
  = incident -> triage_result comparison

investigation harness
  = incident + triage_result -> investigation_result comparison

action harness
  = case -> action_result comparison
```

目的は action-agent を増やすことではなく、**対応方針 / playbook / approval boundary を比較可能な実験枠組みに載せること** にある。

### 20.2 Initial MVP Boundary

MVP では以下に限定する。

- single-scenario 実行
- AI current / AI variant の 2-agent 比較
- compare / judge / summary / metadata 出力
- `action_result.json` の比較
- playbook step の具体性比較
- approval / auto-executable boundary の妥当性比較
- human review 前提
- automatic promotion なし
- candidate auto-apply なし
- batch runner 対応は後続

この段階ではまだ対象外:

- executor comparison
- `decision_log.json` の本格比較
- actual execution result の比較
- approval workflow 実行結果の比較
- deterministic `action_rule` baseline の本格導入
- action-specific rule candidate 自動生成
- action-specific prompt candidate 自動生成
- action promotion recommendation の自動運用
- cross-scenario batch validation
- automatic containment / execution optimization

### 20.3 Action contract

**required input**

- `case.json`

**optional input**

- `incident.json`
- `triage_result.json`
- `investigation_result.json`
- `evaluation_result.json`
- `scenario_metadata.json`
- `execution_policy.json`
- `executor_capability_profile.json`

**output**

- `action_result.json`

MVP では required input を `case.json` に固定する。  
理由は、action stage は case の後段であり、stage boundary を次のように固定した方が triage / investigation harness と同じ contract model に揃えやすいためである。

```text
case -> action
```

ただし、action-agent が incident / triage / investigation の詳細を参照したい場合に備え、それらは optional input として渡せるようにする。

### 20.4 Action output comparison target

action harness の compare 対象は `action_result.json` とする。

最低限、以下の field を比較可能にする。

- `summary`
- `response_strategy`
- `playbook`
- `playbook[].id`
- `playbook[].type`
- `playbook[].title`
- `playbook[].target`
- `playbook[].priority`
- `playbook[].auto_executable`
- `playbook[].approval`
- `playbook[].rationale`
- `playbook[].evidence_refs`
- `missing_information`
- `safety_notes`

MVP の `action_result.json` は、playbook の自然文だけでなく、step type / target / approval / evidence grounding を比較できる形であることが望ましい。

Example:

```json
{
  "action_id": "action-0001",
  "case_id": "case-run-0032",
  "incident_id": "inc-0001",
  "scenario_id": "scenario-006",
  "summary": "Public key reuse followed by suspicious command execution requires containment and evidence collection.",
  "response_strategy": "contain_and_collect",
  "playbook": [
    {
      "id": "step-1",
      "type": "revoke_ssh_key",
      "title": "Revoke suspicious SSH key",
      "target": {
        "host": "ubuntu-victim01",
        "user": "victim01"
      },
      "priority": "high",
      "auto_executable": false,
      "approval": "required",
      "rationale": "Unexpected SSH public-key login was observed.",
      "evidence_refs": [
        "case.timeline[0]"
      ]
    },
    {
      "id": "step-2",
      "type": "collect_forensic_artifacts",
      "title": "Collect payload and process evidence",
      "target": {
        "host": "ubuntu-victim01"
      },
      "priority": "high",
      "auto_executable": true,
      "approval": "not_required",
      "rationale": "Post-login command execution was observed.",
      "evidence_refs": [
        "case.timeline[1]"
      ]
    }
  ],
  "missing_information": [
    "whether the SSH key was business-approved"
  ],
  "safety_notes": [
    "Host isolation should require operator approval."
  ]
}
```

### 20.5 Initial action agents

MVP の agent は以下の 2 つでよい。

- `action_ai_current`
- `action_ai_variant`

この段階では `action_rule` のような deterministic baseline は無理に追加しない。  
まずは AI current / variant の比較実験枠組みと judge 観点を固定することを優先する。

理由:

- action stage は triage より operational / safety 境界が重い
- executor capability / approval policy との接続が必要になる
- deterministic baseline を先に作るより、まず compare / judge の評価軸を固定する方が安全

### 20.6 Compare contract for action

**input**

- 複数 agent の `action_result.json`

**output**

- `compare.json`

action compare は単なる diff ではなく、judge の前処理として扱う。  
最低限、以下の観点を比較対象に含める。

- summary
- response_strategy
- playbook steps
- action type coverage
- target specificity
- approval / auto-executable setting
- evidence grounding
- missing information
- safety notes
- scenario 主役 artifact に対応する action の有無
- case / evidence に基づかない action の有無
- dangerous / over-broad action の有無

Example:

```json
{
  "stage": "action",
  "source_run_id": "run-0032",
  "scenario_id": "scenario-006",
  "agents": [
    "action_ai_current",
    "action_ai_variant"
  ],
  "rubric_context": {
    "primary_artifacts_expected": [
      "ssh_key_login",
      "process_exec"
    ],
    "scenario_focus": "key reuse followed by command execution"
  },
  "common_items": {
    "response_strategy": "contain_and_collect"
  },
  "agent_only_items": {
    "action_ai_current": {
      "captured_steps": [
        "revoke_ssh_key",
        "request_dfir_collection"
      ]
    },
    "action_ai_variant": {
      "captured_steps": [
        "review_executed_command",
        "collect_payload_file"
      ]
    }
  },
  "missing_items": {
    "action_ai_current": [
      "review_executed_command"
    ]
  },
  "approval_mismatches": {
    "action_ai_variant": [
      "host_isolation_marked_auto_executable"
    ]
  },
  "unsafe_or_unsupported_items": {
    "action_ai_variant": [
      "auto containment without approval"
    ]
  },
  "normalization_notes": [
    "contain host and isolate host normalized to host_containment",
    "revoke SSH key and remove unauthorized key normalized to revoke_ssh_key"
  ]
}
```

### 20.7 Judge contract for action

**core input**

- `compare.json`
- `rubric`

**optional assist**

- `evaluation_result.json`
- scenario metadata
- expected action keywords
- `execution_policy.json`
- `executor_capability_profile.json`

**output**

- `judge_result.json`

action judge は winner 判定だけでなく、後続の improvement に使える評価信号を出す。  
特に action stage では、triage / investigation と異なり、**approval boundary** と **execution safety** を first-class evaluation dimension として扱う。

### 20.8 Suggested rubric for action

最小 rubric は以下の 5 観点でよい。

1. `action_coverage`
   - scenario 主役 artifact に対して必要な対応が playbook に含まれているか

2. `action_grounding`
   - case / incident / investigation / evidence から言える範囲に grounded しているか

3. `approval_fitness`
   - auto-executable / approval required の境界が適切か

4. `playbook_specificity`
   - step type / target / params / priority が具体的で、実行または human review しやすいか

5. `safety_control`
   - unsupported / dangerous / over-broad action を安易に提案していないか

必要に応じて将来以下を追加できる。

- `executor_fitness`
  - executor capability profile と整合しているか

- `ordering_quality`
  - containment / collection / verification の順序が妥当か

- `operator_handoff_quality`
  - human operator が判断しやすい説明になっているか

### 20.9 Suggested action rubric example

```yaml
rubric_id: action_generic_v1
stage: action
criteria:
  - id: action_coverage
    weight: 0.30
    description: >
      Required containment, credential/key handling, evidence collection, and
      verification actions are covered for the scenario's primary artifacts.

  - id: action_grounding
    weight: 0.20
    description: >
      Proposed actions are grounded in case, timeline, investigation, and observed
      evidence rather than unsupported assumptions.

  - id: approval_fitness
    weight: 0.20
    description: >
      Auto-executable and approval-required boundaries are appropriate for the
      risk and reversibility of each action.

  - id: playbook_specificity
    weight: 0.20
    description: >
      Playbook steps are specific enough to be executed or reviewed, including
      clear step type, target, priority, rationale, and evidence references.

  - id: safety_control
    weight: 0.10
    description: >
      The action plan avoids unsupported, destructive, or over-broad response
      actions, especially automatic containment without sufficient approval.
```

### 20.10 Scenario-aware action expectations

最初の action harness は `scenario_006` を対象にする。

理由:

- `ssh_key_login` と `process_exec` の両方を含む
- action coverage を評価しやすい
- triage / investigation harness と同じ scenario を使える
- key handling / process review / payload collection / containment という action pattern を比較しやすい

`scenario_006` の expected action examples:

**must-have**

- suspicious SSH key の revoke / rotate / remove
- public key login の妥当性確認
- executed command line / parent login context の review
- suspicious payload file / process evidence の collection

**nice-to-have**

- source IP / key fingerprint の横断確認
- DFIR collection request
- maliciousness confirmed の場合の host containment
- affected user credential rotation
- similar activity search across hosts

### 20.11 Suggested directory shape

```text
data/
  harness_runs/
    <harness_run_id>/
      input/
        case.json
      optional_inputs/
        incident.json
        triage_result.json
        investigation_result.json
        evaluation_result.json
        scenario_metadata.json
        execution_policy.json
        executor_capability_profile.json
      agents/
        action_ai_current.json
        action_ai_variant.json
      compare.json
      judge_result.json
      summary.md
      metadata.json
```

### 20.12 Action harness run example

```yaml
harness_run_id: action-harness-0001
stage: action
source_run_id: run-0032
scenario_id: scenario-006

input_artifacts:
  case: data/runs/run-0032/case.json

optional_inputs:
  incident: data/runs/run-0032/incident.json
  triage_result: data/runs/run-0032/triage_result.json
  investigation_result: data/runs/run-0032/investigation_result.json
  evaluation_result: data/runs/run-0032/evaluation_result.json

agents:
  - name: action_ai_current
    profile: current
    agent_version: v1
    prompt_version: prompt-v1
    output: agents/action_ai_current.json

  - name: action_ai_variant
    profile: variant
    agent_version: v2
    prompt_version: prompt-v2
    output: agents/action_ai_variant.json

compare:
  output: compare.json
  schema: schemas/compare_schema.json

judge:
  rubric_id: action_generic_v1
  rubric_file: rubrics/action_generic_v1.yaml
  schema: schemas/judge_result_schema.json
  output: judge_result.json
  optional_assist:
    evaluation_result: data/runs/run-0032/evaluation_result.json
    scenario_metadata:
      scenario_id: scenario-006
      primary_artifacts:
        - ssh_key_login
        - process_exec
      expected_actions:
        must_have:
          - revoke_or_rotate_ssh_key
          - review_executed_command
          - collect_payload_or_process_evidence
        nice_to_have:
          - validate_source_ip
          - request_dfir_collection
          - contain_host_if_confirmed_malicious

artifacts:
  summary: summary.md
  metadata: metadata.json
```

### 20.13 metadata.json additions

action harness でも metadata は必須とする。

最低限必要な項目:

- `harness_run_id`
- `stage`
- `source_run_id`
- `scenario_id`
- `workflow_path`
- `rubric_id`
- `agent_versions`
- `prompt_versions`
- `schema_versions`

加えて、action harness では以下も保持するのが望ましい。

- `input_artifact_refs`
- `optional_input_refs`
- `judge_optional_assist_refs`
- `approval_policy_version`
- `executor_capability_profile_version`
- `action_schema_version`

Example:

```json
{
  "harness_run_id": "action-harness-0001",
  "stage": "action",
  "source_run_id": "run-0032",
  "scenario_id": "scenario-006",
  "workflow_path": "workflows/action_harness_example.yaml",
  "rubric_id": "action_generic_v1",
  "schema_versions": {
    "compare": "compare_schema_v1",
    "judge_result": "judge_result_schema_v1",
    "action_result": "action_result_schema_v1"
  },
  "agent_versions": {
    "action_ai_current": "v1",
    "action_ai_variant": "v2"
  },
  "prompt_versions": {
    "action_ai_current": "prompt-v1",
    "action_ai_variant": "prompt-v2"
  },
  "approval_policy_version": "approval-policy-v1",
  "executor_capability_profile_version": "executor-capability-profile-v1"
}
```

### 20.14 Relationship to executor-agent

action comparison harness は `action_result.json` の quality を評価する。  
executor-agent の実行結果そのものは MVP の比較対象に含めない。

MVP で比較するもの:

```text
case.json
  ↓
action-agent
  ↓
action_result.json
  ↓
compare / judge
```

MVP で比較しないもの:

```text
action_result.json
  ↓
executor-agent
  ↓
decision_log.json / execution_result
```

理由:

- action planning と execution result を同時に比較すると責務が混ざる
- executor capability / approval policy / environment state の影響が入る
- まずは playbook の妥当性、具体性、安全性を評価する方が設計が安定する

executor comparison は後続で、以下のような別 harness として扱う。

```text
executor harness
  = action_result + policy -> decision_log / execution_result comparison
```

### 20.15 Action harness improvement outputs

MVP では action-specific improvement candidate の自動生成は対象外とする。

ただし、将来のために以下への拡張余地を残す。

future outputs:

- `action_prompt_candidates.yaml`
- `action_policy_candidates.yaml`
- `approval_policy_candidates.yaml`
- `action_promotion_recommendation.yaml`
- `action_candidate_review.md`

最初は triage harness の Rule Improvement Agent と同じ仕組みに無理に載せず、judge result / summary を human review する段階に留める。

理由:

- action stage は operational risk が高い
- automatic containment / credential action の誤適用リスクがある
- approval boundary と safety policy が固定される前に candidate auto-apply へ進むべきではない

### 20.16 Done criteria for action harness MVP

- action harness の責務が文章で固定されている
- required input / optional input / output contract が固定されている
- compare 対象が `action_result.json` で固定されている
- `scenario_006` で end-to-end に比較実行できる
- `compare.json` / `judge_result.json` / `summary.md` / `metadata.json` が出力される
- judge が以下を最低限評価できる
  - `action_coverage`
  - `action_grounding`
  - `approval_fitness`
  - `playbook_specificity`
  - `safety_control`
- approval / auto-executable boundary を compare / judge できる
- executor comparison はまだ対象外と明記されている
- action-specific candidate auto-apply / promotion auto-apply はまだ対象外と明記されている
- batch compare runner 対応は後続と明記されている

### 20.17 One-line summary

```text
action harness は、
case.json を入力に action_result.json を比較・評価する
stage-specific comparison harness の MVP である
```

### 20.18 Near-term priority after action harness design

action harness の設計後は、defense-side の comparison spine が以下まで揃う。

```text
triage_result comparison
  ↓
investigation_result comparison
  ↓
action_result comparison
```

このため、次の優先順位は以下とする。

1. action comparison harness の最小実装
   - `workflows/action_harness_example.yaml`
   - `rubrics/action_generic_v1.yaml`
   - `scripts/run_action_harness.py`
   - `scripts/export_action_for_harness.py`

2. attacker-agent Phase A
   - dispatcher 化
   - loader / validator / selector 分離
   - step / shell backend の最小導入

3. attacker-agent Phase B / C は Phase A 完了後に再判断
   - scenario schema 統一
   - rich attack artifacts
   - attack observed effects の first-class artifact 化

この順序にする理由は、defense-side では action stage まで comparison harness の contract を伸ばすことで SOC pipeline の champion / challenger 比較基盤が一通り揃うためである。  
その後、offense-side の attacker-agent を Phase A で再整理し、attack artifacts 側の contract 整備へ進む。
---

## 21. Current Post-Harness Status

The harness architecture described in this document should now be read as implemented through the action stage and refined through endpoint-aware investigation evaluation.

Current stable boundary:

```text
triage harness        = implemented
investigation harness = implemented with evidence-aware and endpoint-aware refinement
action harness        = implemented with coverage / grounding / specificity refinement
```

Already completed follow-ons:

- `collection_request.json` generation from action output
- `collection_request` schema validation
- action policy registry
- attacker-agent Phase B scenario schema unification
- runtime validation of schema-v1 attacker scenarios
- attack_result metadata bridge from scenario schema
- attack artifact schemas for result, execution log, and observed effects
- runtime generation of `attack_observed_effects.json`
- additive `observed_effects_alignment` in `evaluation_result.json`
- `observed_effects_alignment_signals.json` generation for human review
- normalized endpoint event schema
- auditd to endpoint event conversion
- optional `endpoint_events.json` investigation harness input
- endpoint-derived investigation enriched features
- endpoint-derived investigation pivots
- deterministic judge improvements for evidence specificity, enriched feature quality, and missing-pivot detection

Recommended next work:

1. Keep endpoint telemetry and observed-effects signals human-reviewable.
2. Update roadmap and master docs to reflect #199 through #202.
3. Continue Wazuh / Velociraptor / DFIR result ingestion only after the current telemetry and action contracts remain stable.
4. Extend endpoint event sources only when a new scenario family requires new telemetry coverage.

This document remains the detailed contract for comparison harnesses and improvement workflow. `docs/roadmap/phase6.md` should stay as the high-level index.
