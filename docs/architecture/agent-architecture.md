# Agent Architecture

AI SOC Labで段階的に実装するAgent一覧と依存関係を定義する。  
このドキュメントは **最終アーキテクチャ** を定義しつつ、あわせて **現在の実装範囲** も明記する。

---

## 1. Design Principle

このドキュメントでは、次の2つを分けて扱う。

1. **Full Architecture**
   - ラボ全体の完成形
   - 将来導入予定のAgentも含む

2. **Current Implementation**
   - 現時点で実装済み・動作確認済みの範囲
   - Phase進行に応じて更新する

つまり、**未実装Agentは削除しない**。  
未実装でも、将来の責務として明示的に残す。

---

## 2. Naming Convention

- Workflow / responsibility descriptions use conceptual stage names without "Agent" (for example: Triage, Investigation, Case, Action, Execution).
- Component inventories and implementation references use concrete implementation names with "Agent" (for example: Triage Agent, Investigation Agent, Case Agent, Action Agent, Executor Agent).

### Examples

#### Workflow / responsibility description
```text
Detection
→ Triage
→ Investigation
→ Case
→ Action
→ Execution / Approval
```

#### Component / implementation description
```text
Detection Agent
→ Triage Agent
→ Investigation Agent
→ Case Agent
→ Action Agent
→ Executor Agent
```

---

## 3. Full Agent List

| Agent | Purpose | Input | Output | Main Phase |
|---|---|---|---|---|
| Telemetry Agent | ログ収集 | raw logs | collected raw logs / forwarded logs | Phase0 |
| Log Parser Agent | 正規化 | raw log | normalized events | Phase0 |
| Detection Agent | 単発検知 / 初期 feature 付与 | normalized events | detection hits | Phase1 |
| Correlation Agent | 相関検知 | detection hits | correlated incident candidates | Phase1 |
| Incident Builder Agent | incident生成 | correlated incidents + refs + features | incident.json | Phase1 |
| Triage Agent | SOC分析 / 初期判断 / リスク評価 | incident + optional context | triage_result.json | Phase2 |
| Action Agent | 対応方針 / playbook 生成 | triage / investigation / case | action_result.json | Phase2拡張 |
| Executor Agent | playbook 実行 / approval 制御 | action_result / playbook | execution result / external execution | Phase2拡張 |
| Scenario Agent | 攻撃シナリオ定義 | scenario YAML / templates | runnable scenario definitions | Phase3 |
| Attacker Agent | 攻撃実行 | scenario | attack_result.json / attack execution | Phase3 |
| Attack Planner Agent | objective を subtask に分解し tool / specialist / executor を選択（将来拡張） | objective / constraints / memory | attack plan | Phase3拡張 / 将来 |
| Case Agent | run結果を case.json に正規化し source of truth を作る | incident / triage / investigation / evaluation | case.json | Phase4 |
| Investigation Agent | 前後文脈取得 / attack story / DFIR連携 | incident / triage / case / host context | investigation_result.json / evidence refs | Phase4 |
| Endpoint Telemetry Agent | process telemetry 強化 | endpoint telemetry | enriched endpoint events | Phase5 |
| Rule Improvement Agent | 検知・相関・workflow改善提案 | attack results + incidents + triage + actions + gaps | rule suggestions / improvement notes | Phase6 |
| Scenario Orchestrator | attack→detect→triage→investigate→improve ループ制御 | scenario + config | loop run / orchestration result | Phase6 |
| Deception Agent | decoy / honeytoken生成 | attacker intent / config | deception assets | Phase7 |
| Trap Detection Agent | deception hit検知 | auth / access / endpoint logs | trap alert | Phase7 |
| Background Activity Agent | 正常系ノイズ生成 | schedule / templates | normal activity logs | Phase8 |

---

## 4. Full Dependency Order

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
Investigation Agent
  ↓
Case Agent
  ↓
Action Agent
  ↓
Executor Agent
  ├─ TheHive / case integrations
  ├─ Velociraptor / DFIR integrations
  └─ Rule Improvement Agent

Scenario Agent
  ↓
Attacker Agent
  ↓
Scenario Orchestrator

Endpoint Telemetry Agent
  ↓
Telemetry / Detection / Correlation enrichment

Deception Agent
  ↓
Trap Detection Agent

Background Activity Agent
  ↓
Telemetry realism / false positive evaluation
```

---

## 5. Core Data Flow

### 5.1 Defensive Workflow

```text
Raw Log
→ Normalized Event
→ Detection Hit
→ Correlated Incident
→ Incident
→ Triage
→ Investigation
→ Case
→ Action
→ Execution / Approval
→ DFIR / External Integrations
```

### 5.2 Offensive / Validation Workflow

```text
Scenario
→ Attacker Agent
→ shell runner
→ attack_result.json
→ attack_execution_log.json
→ attack_observed_effects.json
→ defender-side logs / telemetry / fixtures
→ defensive workflow when implemented
```

Important boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

Attacker-side structured runner events and `attack_observed_effects.json` are
useful for auditability and alignment. They are not defender-side telemetry,
detection evidence, or alerts.

### 5.3 Improvement Loop

```text
attack_result.json
+ incident.json
+ triage_result.json
+ investigation_result.json
+ case.json
+ action_result.json
+ execution / integration results
        ↓
Rule Improvement Agent
        ↓
suggestions / gap analysis
        ↓
Scenario Orchestrator
        ↓
attack again
```

### 5.4 Feature Lifecycle

```text
Detection
  ↓
behavior_features
  ↓
Triage
  ↓
derived_features
  ↓
Investigation
  ↓
enriched_features
  ↓
Case
```

---

## 6. Current Implementation Status

### 6.1 Implemented / Working

| Agent | Status | Notes |
|---|---|---|
| Log Parser Agent | Implemented | Parses and normalizes run-scoped logs |
| Detection Agent | Implemented | Generates detection hits |
| Correlation Agent | Implemented | Correlates related activity |
| Incident Builder Agent | Implemented | Builds structured incident.json |
| Triage Agent | Implemented | LLM-based triage with structured output |
| Action Agent | Implemented | Rule-based / AI planning support |
| Executor Agent | Implemented | Executes playbook with approval boundary |
| Scenario Agent | Minimal / implicit | Scenario YAML in use |
| Attacker Agent | Implemented | Local scenario YAML + shell runner model; writes `attack_result.json`, `attack_execution_log.json`, and `attack_observed_effects.json` |
| Case Agent | Implemented | Generates case.json with schema validation |
| Investigation Agent | Partial / integration-oriented | Velociraptor request generation / follow-on workflow |
| Scenario Orchestrator | Minimal / lightweight | Makefile / run-based orchestration |

### 6.2 Implemented Cross-Cutting Capabilities

- run isolation / run-based outputs
- `run_id` traceability
- `attack_id` propagation
- supported pipeline execution across existing implemented stages:
  - attack
  - parse
  - detect
  - correlate
  - incident
  - triage
  - case
  - action
  - execution
- decision logging:
  - detection
  - triage
  - action
  - execution
- TheHive integration
- Velociraptor request generation
- `behavior_features` in case / triage / action planning
- scenario family expansion policy
- Linux scenario family candidates
- Phase7 deception artifact foundation through schemas, local asset generator,
  hit generator, incident bridge, and chain smoke
- `scenario_009_suspicious_archive_staging` local scenario YAML + shell runner
- `scenario_009` attacker-side structured events / observed effects
- initial `scenario_009` synthetic defender-side endpoint fixture
- initial `scenario_009` DSL detection expectation for
  `suspicious_archive_staging`
- initial `scenario_009` helper-level observation incident bridge for
  `suspicious_archive_staging` detection hits

### 6.3 Not Yet Fully Implemented

| Agent / Capability | Planned Phase |
|---|---|
| Telemetry Agent | Phase0 refinement |
| Investigation Agent (full context expansion) | Phase4 refinement / Phase6 workflowization |
| Endpoint Telemetry Agent (broader beyond process telemetry) | Phase5 expansion |
| Rule Improvement apply / deploy / promotion workflows | Phase6 follow-on / review-gated |
| Scenario Orchestrator (full agent form) | Phase6 |
| Phase7 deception scenario runner | Phase7 follow-on / intentionally deferred |
| Live auditd / Wazuh / SIEM telemetry collection for `scenario_009` | Follow-on |
| `scenario_009` triage / investigation / action coverage | Follow-on |
| Atomic Red Team adapter | Later optional / reference mapping only for now |
| CALDERA integration | Later optional |
| Background Activity Agent | Phase8 |
| Attack Planner Agent | Future extension |

---

## 7. Current Practical Pipeline

現時点で実際に動作している run ベースの最小パイプラインは以下。

```text
scenario
→ attacker-agent
→ shell runner
→ attack_result.json
→ attack_execution_log.json
→ attack_observed_effects.json
→ parser-agent
→ detection-agent
→ correlation-agent
→ incident-builder-agent
→ ai-triage-agent
→ case-agent
→ action-agent
→ executor-agent
→ TheHive / Velociraptor request
```

実行は現在、Makefile / run-based orchestration をベースに行う。

---

## 8. Current Output Set

現実装で主に出力される成果物:

```text
data/runs/<run_id>/
  attack_result.json
  normalized_events.json
  detection_hits.json
  correlated_incidents.json
  incident.json
  triage_result.json
  case.json
  action_result.json
  decision_log.json
  collection_request.json
```

process telemetry を使う run では、以下も含まれる。

```text
process_events.json
interesting_process_events.json
process_chain_hits.json
```

For `scenario_009`, the current defender-side slice is fixture based:

```text
tests/fixtures/scenario_009_suspicious_archive_staging/endpoint_events.json
  → detection/dsl/suspicious_archive_staging.yaml
  → suspicious_archive_staging detection expectation
```

This is an initial synthetic defender-side fixture / DSL detection expectation.
It is not live auditd / Wazuh / SIEM coverage, and it does not imply
incident / triage / investigation coverage.

---

## 9. Current Cross-Cutting Design

### 9.1 Run Isolation

- `run_id` ごとに成果物を分離する
- run単位で再現・比較可能にする
- 1 run = 1 experiment unit を維持する

### 9.2 attack_id Traceability

全パイプラインに以下を伝播させる:

```json
"attack_id": "attack-000001"
```

対象:
- normalized events
- detection hits
- correlated incidents
- incidents
- triage results
- case records
- action results

目的:
- run単位評価
- missed detection 分析
- rule improvement の前提データ化

### 9.3 Case as Source of Truth

- case は事実と判断を保持する内部記録
- 後続の TheHive / DFIR / external integrations は case を基準に接続する
- case enrichment は append-only を原則とする

### 9.4 Feature-Based Design Direction

- detection_type / scenario 名依存を減らす
- observed behavior を behavior_features として保持する
- triage で derived_features を生成する
- investigation で enriched_features を追加する
- action は feature + policy を主根拠にする

---

## 10. Future Agent Responsibilities

### 10.1 Case Agent
- incident / triage / investigation を case.json に統合する
- case lifecycle を保持する
- external integrations の source of truth を提供する

### 10.2 Investigation Agent
- surrounding context / timeline / attack story を拡張する
- DFIR / evidence collection を起動する
- evidence と incident / case を関連付ける

### 10.3 Endpoint Telemetry Agent
- process / file / network telemetry を統合する
- Linux auth系以外のシグナルを defensive workflow に供給する
- richer correlation を可能にする

### 10.4 Rule Improvement Agent
- attack run ごとに結果を比較する
- detected / missed / noisy を判断する
- rule improvement suggestions を生成する
- correlation / workflow improvement suggestions も扱う

### 10.5 Scenario Orchestrator
- 複数 scenario の実行制御
- defensive workflow との再実行ループ
- improvement loop のハブ
- 将来的に workflow definitions を実行可能にする

### 10.6 Deception / Trap Detection
- Phase7 foundation currently provides schemas, deterministic local asset
  generation, trap hit generation, an incident bridge, and chain smoke coverage
- honeytoken / decoy deployment through a scenario runner is intentionally
  deferred
- future deception hits should become a high-confidence signal layer without
  bypassing approval gates

### 10.7 Background Activity Agent
- 正常系ノイズを生成する
- false positive 測定を可能にする
- 本番 SOC に近い観測条件を再現する

### 10.8 Attack Planner Agent
- objective を subtask に分解する
- tool / executor / specialist を選択する
- offensive planner / memory / graph への拡張点となる

---

## 11. MVP Order (Recommended)

最終形は大きいが、MVP順は次の通り。

1. Telemetry / Parser
2. Detection
3. Correlation
4. Incident Builder
5. Triage
6. Scenario / Attacker
7. Case / Investigation
8. Action / Executor
9. Endpoint Telemetry
10. Rule Improvement / Orchestrator
11. Deception
12. Background Activity

---

## 12. Key Design Principles

- **Modular**: Agentごとに責務を分ける
- **Traceable**: attack_id / event_ref / incident_id / run_id で追跡する
- **Reproducible**: scenario と run を再現可能にする
- **Phase-based**: 段階実装を前提にする
- **Future-compatible**: 未実装Agentも最終構想として保持する
- **Feature-oriented**: behavior feature を中心に汎用化する
- **Evidence-first**: AI判断より evidence / decision boundary を可視化する

---

## 13. Summary

このアーキテクチャでは、**現在の実装状況** と **将来の完成形** を分けて扱う。

- 現在:
  - attack → detect → triage → case → action → execution の最小SOCループが実行可能
- 将来:
  - investigation / richer telemetry / improvement loop / deception / planner まで拡張

したがって、未実装Agentは削除せず、**最終アーキテクチャの一部として保持する**。
