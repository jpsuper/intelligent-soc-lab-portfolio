# SOC Lab 改善ロードマップ（共通化 & 将来拡張対応 / 完全統合版）

## 🎯 目的

本プロジェクトの目的：

> AIが攻撃・防御・トリアージ・調査・DFIRをどこまで自動化できるかを検証し、  
> どこに人間の判断が必要かを理解する

この目的を維持したまま、以下を実現する：

- シナリオ増加に耐えられる構成
- PentAGI / Vigil のような拡張性
- 実験・比較がしやすい設計
- Atomic / Caldera から将来的に自立型へ進化できる設計
- 攻撃側も objective / planner / delegation / memory を持つ形へ進化できる設計

---

# 🏗️ 設計レイヤー（統合方針）

本ドキュメントは roadmap の Phase 定義を書き換えるものではなく、  
既存Phaseをより拡張しやすくするための **設計統合方針** を扱う。

外部リポジトリの思想は、Phase名そのものとして導入するのではなく、  
以下の設計要素に対応づけて段階的に取り込む。

- **Vigil** → workflow / agent責務分離 / multi-agent化
- **AI-SOC-Agent** → tool呼び出し / adapter / SIEM検索API
- **AI_SOC** → enrichment / threat intelligence / RAG
- **agentic-soc-platform** → event-driven / playbook orchestration / 限定的自動対応
- **PentAGI** → objective-driven攻撃計画 / specialist delegation / offensive memory / isolated execution

---

## 🧠 3層モデル

```text
Control Plane（意思決定）
Execution Plane（実行）
Data Plane（データ）
```

### Control Plane
- attack-planner-agent
- triage-agent
- investigation-agent
- action-agent
- rule-improvement-agent
- orchestrator-agent

### Execution Plane
- attack-executor
- executor-agent
- velociraptor-agent
- thehive-agent
- atomic / caldera / shell / future tool integrations

### Data Plane
- run data
- logs / normalized events
- incident / triage / investigation / case
- features
- decision_log
- attack_plan / attack_graph / tool_activity / offensive memory

---

## 🤖 Agent責務の再整理

- **Detection Agent**: ルール評価、初期 feature 付与
- **Triage Agent**: 初期判断、risk_score / confidence 算出、derived feature 生成
- **Investigation Agent**: 前後文脈取得、attack story 生成、enriched feature 生成
- **Action Agent**: 対応方針決定、playbook 生成
- **Executor Agent**: playbook 実行、approval 制御
- **Rule Improvement Agent**: missed detection / noisy rule 分析、改善提案
- **Orchestrator Agent**: workflow 実行制御、run単位の比較と追跡
- **Attack Planner Agent**: objective を subtask に分解し、tool / specialist / executor を選ぶ
- **Attack Specialist Agents**: recon / exploit research / payload / infra などの役割を分担する

---

# 🧠 全体方針

## ❌ 今の課題

- シナリオごとにファイルが増える
- データが混ざる（Phase4 / Phase5）
- parser / detection がスクリプト単位で分散
- agent同士が強結合
- 実行方法（manual / Atomic / Caldera / autonomous）が固定化されていない
- AI判断と人間判断の境界が記録されていない
- 攻撃側が「シナリオ再生」中心で、objectiveベースの計画・分解・委譲が弱い
- 攻撃側の知見がrunごとに使い捨てで、再利用できる memory / graph がない
- ツール選択や実行環境選択が固定的で、task-aware に切り替えられない

---

## ✅ 改善方針

```text
agent中心 → run / workflow中心へ
```

```text
シナリオ中心 → objective + executor中心へ
```

```text
固定実行 → adapter経由の差し替え可能実行へ
```

```text
attack手法中心 → behavior feature中心へ
```

```text
AI判断中心 → evidence / decision boundary を明示へ
```

```text
静的シナリオ再生中心 → objective / planner / delegation中心へ
```

```text
攻撃知見の使い捨て → memory / knowledge graphで再利用へ
```

```text
固定ツール使用 → task-aware tool / container selectionへ
```

- AIは主に triage / investigation / planning に使う
- detection は deterministic を維持する
- containment など危険操作は approval gate の外に出さない
- 攻撃側も最初は planner + executor の分離から始め、いきなり unrestricted autonomy にしない

---

# 🚀 優先実装（最重要）

## ① run単位の共通化

### 🎯 目的

- データ混在防止
- 実験単位の分離
- 再現性確保
- シナリオ比較・実行方式比較を容易にする

---

### 📂 新構成

```text
data/runs/<run_id>/
  run_meta.json
  attack_plan.json
  attack_graph.json
  attack_result.json
  tool_activity.json
  incident.json
  evaluation_result.json
  triage_result.json
  investigation_result.json
  process_events.json
  interesting_process_events.json
  process_chain_hits.json
  case.json
  action_result.json
  collection_request.json
  decision_log.json
```

---

### 🔧 変更内容

- 全agentに `--run-id` を追加
- 固定パス参照を廃止
- run配下のファイルを参照
- decision / evidence / human approval の記録を run 単位で保持
- 攻撃側の objective / subtask / selected tool / execution trace も run 単位で保持

---

## ② workflow導入（Vigil思想 + 攻撃側拡張）

### 🎯 目的

- agentのオーケストレーション
- 実験単位の明確化
- 自動化 vs 人間判断の比較
- execution / triage / DFIR の分離
- triage / investigation / response の責務分離
- single-agent 依存から multi-agent 構造への移行
- 攻撃側 / 防御側 workflow の分離と比較

---

### 🏗️ 構成

```text
workflows/
  incident_response.yaml
  process_execution.yaml
  payload_investigation.yaml
  attack_objective_execution.yaml
  autonomous_recon.yaml
```

---

### 🔁 例（防御側）

```text
detect
→ triage
→ investigation
→ case
→ action
→ executor
→ thehive
→ velociraptor
```

### 🔁 例（攻撃側）

```text
objective
→ attack planner
→ specialist delegation
→ attack executor
→ logs / telemetry
→ detect
→ triage
→ case
→ action
→ executor
→ thehive
→ velociraptor
```

---

### 🧾 JSON契約の整理

```text
incident.json
→ triage_result.json
→ investigation_result.json
→ case.json
→ action_result.json
```

- triage は verdict / risk_score / confidence を出す
- investigation は attack story / evidence expansion / context enrichment を出す
- case は事実の統合結果として保持し、後続連携の source of truth とする

---

### 🧠 Vigil思想の取り込み方

- 防御側では triage / investigation / response の責務を分離する
- 攻撃側でも objective を workflow として扱い、単一script依存を減らす
- incident側と attack側の両方を run / workflow 単位で比較できるようにする

---

## ③ adapter / integration 層の導入

### 🎯 目的

- 外部ツール統合
- backend差し替え可能化
- Atomic / Caldera / autonomous executor の共存
- tool呼び出しの統一インターフェース化
- 将来的な SIEM検索 / MCP 的設計への接続
- 攻撃ツール群と検索系バックエンドの抽象化

---

### 📂 構成

```text
integrations/
  atomic/
  caldera/
  shell/
  thehive/
  velociraptor/
  wazuh/
  siem/
  threat_intel/
  nmap/
  metasploit/
  sqlmap/
  web_search/
  exploit_search/
```

---

### 🧠 ポイント

- agentは直接ツールを叩かない
- adapter経由で呼ぶ
- executor を差し替えても workflow は維持する
- 検索・実行・収集のインターフェースを統一する
- backend が Elastic / Wazuh / 将来のSIEM に変わっても agent 側は極力変えない
- 攻撃側でも task に応じて tool / container / backend を選べるようにする

---

### 🔌 AI-SOC-Agent思想の取り込み方

- `agent → adapter → tool` の構造を徹底する
- 将来的に `search_siem()` `collect_host_artifacts()` `create_case()` のような共通APIを持つ
- LLMは「ツールを選択して呼ぶ層」に置き、直接ベンダー依存コードを持たせない
- SIEM検索は最初は mock / local API でもよく、後で実製品へ差し替え可能にする

---

## ③A 攻撃側 workflow 強化（PentAGI思想）

### 🎯 目的

- 攻撃側を「静的シナリオ再生」から「目的駆動の実行」へ進化させる
- planner が objective を subtask に分解できるようにする
- reconnaissance / exploit research / payload execution / infrastructure を役割分離する
- 同じ objective を manual / Atomic / Caldera / autonomous で比較可能にする
- 攻撃側の知見を run 後に memory / graph として再利用可能にする

---

### 🏗️ 構成

```text
objective
→ attack-planner
→ specialist delegation
→ tool / container selection
→ attack-executor
→ observe
→ memory update
```

---

### 🤖 specialist の例

- recon-agent
- exploit-research-agent
- payload-agent
- infra-agent
- operator-agent

---

### 🧠 ポイント

- 最初は full autonomous にせず、planner + executor の二段階で導入する
- objective は固定でもよく、subtask 分解から始める
- 実行は sandbox / isolated worker 前提で扱う
- 成功した探索経路や失敗パターンを memory として残す
- 攻撃側も `decision_log` に plan / select / execute / observe を残す

---

# 🔧 機能拡張（Phase5拡張）

## ④ process chain → triage連携

- process_summaryをtriageに入力
- AIに挙動解釈させる
- verdict / risk_score / confidence を case に反映

---

## ⑤ process chain → TheHive

- process_timelineをcase説明に追加
- observable / custom field として拡張可能にする
- caseの説明力向上
- filename / hostname / ip / url を observable として扱う

---

## ⑥ Velociraptor連携強化

```text
executed_payload → DFIR request
```

例：

```text
/tmp/payload.sh
```

- executed_payload から対象ファイル抽出
- Linux.ProcessList / Linux.BashHistory を収集対象にする
- 将来は hash / file retrieval / shell history と接続

---

## ⑦ Action Planning / Playbook / Execution

### 🎯 目的

- triage結果を実行可能な形に落とし込む
- plan と execute を分離する
- SOAR的な実験を可能にする
- AI判断と人間承認の境界を明確にする

---

### 構成

```text
triage
→ action-agent（planner）
→ playbook
→ executor-agent
→ external adapters
```

---

### 現時点の構成

```text
triage
→ action-agent（rule / AI planner）
→ playbook.steps
→ executor-agent
→ velociraptor-agent / TheHive / future integrations
```

---

### 🧠 ポイント

- action-agent = 「何をするか決める」
- executor-agent = 「どう実行するか担当する」
- direct containment は行わず、最初は proposal / approval gate を重視する
- plannerを rule と AI で差し替えられるようにする

---

### ⚡ agentic-soc-platform思想の取り込み方

- playbook を event-driven で起動できる構造に寄せる
- triage / investigation / action の結果を workflow event として扱えるようにする
- 限定的自動対応は approval gate を維持したまま導入する
- 自動対応は「安全操作」から始め、危険操作は引き続き human approval を通す

---

## ⑧ Approval Gate（重要）

### 🎯 目的

- 危険操作を自動実行しない
- human judgment の介在点を記録する
- fully autonomous に急がず、比較可能な設計にする

---

### 現在の考え方

- `request_dfir_collection` → auto executable
- `alert_soc_team` → auto executable
- `review_payload_execution` → auto executable
- `consider_host_isolation` → approval required

---

### 返却イメージ

```json
{
  "id": "step-4",
  "type": "consider_host_isolation",
  "auto_executable": false,
  "params": {
    "target": "ubuntu-victim01"
  }
}
```

---

## ⑨ decision log の追加

### 🎯 目的

- AIが何を見て何を判断したか残す
- 人間判断との境界を明確化
- 実験比較可能化
- planning と execution を分離して観測する

---

### 🧾 各runで記録

```json
{
  "stage": "execution",
  "step_id": "step-4",
  "step_type": "consider_host_isolation",
  "status": "pending_approval",
  "timestamp": "..."
}
```

---

### 現時点での対象

- detection
- triage
- investigation
- action
- execution
- approval
- attack planning
- attack execution

---

### 例

```json
{
  "stage": "action",
  "decision_type": "response_planning",
  "planner_mode": "ai",
  "verdict": "malicious",
  "priority": "P1",
  "risk_score": 90,
  "proposed_actions": [
    "request_dfir_collection",
    "alert_soc_team"
  ],
  "human_required": true
}
```

---

# 🔄 将来拡張

## ⑩ scenario実行の抽象化

### 🎯 目的

- Atomic / Caldera対応
- 実行方式比較
- 将来的な自立型への移行
- objectiveベースの攻撃計画に対応

---

### 🧩 例

```yaml
scenario_id: scenario-002
name: download_and_execute_payload
objective: execute downloaded payload
constraints:
  - no destructive action
  - stay within lab subnet
executor: manual
memory_profile: default
success_conditions:
  - payload executed
  - telemetry generated
```

将来的には：

```yaml
executor: atomic
executor: caldera
executor: autonomous
planner_mode: static
planner_mode: assisted
planner_mode: autonomous
```

---

## ⑪ planner interface の追加

### 🎯 目的

- 自立型への進化を見越した設計
- plan / execute / observe の分離
- approval gate と接続
- rule planner / AI planner の差し替え
- 攻撃側 / 防御側の planner を同じ思想で扱う

---

### 🧩 返却イメージ

```json
{
  "objective": "enumerate exposed services and validate exploitability within lab scope",
  "planner_type": "attack",
  "selected_executor": "autonomous",
  "selected_specialists": [
    "recon-agent",
    "exploit-research-agent",
    "operator-agent"
  ],
  "selected_tools": [
    "nmap",
    "search",
    "manual_shell"
  ],
  "proposed_steps": [],
  "confidence": 0.78,
  "requires_human_approval": true
}
```

---

### 🧠 ポイント

- 最初は固定値でもよい
- 後で planner を差し替え可能にする
- Atomic / Caldera / autonomous を同じインターフェースで扱う
- attack planner では subtask 分解・specialist 選択・tool 選択を返せるようにする

---

## ⑪A offensive memory / knowledge layer

### 🎯 目的

- 過去runの攻撃知見を次回に再利用する
- successful path / failed path / useful artifact を記録する
- scenario 固定ではなく objective 達成パターンを学習できるようにする

---

### 保持したい情報

- 有効だった recon 手順
- 有効だった exploit 調査結果
- 失敗したペイロードや blocked action
- どの tool / container が有効だったか
- run 間の artifact 関係

---

### 方針

- 最初は JSON ベースでよい
- 将来的には graph 形式へ拡張可能にする
- defensive side の case / evidence と offensive side の memory を結びつける

---

## ⑫ behavior feature ベース設計

### 🎯 目的

- 攻撃手法依存コードから脱却する
- シナリオ増加に耐える
- triage / action / execution を汎用化する
- detection / triage / investigation の役割を明確化する

---

### Feature Lifecycle

```text
detection
→ behavior_features（観測事実）
→ triage
→ derived_features（意味付け）
→ investigation
→ enriched_features（文脈補完）
```

---

### 例

```json
{
  "behavior_features": {
    "remote_download": true,
    "temporary_path_execution": true,
    "execution_after_download": true
  },
  "derived_features": {
    "download_and_execute_chain": true,
    "high_risk_execution_flow": true
  },
  "enriched_features": {
    "privilege_escalation_observed": false,
    "lateral_movement_observed": false
  }
}
```

---

### 方針

```text
scenario名ベースの分岐
↓
featureベースの判断
```

- detection は **事実** を付与する
- triage は feature を解釈して **意味** を与える
- investigation は evidence / timeline / surrounding logs から **文脈** を補完する
- action は feature + policy から playbook を作る
- approval は feature に応じて境界を決める
- 攻撃側でも objective を固定しつつ、到達した behavior を比較対象として扱えるようにする

---

### AI_SOC思想の取り込み方

- feature と incident を入力として enrichment を行う
- threat intelligence を behavior / artifact に対して追加する
- 将来的に RAG で過去case・調査メモ・検知知見を参照可能にする
- AIは detect ではなく、文脈理解と説明力の強化に使う

---

# 🔍 detection / parser の進化

## ⑬ detection backend抽象化

```text
engines/
  python_engine.py
  sigma_engine.py
```

---

## ⑭ parser backend抽象化

```text
adapters/
  auditd.py
  wazuh.py
```

---

### 🧠 方針

```text
Python parserを捨てない
→ backend追加
```

- Python = 研究用 / 特殊検知 / enrich
- Wazuh = baseline正規化 / 運用寄り

---

# ⚠️ 重要設計

## Control Plane / Execution Plane 分離

```text
Control Plane:
  attack-planner / triage / investigation / action / decision_log / approval policy

Execution Plane:
  attack-executor / executor / velociraptor / thehive / future integrations
```

### 🧠 攻撃側の原則

- 攻撃実行は sandbox / isolated worker 前提で扱う
- planner と executor を分離し、いきなり unrestricted execution にしない
- tool 実行ログとネットワーク境界を run に紐づけて記録する

---

## Evidenceベース設計

各runで記録：

```json
{
  "decision_input": [],
  "decision_output": "",
  "confidence": "",
  "risk_score": 0,
  "human_required": false,
  "artifacts_used": []
}
```

---

## Approval Gate（再掲）

```text
action-agent
→ playbook
→ executor-agent
→ 自動実行しない step は approval待ち
```

### 🧠 意義

- いきなり fully autonomous にしない
- どこに human judgment が必要かを記録できる
- 自立型への移行時も gate を緩めるだけで対応可能

---

# 🧠 Atomic / Caldera / 自立型の進化ルート

```text
manual scenario
→ Atomic / Caldera executor
→ planner付き semi-autonomous
→ specialist delegation + memory
→ autonomous attacker / responder
```

---

## 🎯 方針

- いきなり fully autonomous にしない
- 同じ scenario semantics を複数 executor で比較する
- AIの役割を段階的に増やす

---

## 例

### Step1
- manual / static scenario

### Step2
- Atomic / Caldera 実行

### Step3
- planner が executor を選択

### Step4
- planner が subtask / specialist / tool を選択

### Step5
- successful path / failed path を memory へ保存

### Step6
- autonomous workflow 実行

---

# 🧠 Wazuh導入方針

## ❌ NG

- Python parser 全置き換え

## ✅ OK

```text
Wazuh → baseline正規化
Python → 拡張・研究用
```

---

# 🎯 実装優先順位

## Phase A（最優先）

1. run単位共通化
2. workflow導入
3. adapter層

---

## Phase B（即価値）

4. process → triage
5. process → TheHive
6. Velociraptor連携
7. action planning / executor / approval gate

---

## Phase C（拡張）

8. scenario executor 抽象化
9. planner interface
10. rule-improvement
11. behavior feature ベース設計
12. offensive memory / graph

---

## Phase D（基盤）

13. Sigma対応
14. Wazuh対応
15. attack tool adapter 拡張

---

## Phase E（自立型への進化）

16. planner付き semi-autonomous
17. approval gate付き autonomous execution
18. 攻撃 / 防御 / triage / DFIR の比較研究

---

# 📂 将来を見越したディレクトリ構成案

```text
agents/
  parser-agent/
  detection-agent/
  correlation-agent/
  ai-triage-agent/
  case-agent/
  thehive-agent/
  velociraptor-agent/
  action-agent/
  executor-agent/
  rule-improvement-agent/
  attack-planner-agent/
  recon-agent/
  exploit-research-agent/
  payload-agent/

workflows/
  process_execution.yaml
  incident_response.yaml
  attack_objective_execution.yaml
  autonomous_recon.yaml

integrations/
  atomic/
  caldera/
  shell/
  thehive/
  velociraptor/
  wazuh/
  siem/
  threat_intel/
  nmap/
  metasploit/
  sqlmap/
  web_search/
  exploit_search/

planner/
  interface.py
  attack_interface.py

memory/
  offensive_memory/
  attack_graph/

data/
  runs/
    <run_id>/
```

---

# 🎯 最重要ポイント

```text
機能追加より共通化
```

```text
agent追加より workflow / run整理
```

```text
自立化より まず比較可能性
```

---

# 💡 この設計の価値

- 実験の再現性が上がる
- AIの有効性を比較できる
- PentAGI / Vigilと同じ方向に進める
- 攻撃側も objective / planner / delegation / memory を持つ設計にできる
- Atomic / Caldera から自立型に進化しやすい
- 攻撃 / 防御の両面で比較研究しやすい
- 研究目的と完全一致

---

# 🔥 一言

👉 この段階で共通化に舵を切ったのはかなり良い判断  
👉 この設計にすると「研究としての価値」が一気に上がる  
👉 いきなり完全自立ではなく、比較可能な進化ルートを持つのが重要
