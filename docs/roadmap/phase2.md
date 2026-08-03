# Phase2 --- AI SOC Triage & Action Planning

## 🎯 Goal

incident.json をもとに AI によるトリアージ（分析・評価）を行い、
優先度付けと初動対応（action plan）を自動生成する。

------------------------------------------------------------------------

## 🏗 Architecture

    incident.json
      ↓
    ai-triage-agent
      ↓
    triage_result.json
      ↓
    action-agent
      ↓
    action_result.json

------------------------------------------------------------------------

## ⚙️ Implemented Agents

### 1. ai-triage-agent

-   incident.json を入力として AI に渡す
-   SOCアナリストとして判断を行う

#### 出力

-   verdict（malicious / suspicious / benign）
-   confidence（low / medium / high）
-   summary
-   attack_story
-   key_observations
-   mitre_attack
-   recommended_actions
-   priority（P1 / P2 / P3）
-   risk_score（0〜100）

------------------------------------------------------------------------

### 2. action-agent

-   triage_result.json をもとにアクションプランを生成

#### 出力

-   action_result.json

#### action内容

-   isolate_host
-   disable_account
-   alert_soc_team
-   monitor / log_only

------------------------------------------------------------------------

## 📦 Output Files

### triage_result.json

-   AIによる分析結果

### action_result.json

-   実行可能なアクションプラン

------------------------------------------------------------------------

## 🔍 Example Flow

    SSH brute force
      ↓
    認証成功
      ↓
    sudo実行
      ↓
    AI triage → malicious / P1
      ↓
    action → isolate + disable + alert

------------------------------------------------------------------------

## 🧠 Key Features

-   AIによるインシデント分析
-   優先度（priority）付け
-   リスクスコア（risk_score）
-   構造化された対応アクション
-   SOC判断の自動化

------------------------------------------------------------------------

## 🧠 Design Principles

-   Detect は deterministic
-   AI は analyst / triage に使用
-   Action は機械可読な形で出力
-   人間の判断を補助しつつ自動化を目指す

------------------------------------------------------------------------

## 🚧 Known Limitations

-   action は planned のみ（実行は未対応）
-   CMDB / asset context が無い
-   誤検知（false positive）の完全排除は不可
-   単一インシデント前提

------------------------------------------------------------------------

## 🚀 Next Phase

### Phase3 --- Adversary Simulation

-   攻撃シナリオの自動実行
-   検知とAIの評価をループさせる
