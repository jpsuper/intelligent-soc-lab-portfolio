# Phase1 — Correlation & Incident Builder

## 🎯 Goal
単発の検知（detection）を相関（correlation）し、  
調査・分析に使える **incident.json を生成する**。

---

## 🏗 Architecture

```
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

---

## ⚙️ Implemented Agents

### 1. parser-agent
- ログを正規化
- event_type を付与
  - ssh_failed_login
  - ssh_success_login
  - sudo_command

---

### 2. detection-agent
- 正規化イベントから検知を生成
- MITRE ATT&CK マッピング
  - ssh_failed_login → T1110
  - ssh_success_login → T1078
  - sudo_command → T1548

---

### 3. correlation-agent
- シナリオベース相関
- 検知をつなげてインシデント化

#### Implemented Scenario
```
ssh_failed_login
  ↓
ssh_success_login
  ↓
sudo_command
```

#### 条件
- success の前に failed（15分以内）
- success の後に sudo（10分以内）
- host / username 一致

#### 改善
- sudo起点に変更（重複排除）
- 最も近い success のみ使用

---

### 4. incident-builder-agent
- 相関結果を人間・AIが読める形式に整形

#### 追加情報
- timeline
- source_ips
- mitre_attack
- summary
- severity / confidence

---

## 📦 Output Files

### normalized_events.json
- 正規化済みイベント

### detection_hits.json
- 検知結果

### correlated_incidents.json
- 相関結果

### incident.json
- 最終インシデント（分析用）

---

## 🔍 Example Incident

- 攻撃元IP: 192.0.2.40
- ユーザー: victim01
- 流れ:
  - SSH brute force（複数failed）
  - 認証成功（success）
  - 権限昇格（sudo）

### MITRE ATT&CK
- T1110: Brute Force
- T1078: Valid Accounts
- T1548: Privilege Escalation

---

## 🧠 Key Design Principles

### 1. 責務分離
```
parser → ログ解釈
detection → 意味付け
correlation → ストーリー化
incident builder → 表現
```

---

### 2. ログ非依存設計
- detection は event_type のみを見る
- ログフォーマットに依存しない

---

### 3. シナリオベース相関
- 単発検知ではなく「攻撃の流れ」を捉える

---

## 🚧 Known Limitations

- failed が多すぎる（ノイズ）
- confidence が固定
- 単一ホスト前提
- lateral movement 未対応

---

## 🚀 Next Phase

### Phase2 — AI Triage Agent

incident.json を入力として：

- 攻撃内容の説明
- 影響範囲の推定
- 初動対応の提案
- 調査手順の提示

👉 SOCアナリストの判断を支援するAIを実装する
