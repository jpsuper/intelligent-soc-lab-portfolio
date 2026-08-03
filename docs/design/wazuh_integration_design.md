# Wazuh 導入方針（Lab 基盤統合案）

## 1. 目的

Wazuh は **lab の土台（baseline collection / decoding / basic detection / search UI / API）** として導入し、既存の Python / AI パイプラインは置き換えずに上位へ載せる。

この導入の目的は以下。

1. endpoint telemetry の収集基盤を強化する
2. baseline の decoding / basic detection を安定化する
3. alert / searchable alert data を investigation の検索ソースとして活用する
4. 既存の `behavior_features` / `triage` / `investigation` / `case` 設計は維持する
5. 将来的な Windows / Sysmon / FIM / TheHive 連携の足場を作る

---

## 2. 全体方針

### 2.1 役割分担

#### Wazuh
- endpoint telemetry 収集
- baseline の decoding / field extraction
- 基本検知
- alert source
- search UI / API
- dashboard
- FIM
- vulnerability detection

#### 既存の Python / AI 側
- `behavior_features`
- `derived_features`
- `enriched_features`
- `assessment`
- `investigation_result`
- `case`
- `action`
- `rule improvement`

### 2.2 重要な考え方

- **Wazuh に全部やらせない**
- **今の auditd / process chain detection は残す**
- **Wazuh は置き換えではなく、基盤として追加する**
- **detect は deterministic のまま**
- **AI は triage / investigation / planning に使う**
- **Wazuh の alert / search result は lab 側の canonical model に変換して使う**

---

## 3. 設計の中核

### 3.1 Wazuh の位置づけ

Wazuh は以下を担当する。

- Linux endpoint agent
- auth / sudo / syslog / application logs 収集
- FIM
- vulnerability detection
- 基本ルールによる alerting
- dashboard / API / search source

### 3.2 既存パイプラインとの関係

既存の流れは維持する。

```text
Attack
→ endpoint telemetry
→ detection
→ incident
→ triage
→ investigation
→ case
→ action
→ execution / approval
→ DFIR / external integrations
```

ここで Wazuh は主に以下の役割を持つ。

- telemetry source
- baseline detection source
- investigation 用の alert / search source

---

## 4. behavior_features との関係

### 4.1 基本方針

`behavior_features` の最初の付与は今までどおり detection 側で行う。

### 4.2 3層設計

- `behavior_features` = 生の観測特徴
- `derived_features` = triage の意味付け
- `enriched_features` = investigation の文脈補強
- `assessment` = 最終判断

### 4.3 Wazuh を使う時のルール

- Wazuh 側では **観測事実ベース** の field / alert を出す
- 結論寄りの意味付けは triage / investigation 側へ回す

#### detection / Wazuh で扱うもの
- `remote_download`
- `temporary_path_execution`
- `execution_after_download`
- `direct_ip_download`

#### triage / investigation で扱うもの
- `download_and_execute_chain`
- `high_risk_execution_flow`
- `payload_path_confirmed`
- `same_parent_process_chain`

---

## 5. investigation の設計

### 5.1 役割

Wazuh 導入後も investigation は **case 前の lightweight investigation** として扱う。

```text
incident
→ triage
→ investigation
→ case
```

### 5.2 input

#### required
- `incident.json`
- `triage_result.json`

#### optional
- `process_events.json`
- `process_chain_hits.json`
- `Wazuh alert`
- `Wazuh API / WQL result`
- `Wazuh indexer search result`

### 5.3 output
- `investigation_result.json`

### 5.4 investigation でやること

- incident / triage から pivot 抽出
  - host
  - user
  - src_ip
  - dst_ip
  - filepath
  - filename
  - hash（あれば）
  - process / parent process
- Wazuh API / indexer で検索
- evidence を整理
- `enriched_features` を生成
- `case.json` に統合しやすい summary / notes を出す

### 5.5 調査時間窓（MVP）
- short window: ±15分
- medium window: 24時間

### 5.6 検索の優先 pivot
- host
- user
- src_ip / dst_ip
- filepath / filename
- hash
- process / parent process

---

## 6. Wazuh の検索ソースの扱い

### 6.1 MVP では alerts を中心に使う

Wazuh を search backend として使うが、MVP では以下を中心に扱う。

- Wazuh alerts
- Wazuh API / WQL result
- dashboard 上で検索可能な alert data

### 6.2 archives は後段で導入する

raw event search は有用だが、MVP の必須要件にはしない。  
archives は必要になった段階で段階的に有効化する。

### 6.3 search backend の意味

本設計における `search backend` は、まず以下を指す。

- alert source
- searchable alert data
- API / WQL による検索対象

raw archives を常時フル活用することは MVP の前提にしない。

Scenario 009 の bounded validation では temporary `logall_json` により
manager receipt と five operations は確認できたが、core serial ごとに
`SYSCALL` だけが残り、`PATH` / `CWD` / `EXECVE` / `PROCTITLE` の complete
grouping は維持されなかった。したがって、この observed
`archives.json` は supporting observability であり、canonical source には
しない。詳細は
[Scenario 009 Wazuh Raw Archive Validation Result](scenarios/scenario009/wazuh_raw_archive_validation.md)
を参照する。

---

## 7. 導入スコープ（MVP）

### 7.1 今回やること

1. Node2 に Wazuh manager / indexer / dashboard を置く
2. Ubuntu victim に Wazuh agent を入れる
3. baseline の Linux logs を Wazuh に入れる
4. FIM を最小構成で有効化する
5. vulnerability detection を有効化する
6. Wazuh API / search を確認する
7. 既存の detection / triage / investigation パイプラインとは並走させる

### 7.2 今回やらないこと

- 既存の Python detection 全置き換え
- full EDR 的な全部入り
- Windows / AD まで一気に展開
- fully autonomous response
- Wazuh alert だけで case 生成まで完結させること
- archives 前提の full raw event investigation

---

## 8. FIM の最小対象

最初は以下だけでよい。

- `/etc`
- `/var/spool/cron`
- `authorized_keys`
- persistence に関係する service / config
- 必要なら `/tmp` は後から追加検討

---

## 9. lab での理想的な使い方

### Step 1: baseline
Wazuh を baseline collection / decoding / basic detection に使う

### Step 2: alert / search source
Wazuh を investigation の alert / API 検索ソースとして使う

### Step 3: integration
Wazuh alert / search result を既存の `incident → triage → investigation` に接続する

### Step 4: 将来拡張
- TheHive 連携
- RAG enrichment
- high severity alert のみ AI に渡す
- playbook / event-driven 実行
- raw archives 活用

---

## 10. 今の lab に一番合うデータフロー

### 10.1 Wazuh alert を流す場合

```text
Wazuh Agent
→ Wazuh Manager / Indexer
→ alert / searchable alert data
→ custom normalizer / incident builder
→ triage
→ investigation
→ case
→ action
```

### 10.2 investigation 側だけ Wazuh を使う場合

```text
custom incident
→ triage
→ investigation
   ├─ process_events.json
   ├─ process_chain_hits.json
   ├─ optional: Zeek enrichment
   └─ Wazuh alert / WQL result / search result
→ investigation_result.json
→ case
```

---

## 11. 実装タスク

### Phase A: 基盤
- Wazuh server 構築
- Ubuntu victim agent 導入
- dashboard で event / alert 確認
- FIM / vulnerability detection 有効化

### Phase B: lab 接続
- Wazuh の alert / search を参照できるようにする
- Python 側から Wazuh API または index 検索できるようにする
- Wazuh alert / search result を canonical event / canonical alert に変換する
- Wazuh 固有の処理は `wazuh_enricher` 方向で切り出す
- `investigation-agent` に Wazuh search optional input を追加する

### Phase C: 統合
- Wazuh alert を incident 生成に活用する
- `behavior_features` と Wazuh field の対応整理
- TheHive / action / rule improvement へつなげる

---

## 12. 実装時の判断基準

### OK
- Wazuh は baseline / alert / search / UI / API に使う
- 既存の lab ロジックは維持する
- feature 設計は自前で持つ
- AI は後段で使う
- Wazuh 固有の field は canonical model に変換して使う

### NG
- 先に Wazuh に完全移行する
- custom detection / behavior_features を捨てる
- investigation を全部 Wazuh dashboard 手作業前提にする
- Wazuh 固有 field をそのまま investigation-agent 本体へ増やし続ける

---

## 13. 一言でまとめると

**Wazuh = baseline SIEM / EDR 土台**  
**既存 agents = 意味づけ・調査・ケース化・対応**

この分担で進める。
