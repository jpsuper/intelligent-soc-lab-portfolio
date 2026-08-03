# Atomic Detection DSL

## 1. 目的

この文書は、AI SOC Lab における **atomic detection DSL の canonical design** を定義する。

本 DSL の目的は以下である。

1. detection 出力の共通契約を backend 非依存で固定する
2. scenario ごとのハードコードを減らす
3. downstream の triage / investigation / case / action が依存できる
   `artifact / behavior_features / evidence` 契約を明文化する
4. Python detection / Wazuh deploy target / 将来の export target に対する
   source of truth を持つ
5. Phase6 以降の correlation-first incident entry を支える

---

## 2. なぜ atomic detection DSL を先にやるのか

最初にやるべきことは、`investigation-agent` の pack 化ではなく、
**atomic detection DSL の導入**である。

理由は、pack ベースの investigation は入力として
`artifact` / `behavior_features` / `evidence` の安定した契約を必要とするためである。

順番としては以下が自然である。

```text
atomic detection DSL
  ↓
artifact / behavior_features / evidence contract
  ↓
investigation pack 化
  ↓
workflow / policy 化
```

もし DSL より先に pack 化すると、pack の入力仕様が後から変わりやすく、
結果として pack 自体が再びシナリオ依存になりやすい。

---

## 3. Source of Truth と全体像

本 lab における基本方針は以下。

```text
atomic detection DSL
  ↓
canonical detection output
  ↓
target adapter / compiler
  ├─ python detection target
  ├─ wazuh deploy target
  └─ future export target
```

### 3.1 Source of truth

- DSL = source of truth
- canonical detection output = lab 内の共通契約
- Wazuh = deploy / search target

つまり、downstream の agent は backend 固有の field ではなく、
**canonical detection output** に依存する。

### 3.2 DSL の役割

atomic detection DSL は以下を表現する。

- どの入力に対する rule か
- どういう条件に一致したら hit か
- 何という `artifact` を出力するか
- どの `behavior_features` を付与するか
- どの target にコンパイル可能か

---

## 4. Feature Lifecycle における責務

本 lab における feature の層は以下。

- `behavior_features` = detection が付与する観測事実
- `derived_features` = triage が意味付けする
- `enriched_features` = investigation が文脈補強する
- `assessment` = 最終判断

### 4.1 重要なルール

detection で付与する feature は、原則として **`behavior_features` のみ** とする。

- detection では **観測事実ベースの feature のみ付与**する
- 結論寄りの意味付けは triage / investigation に回す

### 4.2 detection / DSL で扱うものの例

- `remote_download`
- `temporary_path_execution`
- `execution_after_download`
- `direct_ip_download`
- `permission_change_before_execution`

### 4.3 triage / investigation で扱うものの例

- `download_and_execute_chain`
- `high_risk_execution_flow`
- `same_parent_process_chain`
- `payload_path_confirmed`

つまり、DSL の `behavior_features` は一般 feature 全体の定義場所ではなく、
**観測事実としての behavior_features を定義する場所**である。

---

## 5. 最初の対象範囲

最初から多く作らず、以下の 5 つ程度に限定する。

- `ssh_failed_login`
- `ssh_success_login`
- `ssh_key_login`
- `authorized_keys_modification`
- `process_exec`

必要なら次点:

- `sudo_command`
- `user_creation`

目的は、scenario_003 / 004 / 005 / 006 を支える最低限の artifact 群を
DSL ベースで表現可能にすることである。

---

## 6. 最小 schema 案

最初の schema は以下の程度でよい。

```yaml
id: auth.ssh_success_password
title: SSH successful password login
status: experimental

log_source:
  product: linux
  service: sshd

match:
  event_type: ssh_success_login
  auth_method: password

artifact: ssh_success_login
severity: medium

behavior_features:
  ssh_success: true
  password_authentication: true

metadata:
  mitre:
    - T1078
  references: []
  tags: []

targets:
  - python
  - wazuh
```

### 6.1 必須にしたいフィールド

- `id`
- `title`
- `log_source`
- `match`
- `artifact`
- `severity`
- `behavior_features`
- `targets`

### 6.2 任意でよいフィールド

- `status`
- `metadata`
- `metadata.mitre`
- `metadata.references`
- `metadata.tags`

---

## 7. Canonical Detection Output

DSL から downstream に渡す canonical detection output は、
最低限以下を持つ。

```yaml
id: det-000001
rule_id: auth.ssh_success_password
title: SSH successful password login

log_source:
  product: linux
  service: sshd

event_type: ssh_success_login
artifact: ssh_success_login
severity: medium

host: ubuntu-victim01
user: victim01
src_ip: 192.0.2.40
path: null
command_line: null
auth_method: password
result: success

behavior_features:
  ssh_success: true
  password_authentication: true

evidence_refs:
  - ssh_auth_events.json#event-10

raw_event_refs:
  - sshd.log:1234

time_window_start: 2026-04-11T04:06:55Z
time_window_end: 2026-04-11T04:06:55Z
```

### 7.1 最低限持ちたい共通フィールド

- `id`
- `rule_id`
- `title`
- `log_source`
- `event_type`
- `artifact`
- `severity`
- `host`
- `user`
- `src_ip`
- `path`
- `command_line`
- `behavior_features`
- `evidence_refs`
- `raw_event_refs`
- 時系列情報
  - `time_window_start`
  - `time_window_end`

### 7.2 補足

- `auth_method` や `result` は全 artifact に必須ではないため optional 扱いでよい
- `path` や `command_line` も artifact によって null でよい
- canonical output は backend 非依存の契約として扱う

---

## 8. 最初の 5 ルールひな形

### 8.1 ssh_failed_login

```yaml
id: auth.ssh_failed_login
title: SSH failed login
status: experimental

log_source:
  product: linux
  service: sshd

match:
  event_type: ssh_auth_failure

artifact: ssh_failed_login
severity: low

behavior_features:
  ssh_auth_failure: true
  password_authentication: true

metadata:
  mitre:
    - T1110
  references: []
  tags:
    - auth
    - ssh

targets:
  - python
  - wazuh
```

### 8.2 ssh_success_login

```yaml
id: auth.ssh_success_password
title: SSH successful password login
status: experimental

log_source:
  product: linux
  service: sshd

match:
  event_type: ssh_success_login
  auth_method: password

artifact: ssh_success_login
severity: medium

behavior_features:
  ssh_success: true
  password_authentication: true

metadata:
  mitre:
    - T1078
  references: []
  tags:
    - auth
    - ssh

targets:
  - python
  - wazuh
```

### 8.3 ssh_key_login

```yaml
id: auth.ssh_success_publickey
title: SSH successful public key login
status: experimental

log_source:
  product: linux
  service: sshd

match:
  event_type: ssh_key_login
  auth_method: publickey

artifact: ssh_key_login
severity: medium

behavior_features:
  ssh_success: true
  publickey_authentication: true

metadata:
  mitre:
    - T1078
    - T1021
  references: []
  tags:
    - auth
    - ssh
    - persistence-reuse

targets:
  - python
  - wazuh
```

### 8.4 authorized_keys_modification

```yaml
id: persistence.authorized_keys_modification
title: authorized_keys modification
status: experimental

log_source:
  product: linux
  service: wazuh_fim

match:
  path_suffix: /.ssh/authorized_keys
  event: modified

artifact: authorized_keys_modification
severity: high

behavior_features:
  file_modification: true
  ssh_authorized_keys_targeted: true
  persistence_related_path: true

metadata:
  mitre:
    - T1098
  references: []
  tags:
    - persistence
    - fim
    - ssh

targets:
  - python
  - wazuh
```

### 8.5 process_exec

```yaml
id: execution.process_exec
title: Suspicious process execution chain
status: experimental

log_source:
  product: linux
  service: auditd

match:
  detection_type: suspicious_download_chmod_execute

artifact: process_exec
severity: high

behavior_features:
  remote_download: true
  temporary_path_execution: true
  execution_after_download: true
  permission_change_before_execution: true

metadata:
  mitre:
    - T1105
    - T1059
  references: []
  tags:
    - execution
    - process
    - auditd

targets:
  - python
```

---

## 9. 実装方針

### 9.1 最初にやること

#### Step 1
DSL loader を作る

対象:
- YAML を読む
- 必須フィールドを検証する
- Python で扱いやすい dict / model にする

#### Step 2
Python evaluator を作る

対象:
- 既存の normalized event / Wazuh alert に対して `match` を評価する
- `artifact` と `behavior_features` を canonical detection output に落とす

#### Step 3
最初の 5 ルールを `detection/dsl/` に置く

#### Step 4
scenario_003 / 004 / 005 / 006 に必要な artifact が DSL ベースで出せることを確認する

#### Step 5
その後に investigation-agent の pack 化へ進む

### 9.2 evaluator / compiler の最小実装

最初は 2 つで十分。

- DSL → 現在の Python detection/evaluation で使える形式
- DSL → 将来の Wazuh 用 target に落とすための中間表現

この段階では、いきなり完全な Wazuh XML 生成器を作らなくてよい。  
まずは lab 内で DSL が source of truth として機能することを優先する。

---

## 10. Wazuh との関係

将来的に Wazuh を導入する場合でも、**Wazuh は source of truth ではなく deploy / search target** として扱う。

- DSL = source of truth
- canonical detection output = lab 内の共通契約
- Wazuh = baseline collection / decoding / basic detection / search backend

つまり、Wazuh 固有の field を downstream の agent が直接前提にするのではなく、
必要なら adapter / normalizer を介して canonical model に変換して使う。

---

## 11. 推奨ディレクトリ案

```text
detection/
  dsl/
    ssh_failed_login.yaml
    ssh_success_login.yaml
    ssh_key_login.yaml
    authorized_keys_modification.yaml
    process_exec.yaml
  compiler/
    loader.py
    evaluator.py
    targets/
      python.py
      wazuh.py
```

---

## 12. 今はまだやらなくてよいこと

- 全ルールの Sigma 化
- 完全な Sigma → Wazuh 自動変換
- investigation-agent の全面 rewrite
- queue / Redis Stream などの event-driven 化
- workflow engine の本格導入
- multi-host / external intel 対応

---

## 13. Done

この着手フェーズの Done は以下。

1. atomic detection DSL の最初の schema が決まっている
2. 最初の 5 ルールが DSL で記述されている
3. DSL を読み込む loader / evaluator の最小実装がある
4. scenario_003 / 004 / 005 / 006 に必要な artifact 群が DSL ベースで表現できる
5. downstream が backend 非依存で使える canonical detection output が明文化されている
6. その後に investigation pack 化へ進めるための
   `artifact / behavior_features / evidence` 契約が明文化されている

---

## 14. 一言まとめ

最初にやるべきことは、

**「investigation を汎用化すること」ではなく、  
「investigation が依存する artifact / behavior_features / evidence の共通契約を atomic detection DSL で先に固めること」** である。

その後に pack / policy / workflow へ進むのが最も安全で拡張しやすい。
---

## 15. Current Implementation Status

The atomic detection DSL is no longer only a design proposal. In Phase6, the DSL foundation has been implemented as the canonical detection contract for the current SSH / persistence / process execution scenarios.

Implemented status:

- `detection/dsl/` contains the initial atomic detection rules
- DSL loader / evaluator / dedupe / correlation components exist under `detection/compiler/`
- the initial artifact vocabulary is active:
  - `ssh_failed_login`
  - `ssh_success_login`
  - `ssh_key_login`
  - `authorized_keys_modification`
  - `process_exec`
- scenario_004 / 005 / 006 can be evaluated through the DSL-backed artifact model
- correlation-first incident entry is used for the persistence and key-reuse scenarios
- downstream triage / investigation / case / action stages consume canonical artifacts rather than scenario-only assumptions
- the Windows/Sysmon-specific rules
  `execution.windows_powershell_process_observed` and
  `execution.windows_powershell_encoded_command_observed` reuse the same DSL
  loader, evaluator, and canonical detection output
- Fixture A/B/C `expected_detection` parity is implemented as a separate
  schema-validated test oracle, not as runtime evidence

Current role:

```text
atomic detection DSL
  ↓
canonical detection output
  ↓
incident / triage / investigation / case / action
```

Near-term direction:

- keep the DSL as the source of truth for lab-local detection contracts
- avoid moving DSL internals back into `run_process_pipeline.py`
- use this document as the detailed DSL contract, while `docs/roadmap/phase6.md` remains the high-level index
- treat Wazuh as a deploy / alert / search target, not as the source of truth
- keep Windows rule content and match conditions source/domain-specific while
  the future Common Pipeline v0 owns common invocation and handoff

The implemented Windows operators are:

- `process_name_casefold`: case-insensitive exact process-name comparison
- `command_token_casefold_any`: case-insensitive exact-token comparison against
  an explicit non-empty token list

The Windows rules also require exact `source: sysmon`, `platform: windows`, and
`event_type: process_exec` routing. Substrings such as
`-EncodedCommandSuffix` and `prefix-enc` do not match. Unknown match operators
fail closed. Command text is preserved as untrusted data and is never decoded
or executed.

The two rules use `severity: low` because `severity` remains a required global
DSL field and `low` is the lowest existing value. This is rule metadata, not a
malicious verdict, Incident severity, confidence, assessment, or response
approval. Common Pipeline v0 invocation and Windows detection-to-Incident
execution remain the next separate PR.

Future work:

- add more atomic rules only when needed by new scenarios
- formalize export targets if Wazuh / Sigma deployment becomes necessary
- keep canonical detection output stable before introducing investigation packs or workflow policies

