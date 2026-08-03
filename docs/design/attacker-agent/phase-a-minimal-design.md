# Attacker Agent Phase A — Minimal Design

## 1. Goal

Phase A の目的は、現在の `attacker-agent` を **step 実行器** から **scenario dispatcher** に再整理し、
以下の 2 系統を同じ入口から起動できる最小構成を成立させることです。

1. 旧式の step-based scenario
2. `runner.path` を持つ shell-based scenario

この段階では autonomy や planner は扱わず、**Scenario-first** を維持したまま、
将来の TTP Composition / Autonomous Mode に耐える最小の実行境界を作る。

---

## 2. Background

現状は大きく 2 つの契約が混在している。

### 2.1 旧契約（step-based）

現在の `main.py` は、概ね以下のような scenario 契約を前提にしている。

- `name`
- `mitre_attack`
- `expected_artifacts`
- `steps[].id`
- `steps[].type`
- `steps[].command`

また、実行器としては step type ごとの分岐を内包しており、
実質的に **scenario loader + validator + executor** が 1 ファイルに同居している。

### 2.2 新契約（shell runner-based）

一方、現在ラボで主に使っている `scenario_004 / 005 / 006` は、
`runner.type: shell` と `runner.path` を持つ shell runner ベースの運用である。

この系統では、攻撃ロジックの本体は shell script 側にあり、
scenario は実行対象を指すメタデータに近い。

### 2.3 現時点の問題

Phase A で解くべき問題は次のとおり。

- scenario schema が二重化している
- backend の選択が暗黙的である
- 実行 safety が明示されていない
- execution log が薄い
- shell runner が正式 backend ではなく事実上の暫定実装になっている

---

## 3. Phase A Principles

Phase A では次の原則を採用する。

### 3.1 Scenario-first, not autonomy-first

この段階では完全自律化を狙わない。
まずは reproducible な scenario execution を統一する。

### 3.2 Dispatcher first

`main.py` は実行ロジックの本体ではなく、
**load → validate → select backend → execute → write artifacts** の制御点とする。

### 3.3 One entrypoint, multiple backends

Scenario の種類に応じて backend を切り替えるが、CLI 入口は 1 つにする。

### 3.4 Compare-ready artifacts before autonomy

autonomous mode より先に、
後続の compare / evaluation に耐える attack artifacts を整える。

### 3.5 Safety from the beginning

safety は後回しにしない。
Phase A 時点で最低限の guardrail を導入する。

### 3.6 Traceability first

run traceability は後続 pipeline 接続の前提である。
Phase A から `run_id` を軽く意識し、artifact 間の参照を崩さない。

---

## 4. Phase A Scope

## In scope

- scenario dispatcher 化
- scenario loader / validator 分離
- `step_backend` 導入
- `shell_backend` 導入
- backend selector 導入
- 最小 safety policy 導入
- 最小 execution log 導入
- 最小 `attack_result.json` 出力維持
- optional `--run-id` 導入
- old-style scenario の `scenario_id` 補完規則導入

## Out of scope

- planner
- TTP composition
- autonomous recon
- Atomic Red Team backend
- Caldera backend
- compare harness の実装
- rich attack artifacts 全体の完成
- `attack_plan.json` / `attack_request.json` の full 導入

---

## 5. Target Module Layout

```text
agents/attacker-agent/src/
├─ main.py
├─ loader.py
├─ validator.py
├─ selector.py
├─ models.py
├─ safety.py
├─ artifact_writer.py
└─ backends/
   ├─ __init__.py
   ├─ step_backend.py
   └─ shell_backend.py
```

### Responsibilities

#### `main.py`
- CLI parsing
- scenario load
- validation
- backend selection
- execution orchestration
- artifact writing

#### `loader.py`
- YAML 読み込み
- 旧契約 / 新契約の吸収
- internal normalized structure への変換
- `scenario_id` 補完
- `scenario_id_source` の付与

#### `validator.py`
- 必須項目チェック
- backend ごとの必須項目チェック
- runner.path / steps の整合性チェック

#### `selector.py`
- normalized scenario から backend を決定
- `step` / `shell` を deterministic に返す

#### `models.py`
- internal dataclass / typed dict
- scenario / step / runner / execution result の表現

#### `safety.py`
- path allowlist / command allowlist / denylist
- timeout
- retry_limit
- state-changing action フラグ判定

#### `artifact_writer.py`
- `attack_result.json`
- `attack_execution_log.json`
- 必要なら将来の artifact 参照 field の雛形出力

#### `backends/step_backend.py`
- step-based scenario 実行
- `subprocess.run()` ベースの local execution
- step 単位の execution result 生成

#### `backends/shell_backend.py`
- shell runner 実行
- runner script の path 解決
- shell backend 用 execution result 生成

---

## 6. Internal Normalized Scenario Contract

Phase A では外部 YAML をそのまま実行器に渡さず、
一度 internal normalized scenario に変換してから backend selection を行う。

### 6.1 Minimum internal shape

```json
{
  "scenario_id": "scenario-004",
  "scenario_id_source": "declared",
  "scenario_name": "SSH brute force to authorized_keys persistence",
  "description": "...",
  "backend_hint": "shell",
  "primary_artifact": "authorized_keys_modification",
  "artifacts_expected": [
    "ssh_failed_login",
    "ssh_success_login",
    "authorized_keys_modification"
  ],
  "steps": [],
  "runner": {
    "type": "shell",
    "path": "scenarios/scenario_004.sh",
    "state_changing": true
  },
  "safety": {
    "timeout_seconds": 300,
    "retry_limit": 0
  }
}
```

### 6.2 Mapping rules

#### 旧契約からの取り込み

- `name` → `scenario_name`
- `expected_artifacts` → `artifacts_expected`
- `mitre_attack` は Phase A では optional metadata として保持のみ
- `steps` が存在し、`runner` が無ければ `backend_hint = step`

#### 新契約からの取り込み

- `scenario_name` をそのまま使用
- `artifacts_expected` をそのまま使用
- `runner.type: shell` と `runner.path` があれば `backend_hint = shell`
- `techniques` は Phase A では optional metadata として保持のみ

### 6.3 `scenario_id` completion rule

`scenario_id` は normalized scenario では必須とする。
ただし old-style scenario では未定義の可能性があるため、loader 側で deterministic に補完する。

優先順位は次のとおり。

1. YAML 内に `scenario_id` があればそれを採用
2. 無ければ scenario file 名から補完
3. 補完できなければ validation error

#### File-name based completion example

- `scenario_001_ssh_bruteforce_priv_esc.yaml` → `scenario-001`
- `scenario_004_ssh_bruteforce_authorized_keys_persistence.yaml` → `scenario-004`

loader は補完時に `scenario_id_source = "derived_from_path"` を付与する。
必要に応じて warning を出す。

### 6.4 Validation policy

- `scenario_id` は normalized scenario では必須
- `scenario_name` は必須
- `description` は推奨
- `backend_hint == step` の場合 `steps` 必須
- `backend_hint == shell` の場合 `runner.path` 必須
- `runner.path` はファイル存在確認を行う
- `steps` と `runner` の両方がある場合、明示的な優先順位を持つ

### 6.5 Backend priority rule

Phase A では次の優先順位で backend を決定する。

1. `runner.type` があればそれを優先
2. `steps` があれば `step_backend`
3. どちらもなければ validation error

---

## 7. CLI Design

## 7.1 Command examples

### Dry run

```bash
uv run python agents/attacker-agent/src/main.py \
  --scenario scenarios/scenario_004_ssh_bruteforce_authorized_keys_persistence.yaml \
  --dry-run
```

### Execute

```bash
uv run python agents/attacker-agent/src/main.py \
  --scenario scenarios/scenario_004_ssh_bruteforce_authorized_keys_persistence.yaml \
  --execute
```

### Execute specific step (step backend only)

```bash
uv run python agents/attacker-agent/src/main.py \
  --scenario scenarios/scenario_001_ssh_bruteforce_priv_esc.yaml \
  --execute --step step1
```

### Execute with explicit run ID

```bash
uv run python agents/attacker-agent/src/main.py \
  --scenario scenarios/scenario_004_ssh_bruteforce_authorized_keys_persistence.yaml \
  --execute \
  --run-id run-0042
```

## 7.2 CLI flags

### Required/primary

- `--scenario <path>`
- `--dry-run`
- `--execute`

### Optional

- `--step <step_id>`
- `--run-id <run_id>`
- `--timeout <seconds>`
- `--retry-limit <n>`
- `--allow-command <prefix>`
- `--deny-command <prefix>`
- `--allow-runner-path <prefix>`
- `--output-dir <path>`

### Behavior notes

- `--step` は `step_backend` のみに適用
- `shell_backend` では `--step` 指定時は validation error
- `--dry-run` は command を実行せず backend 判定と summary のみ行う
- `--run-id` 未指定時は内部で自動生成し、artifact に保存する
- `--run-id` は将来 `data/runs/<run_id>/...` へ接続しやすくするための軽量接続点とする

---

## 8. Safety Design

Phase A では minimal safety として次を導入する。

## 8.1 Path allowlist first for shell backend

shell backend では command prefix allowlist よりも、**runner path allowlist を優先**する。

判定順序は次のとおり。

1. `runner.path` を正規化する
2. path allowlist に一致するか確認する
3. `..` や symlink による逸脱がないか確認する
4. deny 条件があれば拒否する
5. timeout / retry / state-changing を適用する
6. 実行する

### Initial path allowlist examples

- `scenarios/`
- `scripts/attackers/`
- `agents/attacker-agent/runners/`

> Note:
> Phase A では shell runner の中身を完全解析しない。
> したがって shell backend の trusted boundary はまず `runner.path` に置く。

## 8.2 Command allowlist / denylist

- step backend では command prefix ベースの簡易判定を行う
- shell backend でも補助的に適用できるが、主境界は path allowlist とする
- denylist が一致した場合は実行拒否

### Initial denylist examples

- `rm -rf /`
- `mkfs`
- `shutdown`
- `reboot`

### Initial allowlist examples

- `bash`
- `sh`
- `python`
- `ssh`
- `sshpass`
- `hydra`
- `curl`
- `chmod`

## 8.3 Timeout

- 各 backend 実行に timeout を設定
- default は 300 秒
- scenario 側または CLI で override 可

## 8.4 Retry limit

- default は 0
- shell backend / step backend とも同一 policy を適用
- retry した場合は execution log に残す

## 8.5 State-changing action

Phase A では厳密な action classification までは行わないが、
scenario または runner に `state_changing: true/false` を持たせる。

例:

- `authorized_keys` 追記 → `true`
- `echo whoami` のみ → `false`
- payload download + execute → `true`

この field は後続 phase の approval / assessment mode の土台とする。

---

## 9. Artifact Design

Phase A では compare-ready artifact の完成形までは作らないが、
最低限 `attack_result` と `attack_execution_log` を分けて出力できる形を先に作る。

## 9.1 `attack_result.json`

### Purpose

run 全体の要約結果。

### Minimum fields

```json
{
  "attack_id": "attack-000001",
  "run_id": "run-0042",
  "scenario_id": "scenario-004",
  "scenario_name": "SSH brute force to authorized_keys persistence",
  "mode": "scenario",
  "backend": "shell",
  "status": "completed",
  "started_at": "2026-05-02T10:00:00Z",
  "ended_at": "2026-05-02T10:03:00Z",
  "primary_artifact": "authorized_keys_modification",
  "artifacts_expected": [
    "ssh_failed_login",
    "ssh_success_login",
    "authorized_keys_modification"
  ],
  "state_changing": true,
  "failure_reason": null,
  "execution_log_ref": "attack_execution_log.json"
}
```

### `failure_reason` policy

`failure_reason` は optional field とする。
成功時は `null`、失敗時は structured に格納する。

推奨 shape:

```json
{
  "code": "path_not_allowed",
  "detail": "runner.path is outside allowed directories"
}
```

初期 code 候補:

- `validation_error`
- `backend_selection_error`
- `runner_not_found`
- `path_not_allowed`
- `timeout`
- `retry_exhausted`
- `nonzero_exit`
- `unsupported_step_type`

## 9.2 `attack_execution_log.json`

### Purpose

step 単位または backend 実行単位の詳細記録。

### Minimum fields

```json
{
  "attack_id": "attack-000001",
  "run_id": "run-0042",
  "backend": "shell",
  "entries": [
    {
      "entry_id": "exec-0001",
      "step_id": null,
      "status": "success",
      "command": "scenarios/scenario_004_ssh_bruteforce_authorized_keys_persistence.sh",
      "execution_backend": "shell",
      "started_at": "2026-05-02T10:00:00Z",
      "ended_at": "2026-05-02T10:03:00Z",
      "exit_code": 0,
      "retry_count": 0,
      "failure_reason": null,
      "stdout_ref": null,
      "stderr_ref": null
    }
  ]
}
```

## 9.3 Observed effects in Phase A

`attack_observed_effects.json` は Phase C で first-class artifact 化するが、
Phase A では full 導入しない。

ただし将来接続しやすくするため、`attack_result.json` に以下の placeholder を許可する。

```json
{
  "observed_effects_ref": null
}
```

---

## 10. Backend Design

## 10.1 Step backend

### Input
- normalized scenario
- optional `step_id`
- safety policy

### Execution unit
- step 単位

### Output
- step ごとの execution entry
- run summary

### Notes
- 既存の `is_supported_executable_step()` と `validate_local_step_environment()` の責務を吸収
- step type ごとの分岐は backend 側に閉じ込める

## 10.2 Shell backend

### Input
- normalized scenario
- runner.path
- safety policy

### Execution unit
- runner script 単位

### Output
- backend 実行 entry 1 件以上
- run summary

### Notes
- `subprocess.run([runner_path], ...)` または `bash runner_path`
- shell backend は scenario の個別ロジックを script 側に委譲する
- stdout / stderr capture は option として導入可能
- shell backend は path allowlist を通過した runner のみを実行対象とする

---

## 11. Execution Flow

```text
CLI
  ↓
load raw scenario YAML
  ↓
normalize scenario
  ↓
complete scenario_id if missing
  ↓
validate normalized scenario
  ↓
build safety policy
  ↓
select backend
  ↓
resolve run_id
  ↓
execute backend
  ↓
write attack_execution_log.json
  ↓
write attack_result.json
  ↓
print summary
```

### Dry-run flow

```text
CLI
  ↓
load raw scenario YAML
  ↓
normalize scenario
  ↓
complete scenario_id if missing
  ↓
validate normalized scenario
  ↓
select backend
  ↓
resolve run_id
  ↓
print summary only
```

---

## 12. PR Split Recommendation

### PR1 — Dispatcher skeleton
- `loader.py`
- `validator.py`
- `selector.py`
- `models.py`
- `main.py` の orchestration 化
- old-style scenario の `scenario_id` 補完
- optional `--run-id`

### PR2 — Backend and safety
- `step_backend.py`
- `shell_backend.py`
- `safety.py`
- shell backend の path allowlist 優先
- timeout / retry / state_changing 導入

### PR3 — Minimal artifacts
- `artifact_writer.py`
- `attack_result.json`
- `attack_execution_log.json`
- `failure_reason` optional field 導入
- `observed_effects_ref` placeholder 導入

---

## 13. Done Criteria

Phase A 完了条件は次のとおり。

- old-style scenario と shell-based scenario を同じ CLI 入口から起動できる
- backend selection が deterministic である
- old-style scenario に `scenario_id` が無い場合でも loader が deterministic に補完できる
- `--run-id` を optional に受け付け、artifact に保存できる
- shell backend が path allowlist 優先で safety 判定を行う
- timeout / retry_limit / state_changing を最小 safety として適用できる
- `attack_result.json` と `attack_execution_log.json` を別 artifact として出力できる
- 失敗時に optional `failure_reason` を格納できる
- dry-run で backend 判定と validation 結果を確認できる

