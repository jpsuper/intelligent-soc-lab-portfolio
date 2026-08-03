# Phase0 — SOC Pipeline Baseline

## Goal
Attack → Log → Forward → Parse → Detect → Incident の最小パイプライン構築

## What was implemented

### Attack
- Kali から SSH brute force 実施（hydra）

### Log Collection
- victim (Ubuntu) の auth.log を取得

### Log Forwarding
- rsyslog により soc-analyzer へ転送

### Parsing
- parser-agent により sshd ログを正規化
- normalized_events.json を生成

### Detection
- ssh_failed_login ルール実装
- detection_hits.json を生成

### Incident
- detection を元に incident-builder-agent で
- INC-0001.json を生成

## Data Flow

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

## Output

- data/normalized/normalized_events.json
- data/detections/detection_hits.json
- data/incidents/INC-0001.json

## Result

- 最小SOCパイプライン構築完了
- 攻撃からインシデント生成まで自動化成功

## Next

- Phase1: Correlation Agent