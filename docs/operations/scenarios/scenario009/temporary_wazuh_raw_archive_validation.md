# Scenario 009 Temporary Wazuh Raw Archive Validation

Status: Executed Once / Outcome C Recorded

## Purpose

This runbook defines a short-lived, reversible observation using temporary
Wazuh JSON raw archive storage for
`scenario_009_suspicious_archive_staging`. It is intended to answer:

- Did the Wazuh manager receive the scenario audit records?
- Does `archives.json` retain original audit identity and message content?
- Can all five expected observations be reconstructed?
- Is the artifact suitable for a later sanitized fixture and adapter test?

Core boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

Archive presence does not itself prove semantic parity, normalization,
detection, or incident consumption.

## Status And Execution Boundary

This procedure was executed once on `2026-07-12`. The result is recorded in
[Scenario 009 Wazuh Raw Archive Validation Result](../../../design/scenarios/scenario009/wazuh_raw_archive_validation.md)
as Outcome C: all five operations were present, but complete multi-record
grouping was not preserved.

The runbook remains reusable only with an explicit operator decision in the
approved lab. Temporary `logall_json` enablement is limited to one observation
window, rollback is mandatory on success or failure, and the procedure stops
when any safety gate fails. There is no continue-despite-error path.

## Confirmed Topology And Roles

| Role | Host | IP |
|---|---|---|
| Runner | `kali-attacker` | `192.0.2.40` |
| Target | `ubuntu-victim01` | `192.0.2.30` |
| Wazuh manager/indexer/dashboard | `wazuh-server` | `192.0.2.23` |

Documentation and Git work may use the local WSL workspace. The controlled
runner executes from `kali-attacker` and is streamed to `ubuntu-victim01` over
SSH stdin.

## Preconditions

Record every result before making a change.

On `wazuh-server` confirm:

- hostname is `wazuh-server`
- manager, indexer, and dashboard packages are the expected 4.14.4 deployment
- the deployed manager service unit name is identified and active
- `/var/ossec/etc/ossec.conf` is the active configuration path
- `logall` and `logall_json` are each present exactly once and both are `no`
- `alerts.json` state and `archives.json` existence or absence
- filesystem utilization, free bytes, and current `/var/ossec` size
- no unrelated maintenance or concurrent configuration edit is in progress

On `ubuntu-victim01` confirm:

- hostname is `ubuntu-victim01`
- auditd and Wazuh agent services are active
- audit status reports enabled `1`, lost `0`, and backlog `0`
- no active rule uses key `scenario009_audit_smoke`
- `/tmp/ai_soc_lab_scenario_009_audit_smoke` is absent

On `kali-attacker` confirm:

- the repository checkout is present
- `attacks/runners/scenario_009_suspicious_archive_staging.sh` exists
- `bash -n attacks/runners/scenario_009_suspicious_archive_staging.sh` succeeds
- SSH access to `victim01@192.0.2.30` succeeds

## Command-Verification Boundary

Do not assume a manager service unit or reload command. On `wazuh-server`,
inspect systemd units and record the unit that owns the deployed manager process:

```bash
systemctl list-unit-files --type=service | grep -i wazuh
systemctl list-units --type=service --all | grep -i wazuh
```

Set `MANAGER_UNIT` only after confirming the result:

```bash
MANAGER_UNIT='<confirmed-manager-service-unit>'
systemctl status "$MANAGER_UNIT" --no-pager
```

All later restart and journal commands refer to that recorded unit. Stop if it
cannot be confirmed. This runbook does not claim that `wazuh-control` provides a
configuration syntax test; no such repository-proven check is assumed.

## Disk And Duration Safety Gate

Repository operational defaults for this lab observation are:

- filesystem containing `/var/ossec` below 80% utilization
- at least 5 GiB free before enablement
- maximum `logall_json` enablement window of 10 minutes
- immediate abort and rollback if utilization reaches 80%, free space drops
  below 5 GiB, or archive growth is unexpected

Record pre-run and post-run filesystem usage plus archive size. Stricter limits
may be used. These are lab safety defaults, not Wazuh product requirements.

Representative read-only checks:

```bash
df -h /var/ossec
df -B1 /var/ossec
sudo du -sh /var/ossec
```

## Configuration Backup

On `wazuh-server`, choose a UTC run identifier and a protected backup adjacent
to the active configuration, outside any Git checkout:

```bash
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
CONF=/var/ossec/etc/ossec.conf
BACKUP="/var/ossec/etc/ossec.conf.scenario009-${RUN_ID}.bak"
sudo cp -a "$CONF" "$BACKUP"
sudo sha256sum "$CONF" "$BACKUP"
sudo stat -c '%U:%G %a %n' "$CONF" "$BACKUP"
```

Record `BACKUP`, the original SHA-256, ownership, and mode. Stop if copy,
checksum, or metadata capture fails. Do not copy the backup or unrelated
configuration into the repository.

Before enablement, record whether the archive already exists and capture a
baseline that the activation check can compare against:

```bash
ARCHIVE=/var/ossec/logs/archives/archives.json
if sudo test -e "$ARCHIVE"; then
  ARCHIVE_EXISTED=1
  ARCHIVE_BASE_SIZE="$(sudo stat -c %s "$ARCHIVE")"
  ARCHIVE_BASE_MTIME="$(sudo stat -c %Y "$ARCHIVE")"
  ARCHIVE_BASE_LINES="$(sudo awk 'END {print NR}' "$ARCHIVE")"
else
  ARCHIVE_EXISTED=0
  ARCHIVE_BASE_SIZE=0
  ARCHIVE_BASE_MTIME=0
  ARCHIVE_BASE_LINES=0
fi
printf 'existed=%s size=%s mtime=%s lines=%s\n' \
  "$ARCHIVE_EXISTED" "$ARCHIVE_BASE_SIZE" \
  "$ARCHIVE_BASE_MTIME" "$ARCHIVE_BASE_LINES"
```

## Controlled Configuration Edit

The only intended setting change is:

```xml
<logall_json>no</logall_json>
```

to:

```xml
<logall_json>yes</logall_json>
```

Keep `<logall>no</logall>` unchanged.

Before editing, require exactly one expected value and exactly one occurrence of
each setting tag:

```bash
LOGALL_NO_COUNT="$(sudo grep -Fc '<logall>no</logall>' "$CONF" || true)"
LOGALL_TAG_COUNT="$(sudo grep -Ec '<logall>[^<]*</logall>' "$CONF" || true)"
LOGALL_JSON_NO_COUNT="$(sudo grep -Fc '<logall_json>no</logall_json>' "$CONF" || true)"
LOGALL_JSON_TAG_COUNT="$(sudo grep -Ec '<logall_json>[^<]*</logall_json>' "$CONF" || true)"

if [ "$LOGALL_NO_COUNT" -ne 1 ] || [ "$LOGALL_TAG_COUNT" -ne 1 ]; then
  echo 'ABORT: expected exactly one <logall>no</logall> setting' >&2
  exit 1
fi

if [ "$LOGALL_JSON_NO_COUNT" -ne 1 ] || [ "$LOGALL_JSON_TAG_COUNT" -ne 1 ]; then
  echo 'ABORT: expected exactly one <logall_json>no</logall_json> setting' >&2
  exit 1
fi

sudo grep -n -E '<logall>|<logall_json>' "$CONF"
```

Use `sudoedit "$CONF"` to change only the one `logall_json` value; do not use a
broad replacement. Then display the two settings and compare against the backup:

```bash
sudo grep -n -E '<logall>|<logall_json>' "$CONF"
sudo diff -u "$BACKUP" "$CONF"
```

Proceed only when the diff is exactly the intended one-line value change. Keep
the backup for exact rollback.

## Manager Restart And Health Gate

After the future edit, restart only the unit confirmed during preflight:

```bash
sudo systemctl restart "$MANAGER_UNIT"
sudo systemctl is-active "$MANAGER_UNIT"
sudo systemctl status "$MANAGER_UNIT" --no-pager
sudo journalctl -u "$MANAGER_UNIT" --since '-5 minutes' --no-pager
```

Confirm the manager is active, expected Wazuh version and server type remain in
place, recent logs show no startup error, and normal alert processing continues.
If health cannot be established, immediately enter rollback.

## Raw Archive Activation Check

After manager health is confirmed, wait for archive creation or a measurable
update relative to the pre-enable baseline. Do not call `stat` or `wc` until the
file exists:

```bash
OBSERVATION_START_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ARCHIVE_ACTIVATED=0

for attempt in $(seq 1 12); do
  if sudo test -e "$ARCHIVE"; then
    CURRENT_SIZE="$(sudo stat -c %s "$ARCHIVE")"
    CURRENT_MTIME="$(sudo stat -c %Y "$ARCHIVE")"

    if [ "$ARCHIVE_EXISTED" -eq 0 ] \
      || [ "$CURRENT_SIZE" -gt "$ARCHIVE_BASE_SIZE" ] \
      || [ "$CURRENT_MTIME" -gt "$ARCHIVE_BASE_MTIME" ]; then
      ARCHIVE_ACTIVATED=1
      break
    fi
  fi
  sleep 5
done

if [ "$ARCHIVE_ACTIVATED" -ne 1 ]; then
  echo 'ABORT: archives.json was not created or updated within 60 seconds' >&2
  echo 'Rollback is mandatory; scenario execution is prohibited.' >&2
else
  sudo stat -c '%U:%G %a %s %y %n' "$ARCHIVE"
  ARCHIVE_CURRENT_LINES="$(sudo awk 'END {print NR}' "$ARCHIVE")"
  printf 'observation_start=%s start_line=%s current_lines=%s\n' \
    "$OBSERVATION_START_UTC" "$ARCHIVE_BASE_LINES" "$ARCHIVE_CURRENT_LINES"
fi
```

The loop is bounded to 12 five-second attempts. Record the observation-start UTC
timestamp, ownership, mode, size, modification time, line count, and starting
line or byte offset. Store temporary counters under a run-specific `/tmp`
directory on `wazuh-server`, not in the repository.

If `ARCHIVE_ACTIVATED` is not `1`, do not execute any subsequent setup or
scenario command. Proceed directly to the rollback procedure and record the
negative result. File existence alone is not scenario evidence.

## Victim Temporary Audit Setup

Reuse the bounded watch semantics previously recorded for scenario_009. Do not
use `auditctl -D`.

On `ubuntu-victim01`, set the exact path and key, explicitly verify the key is
absent, create the controlled base directory, add the exact watch, and confirm
it appears:

```bash
BASE_DIR=/tmp/ai_soc_lab_scenario_009_audit_smoke
AUDIT_KEY=scenario009_audit_smoke

if sudo auditctl -l | grep -F -- "$AUDIT_KEY" >/dev/null; then
  echo "ABORT: audit rule key already exists: $AUDIT_KEY" >&2
  exit 1
else
  echo "Preflight passed: audit rule key is absent: $AUDIT_KEY"
fi

mkdir -p "$BASE_DIR"
sudo auditctl -w "$BASE_DIR" \
  -p wa \
  -k "$AUDIT_KEY"

if sudo auditctl -l | grep -F -- "$AUDIT_KEY" >/dev/null; then
  echo "Audit watch confirmed: $AUDIT_KEY"
else
  echo "ABORT: audit watch was not installed: $AUDIT_KEY" >&2
  exit 1
fi
```

Record UTC time and the starting position of `/var/log/audit/audit.log`. Abort
and rollback if setup or confirmation fails. Never use `auditctl -D`.

## Controlled Runner Execution

From the confirmed repository checkout on `kali-attacker`, record UTC start and
end timestamps and the runner exit code:

```bash
ssh victim01@192.0.2.30 \
  'SCENARIO_009_BASE_DIR=/tmp/ai_soc_lab_scenario_009_audit_smoke bash -s' \
  < attacks/runners/scenario_009_suspicious_archive_staging.sh
```

Confirm expected structured runner events, while preserving their meaning as
attacker-side observed effects only. The runner uses synthetic files in its
controlled directory and introduces no real-data collection, network callback,
or exfiltration behavior.

## Collection Wait And Archive-Window Inspection

Allow a short bounded processing interval while remaining inside the 10-minute
enablement window. Inspect only records appended after the recorded archive
start position. A temporary bounded extraction may be created under `/tmp` on
`wazuh-server`; do not dump or copy the full archive.

Record total new lines and matching lines. Search the bounded window for:

```text
scenario009_audit_smoke
ai_soc_lab_scenario_009_audit_smoke
staged_synthetic_files.tar.gz
note.txt
metadata.json
/usr/bin/tar
/usr/bin/chmod
mkdir
openat
creat
fchmodat
```

Use `grep` and, where each bounded line is valid JSON, `jq` against the extracted
window. Preserve counts and field inventories rather than complete event dumps.

## Required Retained-Field Inventory

For each matching document, classify fields as `Confirmed`,
`Partially retained`, `Transformed`, `Not observed`, or `Not inspected`.

| Area | Fields to assess |
|---|---|
| Wazuh envelope | timestamp, `agent.id`, `agent.name`, manager name if present, location, decoder/rule metadata if present |
| Original audit identity | raw message or `full_log`, audit epoch, audit serial, record type, audit key |
| Audit payload | syscall, success/result, executable, command arguments, AUID/user, CWD, `PATH` records, item index, nametype, `PROCTITLE`, `EOE` or another grouping boundary |

Do not classify a field as unsupported based on one sample absence.

## Five-Observation Matrix

Record new-run serials separately from historical comparison values:

| Expected observation | Historical local serial | New-run local serial | `archives.json` evidence | Required fields retained | Result |
|---|---:|---:|---|---|---|
| staging directory creation | `11496` | Pending | Pending | Pending | Pending |
| `note.txt` creation | `11497` | Pending | Pending | Pending | Pending |
| `metadata.json` creation | `11498` | Pending | Pending | Pending | Pending |
| archive creation | `11500` | Pending | Pending | Pending | Pending |
| permission change | `11504` | Pending | Pending | Pending | Pending |

Historical serials are comparison values only. Never reuse them as current-run
evidence. Five-event Wazuh parity requires all five new-run observations to be
reconstructed from manager-side evidence with reliable grouping identity.

## Multi-Record Grouping Assessment

Assess whether `archives.json` retains host or agent identity, audit epoch,
serial, record type, multiple records sharing one serial, multiple `PATH`
entries, `EXECVE` arguments, `CWD`, `PROCTITLE`, and `EOE` or another reliable
boundary.

Record whether the current auditd parser can consume retained raw messages
directly, a narrow Wazuh-envelope adapter would be needed, grouping information
is lost, exact duplicates exist, and administrative records are present. Do not
design or implement an adapter in this PR or operational run.

## Duplicate And Rsyslog Comparison Boundary

Parallel rsyslog and Wazuh paths may represent the same source events. Compare
Wazuh archive counts with the known centralized rsyslog baseline, but inspect
exact duplicates within the Wazuh source separately.

Do not combine rsyslog and Wazuh records into one detection input. Cross-path
comparison is parity evidence, not additive evidence. One source event must not
inflate canonical event or detection counts.

## Abort Conditions

Enter rollback immediately when any condition occurs:

- hostname or version mismatch
- manager service unit cannot be confirmed
- current `logall_json` value is unexpected
- configuration differs from the backup beyond the intended line
- backup, checksum, or metadata capture fails
- filesystem utilization is at least 80% or free space is below 5 GiB
- manager restart or health verification fails
- `archives.json` is not created or updated within the bounded wait
- auditd reports lost events
- temporary audit rule cannot be added or removed
- runner exits non-zero
- configuration state cannot be proven
- an unexpected concurrent edit is detected

## Rollback Procedure

Rollback is mandatory whether validation succeeds or fails. Prefer exact backup
restoration over another text replacement.

Before restoring, confirm no unexpected concurrent edit occurred, record the
enabled-state checksum, and compare the current file to the backup. Stop and
escalate if changes exceed the planned one-line edit. Then restore and verify:

```bash
sudo cp -a "$BACKUP" "$CONF"
sudo systemctl restart "$MANAGER_UNIT"
sudo systemctl is-active "$MANAGER_UNIT"
sudo grep -n -E '<logall>|<logall_json>' "$CONF"
sudo sha256sum "$CONF" "$BACKUP"
sudo journalctl -u "$MANAGER_UNIT" --since '-5 minutes' --no-pager
```

Require `logall: no`, `logall_json: no`, an active healthy manager, continuing
alert processing, no recent restart errors, and a restored checksum matching the
original.

On `ubuntu-victim01`, remove only the scenario watch using a fail-closed
sequence. Recreate the watched directory if scenario cleanup or a failed runner
removed it before rule deletion. Use the same path, permissions, and key used at
creation:

```bash
BASE_DIR=/tmp/ai_soc_lab_scenario_009_audit_smoke
AUDIT_KEY=scenario009_audit_smoke

if sudo auditctl -l | grep -F -- "$AUDIT_KEY" >/dev/null; then
  echo "Audit watch remains and must be removed: $AUDIT_KEY"
  mkdir -p "$BASE_DIR"
  sudo auditctl -W "$BASE_DIR" \
    -p wa \
    -k "$AUDIT_KEY"
else
  echo "Audit watch already absent: $AUDIT_KEY"
fi

if sudo auditctl -l | grep -F -- "$AUDIT_KEY" >/dev/null; then
  echo "ABORT: audit watch remains; do not delete scenario artifacts" >&2
  exit 1
else
  echo "Audit watch removal confirmed: $AUDIT_KEY"
fi

rm -rf -- "$BASE_DIR"
rm -f /tmp/scenario009_audit_before_line

if [ -e "$BASE_DIR" ]; then
  echo "ABORT: scenario artifacts remain: $BASE_DIR" >&2
  exit 1
else
  echo "Scenario artifacts removed: $BASE_DIR"
fi

if [ -e /tmp/scenario009_audit_before_line ]; then
  echo "ABORT: temporary audit start-position file remains" >&2
  exit 1
else
  echo "Temporary audit start-position file removed"
fi

sudo auditctl -s
```

Do not delete scenario artifacts until absence of the specific audit rule is
confirmed. Confirm that the controlled base directory and temporary
start-position file are absent. Audit status must report enabled `1`, lost `0`, and
backlog `0`. Never use `auditctl -D`.

On `wazuh-server`, remove only run-specific `/tmp` counters and extracted-window
files. Do not delete or truncate active `archives.json` while the manager runs,
and do not delete unrelated alert or archive records. Leave normal log rotation
to the existing Wazuh policy.

## Backup Cleanup Boundary

Do not automatically delete the configuration backup after rollback. First
require matching checksums, healthy manager state, and operator review. The
operator may then deliberately remove the temporary backup. It must never be
committed to Git.

## Sanitization And Fixture Boundary

The run may create a temporary minimal extraction under `/tmp`. Do not commit
complete `archives.json`, `alerts.json`, `audit.log`, unrelated Wazuh events,
administrative noise not needed for the scenario, credentials, keys, tokens, or
certificates.

A later fixture PR may include only minimal scenario event groups, provenance,
explicit sanitization notes, and stable expected fields. This docs PR creates no
fixture.

## Success Classifications

### A. No Matching Archive Evidence

Wazuh receipt remains unconfirmed or negative for the observed path. Do not
create a fixture.

### B. Partial Archive Evidence

Treat the archive as supporting evidence, identify missing records or fields,
and do not claim parity.

### C. Five Observations Present, Grouping Incomplete

Source suitability remains pending. Record the grouping loss.

### D. Five Observations And Grouping Identity Preserved

Treat `archives.json` as a candidate primary source and proceed to a separate
sanitized-fixture PR. Do not declare normalization or detection complete.

## Evidence Record Template

This table remains a reusable operator template. The completed first-run values
are recorded in
[Scenario 009 Wazuh Raw Archive Validation Result](../../../design/scenarios/scenario009/wazuh_raw_archive_validation.md).

| Field | Result |
|---|---|
| Observation date and UTC window | Pending |
| Host and Wazuh versions | Pending |
| Original configuration checksum | Pending |
| Backup path | Pending |
| Free space before and after | Pending |
| Archive start/end size and line count | Pending |
| Scenario runner result | Pending |
| New audit serials | Pending |
| Matching archive count | Pending |
| Retained-field inventory | Pending |
| Five-observation result | Pending |
| Duplicate assessment | Pending |
| Cleanup result | Pending |
| Restored configuration checksum | Pending |
| Manager health after rollback | Pending |
| Final source-artifact conclusion | Pending |

## Explicit Non-Goals

This plan does not execute a configuration change, enable `logall` or
`logall_json`, restart services, add persistent audit rules, commit raw logs,
create fixtures or adapters, modify parsers, add source code or tests, or
validate five-event parity, normalization, DSL detection, incident consumption,
continuous ingestion, Velociraptor, or containment.

It makes no claim of exfiltration, ransomware, credential access, compromise,
or real-data collection.

## Relationship To Existing Documents

- [Wazuh / SIEM Validation Plan](../../../design/scenarios/scenario009/wazuh_siem_validation_plan.md)
- [Wazuh Collection Environment](../../../design/scenarios/scenario009/wazuh_collection_environment.md)
- [Wazuh Alerts Inspection](../../../design/scenarios/scenario009/wazuh_alerts_inspection.md)
- [Wazuh Raw Archive Validation Result](../../../design/scenarios/scenario009/wazuh_raw_archive_validation.md)
- [Live Auditd Telemetry Smoke](../../../design/scenarios/scenario009/live_auditd_telemetry_smoke_validation.md)
- [Centralized Rsyslog Auditd Collection](../../../design/scenarios/scenario009/centralized_rsyslog_auditd_collection_validation.md)

The environment, `alerts.json` inspection, and first bounded raw-archive
observation are complete. `alerts.json` is non-canonical, while `archives.json`
is supporting evidence only because complete serial-linked grouping was not
preserved. The existing sanitized auditd fixture remains the canonical
comparison baseline.
