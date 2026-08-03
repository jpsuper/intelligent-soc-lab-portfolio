# Attacker Artifact Catalog

## Purpose

This catalog documents the current canonical mapping between attacker scenario families, structured runner events, observed-effects artifacts, ATT&CK techniques, and expected defender-side artifact categories.

Key boundaries:

- Attacker-side structured runner events are execution evidence, not defender telemetry.
- Artifact names describe expected defender-side evidence categories.
- `attack_observed_effects.json` records what the attacker side observed or inferred.
- Observed-effects alignment compares attacker-observed effects with defender-observed artifacts.
- Rule Improvement signals from observed-effects alignment are review-only and do not auto-generate rule candidates.
- `overall_result` and `detected` remain defender-side evaluation fields and are not changed by attacker-side observed effects.
- Defender-side telemetry expectations and investigation pivots are tracked in [Defender Coverage Matrix](defender_coverage_matrix.md).

## Scenario Families

| Scenario family | Scenario ID | Summary | Primary artifact |
|---|---|---|---|
| `ssh_bruteforce_to_persistence` | `scenario_004` | SSH brute force, successful login, and authorized_keys persistence write | `authorized_keys_modification` |
| `ssh_key_reuse` | `scenario_005` | SSH public-key authentication reuse | `ssh_key_login` |
| `ssh_key_command_execution` | `scenario_006` | SSH key login followed by post-login command execution | `process_exec` |
| `ssh_key_suspicious_file_write` | `scenario_007` | SSH key login followed by a benign marker file write under `/tmp` | `suspicious_file_write` |
| `ssh_key_system_discovery` | `scenario_008` | SSH key login followed by harmless read-only system discovery commands | `system_discovery` |
| `suspicious_archive_staging` | `scenario_009` | Local lab-safe staging directory, synthetic files, archive creation, and archive permission change | `suspicious_archive_staging` |

## Canonical Artifacts

| Artifact | Description | Typical event types | Scenario coverage | ATT&CK mapping | Notes / limitations |
|---|---|---|---|---|---|
| `ssh_failed_login` | Failed SSH authentication attempts expected from brute force activity | `ssh_bruteforce_attempted` | `scenario_004` | `T1110` | Represents expected defender-side auth failure evidence, not proof that the defender observed it. |
| `ssh_success_login` | Successful password-based SSH login after credential discovery | `ssh_login_succeeded` | `scenario_004` | `T1078` | Context distinguishes this from `ssh_key_login`; avoid overloading the artifact across auth methods. |
| `authorized_keys_modification` | Modification of an SSH `authorized_keys` persistence location | `authorized_keys_write_succeeded` | `scenario_004` | `T1098` | Persistence-specific artifact; do not use for benign file writes outside SSH persistence paths. |
| `ssh_key_login` | Successful SSH public-key authentication | `ssh_login_succeeded` | `scenario_005`, `scenario_006`, `scenario_007`, `scenario_008` | `T1078` | Shared by key-reuse scenarios; downstream context should preserve scenario ID when needed. |
| `process_exec` | Post-login command or payload execution evidence | `payload_execution_succeeded` | `scenario_006` | `T1059` | Current scenario_006 uses payload execution; attacker-side events still do not prove defender observation. |
| `suspicious_file_write` | Benign suspicious file write under `/tmp` after SSH key login | `suspicious_file_write_succeeded` | `scenario_007` | `T1059` | Maps to `T1059` because scenario_007 writes the file via shell command. It is lab-focused and may need refinement if future file-write scenarios use different behavior. |
| `system_discovery` | Harmless read-only system discovery after SSH key login | `system_discovery_succeeded` | `scenario_008` | `T1082` | Covers commands such as `whoami`, `id`, `hostname`, and `uname -a`; attacker-side events still do not prove defender observation. |
| `suspicious_archive_staging` | Lab-safe suspicious archive and staging behavior using only runner-generated synthetic files under a controlled temp directory | `staging_directory_created`, `staged_file_written`, `archive_created`, `archive_permission_changed` | `scenario_009` | `T1074.001`, `T1560.001`, `T1222.002` | Local attacker-side simulation only. It does not read broad directories, collect real data, exfiltrate, use network callbacks, or prove defender observation. |

## Structured Runner Event Mappings

| Scenario | Scenario family | Structured runner `event_type` | Observed-effects `artifact` | Expected defender-side artifact | ATT&CK technique |
|---|---|---|---|---|---|
| `scenario_004` | `ssh_bruteforce_to_persistence` | `ssh_bruteforce_attempted` | `ssh_failed_login` | `ssh_failed_login` | `T1110` |
| `scenario_004` | `ssh_bruteforce_to_persistence` | `ssh_login_succeeded` | `ssh_success_login` | `ssh_success_login` | `T1078` |
| `scenario_004` | `ssh_bruteforce_to_persistence` | `authorized_keys_write_succeeded` | `authorized_keys_modification` | `authorized_keys_modification` | `T1098` |
| `scenario_005` | `ssh_key_reuse` | `ssh_login_succeeded` | `ssh_key_login` | `ssh_key_login` | `T1078` |
| `scenario_006` | `ssh_key_command_execution` | `ssh_login_succeeded` | `ssh_key_login` | `ssh_key_login` | `T1078` |
| `scenario_006` | `ssh_key_command_execution` | `payload_execution_succeeded` | `process_exec` | `process_exec` | `T1059` |
| `scenario_007` | `ssh_key_suspicious_file_write` | `ssh_login_succeeded` | `ssh_key_login` | `ssh_key_login` | `T1078` |
| `scenario_007` | `ssh_key_suspicious_file_write` | `suspicious_file_write_succeeded` | `suspicious_file_write` | `suspicious_file_write` | `T1059` |
| `scenario_008` | `ssh_key_system_discovery` | `ssh_login_succeeded` | `ssh_key_login` | `ssh_key_login` | `T1078` |
| `scenario_008` | `ssh_key_system_discovery` | `system_discovery_succeeded` | `system_discovery` | `system_discovery` | `T1082` |
| `scenario_009` | `suspicious_archive_staging` | `staging_directory_created` | `suspicious_archive_staging` | `suspicious_archive_staging` | `T1074.001` |
| `scenario_009` | `suspicious_archive_staging` | `staged_file_written` | `suspicious_archive_staging` | `suspicious_archive_staging` | `T1074.001` |
| `scenario_009` | `suspicious_archive_staging` | `archive_created` | `suspicious_archive_staging` | `suspicious_archive_staging` | `T1560.001` |
| `scenario_009` | `suspicious_archive_staging` | `archive_permission_changed` | `suspicious_archive_staging` | `suspicious_archive_staging` | `T1222.002` |


## Scenario 008: SSH Key System Discovery

This section documents the implemented `scenario_008_ssh_key_system_discovery` scenario and canonical `system_discovery` artifact.

### Scenario Summary

| Field | Value |
|---|---|
| Scenario ID | `scenario_008` |
| Scenario name | `scenario_008_ssh_key_system_discovery` |
| Scenario family | `ssh_key_system_discovery` |
| Summary | SSH key login followed by harmless read-only system discovery commands |
| Primary artifact | `system_discovery` |

The scenario models this behavioral shape:

```text
SSH key login -> harmless system discovery commands
```

Example harmless commands include:

- `whoami`
- `id`
- `hostname`
- `uname -a`

### Revision Rationale

The earlier download/chmod/execute simulated proposal is not a good separate `scenario_008` candidate because existing `scenario_006` already covers that behavior chain:

- performs SSH key login
- downloads a payload with `curl`
- applies `chmod +x`
- executes the payload with `bash`
- maps execution to `process_exec`

Because `scenario_006` already models SSH key login followed by download, chmod, and execution, `scenario_008` should cover a different behavior family. Harmless system discovery after SSH key login gives the attacker catalog a distinct post-login activity without adding payload execution or persistence behavior.

### Structured Runner Events

These mappings are implemented:

| Structured runner `event_type` | Artifact | Status | Notes |
|---|---|---|---|
| `ssh_login_succeeded` | `ssh_key_login` | Implemented artifact | Same key-login evidence category used by scenario_005 / 006 / 007. |
| `system_discovery_succeeded` | `system_discovery` | Implemented artifact | Represents harmless read-only host/user/system discovery mapped to `T1082`. |

### Artifact Decision

Implemented artifact strategy:

- Reuses `ssh_key_login` for public-key SSH authentication.
- Promotes `system_discovery` as the canonical artifact for harmless read-only discovery activity.
- Maps `system_discovery` to ATT&CK `T1082`.
- Does not use `process_exec` as the primary `scenario_008` artifact; existing `scenario_006` already covers payload download, chmod, and execution mapped to `process_exec`.

### Scenario 008 Artifact and Test Strategy

The implementation stays focused on read-only discovery:

- emits `ssh_login_succeeded` mapped to `ssh_key_login`
- emits `system_discovery_succeeded` mapped to `system_discovery`
- records harmless command output in runner stdout
- does not emit download, chmod, or execution marker events for this scenario
- tests do not execute real attack runners
- real smoke remains manual and is recorded with the smoke checklist

`file_stage` and `file_permission_change` may still become future scenario families if the project needs explicit staging or permission-change coverage, but they should not be part of `scenario_008`.

### Safety Design

The runner is lab-safe and reviewable:

- never download from the external network or internet
- never execute downloaded, staged, or untrusted payloads
- never modify persistence locations such as cron, systemd, or `authorized_keys`
- never modify privileged system files
- never require `sudo`
- run only harmless read-only discovery commands
- keep all commands in a runner file under `attacks/runners`
- avoid inline shell fields in scenario YAML
- keep structured runner events attacker-side evidence, not defender telemetry

### Future Questions

- What defender telemetry is expected to observe read-only discovery commands?
- Should staging or file permission changes become separate future scenario families?

## Status Vocabulary

Structured runner event status values are:

- `observed`
- `not_observed`
- `partial`
- `unknown`

`failed` is not a structured runner event status. Execution-level status may still use `failed`, including runner failure, timeout, or non-zero exit handling.

## Naming Rules

For future scenario and artifact additions:

- `event_type` should describe attacker-side observed behavior.
- `artifact` should describe the expected defender-side evidence category.
- Prefer stable artifact names over scenario-specific names.
- Avoid overloading one artifact with unrelated meanings.
- Add a catalog entry before adding a new artifact.
- Avoid renaming existing artifacts without migration notes.
- Do not treat attacker-side events as defender detections.

## Limitations

- Current artifacts are minimal and lab-focused.
- Some ATT&CK mappings are approximate and should be revisited as scenario families mature.
- `suspicious_file_write` currently maps to `T1059` because scenario_007 writes the file via shell command.
- Defender-side telemetry or log collection may not yet observe every expected artifact.
- Alignment gaps may indicate detection, collection, parser, correlation, or scenario-mapping issues.
- Rule Improvement signals based on alignment gaps require reviewer approval before any rule or prompt candidate work.
