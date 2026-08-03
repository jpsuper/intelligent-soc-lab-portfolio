# Defender Coverage Matrix

## Purpose

This matrix connects current attacker-side scenario artifacts to expected defender-side telemetry, detections, investigation pivots, and coverage gaps. It covers `scenario_004` through `scenario_008` and the current canonical attacker artifacts:

- `ssh_failed_login`
- `ssh_success_login`
- `authorized_keys_modification`
- `ssh_key_login`
- `process_exec`
- `suspicious_file_write`
- `system_discovery`
- `suspicious_archive_staging`

Key boundaries:

- Attacker-side structured events are evidence that a runner executed or attempted an action.
- Attacker-side structured events are not defender telemetry, detections, or alerts.
- Defender-side coverage means the SOC pipeline has telemetry, detection logic, investigation pivots, and evidence to observe or reason about the artifact.
- Missing defender-side telemetry is a coverage gap, not proof that the attack did not happen.
- Observed-effects alignment signals remain review-only.
- This matrix does not auto-generate rule candidates or change Rule Improvement behavior.
- `overall_result` and `detected` remain defender-side evaluation fields and are not changed by attacker-side observed effects.
- Endpoint telemetry collection design for post-login artifacts is tracked in [Endpoint Telemetry Coverage Design](../defender/endpoint_telemetry_coverage.md).
- Minimal auditd coverage for current post-login artifacts is scoped in [Auditd Minimal Coverage Design](../defender/auditd_minimal_coverage.md).

## Coverage Matrix

| Scenario | Artifact | Attacker-side event | Expected defender telemetry | Current likely coverage | Investigation pivots | Gap / follow-up |
|---|---|---|---|---|---|---|
| `scenario_004` | `ssh_failed_login` | `ssh_bruteforce_attempted` | `/var/log/auth.log`, sshd failed password messages, Wazuh auth rules | Strong | Source IP, target user, failure count, time window | Confirm Wazuh/auth parser coverage and threshold behavior. |
| `scenario_004` | `ssh_success_login` | `ssh_login_succeeded` | `/var/log/auth.log`, sshd `Accepted password` messages | Strong | Source IP, target user, session open time | Confirm correlation between brute force window and successful login. |
| `scenario_004` | `authorized_keys_modification` | `authorized_keys_write_succeeded` | File integrity monitoring, auditd, EDR, Wazuh FIM if configured | Medium to weak unless FIM is configured | Modified path, user, timestamp, session context | Define FIM/auditd expectations for SSH persistence paths. |
| `scenario_005` | `ssh_key_login` | `ssh_login_succeeded` | `/var/log/auth.log`, sshd `Accepted publickey` messages | Strong for login, weaker for maliciousness | Source IP, user, key fingerprint if available, prior persistence source | Add context linking key login to earlier persistence or unusual source. |
| `scenario_006` | `process_exec` | `payload_execution_succeeded` | Process telemetry, auditd `execve`, EDR, osquery, Velociraptor, shell history as weak evidence | Weak unless process telemetry exists | Command line, parent process, user, working directory, network staging context | Decide whether auditd, osquery, EDR, or Velociraptor should supply execution evidence. |
| `scenario_007` | `suspicious_file_write` | `suspicious_file_write_succeeded` | auditd, EDR, FIM, process/file telemetry | Weak unless file telemetry exists | Path under `/tmp`, writing user, process, timestamp | Define expected file-write telemetry and whether Wazuh FIM should watch lab paths. |
| `scenario_008` | `system_discovery` | `system_discovery_succeeded` | Process telemetry, auditd `execve`, EDR, osquery, Velociraptor | Weak unless command execution telemetry exists | Commands such as `whoami`, `id`, `hostname`, `uname -a`; user; parent SSH session | Define endpoint telemetry needed for read-only discovery command evidence. |
| `scenario_009` | `suspicious_archive_staging` | `staging_directory_created`, `staged_file_written`, `archive_created`, `archive_permission_changed` | Process telemetry, auditd `execve`, file telemetry, normalized endpoint events | Synthetic and live-derived fixture coverage reaches the bounded incident-to-action chain. `alerts.json` had `0` matching documents. A bounded raw-archive run produced `1026` new documents and `55` strong scenario documents, confirming manager receipt and all five operations. | Runner-controlled temp directory, synthetic file writes, archive path, `tar` invocation, original audit serial/key, manager envelope, source-location split | Outcome C: core serials retained only `SYSCALL`; serial-linked `PATH`, `CWD`, `EXECVE`, and `PROCTITLE` were not preserved. `archives.json` is supporting evidence, not canonical. Source selection, parity, normalization, DSL detection, and incident consumption remain pending; the fixture pipeline remains canonical. |

## Summary

Auth-related artifacts currently have the strongest likely defender coverage because SSH authentication events are usually available in auth logs and Wazuh auth rules. Post-login process, file, and discovery artifacts require stronger endpoint telemetry to move from attacker-side evidence to defender-side observability.

Current gaps point toward Wazuh FIM, auditd, osquery, EDR, or Velociraptor integration. Scenario additions should wait until defender coverage for the current artifact set is understood well enough to say what telemetry and pivots each artifact requires.

## Recommended Next Steps

1. Confirm `/var/log/auth.log` and Wazuh coverage for SSH authentication artifacts.
2. Decide whether auditd, osquery, EDR, or Velociraptor should provide process and file telemetry.
3. Define expected defender evidence for `process_exec`, `suspicious_file_write`, and `system_discovery`.
4. Investigate the Scenario 009 Wazuh collection boundary after Outcome C:
   manager receipt and five operations are confirmed, but complete serial-linked
   grouping is not preserved. Do not create a parity fixture or adapter until a
   canonical source is established. Keep Velociraptor, direct production-log
   ingestion, and containment execution separate.

## Review Boundaries

Observed-effects alignment can highlight gaps such as attacker-observed and defender-missing artifacts, but those signals remain review-only. A reviewer must decide whether a gap represents missing telemetry, missing parsing, missing correlation, benign lab limitations, or a candidate for future rule/prompt work.
