# Defender Coverage Matrix

## Purpose

This matrix connects attacker-side scenario artifacts to expected defender-side
telemetry, detections, investigation pivots, and evidence gaps. It covers the
documented scenario family and canonical attacker-artifact vocabulary:

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

## Status And Evidence Ownership

This matrix owns the technical mapping between attacker artifacts, expected
defender evidence, investigation pivots, and documented gaps. It does not own
project priority, implementation completion, or delivery order; those belong in
the [Main Roadmap](../../roadmap/roadmap.md) and relevant phase documents.

Coverage language is evidence-scoped. `Strong`, `weak`, fixture-backed, or
live-derived descriptions apply only to the evidence stated in the row and do
not prove full cross-platform or production validation.

## Coverage Matrix

| Scenario | Artifact | Attacker-side event | Expected defender telemetry | Documented evidence posture | Investigation pivots | Evidence gap |
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

Authentication artifacts can rely on auth-log or Wazuh evidence when the
documented source is present. Post-login process, file, discovery, and staging
artifacts require endpoint or collection evidence before attacker-side claims
can be treated as defender-side observability.

Wazuh FIM, auditd, osquery, EDR, and Velociraptor are candidate sources, not
implicit implementation claims. A scenario extension should identify the
required defender evidence and pivots before adding a new attacker artifact.

## Gap Review Conditions

A coverage gap may enter planned work only after review identifies:

1. the defender-observable fact that is missing;
2. the candidate telemetry source and its collection limitations;
3. the normalization, detection, correlation, or investigation boundary
   responsible for the gap;
4. bounded fixture or live-validation evidence;
5. the required provenance and pivot fields; and
6. whether the result is a telemetry, parser, correlation, or rule-review
   concern.

Scenario 009 remains subject to its documented source-selection and grouping
boundary. Manager receipt does not establish complete event grouping, canonical
source selection, normalized parity, detection, or Incident consumption.

## Review Boundaries

Observed-effects alignment can highlight gaps such as attacker-observed and defender-missing artifacts, but those signals remain review-only. A reviewer must decide whether a gap represents missing telemetry, missing parsing, missing correlation, benign lab limitations, or a candidate for future rule/prompt work.
