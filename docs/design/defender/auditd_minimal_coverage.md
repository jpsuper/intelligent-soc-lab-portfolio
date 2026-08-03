# Auditd Minimal Coverage Design

## Purpose

auditd is the candidate first endpoint telemetry layer for current post-login artifacts. It can provide defender-side evidence for process execution, persistence-path changes, selected lab file writes, and read-only discovery commands.

This design is a planning document. It does not add auditd rules, enable detection, change `overall_result`, mark `detected=true`, or auto-generate rule candidates.

Key boundaries:

- auditd telemetry is defender-side evidence.
- Attacker-side structured runner events are not auditd evidence, defender telemetry, detections, or alerts.
- Observed-effects alignment remains additive and review-only.
- Rule candidates still require separate reviewer approval.
- Implementation belongs in follow-on PRs.

## Coverage Goals

| Coverage area | Related artifacts | Scenario examples | Desired auditd evidence | Priority | Notes |
|---|---|---|---|---|---|
| SSH session context | `ssh_key_login`, `ssh_success_login` | `scenario_004`, `scenario_005`, `scenario_006`, `scenario_007`, `scenario_008` | User, UID/AUID if available, session timing, source IP correlation through auth logs | High | auditd may not directly capture source IP; correlate with auth.log and Wazuh auth events. |
| Process execution | `process_exec`, `system_discovery` | `scenario_006`, `scenario_008` | `execve`, command line, executable path, UID, AUID, timestamp | High | Key requirement for post-login command execution evidence. |
| Persistence path changes | `authorized_keys_modification` | `scenario_004` | Writes or attribute changes to `/home/*/.ssh/authorized_keys` | High | Persistence-specific and separate from generic file writes. |
| Lab suspicious file writes | `suspicious_file_write` | `scenario_007` | Write, create, or rename events for selected lab marker paths under `/tmp` | Medium to High | Avoid broad noisy `/tmp` coverage. |

## Proposed Minimal Rule Families

Exact auditd syntax should be validated during implementation and may vary by distro or auditd version.

Start with these rule families:

- `execve` monitoring for process execution evidence.
- File watches for selected persistence paths such as `/home/*/.ssh/authorized_keys`.
- File watches for selected lab marker paths, limited to the known scenario-specific `/tmp` marker path when available.
- Optional command-focused monitoring for discovery commands such as `whoami`, `id`, `hostname`, and `uname`.

## Expected Normalized Fields

Future parsers should normalize auditd events into fields that can be compared with attacker-side observed effects and defender investigation artifacts:

- `timestamp`
- `host`
- `user`
- `uid`
- `auid`
- `exe`
- `command` or `argv`
- `cwd`, when available
- `file_path`
- `file_action`
- `process_id`
- `parent_process_id`, when available
- `audit_key` or rule label

## Noise And Safety Boundaries

- Do not monitor all of `/tmp` broadly unless a later design proves it is necessary and tolerable.
- Do not collect sensitive command output.
- Do not assume shell history is reliable endpoint telemetry.
- Avoid high event volume rules that make smoke review noisy or unstable.
- Keep lab scope explicit.
- Absence of auditd evidence is not proof an action did not occur.
- auditd complements auth.log and Wazuh auth detection; it does not replace SSH authentication telemetry.

## Future Validation Strategy

Follow-on smoke validation should compare defender-side auditd evidence with attacker-side `attack_observed_effects.json` without treating attacker-side events as telemetry.

Suggested checks:

1. Run `scenario_006` and confirm process execution evidence for `process_exec`.
2. Run `scenario_007` and confirm selected file-write evidence for `suspicious_file_write`.
3. Run `scenario_008` and confirm discovery command execution evidence for `system_discovery`.
4. Run `scenario_004` and confirm `authorized_keys` path change evidence for `authorized_keys_modification`.
5. Compare auditd evidence against attacker-side observed effects.
6. Record gaps as telemetry backlog items, not automatic rule candidates.

## Observed Smoke Coverage Notes

Manual lab smoke validation confirmed that the minimal auditd rule families can provide defender-side telemetry for the current post-login coverage goals.

Observed examples:

- `scenario_006` / `process_exec`: `isl_execve` captured payload download, `chmod +x`, and the payload execution chain.
- `scenario_007` / `suspicious_file_write`: `isl_tmp_marker` captured write/create/truncate activity for `/tmp/ai_soc_lab_scenario_007_marker.txt`, and `isl_execve` captured the shell command that wrote the marker.
- `scenario_008` / `system_discovery`: `isl_execve` captured `whoami`, `id`, `hostname`, and `uname -a` discovery activity.

Operational notes from the smoke:

- Confirm `auditctl -s` shows `enabled 1`; `auditd.service` can be active while kernel auditing is disabled.
- Ensure file-level watch targets exist before loading rules with `auditctl -R`.
- Existing broad `execve` rules can make output noisy; validate lab-specific audit keys directly.
- These observations confirm telemetry coverage only. They do not change detection verdicts or observed-effects semantics.

## Follow-On PR Plan

Candidate implementation and documentation PRs:

1. `feat: add auditd minimal rules`
2. `feat: collect auditd logs into remote log pipeline`
3. `feat: parse auditd execve events`
4. `feat: parse auditd file watch events`
5. `docs: add auditd smoke checklist`
6. `docs: define defender evidence expectations for process_exec`
