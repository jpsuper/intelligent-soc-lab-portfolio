# Auditd Minimal Rules

## Purpose

This document describes the first concrete auditd rules for lab-scoped endpoint telemetry validation. The rules live in `configs/auditd/intelligent_soc_lab_minimal.rules` and are intended for manual review and manual lab application only.

The rules support the coverage described in [Auditd Minimal Coverage Design](../design/defender/auditd_minimal_coverage.md) and the manual checks in [Auditd Smoke Checklist](auditd_smoke_checklist.md).

Boundaries:

- The rules are not automatically deployed by this repository.
- Review the rules before applying them to any host.
- Generated audit logs should not be committed.
- The rules provide defender-side telemetry, not attacker-side evidence.
- Attacker-side structured events are not auditd evidence.
- These rules do not add parsers, Wazuh ingestion, detections, or automated deployment.
- These rules do not change `overall_result`, `detected`, observed-effects behavior, or Rule Improvement behavior.

## Rule Coverage

| Audit key | Rule family | Related artifacts | Related scenarios | Expected evidence |
|---|---|---|---|---|
| `isl_execve` | Process execution | `process_exec`, `system_discovery` | `scenario_006`, `scenario_008` | `execve`, command/argv, exe, uid, auid, timestamp |
| `isl_ssh_persistence` | SSH persistence path watch | `authorized_keys_modification` | `scenario_004` | Path, write/attribute change, user, timestamp |
| `isl_tmp_marker` | Selected lab marker file watch | `suspicious_file_write` | `scenario_007` | Selected marker path, write/create/change action, user, timestamp |

## Rule Notes

The `isl_execve` rules use both `b64` and `b32` arch entries for Linux auditd on x86_64-style hosts. Exact behavior may vary by distro and auditd version.

The `isl_ssh_persistence` rule watches `/home/victim01/.ssh/` rather than a wildcard under `/home`. This keeps the concrete rule lab-specific and avoids relying on unsupported auditd wildcard behavior. Reviewers and future parsers should filter this audit key to `/home/victim01/.ssh/authorized_keys` for `authorized_keys_modification` validation.

The `isl_tmp_marker` rule watches the known scenario_007 marker path `/tmp/ai_soc_lab_scenario_007_marker.txt`. It intentionally does not watch all of `/tmp`.

## Loading Troubleshooting

If `auditctl -R` exits with a non-zero status, check the following before changing the rules.

### Kernel Auditing Must Be Enabled

`auditd.service` can be active even when kernel auditing is disabled.

```bash
sudo auditctl -s
```

Expected:

```text
enabled 1
```

If `enabled 0` is shown, enable kernel auditing before smoke validation:

```bash
sudo auditctl -e 1
sudo auditctl -s
```

### File-Level Watch Targets Must Exist

The `isl_tmp_marker` rule watches a specific file path:

```text
/tmp/ai_soc_lab_scenario_007_marker.txt
```

Create the file before loading the rules:

```bash
sudo touch /tmp/ai_soc_lab_scenario_007_marker.txt
```

This preserves the intentionally narrow file-level watch and avoids broad `/tmp` monitoring.

### Identify Failing Rules Line-By-Line

If `auditctl -R` does not clearly show which line failed, apply non-comment rules one at a time:

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

This troubleshooting method should be used only for manual validation. It does not imply that the repository should broaden the audit scope.

### Existing Broad Execve Rules

Some lab hosts may already have broad `execve` rules such as:

```text
-a always,exit -F arch=b64 -S execve -F key=exec_log
-a always,exit -F arch=b32 -S execve -F key=exec_log
```

These rules can add noise during smoke validation. Prefer validating lab-specific evidence with:

```bash
sudo ausearch -k isl_execve -ts recent -i
sudo ausearch -k isl_tmp_marker -ts recent -i
sudo ausearch -k isl_ssh_persistence -ts recent -i
```

### AUID Display Note

On some hosts, `auditctl -l` may render `auid!=4294967295` as `auid!=-1`. This is an expected display normalization and does not by itself indicate a rule mismatch.

## Future Manual Examples

These commands are future manual examples only. Review the rules before running them, and adjust commands for the target distro, auditd version, and lab collection path.

```bash
# Future manual example only; review before running.
sudo auditctl -R configs/auditd/intelligent_soc_lab_minimal.rules
sudo auditctl -l
sudo ausearch -k isl_execve --start <time> --end <time>
sudo ausearch -k isl_ssh_persistence --start <time> --end <time>
sudo ausearch -k isl_tmp_marker --start <time> --end <time>
```

Do not commit generated `data/` artifacts, raw audit logs, private hostnames, SSH keys, or local-only paths from manual validation.
