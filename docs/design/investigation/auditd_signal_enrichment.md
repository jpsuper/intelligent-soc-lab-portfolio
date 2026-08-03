# Auditd Investigation Signal Enrichment

## Purpose

This document defines how normalized `auditd_events.json` should contribute to investigation evidence without changing assessment behavior. auditd events are defender-side endpoint telemetry. They can help an investigator see process execution, file writes, and persistence-path changes, but they are not conclusions by themselves.

The goal is narrow enrichment:

- Add factual entries to `evidence_summary.observed_facts`.
- Add factual corroboration to `evidence_summary.supporting_signals`.
- Preserve existing `behavior_features -> derived_features -> assessment` separation.

## Boundaries

auditd enrichment may populate only:

- `observed_facts`
- `supporting_signals`

auditd enrichment must not modify:

- `confidence`
- `severity`
- `attack_story`
- `recommended_actions`
- final assessment
- `overall_result`
- `detected`
- Rule Improvement promotion behavior

Direct auditd enrichment remains intentionally narrow. When auditd-derived records are converted
into the normalized `endpoint_events.json` contract, investigation may additionally derive
endpoint-specific `enriched_features` and investigation pivots from concrete endpoint command,
path, and URL evidence. Those derived endpoint signals remain additive investigation context and
still must not change verdicts, detection results, action decisions, or Rule Improvement promotion.

The enrichment layer must not infer attacker intent from auditd events. For example, `execve` evidence for `curl`, `chmod`, or `bash` may support the factual statement that those commands executed, but it must not by itself assert maliciousness, success of an attack scenario, or an ATT&CK assessment.

## Evidence Model

The lab already separates observed evidence from interpretation:

```text
behavior_features
  -> derived_features
  -> assessment
```

auditd enrichment belongs on the observed-evidence side of this boundary. Normalized auditd events can confirm that the endpoint recorded a process or file action, but they should not create new `behavior_features`, `derived_features`, or assessment outputs in the MVP.

Recommended mapping:

| auditd event | Investigation contribution | Not allowed |
|---|---|---|
| `process_exec` | observed fact for executable, argv, user, timestamp; supporting signal for existing process evidence | Change confidence, severity, verdict, or attack story |
| `file_write` | observed fact for selected file path/action; supporting signal for file-write evidence | Conclude persistence or malicious intent unless another layer owns that logic |
| `persistence_file_change` | observed fact for `.ssh` or `authorized_keys` path change | Automatically recommend response actions or promote rule candidates |

## Scenario Examples

### scenario_006: curl / chmod / bash payload execution

Relevant normalized auditd events may include:

- `event_type=process_exec`
- `audit_key=isl_execve`
- `exe=/usr/bin/curl`
- `argv` containing payload download arguments
- `exe=/usr/bin/chmod`
- `argv` containing permission-change arguments
- `exe=/usr/bin/bash`
- `argv` containing shell execution arguments

Allowed `observed_facts` examples:

- `auditd observed curl execution for the payload download command.`
- `auditd observed chmod execution for the staged payload path.`
- `auditd observed bash execution after payload staging.`

Allowed `supporting_signals` examples:

- `auditd process telemetry corroborates the process execution chain.`
- `auditd recorded endpoint-side execve evidence for curl, chmod, and bash.`

Not allowed:

- Increase severity because auditd saw the commands.
- Change confidence because auditd saw the commands.
- Rewrite `attack_story` to assert a malicious payload was executed.
- Automatically recommend containment or key revocation.

### scenario_007: marker file write

Relevant normalized auditd events may include:

- `event_type=file_write`
- `audit_key=isl_tmp_marker`
- `file_path=/tmp/ai_soc_lab_scenario_007_marker.txt`
- `file_action=file_change` or a more specific write/create action when inferable

Allowed `observed_facts` examples:

- `auditd observed a file event for /tmp/ai_soc_lab_scenario_007_marker.txt.`
- `auditd recorded the selected lab marker path in PATH records.`

Allowed `supporting_signals` examples:

- `auditd file telemetry corroborates the suspicious_file_write artifact.`

Not allowed:

- Treat the marker file as proof of compromise by itself.
- Broaden the conclusion to all `/tmp` activity.
- Auto-create a rule candidate from the marker event.

### scenario_008: whoami / hostname / uname discovery

Relevant normalized auditd events may include:

- `event_type=process_exec`
- `audit_key=isl_execve`
- `exe=/usr/bin/whoami`
- `exe=/usr/bin/hostname`
- `exe=/usr/bin/uname`
- `argv` for the discovery commands

Allowed `observed_facts` examples:

- `auditd observed whoami execution during the scenario window.`
- `auditd observed hostname execution during the scenario window.`
- `auditd observed uname execution during the scenario window.`

Allowed `supporting_signals` examples:

- `auditd process telemetry corroborates system discovery command execution.`

Not allowed:

- Infer attacker intent from discovery commands alone.
- Change the triage assessment.
- Change the investigation's final assessment.
- Recommend actions solely because discovery commands ran.

## Relationship To Normalized Endpoint Events

`auditd_events.json` remains a source-specific normalized artifact. It is useful on its own for
factual investigation enrichment, and it can also be converted into the common
`endpoint_events.json` contract.

```text
auditd_events.json
  -> observed_facts / supporting_signals only

auditd_events.json
  -> endpoint_events.json
  -> observed_facts / supporting_signals
  -> endpoint-derived enriched_features
  -> endpoint-derived missing_pivots / recommended_pivots
```

Allowed endpoint-derived examples after conversion include:

- `endpoint_command_sequence_observed`
- `endpoint_payload_path_observed`
- `endpoint_url_fetch_observed`
- `endpoint_download_then_execute_pattern`
- `endpoint_chmod_execute_chain_observed`
- `inspect_payload_or_command_context`

These are still investigation evidence and pivot signals. They are not detection verdicts,
severity changes, action approvals, or automatic Rule Improvement candidates.


## Implementation Guidance

When implemented, auditd signal enrichment should:

1. Read normalized `auditd_events.json` as optional investigation input.
2. Filter to relevant events by scenario time window, host, user, audit key, or command context when those fields are available.
3. Add concise factual text to `observed_facts`.
4. Add concise corroboration text to `supporting_signals`.
5. Preserve raw normalized events elsewhere in `evidence` for review.
6. Leave all assessment fields untouched.

The enrichment should be idempotent and additive. If `auditd_events.json` is missing, empty, or unrelated, investigation output should remain behaviorally unchanged except for source-input bookkeeping where applicable.

## Review Rule

auditd enrichment answers:

```text
What did defender-side endpoint telemetry observe?
```

It must not answer:

```text
How severe is this?
Was the attack successful?
What should be done?
Should a rule be promoted?
```
