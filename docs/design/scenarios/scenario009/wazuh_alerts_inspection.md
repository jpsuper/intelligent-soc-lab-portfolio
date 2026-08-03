# Scenario 009 Wazuh Alerts Inspection

Status: Alerts Inspection Completed / No Matching Scenario Evidence

## Purpose

This document records a point-in-time inspection of Wazuh manager
`alerts.json` after a controlled execution of
`scenario_009_suspicious_archive_staging`.

The inspection compares confirmed local auditd evidence with alert documents
written under the current Wazuh configuration. It does not treat attacker-side
runner output as defender evidence and does not prove or disprove receipt of the
underlying audit records by Wazuh.

Core boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

## Observation Provenance

The observation was performed on `2026-07-11`.

| Item | Observed value |
|---|---|
| Alerts observation start | `2026-07-11T23:07:47Z` |
| Scenario execution start | `2026-07-11T23:08:32Z` |
| Scenario execution end | `2026-07-11T23:08:33Z` |
| Runner host | `kali-attacker` |
| Target host | `ubuntu-victim01` (`192.0.2.30`) |
| Wazuh manager host | `wazuh-server` (`192.0.2.23`) |
| Execution transport | SSH stdin from the Kali repository checkout |
| Runner exit code | `0` |
| Temporary audit key | `scenario009_audit_smoke` |
| Temporary audit rule cleanup | Confirmed removed |
| Generated scenario artifact cleanup | Confirmed removed |

The local WSL workspace was used only to maintain repository documentation. No
complete `audit.log`, `alerts.json`, raw Wazuh export, credential, key,
certificate, token, or complete command-output dump is committed by this record.

## Existing Environment Baseline

The deployed environment is recorded in
[Scenario 009 Wazuh Collection Environment](wazuh_collection_environment.md).
The relevant baseline is:

- Wazuh manager, indexer, dashboard, and agent version `4.14.4`
- active `ubuntu-victim01` agent connectivity
- agent-local collection of `/var/log/audit/audit.log`
- manager `alerts.json` available
- manager `archives.json` unavailable
- `logall: no`
- `logall_json: no`

## Validation Procedure

The bounded procedure was:

1. Confirm the scenario audit key was not already active.
2. Create the runner-controlled directory and add a temporary audit watch with
   key `scenario009_audit_smoke`.
3. Record the starting line of local `audit.log` and manager `alerts.json`.
4. Stream the existing safe runner from `kali-attacker` to
   `ubuntu-victim01` over SSH stdin.
5. Inspect only records appended after the recorded start positions.
6. Compare local auditd evidence with scenario indicators in `alerts.json`.
7. Remove the temporary audit rule and generated scenario artifacts.

The runner command shape was:

```bash
ssh victim01@192.0.2.30 \
  'SCENARIO_009_BASE_DIR=/tmp/ai_soc_lab_scenario_009_audit_smoke bash -s' \
  < attacks/runners/scenario_009_suspicious_archive_staging.sh
```

The runner emitted the expected attacker-side structured events for staging
directory creation, staged file writes, archive creation, and archive permission
change. Those events confirm runner execution only; local auditd and Wazuh
artifacts were evaluated independently.

## Local Auditd Evidence

Local auditd contained all five expected defender-side file-operation
observations.

| Expected observation | Audit serial | Local evidence | Result |
|---|---:|---|---|
| Staging directory creation | `11496` | successful `mkdir`; `PATH` with `name=staging`, `nametype=CREATE` | Confirmed |
| `note.txt` creation | `11497` | successful `openat`; full file `PATH`, `nametype=CREATE` | Confirmed |
| `metadata.json` creation | `11498` | successful `openat`; full file `PATH`, `nametype=CREATE` | Confirmed |
| Archive creation | `11500` | successful `creat`; archive `PATH`, `nametype=CREATE` | Confirmed |
| Archive permission change | `11504` | successful `fchmodat`; archive `PATH` | Confirmed |

Supporting command-execution evidence was also observed:

- audit serial `11499`: `/usr/bin/tar` execution with `-czf`, archive path,
  staging directory, `note.txt`, and `metadata.json`
- audit serial `11503`: `/usr/bin/chmod` execution with mode `0640` and the
  archive path

The watched file-operation records preserved the scenario audit key and original
audit serials. The command-execution records were also covered by the existing
`isl_execve` audit rules.

The post-run audit health check reported:

- auditing enabled: `1`
- lost events: `0`
- backlog: `0`

A point-in-time query found lines directly containing the scenario audit key,
but that value is not treated as the total event-record count. Related `PATH`,
`EXECVE`, `CWD`, `PROCTITLE`, or other records do not necessarily repeat the key
text, and validation-time administrative or query activity may also appear.

## Wazuh `alerts.json` Results

Before scenario execution, manager `alerts.json` contained `107` JSON lines and
was `113980` bytes. The inspection window began at line `108`.

After the run:

- `31` new JSON lines existed in the inspection window
- manager file size was `142399` bytes
- matching scenario alert documents: `0`
- matching `jq` output: none

The search covered:

- `scenario009_audit_smoke`
- `staged_synthetic_files.tar.gz`
- `note.txt`
- `metadata.json`
- `/usr/bin/tar`
- the runner-controlled base directory

Because no matching scenario alert document existed, the following were not
observed in `alerts.json` for this scenario:

- agent, rule, or decoder metadata tied to scenario evidence
- original audit message or `full_log`
- audit serial or audit key
- syscall, executable, or command arguments
- `CWD`, `PATH`, or `PROCTITLE`

The `31` new lines are not classified as scenario evidence; they may represent
unrelated alerts generated during the same time window.

## Five-Observation Comparison

| Expected observation | Local auditd | `alerts.json` | Retained Wazuh fields | Result |
|---|---|---|---|---|
| Staging directory creation | Confirmed | Not observed | None for matching scenario evidence | No Wazuh alert evidence |
| `note.txt` creation | Confirmed | Not observed | None for matching scenario evidence | No Wazuh alert evidence |
| `metadata.json` creation | Confirmed | Not observed | None for matching scenario evidence | No Wazuh alert evidence |
| Archive creation | Confirmed | Not observed | None for matching scenario evidence | No Wazuh alert evidence |
| Permission change | Confirmed | Not observed | None for matching scenario evidence | No Wazuh alert evidence |

This result is not five-event Wazuh parity. It is a negative alert-storage result
under the observed manager configuration.

## Multi-Record Grouping Assessment

Local auditd preserved the original event serials needed to associate records.
The current `alerts.json` sample provided no matching scenario document, so it
provided no evidence that the following survive the Wazuh alert path:

- audit epoch and serial
- record type
- multiple `PATH` records
- `EXECVE` arguments
- `CWD`
- `PROCTITLE`
- `EOE` or an equivalent grouping boundary

Deterministic grouping from `alerts.json` therefore cannot be evaluated and must
not be claimed.

## Filtering And Duplicate Assessment

The observed configuration had `logall: no` and `logall_json: no`. Under this
configuration, `alerts.json` contains rule-generated alerts rather than every
collected record.

The inspection found no matching scenario alert, so it cannot determine:

- whether Wazuh received but filtered the source audit records
- whether one audit event would be split into multiple alert documents
- whether transport duplicates would occur
- whether exact-record deduplication would be required for this source

The result proves that the current alert output did not expose matching scenario
evidence. It does not prove that the Wazuh agent or manager failed to receive the
underlying audit records.

## Source Artifact Conclusion

`alerts.json` is not suitable as the canonical `scenario_009` source artifact
under the observed configuration.

It is also not confirmed as supporting observability for this scenario because
no matching alert document was produced. The primary source artifact remains
unresolved.

A raw or less-filtered manager-side artifact is required before existing audit
grouping, endpoint normalization, five-event comparison, and DSL evaluation can
be validated through Wazuh.

## Configuration And Cleanup Boundary

The inspection used a bounded temporary audit watch and the existing safe
runner. The temporary rule and generated scenario files were removed after the
observation.

The following remained unchanged:

- manager `logall`
- manager `logall_json`
- persistent audit rules
- Wazuh decoder and rule configuration
- rsyslog configuration
- repository source code and tests

No full log or raw manager artifact was copied into the repository.

## Recommended Next Step

The separate bounded operational procedure for temporary `logall_json`
enablement was executed and is recorded in
[Scenario 009 Wazuh Raw Archive Validation Result](wazuh_raw_archive_validation.md).
That observation confirmed manager receipt and all five semantic operations. Its
retained structured summary did not demonstrate complete serial-linked grouping
and did not retain exact `full_log` values. The result is Outcome C, so
`archives.json` is supporting evidence rather than canonical input.

Stage 3 version-matched source verification predicts that consecutive audit
records sharing one timestamp and serial are grouped by agent logcollector and
that the incoming grouped payload is retained in archive `full_log`. Stage 4
separately confirmed exact grouped-payload identity between one completed
controlled local event and manager `full_log`. The existing sanitized auditd fixture remains
canonical, and a Wazuh parity fixture or adapter test remains future work
requiring a separate source decision.

## Confirmed Versus Pending

| Capability | Status |
|---|---|
| Controlled runner execution from `kali-attacker` | Confirmed |
| Expected attacker-side structured output | Confirmed; not defender evidence |
| Local auditd five-observation evidence | Confirmed |
| Temporary audit rule and artifact cleanup | Confirmed |
| New `alerts.json` lines during the window | Confirmed: `31` |
| Matching scenario evidence in `alerts.json` | Not observed: `0` documents |
| `alerts.json` canonical source suitability | Rejected under observed configuration |
| Wazuh receipt of underlying audit records | Confirmed by the later raw-archive observation |
| Wazuh multi-record grouping suitability | Unresolved; retained summaries classified structured `audit.type=SYSCALL` but omitted exact `full_log` values |
| Primary source artifact selection | Unresolved; `archives.json` supporting only |
| Five-event Wazuh semantic parity | Pending |
| Sanitized Wazuh fixture extraction | Pending |
| Wazuh adapter normalization | Pending |
| Wazuh-path DSL detection | Pending |
| Wazuh-path incident consumption | Pending |

## Explicit Non-Goals

This inspection does not:

- prove Wazuh receipt or loss of the underlying audit records
- validate five-event Wazuh parity
- select `alerts.json` as canonical input
- enable `logall` or `logall_json`
- modify persistent audit, Wazuh, rsyslog, decoder, or rule configuration
- add an adapter, fixture, schema, source-code change, or test
- validate Wazuh-native detection
- validate Velociraptor or continuous production-log ingestion
- execute containment or response
- claim exfiltration, ransomware, credential access, compromise, or real-data
  collection

## Relationship To The Validation Plan

The overall contract is defined in
[Scenario 009 Wazuh / SIEM Validation Plan](wazuh_siem_validation_plan.md).

This inspection answers the narrow `alerts.json` question for the observed
configuration: local auditd produced the expected scenario evidence, while the
manager alert file exposed no matching scenario document. The later raw-archive
observation confirms Wazuh receipt but not complete multi-record grouping; see
[Scenario 009 Wazuh Raw Archive Validation Result](wazuh_raw_archive_validation.md).
