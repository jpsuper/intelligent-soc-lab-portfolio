# Scenario 009 Wazuh Raw Archive Validation Result

Status: Completed / Outcome C — Five Observations Present, Complete Grouping Not Demonstrated By Retained Evidence

## Purpose

This document records the bounded operational validation of temporary Wazuh
JSON raw archive storage for `scenario_009_suspicious_archive_staging`.

The validation answers whether the Wazuh manager received Scenario 009 audit
evidence and whether `/var/ossec/logs/archives/archives.json` preserved enough
multi-record audit identity for the existing parser and normalization pipeline.

Core boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

The result confirms manager-side receipt and five-operation semantic presence.
It does not establish deterministic reconstruction of complete audit event
groups, canonical source suitability, normalization, detection, or incident
consumption.

## Observation Provenance

The bounded observation was performed on `2026-07-12`.

| Item | Observed value |
|---|---|
| Run ID | `20260712T012133Z` |
| Raw archive enablement start | `2026-07-12T01:23:00Z` |
| Archive observation start | `2026-07-12T01:23:15Z` |
| Scenario execution time | `2026-07-12T01:24:09Z` |
| Runner host | `kali-attacker` (`192.0.2.40`) |
| Target host | `ubuntu-victim01` (`192.0.2.30`) |
| Wazuh manager host | `wazuh-server` (`192.0.2.23`) |
| Wazuh version | `4.14.4-1` manager, indexer, dashboard, and agent |
| Manager service | `wazuh-manager.service` |
| Temporary audit key | `scenario009_audit_smoke` |
| Archive start line | `32` |
| Archive end line | `1058` |
| New archive documents | `1026` |
| Broad indicator matches | `66` |
| Strong Scenario 009 documents | `55` |

The controlled runner emitted its start and end markers and all four expected
attacker-side structured events. The numeric runner exit code for this raw
archive observation was not captured and must not be recorded as `0`.

A separate runner-only follow-up at `2026-07-12T01:35:25Z` confirmed exit code
`0`. That follow-up occurred after the raw archive observation and is not used as
manager-side evidence for the bounded archive window.

No complete `archives.json`, `audit.log`, bounded raw window, configuration
backup, credential, key, certificate, or command-output dump is committed by
this record.

## Operational Safety And Rollback

Preflight confirmed:

- `/var/ossec` filesystem utilization was `51%`
- approximately `23 GiB` was free
- manager `logall` was `no`
- manager `logall_json` was `no`
- `archives.json` was absent before temporary enablement
- auditd reported enabled `1`, lost `0`, and backlog `0`
- the Wazuh agent was active and connected to manager TCP port `1514`
- the temporary audit rule and controlled directory were absent

The operation temporarily changed only:

```xml
<logall_json>no</logall_json>
```

to:

```xml
<logall_json>yes</logall_json>
```

`<logall>no</logall>` remained unchanged.

Rollback restored the active configuration from the timestamped backup. The
original, restored, and backup SHA-256 values were identical:

```text
fea58b68b8e0d45b27aaaafda079f8bda4f572d00999a4077e5c6413f07a5820
```

Post-rollback checks confirmed:

- `logall: no`
- `logall_json: no`
- `wazuh-manager.service` active
- temporary Scenario 009 audit watch absent
- controlled scenario artifacts removed
- follow-up runner artifacts removed
- auditd enabled `1`, lost `0`, and backlog `0`

The active `archives.json` file was not deleted or truncated. Removal of the
protected configuration backup is not required for rollback and is not claimed
by this document.

## Local Auditd Baseline

The bounded local audit window contained complete multi-record audit groups for
the five expected file-operation observations.

| Expected observation | New local serial | Local record types | Result |
|---|---:|---|---|
| Staging directory creation | `12174` | `SYSCALL`, `CWD`, two `PATH`, `PROCTITLE` | Confirmed |
| `note.txt` creation | `12175` | `SYSCALL`, `CWD`, two `PATH`, `PROCTITLE` | Confirmed |
| `metadata.json` creation | `12176` | `SYSCALL`, `CWD`, two `PATH`, `PROCTITLE` | Confirmed |
| Archive creation | `12178` | `SYSCALL`, `CWD`, two `PATH`, `PROCTITLE` | Confirmed |
| Archive permission change | `12182` | `SYSCALL`, `CWD`, `PATH`, `PROCTITLE` | Confirmed |

Supporting command-execution groups were also present:

- `12173`: `/usr/bin/mkdir`
- `12177`: `/usr/bin/tar`
- `12181`: `/usr/bin/chmod`

The local audit window contained `656` lines and `141` serial groups, of which
`18` matched Scenario 009 indicators or validation activity. Twelve lines
directly contained the scenario audit key; that count is not the total audit
record count because related records do not necessarily repeat the key. Administrative `sudo`,
`auditctl`, `grep`, `mkdir`, and cleanup records remain distinct from the five
core observations.

## Manager-Side Archive Window

The bounded manager-side archive window contained:

- `1026` JSON Lines documents
- `0` invalid JSON lines
- `55` documents with strong Scenario 009 indicators
- `29` documents containing `scenario009_audit_smoke`
- `39` documents containing the controlled base directory
- `10` documents containing the archive filename
- `4` documents containing `note.txt`
- `4` documents containing `metadata.json`

All `55` strong documents identified agent `001:ubuntu-victim01`.

Locations were split across two collection representations:

| Location | Documents |
|---|---:|
| `/var/log/audit/audit.log` | `21` |
| `journald` | `34` |

All `55` strong documents retained:

- timestamp
- `agent.id`
- `agent.name`
- `manager.name`
- location
- `full_log`
- decoder name

Only `2` of `55` strong documents contained a rule ID. Rule presence is not
required for this raw archive observation.

The preliminary `66`-line broad match included generic syscall terms such as
`mkdir`, `openat`, `creat`, and `fchmodat`. It is recorded for provenance only
and is not treated as a Scenario 009 document count; the refined strong-indicator
count is `55`.

## Five-Observation Comparison

The retained structured summary contained one serial-linked document per core
serial classified as `audit.type=SYSCALL`. Exact `full_log` values were not
retained, so this does not prove `full_log` was `SYSCALL`-only.

| Expected observation | Local serial | Manager archive evidence | Result |
|---|---:|---|---|
| Staging directory creation | `12174` | one serial-linked document classified as structured `audit.type=SYSCALL`; syscall `83`; executable `/usr/bin/mkdir` | Operation present; retained summary did not demonstrate complete grouping |
| `note.txt` creation | `12175` | one serial-linked document classified as structured `audit.type=SYSCALL`; syscall `257`; executable `/usr/bin/bash` | Operation present; retained summary did not demonstrate complete grouping |
| `metadata.json` creation | `12176` | one serial-linked document classified as structured `audit.type=SYSCALL`; syscall `257`; executable `/usr/bin/bash` | Operation present; retained summary did not demonstrate complete grouping |
| Archive creation | `12178` | one serial-linked document classified as structured `audit.type=SYSCALL`; syscall `85`; executable `/usr/bin/tar` | Operation present; retained summary did not demonstrate complete grouping |
| Archive permission change | `12182` | one serial-linked document classified as structured `audit.type=SYSCALL`; syscall `268`; executable `/usr/bin/chmod` | Operation present; retained summary did not demonstrate complete grouping |

Manager-side supporting execution documents were also present for serials
`12173`, `12177`, and `12181`.

This confirms Wazuh manager receipt of all five semantic operations. It does not
complete five-event Wazuh parity because the retained summary did not
demonstrate complete serial-linked groups and did not retain the exact
`full_log` values needed to test the version-matched product expectation.

## Retained-Field Assessment

| Field or capability | Result | Meaning |
|---|---|---|
| Wazuh timestamp and agent identity | Confirmed | Present on all strong scenario documents |
| Manager name and source location | Confirmed | Present on all strong scenario documents |
| `full_log` | Confirmed | Present on all strong scenario documents |
| Audit serial | Confirmed for the `/var/log/audit/audit.log` representation | Core serials matched the local run |
| Structured record type | Confirmed but limited | Each serial-linked document was classified as structured `audit.type=SYSCALL`; exact `full_log` values were not retained |
| Audit key | Confirmed on matching documents | Scenario key survived for relevant records |
| Syscall and executable | Confirmed | Core operations retained syscall numbers and executables |
| Separate `PATH` documents linked by serial | Not demonstrated by retained summary | Local groups had `PATH`; no separate serial-linked manager documents were retained in the summary |
| Separate `CWD` document linked by serial | Not demonstrated by retained summary | Local groups had `CWD`; no separate serial-linked manager document was retained in the summary |
| Separate `EXECVE` document linked by serial | Not demonstrated by retained summary | Supporting local execution groups were multi-record; no separate serial-linked manager document was retained in the summary |
| Structured `PROCTITLE` or separate document linked by serial | Not demonstrated by retained summary | The default decoder has no structured `PROCTITLE` extractor, and exact `full_log` values were not retained |
| `EOE` or equivalent grouping boundary | Not observed | No complete manager-side event boundary was established |
| Journald-located context | Not deterministically groupable | `34` documents lacked an extractable original audit serial in the retained summary |

Some `journald`-located documents retained scenario paths or process context,
but the retained summary does not establish their representation type or a
deterministic join to the serial-bearing audit-log documents.

## Grouping And Duplicate Assessment

The local audit source represented one logical event with multiple records
sharing one serial. In the retained manager summary, each inspected core serial
was represented by one `/var/log/audit/audit.log` document classified with
structured `audit.type=SYSCALL`; the exact grouped `full_log` was not retained.

The additional `journald` representation produced `34` strong documents without
an extractable original audit serial. This creates possible cross-location
overlap or alternate representations, but the bounded summaries do not prove
that they are exact duplicates.

Therefore:

- do not combine `/var/log/audit/audit.log` and `journald` documents additively
- do not use manager document count as event count
- do not reconstruct missing serial links heuristically from timestamps or paths
- keep rsyslog and Wazuh comparison as parity evidence rather than additive
  detection input

## Outcome Classification

The runbook classification is:

```text
Outcome C — Five Observations Present, Complete Grouping Not Demonstrated By Retained Evidence
```

Outcome A is rejected because matching manager-side evidence existed.

Outcome B is rejected because all five expected operations were present.

Outcome D is not reached because the retained manager archive evidence did
not demonstrate the complete `SYSCALL`, `EXECVE`, `CWD`, `PATH`, and
`PROCTITLE` groups under stable serial identity.

## Source Artifact Conclusion

`archives.json` is confirmed as supporting manager-side observability for
Scenario 009. It proves receipt of the five expected operations and preserves
useful envelope, serial, syscall, executable, key, and `full_log` fields.

It is not selected as the canonical Scenario 009 source under the observed
configuration because complete audit grouping is not established from retained
evidence and exact `full_log` values were not retained.

The existing sanitized centralized-auditd fixture remains canonical. The current
auditd parser cannot consume this Wazuh archive result as an equivalent raw
multi-record source without a separate envelope and field-loss boundary. A
narrow adapter alone cannot reconstruct record relationships that were not
preserved.

No sanitized Wazuh fixture should be promoted as a parity fixture from this
Outcome C observation.

## Recommended Next Step

Before implementing normalization or a fixture, investigate the Wazuh collection
and decoding boundary that produced:

- one serial-linked document per core audit event classified in the retained
  structured summary as `audit.type=SYSCALL`; exact `full_log` values were not
  retained, so this does not prove `full_log` was `SYSCALL`-only
- `journald`-located documents without an extractable original audit serial in
  the retained summary
- no separate serial-linked `PATH`, `CWD`, `EXECVE`, or `PROCTITLE` documents in
  the retained summary; exact `full_log` values were not retained

Stage 1 is recorded in
[Wazuh Bounded Evidence Analysis](wazuh_bounded_evidence_analysis.md). Stage 2 is
recorded in
[Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md).
They retain T3 and Outcome C and confirm separate agent collection inputs.
Stage 3 is recorded in
[Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md).
It resolves the expected product path to agent-side audit grouping followed by
archive `full_log` serialization of the incoming payload. Exact bounded
`full_log` values from this historical run remain unavailable. A separate Stage
4 controlled comparison is completed in
[Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md)
and confirms exact grouped-payload identity for one controlled event. It
does not change this Outcome C result.

Only an Outcome D-quality source should proceed to a sanitized parity fixture,
generic adapter, normalization smoke, DSL detection, and incident consumption.

## Confirmed Versus Pending

| Capability | Status |
|---|---|
| Bounded temporary `logall_json` validation | Completed |
| Manager receipt of Scenario 009 evidence | Confirmed |
| All five semantic operations manager-side | Confirmed |
| Agent and source-location metadata | Confirmed |
| Original core audit serials | Confirmed |
| Complete multi-record grouping | Not established from retained evidence |
| Outcome classification | Outcome C |
| `archives.json` supporting observability | Confirmed |
| `archives.json` canonical source suitability | Not established |
| Primary canonical Wazuh source selection | Pending |
| Sanitized Wazuh parity fixture | Pending; not justified by Outcome C |
| Wazuh adapter normalization | Pending |
| Wazuh-path DSL detection | Pending |
| Wazuh-path incident consumption | Pending |

## Explicit Non-Goals

This result does not:

- treat attacker-side structured output as defender evidence
- claim the original raw-archive runner exit code was captured
- treat the separate exit-code follow-up as archive-window evidence
- claim deterministic complete audit grouping
- select `archives.json` as canonical input
- create or approve a sanitized Wazuh fixture
- add a Wazuh adapter or modify the auditd parser
- validate normalization, DSL detection, or incident consumption
- validate continuous production ingestion or Velociraptor
- execute containment or response
- claim exfiltration, ransomware, credential access, compromise, or real-data
  collection

## Relationship To Existing Documents

The operational procedure is defined in
[Scenario 009 Temporary Wazuh Raw Archive Validation](../../../operations/scenarios/scenario009/temporary_wazuh_raw_archive_validation.md).

The wider contract is defined in
[Scenario 009 Wazuh / SIEM Validation Plan](wazuh_siem_validation_plan.md).

The earlier alert-only result is recorded in
[Scenario 009 Wazuh Alerts Inspection](wazuh_alerts_inspection.md).

This document supersedes the earlier uncertainty about whether Wazuh received
the underlying Scenario 009 audit evidence. Receipt is confirmed, while
canonical multi-record source suitability remains unresolved.
