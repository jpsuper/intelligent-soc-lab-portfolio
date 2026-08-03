# Scenario 009 Wazuh Collection And Decoder-Path Inspection

Status: Stage 2 Completed / T3 Retained / Runtime Boundary Unresolved At Stage 2

## Purpose

This document records Stage 2 of the
[Scenario 009 Wazuh Audit Transformation Investigation](wazuh_audit_transformation_investigation.md).
It captures a read-only inspection of the deployed Wazuh agent and manager paths
used by `scenario_009_suspicious_archive_staging`.

The inspection narrows where complete local audit multi-record groups may cease
to be available. It does not use product documentation or source-code claims;
version-matched product behavior remains a separate Stage 3 activity.

Core boundaries:

```text
configured input != proven event parity
direct file read != proven complete transport
post-decoder representation != pre-decoder raw transport
current cumulative counter != bounded Scenario 009 counter
```

## Observation Provenance

The read-only observations were performed on `2026-07-12`.

| Item | Observed value |
|---|---|
| Agent host | `ubuntu-victim01` |
| Agent observation time | `2026-07-12T09:10:20Z` |
| Agent package | `wazuh-agent 4.14.4-1` |
| Agent runtime version | `v4.14.4`, revision `rc2` |
| Audit package | `auditd 3.0.7` |
| Manager host | `wazuh-server` |
| Manager observation times | `2026-07-12T09:17:31Z` and `2026-07-12T09:22:00Z` |
| Manager package | `wazuh-manager 4.14.4-1` |
| Manager runtime version | `v4.14.4`, revision `rc2` |
| Filebeat package | `7.10.2-2` |

No raw Scenario 009 archive window, complete configuration dump, credential,
certificate, key, or command-output transcript is committed by this record.

## Read-Only Safety Result

The inspection performed no configuration edit, service restart, `logall` or
`logall_json` change, decoder test, audit-rule change, scenario execution, raw
window collection, fixture extraction, adapter change, source-code change, or
test execution.

Observed configuration hashes were unchanged between the initial and final
checks.

Agent configuration hashes:

```text
de4df0ceda62692db2fb518f761a72552b17dc79346101d5847c9fd55358fed3  /var/ossec/etc/ossec.conf
d76908d51018ec72afc1a7e17fbc3971c6a812446fd930fdba5ed66f1af47ed0  /var/ossec/etc/shared/agent.conf
764d02acb2601feddb36b537c77c78dbe3be99f79ae328c1bf861d33eed6269e  /var/ossec/etc/shared/merged.mg
```

Manager configuration and definition hashes:

```text
fea58b68b8e0d45b27aaaafda079f8bda4f572d00999a4077e5c6413f07a5820  /var/ossec/etc/ossec.conf
73252a6f47fff93d8ce62ca70a8f9196a216d5e09dc2228758fcf0b0ac77133f  /var/ossec/etc/local_internal_options.conf
700c2714cead187b8774b75f5577cbf6d4474bdd9295e66ac0881592c93d645a  /etc/filebeat/filebeat.yml
c6d7a9abe48af3b8c85814733ba5f186c9a2a7e3ffe4a24c75fb548d869ddea2  /var/ossec/ruleset/decoders/0040-auditd_decoders.xml
026f9aeab3c170b9154ec1bb306688d17d3059a97147d6472715fe66b28fc39f  /var/ossec/ruleset/rules/0365-auditd_rules.xml
2f434217b2f894a4cf3164ef6a1f4471d9196e5ad21f19c2e21c5be97b16e26a  /var/ossec/etc/internal_options.conf
```

## Agent Collection Path

The active agent-local `/var/ossec/etc/ossec.conf` contained two separate
`localfile` entries:

```xml
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
</localfile>

<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

No `localfile` block was present in the inspected shared `agent.conf` or
`merged.mg`. The observed inputs are therefore agent-local under the inspected
configuration.

The running `/var/ossec/bin/wazuh-logcollector` process directly held read-only
file descriptors for:

- `/var/log/audit/audit.log`
- multiple system and user journal files below `/var/log/journal/`

This confirms that `audit.log` and `journald` are separate collection inputs at
the agent collection boundary. It does not prove whether semantically related
records are duplicated across those inputs or how either input is packaged for
transport.

## Agent Collection Counters

The retained `wazuh-logcollector.state` snapshot tracked the inputs separately:

| Wazuh `location` | Cumulative events | Cumulative target drops | Last interval events | Last interval drops |
|---|---:|---:|---:|---:|
| `/var/log/audit/audit.log` | `11522` | `0` | `120` | `0` |
| `journald` | `44399` | `823` | `644` | `0` |

The cumulative interval began on `2026-06-10`, not at the Scenario 009 bounded
run. Therefore:

- the audit-input drop counter provides no evidence of target-queue loss
- the journald drop counter proves some historical target drops occurred
- neither cumulative counter locates loss within the Scenario 009 archive window
- the counters do not establish which records, timestamps, or scenarios were
  affected

At inspection time, auditd reported enabled `1`, lost `0`, and backlog `0`.
Those current values remain health evidence, not a reconstructed Scenario 009
transport trace.

## Manager Processing And Output Path

The manager was active with `wazuh-remoted`, `wazuh-analysisd`,
`wazuh-logcollector`, and `wazuh-monitord` running. The active manager
configuration retained:

```xml
<logall>no</logall>
<logall_json>no</logall_json>
```

The running `wazuh-analysisd` process held write descriptors for the current
archive log and alert outputs. The temporary `archives.json` file remained on
disk with its last modification during the prior temporary `logall_json`
validation, while the current process did not hold it open after rollback.

Combined with the decoded fields previously observed in archive documents, this
strongly localizes `archives.json` to the `wazuh-analysisd` output boundary at
or after decoding and analysis processing. It is not an inspected pre-decoder transport
artifact.

The current manager state files reported:

- `wazuh-remoted` discarded messages: `0`
- `wazuh-analysisd` dropped events: `0`
- current event, rule, alert, and archive queue usage: `0.00`

However, `wazuh-remoted` and `wazuh-analysisd` restarted during the earlier
rollback sequence, after the bounded archive output had been written. These
post-restart counters cannot prove that no drop occurred during the Scenario 009
window.

## Deployed Audit Decoder And Rule Shape

The default audit decoder file was the only audit-specific deployed decoder
definition identified:

```text
/var/ossec/ruleset/decoders/0040-auditd_decoders.xml
```

The parent decoder accepts audit-formatted input beginning with `node=... type=`
or `type=`. The `auditd-syscall` decoder:

- begins with `SYSCALL` or `EXECVE`
- extracts `audit.type` and `audit.id`
- extracts syscall, process, executable, and audit-key fields
- includes child expressions for `EXECVE` arguments
- includes child expressions for `CWD`
- includes child expressions for directory and file `PATH` data

The file's example input contains `SYSCALL`, `CWD`, multiple `PATH`, and
`PROCTITLE` records concatenated into one text value. The XML includes no
`PROCTITLE` field extractor in the inspected definition.

The static decoder definition shows parsing expressions that can consume
associated record text when it is already present in the same input value. It
does not, by itself, demonstrate a cross-message serial cache or identify which
component assembles separate audit lines into one input value.

The base audit rule `80700` describes audit messages as grouped, but a rule
description is not sufficient evidence for the implementation boundary or the
runtime grouping mechanism.

No matching custom audit-specific decoder or rule definition was discovered in
the inspected local decoder and rule directories. The default definitions were
the only audit-specific deployed definitions identified. Stage 2 did not
re-execute the scenario, run a decoder test, or prove the runtime decoder
selection for the retained documents.

## Filebeat And Alternate Artifact Inspection

The active Filebeat Wazuh module configuration was:

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false
```

The running Filebeat process held `alerts.json` open and did not hold
`archives.json` open. The installed Wazuh Filebeat module includes an optional
archive input definition, but it was disabled in the active configuration.

No active Filebeat archive ingestion path was identified. Existing or historical
indexer archive data was not inspected. This finding is limited to the inspected
deployed paths; it is not a universal claim that no other Wazuh export mode can
preserve more complete content.

## Restored Backup Observation

The protected temporary backup remained present:

```text
/var/ossec/etc/ossec.conf.scenario009-20260712T012133Z.bak
```

Its SHA-256 matched the active restored `ossec.conf`:

```text
fea58b68b8e0d45b27aaaafda079f8bda4f572d00999a4077e5c6413f07a5820
```

This is consistent with the prior rollback record, which did not claim that the
protected backup was removed. Stage 2 did not delete it.

## Narrowed Processing Model

| Boundary | Stage 2 result | Remaining limit |
|---|---|---|
| Local auditd groups | Confirmed by prior validation | No new Scenario 009 execution was performed |
| Agent audit input | Direct agent-local `log_format=audit` input confirmed | Exact line-to-message packaging is not established |
| Agent journald input | Separate direct agent-local input confirmed | Cross-input semantic duplication remains unresolved |
| Agent output queue | Audit cumulative drops `0`; journald cumulative drops `823` | Counters are not bounded to Scenario 009 |
| Agent transport | Manager receipt already confirmed | Per-record transported content was not captured |
| Manager remoted | Active; post-restart discarded count `0` | Scenario-window counters were reset by restart |
| Audit decoder | Can parse associated fields when co-located in one input | Group assembly component and runtime input shape remain unknown |
| Analysis/output | `archives.json` strongly localized to the analysisd output boundary | Exact pre-decoder input was not inspected |
| Filebeat/indexer | Alerts enabled; archives disabled | No active Filebeat archive ingestion path was identified; existing or historical indexer archive data was not inspected |

Stage 2 narrows the unresolved grouping boundary to the path between agent-side
audit input packaging and the manager analysisd representation. It does not
distinguish complete grouped content in `full_log` from structured-summary
omission or an earlier incomplete-payload boundary.

## Hypothesis Assessment After Stage 2

| ID | Stage 2 assessment | Evidence update | Remaining limit |
|---|---|---|---|
| H1 | Not confirmed as a decoder-only mechanism | The deployed decoder can extract `EXECVE`, `CWD`, and `PATH` data when associated text is co-located | Static XML does not show the runtime input or grouping component |
| H2 | Unresolved | Decoder capability makes complete associated content in `full_log` technically relevant | Retained `full_log` values and complete nested field inventories are unavailable |
| H3 | Partially supported and narrowed | Journald is a separate direct collection input, not a manager-created display of the audit input | Missing associated records and deterministic cross-input identity remain unproven |
| H4 | Weakened but not refuted | Audit input reported cumulative target drops `0`; current auditd health was clean | No bounded per-record agent transport trace exists |
| H5 | Partially supported | `archives.json` is strongly localized to an analysisd output representation and no earlier inspected manager artifact was found | The transformation may occur during agent packaging, transport, decoding, or output serialization |
| H6 | Not found in inspected deployed paths | Filebeat archives were disabled and no earlier manager artifact was identified | Stage 4 later validated the existing manager archive `full_log` boundary; existing or historical indexer archive data remains uninspected |
| H7 | Confirmed at the agent collection boundary | `audit.log` and `journald` are separate configured inputs read directly by logcollector | Exact and semantic duplication across the two inputs remains unresolved |

No hypothesis is promoted to a final Wazuh product mechanism by Stage 2.

## T1-T4 Decision

| Decision | Stage 2 result | Rationale |
|---|---|---|
| T1: Complete multi-record representation found | Not met | No inspected deployed output exposed deterministic complete groups |
| T2: Transformed records with deterministic identity | Not met | Journald remains without a proven stable join, and archive group completeness is unverified because exact `full_log` values were not retained |
| T3: Semantic evidence without deterministic grouping | Retained | Five operations remain manager-visible while complete grouping is not demonstrated by retained evidence |
| T4: Collection loss confirmed | Not established | Current and cumulative counters cannot localize Scenario 009 loss, and the exact packaging boundary remains unresolved |

Outcome C remains unchanged.

## Source Decision

`archives.json` remains supporting evidence only. No active Filebeat archive
ingestion path was identified, existing or historical indexer archive data was
not inspected, and no inspected alternate manager artifact justified replacing
the sanitized centralized-auditd fixture as the canonical Scenario 009 source.

Stage 2 does not justify:

- a Wazuh parity fixture
- a Wazuh envelope adapter
- heuristic cross-input joining
- additive audit-log and journald evidence
- enabling archive indexing
- a collection or decoder configuration change
- normalization, detection, incident, or response validation through Wazuh

## Next Stage

Stage 3 is recorded in
[Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md).
It confirms from Wazuh `v4.14.4` source that agent logcollector groups consecutive audit
records sharing a timestamp and serial before transport, and that manager archive
`full_log` is initialized from the incoming grouped payload before decoder field
serialization.

The retained Scenario 009 summaries do not include exact `full_log` values. A
separate Stage 4 controlled comparison later confirmed the source-defined path
for one controlled event and is recorded in
[Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md).
That result does not recover the earlier Scenario 009 value.

## Explicit Non-Goals

This inspection does not execute Scenario 009, inspect a new raw bounded window,
change `logall_json`, restart services, delete the protected backup, alter audit
rules, test decoder behavior, claim complete product internals, create a fixture,
implement an adapter, modify parsing or detection, execute response, or change
Outcome C.
