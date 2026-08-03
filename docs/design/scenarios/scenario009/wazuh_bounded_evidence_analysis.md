# Scenario 009 Wazuh Bounded Evidence Analysis

Status: Stage 1 Completed / T3 Retained / Exact Transformation Unresolved

## Purpose

This document records Stage 1 of the
[Scenario 009 Wazuh Audit Transformation Investigation](wazuh_audit_transformation_investigation.md).
It analyzes only the retained bounded summaries from the completed local auditd
and temporary Wazuh raw-archive observations.

No environment inspection, scenario re-execution, configuration change, service
restart, new collection, fixture extraction, adapter design, source-code change,
or test was performed for this analysis. The bounded raw archive window is not
committed to Git and was not reconstructed from incomplete summaries.

Core boundaries:

```text
attacker-side observed effect != defender-side observed artifact
semantic presence != deterministic grouping completeness
retained summary != retained raw document
```

## Evidence Boundary

The analysis uses the following repository records:

- [Wazuh Raw Archive Validation Result](wazuh_raw_archive_validation.md)
- [Wazuh Alerts Inspection](wazuh_alerts_inspection.md)
- [Live Auditd Telemetry Smoke Validation](live_auditd_telemetry_smoke_validation.md)
- [Centralized Rsyslog Auditd Collection Validation](centralized_rsyslog_auditd_collection_validation.md)

The retained evidence establishes:

- a bounded manager archive window of `1026` valid JSON Lines documents
- `55` strong Scenario 009 documents
- agent `001` / `ubuntu-victim01` on all strong documents
- `21` documents located at `/var/log/audit/audit.log`
- `34` documents located at `journald`
- manager receipt of the five expected operations
- serial-bearing manager evidence for the eight known local serials
- one serial-linked document per known serial classified in the retained
  structured summary as `audit.type=SYSCALL`; exact `full_log` values were not
  retained, so this does not prove `full_log` was `SYSCALL`-only
- no extractable original audit serial in the retained summary for the `34`
  `journald`-located documents

The repository does not retain the bounded JSON documents, per-document field
inventory, `full_log` strings, content hashes, or exact timestamp pairs. Those
properties cannot be re-derived from the aggregate record.

## Eight-Serial Comparison

The comparison below distinguishes an exact local record inventory from what the
retained manager-side summary can still prove. `High` confidence means the exact
audit serial was retained manager-side and matched the bounded local run. It does
not mean that complete local multi-record parity was preserved.

| Serial | Known role | Local auditd evidence | Wazuh serial-linked evidence | `full_log` form | Path / argv preservation | Related journald evidence | Correlation confidence |
|---:|---|---|---|---|---|---|---|
| `12173` | `mkdir` execution | 6 records: `CWD`, `EXECVE`, two `PATH`, `PROCTITLE`, `SYSCALL` | One serial-linked document classified as structured `audit.type=SYSCALL`; syscall `59`; executable `/usr/bin/mkdir`; exact `full_log` not retained | Not established from retained summary | No separate serial-linked argument or path document established in the retained summary; `full_log` completeness unverified | The journald subset contained strong Scenario 009 indicator documents; no deterministic association to this serial is established. | High for the serial-bearing audit-log document; not established for journald |
| `12174` | Staging directory creation | 5 records: `CWD`, two `PATH`, `PROCTITLE`, `SYSCALL` | One serial-linked document classified as structured `audit.type=SYSCALL`; syscall `83`; executable `/usr/bin/mkdir`; exact `full_log` not retained | Not established from retained summary | No separate serial-linked `PATH` or command-context document established in the retained summary; `full_log` completeness unverified | The journald subset contained strong Scenario 009 indicator documents; no deterministic association to this serial is established. | High for the serial-bearing audit-log document; not established for journald |
| `12175` | `note.txt` creation | 5 records: `CWD`, two `PATH`, `PROCTITLE`, `SYSCALL` | One serial-linked document classified as structured `audit.type=SYSCALL`; syscall `257`; executable `/usr/bin/bash`; exact `full_log` not retained | Not established from retained summary | No separate serial-linked `note.txt` path document established in the retained summary; `full_log` completeness unverified | The journald subset contained strong Scenario 009 indicator documents; no deterministic association to this serial is established. | High for the serial-bearing audit-log document; not established for journald |
| `12176` | `metadata.json` creation | 5 records: `CWD`, two `PATH`, `PROCTITLE`, `SYSCALL` | One serial-linked document classified as structured `audit.type=SYSCALL`; syscall `257`; executable `/usr/bin/bash`; exact `full_log` not retained | Not established from retained summary | No separate serial-linked `metadata.json` path document established in the retained summary; `full_log` completeness unverified | The journald subset contained strong Scenario 009 indicator documents; no deterministic association to this serial is established. | High for the serial-bearing audit-log document; not established for journald |
| `12177` | `tar` execution | 6 records: `CWD`, `EXECVE`, two `PATH`, `PROCTITLE`, `SYSCALL` | One serial-linked document classified as structured `audit.type=SYSCALL`; syscall `59`; executable `/usr/bin/tar`; exact `full_log` not retained | Not established from retained summary | No separate serial-linked `EXECVE` or command-group document established in the retained summary; `full_log` completeness unverified | The journald subset contained strong Scenario 009 indicator documents; no deterministic association to this serial is established. | High for the serial-bearing audit-log document; not established for journald |
| `12178` | Archive creation | 5 records: `CWD`, two `PATH`, `PROCTITLE`, `SYSCALL` | One serial-linked document classified as structured `audit.type=SYSCALL`; syscall `85`; executable `/usr/bin/tar`; exact `full_log` not retained | Not established from retained summary | No separate serial-linked archive `PATH` or `PROCTITLE` document established in the retained summary; `full_log` completeness unverified | The journald subset contained strong Scenario 009 indicator documents; no deterministic association to this serial is established. | High for the serial-bearing audit-log document; not established for journald |
| `12181` | `chmod` execution | 6 records: `CWD`, `EXECVE`, two `PATH`, `PROCTITLE`, `SYSCALL` | One serial-linked document classified as structured `audit.type=SYSCALL`; syscall `59`; executable `/usr/bin/chmod`; exact `full_log` not retained | Not established from retained summary | No separate serial-linked `EXECVE` or command-group document established in the retained summary; `full_log` completeness unverified | The journald subset contained strong Scenario 009 indicator documents; no deterministic association to this serial is established. | High for the serial-bearing audit-log document; not established for journald |
| `12182` | Archive permission change | 4 records: `CWD`, `PATH`, `PROCTITLE`, `SYSCALL` | One serial-linked document classified as structured `audit.type=SYSCALL`; syscall `268`; executable `/usr/bin/chmod`; exact `full_log` not retained | Not established from retained summary | No separate serial-linked archive `PATH`, mode-context, or `PROCTITLE` document established in the retained summary; `full_log` completeness unverified | The journald subset contained strong Scenario 009 indicator documents; no deterministic association to this serial is established. | High for the serial-bearing audit-log document; not established for journald |

The eight exact serial matches prove manager receipt of corresponding audit-log
representations. They do not prove that the agent transported every local record
or that Wazuh preserved each original group before archive output.

## `full_log` Classification

All `55` strong documents retained `full_log`, but the repository record does not
retain the individual values or structural samples. Stage 1 therefore cannot
reliably classify those values as:

- original single audit line
- reconstructed multi-record event
- decoder-generated summary
- journald message
- other transformed content

The serial-linked documents were classified as structured
`audit.type=SYSCALL` by the bounded validation, but that classification alone
does not prove whether `full_log`
contains one original audit line or generated content representing one record.

Therefore:

- H2 is not confirmed
- H2 is not fully refuted
- no parser or adapter may assume that `full_log` is raw, merged, or complete
- a future raw-document inspection must preserve only sanitized field-shape
  evidence, not the complete observation window

## Journald Document Shape

The `34` strong journald documents shared the retained common envelope recorded
for all strong documents:

- timestamp
- `agent.id`
- `agent.name`
- `manager.name`
- location
- `full_log`
- decoder name

The bounded summary also establishes:

- agent `001` / `ubuntu-victim01`
- location `journald`
- no extractable original audit serial by the prior method
- scenario path or process context in some documents

The retained repository record does not preserve a complete nested-field
inventory for the journald subset. It therefore cannot establish, per document:

- whether syscall, executable, path, argv, command, PID, or process identity were
  structured fields or text inside `full_log`
- whether the audit key was retained consistently
- whether either or both of the two rule-bearing documents among the `55`
  strong documents belonged to the journald subset
- whether a stable non-serial event identity exists
- whether journald documents represent raw messages, decoded summaries, or a
  separate collection path

Timestamp and executable similarity would not be sufficient for deterministic
joining even if those values were retained.

## Duplicate Classification

The existing bounded summaries support the following classification only:

| Duplicate class | Stage 1 result | Reason |
|---|---|---|
| Exact raw-record duplicate within `/var/log/audit/audit.log` | Not established | Raw content and hashes were not retained |
| Same-serial and same-record-type duplicate | Not observed for the eight known serials; not established outside them | Each of the eight known serials had exactly one retained `SYSCALL` document, but raw-content hashes and a complete global duplicate inventory were not retained |
| Exact raw-record duplicate within `journald` | Not established | Raw content and hashes were not retained |
| Transformed duplicate across locations | Possible, not proven | Both locations retained scenario context, but stable cross-location identity is absent |
| Semantic duplicate across audit-log and journald representations | Possible, not proven | Paths or process context may describe the same commands without proving document identity |
| Unrelated concurrent administrative record | Possible | The bounded local window included validation administration; the manager summary is not a complete operation-only inventory |

The safe handling decision remains:

```text
cross-path evidence is parity/supporting evidence, not additive event evidence
```

The `21` documents with Wazuh `location` `/var/log/audit/audit.log` and the `34`
documents with Wazuh `location` `journald` must not be summed into logical event
counts, detection counts, or incident evidence counts.
No deduplication key is defined by this analysis.

## Hypothesis Assessment

| ID | Stage 1 assessment | Supported by current evidence | Not established or limiting evidence | Next evidence boundary |
|---|---|---|---|---|
| H1 | Partially supported | The retained structured summary classified one serial-linked document per known serial as `audit.type=SYSCALL`; exact `full_log` values were not retained | Structured classification does not prove `full_log` was `SYSCALL`-only; decoder intent and runtime payload remain unknown | Stage 2 configuration/definition discovery and Stage 3 version-matched product behavior |
| H2 | Unresolved | All strong documents retained `full_log` | Individual `full_log` values and nested field shapes are not retained; completeness cannot be tested | Sanitized raw-document shape inspection if approved material remains available, otherwise a later controlled comparison |
| H3 | Partially supported | `34` journald documents retained scenario context without an extractable serial | They cannot be proven to contain the missing associated records or be joined to an audit serial | Stage 2 journald collection-path discovery, then field-shape comparison |
| H4 | Unresolved for the historical run | Complete grouping was not demonstrated by retained historical evidence | Stage 4 confirmed complete grouping for one separate controlled event, but cannot establish the earlier runtime payload | Historical Scenario 009 `full_log` remains unavailable |
| H5 | Narrowed by controlled evidence | Semantic operations survive while structured summaries do not demonstrate deterministic grouping | Stage 4 confirmed exact grouped-payload identity after newline removal and single-space joining for one controlled six-record event | Do not generalize one controlled result to the historical run |
| H6 | Controlled archive boundary tested | Stage 4 compared exact local content with one exact manager archive `full_log` | Existing or historical indexer archive data and raw transport artifacts were not inspected | Canonical source selection remains separate |
| H7 | Confirmed at the agent collection boundary | Agent-local `audit.log` and `journald` inputs were configured and read independently | Stage 4 found no matching journald document and did not validate journald ingestion or historical cross-location relationships | Keep journald supporting-only and non-additive |

No hypothesis is promoted to a confirmed product mechanism by Stage 1.

## T1-T4 Narrowing

| Decision | Stage 1 result | Rationale |
|---|---|---|
| T1: Complete multi-record representation found | Not met | The retained summaries did not demonstrate required `PATH`, `CWD`, `EXECVE`, and `PROCTITLE` grouping under stable serial identity |
| T2: Transformed records with deterministic identity | Not met | Deterministic identity exists for documents classified as structured `audit.type=SYSCALL`; exact `full_log` values were not retained, and journald-located context lacks a proven stable join |
| T3: Semantic evidence without deterministic grouping | Best-supported current classification | All five operations are manager-visible, but complete deterministic grouping is not demonstrated by the retained evidence |
| T4: Collection loss confirmed | Not established | The absence of separate records from the retained summary could reflect structured-summary omission, collection, transport, filtering, merging, or representation; Stage 1 cannot locate a loss boundary |

Stage 1 therefore retains the existing Outcome C and T3 decision. This is a
source-suitability decision, not a final conclusion about Wazuh internals.

## Source Decision

`archives.json` remains supporting evidence for manager receipt and semantic
operation presence. It is not selected as the canonical Scenario 009 source.

The sanitized centralized-auditd fixture remains canonical because it preserves
the required deterministic multi-record grouping for normalization and DSL
validation. Stage 1 does not justify:

- a Wazuh parity fixture
- a Wazuh envelope adapter
- heuristic grouping
- cross-location additive evidence
- a configuration change
- normalization, detection, or incident validation through the Wazuh path

## Next Stage

Stage 2 is recorded in
[Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md).
Stage 3 is recorded in
[Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md).

The version-matched source resolves the expected grouping and archive path: the
agent groups consecutive audit records sharing a timestamp and serial before
transport. Manager archive `full_log` is sourced from that incoming grouped
payload. The exact bounded Scenario 009 `full_log` values were not retained, so
T3 and Outcome C remain unchanged. A separate Stage 4 controlled comparison is
completed in
[Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md);
it confirms exact content preservation for one controlled event only.

## Explicit Non-Goals

This analysis does not modify or inspect the live environment, execute Scenario
009, enable `logall_json`, restart services, retain or commit the raw archive
window, invent missing records, create a fixture, implement an adapter, change a
parser or rule, validate Wazuh normalization or detection, execute response, or
change Outcome C.
