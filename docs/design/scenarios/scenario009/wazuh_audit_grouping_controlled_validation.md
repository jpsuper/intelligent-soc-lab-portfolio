# Scenario 009 Wazuh Audit Grouping Controlled Validation

Status: Stage 4 Completed / EXACT_CONTENT_PRESERVED / T1-Equivalent Controlled Evidence

## Purpose

This document records the completed Stage 4 controlled comparison defined by
the
[Scenario 009 Wazuh Audit Transformation Investigation](wazuh_audit_transformation_investigation.md).
It compares one bounded local Linux Audit event with the corresponding Wazuh
manager `archives.json.full_log` representation.

This is separate product-path evidence. It does not recover the exact
`full_log` from the earlier Scenario 009 run, upgrade that historical evidence
from T3, or change its Outcome C classification.

Core boundaries:

```text
controlled product-path evidence != historical Scenario 009 evidence
structured audit.type=SYSCALL != complete full_log contents
incomplete local snapshot != completed local audit group
one controlled event != universal Linux Audit behavior
```

## Controlled-Run Scope

| Item | Observed value |
|---|---|
| Run ID | `20260713T121527Z` |
| Victim | `ubuntu-victim01` |
| Wazuh manager | `4.14.4`, runtime revision `rc2` |
| Selected audit serial | `15157` |
| Probe executable | `/usr/bin/touch` |
| Source location | `/var/log/audit/audit.log` |
| Final classification | `EXACT_CONTENT_PRESERVED` |
| Evidence tier | T1-equivalent controlled evidence |

The probe was selected through a unique run-specific target path,
`/usr/bin/touch` `SYSCALL`, and the exact shared audit serial. No temporary
Linux Audit rule was used in the final run.

## Environment And Safety Boundaries

Manager JSON archive capture was temporarily enabled with:

```text
<logall_json>yes</logall_json>
```

Rollback completed successfully and confirmed:

```text
<logall_json>no</logall_json>
wazuh-manager active
rollback marker confirmed
```

No configuration backup, raw audit line, archive document, runtime transcript,
credential, key, generated evidence, or validation script is committed by this
documentation update.

## Local Event Structure

The completed victim `/var/log/audit/audit.log` contained six newline-terminated
records for serial `15157` in this order:

1. `SYSCALL`
2. `EXECVE`
3. `CWD`
4. `PATH`
5. `PATH`
6. `PROCTITLE`

The records were contiguous in one consecutive chunk. Their six record bodies,
excluding trailing newline delimiters, totaled `1394` UTF-8 bytes.

The audit configuration used `log_format = ENRICHED`,
`flush = INCREMENTAL_ASYNC`, and `freq = 50`.

## Manager Archive Result

The bounded manager archive contained exactly one matching document with Wazuh
`location` `/var/log/audit/audit.log`. No matching `journald` document was
found, so this run does not validate journald ingestion.

The matching `full_log` contained all six records once, in their original
order, and contained only serial `15157`:

1. `SYSCALL`
2. `EXECVE`
3. `CWD`
4. `PATH`
5. `PATH`
6. `PROCTITLE`

The same document exposed structured `audit.type=SYSCALL`. That scalar field did
not represent the complete multi-record contents of `full_log`.

The manager `full_log` was `1399` UTF-8 bytes with SHA-256:

```text
48e66a926e56650115f6a2601a79bb29fc6e12d2adecb6ab22c97ea5166eff7e
```

## Content Comparison

The validation applied the source-defined audit framing before comparison:

1. remove the trailing newline from each completed local record
2. preserve the six-record order
3. join the record bodies with one ASCII space between adjacent records

The five separator spaces produced a `1399`-byte grouped representation. Its
SHA-256 was:

```text
48e66a926e56650115f6a2601a79bb29fc6e12d2adecb6ab22c97ea5166eff7e
```

That newline-stripped, single-space-joined grouped representation matched the
manager `full_log` by byte length and SHA-256. This is exact grouped-payload
identity, not a claim that the raw newline-delimited audit-log slice was
directly identical to `full_log` byte-for-byte.

The interpreted fields previously attributed to the Wazuh path were already
present in the completed local audit log because auditd used the `ENRICHED`
format. This validation does not attribute those fields to Wazuh.

## Superseded Harness Snapshot

The initial victim snapshot was incomplete. The harness stabilized only on
serial, record count, and record types; it did not require newline termination,
stable record byte lengths, or stable content hashes. It therefore captured the
event before the local audit representation was fully written.

The resulting initial `MISMATCH` is a superseded harness observation, not the
final controlled result. Its partial bytes, apparent chunk layout, and hash are
not authoritative evidence and are not retained in this document.

## Final Classification

```text
EXACT_CONTENT_PRESERVED
```

| Property | Result |
|---|---|
| Record completeness | Confirmed for the controlled event |
| Record order | Confirmed for the controlled event |
| Serial integrity | Confirmed for serial `15157` |
| Multi-record grouping in Wazuh `full_log` | Confirmed for the controlled event |
| Original content preservation | Confirmed |
| Completed local group contiguity | Confirmed; one consecutive chunk |
| Newline termination | Confirmed for all six records |
| Exact grouped-payload identity | Confirmed after newline removal and single-space joining |

The final comparison uses the completed local audit group rather than the
superseded initial snapshot.

## Evidence Tier

The final run is T1-equivalent controlled evidence because it provides
deterministic identity through the exact serial and unique target path, six
complete ordered records, one manager-side `full_log`, and byte identity after
the source-defined newline-to-space framing.

It does not change the original Scenario 009 evidence tier from T3. The earlier
run did not retain its exact Wazuh `full_log`, so its group completeness remains
unverified and its Outcome C result remains unchanged.

## Impact On Product-Path Assessment

The controlled run supports these bounded conclusions:

- Wazuh preserved the ordered content of all six Linux Audit records in one
  manager `full_log` for the controlled event.
- Structured `audit.type=SYSCALL` did not mean `full_log` was `SYSCALL`-only.
- The completed local records, after newline removal and single-space joining,
  matched manager `full_log` by byte length and SHA-256.
- Interpreted fields were already present in the completed local audit log and
  are not attributed to Wazuh by this validation.
- Filebeat archive ingestion is not needed to establish this manager archive
  boundary.

This result validates the expected Stage 3 product path for one controlled
execution. It does not prove universal Wazuh behavior, inspect existing or
historical indexer data, or establish the exact historical `full_log` from
Scenario 009.

## Impact On Original Scenario 009

The original Scenario 009 record remains:

- T3
- Outcome C
- `archives.json` supporting evidence
- sanitized centralized-auditd fixture as the canonical validation baseline

The Stage 4 result resolves the separate controlled product-path question. It
does not independently select a canonical Wazuh source, justify a Wazuh parity
fixture or adapter, or validate Wazuh-path normalization, detection, incident
consumption, continuous ingestion, Velociraptor, response, or containment.

## Remaining Limitations

- The exact historical Scenario 009 `full_log` remains unknown.
- Journald ingestion and cross-location duplication were not validated.
- The result covers one controlled synthetic event and is not universal.
- Canonical Wazuh source selection and downstream behavioral validation remain
  separate future decisions.

## Relationship To Existing Documents

- [Scenario 009 Overview](overview.md)
- [Wazuh Audit Transformation Investigation](wazuh_audit_transformation_investigation.md)
- [Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md)
- [Wazuh Bounded Evidence Analysis](wazuh_bounded_evidence_analysis.md)
- [Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md)
- [Wazuh Raw Archive Validation](wazuh_raw_archive_validation.md)
- [Wazuh / SIEM Validation Plan](wazuh_siem_validation_plan.md)
