# Scenario 009 Wazuh Audit Grouping Product Verification

Status: Stage 3 Completed / Product Path Resolved / T3 Retained / Stage 4 Completed Separately

## Purpose

This document records Stage 3 of the
[Scenario 009 Wazuh Audit Transformation Investigation](wazuh_audit_transformation_investigation.md).
It verifies the expected Wazuh `v4.14.4` audit grouping and archive behavior from
version-matched Wazuh primary source code.

Stage 3 answers product-behavior questions that could not be answered from the
retained Scenario 009 summaries alone. It does not claim that the deployed
binary executed every inspected branch exactly as the source predicts, and it
does not replace the observed lab evidence recorded by Stages 1 and 2.

Core boundaries:

```text
version-matched source behavior != captured runtime proof
structured audit fields != complete grouped audit text
archive full_log path != proof that the retained Scenario 009 value was complete
Filebeat archive indexing != an earlier raw collection boundary
```

## Reference Identity

The primary product reference is the official `wazuh/wazuh` repository tag:

```text
tag: v4.14.4
commit: 5933ec9ebee76fb2546e5f7fc9f3a27d0aeca605
```

The inspected lab reported:

```text
wazuh-agent package: 4.14.4-1
wazuh-manager package: 4.14.4-1
runtime version: v4.14.4
runtime revision: rc2
```

The source tag is version-matched to the reported product version. Stage 3 did
not reproduce the package build, compare installed binary hashes with release
artifacts, or prove byte-for-byte deployed-binary provenance.

## Primary Sources Reviewed

| Source | Product boundary established |
|---|---|
| `src/logcollector/read_audit.c` | Agent-side audit record grouping, cache and message limits, queue submission |
| `src/logcollector/logcollector.c` | `log_format=audit` reader selection and target queue handling |
| `src/shared/mq_op.c` | Local queue envelope and message dispatch |
| `src/shared/log_builder.c` | Optional output-format transformation; unformatted payload preservation |
| `src/headers/defs.h` | `OS_MAX_LOG_SIZE` and related size limits |
| `src/analysisd/cleanevent.c` | Manager queue-envelope removal and `full_log` initialization |
| `src/analysisd/analysisd.c` | Decode, rule, and archive-writer queues |
| `src/analysisd/output/jsonout.c` | JSON archive writer selection |
| `src/analysisd/format/to_json.c` | `full_log`, dynamic field, and decoder serialization |
| `src/analysisd/format/json_extended.c` | Nested dynamic JSON field handling |
| `src/shared/string_op.c` | Duplicate dynamic JSON key behavior |
| `ruleset/decoders/0040-auditd_decoders.xml` | Audit structured-field extraction coverage |

The current Wazuh event-logging documentation was used only as supplementary
confirmation that `logall_json` writes `archives.json` and that Filebeat archive
ingestion indexes that archive output. Version-specific conclusions in this
document are based on the `v4.14.4` source tag.

## Product Path Result

The version-matched product path is:

```text
/var/log/audit/audit.log
  -> agent wazuh-logcollector read_audit()
  -> group consecutive records by msg=audit(timestamp:serial)
  -> concatenate group records with single spaces
  -> enqueue one LOCALFILE_MQ message
  -> agent transport / manager remoted path
  -> analysisd OS_CleanMSG()
  -> Eventinfo.full_log = incoming message payload
  -> decode the duplicated parsing buffer
  -> archive writer queue
  -> Eventinfo_to_jsonstr(force_full_log=true)
  -> archives.json full_log
```

This resolves the expected product grouping location: assembly of consecutive
audit records that share one timestamp-and-serial header is an agent-side
`wazuh-logcollector` function performed before transport to the manager.

## Agent-Side Audit Grouping

For a `localfile` configured with `log_format=audit`, Wazuh selects
`read_audit()`.

The `v4.14.4` audit reader:

1. reads audit file lines
2. extracts the value between `msg=audit(` and `):`
3. uses that timestamp-and-serial value as the event header
4. caches consecutive lines that share the same header
5. sends the previous cache when the header changes
6. sends any remaining cache when the read loop ends

The cached lines are concatenated into one message separated by single spaces.
The complete concatenated message, rather than one source line at a time, is
submitted to the logcollector target queue.

Therefore, Wazuh does not rely on the manager audit decoder to reconstruct
separate audit lines by serial. The expected multi-record grouping occurs on the
agent before the message enters the agent output queue.

## Grouping Limits

The relevant `v4.14.4` limits are:

```text
MAX_CACHE = 16 records
OS_MAXSTR = 65536 bytes
OS_LOG_HEADER = 256 bytes
OS_MAX_LOG_SIZE = 65280 bytes
```

The audit reader also discards an individual source line that reaches the
maximum line buffer without a newline.

When the cache already contains 16 records, an additional record for the same
header is rejected with a cache-full error. When concatenating cached records,
a record that would exceed the grouped message buffer is not appended.

The previously observed Scenario 009 local groups contained between four and
six records. They did not reach the 16-record cache-count limit. Stage 1 did not
retain exact grouped byte lengths, so Stage 3 does not exclude an individual
line-size or total grouped-message-size condition from source review alone.

## Queue And Transport Representation

The grouped audit message is copied into the logcollector target queue as a
`LOCALFILE_MQ` event. The output thread sends that message through the normal
agent target path.

The deployed Stage 2 audit `localfile` entry did not contain a custom output
format. Under the source behavior, an absent output pattern preserves the input
message payload, while the queue layer adds the message type and escaped
location envelope.

Stage 3 identifies the expected payload shape before manager intake. It does not
provide a captured Scenario 009 transport packet or prove that no queue,
connection, or manager-input loss occurred during the bounded run.

## Manager `full_log` Boundary

On manager intake, `OS_CleanMSG()` removes the queue envelope and copies the
message body into `Eventinfo.full_log`. It creates a second copy for
`Eventinfo.log`, which is the mutable parsing buffer used by pre-decoding,
decoding, and rules.

This separation is important:

```text
Eventinfo.full_log = original incoming message body
Eventinfo.log      = separate parsing copy
```

Decoder parsing can advance pointers or extract structured fields without
reconstructing `full_log` from those fields.

When `logall` or `logall_json` is enabled, analysisd copies the Eventinfo object
to the archive writer queue. The JSON archive writer calls
`Eventinfo_to_jsonstr(..., force_full_log=true, ...)`, which adds
`Eventinfo.full_log` to the JSON document.

The version-matched source therefore predicts that `archives.json.full_log`
contains the grouped message received by analysisd, independently of which
audit fields the decoder extracts.

## Structured Audit Decoder Behavior

The default `v4.14.4` audit decoder expects associated audit records to already
be co-located in one input string. Its example input contains a concatenated
`SYSCALL`, `CWD`, multiple `PATH`, and `PROCTITLE` group.

The structured decoder definitions include extraction for:

- `audit.type` and `audit.id`
- syscall and process fields
- audit key
- `EXECVE` argument count and arguments `a0` through `a7`
- `CWD`
- one directory-shaped `PATH` field set
- one file-shaped `PATH` field set

The inspected definition has no structured `PROCTITLE` extractor.

The structured PATH fields are scalar names such as:

```text
audit.directory.name
audit.directory.inode
audit.directory.mode
audit.file.name
audit.file.inode
audit.file.mode
```

They are not defined as an ordered array of every PATH record. Dynamic fields
are serialized into nested JSON objects, and the JSON field builder does not add
a second value when the target key already exists. The exact PATH occurrence
selected by the decoder regex engine was not executed or tested by Stage 3.

Consequently:

- structured `audit.type=SYSCALL` does not prove that `full_log` contains only a
  SYSCALL source record
- absence of structured `PROCTITLE` is expected even when PROCTITLE text remains
  inside `full_log`
- structured PATH fields cannot be treated as a lossless ordered representation
  of every PATH record

## Filebeat And Archive Indexing

The supported Filebeat archive path reads manager `archives.json` after the
manager archive has already been produced. Enabling Filebeat archive ingestion
can index and visualize archive documents, but it does not create a pre-decoder
or pre-analysis copy of the agent transport message.

Therefore, Filebeat archive indexing cannot by itself increase event fidelity
beyond the content already present in `archives.json`. Existing or historical
indexer archive data in the lab remains uninspected.

## Reconciliation With Lab Evidence

Stage 1 established that the bounded summaries retained:

- eight serial-linked documents
- structured serial identity for all known serials
- structured record type `SYSCALL` for each serial-linked document
- semantic coverage of all five expected operations
- no retained proof of complete serial-linked `PATH`, `CWD`, `EXECVE`, and
  `PROCTITLE` grouping

Stage 3 establishes a product expectation that differs from a simplistic
interpretation of that summary:

```text
structured audit.type may be SYSCALL
while
full_log may still contain the full grouped audit text
```

The retained Stage 1 summaries do not include the exact `full_log` values, so
Stage 3 cannot determine which of these explanations applies:

### Explanation A: Complete `full_log`, incomplete structured summary

The agent assembled and transported complete groups, `archives.json.full_log`
retained them, but the prior assessment classified the document primarily by
structured `audit.type` and did not retain every type marker in `full_log`.

### Explanation B: Incomplete grouped payload before manager `full_log`

One or more associated records were omitted because of source-line limits,
group-message limits, agent queue loss, transport loss, manager input loss, or
another runtime condition before `OS_CleanMSG()` copied the payload.

### Explanation C: Runtime or package behavior differs from the inspected tag

The deployed package or runtime path differed from the expected `v4.14.4` source
behavior. Stage 3 has no evidence confirming this explanation; it remains a
provenance boundary rather than a selected hypothesis.

The later Stage 4 controlled comparison distinguished these explanations for
one controlled event: the manager `full_log` had exact grouped-payload identity
with the completed contiguous six-record local event after newline removal and
single-space joining. It did not recover the historical Scenario 009 value.

## Hypothesis Assessment After Stage 3

| ID | Stage 3 assessment | Product-source update | Remaining lab limit |
|---|---|---|---|
| H1 | Rejected as a complete decoder-only explanation | Decoder field coverage is lossy, but archive `full_log` is sourced from the incoming grouped payload rather than reconstructed from decoded fields | Exact retained Scenario 009 `full_log` values are unavailable |
| H2 | Strongly supported as product-expected, not lab-confirmed | `archives.json` is forced to include `Eventinfo.full_log`, which is initialized from the incoming message body | The bounded summaries did not retain the values needed to verify complete groups |
| H3 | Unchanged | Product research does not create a deterministic serial join for the separate journald input | Cross-input duplication remains unresolved |
| H4 | Narrowed | Agent logcollector is responsible for grouping; local groups did not hit the 16-record limit | Exact byte lengths and bounded queue/transport evidence are unavailable |
| H5 | Narrowed substantially | Grouping occurs before transport and `full_log` is copied before decoder field serialization | Any incomplete `full_log` must be explained before or at manager payload intake, or by runtime divergence |
| H6 | No higher-fidelity Filebeat path identified | Filebeat archives consume manager `archives.json`, not an earlier transport artifact | Other controlled capture points were not exercised |
| H7 | Unchanged | Audit-log grouping behavior does not resolve journald semantic duplication | Pairwise bounded comparison remains required only if both locations are considered for ingestion |

No lab hypothesis is promoted to a final observed mechanism by source review
alone.

## T1-T4 Decision

| Decision | Stage 3 result | Rationale |
|---|---|---|
| T1: Complete multi-record representation found | Not met in retained lab evidence | Source predicts complete grouped `full_log`, but the exact Scenario 009 value was not retained |
| T2: Transformed records with deterministic identity | Not met | Structured fields remain lossy for repeated PATH and PROCTITLE, and journald has no proven stable join |
| T3: Semantic evidence without deterministic grouping | Retained | This remains the strongest conclusion supported by retained lab evidence |
| T4: Collection loss confirmed | Not established | Source review identifies possible limits and queues but does not prove a Scenario-window loss |

Outcome C remains unchanged. The source review increases confidence that a
complete grouped representation may exist in `full_log`, but source expectation
is not a substitute for the missing bounded runtime value.

## Canonical Source Decision

The sanitized centralized-auditd fixture remains canonical. `archives.json`
remains supporting evidence until a controlled comparison demonstrates that its
`full_log` preserves complete deterministic groups for the required operations.

Stage 3 does not justify:

- promoting `archives.json` to canonical input
- creating a Wazuh parity fixture from unretained values
- treating scalar decoded PATH fields as complete PATH arrays
- reconstructing PROCTITLE from structured fields
- combining audit-log and journald documents additively
- enabling archive indexing as a fidelity fix
- changing agent, manager, decoder, normalization, detection, incident, or
  response behavior

## Stage 4 Result

Stage 4 is completed and recorded in
[Scenario 009 Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md).
It resolved the controlled product-path question as
`EXACT_CONTENT_PRESERVED` / T1-equivalent controlled evidence while leaving the
historical Scenario 009 T3 and Outcome C classifications unchanged.

The controlled comparison:

1. used controlled synthetic Scenario 009 data only
2. predefined a bounded time window and a unique run-specific target path, then
   selected the exact shared audit serial for the probe event
3. retained exact local audit lines temporarily outside Git
4. temporarily captured the exact `archives.json.full_log` value under the
   approved rollback procedure
5. calculated, for serial `15157`:
   - local record count and ordered record types
   - local grouped byte length
   - archive `full_log` byte length
   - count and order of `type=` markers in `full_log`
   - count of matching serial markers in `full_log`
   - structured decoder name and audit fields
6. assessed journald-located documents separately and non-additively
7. committed no raw evidence or comparison fixture
8. restored configuration and verified manager health

The comparison used no network interception, unsupported queue tapping,
persistent archive indexing, or production data.

## Stage 4 Decision Result

| Controlled result | Decision |
|---|---|
| `full_log` matches the complete local group for every required serial | Promote to T1 candidate and design a sanitized Wazuh parity fixture in a later PR |
| `full_log` is complete but structured fields are lossy | Keep `full_log` as candidate extraction boundary; do not use structured fields as complete grouping evidence |
| `full_log` is incomplete with a reproducible limit or drop boundary | Record T4 only if the exact loss boundary is demonstrated |
| Results vary or cannot be reproduced | Retain T3 and the existing canonical fixture |
| Journald overlaps without deterministic identity | Keep journald supporting-only and non-additive |

The observed row was exact content preservation: the completed local records,
after newline removal and single-space joining, matched manager `full_log` by
byte length and SHA-256. Structured fields remained a lossy content summary.

## Explicit Non-Goals

Stage 3 does not inspect or modify the live environment, execute Scenario 009,
enable `logall_json`, restart services, run a decoder test, capture transport
traffic, delete backups, create a fixture, implement an adapter, change parser or
rule behavior, enable Filebeat archives, alter canonical source selection, or
change Outcome C.
