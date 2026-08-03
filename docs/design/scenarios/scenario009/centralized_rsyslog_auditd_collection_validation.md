# Scenario 009 Centralized Rsyslog Auditd Collection Validation

## Purpose

This document records centralized rsyslog collection validation for
`scenario_009_suspicious_archive_staging`.

The validation proves that raw auditd records generated on `ubuntu-victim01`
for scenario activity reached the centralized rsyslog destination on
`soc-analyzer`. It also records a duplicate-forwarding issue that was diagnosed
and corrected.

This is raw log transport validation. A follow-on focused normalization smoke
now proves a sanitized minimal live-derived centralized auditd fixture can be
parsed into grouped auditd events, converted to schema-valid
`endpoint_events.json`, and compared semantically with the synthetic
`scenario_009` fixture. A follow-on live-derived DSL detection smoke evaluates
those normalized fixture events with the existing `suspicious_archive_staging`
rule and produces one archive-staging hit for the normalized `tar` archive
event. The existing incident bridge now consumes that canonical hit and produces
a schema-valid, observation-level incident. A focused boundary-chain smoke then
passes that incident through the existing triage, investigation, and action
paths. Triage remains low-confidence and bounded, investigation retains possible
collection preparation as a hypothesis, and the action playbook remains
advisory, non-destructive, and human-gated. These smokes do not prove Wazuh
ingestion or alerting, SIEM validation, Velociraptor collection, direct ingestion
of the continuously growing production log, or response execution.

The proposed Wazuh / SIEM follow-on contract is defined in
[Scenario 009 Wazuh / SIEM Validation Plan](wazuh_siem_validation_plan.md).
The Wazuh 4.14.4 server/agent topology and agent-local audit collection
configuration are now recorded in
[Scenario 009 Wazuh Collection Environment](wazuh_collection_environment.md).
Manager `alerts.json` exists, but raw archives are disabled. A controlled
follow-on inspection is recorded in
[Scenario 009 Wazuh Alerts Inspection](wazuh_alerts_inspection.md):
all five local auditd observations were present, while the manager alert file
contained zero matching scenario documents. `alerts.json` is not canonical.
A later bounded raw-archive observation confirmed manager receipt and all five
operations. Its retained structured summary classified each serial-linked
document as `SYSCALL`, but it did not retain exact `full_log` values; see
[Scenario 009 Wazuh Raw Archive Validation Result](wazuh_raw_archive_validation.md).
The result is Outcome C and the primary canonical Wazuh source remains unresolved.

Core boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

## Relationship To Earlier Validations

The validation ladder before this point is:

1. [Scenario 009 Runner-Only Smoke Validation](runner_only_smoke_validation.md):
   the runner created expected target-side artifacts on `ubuntu-victim01`.
2. [Scenario 009 Live Auditd Raw Telemetry Smoke Validation](live_auditd_telemetry_smoke_validation.md):
   local auditd generated raw defender-side records for the runner activity.
3. This document: those raw auditd records were centrally collected by rsyslog
   on `soc-analyzer`.

The current live-derived DSL detection is fixture-driven replay: centralized
auditd records are represented by the sanitized minimal fixture, normalized into
endpoint events, and evaluated by the existing DSL rule. It is not direct
continuous ingestion from the production log.

## Normalization Smoke

A focused centralized auditd normalization smoke test is implemented at
`tests/test_scenario009_centralized_auditd_normalization_smoke.py`.

It uses the sanitized minimal live-derived fixture at
`tests/fixtures/scenario_009_suspicious_archive_staging/centralized_auditd_smoke.txt`.
The fixture preserves only the records needed to exercise grouping,
deduplication, explicit scenario-evidence selection, file/syscall evidence, and
endpoint-event conversion. It is not the full captured centralized audit log.

The smoke validates:

- raw rsyslog-prefixed auditd records group into audit events
- exact duplicate raw records do not create duplicate normalized events
- distinct `PATH` records in one audit event are retained
- validation administration and failed cleanup records are excluded by explicit
  scenario-evidence selection in the smoke test
- `mkdir`, synthetic file creation, archive creation, and `chmod` are represented
- normalized endpoint events validate against `schemas/endpoint_events.schema.json`
- semantic coverage overlaps the synthetic `scenario_009` endpoint fixture

Expected differences remain acceptable: live-derived auditd shape can preserve
raw syscall semantics differently from the manually authored synthetic fixture.
This smoke does not rewrite the synthetic fixture. A separate live-derived DSL
detection smoke evaluates the normalized fixture events and confirms the
existing scenario rule detects the normalized `tar` archive event while the
synthetic detection coverage remains valid.

## Live-Derived DSL Detection Smoke

A focused live-derived DSL detection smoke test is implemented at
`tests/test_scenario009_live_derived_dsl_detection_smoke.py`.

The smoke uses the same explicit scenario-evidence selection as the
normalization smoke:

```text
sanitized centralized auditd fixture
  -> auditd parsing and grouping
  -> explicit scenario-evidence selection
  -> endpoint-event conversion
  -> suspicious_archive_staging DSL evaluation
  -> one archive-staging detection hit
```

The hit corresponds to the normalized `tar` archive-creation event for
`staged_synthetic_files.tar.gz`. The rule remains generic to the archive command
shape and does not depend on the synthetic temporary base path or the
live-derived audit-smoke base path. The test also asserts that `mkdir`,
`note.txt`, `metadata.json`, `chmod`, `auditctl`, `CONFIG_CHANGE`, validation
`grep`, and failed stale cleanup records do not independently produce the
archive-staging hit.

This is still fixture-driven replay from a sanitized minimal live-derived
fixture. It is not direct continuous production-log ingestion, not Wazuh / SIEM
coverage, not Velociraptor collection, and not response execution. Focused
follow-on smokes pass the one canonical detection hit through the existing
incident builder and then through the existing triage, investigation, and action
paths. The resulting outputs remain bounded to suspicious local archive staging,
evidence gaps, and advisory human-gated next steps.

## Centralized Collection Architecture

Observed path:

```text
kali-attacker
  -> SSH runner execution on ubuntu-victim01
  -> ubuntu-victim01 auditd raw records
  -> rsyslog imfile reads /var/log/audit/audit.log
  -> UDP forwarding to 192.0.2.20:514
  -> soc-analyzer
  -> /var/log/remote/ubuntu-victim01/auditd.log
```

## Sender Configuration

The `ubuntu-victim01` rsyslog input configuration used:

| Field | Value |
|---|---|
| Configuration file | `/etc/rsyslog.d/audit.conf` |
| Module | `imfile` |
| Watched file | `/var/log/audit/audit.log` |
| Tag | `auditd` |
| Severity | `info` |
| Facility | `local6` |
| `reopenOnTruncate` | `on` |

Forwarding after correction is handled once through the general forwarding
configuration:

```text
*.* @192.0.2.20:514
```

## Receiver Configuration

The `soc-analyzer` receiver used:

- `imudp` enabled
- UDP port `514`
- remote log template:

```text
/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log
```

Messages from non-local hosts are written through that template. Because the
sender-side `imfile` input uses the fixed tag `auditd`, raw audit records from
`/var/log/audit/audit.log` arrive under:

```text
/var/log/remote/ubuntu-victim01/auditd.log
```

## Observed Scenario Event Groups

The centralized auditd log contained these scenario event groups:

| Audit serial | Scenario behavior | CWD | PATH | PROCTITLE | SYSCALL |
|---|---|---:|---:|---:|---:|
| `10309` | `mkdir` staging directory | 1 | 2 | 1 | 1 |
| `10310` | `note.txt` creation | 1 | 2 | 1 | 1 |
| `10311` | `metadata.json` creation | 1 | 2 | 1 | 1 |
| `10313` | `tar` archive creation | 1 | 2 | 1 | 1 |
| `10317` | `chmod 0640` | 1 | 1 | 1 | 1 |

After exact-line deduplication, centralized scenario record totals were:

| Record type | Count |
|---|---:|
| `CWD` | 5 |
| `PATH` | 9 |
| `PROCTITLE` | 5 |
| `SYSCALL` | 5 |

## Raw Record Characteristics

The centralized raw audit records preserve useful defender-side context, but
normalization needs to account for auditd-specific behavior:

- Multiple `PATH` records can belong to one audit event.
- `item=0` often represents the parent directory.
- `item=1` can represent the created or modified target.
- `PROCTITLE` is hex encoded and NUL-delimited in the centralized raw log.
- The `tar` `PROCTITLE` was truncated near the end.
- Normalization must not depend only on a complete `PROCTITLE`.
- `SYSCALL`, `comm`, `exe`, `PATH`, and `CWD` provide additional evidence.
- Event grouping should use at least hostname, audit timestamp, and audit
  serial.

## Administrative Record Classification

The same centralized `auditd.log` also contained validation administration
records, including:

- `auditctl`
- `ausearch`
- `CONFIG_CHANGE`
- `add_rule`
- `remove_rule`

Validation-time `grep` invocations were also observed. Because `grep` may be
legitimate scenario behavior in other contexts, future normalization must not
exclude all `grep` events globally. Exclusion should use the validation command
signature, audit key, event window, executable, and other contextual evidence.

Known validation-administration records should be excluded from scenario
telemetry by explicit evidence-selection logic unless the fixture is explicitly
testing audit administration. This document does not claim that the generic
parser or endpoint-event converter globally removes those records.

## Duplicate-Forwarding Diagnosis

The initial `ubuntu-victim01` rsyslog configuration contained two forwarding
paths:

```text
/etc/rsyslog.d/forward.conf:
  *.* @192.0.2.20:514

/etc/rsyslog.d/audit.conf:
  if $programname == 'auditd' then @192.0.2.20:514
```

Observed result:

- victim-side `/var/log/audit/audit.log` contained one copy of each record
- `soc-analyzer` centralized `auditd.log` contained two copies
- the duplicate originated in rsyslog forwarding, not auditd generation

## Configuration Correction

The correction was:

1. Remove the dedicated auditd forwarding action from `audit.conf`.
2. Keep the `imfile` input in `audit.conf`.
3. Continue forwarding once through `forward.conf`:

```text
*.* @192.0.2.20:514
```

4. Validate rsyslog configuration:

```bash
rsyslogd -N1
```

5. Restart rsyslog.

No repository rsyslog configuration files are changed by this docs-only record.

## Post-Fix Dedupe Validation

Post-fix validation used a temporary key:

```text
rsyslog_audit_dedupe_smoke
```

A controlled `test.txt` file was created under:

```text
/tmp/rsyslog_audit_dedupe_smoke
```

Centralized records appeared once each. Exact-line counts were `1` rather than
`2`, confirming that the duplicate forwarding path was removed.

Past duplicate records remain in the historical centralized log, so future
normalizers should still implement defensive exact-record deduplication.

## Confirmed Scope

This validation confirms:

- `ubuntu-victim01` auditd records reached `soc-analyzer`
- scenario_009 `mkdir`, synthetic file creation, archive creation, and `chmod`
  event groups reached centralized `auditd.log`
- `CWD`, `PATH`, `PROCTITLE`, and `SYSCALL` records were preserved
- duplicate forwarding was diagnosed and corrected
- post-fix centralized audit records appeared once each

## Non-Goals

This validation does not claim:

- this raw collection validation alone produces normalized endpoint events or a
  detection hit without the focused fixture replay smokes
- Wazuh ingestion or alert generation
- plain rsyslog collection as completed SIEM validation
- Velociraptor collection
- incident, triage, investigation, or action consumed centralized live records
- full automation
- exfiltration, compromise, ransomware, credential access, or real data
  collection

No raw audit logs, interpreted audit logs, generated `data/runs/**` artifacts,
fixtures, tests, or `/tmp` outputs are added by this docs-only record.

## Normalizer Requirements

Future centralized auditd normalization should:

1. Group records using hostname, audit timestamp, and audit serial.
2. Retain all `PATH` records and their `item` / `nametype` metadata.
3. Decode hex `PROCTITLE` and replace NUL delimiters with argument separators.
4. Avoid relying solely on `PROCTITLE` completeness.
5. Exclude known validation-administration records from scenario evidence using
   explicit selection criteria such as record type, executable, command
   signature, audit key, and validation time window. Examples include
   `auditctl`, `ausearch`, `CONFIG_CHANGE`, `add_rule`, and `remove_rule`. Do
   not globally exclude generic utilities such as `grep`; exclude only specific
   validation invocations when context proves they are administrative activity.
6. Defensively deduplicate exact records because historical centralized logs
   contain duplicates.
7. Avoid collapsing distinct `PATH` records from the same audit event.
8. Preserve identity, process, syscall, path, `CWD`, host, audit key, and
   source-log context.

## Next Validation Levels

1. Runner-only execution and artifact creation: completed.
2. Live local auditd raw telemetry generation: completed.
3. Centralized rsyslog auditd collection: completed.
4. Duplicate forwarding correction and post-fix validation: completed.
5. Centralized auditd raw records to normalized endpoint events: completed for a
   sanitized minimal live-derived fixture.
6. Compare normalized live-derived events with the synthetic fixture: completed
   semantically for the focused smoke.
7. Run DSL detection against normalized live-derived fixture events: completed.
8. Feed the live-derived detection hit into the existing incident bridge:
   completed for fixture-driven replay.
9. Validate the live-derived incident-to-action boundary chain: completed for
   fixture-driven replay.
10. Wazuh / SIEM validation plan and environment record: defined.
11. Controlled Wazuh `alerts.json` inspection: completed; zero matching scenario
    documents were observed.
12. Temporary Wazuh raw-archive validation: completed as Outcome C; manager
    receipt and all five operations confirmed, while retained summaries did not
    demonstrate complete grouping and omitted exact `full_log` values.
13. Wazuh collection-path inspection and version-matched product verification:
    completed.
14. Stage 4 controlled exact `full_log` comparison: completed as
    `EXACT_CONTENT_PRESERVED` / T1-equivalent with exact grouped-payload
    identity for one separate controlled event.
15. Investigate and select a canonical Wazuh source: future; original Scenario
    009 remains T3/Outcome C.
16. Validate Velociraptor collection: future.
17. Validate direct production-log ingestion: future.
