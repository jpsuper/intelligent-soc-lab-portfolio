# Scenario 009 Live Auditd Raw Telemetry Smoke Validation

## Purpose

This document records the live auditd raw telemetry smoke validation for
`scenario_009_suspicious_archive_staging`.

The validation proves that auditd generated raw defender-side records for the
scenario activity on `ubuntu-victim01`. It does not prove auditd normalization,
DSL live detection, Wazuh alerting, SIEM ingestion, Velociraptor collection, or
live fixture-to-action automation.

Core boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

`ATTACK_EVENT_JSON` lines remain attacker-side observed effects. The auditd
records described here are defender-side raw telemetry. They are not normalized
endpoint events until a converter or parser produces `endpoint_events.json`, and
they are not detections until detection logic evaluates normalized live
telemetry.

## Relationship To Runner-Only Validation

The earlier runner-only validation is recorded in
[Scenario 009 Runner-Only Smoke Validation](runner_only_smoke_validation.md).
It proves only that the runner can create the expected target-side artifacts on
`ubuntu-victim01`.

This validation is the next level in the ladder: auditd observed raw records for
the runner activity. A later centralized rsyslog validation is recorded in
[Scenario 009 Centralized Rsyslog Auditd Collection Validation](centralized_rsyslog_auditd_collection_validation.md).
Follow-on fixture-driven smokes now convert a sanitized minimal live-derived
centralized auditd fixture into normalized endpoint events and evaluate those
events with the existing DSL rule. The one canonical archive-staging hit is also
accepted by the existing incident bridge and produces a schema-valid, bounded
incident. That proves live-derived fixture replay, not direct continuous
production-log ingestion.

## Environment

| Field | Value |
|---|---|
| Scenario | `scenario_009_suspicious_archive_staging` |
| Execution source | `kali-attacker` |
| Execution target | `ubuntu-victim01` |
| Target user | `victim01` |
| Target host | `192.0.2.30` |
| auditd tools | `auditctl`, `ausearch`, and `aureport` installed |
| auditd service state | active and enabled |
| Raw audit log | `/var/log/audit/audit.log` existed |
| sudo mode | interactive password authentication required |
| Temporary audit key | `scenario009_audit_smoke` |
| Watched directory | `/tmp/ai_soc_lab_scenario_009_audit_smoke` |

## Temporary Audit Rule

A temporary audit watch was added for the runner-controlled base directory:

```bash
sudo auditctl -w /tmp/ai_soc_lab_scenario_009_audit_smoke \
  -p wa \
  -k scenario009_audit_smoke
```

The watch was temporary validation scaffolding. It was removed after audit
record collection and must not be treated as a persistent lab rule.

## Execution Method

The scenario runner was streamed from `kali-attacker` to `ubuntu-victim01` over
SSH stdin. The target host did not need a local repository checkout.

Representative execution command:

```bash
ssh victim01@192.0.2.30 \
  'SCENARIO_009_BASE_DIR=/tmp/ai_soc_lab_scenario_009_audit_smoke bash -s' \
  < attacks/runners/scenario_009_suspicious_archive_staging.sh
```

Audit records were queried with the temporary key:

```bash
sudo ausearch -k scenario009_audit_smoke
```

## Observed Auditd Evidence

### Staging Directory Creation

Auditd produced a raw record for staging directory creation:

- `PROCTITLE` included
  `mkdir -p /tmp/ai_soc_lab_scenario_009_audit_smoke/staging`
- `SYSCALL` included `syscall=mkdir` and `success=yes`
- `PATH` included `name=staging` and `nametype=CREATE`
- audit key was `scenario009_audit_smoke`

### Synthetic note.txt Creation

Auditd produced a raw record for synthetic note creation:

- `PATH` included
  `/tmp/ai_soc_lab_scenario_009_audit_smoke/staging/note.txt`
- `nametype=CREATE`
- `SYSCALL` included `syscall=openat` and `success=yes`
- flags included `O_WRONLY|O_CREAT|O_TRUNC`
- executable was `/usr/bin/bash`

### Synthetic metadata.json Creation

Auditd produced a raw record for synthetic metadata creation:

- `PATH` included
  `/tmp/ai_soc_lab_scenario_009_audit_smoke/staging/metadata.json`
- `nametype=CREATE`
- `SYSCALL` included `syscall=openat` and `success=yes`
- flags included `O_WRONLY|O_CREAT|O_TRUNC`
- executable was `/usr/bin/bash`

### Archive Creation

Auditd produced a raw record for archive creation:

- `PROCTITLE` included
  `tar -czf /tmp/ai_soc_lab_scenario_009_audit_smoke/staged_synthetic_files.tar.gz`
- `PATH` included
  `/tmp/ai_soc_lab_scenario_009_audit_smoke/staged_synthetic_files.tar.gz`
- `nametype=CREATE`
- `SYSCALL` included `syscall=creat` and `success=yes`
- `comm=tar`
- `exe=/usr/bin/tar`

### Archive Permission Change

Auditd produced a raw record for archive permission change:

- `PROCTITLE` included
  `chmod 0640 /tmp/ai_soc_lab_scenario_009_audit_smoke/staged_synthetic_files.tar.gz`
- `PATH` included
  `/tmp/ai_soc_lab_scenario_009_audit_smoke/staged_synthetic_files.tar.gz`
- `SYSCALL` included `syscall=fchmodat` and `success=yes`
- requested mode was `0640`
- `comm=chmod`
- `exe=/usr/bin/chmod`

### Identity Context

The scenario activity included identity context:

- `auid=victim01`
- `uid=victim01`
- `gid=victim01`
- `key=scenario009_audit_smoke`

## Evidence Interpretation

This smoke confirms:

- the runner executed on `ubuntu-victim01`
- the expected target artifacts were created
- auditd generated defender-side raw records
- `mkdir`, synthetic file creation, archive creation, and `chmod` activity were
  represented
- audit records included process, syscall, path, identity, and audit key context

This smoke does not confirm that those raw records have been normalized into the
current `endpoint_events.json` schema. It also does not confirm that the current
synthetic fixture exactly matches live telemetry shape, field names, event
grouping, syscall names, or path semantics.

## Administrative Record Exclusion

Audit records also included validation administration activity for audit rule
addition and removal. Those administrative records used `comm=auditctl` and
`key=(null)`.

These records are validation administration records, not scenario behavior. A
future normalizer or fixture derived from this smoke should exclude them from
scenario telemetry unless the fixture is explicitly testing audit rule
administration.

## Cleanup

The temporary audit rule was removed after collection:

```bash
sudo auditctl -W /tmp/ai_soc_lab_scenario_009_audit_smoke \
  -k scenario009_audit_smoke
```

Generated runner artifacts and temporary remote files were cleaned up:

```bash
rm -rf /tmp/ai_soc_lab_scenario_009_audit_smoke
```

No captured audit logs, generated `data/runs/**` outputs, `/tmp` files, or
persistent audit rules are part of this docs-only validation record.

## Confirmed Scope

- runner executed on `ubuntu-victim01`
- expected target artifacts were created
- auditd generated defender-side raw records
- staging directory creation was represented
- synthetic file creation was represented
- archive creation was represented
- archive permission change was represented
- process, syscall, path, identity, and audit key context were present

## Non-Goals and Boundaries

This validation does not claim:

- auditd normalization is validated
- the current synthetic endpoint fixture exactly matches live telemetry
- direct or continuous production-log DSL detection is validated
- Wazuh alert generation is validated
- SIEM ingestion or search is validated
- Velociraptor collection is validated
- incident, triage, investigation, or action consumed live auditd records
- exfiltration, ransomware, credential access, compromise, or real data
  collection occurred
- containment, approval, apply, deploy, update, or promotion behavior occurred

A focused smoke validates DSL detection only for normalized, sanitized
live-derived fixture replay. A follow-on focused smoke validates that the
existing incident bridge can consume the resulting canonical detection hit; it
does not itself extend the replay into triage, investigation, or action. A
separate focused boundary-chain smoke now validates those existing paths: triage
remains uncertain, investigation preserves archive staging as a hypothesis with
evidence gaps, and action remains advisory, non-destructive, and human-gated.

A proposed Wazuh / SIEM validation contract is documented in
[Scenario 009 Wazuh / SIEM Validation Plan](wazuh_siem_validation_plan.md).
The Wazuh 4.14.4 deployment, active victim agent, and agent-local audit
collection configuration are now recorded in
[Scenario 009 Wazuh Collection Environment](wazuh_collection_environment.md).
Manager `alerts.json` exists and raw archives are disabled. A controlled
follow-on inspection is recorded in
[Scenario 009 Wazuh Alerts Inspection](wazuh_alerts_inspection.md):
local auditd again contained all five expected observations, but `31` new alert
lines contained `0` matching scenario documents. `alerts.json` is therefore not
canonical under the observed configuration. A bounded raw-archive observation
is recorded in
[Scenario 009 Wazuh Raw Archive Validation Result](wazuh_raw_archive_validation.md).
It confirmed manager receipt and all five operations. The retained structured
summary contained one serial-linked document per core serial classified as
`audit.type=SYSCALL`, but exact `full_log` values were not retained; this does
not prove `full_log` was `SYSCALL`-only. `journald`-located documents lacked an
extractable original audit serial in the retained summary. The result is Outcome C;
source selection and downstream Wazuh validation remain pending, and the
fixture-driven flow remains canonical.

## Next Validation Levels

1. Runner-only execution and artifact creation: completed.
2. Live auditd raw telemetry generation: completed.
3. Centralized rsyslog auditd collection: completed and recorded in
   [Scenario 009 Centralized Rsyslog Auditd Collection Validation](centralized_rsyslog_auditd_collection_validation.md).
4. Duplicate forwarding correction and post-fix validation: completed.
5. Convert centralized auditd records into normalized endpoint events: completed
   for a sanitized minimal live-derived fixture.
6. Compare normalized live events with the synthetic `scenario_009` fixture:
   completed semantically for the focused smoke.
7. Run DSL detection against normalized live-derived fixture events: completed.
8. Feed the live-derived detection hit into the existing incident bridge:
   completed for fixture-driven replay.
9. Validate the live-derived incident-to-action boundary chain: completed for
   fixture-driven replay.
10. Wazuh / SIEM validation plan and environment record: defined.
11. Controlled Wazuh `alerts.json` inspection: completed; no matching scenario
    evidence was observed despite complete local auditd evidence.
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
