# Scenario 009 Documentation Overview

## Scenario Identity

- Scenario ID: `scenario_009_suspicious_archive_staging`
- Scenario family: `suspicious_archive_staging`
- Data boundary: controlled synthetic data only

## Evidence Progression

```text
runner
  -> local auditd
  -> centralized rsyslog
  -> sanitized live-derived fixture
  -> normalization and DSL
  -> bounded incident-to-action chain
  -> Wazuh environment inspection
  -> alerts.json inspection
  -> temporary raw archive validation
  -> bounded evidence analysis
  -> read-only collection and decoder-path inspection
  -> version-matched audit-grouping product verification
  -> controlled audit-grouping content validation
```

## Current Conclusion

- Local auditd preserves the complete multi-record event groups.
- Centralized rsyslog and the sanitized live-derived fixture remain the
  canonical validation baseline.
- Wazuh manager receipt of the five expected operations is confirmed.
- Wazuh raw archive core serial documents retained `SYSCALL` evidence.
- The retained Wazuh archive summaries did not demonstrate deterministic
  serial-linked `PATH`, `CWD`, `EXECVE`, and `PROCTITLE` grouping. Exact
  `full_log` values were not retained.
- Raw archive validation is classified as Outcome C.
- `alerts.json` is non-canonical under the observed configuration.
- `archives.json` is supporting evidence, not the selected canonical source.
- Stage 1 bounded-evidence analysis retains T3: semantic evidence is present,
  but complete grouping was not demonstrated by retained evidence.
- Exact `full_log` form and audit-log / journald duplicate relationships remain
  unresolved from the retained repository summaries because the bounded raw
  window is not part of the Git evidence set.
- Stage 2 confirms separate agent-local audit-log and journald inputs and
  localizes `archives.json` strongly to the manager analysisd output boundary.
- Stage 3 confirms from Wazuh `v4.14.4` source that agent logcollector groups
  consecutive audit lines sharing a timestamp and serial before transport. It
  also confirms that manager archive `full_log` is sourced from the incoming
  grouped payload rather than rebuilt from decoded fields.
- Stage 4 separately confirmed `EXACT_CONTENT_PRESERVED` for one controlled
  six-record event. This is T1-equivalent controlled evidence; it does not
  recover the historical Scenario 009 `full_log` or change T3 or Outcome C.
- Wazuh normalization, DSL detection, and incident consumption remain pending.

## Runner And Local Auditd Validation

- [Runner-Only Smoke Validation](runner_only_smoke_validation.md)
- [Live Auditd Telemetry Smoke Validation](live_auditd_telemetry_smoke_validation.md)

## Centralized Collection And Fixture Validation

- [Centralized Rsyslog Auditd Collection Validation](centralized_rsyslog_auditd_collection_validation.md)

## Wazuh Planning And Environment

- [Wazuh / SIEM Validation Plan](wazuh_siem_validation_plan.md)
- [Wazuh Collection Environment](wazuh_collection_environment.md)

## Wazuh Alert And Raw Archive Observations

- [Wazuh Alerts Inspection](wazuh_alerts_inspection.md)
- [Wazuh Raw Archive Validation](wazuh_raw_archive_validation.md)
- [Wazuh Audit Transformation Investigation](wazuh_audit_transformation_investigation.md)
- [Wazuh Bounded Evidence Analysis](wazuh_bounded_evidence_analysis.md)
- [Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md)
- [Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md)
- [Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md)

## Operational Procedure

- [Temporary Wazuh Raw Archive Validation](../../../operations/scenarios/scenario009/temporary_wazuh_raw_archive_validation.md)

## Next Investigation

Stages 1 through 4 are recorded in:

- [Wazuh Bounded Evidence Analysis](wazuh_bounded_evidence_analysis.md)
- [Wazuh Collection And Decoder-Path Inspection](wazuh_collection_decoder_inspection.md)
- [Wazuh Audit Grouping Product Verification](wazuh_audit_grouping_product_verification.md)
- [Wazuh Audit Grouping Controlled Validation](wazuh_audit_grouping_controlled_validation.md)

Stages 1 through 3 retain Outcome C and T3 for the original Scenario 009 run.
Stage 4 separately confirms that one controlled `archives.json.full_log`
had exact grouped-payload identity with the completed contiguous six-record
local event after newline removal and single-space joining. The controlled
result is T1-equivalent evidence and does not recover the earlier run's exact
value.

Canonical Wazuh source selection and downstream parity remain separate future
decisions. The controlled result does not by itself justify a fixture, adapter,
normalization, detection, or incident-consumption claim.
