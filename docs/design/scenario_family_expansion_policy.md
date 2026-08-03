# Scenario Family Expansion Policy

## 1. Purpose

This policy defines how new scenario families should be proposed, mapped, and
reviewed before adding scenarios after `scenario_008`.

The goal is to keep scenario growth comparable, evidence-aware, and safe. A new
scenario should not be added only because a runner can perform an action. The
scenario family must first define how attacker-side observed effects map to
defender-side artifacts, how those artifacts flow through detection / incident /
triage / investigation, and which safety and fixture boundaries apply.

This policy is docs-only. It does not add scenario YAML, runners, scripts,
schemas, tests, fixtures, or generated run artifacts.

## 2. Current scenario baseline

Existing scenarios currently include:

- `scenario_001_ssh_bruteforce_priv_esc`
- `scenario_002_process_execution`
- `scenario_003_ssh_bruteforce_download_exec`
- `scenario_004_ssh_bruteforce_authorized_keys_persistence`
- `scenario_005_ssh_authorized_keys_persistence_reuse`
- `scenario_006_ssh_key_login_then_command_execution`
- `scenario_007_ssh_key_login_suspicious_file_write`
- `scenario_008_ssh_key_system_discovery`

Current runner files should also be checked under `attacks/runners/` before any
new scenario ID is selected. The scenario YAML and runner name should match the
same scenario intent and ID.

## 3. Scenario numbering policy

- Do not reuse existing scenario IDs.
- Select new scenario IDs only after checking both `scenarios/` and
  `attacks/runners/`.
- Scenario YAML and runner names should match.
- Avoid assigning scenario numbers in docs-only planning unless the number is
  intentionally reserved.
- If a scenario number is reserved, document why it is reserved and what files
  will be created later.
- Do not skip numbers casually.
- Do not treat a planned scenario family name as a reserved scenario ID.
- The Phase7 deception artifact foundation exists, but the deception scenario
  YAML / runner implementation is intentionally deferred.

## 4. Scenario family definition

A scenario family is a group of related attack or simulation paths that share:

- scenario intent
- attacker-side observed effects
- defender-side expected artifacts
- detection expectations
- incident / triage / investigation expectations
- safety boundaries
- fixture strategy
- runner behavior model

Scenario family policy applies before individual scenario implementation. A
family may later produce one or more scenario IDs, but each implementation PR
should stay narrow and explain whether it adds exactly one scenario ID or a
small justified set.

## 5. Expansion order

The current recommended expansion order is:

1. Scenario family expansion policy.
2. Broader Linux scenario families.
3. Windows telemetry MVP.
4. Wazuh / SIEM optional integration.
5. More practical attacker-agent behavior.
6. Return to the Phase7 deception scenario runner when attacker-agent and
   response automation are more mature.
7. AD / adversary simulation / background activity.

This order preserves the current lab direction: stabilize scenario expansion
rules first, broaden Linux coverage next, then add new telemetry platforms and
more realistic behavior after artifact boundaries are explicit.

## 6. Required mapping before implementation

Before implementing a new scenario family, add or update mapping documentation
with the following table shape:

| Field | Required content |
|---|---|
| `scenario_family` | Stable family name. |
| `proposed scenario_id` | Proposed ID or `not assigned` for docs-only planning. |
| `attacker-side observed effects` | Effects expected in `attack_observed_effects.json` or structured runner event logs. |
| `defender-side artifacts` | Logs, telemetry, parser output, detection hits, deception hits, endpoint events, SIEM alerts, or controlled fixtures expected to prove defender observation. |
| `expected detection artifacts` | Canonical detection outputs, DSL outputs, deception hits, endpoint observations, or other detection-stage artifacts. |
| `expected incident fields` | Primary artifact, evidence refs, correlated observations, and fields that should remain unset without evidence. |
| `triage expectations` | Evidence-grounded derived features and assessment boundaries. |
| `investigation expectations` | Enrichment, evidence gaps, pivots, and unsupported-claim controls. |
| `action / containment boundary` | Approval gates and state-changing response limits. |
| `required fixtures` | Stable synthetic inputs needed for deterministic tests. |
| `required tests` | Focused tests needed for the implementation PR. |
| `generated artifacts that must remain out of git` | Run outputs such as `data/runs/**` and attacker execution artifacts. |

The mapping should be explicit enough for reviewers to see whether the proposed
scenario depends on attacker claims, defender telemetry, controlled fixtures, or
missing future integrations.

## 7. Attacker-side observed effects

Attacker-side observed effects belong to:

- `attack_observed_effects.json`
- structured runner event logs such as valid `ATTACK_EVENT_JSON:` lines
- `attack_execution_log.json` when structured events are preserved additively

These effects are useful for alignment evaluation and attacker-side auditability.
They help answer what the runner believes happened.

They must not be treated as:

- defender-side telemetry
- detection evidence
- alerts
- incident proof
- approval to act
- Rule Improvement promotion evidence

The core boundary remains:

```text
attacker-side observed effect != defender-side observed artifact
```

## 8. Defender-side artifacts

Defender-side artifacts must come from defender-observable sources, such as:

- logs
- telemetry
- parser output
- detection hits
- deception hits
- endpoint events
- SIEM alerts
- controlled fixtures

Defender-side artifacts are the source for incident, triage, investigation, and
case evidence. They may be compared with attacker-side observed effects through
alignment logic, but attacker-side effects do not fill defender evidence gaps.

Preserve this boundary in every scenario family:

```text
attacker-side observed effect != defender-side observed artifact
```

## 9. Detection / incident / triage / investigation expectations

Detection should attach observation-level facts only. Conclusion-like labels
belong in later stages unless a dedicated contract says otherwise.

Incident generation should preserve evidence refs, correlation context, primary
artifact selection, and known gaps. It should avoid unsupported conclusions.

Triage may infer assessment features only when they are supported by defender
evidence, controlled fixtures, or clearly documented context. Triage should not
treat attacker-side success as detection success.

Investigation may enrich context, add pivots, and describe likely storylines, but
it must preserve evidence gaps and unsupported-claim controls.

Action should remain approval-gated. Deletion, blocking, isolation, credential
revocation, containment, and other state-changing operations require explicit
approval-boundary handling.

Rule Improvement should remain review-gated. Observed-effects alignment and
post-action findings may create reviewable signals, but they must not
auto-promote rules, prompts, parsers, telemetry changes, correlation changes, or
promotion recommendations.

## 10. Runner safety boundaries

Runners must be deterministic and lab-scoped.

Runners must not introduce:

- real ransomware behavior
- destructive database operations
- live credential theft
- public callback infrastructure unless explicitly designed and controlled in a
  later phase
- hack-back
- unauthorized scanning
- external attacker-system control
- stealth or unauthorized persistence
- inline shell payloads in scenario YAML when the shell backend contract forbids
  them
- generated run artifacts committed to git

Simulated persistence or credential access may be allowed only when documented,
bounded to the lab, and implemented through approved scenario / runner contracts.
Fake local secrets are allowed for controlled credential-access simulation, but
live credential theft is not.

## 11. Fixture and generated artifact policy

Stable synthetic inputs belong under `tests/fixtures/`.

Generated outputs belong under explicit run output directories or `tmp_path` in
tests.

Generated outputs under `data/runs/**` should not be committed.

If a generated artifact is promoted to a fixture, document why it is stable,
synthetic, and safe to keep in git. Do not commit generated run outputs merely
because they are useful context.

## 12. Acceptance criteria for a new scenario PR

A new scenario PR should:

- add exactly one scenario family or one scenario ID unless explicitly justified
- add matching scenario YAML and runner if it is an implementation PR
- add focused tests
- update mapping documentation if new observed effects or defender artifacts are
  introduced
- avoid unrelated schema or behavior changes
- keep generated `data/runs/**` artifacts out of git
- preserve the attacker-side / defender-side boundary
- keep action gates intact
- keep Rule Improvement review and promotion gates intact
- explain any intentionally reserved scenario number before implementation

Docs-only planning PRs should not add scenario YAML, runners, scripts, schemas,
tests, fixtures, triage / investigation / case / action artifacts, Rule
Improvement artifacts, or generated run artifacts.

## 13. Review checklist

Reviewers should check:

- Has the PR checked existing scenario IDs in `scenarios/` and
  `attacks/runners/`?
- Does the scenario family mapping distinguish attacker-side effects from
  defender-side artifacts?
- Are defender-side artifacts grounded in logs, telemetry, parser output,
  detection hits, deception hits, endpoint events, SIEM alerts, or controlled
  fixtures?
- Does detection attach observation-level facts without unsupported conclusions?
- Does incident generation preserve evidence refs and primary artifact intent?
- Are triage and investigation claims supported by evidence?
- Are action, containment, apply, deploy, update, and promotion gates preserved?
- Are runner behaviors deterministic, lab-scoped, and non-destructive?
- Are generated artifacts excluded from git?
- Are fixtures synthetic, stable, and documented?
- Are tests focused on the new behavior or contract?
- Is the PR free of unrelated cleanup, directory moves, or schema churn?

## 14. Future scenario families

Candidate future Linux scenario families include:

- web initial access simulation with safe local fixture logs
- suspicious archive / staging behavior
- credential access simulation with fake local secrets only
- lateral-movement-like SSH fan-out simulation inside the lab only
- service discovery / internal enumeration expansion
- persistence simulation with documented safe lab-only artifacts

These are candidates only. They are not implemented or assigned scenario IDs by
this policy.

Later expansion may include Windows telemetry, Wazuh / SIEM optional evidence,
more practical attacker-agent behavior, the deferred Phase7 deception scenario
runner, AD scenarios, adversary simulation, and background activity. Each family
must still pass the same mapping, evidence, safety, fixture, and review gates
before implementation.
