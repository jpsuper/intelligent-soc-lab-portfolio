# Phase7 Deception Scenario Contract

## 1. Purpose

This document defines the contract for a future Phase7 deception scenario before
adding scenario YAML or runner files.

The scenario should connect the existing artifact-only Phase7 deception chain:

```text
deception_inventory.yaml
  -> generate_deception_assets.py
  -> generated_deception_assets_manifest.json
  -> controlled trap interaction
  -> generate_deception_hits.py
  -> deception_hits.json
  -> build_incident_from_deception_hits.py
  -> incident.json
```

This document is docs-only. It does not add scenario YAML, runners, scripts,
schemas, tests, fixtures, or generated run artifacts.

## 2. Relationship to existing Phase7 artifacts

The future scenario must reuse the existing Phase7 artifact contracts:

- `schemas/deception_inventory.schema.json`
- `schemas/deception_hits.schema.json`
- `schemas/incident_schema.json`
- `scripts/generate_deception_assets.py`
- `scripts/generate_deception_hits.py`
- `scripts/build_incident_from_deception_hits.py`

The current artifact-only chain already has deterministic local smoke coverage.
The future scenario should wire that same chain into scenario execution without
changing the artifact semantics.

## 3. Scenario family

The scenario family is:

```text
agentic_deception_mvp
```

The scenario should model defender-side agentic deception, not a general
offensive autonomous agent. It may use attacker-side runner events for audit
context, but the source of truth for a deception hit remains defender-side trap
observation material that can produce schema-valid `deception_hits.json`.

## 4. Scenario numbering policy

`scenario_007` and `scenario_008` already exist:

- `scenarios/scenario_007_ssh_key_login_suspicious_file_write.yaml`
- `scenarios/scenario_008_ssh_key_system_discovery.yaml`

Future deception scenario implementation must not reuse `scenario_007` or
`scenario_008`.

No new scenario number is assigned in this docs-only PR. The first implementation
PR should choose the proposed next scenario only after checking the existing
scenario list in the repository. Until then, use wording such as:

- future Phase7 deception scenario family
- proposed next scenario after existing scenario IDs are checked
- no new scenario number is assigned in this docs-only PR

If an example number is unavoidable in later planning text, it must be marked
explicitly as tentative and not a committed contract.

## 5. Allowed runner behavior

The future runner may:

- read known local decoy paths in the lab
- request a local-lab canary endpoint only if the endpoint is lab-controlled or
  represented by a fixture
- attempt non-destructive contact with a fake local decoy service only if the
  service is implemented as a local fixture or safe lab-only descriptor
- emit structured attacker-side runner events for auditability
- write outputs only under explicit run output paths
- use fake credentials and fake tokens only
- preserve raw stdout / stderr and structured runner events according to the
  attacker-agent runner contracts

Allowed runner behavior remains local-lab and deterministic. The runner must not
require public callback infrastructure, live external systems, or uncontrolled
network behavior.

## 6. Forbidden runner behavior

The future runner must not implement:

- real ransomware behavior
- destructive database operations
- live credential theft
- public callback infrastructure
- external attacker-system control
- hack-back
- unauthorized scanning
- persistence outside documented lab simulation
- inline shell payloads in scenario YAML when the shell backend contract forbids
  them
- automatic containment
- approval state changes
- Rule Improvement candidate generation
- apply, deploy, update, or promotion behavior

The scenario and runner must not create triage, investigation, case, action, or
Rule Improvement artifacts.

## 7. Required artifacts

A future scenario implementation PR should add or wire only the artifacts needed
for the scenario path:

- one scenario YAML under `scenarios/`
- one safe runner shell script under `attacks/runners/`
- generated or referenced `deception_inventory.yaml`
- `generated_deception_assets_manifest.json`
- trap observation source or fixture
- `deception_hits.json`
- `incident.json`

This docs-only PR must not create those artifacts.

## 8. Structured runner events

Structured runner events are attacker-side audit context only.

Example attacker-side structured events:

- `decoy_env_read_attempted`
- `canary_url_requested`
- `fake_db_connection_attempted`

These events may support `attack_execution_log.json` and
`attack_observed_effects.json`. They must not be treated as defender-side
detections or deception hits.

Defender-side event names are:

- `deception_lure_accessed`
- `canary_http_requested`
- `decoy_service_contacted`
- `credential_lure_use_attempted`

Defender-side artifact names are:

- `deception_lure_access`
- `canary_http_request`
- `decoy_service_contact`
- `credential_lure_use_attempt`

## 9. Defender-side evidence boundary

Preserve the repository-wide boundary:

```text
attacker-side observed effect != defender-side observed artifact
```

A runner event such as `canary_url_requested` is not a defender-side hit unless
the deception hit generator receives a defender-side trap observation and
produces schema-valid `deception_hits.json`.

The future scenario may compare attacker-side structured runner events with
defender-side deception hits, but it must not convert runner claims directly
into detections, incidents, approval state, or Rule Improvement candidates.

## 10. Output locations

Generated run artifacts should remain out of git.

The future scenario should:

- use explicit run output directories
- write generated artifacts under that explicit run output path
- avoid committing `data/runs/**` outputs
- use `tests/fixtures/` only for stable synthetic inputs explicitly added as
  fixtures in a later PR

The scenario YAML should reference its runner under `attacks/runners/` and must
not embed shell payloads directly if the shell backend contract forbids them.

## 11. Safety boundaries

The future scenario must remain:

- defensive simulation only
- local-lab only
- deterministic
- bounded to fake credentials and fake tokens
- non-destructive
- non-persistent except for documented lab-only simulation artifacts
- non-promoting
- non-applying
- non-deploying

Deception hits are high-confidence signals, but they do not bypass approval
gates and do not automatically trigger containment.

## 12. Acceptance criteria for the first scenario PR

The first Phase7 deception scenario implementation PR should:

- add one scenario YAML and one safe runner only
- not reuse `scenario_007` or `scenario_008`
- not add new schema semantics unless explicitly needed
- reuse the existing deception inventory, deception hit, and incident bridge
  contracts
- produce or wire the artifact chain locally
- keep all canary and decoy behavior local-lab only
- not create triage, investigation, case, action, or Rule Improvement artifacts
- include focused smoke coverage
- preserve the attacker-side observed effect / defender-side observed artifact
  boundary
- keep generated `data/runs/**` outputs out of git

## 13. Future extensions

Future extensions may include:

- canonical detection output integration
- triage and investigation support for deception incidents
- Rule Improvement review signals through the existing reviewed-candidate path
- attacker-agent untrusted artifact safety as a separate track
- simulation-only DB extortion research after deception and attacker-agent
  safety contracts are stable

These extensions are not part of the first scenario implementation contract.
