# Phase7: Deception Layer

## 1. Purpose

Phase7 adds a deception layer for high-confidence defender-side SOC signals.

The first Phase7 MVP is agentic deception in the local lab: create
agent-readable lures, observe deterministic defender-side trap interactions,
and preserve those observations as dedicated deception hit artifacts.

## 2. Current status

Phase7 began with docs-only scope definition. The artifact-only MVP chain now
exists through deterministic local fixtures and smoke coverage:

```text
deception_inventory.yaml
  -> generate_deception_assets.py
  -> generated_deception_assets_manifest.json
  -> trap_observations.json
  -> generate_deception_hits.py
  -> deception_hits.json
  -> build_incident_from_deception_hits.py
  -> incident.json
```

The next step is the scenario contract at
`docs/design/deception/deception_scenario_contract.md`, followed later by a
separate scenario YAML / runner implementation PR. 
The scenario-contract step is docs-only and does not add schemas, scripts,
tests, fixtures, scenarios, runners, or generated run artifacts.

Rule Improvement export MVP is complete for the current candidate-generation
boundary. Apply, deploy, update, promotion workflow, and automatic promotion
remain future work.

## 3. MVP scope

The first MVP is defender-side agentic deception for high-confidence signals.

Initial implementation should be:

- local-lab only
- deterministic
- fixture-friendly
- defensive simulation only
- bounded to reviewed artifacts and approval gates

The MVP should start with a small deception path such as a honey credential,
decoy file, local canary endpoint, or decoy service contact.

## 4. Proposed pipeline

```text
deception_inventory.yaml
  -> local decoy asset generation
  -> controlled trap interaction
  -> deception_hits.json
  -> future incident bridge
  -> triage / investigation / case
```

The incident bridge is future work. `deception_hits.json` should be a dedicated
artifact first, before canonical detection output integration.

## 5. Proposed artifacts

Future artifacts:

- `deception_inventory.yaml`
- `deception_hits.json`

Future schemas:

- `schemas/deception_inventory.schema.json`
- `schemas/deception_hits.schema.json`

Future scripts:

- `scripts/generate_deception_assets.py`
- `scripts/generate_deception_hits.py`
- `scripts/build_incident_from_deception_hits.py`

None of these schemas or scripts are implemented in this docs-only PR.

## 6. Agent responsibilities

### Deception Agent

- select local-lab deception assets from `deception_inventory.yaml`
- generate agent-readable lures
- keep generated assets bounded and deterministic
- avoid public callback infrastructure

### Trap Detection Agent

- observe defender-side trap interactions
- produce deterministic `deception_hits.json`
- keep trap observations separate from attacker-side runner claims
- hand off to a future incident bridge

AI may later summarize, triage, investigate, or suggest improvements. AI must
not be the source of truth for whether a deception hit occurred.

## 7. Safety boundaries

- Defensive simulation only.
- No real ransomware behavior.
- No destructive database operation.
- No hack-back.
- No live credential theft.
- No external attacker-system control.
- No public callback infrastructure in the MVP.
- Canary endpoints are local-lab only.
- Deception hits are high-confidence signals, but they do not bypass approval
  gates.
- Deception hits do not automatically trigger containment.
- Deception hits do not automatically generate or promote Rule Improvement
  candidates.

The core boundary remains:

```text
attacker-side observed effect != defender-side observed artifact
```

Attacker-side structured runner events such as `decoy_env_read_attempted`,
`canary_url_requested`, or `fake_db_connection_attempted` must not be treated
as defender-side detection unless defender telemetry or `deception_hits.json`
confirms the interaction.

## 8. Implementation order

Recommended implementation order:

1. Define Phase7 agentic deception MVP scope.
2. Add deception inventory and deception hits schemas.
3. Add deterministic fixtures.
4. Add local decoy asset generator.
5. Add trap hit generator.
6. Add deception hit to incident bridge.
7. Add artifact-only deception pipeline chain smoke coverage.
8. Define the Phase7 deception scenario contract.
9. Add one local-lab scenario YAML and one safe runner after existing scenario
   IDs are checked.
10. Separately define attacker-agent untrusted artifact safety.
11. Later consider DB extortion simulation with simulation-only flags.

## 9. Acceptance criteria

The next scenario implementation should not be considered ready until a future
PR provides:

- deterministic local decoy asset generation
- deterministic trap hit generation
- local-lab-only canary endpoints
- tests or smoke coverage that prove attacker-side events are not counted as
  defender-side hits
- no automatic containment, apply, deploy, update, Rule Improvement generation,
  Rule Improvement promotion, or automatic promotion behavior
- one scenario YAML and one safe runner that do not reuse `scenario_007` or
  `scenario_008`

## 10. Future work

Future work includes:

- canonical detection output integration
- triage and investigation support for deception incidents
- Rule Improvement review signals through the existing reviewed-candidate path
- one local-lab scenario YAML and one safe runner after
  `docs/design/deception/deception_scenario_contract.md`
- attacker-agent untrusted artifact safety as a separate track
- DB extortion simulation as later simulation-only work

Scenario-family names for planning:

- `agentic_deception_mvp`
- `attacker_agent_untrusted_artifact_safety`
- `agentic_db_extortion_simulation`

No scenario number is assigned in this docs-only PR. Future scenario numbers
must be selected only after existing scenario IDs are checked.

## Current decision: park scenario runner implementation

The Phase7 deception artifact foundation is complete through the local deterministic chain:

```text
deception_inventory.yaml
  -> generate_deception_assets.py
  -> generated_deception_assets_manifest.json
  -> trap_observations.json
  -> generate_deception_hits.py
  -> deception_hits.json
  -> build_incident_from_deception_hits.py
  -> incident.json
```

The next scenario YAML / runner implementation is intentionally deferred.

Reason:

- A scripted runner that touches a known decoy path would add limited research value at this stage.
- Deception becomes more useful after attacker-agent behavior is more exploratory and decision-oriented.
- Deception also becomes more useful after response/action automation, SIEM/EDR-style evidence sources, and approval-gated containment workflows are more mature.
- The current artifact foundation is enough to resume Phase7 later without losing the contract.

Next focus:

- scenario family expansion policy
- broader Linux scenario families
- Windows telemetry MVP
- Wazuh / SIEM optional integration
- later return to deception scenario runner when attacker-agent and response automation are more mature
