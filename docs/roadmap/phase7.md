# Phase7: Deception Layer

> [!NOTE]
> This document preserves Phase7-specific implementation history and validation
> context. The [main Roadmap](roadmap.md) is authoritative for current status,
> active priority, incomplete work, and Done Criteria.

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

The scenario contract now exists at
`docs/design/deception/deception_scenario_contract.md`. It is docs-only and
does not add a scenario YAML or runner. A future scenario YAML / runner
implementation remains intentionally deferred.

Rule Improvement export MVP is complete for the current candidate-generation
boundary. Apply, deploy, update, promotion workflow, and automatic promotion
remain future work.

## 3. MVP scope

The Phase7 MVP is defender-side agentic deception for high-confidence signals.
Its durable boundaries are:

- local-lab only
- deterministic
- fixture-friendly
- defensive simulation only
- bounded to reviewed artifacts and approval gates

The implemented artifact foundation uses a small deception path based on
local-lab lures and deterministic defender-side trap observations. A scenario
YAML / runner is not part of the current MVP implementation.

## 4. Historical implementation plan

The initial docs-only Phase7 plan proposed the following pipeline:

```text
deception_inventory.yaml
  -> local decoy asset generation
  -> controlled trap interaction
  -> deception_hits.json
  -> future incident bridge
  -> triage / investigation / case
```

At that stage, the incident bridge was future work and
`deception_hits.json` was intentionally designed as a dedicated artifact
before canonical detection output integration. The deterministic artifact
foundation and deception-hit-to-Incident bridge are now implemented, while
canonical detection output integration remains future work.

## 5. Historical artifact proposal

The initial docs-only plan listed the following as future artifacts:

- `deception_inventory.yaml`
- `deception_hits.json`

It also listed these schemas and scripts as future work:

- `schemas/deception_inventory.schema.json`
- `schemas/deception_hits.schema.json`
- `scripts/generate_deception_assets.py`
- `scripts/generate_deception_hits.py`
- `scripts/build_incident_from_deception_hits.py`

None of them were implemented in the initial docs-only PR. They now form the
implemented artifact foundation described in
[Current status](#2-current-status).

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
- hand off to the existing deception-hit-to-Incident bridge

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

## 8. Historical implementation order

The original recommended implementation order was:

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

Steps 1 through 8 are complete. Step 9 is intentionally deferred. Steps 10 and
11 remain separate future research tracks and are not part of the current
Phase7 implementation priority.

## 9. Acceptance criteria for a future scenario implementation

A future scenario YAML / runner implementation must reuse the existing
artifact foundation without weakening its evidence or approval boundaries. It
should not be considered ready until it:

- reuses deterministic local decoy asset and trap hit generation
- keeps canary endpoints local-lab only
- includes tests or smoke coverage proving that attacker-side events are not
  counted as defender-side hits
- adds one scenario YAML and one safe runner without reusing
  `scenario_007` or `scenario_008`
- does not add automatic containment, apply, deploy, update, Rule Improvement
  generation, Rule Improvement promotion, or automatic promotion behavior

## 10. Future work

Future work includes:

- canonical detection output integration
- triage and investigation support for deception incidents
- Rule Improvement review signals through the existing reviewed-candidate path
- one local-lab scenario YAML and one safe runner governed by
  `docs/design/deception/deception_scenario_contract.md`
- attacker-agent untrusted artifact safety as a separate track
- DB extortion simulation as later simulation-only work

Scenario-family names for planning:

- `agentic_deception_mvp`
- `attacker_agent_untrusted_artifact_safety`
- `agentic_db_extortion_simulation`

The initial docs-only Phase7 scope assigned no scenario number. No deception
scenario number is currently assigned. A future implementation must select one
only after checking the existing scenario IDs.

## Current decision: park scenario runner implementation

The Phase7 deception artifact foundation is complete through the local
deterministic chain:

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

- A scripted runner that touches a known decoy path would add limited research
  value at this stage.
- Deception becomes more useful after attacker-agent behavior is more
  exploratory and decision-oriented.
- Deception also becomes more useful after response/action automation,
  SIEM/EDR-style evidence sources, and approval-gated containment workflows are
  more mature.
- The current artifact foundation is enough to resume Phase7 later without
  losing the contract.

Current follow-on priorities are maintained in the
[main Roadmap](roadmap.md). This phase document does not define active
sequencing.
