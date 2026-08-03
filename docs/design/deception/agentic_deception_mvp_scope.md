# Agentic Deception MVP Scope

## 1. Purpose

This document defines the Phase7 agentic deception MVP scope.

Phase7 starts with defender-side agentic deception for high-confidence SOC
signals. The MVP is a defensive simulation layer that creates local-lab lures,
records deterministic trap observations, and produces reviewable defender-side
deception hit artifacts.

This is a docs-only scope document. It does not add schemas, scripts, tests,
fixtures, scenarios, runners, or generated run artifacts.

## 2. Why this fits Phase7

Phase6 completed the Rule Improvement export MVP for the current
candidate-generation boundary. The next useful direction is to widen
defender-side signal quality before adding state-changing update or promotion
workflows.

Deception is a good Phase7 starting point because a confirmed interaction with
a canary, decoy credential, decoy service, or decoy file can be a
high-confidence SOC signal while still preserving the repository's approval
and artifact boundaries.

The first Phase7 MVP should be local, deterministic, fixture-friendly, and
bounded to lab-only deception assets.

## 3. Design principles

- Defensive simulation only.
- Deterministic trap detection is the source of truth for deception hits.
- AI may summarize, triage, investigate, or suggest improvements later, but AI
  must not be the source of truth for whether a deception hit occurred.
- Deception hits are high-confidence signals, but they do not bypass approval
  gates.
- Deception hits do not automatically trigger containment.
- Deception hits do not automatically generate or promote Rule Improvement
  candidates.
- Generated run artifacts remain local and are not committed unless a later PR
  explicitly documents them as test fixtures.

## 4. MVP scope

The MVP should define a small, local-lab deception path:

```text
deception_inventory.yaml
  -> local decoy asset generation
  -> controlled trap interaction
  -> deception_hits.json
  -> future incident bridge
  -> triage / investigation / case
```

The first canonical artifact should be a dedicated `deception_hits.json`
artifact. Canonical detection output integration can come later after the
deception hit contract is stable.

The incident bridge is future work. It is not implemented in this docs-only PR.

## 5. Non-goals

The MVP does not include:

- real ransomware behavior
- destructive database operations
- hack-back
- live credential theft
- external attacker-system control
- public callback infrastructure
- automatic containment
- automatic Rule Improvement candidate generation
- automatic Rule Improvement promotion
- apply, deploy, baseline update, prompt update, parser update, telemetry
  update, or correlation update workflows
- agentic DB extortion or ransomware-like simulation

Attacker-agent untrusted artifact safety is a related but separate follow-on
design track. Agentic DB extortion simulation is later work and must wait until
deception and attacker-agent safety contracts are stable.

## 6. Safety boundaries

Canary endpoints are local-lab only in the MVP.

No public callback infrastructure should be required. Trap endpoints should be
bound to the lab network, local host, or deterministic fixture generation
depending on the implementation stage.

The core evidence boundary remains:

```text
attacker-side observed effect != defender-side observed artifact
```

For deception, attacker-side structured runner events such as:

- `decoy_env_read_attempted`
- `canary_url_requested`
- `fake_db_connection_attempted`

must not be treated as defender-side detections unless defender telemetry or a
deception hit artifact confirms the interaction.

## 7. Deception asset model

Future `deception_inventory.yaml` should describe local-lab deception assets.
The future schema should be:

```text
schemas/deception_inventory.schema.json
```

The inventory should be able to describe:

- lure identity
- lure type
- intended local placement
- trap mechanism
- expected defender-side event name
- expected deception hit artifact type
- lab-only endpoint or file path
- scenario-family association
- cleanup expectations

Future generation should be handled by:

```text
scripts/generate_deception_assets.py
```

That script is future work and is not created by this PR.

## 8. Agent-readable lures vs defender-observable traps

Agent-readable lures are content that an agent or runner may encounter:

- `README_INTERNAL.md`
- `tool_manifest.yaml`
- `nacos_decoy.yaml`
- fake `.env`
- fake internal operational notes

Defender-observable traps are the source of truth for deception hits:

- canary URL request
- decoy credential use attempt
- decoy service contact
- decoy file access log

Reading a lure is not enough by itself unless the read is captured by a
defender-side trap observation. A runner claiming that it requested a canary URL
is attacker-side context until the defender-side canary request is observed.

## 9. Proposed artifact contracts

Future `deception_hits.json` should record deterministic defender-side trap
observations. The future schema should be:

```text
schemas/deception_hits.schema.json
```

Future hit generation should be handled by:

```text
scripts/generate_deception_hits.py
```

Future incident bridging should be handled by:

```text
scripts/build_incident_from_deception_hits.py
```

These schemas and scripts are future work and are not created by this PR.

## 10. Event and artifact naming

Defender-side event names should use deterministic trap observations:

| Defender-side event | Recommended primary artifact |
|---|---|
| `deception_lure_accessed` | `deception_lure_access` |
| `canary_http_requested` | `canary_http_request` |
| `decoy_service_contacted` | `decoy_service_contact` |
| `credential_lure_use_attempted` | `credential_lure_use_attempt` |

Scenario-family names should be used until existing scenario IDs are checked:

- `agentic_deception_mvp`
- `attacker_agent_untrusted_artifact_safety`
- `agentic_db_extortion_simulation`

No scenario number is assigned in this docs-only PR. Future scenario numbers
must be chosen only after existing scenario IDs are checked.

## 11. Pipeline position

The MVP should sit on the defender side of the artifact pipeline:

```text
local deception assets
  -> defender-observable trap interaction
  -> deception_hits.json
  -> future incident bridge
  -> triage / investigation / case
  -> optional future Rule Improvement review signal
```

`deception_hits.json` should be a dedicated artifact first. Later canonical
detection output integration may map deception hits into the normal detection
or incident path, but the first contract should preserve the trap source.

Future scenario YAML and runner implementation is governed separately by
`docs/design/deception/deception_scenario_contract.md`. That contract preserves
the artifact-only chain here while documenting scenario numbering, runner
behavior, output locations, and safety boundaries for the first scenario PR.

## 12. Rule Improvement relationship

Deception hits may later become Rule Improvement review context, but they must
use the already established reviewed-candidate path.

Deception hits must not directly trigger:

- candidate generation
- concrete bundle conversion
- rule export
- prompt export
- parser export
- promotion recommendation export
- apply, deploy, update, or promotion behavior

If a deception hit identifies a detection gap, that gap should become a
reviewable signal first. Human review should decide whether it enters the Rule
Improvement candidate workflow.

## 13. Acceptance criteria

The Phase7 agentic deception MVP should be considered ready for implementation
only when future PRs can show:

- `deception_inventory.yaml` has a schema-backed fixture
- `deception_hits.json` has a schema-backed fixture
- local decoy asset generation is deterministic
- trap hit generation is deterministic
- canary endpoints are local-lab only
- attacker-side observed effects are not counted as defender-side hits
- deception hits can be reviewed without bypassing approval gates
- no generated `data/runs/**` artifacts are committed unless explicitly added
  as fixtures

## 14. Follow-on work

Follow-on tracks:

- define `schemas/deception_inventory.schema.json`
- define `schemas/deception_hits.schema.json`
- add deterministic fixtures
- add `scripts/generate_deception_assets.py`
- add `scripts/generate_deception_hits.py`
- add `scripts/build_incident_from_deception_hits.py`
- add a scenario-family smoke after contracts stabilize
- use `docs/design/deception/deception_scenario_contract.md` before adding
  scenario YAML or runner files
- separately define attacker-agent untrusted artifact safety
- later consider simulation-only agentic DB extortion after deception and
  attacker-agent safety contracts are stable
