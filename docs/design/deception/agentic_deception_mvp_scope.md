# Agentic Deception MVP Scope

> [!IMPORTANT]
> This document originated as the docs-only scope for the first Phase7
> deception MVP. The deterministic artifact foundation it proposed is now
> implemented. Historical planning sections are labeled explicitly; current
> status and active priority are maintained in
> [Phase7](../../roadmap/phase7.md) and the
> [main Roadmap](../../roadmap/roadmap.md).

## 1. Purpose

This document defines the Phase7 agentic deception MVP scope.

Phase7 uses defender-side agentic deception for high-confidence SOC signals.
The MVP is a defensive simulation layer that creates local-lab lures, records
deterministic trap observations, and produces reviewable defender-side
deception hit artifacts.

This document preserves the original MVP scope and its durable design and
safety boundaries. It is not the canonical source for current implementation
status or active sequencing.

## 2. Why this fits Phase7

Phase6 completed the Rule Improvement export MVP for the current
candidate-generation boundary. At the start of Phase7, the next useful direction was to widen defender-side
signal quality before adding state-changing update or promotion workflows.

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

## 4. Historical MVP implementation plan

At the initial docs-only stage, the MVP proposed a small local-lab deception
path:

```text
deception_inventory.yaml
  -> local decoy asset generation
  -> controlled trap interaction
  -> deception_hits.json
  -> future incident bridge
  -> triage / investigation / case
```

The initial plan made `deception_hits.json` the first canonical deception
artifact and deferred canonical detection output integration until that
contract stabilized.

At that stage, the incident bridge was future work. The deterministic artifact
foundation and deception-hit-to-Incident bridge are now implemented. Canonical
detection output integration remains future work.

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

`deception_inventory.yaml` describes local-lab deception assets. Its canonical
schema is:

```text
schemas/deception_inventory.schema.json
```

The inventory can describe:

- lure identity
- lure type
- intended local placement
- trap mechanism
- expected defender-side event name
- expected deception hit artifact type
- lab-only endpoint or file path
- scenario-family association
- cleanup expectations

Deterministic generation is handled by:

```text
scripts/generate_deception_assets.py
```

The schema-backed fixture and deterministic generator are implemented. This
artifact model does not assign or implement a deception scenario runner.

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

## 9. Artifact contracts

`deception_hits.json` records deterministic defender-side trap observations.
Its canonical schema is:

```text
schemas/deception_hits.schema.json
```

Deterministic hit generation is handled by:

```text
scripts/generate_deception_hits.py
```

Incident bridging is handled by:

```text
scripts/build_incident_from_deception_hits.py
```

These schemas, scripts, fixture-backed artifacts, and the
deception-hit-to-Incident bridge are implemented. Scenario YAML / runner
integration and canonical detection output integration remain separate future
work.

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

The initial docs-only scope assigned no scenario number. No deception scenario
number is currently assigned. A future implementation must select one only
after checking the existing scenario IDs.

## 11. Pipeline position

The implemented artifact foundation sits on the defender side of the pipeline:

```text
local deception assets
  -> defender-observable trap interaction
  -> deception_hits.json
  -> incident.json
  -> future triage / investigation / case
  -> optional future Rule Improvement review signal
```

`deception_hits.json` remains a dedicated source artifact. Future canonical
detection output integration may map deception hits into the normal detection
path, but it must preserve the deterministic trap source.

Future scenario YAML and runner implementation is governed separately by
`docs/design/deception/deception_scenario_contract.md`. That contract preserves
the artifact-only chain while documenting scenario numbering, runner behavior,
output locations, and safety boundaries for a future scenario PR.

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

## 13. Durable acceptance criteria

The original implementation-readiness criteria remain durable requirements for
the artifact foundation and any future Phase7 extension:

- `deception_inventory.yaml` uses a schema-backed fixture
- `deception_hits.json` uses a schema-backed fixture
- local decoy asset generation is deterministic
- trap hit generation is deterministic
- canary endpoints remain local-lab only
- attacker-side observed effects are not counted as defender-side hits
- deception hits can be reviewed without bypassing approval gates
- generated `data/runs/**` artifacts are not committed unless explicitly added
  as fixtures

These criteria do not claim live deception scenario execution or runtime
validation. Current validation status is maintained in the Phase7 and main
Roadmap documents.

## 14. Implemented foundation and follow-on work

The implemented deterministic artifact foundation includes:

- `schemas/deception_inventory.schema.json`
- `schemas/deception_hits.schema.json`
- deterministic fixtures
- `scripts/generate_deception_assets.py`
- `scripts/generate_deception_hits.py`
- `scripts/build_incident_from_deception_hits.py`
- artifact-chain smoke coverage

Remaining follow-on tracks are:

- add a scenario-family smoke only when a future scenario YAML / runner is
  intentionally resumed
- use `docs/design/deception/deception_scenario_contract.md` before adding
  scenario YAML or runner files
- separately define attacker-agent untrusted artifact safety
- later consider simulation-only agentic DB extortion after deception and
  attacker-agent safety contracts are stable
