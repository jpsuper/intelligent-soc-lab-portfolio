# ADR 0001: Repository Organization Policy

## Status

Accepted

## Context

`intelligent-soc-lab` has grown from a small SOC pipeline into a multi-stage lab with attacker execution, defender telemetry, detection, triage, investigation, case, action, DFIR, comparison harnesses, and Rule Improvement workflows.

The repository already has a useful structure:

```text
agents/
attacks/
common/
configs/
detection/
docs/
rubrics/
schemas/
scripts/
scenarios/
tests/
tools/
workflows/
```

The main pressure point is not that the current layout is wrong. The pressure point is that future harness, DFIR, integration, deception, and coding-agent workflow work could cause uncontrolled directory growth or large mixed-purpose migrations.

The repository may adopt skill-style workflow discipline for coding agents, but that does not require vendoring an external skills repository, adding tool-specific command directories, or changing the top-level layout.

## Decision

The repository will keep the current top-level layout for now.

Near-term changes should focus on documenting structure and contributor policy rather than moving many files at once.

The following policies are adopted:

1. Keep `agents/`, `attacks/`, `detection/`, `scenarios/`, `schemas/`, `scripts/`, `workflows/`, `rubrics/`, and `tests/` stable for now.
2. Keep JSON Schemas centralized under `schemas/`.
3. Use `docs/development/` for repository-wide development and coding-agent guidance.
4. Use `docs/adr/` for durable architectural decisions.
5. Use domain subdirectories under `docs/design/` when a topic has multiple design documents.
6. Keep DFIR design documents under `docs/design/dfir/`.
7. Do not perform large physical directory moves in the same PR as behavior changes.
8. Treat future harness consolidation as a dedicated migration, not an opportunistic cleanup.
9. Keep coding-agent workflow guidance in root `AGENTS.md` and repository policy docs unless a future ADR introduces a dedicated repository-local workflow or skills directory.
10. Do not vendor external agent-skill packs, slash-command folders, or persona catalogs into this repository without a dedicated design or ADR.
11. Keep Phase7 deception artifacts in the existing structure for now: schemas in `schemas/`, scripts in `scripts/`, fixtures in `tests/fixtures/deception/`, and design docs in `docs/design/deception/`.

## Consequences

Positive consequences:

- The current working structure remains stable.
- Existing scripts, tests, workflow paths, and docs references are less likely to break.
- Future contributors and coding agents get clear placement rules.
- Large migrations become reviewable and reversible.
- DFIR, harness, integration, and deception growth can be managed incrementally.
- Coding agents get consistent DEFINE / PLAN / BUILD / VERIFY / REVIEW / SHIP expectations without forcing tool-specific repository structure.

Tradeoffs:

- Harness-related files remain distributed across `scripts/`, `workflows/`, and `rubrics/` for now.
- Some schema naming inconsistencies may remain until a dedicated cleanup PR.
- Integration adapters remain under `agents/` until a future design justifies moving them.
- Agent-skill style workflows remain policy guidance rather than a first-class `skills/` or command directory until there is a dedicated need.

## Rejected alternatives

### Full immediate restructure

Rejected because it would create a large diff across scripts, workflows, tests, docs, and imports while providing little immediate functional benefit.

### Move all harness files now

Rejected for now because harness behavior is still evolving and path churn would make active work harder to review.

### Move integration adapters to `integrations/` immediately

Rejected for now because current adapters participate as artifact-producing pipeline stages. They can remain under `agents/` until the integration boundary becomes more complex.

## Follow-up options

Future ADRs may define:

- harness directory consolidation
- schema naming normalization
- integration adapter split
- test fixture organization
- generated sample artifact policy
- repository-local coding-agent workflow or skills directory, if the project later needs one
- Phase7 deception directory consolidation, if deception scripts and fixtures outgrow the current centralized layout
