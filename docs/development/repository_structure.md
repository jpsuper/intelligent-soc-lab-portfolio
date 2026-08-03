# Repository Structure Policy

## Purpose

This document defines the current repository organization policy for `intelligent-soc-lab`.

The goal is to keep the repository understandable as the lab grows from a single pipeline into a comparable SOC experimentation platform with attacker, defender, investigation, action, DFIR, and improvement-loop components.

This document is policy only. It does not require immediate physical directory moves.

---

## Current organization stance

The current layout is a good base and should not be replaced wholesale.

The following top-level directories are intentionally stable for now:

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

The priority is to make future changes predictable, not to reorganize everything at once.

---

## Directory responsibilities

### `agents/`

Contains stage-specific agents and integration adapters.

Examples:

```text
agents/attacker-agent/
agents/case-agent/
agents/investigation-agent/
agents/post-action-dfir-agent/
agents/rule-improvement-agent/
agents/velociraptor-agent/
```

Current policy:

- Keep agents under `agents/` for now.
- Integration adapters such as Velociraptor and TheHive may remain under `agents/` while they participate in the artifact pipeline.
- If integration adapters grow significantly, consider a future design PR before moving them under a new `integrations/` directory.

Agent-local module organization may be introduced when one agent grows multiple related modules. Keep these local moves scoped to that agent and avoid coupling them to behavior changes.

Current post-action DFIR parser layout:

```text
agents/post-action-dfir-agent/src/
  main.py
  result_builder.py
  parser_registry.py
  parsers/
    __init__.py
    linux_syslog_ssh_login.py
    linux_process_list.py
    linux_bash_history.py
```

Post-action DFIR parser policy:

- Keep artifact-specific post-action parsers under `agents/post-action-dfir-agent/src/parsers/`.
- Keep artifact-to-parser dispatch in `agents/post-action-dfir-agent/src/parser_registry.py`.
- Preserve parser IDs, fact types, limitation wording, and evidence semantics when moving parser modules.
- Add new parser modules with focused tests and update the registry in the same PR.
- Do not mix parser module moves with schema changes, new artifact semantics, or generated run artifacts.

### `attacks/`

Contains runnable attack-side scripts and execution support.

Current policy:

- Keep shell runners under `attacks/runners/`.
- Keep attack scenario definitions separate under `scenarios/`.
- Do not mix generated attack outputs into this directory.

### `scenarios/`

Contains scenario YAML contracts.

Current policy:

- Scenario YAML defines intent and expected artifacts.
- Scenario YAML should not contain inline shell payloads when shell backend policy forbids them.
- Scenario additions should preserve comparable artifacts and tests.

### `detection/`

Contains detection logic, DSLs, and detection-related assets.

Current policy:

- Keep deterministic detection logic separate from AI triage/investigation logic.
- Detection should primarily produce observed facts and canonical detection outputs.
- Conclusion-like fields belong in triage, investigation, case, or action stages.

### `schemas/`

Contains JSON Schemas for repository artifacts.

Current policy:

- Keep schemas centralized at the top level for now.
- Centralized storage does not mean every existing artifact already has a
  schema. Confirm that a schema exists and is intended for the exact artifact
  before requiring schema validation.
- Do not validate an artifact against a related but semantically different
  schema.
- Existing schema-less artifacts should continue to use their established
  structural contract tests until a dedicated schema-introduction PR is
  approved.
- Every new first-class JSON artifact should have a schema unless explicitly documented as experimental.
- Introduce a new first-class schema deliberately, with contract documentation
  and focused tests in the same scoped change.
- Schema naming may be cleaned up later in a dedicated PR, but avoid mixing naming cleanup with behavior changes.

### `common/`

Contains shared utilities used across agents and scripts.

Current policy:

- Shared run-path logic belongs here.
- Avoid placing stage-specific business logic here unless multiple stages genuinely share it.

### `scripts/`

Contains orchestration, export, harness, and utility scripts that are not stage agents.

Current policy:

- Existing harness and export scripts may remain here for now.
- A cohesive domain may use `scripts/<domain>/<family>/` when its
  implementation/operator files share ownership and a review lifecycle.
- Use the existing plural root `scripts/<domain>/<family>/`, not
  `script/<domain>/<family>/`.
- Do not continue adding related files to the flat root when a reviewed domain
  directory exists.
- Domain directories must not become catch-all utility folders.
- The first target is
  [`scripts/windows/sysmon_event1/`](../adr/0002-domain-oriented-scripts-and-tests-layout.md#windows--sysmon-event-id-1-pilot).
- Moving the Sysmon parser or mapper into `parser-agent` is deferred pending a
  separate package-boundary decision.
- Future physical consolidation into a `harnesses/` area should be preceded by an ADR or design note.

### `workflows/`

Contains YAML workflow definitions for harnesses and stage runners.

Current policy:

- Keep current workflow files here for now.
- If harness consolidation happens later, workflows may move together with related rubrics and scripts.

### `rubrics/`

Contains judge and comparison rubrics.

Current policy:

- Keep current rubrics here for now.
- Do not move rubrics without also updating workflow references, scripts, docs, and tests.

### `tools/`

Contains helper tools for local operations, smoke checks, and developer workflows.

Current policy:

- Tools should be safe, explicit, and scoped.
- Tools that produce generated artifacts should default to non-committed paths such as `/tmp` or `data/runs/<run_id>/`.

### `configs/`

Contains deployable or manually applied configuration snippets.

Current policy:

- Configs should be reviewed before manual application.
- Configs should not imply automatic deployment unless a deployment mechanism is explicitly added.

### `tests/`

Contains tests and synthetic fixtures.

Current policy:

- Unit tests should stay focused and deterministic.
- Focused test families may use `tests/<domain>/<family>/` when a reviewed
  domain boundary exists.
- The test tree does not need to mirror the production tree exactly;
  behavioral ownership and fixture family take precedence.
- Use `tests/fixtures/` for stable fixture inputs.
- Keep fixtures centralized at `tests/fixtures/<domain>/<family>/`.
- The first test-layout target is
  [`tests/windows/sysmon_event1/`](../adr/0002-domain-oriented-scripts-and-tests-layout.md#windows--sysmon-event-id-1-pilot),
  while fixtures remain in `tests/fixtures/windows/sysmon_event1/`.
- Avoid relying on generated `data/runs/` artifacts for tests unless explicitly copied into fixtures.

### `docs/`

Contains design, roadmap, operations, architecture, and development documentation.

Current policy:

```text
docs/architecture/   high-level system architecture
docs/design/         contracts and domain-specific design
docs/development/    repository-wide contributor and coding-agent policies
docs/adr/            architectural decision records
docs/operations/     smoke checks and runbooks
docs/roadmap/        phase plans and status
```

---

## Design-document organization

`docs/design/` may use domain subdirectories when a topic has more than one document.

Examples:

```text
docs/design/attacker-agent/
docs/design/defender/
docs/design/deception/
docs/design/dfir/
docs/design/investigation/
docs/design/rule-improvement/
```

Scenario-specific design, validation plans, environment records, and bounded
validation results should use:

```text
docs/design/scenarios/<scenario-id-or-short-name>/
```

Scenario-specific operational procedures and reversible validation runbooks
should remain separate under:

```text
docs/operations/scenarios/<scenario-id-or-short-name>/
```

Use `overview.md` as the scenario navigation entry point. Cross-scenario
contracts remain in shared design directories, and scenario-specific documents
should not accumulate at the `docs/design/` root. Operational procedures remain
separate from design and validation-result records.

DFIR design documents should use:

```text
docs/design/dfir/
```

Current DFIR examples:

```text
docs/design/dfir/collection_result_contract.md
docs/design/dfir/collection_result_ingestion.md
docs/design/dfir/post_action_dfir_investigation.md
```

Phase7 deception design documents should use:

```text
docs/design/deception/
```

Current deception example:

```text
docs/design/deception/agentic_deception_mvp_scope.md
```

---

## Coding-agent workflow policy

Root `AGENTS.md` is the primary coding-agent instruction file. It should contain
repository-specific operating rules, boundaries, and workflow expectations.

The repository may use skill-style workflow discipline, but it does not currently
have a first-class `skills/`, `commands/`, or persona catalog. Do not add
external agent-skill packs, tool-specific command directories, or persona files
as an incidental cleanup.

The workflow guidance was last reviewed against
[`addyosmani/agent-skills@7829ffd`](https://github.com/addyosmani/agent-skills/commit/7829ffd90d973b6325f5f12f1b1226dcace74443).
The external repository is a reference, not a runtime dependency or an automatic
sync source. Its root `AGENTS.md` governs that repository itself. Review upstream
changes selectively and translate applicable principles into this repository's
Python/uv toolchain, artifact contracts, and lab-safety boundaries.

A future guidance refresh should:

1. Record the reviewed upstream commit.
2. Separate applicable workflow principles from plugin, hook, persona, command,
   eval, and ecosystem-specific implementation details.
3. State which material changes were adopted and which were intentionally not
   adopted.
4. Keep `AGENTS.md` concise enough to remain operational and avoid copying the
   external catalog wholesale.

If repository-local skill or workflow files become necessary later:

1. Document the target structure first under `docs/development/` or a new ADR.
2. Keep the first PR docs-only or move-only.
3. Avoid mixing workflow-file introduction with feature behavior changes.
4. Keep workflow files repository-specific and avoid copying large external
   catalogs wholesale.

---

## Phase7 deception organization policy

Phase7 deception files should stay within the existing top-level layout for now.

Current placement policy:

```text
docs/design/deception/              deception design and artifact-boundary docs
schemas/deception_*.schema.json     first-class deception artifact schemas
scripts/generate_deception_*.py     deterministic deception utilities
tests/fixtures/deception/<family>/  stable deception fixtures
tests/test_*deception*.py           focused deception tests
```

Do not create a dedicated top-level `deception/` directory, move schemas under a
schema subdirectory, or add a new Deception Agent package until the behavior and
artifact boundaries justify it. If deception scripts, fixtures, or trap-detection
logic grow significantly, use a dedicated design or migration PR before changing
physical layout.

Generated deception outputs should remain outside git unless they are curated
fixtures under `tests/fixtures/deception/`.

---

## Harness organization policy

Harness-related files are currently distributed across:

```text
scripts/
workflows/
rubrics/
tests/
```

This is acceptable for now.

Future consolidation may introduce a structure such as:

```text
harnesses/
  triage/
  investigation/
  action/
  rule-improvement/
```

However, this should not be done opportunistically inside unrelated PRs.

A harness migration PR should:

1. Move files without behavior changes.
2. Update imports and path references.
3. Update workflow paths and docs references.
4. Run targeted harness tests.
5. Avoid changing judge behavior in the same PR.

---

## Generated artifact policy

Generated artifacts should generally not be committed.

Examples:

```text
data/runs/**
data/harness_runs/**
data/attacks/**/attack_result.json
data/attacks/**/attack_execution_log.json
data/attacks/**/attack_observed_effects.json
review-files-*.tgz
review-files-*.zip
```

Stable synthetic inputs should live under:

```text
tests/fixtures/
```

Sample artifacts may live under a documented sample directory only when they are intentionally curated.

Local review and transfer bundles should be moved outside the repository before
staging unless they are deliberately curated repository artifacts. Do not add
broad ignore rules for `*.txt`, `*.diff`, `*.patch`, `*.tgz`, or `*.zip`; those
patterns could hide legitimate fixtures, documentation assets, or other
intentional repository content.

---

## Migration principles

Use staged migration.

Preferred order:

```text
1. Docs-only ADR / target policy.
2. Move-only migration, including mechanical reference and test-path fixes.
3. Feature work, such as new expected_normalized artifacts.
```

See
[ADR 0002](../adr/0002-domain-oriented-scripts-and-tests-layout.md) for
domain-oriented scripts/tests placement and migration rules.

Avoid:

```text
large move + schema change + behavior change + generated artifacts
```

Large moves should have PR titles that make the migration explicit.

---

## Current recommendation

Do not immediately restructure the full repository.

Recommended near-term focus:

1. Keep current top-level layout stable.
2. Add development and ADR docs.
3. Keep schemas centralized.
4. Keep DFIR design under `docs/design/dfir/`.
5. Keep post-action DFIR parser modules under the local `parsers/` package and dispatch through `parser_registry.py`.
6. Keep Phase7 deception artifacts in the current centralized layout until the deception pipeline stabilizes.
7. Keep coding-agent workflow guidance in `AGENTS.md` and `docs/development/` unless a future ADR creates a dedicated workflow/skills directory.
8. Consider harness consolidation only after current case / action / DFIR result ingestion and Phase7 deception work stabilize.
9. Use Windows / Sysmon Event ID 1 as the first domain-oriented scripts/tests
   pilot.
