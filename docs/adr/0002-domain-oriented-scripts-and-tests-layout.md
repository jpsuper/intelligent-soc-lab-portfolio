# ADR 0002: Domain-Oriented Subdirectories for Scripts and Tests

## Status

Accepted

## Context

The repository top-level layout is not the problem. The stable roots established
by [ADR 0001](0001-repository-organization-policy.md) continue to represent the
lab's major responsibilities well:

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

The narrower pressure is that the flat roots of `scripts/` and `tests/` have
grown. Domain ownership is increasingly encoded only in long filenames.
Windows telemetry for Sysmon Event ID 1 is now a cohesive example: it has a
source parser, normalized mapper, native parity validator, PowerShell collector,
and eight focused test files that share an artifact contract and review
lifecycle.

A repository-wide restructure is unnecessary. Before the next functional
slice adds `expected_normalized` artifacts, the repository needs a placement
rule that improves discoverability without changing runtime behavior or
artifact contracts.

Directory creation is not justified merely by file count. Cohesive ownership,
a shared lifecycle, and a focused validation suite are the decision signals.

## Decision

### Stable top-level layout

The existing top-level directories remain stable. This decision does not add a
top-level `src/`, `harnesses/`, `windows/`, or `telemetry/` directory.

### Domain subdirectories

When a cohesive domain owns multiple implementation, operator, or test files,
it may introduce subdirectories inside the existing top-level roots:

```text
scripts/<domain>/<family>/
tests/<domain>/<family>/
```

Signals that support a domain subdirectory include:

- the files implement or validate the same artifact contract or telemetry
  family;
- the files are reviewed through the same focused validation suite;
- the domain has at least three related implementation/operator files or
  multiple focused test files;
- further growth in the same domain is expected; and
- the directory has clear ownership rather than serving as a catch-all.

The numeric signal is not a hard threshold. Reviewers must evaluate cohesion
and lifecycle ownership.

### Tests mirror behavioral ownership

When implementation/operator files move into a domain directory, focused tests
may move to:

```text
tests/<domain>/<family>/
```

The test tree does not need to mirror the production tree exactly. Behavioral
ownership and fixture family are more important than structural symmetry.

### Fixtures remain centralized

Stable fixtures remain under:

```text
tests/fixtures/<domain>/<family>/
```

The Windows Sysmon Event ID 1 fixtures remain at:

```text
tests/fixtures/windows/sysmon_event1/
```

### Schemas remain centralized

Schemas remain directly under:

```text
schemas/
```

This decision does not create `schemas/windows/`,
`tests/windows/sysmon_event1/schemas/`, or
`scripts/windows/sysmon_event1/schemas/`.

### Documentation remains purpose-oriented

Design documents and runbooks retain their purpose-oriented locations:

```text
docs/design/windows/
docs/runbooks/windows/
```

Documentation is not moved merely to mirror code or test layout.

## Windows / Sysmon Event ID 1 Pilot

Windows Sysmon Event ID 1 is the first domain-oriented layout pilot. The target
layout for a later move-only PR is:

```text
scripts/
  windows/
    sysmon_event1/
      parse_sysmon_event1_source.py
      map_sysmon_event1_to_endpoint_event.py
      validate_sysmon_event1_native_parity.py
      export_sysmon_event1_provider_json.ps1

tests/
  windows/
    sysmon_event1/
      test_sysmon_event1_source_fixture_schema.py
      test_sysmon_event1_source_fixtures.py
      test_parse_sysmon_event1_source.py
      test_sysmon_event1_parsed_event_schema.py
      test_sysmon_event1_expected_parsed.py
      test_sysmon_event1_native_collector_contract.py
      test_validate_sysmon_event1_native_parity.py
      test_map_sysmon_event1_to_endpoint_event.py

tests/
  fixtures/
    windows/
      sysmon_event1/
        source/
        expected_parsed/
```

The exact move inventory confirmed on the decision baseline is:

| Current | Target |
|---|---|
| `scripts/parse_sysmon_event1_source.py` | `scripts/windows/sysmon_event1/parse_sysmon_event1_source.py` |
| `scripts/map_sysmon_event1_to_endpoint_event.py` | `scripts/windows/sysmon_event1/map_sysmon_event1_to_endpoint_event.py` |
| `scripts/validate_sysmon_event1_native_parity.py` | `scripts/windows/sysmon_event1/validate_sysmon_event1_native_parity.py` |
| `scripts/windows/export_sysmon_event1_provider_json.ps1` | `scripts/windows/sysmon_event1/export_sysmon_event1_provider_json.ps1` |
| `tests/test_sysmon_event1_source_fixture_schema.py` | `tests/windows/sysmon_event1/test_sysmon_event1_source_fixture_schema.py` |
| `tests/test_sysmon_event1_source_fixtures.py` | `tests/windows/sysmon_event1/test_sysmon_event1_source_fixtures.py` |
| `tests/test_parse_sysmon_event1_source.py` | `tests/windows/sysmon_event1/test_parse_sysmon_event1_source.py` |
| `tests/test_sysmon_event1_parsed_event_schema.py` | `tests/windows/sysmon_event1/test_sysmon_event1_parsed_event_schema.py` |
| `tests/test_sysmon_event1_expected_parsed.py` | `tests/windows/sysmon_event1/test_sysmon_event1_expected_parsed.py` |
| `tests/test_sysmon_event1_native_collector_contract.py` | `tests/windows/sysmon_event1/test_sysmon_event1_native_collector_contract.py` |
| `tests/test_validate_sysmon_event1_native_parity.py` | `tests/windows/sysmon_event1/test_validate_sysmon_event1_native_parity.py` |
| `tests/test_map_sysmon_event1_to_endpoint_event.py` | `tests/windows/sysmon_event1/test_map_sysmon_event1_to_endpoint_event.py` |

Fixtures, schemas, design documents, and the native parity runbook are
intentionally excluded from this move inventory.

The pilot does not move the parser or mapper into
`agents/parser-agent/src/`. The current Sysmon modules form a small cohesive
implementation set used together by the native validator and focused tests.
A cross-top-level relocation would also require decisions
about the `pyproject.toml` Python path, operator imports, and agent packaging.
That is a parser-agent package-boundary decision, not a simple flat-root
hygiene migration.

Placement in `scripts/` is not permanent. Parser-agent integration may be
reconsidered through a dedicated ADR or feature plan when that integration is
designed.

## Placement Rules

- Use `scripts/<domain>/<family>/`, never the singular
  `script/<domain>/<family>/`.
- Use a domain directory only for cohesive ownership and a shared review
  lifecycle.
- Do not create catch-all `utilities`, `misc`, or equivalent folders for
  unrelated files.
- Preserve current filenames and public function names during a move-only
  migration.
- Keep stable fixtures centralized under `tests/fixtures/`.
- Keep schemas centralized under `schemas/`.
- Keep design documents and runbooks organized by documentation purpose.
- Reconfirm exact current files and references with `git ls-files` and `rg`
  immediately before a migration.

## Migration Rules

### Dedicated move-only PR

The pilot migration must be a dedicated move-only PR.

Allowed:

- `git mv`;
- import path updates;
- schema path resolution updates;
- test file path updates;
- PowerShell collector path-reference updates;
- documentation and runbook command-path updates;
- Makefile, CI, workflow, and helper path updates;
- the minimum necessary `pyproject.toml` Python-path update;
- stale-reference tests or a static guard; and
- minimal `__init__.py` files only when required for stable imports.

Import and schema-path changes are mechanical changes required to preserve
existing behavior after the move. They are not authorization for functional
changes.

Forbidden:

- parser, mapper, validator, or collector behavior changes;
- canonical event ID or timestamp policy changes;
- schema or fixture content changes;
- new expected artifacts or Fixture B;
- detection or Wazuh integration;
- new dependencies;
- generated or live artifacts; and
- unrelated cleanup or renaming.

### Compatibility

Do not add old-path compatibility wrappers by default. Repository-internal
references can be updated atomically, while duplicate module paths preserve
stale imports and create removal debt. Do not use symlinks.

A wrapper may receive separate review only if repository discovery proves that
an externally documented command cannot be updated at the same time. Any
exception must have a deadline and explicit removal condition.

### Imports

The migrated Python modules must support deterministic execution from the
repository root. Pytest must collect and run the intended tests, direct script
invocation must resolve required domain-local modules, and the migration must
not add broad runtime `sys.path` mutation.

If packaging is needed, use only minimal `__init__.py` files. Preserve current
filenames and public functions, and do not change behavior through the import
mechanism. The move-only PR must document its exact import mechanism.

### Reference inventory

Immediately before the move-only PR, enumerate references with:

```bash
rg -n \
  'parse_sysmon_event1_source\.py|map_sysmon_event1_to_endpoint_event\.py|validate_sysmon_event1_native_parity\.py|export_sysmon_event1_provider_json\.ps1|test_.*sysmon_event1' \
  . \
  --glob '!review-files-*' \
  --glob '!data/**'
```

Review candidates include `docs/`, `scripts/`, `tests/`, `tools/`,
`workflows/`, `Makefile`, and `pyproject.toml`. Generated bundles and `data/`
are not repository authority.

### Move-only verification contract

Old implementation/operator paths must be absent:

```bash
test ! -e scripts/parse_sysmon_event1_source.py
test ! -e scripts/map_sysmon_event1_to_endpoint_event.py
test ! -e scripts/validate_sysmon_event1_native_parity.py
test ! -e scripts/windows/export_sysmon_event1_provider_json.ps1
```

New implementation/operator paths must be present:

```bash
test -f scripts/windows/sysmon_event1/parse_sysmon_event1_source.py
test -f scripts/windows/sysmon_event1/map_sysmon_event1_to_endpoint_event.py
test -f scripts/windows/sysmon_event1/validate_sysmon_event1_native_parity.py
test -f scripts/windows/sysmon_event1/export_sysmon_event1_provider_json.ps1
```

The focused suite must be collected and executed from:

```bash
uv run python -m pytest -q tests/windows/sysmon_event1
```

Zero collected tests is not success. Confirm that the current eight test files
or more are collected as intended and that the focused suite retains its
pre-move behavior.

Run Ruff on Python files only:

```bash
uv run ruff check \
  scripts/windows/sysmon_event1 \
  tests/windows/sysmon_event1

uv run ruff format --check \
  scripts/windows/sysmon_event1 \
  tests/windows/sysmon_event1
```

Search for stale old paths:

```bash
rg -n \
  'scripts/parse_sysmon_event1_source\.py|scripts/map_sysmon_event1_to_endpoint_event\.py|scripts/validate_sysmon_event1_native_parity\.py|scripts/windows/export_sysmon_event1_provider_json\.ps1|tests/test_(parse_)?sysmon_event1|tests/test_map_sysmon_event1|tests/test_validate_sysmon_event1' \
  AGENTS.md Makefile pyproject.toml docs scripts tests tools workflows
```

No match is expected except for the historical current-to-target inventory in
this ADR.

Confirm that contracts and fixture contents are unchanged:

```bash
git diff -- \
  schemas \
  tests/fixtures/windows/sysmon_event1
```

Finally, inspect rename detection:

```bash
git diff --summary
```

Target files should be recognized as renames. When mechanical import or
path-resolution edits prevent 100% similarity, reviewers must confirm that the
content changes are limited to path mechanics.

## Consequences

Positive:

- domain ownership becomes visible in paths;
- related implementation/operator files and tests become easier to discover;
- the stable top-level layout and centralized schemas/fixtures remain intact;
- the next Sysmon feature slice can follow a documented placement rule; and
- move-only review remains separate from behavior review.

Tradeoffs:

- imports, schema resolution, pytest discovery, operator commands, and
  documentation references require coordinated mechanical updates;
- some other domain files remain flat until their ownership justifies a
  dedicated migration; and
- parser-agent ownership remains unresolved until integration is designed.

## Rejected Alternatives

### Full repository restructure

Rejected because it would involve unrelated domains, create extensive path
churn, interrupt current feature development, and conflict with ADR 0001's
incremental policy.

### New top-level `windows/` or `src/`

Rejected because it would break the stable top-level policy and prematurely
make a repository-wide packaging decision.

### Move parser and mapper into parser-agent now

Deferred for this pilot because it requires additional parser-agent package and
import-boundary design, increases cross-root imports for the native validator,
and exceeds simple flat-root cleanup. It may be reconsidered through a
dedicated ADR or feature-integration plan.

### Keep everything flat forever

Rejected because domain discoverability would continue to decline, unrelated
root files would continue to accumulate, and new Windows slices would be
harder to place consistently.

### Compatibility wrappers by default

Rejected because they preserve stale paths, create duplicate import surfaces,
and are unnecessary for an atomic repository-internal migration.

## Follow-Up

The intended sequence is:

1. merge this docs-only target policy;
2. perform the Windows Sysmon Event ID 1 move-only migration; and
3. add the new `expected_normalized` feature in a later focused PR.

This ADR does not authorize full repository restructuring or early harness
consolidation.

Explicit non-goals for this docs-only decision are:

- actual file moves;
- import, test, parser, mapper, validator, or collector changes;
- fixture, schema, or dependency changes;
- `expected_normalized`, Fixture B, or detection additions;
- harness consolidation;
- deception, DFIR, action, or unrelated test-file moves;
- a new top-level directory; and
- generated artifact commits.
