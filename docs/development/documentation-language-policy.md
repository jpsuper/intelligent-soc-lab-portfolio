# Documentation Language Policy

## Purpose

This policy defines the canonical language, responsibilities, translation
rules, and synchronization cadence for the repository's primary public and
planning documents. It is intended to keep AI-assisted development grounded in
one authoritative source while allowing Japanese reference translations to be
maintained at a sustainable cadence.

This policy does not change implementation status or resolve existing content
conflicts by itself. When current documents disagree, verify the claim against
the code, tests, schemas, fixtures, and Git history before editing the English
canonical source. Do not reconcile conflicting claims by inference.

## Canonical documents

English is the canonical documentation language for the following files and
document families:

| Canonical English source | Japanese reference translation |
|---|---|
| `README.md` | `README_ja.md` |
| `docs/architecture/defender-event-processing-flow.md` | `docs/architecture/defender-event-processing-flow_ja.md` |
| `docs/AI_SOC_Lab_Master_Guide.md` | `docs/AI_SOC_Lab_Master_Guide_ja.md` |
| `docs/roadmap/roadmap.md` | `docs/roadmap/roadmap_ja.md` |
| `docs/roadmap/phase*.md` | Phase-specific Japanese translations are optional and are not required for every phase. |

The English files are authoritative. Japanese documents are reference
translations derived from an approved English source. If an English document
and a Japanese translation differ, the English document takes precedence.

The English filenames above remain canonical even while known mixed-language
content is being migrated. Existing language mixing does not make the Japanese
prose authoritative.

Phase 8 currently exists as a section in `docs/roadmap/roadmap.md`. There is no
separate `docs/roadmap/phase8.md`. This policy does not introduce one.

## Archived documents

Documents under `docs/design/archive/` provide historical context. They are not
canonical sources for current implementation status, priorities, sequencing,
or Done Criteria.

Archived documents are outside routine Japanese synchronization. A Japanese
reference translation is not required. For current claims, consult the
canonical English documents and current design contracts instead.

## Update cadence

- Update the English canonical documents continuously when implementation,
  validation evidence, priorities, or Done Criteria change.
- Do not require every implementation PR to update every Japanese translation.
- Synchronize Japanese reference translations when explicitly requested or at
  a documented workstream or milestone boundary.
- Synchronize the English and Japanese public document sets before a portfolio
  release.
- If a Japanese translation is not synchronized with its English source, state
  that fact prominently at the beginning of the Japanese document.

Deferring a Japanese synchronization must not defer a necessary update to the
English canonical source.

## Document responsibilities

### README

`README.md` provides a first-visit overview, the major capabilities, concise
current status, architecture boundaries, and links to deeper documentation. It
should not become a detailed implementation log.

### Master Guide

`docs/AI_SOC_Lab_Master_Guide.md` describes stable architecture, design
principles, artifact contracts, evidence boundaries, and operating policy. It
may summarize durable capability boundaries, but it is not the authority for a
frequently changing workstream status or priority list.

### Main Roadmap

`docs/roadmap/roadmap.md` is the canonical source for current status,
priorities, incomplete work, sequencing, and Done Criteria. Changes to
Implemented, Validated, Planned, Deferred, or Unverified status should be
reconciled here.

### Phase documents

`docs/roadmap/phase*.md` contains phase-specific detail, history, validation
results, and scoped decisions. A phase document may preserve historical plans
when they are clearly labeled as historical. It must not silently contradict
the current status or priorities in `docs/roadmap/roadmap.md`.

### Volatile status ownership

Do not maintain the same frequently changing Current Status block in both the
Master Guide and the main Roadmap. Keep volatile status, active priorities,
unfinished work, and current Done Criteria in `docs/roadmap/roadmap.md`. The
Master Guide should link to the Roadmap and retain only stable architectural and
contractual context. The README may carry a short current summary that is kept
consistent with the Roadmap.

## Translation rules

Do not translate:

- code identifiers
- JSON or schema field names
- enum values
- file paths
- CLI options
- scenario IDs
- artifact names
- product names

Do not change executable code, JSON, YAML, commands, paths, schema names,
artifact names, field names, enum values, scenario IDs, or other
machine-consumed values unless the canonical English source itself requires a
separately reviewed technical correction. This rule applies whether those
values appear in prose, a table, or a fenced block.

Human-readable labels and explanatory prose in fenced `text` diagrams and
Mermaid diagrams may be translated. Preserve Mermaid node IDs, edges, ordering,
and technical semantics. Within any diagram, do not translate file paths,
artifact names, field names, or other protected technical values.

Translation must not change status semantics. In particular, do not upgrade,
downgrade, or conflate:

- Implemented
- Validated
- Planned
- Deferred
- Unverified

A translation must preserve whether evidence is fixture-based, manually
observed, live, runtime-validated, schema-validated, or not yet verified. It
must also preserve attacker/defender evidence boundaries, pre-case/post-action
boundaries, and approval or promotion gates.

Translation is not authorization to add implementation claims, remove
limitations, or combine contradictory descriptions. Resolve the English source
first, with evidence, and then translate the approved result.

## Japanese synchronization metadata

Each Japanese reference translation should include a notice at the beginning
of the document that records:

- canonical source
- synchronization status
- last synchronization date or portfolio snapshot identifier

Use an ISO date for `last synchronization date`, or use a stable workstream,
milestone, or portfolio snapshot identifier. Do not embed the SHA of the commit
that contains the notice itself; a document cannot reliably self-identify the
commit being created. A same-commit SHA is not the synchronization mechanism.

Example for a synchronized translation:

```text
Reference translation. The English document is canonical.
Canonical source: README.md
Synchronization status: synchronized
Last synchronization date: 2026-08-03
```

Example for a translation awaiting synchronization:

```text
Reference translation. The English document is canonical.
Canonical source: README.md
Synchronization status: pending synchronization; the English source may be newer
Portfolio snapshot: portfolio-milestone-name
```

The notice must appear before the main translated content when synchronization
is pending. A translation without a current synchronization marker must not be
treated as evidence of current implementation status.

## Documentation workflow

For implementation work:

1. Update the relevant English canonical source when its status or contract is
   affected.
2. Verify technical claims against repository evidence and preserve explicit
   Implemented, Validated, Planned, Deferred, and Unverified boundaries.
3. Update a Japanese translation only when the work explicitly includes it or
   reaches a documented workstream, milestone, or portfolio boundary.
4. When synchronizing, translate from the approved English source and record
   the synchronization metadata.
5. Validate heading correspondence, links, code fences, Mermaid blocks, and
   preserved technical tokens before publishing both languages.

When a conflict is found, report it before consolidating content. The English
source takes precedence only after its claim has been checked against repository
evidence; canonical status does not make an unsupported claim correct.
