# Linux Scenario Family Candidates

## 1. Purpose

This document defines candidate Linux scenario families before adding
`scenario_009` or later scenarios. The first implementation PR selected
`scenario_009` for `suspicious_archive_staging` after checking existing
scenario YAML and runner files.

It began as a mapping-first planning document. The original planning step did
not assign or reserve a scenario ID and did not add scenario YAML, runners,
scripts, schemas, tests, fixtures, vendored Atomic Red Team content, CALDERA
integration, or generated run artifacts.

The goal is to choose the next Linux behavior family by comparing artifact
contracts, defender-side evidence needs, testability, and safety boundaries
before implementation.

## 2. Current baseline

Existing scenarios currently cover:

- SSH brute force
- process execution
- download and execute
- `authorized_keys` persistence
- SSH key reuse
- suspicious file write
- system discovery

The governing policy is
`docs/design/scenario_family_expansion_policy.md`.

Current baseline constraints:

- Phase7 deception artifact foundation is complete, but deception scenario
  YAML / runner implementation is intentionally deferred.
- Local scenario YAML and shell runners remain the default execution model for
  near-term scenario implementation.
- Scenario IDs should be selected only in the implementation PR after checking
  both `scenarios/` and `attacks/runners/`.
- A planned family name is not a reserved scenario ID.

## 3. Runner model and external framework stance

Keep the current local runner model for near-term scenario implementation.

The runner is an execution backend, not the whole scenario contract. The
repository scenario contract remains centered on:

- scenario YAML
- runner output
- `attack_execution_log.json`
- `attack_observed_effects.json`
- `attack_result.json`
- defender-side artifacts
- evaluation / harness compatibility

External frameworks must not bypass artifact contracts, safety boundaries,
approval gates, or attacker-side / defender-side evidence separation.

The core boundary remains:

```text
attacker-side observed effect != defender-side observed artifact
```

## 4. Candidate family evaluation criteria

Each candidate family should be reviewed against the following criteria before
implementation:

| Field | Review question |
|---|---|
| `scenario_family` | What stable family name describes the behavior? |
| likely proposed `scenario_id` status | Is the scenario ID still `not assigned`? |
| attacker-side observed effects | What effects would a runner report in structured events or `attack_observed_effects.json`? |
| defender-side artifacts | What logs, endpoint events, parser outputs, or fixtures would prove defender observation? |
| expected detection artifacts | What DSL hits, canonical detections, endpoint observations, or future detections are expected? |
| incident expectations | What should incident generation claim, and what should it avoid claiming? |
| triage expectations | What can triage infer from defender evidence only? |
| investigation expectations | What pivots, evidence gaps, and limitations should investigation preserve? |
| action / containment boundary | What state-changing operations remain approval-gated or out of scope? |
| fixture requirements | What synthetic inputs are needed for deterministic local tests? |
| tests needed | What focused tests are needed in the implementation PR? |
| safety risks | What behavior could become unsafe if scoped poorly? |
| implementation complexity | How much new runner, telemetry, detection, and pipeline work is needed? |
| research value now | Does the family expand useful Linux SOC coverage now? |
| dependency on future components | Does it require Wazuh, SIEM, deception, Windows, AD, or attacker autonomy? |
| Atomic Red Team reference mapping | Can Atomic Red Team inform technique mapping or command-shape review? |
| CALDERA relevance | Is CALDERA relevant now, later, or not for this family? |

## 5. Candidate families

### 5.1 Suspicious archive / staging behavior

Examples:

- archive creation in an unusual directory
- staging files under `/tmp`, `/var/tmp`, `/dev/shm`, or user-writable app dirs
- `chmod`, `tar`, `gzip`, or `zip` style behavior

Why useful:

- extends Linux process and file telemetry
- maps well to auditd and endpoint events
- useful for DFIR and investigation enrichment
- safe to simulate without destructive behavior

Evaluation:

| Field | Candidate mapping |
|---|---|
| `scenario_family` | `suspicious_archive_staging` |
| likely proposed `scenario_id` status | `scenario_009` selected in the first implementation PR |
| attacker-side observed effects | `staging_directory_created`, `staged_file_written`, `archive_created`, `archive_permission_changed` |
| defender-side artifacts | initial synthetic `endpoint_events.json` fixture; live auditd and centralized rsyslog validation; focused sanitized live-derived fixture coverage through normalization, DSL detection, incident, and the bounded incident-to-action chain; Wazuh 4.14.4 environment; zero matching `alerts.json` documents; bounded raw-archive Outcome C with `1026` new documents, `55` strong scenario documents, manager receipt and all five operations confirmed, but only `SYSCALL` retained per core serial; canonical Wazuh source and downstream validation remain open |
| expected detection artifacts | DSL `suspicious_archive_staging` detection from both synthetic defender-side archive-creation telemetry and normalized sanitized live-derived fixture replay; the live-derived canonical hit is accepted by the existing incident bridge |
| incident expectations | initial helper-level observation incident bridge for defender-side `suspicious_archive_staging` detection hits plus focused live-derived fixture replay coverage; no unsupported exfiltration, ransomware, credential access, compromise, live telemetry, or collection-success claim |
| triage expectations | focused boundary coverage exists for possible staging behavior and possible collection preparation only when evidence supports it; no unsupported exfiltration, ransomware, credential access, compromise, live telemetry, or containment approval claim |
| investigation expectations | focused synthetic and live-derived fixture-replay boundary coverage exists for timeline of `mkdir`, file write, `tar` / `gzip` / `zip`, and `chmod`; Wazuh manager receipt is confirmed but complete raw multi-record grouping remains a gap; archive staging remains a hypothesis with explicit gaps for file content, network transfer, exfiltration, destination host / external endpoint, canonical Wazuh source and downstream validation, direct production-log ingestion, and Velociraptor collection |
| action / containment boundary | focused synthetic and live-derived fixture-replay action coverage exists for non-destructive review, preservation, approved evidence collection, and network-correlation recommendations; no automatic containment, deletion, blocking, credential reset, action approval, containment approval, or response-execution claim |
| fixture requirements | synthetic process events or auditd events; expected detection hits |
| tests needed | scenario/runner contract tests, structured runner output tests if new event types are added, detection smoke when rules are added, focused incident bridge tests for observation-level detection hits, focused triage boundary tests, focused investigation boundary tests, focused action boundary tests, and a focused fixture-to-action boundary chain smoke test |
| safety risks | accidental broad file collection semantics, exfiltration-like wording, or destructive cleanup |
| implementation complexity | low to medium |
| research value now | high |
| dependency on future components | low; benefits from endpoint telemetry but does not require Wazuh, SIEM, Windows, AD, or deception |
| Atomic Red Team reference mapping | useful later for ATT&CK technique metadata and command-shape review |
| CALDERA relevance | later optional only |

### 5.2 Credential access simulation with fake local secrets only

Examples:

- read a fake `.env`
- read a fake config file
- grep for fake token patterns

Safety:

- fake local secrets only
- no live credential theft
- no real secrets in fixtures

This overlaps with deception. Non-deception credential access simulation should
remain separate from deception lures and `deception_hits.json`.

Evaluation:

| Field | Candidate mapping |
|---|---|
| `scenario_family` | `fake_local_secret_access` |
| likely proposed `scenario_id` status | `not assigned` |
| attacker-side observed effects | `fake_secret_file_read_attempted`, `fake_secret_pattern_searched`, `fake_secret_access_observed` |
| defender-side artifacts | process exec events for `cat` / `grep` style reads, file access telemetry if available, controlled fixture logs |
| expected detection artifacts | future credential-access simulation detection, process/file telemetry observations |
| incident expectations | fake local secret access simulation only; no real credential theft claim |
| triage expectations | possible credential-access-like behavior against a known fake asset |
| investigation expectations | confirm fake asset provenance, command line, user, path, and absence of live secret exposure |
| action / containment boundary | no automatic credential revocation, blocking, isolation, or containment |
| fixture requirements | synthetic fake-secret files or fixture records that contain no real secrets |
| tests needed | fixture safety tests, runner safety tests, detection/parser tests when implemented |
| safety risks | real secret exposure, confusing deception lures with non-deception fixtures, overclaiming credential theft |
| implementation complexity | medium |
| research value now | medium to high |
| dependency on future components | moderate if file access telemetry is required |
| Atomic Red Team reference mapping | useful for technique inspiration only after safety review |
| CALDERA relevance | later optional only |

### 5.3 Service discovery / internal enumeration expansion

Examples:

- `hostname`
- `ip addr`
- `ss` or `netstat`
- `systemctl`
- `ps`

Why useful:

- builds on `scenario_008`
- improves process and command-line coverage

This may be too similar to `scenario_008` unless the implementation scope is
clearly distinct.

Evaluation:

| Field | Candidate mapping |
|---|---|
| `scenario_family` | `service_discovery_internal_enumeration` |
| likely proposed `scenario_id` status | `not assigned` |
| attacker-side observed effects | `network_config_discovery_attempted`, `service_listing_attempted`, `process_listing_attempted` |
| defender-side artifacts | auditd process exec events, normalized endpoint events, process chain hits |
| expected detection artifacts | `system_discovery`, future service discovery or internal enumeration detections |
| incident expectations | read-only discovery or enumeration; no unsupported lateral movement claim |
| triage expectations | possible internal discovery when command sequence and SSH/session context support it |
| investigation expectations | command timeline, user/session context, and gaps for network reachability or access attempts |
| action / containment boundary | no automatic containment or host isolation |
| fixture requirements | synthetic process events for selected commands |
| tests needed | detection mapping tests and investigation evidence-grounding tests if new artifacts are introduced |
| safety risks | drifting into unauthorized scanning or broad network enumeration |
| implementation complexity | low |
| research value now | medium |
| dependency on future components | low |
| Atomic Red Team reference mapping | useful for ATT&CK discovery technique mapping |
| CALDERA relevance | later optional only |

### 5.4 Lateral-movement-like SSH fan-out simulation inside lab only

Examples:

- attempted SSH to known lab hosts
- failed or safe connection attempts only

Safety:

- lab hosts only
- no unauthorized scanning
- no credential theft

This is useful later, but it likely requires more lab topology decisions before
implementation.

Evaluation:

| Field | Candidate mapping |
|---|---|
| `scenario_family` | `lab_ssh_fanout_simulation` |
| likely proposed `scenario_id` status | `not assigned` |
| attacker-side observed effects | `ssh_fanout_attempted`, `lab_host_connection_attempted`, `connection_failed_or_refused` |
| defender-side artifacts | auth logs on known lab hosts, endpoint network events, Wazuh or SIEM search results later |
| expected detection artifacts | future SSH fan-out, lateral-movement-like, or multi-host auth correlation detections |
| incident expectations | lab-contained SSH fan-out attempts; no unauthorized lateral movement or compromise claim |
| triage expectations | possible lateral-movement-like behavior only when defender-side multi-host evidence exists |
| investigation expectations | host list provenance, source/destination map, auth outcomes, and topology limitations |
| action / containment boundary | no automatic blocking, isolation, credential revocation, or containment |
| fixture requirements | known lab host inventory and synthetic auth/network events |
| tests needed | topology fixture tests, auth/event correlation tests, safety guard tests |
| safety risks | unauthorized scanning, touching non-lab hosts, credential misuse |
| implementation complexity | medium to high |
| research value now | medium |
| dependency on future components | moderate to high; benefits from SIEM/Wazuh and topology policy |
| Atomic Red Team reference mapping | technique mapping only, not direct execution |
| CALDERA relevance | later optional adversary-emulation integration |

### 5.5 Web initial access simulation with safe local fixture logs

Examples:

- web access log fixture
- suspicious request patterns
- local-only mock web logs

Why useful:

- opens a web detection path

This is likely better after parser and log fixture policy is clarified.

Evaluation:

| Field | Candidate mapping |
|---|---|
| `scenario_family` | `web_initial_access_fixture_simulation` |
| likely proposed `scenario_id` status | `not assigned` |
| attacker-side observed effects | none required for fixture-only start; later `web_request_sent` only if a local runner is added |
| defender-side artifacts | safe local web access log fixtures, future normalized web events |
| expected detection artifacts | future suspicious web request or web initial access detections |
| incident expectations | suspicious local web request observations only; no exploit success claim without evidence |
| triage expectations | possible initial access attempt when request pattern and fixture provenance support it |
| investigation expectations | request path, source IP, user agent, response code, fixture limitations, and parser gaps |
| action / containment boundary | no automatic blocking or containment |
| fixture requirements | curated synthetic web logs with no real victim traffic |
| tests needed | parser fixture tests, detection tests, incident bridge tests |
| safety risks | importing real web logs, overclaiming exploitation, adding unsafe payload content |
| implementation complexity | medium |
| research value now | medium |
| dependency on future components | parser/log fixture policy |
| Atomic Red Team reference mapping | limited; web ATT&CK mapping may help later |
| CALDERA relevance | later optional only |

## 6. Atomic Red Team compatibility stance

Atomic Red Team may be used as:

- a source of ATT&CK technique inspiration
- a mapping reference for candidate Linux behaviors
- a source of command-shape ideas that must be reviewed and adapted safely
- future metadata in scenario mapping, such as technique ID or Atomic test
  reference

Atomic Red Team must not be treated as:

- a direct replacement for intelligent-soc-lab scenario contracts
- proof of defender-side detection
- automatic approval to run a command
- a source of commands to copy without safety review
- vendored content in this PR

Future Atomic compatibility should preserve:

- attacker-side observed effect is not defender-side observed artifact
- generated artifacts remain out of git
- local-lab-only execution
- fake secrets only
- no destructive behavior
- no automatic containment
- no Rule Improvement auto-promotion

A future Atomic adapter may be considered only after:

- scenario family mapping is stable
- runner output contracts are preserved
- safety filtering is defined
- technique/test metadata mapping is documented
- targeted tests prove outputs still fit intelligent-soc-lab artifacts

## 7. CALDERA integration stance

CALDERA is not a near-term replacement for the local runner.

Treat CALDERA as later optional adversary-emulation integration. A future
CALDERA integration should be adapter-based:

```text
CALDERA operation / ability
  -> CALDERA execution result
  -> intelligent-soc-lab adapter
  -> attack_execution_log.json
  -> attack_observed_effects.json
  -> defender-side artifact alignment
```

Do not add CALDERA dependencies, configs, plugins, or integration files in this
PR.

CALDERA should only be considered after scenario family expansion, telemetry
coverage, and artifact alignment are more mature.

## 8. Recommended first implementation candidate

Recommended first implementation candidate:

```text
suspicious_archive_staging
```

Reason:

- easiest to keep deterministic and lab-safe
- extends current Linux auditd / process / file pipeline
- provides useful defender-side artifacts without needing Windows, SIEM, or AD
- less dependent on mature attacker-agent autonomy than deception
- less risky than credential access or lateral movement
- useful bridge toward broader Linux behavior coverage
- can reference Atomic-style ATT&CK mapping later without requiring direct
  Atomic execution now

The first implementation PR selected `scenario_009` after checking
`scenarios/` and `attacks/runners/`.

## 9. Mapping template for the first implementation PR

Suggested starting mapping for `suspicious_archive_staging`:

| Field | Suggested value |
|---|---|
| `scenario_family` | `suspicious_archive_staging` |
| proposed `scenario_id` | `scenario_009` selected in the first implementation PR |
| attacker-side observed effects | `staging_directory_created`, `archive_created`, `staged_file_written`, `archive_permission_changed` |
| defender-side artifacts | auditd process exec events, normalized endpoint events, process chain hits, file write / chmod observations if available |
| expected detection artifacts | `process_exec`, future `suspicious_archive_creation`, future `suspicious_staging_path` |
| incident expectations | primary artifact should remain observation-level; no unsupported exfiltration or ransomware claims |
| triage expectations | possible staging behavior; possible collection preparation only if evidence supports it |
| investigation expectations | timeline of `mkdir` / `tar` / `gzip` / `chmod` or equivalent commands; evidence gaps for file content, network transfer, or exfiltration |
| action boundary | no automatic containment; approval-gated response only |
| fixtures/tests | initial synthetic endpoint events and DSL detection tests exist; incident/triage/investigation smoke only when implementation reaches those stages |
| Atomic compatibility | may include ATT&CK technique metadata or Atomic reference later; do not execute Atomic tests directly in the first implementation PR |

## 10. Non-goals

This PR does not implement:

- destructive behavior
- real data collection
- exfiltration
- credential theft
- malware or ransomware behavior
- scenario YAML
- shell runners
- scripts
- schemas
- tests
- fixtures
- generated `data/runs/**` artifacts
- triage / investigation / case / action artifacts
- Rule Improvement artifacts
- Atomic Red Team adapter behavior
- vendored Atomic Red Team content
- CALDERA integration

## 11. Acceptance criteria before scenario implementation

Before implementing the first new Linux scenario family:

- confirm the desired scenario ID is unused in both `scenarios/` and
  `attacks/runners/`
- define one narrow scenario family and one scenario ID
- preserve local scenario YAML plus shell runner as the default backend
- define attacker-side structured event names only if new observed effects are
  required
- identify the defender-side artifacts that prove observation
- identify any new DSL detections or endpoint event mappings needed
- add focused tests with synthetic fixtures or `tmp_path` outputs
- keep generated run artifacts out of git
- preserve approval gates for containment or other state-changing operations
- preserve Rule Improvement review and promotion gates
- document any Atomic Red Team reference metadata without executing or vendoring
  Atomic tests
- leave CALDERA as later optional integration unless a separate adapter design
  PR is approved
