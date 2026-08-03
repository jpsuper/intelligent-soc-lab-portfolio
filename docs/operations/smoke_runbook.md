# Smoke Runbook

This runbook covers the current structured shell runner and observed-effects smoke workflow. It keeps attacker-side structured events separate from defender-side detections.

Auditd-specific endpoint telemetry validation is tracked separately in [Auditd Smoke Checklist](auditd_smoke_checklist.md).

## Targeted Static Tests

Run targeted pytest directly; do not set `PYTHONPATH=.`. The repository pytest config provides the needed import paths.

```bash
uv run pytest tests/test_shell_backend_contract.py -q
uv run pytest tests/test_structured_runner_events.py agents/attacker-agent/tests/test_attack_observed_effects_generation.py -q
uv run ruff check .
```

These tests are static or synthetic. They must not execute attack runner scripts.

## Optional Post-action DFIR Pipeline Smoke

Run this only in an approved lab environment with a scenario 006 auditd log. Post-action DFIR integration is default-off; `--run-post-action-dfir` explicitly enables collection-result and post-action result generation after the normal process pipeline, case/action, and collection-request stages.

```bash
uv run python scripts/run_process_pipeline.py \
  --run-id <run-id> \
  --audit-log <auditd.log> \
  --scenario scenarios/scenario_006_ssh_key_login_then_command_execution.yaml \
  --run-post-action-dfir
```

Do not prefix the command with `PYTHONPATH=.`. The process pipeline prepends the repository root to `PYTHONPATH` for child Python scripts while preserving the existing environment.

Confirm these run artifacts:

```text
data/runs/<run-id>/collection_request.json
data/runs/<run-id>/collection_result.json
data/runs/<run-id>/forensics/mock/Linux.Syslog.SSHLogin.json
data/runs/<run-id>/post_action_dfir_investigation_result.json
```

Current parser coverage is limited to `Linux.Syslog.SSHLogin`. `Linux.ProcessList` and `Linux.BashHistory` may be present in `collection_result.json`, but their post-action parse results are currently `unsupported`; unsupported or unavailable output remains a gap or limitation, not a security conclusion.

The post-action result must not directly mutate case severity, status, verdict, or confidence; action approval or containment; or Rule Improvement promotion. Generated `data/runs/**` artifacts and source raw logs are local smoke inputs/outputs and must not be committed.

## Structured Runner Smoke

Run only in an approved lab environment. The scenario_004, scenario_005, scenario_006, scenario_007, and scenario_008 shell runners emit attacker-side stdout lines prefixed with `ATTACK_EVENT_JSON:`.

```bash
uv run python agents/attacker-agent/src/main.py --scenario scenarios/scenario_004_ssh_bruteforce_authorized_keys_persistence.yaml --execute --output-dir data/attacks/scenario_004_smoke
uv run python agents/attacker-agent/src/main.py --scenario scenarios/scenario_005_ssh_authorized_keys_persistence_reuse.yaml --execute --output-dir data/attacks/scenario_005_smoke
uv run python agents/attacker-agent/src/main.py --scenario scenarios/scenario_006_ssh_key_login_then_command_execution.yaml --execute --output-dir data/attacks/scenario_006_smoke
uv run python agents/attacker-agent/src/main.py --scenario scenarios/scenario_007_ssh_key_login_suspicious_file_write.yaml --execute --output-dir data/attacks/scenario_007_smoke
uv run python agents/attacker-agent/src/main.py --scenario scenarios/scenario_008_ssh_key_system_discovery.yaml --execute --output-dir data/attacks/scenario_008_smoke
```

For each smoke output directory, confirm the raw runner stdout still contains `ATTACK_EVENT_JSON` in `attack_result.json` step output and `attack_execution_log.json` event output. Also confirm `attack_execution_log.json` includes parsed `structured_events` when valid structured event lines are present. The parsed field is additive and does not replace `events`, raw stdout, or raw stderr.

```bash
jq '.steps[].stdout | select(contains("ATTACK_EVENT_JSON:"))' data/attacks/scenario_006_smoke/attack_result.json
jq '.events[].stdout | select(contains("ATTACK_EVENT_JSON:"))' data/attacks/scenario_006_smoke/attack_execution_log.json
jq '.structured_events' data/attacks/scenario_006_smoke/attack_execution_log.json
```

Check `attack_observed_effects.json` for `structured_runner_event` evidence.

```bash
jq '.effects[].evidence[] | select(.type == "structured_runner_event")' data/attacks/scenario_006_smoke/attack_observed_effects.json
```

## Structured Runner Observed-Effects Smoke

The scenario_004, scenario_005, scenario_006, scenario_007, and scenario_008 smoke outputs should show structured runner events flowing into observed effects without changing raw execution evidence or defender-side verdict behavior.

For each smoke output directory, confirm:

- `attack_execution_log.json` contains additive `structured_events`
- `attack_observed_effects.json` uses `structured_runner_event` evidence
- `structured_runner_event` evidence has source `attack_execution_log.structured_events`
- attacker-side structured events are not defender-side telemetry or detections
- observed-effects alignment remains additive and does not change `overall_result` or `detected`

Expected structured runner event to observed-effect mappings:

- `scenario_004_smoke`: `ssh_bruteforce_attempted` -> `ssh_failed_login`
- `scenario_004_smoke`: `ssh_login_succeeded` -> `ssh_success_login`
- `scenario_004_smoke`: `authorized_keys_write_succeeded` -> `authorized_keys_modification`
- `scenario_005_smoke`: `ssh_login_succeeded` -> `ssh_key_login`
- `scenario_006_smoke`: `ssh_login_succeeded` -> `ssh_key_login`
- `scenario_006_smoke`: `payload_execution_succeeded` -> `process_exec`
- `scenario_007_smoke`: `ssh_login_succeeded` -> `ssh_key_login`
- `scenario_007_smoke`: `suspicious_file_write_succeeded` -> `suspicious_file_write`
- `scenario_008_smoke`: `ssh_login_succeeded` -> `ssh_key_login`
- `scenario_008_smoke`: `system_discovery_succeeded` -> `system_discovery`

Observed-effect status vocabulary is:

- `observed`
- `not_observed`
- `partial`
- `unknown`

`failed` is not a structured runner event status. Runner failures should be represented as `not_observed`, `partial`, or `unknown` depending on available evidence.

```bash
for s in scenario_004_smoke scenario_005_smoke scenario_006_smoke scenario_007_smoke scenario_008_smoke; do
  echo "=== $s structured_events ==="
  jq '.structured_events' "data/attacks/$s/attack_execution_log.json"

  echo "=== $s observed effects structured evidence ==="
  jq '.effects[].evidence[] | select(.type == "structured_runner_event")' \
    "data/attacks/$s/attack_observed_effects.json"
done
```

The `data/` tree is generated and ignored. Do not commit smoke artifacts from these runs.

## Smoke Result Checklist Template

Use this template in PR comments, issue comments, or local notes when recording manual structured runner smoke results. Do not commit generated `data/` artifacts.

### Environment

- [ ] Date/time:
- [ ] Branch / commit SHA:
- [ ] Approved lab environment confirmed
- [ ] Scenario IDs tested: `scenario_004`, `scenario_005`, `scenario_006`, `scenario_007`, `scenario_008`
- [ ] Victim host / target IP confirmed:
- [ ] Generated `data/` artifacts were not committed

### Command Execution

| Scenario | Command executed | Output directory | Runner exit code | `attack_result.json` | `attack_execution_log.json` | `attack_observed_effects.json` |
|---|---|---|---:|---|---|---|
| `scenario_004` |  | `data/attacks/scenario_004_smoke` |  | [ ] | [ ] | [ ] |
| `scenario_005` |  | `data/attacks/scenario_005_smoke` |  | [ ] | [ ] | [ ] |
| `scenario_006` |  | `data/attacks/scenario_006_smoke` |  | [ ] | [ ] | [ ] |
| `scenario_007` |  | `data/attacks/scenario_007_smoke` |  | [ ] | [ ] | [ ] |
| `scenario_008` |  | `data/attacks/scenario_008_smoke` |  | [ ] | [ ] | [ ] |

### Structured Events

- [ ] `scenario_004`: `ssh_bruteforce_attempted` -> `ssh_failed_login`
- [ ] `scenario_004`: `ssh_login_succeeded` -> `ssh_success_login`
- [ ] `scenario_004`: `authorized_keys_write_succeeded` -> `authorized_keys_modification`
- [ ] `scenario_005`: `ssh_login_succeeded` -> `ssh_key_login`
- [ ] `scenario_006`: `ssh_login_succeeded` -> `ssh_key_login`
- [ ] `scenario_006`: `payload_execution_succeeded` -> `process_exec`
- [ ] `scenario_007`: `ssh_login_succeeded` -> `ssh_key_login`
- [ ] `scenario_007`: `suspicious_file_write_succeeded` -> `suspicious_file_write`
- [ ] `scenario_008`: `ssh_login_succeeded` -> `ssh_key_login`
- [ ] `scenario_008`: `system_discovery_succeeded` -> `system_discovery`

### Observed-Effects Evidence

- [ ] Each `attack_observed_effects.json` includes structured evidence
- [ ] Evidence type is `structured_runner_event`
- [ ] Evidence source is `attack_execution_log.structured_events`
- [ ] Legacy stdout fallback was not required when structured events were present

### Verdict Boundaries

- [ ] Structured runner events remain attacker-side evidence
- [ ] Structured runner events are not defender telemetry
- [ ] Observed-effects generation does not change defender-side verdicts
- [ ] `overall_result` / `detected` behavior is not changed by smoke review

### Rule Improvement Signal Boundaries

- [ ] `observed_effects_alignment_signals.json` is review-only
- [ ] `auto_generate_rule_candidate` remains false
- [ ] `rule_candidates.yaml` is not automatically populated from observed-effects alignment
- [ ] Reviewer approval is required before converting gaps into rule or prompt candidates

### Cleanup

- [ ] `git status -sb` is clean or only expected docs changes are present
- [ ] No `data/attacks/*_smoke` artifacts are staged
- [ ] No secrets, SSH keys, private IP changes, or local-only paths were committed

## Observed-Effects Alignment Smoke

Use a synthetic observed-effects alignment check to confirm Rule Improvement signals are review-only inputs. This includes automated regression coverage for the RI signal smoke path that generates `observed_effects_alignment_signals.json` and renders the candidate review section.

```bash
uv run pytest tests/test_observed_effects_alignment.py -q
```

When running the improvement candidate review workflow, confirm `candidate_review.md` displays observed-effects alignment signals for reviewer context. Confirm `rule_candidates.yaml` does not auto-ingest observed-effects signals and does not create rule candidates directly from attacker-side observed effects.

Attacker-side structured events are execution evidence. They may support `attack_observed_effects.json`, but they are not defender-side telemetry, defender-side detections, or promotion evidence by themselves.

## Rule Improvement Signal Smoke

Create a synthetic evaluation result only for smoke testing. This confirms that observed-effects alignment signals are review inputs and are not automatically promoted into rule candidates.

Expected checks:

- `observed_effects_alignment_signals.json` is generated
- `candidate_review.md` includes `Observed Effects Alignment Signals`
- `candidate_review.md` shows `auto_generate_rule_candidate: false`
- `rule_candidates.yaml` does not contain `attacker_observed_defender_missing`
- `rule_candidates.yaml` does not contain `observed_effects_alignment`

This smoke uses synthetic data and does not change `overall_result`, `detected`, or promotion behavior.