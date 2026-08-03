# AI-Assisted Rule Improvement Review Handoff Runbook

## 1. Purpose

This runbook covers the current deterministic, local handoff from post-action
DFIR output through AI-assisted Rule Improvement review, human signal
classification, candidate draft review, and candidate-creation input export. It
documents optional pipeline stages, manual model runners, generated review
artifacts, and the points where a human reviewer must take control.

For a plain Japanese map of the full Rule Improvement artifact chain, see
`docs/design/rule-improvement/rule_improvement_overview_ja.md`.

The default pipeline path remains deterministic and local. Manual model runners
for OpenAI and LM Studio exist outside the process pipeline and require explicit
opt-in. Model outputs remain untrusted until accepted by their importer or
invariant checker. Japanese rewrites are read-only human aids and are not
canonical decision sources.

## 2. Current artifact flow

```text
rule_improvement_review_input.json
  -> rule_improvement_ai_review_draft_prompt_input.json
  -> rule_improvement_ai_review_draft_prompt_bundle.json
  -> manual model/mock/OpenAI/LM Studio execution
  -> untrusted rule_improvement_ai_review_draft_model_output.json
  -> importer acceptance boundary
  -> canonical rule_improvement_ai_review_draft.json / named draft artifacts
  -> optional compare_ai_review_drafts.py descriptive comparison
  -> human_review_worksheet.md
  -> optional human_review_packet_ja.md
  -> human_decisions_template.json
  -> human-completed decisions JSON
  -> rule_improvement_signal_classification.json
  -> rule_improvement_candidate_generation_input.json
  -> rule_improvement_candidate_draft.json
  -> rule_improvement_candidate_review_worksheet.md
  -> optional rule_improvement_candidate_review_worksheet_ja_prompt_bundle.json
  -> optional LM Studio API runner
  -> untrusted rule_improvement_candidate_review_worksheet_ja_model_output.json
  -> importer invariant check
  -> optional rule_improvement_candidate_review_worksheet_ja_rewritten.md
  -> rule_improvement_candidate_review_decisions_template.json
  -> human-completed candidate review decisions JSON
  -> rule_improvement_candidate_review_decisions.json
  -> rule_improvement_candidate_creation_input.json
```

The process pipeline still stops before human classification unless explicit
default-off deterministic export flags are used. It does not automatically edit
templates, author completed decisions JSON, invoke human-review helpers, create
Rule Improvement candidates, or promote anything. Manual and AI-assisted outputs
remain review aids until the relevant schema/invariant validation boundary
accepts them.

### Optional prompt-bundle inspection boundary

`scripts/export_ai_review_draft_prompt_bundle.py` can separately materialize a
local `rule_improvement_ai_review_draft_prompt_bundle.json` from an existing
`rule_improvement_ai_review_draft_prompt_input.json`. The bundle contains the
versioned prompt text, normalized input JSON, response instructions, expected
draft schema, and safety boundaries. It is not part of the current pipeline and
does not generate `rule_improvement_ai_review_draft.json`.

```bash
uv run python scripts/export_ai_review_draft_prompt_bundle.py \
  --prompt-input data/runs/<run-id>/rule_improvement_ai_review_draft_prompt_input.json \
  --output data/runs/<run-id>/rule_improvement_ai_review_draft_prompt_bundle.json
```

The bundle locks model execution and network access off. Exporting it does not
execute the prompt, call a model/API/network service, read evidence refs or raw
logs, or create worksheets, decisions, classification, candidates, or promotion
artifacts. Automatic model execution and pipeline integration remain future work.

### Manual LM Studio execution

The manual runner can send only the bundle `prompt_text` to an LM Studio
OpenAI-compatible `/chat/completions` endpoint. It is not part of the process
pipeline and refuses execution unless `--allow-model-execution` is present.
Loopback (`127.0.0.1`, `localhost`, or `::1`) is allowed by default. An explicit
RFC1918 or IPv4 link-local lab endpoint additionally requires
`--allow-private-lan-endpoint`.

For a lab-hosted Windows LM Studio instance:

> [!NOTE]
> The `192.0.2.7` address below is a documentation-only placeholder used in
> this public snapshot. Replace it with the RFC1918 address of the LM Studio
> host in your isolated lab before running the command.

```bash
uv run python scripts/run_ai_review_draft_lmstudio_model.py \
  --prompt-bundle data/runs/<run-id>/rule_improvement_ai_review_draft_prompt_bundle.json \
  --model qwen3.6-35b-a3b \
  --base-url http://192.0.2.7:1234/v1 \
  --output data/runs/<run-id>/rule_improvement_ai_review_draft_model_output.json \
  --allow-model-execution \
  --allow-private-lan-endpoint
```

Public addresses, non-local domain names, and cloud endpoints such as
`https://api.openai.com/v1` are rejected. The runner uses no OpenAI SDK and no
external model service. Do not include secrets in the normalized prompt bundle,
especially when using unencrypted HTTP on an approved private lab network.

`rule_improvement_ai_review_draft_model_output.json` is untrusted candidate
output, not the canonical draft. It must pass through the importer below before
worksheet or human-decision review.

### Manual OpenAI execution

The separate OpenAI runner is also manual-only. It requires both explicit
`--allow-model-execution` and `--allow-external-api` gates and obtains its
credential only from `OPENAI_API_KEY` in the environment. It sends only bundle
`prompt_text` to the Responses API and requests strict structured output using
an OpenAI-compatible projection of
`schemas/rule_improvement_ai_review_draft.schema.json`. The projection removes
unsupported API keywords such as `uniqueItems` without changing the canonical
schema; the importer still validates against that full schema.

```bash
uv run python scripts/run_ai_review_draft_openai_model.py \
  --prompt-bundle data/runs/<run-id>/rule_improvement_ai_review_draft_prompt_bundle.json \
  --model gpt-5.4 \
  --output data/runs/<run-id>/rule_improvement_ai_review_draft_model_output.json \
  --allow-model-execution \
  --allow-external-api
```

The runner does not read evidence refs or raw logs and does not repair or
accept the response. Its output is the same untrusted candidate handoff used by
the importer below. There is no process-pipeline, classification, candidate,
or promotion integration. Do not commit generated `data/runs/**` artifacts.

An already-produced candidate response may be accepted locally only through the
deterministic model-output importer:

```bash
uv run python scripts/import_ai_review_draft_model_output.py \
  --prompt-bundle data/runs/<run-id>/rule_improvement_ai_review_draft_prompt_bundle.json \
  --model-output <path-to-model-output.json> \
  --output data/runs/<run-id>/rule_improvement_ai_review_draft.json
```

The importer does not run a model. It validates the candidate against
`schemas/rule_improvement_ai_review_draft.schema.json`, verifies locked flags,
review provenance, and signal refs against the bundle's normalized input, and
rejects unknown, forbidden, inconsistent, or malformed output without repair.
Successful import rejoins the existing human worksheet and decisions-template
flow; it does not bypass human review or create downstream artifacts itself.

### Manual draft comparison

`scripts/compare_ai_review_drafts.py` can compare multiple already-produced AI
review draft artifacts for the same `rule_improvement_review_input.json`, for
example deterministic mock output, imported OpenAI output, and imported local
LM Studio output. The comparison is descriptive only: it validates each draft
against `schemas/rule_improvement_ai_review_draft.schema.json`, records invalid
inputs, reports label disagreement and missing signal coverage, and writes
`ai_review_draft_comparison.json`.

```bash
uv run python scripts/compare_ai_review_drafts.py \
  --candidate mock=data/runs/<run-id>/mock_rule_improvement_ai_review_draft.json \
  --candidate openai=data/runs/<run-id>/openai_rule_improvement_ai_review_draft.json \
  --candidate lmstudio=data/runs/<run-id>/lmstudio_rule_improvement_ai_review_draft.json \
  --output data/runs/<run-id>/ai_review_draft_comparison.json
```

The comparison harness does not execute prompts or models, call the importer,
read evidence refs or raw logs, select a winner, classify signals, create
worksheets or human decisions, generate candidates, recommend promotion, or
mutate case/action/investigation/containment/approval/Rule Improvement state.

### End-to-end smoke: mock vs OpenAI vs LM Studio

This manual smoke compares three already-produced AI review drafts for the same
Rule Improvement review input:

- deterministic mock baseline
- manual OpenAI stable runner output
- manual LM Studio local/private-lab challenger output

The smoke exercises the current handoff boundaries without changing pipeline
behavior. It may call the external OpenAI API only when explicitly opted in, and
it may call a local/private-lab LM Studio endpoint only when explicitly opted in.
Model outputs remain untrusted until imported. The importer remains the
acceptance boundary. The comparison is descriptive only: it does not select a
winner, classify signals, generate candidates, recommend promotion, or mutate
case/action/investigation/containment/approval/verdict/severity/confidence/Rule
Improvement state.

Prerequisites:

- an existing `data/runs/<run-id>/rule_improvement_review_input.json`
- a generated
  `data/runs/<run-id>/rule_improvement_ai_review_draft_prompt_input.json`
- a generated
  `data/runs/<run-id>/rule_improvement_ai_review_draft_prompt_bundle.json`
- `OPENAI_API_KEY` in the environment before running the OpenAI command
- OpenAI execution explicitly gated with both `--allow-model-execution` and
  `--allow-external-api`
- a loopback or approved private-lab LM Studio endpoint for the LM Studio
  command
- private LAN LM Studio endpoints explicitly gated with
  `--allow-private-lan-endpoint`

Set the run and model variables:

```bash
RUN_ID="<run-id>"
RUN_DIR="data/runs/$RUN_ID"
OPENAI_MODEL="gpt-4.1-mini"
# Documentation-only placeholder; replace with the RFC1918 address of the
# LM Studio host in the isolated lab before execution.
LMSTUDIO_BASE_URL="http://192.0.2.7:1234/v1"
LMSTUDIO_MODEL="qwen3.6-35b-a3b"
export RUN_ID RUN_DIR OPENAI_MODEL LMSTUDIO_BASE_URL LMSTUDIO_MODEL
```

Verify the required source artifacts exist:

```bash
ls -l "$RUN_DIR/rule_improvement_review_input.json"
ls -l "$RUN_DIR/rule_improvement_ai_review_draft_prompt_input.json"
ls -l "$RUN_DIR/rule_improvement_ai_review_draft_prompt_bundle.json"
```

Generate the deterministic mock draft:

```bash
uv run python scripts/generate_mock_ai_review_draft.py \
  --prompt-input "$RUN_DIR/rule_improvement_ai_review_draft_prompt_input.json" \
  --output "$RUN_DIR/mock_rule_improvement_ai_review_draft.json" \
  --draft-id "ri-ai-review-draft-mock-${RUN_ID}" \
  --source-review-input-ref "$RUN_DIR/rule_improvement_review_input.json"
```

Run the manual OpenAI model-output step:

```bash
uv run python scripts/run_ai_review_draft_openai_model.py \
  --prompt-bundle "$RUN_DIR/rule_improvement_ai_review_draft_prompt_bundle.json" \
  --model "$OPENAI_MODEL" \
  --output "$RUN_DIR/openai_rule_improvement_ai_review_draft_model_output.json" \
  --allow-model-execution \
  --allow-external-api
```

Import the OpenAI output into a canonical draft:

```bash
uv run python scripts/import_ai_review_draft_model_output.py \
  --model-output "$RUN_DIR/openai_rule_improvement_ai_review_draft_model_output.json" \
  --prompt-bundle "$RUN_DIR/rule_improvement_ai_review_draft_prompt_bundle.json" \
  --output "$RUN_DIR/openai_rule_improvement_ai_review_draft.json"
```

Run the manual LM Studio model-output step:

```bash
uv run python scripts/run_ai_review_draft_lmstudio_model.py \
  --prompt-bundle "$RUN_DIR/rule_improvement_ai_review_draft_prompt_bundle.json" \
  --model "$LMSTUDIO_MODEL" \
  --output "$RUN_DIR/lmstudio_rule_improvement_ai_review_draft_model_output.json" \
  --base-url "$LMSTUDIO_BASE_URL" \
  --allow-model-execution \
  --allow-private-lan-endpoint
```

Import the LM Studio output into a canonical draft:

```bash
uv run python scripts/import_ai_review_draft_model_output.py \
  --model-output "$RUN_DIR/lmstudio_rule_improvement_ai_review_draft_model_output.json" \
  --prompt-bundle "$RUN_DIR/rule_improvement_ai_review_draft_prompt_bundle.json" \
  --output "$RUN_DIR/lmstudio_rule_improvement_ai_review_draft.json"
```

Compare the three drafts:

```bash
uv run python scripts/compare_ai_review_drafts.py \
  --candidate mock="$RUN_DIR/mock_rule_improvement_ai_review_draft.json" \
  --candidate openai="$RUN_DIR/openai_rule_improvement_ai_review_draft.json" \
  --candidate lmstudio="$RUN_DIR/lmstudio_rule_improvement_ai_review_draft.json" \
  --output "$RUN_DIR/ai_review_draft_comparison_3way.json"
```

Inspect the descriptive comparison:

```bash
jq '.candidate_count, .valid_candidate_count, .invalid_candidate_count, .summary' \
  "$RUN_DIR/ai_review_draft_comparison_3way.json"

jq '.candidates[] | {name, schema_valid, validation_error, label_counts, empty_evidence_caveat_count, empty_review_question_count, missing_confidence_rationale_count}' \
  "$RUN_DIR/ai_review_draft_comparison_3way.json"

jq '.signal_matrix[] | {source_signal_ref, labels_by_candidate, label_disagreement}' \
  "$RUN_DIR/ai_review_draft_comparison_3way.json"
```

Expected successful smoke shape:

- `candidate_count: 3`
- `valid_candidate_count: 3`
- `invalid_candidate_count: 0`
- `schema_pass_rate: 1.0`
- no missing signal coverage
- label disagreements, if present, are surfaced for human review and are not
  resolved automatically

Confirm generated run artifacts are not staged or committed:

```bash
git status -sb
```

Generated `data/runs/**` artifacts, model outputs, comparison outputs, and raw
logs are local smoke artifacts and must not be committed.

## 3. Optional pipeline flags

All stages in this review handoff are default-off and require explicit flags.

| Stage | Implemented flag |
|---|---|
| Post-action DFIR | `--run-post-action-dfir` |
| Rule Improvement review input export | `--export-ri-review-input` |
| AI review draft prompt-input export | `--export-ai-review-draft-prompt-input` |
| Deterministic mock draft generation | `--generate-mock-ai-review-draft` |
| Human worksheet export | `--export-ai-review-draft-human-worksheet` |
| Human decisions-template export | `--export-ri-signal-classification-decisions-template` |

The implemented review-input flag is `--export-ri-review-input`.
`--export-rule-improvement-review-input` is not a current CLI option.

Each stage requires its source artifact. Missing sources fail closed; the
pipeline does not fabricate upstream artifacts. When all flags are present, the
pipeline preserves the order shown above.

The mock draft is deterministic and local. No prompt, model, LLM API, network
service, or human-classification helper is called. The decisions-template stage
reads `rule_improvement_ai_review_draft.json` directly. It is ordered after the
worksheet when both are requested, but it does not require worksheet output.

## 4. Example pipeline command

Run only in an approved lab environment with appropriate local inputs:

```bash
uv run python scripts/run_process_pipeline.py \
  --run-id <run-id> \
  --audit-log <path-to-auditd.log> \
  --scenario <path-to-scenario.yaml> \
  --run-post-action-dfir \
  --export-ri-review-input \
  --export-ai-review-draft-prompt-input \
  --generate-mock-ai-review-draft \
  --export-ai-review-draft-human-worksheet \
  --export-ri-signal-classification-decisions-template
```

Generated artifacts are written under `data/runs/<run-id>/`. They and raw input
logs must not be committed.

## 5. Produced artifacts

| Artifact | Producer | Purpose | Human-editable? | Final decision? |
|---|---|---|---|---|
| `rule_improvement_review_input.json` | `scripts/export_rule_improvement_review_input.py` | Review-only projection of post-action facts, gaps, limitations, and signals | No | No |
| `rule_improvement_ai_review_draft_prompt_input.json` | `scripts/export_ai_review_draft_prompt_input.py` | Minimized normalized context for draft generation | No | No |
| `rule_improvement_ai_review_draft.json` | `scripts/generate_mock_ai_review_draft.py` or `scripts/import_ai_review_draft_model_output.py`  | Suggestions-only AI review draft from deterministic mock output or accepted model output | No; review rather than edit in place | No |
| `human_review_worksheet.md` | `scripts/export_ai_review_draft_human_worksheet.py` | Readable suggestions, caveats, questions, and blank review fields | Yes, as analyst working notes | No |
| `human_review_packet_ja.md` | `scripts/export_rule_improvement_human_review_packet_ja.py` | Japanese read-only review aid over review input, optional AI draft, and optional comparison | No; use as review aid only | No |
| `human_decisions_template.json` | `scripts/export_ri_signal_classification_decisions_template.py` | Incomplete placeholder template for human decision authoring | Yes; every placeholder requires review | No |
| Completed human-authored decisions JSON | Human reviewer | Separate non-empty decisions array accepted by the classification helper | Yes; human-authored | Human input, not the classification record |
| `rule_improvement_signal_classification.json` | `scripts/create_rule_improvement_signal_classification.py`, invoked manually | Provenance-preserving human classification record | No; regenerate from reviewed input | Yes, for signal classification only |
| `rule_improvement_candidate_generation_input.json` | `scripts/export_rule_improvement_candidate_generation_input.py` | Eligible human-reviewed signals prepared for candidate draft generation | No | No |
| `rule_improvement_candidate_draft.json` | `scripts/generate_rule_improvement_candidate_draft.py` | Reviewable, non-applying candidate draft items | No; review rather than edit in place | No |
| `rule_improvement_candidate_review_decisions.json` | `scripts/create_rule_improvement_candidate_review_decisions.py` | Canonical human-completed candidate draft review decisions | No; regenerate from human-completed input | Yes, for candidate draft review only |
| `rule_improvement_candidate_creation_input.json` | `scripts/export_rule_improvement_candidate_creation_input.py` | Accepted candidate-review decisions prepared for a later candidate-creation workflow | No | No |

None of these artifacts is candidate approval or a promotion decision.

### Japanese human review packet

`scripts/export_rule_improvement_human_review_packet_ja.py` can render a
deterministic Japanese Markdown packet for human reviewers:

```bash
uv run python scripts/export_rule_improvement_human_review_packet_ja.py \
  --review-input data/runs/<run-id>/rule_improvement_review_input.json \
  --ai-review-draft data/runs/<run-id>/rule_improvement_ai_review_draft.json \
  --comparison data/runs/<run-id>/ai_review_draft_comparison_3way.json \
  --output data/runs/<run-id>/human_review_packet_ja.md
```

The AI draft and comparison inputs are optional. When they are omitted, the
packet still renders and states that the optional artifact was not supplied.
The exporter is deterministic and local: it does not call an LLM, execute a
model, use a translation API, or make network calls. It preserves machine
identifiers and label enum values as-is, including `source_signal_ref`,
`source_fact_ids`, `evidence_refs`, labels such as `timing_or_scope_limit`, and
candidate names such as `mock`, `openai`, and `lmstudio`.

`human_review_packet_ja.md` is a Japanese read-only review aid. It is not a
canonical machine-readable artifact, does not replace
`human_decisions_template.json`, and must not be treated as completed human
decisions JSON. It does not classify signals, create
`rule_improvement_signal_classification.json`, generate candidates, recommend
promotion, or mutate case/action/investigation/containment/approval/verdict/
severity/confidence/Rule Improvement state. Future manual translation or
model-based localization may be added separately, but is out of scope for the
current handoff.

## 6. Human handoff procedure

1. Review `data/runs/<run-id>/human_review_worksheet.md`.
   Japanese reviewers may also use
   `data/runs/<run-id>/human_review_packet_ja.md` as a read-only review aid.
2. Inspect `rule_improvement_review_input.json`, its signal provenance, and the
   referenced evidence context. Evidence refs are references; review them
   through approved evidence-handling procedures.
3. Open `human_decisions_template.json` only as an authoring starting point.
   The untouched template is not valid completed decisions JSON.
4. Replace every `<choose_label>`, `<write_human_rationale>`, and
   `<write_human_next_step>` placeholder.
5. Choose one valid label from `allowed_labels` for each signal.
6. Write an independent human rationale. Do not copy an AI suggestion without
   verifying it against the source review input and evidence context.
7. Record reviewable missing requirements and the recommended next step. Use an
   empty `missing_requirements` array only when no requirement remains.
8. Copy only the completed `decisions` array into a separate JSON file, such as
   `<path-to-completed-decisions.json>`. Do not pass the metadata-rich template
   object directly to the helper.
9. Run the classification helper manually with a human reviewer identity and an
   RFC 3339 timestamp:

```bash
uv run python scripts/create_rule_improvement_signal_classification.py \
  --review-input data/runs/<run-id>/rule_improvement_review_input.json \
  --decisions-json <path-to-completed-decisions.json> \
  --reviewer-id <reviewer-id> \
  --reviewed-at <RFC3339-timestamp> \
  --output data/runs/<run-id>/rule_improvement_signal_classification.json
```

The helper derives `candidate_generation_eligible` from the human-selected
label according to the fixed classification contract. The template and mock
draft do not derive it.

### Completed human decisions smoke

This smoke verifies the handoff from human review artifacts to the first formal
human classification record:

```text
human_review_worksheet.md
  + optional human_review_packet_ja.md
  + rule_improvement_review_input.json / evidence refs
  ↓ human authors completed decisions JSON
scripts/create_rule_improvement_signal_classification.py
  ↓
rule_improvement_signal_classification.json
```

The source of truth for classification is the completed human-authored
decisions JSON. AI review drafts, comparison output, and
`human_review_packet_ja.md` are advisory review aids only. The Japanese packet
is not canonical and must not replace canonical JSON. Signal classification is
not candidate generation, not promotion, and does not create automatic
rule/prompt candidates.

Create a separate completed decisions JSON from
`human_decisions_template.json`. Do not pass the metadata-rich template object
directly if the helper expects only the completed `decisions` array.

```bash
RUN_ID="<run-id>"
RUN_DIR="data/runs/$RUN_ID"
REVIEWED_AT="2026-06-25T00:00:00Z"
REVIEWER_ID="human-reviewer-001"

uv run python scripts/create_rule_improvement_signal_classification.py \
  --review-input "$RUN_DIR/rule_improvement_review_input.json" \
  --decisions-json "$RUN_DIR/completed_human_decisions.json" \
  --reviewer-id "$REVIEWER_ID" \
  --reviewed-at "$REVIEWED_AT" \
  --output "$RUN_DIR/rule_improvement_signal_classification.json"
```

Inspect the resulting human classification record:

```bash
jq '.reviewer.reviewer_id, .reviewer.reviewed_at' \
  "$RUN_DIR/rule_improvement_signal_classification.json"

jq '.decisions[] | {source_signal_ref, label, candidate_generation_eligible, rationale, recommended_next_step}' \
  "$RUN_DIR/rule_improvement_signal_classification.json"
```

Confirm that no candidate or promotion artifacts were created:

```bash
for path in \
  "$RUN_DIR/rule_candidates.yaml" \
  "$RUN_DIR/prompt_candidates.yaml" \
  "$RUN_DIR/promotion_recommendation.yaml"
do
  test ! -e "$path" || {
    echo "unexpected artifact exists: $path" >&2
    exit 1
  }
done
```

Confirm that no candidate or promotion artifacts were created. 
The command should complete silently. Any listed artifact must only be created by a later,
explicitly reviewed workflow.

### Candidate-generation input export

After human signal classification exists, a reviewer may export a deterministic
candidate-generation input artifact for a future candidate-generation step:

```bash
RUN_ID="<run-id>"
RUN_DIR="data/runs/$RUN_ID"

uv run python scripts/export_rule_improvement_candidate_generation_input.py \
  --classification "$RUN_DIR/rule_improvement_signal_classification.json" \
  --review-input "$RUN_DIR/rule_improvement_review_input.json" \
  --output "$RUN_DIR/rule_improvement_candidate_generation_input.json"
```

Inspect the exported eligible signals:

```bash
jq '.eligible_signal_count, .signals[] | {signal_ref, label, candidate_generation_eligible, evidence_refs, source_fact_ids}' \
  "$RUN_DIR/rule_improvement_candidate_generation_input.json"
```

This exporter starts after human signal classification. It only carries forward
human-reviewed decisions where `candidate_generation_eligible` is already true
in `rule_improvement_signal_classification.json`. It preserves provenance,
exact English label enum values, `source_fact_ids`, and `evidence_refs`. If
`--review-input` is supplied, the review input is used only to verify those refs
and source signal consistency; it must not override labels or eligibility.

`rule_improvement_candidate_generation_input.json` is not candidate generation.
It does not create `rule_candidates.yaml`, `prompt_candidates.yaml`, or
`promotion_recommendation.yaml`, does not recommend promotion, and does not
mutate case/action/investigation/containment/approval/verdict/severity/
confidence/Rule Improvement state. It is only a reviewable input artifact for a
future, separately reviewed candidate-generation workflow.

### Candidate draft generation smoke

After `rule_improvement_candidate_generation_input.json` exists, a reviewer may
generate a deterministic, reviewable candidate draft:

```bash
RUN_ID="<run-id>"
RUN_DIR="data/runs/$RUN_ID"

uv run python scripts/generate_rule_improvement_candidate_draft.py \
  --candidate-generation-input "$RUN_DIR/rule_improvement_candidate_generation_input.json" \
  --output "$RUN_DIR/rule_improvement_candidate_draft.json"
```

Inspect the generated draft and its locked safety flags:

```bash
jq '{draft_id, promotion_allowed, requires_human_approval, candidate_generation_started}' \
  "$RUN_DIR/rule_improvement_candidate_draft.json"

jq '.candidates[] | {candidate_id, candidate_type, source_signal_ref, source_label, auto_apply_allowed, promotion_recommendation_allowed}' \
  "$RUN_DIR/rule_improvement_candidate_draft.json"
```

This step creates only `rule_improvement_candidate_draft.json`. It starts after
candidate-generation input and before any `rule_candidates.yaml` or
`prompt_candidates.yaml` artifact:

```text
rule_improvement_signal_classification.json
  ↓
rule_improvement_candidate_generation_input.json
  ↓ deterministic candidate draft generator
rule_improvement_candidate_draft.json          (reviewable, non-applying draft)
  ↓ future candidate review
rule_candidates.yaml / prompt_candidates.yaml  (later workflow only)
```

The candidate draft generator is deterministic and local. It does not call an
LLM, execute a model, use a translation API, or make network calls. It uses only
`rule_improvement_candidate_generation_input.json` as the source of draft items,
preserves exact signal refs, source fact IDs, evidence refs, and English label
enum values, and fails closed for unsupported labels or zero eligible signals.

The candidate draft remains reviewable and non-applying. It requires human
approval, keeps `promotion_allowed: false`, keeps candidate-level
`auto_apply_allowed: false`, and does not recommend promotion. It does not
create `rule_candidates.yaml`, `prompt_candidates.yaml`, or
`promotion_recommendation.yaml`; approve or promote anything; modify detection
rules, parser code, telemetry collection, correlation logic, or prompts; or
mutate case/action/investigation/containment/approval/verdict/severity/
confidence/Rule Improvement state. Rule/prompt candidate generation and
promotion remain later explicitly reviewed workflows.

### Candidate draft review handoff smoke

After `rule_improvement_candidate_draft.json` exists, a reviewer may export
deterministic human-review handoff artifacts:

```bash
RUN_ID="<run-id>"
RUN_DIR="data/runs/$RUN_ID"

uv run python scripts/export_rule_improvement_candidate_review_handoff.py \
  --candidate-draft "$RUN_DIR/rule_improvement_candidate_draft.json" \
  --worksheet-output "$RUN_DIR/rule_improvement_candidate_review_worksheet.md" \
  --decisions-template-output "$RUN_DIR/rule_improvement_candidate_review_decisions_template.json"
```

Inspect the worksheet and incomplete decisions template:

```bash
sed -n '1,220p' "$RUN_DIR/rule_improvement_candidate_review_worksheet.md"

jq '{artifact_type, reviewer_id, reviewed_at}' \
  "$RUN_DIR/rule_improvement_candidate_review_decisions_template.json"

jq '.decisions[] | {candidate_id, candidate_type, source_signal_ref, source_label, decision, allowed_next_artifact_type}' \
  "$RUN_DIR/rule_improvement_candidate_review_decisions_template.json"
```

This step starts after `rule_improvement_candidate_draft.json` and creates only:

- `rule_improvement_candidate_review_worksheet.md`
- `rule_improvement_candidate_review_decisions_template.json`

The worksheet preserves candidate IDs, candidate types, source signal refs,
English source labels, source fact IDs, evidence refs, proposed changes,
limitations, and locked safety flags for human review. It documents possible
human decision values such as `accept_for_candidate_creation`, `reject`,
`defer`, and `split`, and possible later artifact types such as
`rule_candidate`, `parser_candidate`, `telemetry_candidate`,
`correlation_candidate`, `prompt_candidate`, and `none`.

The decisions template is incomplete by design. It contains `REPLACE_ME`
placeholders for reviewer identity, review time, decision, rationale, evidence
needs, split status, and allowed next artifact type. It is not a completed
human decision artifact, not canonical approval, and not promotion.

This handoff step does not generate rule, prompt, parser, telemetry, or
correlation candidates; does not create `rule_candidates.yaml`,
`prompt_candidates.yaml`, or `promotion_recommendation.yaml`; does not approve
or promote anything; and does not mutate case/action/investigation/containment/
approval/verdict/severity/confidence/Rule Improvement state.

### Optional Japanese candidate review worksheet rewrite

After `rule_improvement_candidate_review_worksheet.md` exists, a reviewer may
prepare an optional Japanese rewrite for readability. This rewrite is a
read-only human aid. It is not canonical, is not a decision source, and must
not be fed into downstream JSON-producing scripts. Canonical decisions must
still be authored through the English enum-preserving decisions JSON workflow.
IDs, refs, labels, enum values, file paths, safety flags, and boundary artifact
names must remain exact.

Generate a prompt bundle for manual model execution:

```bash
RUN_ID="<run-id>"
RUN_DIR="data/runs/$RUN_ID"

uv run python scripts/rewrite_rule_improvement_candidate_review_worksheet_ja.py \
  --mode prompt_only \
  --worksheet "$RUN_DIR/rule_improvement_candidate_review_worksheet.md" \
  --prompt-output "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_prompt_bundle.json" \
  --output "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_rewritten.md"
```

The prompt-only mode writes the prompt bundle only. It does not call OpenAI, LM
Studio, a translation API, a network service, or any model runner. After manual
model execution outside this script, import the already-produced model output:

```bash
uv run python scripts/rewrite_rule_improvement_candidate_review_worksheet_ja.py \
  --mode import_model_output \
  --worksheet "$RUN_DIR/rule_improvement_candidate_review_worksheet.md" \
  --model-output "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_model_output.json" \
  --output "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_rewritten.md"
```

Inspect the rewritten worksheet:

```bash
sed -n '1,220p' "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_rewritten.md"
```

The importer accepts JSON with `rewritten_markdown` or plain Markdown text. It
fails closed if the output is empty or if required invariant strings are
missing, including candidate IDs, candidate types, source signal refs, English
labels, source fact IDs, required evidence refs, safety flag labels, and the
boundary artifact names `rule_candidates.yaml`, `prompt_candidates.yaml`, and
`promotion_recommendation.yaml`.

The Japanese rewrite must not modify canonical JSON artifacts such as
`rule_improvement_candidate_review_decisions_template.json`,
`rule_improvement_candidate_review_decisions.json`, or
`rule_improvement_candidate_creation_input.json`. It must not approve, reject,
defer, split, promote, deploy, or create any rule/prompt/parser/telemetry/
correlation candidate artifact.

#### Optional LM Studio Japanese rewrite runner

A separate local LM Studio runner can send the prompt bundle to an
OpenAI-compatible local LM Studio `/chat/completions` endpoint and write only
untrusted model output JSON. The runner does not call the importer and does not
write `rule_improvement_candidate_review_worksheet_ja_rewritten.md`; the
existing import mode remains the fail-closed invariant validation boundary.

```bash
RUN_DIR="data/runs/smoke-ja-rewrite-001"

export LMSTUDIO_BASE_URL="http://127.0.0.1:1234/v1"
export LMSTUDIO_MODEL="<LM Studio model id>"

uv run python scripts/rewrite_rule_improvement_candidate_review_worksheet_ja.py \
  --mode prompt_only \
  --worksheet "$RUN_DIR/rule_improvement_candidate_review_worksheet.md" \
  --prompt-output "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_prompt_bundle.json" \
  --output "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_rewritten.md"

uv run python scripts/run_rule_improvement_candidate_review_worksheet_ja_rewrite_lmstudio.py \
  --prompt-bundle "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_prompt_bundle.json" \
  --model-output "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_model_output.json"

uv run python scripts/rewrite_rule_improvement_candidate_review_worksheet_ja.py \
  --mode import_model_output \
  --worksheet "$RUN_DIR/rule_improvement_candidate_review_worksheet.md" \
  --model-output "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_model_output.json" \
  --output "$RUN_DIR/rule_improvement_candidate_review_worksheet_ja_rewritten.md"
```

The LM Studio runner builds hard requirements from the prompt bundle, including
protected backtick-enclosed values that must be copied exactly. Its output is
untrusted. If the model translates protected values, drops candidate IDs,
changes refs, or omits boundary artifact names, the importer should fail closed;
that failure is expected and should be fixed by rerunning or editing the model
output before import, not by weakening the canonical JSON workflow.

### Completed candidate-review decisions smoke

After the candidate review worksheet and decisions template are produced, a
human reviewer may complete a separate decisions JSON file. That human-authored
file can then be validated and normalized into canonical
`rule_improvement_candidate_review_decisions.json`:

To prepare the completed decisions input, copy
`rule_improvement_candidate_review_decisions_template.json` to a separate
human-authored file such as
`rule_improvement_candidate_review_decisions.completed.json`, replace every
`REPLACE_ME` placeholder, and change `artifact_type` to
`rule_improvement_candidate_review_decisions`.

```bash
RUN_ID="<run-id>"
RUN_DIR="data/runs/$RUN_ID"

uv run python scripts/create_rule_improvement_candidate_review_decisions.py \
  --candidate-draft "$RUN_DIR/rule_improvement_candidate_draft.json" \
  --completed-decisions "$RUN_DIR/rule_improvement_candidate_review_decisions.completed.json" \
  --output "$RUN_DIR/rule_improvement_candidate_review_decisions.json"
```

Inspect the canonical decisions artifact:

```bash
jq '{artifact_type, reviewer_id, reviewed_at, decision_count: (.decisions | length)}' \
  "$RUN_DIR/rule_improvement_candidate_review_decisions.json"

jq '.decisions[] | {candidate_id, candidate_type, source_signal_ref, source_label, decision, split_required, requires_more_evidence, allowed_next_artifact_type}' \
  "$RUN_DIR/rule_improvement_candidate_review_decisions.json"
```

This step starts after a human fills in the candidate review decisions template.
The completed decisions file is human-authored input. The script validates the
completed decisions against `rule_improvement_candidate_draft.json`, checks
candidate order and provenance, rejects placeholders, enforces decision
consistency, and writes the canonical decisions artifact.

`accept_for_candidate_creation` means only that the reviewed draft may proceed
to a later candidate-creation workflow. It is not rule approval, prompt
approval, parser approval, telemetry approval, correlation approval, deployment
approval, or promotion.

This workflow does not generate rule, prompt, parser, telemetry, or correlation
candidates; does not create `rule_candidates.yaml`, `prompt_candidates.yaml`,
or `promotion_recommendation.yaml`; does not approve or promote anything; and
does not mutate case/action/investigation/containment/approval/verdict/severity/
confidence/Rule Improvement state.

### Candidate creation input smoke

After canonical `rule_improvement_candidate_review_decisions.json` exists, a
reviewer may export deterministic input for a later candidate-creation workflow:

```bash
RUN_ID="<run-id>"
RUN_DIR="data/runs/$RUN_ID"

uv run python scripts/export_rule_improvement_candidate_creation_input.py \
  --candidate-draft "$RUN_DIR/rule_improvement_candidate_draft.json" \
  --candidate-review-decisions "$RUN_DIR/rule_improvement_candidate_review_decisions.json" \
  --output "$RUN_DIR/rule_improvement_candidate_creation_input.json"
```

Inspect the exported creation input:

```bash
jq '{artifact_type, accepted_candidate_count, candidate_creation_allowed, promotion_allowed, requires_later_candidate_review}' \
  "$RUN_DIR/rule_improvement_candidate_creation_input.json"

jq '.items[] | {candidate_id, candidate_type, allowed_next_artifact_type, source_signal_ref, source_label, human_decision_ref, human_decision_id, human_decision_status, candidate_creation_input_only, auto_apply_allowed, promotion_recommendation_allowed}' \
  "$RUN_DIR/rule_improvement_candidate_creation_input.json"
```

This step starts after canonical candidate-review decisions. It exports only
review decisions whose `decision` is `accept_for_candidate_creation`. `reject`,
`defer`, and `split` decisions are excluded in this MVP. If no decisions are
accepted, the exporter writes a valid artifact with `accepted_candidate_count: 0` and `items: []`.

Each exported item preserves human candidate-review decision provenance through
`human_decision_ref`, `human_decision_id`, and `human_decision_status`. The
`human_decision_id` identifies the source decision by combining the canonical
candidate-review decisions artifact ref with the decision JSON pointer; it is
not derived from `candidate_id`.

`rule_improvement_candidate_creation_input.json` is input for a later
candidate-creation workflow. It does not create rule, prompt, parser, telemetry,
or correlation candidates. `accept_for_candidate_creation` still means only
that the draft item may proceed to a later candidate-creation workflow. It is
not rule approval, prompt approval, deployment approval, promotion, or SOC state
mutation.

This workflow does not create `rule_candidates.yaml`, `prompt_candidates.yaml`,
or `promotion_recommendation.yaml`; does not approve, promote, or deploy
anything; and does not mutate case/action/investigation/containment/approval/
verdict/severity/confidence/Rule Improvement state.

### Candidate proposal v2 generator smoke

After `rule_improvement_candidate_creation_input.json` exists, a reviewer may
run the standalone v2 proposal generator:

```bash
RUN_ID="<run-id>"
RUN_DIR="data/runs/$RUN_ID"

uv run python scripts/generate_rule_improvement_candidate_proposals_v2.py \
  --input "$RUN_DIR/rule_improvement_candidate_creation_input.json" \
  --output "$RUN_DIR/rule_improvement_candidate_proposals_v2.json" \
  --diagnostics-output "$RUN_DIR/rule_improvement_candidate_proposal_generator_diagnostics.json"
```

The generator fits after the human candidate draft / review / classification
flow and after deterministic candidate-creation input export:

```text
rule_improvement_candidate_draft.json
  -> rule_improvement_candidate_review_decisions.json
  -> rule_improvement_candidate_creation_input.json
  -> scripts/generate_rule_improvement_candidate_proposals_v2.py
  -> rule_improvement_candidate_proposals_v2.json
```

Inspect the generated proposal artifact:

```bash
jq '{version, artifact_type, artifact_semantics, proposal_count: (.proposals | length)}' \
  "$RUN_DIR/rule_improvement_candidate_proposals_v2.json"

jq '.proposals[] | {candidate_id, candidate_type, allowed_next_artifact_type, review_status, human_decision_provenance}' \
  "$RUN_DIR/rule_improvement_candidate_proposals_v2.json"
```

If `--diagnostics-output` was used, inspect skipped unsupported future
candidate types:

```bash
jq '{artifact_type, proposal_count, skipped_count, skipped_items}' \
  "$RUN_DIR/rule_improvement_candidate_proposal_generator_diagnostics.json"
```

Optional schema validation:

```bash
uv run python - <<'PY'
import json
from pathlib import Path

from jsonschema import Draft202012Validator

run_dir = Path("data/runs/<run-id>")
schema = json.loads(
    Path("schemas/rule_improvement_candidate_proposals_v2.schema.json").read_text(
        encoding="utf-8"
    )
)
artifact = json.loads(
    (run_dir / "rule_improvement_candidate_proposals_v2.json").read_text(
        encoding="utf-8"
    )
)
Draft202012Validator(schema).validate(artifact)
print("rule_improvement_candidate_proposals_v2.json schema valid")
PY
```

`rule_improvement_candidate_proposals_v2.json` is `proposal_only`. The
generator does not apply rules, prompts, parsers, telemetry, correlation logic,
baselines, active agents, case state, action state, investigation state,
approval state, or promotion state.

The generator preserves human decision provenance from
`rule_improvement_candidate_creation_input.json` by copying item-level
`human_decision_ref`, `human_decision_id`, and `human_decision_status` into
v2 `human_decision_provenance`. It must not derive `decision_id` from
`candidate_id`.

The optional diagnostics artifact is non-proposal metadata for skipped
unsupported future schema-valid candidate types. Diagnostics do not authorize
apply, deployment, baseline update, or promotion, and must not be treated as
proposal items.

Failure behavior:

- invalid input fails closed
- invalid output fails closed
- known `candidate_type` / `allowed_next_artifact_type` mismatches fail closed
- unsupported future schema-valid candidate types may be skipped

Fail-closed errors remain errors even when `--diagnostics-output` is supplied;
the diagnostics file is written only after successful input and output
validation.

Generated `data/runs/**` artifacts are run outputs and should not be committed.

### Proposal review decisions template export

After `rule_improvement_candidate_proposals_v2.json` exists, a reviewer may
create an incomplete proposal review decisions template:

```bash
uv run python scripts/export_rule_improvement_proposal_review_decisions_template.py \
  --input "$RUN_DIR/rule_improvement_candidate_proposals_v2.json" \
  --output "$RUN_DIR/rule_improvement_proposal_review_decisions_template.json"
```

The template exporter validates the proposal v2 input, hashes the exact input
bytes, and writes schema-valid `conversion_review_only` JSON only after output
validation succeeds. It defaults every decision to `defer`, not
`accept_for_conversion`, and uses a placeholder rationale that a human reviewer
must replace before any future importer exists.

Inspect the template:

```bash
jq '{version, artifact_type, artifact_semantics, decision_count: (.decisions | length)}' \
  "$RUN_DIR/rule_improvement_proposal_review_decisions_template.json"

jq '.decisions[] | {candidate_id, proposal_ref, candidate_type, allowed_next_artifact_type, decision, source_human_decision_provenance}' \
  "$RUN_DIR/rule_improvement_proposal_review_decisions_template.json"
```

This output is not imported automatically. It does not authorize conversion,
apply, deployment, baseline update, prompt update, parser update, telemetry
update, correlation update, or promotion. Generated `data/runs/**` artifacts
remain run outputs and should not be committed.

After a human reviewer replaces the TODO rationale placeholders and completes
the decisions, import the completed artifact into canonical JSON:

```bash
uv run python scripts/import_rule_improvement_proposal_review_decisions.py \
  --input "$RUN_DIR/rule_improvement_proposal_review_decisions_template_completed.json" \
  --output "$RUN_DIR/rule_improvement_proposal_review_decisions.json"
```

The importer validates against
`schemas/rule_improvement_proposal_review_decisions_v1.schema.json`, rejects
the template TODO rationale placeholder, refuses to overwrite its input, and
writes stable canonical JSON only after validation succeeds.

Inspect the canonical decisions:

```bash
jq '{version, artifact_type, artifact_semantics, decision_count: (.decisions | length)}' \
  "$RUN_DIR/rule_improvement_proposal_review_decisions.json"

jq '.decisions[] | {candidate_id, proposal_ref, candidate_type, allowed_next_artifact_type, decision, source_human_decision_provenance}' \
  "$RUN_DIR/rule_improvement_proposal_review_decisions.json"
```

Canonical proposal review decisions remain conversion-review-only. Even
`accept_for_conversion` is not apply approval, deployment approval, baseline
update approval, prompt update approval, parser update approval, telemetry
update approval, correlation update approval, or promotion approval. The
importer does not create concrete candidate artifacts, update
`rule_candidates.yaml`, update `prompt_candidates.yaml`, create
`promotion_recommendation.yaml`, or mutate state.

Standalone conversion from canonical proposal review decisions to the
non-applying concrete candidate bundle is implemented at
`scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py`.
Its design boundary is documented in
`docs/design/rule-improvement/rule_improvement_proposal_conversion_contract.md`.
The converter may consider only `accept_for_conversion` decisions for converted
candidates and still must not apply, deploy, update baselines, or promote.

The preferred concrete candidate artifact strategy is documented in
`docs/design/rule-improvement/rule_improvement_concrete_candidate_artifact_strategy.md`.
The converter writes a provenance-preserving
`rule_improvement_concrete_candidate_bundle_v1.json`, not direct legacy
artifacts. Legacy-compatible export remains a separate schema-validated and
separately reviewed narrowing step.

```bash
uv run python scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py \
  --decisions "$RUN_DIR/rule_improvement_proposal_review_decisions.json" \
  --proposals "$RUN_DIR/rule_improvement_candidate_proposals_v2.json" \
  --output "$RUN_DIR/rule_improvement_concrete_candidate_bundle_v1.json"
```

The concrete candidate bundle is non-applying and non-promoting. It does not
create `rule_candidates.yaml`, `prompt_candidates.yaml`, or
`promotion_recommendation.yaml`; does not wire into the process pipeline; and
does not add apply, deployment, baseline update, prompt update, parser update,
telemetry update, correlation update, or promotion workflows.
The legacy-compatible export boundary is documented in
`docs/design/rule-improvement/rule_improvement_legacy_compatible_export_contract.md`;
the Phase 1 rule/prompt exporter is implemented at
`scripts/export_rule_improvement_legacy_rule_prompt_candidates.py` and remains
a separate schema-validated narrowing step.

```bash
uv run python scripts/export_rule_improvement_legacy_rule_prompt_candidates.py \
  --bundle "$RUN_DIR/rule_improvement_concrete_candidate_bundle_v1.json" \
  --rule-output "$RUN_DIR/rule_candidates.yaml" \
  --prompt-output "$RUN_DIR/prompt_candidates.yaml"
```

This exporter handles rule and prompt candidates only. Parser export, telemetry
export, correlation export, process-pipeline wiring, and
apply/deployment/baseline/promotion workflows remain unimplemented. The
promotion recommendation export boundary is documented in
`docs/design/rule-improvement/rule_improvement_promotion_recommendation_export_contract.md`;
the standalone exporter is implemented at
`scripts/export_rule_improvement_promotion_recommendation.py`.

```bash
uv run python scripts/export_rule_improvement_promotion_recommendation.py \
  --bundle "$RUN_DIR/rule_improvement_concrete_candidate_bundle_v1.json" \
  --output "$RUN_DIR/promotion_recommendation.yaml" \
  --diagnostics-output "$RUN_DIR/rule_improvement_promotion_recommendation_export_diagnostics.json"
```

The promotion recommendation exporter considers only converted
`promotion_review` bundle candidates with
`allowed_next_artifact_type: promotion_review_recommendation` and the required
schema-compatible promotion payload fields: `promotion_recommended`,
`current_agent`, `challenger_agent`, `next_baseline_agent`, `score_delta`,
`gates`, and `blocking_gaps`. It does not infer promotion decisions from
incomplete payloads. It validates the bundle input and legacy promotion
recommendation output schemas, writes output only after validation succeeds,
and may write non-recommendation diagnostics for skipped items.
`promotion_recommendation.yaml` is recommendation-only; it is not apply
approval, deployment approval, baseline update approval, prompt update
approval, or promotion approval, and the exporter must not promote anything by
itself.

The implemented artifact-chain smoke test is local-development / WSL-friendly
and uses only synthetic schema-valid fixtures under `tmp_path`:

```bash
uv run pytest tests/test_rule_improvement_phase1_legacy_export_chain_smoke.py -q
```

That smoke covers proposal v2 plus canonical proposal review decisions through
the concrete candidate bundle and Phase 1 rule/prompt export. It verifies that
rule candidates appear only in `rule_candidates.yaml`, prompt candidates appear
only in `prompt_candidates.yaml`, `promotion_review` and non-accept decisions
are reported in diagnostics rather than exported, `promotion_recommendation.yaml`
is not created, and generated rule/prompt outputs do not contain
apply/deploy/promote-like fields. It is not an attack/victim-log end-to-end
test, reads no generated `data/runs/**` artifacts, and requires no victim logs,
Wazuh, rsyslog, Hydra output, Proxmox, Kali, or Ubuntu victim.

The promotion recommendation export-chain smoke is also local-development /
WSL-friendly and uses synthetic schema-valid fixtures under `tmp_path`:

```bash
uv run pytest tests/test_rule_improvement_promotion_recommendation_export_chain_smoke.py -q
```

That smoke covers proposal v2 plus canonical proposal review decisions through
the concrete candidate bundle and promotion recommendation export. It verifies
that schema-safe promotion-review proposal payload fields are preserved into
the concrete candidate bundle payload; schema-valid recommendation-only
`promotion_recommendation.yaml` is produced; non-promotion candidates and
non-accept/skipped decisions are excluded from the recommendation output;
diagnostics report unsupported/skipped items deterministically; and
`rule_candidates.yaml` / `prompt_candidates.yaml` are not created. It is not an
attack/victim-log end-to-end test, reads no generated `data/runs/**` artifacts,
and requires no victim logs, Wazuh, rsyslog, Hydra output, Proxmox, Kali, or
Ubuntu victim.

The export artifact validation summary contract is documented in
`docs/design/rule-improvement/rule_improvement_export_artifact_validation_summary_contract.md`.
The implemented reporter inspects already-generated export artifacts and writes
`rule_improvement_export_artifact_validation_summary.json`:

```bash
uv run python scripts/summarize_rule_improvement_export_artifacts.py \
  --run-dir "$RUN_DIR" \
  --output "$RUN_DIR/rule_improvement_export_artifact_validation_summary.json"
```

That reporter is validation/reporting only over artifacts such as
`rule_improvement_concrete_candidate_bundle_v1.json`,
`rule_candidates.yaml`, `prompt_candidates.yaml`, `promotion_recommendation.yaml`,
and export diagnostics. The summary does not replace human review and is not
apply approval, deployment approval, baseline update approval, prompt
update approval, parser update approval, telemetry update approval, correlation
update approval, promotion approval, or an automatic promotion decision.
The summary schema is implemented at
`schemas/rule_improvement_export_artifact_validation_summary.schema.json`, with
focused schema tests at
`tests/test_rule_improvement_export_artifact_validation_summary_schema.py`. The
schema fixes the JSON contract for the summary artifact, and the reporter
validates the summary against it before writing output. If summary schema
validation fails, the reporter fails closed and does not write the summary
output. This does not change safety semantics, invoke exporters, create rule
candidates, prompt candidates, or promotion recommendations, update active
agents or production state, or add apply, deployment, baseline update, prompt
update, parser update, telemetry update, correlation update, promotion
workflow, or automatic promotion behavior.

The export validation summary chain smoke is local-development / WSL-friendly
and uses synthetic schema-valid fixtures under `tmp_path`:

```bash
uv run pytest tests/test_rule_improvement_export_validation_summary_chain_smoke.py -q
```

That smoke covers the implemented chain from
`rule_improvement_candidate_proposals_v2.json` plus
`rule_improvement_proposal_review_decisions.json` through
`rule_improvement_concrete_candidate_bundle_v1.json`, schema-valid
`rule_candidates.yaml` / `prompt_candidates.yaml`, schema-valid
recommendation-only `promotion_recommendation.yaml`, optional schema-valid
`parser_candidates.yaml`, and
`rule_improvement_export_artifact_validation_summary.json`. It verifies the
summary reporter reads the already-generated artifacts, reports
`overall_status: pass` with no errors, lists the concrete bundle, rule
candidates, prompt candidates, promotion recommendation, and parser candidates
as present when generated, passes schema validation, safety checks, and
consistency checks, treats diagnostics as diagnostics only, excludes
skipped/non-accept candidate IDs from rule, prompt, promotion, and parser
outputs, and does not rewrite primary export artifacts.

The validation summary reporter does not invoke exporter scripts and does not
create `rule_candidates.yaml`, `prompt_candidates.yaml`,
`promotion_recommendation.yaml`, or `parser_candidates.yaml`; those files are
created only by their exporters. The smoke is not an attack/victim-log
end-to-end test, reads no generated `data/runs/**` artifacts, and requires no
victim logs, Wazuh, rsyslog, Hydra output, Proxmox, Kali, or Ubuntu victim. No
telemetry export, correlation export, apply, deployment, baseline update,
prompt update, parser update, telemetry update, correlation update, promotion
workflow, or automatic promotion behavior is implemented.

Operator status: the Rule Improvement export MVP is complete for the current
candidate-generation boundary. Reviewed proposal decisions can flow through
concrete bundle conversion into rule, prompt, promotion-review, and parser
export artifacts, and the validation summary can report over those
already-generated artifacts without mutating them.

The parser legacy export contract is documented in
`docs/design/rule-improvement/rule_improvement_parser_legacy_export_contract.md`.
It defines the `parser_candidates.yaml` and
`rule_improvement_parser_legacy_export_diagnostics.json` boundaries as
candidate/diagnostics-only artifacts from accepted `candidate_type: parser`
concrete candidates. Standalone deterministic
`scripts/export_rule_improvement_parser_candidates.py` can produce
schema-valid candidate-only `parser_candidates.yaml` and optional diagnostics
from `rule_improvement_concrete_candidate_bundle_v1.json`. Deterministic
tmp-path parser export chain smoke coverage is implemented at
`tests/test_rule_improvement_parser_export_chain_smoke.py`; it proves the local
artifact chain from proposal/review decisions through the concrete bundle to
schema-valid `parser_candidates.yaml`, and requires no victim logs, Wazuh,
rsyslog, Hydra output, Proxmox, Kali, Ubuntu victim, or existing
`data/runs/**` artifacts. Parser process-pipeline wiring, parser apply
workflow, parser deployment workflow, and automatic parser update are not
implemented. The parser candidate schema is implemented at
`schemas/parser_candidates_schema.json`, with focused tests at
`tests/test_parser_candidates_schema.py`; focused exporter tests are at
`tests/test_export_rule_improvement_parser_candidates.py`.
`parser_candidates.yaml` is not required today. The validation summary reporter
optionally inspects it when present, validates it against
`schemas/parser_candidates_schema.json`, checks parser candidate IDs against
the concrete bundle, and treats parser diagnostics as diagnostics only. The
validation summary reporter does not invoke the parser exporter and does not
create `parser_candidates.yaml`.

Process-pipeline wiring is documented in
`docs/design/rule-improvement/rule_improvement_export_validation_summary_pipeline_wiring_contract.md`.
`scripts/run_process_pipeline.py` can generate RI export validation summaries
only when explicitly enabled:

```bash
uv run python scripts/run_process_pipeline.py \
  --run-id "$RUN_ID" \
  --audit-log "$AUDIT_LOG" \
  --scenario "$SCENARIO" \
  --enable-ri-export-validation-summary
```

The flag is disabled by default. When enabled, the process pipeline runs the
summary step after existing RI export steps and writes only
`rule_improvement_export_artifact_validation_summary.json` for the current run
directory. The summary reporter validates output before write; schema
validation failure remains fail-closed. The process-pipeline step does not
invoke exporters and does not create `rule_candidates.yaml`,
`prompt_candidates.yaml`, or `promotion_recommendation.yaml`. It is not human
review, apply approval, deployment approval, baseline update approval, prompt
update approval, parser update approval, telemetry update approval,
correlation update approval, promotion approval, or automatic promotion, and
it does not update active agents or production state.

Human review and bundle conversion of
`rule_improvement_candidate_proposals_v2.json` are separate boundaries documented in
`docs/design/rule-improvement/rule_improvement_candidate_proposal_review_conversion_contract.md`.
Proposal review decisions must not be treated as apply, deployment, baseline
update, or promotion approval.

### Legacy candidate artifacts vs candidate-creation input

The repository also contains an older comparison-harness Rule Improvement path
that may produce:

- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`

Those artifacts belong to the comparison-harness review flow. They are not
created by the AI-assisted post-action flow above, and
`rule_improvement_candidate_creation_input.json` is not a replacement spelling
for them. It is only a provenance-preserving input for a future, separately
reviewed candidate-creation workflow.

Any future bridge from `rule_improvement_candidate_creation_input.json` to
concrete `rule_candidates.yaml` or `prompt_candidates.yaml` artifacts must be
implemented as an explicit reviewed workflow with its own validation and tests.
It must not auto-apply rule, prompt, parser, telemetry, or correlation changes.

`promotion_recommendation.yaml` is also only a recommendation artifact in the
existing harness flow. It is not promotion approval, deployment approval, or an
instruction to update the baseline. Promotion still requires human review and
the established validation gates.

## 7. Boundaries and prohibited automation

The current flow must not:

- treat AI suggestions as final human decisions
- treat the untouched template as completed decisions JSON
- treat the candidate review decisions template as completed candidate approval
- treat the Japanese candidate review worksheet rewrite as canonical or as a decision source
- treat completed candidate review decisions as deployment approval or promotion
- treat candidate-creation input as created candidates, approval, or promotion
- auto-run `scripts/create_rule_improvement_signal_classification.py`
- generate `rule_improvement_signal_classification.json` from AI output alone
- derive `candidate_generation_eligible` before human classification
- create or update `rule_candidates.yaml`
- create or update `prompt_candidates.yaml`
- treat `promotion_recommendation.yaml` as apply, deployment, baseline update,
  prompt update, or promotion approval
- auto-approve or auto-promote any candidate
- mutate case, action, investigation, containment, approval, verdict, severity,
  confidence, or Rule Improvement promotion state
- feed post-action DFIR output back into or rewrite pre-case
  `investigation_result.json`

Classification records a human review decision. It does not itself generate a
candidate or allow promotion.

## 8. Evidence caveats

- `Linux.BashHistory` is weak, user-controlled, and timing-sensitive evidence.
  A history entry does not confirm execution, and its absence does not prove
  non-execution.
- `Linux.ProcessList` is a point-in-time snapshot. A matching process supports
  presence only at collection time, and process absence does not prove
  non-execution.
- Absence in any collection artifact is not proof that an action did not occur
  and must not support host-clean or benign conclusions.
- Missing telemetry remains a reviewable telemetry, timing, scope, or evidence
  gap. It is not an automatic rule candidate.

## 9. Validation and smoke checks

Run the documentation and focused regression checks:

```bash
git diff --check
uv run ruff check .
uv run pytest tests/test_post_action_dfir_pipeline_integration.py -q
uv run pytest tests/test_export_ri_signal_classification_decisions_template.py -q
uv run pytest tests/test_export_ai_review_draft_human_worksheet.py -q
uv run pytest tests/test_generate_mock_ai_review_draft.py -q
uv run pytest tests/test_rule_improvement_signal_classification_helper.py -q
uv run pytest tests/test_run_ai_review_draft_openai_model.py -q
uv run pytest tests/test_run_ai_review_draft_lmstudio_model.py -q
uv run pytest tests/test_compare_ai_review_drafts.py -q
```

For a manual smoke run, verify that the five review artifacts are produced in
the run directory, the template contains placeholders rather than copied AI
decisions, and none of these files exists unless separately created through its
reviewed workflow:

```text
decisions.json
rule_improvement_signal_classification.json
rule_candidates.yaml
prompt_candidates.yaml
promotion_recommendation.yaml
```
