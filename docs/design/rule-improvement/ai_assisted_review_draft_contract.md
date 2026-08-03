# AI-Assisted Rule Improvement Review Draft Contract

## 1. Purpose and status

This document defines a future, optional AI-assisted drafting stage for
`rule_improvement_review_input.json`.

The stage may help a human inspect review signals, evidence caveats, and missing
requirements. It may suggest labels, rationale text, questions, and next steps.
It does not classify a signal, generate a candidate, recommend promotion, or
change operational state.

The Draft 2020-12 artifact schema is implemented at
`schemas/rule_improvement_ai_review_draft.schema.json`, with valid and unsafe
fixtures under `tests/fixtures/rule_improvement_ai_review_draft/` and focused
tests in `tests/test_rule_improvement_ai_review_draft_schema.py`.

The prompt/input boundary is defined in
`docs/design/rule-improvement/ai_review_draft_prompt_input_contract.md`, and its
minimized-context schema is implemented at
`schemas/rule_improvement_ai_review_draft_prompt_input.schema.json`. The first
versioned prompt file is
`prompts/rule-improvement/ai_review_draft_v1.md`; it remains inert until an
explicit manual runner uses a generated prompt bundle. No automatic/default
model execution or classification helper integration is implemented. Optional,
default-off pipeline options invoke only deterministic local helpers:
the prompt-input exporter, mock generator, and human worksheet exporter.
They do not execute the prompt or a model.
The implemented `scripts/export_ai_review_draft_prompt_input.py` prepares only
the minimized prompt input; it does not execute that prompt or produce this
draft artifact.

The deterministic `scripts/export_ai_review_draft_prompt_bundle.py` exporter
validates an existing prompt-input artifact and materializes a local JSON bundle
containing the versioned prompt, normalized input, expected response schema,
response instructions, and locked safety boundaries. The bundle is the
model-runner handoff boundary: `model_execution_allowed`,
`model_execution_performed`, and `network_allowed` remain `false`. It has no
pipeline integration and performs no model, prompt, API, network, or downstream
artifact execution.

The deterministic `scripts/import_ai_review_draft_model_output.py` importer is
the corresponding model-output acceptance boundary. It executes no model. It
accepts an already-produced JSON candidate only when the draft schema, locked
safety flags, prompt-bundle provenance, optional review-input ref, and every
`source_signal_ref` are consistent. It preserves valid output as-is, fails
closed without repair or field dropping, and writes the canonical
`rule_improvement_ai_review_draft.json`. Downstream worksheet, human decisions,
classification, candidate, promotion, and state boundaries remain unchanged.

The manual-only `scripts/run_ai_review_draft_lmstudio_model.py` runner is the
first explicit model-execution adapter. It refuses to run without
`--allow-model-execution`, allows only loopback LM Studio endpoints by default,
and requires `--allow-private-lan-endpoint` for explicit RFC1918 or IPv4
link-local lab endpoints. Public IPs, non-local domain names, cloud OpenAI
endpoints, and arbitrary DNS resolution are rejected. The runner uses only the
bundle `prompt_text`, writes untrusted candidate JSON, has no pipeline
integration, and cannot make output canonical; the deterministic importer
remains the acceptance boundary.

The manual-only `scripts/run_ai_review_draft_openai_model.py` runner is a
separate external adapter. It requires both `--allow-model-execution` and
`--allow-external-api`, uses the OpenAI Responses API with strict structured
output from `schemas/rule_improvement_ai_review_draft.schema.json`, and relies
on `OPENAI_API_KEY` from the environment. The API request uses a deterministic
OpenAI-compatible projection that removes unsupported response-format keywords
such as `uniqueItems`; it does not mutate or weaken the canonical schema used
by the importer. It sends only bundle `prompt_text`
and reads no evidence refs or raw logs. Its deterministic JSON file remains
untrusted candidate output: no repair, canonical import, pipeline integration,
candidate generation, promotion, or state mutation occurs, and the importer
remains the sole acceptance boundary.

---

## 2. Canonical flow

```text
rule_improvement_review_input.json
  ↓ scripts/export_ai_review_draft_prompt_input.py
rule_improvement_ai_review_draft_prompt_input.json
  ↓ future prompt/model step
rule_improvement_ai_review_draft.json          (suggestions only)
  ↓ human review and independent judgment
human-authored decisions JSON
  ↓ scripts/create_rule_improvement_signal_classification.py
rule_improvement_signal_classification.json    (human decision record)
  ↓ future candidate intake / review
```

The AI draft is an optional sidecar. The human-operated classification helper
remains the only path to `rule_improvement_signal_classification.json` for now.
The draft must never be passed directly to candidate generation or promotion.

The deterministic local
`scripts/export_ai_review_draft_human_worksheet.py` exporter validates an AI
review draft and renders a Markdown worksheet for manual review. The worksheet
contains blank human fields only. It does not create decisions JSON, a
classification artifact, candidates, a promotion recommendation, or state
changes, and it does not invoke a prompt, model, or helper script. The optional,
default-off `--export-ai-review-draft-human-worksheet` process-pipeline flag
invokes only this local exporter after mock draft generation when combined and
fails closed when the draft is missing.

The deterministic
`scripts/export_ri_signal_classification_decisions_template.py` exporter may
also turn a schema-valid draft into an incomplete JSON authoring template. It
copies only source metadata and signal refs; AI labels, rationales, and next
steps become human-edit placeholders. The untouched template is not decisions
JSON or a classification. The optional, default-off
`--export-ri-signal-classification-decisions-template` pipeline flag runs after
worksheet export when combined, but reads the AI draft directly and does not
require the worksheet. A human must complete and extract its `decisions` array
before separately invoking the classification helper.

---

## 3. Schema-defined artifact

The schema-defined draft artifact is:

```text
data/runs/<run_id>/rule_improvement_ai_review_draft.json
```

Its source is the schema-valid
`data/runs/<run_id>/rule_improvement_review_input.json`. The artifact records
suggestions, not reviewer decisions. Its presence does not mean that a human
reviewed, accepted, or classified any signal.

---

## 4. Required safety invariants

The implemented schema requires:

```json
{
  "source_stage": "post_action_dfir",
  "ai_assistance_only": true,
  "human_review_required": true,
  "classification_decision_allowed": false,
  "candidate_generation_started": false,
  "promotion_allowed": false
}
```

These values are not model choices and must not be overridable by model output.
No AI confidence value may weaken these invariants.

---

## 5. Schema-defined shape

The schema accepts this suggestions-only shape:

```json
{
  "draft_id": "ri-ai-review-draft-run-0033-001",
  "source_stage": "post_action_dfir",
  "source_review_input_ref": "data/runs/run-0033/rule_improvement_review_input.json",
  "source_review_input_id": "ri-review-post-dfir-run-0033-001",
  "ai_assistance_only": true,
  "human_review_required": true,
  "classification_decision_allowed": false,
  "candidate_generation_started": false,
  "promotion_allowed": false,
  "suggestions": [
    {
      "source_signal_ref": "/supporting_signals/0",
      "suggested_label": "correlation_gap",
      "suggested_rationale": "The facts may require temporal correlation; a human must verify this interpretation.",
      "suggested_missing_requirements": [
        {
          "requirement_type": "correlation",
          "summary": "Review whether authentication and process observations can be joined by host, user, and time."
        }
      ],
      "suggested_next_step": "Review source facts and timing before choosing a label.",
      "evidence_caveats": [
        "Linux.ProcessList is a point-in-time snapshot."
      ],
      "review_questions": [
        "Does independent telemetry support the proposed temporal relationship?"
      ],
      "confidence_rationale": "The suggestion is tentative because collection timing limits correlation."
    }
  ],
  "assistant_info": {
    "provider": "future-configured-provider",
    "model": "future-configured-model",
    "configuration_ref": "future-versioned-configuration"
  },
  "warnings": [],
  "errors": []
}
```

`model_info` may be used instead of `assistant_info`, but the chosen field
should preserve model and configuration provenance needed to audit the draft.

---

## 6. Allowed suggestions

The AI draft may contain:

- suggested labels, clearly marked as suggestions
- suggested rationale text for human editing
- suggested missing requirements
- suggested recommended next steps
- evidence caveats
- questions for the human reviewer
- notes about weak or insufficient evidence
- notes about telemetry, parser, correlation, timing, or scope gaps
- warnings and processing errors

Suggested missing requirements may use `telemetry`, `parser`, `correlation`,
`collection_scope`, `collection_timing`, `evidence`, or `review`. All suggested
content remains review context and confers no eligibility, approval, or authority.

Suggestion objects use `additionalProperties: false`. The schema therefore
rejects classification-style fields such as `candidate_generation_eligible`,
final `label`, `decision_id`, `reviewer`, `reviewed_at`, and
`human_review_completed`. Suggested labels never derive eligibility;
eligibility exists only in the human-created
`rule_improvement_signal_classification.json` artifact.

---

## 7. Disallowed outputs and effects

The AI-assisted stage must not emit or assert:

- a final classification decision
- `candidate_generation_eligible`
- candidate approval or promotion
- rule or prompt updates
- `rule_candidates.yaml`
- `prompt_candidates.yaml`
- `promotion_recommendation.yaml`
- changes to case status, severity, verdict, or confidence
- action approval or containment changes
- claims that missing evidence proves non-execution
- host-clean or benign conclusions from missing or weak evidence

It must not modify or overwrite:

- `case.json`
- `action_result.json`
- pre-case `investigation_result.json`
- `post_action_dfir_investigation_result.json`
- `rule_improvement_review_input.json`
- `rule_improvement_signal_classification.json`
- containment or approval state
- verdict, severity, or confidence
- Rule Improvement candidate approval or promotion state

Root `additionalProperties: false` also rejects candidate, promotion, and state
fields such as `rule_candidates`, `prompt_candidates`,
`promotion_recommendation`, case or action state, containment, verdict,
severity, and confidence.

---

## 8. Suggested-label handling

The AI may suggest only labels from the human classification enum:

```text
detection_gap
telemetry_gap
parser_gap
correlation_gap
timing_or_scope_limit
insufficient_evidence
expected_or_authorized_behavior
no_rule_change
```

A suggested label is not a classification label until a human independently
selects it and provides the decision to
`scripts/create_rule_improvement_signal_classification.py`.

The draft must not contain `candidate_generation_eligible`. Eligibility is
derived only in the human classification artifact from the label the reviewer
actually chooses. A suggestion of `detection_gap`, `parser_gap`, or
`correlation_gap` therefore creates no candidate eligibility by itself.

---

## 9. Evidence semantics

### 9.1 BashHistory

`Linux.BashHistory` remains weak, user-controlled, timing-sensitive evidence.

- A history entry does not confirm command execution.
- An absent entry does not prove non-execution.
- A draft must retain `evidence_strength: weak`, `user_controlled`,
  `timing_sensitive`, and `shell_history_entry_not_confirmed_execution` context.
- BashHistory alone must not support a definitive gap, host-clean, or benign
  conclusion.

### 9.2 ProcessList

`Linux.ProcessList` remains a point-in-time snapshot.

- A matching process supports presence only at collection time.
- Process absence does not prove non-execution.
- Timing uncertainty should remain a caveat or possible
  `timing_or_scope_limit`, not a fact resolved by the AI.

### 9.3 Missing or limited evidence

Missing, unsupported, unreadable, unparseable, or scoped evidence remains a
gap, limitation, caveat, or review question. The AI must not convert it into
proof of non-execution or a host-clean or benign conclusion.

---

## 10. Human review boundary

The human reviewer must inspect the source review input, not merely the AI
draft. For each signal, the reviewer should:

1. Verify the cited `source_signal_ref` exists.
2. Inspect linked facts, evidence refs, gaps, limitations, and risk notes.
3. Accept, revise, or reject each AI suggestion.
4. Choose the label independently.
5. Author the rationale and next step under their own reviewer identity.
6. Pass human-authored decisions JSON to the classification helper.

The AI draft must not be automatically transformed into decisions JSON. Copying
suggested text requires deliberate human selection and remains attributable to
the human reviewer in the classification record.

---

## 11. Provenance and auditability

The future draft should preserve its draft ID, source review input path and ID,
source signal refs, assistant or model identity and configuration, creation time
if defined, warnings, and errors. Regeneration should create a new draft ID or
version rather than silently overwrite a human-reviewed draft.

---

## 12. Failure behavior

A future implementation should fail closed:

- invalid source review input: do not emit a usable draft
- unknown signal ref: reject or record an error; do not fabricate provenance
- invalid suggested label: reject the suggestion
- missing caveat for weak or point-in-time evidence: reject or flag it
- model or parsing failure: record an error without creating a classification
- draft schema failure: do not write a completed draft

Failure must not trigger the classification helper, candidate generation,
promotion, or any state mutation.

---

## 13. Implementation status and next steps

Implemented:

1. Draft 2020-12 schema for `rule_improvement_ai_review_draft.json`.
2. Required suggestion fields, evidence caveats, review questions, and locked
   safety invariants.
3. Strict rejection of human-decision, eligibility, candidate, promotion, and
   state-mutation fields.
4. Valid and unsafe synthetic fixtures and focused schema tests, including
   BashHistory weak-evidence and ProcessList point-in-time caveats.
5. Deterministic prompt-evaluation fixture pairs under
   `tests/fixtures/rule_improvement_ai_review_draft_prompt_eval/`, with offline
   checks for grounding, caveats, untrusted instructions, missing evidence, and
   boundary safety. They do not execute a model or generate runtime artifacts.
6. Deterministic `scripts/export_ai_review_draft_prompt_input.py` export of
   minimized, schema-valid prompt context. This is context preparation only: it
   neither executes the versioned prompt or a model nor produces the AI review
   draft artifact.
7. Deterministic mock `scripts/generate_mock_ai_review_draft.py` generation for
   schema, boundary, and downstream-review testing. It produces suggestions
   from fixed rules without executing the versioned prompt or calling a model,
   API, network, subprocess, or human classification helper.
8. Deterministic Markdown worksheet export with
   `scripts/export_ai_review_draft_human_worksheet.py`. It displays suggestions
   and blank reviewer fields without creating or submitting human decisions.
9. Deterministic `scripts/export_ai_review_draft_prompt_bundle.py` export for
   local inspection of the future model request boundary. It embeds only the
   schema-valid normalized prompt input and versioned prompt, locks execution
   and network off, and creates no response or downstream review artifact.
10. Deterministic `scripts/import_ai_review_draft_model_output.py` acceptance of
    already-produced model JSON. It validates schema, provenance, locked flags,
    known signal refs, and forbidden fields without executing a model or
    repairing unsafe output.
11. Manual local/private-LAN LM Studio execution through
    `scripts/run_ai_review_draft_lmstudio_model.py`, gated by explicit execution
    and endpoint opt-ins. Candidate output remains untrusted until imported.

Next:

1. Real model integration remains later and must be explicit and default-off;
   current pipeline integration is limited to the deterministic local exporter
   and mock generator.
2. Define any later UI or workflow around the implemented worksheet without
   auto-submitting decisions.

Candidate generation and promotion are outside this sequence and require their
own later contracts and review gates.

---

## 14. One-line summary

```text
AI may draft review suggestions; only a human may create the classification decision record.
```
