# Rule Improvement Overview（日本語）

## 1. この文書の目的

Rule Improvement は、レビューで見つかった改善点を、後で検討できる
改善候補に変換していくための流れです。

この流れは、あえて小さな artifact に分けています。理由は、生成、human
review、conversion、legacy export、将来の apply / deployment / promotion
を混同しないためです。

一番大事な安全原則は次の通りです。

- observed / reviewed evidence は candidate を作る材料になり得る
- candidate は approval ではない
- export は apply ではない
- recommendation は promotion ではない

この文書は全体像を見るための地図です。schema の正確な field 定義や
script の実装詳細は、最後に挙げる詳細 contract docs を読んでください。

## 2. ざっくり言うと

Rule Improvement は、「レビューで見つけた改善点」をいきなり本番反映する
仕組みではありません。

まず改善候補を作り、人間がレビューし、変換し、既存 harness が読める候補
artifact に出力します。現在の Rule Improvement export MVP は、この
candidate-generation boundary まで完了しています。つまり、reviewed proposal
decisions から concrete candidate bundle を作り、rule、prompt、
promotion-review、parser の export artifact に narrowing し、export
artifact validation summary で検査できます。そこまで進んでも、まだ apply /
deployment / promotion は行いません。

実際に改善を導入するには、将来の別 workflow で明示的な human approval が
必要です。

## 3. 人間の作業として見た流れ

Rule Improvement の流れを人間の作業として見ると、だいたい次の順番です。

1. レビュー結果から「改善できそうな点」を見つける
2. その改善点を、候補案を作るための入力として整理する
3. AI/スクリプトが「改善候補案」を作る
4. 人間がその候補案をレビューする
5. レビューで認めたものだけを、後続処理しやすい中間形式に変換する
6. 必要に応じて、既存の比較 harness が読める legacy 形式に出力する
7. 必要に応じて promotion recommendation を作る
8. 実際の適用・導入・昇格は、別 workflow で人間が判断する

このあとに出てくる file-name diagram は、同じ流れを repository artifact の
名前で表したものです。

## 4. Artifact で見た流れ

すべての矢印が実装済みではありません。現在は、proposal v2、proposal
review decisions、concrete candidate bundle、Phase 1 の rule / prompt
legacy-compatible export、recommendation-only の promotion recommendation
export までが段階的に実装されています。一方で、pipeline wiring、apply /
deployment / promotion workflows はまだ実装されていません。

```text
rule_improvement_review_input.json
  -> AI review draft / human review
  -> rule_improvement_candidate_creation_input.json
  -> rule_improvement_candidate_proposals_v2.json
  -> rule_improvement_proposal_review_decisions.json
  -> rule_improvement_concrete_candidate_bundle_v1.json
  -> rule_candidates.yaml / prompt_candidates.yaml
  -> promotion_recommendation.yaml
  -> rule_improvement_export_artifact_validation_summary.json
  -> future apply / deployment / promotion workflows
```

各段階の意味は次の通りです。

| Stage | 日本語での意味 |
|---|---|
| `rule_improvement_review_input.json` | Review の対象になる材料です。ここではまだ改善候補は確定していません。 |
| AI review draft / human review | AI が draft を作り、人間が見て判断する段階です。AI の出力はそのまま採用しません。 |
| `rule_improvement_candidate_creation_input.json` | 人間レビューで「改善候補を作ってよい」と判断した材料を整理した入力です。 |
| `rule_improvement_candidate_proposals_v2.json` | 具体的な改善候補案です。`proposal_only` であり、approval ではありません。 |
| `rule_improvement_proposal_review_decisions.json` | Proposal を人間がレビューした結果です。`accept_for_conversion` は「変換してよい」だけであり、適用承認ではありません。 |
| `rule_improvement_concrete_candidate_bundle_v1.json` | 変換済み候補を provenance 付きでまとめた中間 bundle です。まだ apply も promotion もしません。 |
| `rule_candidates.yaml` / `prompt_candidates.yaml` | 既存 comparison harness が読める legacy-compatible candidate artifacts です。rule/prompt の適用前の候補 artifact であり、導入承認ではありません。 |
| `promotion_recommendation.yaml` | Recommendation-only artifact です。promotion approval ではありません。 |
| `rule_improvement_export_artifact_validation_summary.json` | 既に生成済みの export artifacts を読む validation / reporting artifact です。exporter 実行、candidate 作成、promotion 承認ではありません。 |
| future apply / deployment / promotion workflows | 未実装です。実際に反映するなら、別 workflow と明示的な human approval が必要です。 |

`rule_candidates.yaml` と `prompt_candidates.yaml` は、現在の流れで得られる
最終承認済み改善ではありません。あくまで適用前の候補 artifact です。改善
の最終導入は、将来の separate apply / deployment / promotion workflow でのみ
扱うべきです。

## 5. レイヤーごとの説明

### A. Review / candidate creation input

人間がレビューした材料は、まず
`rule_improvement_candidate_creation_input.json` にまとめられます。

これは candidate creation のための入力です。まだ `rule_candidates.yaml` や
`prompt_candidates.yaml` ではありません。apply、deploy、baseline update、
promotion の承認でもありません。

### B. Proposal v2

`rule_improvement_candidate_creation_input.json` から、standalone generator が
`rule_improvement_candidate_proposals_v2.json` を作れます。

この artifact は `proposal_only` です。rule / prompt / parser / telemetry /
correlation / promotion_review の提案を表せますが、apply approval、
deployment approval、baseline update approval、promotion approval ではありま
せん。

各 proposal は、元になった human candidate-review decision provenance を
保持します。特に `human_decision_provenance` は、後続の review / conversion
でも追跡できるように残すためのものです。

### C. Proposal review decisions

`rule_improvement_candidate_proposals_v2.json` は、人間による proposal review
を受けます。その結果が canonical
`rule_improvement_proposal_review_decisions.json` です。

主な decision value は次の通りです。

| Decision | 意味 |
|---|---|
| `accept_for_conversion` | 後続の converter が candidate bundle へ変換してよい、という意味だけです。 |
| `reject` | 変換しません。 |
| `defer` | 判断を保留します。 |
| `split_required` | 分割が必要です。 |
| `needs_more_evidence` | 追加 evidence や context が必要です。 |

`accept_for_conversion` は「candidate bundle へ変換してよい」という意味に限
定されます。apply approval でも promotion approval でもありません。

### D. Concrete candidate bundle

`scripts/convert_rule_improvement_proposals_to_concrete_candidate_bundle.py` は、
canonical `rule_improvement_proposal_review_decisions.json` と source
`rule_improvement_candidate_proposals_v2.json` から
`rule_improvement_concrete_candidate_bundle_v1.json` を作ります。

この bundle には主に次の領域があります。

- `converted_candidates`
- `skipped_decisions`

`converted_candidates` は、`accept_for_conversion` された item の
provenance-preserving intermediate representation です。`skipped_decisions`
は、`reject`、`defer`、`split_required`、`needs_more_evidence` などを監査用に
残す領域です。

この bundle は non-applying、non-promoting です。legacy artifact そのもの
でもありません。

### E. Legacy-compatible rule / prompt export

Phase 1 の standalone exporter は
`scripts/export_rule_improvement_legacy_rule_prompt_candidates.py` です。

この exporter が扱うのは次の 2 種類だけです。

| `candidate_type` | Output |
|---|---|
| `rule` | `rule_candidates.yaml` |
| `prompt` | `prompt_candidates.yaml` |

`rule_candidates.yaml` と `prompt_candidates.yaml` は、既存 comparison harness
が読める適用前の候補 artifact です。approval ではなく、apply / deploy /
promotion でもありません。

`promotion_review`、`parser`、`telemetry`、`correlation` は Phase 1 export の
対象外です。unsupported item や skipped item は、必要に応じて diagnostics
に記録されますが、diagnostics は candidate artifact ではありません。

Parser legacy export contract は
`docs/design/rule-improvement/rule_improvement_parser_legacy_export_contract.md`
にあります。この contract は `parser_candidates.yaml` と
`rule_improvement_parser_legacy_export_diagnostics.json` の boundary を定義する
contract です。`parser_candidates.yaml` は parser update approval でも
apply / deployment / promotion approval でもなく、active parser configuration
でも production parser state でもありません。
`schemas/parser_candidates_schema.json` と
`tests/test_parser_candidates_schema.py` は実装済みで、
`parser_candidates.yaml` の candidate-only contract を固定します。ただし現時点
では standalone deterministic parser legacy exporter
`scripts/export_rule_improvement_parser_candidates.py` が実装済みで、accepted
`candidate_type: parser` concrete candidates だけを schema-valid
`parser_candidates.yaml` に narrowing export します。Deterministic tmp-path
parser export chain smoke は
`tests/test_rule_improvement_parser_export_chain_smoke.py` に実装済みで、
proposal / review decisions から concrete bundle を経由して schema-valid
`parser_candidates.yaml` までの local artifact chain を検証します。victim logs、
Wazuh、rsyslog、Hydra output、Proxmox、Kali、Ubuntu victim、既存
`data/runs/**` artifacts は不要です。parser process-pipeline wiring、parser
apply / deployment workflow、自動 parser update は未実装です。

Export artifact validation summary は `parser_candidates.yaml` を optional
artifact として扱います。存在する場合だけ schema validation、safety check、
concrete bundle との candidate ID consistency check を行い、存在しないことだけでは
fail しません。summary reporter は parser exporter を呼び出さず、
`parser_candidates.yaml` を作成しません。parser diagnostics は diagnostics
only であり、candidate artifact ではありません。

### F. Promotion recommendation export

Promotion recommendation export は standalone deterministic exporter として
実装されています。

Exporter は、`candidate_type: promotion_review` かつ
`target_artifact_type: promotion_review_bundle_item` かつ
`allowed_next_artifact_type: promotion_review_recommendation` の bundle candidate
だけを対象に、recommendation-only の `promotion_recommendation.yaml` を作ります。
`promotion_review` proposal が recommendation export に必要な schema-safe
payload fields を持つ場合、converter はそれらを concrete candidate bundle
payload に保持します。ただし optional payload が `target`、
`source_signal_ref`、`source_label`、`source_fact_ids`、
`required_evidence_refs`、`priority`、`review_status` などの base metadata を
上書きしようとした場合は fail closed します。

`tests/test_rule_improvement_promotion_recommendation_export_chain_smoke.py`
は synthetic fixtures を `tmp_path` に作成し、proposal v2 と proposal review
decisions から concrete candidate bundle を経由して
`promotion_recommendation.yaml` まで到達できることを検証します。この smoke は
local-development / WSL-friendly であり、victim logs、Wazuh、rsyslog、Hydra
output、Proxmox、Kali、Ubuntu victim、既存の `data/runs/**` artifacts を
必要としません。

Validation summary contract は
`docs/design/rule-improvement/rule_improvement_export_artifact_validation_summary_contract.md`
にあります。実装済みの
`scripts/summarize_rule_improvement_export_artifacts.py` は、既に生成済みの concrete bundle、`rule_candidates.yaml`、
`prompt_candidates.yaml`、`promotion_recommendation.yaml`、diagnostics を
検査して summary を出す non-mutating reporter です。
`schemas/rule_improvement_export_artifact_validation_summary.schema.json` は
`rule_improvement_export_artifact_validation_summary.json` の contract を固定する
schema で、focused schema tests は
`tests/test_rule_improvement_export_artifact_validation_summary_schema.py` にあります。
この schema は safety semantics を変えません。この summary は human review の代替ではなく、apply / deploy / baseline update / prompt update /
parser update / telemetry update / correlation update / promotion approval でも
ありません。

Process-pipeline wiring contract は
`docs/design/rule-improvement/rule_improvement_export_validation_summary_pipeline_wiring_contract.md`
にあります。`scripts/run_process_pipeline.py` は
`--enable-ri-export-validation-summary` が明示された場合だけ
`rule_improvement_export_artifact_validation_summary.json` を生成できます。default
では生成せず、summary step は既存 RI export artifacts の後に実行されます。
summary reporter は write 前に schema validation し、schema validation failure
は fail-closed のままです。この step は exporter を呼ばず、`rule_candidates.yaml`、
`prompt_candidates.yaml`、`promotion_recommendation.yaml` を作成しません。

`tests/test_rule_improvement_export_validation_summary_chain_smoke.py` は
synthetic な schema-valid fixtures を `tmp_path` に作成し、proposal v2 と
proposal review decisions から concrete bundle、schema-valid
`rule_candidates.yaml` / `prompt_candidates.yaml`、recommendation-only の
`promotion_recommendation.yaml`、そして
`rule_improvement_export_artifact_validation_summary.json` までの実装済み chain を
検証します。この smoke は、summary が既に生成済み artifact を読むだけで
`overall_status: pass` / no errors になり、主要 artifact が present、schema
validation / safety / consistency checks が pass、diagnostics は diagnostics
only、skipped / non-accept candidate IDs が rule / prompt / promotion outputs に
漏れないこと、primary export artifacts を書き換えないことを確認します。
local-development / WSL-friendly であり、victim logs、Wazuh、rsyslog、Hydra
output、Proxmox、Kali、Ubuntu victim、既存の `data/runs/**` artifacts は不要
です。attack/victim-log end-to-end smoke ではありません。

ただし、`promotion_recommendation.yaml` は recommendation-only です。promotion
approval ではなく、自動 promotion でもありません。後続の human review と
separate promotion workflow が必要です。

### G. Future apply / deployment / promotion

Apply、deployment、baseline update、prompt update、parser update、telemetry
update、correlation update、promotion workflow はまだ実装されていません。

これらは Rule Improvement の candidate / export / recommendation とは別の
明示的な human approval と workflow を必要とするべきです。

## 6. 実装済み / 未実装

| 状態 | 内容 |
|---|---|
| 実装済み | proposal v2 schema / generator |
| 実装済み | proposal review decisions schema / template exporter / importer |
| 実装済み | concrete candidate bundle schema |
| 実装済み | concrete candidate bundle converter |
| 実装済み | legacy-compatible export contract |
| 実装済み | parser legacy export future contract |
| 実装済み | parser candidate schema |
| 実装済み | parser candidate schema tests |
| 実装済み | parser legacy exporter |
| 実装済み | parser legacy exporter tests |
| 実装済み | parser export chain smoke |
| 実装済み | Phase 1 rule/prompt exporter |
| 実装済み | promotion recommendation export contract |
| 実装済み | promotion recommendation exporter |
| 実装済み | recommendation-only `promotion_recommendation.yaml` export |
| 実装済み | promotion recommendation export-chain smoke |
| 実装済み | optional schema-safe proposal `payload` preservation |
| 実装済み | export artifact validation summary contract |
| 実装済み | export artifact validation summary schema |
| 実装済み | export artifact validation summary script |
| 実装済み | optional parser artifact validation summary support |
| 実装済み | export artifact validation summary schema tests |
| 実装済み | export validation summary chain smoke |
| 実装済み | export validation summary pipeline wiring contract |
| 実装済み | default-off `--enable-ri-export-validation-summary` process-pipeline wiring |
| 完了 | Rule Improvement export MVP for the current candidate-generation boundary |
| 未実装 | telemetry legacy export |
| 未実装 | correlation legacy export |
| 未実装 | attack-to-detection-to-RI E2E smoke |
| 未実装 | apply workflow |
| 未実装 | deployment workflow |
| 未実装 | baseline update workflow |
| 未実装 | prompt update workflow |
| 未実装 | parser update workflow |
| 未実装 | telemetry update workflow |
| 未実装 | correlation update workflow |
| 未実装 | promotion workflow |
| 未実装 | automatic promotion |

## 7. Artifact glossary

| Artifact / term | 説明 |
|---|---|
| `rule_improvement_candidate_proposals_v2.json` | Candidate creation input から作られる proposal-only artifact。 |
| `rule_improvement_proposal_review_decisions.json` | Proposal に対する human conversion-review decision の canonical artifact。 |
| `rule_improvement_concrete_candidate_bundle_v1.json` | Conversion 後の provenance-preserving intermediate bundle。non-applying / non-promoting。 |
| `rule_candidates.yaml` | Legacy-compatible rule candidate artifact。適用前の候補であり、approval ではない。 |
| `prompt_candidates.yaml` | Legacy-compatible prompt candidate artifact。適用前の候補であり、approval ではない。 |
| `parser_candidates.yaml` | Parser candidate artifact。schema と standalone exporter は実装済み。validation summary は存在する場合だけ optional に検査する。parser update approval ではない。 |
| `promotion_recommendation.yaml` | Future recommendation artifact。promotion approval ではない。 |
| diagnostics artifacts | skipped / unsupported item などを説明する metadata。candidate ではない。 |
| `skipped_decisions` | 変換されなかった review decisions の監査用記録。export target ではない。 |
| `converted_candidates` | `accept_for_conversion` された proposal から作られる bundle items。apply authority ではない。 |

## 8. よく出てくる用語集

| Term | 日本語での意味 |
|---|---|
| candidate | 改善候補。まだ採用・適用が決まったものではない。 |
| proposal | 候補案。candidate よりもさらに「提案」寄りの段階。 |
| artifact | 処理の入出力として残すファイルやデータ。 |
| provenance | その候補が何に基づいて作られたかという由来・根拠・追跡情報。 |
| canonical | 後続処理で正本として扱う正式な形式。 |
| conversion | ある形式の artifact を、次の段階で扱いやすい形式へ変換すること。 |
| bundle | 複数の候補や skipped decision を provenance 付きでまとめた中間 artifact。 |
| legacy-compatible | 既存の比較 harness や既存 schema が読める形式に合わせること。 |
| export | 候補 artifact を別形式で出力すること。適用ではない。 |
| apply | 実際にルールや設定へ反映すること。現在の RI flow では未実装。 |
| deploy / deployment | 実運用環境へ展開すること。現在は未実装。 |
| promotion | candidate / agent / result を champion 扱いに昇格すること。現在は未実装。 |
| recommendation | 判断材料としての推奨。承認や自動実行ではない。 |
| diagnostics | skipped / unsupported item などの説明用 metadata。candidate ではない。 |
| skipped | 今回の変換・export 対象から外したもの。 |
| accepted / rejected / deferred | 受理 / 却下 / 保留。RI docs では review decision の状態を表す。 |
| schema | artifact の形を定義するルール。 |
| validate / validation | artifact が schema に合っているか検査すること。 |
| fail closed | 不明・不正・危険な状態では安全側に倒して失敗させること。 |
| backreference | 後から元 artifact や元 decision に戻れる参照情報。 |
| source ref | 元になった artifact への参照。 |
| SHA-256 | 入力ファイルが同じか確認するためのハッシュ値。 |

## 9. Safety rules: 混同しないこと

```text
- proposal != approval
- accept_for_conversion != apply approval
- bundle != legacy artifact
- export != apply
- recommendation != promotion
- diagnostics != candidate
- skipped_decisions != export target
```

- `proposal != approval`: proposal を approval と誤解すると、まだ人間が認めて
  いない案を採用済みとして扱ってしまいます。これは review gate を飛ばす危
  険があります。
- `accept_for_conversion != apply approval`: `accept_for_conversion` は中間
  bundle へ変換してよいという意味だけです。apply approval と混同すると、
  変換レビューだけで実環境変更を始めてしまう危険があります。
- `bundle != legacy artifact`: bundle は provenance を残す中間 artifact で
  あり、既存 harness 用の `rule_candidates.yaml` などとは別です。混同する
  と、まだ narrowing していない情報を legacy flow に渡したと誤解します。
- `export != apply`: legacy-compatible export は artifact を書くだけで、rule
  や prompt を有効化しません。ここを混同すると、ファイル出力を実際の変更
  として扱ってしまいます。
- `recommendation != promotion`: recommendation は判断材料です。promotion
  自体ではありません。混同すると、別途必要な human review と promotion
  workflow を省略する危険があります。
- `diagnostics != candidate`: diagnostics は metadata であり、candidate artifact
  ではありません。混同すると、skipped / unsupported item を候補として処理
  してしまいます。
- `skipped_decisions != export target`: skipped item は監査用です。export 対象
  と混同すると、review で認められていないものを候補化する危険があります。

## 10. 次に読む文書

- Proposal schema の詳細:
  `docs/design/rule-improvement/rule_improvement_candidate_proposal_v2_contract.md`
- Proposal review decisions:
  `docs/design/rule-improvement/rule_improvement_candidate_proposal_review_conversion_contract.md`
- Concrete bundle:
  `docs/design/rule-improvement/rule_improvement_concrete_candidate_artifact_strategy.md`
- Legacy rule/prompt export:
  `docs/design/rule-improvement/rule_improvement_legacy_compatible_export_contract.md`
- Future promotion recommendation:
  `docs/design/rule-improvement/rule_improvement_promotion_recommendation_export_contract.md`
- Operational command examples:
  `docs/runbooks/ai_assisted_rule_improvement_review_handoff.md`
