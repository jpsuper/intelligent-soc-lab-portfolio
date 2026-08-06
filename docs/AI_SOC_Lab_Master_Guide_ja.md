# AI SOC Lab マスターガイド

[English](AI_SOC_Lab_Master_Guide.md)

> [!NOTE]
> この文書は英語版`AI_SOC_Lab_Master_Guide.md`の参考翻訳です。
> 英語版を正本とし、内容に差異がある場合は英語版を優先してください。
>
> Canonical source: `docs/AI_SOC_Lab_Master_Guide.md`
> Synchronization status: synchronized
> Last synchronization date: 2026-08-05

2台の物理ホスト上に構築したAI SOC研究ラボを、Phaseごとに進めるための統合ガイドです。

> 現在状況の正本:
> [Main Roadmap](roadmap/roadmap.md)
>
> このガイドは、安定したarchitecture、artifact境界、evidenceルール、
> 運用ポリシーを扱います。現在の優先事項、未完了作業のキュー、
> 頻繁に変化するDone Criteriaは扱いません。

---

# 1. ラボの目標

このラボの目的は、次の能力を1つの環境で継続的に学習し、改善できるようにすることです。

- Adversary Simulation（攻撃シミュレーション）
- Detection Engineering（検知エンジニアリング）
- Correlation（相関分析）
- AI Triage
- Investigation Analysis
- Case Management
- Action Planning / Approval
- Investigation / DFIR / External Integrations
- Deception
- Automated Improvement Loop

目標とする研究ループは次のとおりです。

```text
攻撃 / ノイズ / Deception
        ↓
Telemetry収集
        ↓
Detection
        ↓
Correlation
        ↓
Incident Builder
        ↓
Triage
        ↓
Investigation
        ↓
Case
        ↓
Action
        ↓
実行 / 承認
        ↓
DFIR / 外部連携
        ↓
Rule Improvement
        ↓
再攻撃
```

Defender側のtelemetry → parser → normalization → detection → correlation →
triage → investigationフローにおける詳細な責務とtrust boundaryについては、
[Defender Event Processing Flow（日本語参考訳）](architecture/defender-event-processing-flow_ja.md)
を参照してください。

設計原則:

- Detectionは決定論的に行います。
- AIはanalyst、triage、investigation、planningを支援します。
- Deceptionは信頼度の高い検知シグナルを生成します。
- 通常活動とノイズにより、SOC環境をより現実的にします。
- リスクのある操作はapproval gateの内側に留めます。
- 比較可能性を保ちながら、自動化を段階的に進めます。

---

## 1.1 Scenarioに応じたArtifactの選択
このラボでは、検知イベントを単に列挙するのではなく、
各scenarioでどのartifactをprimaryとするかを決定します。

例:
- scenario_003: `process_exec`をprimaryとします（execution）。
- scenario_004: `authorized_keys_modification`をprimaryとします（persistence installation）。
- scenario_005: `ssh_key_login`をprimaryとします（persistence reuse）。
- scenario_006: `process_exec`をprimaryとします（key reuse後のpost-login action）。

この方法により、次のことが可能になります。
- execution、persistence、privilege escalationなど異なる攻撃domainを正確に表現する。
- Case、Investigation、response artifact間の一貫性を高める。

この設計はPhase6における重要なarchitecture上の進展です。

---

## 1.2 Atomic Detection DSLとCorrelation-First Entry

このラボでは、backendに依存しないatomic detection outputを共通contractとして定義し、detection、investigation、Case作成のscenario固有hardcodingを避けます。

基本フロー:

```text
atomic detection DSL
  ↓
canonical detection output
  ↓
dedupe
  ↓
correlation
  ↓
incident / triage / investigation / case
```

### 正本

- DSL = source of truth
- canonical detection output = ラボ内の共通contract
- Wazuh = deploy / search target

### Featureレイヤー

- `behavior_features` = Detectionが付与する観測事実
- `derived_features` = Triageが生成する解釈
- `enriched_features` = Investigationが生成するcontextual enrichment
- `assessment` = 最終的な分析判断

Detectionは原則として`behavior_features`だけを付与し、結論を伴う解釈はdownstream stageへ委ねます。

### Correlation-firstのIncident生成経路

process-firstのIncident構築経路だけでは、persistence中心のscenarioを十分に表現できません。
そのため、atomic detectionをdedupe・correlationした後、その結果からIncidentを構築できるarchitectureにします。

例:
- `ssh_failed_login`
- `ssh_success_login`
- `authorized_keys_modification`

これら3つのdetectionをcorrelationし、`authorized_keys_modification`をprimary artifactとするIncidentを構築します。

### この設計が重要な理由

executionだけでなく、persistenceやpersistence reuseなど異なる攻撃domainを共通基盤上で扱いやすくなります。


## 1.3 Attacker側のArtifact Contract

Attacker Agentは、攻撃実行結果を次のartifactに分離します。

```text
attack_result.json
  attack runの概要

attack_execution_log.json
  shell backend / runnerのexecution log

attack_observed_effects.json
  attacker側で観測したeffect
```

重要な境界:

```text
attacker側observed effect != defender側observed artifact
```

例:

- `ssh_login_succeeded`は、`ssh_key_login`に対応するattacker側の観測です。
- `payload_execution_succeeded`は、`process_exec`に対応するattacker側の観測です。
- attacker側でeffectを観測しても、defender側が検知したことの証明にはなりません。

attacker-agentは現在、shell実行evidenceから次のartifactを導出できます。

```text
scenario_004:
  ssh_bruteforce_attempted        -> ssh_failed_login
  ssh_login_succeeded             -> ssh_success_login
  authorized_keys_write_succeeded -> authorized_keys_modification

scenario_005:
  ssh_login_succeeded             -> ssh_key_login

scenario_006:
  ssh_login_succeeded             -> ssh_key_login
  payload_execution_succeeded     -> process_exec
```

これらのartifactは、`observed_effects_alignment`を通してdefender側のobserved artifactと比較できます。


## 1.4 Structured Runner OutputとObserved Effects Alignment

shell runnerのstdout markerへの過度な依存を避けるため、attacker-agentはstructured runner output規約を使用します。

基本形式:

```text
ATTACK_EVENT_JSON: {"event_type":"ssh_login_succeeded","artifact":"ssh_key_login","status":"observed","confidence":"medium"}
```

重要な境界:

```text
ATTACK_EVENT_JSON = attacker側のstructured evidence
ATTACK_EVENT_JSON != defender側telemetry
ATTACK_EVENT_JSON != defender側detection
```

利用可能な機能:

- `ATTACK_EVENT_JSON:` parser helperとfocused testが存在します。
- scenario_004 / 005 / 006のrunnerがstructured eventを出力します。
- structured runner eventが利用できる場合、`attack_observed_effects.json`はそれを優先します。
- 有効な`ATTACK_EVENT_JSON:`行がある場合、`attack_execution_log.json`は`structured_events`を追加で含みます。
- `structured_events`はraw `stdout`、`stderr`、execution eventを置き換えません。
- structured eventがない場合も、従来のstdout markerと`exit_code` fallbackを使用できます。
- structured runner eventはscenario_004 / 005 / 006でsmoke validation済みです。
  - scenario_004: `ssh_bruteforce_attempted` → `ssh_failed_login`
  - scenario_004: `ssh_login_succeeded` → `ssh_success_login`
  - scenario_004: `authorized_keys_write_succeeded` → `authorized_keys_modification`
  - scenario_005: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_006: `ssh_login_succeeded` → `ssh_key_login`
  - scenario_006: `payload_execution_succeeded` → `process_exec`
- `observed_effects_alignment`は、attacker側のobserved effectとdefender側のobserved artifactを比較する追加シグナルです。
- 既存の`overall_result`、`detected`、verdictの挙動は変更しません。
- Rule Improvement Agentは、
  `evaluation_result.observed_effects_alignment`から`observed_effects_alignment_signals.json`を生成できます。
- `candidate_review.md`は、人間によるreviewのためにobserved-effects alignment signalを提示します。
- observed-effects signalはreview inputに留まり、`rule_candidates.yaml`へ自動挿入されません。
- Shell backend contractのstatic testは、runner path、executable bit、timeout、`state_changing`、inline shell fieldの境界を検証します。
- `docs/operations/smoke_runbook.md`は、structured runnerとobserved-effectsのsmoke checkを記録します。


## 1.5 Comparison Harnessと改善サイクル

Phase6 extended MVPでは、single-run pipelineに加えて**比較可能な改善ループ**を追加します。

comparison spineはTriageだけでなく、Investigationとaction planningまで拡張されています。

```text
triage_resultのcomparison
  ↓
investigation_resultのcomparison
  ↓
action_resultのcomparison
```

基本フロー:

```text
current / champion
        +
variant / challenger
        +
rule baseline
        ↓
compare.json
        ↓
judge_result.json
        ↓
Rule Improvement Agent
        ↓
rule_candidates.yaml
prompt_candidates.yaml
promotion_recommendation.yaml
parser_candidates.yaml
rule_improvement_export_artifact_validation_summary.json
observed_effects_alignment_signals.json
candidate_review.md
        ↓
バッチ検証
        ↓
人間によるレビュー
```

currentとvariantのoutputは、それぞれchampionとchallengerとして扱います。

```text
triage_ai_current = 現在のadopted version / baseline / champion
triage_ai_variant = improvement candidate / challenger
triage_ai_variant_next = 次のimprovement candidate
```

単一のwinnerだけでpromotionを決定しません。
`scenario_004 / 005 / 006`など複数scenarioをbatch compareし、primary artifact coverage、overclaim control、evidence grounding、response fitnessを一連のhuman reviewで評価できるようにします。

利用可能な基盤:

- triage comparison harness
- investigation comparison harness
- action comparison harness
- compare / judge schema
- generic rubric
- response keywordのmust-have / nice-to-have評価
- evidence-awareなcompare / judge refinement
- action compare / judge refinement
- 最小Rule Improvement Agent
- promotion recommendation
- batch compare runner
- `action_result`から`collection_request`への接続
- `collection_request.json`のdownstreamにある`collection_result.json` contract
- observed-effects alignment signalの生成とcandidate reviewでの提示

## 1.6 長期的に維持するCapabilityとEvidenceの境界

現在の実装状況、validation depth、未完了作業、active priorityは
[Main Roadmap](roadmap/roadmap.md)で管理します。この節では、
後続実装で維持すべき安定したpipeline shapeと境界を
定義します。

```text
attack / scenario
  ↓
logs / telemetry
  ↓
normalization
  ↓
canonical detection
  ↓
dedupe / correlation / Incident selection
  ↓
triage
  ↓
Case前investigation
  ↓
initial case
  ↓
action planning
  ↓
collection request / approval / execution
  ↓
collection_result.json
  ↓
Action後DFIR / external integration
  ↓
evaluation / comparison / review済みimprovement
```

安定した境界:

- source parsingとnormalizationは、platformまたはprovider固有のままで構いません。
  downstream stageはraw source formatではなくcanonical artifactを使用します。
- atomic detectionはreview可能な観測として維持します。Dedupe、correlation、
  exact Incident selectionは、downstreamのcase processingより前にある
  独立した境界です。
- fixture parity、schema validation、manual observation、live collection、
  end-to-end executionは異なるevidence levelであり、混同してはいけません。
- attacker側のobserved effectはexecution evidenceであり、defender telemetryでも
  detection発生の証明でもありません。
- Case前の`investigation_result.json`はAction後DFIRと分離します。
  collection resultをCase前artifactへ戻してはいけません。
- collection outcomeによるCase enrichmentはappend-onlyとし、assessment、verdict、
  confidence、severity、approval stateを暗黙に書き換えてはいけません。
- Rule Improvementのproposal、candidate、export、promotion recommendationは
  review artifactに留まります。apply、deployment、mutation、
  promotionを承認するものではありません。
- Deception hitには、決定論的なdefender側trap observationが必要です。
  attacker側runnerのclaimだけではdeception hitを確定できません。
- state-changing response、containment、collection、apply、deployment、
  promotion actionはapproval gateの内側に留めます。

詳細な責務:

- current status、priority、incomplete work、Done Criteria:
  [Main Roadmap](roadmap/roadmap.md)
- Phase6のhistoryとvalidation evidence:
  [Phase6 Roadmap](roadmap/phase6.md)
- Phase7のhistoryとdeferred scenario boundary:
  [Phase7 Roadmap](roadmap/phase7.md)
- cross-platform defender flow:
  [Defender Event Processing Flow（日本語参考訳）](architecture/defender-event-processing-flow_ja.md)
- Action後のevidence boundary:
  [Post-action DFIR Investigation](design/dfir/post_action_dfir_investigation.md)
- review済みRule Improvement artifact flow:
  [Rule Improvement Candidate Creation Workflow](design/rule-improvement/rule_improvement_candidate_creation_workflow.md)

# 2. ハードウェア構成

## Node1: Attack / Victim Lab

既存ホスト:
- TRIGKEY Speed S5 Pro
- Ryzen 7 5800H
- 32GB RAM
- 1TB NVMe

役割:
- attacker
- victim host
- AD / Windows / Linux
- honeypot / deception target
- background activity生成

## Node2: SOC Core Host

2台目のホスト:
- GMKtec NucBox K8 Plus
- Ryzen 7 8845HS
- 64GB RAM
- 1TB NVMe

役割:
- log pipeline
- detection engine
- correlation engine
- Wazuh
- TheHive
- Velociraptor
- triage / investigation
- action / orchestration
- rule improvement
- AI deception

## Node3: 将来のAI Engine（任意）

将来、AI workload専用として追加できる任意のnodeです。

役割:
- Ollama
- Qwen
- embedding
- local AI SOC analyst
- 将来のenrichment / RAG / memory workload

---

# 3. 推奨VM構成

## Node1（Attack / Victim）

| VM | 役割 | 推奨spec |
|---|---|---|
| kali-attacker | attacker / tooling | 4 vCPU / 8GB / 80-100GB |
| ubuntu-victim01 | SSH target / auth.log | 2 vCPU / 4GB / 50GB |
| ubuntu-victim02 | persistence / lateral movement | 2 vCPU / 4GB / 50GB |
| windows-victim01 | Windows telemetry | 4 vCPU / 8GB / 100GB |
| dc01 | AD / identity lab | 4 vCPU / 8GB / 100GB |
| honeypot01 | fake service / share | 2 vCPU / 2-4GB / 40GB |

## Node2: SOC Core VM Layout

| VM | 役割 | 推奨spec |
|---|---|---|
| soc-analyzer | detection / correlation / incident builder | 6 vCPU / 16GB / 200GB |
| wazuh | SIEM / EDR platform | 4 vCPU / 8GB / 200GB |
| log-pipeline | Vector / Fluent Bit | 2 vCPU / 4GB / 80GB |
| thehive | case management | 2 vCPU / 6GB / 100GB |
| velociraptor | investigation / DFIR | 2 vCPU / 4GB / 80GB |
| ai-soc | AI triage / investigation / planning client | 4 vCPU / 8GB / 100GB |

---

# 4. 最終アーキテクチャ

```text
Attack Simulation + Background Activity + Deception
                        │
                        ▼
                 Victimネットワーク
          (Linux / Windows / AD / Honeypot)
                        │
                        ▼
                 Telemetry収集
      (auth.log / Sysmon / auditd / Wazuh agent)
                        │
                        ▼
                   Log Pipeline
              (Vector / Fluent Bit)
                        │
                        ▼
                 Detection Engine
     (Python / Sigma-like rule / 将来のWazuh)
                        │
                        ▼
                Correlation Engine
                        │
                        ▼
                 Incident Builder
                        │
                        ▼
                   Triage Agent
                        │
                        ▼
              Investigationによる分析
                        │
                        ▼
                     Case Agent
                        │
                        ▼
                   Action Agent
                        │
                        ▼
             Executor Agent / Approval Gate
                        │
                        ▼
      DFIR / 外部連携 / Case System
         (Velociraptor / TheHive / 将来のadapter)
                        │
                        ▼
                 Rule Improvement
                        │
                        ▼
                      再攻撃
```

> 注:
> Offensive側はScenarioとAttacker componentから開始します。
> 将来は、objective-driven planner、specialist delegation、tool selection、memory / graph機能を持つoffensive architectureへ発展できます。

---

# 5. Agentアーキテクチャ

ラボへ段階的に導入するAgentです。

| Agent | 役割 | 主なPhase |
|---|---|---|
| Telemetry Agent | raw logとforwarded logを取得 | Phase0 |
| Log Parser Agent | auth.log、sshd、sudo、auditdなどのsourceをcanonical eventへnormalize | Phase0 / Phase5 |
| Detection Agent | 決定論的検知を実行し、`behavior_features`を付与 | Phase1 / Phase6 |
| Correlation Agent | atomic detectionをdeduplicate・correlateし、Incident entry boundaryを形成 | Phase1 / Phase6 |
| Incident Builder Agent | correlated detectionから`incident.json`を生成 | Phase1 |
| Triage Agent | SOC分析と初期判断を行い、`risk_score`、`derived_features`、`assessment`を生成 | Phase2 / Phase6 |
| Rule Triage Baseline | AI Triageと比較する決定論的baselineを提供 | Phase6 |
| Investigation Agent（Case前） | Incident、Triage、defender側telemetryを用いたevidence-aware investigationを実行し、`investigation_result.json`、enriched feature、evidence gap、pivotを生成 | Phase4 / Phase6 |
| Case Agent | run resultをaction planningのinput boundaryとなる`case.json`へnormalizeし、collection resultがある場合は専用DFIR fieldだけをappend | Phase4 / Phase6 |
| Action後DFIR / Integration Workflow | Action / collection後のoutcomeとcollected outputを処理し、DFIR evidence review、review済みfindingに基づくCase enrichment、任意のexternal Case updateを実行。Case前Investigation Agentとは分離 | Follow-on |
| TheHive Agent | initial `case.json`からexternal Caseとobservable recordを作成し、後からreview済みAction後DFIR findingをappend | Phase4 / Phase5 / Follow-on |
| Velociraptor Agent | DFIR collection requestを生成し、collection outcomeを統合し、将来のactual collection executionを支援 | Phase4 / Phase5 / Follow-on |
| Action Agent | Caseとevidenceに基づくresponse policyとplaybookを生成 | Phase2 extension / Phase5 / Phase6 |
| Executor Agent | playbookを実行し、approval gateを適用し、`decision_log`を記録 | Phase5 / future extension |
| Scenario Agent | attack scenarioを定義 | Phase3 |
| Attacker Agent | attackを実行し、`attack_result`、`attack_execution_log`、`attack_observed_effects`を生成 | Phase3 / Phase6 |
| Attack Planner Agent | objectiveをsubtaskへ分解し、toolまたはspecialistを選択（future extension） | Phase3 extension / future |
| Rule Improvement Agent | compare / judge outputからrule、prompt、promotion candidateとreview artifactを生成 | Phase6 |
| Scenario Orchestrator / Harness Runner | process pipeline、Triage / Investigation / Action harness、batch comparisonをorchestrate | Phase6 |
| Deception Agent | honeytoken、honey share、decoyを生成 | Phase7 |
| Trap Detection Agent | deception hitを検知 | Phase7 |
| Background Activity Agent | normal-activity noiseを生成 | Phase8 |

## 5.1 Agentの依存関係

```text
Telemetry Agent
   ↓
Log Parser Agent
   ↓
Detection Agent
   ↓
Correlation Agent
   ↓
Incident Builder Agent
   ↓
Triage Agent
   ↓
Case前Investigation Agent
   ↓
Case Agent（initial case）
   ↓
Action Agent
   ↓
Executor Agent / Approval Gate
   ├─ 初期TheHive / Case連携
   ├─ Collection / Velociraptor execution（必要な場合はapproval後）
   │    ↓
   │  Action後DFIR / Integration Workflow
   │    ├─ レビュー済みfindingに基づくCase enrichment
   │    ├─ 任意の外部Case更新
   │    └─ 人間がレビュー可能なfollow-up signal
   └─ Rule Improvement Agent

Scenario Agent
   ↓
Attacker Agent
   ↓
Scenario Orchestrator

Deception Agent
   ↓
Trap Detection Agent

Background Activity Agent
   ↓
Telemetry / Detectionの現実性
```

## 5.2 履歴上の最小構成Agent導入順序

当初の最小導入順序は次のとおりです。

1. Telemetry Agent
2. Detection Agent
3. Incident Builder Agent
4. Triage Agent
5. Correlation Agent
6. Scenario Agent / Attacker Agent
7. Case Agent / Investigation Agent
8. Action Agent / Executor Agent
9. Deception Agent
10. Background Activity Agent
11. Rule Improvement Agent / Orchestrator

この一覧はarchitecture上の導入順序だけを記録したものです。現在の
実装状況やactive priorityを示すものではありません。いずれも
[Main Roadmap](roadmap/roadmap.md)を参照してください。

---

# 6. 長期的に維持するPhaseアーキテクチャマップ

この章は、各Phaseの安定したarchitecture上の役割を記録します。
[Main Roadmap](roadmap/roadmap.md)が扱うcurrent status、incomplete work、
priority、Done Criteriaは重複して記載しません。

| Phase | 安定したarchitecture上の役割 | 詳細なhistoryとevidence |
|---|---|---|
| Phase0 | 最小のAttack → Log → Parse → Detect → Incident baselineを確立 | [phase0.md](roadmap/phase0.md) |
| Phase1 | 決定論的correlationとIncident構築を追加 | [phase1.md](roadmap/phase1.md) |
| Phase2 | triage、initial assessment、approval-aware action planningを追加 | [phase2.md](roadmap/phase2.md) |
| Phase3 | 再現可能なattacker scenario、run isolation、evaluation inputを追加 | [phase3.md](roadmap/phase3.md) |
| Phase4 | Case ownership、timeline、external integration boundaryを追加 | [phase4.md](roadmap/phase4.md) |
| Phase5 | canonical eventを維持しながらendpoint telemetryとprocess-focused detectionを追加 | [phase5.md](roadmap/phase5.md) |
| Phase6 | feature ownership、comparison harness、Action後evidence、review済みimprovement artifactを追加 | [phase6.md](roadmap/phase6.md) |
| Phase7 | defender側source of truthとapproval boundaryを維持しながら、決定論的local-lab deception artifactを追加 | [phase7.md](roadmap/phase7.md) |
| Phase8 | false-positiveとtuningのためにbackground activityとtelemetry realismを高める。Phase8はMain Roadmap内の節として管理し、個別の`phase8.md`は作成しない | [Main Roadmap](roadmap/roadmap.md) |

Phaseをまたぐルール:

- 後続Phaseはartifact pipelineを拡張します。
  以前のartifactやevidence boundaryを暗黙に再定義しません。
- Phase文書はPhase固有のhistory、validation evidence、
  scoped decisionを保持します。
- Main Roadmapは現在のImplemented、Validated、
  Planned、Deferred、Unverified statusの正本です。
- Design文書は個別contractと
  technical decisionの正本です。
- Phase labelは整理上のcontextであり、そのcapabilityが
  implementedまたはvalidatedである証拠ではありません。

# 7. リポジトリ構成の境界

現在の物理layoutは、
[Repository Structure Policy](development/repository_structure.md)、
[ADR 0001](adr/0001-repository-organization-policy.md)、
[ADR 0002](adr/0002-domain-oriented-scripts-and-tests-layout.md)で管理します。
このガイドは競合するtarget treeを定義しません。

安定して維持するtop-level root:

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

長期的に維持する配置ルール:

- stage固有agentとintegration adapterは、review済みarchitecture decisionで
  境界を変更するまで`agents/`配下に置きます。
- 実行可能なattack supportは`attacks/`、scenario intentは
  `scenarios/`に置きます。
- 決定論的detection logicは`detection/`に置きます。
- schemaは`schemas/`へ集約します。
- shared utilityは`common/`に置き、実際のreuseが示されない限りstage固有の
  business logicを移動しません。
- orchestration、export、harness、utilityのentry pointは
  `scripts/`に置き、cohesive domainはreview済みsubdirectoryを使用できます。
- fixtureは`tests/fixtures/`に置き、generated run artifactは
  version-controlled source pathの外に置きます。
- 文書は目的別に`docs/architecture/`、
  `docs/design/`、`docs/development/`、`docs/adr/`、
  `docs/operations/`、`docs/runbooks/`、`docs/roadmap/`へ配置します。

このガイド内のaspirational treeを根拠に、新しいtop-level rootを作成したり、
repositoryを再編したりしません。新しいrootまたはcross-domain moveには、
repository-structure review processと、必要に応じてADRが必要です。

---

# 8. 文書の責務とメンテナンス

文書更新では、
[Documentation Language Policy](development/documentation-language-policy.md)に従い、
変更に必要な最小限のauthoritative document setだけを更新します。

- `README.md`はfirst-reader overviewと簡潔なcurrent snapshotを扱います。
- このMaster Guideは、安定したarchitecture、artifact boundary、evidence
  rule、operating policyを扱います。
- `docs/roadmap/roadmap.md`はcurrent status、active priority、
  incomplete work、sequencing、Done Criteriaを扱います。
- `docs/roadmap/phase0.md`から`phase7.md`はPhase固有の
  history、validation evidence、scoped decisionを保持します。Phase8は
  Main Roadmap内の節として維持します。
- `docs/design/`は個別contractとtechnical decisionを扱います。
- `docs/operations/`と`docs/runbooks/`は実行可能なoperational procedureと
  handoff procedureを扱います。
- `docs/development/`と`docs/adr/`はrepository-wide policyと
  architecture decisionを扱います。

古いplanning listに名前があるという理由だけでplaceholder documentを作成しません。
明確なowner、長期的な目的、review済みの配置場所がある場合にのみ
文書を追加します。

---

# 9. 主要Schema / Artifact Contract

このラボではAgent実装の詳細よりも**artifact contract**を優先します。
各stageは、downstream stageがinputとして使用するJSONまたはYAML artifactを出力します。

## 9.1 Normalized Event

```json
{
  "timestamp": "2026-03-16T10:00:00Z",
  "host": "ubuntu-victim01",
  "event_type": "ssh_failed_login",
  "src_ip": "192.0.2.40",
  "user": "root",
  "raw_log": "...",
  "rule": null,
  "severity": null
}
```

process telemetryでは、次のようなnormalized process eventを使用します。

```json
{
  "event_type": "process_exec",
  "timestamp": "2026-03-24T08:08:09Z",
  "host": "ubuntu-victim01",
  "pid": 1234,
  "ppid": 1200,
  "user": "victim01",
  "exe": "/usr/bin/curl",
  "command_line": "curl ...",
  "cwd": "/home/victim01",
  "source": "auditd"
}
```

## 9.2 Detection / Atomic Artifact

Detectionは決定論的であり、原則として観測レベルの`behavior_features`だけを付与します。

primary artifactの例:
- `ssh_failed_login`
- `ssh_success_login`
- `ssh_key_login`
- `authorized_keys_modification`
- `sudo_command`
- `process_exec`
- `suspicious_download_chmod_execute`

## 9.3 Incident JSON

```json
{
  "incident_id": "INC-0001",
  "scenario_name": "ssh_bruteforce_priv_esc",
  "severity": "high",
  "host": "ubuntu-victim01",
  "src_ip": "192.0.2.40",
  "timeline": [],
  "matched_rules": [
    "ssh_failed_login",
    "ssh_success_login",
    "sudo_command"
  ],
  "behavior_features": {
    "credential_access": true,
    "privilege_escalation": true
  }
}
```

## 9.4 Triage Result

```json
{
  "incident_id": "INC-0001",
  "verdict": "malicious",
  "confidence": "high",
  "priority": "P1",
  "risk_score": 85,
  "summary": "Possible brute force followed by privilege escalation.",
  "attack_story": "The source IP attempted multiple SSH logins...",
  "key_observations": [],
  "mitre_attack": [],
  "recommended_actions": []
}
```

## 9.5 Feature Lifecycle

```json
{
  "behavior_features": {},
  "derived_features": {},
  "assessment": {},
  "enriched_features": {}
}
```

責務の境界:
- `behavior_features`: Detectionが付与する観測事実
- `derived_features`: Triageが生成する解釈
- `assessment`: verdict、confidence、priority、`risk_score`などの判断
- `enriched_features`: Investigationが追加するcontextとevidence

## 9.6 Investigation Result

`investigation_result.json`はTriageとは別のartifactです。

主要field:
- `evidence_level`
- `evidence_summary`
- `unsupported_claims`
- `missing_pivots`
- `recommended_pivots`
- `enriched_features`

任意input:
- `process_events.json`
- `process_chain_hits.json`
- `zeek_enrichment.json`

## 9.7 Case JSON

`case.json`はaction planningのinput boundaryであり、external integrationのsource of truthです。

必須field:
- `case_id`
- `attack_id`
- `scenario_id`
- `title`
- `status`
- `severity`
- `summary`
- `attack_result`
- `detection_result`
- `coverage`

推奨field:
- `triage_result`
- `key_artifacts`
- `timeline`
- `recommended_actions`
- `process_summary`
- `process_timeline`
- `investigation_notes`

## 9.8 Action Result / Approval Boundary

`action_result.json`はresponse planとplaybookをmachine-readable形式で表現します。

重要な境界:
- safe stepはauto-executableにできます。
- sensitive stepにはapproval gateが必要です。
- containment actionはdefaultでpending approvalとします。
- actionはCaseとevidenceに基づく必要があります。

action typeの例:
- `request_dfir_collection`
- `collect_payload_or_process_evidence`
- `alert_soc_team`
- `review_payload_execution`
- `consider_host_isolation`

## 9.9 Collection Request

`collection_request.json`は`action_result`から生成するDFIR request artifactです。

現在のtrigger type:
- `request_dfir_collection`
- `collect_payload_or_process_evidence`

設計上の注意:
- `collection_request.context.action_types`にaction-driven contextを保持します。
- Velociraptorをcontinuous collectionではなくAction後DFIRとして扱います。

## 9.10 Collection Result

`collection_result.json`は、`collection_request.json`の実行結果、manual collection result、またはmock collection resultを記録するDFIR outcome artifactです。

```text
action_result.json
  ↓
collection_request.json
  ↓
collection_result.json
  ├─ outcome-only case enrichment: `dfir_collection_summary` / `dfir_evidence_refs`（implemented）
  └─ Action後DFIR run workflow MVP / 将来のexternal integration workflow
       ↓
     将来のexecutor / DFIR result comparison
```

主な責務:

- requested、completed、partial、failed、skipped、cancelledなどのcollection statusを記録します。
- `collected_artifacts`、`failed_artifacts`、`skipped_artifacts`を分離して保持します。
- `collection_request.json`、`action_result.json`、`case.json`へのtraceabilityを保持します。
- Velociraptor、manual、mock、将来のcollector outcomeを共通result modelへnormalizeします。
- collected evidenceへのreferenceを`output_refs`へ保持します。
- run-based mock collectionでは、controlled `Linux.Syslog.SSHLogin` outputを`forensics/mock/Linux.Syslog.SSHLogin.json`へ書き込み、collected artifactの`output_refs`から参照します。

重要な境界:

- collection resultはevidence transport artifactであり、Case前の`investigation_result.json`における結論ではありません。
- Action後DFIR workflowはCase前Investigation Agentと分離し、既存の`investigation_result.json`を上書きしません。
- collection outcomeだけでverdict、severity、confidence、`overall_result`、`detected`を変更しません。
- action approvalやcontainment decisionを変更しません。
- Rule Improvement candidateやpromotionを自動生成しません。

詳細設計:

- `docs/design/dfir/collection_result_contract.md`
- `docs/design/dfir/collection_result_ingestion.md`

## 9.11 Attacker側のArtifact Contract

Attacker Agentは次のartifactを分離して出力します。

```text
attack_result.json
  attack runの概要

attack_execution_log.json
  shell backend / runnerのexecution log

attack_observed_effects.json
  attacker側で観測したeffect
```

重要な境界:

```text
attacker側observed effect != defender側observed artifact
```

この分離により、attacker側では成功したがdefender側では検知されなかった状態を、`observed_effects_alignment`のgapとして表現できます。

## 9.12 Evaluation Result / Observed Effects Alignment

expected coverageとobserved coverageに加えて、`evaluation_result.json`は`observed_effects_alignment`を追加のPhase6 signalとして保持します。

主要ポリシー:
- attacker側のobservationとdefender側のdetectionを分離します。
- `observed_effects_alignment`は既存の`overall_result`、`detected`、verdictの挙動を変更しません。
- `observed_effects_alignment_signals.json`はhuman-review可能なRule Improvement signal artifactです。
- `attacker_observed_defender_missing`はreview signalとして扱い、rule candidateへ自動変換しません。

## 9.13 Harness Artifact

harness runでは次のbase artifactを使用します。

```text
data/harness_runs/<harness_run_id>/
  input/
  optional_inputs/
  agents/
  compare.json
  judge_result.json
  summary.md
  metadata.json
```

TriageとRule Improvement flowでは、さらに次のartifactを生成します。

```text
rule_candidates.yaml
prompt_candidates.yaml
promotion_recommendation.yaml
parser_candidates.yaml
rule_improvement_export_artifact_validation_summary.json
observed_effects_alignment_signals.json
candidate_review.md
```

---

# 10. 長期的に維持するビルド・検証順序

active sequencingと次のimplementation priorityは、
[Main Roadmap](roadmap/roadmap.md)で管理します。このガイドでは、
artifactとevidence boundaryを保つために必要な長期的順序だけを記載します。

## 10.1 ビルド順序

1. sourceの意味を変えずにlogまたはtelemetryを取得する。
2. source固有eventをcanonical event contractへnormalizeする。
3. 決定論的なatomic detectionと事実に基づくbehavior featureを生成する。
4. underlying detectionを隠さずにdedupeとcorrelationを適用する。
5. 正確なIncident inputを選択し、決定論的linkageを保持する。
6. triageとCase前investigationを、分離されたreview可能なstageとして実行する。
7. initial caseとapproval-aware action planを構築する。
8. collection requestを生成し、collection resultのtraceabilityを保つ。
9. Case前Investigation artifactを書き換えずにAction後DFIRを実行する。
10. outputを比較し、review-only improvement artifactを作成する。
11. apply、deploy、update、contain、promoteは明示的なapproval
    boundaryを通してのみ実行する。

## 10.2 検証順序

1つのlevelを別のlevelとして扱わず、強度を段階的に高めたevidenceを使用します。

1. schemaと構造のvalidation
2. 決定論的fixtureとexact parity
3. focused component testとcontract test
4. cross-platformまたはcross-scenario regression
5. manualまたはlive collection validation
6. bounded end-to-end execution validation

fixture-backed successをlive parityと表現してはいけません。attacker側の
runner successをdefender側のobservationと表現してはいけません。

## 10.3 変更責務

- active priorityとDone Criteria:
  [Main Roadmap](roadmap/roadmap.md)
- sourceからcommon defender stageまでの境界:
  [Defender Event Processing Flow（日本語参考訳）](architecture/defender-event-processing-flow_ja.md)
- Phase6 implementation history:
  [Phase6 Roadmap](roadmap/phase6.md)
- Phase7 implementation history:
  [Phase7 Roadmap](roadmap/phase7.md)
- Rule Improvement review・export boundary:
  [Rule Improvement Candidate Creation Workflow](design/rule-improvement/rule_improvement_candidate_creation_workflow.md)

# 11. 初期段階で過剰に構築しないもの

初期段階では、次のような過剰構築を避けます。

- 複雑なmulti-agent coordination
- local LLM migrationを最初に完了すること
- Windows、Linux、AD supportを同時に完了しようとすること
- TheHiveまたはVelociraptor integrationから着手すること
- Deceptionを最初に完了すること
- offensive plannerまたはautonomous attackerを最初に完成させること

当初のsuccess criterion:

```text
1つのattack scenario
→ ログ収集
→ 1つのdetection chain
→ incident.json
→ AI Triageレポート
```

---

# 12. 現在の文書索引

このindexは、現在のowner documentを示すnavigationです。
現在状況の正本であるMain Roadmapを置き換えるものではありません。

## アーキテクチャとリポジトリポリシー

- [Agent Architecture](architecture/agent-architecture.md)
- [Lab Architecture](architecture/lab-architecture.md)
- [SOC Lab System Diagram](architecture/soc-lab-system-diagram.md)
- [Defender Event Processing Flow（日本語参考訳）](architecture/defender-event-processing-flow_ja.md)
- [Repository Structure Policy](development/repository_structure.md)
- [Documentation Language Policy](development/documentation-language-policy.md)

## Phaseとステータスの責務

- [Main Roadmap](roadmap/roadmap.md)
- [Phase0の履歴と検証記録](roadmap/phase0.md)
- [Phase1の履歴と検証記録](roadmap/phase1.md)
- [Phase2の履歴と検証記録](roadmap/phase2.md)
- [Phase3の履歴と検証記録](roadmap/phase3.md)
- [Phase4の履歴と検証記録](roadmap/phase4.md)
- [Phase5の履歴と検証記録](roadmap/phase5.md)
- [Phase6の履歴と検証記録](roadmap/phase6.md)
- [Phase7の履歴と検証記録](roadmap/phase7.md)

## 主要Contractと運用引継ぎ

- [Atomic Detection DSL](design/atomic_detection_dsl.md)
- [Normalized Endpoint Event Contract](design/defender/normalized_endpoint_event_contract.md)
- [Windows Telemetry Contract](design/windows/windows_telemetry_contract.md)
- [Scenario Family Expansion Policy](design/scenario_family_expansion_policy.md)
- [Post-action DFIR Investigation](design/dfir/post_action_dfir_investigation.md)
- [Rule Improvement Candidate Creation Workflow](design/rule-improvement/rule_improvement_candidate_creation_workflow.md)
- [AI-assisted Rule Improvement Review Handoff](runbooks/ai_assisted_rule_improvement_review_handoff.md)
- [Smoke Runbook](operations/smoke_runbook.md)

新しいcontractまたはrunbookがauthoritativeになった場合、まず最もspecificな
owner documentへ追加します。このindexを更新するのは、そのreferenceが
workstreamをまたいで安定して有用になった場合だけです。
