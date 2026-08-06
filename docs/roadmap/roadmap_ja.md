# AI SOC Lab ロードマップ

[English](roadmap.md)

> [!NOTE]
> この文書は英語版`roadmap.md`の参考翻訳です。
> 英語版を正本とし、内容に差異がある場合は英語版を優先してください。
>
> Canonical source: `docs/roadmap/roadmap.md`
> Synchronization status: synchronized
> Last synchronization date: 2026-08-05

この文書は、現在の実装状況、優先事項、未完了作業、実施順序、および
Done Criteriaについて、英語版を正本とするロードマップです。

安定したアーキテクチャ、artifact contract、evidence boundary、および運用方針は、
[AI SOC Lab Master Guide](../AI_SOC_Lab_Master_Guide.md)を参照してください。
ソースから共通Defender処理までの責務は、
[Defender Event Processing Flow（日本語参考訳）](../architecture/defender-event-processing-flow_ja.md)を参照してください。
Phase固有の実装履歴と検証エビデンスは、[phase0.md](phase0.md)から
[phase7.md](phase7.md)に記録されています。

---

# 1. ステータスの意味と変更してはならない境界

以下のステータス用語は、意図的に使い分けます。

- **Implemented（実装済み）**: 明示した境界に対応するリポジトリ内のコード、
  schema、fixture、または文書が存在する。
- **Validated（検証済み）**: 明示した境界に、それを裏付けるテスト、fixture parity、
  controlled observation、または明示されたその他のエビデンスがある。
- **Planned（計画済み）**: 実施予定だが、まだ実装されていない。
- **Deferred（延期）**: 現在の実施順序から意図的に除外されている。
- **Unverified（未検証）**: 主張しているエビデンスレベルでは、実装または動作が
  実証されていない。

文書作業によって、エビデンスまたは承認の境界を実態以上に引き上げてはなりません。

```text
fixture validation != live or runtime validation
manual observation != automated execution
attacker-side observed effect != defender-side telemetry or detection evidence
collection request generation != collector API execution or live result ingestion
pre-case investigation != post-action DFIR
candidate / export / recommendation != apply / deploy / update / promotion approval
```

現在の安全性および状態変更の境界は次のとおりです。

- 状態を変更するresponseおよびcontainment actionには、引き続き承認が必要です。
- `investigation_result.json`は、post-action DFIRの出力と分離したままにします。
- `collection_result.json`は、append-onlyのCase enrichmentに利用できますが、
  verdict、severity、confidence、approval、またはdetection stateを上書きしません。
- Rule Improvementのcandidateおよびexport artifactはreview-orientedのままとし、
  apply、deployment、runtime mutation、またはpromotionを承認しません。
- Deception hitには、決定論的なDefender側のtrap observationが必要です。

---

# 2. 現在状況の要約

## 2.1 実装済みの基盤

このリポジトリには、run-scopedかつartifact-drivenなSOC研究パイプラインがあります。

```text
scenario / attack
  ↓
telemetry / normalized events
  ↓
canonical detections
  ↓
dedupe / correlation / Incident selection
  ↓
triage
  ↓
pre-case investigation
  ↓
case
  ↓
action planning / approval boundary
  ↓
collection request
  ↓
mock, manual, or future collector result boundary
  ↓
post-action DFIR / reviewed enrichment
  ↓
comparison / Rule Improvement review artifacts
```

実装済みの機能は次のとおりです。

- 決定論的なLinux detectionおよびcorrelationの基盤
- run-scopedなIncident、Triage、Investigation、Case、およびAction artifact
- evidence-awareなpre-case Investigation
- approval-awareなplaybook表現およびExecutor Agentの境界
- TheHive Caseおよびobservable adapter MVP
- schema validation済みのVelociraptor `collection_request.json`生成
- `collection_result.json`のcontract、schema、controlled mock generation、および
  post-action DFIR workflowの基盤
- Triage、Investigation、Action、およびpost-action DFIRのcomparison harness
- attacker execution、observed-effects、およびstructured runnerのartifact contract
- additiveなattacker/defender observed-effects alignment signal
- Rule Improvementのreview、proposal、concrete candidate、限定的なexport、および
  validation-summary artifact
- 決定論的なlocal-lab Deception inventory、hit、およびIncident-bridge artifact
- normalized endpoint eventおよびWindows Sysmon Event ID 1 fixtureのcontract
- Common Defender Pipeline v0のdetectorおよび限定されたdownstream composition

## 2.2 現在の作業領域

現在の作業領域は**Windows cross-platform expansion**です。Phase5のendpoint-telemetryと
Phase6のcommon-pipeline基盤を拡張しています。

現在の限定された実装は、次をサポートしています。

- Sysmon Event ID 1 source fixtureのparsingおよびnormalized parity
- 決定論的なPowerShell process / encoded-command observation rule
- canonical detection listのvalidationおよび決定論的なordering
- 既存policyを利用したplatform-neutralなdedupe-to-correlation実行
- correlation-resultからのIncident構築
- supporting-detection-IDの完全一致によるIncident selectionおよびobservation suppression
- 選択されたIncidentごとの決定論的なRule Triage
- 関連付けられたIncident/Triage pairごとのevidence-awareなpre-case Investigation
- 明示したfixture境界におけるLinux Scenario 009およびWindows Fixture A/B/Cのfocused regression

これは、完全なcross-platform execution validation、Windows downstream analytical quality、
またはlive Windows telemetry parityが確立したことを意味しません。

## 2.3 現在のステータス基準

| 領域 | 現在のステータス |
|---|---|
| Phase0–5 | 限定されたMVPが完了（Completed bounded MVPs） |
| Phase6 | 拡張MVPが完了（Extended MVP complete） |
| Phase7 | artifact-only MVP基盤が完了。scenario YAMLとrunnerはDeferred |
| Phase8 | Later。独立した`phase8.md`ではなく、このRoadmap内で管理 |
| Common Pipeline v0全体 | 未完了（Not complete） |
| 完全なcross-platform execution validation | 未完了（Not complete） |
| Live Windows Detection-to-Incident/Investigation validation | Unverified / future |
| Rule Improvement export MVP | 現在のcandidate-generation boundaryでは完了 |
| Rule Improvementのapply、deploy、runtime update、promotion | Unimplemented |
| Scenario 009 fixture path | Implementedかつ限定的 |
| Scenario 009のcanonical live-source selectionおよびlive integration | Deferred |

---

# 3. Phaseのステータスと文書の責務

以下のPhaseの説明は要約に限られます。リンク先のPhase文書に、実装履歴、
スコープを限定した判断、および検証エビデンスを保持します。

| Phase | 現在のステータス | 要約と詳細の正本 |
|---|---|---|
| Phase0 | 限定されたMVPが完了 | 最小構成のAttack → Log → Parse → Detect → Incident baseline。[phase0.md](phase0.md)を参照。 |
| Phase1 | 限定されたMVPが完了 | 決定論的なdetection、correlation、およびIncident construction。[phase1.md](phase1.md)を参照。 |
| Phase2 | 限定されたMVPが完了 | AI-assisted Triageとmachine-readableなaction planning、および後続のapproval-aware extension。[phase2.md](phase2.md)を参照。 |
| Phase3 | 限定されたMVPが完了 | 再現可能なattacker scenario、run isolation、追跡可能なattack artifact、およびevaluation基盤。[phase3.md](phase3.md)を参照。 |
| Phase4 | MVPおよびintegration adapterが完了 | Case ownership、schema validation、TheHive adapter MVP、Investigation boundary、およびDFIR request preparation。[phase4.md](phase4.md)を参照。 |
| Phase5 | 限定されたMVPが完了 | process telemetry、process-focused detection、action/execution boundary、およびschema validation済みcollection-request generation。Velociraptor APIの直接実行とlive result ingestionは実装済みとは主張しない。[phase5.md](phase5.md)を参照。 |
| Phase6 | 拡張MVPが完了 | feature lifecycle、comparison harness、post-action evidence transport、attacker/defender alignment、およびreview済みRule Improvement export artifact。applyおよびpromotion workflowは未実装。[phase6.md](phase6.md)を参照。 |
| Phase7 | artifact-only MVP基盤が完了 | local-lab deception inventory、決定論的なhit generation、およびIncident bridge。scenario YAMLとsafe runnerはDeferredのまま。[phase7.md](phase7.md)を参照。 |
| Phase8 | Later | Background activityおよびtelemetry realismは[Phase8](#7-phase8--background-activityとtelemetry-realism)で定義。独立した`phase8.md`は存在しない。 |

---

# 4. 現在の実施順序

## 4.1 完了した前提作業

以下の作業領域は、明示した限定的なエビデンスレベルで完了しています。

```text
Phase6 extended MVP
  ↓
Triage / Investigation / Action comparison harness foundations
  ↓
Action → collection request boundary
  ↓
collection result contract and controlled post-action DFIR workflow
  ↓
attacker artifact contracts and observed-effects alignment
  ↓
Rule Improvement review and export MVP
  ↓
scenario-family policy, broader Linux mapping, and bounded Scenario 009 fixture path
  ↓
Windows Sysmon Event ID 1 fixture, parser, mapper, detection, and bounded common pipeline slice
```

## 4.2 現在の作業

1. Common Defender Pipeline v0の完全なcross-platform execution validationを完了する。
2. 共通境界を通して、LinuxおよびWindowsのfixture regressionを再確認する。
3. 別途レビューされたpersistent identity contractが導入されない限り、identityをrun-localに保つ。
4. 検証中も、完全一致IDによるIncident selectionと既存correlation-policyのsemanticsを維持する。

## 4.3 Common Pipeline v0完了後の作業

1. PID/PPIDと時間的関係に基づく、異なるmulti-event Correlation形状を使用して
   Windows Slice 2を追加する。
2. 同一の境界を通して、LinuxおよびWindows Slice 1/2のregressionを実行する。
3. 2番目のsliceでabstractionを検証した後、共通execution spineをCommon Pipeline v1として固定する。
4. Windows固有のdownstream contractを導入せずに、Windows Triage、Investigation、
   harnessのevidence qualityを改善する。

## 4.4 後続作業

- live Windows collectionおよびWazuh retrieval/conversion integration
- Security 4624/4625やSysmon Event ID 3など、追加のWindows telemetry source
- standalone Windows telemetryが安定した後のAD/DC対応
- 残っているScenario 009 canonical-sourceおよびlive-integration作業
- post-action DFIRの追加artifact parserおよびcollector mapping
- より実用的なattacker-agent behaviorと任意のSIEM integration
- Phase7 deception scenario YAMLおよびsafe runner
- Rule Improvementのapply、deployment、runtime update、およびpromotion workflow

---

# 5. Common Defender Pipeline v0

## 5.1 実装済みの範囲

実装済みのin-memory compositionはcanonical detectionを受け取り、以下の境界を
決定論的な順序で実行します。

```text
canonical detections
  ↓
validation and deterministic ordering
  ↓
dedupe
  ↓
existing fixed correlation policies
  ↓
correlation-result Incident construction
  ↓
exact-ID Incident selection / observation suppression
  ↓
deterministic Rule Triage
  ↓
evidence-aware pre-case Investigation
```

実装済みで、focused testにより検証済みの項目は次のとおりです。

- canonical detection-list inputおよびoutput validation
- duplicate detection IDおよびtimestampをfail-closedで処理
- ruleごとに区別される決定論的なdedupe behavior
- 既存correlation policyの固定順序での実行
- correlation-resultからIncidentへのlinkage
- observation suppressionにおけるsupporting-detection-ID完全一致の優先
- 1対1のIncident/Triage linkage validation
- 1対1のIncident/Triage/Investigation実行
- Linux Scenario 009およびWindows Fixture A/B/Cの限定されたfixture regression

v0要件として実装しない項目は次のとおりです。

- correlation-to-correlation mergeまたはsuppression
- persistent aggregate artifact
- reprocessingまたはselection変更をまたぐstable identity
- live Wazuh Windows integration

## 5.2 残っているv0作業

- 共通境界を通した完全なcross-platform execution validation
- 完全な検証手順でも、確立済みのLinux flowが維持されることの確認
- 個別のfocused testだけでなく、以下のv0 Done Criteriaをすべて同時に満たすことの検証

## 5.3 Common Pipeline v0の完全なDone Criteria

Common Pipeline v0が完了するのは、以下をすべて満たした場合に限ります。

- 該当するLinuxおよびWindowsの`endpoint_events.v1` inputが、共通detector boundaryに入れる。
- 共通spineが、detector invocation、dedupe/correlation、Incident、決定論的なRule Triage、
  およびpre-case Investigationを網羅する。
- Windows Slice 1が、共通contractを通してIncident boundaryへ到達する。
- 既存Linux behaviorのregression validationが維持される。
- source固有のparser、mapper、およびruleを、単一の実装へ強制しない。
- downstream stageが、native auditdまたはSysmon形状ではなく、canonical detectionと
  common artifactを使用する。
- fixture、runtime、およびattacker/defender evidenceの境界を明示する。
- v0完了にはlive Wazuh Windows integrationを要求しない。
- Windows固有のIncident、Triage、またはInvestigation contractを導入しない。
- 完全なcross-platform execution validationについて、使用した正確なコマンドと
  エビデンスを記録して完了とする。

現在の結果: **未完了（not complete）**。

## 5.4 Common Pipeline v1の開始条件

Common Pipeline v1を開始するのは、以下を満たした後に限ります。

- Windows Slice 2で異なるmulti-event Correlation形状を検証する
- Linux/Windows cross-platform regressionに合格する
- post-Incident stageがnative source formatから独立したままである
- common runおよびharness artifactの境界が引き続き有効である

---

# 6. ドメイン別の未完了作業

## 6.1 Windowsおよびcross-platform defender flow

現在:

- v0の完全なexecution validationを完了する
- 限定されたfixture evidenceの主張を維持する
- Windows analytical qualityをstructural parityと分離して扱う

次:

- Windows Slice 2
- cross-platform regression
- Common Pipeline v1
- downstream quality tuning

後続:

- live collection、Wazuh integration、追加telemetry、およびAD/DC

## 6.2 Linux Scenario 009

Implemented（実装済み）:

- 限定されたfixture path
- controlled Wazuh evidence recordおよび補足文書
- Scenario 009のadvisory action-planning boundary

Remaining（残作業）またはDeferred（延期）:

- canonical source selection
- source parityおよびnormalization
- canonical sourceからのDSL detectionおよびIncident consumption
- live integration

これらの手順がレビューおよび実装されるまで、fixture pipelineを正本とします。
後続のcontrolled experimentによって、過去のScenario 009 evidenceのレベルを
実態以上に引き上げてはなりません。

## 6.3 Rule Improvement

現在のImplemented（実装済み）境界:

- human-review inputおよびclassification artifact
- proposalおよびconcrete candidate bundle artifact
- rule、prompt、parser、およびpromotion-recommendation export artifact
- export-artifact validation summary
- 決定論的なlocal chain smoke coverage

Unimplemented（未実装）:

- parser process-pipeline wiring
- telemetryおよびcorrelation candidate artifact export
- candidate apply
- rule、prompt、parser、telemetry、またはcorrelationのruntime update
- deploymentおよびbaseline update workflow
- promotion workflowおよびautomatic promotion
- attack-to-detection-to-Rule-Improvementのlive E2E validation

`promotion_recommendation.yaml`はrecommendation-onlyのままです。

multi-host correlation、external intelligence enrichment、より豊富なattack artifact、
attacker planning extensionなど、Phase6のブロッカーではない追加の後続作業は
Deferred（延期）のままです。
[Phase6 Current Open Items](phase6.md#9-current-open-items)を参照してください。

## 6.4 Post-action DFIRおよびintegration

Implemented（実装済み）:

- collection request generation
- collection result schemaおよびcontrolled mock output
- 現在サポートしているartifact setのpost-action DFIR parsing
- review済みで境界を維持するhandoff artifact

Remaining（残作業）:

- 実際のVelociraptor API execution integration
- より広範なcollector-output mapping
- 追加のartifact parser
- 妥当な場合の明示的なexecutor / collector result comparison
- 現在の限定されたintegrationを超える、review済みのexternal Case update

## 6.5 Deception

Implemented（実装済み）:

- artifact schemaおよび決定論的なfixture
- local-lab assetおよびhit generation
- 決定論的なIncident bridge

Deferred（延期）:

- scenario YAML
- safe scenario runner
- canonical detection output integration
- live/runtime deception validation
- automatic containmentまたはRule Improvement promotion

---

# 7. Phase8 — Background ActivityとTelemetry Realism

独立した`phase8.md`が存在しないため、Phase8はこのRoadmap内で管理します。

## 7.1 目的

制御された通常活動とノイズを生成し、attack-only telemetryではなく、現実的な
false-positive pressureに対してdetection、correlation、triage、および
Rule Improvementを評価できるようにします。

## 7.2 計画しているスコープ

想定するactivity familyには、次が含まれます。

- 定期的なadministrative SSH login
- 通常の`sudo` operation
- package updateおよびbackup script
- cronおよびscheduled-task activity
- Windows administrative PowerShell
- file-share access
- 単独では不審に見える処理と類似するbenign process chain

## 7.3 計画しているartifact

```text
background_activity/
  linux_activity.yaml
  windows_activity.yaml
  background_activity_results.json
```

正確なschemaおよびexecution contractはPlannedのままであり、実装前に対象を限定した
contract PRで導入する必要があります。

## 7.4 開始条件

Phase8の実装を開始するのは、以下を満たした後に限ります。

- noisy runとattack runを比較できる程度にcommon defender pipelineが安定している
- scenario/run identityおよびevidence linkageが決定論的なままである
- false-positiveおよびtuning metricが定義されている
- activity generationが承認されたlab environmentに限定されている

## 7.5 安全性とエビデンスの境界

- Background activityは、決定論的かつlab-scopedでなければならない。
- activityを生成したことは、Defender telemetryが収集された証明にはならない。
- noise generationによってapprovalまたはcontainment stateを変更してはならない。
- 別のapply workflowが承認および実装されるまで、tuning recommendationは
  review-onlyのままとする。

## 7.6 Done Criteria

Phase8が完了するのは、以下をすべて満たした場合に限ります。

- LinuxおよびWindows activity definitionにreview済みschemaがある
- 実行によって追跡可能なrun-scoped result artifactが生成される
- normal-activity telemetryが同じcanonical defender boundaryに入れる
- identity collisionを起こさずにattack runとnoise runを比較できる
- false-positive resilienceおよびtuning effectを明示的なエビデンスで測定する
- production、public、またはunauthorized targetを使用しない

現在のステータス: **Planned / later**。

---

# 8. 過去の計画に関する文脈

当初のtime-horizon planでは、Phase0–2を最初の3か月、Phase3–5を6か月、
Phase5–8を12か月の期間にまとめていました。この計画は過去の文脈としてのみ保持し、
現在のスケジュールではありません。

現在の実施順序は、[現在の実施順序](#4-現在の実施順序)およびCommon Pipeline v0の
Done Criteriaに従います。

過去のarchitecture、tool selection、およびphilosophyは、ここに重複して記載せず、
[Master Guide](../AI_SOC_Lab_Master_Guide.md)およびPhase文書に保持します。

---

# 9. 完了およびレビューのチェックリスト

ステータスを変更する、またはRoadmapの作業項目を完了する前に、以下を確認します。

- コード、schema、fixture、または文書に、対象となる正確なimplementation boundaryが存在する
- 主張するvalidation levelが明記され、裏付けられている
- attacker-sideとdefender-sideのevidenceが分離されている
- pre-caseとpost-actionのInvestigation artifactが分離されている
- request、execution、およびresult-ingestionの境界が明示されている
- candidateまたはrecommendation artifactから、approval、apply、deployment、update、
  またはpromotionを推定していない
- 意図的にfixtureとして整備する場合を除き、生成されたrun artifactをsourceとしてcommitしていない
- 関連するPhaseまたはdesign文書に、詳細なevidenceおよびhistoryが保持されている
- 日本語版を同期する前に、英語Canonicalのstatusが更新されている
- link、anchor、code fence、および保護対象のtechnical identifierが有効なままである

文書のみを変更する場合の最小検証:

```bash
git diff --check
! rg -n \
  'docs/roadmap/attacker-agent-roadmap\.md|\]\([^)]*phase8\.md(?:#[^)]*)?\)' \
  README.md README_ja.md AGENTS.md docs
```

独立した`phase8.md`が存在しないのは意図した状態です。
