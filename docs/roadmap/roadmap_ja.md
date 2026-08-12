# AI SOC Lab ロードマップ

[English](roadmap.md)

> [!NOTE]
> この文書は英語版`roadmap.md`の参考翻訳です。
> 英語版を正本とし、内容に差異がある場合は英語版を優先してください。
>
> Canonical source: `docs/roadmap/roadmap.md`
> Synchronization status: synchronized
> Last synchronization date: 2026-08-10

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
- LinuxおよびWindows Slice 1/2を対象とする限定的なCommon Pipeline v1開始条件の検証

## 2.2 現在の作業領域

現在の作業領域は、**Common Pipeline v1の安定化とWindows downstream evidence
quality**です。Phase5のendpoint-telemetryとPhase6のcommon-pipeline基盤を
拡張しています。

現在の限定された実装は、次をサポートしています。

- Sysmon Event ID 1 source fixtureのparsingおよびnormalized parity
- 決定論的なPowerShell process / encoded-command observation rule
- canonical detection listのvalidationおよび決定論的なordering
- 既存policyを利用したplatform-neutralなdedupe-to-correlation実行
- 限定されたWindows Slice 2 PID/PPIDおよび60秒以内のparent/child
  Correlation fixtureとpolicy
- correlation-resultからのIncident構築
- supporting-detection-IDの完全一致によるIncident selectionおよびobservation suppression
- 選択されたIncidentごとの決定論的なRule Triage
- 関連付けられたIncident/Triage pairごとのevidence-awareなpre-case Investigation
- 明示したfixture境界におけるLinux Scenario 009およびWindows Fixture A/B/Cの
  共通endpoint-to-Investigation entry
- 同じendpoint-to-Investigation entryを使用するLinux Scenario 009および
  Windows Slice 1/2の統合regression matrix
- native sourceまたはscenario dispatch parameterを追加しないcanonical handoff
- assessment ruleを変更しない、決定論的Rule Triageでのcanonical Incident
  artifact grounding
- pre-case Investigationでのcorrelation-Incident-scopedな`input[N]`
  endpoint evidence binding

これは、限定されたfixture levelでCommon Pipeline v1の開始条件を満たしたことだけを
意味します。Windows downstream analytical quality、live Windows telemetry parity、
または継続的なruntime automationを確立したものではありません。

## 2.3 現在のステータス基準

| 領域 | 現在のステータス |
|---|---|
| Phase0–5 | 限定されたMVPが完了（Completed bounded MVPs） |
| Phase6 | 拡張MVPが完了（Extended MVP complete） |
| Phase7 | artifact-only MVP基盤が完了。scenario YAMLとrunnerはDeferred |
| Phase8 | Later。独立した`phase8.md`ではなく、このRoadmap内で管理 |
| Common Pipeline v0全体 | 限定されたfixture execution levelで完了 |
| 完全なcross-platform execution validation | Linux Scenario 009およびWindows Slice 1/2で検証済み |
| Windows Slice 2 correlation boundary | 共通endpoint-to-Investigation regressionで検証済み |
| Common Pipeline v1の開始条件 | 限定されたfixture levelで充足 |
| Windows downstream evidence-quality slice | canonical artifact groundingとcorrelation endpoint evidence bindingを公開版で検証済み。private-lab harness scoringは非公開 |
| 限定されたlive Windows 4625 Detection-to-Incident/Investigation validation | 完全なWazuh alert-plane record 5件について検証済み。dedupe後は4件のDetection/Incident/Triage/Investigation pathとなり、元の5件はすべて表現された |
| 限定されたWazuh Indexer live multi-page cursor smoke | 14件のalert-plane PIT queryをpages `[5, 5, 4]` で取得し、最終deleteを確認済み |
| Windows Security 4624/4625の限定されたcommon-entry boundary | sanitized sourceから既存endpoint-to-Investigation entryまで検証済み。4624はemptyを維持し、4625は正確なdownstream linkageを持つuncorrelated low-severity observationを保持 |
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
  ↓
Windows Slice 2 PID/PPID and temporal Correlation
  ↓
Linux and Windows Slice 1/2 common-entry regression
```

## 4.2 現在の作業

1. 固定したcommon entry boundaryを通してLinuxおよびWindows Slice 1/2の
   regressionを維持する。
2. Windows固有のdownstream contractを導入せずに、限定されたWindows Triageと
   Investigationのevidence-quality regressionを維持する。
3. 限定されたWazuh Sysmon Event ID 1 alert-hit conversion parity regressionを、
   完了したalert-plane transport evidenceおよび未検証のnative parityとは区別して
   維持する。
4. host/time/result bound、refinement、partial-result rejection、hashed provenanceを
   含む、限定された`wazuh-alerts-sysmon-event1` query-planおよびcomplete-page
   response regressionを維持する。
5. final-page、policy-stop、known-failure cleanup semanticsを含む、限定されたWazuh
   Indexer PIT create/search/resume/delete lifecycleを維持する。
6. encryptedかつrequest-boundな30秒Wazuh Indexer cursor、累積100-record cap、
   strictでstableな`search_after` progression、および2026-08-11のlive
   three-page/final-deletion evidenceを維持する。
7. Windows Security 4624/4625 source fixture、parser、normalized mapper、
   sanitized Wazuh alert-hit conversion parity、source registry/query regression、
   atomic detection、common-entry matrix、および完了した5-record 4625 live
   common-pipeline evidenceを維持する。authentication固有の分析、反復失敗の相関、
   native parity、continuous live integrationは推論しない。
8. 別途レビューされたpersistent identity contractが導入されない限り、identityを
   run-localに保つ。
9. 検証中も、完全一致IDによるIncident selectionと既存correlation-policyのsemanticsを
   維持する。

## 4.3 v1開始条件の検証後

1. Windows downstream qualityをさらに変更する場合は、実装前に具体的な
   shared-contractまたはshared-rubricの不足と照合してレビューする。
2. credential-resolving、TLS-verifying、read-only Wazuh HTTPS transportおよび
   bounded smoke harnessについて、完了したlive evidence gateを維持する。
   2026-08-10のlab runでは正確かつ完全なalert-plane recordを14件取得した。
   PIT-enabled rerunでは同じ14件を取得し、2026-08-11のmulti-page rerunでは
   pages `[5, 5, 4]`、2回のprotected cursor resume、final-page deletionを確認した。
3. 完了したWindows Security 4625の限定されたlive common-pipeline gateを維持する。
   2026-08-11のcontrolled queryでは5件すべてをretrieve、adapt、normalize、
   representし、dedupe後の4件をDetection/Incident/Triage/Investigationへ接続した。
   sanitized summaryのSHA-256は
   `e4751c5af21ed7af17f841efa1b8226037fe67614d4c004b22fb600fc8bb9666`。
4. 既存fixture evidenceをlive claimへ読み替えずに、残っているLinux Scenario 009の
   canonical live-source selectionおよび限定されたlive common-pipeline integrationを
   準備する。

## 4.4 後続作業

- live Windows collectionおよびoperational Wazuh retrieval integration
- Security 4624/4625やSysmon Event ID 3など、追加のWindows telemetry source
- standalone Windows telemetryが安定した後のAD/DC対応
- post-action DFIRの追加artifact parserおよびcollector mapping
- より実用的なattacker-agent behaviorと任意のSIEM integration
- Phase7 deception scenario YAMLおよびsafe runner
- Rule Improvementのapply、deployment、runtime update、およびpromotion workflow

---

# 5. Common Defender Pipeline v0およびv1開始条件

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

- 決定論的なdetectionの後に既存Detection-to-Investigation compositionを呼び出す
  endpoint-fixture entry
- canonical detection-list inputおよびoutput validation
- duplicate detection IDおよびtimestampをfail-closedで処理
- ruleごとに区別される決定論的なdedupe behavior
- 既存correlation policyの固定順序での実行
- correlation-resultからIncidentへのlinkage
- observation suppressionにおけるsupporting-detection-ID完全一致の優先
- 1対1のIncident/Triage linkage validation
- 1対1のIncident/Triage/Investigation実行
- Linux Scenario 009およびWindows Fixture A/B/Cの限定されたfixture regression
- Linux Scenario 009およびWindows Slice 1/2の統合common-entry regression

v0要件として実装しない項目は次のとおりです。

- correlation-to-correlation mergeまたはsuppression
- persistent aggregate artifact
- reprocessingまたはselection変更をまたぐstable identity
- 限定された4625 gateを超えるgeneralizedまたはcontinuousなlive Wazuh Windows integration

## 5.2 v0 validation record

cross-platform validation matrixは、Linux Scenario 009とWindows Fixture A/B/Cを
同じendpoint-to-Investigation entryで実行します。確立済みのLinux flow、Windowsの
match / no-match behavior、決定論的なIncident/Triage/Investigation linkage、input
immutability、fail-closedなendpoint validation、および限定したevidence exclusionを
まとめて確認します。

正確なvalidation commandは次のとおりです。

```bash
uv run pytest tests/test_common_defender_pipeline_v0_validation.py -q
uv run pytest tests/test_common_detection_pipeline.py \
  tests/test_common_detection_to_investigation_composition.py \
  tests/windows/sysmon_event1/test_sysmon_event1_investigation_boundary.py -q
uv run ruff check common/defender_pipeline.py \
  tests/test_common_defender_pipeline_v0_validation.py
uv run pytest tests -q
```

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

現在の結果: **限定されたfixture execution levelで完了**。

## 5.4 Common Pipeline v1の開始条件

Common Pipeline v1を開始するのは、以下を満たした後に限ります。

- Windows Slice 2で異なるmulti-event Correlation形状を検証する
  （限定されたfixture levelで検証済み）
- Linux/Windows cross-platform regressionに合格する
  （限定されたfixture levelで検証済み）
- post-Incident stageがnative source formatから独立したままである
  （common endpoint entryで検証済み）
- common runおよびharness artifactの境界が引き続き有効である
  （確立済みの5-list in-memory bundleで検証済み）

現在の結果: **限定されたfixture levelで開始条件を充足**。

## 5.5 v1開始条件のvalidation record

5 caseのmatrix、固定したhandoff property、Done Criteria、evidence limitation、
および正確なvalidation commandは、
[Common Pipeline v1 Entry Validation](../design/defender/common_pipeline_v1_entry_validation.md)
に記録します。

このstatusはv1の安定化開始を意味します。v1を新しいwire schema、persistent identity
model、runtime service、またはlive cross-platform integrationとして定義するものでは
ありません。

## 5.6 Windows downstream evidence-quality validation record

限定されたartifact groundingとcorrelation-Incident-scopedなendpoint evidence
linkageの仕組みは、Done Criteriaとevidence limitationを含めて
[Windows Downstream Evidence-Quality Slice](../design/defender/windows_downstream_evidence_quality.md)
に記録します。

より広いprivate labのdeterministic comparison-harness scoringは、この公開snapshot
には含めていません。

このvalidationは、Windowsのverdict/risk quality、model quality、live collection、
source parity、またはpost-action DFIR coverageを確立するものではありません。

## 5.7 限定されたWazuh Sysmon Event ID 1 conversion record

厳格なサニタイズ済みalert-hit projection、分離したretrieval provenance、Fixture A/B/C
source conversion、normalized semantic parityは、公開版の
[Wazuh hit adapter](../../scripts/windows/sysmon_event1/adapt_wazuh_sysmon_event1_hit.py)
と
[focused conversion test](../../tests/windows/sysmon_event1/test_wazuh_sysmon_event1_conversion.py)
で確認できます。

このvalidationは、live Wazuh connection、operational query behavior、raw archive coverage、
Wazuh rule quality、unalerted event coverage、またはlive Windows parityを確立するものでは
ありません。

## 5.8 限定されたWazuh query-adapter record

レビュー済みsingle-source registry entry、request/response schema、offline search-plan
compiler、complete-page response parser、refinement behavior、partial-result rejection、
hashed provenanceは、公開版の
[query adapter](../../scripts/siem/wazuh_indexer_query_adapter.py)と
[focused tests](../../tests/test_wazuh_indexer_query_adapter.py)
で確認できます。

このvalidationは、credential resolution、HTTPS execution、live index mapping、PIT
pagination、live query success、raw archive coverage、またはend-to-end live source parityを
確立するものではありません。

---

# 6. ドメイン別の未完了作業

## 6.1 Windowsおよびcross-platform defender flow

現在:

- 限定されたCommon Pipeline v1 entry regressionを維持する
- Windows Slice 2 PID/PPIDおよびtemporal Correlation behaviorを維持する
- 限定されたfixture evidenceの主張を維持する
- Windows analytical qualityをstructural parityと分離して扱う
- 限定されたWazuh Sysmon Event ID 1 alert-hit conversion parityを維持する
- 限定されたWazuh query-planおよびresponse-parser regressionを維持する

次:

- downstream quality tuning
- 実装済みcredential-backed Wazuh HTTPS transport smokeをlabで実行し、
  sanitizedされた限定summaryのみを保持する
- noise cleanupより先に、観測したmanager/Indexer clockおよびalert/provider
  time-field alignmentをレビューする
- request-bound cursorおよびcleanup semanticsを備えたPIT/search-after pagination
- 独立したcontractを持つ追加Windows telemetry

後続:

- live collection、operational Wazuh retrieval、追加telemetry、およびAD/DC

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
