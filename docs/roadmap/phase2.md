# Phase2 --- AI SOC Triage & Action Planning

> [!NOTE]
> This document preserves Phase2-specific implementation history and
> validation context. The [main Roadmap](roadmap.md) is authoritative for current
> status, active priority, incomplete work, and Done Criteria.

## 🎯 Goal

Use incident.json as input for AI-assisted triage (analysis and assessment), then automatically generate prioritization and an initial-response action plan.

------------------------------------------------------------------------

## 🏗 Architecture

    incident.json
      ↓
    ai-triage-agent
      ↓
    triage_result.json
      ↓
    action-agent
      ↓
    action_result.json

------------------------------------------------------------------------

## ⚙️ Implemented Agents

### 1. ai-triage-agent

-   Pass incident.json to the AI as input
-   Make an assessment from the perspective of a SOC analyst

#### Triage Output

-   verdict (malicious / suspicious / benign)
-   confidence (low / medium / high)
-   summary
-   attack_story
-   key_observations
-   mitre_attack
-   recommended_actions
-   priority (P1 / P2 / P3)
-   risk_score (0–100)

------------------------------------------------------------------------

### 2. action-agent

-   Generate an action plan from triage_result.json

#### Action Output

-   action_result.json

#### Action Contents

-   isolate_host
-   disable_account
-   alert_soc_team
-   monitor / log_only

------------------------------------------------------------------------

## 📦 Output Files

### triage_result.json

-   AI-generated analysis results

### action_result.json

-   Machine-actionable action plan

------------------------------------------------------------------------

## 🔍 Example Flow

    SSH brute force
      ↓
    Successful authentication
      ↓
    sudo execution
      ↓
    AI triage → malicious / P1
      ↓
    action → isolate + disable + alert

------------------------------------------------------------------------

## 🧠 Key Features

-   AI-assisted incident analysis
-   Priority assignment
-   Risk scoring
-   Structured response actions
-   Automation of SOC assessments

------------------------------------------------------------------------

## 🧠 Design Principles

-   Detection is deterministic
-   AI is used for analyst and triage tasks
-   Actions are emitted in a machine-readable format
-   Aim for automation while supporting human judgment

------------------------------------------------------------------------

## 🚧 Known Limitations

-   Actions are planned only; execution is not supported
-   No CMDB or asset context is available
-   False positives cannot be eliminated completely
-   Assumes a single incident

------------------------------------------------------------------------

## 🚀 Historical Next Phase

### Phase3 --- Adversary Simulation

-   Automatically execute attack scenarios
-   Create a feedback loop between detection and AI assessment
