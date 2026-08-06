# Security Policy

## Scope

This repository is a curated public portfolio snapshot. It is not intended for
production use and is not a supported security product. Active development
continues in a private repository.

## Safe Use

- Run the examples only in an isolated lab that you own or are explicitly
  authorized to test.
- Do not run them against third-party environments, Internet targets, or
  production systems.
- Do not connect the snapshot to production Wazuh, TheHive, Proxmox, OpenAI,
  LM Studio, or other services without a separate authorization, data-handling,
  and configuration review.
- Treat external telemetry and model output as untrusted input. Recommendation
  artifacts are not approval to deploy, promote, contain, or mutate systems.
- Never commit or upload secrets, credentials, tokens, private keys, raw lab
  telemetry, PCAPs, generated run artifacts, or real incident data.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting feature for this repository when
it is available. Include the affected path, impact, reproduction conditions,
and a minimal proof of concept that contains no secret or real-world target
data.

If private vulnerability reporting is unavailable, contact the repository
owner through a private channel before sharing technical details. Do not post
secrets, personal data, private lab details, exploit details, or real incident
data in a Public Issue. A Public Issue may be used only to request a private
contact method, without including vulnerability details.

Because active development occurs privately, a fix may first be prepared in the
private repository and later included in a reviewed public snapshot update.
