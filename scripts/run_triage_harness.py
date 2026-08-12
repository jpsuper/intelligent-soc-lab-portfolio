#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception as exc:  # pragma: no cover
    raise SystemExit("PyYAML is required to run this script.") from exc


ACTION_HINT_KEYWORDS = {
    "isolate",
    "contain",
    "disable",
    "revoke",
    "rotate",
    "collect",
    "investigate",
    "block",
    "kill",
    "remove",
    "quarantine",
}

DEFAULT_ARTIFACT_SYNONYMS: dict[str, list[str]] = {
    "ssh_key_login": [
        "ssh key login",
        "ssh public key login",
        "successful ssh public-key login",
        "successful ssh public key login",
        "public key login",
        "public-key login",
        "public key authentication",
        "public-key authentication",
        "ssh login using public key authentication",
        "successful ssh login using public key authentication",
    ],
    "process_exec": [
        "process execution",
        "command execution",
        "post-login command execution",
        "executed command",
        "executed process",
    ],
    "authorized_keys_modification": [
        "authorized_keys modified",
        "authorized_keys modification",
        "ssh key persistence",
        "public key added to authorized_keys",
    ],
}


SUPPORTED_STAGES = {"triage", "investigation"}

REQUIRED_INPUTS_BY_STAGE: dict[str, list[str]] = {
    "triage": ["incident"],
    "investigation": ["incident", "triage_result"],
}

OPTIONAL_INPUT_PATH_ALIASES: dict[str, tuple[str, ...]] = {
    "endpoint_events": ("endpoint_events_json",),
    "endpoint_events_json": ("endpoint_events",),
}


class HarnessError(RuntimeError):
    pass


@dataclass
class AgentExecutionResult:
    name: str
    output_path: Path
    command: list[str]
    returncode: int | None
    stdout_log: Path | None
    stderr_log: Path | None
    skipped: bool = False


class SafeFormatDict(dict[str, str]):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise HarnessError(f"YAML file must contain an object: {path}")
    return data


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def normalize_incident_payload(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    if isinstance(data, list) and data:
        latest = data[-1]
        if isinstance(latest, dict):
            return latest
    raise HarnessError("incident JSON must be an object or a non-empty list of objects")


def ensure_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessError(f"{label} must be a JSON/YAML object")
    return value


def dump_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def dump_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def slugify(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    text = re.sub(r"-+", "-", text).strip("-")
    return text or "item"


def template_str(value: str, variables: dict[str, str]) -> str:
    return value.format_map(SafeFormatDict(variables))


def template_value(value: Any, variables: dict[str, str]) -> Any:
    if isinstance(value, str):
        return template_str(value, variables)
    if isinstance(value, list):
        return [template_value(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: template_value(item, variables) for key, item in value.items()}
    return value


def canonical_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value.strip()
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def parse_expected_response_keywords(judge_cfg: dict[str, Any]) -> tuple[list[str], list[str]]:
    raw = judge_cfg.get("expected_response_keywords")

    if isinstance(raw, dict):
        must_have = [
            str(item).lower() for item in listify(raw.get("must_have")) if str(item).strip()
        ]
        nice_to_have = [
            str(item).lower() for item in listify(raw.get("nice_to_have")) if str(item).strip()
        ]
        return sorted(set(must_have)), sorted(set(nice_to_have))

    if raw is None:
        return [], []

    legacy = [str(item).lower() for item in listify(raw) if str(item).strip()]
    return sorted(set(legacy)), []


def flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(flatten_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(flatten_text(item) for item in value.values())
    return str(value)


def try_validate_json(instance: dict[str, Any], schema_path: Path | None) -> list[str]:
    if schema_path is None or not schema_path.exists():
        return []
    try:
        import jsonschema  # type: ignore
    except Exception:
        return [f"jsonschema not installed; skipped validation for {schema_path}"]

    schema = load_json(schema_path)
    if not isinstance(schema, dict):
        return [f"schema must be a JSON object: {schema_path}"]

    validator = jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(instance), key=lambda err: list(err.absolute_path))
    return [
        f"{'/'.join(str(p) for p in err.absolute_path) or '$'}: {err.message}" for err in errors
    ]


def detect_schema_path(repo_root: Path, *candidates: str) -> Path | None:
    for relative in candidates:
        candidate = repo_root / relative
        if candidate.exists():
            return candidate
    return None


def resolve_repo_root(workflow_path: Path) -> Path:
    if workflow_path.parent.name == "workflows" and workflow_path.parent.parent.exists():
        return workflow_path.parent.parent.resolve()
    return Path.cwd().resolve()


def resolve_output_path(agent_cfg: dict[str, Any], harness_run_dir: Path) -> Path:
    raw = agent_cfg.get("output")
    if raw:
        output_path = Path(str(raw))
        if not output_path.is_absolute():
            output_path = harness_run_dir / output_path
    else:
        name = slugify(str(agent_cfg.get("name") or "agent"))
        output_path = harness_run_dir / "agents" / f"{name}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    return output_path.resolve()


def build_command(agent_cfg: dict[str, Any], variables: dict[str, str]) -> list[str]:
    if agent_cfg.get("command"):
        templated = template_value(agent_cfg["command"], variables)
        if isinstance(templated, str):
            return shlex.split(templated)
        if isinstance(templated, list) and all(isinstance(item, str) for item in templated):
            return list(templated)
        raise HarnessError(
            f"agent.command must be a string or list of strings for agent={agent_cfg.get('name')}"
        )

    entrypoint = agent_cfg.get("entrypoint")
    if not entrypoint:
        raise HarnessError(
            f"agent must define 'command' or 'entrypoint': agent={agent_cfg.get('name')}"
        )

    interpreter = template_value(agent_cfg.get("interpreter") or [sys.executable], variables)
    if isinstance(interpreter, str):
        interpreter_parts = shlex.split(interpreter)
    elif isinstance(interpreter, list) and all(isinstance(item, str) for item in interpreter):
        interpreter_parts = list(interpreter)
    else:
        raise HarnessError(
            f"agent.interpreter must be a string or list of strings: agent={agent_cfg.get('name')}"
        )

    args = template_value(agent_cfg.get("args") or [], variables)
    if isinstance(args, str):
        arg_parts = shlex.split(args)
    elif isinstance(args, list) and all(isinstance(item, str) for item in args):
        arg_parts = list(args)
    else:
        raise HarnessError(
            f"agent.args must be a string or list of strings: agent={agent_cfg.get('name')}"
        )

    return interpreter_parts + [template_str(str(entrypoint), variables)] + arg_parts


def validate_stage(stage: str) -> str:
    normalized = stage.strip().lower() or "triage"
    if normalized not in SUPPORTED_STAGES:
        raise HarnessError(
            f"unsupported stage: {normalized} (supported: {sorted(SUPPORTED_STAGES)})"
        )
    return normalized


def resolve_artifact_path(repo_root: Path, raw: Any, label: str) -> Path:
    path = Path(str(raw))
    if not path.is_absolute():
        path = (repo_root / path).resolve()
    if not path.exists():
        raise HarnessError(f"{label} file not found: {path}")
    return path.resolve()


def resolve_input_artifact_refs(
    workflow: dict[str, Any],
    repo_root: Path,
    output_dir: Path,
    stage: str,
    incident_override: str | None = None,
) -> dict[str, Path]:
    input_artifacts = workflow.get("input_artifacts") or workflow.get("inputs") or {}
    if not isinstance(input_artifacts, dict):
        raise HarnessError("workflow input_artifacts must be an object")

    required_names = REQUIRED_INPUTS_BY_STAGE.get(stage, [])
    copied: dict[str, Path] = {}

    input_dir = output_dir / "input"
    input_dir.mkdir(parents=True, exist_ok=True)

    for name in required_names:
        raw = (
            incident_override
            if name == "incident" and incident_override
            else input_artifacts.get(name)
        )
        if not raw:
            raise HarnessError(f"workflow input_artifacts.{name} is required for stage={stage}")

        src = resolve_artifact_path(repo_root, raw, f"input artifact {name}")
        ext = src.suffix or ".json"
        dst = input_dir / f"{name}{ext}"
        shutil.copy2(src, dst)
        copied[name] = dst.resolve()

    return copied


def resolve_optional_input_artifact_refs(
    workflow: dict[str, Any],
    repo_root: Path,
    output_dir: Path,
) -> dict[str, Path]:
    optional_cfg = workflow.get("optional_inputs") or {}
    if not optional_cfg:
        return {}
    if not isinstance(optional_cfg, dict):
        raise HarnessError("workflow optional_inputs must be an object when provided")

    optional_dir = output_dir / "optional_inputs"
    optional_dir.mkdir(parents=True, exist_ok=True)

    copied: dict[str, Path] = {}

    for name, raw in optional_cfg.items():
        if not raw:
            continue
        src = resolve_artifact_path(repo_root, raw, f"optional input artifact {name}")
        ext = src.suffix or ".json"
        dst = optional_dir / f"{name}{ext}"
        shutil.copy2(src, dst)
        copied[str(name)] = dst.resolve()

    return copied


def build_agent_template_variables(
    repo_root: Path,
    output_path: Path,
    harness_run_dir: Path,
    agent_cfg: dict[str, Any],
    required_input_paths: dict[str, Path],
    optional_input_paths: dict[str, Path],
    source_run_id: str | None,
    scenario_id: str | None,
) -> dict[str, str]:
    variables = {
        "repo_root": str(repo_root),
        "output_path": str(output_path),
        "harness_run_dir": str(harness_run_dir),
        "agent_name": str(agent_cfg.get("name") or output_path.stem),
        "profile": str(agent_cfg.get("profile") or ""),
        "source_run_id": source_run_id or "",
        "scenario_id": scenario_id or "",
        "agent_version": str(agent_cfg.get("agent_version") or ""),
        "prompt_version": str(agent_cfg.get("prompt_version") or ""),
        "rule_version": str(agent_cfg.get("rule_version") or ""),
    }

    for key, path in required_input_paths.items():
        variables[f"{key}_path"] = str(path)

    for key, path in optional_input_paths.items():
        variables[f"{key}_path"] = str(path)
        for alias in OPTIONAL_INPUT_PATH_ALIASES.get(key, ()):
            variables.setdefault(f"{alias}_path", str(path))

    return variables


def execute_agent(
    repo_root: Path,
    agent_cfg: dict[str, Any],
    required_input_paths: dict[str, Path],
    optional_input_paths: dict[str, Path],
    output_path: Path,
    harness_run_dir: Path,
    source_run_id: str | None,
    scenario_id: str | None,
    dry_run: bool,
    skip_agent_run: bool,
) -> AgentExecutionResult:
    name = str(agent_cfg.get("name") or output_path.stem)
    log_dir = harness_run_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = log_dir / f"{slugify(name)}.stdout.log"
    stderr_log = log_dir / f"{slugify(name)}.stderr.log"

    variables = build_agent_template_variables(
        repo_root=repo_root,
        output_path=output_path,
        harness_run_dir=harness_run_dir,
        agent_cfg=agent_cfg,
        required_input_paths=required_input_paths,
        optional_input_paths=optional_input_paths,
        source_run_id=source_run_id,
        scenario_id=scenario_id,
    )
    command = build_command(agent_cfg, variables)

    if dry_run or skip_agent_run:
        return AgentExecutionResult(
            name=name,
            output_path=output_path,
            command=command,
            returncode=None,
            stdout_log=None,
            stderr_log=None,
            skipped=True,
        )

    cwd = template_str(str(agent_cfg.get("cwd") or repo_root), variables)
    env = os.environ.copy()
    extra_env = template_value(agent_cfg.get("env") or {}, variables)
    if isinstance(extra_env, dict):
        env.update({str(key): str(value) for key, value in extra_env.items()})

    proc = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    stdout_log.write_text(proc.stdout or "", encoding="utf-8")
    stderr_log.write_text(proc.stderr or "", encoding="utf-8")

    return AgentExecutionResult(
        name=name,
        output_path=output_path,
        command=command,
        returncode=proc.returncode,
        stdout_log=stdout_log,
        stderr_log=stderr_log,
        skipped=False,
    )


def read_data_file(path: Path) -> dict[str, Any]:
    if path.suffix.lower() in {".yaml", ".yml"}:
        return load_yaml(path)
    return ensure_object(load_json(path), f"optional assist file {path}")


def load_optional_expected_assist(
    repo_root: Path,
    workflow: dict[str, Any],
    harness_run_dir: Path,
) -> tuple[dict[str, Any], dict[str, str]]:
    judge_cfg = workflow.get("judge") or {}
    expected_cfg = judge_cfg.get("optional_assist") or judge_cfg.get("expected") or {}
    if not isinstance(expected_cfg, dict):
        return {}, {}

    optional_dir = harness_run_dir / "optional_inputs"
    optional_dir.mkdir(parents=True, exist_ok=True)

    loaded: dict[str, Any] = {}
    refs: dict[str, str] = {}

    for key in ("expected_artifacts", "expected_verdict", "expected_priority", "notes"):
        if key in expected_cfg:
            loaded[key] = expected_cfg[key]

    for key in ("evaluation_result", "scenario_metadata"):
        raw = expected_cfg.get(key)
        if not raw:
            continue
        if isinstance(raw, dict):
            loaded[key] = raw
            inline_path = optional_dir / f"{key}.json"
            dump_json(inline_path, raw)
            refs[key] = str(inline_path.relative_to(harness_run_dir))
            continue

        path = Path(str(raw))
        if not path.is_absolute():
            path = (repo_root / path).resolve()
        if not path.exists():
            raise HarnessError(f"judge.optional_assist.{key} file not found: {path}")
        data = read_data_file(path)
        loaded[key] = data
        copied_path = optional_dir / path.name
        shutil.copy2(path, copied_path)
        refs[key] = str(copied_path.relative_to(harness_run_dir))

    return loaded, refs


def get_expected_artifacts(
    workflow: dict[str, Any],
    incident: dict[str, Any],
    expected_assist: dict[str, Any],
) -> list[str]:
    judge_cfg = workflow.get("judge") or {}
    if isinstance(expected_assist.get("expected_artifacts"), list) and expected_assist.get(
        "expected_artifacts"
    ):
        return [str(item) for item in expected_assist["expected_artifacts"]]

    scenario_metadata = expected_assist.get("scenario_metadata")
    if isinstance(scenario_metadata, dict):
        primary = scenario_metadata.get("primary_artifacts") or scenario_metadata.get(
            "expected_artifacts"
        )
        if isinstance(primary, list) and primary:
            return [str(item) for item in primary]

    evaluation_result = expected_assist.get("evaluation_result")
    if isinstance(evaluation_result, dict):
        coverage = (
            evaluation_result.get("coverage")
            if isinstance(evaluation_result.get("coverage"), dict)
            else {}
        )
        cov_expected = coverage.get("expected_artifacts")
        if isinstance(cov_expected, list) and cov_expected:
            return [str(item) for item in cov_expected]

    expected = judge_cfg.get("expected_artifacts")
    if isinstance(expected, list) and expected:
        return [str(item) for item in expected]

    if isinstance(incident.get("coverage"), dict):
        cov_expected = incident["coverage"].get("expected_artifacts")
        if isinstance(cov_expected, list) and cov_expected:
            return [str(item) for item in cov_expected]

    matched_rules = incident.get("matched_rules")
    if isinstance(matched_rules, list) and matched_rules:
        return [str(item) for item in matched_rules]

    return []


def get_expected_value(workflow: dict[str, Any], expected_assist: dict[str, Any], key: str) -> Any:
    if key in expected_assist:
        return expected_assist.get(key)
    scenario_metadata = expected_assist.get("scenario_metadata")
    if isinstance(scenario_metadata, dict) and key in scenario_metadata:
        return scenario_metadata.get(key)
    judge_cfg = workflow.get("judge") or {}
    return judge_cfg.get(key)


def extract_triage_text_blob(payload: dict[str, Any]) -> str:
    parts = [
        flatten_text(payload.get("summary")),
        flatten_text(payload.get("attack_story")),
        flatten_text(payload.get("severity_reasoning")),
        flatten_text(payload.get("recommended_response")),
        flatten_text(payload.get("recommended_actions")),
        flatten_text(payload.get("investigation_notes")),
        flatten_text(payload.get("timeline_notes")),
    ]
    assessment = payload.get("assessment")
    if isinstance(assessment, dict):
        parts.append(flatten_text(assessment))
    return " ".join(part.strip() for part in parts if part and str(part).strip()).lower()


def get_expected_enriched_features(
    workflow: dict[str, Any],
    expected_assist: dict[str, Any],
) -> list[str]:
    scenario_metadata = expected_assist.get("scenario_metadata")
    if isinstance(scenario_metadata, dict):
        raw = scenario_metadata.get("expected_enriched_features")
        if isinstance(raw, list) and raw:
            return [str(item) for item in raw if str(item).strip()]

    judge_cfg = workflow.get("judge") or {}
    raw = judge_cfg.get("expected_enriched_features")
    if isinstance(raw, list) and raw:
        return [str(item) for item in raw if str(item).strip()]

    return []


def extract_investigation_text_blob(payload: dict[str, Any]) -> str:
    parts = [
        flatten_text(payload.get("summary")),
        flatten_text(payload.get("attack_story")),
        flatten_text(payload.get("investigation_notes")),
        flatten_text(payload.get("timeline_notes")),
        flatten_text(payload.get("evidence")),
        flatten_text(payload.get("enriched_features")),
    ]
    return " ".join(part.strip() for part in parts if part and str(part).strip()).lower()


def extract_present_enriched_features(payload: dict[str, Any]) -> list[str]:
    enriched = payload.get("enriched_features")
    present: list[str] = []

    if isinstance(enriched, dict):
        for key, value in enriched.items():
            if isinstance(value, bool):
                if value:
                    present.append(str(key))
            elif value is not None and canonical_str(value):
                present.append(str(key))
    elif isinstance(enriched, list):
        present.extend(str(item) for item in enriched if str(item).strip())

    return sorted(set(present))


def extract_string_list(value: Any) -> list[str]:
    return sorted({str(item).strip() for item in listify(value) if str(item).strip()})


def extract_evidence_level(payload: dict[str, Any]) -> str | None:
    value = canonical_str(payload.get("evidence_level"))
    return value or None


def extract_evidence_summary(payload: dict[str, Any]) -> dict[str, Any]:
    summary = payload.get("evidence_summary")
    if isinstance(summary, dict):
        return summary
    return {}


def extract_evidence_supporting_signals(payload: dict[str, Any]) -> list[str]:
    summary = extract_evidence_summary(payload)
    return extract_string_list(summary.get("supporting_signals"))


def extract_named_entries(
    payload: dict[str, Any],
    field_name: str,
    value_key: str,
) -> list[str]:
    raw = payload.get(field_name)
    if not isinstance(raw, list):
        return []

    values: list[str] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        value = canonical_str(item.get(value_key))
        if value:
            values.append(value)

    return sorted(set(values))


def artifact_search_terms(
    artifact: str,
    workflow_synonyms: dict[str, list[str]] | None = None,
) -> set[str]:
    artifact = artifact.strip().lower()
    if not artifact:
        return set()

    workflow_synonyms = workflow_synonyms or {}
    configured_synonyms = workflow_synonyms.get(artifact, [])
    default_synonyms = DEFAULT_ARTIFACT_SYNONYMS.get(artifact, [])

    terms = {
        artifact,
        artifact.replace("_", " "),
        artifact.replace("-", " "),
    }
    terms.update(str(item).strip().lower() for item in default_synonyms if str(item).strip())
    terms.update(str(item).strip().lower() for item in configured_synonyms if str(item).strip())
    return terms


def extract_mentioned_artifacts(
    text_blob: str,
    expected_artifacts: list[str],
    workflow_synonyms: dict[str, list[str]] | None = None,
) -> list[str]:
    mentioned: list[str] = []
    for artifact in expected_artifacts:
        terms = artifact_search_terms(artifact, workflow_synonyms=workflow_synonyms)
        if any(term in text_blob for term in terms):
            mentioned.append(artifact)
    return mentioned


def get_assessment_value(payload: dict[str, Any], key: str) -> Any:
    assessment = payload.get("assessment")
    if isinstance(assessment, dict) and key in assessment:
        return assessment.get(key)
    return payload.get(key)


def extract_response_keywords(result: dict[str, Any], configured_keywords: list[str]) -> list[str]:
    response_text = flatten_text(
        result.get("recommended_response") or result.get("recommended_actions")
    ).lower()
    keywords = configured_keywords or sorted(ACTION_HINT_KEYWORDS)
    matched = [keyword for keyword in keywords if keyword.lower() in response_text]
    return sorted(set(matched))


def collect_forbidden_keyword_hits(text_blob: str, forbidden_keywords: list[str]) -> list[str]:
    return [keyword for keyword in forbidden_keywords if keyword.lower() in text_blob]


def common_value_map(
    agent_payloads: dict[str, dict[str, Any]], fields: list[str]
) -> dict[str, Any]:
    common: dict[str, Any] = {}
    for field in fields:
        values = [canonical_str(payload.get(field)) for payload in agent_payloads.values()]
        if values and all(value == values[0] and value is not None for value in values):
            common[field] = next(iter(agent_payloads.values())).get(field)
    return common


def build_compare_result(
    workflow: dict[str, Any],
    incident: dict[str, Any],
    expected_assist: dict[str, Any],
    harness_run_id: str,
    source_run_id: str | None,
    scenario_id: str | None,
    agent_payloads: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    stage = str(workflow.get("stage") or "triage").strip().lower()
    judge_cfg = workflow.get("judge") or {}
    compare_cfg = workflow.get("compare") or {}
    expected_artifacts = get_expected_artifacts(workflow, incident, expected_assist)
    expected_enriched_features = get_expected_enriched_features(workflow, expected_assist)
    forbidden_claim_keywords = [
        str(item) for item in listify(judge_cfg.get("forbidden_claim_keywords"))
    ]
    raw_artifact_synonyms = (
        compare_cfg.get("artifact_synonyms") if isinstance(compare_cfg, dict) else {}
    )
    artifact_synonyms: dict[str, list[str]] = {}
    if isinstance(raw_artifact_synonyms, dict):
        for artifact_name, values in raw_artifact_synonyms.items():
            key = str(artifact_name).strip().lower()
            if not key:
                continue
            artifact_synonyms[key] = [
                str(item).strip() for item in listify(values) if str(item).strip()
            ]

    field_matrix: dict[str, Any] = {}
    agent_only_items: dict[str, Any] = {}
    missing_items: dict[str, list[str]] = {}
    overclaimed_items: dict[str, list[str]] = {}
    field_comparisons: list[dict[str, Any]] = []

    if stage == "investigation":
        for agent_name, payload in agent_payloads.items():
            text_blob = extract_investigation_text_blob(payload)
            mentioned_artifacts = extract_mentioned_artifacts(
                text_blob,
                expected_artifacts,
                workflow_synonyms=artifact_synonyms,
            )
            present_enriched_features = extract_present_enriched_features(payload)
            supporting_signals = extract_evidence_supporting_signals(payload)
            unsupported_claims = extract_named_entries(
                payload,
                "unsupported_claims",
                "claim",
            )
            missing_pivots = extract_named_entries(
                payload,
                "missing_pivots",
                "pivot",
            )
            recommended_pivots = extract_named_entries(
                payload,
                "recommended_pivots",
                "pivot",
            )
            evidence_level = extract_evidence_level(payload)
            evidence_summary = extract_evidence_summary(payload)
            evidence_blob = flatten_text(payload.get("evidence"))
            evidence_present = bool(evidence_blob.strip())

            field_matrix[agent_name] = {
                "summary": payload.get("summary"),
                "attack_story": payload.get("attack_story"),
                "evidence_level": evidence_level,
                "investigation_notes": payload.get("investigation_notes"),
                "timeline_notes": payload.get("timeline_notes"),
                "mentioned_artifacts": mentioned_artifacts,
                "present_enriched_features": present_enriched_features,
                "supporting_signals": supporting_signals,
                "unsupported_claims": unsupported_claims,
                "missing_pivots": missing_pivots,
                "recommended_pivots": recommended_pivots,
                "evidence_present": evidence_present,
            }

            missing: list[str] = []
            for artifact in expected_artifacts:
                if artifact not in mentioned_artifacts:
                    missing.append(f"artifact:{artifact}")
            for feature in expected_enriched_features:
                if feature not in present_enriched_features:
                    missing.append(f"enriched_feature:{feature}")
            for field in ("summary", "attack_story", "evidence"):
                if not canonical_str(payload.get(field)):
                    missing.append(f"field:{field}")
            if not canonical_str(payload.get("investigation_notes")):
                missing.append("field:investigation_notes")
            if not canonical_str(payload.get("timeline_notes")):
                missing.append("field:timeline_notes")
            if not evidence_level:
                missing.append("field:evidence_level")
            if not evidence_summary:
                missing.append("field:evidence_summary")
            if "unsupported_claims" not in payload:
                missing.append("field:unsupported_claims")
            if "missing_pivots" not in payload:
                missing.append("field:missing_pivots")
            if "recommended_pivots" not in payload:
                missing.append("field:recommended_pivots")

            missing_items[agent_name] = missing
            overclaimed_items[agent_name] = collect_forbidden_keyword_hits(
                text_blob,
                forbidden_claim_keywords,
            )
            agent_only_items[agent_name] = {
                "captured_items": sorted(
                    set(mentioned_artifacts + present_enriched_features + supporting_signals)
                ),
                "notable_strengths": sorted(set(mentioned_artifacts)),
                "notable_enriched_features": present_enriched_features,
                "notable_unsupported_claims": unsupported_claims,
                "notable_missing_pivots": missing_pivots,
                "notable_recommended_pivots": recommended_pivots,
                "evidence_level": evidence_level,
                "evidence_present": evidence_present,
                "raw_output_ref": (
                    f"agents/{Path(payload.get('_output_ref', f'{agent_name}.json')).name}"
                ),
            }

        for field in (
            "summary",
            "attack_story",
            "evidence_level",
            "investigation_notes",
            "timeline_notes",
        ):
            field_comparisons.append(
                {
                    "field": field,
                    "values_by_agent": {
                        agent_name: field_values.get(field)
                        for agent_name, field_values in field_matrix.items()
                    },
                }
            )

        for field in (
            "supporting_signals",
            "unsupported_claims",
            "missing_pivots",
            "recommended_pivots",
        ):
            field_comparisons.append(
                {
                    "field": field,
                    "values_by_agent": {
                        agent_name: field_values.get(field)
                        for agent_name, field_values in field_matrix.items()
                    },
                }
            )

        common_items = common_value_map(
            {
                agent_name: {
                    "summary": values.get("summary"),
                    "attack_story": values.get("attack_story"),
                    "evidence_level": values.get("evidence_level"),
                }
                for agent_name, values in field_matrix.items()
            },
            ["summary", "attack_story", "evidence_level"],
        )

        mentioned_sets = [
            set(values.get("mentioned_artifacts", []))
            for values in field_matrix.values()
            if isinstance(values.get("mentioned_artifacts"), list)
        ]
        if mentioned_sets:
            common_items["mentioned_artifacts"] = sorted(set.intersection(*mentioned_sets))

        enriched_sets = [
            set(values.get("present_enriched_features", []))
            for values in field_matrix.values()
            if isinstance(values.get("present_enriched_features"), list)
        ]
        if enriched_sets:
            common_items["present_enriched_features"] = sorted(set.intersection(*enriched_sets))

        supporting_sets = [
            set(values.get("supporting_signals", []))
            for values in field_matrix.values()
            if isinstance(values.get("supporting_signals"), list)
        ]
        if supporting_sets:
            common_items["supporting_signals"] = sorted(set.intersection(*supporting_sets))

        missing_pivot_sets = [
            set(values.get("missing_pivots", []))
            for values in field_matrix.values()
            if isinstance(values.get("missing_pivots"), list)
        ]
        if missing_pivot_sets:
            common_items["missing_pivots"] = sorted(set.intersection(*missing_pivot_sets))

        notes: list[str] = [
            "field names aligned to canonical investigation comparison model",
            "evidence-aware investigation fields were normalized",
        ]
        if expected_assist:
            notes.append("optional judge assist inputs were loaded")
        if artifact_synonyms:
            notes.append("workflow artifact synonyms were applied")
        if expected_enriched_features:
            notes.append("expected enriched features were loaded")

        return {
            "stage": workflow.get("stage", "investigation"),
            "harness_run_id": harness_run_id,
            "source_run_id": source_run_id or "",
            "scenario_id": scenario_id or "",
            "generated_at": now_utc_iso(),
            "agents": list(agent_payloads.keys()),
            "rubric_context": {
                "primary_artifacts_expected": expected_artifacts,
                "expected_enriched_features": expected_enriched_features,
                "scenario_focus": (
                    ((workflow.get("compare") or {}).get("rubric_context") or {}).get(
                        "scenario_focus"
                    )
                    or scenario_id
                    or "investigation comparison"
                ),
                "notes": notes,
            },
            "common_items": common_items,
            "agent_only_items": agent_only_items,
            "missing_items": missing_items,
            "overclaimed_items": overclaimed_items,
            "field_comparisons": field_comparisons,
            "normalization_notes": notes,
        }

    must_have_keywords, nice_to_have_keywords = parse_expected_response_keywords(judge_cfg)
    expected_response_keywords = must_have_keywords + nice_to_have_keywords

    for agent_name, payload in agent_payloads.items():
        text_blob = extract_triage_text_blob(payload)
        mentioned_artifacts = extract_mentioned_artifacts(
            text_blob,
            expected_artifacts,
            workflow_synonyms=artifact_synonyms,
        )
        response_keywords = extract_response_keywords(payload, expected_response_keywords)

        field_matrix[agent_name] = {
            "verdict": get_assessment_value(payload, "verdict"),
            "confidence": get_assessment_value(payload, "confidence"),
            "priority": get_assessment_value(payload, "priority"),
            "risk_score": get_assessment_value(payload, "risk_score"),
            "summary": payload.get("summary"),
            "mentioned_artifacts": mentioned_artifacts,
            "response_keywords": response_keywords,
        }

        missing: list[str] = []
        for artifact in expected_artifacts:
            if artifact not in mentioned_artifacts:
                missing.append(f"artifact:{artifact}")
        for field in ("summary", "attack_story"):
            if not canonical_str(payload.get(field)):
                missing.append(f"field:{field}")
        for field in ("verdict", "priority"):
            if not canonical_str(get_assessment_value(payload, field)):
                missing.append(f"assessment:{field}")
        if expected_response_keywords and not response_keywords:
            missing.append("response:expected_keywords")

        missing_items[agent_name] = missing
        overclaimed_items[agent_name] = collect_forbidden_keyword_hits(
            text_blob, forbidden_claim_keywords
        )
        agent_only_items[agent_name] = {
            "captured_items": sorted(set(mentioned_artifacts + response_keywords)),
            "notable_strengths": sorted(set(mentioned_artifacts)),
            "notable_weaknesses": sorted(set(missing)),
            "raw_output_ref": (
                f"agents/{Path(payload.get('_output_ref', f'{agent_name}.json')).name}"
            ),
        }

    for field in ("summary", "verdict", "confidence", "priority"):
        field_comparisons.append(
            {
                "field": field,
                "values_by_agent": {
                    agent_name: field_values.get(field)
                    for agent_name, field_values in field_matrix.items()
                },
            }
        )

    common_items = common_value_map(
        {
            agent_name: {
                "verdict": values.get("verdict"),
                "priority": values.get("priority"),
                "confidence": values.get("confidence"),
            }
            for agent_name, values in field_matrix.items()
        },
        ["verdict", "priority", "confidence"],
    )

    mentioned_sets = [
        set(values.get("mentioned_artifacts", []))
        for values in field_matrix.values()
        if isinstance(values.get("mentioned_artifacts"), list)
    ]
    if mentioned_sets:
        common_items["mentioned_artifacts"] = sorted(set.intersection(*mentioned_sets))

    notes = ["field names aligned to canonical triage comparison model"]
    if expected_assist:
        notes.append("optional judge assist inputs were loaded")
    if artifact_synonyms:
        notes.append("workflow artifact synonyms were applied")

    return {
        "stage": workflow.get("stage", "triage"),
        "harness_run_id": harness_run_id,
        "source_run_id": source_run_id or "",
        "scenario_id": scenario_id or "",
        "generated_at": now_utc_iso(),
        "agents": list(agent_payloads.keys()),
        "rubric_context": {
            "primary_artifacts_expected": expected_artifacts,
            "scenario_focus": (
                ((workflow.get("compare") or {}).get("rubric_context") or {}).get("scenario_focus")
                or scenario_id
                or "triage comparison"
            ),
            "notes": notes,
        },
        "common_items": common_items,
        "agent_only_items": agent_only_items,
        "missing_items": missing_items,
        "overclaimed_items": overclaimed_items,
        "field_comparisons": field_comparisons,
        "normalization_notes": notes,
    }


def criterion_weight_map(rubric: dict[str, Any]) -> dict[str, float]:
    weights: dict[str, float] = {}
    for item in listify(rubric.get("criteria")):
        if not isinstance(item, dict):
            continue
        criterion_id = str(item.get("id") or "").strip()
        if criterion_id:
            weights[criterion_id] = float(item.get("weight") or 0.0)
    return weights


def score_artifact_coverage(compare_result: dict[str, Any], agent_name: str) -> tuple[float, str]:
    mentioned = listify(
        (compare_result.get("agent_only_items") or {}).get(agent_name, {}).get("notable_strengths")
    )
    expected = listify(
        (compare_result.get("rubric_context") or {}).get("primary_artifacts_expected")
    )
    if not expected:
        return 1.0, "no expected artifacts configured; treated as fully covered"
    ratio = len(set(mentioned) & set(expected)) / len(expected)
    return (
        ratio,
        f"mentioned {len(set(mentioned) & set(expected))}/{len(expected)} expected artifacts",
    )


def score_verdict_quality(
    workflow: dict[str, Any],
    expected_assist: dict[str, Any],
    payload: dict[str, Any],
) -> tuple[float, str]:
    expected_verdict = canonical_str(
        get_expected_value(workflow, expected_assist, "expected_verdict")
    )
    expected_priority = canonical_str(
        get_expected_value(workflow, expected_assist, "expected_priority")
    )
    verdict = canonical_str(get_assessment_value(payload, "verdict"))
    priority = canonical_str(get_assessment_value(payload, "priority"))

    details: list[str] = []
    score = 0.0
    checks = 0

    if expected_verdict:
        checks += 1
        if verdict and verdict.lower() == expected_verdict.lower():
            score += 1.0
            details.append("verdict matched expected")
        else:
            details.append("verdict did not match expected")

    if expected_priority:
        checks += 1
        if priority and priority.lower() == expected_priority.lower():
            score += 1.0
            details.append("priority matched expected")
        else:
            details.append("priority did not match expected")

    if checks == 0:
        present = 0
        if verdict:
            present += 1
        if priority:
            present += 1
        score = present / 2
        details.append("scored by presence because expected verdict/priority were not configured")
        return score, "; ".join(details)

    return score / checks, "; ".join(details)


def score_overclaim(compare_result: dict[str, Any], agent_name: str) -> tuple[float, str]:
    overclaims = listify((compare_result.get("overclaimed_items") or {}).get(agent_name))
    if not overclaims:
        return 1.0, "no forbidden overclaim keywords were detected"
    score = max(0.0, 1.0 - (0.25 * len(set(overclaims))))
    return score, f"forbidden-claim hits: {', '.join(str(item) for item in overclaims)}"


def score_response_fitness(workflow: dict[str, Any], payload: dict[str, Any]) -> tuple[float, str]:
    judge_cfg = workflow.get("judge") or {}
    must_have_keywords, nice_to_have_keywords = parse_expected_response_keywords(judge_cfg)
    response_text = flatten_text(
        payload.get("recommended_response") or payload.get("recommended_actions")
    ).lower()
    if must_have_keywords or nice_to_have_keywords:
        matched_must = [keyword for keyword in must_have_keywords if keyword in response_text]
        matched_nice = [keyword for keyword in nice_to_have_keywords if keyword in response_text]

        must_ratio = len(set(matched_must)) / len(must_have_keywords) if must_have_keywords else 1.0
        nice_ratio = (
            len(set(matched_nice)) / len(nice_to_have_keywords) if nice_to_have_keywords else 0.0
        )

        score = min(1.0, (0.8 * must_ratio) + (0.2 * nice_ratio))
        return score, (
            f"matched {len(set(matched_must))}/{len(must_have_keywords)} must-have "
            f"and {len(set(matched_nice))}/{len(nice_to_have_keywords)} nice-to-have "
            "response keywords"
        )

    generic_matches = [keyword for keyword in ACTION_HINT_KEYWORDS if keyword in response_text]
    if not response_text.strip():
        return 0.0, "no recommended response text"
    if generic_matches:
        return min(1.0, 0.4 + (0.15 * len(set(generic_matches)))), (
            "generic action keywords present: " + ", ".join(sorted(set(generic_matches)))
        )
    return 0.4, "response present but no expected or generic action keywords matched"


def score_investigation_evidence_coverage(
    compare_result: dict[str, Any],
    agent_name: str,
) -> tuple[float, str]:
    expected = listify(
        (compare_result.get("rubric_context") or {}).get("primary_artifacts_expected")
    )
    strengths = listify(
        (compare_result.get("agent_only_items") or {}).get(agent_name, {}).get("notable_strengths")
    )
    evidence_present = bool(
        (compare_result.get("agent_only_items") or {}).get(agent_name, {}).get("evidence_present")
    )

    if not expected:
        base = 1.0
        reason = "no expected artifacts configured; treated as fully covered"
    else:
        matched = len(set(expected) & set(strengths))
        base = matched / len(expected)
        reason = f"mentioned {matched}/{len(expected)} expected artifacts"

    score = min(1.0, (0.8 * base) + (0.2 * (1.0 if evidence_present else 0.0)))
    if evidence_present:
        reason += "; evidence field present"
    else:
        reason += "; evidence field missing"
    return score, reason


def score_investigation_enriched_feature_quality(
    compare_result: dict[str, Any],
    payload: dict[str, Any],
    agent_name: str,
) -> tuple[float, str]:
    del agent_name

    expected = listify(
        (compare_result.get("rubric_context") or {}).get("expected_enriched_features")
    )
    captured = extract_present_enriched_features(payload)

    if expected:
        matched = len(set(expected) & set(captured))
        ratio = matched / len(expected)
        return ratio, f"captured {matched}/{len(expected)} expected enriched features"

    if captured:
        score = min(1.0, 0.6 + (0.05 * len(captured)))
        return score, (f"captured {len(captured)} enriched features without explicit expectation")

    return 0.4, "no enriched features captured"


def score_investigation_timeline_grounding(payload: dict[str, Any]) -> tuple[float, str]:
    has_attack_story = bool(canonical_str(payload.get("attack_story")))
    has_investigation_notes = bool(canonical_str(payload.get("investigation_notes")))
    has_timeline_notes = bool(canonical_str(payload.get("timeline_notes")))
    has_evidence = bool(canonical_str(payload.get("evidence")))

    score = (
        0.2 * (1.0 if has_attack_story else 0.0)
        + 0.2 * (1.0 if has_investigation_notes else 0.0)
        + 0.2 * (1.0 if has_timeline_notes else 0.0)
        + 0.4 * (1.0 if has_evidence else 0.0)
    )

    parts = []
    if has_attack_story:
        parts.append("attack_story present")
    if has_investigation_notes:
        parts.append("investigation_notes present")
    if has_timeline_notes:
        parts.append("timeline_notes present")
    if has_evidence:
        parts.append("evidence present")
    return score, "; ".join(parts) if parts else "no timeline-grounding fields present"


def score_evidence_quality(payload: dict[str, Any]) -> tuple[float, str]:
    evidence_level = extract_evidence_level(payload)
    evidence_summary = extract_evidence_summary(payload)
    observed_facts = extract_string_list(evidence_summary.get("observed_facts"))
    supporting_signals = extract_string_list(evidence_summary.get("supporting_signals"))
    evidence_gaps = extract_string_list(evidence_summary.get("evidence_gaps"))
    confidence_rationale = canonical_str(evidence_summary.get("confidence_rationale"))

    score = 0.0
    notes: list[str] = []

    if evidence_level:
        score += 0.2
        notes.append(f"evidence_level={evidence_level}")
    if evidence_summary:
        score += 0.1
        notes.append("evidence_summary present")
    if observed_facts:
        score += 0.2
        notes.append(f"{len(observed_facts)} observed_facts")
    if supporting_signals:
        score += 0.2
        notes.append(f"{len(supporting_signals)} supporting_signals")
    if "evidence_gaps" in evidence_summary:
        score += 0.15
        notes.append(f"{len(evidence_gaps)} evidence_gaps")
    if confidence_rationale:
        score += 0.15
        notes.append("confidence_rationale present")

    if evidence_level == "strong" and len(evidence_gaps) >= 2:
        score = max(0.0, score - 0.15)
        notes.append("strong level with multiple remaining gaps")

    return min(1.0, score), "; ".join(notes) or "evidence-aware fields missing"


def score_unsupported_claim_control(
    compare_result: dict[str, Any],
    payload: dict[str, Any],
    agent_name: str,
) -> tuple[float, str]:
    claims_raw = payload.get("unsupported_claims")
    claims = listify(claims_raw) if isinstance(claims_raw, list) else []
    valid_claims = 0

    for item in claims:
        if not isinstance(item, dict):
            continue
        if canonical_str(item.get("claim")) and canonical_str(item.get("reason")):
            valid_claims += 1

    overclaim_score, overclaim_reason = score_overclaim(compare_result, agent_name)

    if not isinstance(claims_raw, list):
        score = 0.3 * overclaim_score
        return score, f"unsupported_claims missing; {overclaim_reason}"

    if not claims:
        score = 0.6 if overclaim_score >= 1.0 else 0.3
        return score, f"unsupported_claims present but empty; {overclaim_reason}"

    structure_score = 0.8 if valid_claims == len(claims) else 0.6
    score = min(1.0, structure_score + (0.2 * overclaim_score))
    return score, (f"unsupported_claims present with {len(claims)} entry(ies); {overclaim_reason}")


def score_missing_pivot_detection(
    compare_result: dict[str, Any],
    payload: dict[str, Any],
    agent_name: str,
) -> tuple[float, str]:
    missing_raw = payload.get("missing_pivots")
    recommended_raw = payload.get("recommended_pivots")
    missing_pivots = extract_named_entries(payload, "missing_pivots", "pivot")
    recommended_pivots = extract_named_entries(
        payload,
        "recommended_pivots",
        "pivot",
    )

    combined_text = " ".join(missing_pivots + recommended_pivots).lower()
    agent_items = (compare_result.get("agent_only_items") or {}).get(agent_name, {})
    if not isinstance(agent_items, dict):
        agent_items = {}

    captured_items = {
        str(item) for item in listify(agent_items.get("captured_items")) if str(item).strip()
    }
    enriched = {
        str(item)
        for item in listify(agent_items.get("notable_enriched_features"))
        if str(item).strip()
    }

    expectation_groups: list[tuple[str, tuple[str, ...]]] = []

    if "ssh_key_login" in captured_items:
        expectation_groups.append(
            (
                "login context",
                (
                    "validate_login_context",
                    "validate_ssh_key_login_context",
                    "login_context",
                ),
            )
        )

    if (
        "temporary_path_execution_observed" in enriched
        or "process_chain_confirmed" in enriched
        or "process_exec" in captured_items
    ):
        expectation_groups.append(
            (
                "payload or command context",
                (
                    "inspect_payload_or_command_context",
                    "inspect_temp_path_artifact",
                    "inspect_representative_command",
                ),
            )
        )

    if "download_utility_observed" in enriched:
        expectation_groups.append(
            (
                "remote retrieval context",
                (
                    "confirm_remote_retrieval_context",
                    "validate_download_activity",
                ),
            )
        )

    if not expectation_groups:
        present_fields = 0
        if isinstance(missing_raw, list):
            present_fields += 1
        if isinstance(recommended_raw, list):
            present_fields += 1
        score = min(1.0, 0.3 + (0.3 * present_fields))
        return score, (
            f"{present_fields}/2 pivot field(s) were present without stage-specific expectations"
        )

    matched_groups: list[str] = []
    for label, keywords in expectation_groups:
        if any(keyword in combined_text for keyword in keywords):
            matched_groups.append(label)

    ratio = len(matched_groups) / len(expectation_groups)
    score = 0.8 * ratio
    if isinstance(missing_raw, list):
        score += 0.1
    if isinstance(recommended_raw, list):
        score += 0.1

    return min(1.0, score), (
        f"matched {len(matched_groups)}/{len(expectation_groups)} expected "
        f"pivot groups: {', '.join(matched_groups) if matched_groups else 'none'}"
    )


SPECIFICITY_COMMAND_PATTERN = re.compile(
    r"(?:^|[\s\"'(/])(?:curl|chmod|bash|whoami|hostname|uname|id)(?=$|[\s\"').;/])"
)
SPECIFICITY_PATH_PATTERN = re.compile(r"/(?:tmp|var/tmp|dev/shm|bin|usr/bin)/[^\s\"']+")
SPECIFICITY_URL_PATTERN = re.compile(r"https?://[^\s\"']+")


def collect_specificity_texts(
    compare_result: dict[str, Any],
    payload: dict[str, Any],
    agent_name: str,
) -> list[str]:
    texts: list[str] = []
    agent_items = (compare_result.get("agent_only_items") or {}).get(agent_name, {})
    if isinstance(agent_items, dict):
        for key in (
            "captured_items",
            "notable_strengths",
            "notable_enriched_features",
            "supporting_signals",
        ):
            texts.extend(str(item) for item in listify(agent_items.get(key)) if str(item).strip())

    evidence_summary = payload.get("evidence_summary")
    if isinstance(evidence_summary, dict):
        for key in ("observed_facts", "supporting_signals"):
            texts.extend(
                str(item) for item in listify(evidence_summary.get(key)) if str(item).strip()
            )

    for item in listify((compare_result.get("common_items") or {}).get("supporting_signals")):
        if str(item).strip():
            texts.append(str(item))

    for comparison in listify(compare_result.get("field_comparisons")):
        if not isinstance(comparison, dict):
            continue
        if comparison.get("field") not in {"supporting_signals", "evidence_summary"}:
            continue
        texts.append(flatten_text(comparison.get("values_by_agent")))

    return texts


def has_specific_command(text: str) -> bool:
    return bool(SPECIFICITY_COMMAND_PATTERN.search(text) or "/bin/bash" in text)


def has_specific_path(text: str) -> bool:
    return bool(SPECIFICITY_PATH_PATTERN.search(text))


def has_specific_url(text: str) -> bool:
    return bool(SPECIFICITY_URL_PATTERN.search(text))


def concrete_specificity_hits(texts: list[str]) -> list[str]:
    hits: list[str] = []

    for raw_text in texts:
        text = raw_text.strip()
        if not text:
            continue
        lowered = text.lower()

        if lowered.startswith("endpoint telemetry observed command execution") and ":" in text:
            command_detail = text.split(":", 1)[1].strip()
            # The normalized process_exec fact is already a bounded command-line
            # source. Treat its non-empty detail as specific without maintaining a
            # platform-specific executable allowlist in the shared harness.
            if command_detail:
                hits.append("command/path/url evidence from endpoint telemetry")

        if has_specific_command(text):
            hits.append("concrete command evidence")
        if has_specific_path(text):
            hits.append("concrete path evidence")
        if has_specific_url(text):
            hits.append("concrete URL evidence")

    return sorted(set(hits))


def score_evidence_specificity(
    compare_result: dict[str, Any],
    payload: dict[str, Any],
    agent_name: str,
) -> tuple[float, str]:
    agent_items = (compare_result.get("agent_only_items") or {}).get(agent_name, {})
    if not isinstance(agent_items, dict):
        return 0.0, "agent comparison details were missing"

    enriched = {
        str(item)
        for item in listify(agent_items.get("notable_enriched_features"))
        if str(item).strip()
    }
    evidence_present = bool(agent_items.get("evidence_present"))

    specificity_signals = {
        "process_chain_confirmed",
        "download_utility_observed",
        "temporary_path_execution_observed",
        "permission_change_observed",
        "execution_flow_context_observed",
        "shell_execution_observed",
    }

    matched = sorted(enriched & specificity_signals)
    concrete_hits = concrete_specificity_hits(
        collect_specificity_texts(compare_result, payload, agent_name)
    )
    all_hits = sorted(set(matched + concrete_hits))

    if not evidence_present:
        return 0.0, "no evidence fields were present"

    if not all_hits:
        return 0.4, "evidence was present but no concrete specificity signals were captured"

    score = min(1.0, 0.4 + (0.1 * len(all_hits)))
    return score, f"specificity hits: {', '.join(all_hits)}"


def score_next_step_fitness(
    compare_result: dict[str, Any],
    payload: dict[str, Any],
    agent_name: str,
) -> tuple[float, str]:
    steps = listify(payload.get("recommended_next_steps"))
    if not steps:
        return 0.0, "no recommended_next_steps were provided"

    text = flatten_text(steps).lower()
    agent_items = (compare_result.get("agent_only_items") or {}).get(agent_name, {})
    if not isinstance(agent_items, dict):
        agent_items = {}

    captured_items = {
        str(item) for item in listify(agent_items.get("captured_items")) if str(item).strip()
    }
    enriched = {
        str(item)
        for item in listify(agent_items.get("notable_enriched_features"))
        if str(item).strip()
    }

    expectation_groups: list[tuple[str, tuple[str, ...]]] = []

    if "ssh_key_login" in captured_items:
        expectation_groups.append(
            (
                "authentication context",
                ("authentication", "account", "ssh", "public key", "login"),
            )
        )

    if "process_chain_confirmed" in enriched or "execution_flow_context_observed" in enriched:
        expectation_groups.append(
            (
                "process chain context",
                ("chain", "parent", "execution context", "sequence", "flow"),
            )
        )

    if "temporary_path_execution_observed" in enriched:
        expectation_groups.append(
            (
                "temporary-path validation",
                ("temporary", "/tmp", "file", "script"),
            )
        )

    if "download_utility_observed" in enriched:
        expectation_groups.append(
            (
                "download activity validation",
                ("download", "remote", "retrieval", "payload"),
            )
        )

    if not expectation_groups:
        count_score = min(1.0, 0.4 + 0.1 * len(steps))
        return count_score, (
            f"{len(steps)} follow-up step(s) were present without stage-specific expectations"
        )

    matched_groups: list[str] = []
    for label, keywords in expectation_groups:
        if any(keyword in text for keyword in keywords):
            matched_groups.append(label)

    ratio = len(matched_groups) / len(expectation_groups)
    score = 0.15 + (0.7 * ratio)

    specificity_hits: list[str] = []
    specificity_checks = {
        "expected source validation": (
            "expected source" in text or "retrieved content" in text or "source, purpose" in text
        ),
        "permission-change validation": "permission-change" in text,
        "login expectation validation": (
            "expected for the affected account" in text or "expected login context" in text
        ),
    }

    for label, matched in specificity_checks.items():
        if matched:
            specificity_hits.append(label)

    score += min(0.15, 0.05 * len(specificity_hits))

    return min(1.0, score), (
        f"matched {len(matched_groups)}/{len(expectation_groups)} expected "
        f"follow-up groups; specificity hits: "
        + (", ".join(specificity_hits) if specificity_hits else "none")
    )


def build_strengths_and_weaknesses(
    criterion_scores: dict[str, dict[str, Any]],
    compare_result: dict[str, Any],
    agent_name: str,
    stage: str = "triage",
) -> tuple[list[str], list[str], list[str]]:
    strengths: list[str] = []
    weaknesses: list[str] = []
    candidate_hints: list[str] = []

    for criterion_id, info in criterion_scores.items():
        score = float(info["score"])
        reason = str(info["reason"])
        if score >= 0.8:
            strengths.append(f"{criterion_id}: {reason}")
        elif score < 0.6:
            weaknesses.append(f"{criterion_id}: {reason}")

    missing = listify((compare_result.get("missing_items") or {}).get(agent_name))
    if missing:
        weaknesses.append(f"missing items: {', '.join(str(item) for item in missing)}")
        if stage == "investigation":
            if any(str(item).startswith("artifact:") for item in missing):
                candidate_hints.append("improve artifact-aware evidence and attack story grounding")
            if any(str(item).startswith("enriched_feature:") for item in missing):
                candidate_hints.append("improve evidence-grounded enriched feature generation")
            if any(
                str(item)
                in {
                    "field:evidence_level",
                    "field:evidence_summary",
                }
                for item in missing
            ):
                candidate_hints.append("improve evidence-aware investigation field generation")
            if any(
                str(item)
                in {
                    "field:unsupported_claims",
                    "field:missing_pivots",
                    "field:recommended_pivots",
                }
                for item in missing
            ):
                candidate_hints.append("improve unsupported-claim and pivot reasoning")
            if any("timeline" in str(item) for item in missing):
                candidate_hints.append("improve timeline-grounded investigation notes")
        else:
            if any(str(item).startswith("artifact:") for item in missing):
                candidate_hints.append("improve artifact-aware summary and attack story generation")
            if any(str(item).startswith("response:") for item in missing):
                candidate_hints.append("tighten scenario-aware recommended response generation")

    overclaims = listify((compare_result.get("overclaimed_items") or {}).get(agent_name))
    if overclaims:
        candidate_hints.append("tighten overclaim guardrails in prompt or rule layer")

    if not strengths:
        default_strength = (
            "runner completed and produced a structured investigation output"
            if stage == "investigation"
            else "runner completed and produced a structured triage output"
        )
        strengths.append(default_strength)
    if not weaknesses:
        weaknesses.append("no major weakness detected by the current deterministic judge")
    if not candidate_hints:
        candidate_hints.append("no immediate improvement hint generated")

    return strengths, weaknesses, sorted(set(candidate_hints))


def friendly_gap_name(criterion_id: str) -> str:
    mapping = {
        "artifact_coverage": "artifact coverage",
        "verdict_quality": "verdict quality",
        "response_fitness": "response specificity",
        "evidence_coverage": "evidence coverage",
        "evidence_quality": "evidence quality",
        "enriched_feature_quality": "enriched feature quality",
        "timeline_grounding": "timeline grounding",
        "overclaim_control": "overclaim control",
        "unsupported_claim_control": "unsupported-claim control",
        "evidence_specificity": "evidence specificity",
        "missing_pivot_detection": "missing-pivot detection",
        "next_step_fitness": "next-step fitness",
    }
    return mapping.get(criterion_id, criterion_id.replace("_", " "))


def extract_weight_from_notes(notes: str) -> float:
    match = re.search(r"weight=([0-9.]+)", notes)
    if not match:
        return 0.0
    try:
        return float(match.group(1))
    except ValueError:
        return 0.0


def build_judge_result(
    workflow: dict[str, Any],
    rubric: dict[str, Any],
    compare_result: dict[str, Any],
    expected_assist: dict[str, Any],
    agent_payloads: dict[str, dict[str, Any]],
    source_run_id: str | None,
    scenario_id: str | None,
) -> dict[str, Any]:
    stage = str(workflow.get("stage") or "triage").strip().lower()
    weights = criterion_weight_map(rubric)
    pass_threshold = float(
        (workflow.get("judge") or {}).get("pass_threshold") or rubric.get("pass_threshold") or 0.70
    )

    results: list[dict[str, Any]] = []
    best_agent_name: str | None = None
    best_score = -1.0
    most_stable: tuple[str | None, float] = (None, -1.0)

    for agent_name, payload in agent_payloads.items():
        if stage == "investigation":
            criterion_scores = {
                "evidence_coverage": {},
                "evidence_quality": {},
                "enriched_feature_quality": {},
                "timeline_grounding": {},
                "overclaim_control": {},
                "unsupported_claim_control": {},
                "evidence_specificity": {},
                "missing_pivot_detection": {},
                "next_step_fitness": {},
            }

            evidence_score, evidence_reason = score_investigation_evidence_coverage(
                compare_result,
                agent_name,
            )
            evidence_quality_score, evidence_quality_reason = score_evidence_quality(payload)
            enriched_score, enriched_reason = score_investigation_enriched_feature_quality(
                compare_result,
                payload,
                agent_name,
            )
            timeline_score, timeline_reason = score_investigation_timeline_grounding(payload)
            overclaim_score, overclaim_reason = score_overclaim(
                compare_result,
                agent_name,
            )
            unsupported_score, unsupported_reason = score_unsupported_claim_control(
                compare_result,
                payload,
                agent_name,
            )
            specificity_score, specificity_reason = score_evidence_specificity(
                compare_result,
                payload,
                agent_name,
            )
            missing_pivot_score, missing_pivot_reason = score_missing_pivot_detection(
                compare_result,
                payload,
                agent_name,
            )
            next_step_score, next_step_reason = score_next_step_fitness(
                compare_result,
                payload,
                agent_name,
            )

            criterion_scores["evidence_coverage"] = {
                "score": evidence_score,
                "reason": evidence_reason,
            }
            criterion_scores["evidence_quality"] = {
                "score": evidence_quality_score,
                "reason": evidence_quality_reason,
            }
            criterion_scores["enriched_feature_quality"] = {
                "score": enriched_score,
                "reason": enriched_reason,
            }
            criterion_scores["timeline_grounding"] = {
                "score": timeline_score,
                "reason": timeline_reason,
            }
            criterion_scores["overclaim_control"] = {
                "score": overclaim_score,
                "reason": overclaim_reason,
            }
            criterion_scores["unsupported_claim_control"] = {
                "score": unsupported_score,
                "reason": unsupported_reason,
            }
            criterion_scores["evidence_specificity"] = {
                "score": specificity_score,
                "reason": specificity_reason,
            }
            criterion_scores["missing_pivot_detection"] = {
                "score": missing_pivot_score,
                "reason": missing_pivot_reason,
            }
            criterion_scores["next_step_fitness"] = {
                "score": next_step_score,
                "reason": next_step_reason,
            }
        else:
            criterion_scores = {
                "artifact_coverage": {},
                "verdict_quality": {},
                "overclaim_control": {},
                "response_fitness": {},
            }

            artifact_score, artifact_reason = score_artifact_coverage(compare_result, agent_name)
            verdict_score, verdict_reason = score_verdict_quality(
                workflow, expected_assist, payload
            )
            overclaim_score, overclaim_reason = score_overclaim(compare_result, agent_name)
            response_score, response_reason = score_response_fitness(workflow, payload)

            criterion_scores["artifact_coverage"] = {
                "score": artifact_score,
                "reason": artifact_reason,
            }
            criterion_scores["verdict_quality"] = {
                "score": verdict_score,
                "reason": verdict_reason,
            }
            criterion_scores["overclaim_control"] = {
                "score": overclaim_score,
                "reason": overclaim_reason,
            }
            criterion_scores["response_fitness"] = {
                "score": response_score,
                "reason": response_reason,
            }

        total_score = 0.0
        for criterion_id, info in criterion_scores.items():
            total_score += float(info["score"]) * float(weights.get(criterion_id, 0.0))

        strengths, weaknesses, candidate_hints = build_strengths_and_weaknesses(
            criterion_scores,
            compare_result,
            agent_name,
            stage=stage,
        )
        passed = total_score >= pass_threshold

        criterion_scores_array = [
            {
                "criterion_id": criterion_id,
                "score": round(float(info["score"]), 4),
                "notes": (
                    f"{info['reason']} (weight={round(float(weights.get(criterion_id, 0.0)), 4)})"
                ),
            }
            for criterion_id, info in criterion_scores.items()
        ]

        result = {
            "agent_name": agent_name,
            "score": round(total_score, 4),
            "pass": passed,
            "criterion_scores": criterion_scores_array,
            "strengths": strengths,
            "weaknesses": weaknesses,
            "candidate_hints": candidate_hints,
        }
        results.append(result)

        if total_score > best_score:
            best_score = total_score
            best_agent_name = agent_name

        overclaim_score = float(
            next(
                info["score"]
                for cid, info in criterion_scores.items()
                if cid == "overclaim_control"
            )
        )
        if overclaim_score > most_stable[1]:
            most_stable = (agent_name, overclaim_score)

    judge_cfg = workflow.get("judge") or {}
    default_rubric_id = "investigation_rubric" if stage == "investigation" else "triage_rubric"
    rubric_id = str(
        judge_cfg.get("rubric_id")
        or rubric.get("rubric_id")
        or rubric.get("name")
        or default_rubric_id
    )

    judge_summary = {
        "best_balance": best_agent_name,
        "most_stable": most_stable[0],
        "main_gap": infer_main_gap(results, stage=stage),
        "notes": [
            "core judge input: compare + rubric",
            "optional assist input was used"
            if expected_assist
            else "no optional assist input was used",
        ],
    }

    return {
        "stage": workflow.get("stage", stage),
        "source_run_id": source_run_id or "",
        "scenario_id": scenario_id or "",
        "rubric_id": rubric_id,
        "results": results,
        "winner": best_agent_name,
        "judge_summary": judge_summary,
        "generated_at": now_utc_iso(),
    }


def infer_main_gap(results: list[dict[str, Any]], stage: str = "triage") -> str:
    del stage

    weakness_counter: dict[str, int] = {}
    criterion_deficits: dict[str, float] = {}
    criterion_raw_deficits: dict[str, float] = {}

    for result in results:
        for weakness in listify(result.get("weaknesses")):
            text = str(weakness).lower()
            if not text or "no major weakness detected by the current deterministic judge" in text:
                continue

            if "artifact_coverage" in text or "artifact:" in text:
                gap = "artifact coverage"
            elif "response" in text:
                gap = "response specificity"
            elif "overclaim" in text:
                gap = "overclaim control"
            elif "verdict" in text or "priority" in text:
                gap = "verdict quality"
            elif "evidence_quality" in text or "field:evidence_level" in text:
                gap = "evidence quality"
            elif "unsupported_claim" in text or "field:unsupported_claims" in text:
                gap = "unsupported-claim control"
            elif "missing_pivot" in text or "field:missing_pivots" in text:
                gap = "missing-pivot detection"
            elif "enriched_feature" in text or "enriched_feature_quality" in text:
                gap = "enriched feature quality"
            elif "next_step" in text or "follow-up groups" in text:
                gap = "next-step fitness"
            elif "specificity" in text:
                gap = "evidence specificity"
            elif "timeline" in text:
                gap = "timeline grounding"
            else:
                gap = text

            weakness_counter[gap] = weakness_counter.get(gap, 0) + 1

        for criterion in listify(result.get("criterion_scores")):
            if not isinstance(criterion, dict):
                continue

            criterion_id = str(criterion.get("criterion_id") or "").strip()
            if not criterion_id:
                continue

            try:
                score = float(criterion.get("score") or 0.0)
            except (TypeError, ValueError):
                continue

            deficit = max(0.0, 1.0 - score)
            if deficit <= 0.0:
                continue

            notes = str(criterion.get("notes") or "")
            weight = extract_weight_from_notes(notes)
            friendly = friendly_gap_name(criterion_id)

            criterion_deficits[friendly] = criterion_deficits.get(friendly, 0.0) + (
                deficit * max(weight, 0.01)
            )
            criterion_raw_deficits[friendly] = criterion_raw_deficits.get(friendly, 0.0) + deficit

    if weakness_counter:
        return max(weakness_counter.items(), key=lambda item: item[1])[0]

    if criterion_deficits:
        return max(
            criterion_deficits.items(),
            key=lambda item: (
                item[1],
                criterion_raw_deficits.get(item[0], 0.0),
                item[0],
            ),
        )[0]

    return "no dominant gap detected by the current deterministic judge"


def render_summary_md(
    workflow: dict[str, Any],
    compare_result: dict[str, Any],
    judge_result: dict[str, Any],
    metadata: dict[str, Any],
    agent_execution_results: list[AgentExecutionResult],
    compare_validation_errors: list[str],
    judge_validation_errors: list[str],
) -> str:
    lines: list[str] = []
    stage_label = str(compare_result.get("stage") or workflow.get("stage") or "stage").strip()
    stage_title = stage_label.capitalize() if stage_label else "Stage"
    lines.append(f"# {stage_title} Harness Summary: {workflow.get('name', 'stage_harness')}")
    lines.append("")
    lines.append(f"- Stage: {compare_result.get('stage')}")
    lines.append(f"- Harness run id: {metadata.get('harness_run_id')}")
    lines.append(f"- Source run id: {compare_result.get('source_run_id')}")
    lines.append(f"- Scenario id: {compare_result.get('scenario_id')}")
    lines.append(f"- Winner: {judge_result.get('winner')}")
    lines.append(f"- Rubric id: {judge_result.get('rubric_id')}")
    lines.append("")

    lines.append("## Agent versions")
    lines.append("")
    for agent_name, agent_version in (metadata.get("agent_versions") or {}).items():
        prompt_version = (metadata.get("prompt_versions") or {}).get(agent_name)
        rule_version = (metadata.get("rule_versions") or {}).get(agent_name)
        parts = [f"agent={agent_version}"] if agent_version else []
        if prompt_version:
            parts.append(f"prompt={prompt_version}")
        if rule_version:
            parts.append(f"rule={rule_version}")
        lines.append(f"- {agent_name}: {', '.join(parts) if parts else 'version not specified'}")
    lines.append("")

    lines.append("## Agent executions")
    lines.append("")
    for item in agent_execution_results:
        status = (
            "skipped"
            if item.skipped
            else ("ok" if item.returncode == 0 else f"failed ({item.returncode})")
        )
        lines.append(f"- {item.name}: {status}")
    lines.append("")

    lines.append("## Judge inputs")
    lines.append("")
    lines.append("- Core: compare.json + rubric")
    expected_refs = metadata.get("judge_optional_assist_refs") or {}
    if expected_refs:
        lines.append("- Optional assist:")
        for key, value in expected_refs.items():
            lines.append(f"  - {key}: {value}")
    else:
        lines.append("- Optional assist: not provided")
    lines.append("")

    lines.append("## Judge results")
    lines.append("")
    for result in judge_result.get("results", []):
        lines.append(f"### {result['agent_name']}")
        lines.append(f"- Score: {result['score']}")
        lines.append(f"- Pass: {result['pass']}")
        strengths = listify(result.get("strengths"))
        weaknesses = listify(result.get("weaknesses"))
        hints = listify(result.get("candidate_hints"))
        if strengths:
            lines.append("- Strengths:")
            for item in strengths:
                lines.append(f"  - {item}")
        if weaknesses:
            lines.append("- Weaknesses:")
            for item in weaknesses:
                lines.append(f"  - {item}")
        if hints:
            lines.append("- Candidate hints:")
            for item in hints:
                lines.append(f"  - {item}")
        lines.append("")

    if compare_validation_errors or judge_validation_errors:
        lines.append("## Validation")
        lines.append("")
        if compare_validation_errors:
            lines.append("### compare schema")
            for err in compare_validation_errors:
                lines.append(f"- {err}")
        if judge_validation_errors:
            lines.append("### judge schema")
            for err in judge_validation_errors:
                lines.append(f"- {err}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=("Run a triage comparison harness and generate compare/judge outputs.")
    )
    parser.add_argument(
        "--workflow", required=True, help="Path to the triage harness workflow YAML."
    )
    parser.add_argument(
        "--rubric",
        help="Optional rubric path. Defaults to workflow judge.rubric or judge.rubric_file.",
    )
    parser.add_argument(
        "--harness-run-id",
        help="Explicit harness run id. Defaults to a timestamp-based id.",
    )
    parser.add_argument(
        "--output-dir",
        help="Optional output directory. Defaults to data/harness_runs/<harness_run_id>.",
    )
    parser.add_argument("--incident", help="Optional incident path override.")
    parser.add_argument(
        "--skip-agent-run",
        action="store_true",
        help="Do not execute agents; reuse existing agent outputs if present.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Render commands and output paths without executing agents.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    workflow_path = Path(args.workflow).resolve()
    if not workflow_path.exists():
        raise HarnessError(f"workflow file not found: {workflow_path}")

    repo_root = resolve_repo_root(workflow_path)
    workflow = load_yaml(workflow_path)

    stage = validate_stage(str(workflow.get("stage") or "triage"))

    rubric_path = Path(args.rubric).resolve() if args.rubric else None
    if rubric_path is None:
        judge_cfg = workflow.get("judge") or {}
        rubric_ref = judge_cfg.get("rubric") or judge_cfg.get("rubric_file")
        if not rubric_ref:
            raise HarnessError(
                "workflow judge.rubric or judge.rubric_file is required unless --rubric is provided"
            )
        rubric_path = Path(str(rubric_ref))
        if not rubric_path.is_absolute():
            rubric_path = (repo_root / rubric_path).resolve()
    if not rubric_path.exists():
        raise HarnessError(f"rubric file not found: {rubric_path}")
    rubric = load_yaml(rubric_path)

    harness_run_id = args.harness_run_id or str(
        workflow.get("harness_run_id")
        or f"{stage}-harness-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    output_dir = (
        Path(args.output_dir).resolve()
        if args.output_dir
        else (repo_root / "data" / "harness_runs" / harness_run_id)
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    agents_dir = output_dir / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)

    required_input_paths = resolve_input_artifact_refs(
        workflow=workflow,
        repo_root=repo_root,
        output_dir=output_dir,
        stage=stage,
        incident_override=args.incident,
    )
    optional_input_paths = resolve_optional_input_artifact_refs(
        workflow=workflow,
        repo_root=repo_root,
        output_dir=output_dir,
    )

    incident_path = required_input_paths["incident"]
    incident_raw = load_json(incident_path)
    incident = normalize_incident_payload(incident_raw)

    source_run_id = (
        str(
            workflow.get("source_run_id")
            or incident.get("run_id")
            or incident.get("attack_id")
            or ""
        )
        or None
    )
    scenario_id = (
        str(
            workflow.get("scenario_id")
            or incident.get("scenario_id")
            or incident.get("scenario_name")
            or ""
        )
        or None
    )

    expected_assist, judge_expected_refs = load_optional_expected_assist(
        repo_root, workflow, output_dir
    )

    agents_cfg = workflow.get("agents")
    if not isinstance(agents_cfg, list) or not agents_cfg:
        raise HarnessError("workflow agents[] is required")

    agent_execution_results: list[AgentExecutionResult] = []
    agent_payloads: dict[str, dict[str, Any]] = {}
    agent_versions: dict[str, str] = {}
    prompt_versions: dict[str, str] = {}
    rule_versions: dict[str, str] = {}
    agent_origins: dict[str, str] = {}
    output_refs: dict[str, str] = {}

    for agent_cfg in agents_cfg:
        if not isinstance(agent_cfg, dict):
            raise HarnessError("each agent entry must be an object")

        agent_name = slugify(str(agent_cfg.get("name") or "agent"))
        output_path = resolve_output_path(agent_cfg, output_dir)

        execution_result = execute_agent(
            repo_root=repo_root,
            agent_cfg=agent_cfg,
            required_input_paths=required_input_paths,
            optional_input_paths=optional_input_paths,
            output_path=output_path,
            harness_run_dir=output_dir,
            source_run_id=source_run_id,
            scenario_id=scenario_id,
            dry_run=args.dry_run,
            skip_agent_run=args.skip_agent_run,
        )
        agent_execution_results.append(execution_result)

        if not args.dry_run and not output_path.exists():
            raise HarnessError(
                f"agent output was not created for agent={agent_name}: {output_path}\n"
                f"command={' '.join(execution_result.command)}"
            )
        if output_path.exists():
            payload = ensure_object(load_json(output_path), f"agent output {output_path}")
            payload["_output_ref"] = str(output_path.relative_to(output_dir))
            agent_payloads[agent_name] = payload

        if agent_cfg.get("agent_version"):
            agent_versions[agent_name] = str(agent_cfg["agent_version"])
        if agent_cfg.get("prompt_version"):
            prompt_versions[agent_name] = str(agent_cfg["prompt_version"])
        if agent_cfg.get("rule_version"):
            rule_versions[agent_name] = str(agent_cfg["rule_version"])
        if agent_cfg.get("origin"):
            agent_origins[agent_name] = str(agent_cfg["origin"])
        output_refs[agent_name] = str(output_path.relative_to(output_dir))

    compare_result = build_compare_result(
        workflow=workflow,
        incident=incident,
        expected_assist=expected_assist,
        harness_run_id=harness_run_id,
        source_run_id=source_run_id,
        scenario_id=scenario_id,
        agent_payloads=agent_payloads,
    )
    compare_rel = str(((workflow.get("compare") or {}).get("output")) or "compare.json")
    compare_path = (
        (output_dir / compare_rel).resolve()
        if not Path(compare_rel).is_absolute()
        else Path(compare_rel)
    )
    dump_json(compare_path, compare_result)

    judge_result = build_judge_result(
        workflow=workflow,
        rubric=rubric,
        compare_result=compare_result,
        expected_assist=expected_assist,
        agent_payloads=agent_payloads,
        source_run_id=source_run_id,
        scenario_id=scenario_id,
    )
    judge_rel = str(((workflow.get("judge") or {}).get("output")) or "judge_result.json")
    judge_path = (
        (output_dir / judge_rel).resolve() if not Path(judge_rel).is_absolute() else Path(judge_rel)
    )
    dump_json(judge_path, judge_result)

    compare_schema_ref = (workflow.get("compare") or {}).get("schema")
    judge_schema_ref = (workflow.get("judge") or {}).get("schema")

    compare_schema_path = (
        (
            (repo_root / str(compare_schema_ref)).resolve()
            if compare_schema_ref and not Path(str(compare_schema_ref)).is_absolute()
            else Path(str(compare_schema_ref)).resolve()
        )
        if compare_schema_ref
        else detect_schema_path(
            repo_root, "schemas/compare_schema.json", "schemas/compare.schema.json"
        )
    )

    judge_schema_path = (
        (
            (repo_root / str(judge_schema_ref)).resolve()
            if judge_schema_ref and not Path(str(judge_schema_ref)).is_absolute()
            else Path(str(judge_schema_ref)).resolve()
        )
        if judge_schema_ref
        else detect_schema_path(
            repo_root,
            "schemas/judge_result_schema.json",
            "schemas/judge_result.schema.json",
        )
    )

    compare_validation_errors = try_validate_json(compare_result, compare_schema_path)
    judge_validation_errors = try_validate_json(judge_result, judge_schema_path)

    metadata_defaults = workflow.get("metadata_defaults") or {}
    if metadata_defaults and not isinstance(metadata_defaults, dict):
        raise HarnessError("workflow metadata_defaults must be an object")

    default_schema_versions = metadata_defaults.get("schema_versions") or {}
    default_rule_versions = metadata_defaults.get("rule_versions") or {}
    if default_schema_versions and not isinstance(default_schema_versions, dict):
        raise HarnessError("metadata_defaults.schema_versions must be an object")
    if default_rule_versions and not isinstance(default_rule_versions, dict):
        raise HarnessError("metadata_defaults.rule_versions must be an object")

    schema_versions = {
        "compare": default_schema_versions.get("compare")
        or (compare_schema_path.name if compare_schema_path else None),
        "judge_result": default_schema_versions.get("judge_result")
        or (judge_schema_path.name if judge_schema_path else None),
    }

    merged_rule_versions = {str(k): str(v) for k, v in default_rule_versions.items()}
    merged_rule_versions.update(rule_versions)

    metadata = {
        "harness_run_id": harness_run_id,
        "stage": stage,
        "generated_at": now_utc_iso(),
        "source_run_id": source_run_id,
        "scenario_id": scenario_id,
        "workflow_path": str(workflow_path),
        "rubric_id": judge_result.get("rubric_id"),
        "incident_path": str(incident_path),
        "input_artifact_refs": {
            key: str(path.relative_to(output_dir)) for key, path in required_input_paths.items()
        },
        "optional_input_refs": {
            key: str(path.relative_to(output_dir)) for key, path in optional_input_paths.items()
        },
        "compare_path": str(compare_path),
        "judge_path": str(judge_path),
        "schema_versions": schema_versions,
        "compare_schema_path": str(compare_schema_path) if compare_schema_path else None,
        "judge_schema_path": str(judge_schema_path) if judge_schema_path else None,
        "agent_versions": agent_versions,
        "prompt_versions": prompt_versions,
        "rule_versions": merged_rule_versions,
        "agent_origins": agent_origins,
        "agent_output_refs": output_refs,
        "judge_inputs": {
            "core": {
                "compare": str(compare_path.relative_to(output_dir)),
                "rubric": str(rubric_path.relative_to(repo_root))
                if rubric_path.is_absolute()
                else str(rubric_path),
            },
            "optional_assist_present": bool(expected_assist),
        },
        "judge_optional_assist_refs": judge_expected_refs,
        "compare_validation_errors": compare_validation_errors,
        "judge_validation_errors": judge_validation_errors,
        "agent_runs": [
            {
                "name": item.name,
                "command": item.command,
                "returncode": item.returncode,
                "output_path": str(item.output_path),
                "stdout_log": str(item.stdout_log) if item.stdout_log else None,
                "stderr_log": str(item.stderr_log) if item.stderr_log else None,
                "skipped": item.skipped,
            }
            for item in agent_execution_results
        ],
    }
    metadata_rel = str(((workflow.get("artifacts") or {}).get("metadata")) or "metadata.json")
    metadata_path = (
        (output_dir / metadata_rel).resolve()
        if not Path(metadata_rel).is_absolute()
        else Path(metadata_rel)
    )
    dump_json(metadata_path, metadata)

    summary_md = render_summary_md(
        workflow=workflow,
        compare_result=compare_result,
        judge_result=judge_result,
        metadata=metadata,
        agent_execution_results=agent_execution_results,
        compare_validation_errors=compare_validation_errors,
        judge_validation_errors=judge_validation_errors,
    )
    summary_rel = str(((workflow.get("artifacts") or {}).get("summary")) or "summary.md")
    summary_path = (
        (output_dir / summary_rel).resolve()
        if not Path(summary_rel).is_absolute()
        else Path(summary_rel)
    )
    dump_text(summary_path, summary_md)

    print(
        json.dumps(
            {
                "harness_run_id": harness_run_id,
                "output_dir": str(output_dir),
                "compare_path": str(compare_path),
                "judge_path": str(judge_path),
                "metadata_path": str(metadata_path),
                "winner": judge_result.get("winner"),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
