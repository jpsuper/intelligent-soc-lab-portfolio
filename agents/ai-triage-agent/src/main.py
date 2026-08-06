import argparse
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlparse

import yaml
from openai import OpenAI
from prompt_loader import load_prompt_template
from schema_loader import load_schema

from common.decision_log import append_decision_log
from common.run_context import get_run_paths

POLICY_FILE = Path("agents/ai-triage-agent/policies/scenarios.yaml")
PROMPT_FILE = Path("agents/ai-triage-agent/prompts/triage_prompt.txt")
INPUT_FILE = Path("data/incidents/incident.json")
OUTPUT_FILE = Path("data/triage/triage_result.json")
MODEL = "gpt-5.4"


def load_policies() -> dict:
    if not POLICY_FILE.exists():
        return {}
    with POLICY_FILE.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_incident(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        incidents = json.load(fh)

    if isinstance(incidents, dict):
        return incidents
    if isinstance(incidents, list) and incidents:
        return max(incidents, key=lambda x: x.get("time_window_end", ""))
    raise ValueError(f"No incidents found in {path}")


def load_prompt_text(prompt_file: Path | None) -> str:
    if prompt_file is not None:
        return prompt_file.read_text(encoding="utf-8")
    if PROMPT_FILE.exists():
        return PROMPT_FILE.read_text(encoding="utf-8")
    return load_prompt_template()


def build_scenario_guidance(incident: dict) -> str:
    policies = load_policies()
    scenario = incident.get("scenario_name")

    if scenario in policies:
        return policies[scenario].get("guidance", "")

    return "No scenario-specific guidance."


def _classify_url_host(command_line: str) -> str:
    for token in command_line.split():
        if token.startswith("http://") or token.startswith("https://"):
            try:
                parsed = urlparse(token)
                host = parsed.hostname
                if not host:
                    return "unknown"

                try:
                    ipaddress.ip_address(host)
                    return "ip"
                except ValueError:
                    return "domain"
            except Exception:
                return "unknown"

    return "unknown"


def _classify_path_type(value: str | None) -> str:
    if not value:
        return "unknown"
    if "/tmp/" in value or "/dev/shm/" in value:
        return "tmp"
    if "/home/" in value:
        return "home"
    if "/usr/bin/" in value or "/bin/" in value:
        return "system"
    return "unknown"


def extract_behavior_features_from_incident(incident: dict) -> dict:
    existing = incident.get("behavior_features")
    if isinstance(existing, dict) and existing:
        return existing

    timeline = incident.get("timeline", [])
    commands = [event.get("event", "") for event in timeline if isinstance(event, dict)]

    remote_download = any(
        ("curl " in cmd or "wget " in cmd) and ("http://" in cmd or "https://" in cmd)
        for cmd in commands
    )

    download_tool = None
    for cmd in commands:
        if "curl " in cmd:
            download_tool = "curl"
            break
        if "wget " in cmd:
            download_tool = "wget"
            break

    download_source_type = "unknown"
    for cmd in commands:
        classified = _classify_url_host(cmd)
        if classified != "unknown":
            download_source_type = classified
            break

    execution_command = None
    for cmd in commands:
        if any(x in cmd for x in ["bash ", "/bin/bash", "sh ", "/bin/sh"]):
            execution_command = cmd
            break

    execution = execution_command is not None
    execution_path_type = _classify_path_type(execution_command)

    write_path_type = "unknown"
    for cmd in commands:
        classified = _classify_path_type(cmd)
        if classified != "unknown":
            write_path_type = classified
            break

    file_written = remote_download and write_path_type != "unknown"

    download_indices = []
    execution_indices = []
    for idx, cmd in enumerate(commands):
        if ("curl " in cmd or "wget " in cmd) and ("http://" in cmd or "https://" in cmd):
            download_indices.append(idx)
        if any(x in cmd for x in ["bash ", "/bin/bash", "sh ", "/bin/sh"]):
            execution_indices.append(idx)

    execution_after_download = False
    if download_indices and execution_indices:
        execution_after_download = min(execution_indices) > min(download_indices)

    return {
        "remote_download": remote_download,
        "download_source_type": download_source_type,
        "download_tool": download_tool,
        "file_written": file_written,
        "write_path_type": write_path_type,
        "execution": execution,
        "execution_path_type": execution_path_type,
        "execution_after_download": execution_after_download,
        "privilege_escalation": False,
        "credential_access": False,
        "persistence_action": False,
        "lateral_movement": False,
    }


def build_messages(incident: dict, prompt_file: Path | None) -> str:
    template = load_prompt_text(prompt_file)
    scenario_guidance = build_scenario_guidance(incident)
    behavior_features = extract_behavior_features_from_incident(incident)

    return template.format(
        scenario_guidance=scenario_guidance,
        behavior_features=json.dumps(behavior_features, indent=2, ensure_ascii=False),
        incident=json.dumps(incident, indent=2, ensure_ascii=False),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate AI triage result from incident")
    parser.add_argument("--run-id", help="Run ID for run-based decision logging")
    parser.add_argument("--incident", help="Optional incident JSON path override")
    parser.add_argument("--output", help="Optional triage output JSON path override")
    parser.add_argument(
        "--prompt-file",
        help="Optional prompt template override for harness comparison",
    )
    parser.add_argument(
        "--profile",
        help="Optional profile label for comparison runs",
    )
    return parser.parse_args()


def resolve_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    input_path = INPUT_FILE
    output_path = OUTPUT_FILE

    if args.run_id:
        run_paths = get_run_paths(args.run_id)
        input_path = run_paths.incident
        output_path = run_paths.triage_result

    if args.incident:
        input_path = Path(args.incident)
    if args.output:
        output_path = Path(args.output)

    return input_path, output_path


def main() -> None:
    args = parse_args()
    input_path, output_path = resolve_paths(args)
    prompt_file = Path(args.prompt_file) if args.prompt_file else None

    if not input_path.exists():
        raise FileNotFoundError(f"Incident file not found: {input_path}")
    if prompt_file is not None and not prompt_file.exists():
        raise FileNotFoundError(f"Prompt file not found: {prompt_file}")

    incident = load_incident(input_path)
    client = OpenAI()

    response = client.responses.create(
        model=MODEL,
        input=build_messages(incident, prompt_file),
        text={
            "format": {
                "type": "json_schema",
                "name": "soc_triage_result",
                "schema": load_schema(),
                "strict": True,
            }
        },
    )

    result = json.loads(response.output_text)
    result["triage_id"] = result.get("triage_id") or "triage-000001"
    result["incident_id"] = incident["incident_id"]
    result["attack_id"] = incident.get("attack_id")
    if args.profile:
        result["triage_profile"] = args.profile
    if prompt_file is not None:
        result["prompt_file"] = str(prompt_file)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    reasoning_summary = (result.get("key_observations") or result.get("attack_story") or [])[:3]

    if args.run_id:
        run_paths = get_run_paths(args.run_id)
        append_decision_log(
            run_paths.base,
            {
                "stage": "triage",
                "decision_type": "incident_assessment",
                "incident_id": result.get("incident_id"),
                "attack_id": result.get("attack_id"),
                "verdict": result.get("verdict"),
                "confidence": result.get("confidence"),
                "priority": result.get("priority"),
                "risk_score": result.get("risk_score"),
                "reasoning_summary": reasoning_summary,
                "human_required": False,
                "profile": args.profile,
                "prompt_file": str(prompt_file) if prompt_file else None,
            },
        )

    print("Triage result generated.")
    print(f"Saved to {output_path}")


if __name__ == "__main__":
    main()
