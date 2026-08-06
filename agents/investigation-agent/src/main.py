import argparse
import importlib.util
import json
import re
import shlex
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from jsonschema import validate
from jsonschema.validators import validator_for

from common.run_context import get_run_paths

DEFAULT_INCIDENT_FILE = Path("data/incidents/incident.json")
DEFAULT_TRIAGE_FILE = Path("data/triage/triage_result.json")
DEFAULT_ATTACK_FILE = Path("data/attacks/attack_result.json")
DEFAULT_PROCESS_EVENTS_FILE = Path("data/normalized/process_events.json")
DEFAULT_AUDITD_EVENTS_FILE = Path("data/processed/auditd_events.json")
DEFAULT_ENDPOINT_EVENTS_FILE = Path("data/processed/endpoint_events.json")
DEFAULT_PROCESS_CHAIN_HITS_FILE = Path("data/detections/process_chain_hits.json")
DEFAULT_ZEEK_ENRICHMENT_FILE = Path("data/zeek/zeek_enrichment.json")
DEFAULT_WAZUH_FIM_ALERTS_FILE = Path("data/wazuh/wazuh_fim_alerts.json")
DEFAULT_WAZUH_SUDO_ALERTS_FILE = Path("data/wazuh/wazuh_sudo_alerts.json")
DEFAULT_SSH_AUTH_EVENTS_FILE = Path("data/auth/ssh_auth_events.json")
DEFAULT_OUTPUT_FILE = Path("data/investigation/investigation_result.json")
DEFAULT_SCHEMA_FILE = Path("schemas/investigation_result_schema.json")
DEFAULT_ENDPOINT_EVENTS_SCHEMA_FILE = Path("schemas/endpoint_events.schema.json")
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
INCIDENT_SCHEMA_FILE = REPOSITORY_ROOT / "schemas" / "incident_schema.json"
TRIAGE_SCHEMA_FILE = (
    REPOSITORY_ROOT / "agents" / "ai-triage-agent" / "schemas" / "triage_schema.json"
)
INVESTIGATION_SCHEMA_FILE = REPOSITORY_ROOT / "schemas" / "investigation_result_schema.json"
ENDPOINT_EVENTS_SCHEMA_FILE = REPOSITORY_ROOT / "schemas" / "endpoint_events.schema.json"

DOWNLOAD_PREFIXES = ("curl ", "wget ", "fetch ")
EXECUTION_PREFIXES = (
    "bash ",
    "/bin/bash ",
    "sh ",
    "/bin/sh ",
    "python ",
    "python3 ",
    "perl ",
    "ruby ",
    "php ",
    "chmod ",
)
SUSPICIOUS_DIR_RE = re.compile(r"/(?:tmp|dev/shm)/[^\s'\"]+")
URL_RE = re.compile(r"https?://[^\s\'\"]+")

WAZUH_PERSISTENCE_PATHS = [
    "/etc/systemd/system",
    "/var/spool/cron",
    "/.ssh/",
    "authorized_keys",
]
AUDITD_COMMAND_FACTS = {"bash", "chmod", "curl", "hostname", "id", "uname", "whoami"}
AUDITD_DISCOVERY_COMMANDS = {"hostname", "id", "uname", "whoami"}
AUDITD_SIGNAL_KEYS = {"isl_execve", "isl_tmp_marker", "isl_ssh_persistence"}
ENDPOINT_DISCOVERY_COMMANDS = {"hostname", "id", "uname", "whoami"}
ENDPOINT_PAYLOAD_CONTEXT_FEATURES = {
    "endpoint_download_then_execute_pattern",
    "endpoint_payload_path_observed",
    "endpoint_url_fetch_observed",
    "endpoint_chmod_execute_chain_observed",
}


class InvestigationBoundaryValidationError(ValueError):
    """Raised when the bounded pre-case Investigation boundary is invalid."""


def load_json(path: str | Path):
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_optional_json(path: str | Path):
    file_path = Path(path)
    if not file_path.exists():
        return None
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_incident(path: str | Path) -> dict:
    data = load_json(path)
    return data[0] if isinstance(data, list) else data


def parse_ts(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def event_ts(event: dict) -> datetime | None:
    return parse_ts(event.get("timestamp"))


def canonical_user(event: dict | None) -> str | None:
    if not event:
        return None
    return event.get("username") or event.get("user")


def canonical_host(event: dict | None) -> str | None:
    if not event:
        return None
    return event.get("host")


def normalize_process_chain_hits(process_chain_hits: list[dict] | dict | None) -> list[dict]:
    if not process_chain_hits:
        return []
    if isinstance(process_chain_hits, list):
        return process_chain_hits
    if isinstance(process_chain_hits, dict):
        for key in ("hits", "items", "process_chain_hits"):
            value = process_chain_hits.get(key)
            if isinstance(value, list):
                return value
        return [process_chain_hits]
    return []


def extract_urls(cmd: str) -> list[str]:
    return URL_RE.findall(cmd or "")


def extract_tmp_paths(cmd: str) -> list[str]:
    return SUSPICIOUS_DIR_RE.findall(cmd or "")


def extract_local_download_paths(command: str) -> list[str]:
    """Extract explicit local output paths without treating URL paths as local."""

    try:
        tokens = shlex.split(command)
    except ValueError:
        return []

    if not tokens:
        return []
    command_name = Path(tokens[0]).name
    output_options_by_command = {
        "curl": {"-o", "--output"},
        "wget": {"-O", "--output-document"},
        "fetch": {"-o"},
    }
    output_options = output_options_by_command.get(command_name, set())

    paths: list[str] = []
    for index, token in enumerate(tokens):
        candidate = None
        if token in output_options and index + 1 < len(tokens):
            candidate = tokens[index + 1]
        elif "--output" in output_options and token.startswith("--output="):
            candidate = token.partition("=")[2]
        elif "--output-document" in output_options and token.startswith("--output-document="):
            candidate = token.partition("=")[2]

        if not candidate or extract_urls(candidate):
            continue
        for path in extract_tmp_paths(candidate):
            if path not in paths:
                paths.append(path)
    return paths


def resolve_attack_id(
    incident: dict,
    attack_result: dict | None = None,
    run_id: str | None = None,
) -> str | None:
    attack_id = incident.get("attack_id")
    if attack_id:
        return attack_id

    if attack_result and attack_result.get("attack_id"):
        return attack_result["attack_id"]

    if run_id:
        return f"attack-proc-{run_id}"

    return None


def short_command(cmd: str, limit: int = 140) -> str:
    cmd = (cmd or "").strip()
    if len(cmd) <= limit:
        return cmd
    return cmd[: limit - 3] + "..."


def command_name(event: dict) -> str | None:
    exe = event.get("exe") or ""
    cmd = event.get("command_line") or ""
    if exe:
        return Path(exe).name
    if cmd:
        return cmd.split()[0]
    return None


def is_download_command(cmd: str) -> bool:
    cmd = (cmd or "").strip()
    return cmd.startswith(DOWNLOAD_PREFIXES) or bool(extract_urls(cmd))


def is_chmod_command(cmd: str) -> bool:
    return (cmd or "").strip().startswith("chmod ")


def is_execution_command(cmd: str) -> bool:
    cmd = (cmd or "").strip()
    if is_chmod_command(cmd):
        return False
    if any(cmd.startswith(prefix) for prefix in EXECUTION_PREFIXES):
        return True
    return bool(extract_tmp_paths(cmd)) and not is_download_command(cmd)


def select_execution_anchor(incident: dict) -> dict | None:
    timeline = incident.get("timeline", []) or []
    executions = []
    fallbacks = []
    for event in timeline:
        cmd = event.get("command_line", "") or ""
        if is_execution_command(cmd):
            executions.append(event)
        elif extract_tmp_paths(cmd):
            fallbacks.append(event)

    if executions:
        return executions[-1]
    if fallbacks:
        return fallbacks[-1]
    return timeline[-1] if timeline else None


def parse_ports_and_hosts(urls: list[str]) -> tuple[list[str], list[int]]:
    hosts: list[str] = []
    ports: list[int] = []
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname and parsed.hostname not in hosts:
            hosts.append(parsed.hostname)
        if parsed.port is not None:
            if parsed.port not in ports:
                ports.append(parsed.port)
        elif parsed.scheme == "http":
            if 80 not in ports:
                ports.append(80)
        elif parsed.scheme == "https":
            if 443 not in ports:
                ports.append(443)
    return hosts, sorted(ports)


def event_snapshot(event: dict) -> dict:
    snapshot = {
        "timestamp": event.get("timestamp"),
        "pid": event.get("pid"),
        "ppid": event.get("ppid"),
        "host": event.get("host"),
        "user": canonical_user(event),
        "exe": event.get("exe"),
        "command_line": event.get("command_line"),
    }
    return {k: v for k, v in snapshot.items() if v not in (None, "", [])}


def event_identity(event: dict) -> tuple[str | None, str | None, str | None, str | None]:
    return (
        event.get("timestamp"),
        str(event.get("pid")) if event.get("pid") is not None else None,
        str(event.get("ppid")) if event.get("ppid") is not None else None,
        event.get("command_line"),
    )


def build_base_evidence(incident: dict) -> tuple[dict, dict]:
    timeline = incident.get("timeline", []) or []
    download_urls: list[str] = []
    payload_paths: list[str] = []
    execution_paths: list[str] = []
    ppids: list[str] = []

    download_events: list[dict] = []
    chmod_events: list[dict] = []
    execution_events: list[dict] = []

    for event in timeline:
        cmd = event.get("command_line", "") or ""
        if event.get("ppid") is not None:
            ppids.append(str(event.get("ppid")))

        urls = extract_urls(cmd)
        if urls:
            download_urls.extend(url for url in urls if url not in download_urls)
            download_events.append(event_snapshot(event))

        if is_download_command(cmd):
            for path in extract_local_download_paths(cmd):
                if path not in payload_paths:
                    payload_paths.append(path)
        elif is_execution_command(cmd):
            for path in extract_tmp_paths(cmd):
                if path not in execution_paths:
                    execution_paths.append(path)

        if is_chmod_command(cmd):
            chmod_events.append(event_snapshot(event))
        if is_execution_command(cmd):
            execution_events.append(event_snapshot(event))

    download_hosts, download_ports = parse_ports_and_hosts(download_urls)
    parent_pid = ppids[0] if ppids else None
    execution_path = execution_paths[0] if execution_paths else None
    payload_path = payload_paths[0] if payload_paths else None

    evidence = {
        "payload_path": payload_path,
        "execution_path": execution_path,
        "parent_pid": parent_pid,
        "download_hosts": download_hosts,
        "download_ports": download_ports,
        "child_processes": [],
        "download_urls": download_urls,
        "payload_paths_observed": payload_paths,
        "execution_paths_observed": execution_paths,
        "download_events": download_events,
        "chmod_events": chmod_events,
        "execution_events": execution_events,
        "matched_chain_rules": [],
        "execution_pid": None,
        "pre_execution_context": [],
        "post_execution_context": [],
        "descendant_processes": [],
        "lineage": [],
    }

    enriched = {
        "same_parent_process_chain": False,
        "payload_path_confirmed": bool(payload_path),
        "multiple_download_targets_observed": len(download_events) >= 2,
        "port_change_observed": len(download_ports) >= 2,
        "post_execution_child_process_observed": False,
        "same_host_and_user_context_confirmed": bool(incident.get("host"))
        and bool(incident.get("username") or incident.get("user")),
        "execution_context_expanded": False,
        "descendant_process_observed": False,
        "process_chain_hit_present": False,
        "execution_chain_confirmed_by_process_events": False,
        "pre_execution_context_observed": False,
        "post_execution_context_observed": False,
    }

    return evidence, enriched


def filter_related_events(
    process_events: list[dict],
    *,
    host: str | None,
    user: str | None,
) -> list[dict]:
    related = []
    for event in process_events:
        event_host = canonical_host(event)
        event_user = canonical_user(event)
        if host and event_host and event_host != host:
            continue
        if user and event_user and event_user != user:
            continue
        related.append(event)
    return related


def sort_events(events: list[dict]) -> list[dict]:
    return sorted(
        events,
        key=lambda e: (
            event_ts(e) or datetime.min.replace(tzinfo=timezone.utc),
            str(e.get("pid") or ""),
        ),
    )


def find_process_event_anchor(process_events: list[dict], anchor_event: dict | None) -> dict | None:
    if not anchor_event:
        return None

    anchor_pid = anchor_event.get("pid")
    anchor_cmd = anchor_event.get("command_line") or ""
    anchor_time = event_ts(anchor_event)

    candidates = []
    for event in process_events:
        score = 0
        if anchor_pid is not None and str(event.get("pid")) == str(anchor_pid):
            score += 5
        if anchor_cmd and event.get("command_line") == anchor_cmd:
            score += 3
        if anchor_time and event_ts(event):
            delta = abs((event_ts(event) - anchor_time).total_seconds())
            if delta <= 2:
                score += 3
            elif delta <= 10:
                score += 2
            elif delta <= 60:
                score += 1
        if score > 0:
            candidates.append((score, event))

    if not candidates:
        return None
    candidates.sort(
        key=lambda item: (
            item[0],
            event_ts(item[1]) or datetime.min.replace(tzinfo=timezone.utc),
        ),
        reverse=True,
    )
    return candidates[0][1]


def build_process_graph(events: list[dict]) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    by_pid: dict[str, list[dict]] = defaultdict(list)
    children: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        pid = event.get("pid")
        ppid = event.get("ppid")
        if pid is not None:
            by_pid[str(pid)].append(event)
        if ppid is not None:
            children[str(ppid)].append(event)
    return by_pid, children


def summarize_context_events(events: list[dict], limit: int = 5) -> list[dict]:
    summaries: list[dict] = []
    for event in sort_events(events)[:limit]:
        summaries.append(
            {
                "timestamp": event.get("timestamp"),
                "pid": event.get("pid"),
                "ppid": event.get("ppid"),
                "exe": event.get("exe"),
                "command_line": short_command(event.get("command_line") or ""),
            }
        )
    return summaries


def infer_same_parent_process_chain(
    incident: dict,
    execution_pid: str | None,
) -> bool:
    if not execution_pid:
        return False

    timeline = incident.get("timeline", []) or []
    if not timeline:
        return False

    for event in timeline:
        pid = str(event.get("pid")) if event.get("pid") is not None else None
        ppid = str(event.get("ppid")) if event.get("ppid") is not None else None

        # execution event 自身
        if pid == execution_pid:
            continue

        # execution shell の直接子
        if ppid == execution_pid:
            continue

        return False

    return True


def add_auth_execution_context(
    ssh_auth_events: list[dict] | None,
    incident: dict,
    evidence: dict,
    enriched_features: dict,
) -> None:
    if not ssh_auth_events:
        return

    host = incident.get("host")
    user = incident.get("username") or incident.get("user")

    timeline = incident.get("timeline", []) or []
    if not timeline:
        return

    first_incident_ts = None
    for item in timeline:
        ts = parse_ts(item.get("timestamp"))
        if ts is not None:
            first_incident_ts = ts
            break

    if first_incident_ts is None:
        first_incident_ts = parse_ts(incident.get("time_window_start"))

    if first_incident_ts is None:
        return

    key_logins = []
    for event in ssh_auth_events:
        if event.get("event_type") != "ssh_key_login":
            continue
        if host and canonical_host(event) and canonical_host(event) != host:
            continue
        if user and canonical_user(event) and canonical_user(event) != user:
            continue

        ts = event_ts(event)
        if ts is None:
            continue

        if ts <= first_incident_ts and (first_incident_ts - ts) <= timedelta(minutes=5):
            key_logins.append(event)

    if not key_logins:
        return

    key_logins = sort_events(key_logins)
    first_key_login = key_logins[0]
    latest_key_login = key_logins[-1]

    src_ips: list[str] = []
    for event in key_logins:
        src_ip = event.get("src_ip")
        if src_ip and src_ip not in src_ips:
            src_ips.append(src_ip)

    latest_ts = event_ts(latest_key_login)
    gap_seconds = None
    if latest_ts is not None:
        gap_seconds = int((first_incident_ts - latest_ts).total_seconds())

    evidence["auth_source_ips"] = src_ips
    evidence["ssh_key_login_count"] = len(key_logins)
    evidence["first_ssh_key_login"] = {
        "timestamp": first_key_login.get("timestamp"),
        "username": canonical_user(first_key_login),
        "src_ip": first_key_login.get("src_ip"),
        "auth_method": first_key_login.get("auth_method"),
    }
    evidence["latest_ssh_key_login"] = {
        "timestamp": latest_key_login.get("timestamp"),
        "username": canonical_user(latest_key_login),
        "src_ip": latest_key_login.get("src_ip"),
        "auth_method": latest_key_login.get("auth_method"),
    }
    evidence["login_to_execution_gap_seconds"] = gap_seconds

    enriched_features["ssh_key_login_observed"] = True
    enriched_features["public_key_authentication_observed"] = True
    enriched_features["public_key_login_to_execution_observed"] = True


def add_process_context(
    process_events: list[dict] | None,
    incident: dict,
    evidence: dict,
    enriched_features: dict,
) -> None:
    if not process_events:
        return

    host = incident.get("host")
    user = incident.get("username") or incident.get("user")
    related_events = sort_events(filter_related_events(process_events, host=host, user=user))
    if not related_events:
        return

    incident_identities = {event_identity(event) for event in (incident.get("timeline", []) or [])}

    anchor_event = select_execution_anchor(incident)
    process_anchor = find_process_event_anchor(related_events, anchor_event)
    if not process_anchor:
        return

    anchor_pid = str(process_anchor.get("pid")) if process_anchor.get("pid") is not None else None
    anchor_ppid = (
        str(process_anchor.get("ppid")) if process_anchor.get("ppid") is not None else None
    )
    anchor_time = event_ts(process_anchor)
    evidence["execution_pid"] = anchor_pid
    if anchor_pid:
        enriched_features["same_parent_process_chain"] = infer_same_parent_process_chain(
            incident=incident,
            execution_pid=anchor_pid,
        )

    enriched_features["execution_chain_confirmed_by_process_events"] = True

    by_pid, children = build_process_graph(related_events)

    direct_children: list[str] = []
    if anchor_pid:
        for event in sort_events(children.get(anchor_pid, [])):
            name = command_name(event)
            if name and name not in direct_children:
                direct_children.append(name)

    evidence["child_processes"] = direct_children
    if direct_children:
        enriched_features["post_execution_child_process_observed"] = True

    descendant_names: list[str] = []
    lineage: list[dict] = []
    descendant_identities: set[tuple[str | None, str | None, str | None, str | None]] = set()
    if anchor_pid:
        queue: deque[tuple[str, int]] = deque([(anchor_pid, 0)])
        visited = {anchor_pid}
        while queue:
            pid, depth = queue.popleft()
            pid_events = sort_events(by_pid.get(pid, []))
            if pid_events:
                first = pid_events[0]
                lineage.append(
                    {
                        "depth": depth,
                        "pid": pid,
                        "ppid": first.get("ppid"),
                        "exe": first.get("exe"),
                        "command_line": short_command(first.get("command_line") or ""),
                    }
                )
            if depth >= 2:
                continue
            for child in sort_events(children.get(pid, [])):
                child_pid = child.get("pid")
                if child_pid is None:
                    continue
                child_pid_str = str(child_pid)
                if child_pid_str in visited:
                    continue
                visited.add(child_pid_str)
                queue.append((child_pid_str, depth + 1))
                descendant_identities.add(event_identity(child))
                name = command_name(child)
                if name and name not in descendant_names:
                    descendant_names.append(name)

    evidence["descendant_processes"] = descendant_names
    evidence["lineage"] = lineage
    if descendant_names:
        enriched_features["descendant_process_observed"] = True

    if anchor_time:
        pre_window_start = anchor_time - timedelta(seconds=120)
        post_window_end = anchor_time + timedelta(seconds=180)
        pre_events = []
        post_events = []
        for event in related_events:
            identity = event_identity(event)
            if identity in incident_identities:
                continue

            ts = event_ts(event)
            if not ts:
                continue

            if pre_window_start <= ts < anchor_time:
                pre_events.append(event)
                continue

            if anchor_time <= ts <= post_window_end:
                same_event_as_anchor = identity == event_identity(process_anchor)
                descendant_or_child = identity in descendant_identities or (
                    anchor_pid is not None and str(event.get("ppid")) == anchor_pid
                )
                if same_event_as_anchor:
                    continue
                if ts > anchor_time or descendant_or_child:
                    post_events.append(event)

        evidence["pre_execution_context"] = summarize_context_events(pre_events[-5:], limit=5)
        evidence["post_execution_context"] = summarize_context_events(post_events[:5], limit=5)
        if evidence["pre_execution_context"]:
            enriched_features["pre_execution_context_observed"] = True
        if evidence["post_execution_context"]:
            enriched_features["post_execution_context_observed"] = True
        if evidence["pre_execution_context"] or evidence["post_execution_context"]:
            enriched_features["execution_context_expanded"] = True

    if anchor_ppid and evidence.get("parent_pid") is None:
        evidence["parent_pid"] = anchor_ppid


def add_auditd_context(auditd_events: list[dict] | None, evidence: dict) -> None:
    if not auditd_events:
        return

    normalized_events = [event for event in auditd_events if isinstance(event, dict)]
    if not normalized_events:
        return

    evidence["auditd_event_count"] = len(normalized_events)
    evidence["auditd_events"] = normalized_events


def normalize_endpoint_events(endpoint_events: object) -> list[dict]:
    if isinstance(endpoint_events, dict):
        events = endpoint_events.get("events")
    else:
        events = endpoint_events

    if not isinstance(events, list):
        return []
    return [event for event in events if isinstance(event, dict)]


def load_optional_endpoint_events(path: str | Path, schema_path: str | Path) -> dict | None:
    file_path = Path(path)
    if not file_path.exists():
        return None

    endpoint_events = load_json(file_path)
    schema = load_json(schema_path)
    validate(instance=endpoint_events, schema=schema)
    return endpoint_events


def add_endpoint_context(endpoint_events: object, evidence: dict) -> None:
    normalized_events = normalize_endpoint_events(endpoint_events)
    if not normalized_events:
        return

    evidence["endpoint_event_count"] = len(normalized_events)
    evidence["endpoint_events"] = normalized_events


def derive_endpoint_enriched_features(endpoint_events: object) -> dict[str, bool]:
    commands: list[str] = []
    for event in normalize_endpoint_events(endpoint_events):
        if event.get("event_type") != "process_exec":
            continue
        command = endpoint_command_text(event)
        if command:
            commands.append(command)

    if not commands:
        return {}

    combined = " ".join(commands).lower()
    has_url = bool(extract_urls(combined))
    has_payload_path = any(
        extract_local_download_paths(command)
        if is_download_command(command)
        else extract_tmp_paths(command)
        for command in commands
    )
    has_curl = "curl" in endpoint_command_tokens(combined) or "curl " in combined
    has_chmod = any(is_chmod_command(command) for command in commands) or "chmod " in combined
    has_execution = any(is_execution_command(command) for command in commands)

    features: dict[str, bool] = {"endpoint_command_sequence_observed": True}
    if has_payload_path:
        features["endpoint_payload_path_observed"] = True
    if has_url:
        features["endpoint_url_fetch_observed"] = True
    if has_curl and has_execution:
        features["endpoint_download_then_execute_pattern"] = True
    if has_chmod and has_execution:
        features["endpoint_chmod_execute_chain_observed"] = True

    return features


def enrich_with_endpoint_events(endpoint_events: object, enriched_features: dict) -> None:
    for feature, value in derive_endpoint_enriched_features(endpoint_events).items():
        if value:
            enriched_features[feature] = True


def is_suspicious_archive_staging_incident(incident: dict) -> bool:
    if incident.get("primary_artifact") == "suspicious_archive_staging":
        return True
    if incident.get("scenario_name") == "scenario_009_suspicious_archive_staging":
        return True

    matched = [
        *(incident.get("matched_rules") or []),
        *(incident.get("matched_rule_names") or []),
    ]
    return "collection.suspicious_archive_staging" in matched


def add_archive_staging_context(
    incident: dict,
    endpoint_events: object,
    evidence: dict,
    enriched_features: dict,
) -> None:
    if not is_suspicious_archive_staging_incident(incident):
        return

    observations: list[dict] = []
    file_paths: list[str] = []
    process_names: set[str] = set()

    for event in normalize_endpoint_events(endpoint_events):
        event_type = event.get("event_type")
        command = endpoint_command_text(event)
        file_path = event.get("file_path")
        process_name = event.get("process_name")

        if isinstance(process_name, str) and process_name:
            process_names.add(process_name)
        if isinstance(file_path, str) and file_path and file_path not in file_paths:
            file_paths.append(file_path)

        if event_type not in {"process_exec", "file_write"}:
            continue
        if not command and not file_path:
            continue

        observations.append(
            {
                "event_id": event.get("event_id"),
                "timestamp": event.get("timestamp"),
                "event_type": event_type,
                "process_name": process_name,
                "command_line": command,
                "file_path": file_path,
                "raw_ref": event.get("raw_ref"),
            }
        )

    behavior_features = incident.get("behavior_features") or {}
    evidence["archive_staging_observations"] = observations
    evidence["archive_staging_paths"] = file_paths
    evidence["archive_staging_rule"] = "collection.suspicious_archive_staging"
    evidence["archive_creation_observed"] = bool(behavior_features.get("archive_creation"))
    evidence["local_staging_path_observed"] = bool(behavior_features.get("local_staging_path"))
    evidence["synthetic_file_staging_observed"] = bool(
        behavior_features.get("synthetic_file_staging")
    )
    evidence["chmod_event_present_in_fixture"] = "chmod" in process_names
    evidence["chmod_correlated_by_detection_rule"] = bool(
        behavior_features.get("archive_permission_change_observed")
    )

    enriched_features["archive_staging_behavior_observed"] = bool(observations)
    enriched_features["archive_creation_observed"] = evidence["archive_creation_observed"]
    enriched_features["local_archive_staging_path_observed"] = evidence[
        "local_staging_path_observed"
    ]


def endpoint_payload_context_observed(enriched_features: object) -> bool:
    if isinstance(enriched_features, dict):
        feature_names = {str(key) for key, value in enriched_features.items() if value}
    elif isinstance(enriched_features, list):
        feature_names = {str(item) for item in enriched_features if str(item).strip()}
    else:
        feature_names = set()

    return bool(feature_names & ENDPOINT_PAYLOAD_CONTEXT_FEATURES)


def ordered_same_path_chain(events: list[dict]) -> bool:
    stages_by_path: dict[str, dict[str, list[datetime]]] = defaultdict(
        lambda: {"download": [], "chmod": [], "execution": []}
    )
    for event in events:
        timestamp = event_ts(event)
        command = endpoint_command_text(event)
        if timestamp is None or command is None:
            continue
        if is_download_command(command):
            stage = "download"
            paths = extract_local_download_paths(command)
        elif is_chmod_command(command):
            stage = "chmod"
            paths = extract_tmp_paths(command)
        elif is_execution_command(command):
            stage = "execution"
            paths = extract_tmp_paths(command)
        else:
            continue
        for path in paths:
            stages_by_path[path][stage].append(timestamp)

    for stages in stages_by_path.values():
        for download_timestamp in stages["download"]:
            for chmod_timestamp in stages["chmod"]:
                for execution_timestamp in stages["execution"]:
                    try:
                        if download_timestamp < chmod_timestamp < execution_timestamp:
                            return True
                    except TypeError:
                        # Mixed timezone-aware/naive timestamps cannot prove ordering.
                        continue
    return False


def generic_chain_evidence_state(evidence: dict, enriched_features: dict) -> dict:
    """Summarize defender-side support for generic download/chmod/execute claims."""

    endpoint_download_observed = bool(enriched_features.get("endpoint_url_fetch_observed"))
    endpoint_chmod_observed = bool(enriched_features.get("endpoint_chmod_execute_chain_observed"))
    endpoint_execution_observed = bool(
        enriched_features.get("endpoint_download_then_execute_pattern")
        or enriched_features.get("endpoint_chmod_execute_chain_observed")
    )
    endpoint_events = normalize_endpoint_events(evidence.get("endpoint_events"))
    endpoint_full_chain = bool(
        endpoint_download_observed
        and endpoint_chmod_observed
        and endpoint_execution_observed
        and ordered_same_path_chain(endpoint_events)
    )
    endpoint_observed_elements = []
    endpoint_missing_elements = []
    for label, observed in (
        ("download", endpoint_download_observed),
        ("permission change", endpoint_chmod_observed),
        ("execution", endpoint_execution_observed),
    ):
        (endpoint_observed_elements if observed else endpoint_missing_elements).append(label)
    endpoint_full_chain_gaps = list(endpoint_missing_elements)
    if not endpoint_full_chain and not endpoint_full_chain_gaps:
        endpoint_full_chain_gaps.append("ordered same-payload-path correlation")

    matched_chain = bool(evidence.get("matched_chain_rules"))
    timeline_events = [
        event
        for key in ("download_events", "chmod_events", "execution_events")
        for event in (evidence.get(key) or [])
        if isinstance(event, dict)
    ]
    timeline_full_chain = ordered_same_path_chain(timeline_events)
    download_observed = bool(
        evidence.get("download_events")
        or evidence.get("download_urls")
        or endpoint_download_observed
        or matched_chain
    )
    chmod_observed = bool(evidence.get("chmod_events") or endpoint_chmod_observed or matched_chain)
    execution_observed = bool(
        evidence.get("execution_events")
        or evidence.get("execution_paths_observed")
        or enriched_features.get("execution_chain_confirmed_by_process_events")
        or endpoint_execution_observed
        or matched_chain
    )
    full_chain = bool(matched_chain or timeline_full_chain or endpoint_full_chain)

    observed_elements = []
    missing_elements = []
    for label, observed in (
        ("download", download_observed),
        ("permission change", chmod_observed),
        ("execution", execution_observed),
    ):
        (observed_elements if observed else missing_elements).append(label)

    full_chain_gaps = list(missing_elements)
    if not full_chain and not full_chain_gaps:
        full_chain_gaps.append("ordered same-payload-path correlation")

    return {
        "download_observed": download_observed,
        "chmod_observed": chmod_observed,
        "execution_observed": execution_observed,
        "full_chain": full_chain,
        "observed_elements": observed_elements,
        "missing_elements": missing_elements,
        "full_chain_gaps": full_chain_gaps,
        "endpoint_download_observed": endpoint_download_observed,
        "endpoint_chmod_observed": endpoint_chmod_observed,
        "endpoint_execution_observed": endpoint_execution_observed,
        "endpoint_full_chain": endpoint_full_chain,
        "endpoint_observed_elements": endpoint_observed_elements,
        "endpoint_full_chain_gaps": endpoint_full_chain_gaps,
    }


def uses_generic_chain_narrative(evidence: dict, enriched_features: dict) -> bool:
    return not (
        evidence.get("archive_staging_observations") is not None
        or enriched_features.get("public_key_login_to_execution_observed")
        or evidence.get("wazuh_fim_paths")
    )


def append_pivot_once(pivots: list[dict], pivot: dict) -> None:
    pivot_name = pivot.get("pivot")
    if not pivot_name:
        return
    if any(item.get("pivot") == pivot_name for item in pivots):
        return
    pivots.append(pivot)


def endpoint_host(event: dict) -> str:
    host = event.get("host")
    if isinstance(host, str) and host:
        return host
    return "unknown"


def endpoint_command_text(event: dict) -> str | None:
    command_line = event.get("command_line")
    if isinstance(command_line, str) and command_line.strip():
        return command_line.strip()

    argv = event.get("argv")
    if isinstance(argv, list) and argv:
        command = " ".join(str(arg) for arg in argv if str(arg).strip()).strip()
        if command:
            return command

    for key in ("process_name", "exe"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return None


def endpoint_command_tokens(command: str) -> set[str]:
    tokens: set[str] = set()
    for token in command.replace(";", " ").replace("&&", " ").split():
        normalized = Path(token.strip("\"'")).name
        if normalized:
            tokens.add(normalized)
    return tokens


def endpoint_network_fact(event: dict) -> str | None:
    src_ip = event.get("src_ip")
    src_port = event.get("src_port")
    dest_ip = event.get("dest_ip")
    dest_port = event.get("dest_port")
    if None in (src_ip, src_port, dest_ip, dest_port):
        return None
    return (
        f"endpoint telemetry observed network connection on {endpoint_host(event)}: "
        f"{src_ip}:{src_port} -> {dest_ip}:{dest_port}."
    )


def build_endpoint_signal_context(endpoint_events: object) -> tuple[list[str], list[str]]:
    observed_facts: list[str] = []
    supporting_signals: list[str] = []
    saw_process_exec = False
    saw_discovery_exec = False
    saw_file_write = False
    saw_persistence_change = False
    saw_network_connection = False
    saw_auth_success = False
    saw_auth_failure = False

    for event in normalize_endpoint_events(endpoint_events):
        event_type = event.get("event_type")
        host = endpoint_host(event)

        if event_type == "process_exec":
            command = endpoint_command_text(event)
            if not command:
                continue
            append_unique(
                observed_facts,
                f"endpoint telemetry observed command execution on {host}: {command}.",
            )
            saw_process_exec = True
            if endpoint_command_tokens(command) & ENDPOINT_DISCOVERY_COMMANDS:
                saw_discovery_exec = True
            continue

        if event_type == "file_write":
            file_path = event.get("file_path")
            if not isinstance(file_path, str) or not file_path:
                continue
            append_unique(
                observed_facts,
                f"endpoint telemetry observed file write activity on {host}: {file_path}.",
            )
            saw_file_write = True
            continue

        if event_type == "persistence_file_change":
            file_path = event.get("file_path")
            if not isinstance(file_path, str) or not file_path:
                continue
            append_unique(
                observed_facts,
                (
                    "endpoint telemetry observed persistence path file activity "
                    f"on {host}: {file_path}."
                ),
            )
            saw_persistence_change = True
            continue

        if event_type == "network_connection":
            fact = endpoint_network_fact(event)
            if not fact:
                continue
            append_unique(observed_facts, fact)
            saw_network_connection = True
            continue

        if event_type == "auth_success":
            user = event.get("user") or "unknown"
            append_unique(
                observed_facts,
                f"endpoint telemetry observed successful authentication on {host} for {user}.",
            )
            saw_auth_success = True
            continue

        if event_type == "auth_failure":
            user = event.get("user") or "unknown"
            append_unique(
                observed_facts,
                f"endpoint telemetry observed failed authentication on {host} for {user}.",
            )
            saw_auth_failure = True

    if saw_process_exec:
        supporting_signals.append(
            "endpoint process telemetry corroborates endpoint-side command execution."
        )
    if saw_discovery_exec:
        supporting_signals.append(
            "endpoint process telemetry corroborates system discovery command execution."
        )
    if saw_file_write:
        supporting_signals.append(
            "endpoint file telemetry corroborates selected file-write activity."
        )
    if saw_persistence_change:
        supporting_signals.append(
            "endpoint file telemetry corroborates endpoint-side persistence path file activity."
        )
    if saw_network_connection:
        supporting_signals.append(
            "endpoint network telemetry corroborates endpoint-side network activity."
        )
    if saw_auth_success:
        supporting_signals.append(
            "endpoint auth telemetry corroborates successful authentication activity."
        )
    if saw_auth_failure:
        supporting_signals.append(
            "endpoint auth telemetry corroborates failed authentication activity."
        )

    return observed_facts, supporting_signals


def append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def add_auditd_command_name(names: list[str], value: object) -> None:
    if not isinstance(value, str) or not value:
        return

    command = Path(value.strip("\"'")).name
    if command in AUDITD_COMMAND_FACTS:
        append_unique(names, command)


def auditd_command_names(event: dict) -> list[str]:
    names: list[str] = []
    add_auditd_command_name(names, event.get("exe"))
    add_auditd_command_name(names, event.get("comm"))

    argv = event.get("argv")
    if isinstance(argv, list):
        for arg in argv:
            if not isinstance(arg, str):
                continue
            for token in arg.replace(";", " ").replace("&&", " ").split():
                add_auditd_command_name(names, token)

    return names


def auditd_event_path(event: dict) -> str | None:
    file_path = event.get("file_path")
    if isinstance(file_path, str) and file_path:
        return file_path

    for path in event.get("paths") or []:
        if not isinstance(path, dict):
            continue
        name = path.get("name")
        if isinstance(name, str) and name:
            return name

    return None


def build_auditd_signal_context(
    auditd_events: list[dict] | None,
) -> tuple[list[str], list[str]]:
    observed_facts: list[str] = []
    supporting_signals: list[str] = []

    if not auditd_events:
        return observed_facts, supporting_signals

    saw_process_exec = False
    saw_discovery_exec = False
    saw_file_write = False
    saw_persistence_change = False

    for event in auditd_events:
        if not isinstance(event, dict):
            continue

        if event.get("audit_key") not in AUDITD_SIGNAL_KEYS:
            continue

        event_type = event.get("event_type")
        if event_type == "process_exec":
            commands = auditd_command_names(event)
            if not commands:
                continue
            for command in commands:
                append_unique(observed_facts, f"auditd observed {command} execution.")
            saw_process_exec = True
            if any(command in AUDITD_DISCOVERY_COMMANDS for command in commands):
                saw_discovery_exec = True
            continue

        if event_type == "file_write":
            path = auditd_event_path(event)
            if not path:
                continue
            append_unique(observed_facts, f"auditd observed file activity for {path}.")
            saw_file_write = True
            continue

        if event_type == "persistence_file_change":
            path = auditd_event_path(event)
            if not path or (".ssh" not in path and "authorized_keys" not in path):
                continue
            append_unique(
                observed_facts,
                f"auditd observed persistence path file activity for {path}.",
            )
            saw_persistence_change = True

    if saw_process_exec:
        supporting_signals.append(
            "auditd process telemetry corroborates endpoint-side command execution."
        )
    if saw_discovery_exec:
        supporting_signals.append(
            "auditd process telemetry corroborates system discovery command execution."
        )
    if saw_file_write:
        supporting_signals.append(
            "auditd file telemetry corroborates selected file-write activity."
        )
    if saw_persistence_change:
        supporting_signals.append(
            "auditd file telemetry corroborates endpoint-side persistence path file activity."
        )

    return observed_facts, supporting_signals


def enrich_with_process_chain_hits(
    process_chain_hits: list[dict] | dict | None,
    evidence: dict,
    enriched_features: dict,
) -> None:
    hits = normalize_process_chain_hits(process_chain_hits)
    if not hits:
        return

    matched_rule_names: list[str] = []
    for hit in hits:
        rule_name = (
            hit.get("rule_name")
            or hit.get("detection_type")
            or hit.get("name")
            or hit.get("rule_id")
        )
        if rule_name and rule_name not in matched_rule_names:
            matched_rule_names.append(rule_name)

    if matched_rule_names:
        evidence["matched_chain_rules"] = matched_rule_names
        enriched_features["process_chain_hit_present"] = True


def promote_context_into_evidence(evidence: dict) -> None:
    candidate_events: list[dict] = []

    for key in (
        "download_events",
        "chmod_events",
        "execution_events",
        "pre_execution_context",
        "post_execution_context",
    ):
        value = evidence.get(key) or []
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    candidate_events.append(item)

    download_urls = list(evidence.get("download_urls") or [])
    payload_paths = list(evidence.get("payload_paths_observed") or [])
    execution_paths = list(evidence.get("execution_paths_observed") or [])

    for event in candidate_events:
        cmd = event.get("command_line") or ""

        for url in extract_urls(cmd):
            if url not in download_urls:
                download_urls.append(url)

        if is_download_command(cmd):
            for path in extract_local_download_paths(cmd):
                if path not in payload_paths:
                    payload_paths.append(path)
        elif is_execution_command(cmd):
            for path in extract_tmp_paths(cmd):
                if path not in execution_paths:
                    execution_paths.append(path)

    download_hosts, download_ports = parse_ports_and_hosts(download_urls)

    evidence["download_urls"] = download_urls
    evidence["download_hosts"] = download_hosts
    evidence["download_ports"] = download_ports
    evidence["payload_paths_observed"] = payload_paths
    evidence["execution_paths_observed"] = execution_paths

    if evidence.get("payload_path") is None and payload_paths:
        evidence["payload_path"] = payload_paths[0]

    if evidence.get("execution_path") is None:
        if execution_paths:
            evidence["execution_path"] = execution_paths[0]


def enrich_with_zeek_enrichment(
    zeek_enrichment: list[dict] | None,
    evidence: dict,
    enriched_features: dict,
) -> None:
    if not zeek_enrichment:
        enriched_features.setdefault("network_context_observed", False)
        enriched_features.setdefault("http_context_observed", False)
        enriched_features.setdefault("payload_request_observed", False)
        return

    download_hosts = set(evidence.get("download_hosts") or [])
    download_ports = set(evidence.get("download_ports") or [])

    relevant_network: list[dict] = []
    relevant_http: list[dict] = []
    relevant_uids: list[str] = []

    def is_relevant_group(group: dict) -> bool:
        http_obs = group.get("http_observations", []) or []
        if http_obs:
            return True

        for obs in group.get("network_observations", []) or []:
            dest_ip = obs.get("dest_ip")
            dest_port = obs.get("dest_port")
            if download_hosts and dest_ip in download_hosts:
                return True
            if download_ports and dest_port in download_ports:
                return True
        return False

    for group in zeek_enrichment:
        if not is_relevant_group(group):
            continue

        uid = group.get("uid")
        if uid and uid not in relevant_uids:
            relevant_uids.append(uid)

        for obs in group.get("network_observations", []) or []:
            relevant_network.append(obs)

        for obs in group.get("http_observations", []) or []:
            relevant_http.append(obs)

    if relevant_network:
        evidence["network_observations"] = relevant_network
        evidence["zeek_uids"] = relevant_uids
        enriched_features["network_context_observed"] = True
    else:
        enriched_features["network_context_observed"] = False

    if relevant_http:
        evidence["http_observations"] = relevant_http
        evidence["zeek_uids"] = relevant_uids
        enriched_features["http_context_observed"] = True

        payload_request_observed = False
        for obs in relevant_http:
            uri = obs.get("uri") or ""
            if "payload.sh" in uri:
                payload_request_observed = True
                break

        enriched_features["payload_request_observed"] = payload_request_observed
    else:
        enriched_features["http_context_observed"] = False
        enriched_features["payload_request_observed"] = False


def load_auth_patch_builder():
    module_path = Path(__file__).resolve().parents[2] / "parser-agent" / "src" / "auth_enricher.py"
    if not module_path.exists():
        return None

    spec = importlib.util.spec_from_file_location("auth_enricher", module_path)
    if not spec or not spec.loader:
        return None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, "build_auth_patch", None)


def load_wazuh_patch_builder():
    module_path = Path(__file__).resolve().parents[2] / "parser-agent" / "src" / "wazuh_enricher.py"
    if not module_path.exists():
        return None

    spec = importlib.util.spec_from_file_location("wazuh_enricher", module_path)
    if not spec or not spec.loader:
        return None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, "build_wazuh_patch", None)


def merge_patch(
    evidence: dict,
    enriched_features: dict,
    notes: list[str],
    timeline_notes: list[str],
    patch: dict | None,
) -> None:
    if not patch:
        return

    evidence_patch = patch.get("evidence_patch") or {}
    feature_patch = patch.get("enriched_features_patch") or {}
    notes_patch = patch.get("investigation_notes_patch") or []
    timeline_patch = patch.get("timeline_notes_patch") or []

    for key, value in evidence_patch.items():
        if key not in evidence:
            evidence[key] = value
            continue

        current = evidence[key]
        if isinstance(current, list) and isinstance(value, list):
            for item in value:
                if item not in current:
                    current.append(item)
        elif isinstance(current, dict) and isinstance(value, dict):
            current.update(value)
        else:
            evidence[key] = value

    for key, value in feature_patch.items():
        if isinstance(value, bool):
            enriched_features[key] = bool(enriched_features.get(key, False) or value)
        else:
            enriched_features[key] = value

    for item in notes_patch:
        if item not in notes:
            notes.append(item)

    for item in timeline_patch:
        if item not in timeline_notes:
            timeline_notes.append(item)


def render_summary(incident: dict, evidence: dict, enriched_features: dict) -> str:
    host = incident.get("host") or "unknown_host"

    if is_suspicious_archive_staging_incident(incident):
        fragments = [f"Investigation observed suspicious local archive staging on {host}."]
        if evidence.get("archive_creation_observed"):
            fragments.append("Archive creation was observed from defender-side endpoint evidence.")
        if evidence.get("local_staging_path_observed"):
            fragments.append("The observed archive activity used a local staging path.")
        fragments.append(
            "Possible preparation for collection remains a hypothesis, not a confirmed outcome."
        )
        return " ".join(fragments)

    fim_paths = evidence.get("wazuh_fim_paths", []) or []
    has_auth_keys_mod = any(str(path).endswith("/.ssh/authorized_keys") for path in fim_paths)

    if enriched_features.get("public_key_login_to_execution_observed"):
        fragments = [f"Investigation confirmed post-login command execution on {host}."]
        first_key = (
            evidence.get("latest_ssh_key_login") or evidence.get("first_ssh_key_login") or {}
        )
        src_ip = first_key.get("src_ip") or "unknown_source"
        username = (
            first_key.get("username")
            or incident.get("username")
            or incident.get("user")
            or "unknown_user"
        )

        fragments.append(
            f"A successful SSH public key login for "
            f"{username} was observed from {src_ip} before execution."
        )

        if evidence.get("execution_path"):
            fragments.append(f"The executed path was {evidence['execution_path']}.")

        gap = evidence.get("login_to_execution_gap_seconds")
        if isinstance(gap, int) and gap >= 0:
            fragments.append(f"The login-to-execution gap was approximately {gap} seconds.")

        return " ".join(fragments)

    if has_auth_keys_mod:
        fragments = [f"Persistence activity detected on {host}."]
        fragments.append(
            "authorized_keys file was modified, indicating potential SSH key persistence."
        )
        if enriched_features.get("auth_bruteforce_observed"):
            fragments.append("SSH authentication failures were observed before access.")
        if enriched_features.get("auth_success_after_failures_observed"):
            fragments.append(
                "A successful SSH login followed earlier failures in the same context."
            )
        return " ".join(fragments)

    chain_state = generic_chain_evidence_state(evidence, enriched_features)
    if chain_state["full_chain"]:
        fragments = [f"Investigation confirmed a download -> chmod -> execute chain on {host}."]
    elif chain_state["observed_elements"]:
        fragments = [
            f"Investigation observed limited process-chain evidence on {host}: "
            + ", ".join(chain_state["observed_elements"])
            + "."
        ]
        fragments.append(
            "The available evidence does not establish the full download -> chmod -> execute chain."
        )
    else:
        fragments = [
            "The available defender-side evidence does not establish a download, "
            f"permission-change, or execution chain on {host}."
        ]

    if evidence.get("execution_path"):
        fragments.append(f"The executed path was {evidence['execution_path']}.")
    if enriched_features.get("same_parent_process_chain") and evidence.get("parent_pid"):
        fragments.append(
            f"Core steps remained associated with parent PID {evidence['parent_pid']}."
        )
    if evidence.get("matched_chain_rules"):
        fragments.append(
            "Supporting process-chain detections were present: "
            + ", ".join(evidence["matched_chain_rules"])
            + "."
        )
    if evidence.get("child_processes"):
        fragments.append(
            "Immediate child activity after execution included: "
            + ", ".join(evidence["child_processes"])
            + "."
        )
    elif evidence.get("descendant_processes"):
        fragments.append(
            "Follow-on descendant activity after execution included: "
            + ", ".join(evidence["descendant_processes"])
            + "."
        )

    return " ".join(fragments)


def build_notes(
    incident: dict, evidence: dict, enriched_features: dict, triage_result: dict
) -> list[str]:
    notes: list[str] = []

    if evidence.get("ssh_key_login_count"):
        notes.append(
            f"SSH public key login events observed in scope: {evidence['ssh_key_login_count']}."
        )

    if evidence.get("auth_source_ips"):
        notes.append(
            "Authentication source IPs observed: " + ", ".join(evidence["auth_source_ips"]) + "."
        )

    first_key = evidence.get("latest_ssh_key_login") or evidence.get("first_ssh_key_login")
    if isinstance(first_key, dict) and first_key.get("src_ip"):
        username = first_key.get("username") or "unknown_user"
        notes.append(
            f"Public key authentication was observed for {username} from {first_key['src_ip']}."
        )

    gap = evidence.get("login_to_execution_gap_seconds")
    if isinstance(gap, int) and gap >= 0:
        notes.append(f"Login-to-execution gap was approximately {gap} seconds.")

    if evidence.get("download_hosts"):
        notes.append(f"The payload was downloaded from {', '.join(evidence['download_hosts'])}.")
    if evidence.get("download_urls"):
        notes.append(f"Observed download URLs: {', '.join(evidence['download_urls'])}.")
    if len(evidence.get("download_ports", [])) >= 2:
        notes.append(
            "The payload download used multiple ports, indicating retry or alternate delivery."
        )
    if enriched_features.get("same_parent_process_chain") and evidence.get("parent_pid"):
        notes.append(
            f"All core incident timeline steps shared the same parent PID {evidence['parent_pid']}."
        )
    if evidence.get("payload_path"):
        notes.append(f"The payload path was confirmed as {evidence['payload_path']}.")
    if evidence.get("matched_chain_rules"):
        notes.append(
            "Process-chain evidence also matched: "
            + ", ".join(evidence["matched_chain_rules"])
            + "."
        )
    if evidence.get("network_observations"):
        seen_targets: list[str] = []
        for obs in evidence["network_observations"]:
            dest_ip = obs.get("dest_ip")
            dest_port = obs.get("dest_port")
            service = obs.get("service") or obs.get("proto")
            target = (
                f"{dest_ip}:{dest_port}" if dest_ip and dest_port else (dest_ip or "unknown_target")
            )
            if target in seen_targets:
                continue
            seen_targets.append(target)
            suffix = f" ({service})" if service else ""
            notes.append(f"Network telemetry observed a connection to {target}{suffix}.")
    if evidence.get("http_observations"):
        for obs in evidence["http_observations"]:
            method = obs.get("method") or "HTTP"
            host = obs.get("host") or obs.get("dest_ip") or "unknown_host"
            uri = obs.get("uri") or "/"
            status_code = obs.get("status_code")
            mime_types = obs.get("resp_mime_types") or []
            status_part = f" returning {status_code}" if status_code is not None else ""
            mime_part = f" ({', '.join(mime_types)})" if mime_types else ""
            notes.append(
                f"HTTP telemetry observed {method} {uri} on {host}{status_part}{mime_part}."
            )
    if evidence.get("child_processes"):
        notes.append(
            "Direct child processes observed after execution: "
            + ", ".join(evidence["child_processes"])
            + "."
        )
    if evidence.get("descendant_processes"):
        notes.append(
            "Descendant processes observed after execution: "
            + ", ".join(evidence["descendant_processes"])
            + "."
        )
    if evidence.get("pre_execution_context"):
        commands = "; ".join(
            item["command_line"]
            for item in evidence["pre_execution_context"]
            if item.get("command_line")
        )
        if commands:
            notes.append(f"Pre-execution context on the same host/user included: {commands}.")
    if evidence.get("post_execution_context"):
        commands = "; ".join(
            item["command_line"]
            for item in evidence["post_execution_context"]
            if item.get("command_line")
        )
        if commands:
            notes.append(f"Post-execution context on the same host/user included: {commands}.")
    if enriched_features.get("same_host_and_user_context_confirmed"):
        notes.append("The execution chain remained within the same host and user context.")

    verdict = triage_result.get("verdict") if isinstance(triage_result, dict) else None
    confidence = triage_result.get("confidence") if isinstance(triage_result, dict) else None
    if verdict:
        suffix = f" with {confidence} confidence" if confidence else ""
        notes.append(f"Triage currently classifies this flow as {verdict}{suffix}.")

    if evidence.get("archive_staging_observations") is not None:
        notes.append(
            "Investigation is limited to defender-side archive staging observations; "
            "collection, exfiltration, compromise, and live telemetry coverage are not confirmed."
        )

    return notes


def build_timeline_notes(
    incident: dict,
    evidence: dict,
) -> list[str]:
    timeline_notes = []

    first_key = evidence.get("latest_ssh_key_login") or evidence.get("first_ssh_key_login")
    if isinstance(first_key, dict) and first_key.get("timestamp"):
        username = first_key.get("username") or "unknown_user"
        src_ip = first_key.get("src_ip") or "unknown_source"
        timeline_notes.append(
            f"auth: {first_key.get('timestamp')} successful SSH public key login for "
            f"{username} from {src_ip}"
        )

    for event in incident.get("timeline", []) or []:
        ts = event.get("timestamp") or "unknown_time"
        cmd = event.get("command_line", "") or ""
        if cmd:
            timeline_notes.append(f"incident: {ts} {cmd}")

    for event in evidence.get("archive_staging_observations", []):
        ts = event.get("timestamp") or "unknown_time"
        event_type = event.get("event_type") or "endpoint_event"
        command = event.get("command_line")
        file_path = event.get("file_path")
        if command and file_path:
            detail = f"{command} {file_path}"
        else:
            detail = command or file_path or "archive staging observation"
        timeline_notes.append(f"endpoint_archive_staging: {ts} {event_type} {detail}")

    for item in evidence.get("pre_execution_context", []):
        if item.get("command_line"):
            timeline_notes.append(
                f"pre_context: {item.get('timestamp')} {item.get('command_line')}"
            )
    for item in evidence.get("network_observations", []):
        dest_ip = item.get("dest_ip") or "unknown_ip"
        dest_port = item.get("dest_port")
        target = f"{dest_ip}:{dest_port}" if dest_port is not None else dest_ip
        timeline_notes.append(f"zeek_conn: {item.get('timestamp')} {target}")
    for item in evidence.get("http_observations", []):
        host = item.get("host") or item.get("dest_ip") or "unknown_host"
        uri = item.get("uri") or "/"
        method = item.get("method") or "HTTP"
        timeline_notes.append(f"zeek_http: {item.get('timestamp')} {method} {host}{uri}")

    gap = evidence.get("login_to_execution_gap_seconds")
    if isinstance(gap, int) and gap >= 0:
        timeline_notes.append(f"auth_gap: {gap} seconds from key login to execution")

    return timeline_notes


def sort_timeline_notes(notes: list[str]) -> list[str]:
    def note_ts(note: str) -> datetime:
        parts = note.split(" ", 2)
        if len(parts) >= 2:
            ts = parse_ts(parts[1])
            if ts:
                return ts
        return datetime.max.replace(tzinfo=timezone.utc)

    return sorted(notes, key=note_ts)


def render_attack_story(incident: dict, evidence: dict, enriched_features: dict) -> str:
    host = incident.get("host") or "unknown_host"
    fragments: list[str] = []

    if is_suspicious_archive_staging_incident(incident):
        fragments.append(
            f"Defender-side evidence on {host} shows suspicious local archive staging."
        )
        if evidence.get("archive_staging_paths"):
            fragments.append(
                "Observed archive staging paths included: "
                + ", ".join(evidence["archive_staging_paths"])
                + "."
            )
        if evidence.get("archive_creation_observed"):
            fragments.append(
                "The current detection hit is archive-creation-focused and is tied to "
                "collection.suspicious_archive_staging."
            )
        if evidence.get("chmod_event_present_in_fixture"):
            fragments.append(
                "A chmod event is present in the endpoint fixture, but the current DSL "
                "detection hit does not correlate that permission change."
            )
        fragments.append(
            "Possible collection preparation is retained only as a hypothesis because no "
            "file content inspection, network transfer, destination host, or exfiltration "
            "evidence is present."
        )
        return " ".join(fragments)

    if enriched_features.get("public_key_login_to_execution_observed"):
        first_key = (
            evidence.get("latest_ssh_key_login") or evidence.get("first_ssh_key_login") or {}
        )
        username = (
            first_key.get("username")
            or incident.get("username")
            or incident.get("user")
            or "unknown_user"
        )
        src_ip = first_key.get("src_ip") or "unknown_source"
        fragments.append(
            f"A successful SSH public key login for {username} from {src_ip} "
            f"was observed on {host} before command execution."
        )
    else:
        chain_state = generic_chain_evidence_state(evidence, enriched_features)
        if chain_state["full_chain"]:
            fragments.append(
                f"Available process evidence on {host} indicates a suspicious "
                "download, permission change, and execution sequence."
            )
        elif chain_state["observed_elements"]:
            fragments.append(
                f"Defender-side evidence on {host} supports only these process-chain "
                "elements: " + ", ".join(chain_state["observed_elements"]) + "."
            )
            fragments.append(
                "The full download, permission-change, and execution sequence remains "
                "unestablished."
            )
        else:
            fragments.append(
                f"No concrete defender-side process evidence currently establishes a "
                f"download, permission change, or execution sequence on {host}."
            )

    if evidence.get("download_urls"):
        fragments.append(
            "The payload download URL was " + ", ".join(evidence["download_urls"]) + "."
        )

    if evidence.get("payload_path"):
        fragments.append(f"The payload path was {evidence['payload_path']}.")

    if evidence.get("execution_path"):
        fragments.append(f"The executed path was {evidence['execution_path']}.")

    if evidence.get("matched_chain_rules"):
        fragments.append(
            "The sequence matched process-chain rule(s): "
            + ", ".join(evidence["matched_chain_rules"])
            + "."
        )

    if evidence.get("child_processes"):
        fragments.append(
            "Immediate child processes included: " + ", ".join(evidence["child_processes"]) + "."
        )
    elif evidence.get("descendant_processes"):
        fragments.append(
            "Descendant processes included: " + ", ".join(evidence["descendant_processes"]) + "."
        )

    gap = evidence.get("login_to_execution_gap_seconds")
    if isinstance(gap, int) and gap >= 0:
        fragments.append(f"The login-to-execution gap was approximately {gap} seconds.")

    return " ".join(fragments)


def normalize_enriched_features(enriched_features: dict) -> list[str]:
    return sorted(key for key, value in enriched_features.items() if value is True)


def determine_evidence_level(evidence: dict, enriched_features: dict) -> str:
    score = 0

    if evidence.get("download_events") or evidence.get("download_urls"):
        score += 1
    if evidence.get("chmod_events"):
        score += 1
    if evidence.get("execution_events") or evidence.get("execution_path"):
        score += 1
    if evidence.get("matched_chain_rules"):
        score += 1
    if enriched_features.get("execution_chain_confirmed_by_process_events"):
        score += 1
    if evidence.get("network_observations") or evidence.get("http_observations"):
        score += 1
    if enriched_features.get("public_key_login_to_execution_observed"):
        score += 1
    if evidence.get("archive_staging_observations"):
        score += 1

    if score >= 5:
        return "strong"
    if score >= 3:
        return "moderate"
    if score >= 1:
        return "limited"
    return "none"


def build_evidence_summary(evidence: dict, enriched_features: dict) -> dict:
    observed_facts: list[str] = []
    supporting_signals: list[str] = []
    evidence_gaps: list[str] = []

    if evidence.get("download_urls"):
        observed_facts.append(
            "Payload download URL observed: " + ", ".join(evidence["download_urls"])
        )
    if evidence.get("payload_path"):
        observed_facts.append(f"Payload path observed: {evidence['payload_path']}")
    if evidence.get("chmod_events"):
        chmod_commands = [
            event.get("command_line")
            for event in evidence["chmod_events"]
            if isinstance(event, dict)
            and isinstance(event.get("command_line"), str)
            and event["command_line"].strip()
        ]
        if chmod_commands:
            observed_facts.append(
                "Permission-change command(s) observed: " + "; ".join(chmod_commands)
            )
        else:
            observed_facts.append("Permission-change process evidence was observed.")
    if evidence.get("execution_path"):
        observed_facts.append(f"Execution path observed: {evidence['execution_path']}")
    if evidence.get("auth_source_ips"):
        observed_facts.append(
            "Authentication source IP observed: " + ", ".join(evidence["auth_source_ips"])
        )
    if evidence.get("ssh_key_login_count"):
        observed_facts.append(
            f"SSH public key login events observed: {evidence['ssh_key_login_count']}"
        )
    if evidence.get("child_processes"):
        observed_facts.append("Child processes observed: " + ", ".join(evidence["child_processes"]))

    if evidence.get("matched_chain_rules"):
        supporting_signals.append(
            "Matched process-chain rule(s): " + ", ".join(evidence["matched_chain_rules"])
        )
    if enriched_features.get("same_parent_process_chain"):
        supporting_signals.append("Core process-chain steps share the same parent process.")
    if enriched_features.get("execution_chain_confirmed_by_process_events"):
        supporting_signals.append("Execution chain is confirmed by process telemetry.")
    if enriched_features.get("public_key_login_to_execution_observed"):
        supporting_signals.append("Public key login to command execution correlation is observed.")
    if enriched_features.get("payload_path_confirmed"):
        supporting_signals.append("Payload path is confirmed by process evidence.")

    auditd_facts, auditd_signals = build_auditd_signal_context(evidence.get("auditd_events"))
    endpoint_facts, endpoint_signals = build_endpoint_signal_context(
        evidence.get("endpoint_events")
    )
    for fact in auditd_facts + endpoint_facts:
        append_unique(observed_facts, fact)
    for signal in auditd_signals + endpoint_signals:
        append_unique(supporting_signals, signal)

    if evidence.get("archive_staging_observations") is not None:
        if evidence.get("archive_creation_observed"):
            append_unique(
                observed_facts,
                "Suspicious local archive staging was observed from defender-side evidence.",
            )
        append_unique(
            supporting_signals,
            "Matched detection rule: collection.suspicious_archive_staging.",
        )
        if evidence.get("chmod_event_present_in_fixture"):
            append_unique(
                supporting_signals,
                (
                    "A chmod event is present in the endpoint fixture, but the current "
                    "DSL detection hit is archive-creation-focused."
                ),
            )
        evidence_gaps.extend(
            [
                "No file content inspection was present in evidence.",
                "No network transfer was observed.",
                "No exfiltration was observed.",
                "No destination host or external endpoint was observed.",
                (
                    "No live auditd, Wazuh, or SIEM telemetry source is proven by "
                    "this synthetic fixture."
                ),
            ]
        )

    if evidence.get("archive_staging_observations") is None:
        if not evidence.get("download_events") and not evidence.get("download_urls"):
            evidence_gaps.append("Payload download event details were not present in evidence.")
        if not evidence.get("execution_events") and not evidence.get("execution_path"):
            evidence_gaps.append("Payload execution event details were not present in evidence.")
    if not evidence.get("network_observations"):
        evidence_gaps.append("Network telemetry was not available or not correlated.")
    if not evidence.get("http_observations"):
        evidence_gaps.append("HTTP telemetry was not available or not correlated.")
    if not enriched_features.get("public_key_login_to_execution_observed"):
        evidence_gaps.append("SSH public key login context was not available in this run.")

    if not observed_facts:
        observed_facts.append("No concrete process or authentication facts were extracted.")
    if not supporting_signals:
        supporting_signals.append("No additional supporting signals were available.")

    return {
        "observed_facts": observed_facts,
        "supporting_signals": supporting_signals,
        "evidence_gaps": evidence_gaps,
        "confidence_rationale": (
            "Evidence level is based on observed process execution, SSH authentication "
            "context, matched process-chain detections, available enrichment, and "
            "remaining telemetry gaps."
        ),
    }


def build_recommended_next_steps(evidence: dict, enriched_features: dict) -> list[str]:
    if evidence.get("archive_staging_observations") is not None:
        return [
            (
                "Review the defender-side endpoint timeline for mkdir, file write, "
                "tar, and chmod activity."
            ),
            (
                "Inspect the staged archive and source files through an approved "
                "evidence collection path before drawing content conclusions."
            ),
            "Correlate network telemetry separately before making any exfiltration assessment.",
        ]

    chain_state = generic_chain_evidence_state(evidence, enriched_features)
    if chain_state["full_chain"]:
        steps = [
            "Review the downloaded payload and preserve a copy for analysis.",
            "Validate whether the observed command execution was authorized.",
            "Check the affected host for related process executions around the same timestamp.",
        ]
    else:
        steps = [
            (
                "Review the incident timeline and referenced defender-side evidence to "
                "determine whether download, permission change, or execution occurred."
            ),
            (
                "Collect or correlate process telemetry needed to confirm the missing "
                "process-chain elements."
            ),
        ]
        if chain_state["download_observed"]:
            steps.append("Review and preserve the observed download evidence for analysis.")
        if chain_state["chmod_observed"]:
            steps.append("Review the observed permission-change evidence and its target path.")
        if chain_state["execution_observed"]:
            steps.append("Validate whether the observed command execution was authorized.")

    if not enriched_features.get("public_key_login_to_execution_observed"):
        steps.append("Correlate SSH authentication logs to confirm the login context.")

    if not evidence.get("network_observations") and not evidence.get("http_observations"):
        if chain_state["download_observed"]:
            steps.append("Correlate network or HTTP telemetry for the observed download.")
        else:
            steps.append(
                "Correlate network or HTTP telemetry to determine whether a payload "
                "download occurred."
            )

    return steps


def build_unsupported_claims(evidence: dict, enriched_features: dict) -> list[dict]:
    claims: list[dict] = []

    if evidence.get("archive_staging_observations") is not None:
        claims.extend(
            [
                {
                    "claim": "Do not conclude exfiltration.",
                    "reason": (
                        "No network transfer, destination host, or exfiltration "
                        "evidence was observed."
                    ),
                },
                {
                    "claim": "Do not conclude file contents were collected.",
                    "reason": (
                        "No file content inspection was present in the synthetic endpoint fixture."
                    ),
                },
                {
                    "claim": "Do not conclude host compromise.",
                    "reason": "Current evidence supports suspicious archive staging only.",
                },
                {
                    "claim": "Do not conclude live auditd, Wazuh, or SIEM collection is proven.",
                    "reason": "The input is a synthetic defender-side endpoint fixture.",
                },
            ]
        )

    if not evidence.get("network_observations") and not evidence.get("http_observations"):
        claims.append(
            {
                "claim": "Full network delivery path is confirmed.",
                "reason": "Network/HTTP telemetry was not available or not correlated.",
            }
        )

    if not enriched_features.get("public_key_login_to_execution_observed"):
        claims.append(
            {
                "claim": "The execution was preceded by SSH public key authentication.",
                "reason": "SSH authentication context was not available or not correlated.",
            }
        )

    chain_state = generic_chain_evidence_state(evidence, enriched_features)
    if uses_generic_chain_narrative(evidence, enriched_features) and not chain_state["full_chain"]:
        claims.append(
            {
                "claim": "The full download -> chmod -> execute chain is confirmed.",
                "reason": (
                    "Current defender-side evidence does not establish: "
                    + ", ".join(chain_state["full_chain_gaps"])
                    + "."
                ),
            }
        )

    return claims


def build_missing_pivots(evidence: dict, enriched_features: dict) -> list[dict]:
    pivots: list[dict] = []
    chain_state = generic_chain_evidence_state(evidence, enriched_features)

    if evidence.get("archive_staging_observations") is not None:
        pivots.extend(
            [
                {
                    "pivot": "archive_content_review",
                    "reason": "No file content inspection is present in current evidence.",
                    "priority": "medium",
                },
                {
                    "pivot": "network_transfer_context",
                    "reason": (
                        "No network transfer, destination host, or external endpoint was observed."
                    ),
                    "priority": "medium",
                },
            ]
        )

    if not enriched_features.get("public_key_login_to_execution_observed"):
        pivots.append(
            {
                "pivot": "ssh_auth_context",
                "reason": "SSH auth events were not available or not correlated in this run.",
                "priority": "high",
            }
        )

    if not evidence.get("network_observations") and not evidence.get("http_observations"):
        pivots.append(
            {
                "pivot": "network_http_context",
                "reason": "Network/HTTP telemetry was not available or not correlated.",
                "priority": "medium",
            }
        )

    if not chain_state["download_observed"]:
        pivots.append(
            {
                "pivot": "payload_download_event",
                "reason": "Payload download details were not present in investigation evidence.",
                "priority": "medium",
            }
        )

    if endpoint_payload_context_observed(enriched_features):
        if chain_state["endpoint_full_chain"]:
            endpoint_reason = (
                "Endpoint telemetry observed an ordered same-payload-path download, "
                "permission change, and execution chain, but the payload content and "
                "command context are not yet independently validated."
            )
        else:
            observed = ", ".join(chain_state["endpoint_observed_elements"]) or "payload context"
            gaps = ", ".join(chain_state["endpoint_full_chain_gaps"])
            endpoint_reason = (
                f"Endpoint telemetry supports these process-chain elements: {observed}; "
                f"it does not establish the full chain without {gaps}."
            )
        append_pivot_once(
            pivots,
            {
                "pivot": "inspect_payload_or_command_context",
                "reason": endpoint_reason,
                "priority": "high",
            },
        )

    return pivots


def build_recommended_pivots(evidence: dict, enriched_features: dict) -> list[dict]:
    pivots: list[dict] = []
    chain_state = generic_chain_evidence_state(evidence, enriched_features)

    if evidence.get("archive_staging_observations") is not None:
        return [
            {
                "pivot": "archive_staging_timeline_review",
                "reason": (
                    "Review mkdir, file write, tar, and chmod observations in the endpoint fixture."
                ),
                "source_artifact": "endpoint_events",
                "priority": "medium",
            }
        ]

    if evidence.get("payload_path") or evidence.get("execution_path"):
        pivots.append(
            {
                "pivot": "payload_file_review",
                "reason": "A payload or execution path is available and should be reviewed.",
                "source_artifact": "process_events",
                "priority": "high",
            }
        )

    if evidence.get("download_hosts"):
        pivots.append(
            {
                "pivot": "payload_source_review",
                "reason": "Payload source host was observed in the download evidence.",
                "source_artifact": "process_events",
                "priority": "medium",
            }
        )

    if enriched_features.get("public_key_login_to_execution_observed"):
        pivots.append(
            {
                "pivot": "ssh_session_review",
                "reason": "A public key login was correlated with command execution.",
                "source_artifact": "ssh_auth_events",
                "priority": "high",
            }
        )

    if endpoint_payload_context_observed(enriched_features):
        if chain_state["endpoint_full_chain"]:
            endpoint_reason = (
                "Inspect the observed payload path, command line, and related network "
                "or HTTP telemetry to validate the ordered endpoint chain."
            )
        else:
            observed = ", ".join(chain_state["endpoint_observed_elements"]) or "payload context"
            gaps = ", ".join(chain_state["endpoint_full_chain_gaps"])
            endpoint_reason = (
                f"Review endpoint evidence for the observed {observed}; collect or "
                f"correlate {gaps} before assessing a full chain."
            )
        append_pivot_once(
            pivots,
            {
                "pivot": "inspect_payload_or_command_context",
                "reason": endpoint_reason,
                "source_artifact": "endpoint_events",
                "priority": "high",
            },
        )

    if not pivots:
        pivots.append(
            {
                "pivot": "incident_timeline_review",
                "reason": (
                    "Review the incident timeline and referenced defender-side evidence, "
                    "then collect process telemetry for unresolved chain elements."
                ),
                "source_artifact": "incident",
                "priority": "medium",
            }
        )

    return pivots


def build_investigation_result(
    incident: dict,
    triage_result: dict,
    attack_result: dict | None = None,
    process_events: list[dict] | None = None,
    auditd_events: list[dict] | None = None,
    endpoint_events: object = None,
    endpoint_events_source: str | None = None,
    process_chain_hits: list[dict] | dict | None = None,
    zeek_enrichment: list[dict] | None = None,
    wazuh_fim_alerts: list[dict] | None = None,
    wazuh_sudo_alerts: list[dict] | None = None,
    ssh_auth_events: list[dict] | None = None,
    run_id: str | None = None,
) -> dict:
    evidence, enriched_features = build_base_evidence(incident)
    add_process_context(process_events, incident, evidence, enriched_features)
    add_auditd_context(auditd_events, evidence)
    add_endpoint_context(endpoint_events, evidence)
    enrich_with_endpoint_events(endpoint_events, enriched_features)
    add_archive_staging_context(incident, endpoint_events, evidence, enriched_features)
    enrich_with_process_chain_hits(process_chain_hits, evidence, enriched_features)
    add_auth_execution_context(ssh_auth_events, incident, evidence, enriched_features)
    promote_context_into_evidence(evidence)
    enrich_with_zeek_enrichment(zeek_enrichment, evidence, enriched_features)

    notes = build_notes(incident, evidence, enriched_features, triage_result)
    timeline_notes = build_timeline_notes(incident, evidence)

    auth_builder = load_auth_patch_builder()
    if auth_builder:
        auth_patch = auth_builder(
            ssh_auth_events=ssh_auth_events,
            incident=incident,
            payload_source_ips=evidence.get("download_hosts") or [],
        )
        merge_patch(evidence, enriched_features, notes, timeline_notes, auth_patch)

    wazuh_builder = load_wazuh_patch_builder()
    if wazuh_builder:
        fim_patch = wazuh_builder(
            wazuh_alerts=wazuh_fim_alerts,
            host=incident.get("host"),
        )
        merge_patch(evidence, enriched_features, notes, timeline_notes, fim_patch)

        sudo_patch = wazuh_builder(
            wazuh_alerts=wazuh_sudo_alerts,
            host=incident.get("host"),
            candidate_paths=WAZUH_PERSISTENCE_PATHS,
        )
        merge_patch(evidence, enriched_features, notes, timeline_notes, sudo_patch)

    timeline_notes = sort_timeline_notes(timeline_notes)
    summary = render_summary(incident, evidence, enriched_features)

    source_inputs = {
        "incident_json": True,
        "triage_result_json": True,
        "process_events_json": bool(process_events),
        "auditd_events_json": bool(auditd_events),
        "process_chain_hits_json": bool(process_chain_hits),
        "ssh_auth_events_json": bool(ssh_auth_events),
        "zeek_enrichment_json": bool(zeek_enrichment),
        "wazuh_fim_alerts_json": bool(wazuh_fim_alerts),
        "wazuh_sudo_alerts_json": bool(wazuh_sudo_alerts),
    }
    if endpoint_events is not None:
        source_inputs["endpoint_events_json"] = endpoint_events_source or True

    attack_story = render_attack_story(incident, evidence, enriched_features)
    evidence_level = determine_evidence_level(evidence, enriched_features)
    evidence_summary = build_evidence_summary(evidence, enriched_features)
    enriched_feature_list = normalize_enriched_features(enriched_features)
    recommended_next_steps = build_recommended_next_steps(evidence, enriched_features)

    return {
        "investigation_id": f"investigation-{incident['incident_id']}",
        "incident_id": incident["incident_id"],
        "triage_id": triage_result.get("triage_id"),
        "attack_id": resolve_attack_id(
            incident=incident,
            attack_result=attack_result,
            run_id=run_id,
        ),
        "summary": summary,
        "attack_story": attack_story,
        "evidence": evidence,
        "enriched_features": enriched_feature_list,
        "evidence_level": evidence_level,
        "evidence_summary": evidence_summary,
        "unsupported_claims": build_unsupported_claims(evidence, enriched_features),
        "missing_pivots": build_missing_pivots(evidence, enriched_features),
        "recommended_pivots": build_recommended_pivots(evidence, enriched_features),
        "investigation_notes": notes,
        "timeline_notes": timeline_notes,
        "recommended_next_steps": recommended_next_steps,
        "source_inputs": source_inputs,
    }


def _validate_boundary_artifact(
    value: object,
    *,
    schema_path: Path,
    artifact_name: str,
    index: int,
) -> dict:
    schema = load_json(schema_path)
    validator_class = validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema)
    error = next(iter(validator.iter_errors(value)), None)
    if error is not None:
        path = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise InvestigationBoundaryValidationError(
            f"{artifact_name}[{index}] schema validation failed at {path}: {error.message}"
        ) from None
    return value


def build_investigation_results_from_incidents_and_triages(
    incidents: object,
    triage_results: object,
    *,
    attack_result: dict | None = None,
    process_events: list[dict] | None = None,
    auditd_events: list[dict] | None = None,
    endpoint_events: object = None,
    endpoint_events_source: str | None = None,
    process_chain_hits: list[dict] | dict | None = None,
    zeek_enrichment: list[dict] | None = None,
    wazuh_fim_alerts: list[dict] | None = None,
    wazuh_sudo_alerts: list[dict] | None = None,
    ssh_auth_events: list[dict] | None = None,
    run_id: str | None = None,
) -> list[dict]:
    """Build one deterministic pre-case Investigation per Incident/Triage pair."""

    if not isinstance(incidents, list):
        raise InvestigationBoundaryValidationError("incidents must be a list")
    if not isinstance(triage_results, list):
        raise InvestigationBoundaryValidationError("triage_results must be a list")

    validated_incidents: list[dict] = []
    incident_ids: list[str] = []
    for index, incident in enumerate(incidents):
        validated_incident = _validate_boundary_artifact(
            incident,
            schema_path=INCIDENT_SCHEMA_FILE,
            artifact_name="incidents",
            index=index,
        )
        incident_id = validated_incident.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise InvestigationBoundaryValidationError(
                f"incidents[{index}].incident_id must be a non-empty string"
            )
        validated_incidents.append(validated_incident)
        incident_ids.append(incident_id)

    if len(incident_ids) != len(set(incident_ids)):
        raise InvestigationBoundaryValidationError("incident_id values must be unique")

    validated_triages: list[dict] = []
    triage_ids: list[str] = []
    triage_incident_ids: list[str] = []
    for index, triage_result in enumerate(triage_results):
        validated_triage = _validate_boundary_artifact(
            triage_result,
            schema_path=TRIAGE_SCHEMA_FILE,
            artifact_name="triage_results",
            index=index,
        )
        triage_id = validated_triage.get("triage_id")
        if not isinstance(triage_id, str) or not triage_id.strip():
            raise InvestigationBoundaryValidationError(
                f"triage_results[{index}].triage_id must be a non-empty string"
            )
        triage_incident_id = validated_triage.get("incident_id")
        if not isinstance(triage_incident_id, str) or not triage_incident_id.strip():
            raise InvestigationBoundaryValidationError(
                f"triage_results[{index}].incident_id must be a non-empty string"
            )
        validated_triages.append(validated_triage)
        triage_ids.append(triage_id)
        triage_incident_ids.append(triage_incident_id)

    if len(triage_ids) != len(set(triage_ids)):
        raise InvestigationBoundaryValidationError("triage_id values must be unique")
    if len(triage_incident_ids) != len(set(triage_incident_ids)):
        raise InvestigationBoundaryValidationError(
            "triage result incident_id values must be unique"
        )

    incident_id_set = set(incident_ids)
    triage_incident_id_set = set(triage_incident_ids)
    if incident_id_set != triage_incident_id_set:
        missing_triage_ids = sorted(incident_id_set - triage_incident_id_set)
        orphan_triage_ids = sorted(triage_incident_id_set - incident_id_set)
        raise InvestigationBoundaryValidationError(
            "Incident/Triage incident_id sets must match exactly; "
            f"missing triage for {missing_triage_ids}, orphan triage for {orphan_triage_ids}"
        )

    if endpoint_events is not None:
        _validate_boundary_artifact(
            endpoint_events,
            schema_path=ENDPOINT_EVENTS_SCHEMA_FILE,
            artifact_name="endpoint_events",
            index=0,
        )

    triages_by_incident_id = {
        triage_result["incident_id"]: triage_result for triage_result in validated_triages
    }
    ordered_incidents = sorted(
        validated_incidents,
        key=lambda incident: incident["incident_id"],
    )

    investigation_results: list[dict] = []
    for index, incident in enumerate(ordered_incidents):
        triage_result = triages_by_incident_id[incident["incident_id"]]
        investigation_result = build_investigation_result(
            incident=incident,
            triage_result=triage_result,
            attack_result=attack_result,
            process_events=process_events,
            auditd_events=auditd_events,
            endpoint_events=endpoint_events,
            endpoint_events_source=endpoint_events_source,
            process_chain_hits=process_chain_hits,
            zeek_enrichment=zeek_enrichment,
            wazuh_fim_alerts=wazuh_fim_alerts,
            wazuh_sudo_alerts=wazuh_sudo_alerts,
            ssh_auth_events=ssh_auth_events,
            run_id=run_id,
        )
        validated_result = _validate_boundary_artifact(
            investigation_result,
            schema_path=INVESTIGATION_SCHEMA_FILE,
            artifact_name="investigation_results",
            index=index,
        )
        if validated_result["incident_id"] != incident["incident_id"]:
            raise InvestigationBoundaryValidationError(
                f"investigation_results[{index}].incident_id must match input incident_id "
                f"{incident['incident_id']}"
            )
        if validated_result.get("triage_id") != triage_result["triage_id"]:
            raise InvestigationBoundaryValidationError(
                f"investigation_results[{index}].triage_id must match input triage_id "
                f"{triage_result['triage_id']}"
            )
        investigation_id = validated_result.get("investigation_id")
        if not isinstance(investigation_id, str) or not investigation_id.strip():
            raise InvestigationBoundaryValidationError(
                f"investigation_results[{index}].investigation_id must be a non-empty string"
            )
        investigation_results.append(validated_result)

    investigation_ids = [
        investigation_result["investigation_id"] for investigation_result in investigation_results
    ]
    if len(investigation_ids) != len(set(investigation_ids)):
        raise InvestigationBoundaryValidationError("investigation_id values must be unique")

    for index, (incident, investigation_result) in enumerate(
        zip(ordered_incidents, investigation_results, strict=True)
    ):
        expected_investigation_id = f"investigation-{incident['incident_id']}"
        if investigation_result["investigation_id"] != expected_investigation_id:
            raise InvestigationBoundaryValidationError(
                f"investigation_results[{index}].investigation_id must be "
                f"{expected_investigation_id}"
            )

    return investigation_results


def write_json(path: str | Path, data: dict) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate investigation_result.json from incident and triage"
    )
    parser.add_argument("--run-id", help="Run ID for run-based artifact paths")
    parser.add_argument("--incident", default=str(DEFAULT_INCIDENT_FILE))
    parser.add_argument("--triage", default=str(DEFAULT_TRIAGE_FILE))
    parser.add_argument("--attack", default=str(DEFAULT_ATTACK_FILE))
    parser.add_argument("--process-events", default=str(DEFAULT_PROCESS_EVENTS_FILE))
    parser.add_argument("--auditd-events", default=str(DEFAULT_AUDITD_EVENTS_FILE))
    parser.add_argument("--endpoint-events", default=str(DEFAULT_ENDPOINT_EVENTS_FILE))
    parser.add_argument("--process-chain-hits", default=str(DEFAULT_PROCESS_CHAIN_HITS_FILE))
    parser.add_argument("--ssh-auth-events", default=str(DEFAULT_SSH_AUTH_EVENTS_FILE))
    parser.add_argument("--zeek-enrichment", default=str(DEFAULT_ZEEK_ENRICHMENT_FILE))
    parser.add_argument("--wazuh-fim-alerts", default=str(DEFAULT_WAZUH_FIM_ALERTS_FILE))
    parser.add_argument("--wazuh-sudo-alerts", default=str(DEFAULT_WAZUH_SUDO_ALERTS_FILE))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_FILE))
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA_FILE))
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.run_id:
        run_paths = get_run_paths(args.run_id)
        run_dir = getattr(run_paths, "run_dir", Path("data/runs") / args.run_id)

        incident_path = str(run_paths.incident)
        triage_path = str(run_paths.triage_result)
        attack_path = str(run_paths.attack_result)
        process_events_path = str(run_paths.process_events)
        auditd_events_path = str(
            getattr(run_paths, "auditd_events", Path(run_dir) / "auditd_events.json")
        )
        endpoint_events_path = str(
            getattr(run_paths, "endpoint_events", Path(run_dir) / "endpoint_events.json")
        )
        process_chain_hits_path = str(run_paths.process_chain_hits)
        ssh_auth_events_path = str(
            getattr(run_paths, "ssh_auth_events", Path(run_dir) / "ssh_auth_events.json")
        )
        zeek_enrichment_path = str(run_paths.zeek_enrichment)
        wazuh_fim_alerts_path = str(
            getattr(run_paths, "wazuh_fim_alerts", Path(run_dir) / "wazuh_fim_alerts.json")
        )
        wazuh_sudo_alerts_path = str(
            getattr(run_paths, "wazuh_sudo_alerts", Path(run_dir) / "wazuh_sudo_alerts.json")
        )
        output_path = str(run_paths.investigation_result)
    else:
        incident_path = args.incident
        triage_path = args.triage
        attack_path = args.attack
        process_events_path = args.process_events
        auditd_events_path = args.auditd_events
        endpoint_events_path = args.endpoint_events
        process_chain_hits_path = args.process_chain_hits
        ssh_auth_events_path = args.ssh_auth_events
        zeek_enrichment_path = args.zeek_enrichment
        wazuh_fim_alerts_path = args.wazuh_fim_alerts
        wazuh_sudo_alerts_path = args.wazuh_sudo_alerts
        output_path = args.output

    incident = load_incident(incident_path)
    triage_result = load_json(triage_path)
    attack_result = load_optional_json(attack_path)
    process_events = load_optional_json(process_events_path)
    auditd_events = load_optional_json(auditd_events_path)
    endpoint_events = load_optional_endpoint_events(
        endpoint_events_path,
        DEFAULT_ENDPOINT_EVENTS_SCHEMA_FILE,
    )
    process_chain_hits = load_optional_json(process_chain_hits_path)
    ssh_auth_events = load_optional_json(ssh_auth_events_path)
    zeek_enrichment = load_optional_json(zeek_enrichment_path)
    wazuh_fim_alerts = load_optional_json(wazuh_fim_alerts_path)
    wazuh_sudo_alerts = load_optional_json(wazuh_sudo_alerts_path)

    result = build_investigation_result(
        incident=incident,
        triage_result=triage_result,
        attack_result=attack_result,
        process_events=process_events,
        auditd_events=auditd_events,
        endpoint_events=endpoint_events,
        endpoint_events_source=endpoint_events_path if endpoint_events is not None else None,
        process_chain_hits=process_chain_hits,
        ssh_auth_events=ssh_auth_events,
        zeek_enrichment=zeek_enrichment,
        wazuh_fim_alerts=wazuh_fim_alerts,
        wazuh_sudo_alerts=wazuh_sudo_alerts,
        run_id=args.run_id,
    )

    schema = load_json(args.schema)
    validate(instance=result, schema=schema)

    write_json(output_path, result)
    print(f"Generated investigation result: {output_path}")


if __name__ == "__main__":
    main()
