from __future__ import annotations

import argparse
import json
import shlex
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from loader import load_rules
except ImportError:
    from .loader import load_rules


SUPPORTED_MATCH_KEYS = frozenset(
    {
        "event_type",
        "auth_method",
        "result",
        "detection_type",
        "command_contains",
        "path_suffix",
        "event",
        "source",
        "platform",
        "process_name_casefold",
        "command_token_casefold_any",
    }
)


def load_json(path: str | Path) -> Any:
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def parse_ts(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def event_in_time_window(
    event: dict[str, Any],
    time_min: datetime | None,
    time_max: datetime | None,
) -> bool:
    candidates = [
        event.get("timestamp"),
        event.get("time_window_start"),
        event.get("time_window_end"),
    ]

    parsed_candidates = [parse_ts(v) for v in candidates if v]
    parsed_candidates = [v for v in parsed_candidates if v is not None]

    if not parsed_candidates:
        return True

    event_start = min(parsed_candidates)
    event_end = max(parsed_candidates)

    if time_min and event_end < time_min:
        return False

    if time_max and event_start > time_max:
        return False

    return True


def write_json(path: str | Path, data: Any) -> None:
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _safe_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _casefold_command_tokens(command_line: str) -> set[str]:
    try:
        tokens = shlex.split(command_line, posix=False)
    except ValueError:
        return set()

    normalized_tokens: set[str] = set()
    for token in tokens:
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
            token = token[1:-1]
        normalized_tokens.add(token.casefold())
    return normalized_tokens


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize current lab inputs into a minimal backend-neutral event shape.

    Supports:
    - ssh_auth_events.json style records
    - wazuh_fim_alerts.json style records
    - process_chain_hits.json style records
    - already-normalized dicts
    """
    attributes = raw.get("attributes") or {}
    syscheck = attributes.get("syscheck") or {}
    data = attributes.get("data") or {}

    timeline = raw.get("timeline") or []
    first_ts = timeline[0].get("timestamp") if timeline else raw.get("timestamp")
    last_ts = timeline[-1].get("timestamp") if timeline else raw.get("timestamp")

    host = raw.get("host") or raw.get("agent_name") or data.get("hostname")
    user = (
        raw.get("username") or raw.get("user") or syscheck.get("uname_after") or data.get("srcuser")
    )

    return {
        "event_id": raw.get("event_id"),
        "source": raw.get("source"),
        "platform": raw.get("platform"),
        "timestamp": raw.get("timestamp"),
        "time_window_start": raw.get("time_window_start") or first_ts,
        "time_window_end": raw.get("time_window_end") or last_ts,
        "host": host,
        "user": user,
        "src_ip": raw.get("src_ip") or data.get("srcip"),
        "path": raw.get("path") or raw.get("file_path") or syscheck.get("path"),
        "pid": raw.get("pid"),
        "ppid": raw.get("ppid"),
        "process_name": raw.get("process_name"),
        "file_path": raw.get("file_path"),
        "command_line": raw.get("command_line") or data.get("command"),
        "event_type": raw.get("event_type"),
        "auth_method": raw.get("auth_method"),
        "result": raw.get("result"),
        "detection_type": raw.get("detection_type"),
        "event": raw.get("event") or syscheck.get("event"),
        "raw": raw,
    }


def event_matches_rule(event: dict[str, Any], rule: dict[str, Any]) -> bool:
    match = rule.get("match", {})
    if not isinstance(match, dict):
        return False
    if set(match) - SUPPORTED_MATCH_KEYS:
        return False

    source = match.get("source")
    if source is not None and event.get("source") != source:
        return False

    platform = match.get("platform")
    if platform is not None and event.get("platform") != platform:
        return False

    event_type = match.get("event_type")
    if event_type is not None:
        allowed_event_types = event_type if isinstance(event_type, list) else [event_type]
        if event.get("event_type") not in allowed_event_types:
            return False

    auth_method = match.get("auth_method")
    if auth_method is not None and event.get("auth_method") != auth_method:
        return False

    result = match.get("result")
    if result is not None and event.get("result") != result:
        return False

    detection_type = match.get("detection_type")
    if detection_type is not None and event.get("detection_type") != detection_type:
        return False

    command_contains = match.get("command_contains")
    if command_contains is not None:
        command_line = _safe_str(event.get("command_line"))
        if not command_line:
            return False

        required_fragments = (
            command_contains if isinstance(command_contains, list) else [command_contains]
        )
        if not all(str(fragment) in command_line for fragment in required_fragments):
            return False

    path_suffix = match.get("path_suffix")
    if path_suffix is not None:
        path = _safe_str(event.get("path"))
        if not path or not path.endswith(str(path_suffix)):
            return False

    event_name = match.get("event")
    if event_name is not None and event.get("event") != event_name:
        return False

    process_name_casefold = match.get("process_name_casefold")
    if process_name_casefold is not None:
        process_name = _safe_str(event.get("process_name"))
        if (
            not isinstance(process_name_casefold, str)
            or not process_name_casefold.strip()
            or not process_name
            or process_name.casefold() != process_name_casefold.strip().casefold()
        ):
            return False

    command_token_casefold_any = match.get("command_token_casefold_any")
    if command_token_casefold_any is not None:
        if (
            not isinstance(command_token_casefold_any, list)
            or not command_token_casefold_any
            or not all(
                isinstance(token, str) and token.strip() for token in command_token_casefold_any
            )
        ):
            return False

        command_line = _safe_str(event.get("command_line"))
        if not command_line:
            return False

        command_tokens = _casefold_command_tokens(command_line)
        expected_tokens = {token.strip().casefold() for token in command_token_casefold_any}
        if command_tokens.isdisjoint(expected_tokens):
            return False

    return True


def build_canonical_detection_output(
    *,
    event: dict[str, Any],
    rule: dict[str, Any],
    detection_id: str,
    raw_event_ref: str | None = None,
) -> dict[str, Any]:
    raw_event_refs = [raw_event_ref] if raw_event_ref else []

    return {
        "id": detection_id,
        "rule_id": rule["id"],
        "title": rule["title"],
        "log_source": deepcopy(rule["log_source"]),
        "event_type": event.get("event_type"),
        "artifact": rule["artifact"],
        "severity": rule["severity"],
        "host": event.get("host"),
        "user": event.get("user"),
        "src_ip": event.get("src_ip"),
        "path": event.get("path"),
        "event_id": event.get("event_id"),
        "pid": event.get("pid"),
        "ppid": event.get("ppid"),
        "process_name": event.get("process_name"),
        "file_path": event.get("file_path"),
        "command_line": event.get("command_line"),
        "auth_method": event.get("auth_method"),
        "result": event.get("result"),
        "behavior_features": deepcopy(rule.get("behavior_features", {})),
        "evidence_refs": [],
        "raw_event_refs": raw_event_refs,
        "time_window_start": event.get("time_window_start"),
        "time_window_end": event.get("time_window_end"),
    }


def evaluate_rules_against_events(
    raw_events: list[dict[str, Any]],
    rules: list[dict[str, Any]],
    time_min: datetime | None = None,
    time_max: datetime | None = None,
) -> list[dict[str, Any]]:
    detections: list[dict[str, Any]] = []
    counter = 1

    for index, raw in enumerate(raw_events):
        normalized = normalize_event(raw)

        if not event_in_time_window(normalized, time_min, time_max):
            continue

        raw_ref = f"input[{index}]"

        for rule in rules:
            if event_matches_rule(normalized, rule):
                detections.append(
                    build_canonical_detection_output(
                        event=normalized,
                        rule=rule,
                        detection_id=f"det-{counter:06d}",
                        raw_event_ref=raw_ref,
                    )
                )
                counter += 1

    return detections


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate atomic detection DSL rules against JSON events"
    )
    parser.add_argument(
        "--rules-dir",
        required=True,
        help="Directory containing DSL YAML rules",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Input JSON file (list of events/alerts/hits)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON file for canonical detection outputs",
    )
    parser.add_argument(
        "--time-min",
        help="Lower bound timestamp (ISO-8601)",
    )
    parser.add_argument(
        "--time-max",
        help="Upper bound timestamp (ISO-8601)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    rules = load_rules(args.rules_dir)
    data = load_json(args.input)

    if not isinstance(data, list):
        raise ValueError("Input JSON must be a list of event objects")

    time_min = parse_ts(args.time_min) if args.time_min else None
    time_max = parse_ts(args.time_max) if args.time_max else None

    detections = evaluate_rules_against_events(
        raw_events=data,
        rules=rules,
        time_min=time_min,
        time_max=time_max,
    )
    write_json(args.output, detections)

    print(f"Loaded rules: {len(rules)}")
    print(f"Input events: {len(data)}")
    print(f"Detections: {len(detections)}")
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
