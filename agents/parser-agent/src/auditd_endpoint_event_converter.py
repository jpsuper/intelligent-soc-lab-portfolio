import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import validate

SCHEMA_VERSION = "endpoint_events.v1"
CONVERTER_NAME = "auditd_endpoint_event_converter"
DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schemas/endpoint_events.schema.json"
AUDITD_SOURCE_FIELDS = [
    "program",
    "audit_serial",
    "audit_key",
    "syscall",
    "syscall_num",
    "success",
    "session",
    "tty",
    "auid",
    "auid_num",
    "uid",
    "uid_num",
    "gid",
    "gid_num",
    "euid",
    "euid_num",
    "proctitle",
    "paths",
    "record_types",
    "argv_raw",
    "audit_epoch_raw",
    "audit_timestamp",
    "collector_timestamp",
    "raw_record_count",
]
EVENT_TYPE_MAP = {
    "process_exec": "process_exec",
    "file_write": "file_write",
    "persistence_file_change": "persistence_file_change",
}


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def load_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(data: dict[str, Any], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_auditd_events(input_path: str | Path) -> list[dict[str, Any]]:
    data = load_json(input_path)
    if isinstance(data, list):
        return [event for event in data if isinstance(event, dict)]
    if isinstance(data, dict) and isinstance(data.get("events"), list):
        return [event for event in data["events"] if isinstance(event, dict)]
    raise ValueError("auditd input must be a JSON array or an object with an events array")


def parse_iso_datetime(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def event_filter_timestamp(event: dict[str, Any]) -> datetime | None:
    for key in ("audit_timestamp", "collector_timestamp"):
        value = event.get(key)
        if not isinstance(value, str) or not value:
            continue
        try:
            return parse_iso_datetime(value)
        except ValueError:
            continue
    return None


def auditd_event_search_text(event: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "event_type",
        "audit_key",
        "comm",
        "exe",
        "cwd",
        "file_path",
        "file_action",
        "proctitle",
        "syscall",
    ):
        value = event.get(key)
        if value not in (None, ""):
            parts.append(str(value))

    argv = event.get("argv")
    if isinstance(argv, list):
        parts.extend(str(arg) for arg in argv if str(arg))

    paths = event.get("paths")
    if isinstance(paths, list):
        for path_record in paths:
            if isinstance(path_record, dict):
                name = path_record.get("name")
                if name not in (None, ""):
                    parts.append(str(name))

    return " ".join(parts).lower()


def matches_any_keyword(search_text: str, keywords: list[str] | None) -> bool:
    if not keywords:
        return True
    return any(keyword.lower() in search_text for keyword in keywords)


def matches_no_keywords(search_text: str, keywords: list[str] | None) -> bool:
    if not keywords:
        return True
    return not any(keyword.lower() in search_text for keyword in keywords)


def filter_auditd_events(
    auditd_events: list[dict[str, Any]],
    *,
    since: str | None = None,
    until: str | None = None,
    include_keywords: list[str] | None = None,
    exclude_keywords: list[str] | None = None,
    event_types: list[str] | None = None,
    audit_keys: list[str] | None = None,
) -> list[dict[str, Any]]:
    since_dt = parse_iso_datetime(since) if since else None
    until_dt = parse_iso_datetime(until) if until else None
    allowed_event_types = set(event_types or [])
    allowed_audit_keys = set(audit_keys or [])

    filtered: list[dict[str, Any]] = []
    for event in auditd_events:
        if allowed_event_types and event.get("event_type") not in allowed_event_types:
            continue
        if allowed_audit_keys and event.get("audit_key") not in allowed_audit_keys:
            continue

        if since_dt or until_dt:
            event_dt = event_filter_timestamp(event)
            if event_dt is None:
                continue
            if since_dt and event_dt < since_dt:
                continue
            if until_dt and event_dt > until_dt:
                continue

        search_text = auditd_event_search_text(event)
        if not matches_any_keyword(search_text, include_keywords):
            continue
        if not matches_no_keywords(search_text, exclude_keywords):
            continue

        filtered.append(event)

    return filtered


def filter_metadata(
    *,
    source_event_count: int,
    filtered_event_count: int,
    since: str | None,
    until: str | None,
    include_keywords: list[str] | None,
    exclude_keywords: list[str] | None,
    event_types: list[str] | None,
    audit_keys: list[str] | None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "source_event_count": source_event_count,
        "filtered_event_count": filtered_event_count,
    }
    criteria: dict[str, Any] = {}
    if since:
        criteria["since"] = since
    if until:
        criteria["until"] = until
    if include_keywords:
        criteria["include_keywords"] = include_keywords
    if exclude_keywords:
        criteria["exclude_keywords"] = exclude_keywords
    if event_types:
        criteria["event_types"] = event_types
    if audit_keys:
        criteria["audit_keys"] = audit_keys
    if criteria:
        metadata["filter"] = criteria
    return metadata


def choose_timestamp(event: dict[str, Any], generated_at: str) -> tuple[str, str]:
    audit_timestamp = event.get("audit_timestamp")
    if isinstance(audit_timestamp, str) and audit_timestamp:
        return audit_timestamp, "audit_timestamp"

    collector_timestamp = event.get("collector_timestamp")
    if isinstance(collector_timestamp, str) and collector_timestamp:
        return collector_timestamp, "collector_timestamp"

    return generated_at, "generated_at"


def stable_event_id(event: dict[str, Any], index: int) -> str:
    host = str(event.get("host") or "unknown")
    audit_serial = event.get("audit_serial")
    if audit_serial not in (None, ""):
        return f"auditd:{host}:{audit_serial}"

    fingerprint = json.dumps(
        {
            "source": "auditd",
            "host": host,
            "timestamp": event.get("audit_timestamp") or event.get("collector_timestamp"),
            "event_type": event.get("event_type"),
            "index": index,
        },
        sort_keys=True,
        default=str,
    )
    digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16]
    return f"auditd:{host}:derived:{digest}"


def first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, ""):
            return value
    return None


def command_line_from_event(event: dict[str, Any]) -> str | None:
    argv = event.get("argv")
    if isinstance(argv, list) and argv:
        return " ".join(str(arg) for arg in argv)
    proctitle = event.get("proctitle")
    if isinstance(proctitle, str) and proctitle:
        return proctitle
    return None


def source_fields_for_event(event: dict[str, Any], timestamp_source: str) -> dict[str, Any]:
    source_fields = {
        key: event[key] for key in AUDITD_SOURCE_FIELDS if key in event and event[key] is not None
    }
    source_fields["timestamp_source"] = timestamp_source
    if timestamp_source == "generated_at":
        source_fields["timestamp_was_generated"] = True
    return source_fields


def raw_ref_for_event(event: dict[str, Any], source_artifact: str) -> dict[str, Any]:
    raw_ref: dict[str, Any] = {"source_artifact": source_artifact}
    audit_serial = event.get("audit_serial")
    if audit_serial not in (None, ""):
        raw_ref["audit_serial"] = audit_serial
    return raw_ref


def endpoint_event_type(auditd_event_type: Any) -> str:
    return EVENT_TYPE_MAP.get(str(auditd_event_type), "unknown")


def file_action_for_event(event: dict[str, Any], endpoint_type: str) -> str | None:
    source_action = event.get("file_action")
    if isinstance(source_action, str) and source_action:
        return source_action
    if endpoint_type == "file_write":
        return "write"
    if endpoint_type == "persistence_file_change":
        return "modify"
    return None


def file_path_for_event(event: dict[str, Any], endpoint_type: str) -> str | None:
    if endpoint_type in {"file_write", "persistence_file_change"}:
        file_path = event.get("file_path")
        if isinstance(file_path, str) and file_path:
            return file_path
    return None


def prune_none(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}


def convert_auditd_event(
    event: dict[str, Any],
    *,
    index: int,
    generated_at: str,
    source_artifact: str,
) -> dict[str, Any]:
    timestamp, timestamp_source = choose_timestamp(event, generated_at)
    endpoint_type = endpoint_event_type(event.get("event_type"))
    collection_timestamp = event.get("collector_timestamp")

    endpoint_event = {
        "event_id": stable_event_id(event, index),
        "source": "auditd",
        "platform": "linux",
        "host": str(event.get("host") or "unknown"),
        "timestamp": timestamp,
        "collection_timestamp": collection_timestamp
        if isinstance(collection_timestamp, str) and collection_timestamp
        else None,
        "event_type": endpoint_type,
        "user": first_non_empty(event.get("uid"), event.get("auid"), event.get("euid")),
        "uid": first_non_empty(
            event.get("uid_num"),
            event.get("uid"),
            event.get("auid_num"),
            event.get("auid"),
        ),
        "pid": event.get("pid"),
        "ppid": event.get("ppid"),
        "process_name": event.get("comm"),
        "exe": event.get("exe"),
        "argv": event.get("argv") if isinstance(event.get("argv"), list) else None,
        "command_line": command_line_from_event(event),
        "cwd": event.get("cwd"),
        "file_path": file_path_for_event(event, endpoint_type),
        "file_action": file_action_for_event(event, endpoint_type),
        "raw_ref": raw_ref_for_event(event, source_artifact),
        "source_fields": source_fields_for_event(event, timestamp_source),
    }
    return prune_none(endpoint_event)


def convert_auditd_events(
    auditd_events: list[dict[str, Any]],
    *,
    source_artifact: str,
    source_run_id: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated_at = generated_at or utc_now_iso()
    endpoint_events = [
        convert_auditd_event(
            event,
            index=index,
            generated_at=generated_at,
            source_artifact=source_artifact,
        )
        for index, event in enumerate(auditd_events)
    ]

    envelope: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "source_artifact": source_artifact,
        "metadata": {
            "converter": CONVERTER_NAME,
            "input_event_count": len(auditd_events),
            "output_event_count": len(endpoint_events),
        },
        "events": endpoint_events,
    }
    if source_run_id:
        envelope["source_run_id"] = source_run_id
    return envelope


def validate_endpoint_events(envelope: dict[str, Any], schema_path: str | Path) -> None:
    schema = load_json(schema_path)
    validate(instance=envelope, schema=schema)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert normalized auditd_events.json to endpoint_events.json."
    )
    parser.add_argument("--input", required=True, help="Path to auditd_events.json")
    parser.add_argument("--output", required=True, help="Path to write endpoint_events.json")
    parser.add_argument(
        "--source-artifact",
        help="Source artifact label; defaults to the input path.",
    )
    parser.add_argument("--source-run-id", help="Optional source run identifier")
    parser.add_argument(
        "--since",
        help=(
            "Inclusive lower timestamp bound for auditd events. "
            "Uses audit_timestamp or collector_timestamp."
        ),
    )
    parser.add_argument(
        "--until",
        help=(
            "Inclusive upper timestamp bound for auditd events. "
            "Uses audit_timestamp or collector_timestamp."
        ),
    )
    parser.add_argument(
        "--include-keyword",
        action="append",
        dest="include_keywords",
        help=(
            "Keep events whose command, path, audit key, or process text contains this "
            "case-insensitive keyword. Can be repeated."
        ),
    )
    parser.add_argument(
        "--exclude-keyword",
        action="append",
        dest="exclude_keywords",
        help=(
            "Drop events whose command, path, audit key, or process text contains this "
            "case-insensitive keyword. Can be repeated."
        ),
    )
    parser.add_argument(
        "--event-type",
        action="append",
        dest="event_types",
        help="Keep only auditd events with this normalized event_type. Can be repeated.",
    )
    parser.add_argument(
        "--audit-key",
        action="append",
        dest="audit_keys",
        help="Keep only auditd events with this audit_key. Can be repeated.",
    )
    parser.add_argument(
        "--schema",
        default=str(DEFAULT_SCHEMA_PATH),
        help="Endpoint events schema path used for validation.",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip schema validation before writing output.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    auditd_events = load_auditd_events(args.input)
    filtered_events = filter_auditd_events(
        auditd_events,
        since=args.since,
        until=args.until,
        include_keywords=args.include_keywords,
        exclude_keywords=args.exclude_keywords,
        event_types=args.event_types,
        audit_keys=args.audit_keys,
    )

    source_artifact = args.source_artifact or str(args.input)
    envelope = convert_auditd_events(
        filtered_events,
        source_artifact=source_artifact,
        source_run_id=args.source_run_id,
    )
    envelope["metadata"].update(
        filter_metadata(
            source_event_count=len(auditd_events),
            filtered_event_count=len(filtered_events),
            since=args.since,
            until=args.until,
            include_keywords=args.include_keywords,
            exclude_keywords=args.exclude_keywords,
            event_types=args.event_types,
            audit_keys=args.audit_keys,
        )
    )

    if not args.no_validate:
        validate_endpoint_events(envelope, args.schema)
    write_json(envelope, args.output)
    print(
        f"Wrote {len(envelope['events'])} endpoint events to {args.output} "
        f"from {len(auditd_events)} auditd event(s)"
    )


if __name__ == "__main__":
    main()
