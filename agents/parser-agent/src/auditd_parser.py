import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from string import hexdigits
from typing import Any

SYSLOG_RE = re.compile(
    r"^(?P<collector_timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>\S+)\s+"
    r"(?P<message>.*)$"
)
TYPE_RE = re.compile(r"\btype=(?P<record_type>[A-Z_]+)\b")
MSG_RE = re.compile(r"\bmsg=audit\((?P<audit_epoch>[0-9.]+):(?P<audit_serial>\d+)\)")
KV_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\"(?:\\.|[^\"])*\"|\S+)")
EXECVE_SYSCALLS = {"59": "execve"}
FILE_SYSCALLS = {
    "2": "open",
    "82": "rename",
    "85": "creat",
    "87": "unlink",
    "90": "chmod",
    "83": "mkdir",
    "257": "openat",
    "263": "unlinkat",
    "268": "fchmodat",
}
KNOWN_AUDIT_KEYS = {"isl_execve", "isl_tmp_marker", "isl_ssh_persistence"}
O_WRONLY = 0o1
O_RDWR = 0o2
O_CREAT = 0o100
O_TRUNC = 0o1000


def strip_quotes(value: str) -> str:
    if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value


def parse_kv_pairs(message: str) -> dict[str, str]:
    return {
        match.group("key"): strip_quotes(match.group("value")) for match in KV_RE.finditer(message)
    }


def parse_audit_fields(message: str) -> tuple[dict[str, str], dict[str, str]]:
    main_message, *interpreted_parts = message.split("#035")
    return parse_kv_pairs(main_message), parse_kv_pairs(" ".join(interpreted_parts))


def parse_syslog_auditd_line(line: str, host_override: str | None = None) -> dict[str, Any] | None:
    raw_line = line.rstrip("\n")
    if not raw_line.strip():
        return None

    prefix_match = SYSLOG_RE.match(raw_line)
    if not prefix_match:
        return None

    message = prefix_match.group("message")
    type_match = TYPE_RE.search(message)
    msg_match = MSG_RE.search(message)
    if not type_match or not msg_match:
        return None

    fields, interpreted_fields = parse_audit_fields(message)
    host = host_override or prefix_match.group("host")
    program = prefix_match.group("program").removesuffix(":")

    return {
        "collector_timestamp": prefix_match.group("collector_timestamp"),
        "host": host,
        "program": program,
        "record_type": type_match.group("record_type"),
        "audit_epoch_raw": msg_match.group("audit_epoch"),
        "audit_serial": msg_match.group("audit_serial"),
        "fields": fields,
        "interpreted_fields": interpreted_fields,
        "raw_message": message,
        "raw_line": raw_line,
    }


def audit_epoch_to_iso8601(audit_epoch_raw: str | None) -> str | None:
    if not audit_epoch_raw:
        return None
    try:
        return (
            datetime.fromtimestamp(float(audit_epoch_raw), UTC).isoformat().replace("+00:00", "Z")
        )
    except ValueError:
        return None


def maybe_decode_hex(value: str) -> str:
    if len(value) < 2 or len(value) % 2 != 0:
        return value
    if any(char not in hexdigits for char in value):
        return value
    try:
        decoded = bytes.fromhex(value).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return value
    if not decoded:
        return value
    if all(char == "\x00" or (32 <= ord(char) < 127) for char in decoded):
        return decoded.replace("\x00", " ").strip()
    return value


def coerce_int(value: str | None) -> int | str | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return value


def coerce_success(value: str | None) -> bool | str | None:
    if value is None:
        return None
    if value.lower() == "yes":
        return True
    if value.lower() == "no":
        return False
    return value


def first_record(records: list[dict[str, Any]], record_type: str) -> dict[str, Any] | None:
    for record in records:
        if record["record_type"] == record_type:
            return record
    return None


def ordered_record_types(records: list[dict[str, Any]]) -> list[str]:
    record_types: list[str] = []
    for record in records:
        record_type = record["record_type"]
        if record_type not in record_types:
            record_types.append(record_type)
    return record_types


def interpreted_or_numeric(
    syscall_fields: dict[str, str], interpreted_fields: dict[str, str], field: str
) -> tuple[str | None, str | None]:
    numeric = syscall_fields.get(field)
    display = interpreted_fields.get(field.upper())
    return display or numeric, numeric


def normalize_syscall_name(
    syscall_fields: dict[str, str], interpreted_fields: dict[str, str]
) -> tuple[str | None, str | None]:
    syscall_num = syscall_fields.get("syscall")
    syscall = interpreted_fields.get("SYSCALL")
    if not syscall and syscall_num:
        syscall = EXECVE_SYSCALLS.get(syscall_num) or FILE_SYSCALLS.get(syscall_num) or syscall_num
    return syscall, syscall_num


def build_argv(execve_record: dict[str, Any] | None) -> tuple[list[str], list[str]]:
    if not execve_record:
        return [], []

    fields = execve_record["fields"]
    argc_raw = fields.get("argc", "0")
    try:
        argc = int(argc_raw)
    except ValueError:
        argc = 0

    raw_args: list[str] = []
    argv: list[str] = []
    for index in range(argc):
        key = f"a{index}"
        if key not in fields:
            continue
        raw_value = fields[key]
        raw_args.append(raw_value)
        argv.append(maybe_decode_hex(raw_value))
    return argv, raw_args


def build_paths(path_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    for record in path_records:
        fields = record["fields"]
        path = {
            "item": coerce_int(fields.get("item")),
            "name": fields.get("name"),
            "nametype": fields.get("nametype"),
            "mode": fields.get("mode"),
            "ouid": fields.get("ouid"),
            "ogid": fields.get("ogid"),
        }
        paths.append({key: value for key, value in path.items() if value is not None})
    return paths


def choose_file_path(paths: list[dict[str, Any]]) -> str | None:
    for path in paths:
        if path.get("nametype") == "CREATE" and path.get("name"):
            return str(path["name"])
    for path in paths:
        if path.get("nametype") == "NORMAL" and path.get("name"):
            return str(path["name"])
    for path in paths:
        if path.get("name"):
            return str(path["name"])
    return None


def infer_file_action(
    audit_key: str | None, syscall: str | None, syscall_fields: dict[str, str]
) -> str | None:
    if syscall in {"open", "openat"}:
        return file_action_from_open_flags(syscall, syscall_fields)
    if syscall == "creat":
        return "write_create"
    if syscall == "mkdir":
        return "directory_create"
    if syscall in {"chmod", "fchmodat"}:
        return "attribute_change"
    if syscall == "rename":
        return "rename"
    if syscall == "unlink":
        return "delete"
    return None


def parse_numeric_flag(value: str) -> int | None:
    try:
        return int(value, 16)
    except ValueError:
        return None


def open_flag_values(
    syscall: str,
    syscall_fields: dict[str, str],
) -> list[str]:
    values: list[str] = []

    symbolic_flags = syscall_fields.get("flags")
    if symbolic_flags:
        values.append(symbolic_flags)

    argument_name = {
        "open": "a1",
        "openat": "a2",
    }.get(syscall)

    if argument_name:
        numeric_flags = syscall_fields.get(argument_name)
        if numeric_flags:
            values.append(numeric_flags)

    return values


def file_action_from_open_flags(
    syscall: str,
    syscall_fields: dict[str, str],
) -> str | None:
    flag_values = open_flag_values(syscall, syscall_fields)
    flag_text = " ".join(flag_values)

    write_capable = "O_WRONLY" in flag_text or "O_RDWR" in flag_text
    creates = "O_CREAT" in flag_text
    truncates = "O_TRUNC" in flag_text

    for value in flag_values:
        numeric = parse_numeric_flag(value)
        if numeric is None:
            continue
        if numeric & (O_WRONLY | O_RDWR):
            write_capable = True
        if numeric & O_CREAT:
            creates = True
        if numeric & O_TRUNC:
            truncates = True

    if not write_capable:
        return None
    if creates and truncates:
        return "write_create_truncate"
    if creates:
        return "write_create"
    if truncates:
        return "write_truncate"
    return "write"


def infer_event_type(
    audit_key: str | None,
    syscall: str | None,
    paths: list[dict[str, Any]],
    success: bool | str | None,
    file_action: str | None,
) -> str:
    if audit_key == "isl_execve" and syscall == "execve":
        return "process_exec"
    if audit_key == "isl_tmp_marker" and success is True and paths and file_action is not None:
        return "file_write"
    if audit_key == "isl_ssh_persistence":
        names = [str(path.get("name", "")) for path in paths]
        if (
            success is True
            and paths
            and file_action is not None
            and any(".ssh" in name or "authorized_keys" in name for name in names)
        ):
            return "persistence_file_change"
    if audit_key in KNOWN_AUDIT_KEYS:
        return "audit_event"
    if success is True and paths and file_action is not None:
        return "file_write"
    return "audit_event"


def normalize_event(records: list[dict[str, Any]]) -> dict[str, Any]:
    syscall_record = first_record(records, "SYSCALL")
    execve_record = first_record(records, "EXECVE")
    cwd_record = first_record(records, "CWD")
    proctitle_record = first_record(records, "PROCTITLE")
    path_records = [record for record in records if record["record_type"] == "PATH"]

    syscall_fields = syscall_record["fields"] if syscall_record else {}
    interpreted_fields = syscall_record["interpreted_fields"] if syscall_record else {}
    syscall, syscall_num = normalize_syscall_name(syscall_fields, interpreted_fields)
    audit_key = syscall_fields.get("key")

    argv, argv_raw = build_argv(execve_record)
    paths = build_paths(path_records)
    success = coerce_success(syscall_fields.get("success"))
    file_action = infer_file_action(audit_key, syscall, syscall_fields)
    event_type = infer_event_type(audit_key, syscall, paths, success, file_action)
    file_path = None
    if event_type in {"file_write", "persistence_file_change"}:
        file_path = choose_file_path(paths)
    proctitle = None
    if proctitle_record:
        proctitle = maybe_decode_hex(proctitle_record["fields"].get("proctitle", ""))

    event: dict[str, Any] = {
        "source": "auditd",
        "host": records[0]["host"],
        "program": records[0]["program"],
        "audit_serial": records[0]["audit_serial"],
        "collector_timestamp": records[0]["collector_timestamp"],
        "audit_epoch_raw": records[0]["audit_epoch_raw"],
        "audit_timestamp": audit_epoch_to_iso8601(records[0]["audit_epoch_raw"]),
        "record_types": ordered_record_types(records),
        "audit_key": audit_key,
        "event_type": event_type,
        "syscall": syscall,
        "success": success,
        "pid": coerce_int(syscall_fields.get("pid")),
        "ppid": coerce_int(syscall_fields.get("ppid")),
        "session": syscall_fields.get("ses"),
        "tty": syscall_fields.get("tty"),
        "comm": syscall_fields.get("comm"),
        "exe": syscall_fields.get("exe"),
        "cwd": cwd_record["fields"].get("cwd") if cwd_record else None,
        "argv": argv,
        "argv_raw": argv_raw,
        "proctitle": proctitle,
        "paths": paths,
        "file_path": file_path,
        "file_action": file_action,
        "raw_record_count": len(records),
        "raw_records": [record["raw_line"] for record in records],
    }

    if syscall_num is not None:
        event["syscall_num"] = syscall_num

    for field in ("auid", "uid", "gid", "euid"):
        value, numeric = interpreted_or_numeric(syscall_fields, interpreted_fields, field)
        event[field] = value
        if numeric is not None and value != numeric:
            event[f"{field}_num"] = numeric

    return event


def deduplicate_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for record in records:
        key = (
            record["host"],
            record["audit_serial"],
            record["record_type"],
            record["raw_message"],
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped


def parse_auditd_log(
    input_path: str | Path,
    *,
    host: str | None = None,
    audit_key_prefix: str | None = None,
) -> list[dict[str, Any]]:
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(f"auditd log not found: {path}")

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            record = parse_syslog_auditd_line(line, host_override=host)
            if record:
                records.append(record)

    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for record in deduplicate_records(records):
        groups.setdefault(
            (record["host"], record["audit_epoch_raw"], record["audit_serial"]), []
        ).append(record)

    events = [normalize_event(group_records) for group_records in groups.values()]
    if audit_key_prefix:
        events = [
            event
            for event in events
            if isinstance(event.get("audit_key"), str)
            and event["audit_key"].startswith(audit_key_prefix)
        ]

    events.sort(
        key=lambda event: (
            event["collector_timestamp"],
            event["host"],
            event["audit_serial"],
        )
    )
    return events


def write_events(events: list[dict[str, Any]], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(events, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse syslog-collected auditd logs to JSON.")
    parser.add_argument("--input", required=True, help="Path to syslog-collected auditd.log")
    parser.add_argument("--output", required=True, help="Path to write normalized auditd JSON")
    parser.add_argument("--host", help="Optional host override; defaults to syslog prefix host")
    parser.add_argument(
        "--audit-key-prefix",
        help="Optional audit key prefix filter, for example isl_",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    events = parse_auditd_log(
        args.input,
        host=args.host,
        audit_key_prefix=args.audit_key_prefix,
    )
    write_events(events, args.output)
    print(f"Wrote {len(events)} auditd events to {args.output}")


if __name__ == "__main__":
    main()
