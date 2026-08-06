from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = (
    Path(__file__).resolve().parents[3] / "schemas" / "sysmon_event1_source_fixture.schema.json"
)

EXPECTED_PROVIDER_NAME = "Microsoft-Windows-Sysmon"
EXPECTED_PROVIDER_EVENT_ID = 1
EXPECTED_CHANNEL = "Microsoft-Windows-Sysmon/Operational"

SYSTEM_TIME_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
SYSMON_UTC_TIME_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
    r"\.(?P<fraction>\d{3,7})$"
)
DECIMAL_INTEGER_PATTERN = re.compile(r"^[0-9]+$")
HASH_ALGORITHM_PATTERN = re.compile(r"^[A-Z0-9][A-Z0-9_-]*$")
RULE_NAME_SENTINELS = {"-", "N/A", ""}

SYSTEM_OPTIONAL_FIELDS = {
    "provider_guid": "provider_guid",
    "event_version": "event_version",
    "event_level": "event_level",
    "event_task": "event_task",
    "event_opcode": "event_opcode",
    "event_keywords": "event_keywords",
}
EVENT_DATA_OPTIONAL_FIELDS = {
    "FileVersion": "file_version",
    "Description": "description",
    "Product": "product",
    "Company": "company",
    "OriginalFileName": "original_file_name",
    "CurrentDirectory": "current_directory",
    "LogonGuid": "logon_guid",
    "LogonId": "logon_id",
    "IntegrityLevel": "integrity_level",
    "ParentProcessGuid": "parent_process_guid",
    "ParentCommandLine": "parent_command_line",
    "ParentUser": "parent_user",
}


class SysmonEvent1ParseError(ValueError):
    """Raised when a source cannot be parsed as a Sysmon Event ID 1 event."""


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _validation_error_path(error: ValidationError) -> str:
    path = [str(part) for part in error.absolute_path]
    if error.validator == "required" and isinstance(error.instance, dict):
        missing = next(
            (field for field in error.validator_value if field not in error.instance),
            None,
        )
        if missing is not None:
            path.append(str(missing))
    return ".".join(path) if path else "source"


def _validate_source_schema(source: Mapping[str, object]) -> None:
    try:
        Draft202012Validator(_load_schema()).validate(source)
    except ValidationError as exc:
        path = _validation_error_path(exc)
        raise SysmonEvent1ParseError(
            f"Sysmon Event ID 1 source validation failed at {path}"
        ) from exc


def _require_mapping(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}")
    return value


def _validate_provider_routing(system: Mapping[str, object]) -> None:
    expected_values = {
        "provider_name": EXPECTED_PROVIDER_NAME,
        "provider_event_id": EXPECTED_PROVIDER_EVENT_ID,
        "channel": EXPECTED_CHANNEL,
    }
    for field, expected in expected_values.items():
        if system[field] != expected:
            raise SysmonEvent1ParseError(
                f"Sysmon Event ID 1 routing validation failed at system.{field}"
            )


def _parse_system_time(value: object) -> str:
    path = "system.system_time"
    if not isinstance(value, str) or SYSTEM_TIME_PATTERN.fullmatch(value) is None:
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}")

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}")
    return _format_utc(parsed)


def _parse_sysmon_utc_time(value: object) -> str:
    path = "event_data.UtcTime"
    if not isinstance(value, str):
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}")
    match = SYSMON_UTC_TIME_PATTERN.fullmatch(value)
    if match is None:
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}")

    # Python datetime stores microseconds: pad 3-5 digits and truncate 7 digits.
    microseconds = int(match.group("fraction").ljust(6, "0")[:6])
    try:
        parsed = datetime.strptime(match.group("timestamp"), "%Y-%m-%d %H:%M:%S").replace(
            microsecond=microseconds, tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}") from exc
    return _format_utc(parsed)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_decimal_integer(value: object, path: str) -> int:
    if not isinstance(value, str) or DECIMAL_INTEGER_PATTERN.fullmatch(value) is None:
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}")
    try:
        return int(value, 10)
    except ValueError as exc:
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}") from exc


def _parse_hashes(value: object) -> dict[str, str]:
    path = "event_data.Hashes"
    if not isinstance(value, str):
        raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}")

    parsed: dict[str, str] = {}
    for entry in value.split(","):
        entry = entry.strip()
        if "=" not in entry:
            raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}")
        algorithm, hash_value = (part.strip() for part in entry.split("=", 1))
        algorithm = algorithm.upper()
        if (
            HASH_ALGORITHM_PATTERN.fullmatch(algorithm) is None
            or not hash_value
            or algorithm in parsed
        ):
            raise SysmonEvent1ParseError(f"Sysmon Event ID 1 conversion failed at {path}")
        parsed[algorithm] = hash_value
    return parsed


def _copy_present_fields(
    output: dict[str, object],
    source: Mapping[str, object],
    field_mapping: Mapping[str, str],
) -> None:
    for source_field, output_field in field_mapping.items():
        if source_field in source:
            output[output_field] = source[source_field]


def parse_sysmon_event1_source(source: Mapping[str, object]) -> dict:
    """Parse one validated provider-like Sysmon Event ID 1 source mapping."""

    if not isinstance(source, Mapping):
        raise SysmonEvent1ParseError("Sysmon Event ID 1 source validation failed at source")

    _validate_source_schema(source)
    system = _require_mapping(source["system"], "system")
    event_data = _require_mapping(source["event_data"], "event_data")
    _validate_provider_routing(system)

    output: dict[str, object] = {
        "fixture_contract_version": source["fixture_contract_version"],
        "fixture_id": source["fixture_id"],
        "source_format": source["source_format"],
        "provider_name": system["provider_name"],
        "provider_event_id": system["provider_event_id"],
        "event_record_id": system["event_record_id"],
        "computer": system["computer"],
        "channel": system["channel"],
        "system_time": _parse_system_time(system["system_time"]),
        "utc_time": _parse_sysmon_utc_time(event_data["UtcTime"]),
        "process_guid": event_data["ProcessGuid"],
        "process_id": _parse_decimal_integer(event_data["ProcessId"], "event_data.ProcessId"),
        "image": event_data["Image"],
        "command_line": event_data["CommandLine"],
        "user": event_data["User"],
        "parent_process_id": _parse_decimal_integer(
            event_data["ParentProcessId"], "event_data.ParentProcessId"
        ),
        "parent_image": event_data["ParentImage"],
    }
    _copy_present_fields(output, system, SYSTEM_OPTIONAL_FIELDS)
    _copy_present_fields(output, event_data, EVENT_DATA_OPTIONAL_FIELDS)

    if "TerminalSessionId" in event_data:
        output["terminal_session_id"] = _parse_decimal_integer(
            event_data["TerminalSessionId"], "event_data.TerminalSessionId"
        )
    if "Hashes" in event_data:
        output["hashes"] = _parse_hashes(event_data["Hashes"])
    if "RuleName" in event_data and event_data["RuleName"] not in RULE_NAME_SENTINELS:
        output["rule_name"] = event_data["RuleName"]

    return output
