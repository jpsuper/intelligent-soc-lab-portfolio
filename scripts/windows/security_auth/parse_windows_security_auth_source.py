from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_SCHEMA_PATH = (
    REPOSITORY_ROOT / "schemas" / "windows_security_auth_source_fixture.schema.json"
)
PARSED_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "windows_security_auth_parsed_event.schema.json"

EXPECTED_PROVIDER_NAME = "Microsoft-Windows-Security-Auditing"
EXPECTED_PROVIDER_EVENT_IDS = {4624, 4625}
EXPECTED_CHANNEL = "Security"
SYSTEM_TIME_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
DECIMAL_INTEGER_PATTERN = re.compile(r"^[0-9]+$")
SOURCE_SENTINEL = "-"

SYSTEM_OPTIONAL_FIELDS = {
    "provider_guid": "provider_guid",
    "event_version": "event_version",
    "event_level": "event_level",
    "event_task": "event_task",
    "event_opcode": "event_opcode",
    "event_keywords": "event_keywords",
}
EVENT_DATA_REQUIRED_FIELDS = {
    "SubjectUserSid": "subject_user_sid",
    "SubjectLogonId": "subject_logon_id",
    "TargetUserSid": "target_user_sid",
    "TargetUserName": "target_user_name",
    "TargetDomainName": "target_domain_name",
    "LogonProcessName": "logon_process_name",
    "AuthenticationPackageName": "authentication_package_name",
}
EVENT_DATA_OPTIONAL_SENTINEL_FIELDS = {
    "SubjectUserName": "subject_user_name",
    "SubjectDomainName": "subject_domain_name",
    "WorkstationName": "workstation_name",
    "IpAddress": "source_ip",
}


class WindowsSecurityAuthParseError(ValueError):
    """Raised when a source cannot be parsed as a bounded 4624/4625 event."""


def _load_schema(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validation_error_path(error: ValidationError, *, root: str) -> str:
    path = [str(part) for part in error.absolute_path]
    if error.validator == "required" and isinstance(error.instance, dict):
        missing = next(
            (field for field in error.validator_value if field not in error.instance),
            None,
        )
        if missing is not None:
            path.append(str(missing))
    elif error.validator == "additionalProperties" and isinstance(error.instance, dict):
        allowed = set(error.schema.get("properties", {}))
        unexpected = sorted(set(error.instance) - allowed)
        if unexpected:
            path.append(unexpected[0])
    return ".".join(path) if path else root


def _validate(
    value: Mapping[str, object],
    *,
    schema_path: Path,
    root: str,
    stage: str,
) -> None:
    validator = Draft202012Validator(
        _load_schema(schema_path),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    error = next(iter(validator.iter_errors(value)), None)
    if error is not None:
        path = _validation_error_path(error, root=root)
        raise WindowsSecurityAuthParseError(
            f"Windows Security authentication {stage} failed at {path}"
        ) from None


def _require_mapping(value: object, *, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WindowsSecurityAuthParseError(
            f"Windows Security authentication conversion failed at {path}"
        )
    return value


def _validate_route(system: Mapping[str, object]) -> None:
    if system["provider_name"] != EXPECTED_PROVIDER_NAME:
        raise WindowsSecurityAuthParseError(
            "Windows Security authentication routing failed at system.provider_name"
        )
    if system["provider_event_id"] not in EXPECTED_PROVIDER_EVENT_IDS:
        raise WindowsSecurityAuthParseError(
            "Windows Security authentication routing failed at system.provider_event_id"
        )
    if system["channel"] != EXPECTED_CHANNEL:
        raise WindowsSecurityAuthParseError(
            "Windows Security authentication routing failed at system.channel"
        )


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_system_time(value: object) -> str:
    path = "system.system_time"
    if not isinstance(value, str) or SYSTEM_TIME_PATTERN.fullmatch(value) is None:
        raise WindowsSecurityAuthParseError(
            f"Windows Security authentication conversion failed at {path}"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise WindowsSecurityAuthParseError(
            f"Windows Security authentication conversion failed at {path}"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WindowsSecurityAuthParseError(
            f"Windows Security authentication conversion failed at {path}"
        )
    return _format_utc(parsed)


def _parse_decimal_integer(value: object, *, path: str) -> int:
    if not isinstance(value, str) or DECIMAL_INTEGER_PATTERN.fullmatch(value) is None:
        raise WindowsSecurityAuthParseError(
            f"Windows Security authentication conversion failed at {path}"
        )
    return int(value, 10)


def _copy_present_fields(
    output: dict[str, object],
    source: Mapping[str, object],
    field_mapping: Mapping[str, str],
) -> None:
    for source_field, output_field in field_mapping.items():
        if source_field in source:
            output[output_field] = source[source_field]


def _copy_non_sentinel_fields(
    output: dict[str, object],
    source: Mapping[str, object],
    field_mapping: Mapping[str, str],
) -> None:
    for source_field, output_field in field_mapping.items():
        if source[source_field] != SOURCE_SENTINEL:
            output[output_field] = source[source_field]


def parse_windows_security_auth_source(source: Mapping[str, object]) -> dict[str, object]:
    """Parse one validated provider-like Windows Security auth source mapping."""

    if not isinstance(source, Mapping):
        raise WindowsSecurityAuthParseError(
            "Windows Security authentication source validation failed at source"
        )

    _validate(
        source,
        schema_path=SOURCE_SCHEMA_PATH,
        root="source",
        stage="source validation",
    )
    system = _require_mapping(source["system"], path="system")
    event_data = _require_mapping(source["event_data"], path="event_data")
    _validate_route(system)

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
        "logon_type": _parse_decimal_integer(event_data["LogonType"], path="event_data.LogonType"),
    }
    _copy_present_fields(output, system, SYSTEM_OPTIONAL_FIELDS)
    _copy_present_fields(output, event_data, EVENT_DATA_REQUIRED_FIELDS)
    _copy_non_sentinel_fields(output, event_data, EVENT_DATA_OPTIONAL_SENTINEL_FIELDS)

    if event_data["IpPort"] != SOURCE_SENTINEL:
        output["source_port"] = _parse_decimal_integer(
            event_data["IpPort"], path="event_data.IpPort"
        )

    if system["provider_event_id"] == 4624:
        output["target_logon_id"] = event_data["TargetLogonId"]
    else:
        output["failure_reason"] = event_data["FailureReason"]
        output["status"] = event_data["Status"]
        output["sub_status"] = event_data["SubStatus"]

    _validate(
        output,
        schema_path=PARSED_SCHEMA_PATH,
        root="parsed_event",
        stage="parsed output validation",
    )
    return output
