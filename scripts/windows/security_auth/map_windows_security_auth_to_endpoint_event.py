from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PARSED_EVENT_SCHEMA_PATH = (
    REPOSITORY_ROOT / "schemas" / "windows_security_auth_parsed_event.schema.json"
)
ENDPOINT_EVENT_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "endpoint_events.schema.json"

MAPPER_NAME = "windows_security_auth_endpoint_event_mapper"
MAPPER_VERSION = "1.0"
EVENT_IDENTITY_VERSION = "windows-security-auth-event-id.v1"
EVENT_ID_PREFIX = "windows-security-auth:v1:"
EVENT_ID_METHOD = "sha256-json-canonical-v1"

EXPECTED_PROVIDER_NAME = "Microsoft-Windows-Security-Auditing"
EXPECTED_CHANNEL = "Security"
EVENT_TYPE_BY_PROVIDER_EVENT_ID = {
    4624: "auth_success",
    4625: "auth_failure",
}

OPTIONAL_SOURCE_FIELDS = (
    "provider_guid",
    "event_version",
    "event_level",
    "event_task",
    "event_opcode",
    "event_keywords",
    "subject_user_name",
    "subject_domain_name",
    "target_logon_id",
    "workstation_name",
    "failure_reason",
    "status",
    "sub_status",
)


class WindowsSecurityAuthMappingError(ValueError):
    """Raised when a parsed Windows Security auth event cannot be mapped safely."""


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


def validate_parsed_event(parsed_event: dict[str, object]) -> dict[str, object]:
    """Validate and return one parsed authentication event without modifying it."""

    if not isinstance(parsed_event, dict):
        raise WindowsSecurityAuthMappingError(
            "Windows Security authentication mapping failed at parsed_event"
        )

    validator = Draft202012Validator(
        _load_schema(PARSED_EVENT_SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    error = next(iter(validator.iter_errors(parsed_event)), None)
    if error is not None:
        path = _validation_error_path(error, root="parsed_event")
        raise WindowsSecurityAuthMappingError(
            f"Windows Security authentication mapping failed at {path}"
        ) from None

    if parsed_event["provider_name"] != EXPECTED_PROVIDER_NAME:
        raise WindowsSecurityAuthMappingError(
            "Windows Security authentication mapping failed at provider_name"
        )
    if parsed_event["provider_event_id"] not in EVENT_TYPE_BY_PROVIDER_EVENT_ID:
        raise WindowsSecurityAuthMappingError(
            "Windows Security authentication mapping failed at provider_event_id"
        )
    if parsed_event["channel"] != EXPECTED_CHANNEL:
        raise WindowsSecurityAuthMappingError(
            "Windows Security authentication mapping failed at channel"
        )
    return parsed_event


def canonical_event_id(parsed_event: dict[str, object]) -> str:
    """Build the versioned deterministic lab event identifier."""

    identity = {
        "identity_version": EVENT_IDENTITY_VERSION,
        "provider_name": parsed_event["provider_name"],
        "computer_casefold": parsed_event["computer"].casefold(),
        "channel": parsed_event["channel"],
        "event_record_id": parsed_event["event_record_id"],
    }
    fingerprint = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
    return f"{EVENT_ID_PREFIX}{digest}"


def canonical_user(parsed_event: dict[str, object]) -> str:
    """Build the reviewed Windows target-account representation."""

    return f"{parsed_event['target_domain_name']}\\{parsed_event['target_user_name']}"


def build_source_fields(parsed_event: dict[str, object]) -> dict[str, object]:
    """Build compact, allowlisted Windows Security authentication provenance."""

    source_fields: dict[str, object] = {
        "provider_name": parsed_event["provider_name"],
        "provider_event_id": parsed_event["provider_event_id"],
        "event_record_id": parsed_event["event_record_id"],
        "channel": parsed_event["channel"],
        "system_time": parsed_event["system_time"],
        "timestamp_source": "system_time",
        "subject_user_sid": parsed_event["subject_user_sid"],
        "subject_logon_id": parsed_event["subject_logon_id"],
        "target_user_sid": parsed_event["target_user_sid"],
        "target_user_name": parsed_event["target_user_name"],
        "target_domain_name": parsed_event["target_domain_name"],
        "logon_type": parsed_event["logon_type"],
        "logon_process_name": parsed_event["logon_process_name"],
        "authentication_package_name": parsed_event["authentication_package_name"],
        "mapper_name": MAPPER_NAME,
        "mapper_version": MAPPER_VERSION,
        "event_id_method": EVENT_ID_METHOD,
        "event_identity_version": EVENT_IDENTITY_VERSION,
    }
    for field in OPTIONAL_SOURCE_FIELDS:
        if field in parsed_event:
            source_fields[field] = copy.deepcopy(parsed_event[field])
    return source_fields


def validate_endpoint_event(event: dict[str, object]) -> dict[str, object]:
    """Validate and return one event through the canonical endpoint envelope."""

    envelope = {
        "schema_version": "endpoint_events.v1",
        "events": [event],
    }
    validator = Draft202012Validator(
        _load_schema(ENDPOINT_EVENT_SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    error = next(iter(validator.iter_errors(envelope)), None)
    if error is not None:
        path = _validation_error_path(error, root="events.0")
        raise WindowsSecurityAuthMappingError(
            f"Windows Security authentication normalized output failed at {path}"
        ) from None
    return event


def map_windows_security_auth_to_endpoint_event(
    parsed_event: dict[str, object],
    *,
    source_artifact: str,
) -> dict[str, object]:
    """Map one parsed Windows Security 4624/4625 record to one endpoint event."""

    validate_parsed_event(parsed_event)
    if not isinstance(source_artifact, str) or not source_artifact.strip():
        raise WindowsSecurityAuthMappingError(
            "Windows Security authentication mapping failed at source_artifact"
        )

    event: dict[str, object] = {
        "event_id": canonical_event_id(parsed_event),
        "source": "windows_security",
        "platform": "windows",
        "host": parsed_event["computer"],
        "timestamp": parsed_event["system_time"],
        "event_type": EVENT_TYPE_BY_PROVIDER_EVENT_ID[parsed_event["provider_event_id"]],
        "user": canonical_user(parsed_event),
        "raw_ref": {
            "source_artifact": source_artifact,
            "fixture_id": parsed_event["fixture_id"],
        },
        "source_fields": build_source_fields(parsed_event),
    }
    if "source_ip" in parsed_event:
        event["src_ip"] = parsed_event["source_ip"]
    if "source_port" in parsed_event:
        event["src_port"] = parsed_event["source_port"]

    return validate_endpoint_event(event)
