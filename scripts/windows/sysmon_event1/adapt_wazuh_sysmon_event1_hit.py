from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "schemas"
    / "wazuh_sysmon_event1_hit_projection.schema.json"
)

ADAPTER_NAME = "wazuh_sysmon_event1_hit_adapter"
ADAPTER_VERSION = "1.0"

SYSTEM_FIELD_MAPPING = {
    "providerName": "provider_name",
    "providerGuid": "provider_guid",
    "eventID": "provider_event_id",
    "version": "event_version",
    "level": "event_level",
    "task": "event_task",
    "opcode": "event_opcode",
    "keywords": "event_keywords",
    "systemTime": "system_time",
    "eventRecordID": "event_record_id",
    "channel": "channel",
    "computer": "computer",
}
INTEGER_SYSTEM_FIELDS = {
    "eventID",
    "version",
    "level",
    "task",
    "opcode",
    "eventRecordID",
}
EVENT_DATA_FIELD_MAPPING = {
    "ruleName": "RuleName",
    "utcTime": "UtcTime",
    "processGuid": "ProcessGuid",
    "processId": "ProcessId",
    "image": "Image",
    "fileVersion": "FileVersion",
    "description": "Description",
    "product": "Product",
    "company": "Company",
    "originalFileName": "OriginalFileName",
    "commandLine": "CommandLine",
    "currentDirectory": "CurrentDirectory",
    "user": "User",
    "logonGuid": "LogonGuid",
    "logonId": "LogonId",
    "terminalSessionId": "TerminalSessionId",
    "integrityLevel": "IntegrityLevel",
    "hashes": "Hashes",
    "parentProcessGuid": "ParentProcessGuid",
    "parentProcessId": "ParentProcessId",
    "parentImage": "ParentImage",
    "parentCommandLine": "ParentCommandLine",
    "parentUser": "ParentUser",
}


class WazuhSysmonEvent1AdaptError(ValueError):
    """Raised when a Wazuh hit projection cannot be adapted safely."""


def _load_schema() -> dict[str, object]:
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
    elif error.validator == "additionalProperties" and isinstance(error.instance, dict):
        allowed = set(error.schema.get("properties", {}))
        unexpected = sorted(set(error.instance) - allowed)
        if unexpected:
            path.append(unexpected[0])
    return ".".join(path) if path else "projection"


def _validate_projection(projection: Mapping[str, object]) -> None:
    try:
        Draft202012Validator(
            _load_schema(),
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(projection)
    except ValidationError as exc:
        path = _validation_error_path(exc)
        raise WazuhSysmonEvent1AdaptError(
            f"Wazuh Sysmon Event ID 1 projection validation failed at {path}"
        ) from None


def _parse_timestamp(value: str, *, path: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise WazuhSysmonEvent1AdaptError(
            f"Wazuh Sysmon Event ID 1 projection validation failed at {path}"
        ) from None


def _validate_query_window(projection: Mapping[str, object]) -> None:
    retrieval = projection["retrieval"]
    hit = projection["hit"]
    assert isinstance(retrieval, Mapping)
    assert isinstance(hit, Mapping)
    query_window = retrieval["query_window"]
    source = hit["_source"]
    assert isinstance(query_window, Mapping)
    assert isinstance(source, Mapping)

    start = _parse_timestamp(query_window["start"], path="retrieval.query_window.start")
    end = _parse_timestamp(query_window["end"], path="retrieval.query_window.end")
    alert_timestamp = _parse_timestamp(source["timestamp"], path="hit._source.timestamp")
    if start >= end:
        raise WazuhSysmonEvent1AdaptError(
            "Wazuh Sysmon Event ID 1 projection validation failed at retrieval.query_window"
        )
    if not start <= alert_timestamp <= end:
        raise WazuhSysmonEvent1AdaptError(
            "Wazuh Sysmon Event ID 1 projection validation failed at hit._source.timestamp"
        )


def _decimal_integer(value: object, *, path: str) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise WazuhSysmonEvent1AdaptError(f"Wazuh Sysmon Event ID 1 conversion failed at {path}")
    return int(value, 10)


def adapt_wazuh_sysmon_event1_hit(projection: Mapping[str, object]) -> dict[str, object]:
    """Convert one validated Wazuh hit projection to the existing source contract."""

    if not isinstance(projection, Mapping):
        raise WazuhSysmonEvent1AdaptError(
            "Wazuh Sysmon Event ID 1 projection validation failed at projection"
        )
    _validate_projection(projection)
    _validate_query_window(projection)

    retrieval = projection["retrieval"]
    hit = projection["hit"]
    assert isinstance(retrieval, Mapping)
    assert isinstance(hit, Mapping)
    source = hit["_source"]
    assert isinstance(source, Mapping)
    agent = source["agent"]
    manager = source["manager"]
    data = source["data"]
    assert isinstance(agent, Mapping)
    assert isinstance(manager, Mapping)
    assert isinstance(data, Mapping)
    win = data["win"]
    assert isinstance(win, Mapping)
    wazuh_system = win["system"]
    wazuh_event_data = win["eventdata"]
    assert isinstance(wazuh_system, Mapping)
    assert isinstance(wazuh_event_data, Mapping)

    system: dict[str, object] = {}
    for source_field, target_field in SYSTEM_FIELD_MAPPING.items():
        value = wazuh_system[source_field]
        if source_field in INTEGER_SYSTEM_FIELDS:
            value = _decimal_integer(
                value,
                path=f"hit._source.data.win.system.{source_field}",
            )
        system[target_field] = copy.deepcopy(value)

    event_data = {
        target_field: copy.deepcopy(wazuh_event_data[source_field])
        for source_field, target_field in EVENT_DATA_FIELD_MAPPING.items()
        if source_field in wazuh_event_data
    }
    source_event = {
        "fixture_contract_version": "1.0",
        "fixture_id": projection["fixture_id"],
        "source_format": "sysmon_eventlog_json",
        "system": system,
        "event_data": event_data,
    }
    provenance = {
        "source_product": "wazuh_indexer",
        "source_plane": "wazuh_alerts",
        "index": hit["_index"],
        "document_id": hit["_id"],
        "alert_timestamp": source["timestamp"],
        "retrieved_at": retrieval["retrieved_at"],
        "query_ref": retrieval["query_ref"],
        "query_window_start": retrieval["query_window"]["start"],
        "query_window_end": retrieval["query_window"]["end"],
        "agent_id": agent["id"],
        "agent_name": agent["name"],
        "manager_name": manager["name"],
        "adapter_name": ADAPTER_NAME,
        "adapter_version": ADAPTER_VERSION,
        "validation_outcome": "validated",
    }
    return {
        "source_event": source_event,
        "retrieval_provenance": provenance,
    }
