from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone

from jsonschema import Draft202012Validator
from wazuh_indexer_query_adapter import REPOSITORY_ROOT, SiemQueryAdapterError
from wazuh_indexer_transport import SiemTransportError, execute_wazuh_indexer_query

SUMMARY_SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "schemas"
    / "wazuh_indexer_windows_security_auth_live_smoke_summary.schema.json"
)
SOURCE_NAME = "wazuh-alerts-windows-security-auth"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
EVENT_IDS = {"4624", "4625"}
DEFAULT_WINDOW_SECONDS = 300
MAX_WINDOW_SECONDS = 1800
MAX_RECORDS = 100
COMMON_EVENTDATA_FIELDS = {
    "subjectUserSid",
    "subjectLogonId",
    "targetUserSid",
    "targetUserName",
    "targetDomainName",
    "logonType",
    "logonProcessName",
    "authenticationPackageName",
}
EVENT_SPECIFIC_FIELDS = {
    "4624": {"targetLogonId"},
    "4625": {"failureReason", "status", "subStatus"},
}


class WindowsSecurityAuthLiveSmokeError(ValueError):
    """Stable authentication live-smoke failure without event values."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


def _load_schema() -> dict[str, object]:
    return json.loads(SUMMARY_SCHEMA_PATH.read_text(encoding="utf-8"))


def _parse_rfc3339(value: str, *, category: str = "invalid_smoke_input") -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise WindowsSecurityAuthLiveSmokeError(
            category,
            "Windows Security authentication smoke timestamp was invalid",
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WindowsSecurityAuthLiveSmokeError(
            category,
            "Windows Security authentication smoke timestamp was invalid",
        )
    return parsed.astimezone(timezone.utc)


def _format_rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def _required_mapping(value: object, *, category: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WindowsSecurityAuthLiveSmokeError(
            category,
            "Windows Security authentication smoke response field was invalid",
        )
    return value


def _required_string(value: object, *, category: str) -> str:
    if not isinstance(value, str) or not value:
        raise WindowsSecurityAuthLiveSmokeError(
            category,
            "Windows Security authentication smoke response field was invalid",
        )
    return value


def _delta_summary(values: Sequence[float]) -> dict[str, float]:
    if not values:
        raise WindowsSecurityAuthLiveSmokeError(
            "time_alignment_failed",
            "Windows Security authentication smoke lacked comparable provider times",
        )
    return {
        "minimum": min(values),
        "maximum": max(values),
        "maximum_absolute": max(abs(value) for value in values),
    }


def build_windows_security_auth_live_smoke_request(
    *,
    run_id: str,
    host: str,
    event_id: str,
    anchor: str,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> dict[str, object]:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise WindowsSecurityAuthLiveSmokeError(
            "invalid_smoke_input",
            "Windows Security authentication smoke run ID was invalid",
        )
    if not host.strip() or event_id not in EVENT_IDS:
        raise WindowsSecurityAuthLiveSmokeError(
            "invalid_smoke_input",
            "Windows Security authentication smoke input was invalid",
        )
    if type(window_seconds) is not int or not 1 <= window_seconds <= MAX_WINDOW_SECONDS:
        raise WindowsSecurityAuthLiveSmokeError(
            "invalid_smoke_input",
            "Windows Security authentication smoke window was invalid",
        )
    anchor_time = _parse_rfc3339(anchor)
    half_window = timedelta(seconds=window_seconds / 2)
    return {
        "contract_version": "1.0",
        "request_id": f"live-smoke-{run_id}-{event_id}",
        "backend": "wazuh_indexer",
        "source_names": [SOURCE_NAME],
        "time_range": {
            "start": _format_rfc3339(anchor_time - half_window),
            "end": _format_rfc3339(anchor_time + half_window),
        },
        "filters": [
            {"field": "agent.name", "operator": "eq", "value": host},
            {
                "field": "data.win.system.eventID",
                "operator": "eq",
                "value": event_id,
            },
        ],
        "projection_fields": [],
        "aggregation_fields": [],
        "sort": [],
        "limit": MAX_RECORDS,
        "cursor": None,
    }


def build_windows_security_auth_live_smoke_summary(
    *,
    run_id: str,
    host: str,
    event_id: str,
    response: Mapping[str, object],
) -> dict[str, object]:
    if not RUN_ID_PATTERN.fullmatch(run_id) or not host.strip() or event_id not in EVENT_IDS:
        raise WindowsSecurityAuthLiveSmokeError(
            "invalid_smoke_input",
            "Windows Security authentication smoke input was invalid",
        )
    returned_records = response.get("returned_records")
    records = response.get("records")
    if type(returned_records) is not int or not isinstance(records, list):
        raise WindowsSecurityAuthLiveSmokeError(
            "smoke_response_invalid",
            "Windows Security authentication smoke response was invalid",
        )
    if returned_records < 1 or len(records) != returned_records:
        raise WindowsSecurityAuthLiveSmokeError(
            "no_matching_record",
            "Windows Security authentication smoke returned no complete matching record",
        )
    if (
        response.get("partial") is not False
        or response.get("truncated") is not False
        or response.get("refinement_required") is not False
        or response.get("total_hits_relation") != "eq"
        or response.get("total_hits") != returned_records
        or response.get("next_cursor") is not None
    ):
        raise WindowsSecurityAuthLiveSmokeError(
            "incomplete_live_result",
            "Windows Security authentication smoke result requires a narrower window",
        )

    backend_ids = 0
    alert_ids = 0
    windows_ids = 0
    physical_sources: set[str] = set()
    alert_to_system_deltas: list[float] = []
    required_eventdata = COMMON_EVENTDATA_FIELDS | EVENT_SPECIFIC_FIELDS[event_id]
    for raw_record in records:
        record = _required_mapping(raw_record, category="smoke_response_invalid")
        _required_string(
            record.get("backend_record_id"),
            category="identity_alignment_failed",
        )
        physical_source = _required_string(
            record.get("physical_source"),
            category="smoke_response_invalid",
        )
        fields = _required_mapping(record.get("fields"), category="smoke_response_invalid")
        if fields.get("agent.name") != host:
            raise WindowsSecurityAuthLiveSmokeError(
                "filter_alignment_failed",
                "Windows Security authentication smoke host filter did not align",
            )
        system = _required_mapping(
            fields.get("data.win.system"),
            category="conversion_projection_failed",
        )
        eventdata = _required_mapping(
            fields.get("data.win.eventdata"),
            category="conversion_projection_failed",
        )
        expected_system = {
            "providerName": "Microsoft-Windows-Security-Auditing",
            "eventID": event_id,
            "channel": "Security",
        }
        if any(system.get(key) != value for key, value in expected_system.items()):
            raise WindowsSecurityAuthLiveSmokeError(
                "filter_alignment_failed",
                "Windows Security authentication smoke fixed filters did not align",
            )
        required_system = {
            "providerName",
            "providerGuid",
            "eventID",
            "version",
            "level",
            "task",
            "opcode",
            "keywords",
            "systemTime",
            "eventRecordID",
            "channel",
            "computer",
        }
        if not required_system.issubset(system) or not required_eventdata.issubset(eventdata):
            raise WindowsSecurityAuthLiveSmokeError(
                "conversion_projection_failed",
                "Windows Security authentication smoke conversion projection was incomplete",
            )

        _required_string(fields.get("id"), category="identity_alignment_failed")
        _required_string(system.get("eventRecordID"), category="identity_alignment_failed")
        backend_ids += 1
        alert_ids += 1
        windows_ids += 1
        physical_sources.add(physical_source)

        alert_time = _parse_rfc3339(
            _required_string(record.get("event_time"), category="time_alignment_failed"),
            category="time_alignment_failed",
        )
        system_time = _parse_rfc3339(
            _required_string(system.get("systemTime"), category="time_alignment_failed"),
            category="time_alignment_failed",
        )
        alert_to_system_deltas.append((alert_time - system_time).total_seconds() * 1000)

    provenance = _required_mapping(
        response.get("query_provenance"),
        category="smoke_response_invalid",
    )
    time_range = _required_mapping(
        response.get("executed_time_range"),
        category="smoke_response_invalid",
    )
    summary = {
        "contract_version": "1.0",
        "status": "passed",
        "run_id": run_id,
        "event_id": event_id,
        "request_fingerprint": provenance.get("request_fingerprint"),
        "host_value_sha256": _sha256(host),
        "executed_at": provenance.get("executed_at"),
        "logical_source": SOURCE_NAME,
        "physical_source_count": len(physical_sources),
        "executed_time_range": dict(time_range),
        "results": {
            "total_hits": response.get("total_hits"),
            "total_hits_relation": response.get("total_hits_relation"),
            "returned_records": returned_records,
            "truncated": response.get("truncated"),
            "refinement_required": response.get("refinement_required"),
            "partial": response.get("partial"),
        },
        "identity_presence": {
            "backend_record_id_records": backend_ids,
            "wazuh_alert_id_records": alert_ids,
            "windows_event_record_id_records": windows_ids,
        },
        "filter_alignment": {
            "host": True,
            "provider": True,
            "event_id": True,
            "channel": True,
        },
        "conversion_projection_alignment": {
            "system": True,
            "eventdata_common": True,
            "eventdata_event_specific": True,
        },
        "time_alignment": {
            "records_with_system_time": len(alert_to_system_deltas),
            "alert_to_system_delta_ms": _delta_summary(alert_to_system_deltas),
        },
        "evidence_scope": "bounded_live_wazuh_authentication_alert_query",
        "does_not_establish": [
            "raw_archive_completeness",
            "continuous_runtime_collection",
            "alert_or_detection_coverage",
            "credential_validity_or_compromise",
            "native_windows_parity",
            "cross_platform_pipeline_validation",
        ],
    }
    error = next(
        iter(
            Draft202012Validator(
                _load_schema(),
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            ).iter_errors(summary)
        ),
        None,
    )
    if error is not None:
        raise WindowsSecurityAuthLiveSmokeError(
            "smoke_response_invalid",
            "Windows Security authentication smoke summary failed its public schema",
        )
    return summary


def run_windows_security_auth_live_smoke(
    *,
    run_id: str,
    host: str,
    event_id: str,
    anchor: str,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    execute_query: Callable[[Mapping[str, object]], dict[str, object]] = (
        execute_wazuh_indexer_query
    ),
) -> dict[str, object]:
    request = build_windows_security_auth_live_smoke_request(
        run_id=run_id,
        host=host,
        event_id=event_id,
        anchor=anchor,
        window_seconds=window_seconds,
    )
    response = execute_query(request)
    return build_windows_security_auth_live_smoke_summary(
        run_id=run_id,
        host=host,
        event_id=event_id,
        response=response,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=("Run one bounded read-only live Wazuh Windows Security 4624 or 4625 query.")
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--event-id", required=True, choices=sorted(EVENT_IDS))
    parser.add_argument("--anchor", required=True, help="RFC 3339 event/run anchor")
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=DEFAULT_WINDOW_SECONDS,
        help="centered query window in seconds (default: 300; maximum: 1800)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = run_windows_security_auth_live_smoke(
            run_id=args.run_id,
            host=args.host,
            event_id=args.event_id,
            anchor=args.anchor,
            window_seconds=args.window_seconds,
        )
    except (
        WindowsSecurityAuthLiveSmokeError,
        SiemTransportError,
        SiemQueryAdapterError,
    ) as exc:
        print(json.dumps({"status": "failed", "error_category": exc.category}))
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
