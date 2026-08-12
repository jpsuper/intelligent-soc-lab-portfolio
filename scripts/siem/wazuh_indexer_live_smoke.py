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

SUMMARY_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "wazuh_indexer_live_smoke_summary.schema.json"
SOURCE_NAME = "wazuh-alerts-sysmon-event1"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
WINDOW_HALF_WIDTH = timedelta(minutes=15)
MAX_LIVE_SMOKE_PAGES = 100


class LiveSmokeError(ValueError):
    """Stable live-smoke failure without event or connection values."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


def _load_schema() -> dict[str, object]:
    return json.loads(SUMMARY_SCHEMA_PATH.read_text(encoding="utf-8"))


def _parse_rfc3339(value: str, *, category: str = "invalid_smoke_input") -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise LiveSmokeError(category, "Live smoke timestamp was invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LiveSmokeError(category, "Live smoke timestamp was invalid")
    return parsed.astimezone(timezone.utc)


def _parse_sysmon_utc_time(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError:
        raise LiveSmokeError(
            "time_alignment_failed",
            "Live smoke Sysmon utcTime was invalid",
        ) from None
    return parsed.replace(tzinfo=timezone.utc)


def _format_rfc3339(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def build_live_smoke_request(
    *,
    run_id: str,
    host: str,
    anchor: str,
    limit: int = 100,
) -> dict[str, object]:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise LiveSmokeError("invalid_smoke_input", "Live smoke run ID was invalid")
    if not host.strip():
        raise LiveSmokeError("invalid_smoke_input", "Live smoke host was invalid")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise LiveSmokeError("invalid_smoke_input", "Live smoke limit was invalid")
    anchor_time = _parse_rfc3339(anchor)
    return {
        "contract_version": "1.0",
        "request_id": f"live-smoke-{run_id}",
        "backend": "wazuh_indexer",
        "source_names": [SOURCE_NAME],
        "time_range": {
            "start": _format_rfc3339(anchor_time - WINDOW_HALF_WIDTH),
            "end": _format_rfc3339(anchor_time + WINDOW_HALF_WIDTH),
        },
        "filters": [{"field": "agent.name", "operator": "eq", "value": host}],
        "projection_fields": [],
        "aggregation_fields": [],
        "sort": [],
        "limit": limit,
        "cursor": None,
    }


def _required_mapping(value: object, *, category: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise LiveSmokeError(category, "Live smoke response field was invalid")
    return value


def _required_string(value: object, *, category: str) -> str:
    if not isinstance(value, str) or not value:
        raise LiveSmokeError(category, "Live smoke response field was invalid")
    return value


def _delta_summary(values: Sequence[float]) -> dict[str, float]:
    if not values:
        raise LiveSmokeError(
            "time_alignment_failed",
            "Live smoke response did not contain comparable provider times",
        )
    return {
        "minimum": min(values),
        "maximum": max(values),
        "maximum_absolute": max(abs(value) for value in values),
    }


def build_live_smoke_summary(
    *,
    run_id: str,
    host: str,
    response: Mapping[str, object],
    pagination: Mapping[str, object] | None = None,
) -> dict[str, object]:
    if not RUN_ID_PATTERN.fullmatch(run_id) or not host.strip():
        raise LiveSmokeError("invalid_smoke_input", "Live smoke input was invalid")
    returned_records = response.get("returned_records")
    records = response.get("records")
    if type(returned_records) is not int or not isinstance(records, list):
        raise LiveSmokeError("smoke_response_invalid", "Live smoke response was invalid")
    if returned_records < 1 or len(records) != returned_records:
        raise LiveSmokeError(
            "no_matching_record",
            "Live smoke did not return a complete matching record",
        )
    if (
        response.get("partial") is not False
        or response.get("truncated") is not False
        or response.get("refinement_required") is not False
        or response.get("total_hits_relation") != "eq"
        or response.get("total_hits") != returned_records
    ):
        raise LiveSmokeError(
            "incomplete_live_result",
            "Live smoke response was not a complete bounded result",
        )

    backend_ids = 0
    alert_ids = 0
    windows_ids = 0
    physical_sources: set[str] = set()
    alert_to_system_deltas: list[float] = []
    system_to_utc_deltas: list[float] = []
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
        fields = _required_mapping(
            record.get("fields"),
            category="smoke_response_invalid",
        )
        if fields.get("agent.name") != host:
            raise LiveSmokeError(
                "filter_alignment_failed",
                "Live smoke record did not match the requested host",
            )
        system = _required_mapping(
            fields.get("data.win.system"),
            category="filter_alignment_failed",
        )
        eventdata = _required_mapping(
            fields.get("data.win.eventdata"),
            category="time_alignment_failed",
        )
        expected_system_values = {
            "providerName": "Microsoft-Windows-Sysmon",
            "eventID": "1",
            "channel": "Microsoft-Windows-Sysmon/Operational",
        }
        if any(system.get(key) != value for key, value in expected_system_values.items()):
            raise LiveSmokeError(
                "filter_alignment_failed",
                "Live smoke record did not match the registered fixed filters",
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
        utc_time = _parse_sysmon_utc_time(
            _required_string(eventdata.get("utcTime"), category="time_alignment_failed")
        )
        alert_to_system_deltas.append((alert_time - system_time).total_seconds() * 1000)
        system_to_utc_deltas.append((system_time - utc_time).total_seconds() * 1000)

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
        "time_alignment": {
            "records_with_system_time": len(alert_to_system_deltas),
            "records_with_utc_time": len(system_to_utc_deltas),
            "alert_to_system_delta_ms": _delta_summary(alert_to_system_deltas),
            "system_to_utc_delta_ms": _delta_summary(system_to_utc_deltas),
        },
        "evidence_scope": "bounded_live_wazuh_alert_query",
        "does_not_establish": [
            "raw_archive_completeness",
            "continuous_runtime_collection",
            "detection_coverage",
            "incident_or_compromise",
            "cross_platform_pipeline_validation",
        ],
    }
    if pagination is not None:
        summary["pagination"] = dict(pagination)
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
        raise LiveSmokeError(
            "smoke_response_invalid",
            "Live smoke summary failed its public schema",
        )
    return summary


def _page_value(
    response: Mapping[str, object],
    field: str,
    *,
    category: str = "incomplete_live_result",
) -> object:
    if field not in response:
        raise LiveSmokeError(category, "Live smoke page response was invalid")
    return response[field]


def _collect_live_smoke_pages(
    request: dict[str, object],
    *,
    execute_query: Callable[[Mapping[str, object]], dict[str, object]],
) -> tuple[dict[str, object], dict[str, object]]:
    records: list[object] = []
    page_record_counts: list[int] = []
    seen_cursors: set[str] = set()
    expected_total: int | None = None
    expected_fingerprint: str | None = None
    expected_time_range: object | None = None
    first_response: dict[str, object] | None = None
    final_response: dict[str, object] | None = None

    for _page_number in range(1, MAX_LIVE_SMOKE_PAGES + 1):
        response = execute_query(request)
        if not isinstance(response, Mapping):
            raise LiveSmokeError(
                "smoke_response_invalid",
                "Live smoke page response was invalid",
            )
        response = dict(response)
        returned_records = _page_value(response, "returned_records")
        page_records = _page_value(response, "records")
        total_hits = _page_value(response, "total_hits")
        provenance = _required_mapping(
            _page_value(response, "query_provenance", category="smoke_response_invalid"),
            category="smoke_response_invalid",
        )
        fingerprint = _required_string(
            provenance.get("request_fingerprint"),
            category="smoke_response_invalid",
        )
        executed_time_range = _page_value(
            response,
            "executed_time_range",
            category="smoke_response_invalid",
        )

        if (
            type(returned_records) is not int
            or returned_records < 1
            or not isinstance(page_records, list)
            or len(page_records) != returned_records
            or type(total_hits) is not int
            or total_hits < returned_records
            or returned_records > request["limit"]
            or response.get("partial") is not False
            or response.get("total_hits_relation") != "eq"
            or provenance.get("pagination_mode") != "pit_search_after"
        ):
            raise LiveSmokeError(
                "incomplete_live_result",
                "Live smoke page response was incomplete",
            )

        if first_response is None:
            first_response = response
            expected_total = total_hits
            expected_fingerprint = fingerprint
            expected_time_range = executed_time_range
        elif (
            total_hits != expected_total
            or fingerprint != expected_fingerprint
            or executed_time_range != expected_time_range
        ):
            raise LiveSmokeError(
                "pagination_alignment_failed",
                "Live smoke pages did not retain one bounded query",
            )

        records.extend(page_records)
        page_record_counts.append(returned_records)
        if len(records) > 100 or len(records) > total_hits:
            raise LiveSmokeError(
                "incomplete_live_result",
                "Live smoke cumulative result exceeded its bound",
            )

        next_cursor = response.get("next_cursor")
        if next_cursor is None:
            if (
                response.get("truncated") is not False
                or response.get("refinement_required") is not False
                or len(records) != total_hits
            ):
                raise LiveSmokeError(
                    "incomplete_live_result",
                    "Live smoke final page was incomplete",
                )
            final_response = response
            break
        if (
            not isinstance(next_cursor, str)
            or not next_cursor
            or next_cursor in seen_cursors
            or response.get("truncated") is not True
            or response.get("refinement_required") is not False
        ):
            raise LiveSmokeError(
                "pagination_alignment_failed",
                "Live smoke continuation was invalid",
            )
        seen_cursors.add(next_cursor)
        request["cursor"] = next_cursor
    else:
        raise LiveSmokeError(
            "pagination_limit_exceeded",
            "Live smoke exceeded its page bound",
        )

    assert first_response is not None
    assert final_response is not None
    combined_response = dict(final_response)
    combined_response["records"] = records
    combined_response["returned_records"] = len(records)
    combined_response["query_provenance"] = first_response["query_provenance"]
    pagination = {
        "mode": "pit_search_after",
        "requested_page_size": request["limit"],
        "pages_returned": len(page_record_counts),
        "cursor_resumptions": len(page_record_counts) - 1,
        "page_record_counts": page_record_counts,
        "stable_request_fingerprint": True,
        "stable_search_after_progression": True,
        "final_page_cleanup_confirmed": True,
    }
    return combined_response, pagination


def run_live_smoke(
    *,
    run_id: str,
    host: str,
    anchor: str,
    limit: int = 100,
    require_multiple_pages: bool = False,
    execute_query: Callable[[Mapping[str, object]], dict[str, object]] = (
        execute_wazuh_indexer_query
    ),
) -> dict:
    request = build_live_smoke_request(
        run_id=run_id,
        host=host,
        anchor=anchor,
        limit=limit,
    )
    response, pagination = _collect_live_smoke_pages(
        request,
        execute_query=execute_query,
    )
    if require_multiple_pages and pagination["pages_returned"] < 2:
        raise LiveSmokeError(
            "pagination_not_exercised",
            "Live smoke did not exercise cursor pagination",
        )
    return build_live_smoke_summary(
        run_id=run_id,
        host=host,
        response=response,
        pagination=pagination,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one bounded read-only live Wazuh Sysmon Event ID 1 query."
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--anchor", required=True, help="RFC 3339 incident/run anchor")
    parser.add_argument(
        "--limit",
        "--page-size",
        dest="limit",
        type=int,
        default=100,
        help="records requested per page (default: 100)",
    )
    parser.add_argument(
        "--require-multiple-pages",
        action="store_true",
        help="fail unless at least one protected cursor is resumed",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = run_live_smoke(
            run_id=args.run_id,
            host=args.host,
            anchor=args.anchor,
            limit=args.limit,
            require_multiple_pages=args.require_multiple_pages,
        )
    except (LiveSmokeError, SiemTransportError, SiemQueryAdapterError) as exc:
        print(json.dumps({"status": "failed", "error_category": exc.category}))
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
