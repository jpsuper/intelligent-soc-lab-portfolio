from __future__ import annotations

import argparse
import copy
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WINDOWS_AUTH_MODULE_DIR = REPOSITORY_ROOT / "scripts" / "windows" / "security_auth"
for module_path in (REPOSITORY_ROOT, WINDOWS_AUTH_MODULE_DIR):
    module_path_text = str(module_path)
    if module_path_text not in sys.path:
        sys.path.insert(0, module_path_text)

from adapt_wazuh_windows_security_auth_hit import (  # noqa: E402
    EVENT_DATA_FIELD_MAPPING,
    SYSTEM_FIELD_MAPPING,
    WazuhWindowsSecurityAuthAdaptError,
    adapt_wazuh_windows_security_auth_hit,
)
from map_windows_security_auth_to_endpoint_event import (  # noqa: E402
    WindowsSecurityAuthMappingError,
    map_windows_security_auth_to_endpoint_event,
)
from parse_windows_security_auth_source import (  # noqa: E402
    WindowsSecurityAuthParseError,
    parse_windows_security_auth_source,
)
from wazuh_indexer_query_adapter import SiemQueryAdapterError  # noqa: E402
from wazuh_indexer_transport import (  # noqa: E402
    SiemTransportError,
    execute_wazuh_indexer_query,
)
from wazuh_indexer_windows_security_auth_live_smoke import (  # noqa: E402
    WindowsSecurityAuthLiveSmokeError,
    build_windows_security_auth_live_smoke_request,
    build_windows_security_auth_live_smoke_summary,
)

from common import defender_pipeline  # noqa: E402
from detection.compiler.loader import load_rule  # noqa: E402

SUMMARY_SCHEMA_PATH = (
    REPOSITORY_ROOT
    / "schemas"
    / "wazuh_indexer_windows_security_auth_live_pipeline_summary.schema.json"
)
RULE_PATH = REPOSITORY_ROOT / "detection" / "dsl" / "windows_security_auth_failure_observed.yaml"
EVENT_ID = "4625"
MAX_RECORDS = 100
EVIDENCE_SCOPE = "bounded_live_wazuh_authentication_common_pipeline_execution"
DOES_NOT_ESTABLISH = [
    "raw_archive_completeness",
    "continuous_runtime_collection",
    "alert_or_detection_coverage",
    "credential_validity_or_compromise",
    "authentication_specific_analysis",
    "repeated_failure_or_spraying_correlation",
    "native_windows_parity",
    "case_action_or_response",
    "full_cross_platform_pipeline_validation",
]


class WindowsSecurityAuthLivePipelineError(ValueError):
    """Stable live-pipeline failure without event or credential values."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


def _load_schema() -> dict[str, object]:
    return json.loads(SUMMARY_SCHEMA_PATH.read_text(encoding="utf-8"))


def _mapping(value: object, *, category: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WindowsSecurityAuthLivePipelineError(
            category,
            "Windows Security live pipeline input shape was invalid",
        )
    return value


def _string(value: object, *, category: str) -> str:
    if not isinstance(value, str) or not value:
        raise WindowsSecurityAuthLivePipelineError(
            category,
            "Windows Security live pipeline input shape was invalid",
        )
    return value


def _allowlisted_projection_fields(
    source: Mapping[str, object],
    allowlist: Mapping[str, str],
) -> dict[str, object]:
    return {field: copy.deepcopy(source[field]) for field in allowlist if field in source}


def build_live_wazuh_auth_projection(
    *,
    response: Mapping[str, object],
    record: Mapping[str, object],
    record_number: int,
) -> dict[str, object]:
    """Build one ephemeral reviewed Wazuh projection without writing a raw record."""

    if type(record_number) is not int or not 1 <= record_number <= MAX_RECORDS:
        raise WindowsSecurityAuthLivePipelineError(
            "projection_build_failed",
            "Windows Security live projection record number was invalid",
        )

    fields = _mapping(record.get("fields"), category="projection_build_failed")
    system = _mapping(
        fields.get("data.win.system"),
        category="projection_build_failed",
    )
    event_data = _mapping(
        fields.get("data.win.eventdata"),
        category="projection_build_failed",
    )
    provenance = _mapping(
        response.get("query_provenance"),
        category="projection_build_failed",
    )
    time_range = _mapping(
        response.get("executed_time_range"),
        category="projection_build_failed",
    )

    return {
        "fixture_contract_version": "1.0",
        "fixture_id": f"windows-security-4625-live-record-{record_number:03d}",
        "source_format": "wazuh_indexer_alert_hit_projection",
        "retrieval": {
            "query_ref": _string(
                response.get("request_id"),
                category="projection_build_failed",
            ),
            "retrieved_at": _string(
                provenance.get("executed_at"),
                category="projection_build_failed",
            ),
            "query_window": {
                "start": _string(
                    time_range.get("start"),
                    category="projection_build_failed",
                ),
                "end": _string(
                    time_range.get("end"),
                    category="projection_build_failed",
                ),
            },
        },
        "hit": {
            "_index": _string(
                record.get("physical_source"),
                category="projection_build_failed",
            ),
            "_id": _string(
                record.get("backend_record_id"),
                category="projection_build_failed",
            ),
            "_source": {
                "timestamp": _string(
                    record.get("event_time"),
                    category="projection_build_failed",
                ),
                "agent": {
                    "id": _string(
                        fields.get("agent.id"),
                        category="projection_build_failed",
                    ),
                    "name": _string(
                        fields.get("agent.name"),
                        category="projection_build_failed",
                    ),
                },
                "manager": {
                    "name": _string(
                        fields.get("manager.name"),
                        category="projection_build_failed",
                    )
                },
                "data": {
                    "win": {
                        "system": _allowlisted_projection_fields(
                            system,
                            SYSTEM_FIELD_MAPPING,
                        ),
                        "eventdata": _allowlisted_projection_fields(
                            event_data,
                            EVENT_DATA_FIELD_MAPPING,
                        ),
                    }
                },
            },
        },
    }


def _convert_live_records(
    *,
    run_id: str,
    response: Mapping[str, object],
) -> list[dict[str, object]]:
    records = response.get("records")
    if not isinstance(records, list):
        raise WindowsSecurityAuthLivePipelineError(
            "projection_build_failed",
            "Windows Security live pipeline records were invalid",
        )

    events: list[dict[str, object]] = []
    for record_number, raw_record in enumerate(records, start=1):
        record = _mapping(raw_record, category="projection_build_failed")
        projection = build_live_wazuh_auth_projection(
            response=response,
            record=record,
            record_number=record_number,
        )
        try:
            adapted = adapt_wazuh_windows_security_auth_hit(projection)
        except WazuhWindowsSecurityAuthAdaptError as exc:
            raise WindowsSecurityAuthLivePipelineError(
                "representation_conversion_failed",
                "Windows Security live Wazuh representation conversion failed",
            ) from exc
        try:
            parsed = parse_windows_security_auth_source(adapted["source_event"])
        except WindowsSecurityAuthParseError as exc:
            raise WindowsSecurityAuthLivePipelineError(
                "source_parse_failed",
                "Windows Security live source parsing failed",
            ) from exc
        try:
            event = map_windows_security_auth_to_endpoint_event(
                parsed,
                source_artifact=(
                    "memory://wazuh-alerts-windows-security-auth/"
                    f"{run_id}/record-{record_number:03d}"
                ),
            )
        except WindowsSecurityAuthMappingError as exc:
            raise WindowsSecurityAuthLivePipelineError(
                "normalized_mapping_failed",
                "Windows Security live normalized mapping failed",
            ) from exc
        if event.get("event_type") != "auth_failure":
            raise WindowsSecurityAuthLivePipelineError(
                "normalized_mapping_failed",
                "Windows Security live event did not map to auth_failure",
            )
        events.append(event)
    return events


def _run_common_entry(
    *,
    run_id: str,
    events: list[dict[str, object]],
) -> dict[str, list[dict]]:
    source_ref = f"memory://wazuh-alerts-windows-security-auth/{run_id}"
    endpoint_events = {
        "schema_version": "endpoint_events.v1",
        "source_artifact": source_ref,
        "source_run_id": run_id,
        "events": events,
    }
    try:
        rule = load_rule(RULE_PATH)
    except (OSError, ValueError) as exc:
        raise WindowsSecurityAuthLivePipelineError(
            "rule_load_failed",
            "Windows Security live pipeline rule could not be loaded",
        ) from exc
    try:
        return defender_pipeline.run_common_endpoint_to_investigation(
            endpoint_events,
            [rule],
            endpoint_events_source=source_ref,
            observation_incident_severity="low",
        )
    except defender_pipeline.CommonPipelineCompositionError as exc:
        raise WindowsSecurityAuthLivePipelineError(
            "common_pipeline_failed",
            "Windows Security live common pipeline execution failed",
        ) from exc


def _validate_pipeline_coverage(
    *,
    record_count: int,
    bundle: Mapping[str, list[dict]],
) -> tuple[int, set[str]]:
    deduped = bundle["deduped_detections"]
    represented_records = 0
    raw_refs: set[str] = set()
    for detection in deduped:
        duplicate_count = detection.get("duplicate_count")
        if type(duplicate_count) is not int or duplicate_count < 1:
            raise WindowsSecurityAuthLivePipelineError(
                "pipeline_alignment_failed",
                "Windows Security live detection coverage was invalid",
            )
        represented_records += duplicate_count
        refs = detection.get("raw_event_refs")
        if not isinstance(refs, list) or not all(isinstance(item, str) for item in refs):
            raise WindowsSecurityAuthLivePipelineError(
                "pipeline_alignment_failed",
                "Windows Security live detection references were invalid",
            )
        raw_refs.update(refs)

    expected_refs = {f"input[{index}]" for index in range(record_count)}
    if (
        represented_records != record_count
        or raw_refs != expected_refs
        or bundle["correlations"]
        or len(bundle["incidents"]) != len(deduped)
        or len(bundle["triage_results"]) != len(deduped)
        or len(bundle["investigation_results"]) != len(deduped)
    ):
        raise WindowsSecurityAuthLivePipelineError(
            "pipeline_alignment_failed",
            "Windows Security live pipeline stage alignment failed",
        )
    return represented_records, raw_refs


def build_windows_security_auth_live_pipeline_summary(
    *,
    run_id: str,
    host: str,
    response: Mapping[str, object],
) -> dict[str, object]:
    retrieval_summary = build_windows_security_auth_live_smoke_summary(
        run_id=run_id,
        host=host,
        event_id=EVENT_ID,
        response=response,
    )
    events = _convert_live_records(run_id=run_id, response=response)
    bundle = _run_common_entry(run_id=run_id, events=events)
    represented_records, _ = _validate_pipeline_coverage(
        record_count=len(events),
        bundle=bundle,
    )

    stage_counts = {
        "retrieved_records": retrieval_summary["results"]["returned_records"],
        "adapted_records": len(events),
        "normalized_events": len(events),
        "represented_detection_events": represented_records,
        "deduped_detections": len(bundle["deduped_detections"]),
        "correlations": len(bundle["correlations"]),
        "incidents": len(bundle["incidents"]),
        "triage_results": len(bundle["triage_results"]),
        "investigation_results": len(bundle["investigation_results"]),
    }
    summary = {
        "contract_version": "1.0",
        "status": "passed",
        "run_id": run_id,
        "event_id": EVENT_ID,
        "request_fingerprint": retrieval_summary["request_fingerprint"],
        "host_value_sha256": retrieval_summary["host_value_sha256"],
        "executed_at": retrieval_summary["executed_at"],
        "logical_source": retrieval_summary["logical_source"],
        "physical_source_count": retrieval_summary["physical_source_count"],
        "executed_time_range": retrieval_summary["executed_time_range"],
        "retrieval_results": retrieval_summary["results"],
        "rule_id": "authentication.windows_security_failure_observed",
        "stage_counts": stage_counts,
        "pipeline_alignment": {
            "all_records_adapted": True,
            "all_records_normalized": True,
            "all_records_represented_by_detection": True,
            "raw_event_reference_coverage": True,
            "incident_triage_investigation_linkage": True,
            "in_memory_only": True,
        },
        "evidence_scope": EVIDENCE_SCOPE,
        "does_not_establish": DOES_NOT_ESTABLISH,
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
        raise WindowsSecurityAuthLivePipelineError(
            "summary_validation_failed",
            "Windows Security live pipeline summary failed its public schema",
        )
    return summary


def run_windows_security_auth_live_pipeline(
    *,
    run_id: str,
    host: str,
    anchor: str,
    window_seconds: int = 300,
    execute_query: Callable[[Mapping[str, object]], dict[str, object]] = (
        execute_wazuh_indexer_query
    ),
) -> dict[str, object]:
    request = build_windows_security_auth_live_smoke_request(
        run_id=run_id,
        host=host,
        event_id=EVENT_ID,
        anchor=anchor,
        window_seconds=window_seconds,
    )
    response = execute_query(request)
    return build_windows_security_auth_live_pipeline_summary(
        run_id=run_id,
        host=host,
        response=response,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run one bounded Wazuh Windows Security 4625 result through "
            "the common endpoint-to-Investigation entry."
        )
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--anchor", required=True, help="RFC 3339 event/run anchor")
    parser.add_argument(
        "--window-seconds",
        type=int,
        default=300,
        help="centered query window in seconds (default: 300; maximum: 1800)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = run_windows_security_auth_live_pipeline(
            run_id=args.run_id,
            host=args.host,
            anchor=args.anchor,
            window_seconds=args.window_seconds,
        )
    except (
        WindowsSecurityAuthLivePipelineError,
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
