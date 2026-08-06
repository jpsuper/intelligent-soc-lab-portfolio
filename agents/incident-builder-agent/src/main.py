import json

from jsonschema import Draft7Validator

from common.run_context import get_run_paths
from detection.compiler.incident_correlation import (
    build_correlation_incident_payload,
)
from detection.compiler.incident_correlation import (
    flatten_supporting_detections as _flatten_supporting_detections,
)
from detection.compiler.incident_correlation import (
    validate_correlation_incident_semantics as _validate_correlation_incident_semantics,
)
from detection.compiler.incident_legacy import (
    CORRELATED_FILE,
    HITS_FILE,
    INCIDENT_SCHEMA_FILE,
    INCIDENT_SEVERITIES,
    OUTPUT_FILE,
    build_incident,
    build_process_incident,
    build_timeline,
    collect_behavior_features_from_hits,
    collect_raw_event_refs,
    collect_source_ips,
    load_json,
    map_mitre,
    merge_behavior_features,
    parse_args,
)
from detection.compiler.incident_selection import select_incidents
from detection.compiler.incident_semantics import (
    build_observation_incident_payload,
    validate_observation_incident_semantics,
)
from detection.compiler.pipeline import (
    CommonPipelineValidationError,
    dedupe_canonical_detections,
    sort_correlation_results,
    validate_canonical_detections,
    validate_correlation_results_against_policies,
)

__all__ = [
    "CORRELATED_FILE",
    "HITS_FILE",
    "INCIDENT_SCHEMA_FILE",
    "INCIDENT_SEVERITIES",
    "OUTPUT_FILE",
    "IncidentBoundaryValidationError",
    "build_correlation_incident",
    "build_correlation_incidents_from_results",
    "build_detection_hit_incident",
    "build_incident",
    "build_observation_incidents_from_detections",
    "build_process_incident",
    "build_selected_incidents_from_results",
    "build_timeline",
    "collect_behavior_features_from_hits",
    "collect_raw_event_refs",
    "collect_source_ips",
    "load_json",
    "main",
    "map_mitre",
    "merge_behavior_features",
    "parse_args",
]


class IncidentBoundaryValidationError(ValueError):
    """Raised when the canonical detection-to-Incident boundary is invalid."""


def build_detection_hit_incident(
    hit: dict,
    idx: int,
    *,
    scenario_name: str | None = None,
    incident_severity: str | None = None,
) -> dict:
    return build_observation_incident_payload(
        hit,
        idx,
        scenario_name=scenario_name,
        incident_severity=incident_severity,
    )


def _load_incident_schema() -> dict:
    return json.loads(INCIDENT_SCHEMA_FILE.read_text(encoding="utf-8"))


def _validate_incident(incident: object, *, index: int) -> dict:
    validator = Draft7Validator(_load_incident_schema())
    error = next(iter(validator.iter_errors(incident)), None)
    if error is not None:
        path = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise IncidentBoundaryValidationError(
            f"incidents[{index}] schema validation failed at {path}: {error.message}"
        ) from None
    return incident


def build_observation_incidents_from_detections(
    detections: object,
    *,
    scenario_name: str | None = None,
    incident_severity: str | None = None,
) -> list[dict]:
    """Build one deterministic observation-level Incident per canonical detection."""

    try:
        validated_detections = validate_canonical_detections(detections)
    except CommonPipelineValidationError as exc:
        raise IncidentBoundaryValidationError(
            f"canonical detection validation failed: {exc}"
        ) from exc

    if scenario_name is not None and (
        not isinstance(scenario_name, str) or not scenario_name.strip()
    ):
        raise IncidentBoundaryValidationError("scenario_name must be a non-empty string or null")
    if incident_severity is not None and incident_severity not in INCIDENT_SEVERITIES:
        raise IncidentBoundaryValidationError(
            "incident_severity must be one of: critical, high, low, medium"
        )

    detection_ids = [detection["id"] for detection in validated_detections]
    if len(detection_ids) != len(set(detection_ids)):
        raise IncidentBoundaryValidationError("canonical detection ids must be unique")

    ordered_detections = sorted(
        validated_detections,
        key=lambda detection: (detection["rule_id"], detection["id"]),
    )
    incidents: list[dict] = []
    for index, detection in enumerate(ordered_detections, start=1):
        incident = build_detection_hit_incident(
            detection,
            idx=index,
            scenario_name=scenario_name,
            incident_severity=incident_severity,
        )
        validated_incident = _validate_incident(incident, index=index - 1)
        expected_incident_id = f"inc-{index:06d}"
        if validated_incident["incident_id"] != expected_incident_id:
            raise IncidentBoundaryValidationError(
                f"incidents[{index - 1}].incident_id must be {expected_incident_id}"
            )
        validate_observation_incident_semantics(
            validated_incident,
            detection,
            index=index - 1,
            incident_sequence=index,
            scenario_name=scenario_name,
            incident_severity=incident_severity,
            error_type=IncidentBoundaryValidationError,
        )
        incidents.append(validated_incident)

    return incidents


def build_correlation_incident(correlation: dict) -> dict:
    """Build one correlation-level Incident from a validated correlation result."""

    return build_correlation_incident_payload(correlation)


def _without_duplicate_count(detection: dict) -> dict:
    normalized = dict(detection)
    normalized.pop("duplicate_count", None)
    return normalized


def _validate_deduped_canonical_detections(
    deduped_detections: object,
) -> list[dict]:
    try:
        validated_deduped = validate_canonical_detections(deduped_detections)
    except CommonPipelineValidationError as exc:
        raise IncidentBoundaryValidationError(
            f"deduped canonical detection validation failed: {exc}"
        ) from exc

    for index, detection in enumerate(validated_deduped):
        if "duplicate_count" not in detection:
            continue
        duplicate_count = detection["duplicate_count"]
        if (
            not isinstance(duplicate_count, int)
            or isinstance(duplicate_count, bool)
            or duplicate_count <= 0
        ):
            raise IncidentBoundaryValidationError(
                "deduped canonical detection validation failed: "
                f"detections[{index}].duplicate_count must be a positive integer"
            )

    try:
        revalidated_deduped = dedupe_canonical_detections(validated_deduped)
    except CommonPipelineValidationError as exc:
        raise IncidentBoundaryValidationError(
            f"deduped canonical detection validation failed: {exc}"
        ) from exc

    normalized_input = [_without_duplicate_count(detection) for detection in validated_deduped]
    normalized_revalidated = [
        _without_duplicate_count(detection) for detection in revalidated_deduped
    ]
    if normalized_revalidated != normalized_input:
        raise IncidentBoundaryValidationError(
            "deduped canonical detection validation failed: deduped canonical "
            "detections do not match deterministic dedupe output"
        )

    return validated_deduped


def _validate_correlation_stage_inputs(
    correlations: object,
    deduped_detections: object,
) -> tuple[list[dict], list[dict]]:
    validated_deduped = _validate_deduped_canonical_detections(deduped_detections)

    try:
        validated_correlations = validate_correlation_results_against_policies(
            correlations,
            validated_deduped,
        )
    except CommonPipelineValidationError as exc:
        raise IncidentBoundaryValidationError(
            f"correlation result validation failed: {exc}"
        ) from exc

    return validated_deduped, sort_correlation_results(validated_correlations)


def build_correlation_incidents_from_results(
    correlations: object,
    deduped_detections: object,
) -> list[dict]:
    """Build deterministic correlation-level Incidents from validated results."""

    _validated_deduped, ordered_correlations = _validate_correlation_stage_inputs(
        correlations,
        deduped_detections,
    )
    incidents: list[dict] = []
    for index, correlation in enumerate(ordered_correlations):
        incident = build_correlation_incident(correlation)
        validated_incident = _validate_incident(incident, index=index)
        _validate_correlation_incident_semantics(
            validated_incident,
            correlation,
            index=index,
            error_type=IncidentBoundaryValidationError,
        )
        incidents.append(validated_incident)

    incident_ids = [incident["incident_id"] for incident in incidents]
    if len(incident_ids) != len(set(incident_ids)):
        raise IncidentBoundaryValidationError("incident_id values must be unique")

    return incidents


def build_selected_incidents_from_results(
    correlations: object,
    deduped_detections: object,
    *,
    observation_scenario_name: str | None = None,
    observation_incident_severity: str | None = None,
) -> list[dict]:
    """Select correlation Incidents first and observation fallbacks second."""

    validated_deduped, ordered_correlations = _validate_correlation_stage_inputs(
        correlations,
        deduped_detections,
    )
    return select_incidents(
        ordered_correlations,
        validated_deduped,
        build_correlation_incidents=build_correlation_incidents_from_results,
        build_observation_incidents=build_observation_incidents_from_detections,
        validate_incident=_validate_incident,
        validate_correlation_semantics=_validate_correlation_incident_semantics,
        validate_observation_semantics=validate_observation_incident_semantics,
        flatten_supporting_detections=_flatten_supporting_detections,
        observation_scenario_name=observation_scenario_name,
        observation_incident_severity=observation_incident_severity,
        error_type=IncidentBoundaryValidationError,
    )


def main() -> None:
    args = parse_args()

    if args.run_id:
        run_paths = get_run_paths(args.run_id)
        process_hits = load_json(run_paths.process_chain_hits)
        incidents = [
            build_process_incident(hit, index) for index, hit in enumerate(process_hits, start=1)
        ]
        run_paths.incident.parent.mkdir(parents=True, exist_ok=True)
        with run_paths.incident.open("w") as output:
            json.dump(incidents, output, indent=2)
        print(f"Loaded {len(process_hits)} process chain hits")
        print(f"Built {len(incidents)} incidents")
        print(f"Saved to {run_paths.incident}")
        return

    correlated = load_json(CORRELATED_FILE)
    hits = load_json(HITS_FILE)
    hits_by_id = {hit["detection_id"]: hit for hit in hits}
    incidents = [
        build_incident(correlation, hits_by_id, index)
        for index, correlation in enumerate(correlated, start=1)
    ]
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w") as output:
        json.dump(incidents, output, indent=2)
    print(f"Loaded {len(correlated)} correlated incidents")
    print(f"Built {len(incidents)} incidents")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
