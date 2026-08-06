from __future__ import annotations

from typing import Callable


def _covered_detection_ids(correlations: list[dict]) -> set[str]:
    return {
        detection["id"]
        for correlation in correlations
        for detections in correlation["supporting_detections"].values()
        for detection in detections
    }


def select_incidents(
    correlations: list[dict],
    deduped_detections: list[dict],
    *,
    build_correlation_incidents: Callable[..., list[dict]],
    build_observation_incidents: Callable[..., list[dict]],
    validate_incident: Callable[..., dict],
    validate_correlation_semantics: Callable[..., None],
    validate_observation_semantics: Callable[..., None],
    flatten_supporting_detections: Callable[[dict], list[dict]],
    observation_scenario_name: str | None,
    observation_incident_severity: str | None,
    error_type: type[ValueError],
) -> list[dict]:
    covered_ids = _covered_detection_ids(correlations)
    uncovered = [
        detection for detection in deduped_detections if detection["id"] not in covered_ids
    ]
    correlation_incidents = build_correlation_incidents(
        correlations,
        deduped_detections,
    )
    observation_incidents = build_observation_incidents(
        uncovered,
        scenario_name=observation_scenario_name,
        incident_severity=observation_incident_severity,
    )
    return _validate_selected_incidents(
        correlation_incidents,
        observation_incidents,
        correlations=correlations,
        deduped_detections=deduped_detections,
        uncovered_detections=uncovered,
        covered_detection_ids=covered_ids,
        validate_incident=validate_incident,
        validate_correlation_semantics=validate_correlation_semantics,
        validate_observation_semantics=validate_observation_semantics,
        flatten_supporting_detections=flatten_supporting_detections,
        observation_scenario_name=observation_scenario_name,
        observation_incident_severity=observation_incident_severity,
        error_type=error_type,
    )


def _validate_selected_incidents(
    correlation_incidents: object,
    observation_incidents: object,
    *,
    correlations: list[dict],
    deduped_detections: list[dict],
    uncovered_detections: list[dict],
    covered_detection_ids: set[str],
    validate_incident: Callable[..., dict],
    validate_correlation_semantics: Callable[..., None],
    validate_observation_semantics: Callable[..., None],
    flatten_supporting_detections: Callable[[dict], list[dict]],
    observation_scenario_name: str | None,
    observation_incident_severity: str | None,
    error_type: type[ValueError],
) -> list[dict]:
    if not isinstance(correlation_incidents, list):
        raise error_type("selected correlation incidents must be a list")
    if not isinstance(observation_incidents, list):
        raise error_type("selected observation incidents must be a list")
    if len(correlation_incidents) != len(correlations):
        raise error_type("selected correlation incident count must match correlation result count")
    if len(observation_incidents) != len(uncovered_detections):
        raise error_type("selected observation incident count must match uncovered detection count")

    selected = [*correlation_incidents, *observation_incidents]
    validated: list[dict] = []
    incident_ids: list[str] = []
    for index, incident in enumerate(selected):
        checked = validate_incident(incident, index=index)
        incident_id = checked.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise error_type(f"incidents[{index}].incident_id must be a non-empty string")
        validated.append(checked)
        incident_ids.append(incident_id)
    if len(incident_ids) != len(set(incident_ids)):
        raise error_type("selected incident_id values must be unique")

    expected_correlation_ids: list[str] = []
    represented_correlation_ids: set[str] = set()
    for index, (correlation, incident) in enumerate(
        zip(correlations, correlation_incidents, strict=True)
    ):
        expected_id = f"inc-{correlation['correlation_id']}"
        expected_correlation_ids.append(expected_id)
        if incident.get("incident_id") != expected_id:
            raise error_type(
                f"selected correlation incidents[{index}].incident_id must be {expected_id}"
            )
        if incident.get("correlation_id") != correlation["correlation_id"]:
            raise error_type(
                f"selected correlation incidents[{index}].correlation_id must match input"
            )
        if incident.get("correlation_type") != correlation["correlation_type"]:
            raise error_type(
                f"selected correlation incidents[{index}].correlation_type must match input"
            )
        validate_correlation_semantics(
            incident,
            correlation,
            index=index,
            error_type=error_type,
        )
        expected_detection_ids = [
            detection["id"] for detection in flatten_supporting_detections(correlation)
        ]
        if incident.get("matched_detection_ids") != expected_detection_ids:
            raise error_type(
                f"selected correlation incidents[{index}].matched_detection_ids "
                "must match supporting detections"
            )
        represented_correlation_ids.update(expected_detection_ids)

    ordered_uncovered = sorted(
        uncovered_detections,
        key=lambda detection: (detection["rule_id"], detection["id"]),
    )
    expected_observation_ids: list[str] = []
    represented_observation_ids: set[str] = set()
    all_input_ids = {detection["id"] for detection in deduped_detections}
    for sequence, (detection, incident) in enumerate(
        zip(ordered_uncovered, observation_incidents, strict=True),
        start=1,
    ):
        expected_id = f"inc-{sequence:06d}"
        expected_observation_ids.append(expected_id)
        if incident.get("incident_id") != expected_id:
            raise error_type(
                f"selected observation incidents[{sequence - 1}].incident_id must be {expected_id}"
            )
        validate_observation_semantics(
            incident,
            detection,
            index=len(correlation_incidents) + sequence - 1,
            incident_sequence=sequence,
            scenario_name=observation_scenario_name,
            incident_severity=observation_incident_severity,
            error_type=error_type,
        )
        if incident.get("matched_detection_ids") != [detection["id"]]:
            raise error_type(
                f"selected observation incidents[{sequence - 1}].matched_detection_ids "
                "must contain its uncovered detection only"
            )
        represented_observation_ids.add(detection["id"])

    if represented_observation_ids & covered_detection_ids:
        raise error_type(
            "selected observation incidents must not reference correlation-covered detections"
        )
    if not represented_observation_ids <= all_input_ids:
        raise error_type("selected observation incidents reference an unknown detection id")
    if represented_correlation_ids != covered_detection_ids:
        raise error_type("selected correlation incidents must represent all covered detections")
    if represented_correlation_ids | represented_observation_ids != all_input_ids:
        raise error_type("selected incidents must represent every input detection")

    expected_ids = [*expected_correlation_ids, *expected_observation_ids]
    if incident_ids != expected_ids:
        raise error_type("selected incidents must preserve correlation-then-observation order")
    return validated
