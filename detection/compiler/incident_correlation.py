from __future__ import annotations

from copy import deepcopy

from .correlation import sort_detections

CORRELATION_INCIDENT_SUMMARY = (
    "This defender-side correlation records a time and identity relationship between "
    "validated canonical detections. The correlation does not prove compromise, "
    "maliciousness, or attack success, and it creates no containment, approval, or "
    "response action."
)
CORRELATION_INCIDENT_NOTES = [
    "Defender-side correlation evidence only.",
    "Correlation does not prove compromise, maliciousness, or attack success.",
    "No response action, containment, or approval is generated.",
]


def flatten_supporting_detections(correlation: dict) -> list[dict]:
    supporting = [
        detection
        for detections in correlation["supporting_detections"].values()
        for detection in detections
    ]
    return sort_detections(supporting)


def _unique_nonempty(values: list[object], *, sorted_output: bool = False) -> list[str]:
    unique = {value for value in values if isinstance(value, str) and value}
    if sorted_output:
        return sorted(unique)
    return list(dict.fromkeys(value for value in values if isinstance(value, str) and value))


def _build_timeline_entry(detection: dict) -> dict:
    raw_event_refs = list(detection["raw_event_refs"])
    return {
        "timestamp": detection["time_window_start"] or detection["time_window_end"],
        "rule_id": detection["rule_id"],
        "event_ref": raw_event_refs[0] if raw_event_refs else None,
        "host": detection["host"],
        "username": detection["user"],
        "severity": detection["severity"],
        "artifact": detection["artifact"],
        "event_type": detection["event_type"],
        "command_line": detection["command_line"],
        "evidence_refs": list(detection["evidence_refs"]),
        "raw_event_refs": raw_event_refs,
        "detection_id": detection["id"],
    }


def build_correlation_incident_payload(correlation: dict) -> dict:
    supporting = flatten_supporting_detections(correlation)
    timeline = [_build_timeline_entry(detection) for detection in supporting]
    detection_ids = _unique_nonempty([detection["id"] for detection in supporting])
    rule_ids = _unique_nonempty([detection["rule_id"] for detection in supporting])
    return {
        "incident_id": f"inc-{correlation['correlation_id']}",
        "attack_id": None,
        "scenario_name": correlation["correlation_type"],
        "title": correlation["title"],
        "severity": correlation["severity"],
        "confidence": "medium",
        "summary": CORRELATION_INCIDENT_SUMMARY,
        "host": correlation["host"],
        "username": correlation["user"],
        "source_hosts": _unique_nonempty(
            [detection["host"] for detection in supporting], sorted_output=True
        ),
        "source_ips": _unique_nonempty(
            [detection["src_ip"] for detection in supporting], sorted_output=True
        ),
        "time_window_start": correlation["time_window_start"],
        "time_window_end": correlation["time_window_end"],
        "matched_detection_ids": detection_ids,
        "matched_rule_names": rule_ids,
        "matched_rules": rule_ids,
        "mitre_attack": [],
        "raw_event_refs": list(correlation["raw_event_refs"]),
        "evidence_refs": list(correlation["evidence_refs"]),
        "timeline": timeline,
        "behavior_features": deepcopy(correlation["behavior_features"]),
        "primary_artifact": correlation["primary_artifact"],
        "correlation_id": correlation["correlation_id"],
        "correlation_type": correlation["correlation_type"],
        "artifacts": list(correlation["artifacts"]),
        "notes": list(CORRELATION_INCIDENT_NOTES),
    }


def validate_correlation_incident_semantics(
    incident: dict,
    correlation: dict,
    *,
    index: int,
    error_type: type[ValueError] | None = None,
) -> None:
    error_type = error_type or ValueError
    expected = build_correlation_incident_payload(correlation)
    missing = object()
    for field in sorted(set(expected) | set(incident)):
        if incident.get(field, missing) != expected.get(field, missing):
            raise error_type(f"incidents[{index}].{field} must match validated correlation input")
    if not incident["timeline"]:
        raise error_type(f"incidents[{index}].timeline must not be empty")
    timeline_ids = [entry.get("detection_id") for entry in incident["timeline"]]
    if len(timeline_ids) != len(set(timeline_ids)):
        raise error_type(f"incidents[{index}].timeline detection_id values must be unique")
