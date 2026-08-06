from __future__ import annotations


def build_observation_incident_payload(
    detection: dict,
    sequence: int,
    *,
    scenario_name: str | None,
    incident_severity: str | None,
) -> dict:
    artifact = detection.get("artifact") or "unknown"
    rule_id = (
        detection.get("rule_id") or detection.get("rule_name") or detection.get("detection_type")
    )
    raw_event_refs = list(dict.fromkeys(detection.get("raw_event_refs", []) or []))
    evidence_refs = list(dict.fromkeys(detection.get("evidence_refs", []) or []))
    timestamp = (
        detection.get("time_window_start")
        or detection.get("time_window_end")
        or detection.get("timestamp")
    )
    behavior_features = {}
    if isinstance(detection.get("behavior_features"), dict):
        behavior_features = detection["behavior_features"]
    elif isinstance(detection.get("feature_mapping"), dict):
        behavior_features = detection["feature_mapping"]
    severity = incident_severity or detection.get("severity", "medium")
    detection_id = detection.get("id") or detection.get("detection_id")
    timeline_entry = {
        "timestamp": timestamp,
        "rule_id": rule_id,
        "event_ref": raw_event_refs[0] if raw_event_refs else None,
        "host": detection.get("host"),
        "username": detection.get("user") or detection.get("username"),
        "severity": severity,
        "artifact": artifact,
        "event_type": detection.get("event_type"),
        "command_line": detection.get("command_line"),
        "evidence_refs": evidence_refs,
        "raw_event_refs": raw_event_refs,
    }
    return {
        "incident_id": f"inc-{sequence:06d}",
        "attack_id": None,
        "scenario_name": scenario_name or artifact,
        "title": f"Observed {artifact.replace('_', ' ')} behavior",
        "severity": severity,
        "confidence": "medium",
        "summary": (
            "Defender-side detection hit observed for "
            f"{artifact.replace('_', ' ')}. This incident records observed "
            "behavior only and does not infer compromise, exfiltration, "
            "ransomware behavior, credential access, real data collection, "
            "or live telemetry coverage."
        ),
        "host": detection.get("host"),
        "username": detection.get("user") or detection.get("username"),
        "source_hosts": [detection.get("host")] if detection.get("host") else [],
        "source_ips": [detection.get("src_ip")] if detection.get("src_ip") else [],
        "time_window_start": detection.get("time_window_start") or timestamp,
        "time_window_end": detection.get("time_window_end") or timestamp,
        "matched_detection_ids": [detection_id] if detection_id else [],
        "matched_rule_names": [rule_id] if rule_id else [],
        "matched_rules": [rule_id] if rule_id else [],
        "mitre_attack": [],
        "raw_event_refs": raw_event_refs,
        "evidence_refs": evidence_refs,
        "timeline": [timeline_entry],
        "behavior_features": behavior_features,
        "primary_artifact": artifact,
        "notes": [
            "Defender-side detection hit and endpoint event only.",
            "No attacker-side observed effects are used as defender evidence.",
            "No file content inspection is represented by this incident.",
            "No network transfer observed.",
            "No exfiltration observed.",
            "No live auditd, Wazuh, or SIEM collection is proven by this fixture.",
        ],
    }


def validate_observation_incident_semantics(
    incident: dict,
    detection: dict,
    *,
    index: int,
    incident_sequence: int,
    scenario_name: str | None,
    incident_severity: str | None,
    error_type: type[ValueError],
) -> None:
    expected = build_observation_incident_payload(
        detection,
        incident_sequence,
        scenario_name=scenario_name,
        incident_severity=incident_severity,
    )
    missing = object()
    for field in sorted(set(expected) | set(incident)):
        if incident.get(field, missing) != expected.get(field, missing):
            raise error_type(
                f"incidents[{index}].{field} must match validated canonical detection input"
            )
