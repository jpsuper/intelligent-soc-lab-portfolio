from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def parse_ts(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _normalized_ts(value: str | None) -> datetime | None:
    parsed = parse_ts(value)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first_ts(detection: dict[str, Any]) -> datetime | None:
    return _normalized_ts(detection.get("time_window_start")) or _normalized_ts(
        detection.get("time_window_end")
    )


def _artifact_key(detection: dict[str, Any]) -> tuple:
    rule_id = detection.get("rule_id")
    artifact = detection.get("artifact")
    host = detection.get("host")
    user = detection.get("user")
    src_ip = detection.get("src_ip")
    path = detection.get("path")

    if detection.get("event_type") == "process_exec":
        event_id = detection.get("event_id")
        if event_id is not None:
            return (rule_id, artifact, host, user, src_ip, path, "event_id", str(event_id))

    if artifact == "authorized_keys_modification":
        return (rule_id, artifact, host, path)

    if artifact in {"ssh_failed_login", "ssh_success_login", "ssh_key_login"}:
        return (rule_id, artifact, host, user, src_ip)

    return (rule_id, artifact, host, user, src_ip, path)


def _detection_sort_key(detection: dict[str, Any]) -> tuple:
    timestamp = _first_ts(detection)
    return (
        timestamp is None,
        timestamp or datetime.max.replace(tzinfo=timezone.utc),
        str(detection.get("rule_id") or ""),
        str(detection.get("id") or ""),
    )


def _window_seconds_for_artifact(artifact: str | None) -> int:
    if artifact in {"ssh_failed_login", "ssh_success_login", "ssh_key_login"}:
        return 30
    if artifact == "authorized_keys_modification":
        return 120
    return 60


def merge_detection_group(group: list[dict[str, Any]]) -> dict[str, Any]:
    if not group:
        raise ValueError("group must not be empty")

    group = sorted(group, key=_detection_sort_key)

    merged = dict(group[0])

    raw_event_refs: set[str] = set()
    evidence_refs: set[str] = set()
    behavior_feature_keys: set[str] = set()

    first_times = []
    last_times = []

    for item in group:
        raw_event_refs.update(item.get("raw_event_refs", []) or [])
        evidence_refs.update(item.get("evidence_refs", []) or [])
        behavior_features = item.get("behavior_features", {}) or {}
        if isinstance(behavior_features, dict):
            behavior_feature_keys.update(behavior_features)

        start_ts = _normalized_ts(item.get("time_window_start"))
        end_ts = _normalized_ts(item.get("time_window_end"))

        if start_ts:
            first_times.append(start_ts)
        if end_ts:
            last_times.append(end_ts)

    merged["raw_event_refs"] = sorted(raw_event_refs)
    merged["evidence_refs"] = sorted(evidence_refs)
    merged["behavior_features"] = {
        key: any(
            isinstance(item.get("behavior_features"), dict)
            and item["behavior_features"].get(key) is True
            for item in group
        )
        for key in sorted(behavior_feature_keys)
    }
    merged["duplicate_count"] = len(group)

    if first_times:
        merged["time_window_start"] = min(first_times).isoformat()
    if last_times:
        merged["time_window_end"] = max(last_times).isoformat()

    return merged


def dedupe_detections(
    detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not detections:
        return []

    grouped: dict[tuple, list[dict[str, Any]]] = {}
    for det in detections:
        key = _artifact_key(det)
        grouped.setdefault(key, []).append(det)

    merged_results: list[dict[str, Any]] = []

    for key in sorted(grouped, key=repr):
        items = sorted(grouped[key], key=_detection_sort_key)

        current_group: list[dict[str, Any]] = []
        artifact = items[0].get("artifact")
        max_gap = timedelta(seconds=_window_seconds_for_artifact(artifact))

        for item in items:
            if not current_group:
                current_group = [item]
                continue

            prev_ts = _first_ts(current_group[-1])
            cur_ts = _first_ts(item)

            if prev_ts and cur_ts and (cur_ts - prev_ts) <= max_gap:
                current_group.append(item)
            else:
                merged_results.append(merge_detection_group(current_group))
                current_group = [item]

        if current_group:
            merged_results.append(merge_detection_group(current_group))

    merged_results.sort(key=_detection_sort_key)
    return merged_results
