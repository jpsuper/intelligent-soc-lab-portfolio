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


def detection_ts(detection: dict[str, Any]) -> datetime | None:
    parsed = parse_ts(detection.get("time_window_start")) or parse_ts(
        detection.get("time_window_end")
    )
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def detection_sort_key(detection: dict[str, Any]) -> tuple:
    timestamp = detection_ts(detection)
    return (
        timestamp is None,
        timestamp or datetime.max.replace(tzinfo=timezone.utc),
        str(detection.get("rule_id") or ""),
        str(detection.get("id") or ""),
    )


def sort_detections(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(detections, key=detection_sort_key)


def correlate_auth_then_authorized_keys(
    detections: list[dict[str, Any]],
    *,
    auth_window_seconds: int = 300,
    persistence_window_seconds: int = 900,
) -> list[dict[str, Any]]:
    """
    Correlate:
      ssh_failed_login -> ssh_success_login -> authorized_keys_modification
    """
    detections = sort_detections(detections)

    failed = [d for d in detections if d.get("artifact") == "ssh_failed_login"]
    success = [d for d in detections if d.get("artifact") == "ssh_success_login"]
    auth_keys = [d for d in detections if d.get("artifact") == "authorized_keys_modification"]

    results: list[dict[str, Any]] = []

    for success_det in success:
        success_ts = detection_ts(success_det)
        if not success_ts:
            continue

        host = success_det.get("host")
        user = success_det.get("user")
        src_ip = success_det.get("src_ip")

        matched_failed = []
        for failed_det in failed:
            failed_ts = detection_ts(failed_det)
            if not failed_ts:
                continue

            if failed_det.get("host") != host:
                continue
            if failed_det.get("user") != user:
                continue
            if failed_det.get("src_ip") != src_ip:
                continue

            if failed_ts <= success_ts and (success_ts - failed_ts) <= timedelta(
                seconds=auth_window_seconds
            ):
                matched_failed.append(failed_det)

        if not matched_failed:
            continue

        matched_auth_keys = []
        for ak_det in auth_keys:
            ak_ts = detection_ts(ak_det)
            if not ak_ts:
                continue

            if ak_det.get("host") != host:
                continue

            if ak_ts >= success_ts and (ak_ts - success_ts) <= timedelta(
                seconds=persistence_window_seconds
            ):
                matched_auth_keys.append(ak_det)

        if not matched_auth_keys:
            continue

        first_failed_ts = min(
            detection_ts(item) for item in matched_failed if detection_ts(item) is not None
        )
        last_ak_ts = max(
            detection_ts(item) for item in matched_auth_keys if detection_ts(item) is not None
        )

        evidence_refs: list[str] = []
        raw_event_refs: list[str] = []

        all_items = matched_failed + [success_det] + matched_auth_keys
        for item in all_items:
            evidence_refs.extend(item.get("evidence_refs", []) or [])
            raw_event_refs.extend(item.get("raw_event_refs", []) or [])

        results.append(
            {
                "correlation_id": f"corr-auth-persistence-{len(results) + 1:06d}",
                "correlation_type": "auth_then_authorized_keys",
                "title": "SSH authentication followed by authorized_keys persistence",
                "primary_artifact": "authorized_keys_modification",
                "severity": "high",
                "host": host,
                "user": user,
                "src_ip": src_ip,
                "artifacts": [
                    "ssh_failed_login",
                    "ssh_success_login",
                    "authorized_keys_modification",
                ],
                "behavior_features": {
                    "ssh_auth_failure_observed": True,
                    "ssh_success_observed": True,
                    "password_authentication": True,
                    "ssh_authorized_keys_targeted": True,
                    "persistence_related_path": True,
                },
                "supporting_detections": {
                    "ssh_failed_login": matched_failed,
                    "ssh_success_login": [success_det],
                    "authorized_keys_modification": matched_auth_keys,
                },
                "raw_event_refs": sorted(set(raw_event_refs)),
                "evidence_refs": sorted(set(evidence_refs)),
                "time_window_start": first_failed_ts.isoformat() if first_failed_ts else None,
                "time_window_end": last_ak_ts.isoformat() if last_ak_ts else None,
            }
        )

    return results


def correlate_key_login_then_process_exec(
    detections: list[dict[str, Any]],
    *,
    execution_window_seconds: int = 300,
) -> list[dict[str, Any]]:
    """
    Correlate:
      ssh_key_login -> process_exec

    Intended for scenarios where SSH key-based access is reused and followed
    by post-login command execution on the same host/user context.
    """
    detections = sort_detections(detections)

    key_logins = [d for d in detections if d.get("artifact") == "ssh_key_login"]
    process_execs = [d for d in detections if d.get("artifact") == "process_exec"]

    results: list[dict[str, Any]] = []

    for exec_det in process_execs:
        exec_ts = detection_ts(exec_det)
        if not exec_ts:
            continue

        host = exec_det.get("host")
        user = exec_det.get("user")

        matched_key_logins = []
        for key_det in key_logins:
            key_ts = detection_ts(key_det)
            if not key_ts:
                continue

            if key_det.get("host") != host:
                continue
            if key_det.get("user") != user:
                continue

            if key_ts <= exec_ts and (exec_ts - key_ts) <= timedelta(
                seconds=execution_window_seconds
            ):
                matched_key_logins.append(key_det)

        if not matched_key_logins:
            continue

        first_key_ts = min(
            detection_ts(item) for item in matched_key_logins if detection_ts(item) is not None
        )

        evidence_refs: list[str] = []
        raw_event_refs: list[str] = []

        all_items = matched_key_logins + [exec_det]
        for item in all_items:
            evidence_refs.extend(item.get("evidence_refs", []) or [])
            raw_event_refs.extend(item.get("raw_event_refs", []) or [])

        src_ips = [item.get("src_ip") for item in matched_key_logins if item.get("src_ip")]
        src_ip = src_ips[0] if src_ips else None

        results.append(
            {
                "correlation_id": f"corr-key-exec-{len(results) + 1:06d}",
                "correlation_type": "key_login_then_process_exec",
                "title": "SSH key login followed by command execution",
                "primary_artifact": "process_exec",
                "severity": "high",
                "host": host,
                "user": user,
                "src_ip": src_ip,
                "artifacts": [
                    "ssh_key_login",
                    "process_exec",
                ],
                "behavior_features": {
                    "ssh_success_observed": True,
                    "publickey_authentication": True,
                    "post_login_execution_observed": True,
                },
                "supporting_detections": {
                    "ssh_key_login": matched_key_logins,
                    "process_exec": [exec_det],
                },
                "raw_event_refs": sorted(set(raw_event_refs)),
                "evidence_refs": sorted(set(evidence_refs)),
                "time_window_start": first_key_ts.isoformat() if first_key_ts else None,
                "time_window_end": exec_ts.isoformat() if exec_ts else None,
            }
        )

    return results
