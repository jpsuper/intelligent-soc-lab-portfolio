import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


def load_optional_json(path: str | Path) -> list[dict] | None:
    file_path = Path(path)
    if not file_path.exists():
        return None
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return None


def parse_ts(value: str | None) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def event_ts(event: dict) -> datetime | None:
    return parse_ts(event.get("timestamp"))


def incident_start_ts(incident: dict) -> datetime | None:
    start = parse_ts(incident.get("time_window_start"))
    if start:
        return start

    timeline = incident.get("timeline", []) or []
    timestamps = [event_ts(item) for item in timeline]
    timestamps = [ts for ts in timestamps if ts is not None]
    return min(timestamps) if timestamps else None


def incident_end_ts(incident: dict) -> datetime | None:
    end = parse_ts(incident.get("time_window_end"))
    if end:
        return end

    timeline = incident.get("timeline", []) or []
    timestamps = [event_ts(item) for item in timeline]
    timestamps = [ts for ts in timestamps if ts is not None]
    return max(timestamps) if timestamps else None


def dedupe_events(events: list[dict]) -> list[dict]:
    seen = set()
    deduped = []
    for event in events:
        key = (
            event.get("timestamp"),
            event.get("event_type"),
            event.get("username"),
            event.get("src_ip"),
            event.get("src_port"),
            event.get("pid"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def summarize_time(events: list[dict]) -> str | None:
    timestamps = [event.get("timestamp") for event in events if event.get("timestamp")]
    if not timestamps:
        return None
    return sorted(timestamps)[0]


def build_auth_patch(
    ssh_auth_events: list[dict] | None,
    incident: dict,
    payload_source_ips: list[str] | None = None,
    failed_window_minutes: int = 10,
    success_window_minutes: int = 3,
) -> dict:
    evidence_patch: dict[str, Any] = {}
    enriched_features_patch: dict[str, bool] = {
        "auth_bruteforce_observed": False,
        "auth_success_after_failures_observed": False,
        "same_source_ip_auth_and_payload_observed": False,
    }
    investigation_notes_patch: list[str] = []
    timeline_notes_patch: list[str] = []

    if not ssh_auth_events:
        return {
            "evidence_patch": evidence_patch,
            "enriched_features_patch": enriched_features_patch,
            "investigation_notes_patch": investigation_notes_patch,
            "timeline_notes_patch": timeline_notes_patch,
        }

    host = incident.get("host")
    username = incident.get("username") or incident.get("user")
    start_ts = incident_start_ts(incident)
    end_ts = incident_end_ts(incident)

    if not start_ts or not end_ts:
        return {
            "evidence_patch": evidence_patch,
            "enriched_features_patch": enriched_features_patch,
            "investigation_notes_patch": investigation_notes_patch,
            "timeline_notes_patch": timeline_notes_patch,
        }

    failed_start = start_ts - timedelta(minutes=failed_window_minutes)
    success_start = start_ts - timedelta(minutes=success_window_minutes)
    success_end = end_ts + timedelta(minutes=success_window_minutes)

    failed_events: list[dict] = []
    success_events: list[dict] = []
    publickey_events: list[dict] = []

    for event in ssh_auth_events:
        if host and event.get("host") and event.get("host") != host:
            continue
        if username and event.get("username") and event.get("username") != username:
            continue

        ts = event_ts(event)
        if not ts:
            continue

        event_type = event.get("event_type")
        if event_type in {"ssh_failed_login", "ssh_auth_failure"}:
            if failed_start <= ts <= end_ts:
                failed_events.append(event)
        elif event_type == "ssh_success_login":
            if success_start <= ts <= success_end:
                success_events.append(event)
        elif event_type == "ssh_publickey_login":
            if success_start <= ts <= success_end:
                publickey_events.append(event)

    failed_events = dedupe_events(sorted(failed_events, key=event_ts))
    success_events = dedupe_events(sorted(success_events, key=event_ts))
    publickey_events = dedupe_events(sorted(publickey_events, key=event_ts))

    if failed_events:
        evidence_patch["ssh_failed_login_events"] = failed_events
        evidence_patch["ssh_failed_login_count"] = len(failed_events)
        enriched_features_patch["auth_bruteforce_observed"] = True

    if success_events:
        evidence_patch["ssh_success_login_events"] = success_events
        evidence_patch["ssh_success_login_count"] = len(success_events)
        evidence_patch["first_ssh_success_login"] = success_events[0]

    if publickey_events:
        evidence_patch["ssh_publickey_login_events"] = publickey_events
        evidence_patch["ssh_publickey_login_count"] = len(publickey_events)

    auth_source_ips = sorted(
        {
            event.get("src_ip")
            for event in (failed_events + success_events + publickey_events)
            if event.get("src_ip")
        }
    )
    if auth_source_ips:
        evidence_patch["auth_source_ips"] = auth_source_ips

    if failed_events or success_events or publickey_events:
        timestamps = [
            event.get("timestamp")
            for event in (failed_events + success_events + publickey_events)
            if event.get("timestamp")
        ]
        if timestamps:
            evidence_patch["auth_burst_window_start"] = min(timestamps)
            evidence_patch["auth_burst_window_end"] = max(timestamps)

    if failed_events and success_events:
        first_success_ts = event_ts(success_events[0])
        if first_success_ts:
            prior_failures = [
                event
                for event in failed_events
                if event_ts(event) and event_ts(event) <= first_success_ts
            ]
            if prior_failures:
                enriched_features_patch["auth_success_after_failures_observed"] = True

    payload_source_ips = payload_source_ips or []
    if auth_source_ips and payload_source_ips:
        if set(auth_source_ips) & set(payload_source_ips):
            enriched_features_patch["same_source_ip_auth_and_payload_observed"] = True

    source_ip_display = ", ".join(auth_source_ips) if auth_source_ips else "unknown_source"

    if failed_events:
        first_failed_ts = summarize_time(failed_events) or "unknown_time"
        investigation_notes_patch.append(
            "SSH authentication failures were observed before execution "
            f"({len(failed_events)} events) from {source_ip_display}."
        )
        timeline_notes_patch.append(
            f"ssh_auth: {first_failed_ts} "
            f"{len(failed_events)} failed login events for "
            f"{username or 'unknown_user'} from {source_ip_display}"
        )
    if success_events:
        first_success = success_events[0]
        investigation_notes_patch.append(
            "Successful SSH password login was observed for "
            f"{first_success.get('username')} from "
            f"{first_success.get('src_ip')}."
        )
        timeline_notes_patch.append(
            f"ssh_auth: {first_success.get('timestamp')} "
            "successful password login for "
            f"{first_success.get('username')} from "
            f"{first_success.get('src_ip')}"
        )

    # Only surface publickey in notes when password success is absent,
    # so scenario_003 stays focused.
    if publickey_events and not success_events:
        first_publickey = publickey_events[0]
        investigation_notes_patch.append(
            "SSH publickey login was also observed for "
            f"{first_publickey.get('username')} from "
            f"{first_publickey.get('src_ip')}."
        )
        timeline_notes_patch.append(
            f"ssh_auth: {first_publickey.get('timestamp')} "
            "successful publickey login for "
            f"{first_publickey.get('username')} from "
            f"{first_publickey.get('src_ip')}"
        )

    if enriched_features_patch["auth_success_after_failures_observed"]:
        investigation_notes_patch.append(
            "A successful SSH password login followed earlier "
            "authentication failures in the same context."
        )

    if enriched_features_patch["same_source_ip_auth_and_payload_observed"]:
        investigation_notes_patch.append(
            "The SSH source IP matched the payload delivery source IP."
        )

    return {
        "evidence_patch": evidence_patch,
        "enriched_features_patch": enriched_features_patch,
        "investigation_notes_patch": investigation_notes_patch,
        "timeline_notes_patch": timeline_notes_patch,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build an SSH auth investigation patch.")
    parser.add_argument("--input", required=True, help="Path to ssh_auth_events.json")
    parser.add_argument("--incident", required=True, help="Path to incident.json")
    parser.add_argument(
        "--payload-source-ip",
        action="append",
        default=[],
        help="Optional payload source IP. Repeatable.",
    )
    parser.add_argument("--output", required=True, help="Output path for patch JSON")
    args = parser.parse_args()

    with Path(args.incident).open("r", encoding="utf-8") as f:
        incident_data = json.load(f)
    incident = incident_data[0] if isinstance(incident_data, list) else incident_data

    ssh_auth_events = load_optional_json(args.input)
    patch = build_auth_patch(
        ssh_auth_events=ssh_auth_events,
        incident=incident,
        payload_source_ips=args.payload_source_ip,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(patch, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote auth patch to {output_path}")
