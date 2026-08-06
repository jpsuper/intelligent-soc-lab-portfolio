import json
from pathlib import Path
from typing import Any

DEFAULT_SUDO_EXCLUDE_PATTERNS = [
    "/var/ossec/etc/ossec.conf",
    "systemctl status wazuh-agent",
    "scp /var/ossec/etc/ossec.conf",
    "grep -nA5 <vulnerability-detection>",
    "cat /var/ossec/etc/ossec.conf",
]

DEFAULT_FIM_EXCLUDE_PATTERNS = [
    "/etc/systemd/system/snap-",
    "/etc/systemd/system/snap.",
    "/etc/systemd/system/multi-user.target.wants/snap",
    "/etc/systemd/system/snapd.mounts.target.wants/snap",
    "/etc/systemd/system/sockets.target.wants/snap",
    "snap.lxd.",
    "/etc/ld.so.cache",
    "/usr/bin/c_rehash",
    "/usr/bin/openssl",
]


def load_optional_json(path: str | Path) -> list[dict] | None:
    file_path = Path(path)
    if not file_path.exists():
        return None
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return None


def _safe_str(value: Any) -> str:
    return "" if value is None else str(value)


def _get_syscheck(alert: dict) -> dict:
    return (alert.get("attributes") or {}).get("syscheck") or {}


def _get_data(alert: dict) -> dict:
    return (alert.get("attributes") or {}).get("data") or {}


def _get_window_type(alert: dict) -> str:
    return _safe_str(alert.get("search_window_type"))


def _collect_window_types(alerts: list[dict]) -> list[str]:
    values = sorted({value for value in (_get_window_type(a) for a in alerts) if value})
    return values


def _matches_host(alert: dict, host: str | None) -> bool:
    if not host:
        return True
    return _safe_str(alert.get("agent_name")) == host


def _matches_user(alert: dict, username: str | None) -> bool:
    if not username:
        return True

    syscheck = _get_syscheck(alert)
    uname_after = _safe_str(syscheck.get("uname_after"))
    data = _get_data(alert)
    srcuser = _safe_str(data.get("srcuser"))

    return username in {uname_after, srcuser}


def _matches_paths(alert: dict, candidate_paths: list[str] | None) -> bool:
    if not candidate_paths:
        return True

    syscheck = _get_syscheck(alert)
    path = _safe_str(syscheck.get("path"))
    data = _get_data(alert)
    command = _safe_str(data.get("command"))
    full_log = _safe_str(alert.get("full_log"))

    for candidate in candidate_paths:
        if not candidate:
            continue
        if candidate == path or candidate in path or candidate in command or candidate in full_log:
            return True
    return False


def _is_fim_alert(alert: dict) -> bool:
    groups = set(alert.get("rule_groups") or [])
    return "syscheck" in groups


def _is_sudo_alert(alert: dict) -> bool:
    groups = set(alert.get("rule_groups") or [])
    return "sudo" in groups


def _is_persistence_related_path(path: str) -> bool:
    checks = [
        "/etc/systemd/system",
        "/var/spool/cron",
        "/.ssh/",
        "authorized_keys",
    ]
    return any(token in path for token in checks)


def _is_fim_path_noise(path: str, exclude_patterns: list[str] | None = None) -> bool:
    patterns = exclude_patterns or DEFAULT_FIM_EXCLUDE_PATTERNS
    return any(pattern in path for pattern in patterns)


def _is_sudo_command_noise(command: str, exclude_patterns: list[str] | None = None) -> bool:
    patterns = exclude_patterns or DEFAULT_SUDO_EXCLUDE_PATTERNS
    return any(pattern in command for pattern in patterns)


def _is_persistence_related_command(command: str) -> bool:
    checks = [
        "/etc/systemd/system",
        "/var/spool/cron",
        "/.ssh/",
        "authorized_keys",
    ]
    return any(token in command for token in checks)


def build_wazuh_patch(
    wazuh_alerts: list[dict] | None,
    host: str | None = None,
    username: str | None = None,
    candidate_paths: list[str] | None = None,
    sudo_exclude_patterns: list[str] | None = None,
    fim_exclude_patterns: list[str] | None = None,
) -> dict:
    evidence_patch: dict[str, Any] = {}
    enriched_features_patch: dict[str, bool] = {
        "wazuh_context_observed": False,
        "fim_context_observed": False,
        "sudo_context_observed": False,
        "persistence_related_file_change_observed": False,
        "persistence_related_sudo_observed": False,
    }
    investigation_notes_patch: list[str] = []
    timeline_notes_patch: list[str] = []

    if not wazuh_alerts:
        return {
            "evidence_patch": evidence_patch,
            "enriched_features_patch": enriched_features_patch,
            "investigation_notes_patch": investigation_notes_patch,
            "timeline_notes_patch": timeline_notes_patch,
        }

    filtered = [
        alert
        for alert in wazuh_alerts
        if _matches_host(alert, host)
        and _matches_user(alert, username)
        and _matches_paths(alert, candidate_paths)
    ]

    if not filtered:
        return {
            "evidence_patch": evidence_patch,
            "enriched_features_patch": enriched_features_patch,
            "investigation_notes_patch": investigation_notes_patch,
            "timeline_notes_patch": timeline_notes_patch,
        }

    enriched_features_patch["wazuh_context_observed"] = True

    fim_alerts_raw = [a for a in filtered if _is_fim_alert(a)]
    sudo_alerts_raw = [a for a in filtered if _is_sudo_alert(a)]

    fim_alerts: list[dict] = []
    excluded_fim_paths: list[str] = []

    for alert in fim_alerts_raw:
        syscheck = _get_syscheck(alert)
        path = _safe_str(syscheck.get("path"))

        if path and _is_fim_path_noise(path, fim_exclude_patterns):
            if path not in excluded_fim_paths:
                excluded_fim_paths.append(path)
            continue

        fim_alerts.append(alert)

    if fim_alerts:
        evidence_patch["wazuh_fim_observations"] = fim_alerts
        enriched_features_patch["fim_context_observed"] = True

        affected_paths: list[str] = []
        affected_events: list[str] = []

        for alert in fim_alerts:
            syscheck = _get_syscheck(alert)
            path = _safe_str(syscheck.get("path"))
            event = _safe_str(syscheck.get("event"))
            ts = _safe_str(alert.get("timestamp"))

            if path and path not in affected_paths:
                affected_paths.append(path)
            if event and event not in affected_events:
                affected_events.append(event)

            if _is_persistence_related_path(path):
                enriched_features_patch["persistence_related_file_change_observed"] = True

            timeline_notes_patch.append(
                f"wazuh_fim: {ts} {event or 'changed'} {path or 'unknown_path'}"
            )

        if affected_paths:
            evidence_patch["wazuh_fim_paths"] = affected_paths
        if affected_events:
            evidence_patch["wazuh_fim_events"] = affected_events
        if excluded_fim_paths:
            evidence_patch["wazuh_fim_excluded_paths"] = excluded_fim_paths

        window_types = _collect_window_types(fim_alerts)
        if window_types:
            evidence_patch["wazuh_fim_search_window_types"] = window_types
            if window_types == ["medium"]:
                investigation_notes_patch.append(
                    "Wazuh FIM evidence came from the medium fallback window "
                    "and should be treated as supporting evidence."
                )

        if affected_paths:
            investigation_notes_patch.append(
                "Wazuh FIM observed file changes for: " + "; ".join(affected_paths) + "."
            )

        if enriched_features_patch["persistence_related_file_change_observed"]:
            investigation_notes_patch.append("Wazuh FIM observed persistence-related file changes.")
    elif excluded_fim_paths:
        evidence_patch["wazuh_fim_excluded_paths"] = excluded_fim_paths

    sudo_alerts: list[dict] = []
    sudo_commands: list[str] = []
    excluded_sudo_commands: list[str] = []

    for alert in sudo_alerts_raw:
        data = _get_data(alert)
        command = _safe_str(data.get("command"))

        if not command:
            continue

        if _is_sudo_command_noise(command, sudo_exclude_patterns):
            if command not in excluded_sudo_commands:
                excluded_sudo_commands.append(command)
            continue

        if candidate_paths and not _is_persistence_related_command(command):
            if not any(candidate in command for candidate in candidate_paths if candidate):
                if command not in excluded_sudo_commands:
                    excluded_sudo_commands.append(command)
                continue

        sudo_alerts.append(alert)
        if command not in sudo_commands:
            sudo_commands.append(command)

    if sudo_alerts:
        evidence_patch["wazuh_sudo_observations"] = sudo_alerts
        evidence_patch["wazuh_sudo_commands"] = sudo_commands
        if excluded_sudo_commands:
            evidence_patch["wazuh_sudo_excluded_commands"] = excluded_sudo_commands

        enriched_features_patch["sudo_context_observed"] = True

        for alert in sudo_alerts:
            data = _get_data(alert)
            command = _safe_str(data.get("command"))
            ts = _safe_str(alert.get("timestamp"))

            if _is_persistence_related_command(command):
                enriched_features_patch["persistence_related_sudo_observed"] = True

            timeline_notes_patch.append(f"wazuh_sudo: {ts} {command}")

        window_types = _collect_window_types(sudo_alerts)
        if window_types:
            evidence_patch["wazuh_sudo_search_window_types"] = window_types
            if window_types == ["medium"]:
                investigation_notes_patch.append(
                    "Wazuh sudo evidence came from the medium fallback window "
                    "and should be treated as supporting evidence."
                )

        investigation_notes_patch.append(
            "Wazuh sudo alerts observed commands: " + "; ".join(sudo_commands) + "."
        )

        if enriched_features_patch["persistence_related_sudo_observed"]:
            investigation_notes_patch.append(
                "Wazuh sudo alerts included persistence-related commands."
            )
    elif excluded_sudo_commands:
        evidence_patch["wazuh_sudo_excluded_commands"] = excluded_sudo_commands

    return {
        "evidence_patch": evidence_patch,
        "enriched_features_patch": enriched_features_patch,
        "investigation_notes_patch": investigation_notes_patch,
        "timeline_notes_patch": timeline_notes_patch,
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build a Wazuh investigation patch.")
    parser.add_argument("--input", required=True, help="Path to canonical Wazuh alerts JSON")
    parser.add_argument("--host", help="Optional host filter, e.g. ubuntu-victim01")
    parser.add_argument("--user", help="Optional user filter")
    parser.add_argument(
        "--path", action="append", help="Optional candidate path filter (repeatable)"
    )
    parser.add_argument(
        "--exclude-sudo", action="append", help="Optional sudo noise pattern override/addition"
    )
    parser.add_argument(
        "--exclude-fim", action="append", help="Optional FIM noise pattern override/addition"
    )
    parser.add_argument("--output", required=True, help="Output path for generated patch JSON")
    args = parser.parse_args()

    alerts = load_optional_json(args.input)
    patch = build_wazuh_patch(
        wazuh_alerts=alerts,
        host=args.host,
        username=args.user,
        candidate_paths=args.path,
        sudo_exclude_patterns=args.exclude_sudo,
        fim_exclude_patterns=args.exclude_fim,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(patch, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote Wazuh patch to {output_path}")
