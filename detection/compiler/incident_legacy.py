from __future__ import annotations

import argparse
import json
from pathlib import Path

from common.run_context import get_run_paths

CORRELATED_FILE = Path("data/correlation/correlated_incidents.json")
HITS_FILE = Path("data/detections/detection_hits.json")
OUTPUT_FILE = Path("data/incidents/incident.json")
INCIDENT_SCHEMA_FILE = Path(__file__).resolve().parents[2] / "schemas" / "incident_schema.json"
INCIDENT_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


def load_json(path: Path) -> list[dict]:
    with path.open() as f:
        return json.load(f)


def build_timeline(matched_detection_ids: list[str], hits_by_id: dict[str, dict]) -> list[dict]:
    timeline = []

    for det_id in matched_detection_ids:
        hit = hits_by_id.get(det_id)
        if not hit:
            continue

        timeline.append(
            {
                "timestamp": hit["timestamp"],
                "rule_name": hit["rule_name"],
                "event_ref": hit["event_ref"],
                "host": hit["host"],
                "src_ip": hit.get("src_ip"),
                "username": hit.get("username"),
                "severity": hit["severity"],
            }
        )

    timeline.sort(key=lambda x: x["timestamp"])
    return timeline


def collect_source_ips(timeline: list[dict]) -> list[str]:
    ips = []
    for item in timeline:
        ip = item.get("src_ip")
        if ip and ip not in ips:
            ips.append(ip)
    return ips


def collect_raw_event_refs(timeline: list[dict]) -> list[str]:
    refs = []
    for item in timeline:
        ref = item.get("event_ref")
        if ref and ref not in refs:
            refs.append(ref)
    return refs


def map_mitre(rule_names: list[str]) -> list[str]:
    mapping = {
        "ssh_failed_login": "T1110",
        "ssh_success_login": "T1078",
        "sudo_command": "T1548",
    }

    mitre = []
    for rule_name in rule_names:
        technique = mapping.get(rule_name)
        if technique and technique not in mitre:
            mitre.append(technique)
    return mitre


def merge_behavior_features(feature_objects: list[dict]) -> dict:
    merged: dict[str, bool] = {}

    for features in feature_objects:
        if not isinstance(features, dict):
            continue

        for key, value in features.items():
            if isinstance(value, bool):
                merged[key] = merged.get(key, False) or value

    return merged


def collect_behavior_features_from_hits(
    matched_detection_ids: list[str],
    hits_by_id: dict[str, dict],
) -> dict:
    feature_objects = []

    for det_id in matched_detection_ids:
        hit = hits_by_id.get(det_id)
        if not hit:
            continue

        if isinstance(hit.get("behavior_features"), dict):
            feature_objects.append(hit["behavior_features"])
        elif isinstance(hit.get("feature_mapping"), dict):
            feature_objects.append(hit["feature_mapping"])

    return merge_behavior_features(feature_objects)


def build_incident(corr: dict, hits_by_id: dict[str, dict], idx: int) -> dict:
    timeline = build_timeline(corr["matched_detection_ids"], hits_by_id)
    source_ips = collect_source_ips(timeline)
    raw_event_refs = collect_raw_event_refs(timeline)
    behavior_features = collect_behavior_features_from_hits(
        corr["matched_detection_ids"],
        hits_by_id,
    )

    return {
        "incident_id": f"inc-{idx:06d}",
        "attack_id": corr.get("attack_id"),
        "scenario_name": corr["scenario_name"],
        "title": "Possible SSH compromise followed by sudo activity",
        "severity": corr["severity"],
        "confidence": corr["confidence"],
        "summary": corr["summary"],
        "host": corr["host"],
        "username": corr["username"],
        "source_hosts": [corr["host"]],
        "source_ips": source_ips,
        "time_window_start": corr["time_window_start"],
        "time_window_end": corr["time_window_end"],
        "matched_detection_ids": corr["matched_detection_ids"],
        "matched_rule_names": corr["matched_rule_names"],
        "mitre_attack": map_mitre(corr["matched_rule_names"]),
        "raw_event_refs": raw_event_refs,
        "timeline": timeline,
        "behavior_features": behavior_features,
    }


def build_process_incident(hit: dict, idx: int) -> dict:
    timeline = hit.get("timeline", [])

    start = timeline[0]["timestamp"] if timeline else None
    end = timeline[-1]["timestamp"] if timeline else None

    behavior_features = {}
    if isinstance(hit.get("behavior_features"), dict):
        behavior_features = hit["behavior_features"]
    elif isinstance(hit.get("feature_mapping"), dict):
        behavior_features = hit["feature_mapping"]

    return {
        "incident_id": f"inc-{idx:06d}",
        "attack_id": None,
        "scenario_name": "download_and_execute_payload",
        "title": "Suspicious payload download and execution",
        "severity": hit.get("severity", "high"),
        "confidence": "medium",
        "summary": (
            "A payload was downloaded, made executable, and executed from a temporary path."
        ),
        "host": hit.get("host"),
        "username": hit.get("user"),
        "source_hosts": [hit.get("host")] if hit.get("host") else [],
        "source_ips": [],
        "time_window_start": start,
        "time_window_end": end,
        "matched_detection_ids": [],
        "matched_rule_names": [hit.get("detection_type")],
        "mitre_attack": ["T1105", "T1059"],
        "raw_event_refs": [],
        "timeline": timeline,
        "behavior_features": behavior_features,
        "process_summary": {
            "download_attempts": hit.get("download_attempts"),
            "detection_type": hit.get("detection_type"),
        },
    }


def parse_args():
    parser = argparse.ArgumentParser(description="Build incidents from detections")
    parser.add_argument("--run-id", help="Run ID for run-based process incident building")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.run_id:
        run_paths = get_run_paths(args.run_id)
        process_hits = load_json(run_paths.process_chain_hits)

        incidents = []
        for idx, hit in enumerate(process_hits, start=1):
            incidents.append(build_process_incident(hit, idx))

        run_paths.incident.parent.mkdir(parents=True, exist_ok=True)
        with run_paths.incident.open("w") as f:
            json.dump(incidents, f, indent=2)

        print(f"Loaded {len(process_hits)} process chain hits")
        print(f"Built {len(incidents)} incidents")
        print(f"Saved to {run_paths.incident}")
        return

    correlated = load_json(CORRELATED_FILE)
    hits = load_json(HITS_FILE)

    hits_by_id = {hit["detection_id"]: hit for hit in hits}

    incidents = []
    for idx, corr in enumerate(correlated, start=1):
        incidents.append(build_incident(corr, hits_by_id, idx))

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("w") as f:
        json.dump(incidents, f, indent=2)

    print(f"Loaded {len(correlated)} correlated incidents")
    print(f"Built {len(incidents)} incidents")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
