from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .correlation import (
    correlate_auth_then_authorized_keys,
    correlate_key_login_then_process_exec,
    correlate_windows_powershell_parent_child_encoded_command,
)
from .dedupe import dedupe_detections, parse_ts
from .evaluator import evaluate_rules_against_events
from .loader import validate_rule

ENDPOINT_EVENTS_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "endpoint_events.schema.json"
)
REQUIRED_DETECTION_KEYS = frozenset(
    {
        "id",
        "rule_id",
        "title",
        "log_source",
        "event_type",
        "artifact",
        "severity",
        "host",
        "user",
        "src_ip",
        "path",
        "command_line",
        "behavior_features",
        "evidence_refs",
        "raw_event_refs",
        "time_window_start",
        "time_window_end",
    }
)
SUPPORTED_CORRELATION_TYPES = frozenset(
    {
        "auth_then_authorized_keys",
        "key_login_then_process_exec",
        "windows_powershell_parent_child_encoded_command",
    }
)
REQUIRED_CORRELATION_KEYS = frozenset(
    {
        "correlation_id",
        "correlation_type",
        "title",
        "primary_artifact",
        "severity",
        "host",
        "user",
        "src_ip",
        "artifacts",
        "behavior_features",
        "supporting_detections",
        "evidence_refs",
        "raw_event_refs",
        "time_window_start",
        "time_window_end",
    }
)


class CommonPipelineValidationError(ValueError):
    """Raised when a common detection-pipeline boundary is invalid."""


def _load_endpoint_events_schema() -> dict[str, Any]:
    return json.loads(ENDPOINT_EVENTS_SCHEMA_PATH.read_text(encoding="utf-8"))


def _format_validation_path(error: Any) -> str:
    path = ".".join(str(part) for part in error.absolute_path)
    return path or "<root>"


def _validate_endpoint_events(endpoint_events: object) -> dict[str, Any]:
    validator = Draft202012Validator(
        _load_endpoint_events_schema(),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    error = next(iter(validator.iter_errors(endpoint_events)), None)
    if error is not None:
        path = _format_validation_path(error)
        raise CommonPipelineValidationError(
            f"endpoint_events.v1 validation failed at {path}: {error.message}"
        ) from None
    return endpoint_events


def _validated_rules(rules: object) -> list[dict[str, Any]]:
    if not isinstance(rules, list) or not rules:
        raise CommonPipelineValidationError("rules must be a non-empty list")

    validated: list[dict[str, Any]] = []
    rule_ids: set[str] = set()
    for index, rule in enumerate(rules):
        try:
            validate_rule(rule, source=f"rules[{index}]")
        except ValueError as exc:
            raise CommonPipelineValidationError(str(exc)) from exc

        behavior_features = rule["behavior_features"]
        if not all(
            isinstance(key, str) and isinstance(value, bool)
            for key, value in behavior_features.items()
        ):
            raise CommonPipelineValidationError(
                f"rules[{index}]: 'behavior_features' must be an object of booleans"
            )

        rule_id = rule["id"]
        if rule_id in rule_ids:
            raise CommonPipelineValidationError(f"duplicate rule id: {rule_id}")
        rule_ids.add(rule_id)
        validated.append(rule)

    return sorted(validated, key=lambda rule: rule["id"])


def validate_canonical_detections(detections: object) -> list[dict[str, Any]]:
    """Validate and return the established canonical detection-list boundary."""

    if not isinstance(detections, list):
        raise CommonPipelineValidationError("canonical detection output must be a list")

    for index, detection in enumerate(detections):
        if not isinstance(detection, dict):
            raise CommonPipelineValidationError(f"detections[{index}] must be an object")

        missing = REQUIRED_DETECTION_KEYS - set(detection)
        if missing:
            fields = ", ".join(sorted(missing))
            raise CommonPipelineValidationError(
                f"detections[{index}] missing canonical fields: {fields}"
            )

        for field in ("id", "rule_id", "title", "artifact", "severity"):
            if not isinstance(detection[field], str) or not detection[field]:
                raise CommonPipelineValidationError(
                    f"detections[{index}].{field} must be a non-empty string"
                )
        if not isinstance(detection["log_source"], dict):
            raise CommonPipelineValidationError(f"detections[{index}].log_source must be an object")
        if detection["event_type"] is not None and not isinstance(detection["event_type"], str):
            raise CommonPipelineValidationError(
                f"detections[{index}].event_type must be a string or null"
            )
        if not isinstance(detection["host"], str) or not detection["host"].strip():
            raise CommonPipelineValidationError(
                f"detections[{index}].host must be a non-empty string"
            )
        for field in ("user", "src_ip", "path", "command_line"):
            if detection[field] is not None and not isinstance(detection[field], str):
                raise CommonPipelineValidationError(
                    f"detections[{index}].{field} must be a string or null"
                )
        if (
            "event_id" in detection
            and detection["event_id"] is not None
            and not isinstance(detection["event_id"], str)
        ):
            raise CommonPipelineValidationError(
                f"detections[{index}].event_id must be a string or null"
            )
        for field in ("pid", "ppid"):
            if field not in detection or detection[field] is None:
                continue
            if isinstance(detection[field], bool) or not isinstance(
                detection[field], (str, int, float)
            ):
                raise CommonPipelineValidationError(
                    f"detections[{index}].{field} must be a string, number, or null"
                )
        if not isinstance(detection["behavior_features"], dict) or not all(
            isinstance(key, str) and isinstance(value, bool)
            for key, value in detection["behavior_features"].items()
        ):
            raise CommonPipelineValidationError(
                f"detections[{index}].behavior_features must be an object of booleans"
            )
        for field in ("evidence_refs", "raw_event_refs"):
            if not isinstance(detection[field], list) or not all(
                isinstance(value, str) for value in detection[field]
            ):
                raise CommonPipelineValidationError(
                    f"detections[{index}].{field} must be a list of strings"
                )
        for field in ("time_window_start", "time_window_end"):
            if detection[field] is not None and not isinstance(detection[field], str):
                raise CommonPipelineValidationError(
                    f"detections[{index}].{field} must be a string or null"
                )

    return detections


def _validate_unique_detection_ids(detections: list[dict[str, Any]]) -> None:
    detection_ids: set[str] = set()
    for detection in detections:
        detection_id = detection["id"]
        if detection_id in detection_ids:
            raise CommonPipelineValidationError(f"duplicate detection id: {detection_id}")
        detection_ids.add(detection_id)


def _validate_dedupe_timestamps(detections: list[dict[str, Any]]) -> None:
    for index, detection in enumerate(detections):
        for field in ("time_window_start", "time_window_end"):
            value = detection[field]
            if value is not None and parse_ts(value) is None:
                raise CommonPipelineValidationError(
                    f"detections[{index}].{field} must be a valid ISO-8601 timestamp or null"
                )


def dedupe_canonical_detections(detections: object) -> list[dict[str, Any]]:
    """Validate and deterministically dedupe canonical detection results."""

    validated = validate_canonical_detections(detections)
    _validate_unique_detection_ids(validated)
    _validate_dedupe_timestamps(validated)
    if not validated:
        return []

    try:
        deduped = dedupe_detections(validated)
    except (TypeError, ValueError) as exc:
        raise CommonPipelineValidationError(f"canonical detection dedupe failed: {exc}") from exc

    validated_deduped = validate_canonical_detections(deduped)
    _validate_unique_detection_ids(validated_deduped)
    _validate_dedupe_timestamps(validated_deduped)
    return validated_deduped


def _normalized_timestamp(value: object) -> datetime | None:
    parsed = parse_ts(value) if isinstance(value, str) else None
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _validate_correlation_refs(
    correlation: dict[str, Any],
    *,
    index: int,
    supporting_detections: list[dict[str, Any]],
) -> None:
    for field in ("evidence_refs", "raw_event_refs"):
        refs = correlation[field]
        if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs):
            raise CommonPipelineValidationError(
                f"correlations[{index}].{field} must be a sorted unique list of strings"
            )
        if refs != sorted(set(refs)):
            raise CommonPipelineValidationError(
                f"correlations[{index}].{field} must be a sorted unique list of strings"
            )
        expected_refs = sorted(
            {ref for detection in supporting_detections for ref in detection.get(field, [])}
        )
        if refs != expected_refs:
            raise CommonPipelineValidationError(
                f"correlations[{index}].{field} must equal supporting detection refs"
            )


def validate_correlation_results(
    correlations: object,
    deduped_detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Structurally validate in-memory correlation results without a new schema."""

    if not isinstance(correlations, list):
        raise CommonPipelineValidationError("correlation output must be a list")

    detections_by_id = {detection["id"]: detection for detection in deduped_detections}
    correlation_ids: set[str] = set()
    for index, correlation in enumerate(correlations):
        if not isinstance(correlation, dict):
            raise CommonPipelineValidationError(f"correlations[{index}] must be an object")

        missing = REQUIRED_CORRELATION_KEYS - set(correlation)
        if missing:
            fields = ", ".join(sorted(missing))
            raise CommonPipelineValidationError(
                f"correlations[{index}] missing correlation fields: {fields}"
            )

        correlation_id = correlation["correlation_id"]
        if not isinstance(correlation_id, str) or not correlation_id.strip():
            raise CommonPipelineValidationError(
                f"correlations[{index}].correlation_id must be a non-empty string"
            )
        if correlation_id in correlation_ids:
            raise CommonPipelineValidationError(f"duplicate correlation id: {correlation_id}")
        correlation_ids.add(correlation_id)

        correlation_type = correlation["correlation_type"]
        if (
            not isinstance(correlation_type, str)
            or correlation_type not in SUPPORTED_CORRELATION_TYPES
        ):
            raise CommonPipelineValidationError(
                f"correlations[{index}].correlation_type is not supported: {correlation_type}"
            )
        for field in ("title", "primary_artifact", "severity", "host"):
            if not isinstance(correlation[field], str) or not correlation[field].strip():
                raise CommonPipelineValidationError(
                    f"correlations[{index}].{field} must be a non-empty string"
                )
        for field in ("user", "src_ip"):
            if correlation[field] is not None and not isinstance(correlation[field], str):
                raise CommonPipelineValidationError(
                    f"correlations[{index}].{field} must be a string or null"
                )

        artifacts = correlation["artifacts"]
        if not isinstance(artifacts, list) or not all(
            isinstance(artifact, str) for artifact in artifacts
        ):
            raise CommonPipelineValidationError(
                f"correlations[{index}].artifacts must be a unique list of strings"
            )
        if len(artifacts) != len(set(artifacts)):
            raise CommonPipelineValidationError(
                f"correlations[{index}].artifacts must be a unique list of strings"
            )
        if correlation["primary_artifact"] not in artifacts:
            raise CommonPipelineValidationError(
                f"correlations[{index}].primary_artifact must be present in artifacts"
            )

        behavior_features = correlation["behavior_features"]
        if not isinstance(behavior_features, dict) or not all(
            isinstance(key, str) and isinstance(value, bool)
            for key, value in behavior_features.items()
        ):
            raise CommonPipelineValidationError(
                f"correlations[{index}].behavior_features must be an object of booleans"
            )

        supporting = correlation["supporting_detections"]
        if not isinstance(supporting, dict) or not supporting:
            raise CommonPipelineValidationError(
                f"correlations[{index}].supporting_detections must be a non-empty mapping"
            )
        flattened: list[dict[str, Any]] = []
        for artifact, detections in supporting.items():
            if not isinstance(artifact, str) or not isinstance(detections, list):
                raise CommonPipelineValidationError(
                    f"correlations[{index}].supporting_detections must map strings to lists"
                )
            flattened.extend(validate_canonical_detections(detections))
        if not flattened:
            raise CommonPipelineValidationError(
                f"correlations[{index}].supporting_detections must not be empty"
            )

        supporting_ids: set[str] = set()
        for detection in flattened:
            detection_id = detection["id"]
            if detection_id in supporting_ids:
                raise CommonPipelineValidationError(
                    f"correlations[{index}] repeats supporting detection id: {detection_id}"
                )
            supporting_ids.add(detection_id)
            if detection_id not in detections_by_id:
                raise CommonPipelineValidationError(
                    f"correlations[{index}] references unknown detection id: {detection_id}"
                )
            if detection != detections_by_id[detection_id]:
                raise CommonPipelineValidationError(
                    f"correlations[{index}] supporting detection differs from input: {detection_id}"
                )

        _validate_correlation_refs(
            correlation,
            index=index,
            supporting_detections=flattened,
        )

        start = _normalized_timestamp(correlation["time_window_start"])
        end = _normalized_timestamp(correlation["time_window_end"])
        if start is None or end is None:
            raise CommonPipelineValidationError(
                f"correlations[{index}] time window must contain valid timestamps"
            )
        if start > end:
            raise CommonPipelineValidationError(
                f"correlations[{index}].time_window_start must not be after time_window_end"
            )

    return correlations


def _correlation_sort_key(correlation: dict[str, Any]) -> tuple:
    start = _normalized_timestamp(correlation.get("time_window_start"))
    return (
        start is None,
        start or datetime.max.replace(tzinfo=timezone.utc),
        str(correlation.get("correlation_type") or ""),
        str(correlation.get("correlation_id") or ""),
    )


def sort_correlation_results(
    correlations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return correlation results in the established deterministic order."""

    return sorted(correlations, key=_correlation_sort_key)


def _run_fixed_correlation_policies(
    deduped_detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Execute the fixed correlation policy set without validating supplied output."""

    try:
        auth_correlations = correlate_auth_then_authorized_keys(deduped_detections)
    except (TypeError, ValueError) as exc:
        raise CommonPipelineValidationError(
            f"correlation policy auth_then_authorized_keys failed: {exc}"
        ) from exc
    if not isinstance(auth_correlations, list):
        raise CommonPipelineValidationError(
            "correlation policy auth_then_authorized_keys output must be a list"
        )

    try:
        key_exec_correlations = correlate_key_login_then_process_exec(deduped_detections)
    except (TypeError, ValueError) as exc:
        raise CommonPipelineValidationError(
            f"correlation policy key_login_then_process_exec failed: {exc}"
        ) from exc
    if not isinstance(key_exec_correlations, list):
        raise CommonPipelineValidationError(
            "correlation policy key_login_then_process_exec output must be a list"
        )

    try:
        windows_process_correlations = correlate_windows_powershell_parent_child_encoded_command(
            deduped_detections
        )
    except (TypeError, ValueError) as exc:
        raise CommonPipelineValidationError(
            f"correlation policy windows_powershell_parent_child_encoded_command failed: {exc}"
        ) from exc
    if not isinstance(windows_process_correlations, list):
        raise CommonPipelineValidationError(
            "correlation policy windows_powershell_parent_child_encoded_command "
            "output must be a list"
        )

    return [
        *auth_correlations,
        *key_exec_correlations,
        *windows_process_correlations,
    ]


def validate_correlation_results_against_policies(
    correlations: object,
    deduped_detections: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate supplied correlations against deterministic fixed-policy output."""

    supplied = sort_correlation_results(
        validate_correlation_results(correlations, deduped_detections)
    )
    expected = sort_correlation_results(
        validate_correlation_results(
            _run_fixed_correlation_policies(deduped_detections),
            deduped_detections,
        )
    )
    if supplied != expected:
        raise CommonPipelineValidationError(
            "correlation results do not match deterministic fixed-policy output"
        )
    return supplied


def run_common_correlation_stage(
    detections: object,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Run fixed correlation policies over validated, deduped canonical detections."""

    deduped = dedupe_canonical_detections(detections)
    if not deduped:
        return [], []

    correlations = _run_fixed_correlation_policies(deduped)
    validated = validate_correlation_results(correlations, deduped)
    return deduped, sort_correlation_results(validated)


def run_common_detection_pipeline(
    endpoint_events: object,
    rules: object,
    *,
    time_min: datetime | None = None,
    time_max: datetime | None = None,
) -> list[dict[str, Any]]:
    """Validate normalized endpoint events and evaluate atomic rules deterministically."""

    validated_events = _validate_endpoint_events(endpoint_events)
    ordered_rules = _validated_rules(rules)
    detections = evaluate_rules_against_events(
        validated_events["events"],
        ordered_rules,
        time_min=time_min,
        time_max=time_max,
    )
    return validate_canonical_detections(detections)
