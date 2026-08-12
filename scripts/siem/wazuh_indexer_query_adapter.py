from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, ValidationError
from wazuh_indexer_cursor import (
    WazuhIndexerCursor,
    WazuhIndexerCursorError,
    decode_wazuh_indexer_cursor,
    encode_wazuh_indexer_cursor,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REQUEST_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "siem_query_request.schema.json"
RESPONSE_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "siem_query_response.schema.json"
REGISTRY_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "siem_source_registry_entry.schema.json"
DEFAULT_REGISTRY_PATH = (
    REPOSITORY_ROOT / "config" / "siem_sources" / "wazuh_alerts_sysmon_event1.yaml"
)
WINDOWS_SECURITY_AUTH_REGISTRY_PATH = (
    REPOSITORY_ROOT / "config" / "siem_sources" / "wazuh_alerts_windows_security_auth.yaml"
)

SUPPORTED_BACKEND = "wazuh_indexer"
SOURCE_REGISTRY_PATHS = {
    "wazuh-alerts-sysmon-event1": DEFAULT_REGISTRY_PATH,
    "wazuh-alerts-windows-security-auth": WINDOWS_SECURITY_AUTH_REGISTRY_PATH,
}
REFINEMENT_PAGINATION_MODE = "refine_required"
PIT_PAGINATION_MODE = "pit_search_after"


class SiemQueryAdapterError(ValueError):
    """Stable, safe SIEM query adapter failure."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _validation_error_path(error: ValidationError, *, root: str) -> str:
    path = [str(part) for part in error.absolute_path]
    if error.validator == "required" and isinstance(error.instance, dict):
        missing = next(
            (field for field in error.validator_value if field not in error.instance),
            None,
        )
        if missing is not None:
            path.append(str(missing))
    elif error.validator == "additionalProperties" and isinstance(error.instance, dict):
        allowed = set(error.schema.get("properties", {}))
        unexpected = sorted(set(error.instance) - allowed)
        if unexpected:
            path.append(unexpected[0])
    return ".".join(path) if path else root


def _validate_schema(
    value: object,
    *,
    schema_path: Path,
    root: str,
    category: str,
) -> None:
    validator = Draft202012Validator(
        _load_json(schema_path),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    error = next(iter(validator.iter_errors(value)), None)
    if error is not None:
        path = _validation_error_path(error, root=root)
        raise SiemQueryAdapterError(category, f"SIEM query validation failed at {path}")


def load_source_registry(path: str | Path = DEFAULT_REGISTRY_PATH) -> dict[str, object]:
    """Load and validate one reviewed Wazuh source-registry entry."""

    registry_path = Path(path)
    try:
        loaded = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise SiemQueryAdapterError(
            "unknown_source",
            "SIEM source registry could not be loaded",
        ) from exc
    _validate_schema(
        loaded,
        schema_path=REGISTRY_SCHEMA_PATH,
        root="registry",
        category="unknown_source",
    )
    assert isinstance(loaded, dict)
    expected_path = SOURCE_REGISTRY_PATHS.get(loaded["name"])
    if (
        loaded["backend"] != SUPPORTED_BACKEND
        or expected_path is None
        or registry_path.resolve() != expected_path.resolve()
    ):
        raise SiemQueryAdapterError(
            "unknown_source",
            "SIEM source registry does not match the supported adapter scope",
        )
    return loaded


def _registry_path_for_request(
    request: Mapping[str, object],
    registry_path: str | Path | None,
) -> Path:
    if registry_path is not None:
        return Path(registry_path)
    source_names = request.get("source_names")
    if not isinstance(source_names, list) or len(source_names) != 1:
        raise SiemQueryAdapterError(
            "unknown_source",
            "SIEM query source is outside the reviewed Wazuh adapter scope",
        )
    path = SOURCE_REGISTRY_PATHS.get(source_names[0])
    if path is None:
        raise SiemQueryAdapterError(
            "unknown_source",
            "SIEM query source is outside the reviewed Wazuh adapter scope",
        )
    return path


def _parse_timestamp(
    value: str,
    *,
    path: str,
    category: str = "invalid_time_range",
) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SiemQueryAdapterError(
            category,
            f"SIEM query validation failed at {path}",
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SiemQueryAdapterError(
            category,
            f"SIEM query validation failed at {path}",
        )
    return parsed


def _rfc3339_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(value: object) -> str:
    digest = hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _request_fingerprint(request: Mapping[str, object]) -> str:
    normalized = copy.deepcopy(dict(request))
    normalized["cursor"] = None
    return _sha256(normalized)


def _validate_time_range(request: Mapping[str, object], registry: Mapping[str, object]) -> None:
    time_range = request["time_range"]
    assert isinstance(time_range, Mapping)
    start = _parse_timestamp(time_range["start"], path="request.time_range.start")
    end = _parse_timestamp(time_range["end"], path="request.time_range.end")
    if start >= end:
        raise SiemQueryAdapterError(
            "invalid_time_range",
            "SIEM query validation failed at request.time_range",
        )
    window_seconds = (end - start).total_seconds()
    if window_seconds > registry["max_query_window_seconds"]:
        raise SiemQueryAdapterError(
            "time_range_too_large",
            "SIEM query time range exceeds the registered maximum",
        )


def _resolve_filters(
    request: Mapping[str, object],
    registry: Mapping[str, object],
) -> list[dict[str, object]]:
    filters = request["filters"]
    field_definitions = registry["field_definitions"]
    assert isinstance(filters, list)
    assert isinstance(field_definitions, Mapping)

    seen: set[str] = set()
    resolved: list[dict[str, object]] = []
    for item in filters:
        assert isinstance(item, Mapping)
        field = item["field"]
        operator = item["operator"]
        if field in seen:
            raise SiemQueryAdapterError(
                "invalid_request",
                "SIEM query contains a duplicate filter field",
            )
        seen.add(field)
        definition = field_definitions.get(field)
        if not isinstance(definition, Mapping):
            raise SiemQueryAdapterError(
                "unknown_field",
                "SIEM query filter uses an unregistered field",
            )
        if operator not in definition["operators"]:
            raise SiemQueryAdapterError(
                "unsupported_filter",
                "SIEM query filter operator is not registered for the field",
            )
        if operator != "eq" or not isinstance(item["value"], str) or not item["value"].strip():
            raise SiemQueryAdapterError(
                "field_type_mismatch",
                "SIEM query filter value is incompatible with this adapter slice",
            )
        resolved.append(copy.deepcopy(dict(item)))

    required_filters = registry["required_filters"]
    assert isinstance(required_filters, list)
    missing = [field for field in required_filters if field not in seen]
    if missing:
        raise SiemQueryAdapterError(
            "invalid_request",
            "SIEM query is missing a required host filter",
        )
    return resolved


def _resolve_projection(
    request: Mapping[str, object],
    registry: Mapping[str, object],
) -> list[str]:
    requested = request["projection_fields"]
    assert isinstance(requested, list)
    projection = requested or registry["default_projection"]
    assert isinstance(projection, list)
    field_definitions = registry["field_definitions"]
    assert isinstance(field_definitions, Mapping)
    for field in projection:
        definition = field_definitions.get(field)
        if not isinstance(definition, Mapping):
            raise SiemQueryAdapterError(
                "unknown_field",
                "SIEM query projection uses an unregistered field",
            )
        if definition["projectable"] is not True:
            raise SiemQueryAdapterError(
                "unknown_field",
                "SIEM query projection uses a non-projectable field",
            )
    if projection != registry["default_projection"]:
        raise SiemQueryAdapterError(
            "invalid_request",
            "SIEM query projection must use the registered bounded source projection",
        )
    return copy.deepcopy(projection)


def _resolve_sort(
    request: Mapping[str, object],
    registry: Mapping[str, object],
) -> list[dict[str, str]]:
    requested = request["sort"]
    assert isinstance(requested, list)
    resolved = requested or registry["default_sort"]
    assert isinstance(resolved, list)
    default_sort = registry["default_sort"]
    if resolved != default_sort:
        raise SiemQueryAdapterError(
            "invalid_request",
            "SIEM query sort must use the registered stable timestamp and alert ID order",
        )
    return copy.deepcopy(resolved)


def _validate_request_scope(
    request: Mapping[str, object],
    registry: Mapping[str, object],
) -> None:
    if request["backend"] != registry["backend"]:
        raise SiemQueryAdapterError(
            "unsupported_backend",
            "SIEM query backend does not match the registered source",
        )
    if request["source_names"] != [registry["name"]]:
        raise SiemQueryAdapterError(
            "unknown_source",
            "SIEM query source is outside this single-source adapter slice",
        )
    if request["aggregation_fields"]:
        raise SiemQueryAdapterError(
            "invalid_request",
            "SIEM query aggregations are outside this adapter slice",
        )
    if request["limit"] > registry["max_limit"]:
        raise SiemQueryAdapterError(
            "result_limit_exceeded",
            "SIEM query limit exceeds the registered maximum",
        )


def _opensearch_sort(sort: list[dict[str, str]]) -> list[dict[str, dict[str, str]]]:
    return [{item["field"]: {"order": item["direction"]}} for item in sort]


def _cursor_time(now: datetime | None) -> datetime:
    current = datetime.now(timezone.utc) if now is None else now
    if current.tzinfo is None or current.utcoffset() is None:
        raise SiemQueryAdapterError(
            "cursor_invalid",
            "Wazuh Indexer cursor is invalid or expired",
        )
    return current.astimezone(timezone.utc)


def _resolve_cursor_state(
    request: Mapping[str, object],
    registry: Mapping[str, object],
    sort: list[dict[str, str]],
    *,
    environment: Mapping[str, str] | None,
    now: datetime | None,
) -> WazuhIndexerCursor | None:
    token = request["cursor"]
    if token is None:
        return None
    assert isinstance(token, str)
    try:
        cursor = decode_wazuh_indexer_cursor(
            token,
            request,
            environment=environment,
            now=now,
        )
    except WazuhIndexerCursorError as exc:
        raise SiemQueryAdapterError(exc.category, str(exc)) from None

    validation_time = _cursor_time(now)
    expires_at = _parse_timestamp(
        cursor.expires_at,
        path="request.cursor",
        category="cursor_invalid",
    )
    transport_policy = registry["transport_policy"]
    assert isinstance(transport_policy, Mapping)
    pit_keep_alive_seconds = transport_policy["pit_keep_alive_seconds"]
    assert isinstance(pit_keep_alive_seconds, int)
    if expires_at > validation_time + timedelta(seconds=pit_keep_alive_seconds):
        raise SiemQueryAdapterError(
            "cursor_invalid",
            "Wazuh Indexer cursor is invalid or expired",
        )
    if cursor.returned_records >= registry["max_limit"]:
        raise SiemQueryAdapterError(
            "cursor_invalid",
            "Wazuh Indexer cursor is invalid or expired",
        )
    if len(cursor.search_after) != len(sort):
        raise SiemQueryAdapterError(
            "cursor_invalid",
            "Wazuh Indexer cursor is invalid or expired",
        )

    field_definitions = registry["field_definitions"]
    assert isinstance(field_definitions, Mapping)
    for position, item in enumerate(sort):
        definition = field_definitions[item["field"]]
        assert isinstance(definition, Mapping)
        value = cursor.search_after[position]
        if definition["type"] == "timestamp":
            if isinstance(value, str):
                try:
                    _parse_timestamp(value, path="request.cursor", category="cursor_invalid")
                except SiemQueryAdapterError:
                    raise SiemQueryAdapterError(
                        "cursor_invalid",
                        "Wazuh Indexer cursor is invalid or expired",
                    ) from None
            elif type(value) not in {int, float}:
                raise SiemQueryAdapterError(
                    "cursor_invalid",
                    "Wazuh Indexer cursor is invalid or expired",
                )
        elif not isinstance(value, str):
            raise SiemQueryAdapterError(
                "cursor_invalid",
                "Wazuh Indexer cursor is invalid or expired",
            )
    return cursor


def build_wazuh_indexer_query_plan(
    request: Mapping[str, object],
    *,
    registry_path: str | Path | None = None,
    cursor_environment: Mapping[str, str] | None = None,
    cursor_now: datetime | None = None,
) -> dict[str, object]:
    """Validate one request and compile a read-only Wazuh Indexer search plan."""

    if not isinstance(request, Mapping):
        raise SiemQueryAdapterError(
            "invalid_request",
            "SIEM query validation failed at request",
        )
    _validate_schema(
        request,
        schema_path=REQUEST_SCHEMA_PATH,
        root="request",
        category="invalid_request",
    )
    resolved_registry_path = _registry_path_for_request(request, registry_path)
    registry = load_source_registry(resolved_registry_path)
    _validate_request_scope(request, registry)
    _validate_time_range(request, registry)
    request_filters = _resolve_filters(request, registry)
    projection = _resolve_projection(request, registry)
    sort = _resolve_sort(request, registry)
    cursor_state = _resolve_cursor_state(
        request,
        registry,
        sort,
        environment=cursor_environment,
        now=cursor_now,
    )
    policy = registry["transport_policy"]
    assert isinstance(policy, Mapping)
    pit_keep_alive = f"{policy['pit_keep_alive_seconds']}s"

    time_range = request["time_range"]
    assert isinstance(time_range, Mapping)
    query_filters: list[dict[str, object]] = [
        {
            "range": {
                registry["time_field"]: {
                    "gte": time_range["start"],
                    "lt": time_range["end"],
                }
            }
        }
    ]
    for item in [*registry["fixed_filters"], *request_filters]:
        query_filters.append({"term": {item["field"]: item["value"]}})

    body: dict[str, object] = {
        "size": (
            request["limit"]
            if cursor_state is None
            else min(request["limit"], registry["max_limit"] - cursor_state.returned_records)
        ),
        "track_total_hits": True,
        "timeout": f"{registry['transport_policy']['read_timeout_seconds']}s",
        "_source": projection,
        "query": {"bool": {"filter": query_filters}},
        "sort": _opensearch_sort(sort),
    }
    if cursor_state is not None:
        body["search_after"] = copy.deepcopy(list(cursor_state.search_after))

    plan: dict[str, object] = {
        "method": "POST",
        "path": "/_search",
        "query_parameters": {
            "allow_partial_search_results": "false",
        },
        "connection_name": registry["connection_name"],
        "transport_policy": copy.deepcopy(policy),
        "pit_lifecycle": {
            "create_method": "POST",
            "create_path": f"/{registry['physical_source']}/_search/point_in_time",
            "create_query_parameters": {
                "keep_alive": pit_keep_alive,
                "allow_partial_pit_creation": "false",
            },
            "keep_alive": pit_keep_alive,
            "delete_method": "DELETE",
            "delete_path": "/_search/point_in_time",
        },
        "body": body,
    }
    if cursor_state is not None:
        plan["cursor_state"] = cursor_state
    return plan


def _require_mapping(value: object, *, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SiemQueryAdapterError(
            "response_parse_error",
            f"Wazuh Indexer response validation failed at {path}",
        )
    return value


def _require_integer(value: object, *, path: str) -> int:
    if type(value) is not int or value < 0:
        raise SiemQueryAdapterError(
            "response_parse_error",
            f"Wazuh Indexer response validation failed at {path}",
        )
    return value


def _source_value(source: Mapping[str, object], field: str) -> object | None:
    value: object = source
    for part in field.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def _timestamp_sort_value(
    value: object,
    *,
    source_value: object,
    path: str,
) -> float:
    if not isinstance(source_value, str):
        raise SiemQueryAdapterError(
            "response_parse_error",
            f"Wazuh Indexer response validation failed at {path}",
        )
    source_timestamp = _parse_timestamp(
        source_value,
        path=path,
        category="response_parse_error",
    )
    if isinstance(value, str):
        sort_timestamp = _parse_timestamp(
            value,
            path=path,
            category="response_parse_error",
        )
        if sort_timestamp != source_timestamp:
            raise SiemQueryAdapterError(
                "response_parse_error",
                f"Wazuh Indexer response validation failed at {path}",
            )
        return sort_timestamp.timestamp()
    if type(value) not in {int, float}:
        raise SiemQueryAdapterError(
            "response_parse_error",
            f"Wazuh Indexer response validation failed at {path}",
        )
    epoch_millis = int(source_timestamp.timestamp() * 1000)
    if value != epoch_millis:
        raise SiemQueryAdapterError(
            "response_parse_error",
            f"Wazuh Indexer response validation failed at {path}",
        )
    return source_timestamp.timestamp()


def _validated_hit_sort(
    hit_sort: object,
    *,
    source: Mapping[str, object],
    sort: list[dict[str, str]],
    field_definitions: Mapping[str, object],
    index: int,
) -> tuple[float | str, ...]:
    path = f"response.hits.hits.{index}.sort"
    if not isinstance(hit_sort, list) or len(hit_sort) != len(sort):
        raise SiemQueryAdapterError(
            "response_parse_error",
            f"Wazuh Indexer response validation failed at {path}",
        )
    normalized: list[float | str] = []
    for position, item in enumerate(sort):
        source_value = _source_value(source, item["field"])
        definition = field_definitions[item["field"]]
        assert isinstance(definition, Mapping)
        if definition["type"] == "timestamp":
            normalized.append(
                _timestamp_sort_value(
                    hit_sort[position],
                    source_value=source_value,
                    path=path,
                )
            )
        elif not isinstance(source_value, str) or hit_sort[position] != source_value:
            raise SiemQueryAdapterError(
                "response_parse_error",
                f"Wazuh Indexer response validation failed at {path}",
            )
        else:
            normalized.append(source_value)
    return tuple(normalized)


def _normalized_cursor_sort(
    cursor: WazuhIndexerCursor,
    *,
    sort: list[dict[str, str]],
    field_definitions: Mapping[str, object],
) -> tuple[float | str, ...]:
    normalized: list[float | str] = []
    for position, item in enumerate(sort):
        definition = field_definitions[item["field"]]
        assert isinstance(definition, Mapping)
        value = cursor.search_after[position]
        if definition["type"] == "timestamp":
            if isinstance(value, str):
                normalized.append(
                    _parse_timestamp(
                        value,
                        path="request.cursor",
                        category="cursor_invalid",
                    ).timestamp()
                )
            else:
                assert type(value) in {int, float}
                normalized.append(float(value) / 1000)
        else:
            assert isinstance(value, str)
            normalized.append(value)
    return tuple(normalized)


def _filter_descriptors(
    registry: Mapping[str, object],
    request: Mapping[str, object],
) -> list[dict[str, str]]:
    descriptors: list[dict[str, str]] = []
    for origin, filters in (
        ("registry", registry["fixed_filters"]),
        ("request", request["filters"]),
    ):
        assert isinstance(filters, list)
        for item in filters:
            assert isinstance(item, Mapping)
            descriptors.append(
                {
                    "field": item["field"],
                    "operator": item["operator"],
                    "value_sha256": _sha256(item["value"]),
                    "origin": origin,
                }
            )
    return descriptors


def _validate_executed_at(value: str) -> None:
    _parse_timestamp(
        value,
        path="query_provenance.executed_at",
        category="response_parse_error",
    )


def parse_wazuh_indexer_response(
    request: Mapping[str, object],
    backend_response: Mapping[str, object],
    *,
    executed_at: str,
    registry_path: str | Path | None = None,
    pit_id: str | None = None,
    cursor_environment: Mapping[str, str] | None = None,
    cursor_now: datetime | None = None,
) -> dict[str, object]:
    """Convert one complete backend page to the provider-neutral response."""

    plan = build_wazuh_indexer_query_plan(
        request,
        registry_path=registry_path,
        cursor_environment=cursor_environment,
        cursor_now=cursor_now,
    )
    resolved_registry_path = _registry_path_for_request(request, registry_path)
    registry = load_source_registry(resolved_registry_path)
    cursor_state = plan.get("cursor_state")
    if cursor_state is not None and not isinstance(cursor_state, WazuhIndexerCursor):
        raise SiemQueryAdapterError(
            "cursor_invalid",
            "Wazuh Indexer cursor is invalid or expired",
        )
    if pit_id is not None and (not isinstance(pit_id, str) or not pit_id):
        raise SiemQueryAdapterError(
            "cursor_invalid",
            "Wazuh Indexer cursor is invalid or expired",
        )
    if isinstance(cursor_state, WazuhIndexerCursor):
        if pit_id is None or pit_id != cursor_state.pit_id:
            raise SiemQueryAdapterError(
                "cursor_invalid",
                "Wazuh Indexer cursor is invalid or expired",
            )
    _validate_executed_at(executed_at)
    if not isinstance(backend_response, Mapping):
        raise SiemQueryAdapterError(
            "response_parse_error",
            "Wazuh Indexer response validation failed at response",
        )

    if backend_response.get("timed_out") is not False:
        raise SiemQueryAdapterError(
            "partial_result",
            "Wazuh Indexer response was incomplete",
        )
    shards = _require_mapping(backend_response.get("_shards"), path="response._shards")
    if _require_integer(shards.get("failed"), path="response._shards.failed") != 0:
        raise SiemQueryAdapterError(
            "partial_result",
            "Wazuh Indexer response was incomplete",
        )

    hits_container = _require_mapping(backend_response.get("hits"), path="response.hits")
    total = _require_mapping(hits_container.get("total"), path="response.hits.total")
    total_value = _require_integer(total.get("value"), path="response.hits.total.value")
    relation = total.get("relation")
    if relation not in {"eq", "gte"}:
        raise SiemQueryAdapterError(
            "response_parse_error",
            "Wazuh Indexer response validation failed at response.hits.total.relation",
        )
    raw_hits = hits_container.get("hits")
    if not isinstance(raw_hits, list):
        raise SiemQueryAdapterError(
            "response_parse_error",
            "Wazuh Indexer response validation failed at response.hits.hits",
        )
    page_size = plan["body"]["size"]
    assert isinstance(page_size, int)
    if len(raw_hits) > page_size:
        raise SiemQueryAdapterError(
            "response_parse_error",
            "Wazuh Indexer returned more records than the requested limit",
        )
    previously_returned = cursor_state.returned_records if cursor_state is not None else 0
    cumulative_returned = previously_returned + len(raw_hits)
    if relation == "eq" and total_value < cumulative_returned:
        raise SiemQueryAdapterError(
            "response_parse_error",
            "Wazuh Indexer total hit count is inconsistent",
        )

    projection = plan["body"]["_source"]
    sort = _resolve_sort(request, registry)
    field_definitions = registry["field_definitions"]
    assert isinstance(field_definitions, Mapping)
    records: list[dict[str, object]] = []
    physical_sources: set[str] = set()
    prior_sort = (
        _normalized_cursor_sort(
            cursor_state,
            sort=sort,
            field_definitions=field_definitions,
        )
        if isinstance(cursor_state, WazuhIndexerCursor)
        else None
    )
    last_search_after: list[str | int | float] | None = None
    for index, raw_hit in enumerate(raw_hits):
        hit = _require_mapping(raw_hit, path=f"response.hits.hits.{index}")
        physical_source = hit.get("_index")
        if not isinstance(physical_source, str) or not fnmatch.fnmatchcase(
            physical_source,
            registry["physical_source"],
        ):
            raise SiemQueryAdapterError(
                "response_parse_error",
                f"Wazuh Indexer response validation failed at response.hits.hits.{index}._index",
            )
        backend_record_id = hit.get("_id")
        if not isinstance(backend_record_id, str) or not backend_record_id:
            raise SiemQueryAdapterError(
                "response_parse_error",
                f"Wazuh Indexer response validation failed at response.hits.hits.{index}._id",
            )
        source = _require_mapping(
            hit.get("_source"),
            path=f"response.hits.hits.{index}._source",
        )
        event_time = _source_value(source, registry["time_field"])
        if not isinstance(event_time, str):
            raise SiemQueryAdapterError(
                "response_parse_error",
                "Wazuh Indexer response validation failed at "
                f"response.hits.hits.{index}._source.timestamp",
            )
        parsed_event_time = _parse_timestamp(
            event_time,
            path=f"response.hits.hits.{index}._source.timestamp",
            category="response_parse_error",
        )

        raw_sort = hit.get("sort")
        current_sort = _validated_hit_sort(
            raw_sort,
            source=source,
            sort=sort,
            field_definitions=field_definitions,
            index=index,
        )
        if prior_sort is not None and current_sort <= prior_sort:
            raise SiemQueryAdapterError(
                "response_parse_error",
                "Wazuh Indexer response records are not in registered stable order",
            )
        prior_sort = current_sort
        assert isinstance(raw_sort, list)
        last_search_after = copy.deepcopy(raw_sort)

        fields = {
            field: copy.deepcopy(value)
            for field in projection
            if (value := _source_value(source, field)) is not None
        }
        physical_sources.add(physical_source)
        records.append(
            {
                "logical_source": registry["name"],
                "physical_source": physical_source,
                "backend_record_id": backend_record_id,
                "event_time": _rfc3339_utc(parsed_event_time),
                "fields": fields,
                "redacted_fields": [],
                "raw_payload_available": False,
            }
        )

    max_limit = registry["max_limit"]
    assert isinstance(max_limit, int)
    if cumulative_returned > max_limit:
        raise SiemQueryAdapterError(
            "response_parse_error",
            "Wazuh Indexer cumulative result count exceeded the registered maximum",
        )
    exact_more_results = relation == "eq" and total_value > cumulative_returned
    if exact_more_results and not records:
        raise SiemQueryAdapterError(
            "response_parse_error",
            "Wazuh Indexer response made no progress toward the exact total",
        )

    next_cursor: str | None = None
    if (
        exact_more_results
        and cumulative_returned < max_limit
        and pit_id is not None
        and last_search_after is not None
    ):
        validation_time = _cursor_time(cursor_now)
        policy = registry["transport_policy"]
        assert isinstance(policy, Mapping)
        keep_alive_seconds = policy["pit_keep_alive_seconds"]
        assert isinstance(keep_alive_seconds, int)
        try:
            next_cursor = encode_wazuh_indexer_cursor(
                request,
                pit_id=pit_id,
                search_after=last_search_after,
                returned_records=cumulative_returned,
                expires_at=_rfc3339_utc(validation_time + timedelta(seconds=keep_alive_seconds)),
                environment=cursor_environment,
                now=validation_time,
            )
        except WazuhIndexerCursorError as exc:
            raise SiemQueryAdapterError(exc.category, str(exc)) from None

    truncated = relation == "gte" or exact_more_results
    refinement_required = truncated and next_cursor is None
    if next_cursor is not None:
        warnings = ["additional_results_available"]
    elif refinement_required:
        warnings = ["result_volume_requires_refinement"]
    else:
        warnings = []
    response = {
        "contract_version": "1.0",
        "request_id": request["request_id"],
        "backend": registry["backend"],
        "queried_sources": [
            {
                "logical_name": registry["name"],
                "physical_sources": sorted(physical_sources),
            }
        ],
        "executed_time_range": {
            "start": request["time_range"]["start"],
            "end": request["time_range"]["end"],
            "time_field": registry["time_field"],
        },
        "total_hits": total_value,
        "total_hits_relation": relation,
        "returned_records": len(records),
        "truncated": truncated,
        "refinement_required": refinement_required,
        "partial": False,
        "source_statuses": [
            {
                "logical_name": registry["name"],
                "status": "complete",
                "error_category": None,
            }
        ],
        "warnings": warnings,
        "records": records,
        "aggregations": [],
        "next_cursor": next_cursor,
        "query_provenance": {
            "executed_at": executed_at,
            "adapter_name": registry["adapter_name"],
            "adapter_version": registry["adapter_version"],
            "connection_name": registry["connection_name"],
            "request_fingerprint": _request_fingerprint(request),
            "filter_descriptors": _filter_descriptors(registry, request),
            "projection_fields": copy.deepcopy(projection),
            "sort": sort,
            "limit": request["limit"],
            "pagination_mode": (
                PIT_PAGINATION_MODE if pit_id is not None else REFINEMENT_PAGINATION_MODE
            ),
        },
    }
    _validate_schema(
        response,
        schema_path=RESPONSE_SCHEMA_PATH,
        root="response",
        category="response_parse_error",
    )
    return response
