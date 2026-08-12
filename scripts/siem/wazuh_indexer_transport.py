from __future__ import annotations

import copy
import json
import os
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.auth import HTTPBasicAuth
from wazuh_indexer_cursor import WazuhIndexerCursor
from wazuh_indexer_query_adapter import (
    build_wazuh_indexer_query_plan,
    parse_wazuh_indexer_response,
)

SUPPORTED_CONNECTION = "wazuh_indexer_readonly"
ENV_PREFIX = "WAZUH_INDEXER_READONLY_"


class SiemTransportError(ValueError):
    """Stable transport failure that never includes runtime connection values."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


@dataclass(frozen=True, repr=False)
class WazuhIndexerConnection:
    base_url: str = field(repr=False)
    username: str = field(repr=False)
    password: str = field(repr=False)
    verify: bool | str = field(repr=False)

    def __repr__(self) -> str:
        return "WazuhIndexerConnection(<redacted>)"


class ResponseLike(Protocol):
    status_code: int
    headers: Mapping[str, str]

    def iter_content(self, chunk_size: int) -> Iterator[bytes]: ...

    def close(self) -> None: ...


class SessionLike(Protocol):
    def request(self, method: str, url: str, **kwargs: object) -> ResponseLike: ...


def _required_environment_value(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if not isinstance(value, str) or not value:
        raise SiemTransportError(
            "connection_config_error",
            "Wazuh Indexer runtime connection configuration is incomplete",
        )
    return value


def _validated_base_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise SiemTransportError(
            "connection_config_error",
            "Wazuh Indexer runtime base URL is invalid",
        ) from None
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise SiemTransportError(
            "connection_config_error",
            "Wazuh Indexer runtime base URL must be an HTTPS origin",
        )
    hostname = parsed.hostname
    assert hostname is not None
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = hostname if port is None else f"{hostname}:{port}"
    return urlunsplit(("https", netloc, "", "", ""))


def resolve_wazuh_indexer_connection(
    connection_name: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> WazuhIndexerConnection:
    """Resolve the one reviewed connection from runtime-only environment values."""

    if connection_name != SUPPORTED_CONNECTION:
        raise SiemTransportError(
            "connection_config_error",
            "Wazuh Indexer query plan selected an unsupported connection",
        )
    values = os.environ if environment is None else environment
    base_url = _validated_base_url(_required_environment_value(values, f"{ENV_PREFIX}URL"))
    username = _required_environment_value(values, f"{ENV_PREFIX}USERNAME").strip()
    password = _required_environment_value(values, f"{ENV_PREFIX}PASSWORD")
    if not username:
        raise SiemTransportError(
            "connection_config_error",
            "Wazuh Indexer runtime connection configuration is incomplete",
        )

    ca_bundle = values.get(f"{ENV_PREFIX}CA_BUNDLE")
    verify: bool | str = True
    if ca_bundle:
        ca_path = Path(ca_bundle)
        if not ca_path.is_file():
            raise SiemTransportError(
                "connection_config_error",
                "Wazuh Indexer CA bundle could not be loaded",
            )
        verify = str(ca_path)
    return WazuhIndexerConnection(
        base_url=base_url,
        username=username,
        password=password,
        verify=verify,
    )


def _executed_at_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _response_json(response: ResponseLike, *, max_response_bytes: int) -> Mapping[str, object]:
    content_type = response.headers.get("Content-Type", "").lower()
    if "application/json" not in content_type:
        raise SiemTransportError(
            "response_parse_error",
            "Wazuh Indexer response did not use the required JSON media type",
        )
    chunks: list[bytes] = []
    received_bytes = 0
    try:
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            received_bytes += len(chunk)
            if received_bytes > max_response_bytes:
                raise SiemTransportError(
                    "response_too_large",
                    "Wazuh Indexer response exceeded the registered byte limit",
                )
            chunks.append(chunk)
    except requests.exceptions.RequestException:
        raise SiemTransportError(
            "transport_failed",
            "Wazuh Indexer response transport failed",
        ) from None
    content = b"".join(chunks)
    try:
        loaded = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SiemTransportError(
            "response_parse_error",
            "Wazuh Indexer response was not valid UTF-8 JSON",
        ) from None
    if not isinstance(loaded, Mapping):
        raise SiemTransportError(
            "response_parse_error",
            "Wazuh Indexer response JSON was not an object",
        )
    return loaded


def _raise_for_status(status_code: int) -> None:
    if status_code == 200:
        return
    if status_code == 401:
        category = "authentication_failed"
    elif status_code == 403:
        category = "authorization_failed"
    elif 400 <= status_code < 500:
        category = "backend_request_failed"
    else:
        category = "backend_unavailable"
    raise SiemTransportError(category, "Wazuh Indexer request failed")


def _request_json(
    session: SessionLike,
    connection: WazuhIndexerConnection,
    policy: Mapping[str, object],
    *,
    method: str,
    path: str,
    query_parameters: Mapping[str, object] | None,
    body: Mapping[str, object] | None,
) -> Mapping[str, object]:
    try:
        response = session.request(
            method,
            f"{connection.base_url}{path}",
            params=query_parameters,
            json=body,
            auth=HTTPBasicAuth(connection.username, connection.password),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            verify=connection.verify,
            timeout=(
                policy["connect_timeout_seconds"],
                policy["read_timeout_seconds"],
            ),
            allow_redirects=False,
            stream=True,
        )
    except requests.exceptions.SSLError:
        raise SiemTransportError(
            "tls_verification_failed",
            "Wazuh Indexer TLS verification failed",
        ) from None
    except requests.exceptions.Timeout:
        raise SiemTransportError(
            "transport_timeout",
            "Wazuh Indexer request timed out",
        ) from None
    except requests.exceptions.ConnectionError:
        raise SiemTransportError(
            "connection_failed",
            "Wazuh Indexer connection failed",
        ) from None
    except requests.exceptions.RequestException:
        raise SiemTransportError(
            "transport_failed",
            "Wazuh Indexer transport failed",
        ) from None

    try:
        _raise_for_status(response.status_code)
        return _response_json(
            response,
            max_response_bytes=int(policy["max_response_bytes"]),
        )
    finally:
        response.close()


def _pit_id(create_response: Mapping[str, object]) -> str:
    value = create_response.get("pit_id")
    if not isinstance(value, str) or not value:
        raise SiemTransportError(
            "response_parse_error",
            "Wazuh Indexer PIT creation response was invalid",
        )
    return value


def _validate_pit_creation(create_response: Mapping[str, object]) -> None:
    shards = create_response.get("_shards")
    if not isinstance(shards, Mapping):
        raise SiemTransportError(
            "response_parse_error",
            "Wazuh Indexer PIT creation response was invalid",
        )
    total = shards.get("total")
    successful = shards.get("successful")
    failed = shards.get("failed")
    if (
        type(total) is not int
        or type(successful) is not int
        or type(failed) is not int
        or total < 1
        or successful < 0
        or failed < 0
        or successful + failed > total
    ):
        raise SiemTransportError(
            "response_parse_error",
            "Wazuh Indexer PIT creation response was invalid",
        )
    if failed != 0 or successful != total:
        raise SiemTransportError(
            "pit_creation_failed",
            "Wazuh Indexer PIT creation was incomplete",
        )


def _validate_pit_cleanup(cleanup_response: Mapping[str, object], *, pit_id: str) -> None:
    pits = cleanup_response.get("pits")
    if not isinstance(pits, list) or len(pits) != 1:
        raise SiemTransportError(
            "pit_cleanup_failed",
            "Wazuh Indexer PIT cleanup was not confirmed",
        )
    result = pits[0]
    if (
        not isinstance(result, Mapping)
        or result.get("successful") is not True
        or result.get("pit_id") != pit_id
    ):
        raise SiemTransportError(
            "pit_cleanup_failed",
            "Wazuh Indexer PIT cleanup was not confirmed",
        )


def execute_wazuh_indexer_query(
    request: Mapping[str, object],
    *,
    environment: Mapping[str, str] | None = None,
    session: SessionLike | None = None,
    executed_at_factory: Callable[[], str] = _executed_at_now,
    registry_path: str | Path | None = None,
    cursor_now: datetime | None = None,
) -> dict[str, object]:
    """Execute one bounded query plan and return its provider-neutral response."""

    cursor_operation_time = datetime.now(timezone.utc) if cursor_now is None else cursor_now
    plan = build_wazuh_indexer_query_plan(
        request,
        registry_path=registry_path,
        cursor_environment=environment,
        cursor_now=cursor_operation_time,
    )
    cursor_state = plan.get("cursor_state")
    if cursor_state is not None and not isinstance(cursor_state, WazuhIndexerCursor):
        raise SiemTransportError(
            "transport_policy_error",
            "Wazuh Indexer query plan contained an invalid cursor state",
        )
    policy = plan["transport_policy"]
    assert isinstance(policy, Mapping)
    pit_lifecycle = plan.get("pit_lifecycle")
    if not isinstance(pit_lifecycle, Mapping):
        raise SiemTransportError(
            "transport_policy_error",
            "Wazuh Indexer query plan omitted the registered PIT lifecycle",
        )
    if (
        plan["method"] != "POST"
        or plan["path"] != "/_search"
        or policy.get("read_only") is not True
        or policy.get("tls_verify") is not True
        or pit_lifecycle.get("create_method") != "POST"
        or pit_lifecycle.get("delete_method") != "DELETE"
    ):
        raise SiemTransportError(
            "transport_policy_error",
            "Wazuh Indexer query plan violated the registered transport policy",
        )
    connection = resolve_wazuh_indexer_connection(
        str(plan["connection_name"]),
        environment=environment,
    )
    owned_session = session is None
    active_session: SessionLike
    if session is None:
        created_session = requests.Session()
        created_session.trust_env = False
        active_session = created_session
    else:
        active_session = session

    try:
        primary_error: Exception | None = None
        result: dict[str, object] | None = None
        if isinstance(cursor_state, WazuhIndexerCursor):
            pit_id = cursor_state.pit_id
        else:
            create_response = _request_json(
                active_session,
                connection,
                policy,
                method=str(pit_lifecycle["create_method"]),
                path=str(pit_lifecycle["create_path"]),
                query_parameters=pit_lifecycle["create_query_parameters"],
                body=None,
            )
            pit_id = _pit_id(create_response)
            try:
                _validate_pit_creation(create_response)
            except Exception as exc:
                primary_error = exc

        if primary_error is None:
            try:
                search_body = copy.deepcopy(plan["body"])
                assert isinstance(search_body, dict)
                search_body["pit"] = {
                    "id": pit_id,
                    "keep_alive": pit_lifecycle["keep_alive"],
                }
                backend_response = _request_json(
                    active_session,
                    connection,
                    policy,
                    method=str(plan["method"]),
                    path=str(plan["path"]),
                    query_parameters=plan["query_parameters"],
                    body=search_body,
                )
                result = parse_wazuh_indexer_response(
                    request,
                    backend_response,
                    executed_at=executed_at_factory(),
                    registry_path=registry_path,
                    pit_id=pit_id,
                    cursor_environment=environment,
                    cursor_now=cursor_operation_time,
                )
            except Exception as exc:
                primary_error = exc

        cleanup_required = (
            primary_error is not None or result is None or result.get("next_cursor") is None
        )
        if cleanup_required:
            try:
                cleanup_response = _request_json(
                    active_session,
                    connection,
                    policy,
                    method=str(pit_lifecycle["delete_method"]),
                    path=str(pit_lifecycle["delete_path"]),
                    query_parameters=None,
                    body={"pit_id": [pit_id]},
                )
                _validate_pit_cleanup(cleanup_response, pit_id=pit_id)
            except Exception:
                if primary_error is None:
                    raise
                primary_error.add_note("Wazuh Indexer PIT cleanup also failed")

        if primary_error is not None:
            raise primary_error
        assert result is not None
        return result
    finally:
        if owned_session and isinstance(active_session, requests.Session):
            active_session.close()
