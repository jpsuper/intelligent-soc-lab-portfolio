import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import requests
from cryptography.fernet import Fernet

MODULE_DIR = Path(__file__).resolve().parents[1] / "scripts" / "siem"
sys.path.insert(0, str(MODULE_DIR))

from wazuh_indexer_cursor import (  # noqa: E402
    CURSOR_KEY_ENV,
    decode_wazuh_indexer_cursor,
    encode_wazuh_indexer_cursor,
)
from wazuh_indexer_query_adapter import SiemQueryAdapterError  # noqa: E402
from wazuh_indexer_transport import (  # noqa: E402
    SiemTransportError,
    execute_wazuh_indexer_query,
    resolve_wazuh_indexer_connection,
)

REQUEST_PATH = Path("tests/fixtures/siem/wazuh_alerts_sysmon_event1/query_request.json")
AUTH_REQUEST_PATH = Path(
    "tests/fixtures/siem/wazuh_alerts_windows_security_auth/query_request.json"
)
WAZUH_FIXTURE_PATH = Path(
    "tests/fixtures/windows/sysmon_event1/wazuh_indexer/sysmon-event1-ordinary-powershell-001.json"
)
AUTH_WAZUH_FIXTURE_PATH = Path(
    "tests/fixtures/windows/security_auth/wazuh_indexer/"
    "windows-security-4625-network-logon-failure-001.json"
)
EXECUTED_AT = "2026-01-15T01:06:00Z"
SECRET_VALUES = ("readonly-user", "super-secret-password", "https://indexer.internal:9200")
PIT_ID = "private-pit-id"
CURSOR_NOW = datetime(2026, 1, 15, 1, 6, tzinfo=timezone.utc)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def request() -> dict:
    value = load_json(REQUEST_PATH)
    value["limit"] = 1
    return value


def backend_response(
    *,
    alert_id: str = "wazuh-alert-001",
    timestamp: str | None = None,
    total: int = 1,
) -> dict:
    hit = copy.deepcopy(load_json(WAZUH_FIXTURE_PATH)["hit"])
    if timestamp is not None:
        hit["_source"]["timestamp"] = timestamp
    hit["_source"]["id"] = alert_id
    hit["sort"] = [hit["_source"]["timestamp"], hit["_source"]["id"]]
    return {
        "took": 3,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": total, "relation": "eq"},
            "max_score": None,
            "hits": [hit],
        },
    }


def auth_backend_response() -> dict:
    hit = copy.deepcopy(load_json(AUTH_WAZUH_FIXTURE_PATH)["hit"])
    hit["_source"]["id"] = "wazuh-auth-alert-001"
    hit["sort"] = [hit["_source"]["timestamp"], hit["_source"]["id"]]
    return {
        "took": 3,
        "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {
            "total": {"value": 1, "relation": "eq"},
            "max_score": None,
            "hits": [hit],
        },
    }


def pit_create_response(*, failed_shards: int = 0) -> dict:
    return {
        "pit_id": PIT_ID,
        "_shards": {
            "total": 1,
            "successful": 1 - failed_shards,
            "skipped": 0,
            "failed": failed_shards,
        },
        "creation_time": 1768439160000,
    }


def pit_cleanup_response(*, successful: bool = True) -> dict:
    return {"pits": [{"successful": successful, "pit_id": PIT_ID}]}


def environment(ca_bundle: Path | None = None) -> dict[str, str]:
    values = {
        "WAZUH_INDEXER_READONLY_URL": SECRET_VALUES[2],
        "WAZUH_INDEXER_READONLY_USERNAME": SECRET_VALUES[0],
        "WAZUH_INDEXER_READONLY_PASSWORD": SECRET_VALUES[1],
    }
    if ca_bundle is not None:
        values["WAZUH_INDEXER_READONLY_CA_BUNDLE"] = str(ca_bundle)
    return values


class FakeResponse:
    def __init__(
        self,
        body: object,
        *,
        status_code: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.status_code = status_code
        self.headers = {"Content-Type": content_type}
        self.content = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.closed = False

    def iter_content(self, chunk_size: int):
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset : offset + chunk_size]

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(
        self, responses: FakeResponse | Exception | list[FakeResponse | Exception]
    ) -> None:
        self.responses = list(responses) if isinstance(responses, list) else [responses]
        self.returned_responses: list[FakeResponse] = []
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def request(self, method: str, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        if not self.responses:
            raise AssertionError("unexpected Wazuh Indexer request")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        self.returned_responses.append(response)
        return response


class StreamingFailureResponse(FakeResponse):
    def iter_content(self, chunk_size: int):
        del chunk_size
        raise requests.exceptions.ChunkedEncodingError("private streaming detail")
        yield b""  # pragma: no cover


def execute(fake_session: FakeSession, *, values: dict[str, str] | None = None) -> dict:
    return execute_wazuh_indexer_query(
        request(),
        environment=environment() if values is None else values,
        session=fake_session,
        executed_at_factory=lambda: EXECUTED_AT,
    )


def lifecycle_session(search_response: FakeResponse | Exception | None = None) -> FakeSession:
    return FakeSession(
        [
            FakeResponse(pit_create_response()),
            search_response or FakeResponse(backend_response()),
            FakeResponse(pit_cleanup_response()),
        ]
    )


def test_transport_keeps_first_pit_and_resumes_it_until_final_page() -> None:
    values = environment()
    values[CURSOR_KEY_ENV] = Fernet.generate_key().decode("ascii")
    first_session = FakeSession(
        [
            FakeResponse(pit_create_response()),
            FakeResponse(backend_response(total=2)),
        ]
    )

    first_result = execute_wazuh_indexer_query(
        request(),
        environment=values,
        session=first_session,
        executed_at_factory=lambda: EXECUTED_AT,
        cursor_now=CURSOR_NOW,
    )
    token = first_result["next_cursor"]
    assert isinstance(token, str)
    decoded = decode_wazuh_indexer_cursor(
        token,
        request(),
        environment=values,
        now=CURSOR_NOW,
    )
    assert decoded.pit_id == PIT_ID
    assert decoded.expires_at == "2026-01-15T01:06:30Z"
    assert PIT_ID not in token
    assert [call[0] for call in first_session.calls] == ["POST", "POST"]
    first_search_body = first_session.calls[1][2]["json"]
    assert "search_after" not in first_search_body
    assert first_search_body["pit"] == {"id": PIT_ID, "keep_alive": "30s"}

    resumed_request = request()
    resumed_request["cursor"] = token
    final_response = backend_response(
        alert_id="wazuh-alert-002",
        timestamp="2026-01-15T01:03:04.125Z",
        total=2,
    )
    resumed_session = FakeSession(
        [
            FakeResponse(final_response),
            FakeResponse(pit_cleanup_response()),
        ]
    )

    final_result = execute_wazuh_indexer_query(
        resumed_request,
        environment=values,
        session=resumed_session,
        executed_at_factory=lambda: EXECUTED_AT,
        cursor_now=CURSOR_NOW,
    )

    assert final_result["next_cursor"] is None
    assert final_result["truncated"] is False
    assert [call[0] for call in resumed_session.calls] == ["POST", "DELETE"]
    resumed_search_body = resumed_session.calls[0][2]["json"]
    assert resumed_search_body["pit"] == {"id": PIT_ID, "keep_alive": "30s"}
    assert resumed_search_body["search_after"] == backend_response()["hits"]["hits"][0]["sort"]
    assert resumed_session.calls[1][2]["json"] == {"pit_id": [PIT_ID]}


def test_resumed_search_failure_deletes_existing_pit() -> None:
    values = environment()
    values[CURSOR_KEY_ENV] = Fernet.generate_key().decode("ascii")
    query = request()
    token = encode_wazuh_indexer_cursor(
        query,
        pit_id=PIT_ID,
        search_after=["2026-01-15T01:02:04.125Z", "wazuh-alert-001"],
        returned_records=1,
        expires_at="2026-01-15T01:06:30Z",
        environment=values,
        now=CURSOR_NOW,
    )
    query["cursor"] = token
    session = FakeSession(
        [
            requests.exceptions.Timeout("private resumed search detail"),
            FakeResponse(pit_cleanup_response()),
        ]
    )

    with pytest.raises(SiemTransportError) as exc_info:
        execute_wazuh_indexer_query(
            query,
            environment=values,
            session=session,
            executed_at_factory=lambda: EXECUTED_AT,
            cursor_now=CURSOR_NOW,
        )

    assert exc_info.value.category == "transport_timeout"
    assert [call[0] for call in session.calls] == ["POST", "DELETE"]
    assert session.calls[1][2]["json"] == {"pit_id": [PIT_ID]}
    assert PIT_ID not in str(exc_info.value)
    assert token not in str(exc_info.value)


def test_cursor_issuance_failure_deletes_new_pit() -> None:
    session = FakeSession(
        [
            FakeResponse(pit_create_response()),
            FakeResponse(backend_response(total=2)),
            FakeResponse(pit_cleanup_response()),
        ]
    )

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        execute_wazuh_indexer_query(
            request(),
            environment=environment(),
            session=session,
            executed_at_factory=lambda: EXECUTED_AT,
            cursor_now=CURSOR_NOW,
        )

    assert exc_info.value.category == "cursor_config_error"
    assert [call[0] for call in session.calls] == ["POST", "POST", "DELETE"]
    assert session.calls[2][2]["json"] == {"pit_id": [PIT_ID]}


def test_runtime_connection_is_https_only_redacted_and_ca_verifying(tmp_path: Path) -> None:
    ca_bundle = tmp_path / "root-ca.pem"
    ca_bundle.write_text("synthetic test CA", encoding="utf-8")

    connection = resolve_wazuh_indexer_connection(
        "wazuh_indexer_readonly",
        environment=environment(ca_bundle),
    )

    assert connection.base_url == SECRET_VALUES[2]
    assert connection.verify == str(ca_bundle)
    assert repr(connection) == "WazuhIndexerConnection(<redacted>)"
    assert all(secret not in repr(connection) for secret in SECRET_VALUES)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda values: values.pop("WAZUH_INDEXER_READONLY_PASSWORD"),
        lambda values: values.update(WAZUH_INDEXER_READONLY_USERNAME=" "),
        lambda values: values.update(WAZUH_INDEXER_READONLY_URL="http://indexer:9200"),
        lambda values: values.update(WAZUH_INDEXER_READONLY_URL="https://user:pass@indexer:9200"),
        lambda values: values.update(WAZUH_INDEXER_READONLY_URL="https://indexer:9200/path"),
        lambda values: values.update(WAZUH_INDEXER_READONLY_CA_BUNDLE="/missing/ca.pem"),
    ],
)
def test_invalid_runtime_connection_fails_closed_without_disclosure(mutation) -> None:
    values = environment()
    mutation(values)

    with pytest.raises(SiemTransportError) as exc_info:
        resolve_wazuh_indexer_connection(
            "wazuh_indexer_readonly",
            environment=values,
        )

    assert exc_info.value.category == "connection_config_error"
    assert all(secret not in str(exc_info.value) for secret in SECRET_VALUES)


def test_transport_executes_exact_registered_read_only_plan() -> None:
    session = lifecycle_session()

    result = execute(session)

    assert result["returned_records"] == 1
    assert result["query_provenance"]["executed_at"] == EXECUTED_AT
    assert len(session.calls) == 3
    create_method, create_url, create_kwargs = session.calls[0]
    assert create_method == "POST"
    assert create_url == f"{SECRET_VALUES[2]}/wazuh-alerts-*/_search/point_in_time"
    assert create_kwargs["params"] == {
        "keep_alive": "30s",
        "allow_partial_pit_creation": "false",
    }
    assert create_kwargs["json"] is None

    search_method, search_url, search_kwargs = session.calls[1]
    assert search_method == "POST"
    assert search_url == f"{SECRET_VALUES[2]}/_search"
    assert search_kwargs["params"] == {"allow_partial_search_results": "false"}
    assert search_kwargs["json"]["pit"] == {"id": PIT_ID, "keep_alive": "30s"}

    delete_method, delete_url, delete_kwargs = session.calls[2]
    assert delete_method == "DELETE"
    assert delete_url == f"{SECRET_VALUES[2]}/_search/point_in_time"
    assert delete_kwargs["params"] is None
    assert delete_kwargs["json"] == {"pit_id": [PIT_ID]}

    for _, _, kwargs in session.calls:
        assert kwargs["timeout"] == (3, 10)
        assert kwargs["verify"] is True
        assert kwargs["allow_redirects"] is False
        assert kwargs["stream"] is True
        assert kwargs["headers"] == {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        auth = kwargs["auth"]
        assert auth.username == SECRET_VALUES[0]
        assert auth.password == SECRET_VALUES[1]
    assert all(response.closed for response in session.returned_responses)


def test_transport_query_parameters_use_opensearch_boolean_spelling() -> None:
    session = lifecycle_session()

    execute(session)

    _, _, create_kwargs = session.calls[0]
    prepared_create = requests.Request(
        "POST",
        "https://indexer.invalid",
        params=create_kwargs["params"],
    ).prepare()
    assert prepared_create.url == (
        "https://indexer.invalid/?keep_alive=30s&allow_partial_pit_creation=false"
    )
    _, _, search_kwargs = session.calls[1]
    prepared_search = requests.Request(
        "POST",
        "https://indexer.invalid",
        params=search_kwargs["params"],
    ).prepare()
    assert prepared_search.url == ("https://indexer.invalid/?allow_partial_search_results=false")


@pytest.mark.parametrize(
    ("failure", "category"),
    [
        (requests.exceptions.SSLError("contains secret"), "tls_verification_failed"),
        (requests.exceptions.Timeout("contains secret"), "transport_timeout"),
        (requests.exceptions.ConnectionError("contains secret"), "connection_failed"),
        (requests.exceptions.RequestException("contains secret"), "transport_failed"),
    ],
)
def test_request_failures_use_stable_categories_without_backend_text(
    failure: Exception,
    category: str,
) -> None:
    with pytest.raises(SiemTransportError) as exc_info:
        execute(FakeSession(failure))

    assert exc_info.value.category == category
    assert "contains secret" not in str(exc_info.value)
    assert all(secret not in str(exc_info.value) for secret in SECRET_VALUES)


@pytest.mark.parametrize(
    ("status_code", "category"),
    [
        (401, "authentication_failed"),
        (403, "authorization_failed"),
        (400, "backend_request_failed"),
        (429, "backend_request_failed"),
        (500, "backend_unavailable"),
    ],
)
def test_http_failures_do_not_parse_or_disclose_backend_body(
    status_code: int,
    category: str,
) -> None:
    response = FakeResponse({"error": "private backend detail"}, status_code=status_code)

    with pytest.raises(SiemTransportError) as exc_info:
        execute(FakeSession(response))

    assert exc_info.value.category == category
    assert "private backend detail" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("response", "category"),
    [
        (FakeResponse(b"not-json"), "response_parse_error"),
        (FakeResponse([], content_type="application/json"), "response_parse_error"),
        (FakeResponse({}, content_type="text/html"), "response_parse_error"),
        (FakeResponse(b"x" * (5 * 1024 * 1024 + 1)), "response_too_large"),
    ],
)
def test_response_envelope_fails_closed(response: FakeResponse, category: str) -> None:
    with pytest.raises(SiemTransportError) as exc_info:
        execute(FakeSession(response))

    assert exc_info.value.category == category


def test_streaming_failure_is_safe_and_closes_response() -> None:
    response = StreamingFailureResponse(backend_response())

    with pytest.raises(SiemTransportError) as exc_info:
        execute(FakeSession(response))

    assert exc_info.value.category == "transport_failed"
    assert "private streaming detail" not in str(exc_info.value)
    assert response.closed is True


def test_partial_backend_response_remains_an_adapter_failure() -> None:
    backend = backend_response()
    backend["timed_out"] = True

    with pytest.raises(SiemQueryAdapterError) as exc_info:
        execute(lifecycle_session(FakeResponse(backend)))

    assert exc_info.value.category == "partial_result"


def test_search_failure_still_deletes_the_created_pit() -> None:
    session = lifecycle_session(requests.exceptions.Timeout("private search detail"))

    with pytest.raises(SiemTransportError) as exc_info:
        execute(session)

    assert exc_info.value.category == "transport_timeout"
    assert [call[0] for call in session.calls] == ["POST", "POST", "DELETE"]
    assert session.calls[2][2]["json"] == {"pit_id": [PIT_ID]}


def test_partial_pit_creation_fails_closed_and_still_attempts_cleanup() -> None:
    session = FakeSession(
        [
            FakeResponse(pit_create_response(failed_shards=1)),
            FakeResponse(pit_cleanup_response()),
        ]
    )

    with pytest.raises(SiemTransportError) as exc_info:
        execute(session)

    assert exc_info.value.category == "pit_creation_failed"
    assert [call[0] for call in session.calls] == ["POST", "DELETE"]


def test_unconfirmed_pit_cleanup_fails_closed_without_disclosing_pit_id() -> None:
    session = FakeSession(
        [
            FakeResponse(pit_create_response()),
            FakeResponse(backend_response()),
            FakeResponse(pit_cleanup_response(successful=False)),
        ]
    )

    with pytest.raises(SiemTransportError) as exc_info:
        execute(session)

    assert exc_info.value.category == "pit_cleanup_failed"
    assert PIT_ID not in str(exc_info.value)


def test_transport_auto_selects_windows_security_auth_registry() -> None:
    session = FakeSession(
        [
            FakeResponse(pit_create_response()),
            FakeResponse(auth_backend_response()),
            FakeResponse(pit_cleanup_response()),
        ]
    )

    result = execute_wazuh_indexer_query(
        load_json(AUTH_REQUEST_PATH),
        environment=environment(),
        session=session,
        executed_at_factory=lambda: EXECUTED_AT,
    )

    assert result["returned_records"] == 1
    assert result["queried_sources"] == [
        {
            "logical_name": "wazuh-alerts-windows-security-auth",
            "physical_sources": ["wazuh-alerts-4.x-2026.01.15"],
        }
    ]
    assert [call[0] for call in session.calls] == ["POST", "POST", "DELETE"]
    search_body = session.calls[1][2]["json"]
    assert {"term": {"data.win.system.eventID": "4625"}} in (search_body["query"]["bool"]["filter"])
