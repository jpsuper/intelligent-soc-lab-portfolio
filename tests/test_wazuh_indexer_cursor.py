import copy
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

MODULE_DIR = Path(__file__).resolve().parents[1] / "scripts" / "siem"
sys.path.insert(0, str(MODULE_DIR))

from wazuh_indexer_cursor import (  # noqa: E402
    CURSOR_KEY_ENV,
    MAX_CURSOR_LENGTH,
    MAX_PIT_ID_LENGTH,
    WazuhIndexerCursorError,
    decode_wazuh_indexer_cursor,
    encode_wazuh_indexer_cursor,
)

REQUEST_PATH = Path("tests/fixtures/siem/wazuh_alerts_sysmon_event1/query_request.json")
NOW = datetime(2026, 8, 10, 22, 15, 34, tzinfo=timezone.utc)
EXPIRES_AT = "2026-08-10T22:16:04Z"
PIT_ID = "private-pit-id-with-resolved-index-data"
SEARCH_AFTER = ["2026-08-10T22:15:34.804Z", "wazuh-alert-014"]


def request() -> dict:
    return json.loads(REQUEST_PATH.read_text(encoding="utf-8"))


def environment() -> dict[str, str]:
    return {CURSOR_KEY_ENV: Fernet.generate_key().decode("ascii")}


def encode(values: dict[str, str], query: dict | None = None, **overrides: object) -> str:
    arguments = {
        "pit_id": PIT_ID,
        "search_after": SEARCH_AFTER,
        "returned_records": 14,
        "expires_at": EXPIRES_AT,
        "environment": values,
        "now": NOW,
    }
    arguments.update(overrides)
    return encode_wazuh_indexer_cursor(query or request(), **arguments)


def test_cursor_round_trip_is_request_bound_and_redacted() -> None:
    values = environment()
    query = request()
    original = copy.deepcopy(query)

    token = encode(values, query)
    decoded = decode_wazuh_indexer_cursor(token, query, environment=values, now=NOW)

    assert decoded.pit_id == PIT_ID
    assert decoded.search_after == tuple(SEARCH_AFTER)
    assert decoded.returned_records == 14
    assert decoded.expires_at == EXPIRES_AT
    assert PIT_ID not in token
    assert PIT_ID not in repr(decoded)
    assert SEARCH_AFTER[1] not in repr(decoded)
    assert query == original


def test_cursor_round_trip_accepts_bounded_multi_shard_pit_id() -> None:
    values = environment()
    pit_id = "p" * (64 * 1024)

    token = encode(values, pit_id=pit_id)
    decoded = decode_wazuh_indexer_cursor(
        token,
        request(),
        environment=values,
        now=NOW,
    )

    assert len(token) > 8192
    assert len(token) <= MAX_CURSOR_LENGTH
    assert decoded.pit_id == pit_id
    assert pit_id not in token
    assert pit_id not in repr(decoded)


def test_cursor_rejects_pit_id_above_reviewed_capacity_without_disclosure() -> None:
    pit_id = "p" * (MAX_PIT_ID_LENGTH + 1)

    with pytest.raises(WazuhIndexerCursorError) as exc_info:
        encode(environment(), pit_id=pit_id)

    assert exc_info.value.category == "cursor_invalid"
    assert pit_id not in str(exc_info.value)


def test_cursor_fingerprint_ignores_only_the_cursor_value() -> None:
    values = environment()
    query = request()
    token = encode(values, query)
    continued_query = copy.deepcopy(query)
    continued_query["cursor"] = token

    decoded = decode_wazuh_indexer_cursor(
        token,
        continued_query,
        environment=values,
        now=NOW,
    )

    assert decoded.pit_id == PIT_ID


@pytest.mark.parametrize(
    "mutation",
    [
        lambda token: f"{token[:-1]}{'A' if token[-1] != 'A' else 'B'}",
        lambda token: token[:20],
        lambda token: "not-a-cursor",
    ],
)
def test_tampered_or_malformed_cursor_fails_closed(mutation) -> None:
    values = environment()
    token = mutation(encode(values))

    with pytest.raises(WazuhIndexerCursorError) as exc_info:
        decode_wazuh_indexer_cursor(token, request(), environment=values, now=NOW)

    assert exc_info.value.category == "cursor_invalid"
    assert PIT_ID not in str(exc_info.value)
    assert token not in str(exc_info.value)


def test_cursor_cannot_be_reused_for_a_different_request() -> None:
    values = environment()
    token = encode(values)
    changed_request = request()
    changed_request["limit"] = 1

    with pytest.raises(WazuhIndexerCursorError) as exc_info:
        decode_wazuh_indexer_cursor(token, changed_request, environment=values, now=NOW)

    assert exc_info.value.category == "cursor_invalid"


def test_expired_cursor_fails_closed() -> None:
    values = environment()
    token = encode(values)

    with pytest.raises(WazuhIndexerCursorError) as exc_info:
        decode_wazuh_indexer_cursor(
            token,
            request(),
            environment=values,
            now=datetime(2026, 8, 10, 22, 16, 4, tzinfo=timezone.utc),
        )

    assert exc_info.value.category == "cursor_invalid"


def test_cursor_encrypted_with_another_key_fails_closed() -> None:
    token = encode(environment())

    with pytest.raises(WazuhIndexerCursorError) as exc_info:
        decode_wazuh_indexer_cursor(token, request(), environment=environment(), now=NOW)

    assert exc_info.value.category == "cursor_invalid"


@pytest.mark.parametrize(
    "values",
    [
        {},
        {CURSOR_KEY_ENV: ""},
        {CURSOR_KEY_ENV: "not-a-fernet-key"},
        {CURSOR_KEY_ENV: "\N{LOCK}"},
    ],
)
def test_missing_or_invalid_runtime_key_fails_without_disclosure(values) -> None:
    with pytest.raises(WazuhIndexerCursorError) as exc_info:
        encode(values)

    assert exc_info.value.category == "cursor_config_error"
    supplied_key = values.get(CURSOR_KEY_ENV)
    if supplied_key:
        assert supplied_key not in str(exc_info.value)
    assert PIT_ID not in str(exc_info.value)


@pytest.mark.parametrize(
    "overrides",
    [
        {"pit_id": ""},
        {"search_after": []},
        {"search_after": "not-a-sort-list"},
        {"search_after": [None]},
        {"search_after": [float("nan")]},
        {"search_after": [float("inf")]},
        {"returned_records": -1},
        {"returned_records": 101},
        {"expires_at": "not-a-time"},
        {"expires_at": "2026-08-10T22:15:34Z"},
    ],
)
def test_invalid_cursor_envelope_fails_closed(overrides) -> None:
    with pytest.raises(WazuhIndexerCursorError) as exc_info:
        encode(environment(), **overrides)

    assert exc_info.value.category == "cursor_invalid"
    assert PIT_ID not in str(exc_info.value)


def test_naive_validation_time_fails_closed() -> None:
    values = environment()

    with pytest.raises(WazuhIndexerCursorError) as exc_info:
        encode(values, now=datetime(2026, 8, 10, 22, 15, 34))

    assert exc_info.value.category == "cursor_invalid"
