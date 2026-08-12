from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from jsonschema import Draft202012Validator, ValidationError

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CURSOR_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "wazuh_indexer_cursor_envelope.schema.json"
CURSOR_KEY_ENV = "WAZUH_INDEXER_CURSOR_FERNET_KEY"
MAX_PIT_ID_LENGTH = 128 * 1024
MAX_CURSOR_LENGTH = 256 * 1024


class WazuhIndexerCursorError(ValueError):
    """Stable cursor failure that never echoes cursor or envelope values."""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        super().__init__(message)


@dataclass(frozen=True, repr=False)
class WazuhIndexerCursor:
    pit_id: str = field(repr=False)
    search_after: tuple[str | int | float, ...] = field(repr=False)
    returned_records: int
    expires_at: str

    def __repr__(self) -> str:
        return (
            "WazuhIndexerCursor(<redacted>, "
            f"returned_records={self.returned_records}, expires_at={self.expires_at!r})"
        )


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _invalid_cursor() -> WazuhIndexerCursorError:
    return WazuhIndexerCursorError(
        "cursor_invalid",
        "Wazuh Indexer cursor is invalid or expired",
    )


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise _invalid_cursor()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _invalid_cursor() from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _invalid_cursor()
    return parsed.astimezone(timezone.utc)


def _request_fingerprint(request: Mapping[str, object]) -> str:
    try:
        normalized = copy.deepcopy(dict(request))
        normalized["cursor"] = None
        encoded = _canonical_json(normalized).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        raise _invalid_cursor() from None
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _fernet(environment: Mapping[str, str] | None) -> Fernet:
    values = os.environ if environment is None else environment
    key = values.get(CURSOR_KEY_ENV)
    if not isinstance(key, str) or not key:
        raise WazuhIndexerCursorError(
            "cursor_config_error",
            "Wazuh Indexer cursor runtime key is missing or invalid",
        )
    try:
        return Fernet(key.encode("ascii"))
    except (UnicodeEncodeError, ValueError):
        raise WazuhIndexerCursorError(
            "cursor_config_error",
            "Wazuh Indexer cursor runtime key is missing or invalid",
        ) from None


def _validate_envelope(envelope: object) -> Mapping[str, object]:
    try:
        schema = json.loads(CURSOR_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise WazuhIndexerCursorError(
            "cursor_config_error",
            "Wazuh Indexer cursor schema could not be loaded",
        ) from None
    try:
        Draft202012Validator(
            schema,
            format_checker=Draft202012Validator.FORMAT_CHECKER,
        ).validate(envelope)
    except ValidationError:
        raise _invalid_cursor() from None
    if not isinstance(envelope, Mapping):
        raise _invalid_cursor()
    search_after = envelope["search_after"]
    assert isinstance(search_after, list)
    if any(isinstance(value, float) and not math.isfinite(value) for value in search_after):
        raise _invalid_cursor()
    return envelope


def _current_time_utc(value: datetime | None) -> datetime:
    current_time = datetime.now(timezone.utc) if value is None else value
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise _invalid_cursor()
    return current_time.astimezone(timezone.utc)


def encode_wazuh_indexer_cursor(
    request: Mapping[str, object],
    *,
    pit_id: str,
    search_after: Sequence[str | int | float],
    returned_records: int,
    expires_at: str,
    environment: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> str:
    """Create one authenticated, encrypted, request-bound cursor token."""

    if not isinstance(pit_id, str) or not pit_id or len(pit_id) > MAX_PIT_ID_LENGTH:
        raise _invalid_cursor()
    if isinstance(search_after, (str, bytes)):
        raise _invalid_cursor()
    current_time = _current_time_utc(now)
    envelope = {
        "contract_version": "1.0",
        "request_fingerprint": _request_fingerprint(request),
        "pit_id": pit_id,
        "search_after": copy.deepcopy(list(search_after)),
        "returned_records": returned_records,
        "expires_at": expires_at,
    }
    _validate_envelope(envelope)
    if _parse_timestamp(expires_at) <= current_time:
        raise _invalid_cursor()
    token = _fernet(environment).encrypt(_canonical_json(envelope).encode("utf-8")).decode("ascii")
    if len(token) > MAX_CURSOR_LENGTH:
        raise _invalid_cursor()
    return token


def decode_wazuh_indexer_cursor(
    token: str,
    request: Mapping[str, object],
    *,
    environment: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> WazuhIndexerCursor:
    """Validate one cursor without disclosing its protected values."""

    if not isinstance(token, str) or not token or len(token) > MAX_CURSOR_LENGTH:
        raise _invalid_cursor()
    try:
        plaintext = _fernet(environment).decrypt(token.encode("ascii"))
        envelope = json.loads(plaintext.decode("utf-8"))
    except (InvalidToken, UnicodeEncodeError, UnicodeDecodeError, json.JSONDecodeError):
        raise _invalid_cursor() from None
    validated = _validate_envelope(envelope)
    current_time = _current_time_utc(now)
    if _parse_timestamp(validated["expires_at"]) <= current_time:
        raise _invalid_cursor()
    if not hmac.compare_digest(
        str(validated["request_fingerprint"]),
        _request_fingerprint(request),
    ):
        raise _invalid_cursor()
    search_after = validated["search_after"]
    assert isinstance(search_after, list)
    return WazuhIndexerCursor(
        pit_id=str(validated["pit_id"]),
        search_after=tuple(search_after),
        returned_records=int(validated["returned_records"]),
        expires_at=str(validated["expires_at"]),
    )
