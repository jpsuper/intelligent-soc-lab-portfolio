import json
import ntpath
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path("schemas/sysmon_event1_source_fixture.schema.json")
FIXTURE_DIR = Path("tests/fixtures/windows/sysmon_event1/source")
FIXTURE_A_ID = "sysmon-event1-ordinary-powershell-001"
FIXTURE_B_ID = "sysmon-event1-encoded-flag-001"
FIXTURE_C_ID = "sysmon-event1-ordinary-notepad-001"
SYNTHETIC_PROVIDER_GUID = "{44444444-4444-4444-4444-444444444444}"

FORBIDDEN_DOWNSTREAM_KEYS = {
    "expected_parsed",
    "expected_normalized",
    "expected_detection",
    "powershell_process_observed",
    "encoded_command_observed",
    "event_id",
    "event_type",
    "platform",
    "source",
    "malicious",
    "verdict",
    "severity",
    "confidence",
    "response",
}
FORBIDDEN_RUNTIME_VALUES = {"WIN-VICTIM01", "192.0.2.31"}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def fixture_paths() -> list[Path]:
    return sorted(FIXTURE_DIR.glob("*.json"))


def fixtures() -> list[tuple[Path, dict]]:
    return [(path, load_json(path)) for path in fixture_paths()]


def validator() -> Draft202012Validator:
    return Draft202012Validator(
        load_json(SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(
            *(collect_keys(child) for child in value.values()),
        )
    if isinstance(value, list):
        return set().union(*(collect_keys(child) for child in value))
    return set()


def collect_string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for child in value.values() for text in collect_string_values(child)]
    if isinstance(value, list):
        return [text for child in value for text in collect_string_values(child)]
    return []


def parse_sysmon_utc_time(value: str) -> datetime:
    timestamp, fractional_seconds = value.rsplit(".", maxsplit=1)
    # datetime stores microseconds, so right-pad 3-5 digits and truncate 7 digits.
    microseconds = fractional_seconds.ljust(6, "0")[:6]
    return datetime.strptime(f"{timestamp}.{microseconds}", "%Y-%m-%d %H:%M:%S.%f").replace(
        tzinfo=timezone.utc
    )


def source_times(fixture: dict) -> tuple[datetime, datetime]:
    system_time = datetime.fromisoformat(
        fixture["system"]["system_time"].replace("Z", "+00:00")
    ).astimezone(timezone.utc)
    return system_time, parse_sysmon_utc_time(fixture["event_data"]["UtcTime"])


def fixture_by_id(fixture_id: str) -> dict:
    return next(fixture for _, fixture in fixtures() if fixture["fixture_id"] == fixture_id)


def test_all_current_source_fixtures_are_schema_valid() -> None:
    paths = fixture_paths()
    assert paths
    source_validator = validator()
    for path in paths:
        source_validator.validate(load_json(path))


def test_fixture_a_b_and_c_are_schema_valid() -> None:
    source_validator = validator()
    for fixture_id in (FIXTURE_A_ID, FIXTURE_B_ID, FIXTURE_C_ID):
        source_validator.validate(fixture_by_id(fixture_id))


def test_current_inventory_contains_fixture_a_b_and_c() -> None:
    assert {fixture["fixture_id"] for _, fixture in fixtures()} == {
        FIXTURE_A_ID,
        FIXTURE_B_ID,
        FIXTURE_C_ID,
    }


def test_filenames_match_fixture_ids() -> None:
    for path, fixture in fixtures():
        assert path.stem == fixture["fixture_id"]


def test_source_fixture_identities_are_unique() -> None:
    loaded = [fixture for _, fixture in fixtures()]
    identities = (
        [fixture["fixture_id"] for fixture in loaded],
        [fixture["system"]["event_record_id"] for fixture in loaded],
        [fixture["event_data"]["ProcessGuid"] for fixture in loaded],
    )
    for values in identities:
        assert len(values) == len(set(values))


def test_provider_invariants() -> None:
    for _, fixture in fixtures():
        assert fixture["fixture_contract_version"] == "1.0"
        assert fixture["source_format"] == "sysmon_eventlog_json"
        assert fixture["system"]["provider_name"] == "Microsoft-Windows-Sysmon"
        assert fixture["system"]["provider_guid"] == SYNTHETIC_PROVIDER_GUID
        assert fixture["system"]["provider_event_id"] == 1
        assert fixture["system"]["channel"] == "Microsoft-Windows-Sysmon/Operational"


def test_system_time_and_utc_time_represent_the_same_observation() -> None:
    for _, fixture in fixtures():
        system_time, utc_time = source_times(fixture)
        assert system_time == utc_time


def test_sysmon_utc_time_with_seven_fractional_digits_uses_microsecond_precision() -> None:
    assert parse_sysmon_utc_time("2026-01-15 01:02:03.1234567") == datetime(
        2026, 1, 15, 1, 2, 3, 123456, tzinfo=timezone.utc
    )


def test_fixture_a_is_ordinary_powershell_source_observation() -> None:
    fixture = fixture_by_id(FIXTURE_A_ID)
    event_data = fixture["event_data"]
    command_line = event_data["CommandLine"].lower()
    command_tokens = command_line.split()

    assert fixture["fixture_id"] == FIXTURE_A_ID
    assert ntpath.basename(event_data["Image"]).lower() == "powershell.exe"
    assert "powershell.exe" in command_tokens
    assert "encodedcommand" not in command_line
    assert "-enc" not in command_tokens


def test_fixture_b_is_safe_encoded_command_flag_source_observation() -> None:
    fixture = fixture_by_id(FIXTURE_B_ID)
    event_data = fixture["event_data"]
    command_line = event_data["CommandLine"]
    command_tokens = command_line.split()

    assert fixture["fixture_id"] == FIXTURE_B_ID
    assert ntpath.basename(event_data["Image"]).lower() == "powershell.exe"
    assert "-EncodedCommand" in command_tokens
    assert "SAFE_PLACEHOLDER" in command_tokens
    assert "http://" not in command_line.lower()
    assert "https://" not in command_line.lower()
    assert collect_keys(fixture).isdisjoint(FORBIDDEN_DOWNSTREAM_KEYS)


def test_fixture_c_is_ordinary_notepad_source_observation() -> None:
    fixture = fixture_by_id(FIXTURE_C_ID)
    event_data = fixture["event_data"]

    assert fixture["fixture_id"] == FIXTURE_C_ID
    assert ntpath.basename(event_data["Image"]).lower() == "notepad.exe"
    assert event_data["CommandLine"].lower().split()[0] == "notepad.exe"
    assert "powershell.exe" not in event_data["CommandLine"].lower()


def test_source_fixtures_do_not_contain_downstream_keys() -> None:
    for _, fixture in fixtures():
        assert collect_keys(fixture).isdisjoint(FORBIDDEN_DOWNSTREAM_KEYS)


def test_source_fixtures_do_not_contain_runtime_identifiers() -> None:
    for _, fixture in fixtures():
        values = collect_string_values(fixture)
        for forbidden_value in FORBIDDEN_RUNTIME_VALUES:
            assert all(forbidden_value not in value for value in values)
