import copy
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

DOMAIN_MODULE_DIR = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "sysmon_event1"
sys.path.insert(0, str(DOMAIN_MODULE_DIR))

from parse_sysmon_event1_source import parse_sysmon_event1_source  # noqa: E402

SCHEMA_PATH = Path("schemas/sysmon_event1_parsed_event.schema.json")
SOURCE_DIR = Path("tests/fixtures/windows/sysmon_event1/source")
EXPECTED_DIR = Path("tests/fixtures/windows/sysmon_event1/expected_parsed")
FIXTURE_A_ID = "sysmon-event1-ordinary-powershell-001"
FIXTURE_B_ID = "sysmon-event1-encoded-flag-001"
FIXTURE_C_ID = "sysmon-event1-ordinary-notepad-001"
NORMALIZED_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

FORBIDDEN_PARSED_KEYS = {
    "event_id",
    "platform",
    "source",
    "host",
    "timestamp",
    "event_type",
    "pid",
    "ppid",
    "process_name",
    "exe",
    "cwd",
    "parent_process_name",
    "parent_exe",
    "raw_ref",
    "source_fields",
    "canonical_event_id",
    "expected_detection",
    "powershell_process_observed",
    "encoded_command_observed",
    "malicious",
    "verdict",
    "severity",
    "confidence",
    "response",
    "detection",
    "incident",
}
FORBIDDEN_RUNTIME_VALUES = {
    "".join(("WIN-", "VICTIM01")),
    ".".join(("192", "168", "1", "31")),
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def source_paths() -> list[Path]:
    return sorted(SOURCE_DIR.glob("*.json"))


def expected_paths() -> list[Path]:
    return sorted(EXPECTED_DIR.glob("*.json"))


def expected_artifacts() -> list[tuple[Path, dict]]:
    return [(path, load_json(path)) for path in expected_paths()]


def validator() -> Draft202012Validator:
    return Draft202012Validator(
        load_json(SCHEMA_PATH),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(collect_keys(child) for child in value.values()))
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


def test_current_expected_parsed_inventory_is_a_b_and_c() -> None:
    assert {artifact["fixture_id"] for _, artifact in expected_artifacts()} == {
        FIXTURE_A_ID,
        FIXTURE_B_ID,
        FIXTURE_C_ID,
    }


def test_source_and_expected_parsed_filename_inventories_match() -> None:
    assert {path.name for path in source_paths()} == {path.name for path in expected_paths()}


def test_expected_parsed_filenames_match_fixture_ids() -> None:
    for path, artifact in expected_artifacts():
        assert path.stem == artifact["fixture_id"]


def test_all_expected_parsed_artifacts_are_schema_valid() -> None:
    paths = expected_paths()
    assert paths
    parsed_validator = validator()
    for path in paths:
        parsed_validator.validate(load_json(path))


def test_source_parser_output_exactly_matches_expected_parsed_artifacts() -> None:
    for source_path in source_paths():
        expected_path = EXPECTED_DIR / source_path.name
        actual = parse_sysmon_event1_source(load_json(source_path))
        expected = load_json(expected_path)
        assert actual == expected


def test_parser_supported_hash_variants_match_parsed_event_schema() -> None:
    source = copy.deepcopy(load_json(SOURCE_DIR / f"{FIXTURE_A_ID}.json"))
    source["event_data"]["Hashes"] = "sha256=AAAA,md5=BBBB"

    parsed = parse_sysmon_event1_source(source)

    validator().validate(parsed)
    assert parsed["hashes"] == {"SHA256": "AAAA", "MD5": "BBBB"}


def test_expected_parsed_identities_are_unique() -> None:
    artifacts = [artifact for _, artifact in expected_artifacts()]
    identities = (
        [artifact["fixture_id"] for artifact in artifacts],
        [artifact["event_record_id"] for artifact in artifacts],
        [artifact["process_guid"] for artifact in artifacts],
    )
    for values in identities:
        assert len(values) == len(set(values))


def test_expected_parsed_type_boundary() -> None:
    for _, artifact in expected_artifacts():
        assert type(artifact["provider_event_id"]) is int
        assert type(artifact["event_record_id"]) is int
        assert type(artifact["process_id"]) is int
        assert type(artifact["parent_process_id"]) is int
        if "terminal_session_id" in artifact:
            assert type(artifact["terminal_session_id"]) is int
        if "hashes" in artifact:
            assert isinstance(artifact["hashes"], dict)


def test_expected_parsed_timestamps_use_fixed_utc_format_independently() -> None:
    for _, artifact in expected_artifacts():
        assert NORMALIZED_TIMESTAMP_PATTERN.fullmatch(artifact["system_time"])
        assert NORMALIZED_TIMESTAMP_PATTERN.fullmatch(artifact["utc_time"])


def test_fixture_a_b_and_c_omit_rule_name_sentinel_output() -> None:
    artifacts_by_id = {artifact["fixture_id"]: artifact for _, artifact in expected_artifacts()}
    assert "rule_name" not in artifacts_by_id[FIXTURE_A_ID]
    assert "rule_name" not in artifacts_by_id[FIXTURE_B_ID]
    assert "rule_name" not in artifacts_by_id[FIXTURE_C_ID]


def test_expected_parsed_artifacts_do_not_cross_canonical_or_detection_boundary() -> None:
    for _, artifact in expected_artifacts():
        assert collect_keys(artifact).isdisjoint(FORBIDDEN_PARSED_KEYS)


def test_expected_parsed_artifacts_do_not_contain_runtime_identifiers() -> None:
    for _, artifact in expected_artifacts():
        values = collect_string_values(artifact)
        for forbidden_value in FORBIDDEN_RUNTIME_VALUES:
            assert all(forbidden_value not in value for value in values)
