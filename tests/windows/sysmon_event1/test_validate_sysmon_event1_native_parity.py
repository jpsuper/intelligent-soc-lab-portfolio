import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

DOMAIN_MODULE_DIR = Path(__file__).resolve().parents[3] / "scripts" / "windows" / "sysmon_event1"
sys.path.insert(0, str(DOMAIN_MODULE_DIR))

import validate_sysmon_event1_native_parity as native_parity  # noqa: E402

SOURCE_DIR = Path("tests/fixtures/windows/sysmon_event1/source")
FIXTURE_A_PATH = SOURCE_DIR / "sysmon-event1-ordinary-powershell-001.json"
FIXTURE_C_PATH = SOURCE_DIR / "sysmon-event1-ordinary-notepad-001.json"
SENSITIVE_MARKERS = {
    "sensitive-command-text",
    "LAB\\private-user",
    "WIN-PRIVATE01",
}


def load_source(path: Path = FIXTURE_A_PATH) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def assert_safe_text(text: str) -> None:
    for marker in SENSITIVE_MARKERS:
        assert marker not in text


def test_single_valid_source_fixture_passes_full_validation_chain() -> None:
    summary = native_parity.validate_native_parity_file(FIXTURE_A_PATH)

    assert summary == {
        "filename": FIXTURE_A_PATH.name,
        "source_schema": "ok",
        "parser": "ok",
        "parsed_schema": "ok",
        "provider_event_id": 1,
        "timestamps_equal": True,
    }


def test_directory_discovery_is_direct_child_json_only_and_filename_sorted(
    tmp_path: Path,
) -> None:
    source_z = load_source(FIXTURE_C_PATH)
    source_z["fixture_id"] = "sysmon-event1-z-001"
    source_a = load_source(FIXTURE_A_PATH)
    source_a["fixture_id"] = "sysmon-event1-a-001"
    write_json(tmp_path / "sysmon-event1-z-001.json", source_z)
    write_json(tmp_path / "sysmon-event1-a-001.json", source_a)
    nested = tmp_path / "nested"
    nested.mkdir()
    write_json(nested / "ignored.json", load_source())
    (tmp_path / "ignored.txt").write_text("not-json", encoding="utf-8")

    paths = native_parity.discover_input_paths(tmp_path)
    summaries = [native_parity.validate_native_parity_file(path) for path in paths]

    assert [path.name for path in paths] == [
        "sysmon-event1-a-001.json",
        "sysmon-event1-z-001.json",
    ]
    assert [summary["provider_event_id"] for summary in summaries] == [1, 1]


def test_summary_excludes_runtime_and_source_values(tmp_path: Path) -> None:
    source = load_source()
    source["fixture_id"] = "sysmon-event1-capture-001"
    source["system"]["computer"] = "WIN-PRIVATE01"
    source["event_data"]["User"] = "LAB\\private-user"
    source["event_data"]["CommandLine"] = "sensitive-command-text"
    path = write_json(tmp_path / "sysmon-event1-capture-001.json", source)

    summary = native_parity.validate_native_parity_file(path)
    serialized = json.dumps(summary, sort_keys=True)

    assert set(summary) == {
        "filename",
        "source_schema",
        "parser",
        "parsed_schema",
        "provider_event_id",
        "timestamps_equal",
    }
    assert_safe_text(serialized)


def test_independently_valid_unequal_timestamps_pass_without_value_disclosure_or_mutation(
    tmp_path: Path,
) -> None:
    source = copy.deepcopy(load_source())
    source["fixture_id"] = "sysmon-event1-independent-timestamps-001"
    source["system"]["system_time"] = "2026-01-15T01:02:03.124Z"
    source["event_data"]["UtcTime"] = "2026-01-15 01:02:03.123"
    path = write_json(
        tmp_path / "sysmon-event1-independent-timestamps-001.json",
        source,
    )
    before = hashlib.sha256(path.read_bytes()).digest()

    summary = native_parity.validate_native_parity_file(path)
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["source_schema"] == "ok"
    assert summary["parser"] == "ok"
    assert summary["parsed_schema"] == "ok"
    assert summary["timestamps_equal"] is False
    assert source["system"]["system_time"] not in serialized
    assert source["event_data"]["UtcTime"] not in serialized
    assert hashlib.sha256(path.read_bytes()).digest() == before


@pytest.mark.parametrize("kind", ["missing", "empty"])
def test_input_discovery_errors(kind: str, tmp_path: Path) -> None:
    input_path = tmp_path / kind
    if kind == "empty":
        input_path.mkdir()

    with pytest.raises(
        native_parity.SysmonEvent1NativeParityError,
        match=r"input discovery failed at input",
    ):
        native_parity.discover_input_paths(input_path)


def test_malformed_json_is_rejected_without_content_dump(tmp_path: Path) -> None:
    path = tmp_path / "malformed.json"
    path.write_text('{"CommandLine": "sensitive-command-text"', encoding="utf-8")

    with pytest.raises(
        native_parity.SysmonEvent1NativeParityError,
        match=r"malformed\.json: json_parse failed at source",
    ) as exc_info:
        native_parity.validate_native_parity_file(path)

    assert_safe_text(str(exc_info.value))


def test_non_object_json_is_rejected_at_source_schema(tmp_path: Path) -> None:
    path = write_json(tmp_path / "array.json", [])

    with pytest.raises(
        native_parity.SysmonEvent1NativeParityError,
        match=r"array\.json: source_schema failed at source",
    ):
        native_parity.validate_native_parity_file(path)


@pytest.mark.parametrize(
    ("mutate", "expected_path"),
    [
        (
            lambda source: source["event_data"].update(
                {"UnexpectedField": "sensitive-command-text"}
            ),
            "event_data.UnexpectedField",
        ),
        (
            lambda source: source["event_data"].pop("CommandLine"),
            "event_data.CommandLine",
        ),
    ],
)
def test_source_schema_errors_report_safe_field_path(
    mutate,
    expected_path: str,
    tmp_path: Path,
) -> None:
    source = load_source()
    source["system"]["computer"] = "WIN-PRIVATE01"
    source["event_data"]["User"] = "LAB\\private-user"
    mutate(source)
    path = write_json(tmp_path / "source-invalid.json", source)

    with pytest.raises(native_parity.SysmonEvent1NativeParityError) as exc_info:
        native_parity.validate_native_parity_file(path)

    message = str(exc_info.value)
    assert "source-invalid.json: source_schema failed" in message
    assert expected_path in message
    assert_safe_text(message)


def test_source_schema_valid_parser_failure_is_wrapped_safely(tmp_path: Path) -> None:
    source = load_source()
    source["fixture_id"] = "sysmon-event1-parser-invalid-001"
    source["event_data"]["Hashes"] = "SHA 256=AAAA"
    source["event_data"]["CommandLine"] = "sensitive-command-text"
    path = write_json(tmp_path / "sysmon-event1-parser-invalid-001.json", source)

    with pytest.raises(native_parity.SysmonEvent1NativeParityError) as exc_info:
        native_parity.validate_native_parity_file(path)

    message = str(exc_info.value)
    assert "sysmon-event1-parser-invalid-001.json: parser failed at event_data.Hashes" in message
    assert_safe_text(message)


def test_filename_and_fixture_id_mismatch_is_rejected_safely(tmp_path: Path) -> None:
    source = load_source()
    source["system"]["computer"] = "WIN-PRIVATE01"
    source["event_data"]["User"] = "LAB\\private-user"
    source["event_data"]["CommandLine"] = "sensitive-command-text"
    path = write_json(tmp_path / "sysmon-event1-other-001.json", source)

    with pytest.raises(native_parity.SysmonEvent1NativeParityError) as exc_info:
        native_parity.validate_native_parity_file(path)

    message = str(exc_info.value)
    assert "sysmon-event1-other-001.json: source_identity failed at fixture_id" in message
    assert source["fixture_id"] not in message
    assert_safe_text(message)


def test_parsed_schema_failure_is_wrapped_with_safe_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = load_source()
    source["fixture_id"] = "sysmon-event1-parsed-invalid-001"
    path = write_json(tmp_path / "sysmon-event1-parsed-invalid-001.json", source)
    original_parser = native_parity.parse_sysmon_event1_source

    def invalid_parser(value):
        parsed = original_parser(value)
        parsed["event_id"] = "canonical-not-allowed"
        return parsed

    monkeypatch.setattr(native_parity, "parse_sysmon_event1_source", invalid_parser)

    with pytest.raises(native_parity.SysmonEvent1NativeParityError) as exc_info:
        native_parity.validate_native_parity_file(path)

    assert "parsed_schema failed at event_id" in str(exc_info.value)


def test_main_returns_zero_and_prints_only_safe_success_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = load_source()
    source["fixture_id"] = "sysmon-event1-capture-001"
    source["system"]["computer"] = "WIN-PRIVATE01"
    source["event_data"]["User"] = "LAB\\private-user"
    source["event_data"]["CommandLine"] = "sensitive-command-text"
    path = write_json(tmp_path / "sysmon-event1-capture-001.json", source)

    result = native_parity.main(["--input", str(path)])
    captured = capsys.readouterr()

    assert result == 0
    assert "native-parity-ok: sysmon-event1-capture-001.json" in captured.out
    assert "provider_event_id=1 timestamps_equal=true" in captured.out
    assert "native-parity-count: 1" in captured.out
    assert captured.err == ""
    assert_safe_text(captured.out)


def test_main_returns_zero_when_valid_timestamps_are_unequal(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = load_source()
    source["fixture_id"] = "sysmon-event1-independent-timestamps-001"
    source["system"]["system_time"] = "2026-01-15T01:02:03.124Z"
    source["event_data"]["UtcTime"] = "2026-01-15 01:02:03.123"
    path = write_json(
        tmp_path / "sysmon-event1-independent-timestamps-001.json",
        source,
    )

    result = native_parity.main(["--input", str(path)])
    captured = capsys.readouterr()

    assert result == 0
    assert "provider_event_id=1 timestamps_equal=false" in captured.out
    assert captured.err == ""


def test_main_returns_nonzero_and_prints_only_safe_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = load_source()
    source["event_data"]["CommandLine"] = "sensitive-command-text"
    source["event_data"]["UnexpectedField"] = "LAB\\private-user"
    path = write_json(tmp_path / "invalid.json", source)

    result = native_parity.main(["--input", str(path)])
    captured = capsys.readouterr()

    assert result == 1
    assert captured.out == ""
    assert "native-parity-error: invalid.json: source_schema failed" in captured.err
    assert "event_data.UnexpectedField" in captured.err
    assert_safe_text(captured.err)


def test_validator_does_not_mutate_input_file(tmp_path: Path) -> None:
    source = copy.deepcopy(load_source())
    source["fixture_id"] = "sysmon-event1-capture-001"
    path = write_json(tmp_path / "sysmon-event1-capture-001.json", source)
    before = hashlib.sha256(path.read_bytes()).digest()

    native_parity.validate_native_parity_file(path)

    assert hashlib.sha256(path.read_bytes()).digest() == before
