from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError
from parse_sysmon_event1_source import (
    SysmonEvent1ParseError,
    parse_sysmon_event1_source,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "sysmon_event1_source_fixture.schema.json"
PARSED_SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "sysmon_event1_parsed_event.schema.json"
SAFE_PARSER_PATH_PATTERN = re.compile(r"\bat ([A-Za-z0-9_.]+)$")


class SysmonEvent1NativeParityError(ValueError):
    """Raised when a local native parity input fails a validation stage."""


def _load_schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


SOURCE_VALIDATOR = Draft202012Validator(
    _load_schema(SOURCE_SCHEMA_PATH),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)
PARSED_VALIDATOR = Draft202012Validator(
    _load_schema(PARSED_SCHEMA_PATH),
    format_checker=Draft202012Validator.FORMAT_CHECKER,
)


def discover_input_paths(input_path: Path) -> list[Path]:
    if not input_path.exists():
        raise SysmonEvent1NativeParityError(f"{input_path.name}: input discovery failed at input")
    if input_path.is_file():
        return [input_path]
    if not input_path.is_dir():
        raise SysmonEvent1NativeParityError(f"{input_path.name}: input discovery failed at input")

    paths = sorted(input_path.glob("*.json"), key=lambda path: path.name)
    if not paths:
        raise SysmonEvent1NativeParityError(
            f"{input_path.name}: input discovery failed at input.json"
        )
    return paths


def _validation_error_path(error: ValidationError) -> str:
    path = [str(part) for part in error.absolute_path]
    if error.validator == "required" and isinstance(error.instance, dict):
        missing = next(
            (field for field in error.validator_value if field not in error.instance),
            None,
        )
        if missing is not None:
            path.append(str(missing))
    elif error.validator == "additionalProperties" and isinstance(error.instance, dict):
        properties = error.schema.get("properties", {})
        unknown = sorted(set(error.instance).difference(properties))
        if unknown:
            path.append(str(unknown[0]))
    return ".".join(path) if path else "source"


def _raise_schema_error(filename: str, stage: str, error: ValidationError) -> None:
    path = _validation_error_path(error)
    raise SysmonEvent1NativeParityError(f"{filename}: {stage} failed at {path}") from error


def validate_source_event(source: object, filename: str) -> Mapping[str, object]:
    if not isinstance(source, Mapping):
        raise SysmonEvent1NativeParityError(f"{filename}: source_schema failed at source")
    try:
        SOURCE_VALIDATOR.validate(source)
    except ValidationError as exc:
        _raise_schema_error(filename, "source_schema", exc)
    return source


def validate_parsed_event(parsed: object, filename: str) -> Mapping[str, object]:
    if not isinstance(parsed, Mapping):
        raise SysmonEvent1NativeParityError(f"{filename}: parsed_schema failed at parsed")
    try:
        PARSED_VALIDATOR.validate(parsed)
    except ValidationError as exc:
        _raise_schema_error(filename, "parsed_schema", exc)
    return parsed


def _safe_parser_path(error: SysmonEvent1ParseError) -> str:
    match = SAFE_PARSER_PATH_PATTERN.search(str(error))
    return match.group(1) if match is not None else "source"


def validate_native_parity_file(path: Path) -> dict[str, object]:
    filename = path.name
    try:
        source = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SysmonEvent1NativeParityError(f"{filename}: json_parse failed at source") from exc

    validated_source = validate_source_event(source, filename)
    if path.stem != validated_source["fixture_id"]:
        raise SysmonEvent1NativeParityError(f"{filename}: source_identity failed at fixture_id")
    try:
        parsed = parse_sysmon_event1_source(validated_source)
    except SysmonEvent1ParseError as exc:
        path_text = _safe_parser_path(exc)
        raise SysmonEvent1NativeParityError(f"{filename}: parser failed at {path_text}") from exc
    validated_parsed = validate_parsed_event(parsed, filename)

    return {
        "filename": filename,
        "source_schema": "ok",
        "parser": "ok",
        "parsed_schema": "ok",
        "provider_event_id": validated_parsed["provider_event_id"],
        "timestamps_equal": (validated_parsed["system_time"] == validated_parsed["utc_time"]),
    }


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate local Sysmon Event ID 1 provider-like JSON through source, "
            "parser, and parsed-event contracts."
        )
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="One provider-like JSON file or a directory of direct-child JSON files.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        paths = discover_input_paths(args.input)
        summaries = [validate_native_parity_file(path) for path in paths]
    except SysmonEvent1NativeParityError as exc:
        print(f"native-parity-error: {exc}", file=sys.stderr)
        return 1

    for summary in summaries:
        print(f"native-parity-ok: {summary['filename']}")
        print(
            "  source_schema=ok parser=ok parsed_schema=ok "
            f"provider_event_id={summary['provider_event_id']} "
            f"timestamps_equal={str(summary['timestamps_equal']).lower()}"
        )
    print(f"native-parity-count: {len(summaries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
