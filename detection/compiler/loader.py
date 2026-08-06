from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REQUIRED_RULE_KEYS = {
    "id",
    "title",
    "log_source",
    "match",
    "artifact",
    "severity",
    "behavior_features",
    "targets",
}


class RuleValidationError(ValueError):
    """Raised when a DSL rule is invalid."""


def validate_rule(rule: dict[str, Any], source: str = "<memory>") -> None:
    if not isinstance(rule, dict):
        raise RuleValidationError(f"{source}: rule must be a mapping/dict")

    missing = REQUIRED_RULE_KEYS - set(rule.keys())
    if missing:
        raise RuleValidationError(f"{source}: missing required keys: {', '.join(sorted(missing))}")

    if not isinstance(rule["id"], str) or not rule["id"].strip():
        raise RuleValidationError(f"{source}: 'id' must be a non-empty string")

    if not isinstance(rule["title"], str) or not rule["title"].strip():
        raise RuleValidationError(f"{source}: 'title' must be a non-empty string")

    if not isinstance(rule["log_source"], dict):
        raise RuleValidationError(f"{source}: 'log_source' must be a mapping/dict")

    if not isinstance(rule["match"], dict):
        raise RuleValidationError(f"{source}: 'match' must be a mapping/dict")

    if not isinstance(rule["artifact"], str) or not rule["artifact"].strip():
        raise RuleValidationError(f"{source}: 'artifact' must be a non-empty string")

    if not isinstance(rule["severity"], str) or not rule["severity"].strip():
        raise RuleValidationError(f"{source}: 'severity' must be a non-empty string")

    if not isinstance(rule["behavior_features"], dict):
        raise RuleValidationError(f"{source}: 'behavior_features' must be a mapping/dict")

    if not isinstance(rule["targets"], list) or not all(
        isinstance(item, str) for item in rule["targets"]
    ):
        raise RuleValidationError(f"{source}: 'targets' must be a list[str]")


def load_rule(path: str | Path) -> dict[str, Any]:
    rule_path = Path(path)
    with rule_path.open("r", encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    validate_rule(rule, source=str(rule_path))
    return rule


def load_rules(directory: str | Path) -> list[dict[str, Any]]:
    rules_dir = Path(directory)
    if not rules_dir.exists():
        raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

    rules: list[dict[str, Any]] = []
    for path in sorted(rules_dir.glob("*.y*ml")):
        rules.append(load_rule(path))

    if not rules:
        raise FileNotFoundError(f"No YAML rules found in: {rules_dir}")

    return rules
