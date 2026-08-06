from pathlib import Path

import yaml
from rule_validator import validate_rules

DEFAULT_RULE_FILE = Path(__file__).parent.parent / "rules" / "derived_feature_rules.yaml"


def load_rules(rule_file: str | None = None) -> list[dict]:
    path = Path(rule_file) if rule_file else DEFAULT_RULE_FILE
    if not path.exists():
        raise FileNotFoundError(f"Rule file not found: {path}")

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules = data.get("rules", [])

    if not isinstance(rules, list):
        raise ValueError("rules must be a list")

    validate_rules(rules)
    return rules
