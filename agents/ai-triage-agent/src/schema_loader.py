import json
from pathlib import Path

SCHEMA_FILE = Path(__file__).parent.parent / "schemas" / "triage_schema.json"


def load_schema() -> dict:
    if not SCHEMA_FILE.exists():
        raise FileNotFoundError(f"Schema file not found: {SCHEMA_FILE}")

    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
