import json
from datetime import UTC, datetime
from pathlib import Path


def append_decision_log(run_dir: Path, entry: dict):
    log_file = run_dir / "decision_log.json"

    if log_file.exists():
        with log_file.open() as f:
            data = json.load(f)
    else:
        data = []

    entry["timestamp"] = datetime.now(UTC).isoformat()

    data.append(entry)

    with log_file.open("w") as f:
        json.dump(data, f, indent=2)
