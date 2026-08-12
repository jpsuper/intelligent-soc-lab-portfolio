import argparse
import json
from pathlib import Path

from evaluator import apply_assessment_rules, apply_derived_feature_rules
from jsonschema import Draft7Validator
from rule_loader import load_rules
from yaml import YAMLError

DEFAULT_DERIVED_RULES = Path(__file__).parent.parent / "rules" / "derived_feature_rules.yaml"
DEFAULT_ASSESSMENT_RULES = Path(__file__).parent.parent / "rules" / "assessment_rules.yaml"
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
INCIDENT_SCHEMA_FILE = REPOSITORY_ROOT / "schemas" / "incident_schema.json"
TRIAGE_SCHEMA_FILE = (
    REPOSITORY_ROOT / "agents" / "ai-triage-agent" / "schemas" / "triage_schema.json"
)


class TriageBoundaryValidationError(ValueError):
    """Raised when the canonical Incident-to-Triage boundary is invalid."""


def _canonical_artifact_observations(incident: dict) -> list[str]:
    """Render canonical Incident artifacts without source- or platform-specific logic."""

    values = incident.get("artifacts")
    if not isinstance(values, list) or not values:
        values = [incident.get("primary_artifact")]

    observations: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        observation = value.strip().replace("_", " ")
        if observation not in observations:
            observations.append(observation)
    return observations


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: dict):
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def build_output(
    incident: dict,
    derived_rules_path: str | None = None,
    assessment_rules_path: str | None = None,
) -> dict:
    behavior_features = incident.get("behavior_features", {})

    derived_rules = load_rules(derived_rules_path or str(DEFAULT_DERIVED_RULES))
    assessment_rules = load_rules(assessment_rules_path or str(DEFAULT_ASSESSMENT_RULES))

    derived_features, derived_features_extra = apply_derived_feature_rules(
        derived_rules,
        behavior_features,
    )

    assessment = apply_assessment_rules(assessment_rules, derived_features)

    matched_rules = incident.get("matched_rules", []) or []
    artifacts = [str(item) for item in matched_rules if item]

    artifact_parts: list[str] = []
    if "ssh_key_login" in artifacts:
        artifact_parts.append("successful SSH public key login")
    if "process_exec" in artifacts:
        artifact_parts.append("process execution")
    if "authorized_keys_modification" in artifacts:
        artifact_parts.append("authorized_keys modification")

    used_canonical_artifacts = False
    if not artifact_parts:
        artifact_parts = _canonical_artifact_observations(incident)
        used_canonical_artifacts = bool(artifact_parts)

    if artifact_parts:
        prefix = (
            "Rule-based triage observed canonical artifact(s): "
            if used_canonical_artifacts
            else "Rule-based triage observed: "
        )
        summary = prefix + ", ".join(artifact_parts) + "."
    else:
        summary = (
            "Rule-based triage result based on externalized derived feature and assessment rules."
        )

    recommended_actions: list[str] = []
    if "ssh_key_login" in artifacts:
        recommended_actions.append("Review whether the SSH public key login was expected.")
    if "process_exec" in artifacts:
        recommended_actions.append("Review the executed command and parent process context.")
    if assessment["verdict"] in {"suspicious", "malicious"}:
        recommended_actions.append("Validate the source IP and account activity.")
        recommended_actions.append("Collect related authentication and process evidence.")

    return {
        "triage_id": f"triage-{incident['incident_id']}",
        "incident_id": incident["incident_id"],
        "attack_id": incident.get("attack_id"),
        "verdict": assessment["verdict"],
        "confidence": assessment["confidence"],
        "priority": assessment["priority"],
        "risk_score": assessment["risk_score"],
        "summary": summary,
        "attack_story": artifact_parts,
        "key_observations": artifact_parts,
        "derived_features": derived_features,
        "derived_features_extra": derived_features_extra,
        "mitre_attack": incident.get("mitre_attack", []),
        "recommended_actions": recommended_actions,
    }


def _load_schema(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _validate_schema(
    value: object,
    *,
    schema_path: Path,
    artifact_name: str,
    index: int,
) -> dict:
    validator = Draft7Validator(_load_schema(schema_path))
    error = next(iter(validator.iter_errors(value)), None)
    if error is not None:
        path = ".".join(str(part) for part in error.absolute_path) or "<root>"
        raise TriageBoundaryValidationError(
            f"{artifact_name}[{index}] schema validation failed at {path}: {error.message}"
        ) from None
    return value


def build_triage_results_from_incidents(
    incidents: object,
    *,
    derived_rules_path: str | None = None,
    assessment_rules_path: str | None = None,
) -> list[dict]:
    """Build one deterministic Rule Triage result per canonical Incident."""

    if not isinstance(incidents, list):
        raise TriageBoundaryValidationError("incidents must be a list")

    validated_incidents: list[dict] = []
    incident_ids: list[str] = []
    for index, incident in enumerate(incidents):
        validated_incident = _validate_schema(
            incident,
            schema_path=INCIDENT_SCHEMA_FILE,
            artifact_name="incidents",
            index=index,
        )
        incident_id = validated_incident.get("incident_id")
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise TriageBoundaryValidationError(
                f"incidents[{index}].incident_id must be a non-empty string"
            )
        validated_incidents.append(validated_incident)
        incident_ids.append(incident_id)

    if len(incident_ids) != len(set(incident_ids)):
        raise TriageBoundaryValidationError("incident_id values must be unique")

    ordered_incidents = sorted(
        validated_incidents,
        key=lambda incident: incident["incident_id"],
    )
    triage_results: list[dict] = []
    for index, incident in enumerate(ordered_incidents):
        try:
            triage = build_output(
                incident,
                derived_rules_path=derived_rules_path,
                assessment_rules_path=assessment_rules_path,
            )
        except TriageBoundaryValidationError:
            raise
        except (OSError, ValueError, YAMLError) as exc:
            raise TriageBoundaryValidationError(
                f"triage_results[{index}] rule evaluation failed: {exc}"
            ) from exc

        validated_triage = _validate_schema(
            triage,
            schema_path=TRIAGE_SCHEMA_FILE,
            artifact_name="triage_results",
            index=index,
        )
        if validated_triage["incident_id"] != incident["incident_id"]:
            raise TriageBoundaryValidationError(
                f"triage_results[{index}].incident_id must match input incident_id "
                f"{incident['incident_id']}"
            )
        triage_results.append(validated_triage)

    triage_ids = [triage["triage_id"] for triage in triage_results]
    if len(triage_ids) != len(set(triage_ids)):
        raise TriageBoundaryValidationError("triage_id values must be unique")

    for index, (incident, triage) in enumerate(zip(ordered_incidents, triage_results, strict=True)):
        expected_triage_id = f"triage-{incident['incident_id']}"
        if triage["triage_id"] != expected_triage_id:
            raise TriageBoundaryValidationError(
                f"triage_results[{index}].triage_id must be {expected_triage_id}"
            )

    return triage_results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--incident", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--derived-rules", help="Optional path to derived feature rule YAML")
    parser.add_argument("--assessment-rules", help="Optional path to assessment rule YAML")
    args = parser.parse_args()

    incident_data = load_json(args.incident)
    incident = incident_data[0] if isinstance(incident_data, list) else incident_data

    result = build_output(
        incident,
        derived_rules_path=args.derived_rules,
        assessment_rules_path=args.assessment_rules,
    )
    save_json(args.output, result)


if __name__ == "__main__":
    main()
