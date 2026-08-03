"""In-memory composition from canonical Detections to pre-case Investigation.

This boundary reuses existing public list APIs. Its identities are deterministic
within one execution but remain run-local; it defines no persistent artifact or
stable identity across reprocessing or changed Incident selection results.
"""

from __future__ import annotations

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Callable

from detection.compiler.pipeline import (
    CommonPipelineValidationError,
    run_common_correlation_stage,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
INCIDENT_BUILDER_PATH = REPOSITORY_ROOT / "agents/incident-builder-agent/src/main.py"
RULE_TRIAGE_PATH = REPOSITORY_ROOT / "agents/rule-triage-agent/src/main.py"
INVESTIGATION_PATH = REPOSITORY_ROOT / "agents/investigation-agent/src/main.py"
COMPOSITION_KEYS = frozenset(
    {
        "deduped_detections",
        "correlations",
        "incidents",
        "triage_results",
        "investigation_results",
    }
)


class CommonPipelineCompositionError(ValueError):
    """Raised when common Detection-to-Investigation composition is invalid."""


def _load_module(
    module_name: str,
    module_path: Path,
    *,
    import_path: Path | None = None,
) -> ModuleType:
    """Load one agent module without retaining mutable stage-module state."""

    inserted_path = False
    saved_local_modules: dict[str, ModuleType] = {}
    local_module_names: set[str] = set()
    if import_path is not None:
        local_module_names = {
            path.stem
            for path in import_path.glob("*.py")
            if path.stem not in {"__init__", module_path.stem}
        }
        for name in local_module_names:
            existing = sys.modules.pop(name, None)
            if existing is not None:
                saved_local_modules[name] = existing
        import_path_text = str(import_path)
        if import_path_text not in sys.path:
            sys.path.insert(0, import_path_text)
            inserted_path = True

    try:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot create module spec for {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if inserted_path:
            sys.path.remove(str(import_path))
        for name in local_module_names:
            sys.modules.pop(name, None)
        sys.modules.update(saved_local_modules)


def _load_incident_builder_module() -> ModuleType:
    return _load_module(
        "common_pipeline_incident_builder",
        INCIDENT_BUILDER_PATH,
    )


def _load_rule_triage_module() -> ModuleType:
    return _load_module(
        "common_pipeline_rule_triage",
        RULE_TRIAGE_PATH,
        import_path=RULE_TRIAGE_PATH.parent,
    )


def _load_investigation_module() -> ModuleType:
    return _load_module(
        "common_pipeline_investigation",
        INVESTIGATION_PATH,
    )


def _load_stage_module(
    stage_name: str,
    loader: Callable[[], ModuleType],
) -> ModuleType:
    try:
        return loader()
    except (ImportError, FileNotFoundError) as exc:
        raise CommonPipelineCompositionError(f"{stage_name} stage failed: {exc}") from exc


def _unique_ids(items: list[dict], field: str, artifact_name: str) -> list[str]:
    values: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"{artifact_name}[{index}] must be an object")
        value = item.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{artifact_name}[{index}].{field} must be a non-empty string")
        values.append(value)
    if len(values) != len(set(values)):
        raise ValueError(f"{artifact_name} {field} values must be unique")
    return values


def _validate_composition_bundle(bundle: object) -> dict[str, list[dict]]:
    if not isinstance(bundle, dict):
        raise ValueError("composition output must be an object")
    if set(bundle) != COMPOSITION_KEYS:
        raise ValueError("composition output must contain exactly the five stage lists")
    for key in sorted(COMPOSITION_KEYS):
        if not isinstance(bundle[key], list):
            raise ValueError(f"composition output {key} must be a list")

    deduped = bundle["deduped_detections"]
    correlations = bundle["correlations"]
    incidents = bundle["incidents"]
    triages = bundle["triage_results"]
    investigations = bundle["investigation_results"]

    _unique_ids(deduped, "id", "deduped_detections")
    correlation_ids = _unique_ids(correlations, "correlation_id", "correlations")
    incident_ids = _unique_ids(incidents, "incident_id", "incidents")
    triage_ids = _unique_ids(triages, "triage_id", "triage_results")
    investigation_ids = _unique_ids(
        investigations,
        "investigation_id",
        "investigation_results",
    )

    if len(triages) != len(incidents):
        raise ValueError("triage result count must match incident count")
    if len(investigations) != len(incidents):
        raise ValueError("investigation result count must match incident count")

    triage_incident_ids = _unique_ids(triages, "incident_id", "triage_results")
    investigation_incident_ids = _unique_ids(
        investigations,
        "incident_id",
        "investigation_results",
    )
    incident_id_set = set(incident_ids)
    if set(triage_incident_ids) != incident_id_set:
        raise ValueError("Incident and Triage incident_id sets must match exactly")
    if set(investigation_incident_ids) != incident_id_set:
        raise ValueError("Incident and Investigation incident_id sets must match exactly")

    triages_by_incident = {triage["incident_id"]: triage for triage in triages}
    investigations_by_incident = {
        investigation["incident_id"]: investigation for investigation in investigations
    }
    for incident_id in incident_ids:
        triage = triages_by_incident[incident_id]
        investigation = investigations_by_incident[incident_id]
        expected_triage_id = f"triage-{incident_id}"
        expected_investigation_id = f"investigation-{incident_id}"
        if triage["triage_id"] != expected_triage_id:
            raise ValueError(f"triage_id must be {expected_triage_id}")
        if investigation["investigation_id"] != expected_investigation_id:
            raise ValueError(f"investigation_id must be {expected_investigation_id}")
        if investigation.get("triage_id") != triage["triage_id"]:
            raise ValueError(
                f"Investigation triage_id must match Triage for incident {incident_id}"
            )

    expected_incident_order = [
        *(f"inc-{correlation_id}" for correlation_id in correlation_ids),
        *(f"inc-{index:06d}" for index in range(1, len(incidents) - len(correlations) + 1)),
    ]
    if incident_ids != expected_incident_order:
        raise ValueError("incidents must preserve correlation-then-observation ordering")
    expected_downstream_order = sorted(incident_ids)
    if triage_incident_ids != expected_downstream_order:
        raise ValueError("triage_results must preserve incident_id ordering")
    if investigation_incident_ids != expected_downstream_order:
        raise ValueError("investigation_results must preserve incident_id ordering")

    if triage_ids != [f"triage-{incident_id}" for incident_id in expected_downstream_order]:
        raise ValueError("triage_results must preserve derived identity ordering")
    if investigation_ids != [
        f"investigation-{incident_id}" for incident_id in expected_downstream_order
    ]:
        raise ValueError("investigation_results must preserve derived identity ordering")

    return bundle


def run_common_detection_to_investigation(
    detections: object,
    *,
    observation_scenario_name: str | None = None,
    observation_incident_severity: str | None = None,
    derived_rules_path: str | None = None,
    assessment_rules_path: str | None = None,
    attack_result: dict | None = None,
    process_events: list[dict] | None = None,
    auditd_events: list[dict] | None = None,
    endpoint_events: object = None,
    endpoint_events_source: str | None = None,
    process_chain_hits: list[dict] | dict | None = None,
    zeek_enrichment: list[dict] | None = None,
    wazuh_fim_alerts: list[dict] | None = None,
    wazuh_sudo_alerts: list[dict] | None = None,
    ssh_auth_events: list[dict] | None = None,
    run_id: str | None = None,
) -> dict[str, list[dict]]:
    """Compose existing platform-neutral list boundaries in memory."""

    try:
        deduped_detections, correlations = run_common_correlation_stage(deepcopy(detections))
    except CommonPipelineValidationError as exc:
        raise CommonPipelineCompositionError(f"correlation stage failed: {exc}") from exc

    incident_builder = _load_stage_module(
        "incident selection",
        _load_incident_builder_module,
    )
    try:
        incidents = incident_builder.build_selected_incidents_from_results(
            correlations,
            deduped_detections,
            observation_scenario_name=observation_scenario_name,
            observation_incident_severity=observation_incident_severity,
        )
    except incident_builder.IncidentBoundaryValidationError as exc:
        raise CommonPipelineCompositionError(f"incident selection stage failed: {exc}") from exc

    rule_triage = _load_stage_module("rule triage", _load_rule_triage_module)
    try:
        triage_results = rule_triage.build_triage_results_from_incidents(
            incidents,
            derived_rules_path=derived_rules_path,
            assessment_rules_path=assessment_rules_path,
        )
    except rule_triage.TriageBoundaryValidationError as exc:
        raise CommonPipelineCompositionError(f"rule triage stage failed: {exc}") from exc

    investigation = _load_stage_module("investigation", _load_investigation_module)
    try:
        investigation_results = (
            investigation.build_investigation_results_from_incidents_and_triages(
                incidents,
                triage_results,
                attack_result=deepcopy(attack_result),
                process_events=deepcopy(process_events),
                auditd_events=deepcopy(auditd_events),
                endpoint_events=deepcopy(endpoint_events),
                endpoint_events_source=endpoint_events_source,
                process_chain_hits=deepcopy(process_chain_hits),
                zeek_enrichment=deepcopy(zeek_enrichment),
                wazuh_fim_alerts=deepcopy(wazuh_fim_alerts),
                wazuh_sudo_alerts=deepcopy(wazuh_sudo_alerts),
                ssh_auth_events=deepcopy(ssh_auth_events),
                run_id=run_id,
            )
        )
    except investigation.InvestigationBoundaryValidationError as exc:
        raise CommonPipelineCompositionError(f"investigation stage failed: {exc}") from exc

    bundle = {
        "deduped_detections": deduped_detections,
        "correlations": correlations,
        "incidents": incidents,
        "triage_results": triage_results,
        "investigation_results": investigation_results,
    }
    try:
        return _validate_composition_bundle(bundle)
    except ValueError as exc:
        raise CommonPipelineCompositionError(
            f"composition output validation failed: {exc}"
        ) from exc
