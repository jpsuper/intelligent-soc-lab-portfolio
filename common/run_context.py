import json
from dataclasses import dataclass
from pathlib import Path

RUNS_DIR = Path("data/runs")


@dataclass(frozen=True)
class RunPaths:
    run_id: str
    base: Path

    @property
    def run_dir(self) -> Path:
        return self.base

    @property
    def meta(self) -> Path:
        return self.base / "run_meta.json"

    @property
    def incident(self) -> Path:
        return self.base / "incident.json"

    @property
    def attack_result(self) -> Path:
        return self.base / "attack_result.json"

    @property
    def evaluation_result(self) -> Path:
        return self.base / "evaluation_result.json"

    @property
    def triage_result(self) -> Path:
        return self.base / "triage_result.json"

    @property
    def investigation_result(self) -> Path:
        return self.base / "investigation_result.json"

    @property
    def triage_rule(self) -> Path:
        return self.base / "triage_rule.json"

    @property
    def triage_diff(self) -> Path:
        return self.base / "triage_diff.json"

    @property
    def process_events(self) -> Path:
        return self.base / "process_events.json"

    @property
    def auditd_events(self) -> Path:
        return self.base / "auditd_events.json"

    @property
    def endpoint_events(self) -> Path:
        return self.base / "endpoint_events.json"

    @property
    def interesting_process_events(self) -> Path:
        return self.base / "interesting_process_events.json"

    @property
    def process_chain_hits(self) -> Path:
        return self.base / "process_chain_hits.json"

    @property
    def case(self) -> Path:
        return self.base / "case.json"

    @property
    def decision_log(self) -> Path:
        return self.base / "decision_log.json"

    @property
    def action_result(self) -> Path:
        return self.base / "action_result.json"

    @property
    def collection_request(self) -> Path:
        return self.base / "collection_request.json"

    @property
    def collection_result(self) -> Path:
        return self.base / "collection_result.json"

    @property
    def post_action_dfir_investigation_result(self) -> Path:
        return self.base / "post_action_dfir_investigation_result.json"

    @property
    def rule_improvement_review_input(self) -> Path:
        return self.base / "rule_improvement_review_input.json"

    @property
    def zeek_dir(self) -> Path:
        return self.base / "zeek"

    @property
    def zeek_conn_events(self) -> Path:
        return self.base / "zeek_conn_events.json"

    @property
    def zeek_http_events(self) -> Path:
        return self.base / "zeek_http_events.json"

    @property
    def zeek_enrichment(self) -> Path:
        return self.base / "zeek_enrichment.json"

    @property
    def wazuh_fim_search(self) -> Path:
        return self.base / "wazuh_fim_search.json"

    @property
    def wazuh_sudo_search(self) -> Path:
        return self.base / "wazuh_sudo_search.json"

    @property
    def wazuh_fim_alerts(self) -> Path:
        return self.base / "wazuh_fim_alerts.json"

    @property
    def wazuh_sudo_alerts(self) -> Path:
        return self.base / "wazuh_sudo_alerts.json"

    @property
    def ssh_auth_events(self) -> Path:
        return self.base / "ssh_auth_events.json"


def get_run_paths(run_id: str) -> RunPaths:
    base = RUNS_DIR / run_id
    return RunPaths(run_id=run_id, base=base)


def ensure_run_dir(run_id: str) -> RunPaths:
    paths = get_run_paths(run_id)
    paths.base.mkdir(parents=True, exist_ok=True)
    return paths


def load_run_meta(run_paths: RunPaths) -> dict:
    if not run_paths.meta.exists():
        return {}

    with run_paths.meta.open() as f:
        return json.load(f)


def save_run_meta(run_paths: RunPaths, meta: dict):
    with run_paths.meta.open("w") as f:
        json.dump(meta, f, indent=2)
