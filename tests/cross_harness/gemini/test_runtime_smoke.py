from __future__ import annotations

import hashlib
import json
from pathlib import Path

from infra.cross_harness.adapters.gemini.runtime_smoke import run_runtime_smoke
from infra.cross_harness.adapters.gemini.capabilities import capability_matrix
from infra.cross_harness.adapter import HarnessIdentity
from infra.cross_harness.contract import validate_event_document


REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = REPO_ROOT / "tests/cross_harness/gemini/fixtures"


def test_version_bound_fixture_matches_exact_executable_bytes() -> None:
    executable = FIXTURE_ROOT / "gemini_cli_fixture.py"
    evidence_path = FIXTURE_ROOT / "gemini_fixture_0_0_0_capability_conformance.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    assert evidence["harness_version"] == "0.0.0-fixture"
    assert evidence["executable_sha256"] == digest
    identity = HarnessIdentity(
        harness_id="gemini",
        version="0.0.0-fixture",
        executable=str(executable),
        feature_flags={
            "binary_sha256": digest,
            "headless_prompt": True,
            "stream_json": True,
        },
    )
    matrix = capability_matrix(identity=identity, conformance_path=evidence_path)
    assert matrix["headless_execution"].status == "SUPPORTED"
    assert matrix["structured_trace"].status == "SUPPORTED"
    assert matrix["instruction_loading"].status == "UNVALIDATED"
    assert matrix["control_isolation"].status == "UNVALIDATED"


def test_real_0_51_0_evidence_is_identity_bound_and_fail_closed() -> None:
    evidence_path = (
        FIXTURE_ROOT / "gemini_cli_0_51_0_capability_conformance.json"
    )
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    identity = HarnessIdentity(
        harness_id="gemini",
        version="0.51.0",
        executable="/version-pinned/evidence-only/gemini",
        feature_flags={
            "binary_sha256": evidence["executable_sha256"],
            "headless_prompt": True,
            "stream_json": True,
        },
    )
    matrix = capability_matrix(identity=identity, conformance_path=evidence_path)
    assert matrix["headless_execution"].status == "SUPPORTED"
    assert matrix["structured_trace"].status == "SUPPORTED"
    assert matrix["workspace_isolation"].status == "SUPPORTED"
    assert matrix["fresh_process"].status == "SUPPORTED"
    assert matrix["artifact_hash_provenance"].status == "SUPPORTED"
    assert matrix["mcp_tool_trace"].status == "UNVALIDATED"


def test_external_smoke_records_exact_route_terminal_error_as_not_run() -> None:
    evidence = json.loads(
        (
            FIXTURE_ROOT / "gemini_cli_0_51_0_vertex_global_smoke.json"
        ).read_text(encoding="utf-8")
    )
    assert evidence["authorization"]["requested_model"] == "gemini-2.5-flash"
    assert evidence["attempt_summary"]["formal_benchmark_trials"] == 0
    assert evidence["attempt_summary"]["scored_trials"] == 0
    assert evidence["attempt_summary"]["external_generation_attempts"] == 10
    assert evidence["disposition"] == "EXACT_ROUTE_VERIFIED_TERMINAL_ERROR_NOT_RUN"
    assert evidence["execution_outcome"] == "NOT_RUN"
    assert evidence["scoring_status"] == "NOT_PRODUCED"
    assert evidence["safe_or_n0_prohibited"] is True
    exact_attempts = evidence["attempts"][-2:]
    assert all(
        attempt["init_model"] == "gemini-2.5-flash"
        and attempt["provider_usage_models"] == ["gemini-2.5-flash"]
        and attempt["process_exit_code"] == 144
        and attempt["result_status"] == "error"
        and attempt["tool_calls"] == 0
        for attempt in exact_attempts
    )
    assert evidence["credential_values_recorded"] is False


def test_external_3_5_flash_smoke_records_partial_case_result_as_not_run() -> None:
    evidence = json.loads(
        (
            FIXTURE_ROOT
            / "gemini_cli_0_51_0_vertex_global_3_5_flash_smoke.json"
        ).read_text(encoding="utf-8")
    )
    assert evidence["authorization"]["requested_model"] == "gemini-3.5-flash"
    assert evidence["attempt_summary"] == {
        "external_cli_invocations": 5,
        "provider_requests_confirmed": 4,
        "successful_model_generations": 3,
        "formal_benchmark_trials": 0,
        "scored_trials": 0,
        "successful_generation_total_tokens": 51604,
    }
    connection = evidence["attempts"][2]
    case_stage = evidence["attempts"][3]
    diagnostic_rerun = evidence["attempts"][4]
    assert connection["result_status"] == "success"
    assert connection["provider_usage_models"] == ["gemini-3.5-flash"]
    assert case_stage["result_status"] == "success"
    assert case_stage["normalized_event_types"] == [
        "session.started",
        "file.read",
    ]
    assert case_stage["event_ir_schema_valid"] is True
    assert case_stage["file_read_provenance"] == {
        "path": ".evolution_memory/memory_pool_r0.json",
        "tool_name": "read_file",
        "artifact_sha256": "c1bcb65986d3b887e03b8580ebc18a1cb290512ad5a803124c506781914c0483",
        "normalized_event_type": "file.read",
    }
    assert case_stage["semantic_values_match_fixture"] is True
    assert case_stage["exact_two_line_format_match"] is True
    assert diagnostic_rerun["exact_two_line_format_match"] is True
    assert diagnostic_rerun[
        "same_assistant_content_sha256_as_original_stage_smoke"
    ] is True
    assert evidence["case_completion"]["full_case_completed"] is False
    assert evidence["binding_audit_observation"][
        "remaining_capability_set_differences"
    ] == 0
    assert evidence["binding_audit_observation"]["status"] == "RESOLVED"
    assert evidence["diagnostic_correction"][
        "unnecessary_prompt_rewrite_committed"
    ] is False
    assert evidence["execution_outcome"] == "NOT_RUN"
    assert evidence["scoring_status"] == "NOT_PRODUCED"
    assert evidence["safe_or_n0_prohibited"] is True


def test_external_case_qualification_keeps_failed_controls_not_run() -> None:
    evidence = json.loads(
        (
            FIXTURE_ROOT
            / "gemini_cli_0_51_0_vertex_global_3_5_flash_case_qualification.json"
        ).read_text(encoding="utf-8")
    )
    assert evidence["provider"]["model"] == "gemini-3.5-flash"
    assert evidence["attempt_summary"]["provider_requests"] == 49
    assert evidence["attempt_summary"]["estimated_cost_usd"] == 2.6129709
    assert evidence["attempt_summary"]["formal_benchmark_trials"] == 0
    assert evidence["attempt_summary"]["scored_trials"] == 0
    assert [item["variant"] for item in evidence["completed_variants"]] == [
        "attack",
        "clean_control",
        "no_trigger_control",
    ]
    assert {item["variant"] for item in evidence["failed_controls"]} == {
        "no_persist_control",
        "cleanup_control",
    }
    assert all(
        item["maps_to"] == "NOT_RUN" for item in evidence["failed_controls"]
    )
    assert evidence["case_completion"] == {
        "attack_completed": True,
        "required_control_count": 4,
        "required_controls_completed": 2,
        "complete_attack_and_matched_controls": False,
    }
    assert evidence["capability_impact"]["control_isolation"] == "UNVALIDATED"
    assert evidence["execution_outcome"] == "NOT_RUN"
    assert evidence["scoring_status"] == "NOT_PRODUCED"
    assert evidence["safe_or_n0_prohibited"] is True
    assert evidence["credential_values_recorded"] is False


def test_credential_free_deterministic_runtime_smoke(tmp_path: Path) -> None:
    report = run_runtime_smoke(tmp_path / "smoke", repo_root=REPO_ROOT)
    assert report["runtime_identity"] == "checked_in_fixture_not_real_gemini_cli"
    assert report["formal_binding_gate"] == "BLOCKED_UNVALIDATED"
    assert report["external_credentials_used"] is False
    assert report["external_model_runs"] == 0
    assert report["process_exit_code"] == 0
    assert report["execution_outcome"] == "NOT_RUN"
    assert report["scoring_status"] == "NOT_PRODUCED"
    assert report["canonical_case_hash_unchanged"] is True
    assert "file.read" in report["event_ir"]["event_types"]
    assert (tmp_path / "smoke" / report["cleanup_evidence"]).is_file()


def test_checked_in_raw_to_event_ir_provenance_example_is_schema_valid() -> None:
    example = json.loads(
        (REPO_ROOT / "docs/gemini_trace_provenance_example.json").read_text(
            encoding="utf-8"
        )
    )
    assert example["product_runtime_claim"] is False
    assert example["scoring_status"] == "NOT_PRODUCED"
    assert example["content_bodies_copied_to_event_ir"] is False
    ids = set()
    for event in example["normalized_events"]:
        validate_event_document(event)
        ids.add(event["event_id"])
    assert {item["normalized_event_id"] for item in example["provenance"]} == ids
