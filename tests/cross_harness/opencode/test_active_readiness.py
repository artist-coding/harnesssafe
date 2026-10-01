from __future__ import annotations

import json
from pathlib import Path

from infra.cross_harness.adapter import HarnessIdentity
from infra.cross_harness.contract import CAPABILITIES
from infra.cross_harness.adapters.opencode import active_readiness
from infra.cross_harness.adapters.opencode.active_readiness import (
    build_active_readiness,
)
from infra.cross_harness.adapters.opencode.active_attack_runner import (
    active_binding_document,
)
from infra.cross_harness.adapters.opencode.bench_inventory import build_inventory
from infra.cross_harness.adapters.opencode.provider import OpenCodeProviderProfile


REPO_ROOT = Path(__file__).resolve().parents[3]


SUPPORTED_CAPABILITIES = {
    "headless_execution",
    "structured_trace",
    "workspace_isolation",
    "fresh_process",
    "skill_discovery",
    "skill_activation_trace",
    "instruction_loading",
    "mcp_configuration",
    "mcp_health_trace",
    "mcp_tool_trace",
    "session_resume",
    "subagent_delegation",
    "artifact_hash_provenance",
}


def test_opencode_active_328_inventory_counts() -> None:
    document = build_inventory(REPO_ROOT)

    assert document["summary"]["case_count"] == 328
    assert document["summary"]["stage_count"] == 690
    assert document["summary"]["suite_counts"] == {
        "v2_skill_runtime": 84,
        "v2_tool_mcp_runtime": 70,
        "F1_memory_runtime": 72,
        "T2_memory_to_skill": 36,
        "T3_subagent_poisoning": 30,
        "T3_compaction_resume_poisoning": 30,
        "T3_shared_artifact_supply_chain": 6,
    }
    assert document["summary"]["scoring_status"] == "NOT_PRODUCED"


def test_active_readiness_marks_capability_gaps_not_run(
    tmp_path: Path, monkeypatch
) -> None:
    executable_sha256 = "0" * 64
    conformance_path = tmp_path / "opencode-conformance.json"
    conformance_path.write_text(
        json.dumps(
            {
                "schema_name": "safety_bench_opencode_capability_conformance",
                "schema_version": 1,
                "harness_id": "opencode",
                "harness_version": "1.18.4",
                "executable_sha256": executable_sha256,
                "generated_at": "2026-07-25T00:00:00+00:00",
                "capabilities": {
                    capability: (
                        {
                            "status": "SUPPORTED",
                            "executed": True,
                            "evidence": [f"unit:{capability}"],
                            "reason": "",
                        }
                        if capability in SUPPORTED_CAPABILITIES
                        else {
                            "status": "UNVALIDATED",
                            "executed": False,
                            "evidence": [],
                            "reason": f"unit fail-closed: {capability}",
                        }
                    )
                    for capability in CAPABILITIES
                },
            }
        ),
        encoding="utf-8",
    )

    def fake_detect_identity(**_: object):
        return (
            HarnessIdentity(
                harness_id="opencode",
                version="1.18.4",
                executable="/unit/opencode",
                feature_flags={
                    "binary_sha256": executable_sha256,
                    "headless_run": True,
                    "json_trace": True,
                    "session_resume": True,
                },
            ),
            None,
        )

    monkeypatch.setattr(active_readiness, "_detect_identity", fake_detect_identity)
    profile = OpenCodeProviderProfile(
        profile_id="unit",
        provider_id="unit",
        provider_name="Unit",
        model_id="model",
        model_name="model",
        protocol="chat_completions",
        base_url="https://example.invalid/v1",
        credential_env="OPENCODE_BENCH_API_KEY",
    )

    document = build_active_readiness(
        repo_root=REPO_ROOT,
        executable="/unit/opencode",
        work_root=tmp_path,
        profile=profile,
        profile_path=None,
        conformance_path=conformance_path,
        environ={"OPENCODE_BENCH_API_KEY": "dummy"},
    )

    assert document["summary"]["attack_status_counts"] == {
        "ATTACK_READY": 258,
        "NOT_RUN": 70,
    }
    assert document["summary"]["not_run_blocker_group_counts"] == {
        "durable_memory_write + durable_memory_retrieval": 52,
        "durable_memory_write + durable_memory_retrieval + session_compaction": 3,
        "session_compaction": 15,
    }
    assert document["summary"]["experiment_status_counts"] == {
        "EXPERIMENT_READY": 258,
        "NOT_EXPERIMENTABLE": 70,
    }
    assert document["summary"]["not_experimentable_blocker_class_counts"] == {
        "opencode_missing_durable_memory_surface": 52,
        "opencode_missing_durable_memory_surface_and_session_compaction_evidence": 3,
        "opencode_missing_session_compaction_evidence": 15,
    }
    assert {
        row["experiment_status"]
        for row in document["cases"]
        if row["attack_status"] == "NOT_RUN"
    } == {"NOT_EXPERIMENTABLE"}
    assert document["summary"]["scoring_status"] == "NOT_PRODUCED"


def test_active_binding_allows_only_bwrap_scoped_external_paths() -> None:
    inventory = build_inventory(REPO_ROOT)
    row = next(
        case
        for case in inventory["cases"]
        if case["case_id"]
        == "F1_memory_evolution_040_mental_01_historical_label_fixation_round1"
    )
    binding = active_binding_document(
        inventory_row=row,
        case_dir=REPO_ROOT / row["case_dir"],
    )

    permissions = binding["harness_native_binding"]["opencode"]["config"][
        "permissions"
    ]
    assert permissions["external_directory"] == "allow"
