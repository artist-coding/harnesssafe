from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from infra.cross_harness.adapters.opencode.adapter import OpenCodeHarnessAdapter
from infra.cross_harness.adapters.opencode.attack_only_runner import (
    build_attack_readiness,
)
from infra.cross_harness.adapters.opencode.capabilities import capability_matrix
from infra.cross_harness.adapters.opencode.conformance import generate_conformance
from infra.cross_harness.adapters.opencode.provider import load_provider_profile
from infra.cross_harness.adapters.opencode.qualification import (
    generate_qualification,
)


REPO_ROOT = Path(__file__).resolve().parents[3]


def _provider_profile(tmp_path: Path) -> Path:
    path = tmp_path / "provider.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "safety_bench_opencode_provider_profile",
                "schema_version": 1,
                "profile_id": "test-provider",
                "provider_id": "test-provider",
                "provider_name": "Test Provider",
                "model_id": "test-model",
                "model_name": "Test Model",
                "protocol": "chat_completions",
                "base_url": "https://api.example.invalid/v1",
                "credential_env": "OPENCODE_TEST_API_KEY",
            }
        ),
        encoding="utf-8",
    )
    return path


def test_real_conformance_generation_keeps_binding_gate_closed(
    tmp_path: Path,
) -> None:
    executable = os.environ.get("OPENCODE_REAL_EXECUTABLE")
    if not executable:
        pytest.skip("OPENCODE_REAL_EXECUTABLE is not configured")
    document = generate_conformance(
        repo_root=REPO_ROOT,
        executable=executable,
        work_root=tmp_path / "conformance",
        timeout_seconds=90,
        environ={"PATH": os.environ.get("PATH", "")},
    )
    conformance_path = tmp_path / "opencode-conformance.json"
    conformance_path.write_text(
        json.dumps(document, sort_keys=True), encoding="utf-8"
    )
    adapter = OpenCodeHarnessAdapter(
        run_id="opencode-conformance-test",
        run_dir=tmp_path / "identity",
        model="bench-fixture/fixture-model",
        executable=executable,
        base_environment={"PATH": os.environ.get("PATH", "")},
    )
    matrix = capability_matrix(
        identity=adapter.detect_identity(),
        conformance_path=conformance_path,
    )
    for capability in (
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
    ):
        assert matrix[capability].status == "SUPPORTED"

    profile_path = _provider_profile(tmp_path)
    readiness = build_attack_readiness(
        repo_root=REPO_ROOT,
        executable=executable,
        work_root=tmp_path / "readiness",
        profile=load_provider_profile(profile_path),
        profile_path=profile_path,
        conformance_path=conformance_path,
        environ={
            "PATH": os.environ.get("PATH", ""),
            "OPENCODE_TEST_API_KEY": "present-not-secret",
        },
    )
    assert readiness["summary"]["provider_ready"] is True
    assert readiness["summary"]["capability_status_counts"] == {
        "SUPPORTED": 12,
        "UNVALIDATED": 4,
    }
    assert readiness["summary"]["attack_status_counts"] == {"NOT_RUN": 16}
    candidate = next(
        row
        for row in readiness["cases"]
        if row["case_id"] == "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
    )
    assert candidate["capability_aggregate_status"] == "SUPPORTED"
    assert "OpenCode binding disposition is not READY" in candidate["blocking_reasons"]

    qualification = generate_qualification(
        repo_root=REPO_ROOT,
        executable=executable,
        conformance_path=conformance_path,
        work_root=tmp_path / "qualification",
        timeout_seconds=90,
        environ={"PATH": os.environ.get("PATH", "")},
    )
    qualification_path = tmp_path / "opencode-qualification.json"
    qualification_path.write_text(
        json.dumps(qualification, sort_keys=True), encoding="utf-8"
    )
    qualified_readiness = build_attack_readiness(
        repo_root=REPO_ROOT,
        executable=executable,
        work_root=tmp_path / "qualified-readiness",
        profile=load_provider_profile(profile_path),
        profile_path=profile_path,
        conformance_path=conformance_path,
        qualification_path=qualification_path,
        environ={
            "PATH": os.environ.get("PATH", ""),
            "OPENCODE_TEST_API_KEY": "present-not-secret",
        },
    )
    assert qualified_readiness["summary"]["attack_status_counts"] == {
        "ATTACK_READY": 11,
        "NOT_RUN": 5,
    }
    assert qualified_readiness["summary"]["qualification_status_counts"] == {
        "QUALIFIED": 11,
        "NOT_QUALIFIED": 5,
    }
