from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess

import pytest

from infra.cross_harness.adapters.opencode.attack_only_runner import (
    build_attack_readiness,
    execute_attack_case,
    run_batch,
)
from infra.cross_harness.adapters.opencode.materializer import sha256_file
from infra.cross_harness.adapters.opencode.provider import load_provider_profile
from infra.cross_harness.bindings.opencode import load_opencode_smoke_bindings

from .fixtures.openai_fixture_server import OpenAIFixtureServer


REPO_ROOT = Path(__file__).resolve().parents[3]


def _profile(tmp_path: Path):
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
    return path, load_provider_profile(path)


def test_readiness_is_fail_closed_without_provider_or_conformance(
    tmp_path: Path,
) -> None:
    readiness = build_attack_readiness(
        repo_root=REPO_ROOT,
        executable="/missing/opencode",
        work_root=tmp_path / "run",
        profile=None,
        profile_path=None,
        conformance_path=None,
        environ={"PATH": "/usr/bin:/bin"},
    )
    assert readiness["summary"]["case_count"] == 16
    assert readiness["summary"]["attack_status_counts"] == {"NOT_RUN": 16}
    assert readiness["summary"]["binding_status_counts"] == {
        "unvalidated": 11,
        "unsupported": 5,
    }
    assert readiness["summary"]["provider_ready"] is False
    assert readiness["protocol"]["scoring"]["status_during_execution"] == (
        "NOT_PRODUCED"
    )
    assert all(
        row["execution_outcome"] == "NOT_RUN"
        and row["scoring_status"] == "NOT_PRODUCED"
        for row in readiness["cases"]
    )


def test_non_ready_case_writes_not_run_without_invocation(
    tmp_path: Path,
) -> None:
    profile_path, profile = _profile(tmp_path)
    readiness = build_attack_readiness(
        repo_root=REPO_ROOT,
        executable="/missing/opencode",
        work_root=tmp_path / "preflight",
        profile=profile,
        profile_path=profile_path,
        conformance_path=None,
        environ={"PATH": "/usr/bin:/bin"},
    )
    case_row = next(
        row
        for row in readiness["cases"]
        if row["case_id"] == "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
    )
    bindings = load_opencode_smoke_bindings(repo_root=REPO_ROOT)
    work_root = tmp_path / "batch"
    outcome = execute_attack_case(
        case_row=case_row,
        binding=bindings[case_row["case_id"]],
        case_dir=REPO_ROOT / case_row["case_dir"],
        work_root=work_root,
        protocol=readiness["protocol"],
        profile=profile,
        executable="/missing/opencode",
        conformance_path=tmp_path / "missing-conformance.json",
        environ={
            "PATH": "/usr/bin:/bin",
            "OPENCODE_TEST_API_KEY": "not-recorded",
        },
        timeout_seconds=1,
    )
    assert outcome["attack_status"] == "NOT_RUN"
    assert outcome["failure_type"] == "pre_execution_gate"
    assert outcome["scoring_status"] == "NOT_PRODUCED"
    assert outcome["safe_or_n0_prohibited"] is True
    assert not list(work_root.rglob("materialized_case"))


def test_batch_case_filter_keeps_scoring_separate(tmp_path: Path) -> None:
    profile_path, profile = _profile(tmp_path)
    readiness = build_attack_readiness(
        repo_root=REPO_ROOT,
        executable="/missing/opencode",
        work_root=tmp_path / "preflight",
        profile=profile,
        profile_path=profile_path,
        conformance_path=None,
        environ={"PATH": "/usr/bin:/bin"},
    )
    case_id = "F1_memory_evolution_001_customerservice_01_refund_case_overgeneralization_round1"
    report = run_batch(
        readiness=readiness,
        repo_root=REPO_ROOT,
        work_root=tmp_path / "batch",
        profile=profile,
        executable="/missing/opencode",
        conformance_path=tmp_path / "missing-conformance.json",
        environ={
            "PATH": "/usr/bin:/bin",
            "OPENCODE_TEST_API_KEY": "not-recorded",
        },
        timeout_seconds=1,
        case_ids=[case_id],
    )
    assert report["selected_case_count"] == 1
    assert report["outcome_counts"] == {"NOT_RUN": 1}
    assert report["scoring_status"] == "NOT_PRODUCED"
    assert report["outcomes"][0]["case_id"] == case_id


def test_real_runner_completes_when_expected_attack_event_is_absent(
    tmp_path: Path,
) -> None:
    executable = os.environ.get("OPENCODE_REAL_EXECUTABLE")
    if not executable:
        pytest.skip("OPENCODE_REAL_EXECUTABLE is not configured")
    resolved = Path(executable).resolve()
    version = subprocess.run(
        [executable, "--version"],
        text=True,
        capture_output=True,
        check=True,
    ).stdout.strip()
    required = [
        "headless_execution",
        "structured_trace",
        "workspace_isolation",
        "skill_discovery",
        "skill_activation_trace",
    ]
    conformance_path = tmp_path / "conformance.json"
    conformance_path.write_text(
        json.dumps(
            {
                "schema_name": "safety_bench_opencode_capability_conformance",
                "schema_version": 1,
                "harness_id": "opencode",
                "harness_version": version,
                "executable_sha256": sha256_file(resolved),
                "generated_at": "2026-07-25T00:00:00+00:00",
                "capabilities": {
                    capability: {
                        "status": "SUPPORTED",
                        "executed": True,
                        "evidence": [f"test-local-fixture:{capability}"],
                        "reason": "",
                    }
                    for capability in required
                },
            }
        ),
        encoding="utf-8",
    )
    with OpenAIFixtureServer(request_log=tmp_path / "requests.jsonl") as server:
        profile_path = tmp_path / "provider.json"
        profile_path.write_text(
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
                    "base_url": server.base_url,
                    "credential_env": "OPENCODE_TEST_API_KEY",
                }
            ),
            encoding="utf-8",
        )
        profile = load_provider_profile(
            profile_path, allow_insecure_loopback=True
        )
        case_id = "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
        binding = copy.deepcopy(
            load_opencode_smoke_bindings(repo_root=REPO_ROOT)[case_id]
        )
        binding["supported_harnesses"]["opencode"]["status"] = "conditional"
        config = binding["harness_native_binding"]["opencode"]["config"]
        config["disposition"] = "READY"
        config["blocking_reasons"] = []
        config["stages"][0]["prompt"] = "[fixture:skill inventory-viewer]"
        binding["harness_native_binding"]["opencode"][
            "expected_event_types"
        ].append("file.write")
        inventory = json.loads(
            (REPO_ROOT / "docs/codex_conformance_smoke_v1.json").read_text()
        )
        source = next(
            row for row in inventory["cases"] if row["case_id"] == case_id
        )
        case_row = {
            "manifest_index": 3,
            "case_id": case_id,
            "case_dir": source["case_dir"],
            "case_meta_sha256": source["case_meta_sha256"],
            "required_capabilities": required,
            "stage_count": 1,
            "attack_status": "ATTACK_READY",
            "blocking_reasons": [],
        }
        outcome = execute_attack_case(
            case_row=case_row,
            binding=binding,
            case_dir=REPO_ROOT / source["case_dir"],
            work_root=tmp_path / "batch",
            protocol={"protocol_sha256": "a" * 64},
            profile=profile,
            executable=executable,
            conformance_path=conformance_path,
            environ={
                "PATH": os.environ.get("PATH", ""),
                "OPENCODE_TEST_API_KEY": "fixture-only",
            },
            timeout_seconds=45,
        )
    assert outcome["attack_status"] == "ATTACK_COMPLETED"
    assert outcome["stage_count_completed"] == 1
    assert set(outcome["required_event_types"]) == {
        "skill.discovered",
        "skill.activated",
        "file.write",
    }
    assert outcome["missing_expected_event_types"] == ["file.write"]
    assert "file.write" not in outcome["observed_event_types"]
    assert outcome["scoring_status"] == "NOT_PRODUCED"
    assert outcome["safe_or_n0_prohibited"] is True
