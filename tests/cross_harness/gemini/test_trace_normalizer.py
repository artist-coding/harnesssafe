from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from infra.cross_harness.adapters.gemini import (
    GeminiHarnessAdapter,
    GeminiTraceNormalizationError,
)
from infra.cross_harness.adapters.gemini.trace import normalize_gemini_trace
from infra.cross_harness.bindings.gemini import load_gemini_all_bindings

from .conftest import write_jsonl


SHA = "0" * 64


def _adapter_materialization(
    tmp_path: Path, fake_gemini: Path, case_id: str, gemini_bindings, case_dirs,
    *, stage_index: int = 0
):
    run_dir = tmp_path / "run"
    adapter = GeminiHarnessAdapter(
        run_id="trace-fixture",
        run_dir=run_dir,
        stage_index=stage_index,
        executable=str(fake_gemini),
        model="fixture-model",
        base_environment={"PATH": str(tmp_path)},
    )
    materialized = adapter.materialize_binding(
        case_dir=case_dirs[case_id],
        binding_document=gemini_bindings[case_id],
        run_dir=run_dir,
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    return adapter, materialized, manifest


def _full_case(case_id: str) -> tuple[dict, Path]:
    repo_root = Path(__file__).resolve().parents[3]
    bindings = load_gemini_all_bindings(repo_root=repo_root)
    inventory = json.loads(
        (
            repo_root / "infra/cross_harness/bindings/gemini/active_328_v1.json"
        ).read_text(encoding="utf-8")
    )
    row = next(item for item in inventory["cases"] if item["case_id"] == case_id)
    return bindings[case_id], repo_root / row["case_dir"]


def _stream(stage, session_id, timestamp):
    write_jsonl(
        Path(stage["trace_path"]),
        [
            {
                "type": "init",
                "timestamp": timestamp,
                "session_id": session_id,
                "model": "fixture-model",
            },
            {
                "type": "result",
                "timestamp": timestamp,
                "status": "success",
                "stats": {"models": {"fixture-model": {"total_tokens": 1}}},
            },
        ],
    )


def test_skill_activation_normalizes_to_discovery_and_activation(
    tmp_path: Path, fake_gemini: Path, gemini_bindings, case_dirs
) -> None:
    case_id = "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path, fake_gemini, case_id, gemini_bindings, case_dirs
    )
    stage = manifest["stages"][0]
    _stream(stage, "session-skill", "2026-07-21T10:00:00Z")
    skill = manifest["skills"]["inventory-viewer"]
    write_jsonl(
        Path(stage["hook_trace_path"]),
        [
            {
                "kind": "skill_activated",
                "hook_event_name": "AfterTool",
                "session_id": "session-skill",
                "timestamp": "2026-07-21T10:00:01Z",
                "tool_name": "activate_skill",
                "arguments_sha256": SHA,
                "response_sha256": SHA,
                "skill_name": "inventory-viewer",
                "path": ".gemini/skills/inventory-viewer/SKILL.md",
                "sha256": skill["sha256"],
            }
        ],
    )
    events = list(
        adapter.normalize_trace(
            identity=adapter.detect_identity(),
            materialized=materialized,
            raw_trace_path=Path(stage["trace_path"]),
        )
    )
    assert [event["event_type"] for event in events] == [
        "session.started",
        "skill.discovered",
        "skill.activated",
    ]
    assert all("skill body" not in json.dumps(event) for event in events)


def test_skill_file_read_normalizes_to_discovery_and_activation(
    tmp_path: Path, fake_gemini: Path, gemini_bindings, case_dirs
) -> None:
    case_id = "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path, fake_gemini, case_id, gemini_bindings, case_dirs
    )
    stage = manifest["stages"][0]
    _stream(stage, "session-skill-read", "2026-07-21T10:00:00Z")
    skill = manifest["skills"]["inventory-viewer"]
    write_jsonl(
        Path(stage["hook_trace_path"]),
        [
            {
                "kind": "file_artifact",
                "hook_event_name": "AfterTool",
                "operation": "read",
                "path": ".gemini/skills/inventory-viewer/SKILL.md",
                "sha256": skill["sha256"],
                "session_id": "session-skill-read",
                "timestamp": "2026-07-21T10:00:01Z",
                "tool_name": "read_file",
                "arguments_sha256": SHA,
                "response_sha256": SHA,
            }
        ],
    )
    events = list(
        adapter.normalize_trace(
            identity=adapter.detect_identity(),
            materialized=materialized,
            raw_trace_path=Path(stage["trace_path"]),
        )
    )
    assert [event["event_type"] for event in events] == [
        "session.started",
        "file.read",
        "skill.discovered",
        "skill.activated",
    ]
    skill_event = next(event for event in events if event["event_type"] == "skill.activated")
    assert skill_event["attributes"]["activation_via"] == "skill_file_read"
    assert all("skill body" not in json.dumps(event) for event in events)


def test_generated_project_instruction_uses_prior_write_hash(
    tmp_path: Path, fake_gemini: Path
) -> None:
    case_id = "SK_E_sk_e_case_702_local_memory_state_attack_v2_claudemd_write_phase1_enhanced"
    binding, case_dir = _full_case(case_id)
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path,
        fake_gemini,
        case_id,
        {case_id: binding},
        {case_id: case_dir},
        stage_index=1,
    )
    stage0, stage1 = manifest["stages"]
    instruction_sha = "1" * 64
    skill = manifest["skills"]["project-setup"]
    _stream(stage0, "session-generate-instruction-0", "2026-07-21T10:00:00Z")
    _stream(stage1, "session-generate-instruction-1", "2026-07-21T10:01:00Z")
    write_jsonl(
        Path(stage0["hook_trace_path"]),
        [
            {
                "kind": "file_artifact",
                "hook_event_name": "AfterTool",
                "operation": "write",
                "path": "GEMINI.md",
                "sha256": instruction_sha,
                "session_id": "session-generate-instruction-0",
                "timestamp": "2026-07-21T10:00:01Z",
                "tool_name": "write_file",
                "arguments_sha256": SHA,
                "response_sha256": SHA,
            }
        ],
    )
    write_jsonl(
        Path(stage1["hook_trace_path"]),
        [
            {
                "kind": "instruction_loaded",
                "hook_event_name": "BeforeModel",
                "path": "GEMINI.md",
                "sha256": instruction_sha,
                "session_id": "session-generate-instruction-1",
                "timestamp": "2026-07-21T10:01:01Z",
            },
            {
                "kind": "file_artifact",
                "hook_event_name": "AfterTool",
                "operation": "read",
                "path": ".gemini/skills/project-setup/SKILL.md",
                "sha256": skill["sha256"],
                "session_id": "session-generate-instruction-1",
                "timestamp": "2026-07-21T10:01:02Z",
                "tool_name": "read_file",
                "arguments_sha256": SHA,
                "response_sha256": SHA,
            },
        ],
    )

    events = list(
        adapter.normalize_trace(
            identity=adapter.detect_identity(),
            materialized=materialized,
            raw_trace_path=Path(stage1["trace_path"]),
        )
    )
    event_types = [event["event_type"] for event in events]
    assert "instruction.loaded" in event_types
    instruction = next(
        event for event in events if event["event_type"] == "instruction.loaded"
    )
    assert instruction["attributes"]["activation_via"] == (
        "generated_project_instruction"
    )
    assert instruction["attributes"]["producer_stage_index"] == 0


def test_generated_project_instruction_file_read_counts_as_loaded(
    tmp_path: Path, fake_gemini: Path
) -> None:
    case_id = "SK_E_sk_e_case_702_local_memory_state_attack_v2_claudemd_write_phase1_enhanced"
    binding, case_dir = _full_case(case_id)
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path,
        fake_gemini,
        case_id,
        {case_id: binding},
        {case_id: case_dir},
        stage_index=1,
    )
    stage0, stage1 = manifest["stages"]
    instruction_sha = "1" * 64
    skill = manifest["skills"]["project-setup"]
    _stream(stage0, "session-instruction-read-0", "2026-07-21T10:00:00Z")
    _stream(stage1, "session-instruction-read-1", "2026-07-21T10:01:00Z")
    write_jsonl(
        Path(stage0["hook_trace_path"]),
        [
            {
                "kind": "file_artifact",
                "hook_event_name": "AfterTool",
                "operation": "write",
                "path": "GEMINI.md",
                "sha256": instruction_sha,
                "session_id": "session-instruction-read-0",
                "timestamp": "2026-07-21T10:00:01Z",
                "tool_name": "write_file",
                "arguments_sha256": SHA,
                "response_sha256": SHA,
            }
        ],
    )
    write_jsonl(
        Path(stage1["hook_trace_path"]),
        [
            {
                "kind": "file_artifact",
                "hook_event_name": "AfterTool",
                "operation": "read",
                "path": ".gemini/skills/project-setup/SKILL.md",
                "sha256": skill["sha256"],
                "session_id": "session-instruction-read-1",
                "timestamp": "2026-07-21T10:01:01Z",
                "tool_name": "read_file",
                "arguments_sha256": SHA,
                "response_sha256": SHA,
            },
            {
                "kind": "file_artifact",
                "hook_event_name": "AfterTool",
                "operation": "read",
                "path": "GEMINI.md",
                "sha256": instruction_sha,
                "session_id": "session-instruction-read-1",
                "timestamp": "2026-07-21T10:01:02Z",
                "tool_name": "read_file",
                "arguments_sha256": SHA,
                "response_sha256": SHA,
            },
        ],
    )

    events = list(
        adapter.normalize_trace(
            identity=adapter.detect_identity(),
            materialized=materialized,
            raw_trace_path=Path(stage1["trace_path"]),
        )
    )
    instruction = next(
        event for event in events if event["event_type"] == "instruction.loaded"
    )
    assert instruction["attributes"]["activation_via"] == (
        "generated_instruction_file_read"
    )
    assert instruction["attributes"]["producer_stage_index"] == 0


def test_missing_required_evidence_never_becomes_safe(
    tmp_path: Path, fake_gemini: Path, gemini_bindings, case_dirs
) -> None:
    case_id = "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path, fake_gemini, case_id, gemini_bindings, case_dirs
    )
    stage = manifest["stages"][0]
    _stream(stage, "session-missing", "2026-07-21T10:00:00Z")
    with pytest.raises(GeminiTraceNormalizationError, match="not scoreable") as exc:
        list(
            adapter.normalize_trace(
                identity=adapter.detect_identity(),
                materialized=materialized,
                raw_trace_path=Path(stage["trace_path"]),
            )
        )
    assert "SAFE" not in str(exc.value)
    assert "N0" not in str(exc.value)


def test_incomplete_stream_is_not_normalized_as_a_successful_trial(
    tmp_path: Path, fake_gemini: Path, gemini_bindings, case_dirs
) -> None:
    case_id = "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path, fake_gemini, case_id, gemini_bindings, case_dirs
    )
    stage = manifest["stages"][0]
    write_jsonl(
        Path(stage["trace_path"]),
        [{
            "type": "init",
            "timestamp": "2026-07-21T10:00:00Z",
            "session_id": "session-incomplete",
            "model": "fixture-model",
        }],
    )
    with pytest.raises(GeminiTraceNormalizationError, match="no successful terminal"):
        list(
            adapter.normalize_trace(
                identity=adapter.detect_identity(),
                materialized=materialized,
                raw_trace_path=Path(stage["trace_path"]),
            )
        )


def test_provider_model_routing_mismatch_is_not_scoreable(
    tmp_path: Path, fake_gemini: Path, gemini_bindings, case_dirs
) -> None:
    case_id = "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path, fake_gemini, case_id, gemini_bindings, case_dirs
    )
    stage = manifest["stages"][0]
    write_jsonl(
        Path(stage["trace_path"]),
        [
            {
                "type": "init",
                "timestamp": "2026-07-21T10:00:00Z",
                "session_id": "session-routed",
                "model": "fixture-model",
            },
            {
                "type": "result",
                "timestamp": "2026-07-21T10:00:01Z",
                "status": "success",
                "stats": {"models": {"another-model": {"total_tokens": 1}}},
            },
        ],
    )
    with pytest.raises(GeminiTraceNormalizationError, match="model usage"):
        list(
            adapter.normalize_trace(
                identity=adapter.detect_identity(),
                materialized=materialized,
                raw_trace_path=Path(stage["trace_path"]),
            )
        )


def test_mcp_proxy_and_file_hooks_form_a_correlated_multistage_trace(
    tmp_path: Path, fake_gemini: Path, gemini_bindings, case_dirs
) -> None:
    case_id = "F3_mcp_resource_runbook_005"
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path,
        fake_gemini,
        case_id,
        gemini_bindings,
        case_dirs,
        stage_index=1,
    )
    first, second = manifest["stages"]
    _stream(first, "session-mcp-1", "2026-07-21T10:00:00Z")
    _stream(second, "session-mcp-2", "2026-07-21T10:01:00Z")
    workspace = Path(manifest["workspace_dir"])
    carrier = workspace / "docs" / "mcp_runbook_005.md"
    carrier.parent.mkdir(parents=True, exist_ok=True)
    carrier.write_text("fixture carrier\n", encoding="utf-8")
    digest = hashlib.sha256(carrier.read_bytes()).hexdigest()
    write_jsonl(
        Path(first["hook_trace_path"]),
        [{
            "kind": "file_artifact", "operation": "write", "path": "docs/mcp_runbook_005.md",
            "sha256": digest, "timestamp": "2026-07-21T10:00:03Z", "session_id": "session-mcp-1",
            "tool_name": "write_file", "arguments_sha256": SHA, "response_sha256": SHA,
        }],
    )
    write_jsonl(
        Path(second["hook_trace_path"]),
        [{
            "kind": "file_artifact", "operation": "read", "path": "docs/mcp_runbook_005.md",
            "sha256": digest, "timestamp": "2026-07-21T10:01:01Z", "session_id": "session-mcp-2",
            "tool_name": "read_file", "arguments_sha256": SHA, "response_sha256": SHA,
        }],
    )
    write_jsonl(
        Path(first["mcp_trace_path"]),
        [
            {"kind": "mcp_server_initialized", "timestamp": "2026-07-21T10:00:01Z", "server": "deployment-health", "call_id": "init-1", "status": "connected", "response_sha256": SHA},
            {"kind": "mcp_tool_requested", "timestamp": "2026-07-21T10:00:02Z", "server": "deployment-health", "tool_name": "deployment_runbook", "call_id": "call-1", "arguments_sha256": SHA, "request_sha256": SHA},
            {"kind": "mcp_tool_result", "timestamp": "2026-07-21T10:00:02.500Z", "server": "deployment-health", "tool_name": "deployment_runbook", "call_id": "call-1", "status": "success", "result_sha256": SHA, "response_sha256": SHA},
        ],
    )
    events = list(
        adapter.normalize_trace(
            identity=adapter.detect_identity(),
            materialized=materialized,
            raw_trace_path=Path(second["trace_path"]),
        )
    )
    types = {event["event_type"] for event in events}
    assert {
        "mcp.server_initialized",
        "mcp.tool_requested",
        "mcp.tool_result",
        "file.write",
        "file.read",
    } <= types
    requested = next(event for event in events if event["event_type"] == "mcp.tool_requested")
    result = next(event for event in events if event["event_type"] == "mcp.tool_result")
    assert requested["tool"]["call_id"] == result["tool"]["call_id"] == "call-1"


def test_precompress_alone_cannot_be_projected_to_compaction(
    tmp_path: Path, fake_gemini: Path, gemini_bindings, case_dirs
) -> None:
    case_id = "SK_I_sk_i_case_101_permission_claim_spoofing_v1"
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path, fake_gemini, case_id, gemini_bindings, case_dirs
    )
    stage = manifest["stages"][0]
    _stream(stage, "session-compact", "2026-07-21T10:00:00Z")
    skill = manifest["skills"]["inventory-viewer"]
    write_jsonl(
        Path(stage["hook_trace_path"]),
        [
            {"kind": "pre_compress", "hook_event_name": "PreCompress", "session_id": "session-compact", "timestamp": "2026-07-21T10:00:01Z", "trigger": "auto"},
            {"kind": "skill_activated", "hook_event_name": "AfterTool", "session_id": "session-compact", "timestamp": "2026-07-21T10:00:02Z", "tool_name": "activate_skill", "arguments_sha256": SHA, "response_sha256": SHA, "skill_name": "inventory-viewer", "path": ".gemini/skills/inventory-viewer/SKILL.md", "sha256": skill["sha256"]},
        ],
    )
    modified = json.loads(json.dumps(gemini_bindings[case_id]))
    modified["harness_native_binding"]["gemini"]["expected_event_types"].append("session.compacted")
    with pytest.raises(GeminiTraceNormalizationError, match="PreCompress is advisory"):
        list(
            normalize_gemini_trace(
                identity=adapter.detect_identity(), materialized=materialized,
                manifest=manifest, binding_document=modified,
                raw_trace_path=Path(stage["trace_path"]), stage_index=0,
            )
        )


def test_exact_cross_stage_hash_emits_artifact_handoff(
    tmp_path: Path, fake_gemini: Path, gemini_bindings, case_dirs
) -> None:
    case_id = "T3_shared_artifact_supply_chain_001_shared_decision_artifact_decision"
    adapter, materialized, manifest = _adapter_materialization(
        tmp_path, fake_gemini, case_id, gemini_bindings, case_dirs, stage_index=1
    )
    first, second = manifest["stages"]
    _stream(first, "session-handoff-1", "2026-07-21T10:00:00Z")
    _stream(second, "session-handoff-2", "2026-07-21T10:01:00Z")
    handoff = Path(manifest["workspace_dir"]) / "reports" / "generated_decision.md"
    handoff.parent.mkdir(parents=True, exist_ok=True)
    handoff.write_text("exact handoff\n", encoding="utf-8")
    digest = hashlib.sha256(handoff.read_bytes()).hexdigest()
    common = {
        "kind": "file_artifact",
        "path": "reports/generated_decision.md",
        "sha256": digest,
        "tool_name": "fixture_file_tool",
        "arguments_sha256": SHA,
        "response_sha256": SHA,
    }
    write_jsonl(
        Path(first["hook_trace_path"]),
        [{**common, "operation": "write", "timestamp": "2026-07-21T10:00:01Z", "session_id": "session-handoff-1"}],
    )
    write_jsonl(
        Path(second["hook_trace_path"]),
        [{**common, "operation": "read", "timestamp": "2026-07-21T10:01:01Z", "session_id": "session-handoff-2"}],
    )
    events = list(
        adapter.normalize_trace(
            identity=adapter.detect_identity(), materialized=materialized,
            raw_trace_path=Path(second["trace_path"]),
        )
    )
    handoff_event = next(event for event in events if event["event_type"] == "artifact.handoff")
    assert handoff_event["artifact"]["sha256"] == digest
    assert handoff_event["attributes"]["producer_stage_index"] == 0


def test_hook_recorder_hashes_content_instead_of_copying_it(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifact = workspace / "private.txt"
    artifact.write_text("sensitive fixture body", encoding="utf-8")
    event_log = tmp_path / "hooks.jsonl"
    script = Path(__file__).resolve().parents[3] / "infra" / "cross_harness" / "adapters" / "gemini" / "hook_capture.py"
    payload = {
        "session_id": "session-private",
        "timestamp": "2026-07-21T10:00:00Z",
        "hook_event_name": "AfterTool",
        "tool_name": "read_file",
        "tool_input": {"file_path": "private.txt"},
        "tool_response": {"llmContent": "sensitive fixture body"},
    }
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--event-log",
            str(event_log),
            "--workspace",
            str(workspace),
        ],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(result.stdout) == {}
    recorded = event_log.read_text(encoding="utf-8")
    assert "sensitive fixture body" not in recorded
    assert hashlib.sha256(artifact.read_bytes()).hexdigest() in recorded
