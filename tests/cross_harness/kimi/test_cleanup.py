from __future__ import annotations

import json
from pathlib import Path

import pytest

from infra.cross_harness.adapters.kimi import KimiHarnessAdapter, KimiMaterializationError


def test_cleanup_terminates_and_removes_only_current_run_resources(
    tmp_path: Path, reviewed_case_and_binding
) -> None:
    case_dir, binding = reviewed_case_and_binding
    terminated: list[int] = []

    def inspect(pid: int):
        run_id = "cleanup-001" if pid != 42004 else "other-live-run"
        argv = (
            ["/fixture/kimi", "/tmp/no-owned-token"]
            if pid == 42005
            else ["/fixture/kimi", "/tmp/run-kimi-cleanup-001/config"]
        )
        return {
            "start_time": "111",
            "environ": {
                "SAFETY_BENCH_HARNESS": "kimi",
                "SAFETY_BENCH_RUN_ID": run_id,
            },
            "argv": argv,
        }

    adapter = KimiHarnessAdapter(
        run_id="cleanup-001",
        state_root=tmp_path / "state",
        executable="/fixture/not-needed-for-cleanup",
        process_inspector=inspect,
        process_terminator=terminated.append,
    )
    materialized = adapter.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=adapter.run_dir,
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    stage = manifest["stages"][0]
    pid_path = Path(stage["pid_record"])
    pid_path.write_text(
        json.dumps(
            {
                "processes": [
                    {
                        "pid": 42001,
                        "run_id": "cleanup-001",
                        "harness_id": "kimi",
                        "start_time": "111",
                    },
                    {
                        "pid": 42002,
                        "run_id": "different-run",
                        "harness_id": "kimi",
                        "start_time": "111",
                    },
                    {
                        "pid": 42003,
                        "run_id": "cleanup-001",
                        "harness_id": "kimi",
                        "start_time": "999",
                    },
                    {
                        "pid": 42004,
                        "run_id": "cleanup-001",
                        "harness_id": "kimi",
                        "start_time": "111",
                    },
                    {
                        "pid": 42005,
                        "run_id": "cleanup-001",
                        "harness_id": "kimi",
                        "start_time": "111",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    trace_path = Path(stage["trace_path"])
    trace_path.write_text("preserve raw trace\n", encoding="utf-8")
    result_sentinel = Path(stage["result_dir"]) / "result.json"
    result_sentinel.write_text("{}\n", encoding="utf-8")
    workspace_sentinel = Path(manifest["materialized"]["workspace_dir"]) / "README.md"

    other_kimi = tmp_path / "run-kimi-other-run" / "sentinel"
    claude = tmp_path / "claude-state" / "sentinel"
    codex = tmp_path / "codex-state" / "sentinel"
    user_kimi = tmp_path / ".kimi-code" / "config.toml"
    for sentinel in (other_kimi, claude, codex, user_kimi):
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text("unchanged", encoding="utf-8")

    cleanup_paths = [Path(path) for path in manifest["cleanup_paths"]]
    assert all(path.exists() for path in cleanup_paths)
    adapter.cleanup(materialized=materialized)

    assert terminated == [42001]
    assert all(not path.exists() for path in cleanup_paths)
    assert trace_path.read_text(encoding="utf-8") == "preserve raw trace\n"
    assert result_sentinel.is_file()
    assert workspace_sentinel.is_file()
    assert materialized.manifest_path.is_file()
    assert all(sentinel.read_text(encoding="utf-8") == "unchanged" for sentinel in (
        other_kimi,
        claude,
        codex,
        user_kimi,
    ))
    report = adapter.evidence_dir / "cleanup-kimi-cleanup-001.json"
    document = json.loads(report.read_text(encoding="utf-8"))
    assert document["terminated_pids"] == [42001]
    assert document["skipped_pids"] == [
        {"pid": 42002, "reason": "record_owner_mismatch"},
        {"pid": 42003, "reason": "start_time_mismatch"},
        {"pid": 42004, "reason": "environment_owner_mismatch"},
        {"pid": 42005, "reason": "argv_owner_mismatch"},
    ]


def test_cleanup_rejects_manifest_path_escape(
    tmp_path: Path, reviewed_case_and_binding
) -> None:
    case_dir, binding = reviewed_case_and_binding
    adapter = KimiHarnessAdapter(
        run_id="cleanup-escape",
        state_root=tmp_path / "state",
        process_inspector=lambda _pid: None,
        process_terminator=lambda _pid: None,
    )
    materialized = adapter.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=adapter.run_dir,
    )
    outside = tmp_path / "outside-sentinel"
    outside.write_text("keep", encoding="utf-8")
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    manifest["cleanup_paths"] = [str(outside)]
    materialized.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(KimiMaterializationError, match="integrity check failed"):
        adapter.cleanup(materialized=materialized)

    assert outside.read_text(encoding="utf-8") == "keep"
