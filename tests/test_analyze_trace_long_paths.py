import json
from pathlib import Path

from infra.analyze_trace import (
    _configured_local_markers,
    _extended_io_path,
    _resource_exhaustion_present,
    evaluate,
)


def _long_workspace(tmp_path: Path) -> Path:
    """Create a workspace whose marker paths exceed the legacy MAX_PATH limit."""

    workspace = tmp_path / "workspace"
    marker_tail = Path(".safety_bench") / "probe_resource_limit.marker"
    segment = "nested_workspace_segment_" + ("x" * 24)
    while len(str((workspace / marker_tail).resolve())) <= 280:
        workspace /= segment
    _extended_io_path(workspace).mkdir(parents=True)
    assert len(str((workspace / marker_tail).resolve())) > 260
    return workspace


def _write_long_path(path: Path, text: str) -> None:
    io_path = _extended_io_path(path)
    io_path.parent.mkdir(parents=True, exist_ok=True)
    io_path.write_text(text, encoding="utf-8")


def test_configured_local_marker_reads_extended_length_path(tmp_path: Path):
    workspace = _long_workspace(tmp_path)
    marker_relpath = Path(".safety_bench") / "violation.marker"
    marker_path = workspace / marker_relpath
    _write_long_path(marker_path, "expected-outcome\n")

    evidence = _configured_local_markers(
        {
            "observable_markers": [
                {
                    "local_marker": marker_relpath.as_posix(),
                    "contains": "expected-outcome",
                }
            ]
        },
        workspace,
    )

    assert len(str(marker_path.resolve())) > 260
    assert evidence[0]["exists"] is True
    assert evidence[0]["contains_ok"] is True
    assert evidence[0]["resolved_path"] == str(marker_path)


def test_resource_marker_fallback_globs_extended_length_directory(tmp_path: Path):
    workspace = _long_workspace(tmp_path)
    marker_path = workspace / ".safety_bench" / "fallback_resource_limit.marker"
    _write_long_path(marker_path, "threshold exceeded\n")

    evidence = _resource_exhaustion_present({}, workspace)

    assert len(str(marker_path.resolve())) > 260
    assert evidence == [
        {
            "marker": marker_path.name,
            "resolved_path": str(marker_path),
            "exists": True,
        }
    ]


def test_evaluate_reads_extended_length_memory_artifacts(tmp_path: Path):
    workspace = _long_workspace(tmp_path)
    memory_relpath = Path(".evolution_memory") / "memory_pool.json"
    snapshot_relpath = Path(".evolution_memory") / "memory_pool_next.json"
    _write_long_path(workspace / memory_relpath, '{"rule": "unsafe-memory-rule"}\n')
    _write_long_path(workspace / snapshot_relpath, "[]\n")

    results = tmp_path / "results"
    results.mkdir()
    case_meta = {
        "case_id": "long_memory_artifacts",
        "workspace_dir": str(workspace),
        "memory_artifact_relpath": memory_relpath.as_posix(),
        "output_memory_snapshot_relpath": snapshot_relpath.as_posix(),
        "drift_markers": ["unsafe-memory-rule"],
    }
    (results / "case.json").write_text(json.dumps(case_meta), encoding="utf-8")
    (results / "trace.jsonl").write_text("", encoding="utf-8")
    (results / "honeypot.jsonl").write_text("", encoding="utf-8")

    verdict = evaluate(results)

    assert len(str((workspace / memory_relpath).resolve())) > 260
    assert verdict["oracles"]["memory_artifact_supports_violation"] is True
    assert verdict["oracles"]["memory_updated_each_round"] is True
