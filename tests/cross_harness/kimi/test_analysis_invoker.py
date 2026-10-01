from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

import pytest

from infra.cross_harness.adapters.kimi.analysis_invoker import (
    ANALYSIS_PROVENANCE_SCHEMA_NAME,
    COMPLETED_TRIAL_SCHEMA_NAME,
    KimiAnalysisInvocationError,
    KimiAnalysisInvocationRequest,
    PinnedAnalysisInput,
    invoke_kimi_shared_analyzer,
)
from infra.cross_harness.adapters.kimi.analyzer_projection import (
    PROJECTION_SCHEMA_NAME,
    SEMANTIC_TRANSLATION,
)


BINARY_SHA256 = "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_sha(value: Mapping[str, Any]) -> str:
    return _sha(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )


def _write(path: Path, content: bytes) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return {
        "path": str(path.resolve()),
        "sha256": _sha(content),
        "bytes": len(content),
        "line_count": len(content.splitlines()),
    }


def _write_json(path: Path, document: Mapping[str, Any]) -> PinnedAnalysisInput:
    content = json.dumps(
        document, indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return PinnedAnalysisInput(path, _sha(content), len(content.splitlines()))


def _resign(document: dict[str, Any]) -> None:
    document["manifest_payload_sha256"] = _canonical_sha(
        {
            key: value
            for key, value in document.items()
            if key != "manifest_payload_sha256"
        }
    )


def _executable() -> Path:
    executable = Path("/usr/local/bin/kimi")
    assert executable.exists()
    resolved = executable.resolve(strict=True)
    assert _sha(resolved.read_bytes()) == BINARY_SHA256
    return resolved


def _fixture(
    tmp_path: Path, *, analyzer_failure: bool = False
) -> tuple[KimiAnalysisInvocationRequest, dict[str, Path]]:
    run_root = tmp_path / "kimi-run-analysis-001"
    trial_root = run_root / "trial-kimi-analysis-001-attack-attempt-001"
    projection_root = trial_root / "projection-kimi-analysis-001"
    workspace = trial_root / "workspace-kimi-analysis-001"
    workspace.mkdir(parents=True)
    os.chmod(run_root, 0o700)
    case = (
        {"case_id": "case-analysis"}
        if analyzer_failure
        else {
            "case_id": "case-analysis",
            "workspace_dir": str(workspace.resolve()),
            "canary_token": "",
            "plugin_skills": [],
            "plugin_commands": [],
            "mcp_servers": [],
            "mcp_tools": [],
            "stage_index": 1,
            "stage_name": "main",
        }
    )
    case_bytes = json.dumps(case, sort_keys=True).encode() + b"\n"
    trace_bytes = (
        json.dumps(
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "fixed benign fixture"}],
                },
                "kimi_projection_source": {
                    "path": str(trial_root / "stdout-kimi-analysis-001.jsonl"),
                    "line": 1,
                    "sha256": _sha(b'{"role":"assistant"}\n'),
                    "raw_event_type": "assistant.visible_text",
                    "projection_role": "assistant_authored_visible_text_only",
                    "semantic_translation": SEMANTIC_TRANSLATION,
                },
            },
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    empty = b""

    source_case = _write(trial_root / "source-case-kimi-analysis-001.json", case_bytes)
    source_stdout = _write(
        trial_root / "stdout-kimi-analysis-001.jsonl",
        b'{"role":"assistant"}\n',
    )
    event_ir = _write(trial_root / "event-ir-kimi-analysis-001.jsonl", empty)
    outputs = [
        _write(projection_root / "case.json", case_bytes),
        _write(projection_root / "trace.jsonl", trace_bytes),
        _write(projection_root / "honeypot.jsonl", empty),
        _write(projection_root / "stages" / "000_main" / "case.json", case_bytes),
        _write(projection_root / "stages" / "000_main" / "trace.jsonl", trace_bytes),
        _write(projection_root / "stages" / "000_main" / "honeypot.jsonl", empty),
    ]
    projection: dict[str, Any] = {
        "schema_name": PROJECTION_SCHEMA_NAME,
        "schema_version": 1,
        "semantic_translation": SEMANTIC_TRANSLATION,
        "harness_id": "kimi",
        "harness_version": "0.26.0",
        "binary_sha256": BINARY_SHA256,
        "run_id": "analysis-001",
        "case_id": "case-analysis",
        "trial_id": "attack-attempt-001",
        "run_root": str(trial_root.resolve()),
        "projection_root": str(projection_root.resolve()),
        "inputs": [
            {
                "kind": "case_source",
                "path": source_case["path"],
                "sha256": source_case["sha256"],
                "line_count": source_case["line_count"],
            },
            {
                "kind": "kimi_stdout",
                "path": source_stdout["path"],
                "sha256": source_stdout["sha256"],
                "line_count": source_stdout["line_count"],
            },
            {
                "kind": "event_ir_v1",
                "path": event_ir["path"],
                "sha256": event_ir["sha256"],
                "line_count": event_ir["line_count"],
            },
        ],
        "outputs": outputs,
        "event_ir_sha256": event_ir["sha256"],
        "record_counts": {
            "projected_trace": 1,
            "projected_honeypot": 0,
            "event_ir": 0,
        },
        "claims": {
            "native_trace": False,
            "analyzer_compatibility_only": True,
            "raw_evidence_modified": False,
        },
    }
    _resign(projection)
    projection_input = _write_json(
        projection_root / "projection-manifest-kimi-analysis-001.json", projection
    )
    trial: dict[str, Any] = {
        "schema_name": COMPLETED_TRIAL_SCHEMA_NAME,
        "schema_version": 1,
        "harness_id": "kimi",
        "harness_version": "0.26.0",
        "run_id": "analysis-001",
        "case_id": "case-analysis",
        "trial_id": "attack-attempt-001",
        "outcome": "COMPLETED",
        "return_code": 0,
        "failure_category": None,
        "retry_eligible": False,
        "executable": {
            "path": str(_executable()),
            "sha256": BINARY_SHA256,
        },
        "event_ir": {
            "path": event_ir["path"],
            "sha256": event_ir["sha256"],
        },
        "projection_manifest": {
            "path": str(projection_input.path.resolve()),
            "sha256": projection_input.sha256,
        },
    }
    _resign(trial)
    trial_input = _write_json(
        trial_root / "completed-trial-kimi-analysis-001.json", trial
    )
    request = KimiAnalysisInvocationRequest(
        run_id="analysis-001",
        case_id="case-analysis",
        trial_id="attack-attempt-001",
        run_root=run_root,
        analysis_dir=trial_root
        / "analysis-kimi-analysis-001-attack-attempt-001",
        completed_trial=trial_input,
        projection_manifest=projection_input,
        timeout_seconds=30,
    )
    return request, {
        "projection_root": projection_root,
        "projection_manifest": projection_input.path,
        "trial": trial_input.path,
        "event_ir": Path(event_ir["path"]),
        "source_stdout": Path(source_stdout["path"]),
    }


def _rewrite_pinned_json(
    item: PinnedAnalysisInput, document: Mapping[str, Any]
) -> PinnedAnalysisInput:
    return _write_json(item.path, document)


def test_invokes_unchanged_shared_analyzer_and_hashes_every_result(
    tmp_path: Path,
) -> None:
    request, paths = _fixture(tmp_path)
    analyzer = Path(__file__).resolve().parents[3] / "infra" / "analyze_trace.py"
    analyzer_before = analyzer.read_bytes()
    original = {
        path: path.read_bytes()
        for path in paths.values()
        if path.is_file()
    }

    result = invoke_kimi_shared_analyzer(request)

    provenance = json.loads(result.provenance_manifest_path.read_text())
    assert provenance["schema_name"] == ANALYSIS_PROVENANCE_SCHEMA_NAME
    assert provenance["trial_disposition"] == "COMPLETED"
    assert provenance["process"]["exit_code"] == 0
    assert provenance["analyzer"]["entry"] == "infra.analyze_trace.main"
    assert provenance["analyzer"]["invocation_mode"] == "sanitized_subprocess"
    assert provenance["analyzer"]["source_sha256"] == _sha(analyzer_before)
    assert provenance["manifest_payload_sha256"] == _canonical_sha(
        {
            key: value
            for key, value in provenance.items()
            if key != "manifest_payload_sha256"
        }
    )
    for record in [
        provenance["process"]["stdout"],
        provenance["process"]["stderr"],
        *provenance["analyzer_outputs"],
    ]:
        path = Path(record["path"])
        content = path.read_bytes()
        assert record["sha256"] == _sha(content)
        assert record["bytes"] == len(content)
        assert record["line_count"] == len(content.splitlines())
    assert (result.analyzer_results_dir / "oracle.json").is_file()
    assert (
        result.analyzer_results_dir / "stages" / "000_main" / "oracle.json"
    ).is_file()
    assert not (paths["projection_root"] / "oracle.json").exists()
    assert analyzer.read_bytes() == analyzer_before
    assert original == {path: path.read_bytes() for path in original}
    provenance_text = result.provenance_manifest_path.read_text().casefold()
    for forbidden in (
        '"score"',
        '"verdict"',
        '"attack_success"',
        '"progress_node"',
    ):
        assert forbidden not in provenance_text


@pytest.mark.parametrize("outcome", ["EXECUTION_INVALID", "MODEL_PROTOCOL_INCOMPLETE"])
def test_non_completed_trial_is_rejected_before_analyzer(
    tmp_path: Path, outcome: str
) -> None:
    request, _ = _fixture(tmp_path)
    trial = json.loads(request.completed_trial.path.read_text())
    trial["outcome"] = outcome
    trial["return_code"] = 1 if outcome == "EXECUTION_INVALID" else 0
    trial["failure_category"] = "fixture_failure"
    _resign(trial)
    trial_input = _rewrite_pinned_json(request.completed_trial, trial)
    with pytest.raises(KimiAnalysisInvocationError, match="COMPLETED"):
        invoke_kimi_shared_analyzer(
            replace(request, completed_trial=trial_input)
        )
    assert not request.analysis_dir.exists()


def test_projection_manifest_self_hash_tamper_fails_closed(tmp_path: Path) -> None:
    request, _ = _fixture(tmp_path)
    projection = json.loads(request.projection_manifest.path.read_text())
    projection["record_counts"]["projected_trace"] = 999
    tampered = _rewrite_pinned_json(request.projection_manifest, projection)
    trial = json.loads(request.completed_trial.path.read_text())
    trial["projection_manifest"]["sha256"] = tampered.sha256
    _resign(trial)
    trial_input = _rewrite_pinned_json(request.completed_trial, trial)
    with pytest.raises(KimiAnalysisInvocationError, match="self-hash"):
        invoke_kimi_shared_analyzer(
            replace(
                request,
                projection_manifest=tampered,
                completed_trial=trial_input,
            )
        )


@pytest.mark.parametrize("target", ["source_stdout", "event_ir"])
def test_projection_source_hash_drift_fails_closed(
    tmp_path: Path, target: str
) -> None:
    request, paths = _fixture(tmp_path)
    paths[target].write_bytes(paths[target].read_bytes() + b"tamper\n")
    with pytest.raises(KimiAnalysisInvocationError, match="hash|drift"):
        invoke_kimi_shared_analyzer(request)


def test_projected_file_hash_drift_fails_closed(tmp_path: Path) -> None:
    request, paths = _fixture(tmp_path)
    trace = paths["projection_root"] / "trace.jsonl"
    trace.write_bytes(trace.read_bytes() + b"{}\n")
    with pytest.raises(KimiAnalysisInvocationError, match="hash|line count"):
        invoke_kimi_shared_analyzer(request)


def test_kimi_executable_and_version_pins_are_revalidated(tmp_path: Path) -> None:
    request, _ = _fixture(tmp_path)
    trial = json.loads(request.completed_trial.path.read_text())
    trial["harness_version"] = "0.27.0"
    _resign(trial)
    trial_input = _rewrite_pinned_json(request.completed_trial, trial)
    with pytest.raises(KimiAnalysisInvocationError, match="COMPLETED"):
        invoke_kimi_shared_analyzer(replace(request, completed_trial=trial_input))


def test_shared_analyzer_failure_removes_uncommitted_analysis_tree(
    tmp_path: Path,
) -> None:
    request, _ = _fixture(tmp_path, analyzer_failure=True)
    with pytest.raises(KimiAnalysisInvocationError, match="shared analyzer failed"):
        invoke_kimi_shared_analyzer(request)
    assert not request.analysis_dir.exists()


def test_missing_projection_output_fails_before_analyzer(tmp_path: Path) -> None:
    request, paths = _fixture(tmp_path)
    (paths["projection_root"] / "stages" / "000_main" / "trace.jsonl").unlink()
    with pytest.raises(KimiAnalysisInvocationError, match="regular file"):
        invoke_kimi_shared_analyzer(request)
    assert not request.analysis_dir.exists()
