from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from infra.cross_harness.adapters.kimi.analysis_invoker import (
    COMPLETED_TRIAL_SCHEMA_NAME,
    KimiAnalysisInvocationResult,
)
from infra.cross_harness.adapters.kimi.analysis_pipeline import (
    EXPECTED_KIMI_EXECUTABLE,
    EXPECTED_KIMI_EXECUTABLE_SHA256,
    KimiAnalysisPipelineError,
    KimiAnalyzingExecutor,
    KimiCallbackEvidencePaths,
    KimiCompletedAnalysisRequest,
    KimiCompletedAnalysisResult,
    build_kimi_analyzing_executor,
    run_kimi_completed_analysis,
)
from infra.cross_harness.adapters.kimi.analyzer_projection import (
    KimiAnalyzerProjectionResult,
    SEMANTIC_TRANSLATION,
)
from infra.cross_harness.adapters.kimi.runner import (
    COMPLETED,
    EXECUTION_INVALID,
    ExecutionResult,
    MaterializedCase,
)


RUN_ID = "pipeline-001"
CASE_ID = "case-pipeline"
TRIAL_ID = "attack-attempt-001"


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_sha(value: Any) -> str:
    return _sha(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> tuple[Path, str]:
    content = json.dumps(
        value, indent=2, sort_keys=True, ensure_ascii=False
    ).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path.resolve(), _sha(content)


def _write_jsonl(path: Path, records: list[Mapping[str, Any]]) -> tuple[Path, str, int]:
    content = b"".join(
        json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")
        + b"\n"
        for record in records
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path.resolve(), _sha(content), len(records)


def _assert_no_scoring_keys(value: Any) -> None:
    forbidden = {
        "attack_success",
        "confirmed_compromise",
        "progress_node",
        "risk_score",
        "score",
        "scored_result",
        "verdict",
    }
    if isinstance(value, Mapping):
        assert not forbidden.intersection(str(key).casefold() for key in value)
        for child in value.values():
            _assert_no_scoring_keys(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_scoring_keys(child)


@dataclass
class _Fixture:
    request: KimiCompletedAnalysisRequest
    result: ExecutionResult
    materialized: MaterializedCase
    run_root: Path
    manifest_path: Path
    auxiliary_path: Path | None


def _fixture(tmp_path: Path, *, auxiliary: bool = False) -> _Fixture:
    run_root = (tmp_path / f"case-kimi-{RUN_ID}").resolve()
    workspace = run_root / f"workspace-kimi-{RUN_ID}"
    workspace.mkdir(parents=True)
    run_root.chmod(0o700)
    analysis_inputs = run_root / f"analysis-inputs-kimi-{RUN_ID}"
    analysis_inputs.mkdir()

    case = {
        "case_id": CASE_ID,
        "workspace_dir": str(workspace),
        "canary_token": "",
        "plugin_skills": [],
        "plugin_commands": [],
        "mcp_servers": [],
        "mcp_tools": [],
    }
    case_path, case_sha = _write_json(
        analysis_inputs / f"case-source-kimi-{RUN_ID}.json", case
    )
    stage_case_path, stage_case_sha = _write_json(
        analysis_inputs / f"case-stage-000-main-kimi-{RUN_ID}.json",
        {**case, "stage_index": 1, "stage_name": "main"},
    )

    stage_root = run_root / f"stage-kimi-{RUN_ID}-stage-000-main"
    runtime = stage_root / f"runtime-kimi-{RUN_ID}-stage-000-main"
    artifact = runtime / f"artifact-kimi-{RUN_ID}-stage-000-main"
    native_wire_path = (
        runtime
        / f"config-kimi-{RUN_ID}-stage-000-main"
        / "sessions"
        / "session-fixture"
        / "agents"
        / "main"
        / "wire.jsonl"
    )
    wire_record = {
        "type": "config.update",
        "time": 1784512800000,
        "systemPrompt": "Available skills: fixture-skill",
    }
    native_wire_path, native_wire_sha, wire_lines = _write_jsonl(
        native_wire_path, [wire_record]
    )
    captured_wire_path, captured_wire_sha, _ = _write_jsonl(
        artifact / f"wire-captures-kimi-{RUN_ID}-stage-000" / "wire-000.jsonl",
        [wire_record],
    )
    assert native_wire_sha == captured_wire_sha
    main_wire_path, main_wire_sha, _ = _write_jsonl(
        runtime / f"wire-kimi-{RUN_ID}-stage-000-main.jsonl", [wire_record]
    )
    stdout_path, stdout_sha, stdout_lines = _write_jsonl(
        runtime / f"trace-kimi-{RUN_ID}-stage-000-main.jsonl",
        [
            {
                "role": "assistant",
                "content": [{"type": "text", "text": "fixed benign fixture"}],
            }
        ],
    )

    wire_capture = {
        "source_path": str(native_wire_path),
        "captured_path": str(captured_wire_path),
        "sha256": captured_wire_sha,
        "line_count": wire_lines,
        "is_main": True,
    }
    controller_path: Path | None = None
    controller_sha: str | None = None
    observation_path: Path | None = None
    observation_sha: str | None = None
    observation_record_count: int | None = None
    health: list[Mapping[str, Any]] = []
    auxiliary_path: Path | None = None
    if auxiliary:
        request_observer_path, request_observer_sha, request_observer_lines = _write_jsonl(
            artifact / f"provider-request-observer-kimi-{RUN_ID}-stage-000.jsonl",
            [
                {
                    "schema_name": "safety_bench_kimi_provider_request_observation",
                    "schema_version": 1,
                    "harness_id": "kimi",
                    "run_id": RUN_ID,
                    "case_id": CASE_ID,
                    "trial_id": TRIAL_ID,
                    "stage_index": 0,
                    "sequence": 1,
                }
            ],
        )
        observation_path, observation_sha, observation_record_count = _write_jsonl(
            artifact / f"control-observations-kimi-{RUN_ID}-stage-000.jsonl",
            [
                {
                    "type": "adapter.instruction_loading_observed",
                    "time": "2026-07-20T00:00:00+00:00",
                    "request_observer": {
                        "path": str(request_observer_path),
                        "sha256": request_observer_sha,
                        "line": 1,
                        "line_count": request_observer_lines,
                    },
                }
            ],
        )
        controller_path, controller_sha, _ = _write_jsonl(
            runtime / f"acp-trace-kimi-{RUN_ID}-stage-000.jsonl",
            [{"jsonrpc": "2.0", "id": 1, "result": {}}],
        )
        mcp_path, mcp_sha, mcp_lines = _write_jsonl(
            runtime / f"mcp-evidence-kimi-{RUN_ID}-stage-000.jsonl",
            [
                {
                    "schema_name": "safety_bench_kimi_mcp_stdio_evidence",
                    "schema_version": 1,
                    "harness_id": "kimi",
                    "run_id": RUN_ID,
                    "stage_index": 0,
                }
            ],
        )
        auxiliary_path = mcp_path
        health = [
            {
                "server": "fixture",
                "evidence_files": [
                    {
                        "kind": "stdio_trace",
                        "path": str(mcp_path),
                        "sha256": mcp_sha,
                        "line_count": mcp_lines,
                    }
                ],
            }
        ]

    result_document: dict[str, Any] = {
        "schema_name": "safety_bench_kimi_stage_execution",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": RUN_ID,
        "case_id": CASE_ID,
        "stage": {"index": 0, "name": "main"},
        "return_code": 0,
        "timed_out": False,
        "stdout": {
            "path": str(stdout_path),
            "sha256": stdout_sha,
            "line_count": stdout_lines,
        },
        "wire": {
            "main_path": str(main_wire_path),
            "main_sha256": main_wire_sha,
            "captures": [wire_capture],
        },
        "mcp_health": health,
        "controller_trace": (
            {"path": str(controller_path), "sha256": controller_sha}
            if controller_path is not None
            else None
        ),
        "control_observation_trace": (
            {
                "path": str(observation_path),
                "sha256": observation_sha,
                "record_count": observation_record_count,
            }
            if observation_path is not None
            else None
        ),
    }
    result_path, _ = _write_json(
        runtime / f"result-kimi-{RUN_ID}-stage-000-main.json", result_document
    )

    event = {
        "schema_name": "safety_bench_cross_harness_event",
        "schema_version": 1,
        "event_id": "event:skill:discovered",
        "event_type": "skill.discovered",
        "run_id": RUN_ID,
        "case_id": CASE_ID,
        "harness": {
            "id": "kimi",
            "version": "0.26.0",
            "feature_flags": {"binary_sha256": EXPECTED_KIMI_EXECUTABLE_SHA256},
        },
        "stage": {"index": 0, "name": "main"},
        "sequence": 0,
        "timestamp": "2026-07-20T00:00:00+00:00",
        "source": {
            "trace_path": str(captured_wire_path),
            "line": 1,
            "raw_event_type": "config.update:systemPrompt:skill_listing",
        },
        "attributes": {
            "skill_name": "fixture-skill",
            "skill_sha256": _sha(b"fixture-skill"),
        },
    }
    event_ir_path, event_ir_sha, _ = _write_jsonl(
        run_root / f"event-ir-kimi-{RUN_ID}.jsonl", [event]
    )

    manifest: dict[str, Any] = {
        "schema_name": "safety_bench_kimi_bench_plan",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": RUN_ID,
        "case_id": CASE_ID,
        "suite_id": "fixture-suite",
        "disposition": "READY",
        "stages": [{"index": 0, "name": "main"}],
        "analysis_projection_inputs": {
            "schema_version": 1,
            "semantic_translation": SEMANTIC_TRANSLATION,
            "root": str(analysis_inputs),
            "case_document": {"path": str(case_path), "sha256": case_sha},
            "stages": [
                {
                    "index": 0,
                    "name": "main",
                    "case_document": {
                        "path": str(stage_case_path),
                        "sha256": stage_case_sha,
                    },
                }
            ],
        },
    }
    manifest["manifest_payload_sha256"] = _canonical_sha(manifest)
    manifest_path, manifest_file_sha = _write_json(
        run_root / f"manifest-kimi-{RUN_ID}.json", manifest
    )

    executable = EXPECTED_KIMI_EXECUTABLE.resolve(strict=True)
    assert _sha(executable.read_bytes()) == EXPECTED_KIMI_EXECUTABLE_SHA256
    stage_metadata = {
        "index": 0,
        "name": "main",
        "return_code": 0,
        "stdout_path": str(stdout_path),
        "stdout_sha256": stdout_sha,
        "main_wire_path": str(main_wire_path),
        "main_wire_sha256": main_wire_sha,
        "wire_captures": [wire_capture],
        "result_path": str(result_path),
        "mcp_health": health,
        "controller_trace_path": str(controller_path) if controller_path else None,
        "controller_trace_sha256": controller_sha,
        "observation_trace_path": (
            str(observation_path) if observation_path else None
        ),
        "observation_trace_sha256": observation_sha,
    }
    execution = ExecutionResult(
        outcome=COMPLETED,
        return_code=0,
        raw_stdout_path=stdout_path,
        raw_wire_path=main_wire_path,
        event_ir_path=event_ir_path,
        metadata={
            "schema_name": "safety_bench_kimi_execution_evidence",
            "schema_version": 1,
            "harness_id": "kimi",
            "run_id": RUN_ID,
            "case_id": CASE_ID,
            "manifest_path": str(manifest_path),
            "manifest_sha256": manifest_file_sha,
            "executable": {
                "path": str(executable),
                "sha256": EXPECTED_KIMI_EXECUTABLE_SHA256,
            },
            "fresh_os_process_count": 1,
            "stages": [stage_metadata],
            "event_ir_sha256": event_ir_sha,
        },
    )
    materialized = MaterializedCase(
        case_id=CASE_ID,
        root=run_root,
        workspace=workspace,
        config=run_root / "config-kimi-placeholder",
        trace=runtime,
        result=runtime,
        session=runtime,
        cache=runtime,
        artifact=artifact,
        manifest_path=manifest_path,
    )
    return _Fixture(
        request=KimiCompletedAnalysisRequest(
            run_id=RUN_ID,
            case_id=CASE_ID,
            trial_id=TRIAL_ID,
            run_root=run_root,
            materialization_manifest_path=manifest_path,
            execution_result=execution,
            timeout_seconds=30,
        ),
        result=execution,
        materialized=materialized,
        run_root=run_root,
        manifest_path=manifest_path,
        auxiliary_path=auxiliary_path,
    )


def _fake_analysis_result(run_root: Path) -> KimiCompletedAnalysisResult:
    projection_root = run_root / "fake-projection-kimi-pipeline-001"
    projection_root.mkdir()
    projection_manifest, _ = _write_json(
        projection_root / "projection-manifest-kimi-pipeline-001.json",
        {"kind": "fixture-projection"},
    )
    for name in ("trace.jsonl", "honeypot.jsonl"):
        (projection_root / name).write_text("", encoding="utf-8")
    case_path, _ = _write_json(projection_root / "case.json", {"case_id": CASE_ID})
    completed_trial, completed_sha = _write_json(
        run_root / "fake-completed-trial-kimi-pipeline-001.json",
        {"kind": "fixture-completed"},
    )
    analysis_dir = run_root / "fake-analysis-kimi-pipeline-001"
    results_dir = analysis_dir / "results"
    results_dir.mkdir(parents=True)
    provenance, _ = _write_json(
        analysis_dir / "analysis-provenance-kimi-pipeline-001.json",
        {"kind": "fixture-provenance"},
    )
    stdout = analysis_dir / "stdout.log"
    stderr = analysis_dir / "stderr.log"
    stdout.write_bytes(b"")
    stderr.write_bytes(b"")
    return KimiCompletedAnalysisResult(
        projection=KimiAnalyzerProjectionResult(
            root=projection_root,
            manifest_path=projection_manifest,
            trace_path=projection_root / "trace.jsonl",
            honeypot_path=projection_root / "honeypot.jsonl",
            case_path=case_path,
        ),
        completed_trial_path=completed_trial,
        completed_trial_sha256=completed_sha,
        invocation=KimiAnalysisInvocationResult(
            analysis_dir=analysis_dir,
            analyzer_results_dir=results_dir,
            provenance_manifest_path=provenance,
            stdout_path=stdout,
            stderr_path=stderr,
        ),
    )


def test_real_projection_completed_trial_and_shared_analyzer_close_loop(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)

    result = run_kimi_completed_analysis(fixture.request)

    completed = json.loads(result.completed_trial_path.read_text())
    assert completed["schema_name"] == COMPLETED_TRIAL_SCHEMA_NAME
    assert completed["outcome"] == COMPLETED
    assert completed["projection_manifest"]["path"] == str(
        result.projection.manifest_path
    )
    assert completed["manifest_payload_sha256"] == _canonical_sha(
        {key: value for key, value in completed.items() if key != "manifest_payload_sha256"}
    )
    assert result.invocation.provenance_manifest_path.is_file()
    provenance = json.loads(result.invocation.provenance_manifest_path.read_text())
    assert provenance["process"]["exit_code"] == 0
    assert provenance["inputs"]["completed_trial"]["sha256"] == (
        result.completed_trial_sha256
    )
    _assert_no_scoring_keys(completed)
    _assert_no_scoring_keys(provenance)


def test_pipeline_pins_observation_controller_provider_and_mcp_auxiliary_sources(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, auxiliary=True)
    captured: list[Any] = []

    def projector(request: Any) -> KimiAnalyzerProjectionResult:
        captured.append(request)
        from infra.cross_harness.adapters.kimi.analyzer_projection import (
            project_kimi_analyzer_compatibility,
        )

        return project_kimi_analyzer_compatibility(request)

    result = run_kimi_completed_analysis(fixture.request, projector=projector)

    assert result.invocation.provenance_manifest_path.is_file()
    kinds = {
        item.kind
        for stage in captured[0].stages
        for item in stage.auxiliary_sources
    }
    assert {
        "main_wire_copy",
        "controller_trace",
        "adapter_observation",
        "provider_request_observation",
        "mcp_stdio_trace",
    } <= kinds


def test_auxiliary_hash_drift_fails_before_projector_and_creates_no_outputs(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path, auxiliary=True)
    assert fixture.auxiliary_path is not None
    fixture.auxiliary_path.write_text('{"tampered":true}\n', encoding="utf-8")
    calls: list[Any] = []

    with pytest.raises(KimiAnalysisPipelineError, match="SHA-256 drifted"):
        run_kimi_completed_analysis(
            fixture.request,
            projector=lambda request: calls.append(request),  # type: ignore[arg-type,return-value]
        )

    assert calls == []
    assert not any(
        path.name.startswith(
            ("analyzer-projection-kimi-", "completed-trial-kimi-", "analysis-kimi-")
        )
        for path in fixture.run_root.iterdir()
    )


def test_noncompleted_execution_is_rejected_without_projector(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    invalid = ExecutionResult(
        outcome=EXECUTION_INVALID,
        return_code=1,
        raw_stdout_path=fixture.result.raw_stdout_path,
        raw_wire_path=fixture.result.raw_wire_path,
        event_ir_path=None,
        metadata={},
        failure_category="PROCESS_EXIT_NONZERO",
        retry_eligible=False,
    )
    request = KimiCompletedAnalysisRequest(
        **{
            **fixture.request.__dict__,
            "execution_result": invalid,
        }
    )
    calls: list[Any] = []

    with pytest.raises(KimiAnalysisPipelineError, match="terminal COMPLETED"):
        run_kimi_completed_analysis(
            request,
            projector=lambda value: calls.append(value),  # type: ignore[arg-type,return-value]
        )
    assert calls == []


def test_existing_output_is_never_overwritten(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    output = fixture.run_root / f"analyzer-projection-kimi-{RUN_ID}-{TRIAL_ID}"
    output.mkdir()
    marker = output / "owned-by-prior-run"
    marker.write_text("keep", encoding="utf-8")

    with pytest.raises(KimiAnalysisPipelineError, match="already exists"):
        run_kimi_completed_analysis(fixture.request)

    assert marker.read_text() == "keep"


def test_failed_injected_projector_rolls_back_only_its_new_output(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    unrelated = fixture.run_root / "unrelated-kimi-evidence.json"
    unrelated.write_text("keep\n", encoding="utf-8")

    def failing_projector(request: Any) -> Any:
        request.output_dir.mkdir()
        (request.output_dir / "partial").write_text("partial", encoding="utf-8")
        raise RuntimeError("fixture projector failure")

    with pytest.raises(RuntimeError, match="fixture projector failure"):
        run_kimi_completed_analysis(
            fixture.request,
            projector=failing_projector,
        )

    assert not (
        fixture.run_root / f"analyzer-projection-kimi-{RUN_ID}-{TRIAL_ID}"
    ).exists()
    assert unrelated.read_text() == "keep\n"


class _Delegate:
    def __init__(self, result: ExecutionResult) -> None:
        self.result = result
        self.calls = 0

    def execute(self, plan: Any, materialized: Any, context: Any) -> ExecutionResult:
        del plan, materialized, context
        self.calls += 1
        return self.result


def test_analyzing_executor_returns_noncompleted_result_unchanged(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    invalid = ExecutionResult(
        outcome=EXECUTION_INVALID,
        return_code=1,
        raw_stdout_path=fixture.result.raw_stdout_path,
        raw_wire_path=fixture.result.raw_wire_path,
        event_ir_path=None,
        metadata={},
        failure_category="PROCESS_EXIT_NONZERO",
        retry_eligible=False,
    )
    delegate = _Delegate(invalid)
    executor = KimiAnalyzingExecutor(
        delegate=delegate,
        trial_id=TRIAL_ID,
        pipeline=lambda request: pytest.fail("pipeline must not run"),
    )

    observed = executor.execute(
        SimpleNamespace(),
        fixture.materialized,
        SimpleNamespace(run_id=RUN_ID),
    )

    assert observed is invalid
    assert delegate.calls == 1


def test_analyzing_executor_appends_only_hash_pinned_non_scoring_metadata(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    delegate = _Delegate(fixture.result)
    analyzed = _fake_analysis_result(fixture.run_root)
    requests: list[KimiCompletedAnalysisRequest] = []

    def pipeline(request: KimiCompletedAnalysisRequest) -> KimiCompletedAnalysisResult:
        requests.append(request)
        return analyzed

    executor = KimiAnalyzingExecutor(
        delegate=delegate,
        trial_id=TRIAL_ID,
        pipeline=pipeline,
    )
    observed = executor.execute(
        SimpleNamespace(),
        fixture.materialized,
        SimpleNamespace(run_id=RUN_ID),
    )

    assert len(requests) == 1
    assert "analysis_pipeline" not in fixture.result.metadata
    records = observed.metadata["analysis_pipeline"]
    assert set(records) == {
        "projection_manifest",
        "completed_trial",
        "analysis_provenance",
        "semantic_translation",
        "pipeline_version",
    }
    for key in ("projection_manifest", "completed_trial", "analysis_provenance"):
        path = Path(records[key]["path"])
        assert records[key]["sha256"] == _sha(path.read_bytes())
    _assert_no_scoring_keys(observed.metadata)


def test_production_factory_binds_exact_callback_collector_identity(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    callback_root = fixture.run_root / f"callback-kimi-{RUN_ID}"
    callback_root.mkdir()
    callback_manifest = callback_root / f"callback-manifest-kimi-{RUN_ID}.json"
    callback_evidence = callback_root / f"callback-evidence-kimi-{RUN_ID}.jsonl"
    callback_manifest.write_text("{}\n", encoding="utf-8")
    callback_evidence.write_text("", encoding="utf-8")
    collector = SimpleNamespace(
        run_id=RUN_ID,
        case_id=CASE_ID,
        trial_id=TRIAL_ID,
        evidence_manifest_path=callback_manifest,
        evidence_path=callback_evidence,
    )
    delegate = _Delegate(fixture.result)
    analyzed = _fake_analysis_result(fixture.run_root)
    requests: list[KimiCompletedAnalysisRequest] = []

    def pipeline(request: KimiCompletedAnalysisRequest) -> KimiCompletedAnalysisResult:
        requests.append(request)
        return analyzed

    executor = build_kimi_analyzing_executor(
        delegate=delegate,
        run_id=RUN_ID,
        case_id=CASE_ID,
        trial_id=TRIAL_ID,
        run_root=fixture.run_root,
        callback_collector=collector,
        pipeline=pipeline,
    )
    result = executor.execute(
        SimpleNamespace(),
        fixture.materialized,
        SimpleNamespace(run_id=RUN_ID),
    )

    assert result.outcome == COMPLETED
    assert requests[0].callback == KimiCallbackEvidencePaths(
        callback_manifest, callback_evidence
    )

    collector.case_id = "another-case"
    with pytest.raises(KimiAnalysisPipelineError, match="identity drifted"):
        executor.execute(
            SimpleNamespace(),
            fixture.materialized,
            SimpleNamespace(run_id=RUN_ID),
        )
