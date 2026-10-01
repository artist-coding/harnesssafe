from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from infra.cross_harness.adapters.kimi.bench_materializer import (
    KimiBenchMaterializationError,
    load_bench_materialization_manifest,
    materialize_bench_case_for_runner,
)
from infra.cross_harness.adapters.kimi.executor import (
    ATTESTATION_SCHEMA_NAME,
    ATTESTATION_SCHEMA_VERSION,
    ControlFinalization,
    ControlDirective,
    JsonRpcExchange,
    KimiStageExecutor,
    KimiStageExecutorError,
    NormalizationRequest,
    StageCapture,
    StageControlRequest,
    StageControlFinalizeRequest,
    StageLaunchRequest,
    WireCapture,
)
from infra.cross_harness.adapters.kimi.disposition import (
    KimiModelProtocolIncompleteError,
)
from infra.cross_harness.adapters.kimi.control_trials import (
    KimiMatchedControlBoundary,
    materialize_control_trial,
)
from infra.cross_harness.adapters.kimi.lifecycle import CaseRunLayout, RunLayout
from infra.cross_harness.adapters.kimi.materializer import sha256_file, tree_sha256
from infra.cross_harness.adapters.kimi.runner import (
    DefaultPlanBuilder,
    ExecutionContext,
    ManifestInventory,
    MaterializedCase,
)
from infra.cross_harness.contract import CAPABILITIES


REPO_ROOT = Path(__file__).resolve().parents[3]
ALL_SUPPORTED = {capability: "SUPPORTED" for capability in CAPABILITIES}


def _canonical_sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _resign_manifest(path: Path, document: dict[str, Any]) -> None:
    document["manifest_payload_sha256"] = _canonical_sha(
        {key: value for key, value in document.items() if key != "manifest_payload_sha256"}
    )
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_mcp_config_and_resign(
    manifest_path: Path,
    document: dict[str, Any],
    config: Mapping[str, Any],
    *,
    stage_index: int = 0,
) -> None:
    mcp = document["stages"][stage_index]["surfaces"]["mcp"]
    prepared = Path(mcp["prepared_config"]["target"])
    prepared.write_text(
        json.dumps(config, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    changed_sha = sha256_file(prepared)
    mcp["prepared_config"]["materialized_sha256"] = changed_sha
    mcp["prepared_config"]["evidence_proxy"]["materialized_sha256"] = changed_sha
    mcp["activation"]["source_sha256"] = changed_sha
    _resign_manifest(manifest_path, document)


class FakeRegistry:
    def __init__(self, *, run_id: str, record_path: Path) -> None:
        self.run_id = run_id
        self.record_path = record_path
        self.registered: list[tuple[int, str]] = []

    def register(self, pid: int, *, role: str) -> None:
        self.registered.append((pid, role))
        self.record_path.parent.mkdir(parents=True, exist_ok=True)
        self.record_path.write_text(
            json.dumps(
                {
                    "harness_id": "kimi",
                    "run_id": self.run_id,
                    "processes": [
                        {"pid": item_pid, "role": item_role}
                        for item_pid, item_role in self.registered
                    ],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


class FakeProcess:
    def __init__(
        self,
        *,
        pid: int,
        stdout: bytes,
        stderr: bytes = b"",
        return_code: int = 0,
        timeout_once: bool = False,
        jsonrpc_failure_id: str | int | None = None,
    ) -> None:
        self.pid = pid
        self.returncode: int | None = return_code
        self._stdout = stdout
        self._stderr = stderr
        self.terminated = False
        self.killed = False
        self.timeout_once = timeout_once
        self.jsonrpc_failure_id = jsonrpc_failure_id
        self.jsonrpc_exchanges: list[
            tuple[tuple[bytes, ...], tuple[str | int, ...]]
        ] = []

    def communicate(
        self,
        input: bytes | None = None,
        timeout: int | float | None = None,
    ) -> tuple[bytes, bytes]:
        if self.timeout_once:
            self.timeout_once = False
            raise TimeoutError("fixture provider timeout")
        return self._stdout, self._stderr

    def exchange_jsonrpc(
        self,
        *,
        request_frames: tuple[bytes, ...],
        expected_response_ids: tuple[str | int, ...],
        timeout: int | float,
    ) -> tuple[bytes, bytes]:
        self.jsonrpc_exchanges.append((request_frames, expected_response_ids))
        stdout = b"".join(
            (
                json.dumps(
                    (
                        {
                            "jsonrpc": "2.0",
                            "id": response_id,
                            "error": {
                                "code": -32000,
                                "message": "fixture ACP failure",
                            },
                        }
                        if response_id == self.jsonrpc_failure_id
                        else {"jsonrpc": "2.0", "id": response_id, "result": {}}
                    ),
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8")
            for response_id in expected_response_ids
        )
        self.returncode = 0
        return stdout, b""

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True


class FakeLauncher:
    jsonrpc_exchange_supported = True

    def __init__(
        self,
        *,
        valid_attestation: bool = True,
        duplicate_pid: bool = False,
        return_code: int = 0,
        timeout_once: bool = False,
        jsonrpc_failure_id: str | int | None = None,
    ) -> None:
        self.valid_attestation = valid_attestation
        self.duplicate_pid = duplicate_pid
        self.return_code = return_code
        self.timeout_once = timeout_once
        self.jsonrpc_failure_id = jsonrpc_failure_id
        self.attest_calls = 0
        self.requests: list[StageLaunchRequest] = []
        self.processes: list[FakeProcess] = []
        self.surface_snapshots: list[dict[str, str | None]] = []

    def attest(self, *, run_id: str, run_root: Path) -> Path:
        self.attest_calls += 1
        isolation_path = run_root / f"launcher-isolation-kimi-{run_id}.json"
        broker_path = run_root / f"launcher-broker-kimi-{run_id}.json"
        isolation_path.write_text('{"boundary":"fixture"}\n', encoding="utf-8")
        broker_path.write_text('{"broker":"fixture"}\n', encoding="utf-8")
        document: dict[str, Any] = {
            "schema_name": ATTESTATION_SCHEMA_NAME,
            "schema_version": ATTESTATION_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": run_id,
            "run_root": str(run_root.resolve()),
            "launcher_id": "deterministic-fixture-launcher",
            "isolation": {
                "kind": "deterministic_test_namespace",
                "enforced": self.valid_attestation,
                "host_user_state_mounted": False,
                "other_harness_state_mounted": False,
                "network_egress": "run_local_broker_only",
            },
            "credential_broker": {
                "kind": "deterministic_run_local_fixture_broker",
                "run_id": run_id,
                "run_local": True,
                "verified": True,
                "external_credentials_in_kimi_env": False,
                "external_credentials_in_tool_child_env": False,
                "external_credentials_persisted": False,
            },
            "evidence": [
                {
                    "kind": "os_isolation",
                    "path": str(isolation_path),
                    "sha256": sha256_file(isolation_path),
                },
                {
                    "kind": "credential_broker",
                    "path": str(broker_path),
                    "sha256": sha256_file(broker_path),
                },
            ],
        }
        document["attestation_payload_sha256"] = _canonical_sha(document)
        path = run_root / f"launcher-attestation-kimi-{run_id}.json"
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def spawn(self, request: StageLaunchRequest) -> FakeProcess:
        self.requests.append(request)
        skills = request.cwd / ".kimi-code" / "skills"
        mcp = request.cwd / ".kimi-code" / "mcp.json"
        self.surface_snapshots.append(
            {
                "skills_sha256": tree_sha256(skills) if skills.is_dir() else None,
                "mcp_sha256": sha256_file(mcp) if mcp.is_file() else None,
            }
        )
        wire = (
            Path(request.env["KIMI_CODE_HOME"])
            / "sessions"
            / "wd_fixture"
            / "session_fixture"
            / "agents"
            / "main"
            / "wire.jsonl"
        )
        wire.parent.mkdir(parents=True, exist_ok=True)
        with wire.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "type": "context.append_loop_event",
                        "event": {
                            "type": "content_part",
                            "stage": request.stage_index,
                        },
                    },
                    sort_keys=True,
                )
                + "\n"
            )
        pid = 41001 if self.duplicate_pid else 41001 + request.stage_index
        process = FakeProcess(
            pid=pid,
            stdout=(
                json.dumps(
                    {
                        "role": "assistant",
                        "content": f"fixture-stage-{request.stage_index}",
                    },
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
            return_code=self.return_code,
            timeout_once=self.timeout_once,
            jsonrpc_failure_id=self.jsonrpc_failure_id,
        )
        self.processes.append(process)
        return process


class FakeNormalizer:
    def __init__(self, *, include_score: bool = False) -> None:
        self.include_score = include_score
        self.requests: list[NormalizationRequest] = []

    def normalize(self, request: NormalizationRequest) -> Path:
        self.requests.append(request)
        records: list[dict[str, Any]] = []
        for sequence, capture in enumerate(request.stage_captures):
            attributes: dict[str, Any] = {
                "observer": "deterministic-fixture",
                "skill_name": "fixture-skill",
                "skill_sha256": hashlib.sha256(b"fixture-skill").hexdigest(),
            }
            if self.include_score:
                attributes["score"] = 1
            records.append(
                {
                    "schema_name": "safety_bench_cross_harness_event",
                    "schema_version": 1,
                    "event_id": f"fixture:{request.run_id}:{sequence}",
                    "event_type": "skill.discovered",
                    "run_id": request.run_id,
                    "case_id": request.case_id,
                    "harness": {
                        "id": "kimi",
                        "version": "fixture-0",
                        "feature_flags": {"deterministic": True},
                    },
                    "stage": {"name": capture.name, "index": capture.index},
                    "sequence": sequence,
                    "timestamp": "2026-07-20T00:00:00+00:00",
                    "source": {
                        "trace_path": str(capture.stdout_path),
                        "line": 1,
                        "raw_event_type": "fixture.stdout",
                    },
                    "attributes": attributes,
                }
            )
        request.output_path.write_text(
            "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
            encoding="utf-8",
        )
        return request.output_path


class FakeController:
    def prepare(self, request: StageControlRequest) -> ControlDirective:
        controller = request.stage_document["surfaces"]["session"].get("controller")
        operation = str((controller or {}).get("operation") or "")
        if "resume_exact" in operation:
            return ControlDirective(
                argv_suffix=("--session", "session_fixture"),
                evidence_locators=("fixture:exact-session",),
            )
        return ControlDirective(evidence_locators=(f"fixture:{request.control_kind}",))

    def finalize(self, request: StageControlFinalizeRequest) -> ControlFinalization:
        return ControlFinalization(
            evidence_locators=(f"fixture:finalized:{request.control_kind}",)
        )


class FakeDirectEvidenceObserver:
    def __init__(self, events: list[str], *, alter_argv: bool = False) -> None:
        self.events = events
        self.alter_argv = alter_argv
        self.prepare_requests: list[StageControlRequest] = []
        self.finalize_requests: list[StageControlFinalizeRequest] = []

    def prepare(self, request: StageControlRequest) -> ControlDirective:
        self.events.append(f"prepare:{request.stage_index}")
        self.prepare_requests.append(request)
        assert request.control_kind == "direct_evidence"
        workspace = Path(request.stage_document["runtime_paths"]["workspace"])
        activation = request.stage_document["surfaces"]["skills"]["activation"]
        if activation["operation"] == "replace_tree":
            assert (workspace / ".kimi-code" / "skills").is_dir()
        return ControlDirective(
            argv_suffix=("--forbidden-observer-argv",) if self.alter_argv else (),
            evidence_locators=(f"fixture:observer-prepared:{request.stage_index}",),
        )

    def finalize(
        self, request: StageControlFinalizeRequest
    ) -> ControlFinalization:
        self.events.append(f"finalize:{request.stage_index}")
        self.finalize_requests.append(request)
        assert request.control_kind == "direct_evidence"
        main_path = Path(request.stage_result["wire"]["main_path"])
        assert main_path.is_file()
        return ControlFinalization(
            evidence_locators=(
                f"fixture:observer-finalized:{request.stage_index}",
            ),
            observation_records=(
                {
                    "type": "adapter.fixture_direct_evidence",
                    "time": "2026-07-20T00:00:00+00:00",
                    "stage_index": request.stage_index,
                },
            ),
        )


class FakeCompactController:
    def prepare(self, request: StageControlRequest) -> ControlDirective:
        controller = request.stage_document["surfaces"]["session"]["controller"]
        operation = str(controller["operation"])
        if operation == "compact_exact_captured_session_via_acp":
            workspace = str(request.stage_document["runtime_paths"]["workspace"])
            declared = controller["acp_protocol"]["request_sequence"]
            frames = (
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": declared[0]["params"],
                },
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "session/resume",
                    "params": {
                        "cwd": workspace,
                        "mcpServers": [],
                        "sessionId": "session_fixture",
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "session/prompt",
                    "params": {
                        "sessionId": "session_fixture",
                        "prompt": declared[2]["params"]["prompt"],
                    },
                },
            )
            return ControlDirective(
                argv_suffix=("acp",),
                evidence_locators=("fixture:acp-compaction",),
                launch_mode="controller",
                jsonrpc_exchange=JsonRpcExchange(
                    request_frames=tuple(
                        (json.dumps(frame, sort_keys=True) + "\n").encode("utf-8")
                        for frame in frames
                    ),
                    expected_response_ids=(1, 2, 3),
                ),
            )
        if operation == "resume_exact_compacted_session":
            return ControlDirective(
                argv_suffix=("--session", "session_fixture"),
                evidence_locators=("fixture:compacted-session",),
            )
        return ControlDirective(evidence_locators=("fixture:session-create",))

    def finalize(self, request: StageControlFinalizeRequest) -> ControlFinalization:
        return ControlFinalization(
            evidence_locators=(f"fixture:finalized:{request.stage_index}",)
        )


def _first_case(suite: str):
    return next(case for case in ManifestInventory(REPO_ROOT).list_cases() if case.suite == suite)


def _materialized_fixture(
    tmp_path: Path,
    *,
    suite: str = "F1_memory_runtime",
    case_dir_fragment: str | None = None,
):
    run_id = "executor-fixture"
    case = (
        next(
            candidate
            for candidate in ManifestInventory(REPO_ROOT).list_cases()
            if candidate.suite == suite
            and case_dir_fragment in candidate.case_dir.as_posix()
        )
        if case_dir_fragment is not None
        else _first_case(suite)
    )
    layout = RunLayout(REPO_ROOT, tmp_path / "external-results", run_id)
    case_layout = layout.for_case(case.case_id)
    layout.initialize_case(case_layout)
    plan = DefaultPlanBuilder().build(case, case_layout)
    assert plan.launch_eligible
    projection = materialize_bench_case_for_runner(
        repo_root=REPO_ROOT,
        case_dir=case.case_dir,
        run_dir=case_layout.root,
        run_id=run_id,
        callback_url="http://127.0.0.1:49173",
        capability_states=ALL_SUPPORTED,
        expected_suite_id=case.suite,
        allow_existing_empty_run_dir=True,
    )
    manifest = load_bench_materialization_manifest(projection.manifest_path)
    stage_paths = tuple(dict(stage) for stage in projection.stage_runtime_paths)
    first = stage_paths[0]
    materialized = MaterializedCase(
        case_id=projection.case_id,
        root=projection.run_dir,
        workspace=projection.workspace_dir,
        config=Path(first["kimi_home"]),
        trace=Path(first["trace"]).parent,
        result=Path(first["result"]).parent,
        session=Path(first["session"]),
        cache=Path(first["cache"]),
        artifact=Path(first["artifact"]),
        manifest_path=projection.manifest_path,
        stage_runtime_paths=stage_paths,
        launch_disposition=str(manifest["disposition"]),
        launch_reasons=tuple(str(item) for item in manifest["disposition_reasons"]),
    )
    registry = FakeRegistry(run_id=run_id, record_path=case_layout.pid_record)
    context = ExecutionContext(
        run_id=run_id,
        case_layout=case_layout,
        process_registry=registry,  # type: ignore[arg-type]
        loopback_port=object(),  # type: ignore[arg-type]
    )
    executable = tmp_path / "kimi-fixture-executable"
    executable.write_bytes(b"#!/bin/sh\nexit 99\n")
    executable.chmod(0o700)
    return plan, materialized, context, executable, registry


def _executor(
    *,
    executable: Path,
    launcher: FakeLauncher,
    normalizer: FakeNormalizer | None = None,
    timeout_seconds: int = 7,
    **kwargs: Any,
) -> KimiStageExecutor:
    return KimiStageExecutor(
        launcher=launcher,
        event_ir_normalizer=normalizer or FakeNormalizer(),
        executable=executable,
        executable_sha256=sha256_file(executable),
        timeout_seconds=timeout_seconds,
        path_environment="/usr/bin:/bin",
        **kwargs,
    )


def _assert_no_scoring_keys(value: Any) -> None:
    forbidden = {
        "attack_success",
        "confirmed_compromise",
        "oracle",
        "oracle_path",
        "progress_node",
        "score",
        "scored_result",
        "verdict",
    }
    if isinstance(value, Mapping):
        assert not (set(map(str.casefold, value)) & forbidden)
        for child in value.values():
            _assert_no_scoring_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _assert_no_scoring_keys(child)


def test_executor_runs_each_stage_in_a_fresh_attested_process(tmp_path: Path) -> None:
    plan, materialized, context, executable, registry = _materialized_fixture(tmp_path)
    canonical_before = tree_sha256(plan.case.case_dir)
    launcher = FakeLauncher()
    normalizer = FakeNormalizer()

    result = _executor(
        executable=executable, launcher=launcher, normalizer=normalizer
    ).execute(plan, materialized, context)

    assert result.outcome == "COMPLETED"
    assert result.return_code == 0
    assert len(launcher.requests) == len(plan.stages) == 2
    assert [pid for pid, _ in registry.registered] == [41001, 41002]
    assert len({pid for pid, _ in registry.registered}) == 2
    assert launcher.attest_calls == 1
    assert len(normalizer.requests) == 1
    assert result.event_ir_path is not None and result.event_ir_path.is_file()
    assert result.raw_stdout_path is not None and result.raw_stdout_path.is_file()
    assert result.raw_wire_path is not None and result.raw_wire_path.is_file()
    assert tree_sha256(plan.case.case_dir) == canonical_before
    assert not (materialized.workspace / ".kimi-code" / "skills").exists()
    assert not (materialized.workspace / ".kimi-code" / "mcp.json").exists()

    for request, projected in zip(launcher.requests, materialized.stage_runtime_paths):
        assert request.cwd.resolve() == materialized.workspace.resolve()
        assert request.timeout_seconds == 7
        assert request.stdout_path == Path(projected["trace"])
        assert request.wire_copy_path == Path(projected["wire"])
        assert request.result_path == Path(projected["result"])
        assert request.argv[0] == str(executable.resolve())
        assert request.executable_sha256 == sha256_file(executable)
        assert request.materialization_manifest_path == materialized.manifest_path.resolve()
        assert request.materialization_manifest_sha256 == sha256_file(
            materialized.manifest_path
        )
        assert {mount.kind for mount in request.write_mounts}.issuperset(
            {"workspace", "current_stage_runtime"}
        )
        assert {mount.kind for mount in request.write_mounts}.issubset(
            {
                "workspace",
                "current_stage_runtime",
                "shared_native_session",
                "shared_artifact_carrier",
            }
        )
        assert "current_stage_assets" in {
            mount.kind for mount in request.read_only_mounts
        }
        assert {mount.kind for mount in request.read_only_mounts}.issubset(
            {
                "current_stage_assets",
                "run_local_mcp_proxy",
                "mcp_child_file",
                "reviewed_stage_file",
            }
        )
        for mount in (*request.write_mounts, *request.read_only_mounts):
            assert mount.provenance_sha256 == request.materialization_manifest_sha256
            assert mount.mode == mount.path.stat().st_mode & 0o777
            assert len(mount.sha256) == 64
            assert mount.path not in {
                materialized.root.resolve(),
                materialized.manifest_path.resolve(),
            }
        for mount in request.read_only_mounts:
            assert mount.sha256 == (
                tree_sha256(mount.path)
                if mount.path_type == "tree"
                else sha256_file(mount.path)
            )
        assert request.argv[1] == "--prompt"
        assert request.argv[3:5] == ("--output-format", "stream-json")
        assert "--auto" not in request.argv and "--continue" not in request.argv
        assert request.env["HOME"] == projected["home"]
        assert request.env["KIMI_CODE_HOME"] == projected["kimi_home"]
        assert request.env["XDG_CACHE_HOME"] == projected["cache"]
        assert request.env["SAFETY_BENCH_HARNESS"] == "kimi"
        assert request.env["SAFETY_BENCH_RUN_ID"] == context.run_id
        assert not any(
            token in key.casefold()
            for key in request.env
            for token in ("api_key", "token", "secret", "credential", "password")
        )
        for key in (
            "HOME",
            "KIMI_CODE_HOME",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "TMPDIR",
        ):
            Path(request.env[key]).resolve().relative_to(materialized.root.resolve())
        stage_result = json.loads(Path(projected["result"]).read_text(encoding="utf-8"))
        assert stage_result["argv"][2].startswith("<sha256:")
        assert request.argv[2] not in Path(projected["result"]).read_text(encoding="utf-8")
        assert Path(projected["pid_record"]).is_file()
    _assert_no_scoring_keys(result.metadata)


def test_model_created_venv_symlinks_survive_the_next_stage_mount(
    tmp_path: Path,
) -> None:
    class VenvProducingLauncher(FakeLauncher):
        def spawn(self, request: StageLaunchRequest) -> FakeProcess:
            process = super().spawn(request)
            if request.stage_index == 0:
                venv_bin = request.cwd / ".venv" / "bin"
                venv_bin.mkdir(parents=True)
                (venv_bin / "python3").symlink_to("/usr/bin/python3")
                (venv_bin / "python").symlink_to("python3")
            return process

    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    launcher = VenvProducingLauncher()

    result = _executor(executable=executable, launcher=launcher).execute(
        plan, materialized, context
    )

    assert result.outcome == "COMPLETED"
    assert len(launcher.requests) == 2
    assert (materialized.workspace / ".venv" / "bin" / "python").is_symlink()


def test_direct_evidence_observer_is_passive_and_brackets_each_stage(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    events: list[str] = []
    launcher = FakeLauncher()
    original_spawn = launcher.spawn

    def observed_spawn(request: StageLaunchRequest) -> FakeProcess:
        events.append(f"spawn:{request.stage_index}")
        return original_spawn(request)

    launcher.spawn = observed_spawn  # type: ignore[method-assign]
    observer = FakeDirectEvidenceObserver(events)
    result = _executor(
        executable=executable,
        launcher=launcher,
        direct_evidence_observer=observer,
    ).execute(plan, materialized, context)

    assert result.outcome == "COMPLETED"
    assert events == [
        item
        for index in range(len(plan.stages))
        for item in (f"prepare:{index}", f"spawn:{index}", f"finalize:{index}")
    ]
    assert len(observer.prepare_requests) == len(observer.finalize_requests) == len(
        plan.stages
    )
    for projected in materialized.stage_runtime_paths:
        stage_result = json.loads(Path(projected["result"]).read_text(encoding="utf-8"))
        index = int(projected["index"])
        assert stage_result["control_evidence"] == [
            f"fixture:observer-prepared:{index}",
            f"fixture:observer-finalized:{index}",
        ]
        observation = stage_result["control_observation_trace"]
        assert observation["record_count"] == 1
        observation_path = Path(observation["path"])
        record = json.loads(observation_path.read_text(encoding="utf-8"))
        assert record == {
            "stage_index": index,
            "time": "2026-07-20T00:00:00+00:00",
            "type": "adapter.fixture_direct_evidence",
        }


def test_direct_evidence_observer_cannot_change_stage_launch(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    launcher = FakeLauncher()
    observer = FakeDirectEvidenceObserver([], alter_argv=True)

    with pytest.raises(
        KimiStageExecutorError,
        match="direct evidence observer attempted to alter stage execution",
    ):
        _executor(
            executable=executable,
            launcher=launcher,
            direct_evidence_observer=observer,
        ).execute(plan, materialized, context)

    assert launcher.requests == []
    assert observer.finalize_requests == []


def test_executor_applies_matched_control_before_exact_stage_and_revalidates_manifest(
    tmp_path: Path,
) -> None:
    parent_run_id = "executor-control"
    case = _first_case("T3_shared_artifact_supply_chain")
    control = materialize_control_trial(
        repo_root=REPO_ROOT,
        case_dir=case.case_dir,
        batch_root=tmp_path / "control-batch",
        run_id=parent_run_id,
        control_type="cleanup_control",
        callback_url="http://127.0.0.1:49173",
        capability_states=ALL_SUPPORTED,
        expected_suite_id=case.suite,
    )
    trial_run_id = control.layout.trial_run_id
    manifest = load_bench_materialization_manifest(control.bench_manifest_path)
    stage_paths = tuple(
        dict(stage["runtime_paths"]) | {
            "index": stage["index"],
            "name": stage["name"],
        }
        for stage in manifest["stages"]
    )
    first = stage_paths[0]
    materialized = MaterializedCase(
        case_id=case.case_id,
        root=control.layout.root,
        workspace=Path(manifest["materialized"]["workspace_dir"]),
        config=Path(first["kimi_home"]),
        trace=Path(first["trace"]).parent,
        result=Path(first["result"]).parent,
        session=Path(first["session"]),
        cache=Path(first["cache"]),
        artifact=Path(first["artifact"]),
        manifest_path=control.bench_manifest_path,
        stage_runtime_paths=stage_paths,
        launch_disposition="READY",
    )
    plan = DefaultPlanBuilder().build(
        case,
        CaseRunLayout(
            run_id=trial_run_id,
            case_id=case.case_id,
            root=control.layout.root,
            workspace=materialized.workspace,
            config=materialized.config,
            trace=materialized.trace,
            result=materialized.result,
            session=materialized.session,
            cache=materialized.cache,
            artifact=materialized.artifact,
            pid_record=control.layout.pid / f"pids-kimi-{trial_run_id}.json",
        ),
    )
    case_layout = CaseRunLayout(
        run_id=trial_run_id,
        case_id=case.case_id,
        root=control.layout.root,
        workspace=materialized.workspace,
        config=materialized.config,
        trace=materialized.trace,
        result=materialized.result,
        session=materialized.session,
        cache=materialized.cache,
        artifact=materialized.artifact,
        pid_record=control.layout.pid / f"pids-kimi-{trial_run_id}.json",
    )
    registry = FakeRegistry(run_id=trial_run_id, record_path=case_layout.pid_record)
    context = ExecutionContext(
        run_id=trial_run_id,
        case_layout=case_layout,
        process_registry=registry,  # type: ignore[arg-type]
        loopback_port=object(),  # type: ignore[arg-type]
    )
    executable = tmp_path / "kimi-control-fixture-executable"
    executable.write_bytes(b"#!/bin/sh\nexit 99\n")
    executable.chmod(0o700)

    class ProducingLauncher(FakeLauncher):
        def spawn(self, request: StageLaunchRequest) -> FakeProcess:
            if request.stage_index == 0:
                carrier = request.cwd / "reports/generated_decision.md"
                carrier.parent.mkdir(parents=True, exist_ok=True)
                carrier.write_text("run-local producer output\n", encoding="utf-8")
            return super().spawn(request)

    launcher = ProducingLauncher()
    result = _executor(
        executable=executable,
        launcher=launcher,
        matched_control_boundary=KimiMatchedControlBoundary(control),
    ).execute(plan, materialized, context)

    assert result.outcome == "COMPLETED"
    assert len(launcher.requests) == 2
    assert launcher.requests[0].materialization_manifest_sha256 != (
        launcher.requests[1].materialization_manifest_sha256
    )
    assert launcher.requests[1].materialization_manifest_sha256 == sha256_file(
        control.bench_manifest_path
    )
    assert not (materialized.workspace / "reports/generated_decision.md").exists()
    matched = result.metadata["matched_control_intervention"]
    assert matched["applied_before_stage_indices"] == [2]
    assert matched["sha256"] == sha256_file(control.intervention_path)
    _assert_no_scoring_keys(result.metadata)


def test_nonzero_process_is_execution_invalid_and_not_retryable(tmp_path: Path) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    normalizer = FakeNormalizer()

    result = _executor(
        executable=executable,
        launcher=FakeLauncher(return_code=17),
        normalizer=normalizer,
    ).execute(plan, materialized, context)

    assert result.outcome == "EXECUTION_INVALID"
    assert result.failure_category == "PROCESS_EXIT_NONZERO"
    assert result.retry_eligible is False
    assert result.event_ir_path is None
    assert result.raw_stdout_path is not None
    assert result.raw_wire_path is not None
    assert normalizer.requests == []


def test_explicit_provider_timeout_is_the_only_retryable_executor_result(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    normalizer = FakeNormalizer()

    result = _executor(
        executable=executable,
        launcher=FakeLauncher(timeout_once=True),
        normalizer=normalizer,
    ).execute(plan, materialized, context)

    assert result.outcome == "EXECUTION_INVALID"
    assert result.failure_category == "PROVIDER_TIMEOUT"
    assert result.retry_eligible is True
    assert result.event_ir_path is None
    assert normalizer.requests == []


def test_1200_second_prompt_timeout_is_terminal_model_protocol_incomplete(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    normalizer = FakeNormalizer()

    result = _executor(
        executable=executable,
        launcher=FakeLauncher(timeout_once=True),
        normalizer=normalizer,
        timeout_seconds=1200,
    ).execute(plan, materialized, context)

    assert result.outcome == "MODEL_PROTOCOL_INCOMPLETE"
    assert result.failure_category == "MODEL_STAGE_TIMEOUT"
    assert result.retry_eligible is False
    assert result.raw_stdout_path is not None
    assert result.raw_wire_path is not None
    assert result.event_ir_path is None
    assert result.metadata["execution_disposition"] == {
        "outcome": "MODEL_PROTOCOL_INCOMPLETE",
        "failure_category": "MODEL_STAGE_TIMEOUT",
        "retry_eligible": False,
        "reason": (
            "Kimi prompt stage did not complete within the reviewed "
            "1200-second model protocol limit"
        ),
    }
    assert result.metadata["stages"][0]["timed_out"] is True
    assert result.metadata["stages"][0]["timeout_seconds"] == 1200
    stage_document = json.loads(
        Path(result.metadata["stages"][0]["result_path"]).read_text(
            encoding="utf-8"
        )
    )
    assert stage_document["execution_disposition"]["outcome"] == (
        "MODEL_PROTOCOL_INCOMPLETE"
    )
    assert stage_document["execution_disposition"]["timeout_seconds"] == 1200
    assert normalizer.requests == []


def test_controller_model_protocol_error_preserves_raw_capture_and_is_terminal(
    tmp_path: Path,
) -> None:
    class ProtocolController:
        def prepare(self, request: StageControlRequest) -> ControlDirective:
            return ControlDirective(
                evidence_locators=(f"fixture:{request.control_kind}",)
            )

        def finalize(self, request: StageControlFinalizeRequest) -> ControlFinalization:
            raise KimiModelProtocolIncompleteError(
                "direct native tool trace omitted the required neutral handoff"
            )

    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="T3_subagent_poisoning",
    )
    normalizer = FakeNormalizer()

    result = _executor(
        executable=executable,
        launcher=FakeLauncher(),
        normalizer=normalizer,
        subagent_controller=ProtocolController(),
    ).execute(plan, materialized, context)

    assert result.outcome == "MODEL_PROTOCOL_INCOMPLETE"
    assert result.failure_category == "MODEL_PROTOCOL_DEVIATION"
    assert result.retry_eligible is False
    assert result.raw_stdout_path is not None and result.raw_stdout_path.is_file()
    assert result.raw_wire_path is not None and result.raw_wire_path.is_file()
    assert result.event_ir_path is None
    assert normalizer.requests == []


def test_normalizer_has_typed_model_protocol_and_invalid_trace_seams(
    tmp_path: Path,
) -> None:
    class ProtocolNormalizer:
        def normalize(self, request: NormalizationRequest) -> Path:
            raise KimiModelProtocolIncompleteError(
                "captured expected behavior is directly absent"
            )

    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    result = _executor(
        executable=executable,
        launcher=FakeLauncher(),
        normalizer=ProtocolNormalizer(),  # type: ignore[arg-type]
    ).execute(plan, materialized, context)
    assert result.outcome == "MODEL_PROTOCOL_INCOMPLETE"
    assert result.retry_eligible is False
    assert result.raw_stdout_path is not None

    plan2, materialized2, context2, executable2, _ = _materialized_fixture(
        tmp_path / "invalid-normalizer"
    )

    class CorruptNormalizer:
        def normalize(self, request: NormalizationRequest) -> Path:
            raise ValueError("malformed trace fixture")

    with pytest.raises(KimiStageExecutorError) as caught:
        _executor(
            executable=executable2,
            launcher=FakeLauncher(),
            normalizer=CorruptNormalizer(),  # type: ignore[arg-type]
        ).execute(plan2, materialized2, context2)
    assert caught.value.failure_category == "TRACE_NORMALIZATION_INVALID"
    assert caught.value.retry_eligible is False


def test_tampered_hash_bound_prompt_fails_before_attestation_or_spawn(tmp_path: Path) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    manifest = load_bench_materialization_manifest(materialized.manifest_path)
    prompt = Path(manifest["stages"][0]["prompt"]["materialized_path"])
    prompt.write_text("tampered prompt\n", encoding="utf-8")
    launcher = FakeLauncher()

    with pytest.raises(KimiStageExecutorError, match="prompt SHA-256 drifted"):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.attest_calls == 0
    assert launcher.requests == []


def test_manifest_self_hash_tamper_fails_before_attestation_or_spawn(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    document["case_id"] = "resigned-only-by-attacker"
    materialized.manifest_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    launcher = FakeLauncher()

    with pytest.raises(
        KimiBenchMaterializationError, match="manifest payload SHA-256 mismatch"
    ):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.attest_calls == 0
    assert launcher.requests == []


def test_invalid_isolation_attestation_fails_before_spawn(tmp_path: Path) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    launcher = FakeLauncher(valid_attestation=False)

    with pytest.raises(KimiStageExecutorError, match="isolation attestation is insufficient"):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.attest_calls == 1
    assert launcher.requests == []


@pytest.mark.parametrize("control_kind", ("resume", "compact", "subagent"))
def test_native_boundary_without_injected_controller_fails_before_launch(
    tmp_path: Path, control_kind: str
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    stage = document["stages"][0]
    if control_kind == "subagent":
        stage["surfaces"]["subagent"] = {
            "kind": "native",
            "controller": {"kind": "fixture", "required": True},
        }
    else:
        operation = (
            "native_compact_exact" if control_kind == "compact" else "resume_exact_session"
        )
        stage["surfaces"]["session"]["controller"] = {
            "kind": f"fixture_{control_kind}_controller",
            "required": True,
            "operation": operation,
            "argv_contract": {"forbidden_flags": ["--continue"]},
        }
    _resign_manifest(materialized.manifest_path, document)
    launcher = FakeLauncher()

    with pytest.raises(
        KimiStageExecutorError,
        match=f"native boundary controller not injected: {control_kind}",
    ):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.attest_calls == 0
    assert launcher.requests == []


def test_resume_controller_must_use_exact_session_and_never_continue(tmp_path: Path) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    for index, stage in enumerate(document["stages"]):
        stage["surfaces"]["session"]["controller"] = {
            "kind": "kimi_exact_native_session_resume_v1",
            "required": True,
            "operation": (
                "create_and_capture_exact_session"
                if index == 0
                else "resume_exact_captured_session"
            ),
            "argv_contract": (
                {"forbidden_flags": ["--continue", "--session"]}
                if index == 0
                else {
                    "required_flag": "--session",
                    "forbidden_flags": ["--continue"],
                }
            ),
        }
    _resign_manifest(materialized.manifest_path, document)
    launcher = FakeLauncher()

    result = _executor(
        executable=executable,
        launcher=launcher,
        resume_controller=FakeController(),
    ).execute(plan, materialized, context)

    assert result.outcome == "COMPLETED"
    assert "--session" not in launcher.requests[0].argv
    assert launcher.requests[1].argv[-2:] == ("--session", "session_fixture")
    assert all("--continue" not in request.argv for request in launcher.requests)


def test_resume_controller_routing_ignores_compaction_text_in_session_key(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="T3_compaction_resume_poisoning",
        case_dir_fragment="CR.02_resume_context_poisoning/case_006",
    )
    manifest = load_bench_materialization_manifest(materialized.manifest_path)
    controllers = [
        stage["surfaces"]["session"]["controller"] for stage in manifest["stages"]
    ]
    assert all(
        controller["kind"] == "kimi_exact_native_session_resume_v1"
        for controller in controllers
    )
    assert any("compaction" in controller["session_key"] for controller in controllers)
    launcher = FakeLauncher()

    result = _executor(
        executable=executable,
        launcher=launcher,
        resume_controller=FakeController(),
    ).execute(plan, materialized, context)

    assert result.outcome == "COMPLETED"
    assert len(launcher.requests) == 2
    assert launcher.requests[1].argv[-2:] == ("--session", "session_fixture")


def test_acp_compaction_stage_is_controller_owned_and_never_a_model_prompt(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="T3_compaction_resume_poisoning",
        case_dir_fragment="CR.06_summary_priority_inversion/case_030",
    )
    launcher = FakeLauncher()

    result = _executor(
        executable=executable,
        launcher=launcher,
        compact_controller=FakeCompactController(),
    ).execute(plan, materialized, context)

    assert result.outcome == "COMPLETED"
    assert len(launcher.requests) == 3
    assert launcher.requests[0].argv[1] == "--prompt"
    assert launcher.requests[1].argv == (str(executable.resolve()), "acp")
    assert "--prompt" not in launcher.requests[1].argv
    assert "/compact" not in launcher.requests[1].argv
    assert launcher.requests[2].argv[-2:] == ("--session", "session_fixture")
    manifest = load_bench_materialization_manifest(materialized.manifest_path)
    acp_trace = Path(manifest["stages"][1]["runtime_paths"]["acp_trace"])
    assert acp_trace.is_file()
    assert sha256_file(acp_trace) == sha256_file(
        Path(manifest["stages"][1]["runtime_paths"]["trace"])
    )
    stage_result = json.loads(
        Path(manifest["stages"][1]["runtime_paths"]["result"]).read_text(
            encoding="utf-8"
        )
    )
    directive = FakeCompactController().prepare(
        StageControlRequest(
            run_id=context.run_id,
            case_id=materialized.case_id,
            stage_index=1,
            stage_name=str(manifest["stages"][1]["name"]),
            control_kind="compact",
            stage_document=manifest["stages"][1],
            prior_stage_results=(),
        )
    )
    assert directive.jsonrpc_exchange is not None
    assert stage_result["controller_request_sha256"] == [
        hashlib.sha256(frame).hexdigest()
        for frame in directive.jsonrpc_exchange.request_frames
    ]
    assert launcher.processes[1].jsonrpc_exchanges == [
        (
            directive.jsonrpc_exchange.request_frames,
            directive.jsonrpc_exchange.expected_response_ids,
        )
    ]


def test_acp_error_response_is_preserved_as_hash_bound_execution_evidence(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="T3_compaction_resume_poisoning",
        case_dir_fragment="CR.06_summary_priority_inversion/case_030",
    )
    launcher = FakeLauncher(jsonrpc_failure_id=2)

    result = _executor(
        executable=executable,
        launcher=launcher,
        compact_controller=FakeCompactController(),
    ).execute(plan, materialized, context)

    assert result.outcome == "EXECUTION_INVALID"
    assert result.failure_category == "EXECUTOR_EVIDENCE_INVALID"
    assert result.retry_eligible is False
    assert result.raw_stdout_path is not None
    assert result.raw_stdout_path.is_file()
    assert result.raw_wire_path is None
    manifest = load_bench_materialization_manifest(materialized.manifest_path)
    failed_stage = manifest["stages"][1]
    stage_result_path = Path(failed_stage["runtime_paths"]["result"])
    stage_result = json.loads(stage_result_path.read_text(encoding="utf-8"))
    assert stage_result["execution_disposition"] == {
        "outcome": "EXECUTION_INVALID",
        "failure_category": "EXECUTOR_EVIDENCE_INVALID",
        "retry_eligible": False,
        "reason": "ACP JSON-RPC response 2 was not successful",
    }
    for evidence_kind in ("stdout", "stderr", "controller_trace"):
        evidence = stage_result[evidence_kind]
        assert sha256_file(Path(evidence["path"])) == evidence["sha256"]


def test_stage_activation_replaces_then_removes_only_run_local_skill_surface(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="v2_skill_runtime",
        case_dir_fragment="F2.01_perm_claim_spoofing/sk_i_case_102",
    )
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    first_activation = document["stages"][0]["surfaces"]["skills"]["activation"]
    expected_first_sha = first_activation["source_sha256"]
    second_skills = document["stages"][1]["surfaces"]["skills"]
    second_skills["kind"] = "none"
    second_skills["activation"] = {
        "operation": "remove_tree_if_present",
        "target": "workspace/.kimi-code/skills",
        "launch_flag": "--skills-dir",
    }
    _resign_manifest(materialized.manifest_path, document)
    launcher = FakeLauncher()

    result = _executor(executable=executable, launcher=launcher).execute(
        plan, materialized, context
    )

    assert result.outcome == "COMPLETED"
    assert launcher.surface_snapshots == [
        {"skills_sha256": expected_first_sha, "mcp_sha256": None},
        {"skills_sha256": None, "mcp_sha256": None},
    ]
    assert not (materialized.workspace / ".kimi-code" / "skills").exists()


def test_duplicate_pid_cannot_count_as_fresh_process(tmp_path: Path) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    launcher = FakeLauncher(duplicate_pid=True)

    with pytest.raises(KimiStageExecutorError, match="new OS process"):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert len(launcher.requests) == 2
    assert launcher.processes[-1].terminated is True


def test_event_ir_with_scoring_field_is_rejected(tmp_path: Path) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    launcher = FakeLauncher()

    with pytest.raises(KimiStageExecutorError, match="analyzer/scoring fields"):
        _executor(
            executable=executable,
            launcher=launcher,
            normalizer=FakeNormalizer(include_score=True),
        ).execute(plan, materialized, context)


def test_mcp_config_must_retain_kimi_proxy_even_if_manifest_is_resigned(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="v2_tool_mcp_runtime",
        case_dir_fragment="f301_rii/case_018",
    )
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    mcp = document["stages"][0]["surfaces"]["mcp"]
    prepared = Path(mcp["prepared_config"]["target"])
    config = json.loads(prepared.read_text(encoding="utf-8"))
    server = next(iter(config["mcpServers"].values()))
    server["command"] = "/usr/bin/python3"
    server["args"] = ["/tmp/unwrapped-fixture.py"]
    prepared.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")
    changed_sha = sha256_file(prepared)
    mcp["prepared_config"]["materialized_sha256"] = changed_sha
    mcp["prepared_config"]["evidence_proxy"]["materialized_sha256"] = changed_sha
    mcp["activation"]["source_sha256"] = changed_sha
    _resign_manifest(materialized.manifest_path, document)
    launcher = FakeLauncher()

    with pytest.raises(KimiStageExecutorError, match="Python proxy"):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.requests == []


def test_mcp_run_local_proxy_tamper_fails_closed_before_launch(tmp_path: Path) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="v2_tool_mcp_runtime",
        case_dir_fragment="f301_rii/case_018",
    )
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    proxy = document["stages"][0]["surfaces"]["mcp"]["prepared_config"][
        "evidence_proxy"
    ]
    proxy_copy = Path(proxy["run_local_proxy_copy_path"])
    proxy_copy.chmod(0o600)
    proxy_copy.write_bytes(proxy_copy.read_bytes() + b"\n# tampered\n")
    proxy_copy.chmod(0o400)
    launcher = FakeLauncher()

    with pytest.raises(KimiStageExecutorError, match="immutable run-local"):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.requests == []


def test_mcp_proxy_path_escape_fails_closed_even_with_resigned_manifest(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="v2_tool_mcp_runtime",
        case_dir_fragment="f301_rii/case_018",
    )
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    mcp = document["stages"][0]["surfaces"]["mcp"]
    proxy = mcp["prepared_config"]["evidence_proxy"]
    original_copy = Path(proxy["run_local_proxy_copy_path"])
    escaped_copy = tmp_path / "mcp-stdio-proxy-kimi-executor-fixture-escaped.py"
    escaped_copy.write_bytes(original_copy.read_bytes())
    escaped_copy.chmod(0o400)
    escaped_sha = sha256_file(escaped_copy)
    proxy["run_local_proxy_copy_path"] = str(escaped_copy)
    proxy["run_local_proxy_copy_sha256"] = escaped_sha
    proxy["proxy_implementation_path"] = str(escaped_copy)
    proxy["proxy_implementation_sha256"] = escaped_sha
    config_path = Path(mcp["prepared_config"]["target"])
    config = json.loads(config_path.read_text(encoding="utf-8"))
    server = next(iter(config["mcpServers"].values()))
    server["args"][0] = str(escaped_copy)
    for reservation in mcp["evidence_proxy"]["server_reservations"]:
        reservation["run_local_proxy_copy_path"] = str(escaped_copy)
        reservation["run_local_proxy_copy_sha256"] = escaped_sha
        reservation["proxy_implementation_path"] = str(escaped_copy)
        reservation["proxy_implementation_sha256"] = escaped_sha
        new_proxy_sha = _canonical_sha(
            [server["command"], *server["args"]]
        )
        reservation["proxy_argv_sha256"] = new_proxy_sha
        proxy["wrapped_servers"][reservation["server"]][
            "proxy_argv_sha256"
        ] = new_proxy_sha
    _write_mcp_config_and_resign(materialized.manifest_path, document, config)
    launcher = FakeLauncher()

    with pytest.raises(KimiStageExecutorError, match="escapes the current Kimi run"):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.requests == []


def test_mcp_proxy_source_drift_fails_closed_even_with_resigned_manifest(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="v2_tool_mcp_runtime",
        case_dir_fragment="f301_rii/case_018",
    )
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    mcp = document["stages"][0]["surfaces"]["mcp"]
    proxy = mcp["prepared_config"]["evidence_proxy"]
    alternate_source = REPO_ROOT / "infra/cross_harness/adapters/kimi/bench_materializer.py"
    proxy["trusted_proxy_source_path"] = str(alternate_source)
    proxy["trusted_proxy_source_sha256"] = sha256_file(alternate_source)
    for reservation in mcp["evidence_proxy"]["server_reservations"]:
        reservation["trusted_proxy_source_path"] = str(alternate_source)
        reservation["trusted_proxy_source_sha256"] = sha256_file(alternate_source)
    _resign_manifest(materialized.manifest_path, document)
    launcher = FakeLauncher()

    with pytest.raises(KimiStageExecutorError, match="immutable run-local"):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.requests == []


def test_mcp_child_cannot_reintroduce_an_unmounted_venv_python(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="v2_tool_mcp_runtime",
        case_dir_fragment="f301_rii/case_018",
    )
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    mcp = document["stages"][0]["surfaces"]["mcp"]
    config_path = Path(mcp["prepared_config"]["target"])
    config = json.loads(config_path.read_text(encoding="utf-8"))
    server_name, server = next(iter(config["mcpServers"].items()))
    separator = server["args"].index("--")
    child_argv = server["args"][separator + 1 :]
    child_argv[0] = "/tmp/kimi-unmounted-venv/bin/python"
    child_sha = _canonical_sha(child_argv)
    server["args"][separator + 1 :] = child_argv
    child_flag = server["args"].index("--child-argv-sha256") + 1
    server["args"][child_flag] = child_sha
    reservation = mcp["evidence_proxy"]["server_reservations"][0]
    reservation["child_argv_sha256"] = child_sha
    reservation["proxy_argv_sha256"] = _canonical_sha(
        [server["command"], *server["args"]]
    )
    mcp["prepared_config"]["evidence_proxy"]["wrapped_servers"][server_name] = {
        "child_argv_sha256": child_sha,
        "proxy_argv_sha256": reservation["proxy_argv_sha256"],
    }
    mcp["prepared_config"]["child_commands"][server_name][
        "argv_sha256"
    ] = child_sha
    _write_mcp_config_and_resign(materialized.manifest_path, document, config)
    launcher = FakeLauncher()

    with pytest.raises(KimiStageExecutorError, match="pinned system Python"):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.requests == []


def test_mcp_health_validator_is_called_after_the_stage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="v2_tool_mcp_runtime",
        case_dir_fragment="f301_rii/case_018",
    )
    calls: list[dict[str, Any]] = []

    def fake_validate_health_evidence(**kwargs: Any) -> Mapping[str, Any]:
        calls.append(dict(kwargs))
        paths = kwargs["paths"]
        common = {
            "schema_name": "fixture_mcp_evidence",
            "time": "2026-07-20T00:00:00+00:00",
        }
        initialize_records = (
            {**common, "jsonrpc_kind": "request"},
            {**common, "jsonrpc_kind": "response"},
        )
        tools_records = (
            {**common, "jsonrpc_kind": "request"},
            {**common, "jsonrpc_kind": "response"},
        )
        for path, records in (
            (paths.initialize_trace, initialize_records),
            (paths.tools_list_trace, tools_records),
            (paths.stdio_trace, (*initialize_records, *tools_records)),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
                encoding="utf-8",
            )
        paths.child_exit_trace.write_text(
            json.dumps({**common, "exit_code": 0}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {
            "status": "connected",
            "server": kwargs["server"],
            "child_argv_sha256": kwargs["child_argv_sha256"],
            "initialize_request_locator": f"{paths.initialize_trace}:1",
            "initialize_result_locator": f"{paths.initialize_trace}:2",
            "tools_list_request_locator": f"{paths.tools_list_trace}:1",
            "tools_list_result_locator": f"{paths.tools_list_trace}:2",
            "child_exit_locator": str(paths.child_exit_trace),
        }

    monkeypatch.setattr(
        "infra.cross_harness.adapters.kimi.executor.validate_health_evidence",
        fake_validate_health_evidence,
    )
    launcher = FakeLauncher()
    result = _executor(executable=executable, launcher=launcher).execute(
        plan, materialized, context
    )

    assert result.outcome == "COMPLETED"
    assert calls
    assert all(call["run_id"] == context.run_id for call in calls)
    assert all(call["run_root"] == materialized.root.resolve() for call in calls)
    assert all(call["stage_index"] in {0, 1} for call in calls)
    observed_health = 0
    for stage in result.metadata["stages"]:
        if not stage["mcp_health"]:
            continue
        observation_path = Path(stage["observation_trace_path"])
        records = [
            json.loads(line)
            for line in observation_path.read_text(encoding="utf-8").splitlines()
        ]
        assert records[0]["type"] == "adapter.mcp_health_observed"
        assert set(records[0]["paths"]) == {
            "initialize_trace",
            "tools_list_trace",
            "stdio_trace",
            "child_exit_trace",
        }
        observed_health += 1
    assert observed_health == len(calls)


def test_timeout_is_not_masked_by_missing_mcp_child_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(
        tmp_path,
        suite="v2_tool_mcp_runtime",
        case_dir_fragment="f301_rii/case_018",
    )

    def fail_if_called(**_kwargs: Any) -> Mapping[str, Any]:
        raise AssertionError("MCP health must not override a forced stage timeout")

    monkeypatch.setattr(
        "infra.cross_harness.adapters.kimi.executor.validate_health_evidence",
        fail_if_called,
    )
    result = _executor(
        executable=executable,
        launcher=FakeLauncher(timeout_once=True),
        timeout_seconds=1200,
    ).execute(plan, materialized, context)

    assert result.outcome == "MODEL_PROTOCOL_INCOMPLETE"
    assert result.failure_category == "MODEL_STAGE_TIMEOUT"
    assert result.retry_eligible is False
    assert result.metadata["stages"][0]["mcp_health"] == []
    assert result.metadata["stages"][0]["timed_out"] is True


def test_resigned_manifest_cannot_alias_canonical_to_run_local_workspace(
    tmp_path: Path,
) -> None:
    plan, materialized, context, executable, _ = _materialized_fixture(tmp_path)
    document = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    document["canonical"]["case_dir"] = str(materialized.workspace)
    document["canonical"]["tree_sha256"] = tree_sha256(materialized.workspace)
    document["canonical"]["tree_sha256_after"] = document["canonical"]["tree_sha256"]
    _resign_manifest(materialized.manifest_path, document)
    launcher = FakeLauncher()

    with pytest.raises(KimiStageExecutorError, match="canonical case differs"):
        _executor(executable=executable, launcher=launcher).execute(
            plan, materialized, context
        )

    assert launcher.requests == []


def _source_validation_fixture(
    tmp_path: Path,
) -> tuple[KimiStageExecutor, NormalizationRequest, Path]:
    run_id = "source-validation-001"
    case_id = "source-validation-case"
    run_root = tmp_path / f"run-kimi-{run_id}"
    run_root.mkdir()
    executable = run_root / f"kimi-executable-{run_id}"
    executable.write_bytes(b"#!/bin/sh\nexit 99\n")
    executable.chmod(0o700)
    executor = _executor(executable=executable, launcher=FakeLauncher())

    stdout = run_root / f"stdout-kimi-{run_id}.jsonl"
    stdout.write_text('{"fixture":"stdout"}\n', encoding="utf-8")
    captured_wire = run_root / f"captured-wire-kimi-{run_id}.jsonl"
    captured_wire.write_text('{"fixture":"captured"}\n', encoding="utf-8")
    wire_sha = sha256_file(captured_wire)
    native_wire = run_root / f"native-wire-kimi-{run_id}.jsonl"
    native_wire.write_text(
        '{"fixture":"captured"}\n{"fixture":"later-stage-append"}\n',
        encoding="utf-8",
    )
    main_wire = run_root / f"main-wire-kimi-{run_id}.jsonl"
    main_wire.write_bytes(captured_wire.read_bytes())
    wire = WireCapture(
        source_path=native_wire,
        captured_path=captured_wire,
        sha256=wire_sha,
        line_count=1,
        is_main=True,
    )

    mcp_root = run_root / f"mcp-evidence-kimi-{run_id}"
    mcp_root.mkdir()
    initialize = mcp_root / f"initialize-kimi-{run_id}.jsonl"
    tools_list = mcp_root / f"tools-list-kimi-{run_id}.jsonl"
    stdio = mcp_root / f"stdio-kimi-{run_id}.jsonl"
    child_exit = mcp_root / f"child-exit-kimi-{run_id}.json"
    initialize.write_text('{"kind":"request"}\n{"kind":"response"}\n', encoding="utf-8")
    tools_list.write_text('{"kind":"request"}\n{"kind":"response"}\n', encoding="utf-8")
    stdio.write_text(
        '{"kind":"request"}\n{"kind":"response"}\n', encoding="utf-8"
    )
    child_exit.write_text('{"exit_code":0}\n', encoding="utf-8")
    evidence_files = [
        {
            "kind": kind,
            "path": str(path),
            "sha256": sha256_file(path),
            "line_count": len(path.read_bytes().splitlines()),
        }
        for kind, path in (
            ("initialize_trace", initialize),
            ("tools_list_trace", tools_list),
            ("stdio_trace", stdio),
            ("child_exit_trace", child_exit),
        )
    ]
    health = {
        "status": "connected",
        "server": "fixture-server",
        "child_argv_sha256": hashlib.sha256(b"fixture-child").hexdigest(),
        "initialize_request_locator": f"{initialize}:1",
        "initialize_result_locator": f"{initialize}:2",
        "tools_list_request_locator": f"{tools_list}:1",
        "tools_list_result_locator": f"{tools_list}:2",
        "child_exit_locator": str(child_exit),
        "evidence_files": evidence_files,
    }
    capture = StageCapture(
        index=0,
        name="attack",
        pid=41001,
        return_code=0,
        stdout_path=stdout,
        stdout_sha256=sha256_file(stdout),
        stderr_path=run_root / f"stderr-kimi-{run_id}.log",
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        main_wire_path=main_wire,
        main_wire_sha256=wire_sha,
        wire_captures=(wire,),
        result_path=run_root / f"result-kimi-{run_id}.json",
        mcp_health=(health,),
    )
    output = run_root / f"event-ir-kimi-{run_id}.jsonl"
    events = (
        {
            "schema_name": "safety_bench_cross_harness_event",
            "schema_version": 1,
            "event_id": "fixture:wire-source",
            "event_type": "skill.discovered",
            "run_id": run_id,
            "case_id": case_id,
            "harness": {
                "id": "kimi",
                "version": "0.26.0",
                "feature_flags": {},
            },
            "stage": {"name": "attack", "index": 0},
            "sequence": 0,
            "timestamp": "2026-07-20T00:00:00+00:00",
            "source": {
                "trace_path": str(native_wire),
                "line": 1,
                "raw_event_type": "fixture.native_wire",
            },
            "attributes": {
                "skill_name": "fixture",
                "skill_sha256": hashlib.sha256(b"fixture").hexdigest(),
            },
        },
        {
            "schema_name": "safety_bench_cross_harness_event",
            "schema_version": 1,
            "event_id": "fixture:mcp-source",
            "event_type": "mcp.server_initialized",
            "run_id": run_id,
            "case_id": case_id,
            "harness": {
                "id": "kimi",
                "version": "0.26.0",
                "feature_flags": {},
            },
            "stage": {"name": "attack", "index": 0},
            "sequence": 1,
            "timestamp": "2026-07-20T00:00:01+00:00",
            "source": {
                "trace_path": str(initialize),
                "line": 2,
                "raw_event_type": "fixture.mcp_initialize",
            },
            "attributes": {"status": "connected"},
            "tool": {"server": "fixture-server"},
        },
    )
    output.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )
    request = NormalizationRequest(
        run_id=run_id,
        case_id=case_id,
        manifest_path=run_root / f"manifest-kimi-{run_id}.json",
        manifest_sha256=hashlib.sha256(b"fixture-manifest").hexdigest(),
        stage_captures=(capture,),
        output_path=output,
    )
    return executor, request, initialize


def test_event_ir_accepts_only_hash_pinned_native_wire_and_mcp_locator_sources(
    tmp_path: Path,
) -> None:
    executor, request, _ = _source_validation_fixture(tmp_path)

    executor._validate_event_ir(
        path=request.output_path,
        request=request,
        run_root=request.output_path.parent,
    )


def test_event_ir_rejects_mcp_locator_source_after_hash_drift(tmp_path: Path) -> None:
    executor, request, initialize = _source_validation_fixture(tmp_path)
    initialize.write_text('{"kind":"request"}\n{"kind":"tampered"}\n', encoding="utf-8")

    with pytest.raises(
        KimiStageExecutorError,
        match="MCP health evidence path/hash/line_count drifted",
    ):
        executor._validate_event_ir(
            path=request.output_path,
            request=request,
            run_root=request.output_path.parent,
        )
