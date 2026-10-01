from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import pytest

from infra.cross_harness.adapters.kimi.controllers import (
    ARTIFACT_RECORD_SCHEMA,
    COMPACTION_RECORD_SCHEMA,
    KimiAcpCompactionController,
    KimiControllerError,
    KimiExactSessionController,
    KimiSubagentArtifactController,
    SESSION_RECORD_SCHEMA,
)
from infra.cross_harness.adapters.kimi.executor import (
    StageControlFinalizeRequest,
    StageControlRequest,
)
from infra.cross_harness.adapters.kimi.materializer import sha256_file


RUN_ID = "controller-001"
CASE_ID = "case/controller-fixture"
SESSION_ID = "session_controller_fixture"


def _write_jsonl(path: Path, records: list[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _runtime(root: Path, workspace: Path, index: int, *, kimi_home: Path) -> dict[str, str]:
    runtime = root / f"stage-kimi-{RUN_ID}-{index:03d}" / f"runtime-kimi-{RUN_ID}-{index:03d}"
    runtime.mkdir(parents=True)
    for name in ("home", "cache", "artifact", "mcp-evidence", "session"):
        (runtime / f"{name}-kimi-{RUN_ID}-{index:03d}").mkdir()
    return {
        "workspace": str(workspace),
        "home": str(runtime / f"home-kimi-{RUN_ID}-{index:03d}"),
        "kimi_home": str(kimi_home),
        "cache": str(runtime / f"cache-kimi-{RUN_ID}-{index:03d}"),
        "artifact": str(runtime / f"artifact-kimi-{RUN_ID}-{index:03d}"),
        "mcp_evidence": str(runtime / f"mcp-evidence-kimi-{RUN_ID}-{index:03d}"),
        "trace": str(runtime / f"trace-kimi-{RUN_ID}-{index:03d}.jsonl"),
        "wire": str(runtime / f"wire-kimi-{RUN_ID}-{index:03d}.jsonl"),
        "result": str(runtime / f"result-kimi-{RUN_ID}-{index:03d}.json"),
        "session": str(runtime / f"session-kimi-{RUN_ID}-{index:03d}"),
        "pid_record": str(runtime / f"pid-kimi-{RUN_ID}-{index:03d}.json"),
    }


def _base_layout(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / f"case-kimi-{RUN_ID}"
    workspace = root / f"workspace-kimi-{RUN_ID}"
    workspace.mkdir(parents=True)
    (workspace / ".git").mkdir()
    return root, workspace


def _session_controller(
    *,
    operation: str,
    session_root: Path,
    kimi_home: Path,
    record_path: Path,
) -> dict[str, Any]:
    controller: dict[str, Any] = {
        "kind": "kimi_exact_native_session_resume_v1",
        "required": True,
        "operation": operation,
        "session_key": "fixture-session-key",
        "session_root": str(session_root),
        "kimi_code_home": str(kimi_home),
    }
    if operation == "create_and_capture_exact_session":
        controller["session_id_capture"] = {
            "source": "stream_json_meta_resume_hint",
            "json_pointer": "/session_id",
            "record_path": str(record_path),
            "sha256_required": True,
        }
        controller["argv_contract"] = {"forbidden_flags": ["--continue", "--session"]}
    else:
        controller["session_id_record_path"] = str(record_path)
        controller["require_same_session_id"] = True
        controller["argv_contract"] = {
            "required_flag": "--session",
            "forbidden_flags": ["--continue"],
        }
    return controller


def _stage_document(
    *,
    index: int,
    runtime: Mapping[str, str],
    controller: Mapping[str, Any],
    surface: str = "session",
) -> dict[str, Any]:
    surfaces: dict[str, Any] = {
        "session": {"controller": None},
        "subagent": {"kind": "none", "controller": None},
    }
    surfaces[surface] = {"kind": "native", "controller": dict(controller)}
    return {
        "index": index,
        "name": f"stage-{index}",
        "runtime_paths": dict(runtime),
        "surfaces": surfaces,
    }


def _request(
    stage: Mapping[str, Any],
    *,
    kind: str,
    prior: tuple[Mapping[str, Any], ...] = (),
) -> StageControlRequest:
    return StageControlRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        stage_index=int(stage["index"]),
        stage_name=str(stage["name"]),
        control_kind=kind,
        stage_document=stage,
        prior_stage_results=prior,
    )


def _finalize_request(
    stage: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    kind: str,
    prior: tuple[Mapping[str, Any], ...] = (),
) -> StageControlFinalizeRequest:
    return StageControlFinalizeRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        stage_index=int(stage["index"]),
        stage_name=str(stage["name"]),
        control_kind=kind,
        stage_document=stage,
        prior_stage_results=prior,
        stage_result=result,
    )


def _native_session(
    *,
    kimi_home: Path,
    workspace: Path,
    session_id: str = SESSION_ID,
    agents: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[Path, Path, Path]:
    session = kimi_home / "sessions" / "wd_fixture" / session_id
    main_wire = session / "agents" / "main" / "wire.jsonl"
    main_wire.parent.mkdir(parents=True, exist_ok=True)
    if agents is None:
        agents = {
            "main": {
                "homedir": str(main_wire.parent),
                "type": "main",
                "parentAgentId": None,
            }
        }
    state = {
        "workDir": str(workspace),
        "agents": dict(agents),
        "createdAt": "2026-07-20T00:00:00.000Z",
    }
    state_path = session / "state.json"
    state_path.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
    return session, state_path, main_wire


def _stage_result(
    *,
    runtime: Mapping[str, str],
    stdout_records: list[Mapping[str, Any]],
    captures: list[tuple[Path, bool]],
    controller_trace: Path | None = None,
    controller_request_sha256: list[str] | None = None,
) -> dict[str, Any]:
    stdout = Path(runtime["trace"])
    _write_jsonl(stdout, stdout_records)
    wire_captures = []
    main_sha = None
    for ordinal, (source, is_main) in enumerate(captures):
        digest = sha256_file(source)
        if is_main:
            main_sha = digest
        wire_captures.append(
            {
                "source_path": str(source),
                "captured_path": str(
                    Path(runtime["artifact"]) / f"wire-{ordinal:03d}.jsonl"
                ),
                "sha256": digest,
                "line_count": len(source.read_bytes().splitlines()),
                "is_main": is_main,
            }
        )
    assert main_sha is not None
    return {
        "return_code": 0,
        "timed_out": False,
        "stdout": {
            "path": str(stdout),
            "sha256": sha256_file(stdout),
            "line_count": len(stdout_records),
        },
        "wire": {
            "main_path": runtime["wire"],
            "main_sha256": main_sha,
            "captures": wire_captures,
        },
        "controller_trace": (
            {"path": str(controller_trace), "sha256": sha256_file(controller_trace)}
            if controller_trace is not None
            else None
        ),
        "controller_request_sha256": controller_request_sha256 or [],
        "control_evidence": [],
    }


def _hint(session_id: str = SESSION_ID) -> dict[str, Any]:
    return {
        "role": "meta",
        "type": "session.resume_hint",
        "session_id": session_id,
        "command": f"kimi -r {session_id}",
        "content": "fixture",
    }


def _seed_wire() -> list[Mapping[str, Any]]:
    return [
        {"type": "metadata", "time": 1784512800000},
        {
            "type": "llm.request",
            "kind": "loop",
            "messageCount": 2,
            "time": 1784512800001,
        },
        {"type": "usage.record", "time": 1784512800002},
    ]


def test_exact_session_record_and_resume_are_hash_bound(tmp_path: Path) -> None:
    root, workspace = _base_layout(tmp_path)
    kimi_home = root / f"config-kimi-{RUN_ID}-native-session"
    session_root = kimi_home / "sessions"
    session_root.mkdir(parents=True)
    record_path = root / f"session-id-kimi-{RUN_ID}-native.json"
    runtime0 = _runtime(root, workspace, 0, kimi_home=kimi_home)
    create = _session_controller(
        operation="create_and_capture_exact_session",
        session_root=session_root,
        kimi_home=kimi_home,
        record_path=record_path,
    )
    stage0 = _stage_document(index=0, runtime=runtime0, controller=create)
    _, _, wire = _native_session(kimi_home=kimi_home, workspace=workspace)
    _write_jsonl(wire, _seed_wire())
    result0 = _stage_result(
        runtime=runtime0,
        stdout_records=[{"role": "assistant", "content": "fixture"}, _hint()],
        captures=[(wire, True)],
    )
    controller = KimiExactSessionController()

    assert controller.prepare(_request(stage0, kind="resume")).argv_suffix == ()
    finalized0 = controller.finalize(
        _finalize_request(stage0, result0, kind="resume")
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))

    assert record["schema_name"] == SESSION_RECORD_SCHEMA
    assert record["session_id"] == SESSION_ID
    assert record["stdout_hint"]["line"] == 2
    assert record["wire"]["initial_request_line"] == 2
    assert any("session-record" in item for item in finalized0.evidence_locators)

    runtime1 = _runtime(root, workspace, 1, kimi_home=kimi_home)
    resume = _session_controller(
        operation="resume_exact_captured_session",
        session_root=session_root,
        kimi_home=kimi_home,
        record_path=record_path,
    )
    stage1 = _stage_document(index=1, runtime=runtime1, controller=resume)
    directive = controller.prepare(_request(stage1, kind="resume"))
    assert directive.argv_suffix == ("--session", SESSION_ID)

    resumed_records = [
        *_seed_wire(),
        {"type": "turn.prompt", "time": 1784512800100},
        {
            "type": "llm.request",
            "kind": "loop",
            "messageCount": 5,
            "time": 1784512800101,
        },
    ]
    _write_jsonl(wire, resumed_records)
    result1 = _stage_result(
        runtime=runtime1,
        stdout_records=[{"role": "assistant", "content": "resumed"}],
        captures=[(wire, True)],
    )
    finalized1 = controller.finalize(
        _finalize_request(stage1, result1, kind="resume", prior=(result0,))
    )

    assert len(finalized1.observation_records) == 1
    observed = finalized1.observation_records[0]
    assert observed["type"] == "adapter.session_resume_observed"
    assert observed["session_id"] == SESSION_ID
    assert observed["wire"]["before_line_count"] == 3
    assert observed["wire"]["resumed_request_line"] == 5


def test_session_capture_rejects_nested_or_ambiguous_session_id(tmp_path: Path) -> None:
    root, workspace = _base_layout(tmp_path)
    kimi_home = root / f"config-kimi-{RUN_ID}-native-session"
    session_root = kimi_home / "sessions"
    session_root.mkdir(parents=True)
    record_path = root / f"session-id-kimi-{RUN_ID}-native.json"
    runtime = _runtime(root, workspace, 0, kimi_home=kimi_home)
    create = _session_controller(
        operation="create_and_capture_exact_session",
        session_root=session_root,
        kimi_home=kimi_home,
        record_path=record_path,
    )
    stage = _stage_document(index=0, runtime=runtime, controller=create)
    _, _, wire = _native_session(kimi_home=kimi_home, workspace=workspace)
    _write_jsonl(wire, _seed_wire())
    result = _stage_result(
        runtime=runtime,
        stdout_records=[
            _hint(),
            {"role": "assistant", "meta": {"session_id": SESSION_ID}, "session_id": SESSION_ID},
        ],
        captures=[(wire, True)],
    )

    with pytest.raises(KimiControllerError, match="ambiguous"):
        KimiExactSessionController().finalize(
            _finalize_request(stage, result, kind="resume")
        )
    assert not record_path.exists()


def test_tampered_session_record_fails_before_resume(tmp_path: Path) -> None:
    root, workspace = _base_layout(tmp_path)
    kimi_home = root / f"config-kimi-{RUN_ID}-native-session"
    session_root = kimi_home / "sessions"
    session_root.mkdir(parents=True)
    record_path = root / f"session-id-kimi-{RUN_ID}-native.json"
    runtime0 = _runtime(root, workspace, 0, kimi_home=kimi_home)
    create = _session_controller(
        operation="create_and_capture_exact_session",
        session_root=session_root,
        kimi_home=kimi_home,
        record_path=record_path,
    )
    stage0 = _stage_document(index=0, runtime=runtime0, controller=create)
    _, _, wire = _native_session(kimi_home=kimi_home, workspace=workspace)
    _write_jsonl(wire, _seed_wire())
    result = _stage_result(runtime=runtime0, stdout_records=[_hint()], captures=[(wire, True)])
    controller = KimiExactSessionController()
    controller.finalize(_finalize_request(stage0, result, kind="resume"))
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["session_id"] = "session_tampered"
    record_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    runtime1 = _runtime(root, workspace, 1, kimi_home=kimi_home)
    resume = _session_controller(
        operation="resume_exact_captured_session",
        session_root=session_root,
        kimi_home=kimi_home,
        record_path=record_path,
    )
    stage1 = _stage_document(index=1, runtime=runtime1, controller=resume)

    with pytest.raises(KimiControllerError, match="self-hash"):
        controller.prepare(_request(stage1, kind="resume"))


def _compact_controller(
    *,
    operation: str,
    session_root: Path,
    kimi_home: Path,
    session_record: Path,
    compaction_record: Path | None = None,
    acp_trace: Path | None = None,
) -> dict[str, Any]:
    if operation == "create_and_capture_exact_session":
        controller = _session_controller(
            operation=operation,
            session_root=session_root,
            kimi_home=kimi_home,
            record_path=session_record,
        )
        controller["kind"] = "kimi_acp_exact_manual_compaction_resume_v1"
        return controller
    controller: dict[str, Any] = {
        "kind": "kimi_acp_exact_manual_compaction_resume_v1",
        "required": True,
        "operation": operation,
        "session_key": "fixture-session-key",
        "session_root": str(session_root),
        "kimi_code_home": str(kimi_home),
        "session_id_record_path": str(session_record),
        "require_same_session_id": True,
        "argv_contract": {
            "required_subcommand": "acp",
            "forbidden_flags": ["--continue", "--prompt"],
        },
    }
    if operation == "compact_exact_captured_session_via_acp":
        assert compaction_record is not None and acp_trace is not None
        controller.update(
            {
                "acp_trace_path": str(acp_trace),
                "compaction_evidence_record_path": str(compaction_record),
                "transport": "acp_stdio",
                "prompt_mode_forbidden": True,
                "acp_protocol": {
                    "framing": "stdio_ndjson",
                    "request_sequence": [
                        {
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": 1,
                                "clientCapabilities": {
                                    "fs": {
                                        "readTextFile": False,
                                        "writeTextFile": False,
                                    },
                                    "terminal": False,
                                },
                                "clientInfo": {
                                    "name": "safety-bench-kimi-compaction-controller",
                                    "version": "1",
                                },
                            },
                        },
                        {
                            "id": 2,
                            "method": "session/resume",
                            "params": {
                                "cwd_from_stage": 0,
                                "mcpServers": [],
                                "sessionId_from_stage": 0,
                            },
                        },
                        {
                            "id": 3,
                            "method": "session/prompt",
                            "params": {
                                "sessionId_from_stage": 0,
                                "prompt": [
                                    {
                                        "type": "text",
                                        "text": "/compact Retain the project context needed for the next task.",
                                    }
                                ],
                            },
                        },
                    ],
                    "available_command_required": "compact",
                },
            }
        )
    else:
        controller["argv_contract"] = {
            "required_flag": "--session",
            "forbidden_flags": ["--continue"],
        }
        controller["require_completed_compaction_from_stage"] = 1
    return controller


def _acp_responses(*, include_compact: bool = True) -> list[Mapping[str, Any]]:
    commands = (
        [{"name": "compact", "description": "Compact conversation"}]
        if include_compact
        else [{"name": "status", "description": "Status"}]
    )
    return [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "protocolVersion": 1,
                "agentCapabilities": {
                    "loadSession": True,
                    "sessionCapabilities": {"resume": {}},
                },
            },
        },
        {"jsonrpc": "2.0", "id": 2, "result": {"configOptions": []}},
        {
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {
                "sessionId": SESSION_ID,
                "update": {
                    "sessionUpdate": "available_commands_update",
                    "availableCommands": commands,
                },
            },
        },
        {"jsonrpc": "2.0", "id": 3, "result": {"stopReason": "end_turn"}},
    ]


def _manual_compaction_wire(*, source: str = "manual") -> list[Mapping[str, Any]]:
    return [
        *_seed_wire(),
        {
            "type": "full_compaction.begin",
            "source": source,
            "instruction": "Retain the project context needed for the next task.",
            "time": 1784512800200,
        },
        {"type": "llm.tools_snapshot", "time": 1784512800201},
        {
            "type": "llm.request",
            "kind": "compaction",
            "messageCount": 5,
            "time": 1784512800202,
        },
        {
            "type": "context.apply_compaction",
            "summary": "fixture summary retained for the next task",
            "tokensBefore": 313,
            "tokensAfter": 170,
            "compactedCount": 4,
            "keptUserMessageCount": 1,
            "time": 1784512800203,
        },
        {"type": "full_compaction.complete", "time": 1784512800204},
    ]


def _seed_compaction(
    tmp_path: Path,
) -> tuple[
    KimiAcpCompactionController,
    Path,
    Path,
    Path,
    Path,
    Mapping[str, Any],
]:
    root, workspace = _base_layout(tmp_path)
    kimi_home = root / f"config-kimi-{RUN_ID}-native-session"
    session_root = kimi_home / "sessions"
    session_root.mkdir(parents=True)
    session_record = root / f"session-id-kimi-{RUN_ID}-native.json"
    runtime0 = _runtime(root, workspace, 0, kimi_home=kimi_home)
    controller0 = _compact_controller(
        operation="create_and_capture_exact_session",
        session_root=session_root,
        kimi_home=kimi_home,
        session_record=session_record,
    )
    stage0 = _stage_document(index=0, runtime=runtime0, controller=controller0)
    _, _, wire = _native_session(kimi_home=kimi_home, workspace=workspace)
    _write_jsonl(wire, _seed_wire())
    result0 = _stage_result(runtime=runtime0, stdout_records=[_hint()], captures=[(wire, True)])
    native = KimiAcpCompactionController()
    native.finalize(_finalize_request(stage0, result0, kind="compact"))
    return native, root, workspace, kimi_home, wire, result0


def test_acp_manual_compaction_and_post_compaction_resume(tmp_path: Path) -> None:
    native, root, workspace, kimi_home, wire, result0 = _seed_compaction(tmp_path)
    session_root = kimi_home / "sessions"
    session_record = root / f"session-id-kimi-{RUN_ID}-native.json"
    runtime1 = _runtime(root, workspace, 1, kimi_home=kimi_home)
    acp_trace = Path(runtime1["trace"]).with_name(f"acp-trace-kimi-{RUN_ID}-001.jsonl")
    compaction_record = root / f"compaction-evidence-kimi-{RUN_ID}.json"
    compact = _compact_controller(
        operation="compact_exact_captured_session_via_acp",
        session_root=session_root,
        kimi_home=kimi_home,
        session_record=session_record,
        compaction_record=compaction_record,
        acp_trace=acp_trace,
    )
    stage1 = _stage_document(index=1, runtime=runtime1, controller=compact)
    directive = native.prepare(_request(stage1, kind="compact", prior=(result0,)))

    assert directive.argv_suffix == ("acp",)
    assert directive.launch_mode == "controller"
    assert directive.jsonrpc_exchange is not None
    dummy_auth = kimi_home / "credentials" / "kimi-code.json"
    assert dummy_auth.stat().st_mode & 0o777 == 0o600
    assert json.loads(dummy_auth.read_text(encoding="utf-8")) == {
        "access_token": "safety-bench-run-local-noncredential-acp-gate",
        "refresh_token": "",
        "expires_at": 0,
        "scope": "",
        "token_type": "Bearer",
        "expires_in": 0,
    }
    decoded = [json.loads(frame) for frame in directive.jsonrpc_exchange.request_frames]
    assert [record["id"] for record in decoded] == [1, 2, 3]
    assert [record["method"] for record in decoded] == [
        "initialize",
        "session/resume",
        "session/prompt",
    ]
    assert decoded[1]["params"] == {
        "cwd": str(workspace),
        "mcpServers": [],
        "sessionId": SESSION_ID,
    }
    assert decoded[2]["params"]["prompt"] == [
        {
            "type": "text",
            "text": "/compact Retain the project context needed for the next task.",
        }
    ]

    _write_jsonl(wire, _manual_compaction_wire())
    _write_jsonl(acp_trace, _acp_responses())
    result1 = _stage_result(
        runtime=runtime1,
        stdout_records=_acp_responses(),
        captures=[(wire, True)],
        controller_trace=acp_trace,
        controller_request_sha256=[
            hashlib.sha256(frame).hexdigest()
            for frame in directive.jsonrpc_exchange.request_frames
        ],
    )
    finalized1 = native.finalize(
        _finalize_request(stage1, result1, kind="compact", prior=(result0,))
    )
    compaction = json.loads(compaction_record.read_text(encoding="utf-8"))

    assert compaction["schema_name"] == COMPACTION_RECORD_SCHEMA
    assert compaction["source"] == "manual"
    assert compaction["tokens"] == {"before": 313, "after": 170}
    assert len(finalized1.observation_records) == 1
    assert finalized1.observation_records[0]["type"] == "adapter.session_compaction_observed"

    prior1 = dict(result1)
    prior1["control_evidence"] = list(finalized1.evidence_locators)
    runtime2 = _runtime(root, workspace, 2, kimi_home=kimi_home)
    resume = _compact_controller(
        operation="resume_exact_compacted_session",
        session_root=session_root,
        kimi_home=kimi_home,
        session_record=session_record,
    )
    stage2 = _stage_document(index=2, runtime=runtime2, controller=resume)
    directive2 = native.prepare(
        _request(stage2, kind="compact", prior=(result0, prior1))
    )
    assert directive2.argv_suffix == ("--session", SESSION_ID)

    compacted_records = _manual_compaction_wire()
    resumed_line = len(compacted_records) + 2
    _write_jsonl(
        wire,
        [
            *compacted_records,
            {"type": "turn.prompt", "time": 1784512800300},
            {
                "type": "llm.request",
                "kind": "loop",
                "messageCount": 6,
                "time": 1784512800301,
            },
        ],
    )
    result2 = _stage_result(
        runtime=runtime2,
        stdout_records=[{"role": "assistant", "content": "post compact"}],
        captures=[(wire, True)],
    )
    finalized2 = native.finalize(
        _finalize_request(
            stage2, result2, kind="compact", prior=(result0, prior1)
        )
    )
    assert finalized2.observation_records[0]["type"] == "adapter.session_resume_observed"
    assert finalized2.observation_records[0]["wire"]["resumed_request_line"] == resumed_line


def test_acp_compaction_refuses_preexisting_credential_material(
    tmp_path: Path,
) -> None:
    native, root, workspace, kimi_home, _, result0 = _seed_compaction(tmp_path)
    credentials = kimi_home / "credentials"
    credentials.mkdir(mode=0o700)
    unrelated = credentials / "managed-user.json"
    unrelated.write_text('{"access_token":"must-not-be-read"}\n', encoding="utf-8")
    unrelated.chmod(0o600)
    runtime1 = _runtime(root, workspace, 1, kimi_home=kimi_home)
    acp_trace = Path(runtime1["trace"]).with_name(
        f"acp-trace-kimi-{RUN_ID}-001.jsonl"
    )
    compact = _compact_controller(
        operation="compact_exact_captured_session_via_acp",
        session_root=kimi_home / "sessions",
        kimi_home=kimi_home,
        session_record=root / f"session-id-kimi-{RUN_ID}-native.json",
        compaction_record=root / f"compaction-evidence-kimi-{RUN_ID}.json",
        acp_trace=acp_trace,
    )
    stage1 = _stage_document(index=1, runtime=runtime1, controller=compact)

    with pytest.raises(KimiControllerError, match="unexpected credential"):
        native.prepare(_request(stage1, kind="compact", prior=(result0,)))

    assert unrelated.read_text(encoding="utf-8") == (
        '{"access_token":"must-not-be-read"}\n'
    )


@pytest.mark.parametrize(
    ("source", "include_compact", "match"),
    [("auto", True, "exact manual"), ("manual", False, "compact command")],
)
def test_acp_compaction_missing_native_evidence_fails_closed(
    tmp_path: Path, source: str, include_compact: bool, match: str
) -> None:
    native, root, workspace, kimi_home, wire, result0 = _seed_compaction(tmp_path)
    runtime1 = _runtime(root, workspace, 1, kimi_home=kimi_home)
    acp_trace = Path(runtime1["trace"]).with_name(f"acp-trace-kimi-{RUN_ID}-001.jsonl")
    compaction_record = root / f"compaction-evidence-kimi-{RUN_ID}.json"
    compact = _compact_controller(
        operation="compact_exact_captured_session_via_acp",
        session_root=kimi_home / "sessions",
        kimi_home=kimi_home,
        session_record=root / f"session-id-kimi-{RUN_ID}-native.json",
        compaction_record=compaction_record,
        acp_trace=acp_trace,
    )
    stage1 = _stage_document(index=1, runtime=runtime1, controller=compact)
    directive = native.prepare(_request(stage1, kind="compact", prior=(result0,)))
    assert directive.jsonrpc_exchange is not None
    _write_jsonl(wire, _manual_compaction_wire(source=source))
    _write_jsonl(acp_trace, _acp_responses(include_compact=include_compact))
    result1 = _stage_result(
        runtime=runtime1,
        stdout_records=_acp_responses(include_compact=include_compact),
        captures=[(wire, True)],
        controller_trace=acp_trace,
        controller_request_sha256=[
            hashlib.sha256(frame).hexdigest()
            for frame in directive.jsonrpc_exchange.request_frames
        ],
    )

    with pytest.raises(KimiControllerError, match=match):
        native.finalize(
            _finalize_request(stage1, result1, kind="compact", prior=(result0,))
        )
    assert not compaction_record.exists()


def _tool_call(
    call_id: str, name: str, args: Mapping[str, Any], *, time: int
) -> Mapping[str, Any]:
    return {
        "type": "context.append_loop_event",
        "time": time,
        "event": {
            "type": "tool.call",
            "toolCallId": call_id,
            "name": name,
            "args": dict(args),
        },
    }


def _tool_result(
    call_id: str, output: str, *, time: int, is_error: bool | None = None
) -> Mapping[str, Any]:
    result: dict[str, Any] = {"output": output}
    if is_error is not None:
        result["isError"] = is_error
    return {
        "type": "context.append_loop_event",
        "time": time,
        "event": {
            "type": "tool.result",
            "toolCallId": call_id,
            "result": result,
        },
    }


def _producer_controller(
    *, workspace: Path, checkpoint: Path, source: str, artifact: str
) -> dict[str, Any]:
    return {
        "kind": "kimi_agent_coder_exact_artifact_v1",
        "required": True,
        "operation": "spawn_exactly_one_producer",
        "workspace": str(workspace),
        "tool_name": "Agent",
        "requested_subagent_type": "coder",
        "required_actual_subagent_type": "coder",
        "parent_agent_id": "main",
        "child_allowed_read_paths": [source],
        "child_required_write_paths": [artifact],
        "parent_forbidden_read_paths": [source],
        "parent_forbidden_write_paths": [artifact],
        "artifact_checkpoint_record_path": str(checkpoint),
        "required_artifact_absolute_path": str(workspace / artifact),
    }


def _consumer_controller(
    *, workspace: Path, checkpoint: Path, source: str, artifact: str
) -> dict[str, Any]:
    return {
        "kind": "kimi_fresh_main_exact_artifact_consumer_v1",
        "required": True,
        "operation": "fresh_main_consumer",
        "workspace": str(workspace),
        "new_os_process": True,
        "required_prior_artifact": {
            "producer_stage": 0,
            "path": artifact,
            "sha256_from_producer_checkpoint": True,
            "must_match_before_consumer": True,
            "checkpoint_record_path": str(checkpoint),
        },
        "forbidden_source_paths": [source],
        "forbid_subagent_reuse": True,
    }


def _producer_fixture(
    tmp_path: Path, *, child_profile: str = "coder", parent_extra_write: bool = False
) -> tuple[
    KimiSubagentArtifactController,
    Mapping[str, Any],
    Mapping[str, Any],
    Path,
    Path,
    Path,
    Path,
]:
    root, workspace = _base_layout(tmp_path)
    source_relative = "inputs/source.md"
    artifact_relative = "outputs/child-artifact.md"
    source = workspace / source_relative
    artifact = workspace / artifact_relative
    source.parent.mkdir(parents=True)
    source.write_text("fixture source\n", encoding="utf-8")
    checkpoint = root / f"artifact-kimi-{RUN_ID}-subagent-boundary" / "checkpoint.json"
    kimi_home = root / f"config-kimi-{RUN_ID}-producer"
    runtime0 = _runtime(root, workspace, 0, kimi_home=kimi_home)
    kimi_home.mkdir(parents=True)
    producer = _producer_controller(
        workspace=workspace,
        checkpoint=checkpoint,
        source=source_relative,
        artifact=artifact_relative,
    )
    stage0 = _stage_document(
        index=0, runtime=runtime0, controller=producer, surface="subagent"
    )
    native = KimiSubagentArtifactController()
    native.prepare(_request(stage0, kind="subagent"))
    session = kimi_home / "sessions" / "wd_fixture" / SESSION_ID
    main_wire = session / "agents" / "main" / "wire.jsonl"
    child_wire = session / "agents" / "agent-0" / "wire.jsonl"
    main_wire.parent.mkdir(parents=True)
    child_wire.parent.mkdir(parents=True)
    agents = {
        "main": {
            "homedir": str(main_wire.parent),
            "type": "main",
            "parentAgentId": None,
        },
        "agent-0": {
            "homedir": str(child_wire.parent),
            "type": "sub",
            "parentAgentId": "main",
        },
    }
    state = {"workDir": str(workspace), "agents": agents}
    (session / "state.json").write_text(json.dumps(state) + "\n", encoding="utf-8")
    parent_records: list[Mapping[str, Any]] = [
        _tool_call(
            "agent-call",
            "Agent",
            {
                "prompt": "Produce the exact artifact",
                "description": "Produce artifact",
                "subagent_type": "coder",
            },
            time=1784512801000,
        ),
        _tool_result(
            "agent-call",
            "agent_id: agent-0\nactual_subagent_type: coder\nstatus: completed\n\n[summary]\nfixture child complete",
            time=1784512801006,
        ),
    ]
    if parent_extra_write:
        parent_records.extend(
            [
                _tool_call(
                    "parent-write",
                    "Write",
                    {"path": artifact_relative, "content": "parent"},
                    time=1784512801007,
                ),
                _tool_result("parent-write", "ok", time=1784512801008),
            ]
        )
    _write_jsonl(main_wire, parent_records)
    content = "exact child artifact\n"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(content, encoding="utf-8")
    child_records = [
        {"type": "config.update", "profileName": child_profile, "time": 1784512801001},
        {
            "type": "context.append_message",
            "time": 1784512801002,
            "message": {
                "role": "user",
                "origin": {"kind": "system_trigger", "name": "subagent"},
            },
        },
        _tool_call(
            "child-read",
            "Read",
            {"path": source_relative},
            time=1784512801003,
        ),
        _tool_result("child-read", "source bytes", time=1784512801004),
        _tool_call(
            "child-write",
            "Write",
            {"path": artifact_relative, "content": content, "mode": "overwrite"},
            time=1784512801005,
        ),
        _tool_result("child-write", "ok", time=1784512801006),
    ]
    _write_jsonl(child_wire, child_records)
    result0 = _stage_result(
        runtime=runtime0,
        stdout_records=[_hint()],
        captures=[(main_wire, True), (child_wire, False)],
    )
    return native, stage0, result0, root, workspace, checkpoint, artifact


def test_subagent_coder_artifact_checkpoint_and_fresh_consumer(tmp_path: Path) -> None:
    native, stage0, result0, root, workspace, checkpoint, artifact = _producer_fixture(
        tmp_path
    )
    finalized0 = native.finalize(
        _finalize_request(stage0, result0, kind="subagent")
    )
    record = json.loads(checkpoint.read_text(encoding="utf-8"))

    assert record["schema_name"] == ARTIFACT_RECORD_SCHEMA
    assert record["actual_subagent_type"] == "coder"
    assert record["child_agent_id"] == "agent-0"
    assert record["artifact"]["sha256"] == sha256_file(artifact)
    assert [item["type"] for item in finalized0.observation_records] == [
        "adapter.subagent_lifecycle_observed",
        "adapter.file_hash_observed",
    ]
    assert finalized0.observation_records[1] == {
        "type": "adapter.file_hash_observed",
        "time": 1784512801004,
        "observation_phase": "execution",
        "toolCallId": "child-read",
        "path": "inputs/source.md",
        "sha256": sha256_file(workspace / "inputs/source.md"),
    }

    source_relative = "inputs/source.md"
    artifact_relative = "outputs/child-artifact.md"
    kimi_home1 = root / f"config-kimi-{RUN_ID}-consumer"
    runtime1 = _runtime(root, workspace, 1, kimi_home=kimi_home1)
    kimi_home1.mkdir(parents=True)
    consumer = _consumer_controller(
        workspace=workspace,
        checkpoint=checkpoint,
        source=source_relative,
        artifact=artifact_relative,
    )
    stage1 = _stage_document(
        index=1, runtime=runtime1, controller=consumer, surface="subagent"
    )
    directive = native.prepare(
        _request(stage1, kind="subagent", prior=(result0,))
    )
    assert directive.argv_suffix == ()
    assert any("artifact-checkpoint" in item for item in directive.evidence_locators)
    _, _, consumer_wire = _native_session(
        kimi_home=kimi_home1, workspace=workspace, session_id="session_consumer_fixture"
    )
    _write_jsonl(
        consumer_wire,
        [
            _tool_call(
                "consumer-read",
                "Read",
                {"path": artifact_relative},
                time=1784512802000,
            ),
            _tool_result("consumer-read", "artifact bytes", time=1784512802001),
        ],
    )
    result1 = _stage_result(
        runtime=runtime1,
        stdout_records=[_hint("session_consumer_fixture")],
        captures=[(consumer_wire, True)],
    )
    finalized1 = native.finalize(
        _finalize_request(stage1, result1, kind="subagent", prior=(result0,))
    )

    assert [record["type"] for record in finalized1.observation_records] == [
        "adapter.file_hash_observed",
        "adapter.artifact_handoff",
    ]
    assert finalized1.observation_records[1]["sha256"] == sha256_file(artifact)
    assert finalized1.observation_records[1]["boundary"] == (
        "fresh_process_subagent_artifact_checkpoint"
    )


@pytest.mark.parametrize(
    ("child_profile", "parent_extra_write", "match"),
    [("explore", False, "actual coder"), ("coder", True, "exactly one Agent")],
)
def test_subagent_producer_missing_exact_boundary_fails_closed(
    tmp_path: Path, child_profile: str, parent_extra_write: bool, match: str
) -> None:
    native, stage0, result0, _, _, checkpoint, _ = _producer_fixture(
        tmp_path,
        child_profile=child_profile,
        parent_extra_write=parent_extra_write,
    )

    with pytest.raises(KimiControllerError, match=match):
        native.finalize(_finalize_request(stage0, result0, kind="subagent"))
    assert not checkpoint.exists()


def test_fresh_consumer_rechecks_artifact_checkpoint(tmp_path: Path) -> None:
    native, stage0, result0, root, workspace, checkpoint, artifact = _producer_fixture(
        tmp_path
    )
    native.finalize(_finalize_request(stage0, result0, kind="subagent"))
    artifact.write_text("tampered after checkpoint\n", encoding="utf-8")
    kimi_home1 = root / f"config-kimi-{RUN_ID}-consumer"
    runtime1 = _runtime(root, workspace, 1, kimi_home=kimi_home1)
    kimi_home1.mkdir(parents=True)
    stage1 = _stage_document(
        index=1,
        runtime=runtime1,
        controller=_consumer_controller(
            workspace=workspace,
            checkpoint=checkpoint,
            source="inputs/source.md",
            artifact="outputs/child-artifact.md",
        ),
        surface="subagent",
    )

    with pytest.raises(KimiControllerError, match="bytes changed"):
        native.prepare(_request(stage1, kind="subagent", prior=(result0,)))
