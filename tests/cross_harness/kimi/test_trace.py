from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
from typing import Mapping

import pytest
from jsonschema import Draft7Validator

from infra.cross_harness.adapter import HarnessIdentity
from infra.cross_harness.adapters.kimi import KimiTraceNormalizationError
from infra.cross_harness.adapters.kimi.disposition import (
    KimiModelProtocolIncompleteError,
)
from infra.cross_harness.adapters.kimi.materializer import materialize_kimi_binding
from infra.cross_harness.adapters.kimi.trace import (
    KimiObservedTraceContext,
    KimiObservedTraceSource,
    normalize_kimi_trace,
)


FIXTURE = Path(__file__).with_name("fixtures") / "kimi_0_26_0_wire_static_redacted.jsonl"
REPO_ROOT = Path(__file__).resolve().parents[3]
ARTIFACT_SHA = "c1d73659b427ed35aa922d857055638e99574128d50e91ad2f0b28b8691865c8"
_TRUSTED_BINDINGS: dict[Path, dict] = {}
_TRUSTED_MANIFESTS: dict[Path, dict] = {}


def _identity() -> HarnessIdentity:
    return HarnessIdentity(
        harness_id="kimi",
        version="0.26.0",
        executable="/fixture/kimi",
        feature_flags={
            "structured_trace": "static-derived-fixture",
            "binary_sha256": (
                "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"
            ),
        },
    )


def _materialized(tmp_path: Path, factory, *, expected: list[str]):
    case_dir, binding = factory(expected_event_types=expected)
    materialized = materialize_kimi_binding(
        run_id="trace-001",
        case_dir=case_dir,
        binding_document=binding,
        run_dir=tmp_path / "run-kimi-trace-001",
        callback_port=53001,
    )
    manifest_key = materialized.manifest_path.resolve()
    _TRUSTED_BINDINGS[manifest_key] = copy.deepcopy(binding)
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    _TRUSTED_MANIFESTS[manifest_key] = copy.deepcopy(manifest)
    return materialized


def _normalize_trace(*, identity, materialized, raw_trace_path, stage_index):
    return normalize_kimi_trace(
        identity=identity,
        materialized=materialized,
        raw_trace_path=raw_trace_path,
        stage_index=stage_index,
        trusted_binding_document=_TRUSTED_BINDINGS[
            materialized.manifest_path.resolve()
        ],
        trusted_manifest_document=_TRUSTED_MANIFESTS[
            materialized.manifest_path.resolve()
        ],
    )


def _trace_path(materialized) -> Path:
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    return Path(manifest["stages"][0]["trace_path"])


def test_kimi_wire_parser_emits_valid_correlated_event_ir(
    tmp_path: Path, case_and_binding_factory
) -> None:
    expected = [
        "mcp.server_initialized",
        "mcp.tool_requested",
        "mcp.tool_result",
        "file.write",
        "file.read",
        "artifact.handoff",
    ]
    materialized = _materialized(tmp_path, case_and_binding_factory, expected=expected)
    trace_path = _trace_path(materialized)
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    artifact = Path(manifest["materialized"]["workspace_dir"]) / "reports" / "generated_decision.md"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("handoff\n", encoding="utf-8")
    shutil.copyfile(FIXTURE, trace_path)

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )
    schema = json.loads(
        (REPO_ROOT / "docs" / "cross_harness_event_ir_schema_v1.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft7Validator(schema)
    for event in events:
        validator.validate(event)

    assert [event["sequence"] for event in events] == list(range(len(events)))
    assert {event["event_type"] for event in events} == set(expected)
    requested = next(event for event in events if event["event_type"] == "mcp.tool_requested")
    result = next(event for event in events if event["event_type"] == "mcp.tool_result")
    assert requested["tool"]["call_id"] == result["tool"]["call_id"] == "call-mcp-1"
    assert requested["tool"]["server"] == result["tool"]["server"]
    assert requested["tool"]["name"] == result["tool"]["name"] == "lookup"
    expected_args_hash = hashlib.sha256(
        b'{"project_name":"current-workspace"}'
    ).hexdigest()
    assert requested["tool"]["arguments_sha256"] == expected_args_hash
    assert result["tool"]["status"] == "success"
    assert result["tool"]["result_sha256"] == hashlib.sha256(
        b'{"registered":true}'
    ).hexdigest()

    write = next(event for event in events if event["event_type"] == "file.write")
    read = next(event for event in events if event["event_type"] == "file.read")
    handoff = next(event for event in events if event["event_type"] == "artifact.handoff")
    assert write["artifact"]["sha256"] == ARTIFACT_SHA
    assert read["artifact"]["sha256"] == ARTIFACT_SHA
    assert handoff["artifact"]["sha256"] == ARTIFACT_SHA
    assert read["attributes"]["origin_tool_call_id"] == "call-read-1"
    assert handoff["source"]["line"] == 9
    assert handoff["source"]["raw_event_type"] == "adapter.artifact_handoff"
    assert all(event["source"]["trace_path"] == str(trace_path) for event in events)


def test_malformed_trace_fails_closed_without_partial_events(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["file.read"]
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text('{"role":"assistant"}\n{malformed\n', encoding="utf-8")

    with pytest.raises(KimiTraceNormalizationError, match="malformed JSON"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_uncorrelated_mcp_result_fails_closed(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["mcp.tool_result"]
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "context.append_loop_event",
                "time": 1784512800000,
                "event": {
                    "type": "tool.result",
                    "toolCallId": "missing-request",
                    "result": {"output": "orphan", "isError": False},
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match="no unique request"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_missing_required_event_and_tools_discovered_do_not_score(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["mcp.server_initialized"],
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "mcp.tools_discovered",
                "time": 1784512800000,
                "server": "deployment-health",
                "tools_sha256": "0" * 64,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match="not directly observed"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_missing_model_skill_action_is_protocol_incomplete(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["skill.discovered", "skill.activated"],
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "llm.request",
                "kind": "loop",
                "messageCount": 2,
                "time": 1784512800000,
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        KimiModelProtocolIncompleteError, match="not directly observed"
    ) as raised:
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )
    assert raised.value.failure_category == "MODEL_REQUIRED_EVENT_MISSING"


def test_file_trace_cannot_escape_into_other_harness_state(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["file.read"]
    )
    trace_path = _trace_path(materialized)
    records = [
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "read-other-harness",
                "name": "Read",
                "args": {"path": "/tmp/claude/session.json"},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512801000,
            "event": {
                "type": "tool.result",
                "toolCallId": "read-other-harness",
                "result": {"output": "redacted", "isError": False},
            },
        },
    ]
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )

    with pytest.raises(KimiTraceNormalizationError, match="escapes the Kimi workspace"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_nonrequired_external_read_does_not_discard_required_mcp_events(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["mcp.tool_requested", "mcp.tool_result"],
    )
    trace_path = _trace_path(materialized)
    records = [
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "read-run-local-fixture",
                "name": "Read",
                "args": {"path": "/tmp/run-local-fixture/deployment.id"},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512801000,
            "event": {
                "type": "tool.result",
                "toolCallId": "read-run-local-fixture",
                "result": {"output": "redacted", "isError": False},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512802000,
            "event": {
                "type": "tool.call",
                "toolCallId": "mcp-after-read",
                "name": "mcp__deployment_health__check",
                "args": {"deployment_id": "redacted"},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512803000,
            "event": {
                "type": "tool.result",
                "toolCallId": "mcp-after-read",
                "result": {"output": "redacted", "isError": False},
            },
        },
    ]
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )

    assert [event["event_type"] for event in events] == [
        "mcp.tool_requested",
        "mcp.tool_result",
    ]


def test_file_write_uses_last_successful_structured_mutation(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["file.write"],
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    artifact = (
        Path(manifest["materialized"]["workspace_dir"]) / "state" / "cache.json"
    )
    artifact.parent.mkdir()
    artifact.write_text('{"status":"final"}\n', encoding="utf-8")
    records = [
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "write-initial",
                "name": "Write",
                "args": {
                    "path": "state/cache.json",
                    "content": '{"status":"initial"}\n',
                },
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512801000,
            "event": {
                "type": "tool.result",
                "toolCallId": "write-initial",
                "result": {"output": "redacted", "isError": False},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512802000,
            "event": {
                "type": "tool.call",
                "toolCallId": "edit-final",
                "name": "Edit",
                "args": {
                    "path": "state/cache.json",
                    "old_string": "initial",
                    "new_string": "final",
                },
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512803000,
            "event": {
                "type": "tool.result",
                "toolCallId": "edit-final",
                "result": {"output": "redacted", "isError": False},
            },
        },
    ]
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )

    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "file.write"
    assert event["attributes"]["origin_tool_call_id"] == "edit-final"
    assert event["attributes"]["native_tool_name"] == "Edit"
    assert event["artifact"]["sha256"] == hashlib.sha256(
        artifact.read_bytes()
    ).hexdigest()


def test_file_write_rejects_later_opaque_workspace_mutation(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["file.write"],
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    artifact = Path(manifest["materialized"]["workspace_dir"]) / "state.txt"
    artifact.write_text("changed later\n", encoding="utf-8")
    records = [
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "write-before-bash",
                "name": "Write",
                "args": {"path": "state.txt", "content": "written\n"},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512801000,
            "event": {
                "type": "tool.result",
                "toolCallId": "write-before-bash",
                "result": {"output": "redacted", "isError": False},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512802000,
            "event": {
                "type": "tool.call",
                "toolCallId": "opaque-bash",
                "name": "Bash",
                "args": {"command": "redacted"},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512803000,
            "event": {
                "type": "tool.result",
                "toolCallId": "opaque-bash",
                "result": {"output": "redacted", "isError": False},
            },
        },
    ]
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )

    with pytest.raises(
        KimiTraceNormalizationError,
        match="opaque same-workspace mutator",
    ):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_read_hash_observation_must_immediately_follow_native_result(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["file.read"]
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    artifact = Path(manifest["materialized"]["workspace_dir"]) / "evidence.txt"
    artifact.write_text("evidence\n", encoding="utf-8")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    records = [
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "read-delayed-hash",
                "name": "Read",
                "args": {"path": "evidence.txt"},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512801000,
            "event": {
                "type": "tool.result",
                "toolCallId": "read-delayed-hash",
                "result": {"output": "redacted", "isError": False},
            },
        },
        {"type": "turn.ended", "time": 1784512802000},
        {
            "type": "adapter.file_hash_observed",
            "time": 1784512803000,
            "observation_phase": "execution",
            "toolCallId": "read-delayed-hash",
            "path": "evidence.txt",
            "sha256": digest,
        },
    ]
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match="immediately after"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_artifact_observation_must_match_real_run_local_bytes(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["artifact.handoff"]
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    artifact = Path(manifest["materialized"]["workspace_dir"]) / "handoff.md"
    artifact.write_text("different bytes\n", encoding="utf-8")
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "adapter.artifact_handoff",
                "time": 1784512800000,
                "path": "handoff.md",
                "sha256": "0" * 64,
                "boundary": "fresh_process",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match="does not match"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_completed_mcp_call_id_cannot_be_reused(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["mcp.tool_requested", "mcp.tool_result"],
    )
    call = {
        "type": "context.append_loop_event",
        "time": 1784512800000,
        "event": {
            "type": "tool.call",
            "toolCallId": "reused",
            "name": "mcp__fixture__lookup",
            "args": {},
        },
    }
    result = {
        "type": "context.append_loop_event",
        "time": 1784512801000,
        "event": {
            "type": "tool.result",
            "toolCallId": "reused",
            "result": {"output": "ok", "isError": False},
        },
    }
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in (call, result, call)),
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match="duplicate tool call id"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_raw_stage_cannot_spoof_another_stage(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["mcp.tool_requested"]
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "role": "assistant",
                "time": 1784512800000,
                "_stage": {"name": "other", "index": 7},
                "tool_calls": [
                    {
                        "id": "spoofed-stage",
                        "function": {
                            "name": "mcp__fixture__lookup",
                            "arguments": "{}",
                        },
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match="does not match"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_failed_mcp_health_does_not_satisfy_initialization(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["mcp.server_initialized"]
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "mcp.server.status",
                "time": 1784512800000,
                "server": {
                    "name": "fixture",
                    "transport": "stdio",
                    "status": "failed",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match="health precondition"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_adapter_mcp_proxy_health_requires_initialize_tools_list_and_clean_exit(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["mcp.server_initialized"]
    )
    evidence_dir = materialized.run_dir / "evidence-kimi-trace-001-mcp"
    evidence_dir.mkdir(parents=True)
    initialize = evidence_dir / "initialize-kimi-trace-001.jsonl"
    tools_list = evidence_dir / "tools-list-kimi-trace-001.jsonl"
    stdio = evidence_dir / "stdio-kimi-trace-001.jsonl"
    child_exit = evidence_dir / "child-exit-kimi-trace-001.json"
    child_digest = "a" * 64

    def proxy_record(sequence: int, **extra) -> dict:
        return {
            "schema_name": "safety_bench_kimi_mcp_stdio_proxy_event",
            "schema_version": 1,
            "run_id": "trace-001",
            "harness_id": "kimi",
            "server": "fixture-server",
            "stage_index": 0,
            "sequence": sequence,
            "time": f"2026-07-20T10:00:0{sequence}+00:00",
            "child_argv_sha256": child_digest,
            **extra,
        }

    initialize_records = [
        proxy_record(
            0,
            jsonrpc_kind="request",
            method="initialize",
            id_sha256="1" * 64,
        ),
        proxy_record(
            1,
            jsonrpc_kind="response",
            correlated_method="initialize",
            response_status="success",
            id_sha256="1" * 64,
        ),
    ]
    tools_records = [
        proxy_record(
            2,
            jsonrpc_kind="request",
            method="tools/list",
            id_sha256="2" * 64,
        ),
        proxy_record(
            3,
            jsonrpc_kind="response",
            correlated_method="tools/list",
            response_status="success",
            id_sha256="2" * 64,
        ),
    ]
    initialize.write_text(
        "".join(json.dumps(record) + "\n" for record in initialize_records),
        encoding="utf-8",
    )
    tools_list.write_text(
        "".join(json.dumps(record) + "\n" for record in tools_records),
        encoding="utf-8",
    )
    stdio.write_text(
        "".join(
            json.dumps(record) + "\n"
            for record in (*initialize_records, *tools_records)
        ),
        encoding="utf-8",
    )
    child_exit.write_text(
        json.dumps(
            {
                "schema_name": "safety_bench_kimi_mcp_child_exit",
                "schema_version": 1,
                "run_id": "trace-001",
                "harness_id": "kimi",
                "server": "fixture-server",
                "stage_index": 0,
                "time": "2026-07-20T10:00:04+00:00",
                "child_argv_sha256": child_digest,
                "exit_code": 0,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "adapter.mcp_health_observed",
                "time": "2026-07-20T10:00:05+00:00",
                "server": "fixture-server",
                "child_argv_sha256": child_digest,
                "paths": {
                    "initialize_trace": str(initialize),
                    "tools_list_trace": str(tools_list),
                    "stdio_trace": str(stdio),
                    "child_exit_trace": str(child_exit),
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )

    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "mcp.server_initialized"
    assert event["tool"] == {"server": "fixture-server"}
    assert event["source"]["trace_path"] == str(initialize)
    assert event["source"]["line"] == 2
    assert event["attributes"]["tools_discovered_used_as_health"] is False
    assert event["attributes"]["child_exit_locator"] == str(child_exit)


def test_trace_path_must_exactly_match_materialized_stage(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["mcp.server_initialized"]
    )
    alternate = materialized.run_dir / "alternate-trace-kimi-trace-001.jsonl"
    alternate.write_text(
        json.dumps(
            {
                "type": "mcp.server.status",
                "time": 1784512800000,
                "server": {"name": "fixture", "status": "connected"},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match="exact materialized stage"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=alternate,
            stage_index=0,
        )


def test_wire_result_rejects_non_boolean_error_state(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["mcp.tool_requested", "mcp.tool_result"],
    )
    records = [
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "bad-error-state",
                "name": "mcp__fixture__lookup",
                "args": {},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512801000,
            "event": {
                "type": "tool.result",
                "toolCallId": "bad-error-state",
                "result": {"output": "ok", "isError": "false"},
            },
        },
    ]
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )

    with pytest.raises(KimiTraceNormalizationError, match="must be boolean"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_kimi_0_26_wire_omission_is_version_scoped_success(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["mcp.tool_requested", "mcp.tool_result"],
    )
    records = [
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "native-success-omission",
                "name": "mcp__fixture__lookup",
                "args": {},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512801000,
            "event": {
                "type": "tool.result",
                "toolCallId": "native-success-omission",
                "result": {"output": "ok"},
            },
        },
    ]
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )

    result = next(event for event in events if event["event_type"] == "mcp.tool_result")
    assert result["tool"]["status"] == "success"


def test_wire_success_omission_is_rejected_for_another_version(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["mcp.tool_requested", "mcp.tool_result"],
    )
    records = [
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "unvalidated-version",
                "name": "mcp__fixture__lookup",
                "args": {},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512801000,
            "event": {
                "type": "tool.result",
                "toolCallId": "unvalidated-version",
                "result": {"output": "ok"},
            },
        },
    ]
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )
    other_version = HarnessIdentity(
        harness_id="kimi",
        version="0.27.0",
        executable="/fixture/kimi",
        feature_flags={"structured_trace": "unvalidated-version"},
    )

    with pytest.raises(KimiTraceNormalizationError, match="unvalidated Kimi version"):
        _normalize_trace(
            identity=other_version,
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_native_skill_activation_emits_hashed_run_local_event(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["skill.discovered", "skill.activated"],
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    skill_path = (
        Path(manifest["stages"][0]["skills_dir"])
        / "fixture-probe"
        / "SKILL.md"
    )
    skill_path.parent.mkdir(parents=True, exist_ok=True)
    skill_bytes = b"---\nname: fixture-probe\n---\nDeterministic fixture.\n"
    skill_path.write_bytes(skill_bytes)
    records = [
        {
            "type": "config.update",
            "time": 1784512799999,
            "systemPrompt": (
                "Current available skills:\n### User\n"
                "- fixture-probe: deterministic fixture\n"
                f"  Path: {skill_path}\n"
            ),
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "skill-call-1",
                "name": "Skill",
                "args": {"skill": "fixture-probe"},
            },
        },
        {
            "type": "context.append_message",
            "time": 1784512800001,
            "message": {
                "role": "user",
                "origin": {
                    "kind": "skill_activation",
                    "activationId": "activation-1",
                    "skillName": "fixture-probe",
                    "skillPath": str(skill_path),
                    "skillSource": "user",
                    "skillType": "prompt",
                    "trigger": "model-tool",
                },
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512800002,
            "event": {
                "type": "tool.result",
                "toolCallId": "skill-call-1",
                "result": {"output": "loaded"},
            },
        },
    ]
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        "".join(json.dumps(record) + "\n" for record in records), encoding="utf-8"
    )

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )

    assert [event["event_type"] for event in events] == [
        "skill.discovered",
        "skill.activated",
    ]
    discovered, event = events
    assert discovered["source"]["line"] == 1
    assert discovered["source"]["raw_event_type"] == (
        "config.update:systemPrompt:skill_listing"
    )
    assert discovered["attributes"]["skill_sha256"] == hashlib.sha256(
        skill_bytes
    ).hexdigest()
    assert "Current available skills" not in json.dumps(discovered)
    assert event["source"]["line"] == 3
    assert event["source"]["raw_event_type"] == (
        "context.append_message:skill_activation"
    )
    assert event["attributes"]["skill_name"] == "fixture-probe"
    assert event["attributes"]["origin_tool_call_id"] == "skill-call-1"
    assert event["attributes"]["skill_sha256"] == hashlib.sha256(
        skill_bytes
    ).hexdigest()
    assert "Deterministic fixture" not in json.dumps(event)


def _write_native_observation_file(path: Path, document: dict | list[dict]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(document, list):
        path.write_text(
            "".join(json.dumps(record) + "\n" for record in document),
            encoding="utf-8",
        )
    else:
        path.write_text(json.dumps(document) + "\n", encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_instruction_loading_requires_hashed_artifact_and_request_marker(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["instruction.loaded"]
    )
    manifest = json.loads(materialized.manifest_path.read_text(encoding="utf-8"))
    workspace = Path(manifest["materialized"]["workspace_dir"])
    instruction = workspace / ".kimi-code" / "AGENTS.md"
    marker = b"INERT_KIMI_INSTRUCTION_MARKER_001"
    instruction_bytes = b"Project instructions.\nMarker: " + marker + b"\n"
    instruction.parent.mkdir(parents=True, exist_ok=True)
    instruction.write_bytes(instruction_bytes)
    instruction_sha256 = hashlib.sha256(instruction_bytes).hexdigest()
    marker_sha256 = hashlib.sha256(marker).hexdigest()
    marker_offset = instruction_bytes.index(marker)

    observer = materialized.run_dir / "request-observer-kimi-trace-001.jsonl"
    request_body_sha256 = "b" * 64
    observer_sha256 = _write_native_observation_file(
        observer,
        {
            "time": "2026-07-20T10:00:00+00:00",
            "body_sha256": request_body_sha256,
            "expected_substring_present": True,
            "expected_substring_sha256": marker_sha256,
            "message_roles": ["system", "user", "user"],
        },
    )
    session_id = "session_fixture_instruction"
    wire = (
        materialized.run_dir
        / "config-kimi-trace-001"
        / "sessions"
        / session_id
        / "agents"
        / "main"
        / "wire.jsonl"
    )
    wire_sha256 = _write_native_observation_file(
        wire,
        [
            {"type": "metadata", "protocol_version": 1},
            {
                "type": "llm.request",
                "kind": "loop",
                "messageCount": 2,
                "time": 1784512800000,
            },
        ],
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "adapter.instruction_loading_observed",
                "time": "2026-07-20T10:00:01+00:00",
                "session_id": session_id,
                "instruction": {
                    "path": str(instruction),
                    "sha256": instruction_sha256,
                    "marker_offset": marker_offset,
                    "marker_length": len(marker),
                    "marker_sha256": marker_sha256,
                },
                "request_observer": {
                    "path": str(observer),
                    "sha256": observer_sha256,
                    "line": 1,
                },
                "wire": {
                    "path": str(wire),
                    "sha256": wire_sha256,
                    "llm_request_line": 2,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )

    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "instruction.loaded"
    assert event["session_id"] == session_id
    assert event["attributes"]["path"] == ".kimi-code/AGENTS.md"
    assert event["attributes"]["sha256"] == instruction_sha256
    assert event["attributes"]["marker_sha256"] == marker_sha256
    assert event["attributes"]["request_body_sha256"] == request_body_sha256
    assert marker.decode("ascii") not in json.dumps(event)


def _direct_source_context(
    *,
    run_dir: Path,
    workspace: Path,
    wire: Path,
    adapter: Path,
    expected: tuple[str, ...],
    artifacts: Mapping[str, object],
) -> KimiObservedTraceContext:
    return KimiObservedTraceContext(
        run_id="direct-001",
        case_id="case-direct",
        run_dir=run_dir,
        workspace=workspace,
        stage={
            "index": 0,
            "name": "main",
            "skills_dir": str(workspace / ".kimi-code" / "skills"),
            "artifacts": dict(artifacts),
        },
        expected_event_types=expected,
        sources=(
            KimiObservedTraceSource(
                path=wire,
                sha256=hashlib.sha256(wire.read_bytes()).hexdigest(),
                mode="all",
            ),
            KimiObservedTraceSource(
                path=adapter,
                sha256=hashlib.sha256(adapter.read_bytes()).hexdigest(),
                mode="adapter",
            ),
        ),
    )


def test_zero_expected_event_stage_does_not_invent_unrequested_session_event(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-kimi-direct-001"
    workspace = run_dir / "workspace-kimi-direct-001"
    workspace.mkdir(parents=True)
    wire = run_dir / "trace-kimi-direct-001.jsonl"
    wire.write_text(
        json.dumps(
            {
                "role": "meta",
                "type": "session.resume_hint",
                "session_id": "session_direct_zero_expected",
                "time": "2026-07-21T00:00:00+00:00",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    context = KimiObservedTraceContext(
        run_id="direct-001",
        case_id="case-direct",
        run_dir=run_dir,
        workspace=workspace,
        stage={
            "index": 0,
            "name": "main",
            "skills_dir": str(workspace / ".kimi-code" / "skills"),
            "artifacts": {"produce": [], "consume": []},
        },
        expected_event_types=(),
        sources=(
            KimiObservedTraceSource(
                path=wire,
                sha256=hashlib.sha256(wire.read_bytes()).hexdigest(),
            ),
        ),
    )

    events = normalize_kimi_trace(
        identity=_identity(),
        raw_trace_path=wire,
        stage_index=0,
        observed_context=context,
    )

    assert events == []


def test_zero_expected_stage_accepts_adapter_bound_fresh_session_start(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-kimi-direct-001"
    workspace = run_dir / "workspace-kimi-direct-001"
    workspace.mkdir(parents=True)
    stdout = run_dir / "stdout-kimi-direct-001.jsonl"
    wire = run_dir / "wire-kimi-direct-001.jsonl"
    adapter = run_dir / "adapter-kimi-direct-001.jsonl"
    session_id = "session_direct_bound_start"
    event_time = "2026-07-21T00:00:01+00:00"
    stdout.write_text(
        json.dumps(
            {
                "role": "meta",
                "type": "session.resume_hint",
                "session_id": session_id,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    wire.write_text(
        json.dumps(
            {
                "type": "llm.request",
                "kind": "loop",
                "messageCount": 2,
                "time": event_time,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    adapter.write_text(
        json.dumps(
            {
                "type": "adapter.session_start_observed",
                "time": event_time,
                "session_id": session_id,
                "stdout": {
                    "path": str(stdout),
                    "sha256": hashlib.sha256(stdout.read_bytes()).hexdigest(),
                    "line_count": 1,
                    "hint_line": 1,
                },
                "wire": {
                    "path": str(wire),
                    "sha256": hashlib.sha256(wire.read_bytes()).hexdigest(),
                    "line_count": 1,
                    "request_line": 1,
                    "prior_line_count": 0,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    context = KimiObservedTraceContext(
        run_id="direct-001",
        case_id="case-direct",
        run_dir=run_dir,
        workspace=workspace,
        stage={
            "index": 0,
            "name": "main",
            "skills_dir": str(workspace / ".kimi-code" / "skills"),
            "artifacts": {"produce": [], "consume": []},
        },
        expected_event_types=(),
        sources=(
            KimiObservedTraceSource(
                path=stdout,
                sha256=hashlib.sha256(stdout.read_bytes()).hexdigest(),
                mode="session_meta",
            ),
            KimiObservedTraceSource(
                path=wire,
                sha256=hashlib.sha256(wire.read_bytes()).hexdigest(),
                mode="all",
            ),
            KimiObservedTraceSource(
                path=adapter,
                sha256=hashlib.sha256(adapter.read_bytes()).hexdigest(),
                mode="adapter",
            ),
        ),
    )

    events = normalize_kimi_trace(
        identity=_identity(),
        raw_trace_path=stdout,
        stage_index=0,
        observed_context=context,
    )

    assert [event["event_type"] for event in events] == ["session.started"]
    assert events[0]["session_id"] == session_id
    assert events[0]["timestamp"] == event_time
    assert events[0]["source"]["trace_path"] == str(adapter)


def test_direct_instruction_uses_pinned_adapter_source_and_correlated_capture(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-kimi-direct-001"
    workspace = run_dir / "workspace-kimi-direct-001"
    workspace.mkdir(parents=True)
    instruction = workspace / ".kimi-code" / "AGENTS.md"
    instruction.parent.mkdir()
    instruction_bytes = b"# Direct instruction\nFixture project convention.\n"
    instruction.write_bytes(instruction_bytes)
    marker_sha = hashlib.sha256(instruction_bytes).hexdigest()
    system_prompt = "native header\n" + instruction_bytes.decode("utf-8")
    request_time = "2026-07-21T01:00:00+00:00"
    observer_time = "2026-07-21T01:00:01+00:00"
    wire_records = [
        {
            "type": "config.update",
            "systemPrompt": system_prompt,
            "time": request_time,
        },
        {
            "type": "llm.request",
            "kind": "loop",
            "systemPromptHash": hashlib.sha256(
                system_prompt.encode("utf-8")
            ).hexdigest(),
            "messageCount": 2,
            "time": request_time,
        },
    ]
    session_id = "session_direct_instruction"
    native_wire = (
        run_dir
        / "config-kimi-direct-001"
        / "sessions"
        / session_id
        / "agents"
        / "main"
        / "wire.jsonl"
    )
    captured_wire = run_dir / "artifact-kimi-direct-001" / "wire-000.jsonl"
    for path in (native_wire, captured_wire):
        _write_native_observation_file(path, wire_records)
    wire_sha = hashlib.sha256(captured_wire.read_bytes()).hexdigest()
    observer = run_dir / "broker-kimi-direct-001" / "request-observer.jsonl"
    observer_record = {
        "schema_name": "safety_bench_kimi_provider_request_observation",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": "direct-001",
        "case_id": "case-direct",
        "trial_id": "attack-attempt-001",
        "stage_index": 0,
        "sequence": 1,
        "time": observer_time,
        "body_sha256": "b" * 64,
        "body_bytes": 123,
        "target_sha256": "c" * 64,
        "message_roles": ["system", "user", "user"],
        "expected_substring_present": True,
        "expected_substring_sha256": marker_sha,
    }
    observer_sha = _write_native_observation_file(observer, observer_record)
    observer.chmod(0o600)
    adapter = run_dir / "artifact-kimi-direct-001" / "observations.jsonl"
    adapter_record = {
        "type": "adapter.instruction_loading_observed",
        "time": observer_time,
        "session_id": session_id,
        "instruction": {
            "path": str(instruction),
            "sha256": hashlib.sha256(instruction_bytes).hexdigest(),
            "marker_offset": 0,
            "marker_length": len(instruction_bytes),
            "marker_sha256": marker_sha,
        },
        "request_observer": {
            "path": str(observer),
            "sha256": observer_sha,
            "line": 1,
            "line_count": 1,
        },
        "wire": {
            "path": str(captured_wire),
            "sha256": wire_sha,
            "line_count": 2,
            "prior_line_count": 0,
            "llm_request_line": 2,
            "llm_request_ordinal": 1,
            "message_count": 2,
            "config_update_line": 1,
            "system_prompt_sha256": hashlib.sha256(
                system_prompt.encode("utf-8")
            ).hexdigest(),
            "native_source_path": str(native_wire),
        },
    }
    _write_native_observation_file(adapter, adapter_record)
    context = _direct_source_context(
        run_dir=run_dir,
        workspace=workspace,
        wire=captured_wire,
        adapter=adapter,
        expected=("instruction.loaded",),
        artifacts={"produce": [], "consume": []},
    )

    events = normalize_kimi_trace(
        identity=_identity(),
        raw_trace_path=captured_wire,
        stage_index=0,
        observed_context=context,
    )

    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "instruction.loaded"
    assert event["source"]["trace_path"] == str(adapter.resolve())
    assert event["source"]["line"] == 1
    assert event["attributes"]["request_observer_path"] == str(observer.resolve())
    assert event["attributes"]["native_wire_path"] == str(captured_wire.resolve())


def _post_stage_read_fixture(
    tmp_path: Path, *, mutate_after_read: bool = False
) -> tuple[Path, Path, KimiObservedTraceContext]:
    run_dir = tmp_path / "run-kimi-direct-001"
    workspace = run_dir / "workspace-kimi-direct-001"
    workspace.mkdir(parents=True)
    artifact = workspace / "inputs" / "context.md"
    artifact.parent.mkdir()
    artifact.write_text(
        "mutated\n" if mutate_after_read else "evidence\n", encoding="utf-8"
    )
    read_time = "2026-07-21T02:00:00+00:00"
    records: list[dict] = [
        {
            "type": "context.append_loop_event",
            "time": read_time,
            "event": {
                "type": "tool.call",
                "toolCallId": "read-direct-001",
                "name": "Read",
                "args": {"path": "inputs/context.md"},
            },
        },
        {
            "type": "context.append_loop_event",
            "time": read_time,
            "event": {
                "type": "tool.result",
                "toolCallId": "read-direct-001",
                "result": {"output": "redacted", "isError": False},
            },
        },
    ]
    if mutate_after_read:
        records.extend(
            [
                {
                    "type": "context.append_loop_event",
                    "time": "2026-07-21T02:00:01+00:00",
                    "event": {
                        "type": "tool.call",
                        "toolCallId": "write-direct-001",
                        "name": "Write",
                        "args": {
                            "path": "inputs/context.md",
                            "content": "mutated\n",
                            "mode": "overwrite",
                        },
                    },
                },
                {
                    "type": "context.append_loop_event",
                    "time": "2026-07-21T02:00:01+00:00",
                    "event": {
                        "type": "tool.result",
                        "toolCallId": "write-direct-001",
                        "result": {"output": "ok", "isError": False},
                    },
                },
            ]
        )
    wire = run_dir / "artifact-kimi-direct-001" / "wire-000.jsonl"
    wire_sha = _write_native_observation_file(wire, records)
    adapter = run_dir / "artifact-kimi-direct-001" / "observations.jsonl"
    _write_native_observation_file(
        adapter,
        {
            "type": "adapter.file_hash_observed",
            "time": "2026-07-21T02:00:03+00:00",
            "observation_phase": "post_stage",
            "stage_completed_at": "2026-07-21T02:00:02+00:00",
            "toolCallId": "read-direct-001",
            "path": "inputs/context.md",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "native_call_line": 1,
            "native_result_line": 2,
            "captured_wire_path": str(wire),
            "captured_wire_sha256": wire_sha,
            "captured_wire_line_count": len(records),
        },
    )
    context = _direct_source_context(
        run_dir=run_dir,
        workspace=workspace,
        wire=wire,
        adapter=adapter,
        expected=("file.read",),
        artifacts={
            "produce": [],
            "consume": ["inputs/context.md"],
            "entry_artifact": None,
            "consumes_carrier_artifact": None,
        },
    )
    return wire, adapter, context


def test_post_stage_read_requires_immutable_wire_and_time_order(tmp_path: Path) -> None:
    wire, adapter, context = _post_stage_read_fixture(tmp_path)

    events = normalize_kimi_trace(
        identity=_identity(),
        raw_trace_path=wire,
        stage_index=0,
        observed_context=context,
    )

    event = next(item for item in events if item["event_type"] == "file.read")
    assert event["source"]["trace_path"] == str(adapter.resolve())
    assert event["attributes"]["hash_observation_phase"] == "post_stage"
    assert event["attributes"]["native_wire_sha256"] == hashlib.sha256(
        wire.read_bytes()
    ).hexdigest()


def test_post_stage_read_rejects_later_same_path_write(tmp_path: Path) -> None:
    wire, _, context = _post_stage_read_fixture(
        tmp_path, mutate_after_read=True
    )

    with pytest.raises(KimiTraceNormalizationError, match="same-path Write"):
        normalize_kimi_trace(
            identity=_identity(),
            raw_trace_path=wire,
            stage_index=0,
            observed_context=context,
        )


def test_direct_handoff_requires_exact_post_stage_produce_declaration(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run-kimi-direct-001"
    workspace = run_dir / "workspace-kimi-direct-001"
    workspace.mkdir(parents=True)
    artifact = workspace / "reports" / "generated.md"
    artifact.parent.mkdir()
    artifact.write_text("handoff\n", encoding="utf-8")
    wire = run_dir / "artifact-kimi-direct-001" / "wire-000.jsonl"
    _write_native_observation_file(
        wire, {"type": "turn.ended", "time": "2026-07-21T03:00:00+00:00"}
    )
    adapter = run_dir / "artifact-kimi-direct-001" / "observations.jsonl"
    _write_native_observation_file(
        adapter,
        {
            "type": "adapter.artifact_handoff",
            "time": "2026-07-21T03:00:02+00:00",
            "observation_phase": "post_stage",
            "stage_completed_at": "2026-07-21T03:00:01+00:00",
            "path": "reports/generated.md",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "declared_change": "created_or_modified",
            "boundary": "stage_completion_artifacts_produce",
        },
    )
    declaration = {
        "path": "reports/generated.md",
        "change": "created_or_modified",
        "sha256_required_after_stage": "yes",
    }
    context = _direct_source_context(
        run_dir=run_dir,
        workspace=workspace,
        wire=wire,
        adapter=adapter,
        expected=("artifact.handoff",),
        artifacts={"produce": [declaration], "consume": []},
    )

    events = normalize_kimi_trace(
        identity=_identity(),
        raw_trace_path=wire,
        stage_index=0,
        observed_context=context,
    )

    assert [event["event_type"] for event in events] == ["artifact.handoff"]
    invalid_context = replace(
        context,
        stage={
            **dict(context.stage),
            "artifacts": {
                "produce": [{**declaration, "path": "reports/other.md"}],
                "consume": [],
            },
        },
    )
    with pytest.raises(KimiTraceNormalizationError, match="produce declaration"):
        normalize_kimi_trace(
            identity=_identity(),
            raw_trace_path=wire,
            stage_index=0,
            observed_context=invalid_context,
        )


def test_native_resume_observation_binds_same_session_and_wire_prefix(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["session.resumed"]
    )
    session_id = "session_fixture_resume"
    session_dir = materialized.run_dir / "config-kimi-trace-001" / "sessions" / session_id
    state_path = session_dir / "state.json"
    state_sha256 = _write_native_observation_file(
        state_path,
        {"agents": {"main": {"type": "main", "parentAgentId": None}}},
    )
    wire_path = session_dir / "agents" / "main" / "wire.jsonl"
    wire_records = [
        {"type": "metadata", "protocol_version": 1},
        {
            "type": "llm.request",
            "kind": "loop",
            "messageCount": 2,
            "time": 1784512800000,
        },
        {"type": "context.append_message", "time": 1784512800001, "message": {}},
        {
            "type": "llm.request",
            "kind": "loop",
            "messageCount": 5,
            "time": 1784512800002,
        },
    ]
    wire_sha256 = _write_native_observation_file(wire_path, wire_records)
    prefix = b"".join(wire_path.read_bytes().splitlines(keepends=True)[:3])
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "adapter.session_resume_observed",
                "time": 1784512800003,
                "session_id": session_id,
                "state": {"path": str(state_path), "sha256": state_sha256},
                "wire": {
                    "path": str(wire_path),
                    "sha256": wire_sha256,
                    "before_line_count": 3,
                    "before_sha256": hashlib.sha256(prefix).hexdigest(),
                    "initial_request_line": 2,
                    "resumed_request_line": 4,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )

    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "session.resumed"
    assert event["session_id"] == session_id
    assert event["source"]["trace_path"] == str(wire_path)
    assert event["source"]["line"] == 4
    assert event["attributes"]["initial_message_count"] == 2
    assert event["attributes"]["resumed_message_count"] == 5
    assert event["attributes"]["post_resume_sha256"] == wire_sha256


def test_native_compaction_observation_emits_summary_hash_and_token_reduction(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["session.compacted"]
    )
    session_id = "session_fixture_compaction"
    session_dir = materialized.run_dir / "config-kimi-trace-001" / "sessions" / session_id
    state_path = session_dir / "state.json"
    state_sha256 = _write_native_observation_file(
        state_path,
        {
            "agents": {
                "main": {
                    "type": "main",
                    "parentAgentId": None,
                    "homedir": str(session_dir / "agents" / "main"),
                }
            }
        },
    )
    summary = "redacted fixture compaction summary"
    wire_records = [
        {"type": "full_compaction.begin", "source": "manual", "time": 1784512800000},
        {
            "type": "llm.request",
            "kind": "compaction",
            "messageCount": 7,
            "time": 1784512800001,
        },
        {
            "type": "context.apply_compaction",
            "summary": summary,
            "contextSummary": "not copied into Event IR",
            "compactedCount": 6,
            "tokensBefore": 317,
            "tokensAfter": 170,
            "keptUserMessageCount": 2,
            "time": 1784512800002,
        },
        {"type": "full_compaction.complete", "time": 1784512800003},
    ]
    wire_path = session_dir / "agents" / "main" / "wire.jsonl"
    wire_sha256 = _write_native_observation_file(wire_path, wire_records)
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "adapter.session_compaction_observed",
                "time": 1784512800003,
                "session_id": session_id,
                "state": {"path": str(state_path), "sha256": state_sha256},
                "wire": {
                    "path": str(wire_path),
                    "sha256": wire_sha256,
                    "begin_line": 1,
                    "request_line": 2,
                    "apply_line": 3,
                    "complete_line": 4,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )

    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "session.compacted"
    assert event["session_id"] == session_id
    assert event["source"] == {
        "trace_path": str(wire_path),
        "line": 3,
        "raw_event_type": "context.apply_compaction",
    }
    assert event["attributes"]["compaction_source"] == "manual"
    assert event["attributes"]["request_line"] == 2
    assert event["attributes"]["request_message_count"] == 7
    assert event["attributes"]["pre_tokens"] == 317
    assert event["attributes"]["post_tokens"] == 170
    assert event["attributes"]["summary_sha256"] == hashlib.sha256(
        summary.encode("utf-8")
    ).hexdigest()
    assert summary not in json.dumps(event)


@pytest.mark.parametrize(
    ("source", "request_kind", "message_count", "error"),
    [
        ("workspace", "compaction", 7, "source is not auto or manual"),
        ("manual", "loop", 7, "begin/request/apply/complete"),
        ("manual", "compaction", 0, "messageCount is invalid"),
    ],
)
def test_compaction_requires_reviewed_source_and_native_request(
    tmp_path: Path,
    case_and_binding_factory,
    source: str,
    request_kind: str,
    message_count: int,
    error: str,
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["session.compacted"]
    )
    session_id = "session_fixture_invalid_compaction_request"
    session_dir = materialized.run_dir / "config-kimi-trace-001" / "sessions" / session_id
    state_path = session_dir / "state.json"
    state_sha256 = _write_native_observation_file(
        state_path,
        {"agents": {"main": {"type": "main", "parentAgentId": None}}},
    )
    wire_path = session_dir / "agents" / "main" / "wire.jsonl"
    wire_sha256 = _write_native_observation_file(
        wire_path,
        [
            {"type": "full_compaction.begin", "source": source, "time": 1},
            {
                "type": "llm.request",
                "kind": request_kind,
                "messageCount": message_count,
                "time": 2,
            },
            {
                "type": "context.apply_compaction",
                "summary": "summary",
                "compactedCount": 1,
                "tokensBefore": 100,
                "tokensAfter": 50,
                "keptUserMessageCount": 1,
                "time": 3,
            },
            {"type": "full_compaction.complete", "time": 4},
        ],
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "adapter.session_compaction_observed",
                "time": 5,
                "session_id": session_id,
                "state": {"path": str(state_path), "sha256": state_sha256},
                "wire": {
                    "path": str(wire_path),
                    "sha256": wire_sha256,
                    "begin_line": 1,
                    "request_line": 2,
                    "apply_line": 3,
                    "complete_line": 4,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match=error):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_compaction_without_token_reduction_fails_closed(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path, case_and_binding_factory, expected=["session.compacted"]
    )
    session_id = "session_fixture_no_reduction"
    session_dir = materialized.run_dir / "config-kimi-trace-001" / "sessions" / session_id
    state_path = session_dir / "state.json"
    state_sha256 = _write_native_observation_file(
        state_path,
        {"agents": {"main": {"type": "main", "parentAgentId": None}}},
    )
    wire_path = session_dir / "agents" / "main" / "wire.jsonl"
    wire_sha256 = _write_native_observation_file(
        wire_path,
        [
            {"type": "full_compaction.begin", "source": "auto", "time": 1},
            {
                "type": "llm.request",
                "kind": "compaction",
                "messageCount": 6,
                "time": 2,
            },
            {
                "type": "context.apply_compaction",
                "summary": "summary",
                "compactedCount": 1,
                "tokensBefore": 100,
                "tokensAfter": 100,
                "keptUserMessageCount": 1,
                "time": 3,
            },
            {"type": "full_compaction.complete", "time": 4},
        ],
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "adapter.session_compaction_observed",
                "time": 4,
                "session_id": session_id,
                "state": {"path": str(state_path), "sha256": state_sha256},
                "wire": {
                    "path": str(wire_path),
                    "sha256": wire_sha256,
                    "begin_line": 1,
                    "request_line": 2,
                    "apply_line": 3,
                    "complete_line": 4,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(KimiTraceNormalizationError, match="reduce token count"):
        _normalize_trace(
            identity=_identity(),
            materialized=materialized,
            raw_trace_path=trace_path,
            stage_index=0,
        )


def test_native_subagent_requires_state_parent_and_two_hashed_wires(
    tmp_path: Path, case_and_binding_factory
) -> None:
    materialized = _materialized(
        tmp_path,
        case_and_binding_factory,
        expected=["agent.spawned", "agent.completed"],
    )
    session_id = "session_fixture_subagent"
    session_dir = materialized.run_dir / "config-kimi-trace-001" / "sessions" / session_id
    state_path = session_dir / "state.json"
    state_sha256 = _write_native_observation_file(
        state_path,
        {
            "agents": {
                "main": {"type": "main", "parentAgentId": None},
                "agent-0": {"type": "sub", "parentAgentId": "main"},
            }
        },
    )
    parent_wire = session_dir / "agents" / "main" / "wire.jsonl"
    handoff = "deterministic child handoff"
    parent_sha256 = _write_native_observation_file(
        parent_wire,
        [
            {
                "type": "context.append_loop_event",
                "time": 1784512800000,
                "event": {
                    "type": "tool.call",
                    "toolCallId": "agent-call-1",
                    "name": "Agent",
                    "args": {
                        "description": "fixture",
                        "subagent_type": "explore",
                    },
                },
            },
            {
                "type": "context.append_loop_event",
                "time": 1784512800002,
                "event": {
                    "type": "tool.result",
                    "toolCallId": "agent-call-1",
                    "result": {"output": handoff},
                },
            },
        ],
    )
    child_wire = session_dir / "agents" / "agent-0" / "wire.jsonl"
    child_sha256 = _write_native_observation_file(
        child_wire,
        [
            {
                "type": "context.append_message",
                "time": 1784512800001,
                "message": {
                    "role": "user",
                    "origin": {"kind": "system_trigger", "name": "subagent"},
                },
            }
        ],
    )
    trace_path = _trace_path(materialized)
    trace_path.write_text(
        json.dumps(
            {
                "type": "adapter.subagent_lifecycle_observed",
                "time": 1784512800003,
                "session_id": session_id,
                "parent_agent_id": "main",
                "child_agent_id": "agent-0",
                "state": {"path": str(state_path), "sha256": state_sha256},
                "parent_wire": {
                    "path": str(parent_wire),
                    "sha256": parent_sha256,
                    "tool_call_line": 1,
                    "tool_result_line": 2,
                },
                "child_wire": {
                    "path": str(child_wire),
                    "sha256": child_sha256,
                    "trigger_line": 1,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    events = _normalize_trace(
        identity=_identity(),
        materialized=materialized,
        raw_trace_path=trace_path,
        stage_index=0,
    )

    assert [event["event_type"] for event in events] == [
        "agent.spawned",
        "agent.completed",
    ]
    assert all(event["session_id"] == session_id for event in events)
    assert all(event["agent_id"] == "agent-0" for event in events)
    assert all(event["parent_agent_id"] == "main" for event in events)
    assert events[0]["source"]["trace_path"] == str(child_wire)
    assert events[1]["source"]["trace_path"] == str(parent_wire)
    assert events[1]["attributes"]["handoff_sha256"] == hashlib.sha256(
        handoff.encode("utf-8")
    ).hexdigest()
    assert handoff not in json.dumps(events)
