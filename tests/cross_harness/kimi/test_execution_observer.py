from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

import pytest

from infra.cross_harness.adapters.kimi.execution_observer import (
    KimiDirectEvidenceError,
    KimiDirectEvidenceObserver,
)
from infra.cross_harness.adapters.kimi.executor import (
    StageControlFinalizeRequest,
    StageControlRequest,
)
from infra.cross_harness.adapters.kimi.provider_broker import (
    InstructionRequestObservation,
    REQUEST_OBSERVATION_SCHEMA_NAME,
    REQUEST_OBSERVATION_SCHEMA_VERSION,
)


RUN_ID = "observer-001"
CASE_ID = "case-observer"
TRIAL_ID = "attack-attempt-001"


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class FakeInstructionBroker:
    def __init__(self, run_root: Path, *, tamper_digest: bool = False) -> None:
        self.run_id = RUN_ID
        self.case_id = CASE_ID
        self.trial_id = TRIAL_ID
        self.root = run_root / f"broker-kimi-{RUN_ID}-{TRIAL_ID}"
        self.root.mkdir(mode=0o700)
        self.tamper_digest = tamper_digest
        self.configured: dict[int, tuple[Path, bytes, tuple[str, ...]]] = {}
        self.observed_time = (
            datetime.now(timezone.utc) - timedelta(seconds=4)
        ).isoformat()

    def configure_instruction_observer(
        self,
        *,
        run_id: str,
        stage_index: int,
        marker: bytes,
        expected_roles: Sequence[str] = ("system", "user", "user"),
    ) -> Path:
        assert run_id == self.run_id
        path = self.root / (
            f"request-observer-kimi-{run_id}-stage-{stage_index:03d}.jsonl"
        )
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        self.configured[stage_index] = (path, marker, tuple(expected_roles))
        return path

    def finalize_instruction_observer(
        self, *, run_id: str, stage_index: int
    ) -> InstructionRequestObservation:
        assert run_id == self.run_id
        path, marker, roles = self.configured[stage_index]
        body_sha = _sha(b"redacted-provider-body")
        record = {
            "schema_name": REQUEST_OBSERVATION_SCHEMA_NAME,
            "schema_version": REQUEST_OBSERVATION_SCHEMA_VERSION,
            "harness_id": "kimi",
            "run_id": self.run_id,
            "case_id": self.case_id,
            "trial_id": self.trial_id,
            "stage_index": stage_index,
            "sequence": 1,
            "time": self.observed_time,
            "body_sha256": body_sha,
            "body_bytes": 317,
            "target_sha256": _sha(b"/v1/chat/completions"),
            "message_roles": list(roles),
            "expected_substring_present": True,
            "expected_substring_sha256": _sha(marker),
        }
        path.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        digest = _sha(path.read_bytes())
        return InstructionRequestObservation(
            path=path,
            sha256="0" * 64 if self.tamper_digest else digest,
            line=1,
            line_count=1,
            body_sha256=body_sha,
            marker_sha256=_sha(marker),
            message_roles=roles,
            observed_time=self.observed_time,
        )


def _wire_record(
    *, call_id: str, name: str, args: Mapping[str, Any], time: str
) -> list[dict[str, Any]]:
    return [
        {
            "type": "context.append_loop_event",
            "time": time,
            "event": {
                "type": "tool.call",
                "toolCallId": call_id,
                "name": name,
                "args": dict(args),
            },
        },
        {
            "type": "context.append_loop_event",
            "time": time,
            "event": {
                "type": "tool.result",
                "toolCallId": call_id,
                "result": {"output": "redacted", "isError": False},
            },
        },
    ]


def _stage_fixture(
    tmp_path: Path,
    *,
    expected: Sequence[str],
    read_path: str | None = None,
    produce_path: str | None = None,
    instruction: bool = False,
    extra_wire: Sequence[Mapping[str, Any]] = (),
) -> tuple[
    StageControlRequest,
    StageControlFinalizeRequest,
    dict[str, Path],
]:
    run_root = tmp_path / f"run-kimi-{RUN_ID}"
    stage_root = run_root / f"stage-kimi-{RUN_ID}-stage-000-main"
    runtime = stage_root / f"runtime-kimi-{RUN_ID}-stage-000-main"
    workspace = run_root / f"workspace-kimi-{RUN_ID}"
    artifact_root = runtime / f"artifact-kimi-{RUN_ID}-stage-000"
    for path in (runtime, workspace, artifact_root):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    instruction_path = workspace / ".kimi-code" / "AGENTS.md"
    instruction_bytes = (
        b"# Kimi project instruction\nUse the exact run-local project conventions.\n"
    )
    if instruction:
        instruction_path.parent.mkdir(mode=0o700)
        instruction_path.write_bytes(instruction_bytes)
    if read_path is not None:
        read_artifact = workspace / read_path
        read_artifact.parent.mkdir(parents=True, exist_ok=True)
        read_artifact.write_text("read evidence\n", encoding="utf-8")
    if produce_path is not None:
        produced = workspace / produce_path
        produced.parent.mkdir(parents=True, exist_ok=True)
        produced.write_text("produced evidence\n", encoding="utf-8")

    now = datetime.now(timezone.utc)
    native_request_time = (now - timedelta(seconds=5)).isoformat()
    tool_time = (now - timedelta(seconds=2)).isoformat()
    system_prompt = "native header\n" + instruction_bytes.decode("utf-8")
    records: list[Mapping[str, Any]] = []
    if instruction:
        records.extend(
            (
                {
                    "type": "config.update",
                    "systemPrompt": system_prompt,
                    "time": native_request_time,
                },
                {
                    "type": "llm.request",
                    "kind": "loop",
                    "systemPromptHash": _sha(system_prompt.encode("utf-8")),
                    "messageCount": 2,
                    "time": native_request_time,
                },
            )
        )
    else:
        records.append(
            {
                "type": "llm.request",
                "kind": "loop",
                "systemPromptHash": "a" * 64,
                "messageCount": 2,
                "time": native_request_time,
            }
        )
    if read_path is not None:
        records.extend(
            _wire_record(
                call_id="read-001",
                name="Read",
                args={"path": read_path},
                time=tool_time,
            )
        )
    records.extend(extra_wire)
    wire_bytes = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    ).encode("utf-8")
    session_id = "session_fixture_observer"
    native_wire = (
        runtime
        / f"config-kimi-{RUN_ID}"
        / "sessions"
        / session_id
        / "agents"
        / "main"
        / "wire.jsonl"
    )
    captured_wire = artifact_root / "wire-captures" / "wire-000.jsonl"
    main_copy = runtime / f"wire-kimi-{RUN_ID}-stage-000.jsonl"
    for path in (native_wire, captured_wire, main_copy):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(wire_bytes)
    wire_sha = _sha(wire_bytes)
    stdout_path = runtime / f"trace-kimi-{RUN_ID}-stage-000.jsonl"
    stdout_bytes = (
        json.dumps(
            {
                "role": "meta",
                "type": "session.resume_hint",
                "session_id": session_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    stdout_path.write_bytes(stdout_bytes)

    consume = [read_path] if read_path is not None else []
    produce = (
        [
            {
                "path": produce_path,
                "change": "created_or_modified",
                "sha256_required_after_stage": "yes",
            }
        ]
        if produce_path is not None
        else []
    )
    stage_document: dict[str, Any] = {
        "index": 0,
        "name": "main",
        "expected_event_ir": list(expected),
        "runtime_paths": {
            "workspace": str(workspace),
            "trace": str(stdout_path),
        },
        "surfaces": {
            "instruction": (
                {
                    "kind": "project_instruction",
                    "target": "workspace/.kimi-code/AGENTS.md",
                }
                if instruction
                else None
            ),
            "artifacts": {
                "produce": produce,
                "consume": consume,
                "entry_artifact": None,
                "consumes_carrier_artifact": None,
            },
        },
    }
    prepare = StageControlRequest(
        run_id=RUN_ID,
        case_id=CASE_ID,
        stage_index=0,
        stage_name="main",
        control_kind="direct_evidence",
        stage_document=stage_document,
        prior_stage_results=(),
    )
    stage_result = {
        "schema_name": "safety_bench_kimi_stage_execution",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": RUN_ID,
        "case_id": CASE_ID,
        "stage": {"index": 0, "name": "main"},
        "return_code": 0,
        "timed_out": False,
        "cwd": str(workspace),
        "wire": {
            "main_path": str(main_copy),
            "main_sha256": wire_sha,
            "captures": [
                {
                    "source_path": str(native_wire),
                    "captured_path": str(captured_wire),
                    "sha256": wire_sha,
                    "line_count": len(wire_bytes.splitlines()),
                    "is_main": True,
                }
            ],
        },
        "stdout": {
            "path": str(stdout_path),
            "sha256": _sha(stdout_bytes),
            "line_count": 1,
        },
        "completed_at": (now - timedelta(seconds=1)).isoformat(),
    }
    finalize = StageControlFinalizeRequest(
        **prepare.__dict__, stage_result=stage_result
    )
    return prepare, finalize, {
        "run_root": run_root,
        "workspace": workspace,
        "instruction": instruction_path,
        "native_wire": native_wire,
        "captured_wire": captured_wire,
        "main_copy": main_copy,
        "stdout": stdout_path,
    }


def test_direct_observer_emits_instruction_read_and_handoff_evidence(
    tmp_path: Path,
) -> None:
    prepare, finalize, paths = _stage_fixture(
        tmp_path,
        expected=("instruction.loaded", "file.read", "artifact.handoff"),
        read_path="inputs/context.md",
        produce_path="reports/output.md",
        instruction=True,
    )
    broker = FakeInstructionBroker(paths["run_root"])
    observer = KimiDirectEvidenceObserver(broker)

    directive = observer.prepare(prepare)
    result = observer.finalize(finalize)

    assert directive.argv_suffix == ()
    assert directive.launch_mode == "prompt"
    assert [record["type"] for record in result.observation_records] == [
        "adapter.instruction_loading_observed",
        "adapter.file_hash_observed",
        "adapter.artifact_handoff",
    ]
    instruction = result.observation_records[0]
    instruction_bytes = paths["instruction"].read_bytes()
    marker = instruction["instruction"]
    assert _sha(
        instruction_bytes[
            marker["marker_offset"] : marker["marker_offset"]
            + marker["marker_length"]
        ]
    ) == marker["marker_sha256"]
    assert instruction["wire"]["path"] == str(paths["captured_wire"])
    assert instruction["wire"]["native_source_path"] == str(
        paths["native_wire"]
    )
    read = result.observation_records[1]
    assert read["observation_phase"] == "post_stage"
    assert read["native_result_line"] == 4
    assert read["captured_wire_sha256"] == _sha(
        paths["captured_wire"].read_bytes()
    )
    assert datetime.fromisoformat(read["time"]) >= datetime.fromisoformat(
        read["stage_completed_at"]
    )
    handoff = result.observation_records[2]
    assert handoff["boundary"] == "stage_completion_artifacts_produce"
    assert handoff["sha256"] == _sha(
        (paths["workspace"] / "reports/output.md").read_bytes()
    )
    serialized = json.dumps(result.observation_records).casefold()
    for forbidden in ("score", "verdict", "attack_success", "progress_node"):
        assert f'"{forbidden}"' not in serialized


def test_empty_expected_stage_emits_bound_session_start_evidence(
    tmp_path: Path,
) -> None:
    prepare, finalize, paths = _stage_fixture(tmp_path, expected=())
    observer = KimiDirectEvidenceObserver()

    observer.prepare(prepare)
    result = observer.finalize(finalize)

    assert len(result.observation_records) == 1
    start = result.observation_records[0]
    assert start["type"] == "adapter.session_start_observed"
    assert start["session_id"] == "session_fixture_observer"
    assert start["stdout"]["path"] == str(paths["stdout"])
    assert start["wire"]["path"] == str(paths["captured_wire"])
    assert start["wire"]["prior_line_count"] == 0


@pytest.mark.parametrize("mutator", ["same_path_write", "opaque_agent"])
def test_read_uses_pre_stage_snapshot_when_later_tool_may_mutate(
    tmp_path: Path, mutator: str
) -> None:
    now = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    if mutator == "same_path_write":
        extra = _wire_record(
            call_id="write-001",
            name="Write",
            args={
                "path": "inputs/context.md",
                "content": "mutated\n",
                "mode": "overwrite",
            },
            time=now,
        )
    else:
        extra = _wire_record(
            call_id="agent-001",
            name="Agent",
            args={"subagent_type": "coder", "prompt": "fixture"},
            time=now,
        )
    prepare, finalize, paths = _stage_fixture(
        tmp_path,
        expected=("file.read",),
        read_path="inputs/context.md",
        extra_wire=extra,
    )
    if mutator == "same_path_write":
        (paths["workspace"] / "inputs/context.md").write_text(
            "mutated\n", encoding="utf-8"
        )
    observer = KimiDirectEvidenceObserver()
    observer.prepare(prepare)

    result = observer.finalize(finalize)

    assert len(result.observation_records) == 1
    observation = result.observation_records[0]
    assert observation["type"] == "adapter.file_hash_observed"
    assert observation["observation_phase"] == "pre_stage"
    assert observation["toolCallId"] == "read-001"
    assert observation["path"] == "inputs/context.md"


def test_handoff_hashes_only_declared_produce_at_real_finalize_boundary(
    tmp_path: Path,
) -> None:
    prepare, finalize, paths = _stage_fixture(
        tmp_path,
        expected=("artifact.handoff",),
        produce_path="reports/generated.md",
    )
    observer = KimiDirectEvidenceObserver()
    observer.prepare(prepare)

    result = observer.finalize(finalize)

    assert len(result.observation_records) == 1
    handoff = result.observation_records[0]
    assert handoff["type"] == "adapter.artifact_handoff"
    assert handoff["path"] == "reports/generated.md"
    assert datetime.fromisoformat(handoff["time"]) >= datetime.fromisoformat(
        handoff["stage_completed_at"]
    )
    assert handoff["sha256"] == _sha(
        (paths["workspace"] / "reports/generated.md").read_bytes()
    )


def test_instruction_and_wire_hash_drift_fail_closed(tmp_path: Path) -> None:
    prepare, finalize, paths = _stage_fixture(
        tmp_path,
        expected=("instruction.loaded",),
        instruction=True,
    )
    broker = FakeInstructionBroker(paths["run_root"])
    observer = KimiDirectEvidenceObserver(broker)
    observer.prepare(prepare)
    paths["instruction"].write_text("changed\n", encoding="utf-8")

    with pytest.raises(KimiDirectEvidenceError, match="instruction changed"):
        observer.finalize(finalize)

    prepare2, finalize2, paths2 = _stage_fixture(
        tmp_path / "second",
        expected=("file.read",),
        read_path="inputs/context.md",
    )
    observer2 = KimiDirectEvidenceObserver()
    observer2.prepare(prepare2)
    paths2["captured_wire"].write_bytes(
        paths2["captured_wire"].read_bytes() + b"{}\n"
    )
    with pytest.raises(KimiDirectEvidenceError, match="captured main wire"):
        observer2.finalize(finalize2)


def test_malformed_broker_snapshot_and_finalize_without_prepare_fail_closed(
    tmp_path: Path,
) -> None:
    prepare, finalize, paths = _stage_fixture(
        tmp_path,
        expected=("instruction.loaded",),
        instruction=True,
    )
    broker = FakeInstructionBroker(paths["run_root"], tamper_digest=True)
    observer = KimiDirectEvidenceObserver(broker)
    observer.prepare(prepare)

    with pytest.raises(KimiDirectEvidenceError, match="observer SHA-256"):
        observer.finalize(finalize)

    with pytest.raises(KimiDirectEvidenceError, match="not prepared"):
        KimiDirectEvidenceObserver().finalize(replace(finalize))
