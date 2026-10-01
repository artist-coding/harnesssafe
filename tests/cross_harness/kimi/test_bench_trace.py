from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from infra.cross_harness.adapter import HarnessIdentity
from infra.cross_harness.adapters.kimi.executor import (
    NormalizationRequest,
    StageCapture,
    WireCapture,
)
from infra.cross_harness.adapters.kimi.disposition import (
    KimiModelProtocolIncompleteError,
)
from infra.cross_harness.adapters.kimi.materializer import sha256_file
from infra.cross_harness.adapters.kimi.trace import (
    KimiBenchEventIRNormalizer,
    KimiTraceNormalizationError,
)


BINARY_SHA256 = "bc310a7d2f0c3c2cb1367fa7b2092375351efff51c6d4a358b8681b4a01fb7b0"


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _identity() -> HarnessIdentity:
    return HarnessIdentity(
        harness_id="kimi",
        executable="/usr/local/bin/kimi",
        version="0.26.0",
        feature_flags={"binary_sha256": BINARY_SHA256},
    )


def _fixture(tmp_path: Path) -> tuple[NormalizationRequest, Path, Path]:
    run_id = "bench-trace-001"
    case_id = "fixture-case"
    run_dir = tmp_path / f"run-kimi-{run_id}"
    workspace = run_dir / f"workspace-kimi-{run_id}"
    workspace.mkdir(parents=True)
    artifact = workspace / "generated.txt"
    content = "directly observed bytes\n"
    artifact.write_text(content, encoding="utf-8")

    stdout = run_dir / f"trace-kimi-{run_id}-stage-000.jsonl"
    stdout.write_text(
        json.dumps({"role": "assistant", "content": "redacted"}) + "\n",
        encoding="utf-8",
    )
    native_wire = (
        run_dir
        / f"config-kimi-{run_id}"
        / "sessions"
        / "wd_fixture"
        / "session_fixture"
        / "agents"
        / "main"
        / "wire.jsonl"
    )
    native_wire.parent.mkdir(parents=True)
    records = (
        {
            "type": "context.append_loop_event",
            "time": 1784512800000,
            "event": {
                "type": "tool.call",
                "toolCallId": "write-fixture",
                "name": "Write",
                "args": {
                    "path": "generated.txt",
                    "content": content,
                    "mode": "overwrite",
                },
            },
        },
        {
            "type": "context.append_loop_event",
            "time": 1784512801000,
            "event": {
                "type": "tool.result",
                "toolCallId": "write-fixture",
                "result": {"output": "redacted"},
            },
        },
    )
    wire_bytes = "".join(
        json.dumps(record, sort_keys=True) + "\n" for record in records
    ).encode("utf-8")
    native_wire.write_bytes(wire_bytes)
    wire_sha = hashlib.sha256(wire_bytes).hexdigest()
    captured_wire = run_dir / f"wire-capture-kimi-{run_id}-stage-000.jsonl"
    captured_wire.write_bytes(wire_bytes)
    main_wire = run_dir / f"wire-kimi-{run_id}-stage-000.jsonl"
    main_wire.write_bytes(wire_bytes)
    wire = WireCapture(
        source_path=native_wire,
        captured_path=captured_wire,
        sha256=wire_sha,
        line_count=2,
        is_main=True,
    )

    result_path = run_dir / f"result-kimi-{run_id}-stage-000.json"
    result = {
        "schema_name": "safety_bench_kimi_stage_execution",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": run_id,
        "case_id": case_id,
        "stage": {"index": 0, "name": "attack"},
        "pid": 41001,
        "return_code": 0,
        "stdout": {
            "path": str(stdout),
            "sha256": sha256_file(stdout),
            "line_count": 1,
        },
        "wire": {
            "main_path": str(main_wire),
            "main_sha256": wire_sha,
            "captures": [wire.as_dict()],
        },
        "control_observation_trace": None,
    }
    result_path.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    capture = StageCapture(
        index=0,
        name="attack",
        pid=41001,
        return_code=0,
        stdout_path=stdout,
        stdout_sha256=sha256_file(stdout),
        stderr_path=run_dir / f"stderr-kimi-{run_id}-stage-000.log",
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        main_wire_path=main_wire,
        main_wire_sha256=wire_sha,
        wire_captures=(wire,),
        result_path=result_path,
    )

    manifest = {
        "schema_name": "safety_bench_kimi_bench_plan",
        "schema_version": 1,
        "harness_id": "kimi",
        "run_id": run_id,
        "case_id": case_id,
        "disposition": "READY",
        "materialized": {
            "run_dir": str(run_dir),
            "workspace_dir": str(workspace),
        },
        "stages": [
            {
                "index": 0,
                "name": "attack",
                "expected_event_ir": ["file.write"],
                "surfaces": {
                    "artifacts": {
                        "produce": [
                            {
                                "path": "generated.txt",
                                "change": "created_or_modified",
                                "sha256_required_after_stage": "yes",
                            }
                        ],
                        "consume": [],
                        "quarantine_after": [],
                        "forbid_before": [],
                        "carrier_artifact": None,
                        "consumes_carrier_artifact": None,
                        "entry_artifact": None,
                    }
                },
            }
        ],
    }
    manifest["manifest_payload_sha256"] = _canonical_sha256(manifest)
    manifest_path = run_dir / f"manifest-kimi-{run_id}.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    request = NormalizationRequest(
        run_id=run_id,
        case_id=case_id,
        manifest_path=manifest_path,
        manifest_sha256=sha256_file(manifest_path),
        stage_captures=(capture,),
        output_path=run_dir / f"event-ir-kimi-{run_id}.jsonl",
    )
    return request, native_wire, captured_wire


def test_bench_normalizer_writes_run_global_event_ir_from_pinned_capture(
    tmp_path: Path,
) -> None:
    request, native_wire, captured_wire = _fixture(tmp_path)
    with native_wire.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {"type": "turn.ended", "time": 1784512802000}, sort_keys=True
            )
            + "\n"
        )

    output = KimiBenchEventIRNormalizer(identity=_identity()).normalize(request)

    events = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 1
    event = events[0]
    assert event["event_type"] == "file.write"
    assert event["sequence"] == 0
    assert event["stage"] == {"index": 0, "name": "attack"}
    assert event["source"]["trace_path"] == str(captured_wire.resolve())
    assert event["source"]["line"] == 2
    assert event["artifact"]["path"] == "generated.txt"
    assert event["artifact"]["sha256"] == hashlib.sha256(
        b"directly observed bytes\n"
    ).hexdigest()


def test_bench_normalizer_fails_closed_when_immutable_wire_capture_drifts(
    tmp_path: Path,
) -> None:
    request, _, captured_wire = _fixture(tmp_path)
    captured_wire.write_text("{}\n", encoding="utf-8")

    with pytest.raises(KimiTraceNormalizationError, match="SHA-256 drifted"):
        KimiBenchEventIRNormalizer(identity=_identity()).normalize(request)


def test_bench_normalizer_fails_closed_when_required_event_is_absent(
    tmp_path: Path,
) -> None:
    request, _, _ = _fixture(tmp_path)
    manifest = json.loads(request.manifest_path.read_text(encoding="utf-8"))
    manifest["stages"][0]["expected_event_ir"] = ["file.read"]
    manifest["manifest_payload_sha256"] = _canonical_sha256(
        {
            key: value
            for key, value in manifest.items()
            if key != "manifest_payload_sha256"
        }
    )
    request.manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    request = NormalizationRequest(
        run_id=request.run_id,
        case_id=request.case_id,
        manifest_path=request.manifest_path,
        manifest_sha256=sha256_file(request.manifest_path),
        stage_captures=request.stage_captures,
        output_path=request.output_path,
    )

    with pytest.raises(
        KimiModelProtocolIncompleteError, match="not directly observed"
    ):
        KimiBenchEventIRNormalizer(identity=_identity()).normalize(request)
