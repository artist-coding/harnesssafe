"""Generate exact-binary OpenCode Contract v1 conformance evidence."""

from __future__ import annotations

import argparse
from collections import Counter
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Mapping, Sequence

from ...adapter import HarnessIdentity, MaterializedBinding
from ...bindings.opencode import load_opencode_smoke_bindings
from ...contract import CAPABILITIES, validate_event_document
from .adapter import OpenCodeHarnessAdapter
from .launcher import build_opencode_bwrap_command, build_opencode_launch_spec
from .local_fixture import OpenAIFixtureServer
from .materializer import (
    load_materialization_manifest,
    materialize_opencode_binding,
    sha256_file,
)
from .trace import normalize_opencode_trace


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_WORK_ROOT = Path("/tmp/safety-bench-opencode-conformance-v1")
DEFAULT_OUTPUT = DEFAULT_WORK_ROOT / "opencode-conformance.json"
MODEL = "bench-fixture/fixture-model"


class OpenCodeConformanceError(RuntimeError):
    """OpenCode conformance generation could not complete safely."""


@dataclass
class ProbeResult:
    name: str
    events: tuple[str, ...]
    evidence: tuple[str, ...]
    session_id: str | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _provider(base_url: str) -> dict[str, Any]:
    return {
        "bench-fixture": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "Safety Bench Fixture",
            "options": {"baseURL": base_url, "apiKey": "fixture-key"},
            "models": {"fixture-model": {"name": "Fixture Model"}},
        }
    }


def _case_row(repo_root: Path, case_id: str) -> Mapping[str, Any]:
    inventory = json.loads(
        (repo_root / "docs/codex_conformance_smoke_v1.json").read_text(
            encoding="utf-8"
        )
    )
    for row in inventory["cases"]:
        if row["case_id"] == case_id:
            return row
    raise OpenCodeConformanceError(f"unknown smoke case: {case_id}")


def _binding_with_prompts(
    repo_root: Path,
    case_id: str,
    prompts: Mapping[int, str],
    *,
    stage_limit: int | None = None,
) -> tuple[dict[str, Any], Path]:
    bindings = load_opencode_smoke_bindings(repo_root=repo_root)
    binding = copy.deepcopy(bindings[case_id])
    native = binding["harness_native_binding"]["opencode"]
    config = native["config"]
    config["disposition"] = "READY"
    config["blocking_reasons"] = []
    if stage_limit is not None:
        config["stages"] = config["stages"][:stage_limit]
    for stage in config["stages"]:
        index = int(stage["index"])
        if index in prompts:
            stage["prompt"] = prompts[index]
    row = _case_row(repo_root, case_id)
    return binding, repo_root / row["case_dir"]


def _session_id(path: Path) -> str:
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        row = json.loads(raw)
        value = row.get("sessionID")
        if isinstance(value, str) and value:
            return value
        part = row.get("part")
        if isinstance(part, Mapping):
            value = part.get("sessionID")
            if isinstance(value, str) and value:
                return value
    raise OpenCodeConformanceError(f"trace has no sessionID: {path}")


def _message_text(messages: Any) -> str:
    if not isinstance(messages, list):
        return ""
    values: list[str] = []
    for message in messages:
        if not isinstance(message, Mapping):
            continue
        content = message.get("content")
        if isinstance(content, str):
            values.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, Mapping) and isinstance(part.get("text"), str):
                    values.append(part["text"])
    return "\n".join(values)


def _request_text(record: Mapping[str, Any]) -> str:
    texts = [_message_text(record.get("messages"))]
    system = record.get("system")
    if isinstance(system, str):
        texts.append(system)
    return "\n".join(value for value in texts if value)


def _matching_instruction_request(
    *,
    request_log: Path,
    instruction_text: str,
    start_line: int,
) -> int | None:
    required_lines = [
        line.strip()
        for line in instruction_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if len(required_lines) < 5:
        raise OpenCodeConformanceError(
            "instruction loading probe needs at least five non-empty content lines"
        )
    if not request_log.is_file():
        return None
    for line_number, raw in enumerate(
        request_log.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if line_number < start_line or not raw.strip():
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, Mapping):
            continue
        text = _request_text(record)
        if all(line in text for line in required_lines):
            return line_number
    return None


def _request_log_line_count(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line)


def _instruction_probe_binding(repo_root: Path) -> tuple[dict[str, Any], Path]:
    case_id = "SK_E_sk_e_case_703_local_memory_state_attack_v3_prepoisoned_claudemd"
    bindings = load_opencode_smoke_bindings(repo_root=repo_root)
    binding = copy.deepcopy(bindings[case_id])
    row = _case_row(repo_root, case_id)
    binding["harness_native_binding"]["opencode"] = {
        "adapter": "opencode.adapter_v1",
        "variant_kind": "native",
        "config": {
            "binding_class": "M",
            "disposition": "READY",
            "blocking_reasons": [],
            "stages": [
                {
                    "index": 0,
                    "name": "instruction_loading_probe",
                    "skills": ["plugin/skills/workspace-test-runner"],
                    "prompt": "[fixture:skill workspace-test-runner]",
                }
            ],
            "permissions": {
                "read": "allow",
                "edit": "allow",
                "skill": "allow",
                "bash": "allow",
            },
        },
        "expected_event_types": [
            "instruction.loaded",
            "skill.discovered",
            "skill.activated",
        ],
        "artifact_bindings": {
            "instruction": "AGENTS.md",
            "skill": "plugin/skills/workspace-test-runner/SKILL.md",
        },
    }
    return binding, repo_root / row["case_dir"]


def _instruction_loaded_event(
    *,
    identity: HarnessIdentity,
    materialized: MaterializedBinding,
    run_id: str,
    instruction: Mapping[str, str],
    request_log: Path,
    request_line: int,
) -> dict[str, Any]:
    manifest = load_materialization_manifest(materialized)
    stage = manifest["stages"][0]
    event = {
        "schema_name": "safety_bench_cross_harness_event",
        "schema_version": 1,
        "event_id": f"{run_id}:instruction-loaded:{request_line}",
        "event_type": "instruction.loaded",
        "run_id": run_id,
        "case_id": materialized.case_id,
        "sequence": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "harness": {
            "id": identity.harness_id,
            "version": identity.version,
            "feature_flags": dict(identity.feature_flags),
        },
        "stage": {"name": str(stage["name"]), "index": int(stage["index"])},
        "source": {
            "trace_path": str(request_log),
            "line": request_line,
            "raw_event_type": "provider.request.messages",
        },
        "attributes": {
            "path": instruction["target"],
            "sha256": instruction["sha256"],
        },
    }
    validate_event_document(event)
    return event


def _run_instruction_loading_probe(
    *,
    repo_root: Path,
    identity: HarnessIdentity,
    provider_config: Mapping[str, Any],
    request_log: Path,
    work_root: Path,
    timeout_seconds: int,
    base_environment: Mapping[str, str],
) -> list[ProbeResult]:
    run_id = "oc-conf-instruction"
    case_run_dir = work_root / "probes" / run_id
    if case_run_dir.exists():
        shutil.rmtree(case_run_dir)
    binding, case_dir = _instruction_probe_binding(repo_root)
    materialized = materialize_opencode_binding(
        run_id=run_id,
        case_dir=case_dir,
        binding_document=binding,
        run_dir=case_run_dir,
        model=MODEL,
        provider_config=provider_config,
    )
    manifest = load_materialization_manifest(materialized)
    instructions = manifest.get("instructions")
    if not isinstance(instructions, list) or len(instructions) != 1:
        raise OpenCodeConformanceError(
            "instruction loading probe did not materialize exactly one instruction"
        )
    instruction = instructions[0]
    if not isinstance(instruction, Mapping):
        raise OpenCodeConformanceError("instruction manifest entry is invalid")
    instruction_path = Path(str(manifest["workspace_dir"])) / str(instruction["target"])
    instruction_text = instruction_path.read_text(encoding="utf-8")
    start_line = _request_log_line_count(request_log) + 1
    stage_result = _run_stage(
        identity=identity,
        materialized=materialized,
        run_id=run_id,
        case_run_dir=case_run_dir,
        stage_index=0,
        session_id=None,
        timeout_seconds=timeout_seconds,
        base_environment=base_environment,
    )
    request_line = _matching_instruction_request(
        request_log=request_log,
        instruction_text=instruction_text,
        start_line=start_line,
    )
    if request_line is None:
        raise OpenCodeConformanceError(
            "fixture provider request did not contain the translated AGENTS.md content"
        )
    event = _instruction_loaded_event(
        identity=identity,
        materialized=materialized,
        run_id=run_id,
        instruction={
            "target": str(instruction["target"]),
            "sha256": str(instruction["sha256"]),
        },
        request_log=request_log,
        request_line=request_line,
    )
    event_path = case_run_dir / "normalized" / "instruction-loading.jsonl"
    _write_jsonl(event_path, [event])
    instruction_result = ProbeResult(
        name=run_id,
        events=("instruction.loaded",),
        evidence=(
            f"probe:{run_id}",
            f"provider-request:{request_log}:{request_line}",
            f"events:{event_path}",
            f"instruction:{instruction_path}",
            f"instruction-sha256:{instruction['sha256']}",
        ),
        session_id=stage_result.session_id,
    )
    return [stage_result, instruction_result]


def _run_stage(
    *,
    identity: HarnessIdentity,
    materialized: MaterializedBinding,
    run_id: str,
    case_run_dir: Path,
    stage_index: int,
    session_id: str | None,
    timeout_seconds: int,
    base_environment: Mapping[str, str],
) -> ProbeResult:
    manifest = load_materialization_manifest(materialized)
    stage = next(
        stage
        for stage in manifest["stages"]
        if int(stage["index"]) == stage_index
    )
    prompt = Path(stage["prompt_path"]).read_text(encoding="utf-8")
    spec = build_opencode_launch_spec(
        materialized=materialized,
        executable=identity.executable,
        prompt=prompt,
        timeout_seconds=timeout_seconds,
        stage_index=stage_index,
        session_id=session_id,
        base_environment=base_environment,
    )
    command = build_opencode_bwrap_command(
        launch_spec=spec,
        run_dir=case_run_dir,
        executable=Path(identity.executable),
    )
    result = subprocess.run(
        command,
        cwd="/",
        env={"PATH": "/usr/bin:/bin"},
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    spec.trace_path.parent.mkdir(parents=True, exist_ok=True)
    spec.trace_path.write_text(result.stdout, encoding="utf-8")
    stderr_path = case_run_dir / "raw" / f"stage-{stage_index:02d}-stderr.txt"
    stderr_path.write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        raise OpenCodeConformanceError(
            f"{run_id} stage {stage_index} exited {result.returncode}"
        )
    events = list(
        normalize_opencode_trace(
            identity=identity,
            materialized=materialized,
            raw_trace_path=spec.trace_path,
            stage_index=stage_index,
            run_id=run_id,
        )
    )
    event_path = case_run_dir / "normalized" / f"stage-{stage_index:02d}.jsonl"
    _write_jsonl(event_path, events)
    sid = _session_id(spec.trace_path)
    event_types = tuple(sorted({str(event["event_type"]) for event in events}))
    return ProbeResult(
        name=run_id,
        events=event_types,
        evidence=(
            f"probe:{run_id}",
            f"raw:{spec.trace_path}",
            f"events:{event_path}",
            f"stderr:{stderr_path}",
        ),
        session_id=sid,
    )


def _run_probe(
    *,
    repo_root: Path,
    identity: HarnessIdentity,
    provider_config: Mapping[str, Any],
    case_id: str,
    prompts: Mapping[int, str],
    work_root: Path,
    run_id: str,
    timeout_seconds: int,
    base_environment: Mapping[str, str],
    stage_limit: int | None = None,
) -> list[ProbeResult]:
    case_run_dir = work_root / "probes" / run_id
    if case_run_dir.exists():
        shutil.rmtree(case_run_dir)
    binding, case_dir = _binding_with_prompts(
        repo_root, case_id, prompts, stage_limit=stage_limit
    )
    materialized = materialize_opencode_binding(
        run_id=run_id,
        case_dir=case_dir,
        binding_document=binding,
        run_dir=case_run_dir,
        model=MODEL,
        provider_config=provider_config,
    )
    manifest = load_materialization_manifest(materialized)
    results: list[ProbeResult] = []
    session_id: str | None = None
    for stage in manifest["stages"]:
        index = int(stage["index"])
        result = _run_stage(
            identity=identity,
            materialized=materialized,
            run_id=run_id,
            case_run_dir=case_run_dir,
            stage_index=index,
            session_id=session_id,
            timeout_seconds=timeout_seconds,
            base_environment=base_environment,
        )
        if stage.get("session_action") in {"resume", "continue"}:
            if session_id is None or result.session_id != session_id:
                raise OpenCodeConformanceError(
                    f"{run_id} did not resume the exact prior session"
                )
        else:
            session_id = result.session_id
        results.append(result)
    return results


def _entry(
    status: str,
    *,
    evidence: Sequence[str] = (),
    reason: str = "",
    executed: bool | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "executed": bool(evidence) if executed is None else executed,
        "evidence": list(dict.fromkeys(evidence)),
        "reason": reason,
    }


def _support_from_probes(probes: Sequence[ProbeResult]) -> dict[str, Any]:
    by_event: dict[str, list[str]] = {}
    all_evidence: list[str] = []
    session_ids: list[str] = []
    for probe in probes:
        if not probe.ok:
            continue
        all_evidence.extend(probe.evidence)
        if probe.session_id:
            session_ids.append(probe.session_id)
        for event_type in probe.events:
            by_event.setdefault(event_type, []).extend(probe.evidence)
    supported: dict[str, Any] = {}
    if "session.started" in by_event:
        supported["headless_execution"] = _entry(
            "SUPPORTED", evidence=by_event["session.started"]
        )
        supported["structured_trace"] = _entry(
            "SUPPORTED", evidence=by_event["session.started"]
        )
        supported["workspace_isolation"] = _entry(
            "SUPPORTED", evidence=by_event["session.started"]
        )
    if len(set(session_ids)) >= 2:
        supported["fresh_process"] = _entry(
            "SUPPORTED",
            evidence=[
                *all_evidence,
                "probe:fresh-process:distinct-session-ids",
            ],
        )
    if "skill.discovered" in by_event:
        supported["skill_discovery"] = _entry(
            "SUPPORTED", evidence=by_event["skill.discovered"]
        )
    if "skill.activated" in by_event:
        supported["skill_activation_trace"] = _entry(
            "SUPPORTED", evidence=by_event["skill.activated"]
        )
    if "instruction.loaded" in by_event:
        supported["instruction_loading"] = _entry(
            "SUPPORTED", evidence=by_event["instruction.loaded"]
        )
    if "mcp.server_initialized" in by_event:
        supported["mcp_configuration"] = _entry(
            "SUPPORTED", evidence=by_event["mcp.server_initialized"]
        )
        supported["mcp_health_trace"] = _entry(
            "SUPPORTED", evidence=by_event["mcp.server_initialized"]
        )
    if "mcp.tool_requested" in by_event and "mcp.tool_result" in by_event:
        supported["mcp_tool_trace"] = _entry(
            "SUPPORTED",
            evidence=[
                *by_event["mcp.tool_requested"],
                *by_event["mcp.tool_result"],
            ],
        )
    if "session.resumed" in by_event:
        supported["session_resume"] = _entry(
            "SUPPORTED", evidence=by_event["session.resumed"]
        )
    if "agent.spawned" in by_event and "agent.completed" in by_event:
        supported["subagent_delegation"] = _entry(
            "SUPPORTED",
            evidence=[
                *by_event["agent.spawned"],
                *by_event["agent.completed"],
            ],
        )
    if any(event in by_event for event in ("file.read", "file.write", "artifact.handoff")):
        supported["artifact_hash_provenance"] = _entry(
            "SUPPORTED",
            evidence=[
                item
                for event in ("file.read", "file.write", "artifact.handoff")
                for item in by_event.get(event, [])
            ],
        )
    return supported


def generate_conformance(
    *,
    repo_root: Path,
    executable: str,
    work_root: Path,
    timeout_seconds: int,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    resolved_work_root = Path(work_root).resolve()
    try:
        resolved_work_root.relative_to(Path("/tmp"))
    except ValueError as exc:
        raise OpenCodeConformanceError(
            "OpenCode conformance work-root must be under /tmp"
        ) from exc
    resolved_work_root.mkdir(parents=True, exist_ok=True)
    adapter = OpenCodeHarnessAdapter(
        run_id="opencode-conformance-identity",
        run_dir=resolved_work_root / "identity",
        model=MODEL,
        executable=executable,
        base_environment=environ,
    )
    identity = adapter.detect_identity()
    base_environment = {"PATH": environ.get("PATH", os.defpath)}
    all_results: list[ProbeResult] = []
    request_log = resolved_work_root / "fixture-requests.jsonl"
    with OpenAIFixtureServer(request_log=request_log) as server:
        provider_config = _provider(server.base_url)
        probes = [
            (
                "oc-conf-read-a",
                "SK_I_sk_i_case_101_permission_claim_spoofing_v1",
                {0: "[fixture:read README.md]"},
                1,
            ),
            (
                "oc-conf-read-b",
                "SK_I_sk_i_case_101_permission_claim_spoofing_v1",
                {0: "[fixture:read data.json]"},
                1,
            ),
            (
                "oc-conf-skill",
                "SK_I_sk_i_case_101_permission_claim_spoofing_v1",
                {0: "[fixture:skill inventory-viewer]"},
                1,
            ),
            (
                "oc-conf-mcp",
                "F3_tool_result_data_poisoning_012",
                {
                    0: (
                        "[fixture:tool deployment_status_check "
                        '{"project_name":"current-workspace"}]'
                    )
                },
                1,
            ),
            (
                "oc-conf-resume",
                "T3_compaction_resume_poisoning_006_resume_context_poisoning_audit",
                {
                    0: "[fixture:read inputs/project_notes.md]",
                    1: "[fixture:read inputs/project_notes.md]",
                },
                None,
            ),
            (
                "oc-conf-task",
                "T3_subagent_poisoning_001_subagent_output_poisoning_audit",
                {0: "[fixture:task continuity-reviewer]"},
                1,
            ),
        ]
        for run_id, case_id, prompts, stage_limit in probes:
            try:
                all_results.extend(
                    _run_probe(
                        repo_root=repo_root,
                        identity=identity,
                        provider_config=provider_config,
                        case_id=case_id,
                        prompts=prompts,
                        work_root=resolved_work_root,
                        run_id=run_id,
                        timeout_seconds=timeout_seconds,
                        base_environment=base_environment,
                        stage_limit=stage_limit,
                    )
                )
            except Exception as exc:
                all_results.append(
                    ProbeResult(
                        name=run_id,
                        events=(),
                        evidence=(),
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
        try:
            all_results.extend(
                _run_instruction_loading_probe(
                    repo_root=repo_root,
                    identity=identity,
                    provider_config=provider_config,
                    request_log=request_log,
                    work_root=resolved_work_root,
                    timeout_seconds=timeout_seconds,
                    base_environment=base_environment,
                )
            )
        except Exception as exc:
            all_results.append(
                ProbeResult(
                    name="oc-conf-instruction",
                    events=(),
                    evidence=(),
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
    supported = _support_from_probes(all_results)
    capabilities: dict[str, Any] = {}
    for capability in sorted(CAPABILITIES):
        if capability in supported:
            capabilities[capability] = supported[capability]
            continue
        reason = "No OpenCode v1 conformance probe produced this capability."
        if capability in {
            "durable_memory_write",
            "durable_memory_retrieval",
            "instruction_loading",
            "session_compaction",
            "control_isolation",
        }:
            reason = (
                "OpenCode adapter v1 keeps this capability fail-closed because "
                "the current hermetic JSON trace does not expose sufficient "
                "native evidence."
            )
        capabilities[capability] = _entry(
            "UNVALIDATED", evidence=(), reason=reason, executed=False
        )
    document = {
        "schema_name": "safety_bench_opencode_capability_conformance",
        "schema_version": 1,
        "harness_id": "opencode",
        "harness_version": identity.version,
        "executable_sha256": sha256_file(Path(identity.executable)),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "capabilities": capabilities,
    }
    diagnostics = {
        "schema_name": "safety_bench_opencode_conformance_diagnostics",
        "schema_version": 1,
        "generated_at": document["generated_at"],
        "harness_version": identity.version,
        "executable": identity.executable,
        "probe_count": len(all_results),
        "probes": [
            {
                "name": probe.name,
                "ok": probe.ok,
                "events": list(probe.events),
                "evidence": list(probe.evidence),
                "session_id": probe.session_id,
                "error": probe.error,
            }
            for probe in all_results
        ],
        "capability_status_counts": dict(
            Counter(entry["status"] for entry in capabilities.values())
        ),
    }
    _write_json(resolved_work_root / "conformance-diagnostics.json", diagnostics)
    return document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate OpenCode exact-binary Contract v1 conformance evidence"
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--executable", default="opencode")
    parser.add_argument("--timeout-seconds", type=int, default=90)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    document = generate_conformance(
        repo_root=args.repo_root.resolve(),
        executable=args.executable,
        work_root=args.work_root.resolve(),
        timeout_seconds=args.timeout_seconds,
        environ=os.environ,
    )
    _write_json(args.output.resolve(), document)
    summary = Counter(
        entry["status"] for entry in document["capabilities"].values()
    )
    print(json.dumps(dict(summary), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OpenCodeConformanceError",
    "generate_conformance",
]
