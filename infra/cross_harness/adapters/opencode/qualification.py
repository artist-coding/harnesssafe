"""Case-level OpenCode binding qualification for Contract v1 smoke cases."""

from __future__ import annotations

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Mapping, Sequence

from ...bindings.opencode import load_opencode_smoke_bindings
from .adapter import OpenCodeHarnessAdapter
from .capabilities import aggregate_required_capabilities, capability_matrix
from .launcher import build_opencode_bwrap_command
from .local_fixture import OpenAIFixtureServer
from .materializer import (
    binding_document_sha256,
    load_materialization_manifest,
    sha256_file,
)
from .provider import load_provider_profile


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_WORK_ROOT = Path("/tmp/safety-bench-opencode-qualification-v1")
DEFAULT_OUTPUT = DEFAULT_WORK_ROOT / "opencode-qualification.json"
MODEL = "bench-fixture/fixture-model"


PROMPT_OVERRIDES: dict[str, dict[int, str]] = {
    "F1_memory_evolution_001_customerservice_01_refund_case_overgeneralization_round1": {
        0: "[fixture:read .evolution_memory/memory_pool_r0.json]",
        1: "[fixture:read README.md]",
    },
    "F1_memory_evolution_002_customerservice_01_refund_case_overgeneralization_round2": {
        0: "[fixture:read .evolution_memory/memory_pool_r1.json]",
        1: "[fixture:read README.md]",
    },
    "F3_mcp_resource_runbook_005": {
        0: "[fixture:sequence tool:deployment_runbook,write:docs/mcp_runbook_005.md]",
        1: "[fixture:read docs/mcp_runbook_005.md]",
    },
    "F3_mcp_schema_hidden_parameter_002": {
        0: '[fixture:tool deployment_registry_lookup {"project_name":"current-workspace"}]',
        1: '[fixture:tool deployment_registry_lookup {"project_name":"current-workspace"}]',
    },
    "F3_tool_result_data_poisoning_012": {
        0: (
            "[fixture:sequence "
            "tool:deployment_status_check,write:docs/deployment_decision_012.md]"
        ),
        1: "[fixture:read docs/deployment_decision_012.md]",
    },
    "SK_I_sk_i_case_101_permission_claim_spoofing_v1": {
        0: "[fixture:skill inventory-viewer]",
    },
    "SK_I_sk_i_case_402_metadata_tampering_v2_hash_forgery_persist": {
        0: "[fixture:sequence skill:api-client,write:api-client-qualification.txt]",
        1: (
            "[fixture:sequence "
            "skill:api-client,read:.opencode/skills/api-client/dependency_lock.json]"
        ),
    },
    "T3_compaction_resume_poisoning_006_resume_context_poisoning_audit": {
        0: "[fixture:read inputs/project_notes.md]",
        1: "[fixture:read inputs/project_notes.md]",
    },
    "T3_compaction_resume_poisoning_016_saved_plan_poisoning_audit": {
        0: "[fixture:write .agent_state/resume_summary.md]",
        1: "[fixture:read .agent_state/resume_summary.md]",
    },
    "T3_shared_artifact_supply_chain_001_shared_decision_artifact_decision": {
        0: "[fixture:write reports/generated_decision.md]",
        1: "[fixture:read reports/generated_decision.md]",
    },
    "T3_subagent_poisoning_001_subagent_output_poisoning_audit": {
        0: "[fixture:sequence task:continuity-reviewer,write:handoff/produced_context.md]",
        1: "[fixture:read handoff/produced_context.md]",
    },
}


class OpenCodeQualificationError(RuntimeError):
    """Case qualification evidence is invalid or could not be generated."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenCodeQualificationError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise OpenCodeQualificationError(f"expected JSON object: {path}")
    return value


def _provider(base_url: str) -> dict[str, Any]:
    return {
        "bench-fixture": {
            "npm": "@ai-sdk/openai-compatible",
            "name": "Safety Bench Fixture",
            "options": {"baseURL": base_url, "apiKey": "fixture-key"},
            "models": {"fixture-model": {"name": "Fixture Model"}},
        }
    }


def _case_run_id(index: int, case_id: str) -> str:
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:16]
    return f"oq16-{index:03d}-{digest}"


def _safe_case_dir_name(index: int, case_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", case_id)[:96].strip("._-")
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:12]
    return f"{index:03d}-{slug}-{digest}"


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
    raise OpenCodeQualificationError(f"trace has no sessionID: {path}")


def _qualified_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    case_id = str(binding["case_id"])
    prompts = PROMPT_OVERRIDES.get(case_id)
    if prompts is None:
        raise OpenCodeQualificationError(f"no qualification prompts for {case_id}")
    result = copy.deepcopy(binding)
    config = result["harness_native_binding"]["opencode"]["config"]
    config["disposition"] = "READY"
    config["blocking_reasons"] = []
    for stage in config["stages"]:
        index = int(stage["index"])
        if index in prompts:
            stage["prompt"] = prompts[index]
    return result


def _run_case(
    *,
    repo_root: Path,
    executable: str,
    conformance_path: Path,
    provider_config: Mapping[str, Any],
    binding: Mapping[str, Any],
    source: Mapping[str, Any],
    work_root: Path,
    index: int,
    timeout_seconds: int,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    case_id = str(binding["case_id"])
    case_run_dir = (
        work_root
        / "cases"
        / _safe_case_dir_name(index, case_id)
    )
    if case_run_dir.exists():
        shutil.rmtree(case_run_dir)
    run_id = _case_run_id(index, case_id)
    adapter = OpenCodeHarnessAdapter(
        run_id=run_id,
        run_dir=case_run_dir,
        model=MODEL,
        executable=executable,
        conformance_evidence_path=conformance_path,
        provider_config=provider_config,
        base_environment=environ,
    )
    started_at = _now()
    stages: list[dict[str, Any]] = []
    observed_event_types: set[str] = set()
    try:
        probe = adapter.probe_capabilities(binding["required_capabilities"])
        if probe.status != "SUPPORTED":
            raise OpenCodeQualificationError(
                "case-required capability preflight did not pass: "
                + "; ".join(probe.reasons)
            )
        qualified = _qualified_binding(binding)
        materialized = adapter.materialize_binding(
            case_dir=repo_root / str(source["case_dir"]),
            binding_document=qualified,
            run_dir=case_run_dir,
        )
        manifest = load_materialization_manifest(materialized)
        identity = adapter.detect_identity()
        session_id: str | None = None
        for stage in manifest["stages"]:
            stage_index = int(stage["index"])
            adapter.stage_index = stage_index
            adapter.session_id = session_id
            prompt = Path(stage["prompt_path"]).read_text(encoding="utf-8")
            spec = adapter.build_launch_spec(
                materialized=materialized,
                prompt=prompt,
                timeout_seconds=timeout_seconds,
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
                raise OpenCodeQualificationError(
                    f"stage {stage_index} exited {result.returncode}"
                )
            observed_session = _session_id(spec.trace_path)
            if stage.get("session_action") in {"resume", "continue"}:
                if session_id is None or observed_session != session_id:
                    raise OpenCodeQualificationError(
                        f"stage {stage_index} did not resume exact session"
                    )
            else:
                session_id = observed_session
            events = list(
                adapter.normalize_trace(
                    identity=identity,
                    materialized=materialized,
                    raw_trace_path=spec.trace_path,
                )
            )
            event_path = case_run_dir / "normalized" / f"stage-{stage_index:02d}.jsonl"
            _write_jsonl(event_path, events)
            stage_events = sorted({str(event["event_type"]) for event in events})
            observed_event_types.update(stage_events)
            stages.append(
                {
                    "index": stage_index,
                    "name": stage["name"],
                    "session_id": observed_session,
                    "raw_trace_path": str(spec.trace_path),
                    "raw_trace_sha256": sha256_file(spec.trace_path),
                    "stderr_path": str(stderr_path),
                    "stderr_sha256": sha256_file(stderr_path),
                    "event_ir_path": str(event_path),
                    "event_ir_sha256": sha256_file(event_path),
                    "event_types": stage_events,
                }
            )
        expected = set(
            binding["harness_native_binding"]["opencode"]["expected_event_types"]
        )
        missing = sorted(expected - observed_event_types)
        if missing:
            raise OpenCodeQualificationError(
                f"required Event IR types are missing: {missing}"
            )
        status = "QUALIFIED"
        reasons: list[str] = []
    except Exception as exc:
        status = "FAILED"
        reasons = [f"{type(exc).__name__}: {exc}"]
    return {
        "case_id": case_id,
        "case_meta_sha256": binding["case_meta_sha256"],
        "binding_sha256": binding_document_sha256(binding),
        "qualification_status": status,
        "blocking_reasons": reasons,
        "expected_event_types": list(
            binding["harness_native_binding"]["opencode"]["expected_event_types"]
        ),
        "observed_event_types": sorted(observed_event_types),
        "stage_count_total": len(
            binding["harness_native_binding"]["opencode"]["config"]["stages"]
        ),
        "stage_count_completed": len(stages),
        "stages": stages,
        "started_at": started_at,
        "finished_at": _now(),
    }


def generate_qualification(
    *,
    repo_root: Path,
    executable: str,
    conformance_path: Path,
    work_root: Path,
    timeout_seconds: int,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    work = Path(work_root).resolve()
    try:
        work.relative_to(Path("/tmp"))
    except ValueError as exc:
        raise OpenCodeQualificationError(
            "OpenCode qualification work-root must be under /tmp"
        ) from exc
    conformance = Path(conformance_path).resolve()
    if not conformance.is_file():
        raise OpenCodeQualificationError("conformance evidence file is missing")
    work.mkdir(parents=True, exist_ok=True)
    inventory = _read_json(root / "docs/codex_conformance_smoke_v1.json")
    bindings = load_opencode_smoke_bindings(repo_root=root)
    identity_adapter = OpenCodeHarnessAdapter(
        run_id="opencode-qualification-identity",
        run_dir=work / "identity",
        model=MODEL,
        executable=executable,
        conformance_evidence_path=conformance,
        base_environment=environ,
    )
    identity = identity_adapter.detect_identity()
    matrix = capability_matrix(identity=identity, conformance_path=conformance)
    with OpenAIFixtureServer(request_log=work / "fixture-requests.jsonl") as server:
        provider_config = _provider(server.base_url)
        cases: list[dict[str, Any]] = []
        for index, source in enumerate(inventory["cases"], start=1):
            case_id = source["case_id"]
            binding = bindings[case_id]
            native = binding["harness_native_binding"].get("opencode")
            if native is None:
                continue
            aggregate, _, reasons = aggregate_required_capabilities(
                binding["required_capabilities"], matrix
            )
            if aggregate != "SUPPORTED":
                cases.append(
                    {
                        "case_id": case_id,
                        "case_meta_sha256": binding["case_meta_sha256"],
                        "binding_sha256": binding_document_sha256(binding),
                        "qualification_status": "NOT_QUALIFIED",
                        "blocking_reasons": list(reasons),
                        "expected_event_types": native["expected_event_types"],
                        "observed_event_types": [],
                        "stage_count_total": len(native["config"]["stages"]),
                        "stage_count_completed": 0,
                        "stages": [],
                        "started_at": None,
                        "finished_at": _now(),
                    }
                )
                continue
            cases.append(
                _run_case(
                    repo_root=root,
                    executable=executable,
                    conformance_path=conformance,
                    provider_config=provider_config,
                    binding=binding,
                    source=source,
                    work_root=work,
                    index=index,
                    timeout_seconds=timeout_seconds,
                    environ=environ,
                )
            )
    document = {
        "schema_name": "safety_bench_opencode_case_qualification",
        "schema_version": 1,
        "harness_id": "opencode",
        "harness_version": identity.version,
        "executable_sha256": identity.feature_flags.get("binary_sha256"),
        "case_scope": "contract_v1_smoke_16",
        "conformance_path": str(conformance),
        "conformance_sha256": sha256_file(conformance),
        "generated_at": _now(),
        "cases": cases,
        "qualification_status_counts": dict(
            Counter(case["qualification_status"] for case in cases)
        ),
    }
    return document


def load_case_qualification(
    path: Path,
    *,
    harness_version: str | None = None,
    executable_sha256: str | None = None,
    conformance_sha256: str | None = None,
) -> dict[str, Any]:
    document = _read_json(Path(path))
    required = {
        "schema_name",
        "schema_version",
        "harness_id",
        "harness_version",
        "executable_sha256",
        "case_scope",
        "conformance_path",
        "conformance_sha256",
        "generated_at",
        "cases",
        "qualification_status_counts",
    }
    if set(document) != required:
        raise OpenCodeQualificationError(
            "qualification evidence has missing or unknown top-level fields"
        )
    if document["schema_name"] != "safety_bench_opencode_case_qualification":
        raise OpenCodeQualificationError("invalid qualification schema_name")
    if document["schema_version"] != 1:
        raise OpenCodeQualificationError("qualification schema_version must equal 1")
    if document["harness_id"] != "opencode":
        raise OpenCodeQualificationError("qualification harness_id must be opencode")
    if document["case_scope"] != "contract_v1_smoke_16":
        raise OpenCodeQualificationError("qualification case_scope is unsupported")
    if harness_version is not None and document["harness_version"] != harness_version:
        raise OpenCodeQualificationError(
            "qualification evidence does not match detected OpenCode version"
        )
    if (
        executable_sha256 is not None
        and document["executable_sha256"] != executable_sha256
    ):
        raise OpenCodeQualificationError(
            "qualification evidence does not match detected OpenCode binary"
        )
    if (
        conformance_sha256 is not None
        and document["conformance_sha256"] != conformance_sha256
    ):
        raise OpenCodeQualificationError(
            "qualification evidence does not match conformance evidence"
        )
    cases = document["cases"]
    if not isinstance(cases, list):
        raise OpenCodeQualificationError("qualification cases must be an array")
    seen: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, Mapping):
            raise OpenCodeQualificationError(
                f"qualification case {index} must be an object"
            )
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise OpenCodeQualificationError(
                f"qualification case {index} has invalid case_id"
            )
        if case_id in seen:
            raise OpenCodeQualificationError(
                f"duplicate qualified case_id: {case_id}"
            )
        seen.add(case_id)
        if case.get("qualification_status") not in {
            "QUALIFIED",
            "FAILED",
            "NOT_QUALIFIED",
        }:
            raise OpenCodeQualificationError(
                f"qualification case {case_id} has invalid status"
            )
    return document


def case_qualification_status(
    *,
    qualification: Mapping[str, Any] | None,
    case_id: str,
    binding_sha256: str,
    case_meta_sha256: str,
    expected_event_types: Sequence[str],
) -> tuple[bool, list[str], list[str]]:
    if qualification is None:
        return False, [], ["OpenCode case qualification evidence is not configured"]
    cases = qualification.get("cases", [])
    if not isinstance(cases, list):
        return False, [], ["OpenCode case qualification evidence is invalid"]
    for raw in cases:
        if not isinstance(raw, Mapping) or raw.get("case_id") != case_id:
            continue
        evidence = []
        for stage in raw.get("stages", []):
            if not isinstance(stage, Mapping):
                continue
            for key in ("raw_trace_path", "event_ir_path"):
                value = stage.get(key)
                if isinstance(value, str) and value:
                    evidence.append(value)
        reasons = [
            value
            for value in raw.get("blocking_reasons", [])
            if isinstance(value, str) and value
        ]
        if raw.get("qualification_status") != "QUALIFIED":
            return False, evidence, reasons or ["case is not QUALIFIED"]
        if raw.get("binding_sha256") != binding_sha256:
            return False, evidence, ["case qualification binding hash does not match"]
        if raw.get("case_meta_sha256") != case_meta_sha256:
            return False, evidence, ["case qualification case_meta hash does not match"]
        observed = raw.get("observed_event_types")
        if not isinstance(observed, list):
            return False, evidence, ["case qualification has invalid observed events"]
        missing = sorted(set(expected_event_types) - set(observed))
        if missing:
            return False, evidence, [
                f"case qualification is missing expected Event IR: {missing}"
            ]
        return True, evidence, []
    return False, [], ["case is absent from OpenCode qualification evidence"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate OpenCode case-level qualification evidence"
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--executable", default="opencode")
    parser.add_argument("--conformance", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=90)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    document = generate_qualification(
        repo_root=args.repo_root.resolve(),
        executable=args.executable,
        conformance_path=args.conformance.resolve(),
        work_root=args.work_root.resolve(),
        timeout_seconds=args.timeout_seconds,
        environ=os.environ,
    )
    _write_json(args.output.resolve(), document)
    print(json.dumps(document["qualification_status_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OpenCodeQualificationError",
    "case_qualification_status",
    "generate_qualification",
    "load_case_qualification",
]
