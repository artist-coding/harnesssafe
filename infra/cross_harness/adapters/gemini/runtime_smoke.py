"""Credential-free deterministic runtime smoke for the Gemini adapter path."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from .adapter import GeminiHarnessAdapter, GeminiPreflightError
from .launcher import build_gemini_launch_spec
from .materializer import load_materialization_manifest, sha256_file
from .trace import normalize_gemini_trace
from ...bindings.gemini import load_gemini_smoke_bindings


SMOKE_CASE_ID = (
    "F1_memory_evolution_001_customerservice_01_"
    "refund_case_overgeneralization_round1"
)


class GeminiRuntimeSmokeError(RuntimeError):
    """The deterministic local adapter smoke failed closed."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _fixture_paths(root: Path) -> tuple[Path, Path]:
    fixture_root = root / "tests/cross_harness/gemini/fixtures"
    return (
        fixture_root / "gemini_cli_fixture.py",
        fixture_root / "gemini_fixture_0_0_0_capability_conformance.json",
    )


def _canonical_case_dir(root: Path, case_id: str) -> Path:
    inventory = json.loads(
        (root / "docs/codex_conformance_smoke_v1.json").read_text(encoding="utf-8")
    )
    matches = [item for item in inventory["cases"] if item["case_id"] == case_id]
    if len(matches) != 1:
        raise GeminiRuntimeSmokeError("runtime smoke case is not uniquely frozen")
    return (root / matches[0]["case_dir"]).resolve()


def run_runtime_smoke(
    result_root: Path,
    *,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    root = (repo_root or _repo_root()).resolve()
    result_root = Path(result_root).resolve()
    if result_root.exists() and any(result_root.iterdir()):
        raise GeminiRuntimeSmokeError("runtime smoke result root must be empty")
    result_root.mkdir(parents=True, exist_ok=True)
    executable, conformance = _fixture_paths(root)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise GeminiRuntimeSmokeError("deterministic Gemini fixture is not executable")
    evidence = json.loads(conformance.read_text(encoding="utf-8"))
    executable_sha256 = sha256_file(executable)
    if evidence.get("executable_sha256") != executable_sha256:
        raise GeminiRuntimeSmokeError("fixture capability evidence binary hash drifted")

    bindings = load_gemini_smoke_bindings(repo_root=root)
    binding = bindings[SMOKE_CASE_ID]
    case_dir = _canonical_case_dir(root, SMOKE_CASE_ID)
    canonical_before = hashlib.sha256((case_dir / "case_meta.json").read_bytes()).hexdigest()
    run_dir = result_root / "run"
    adapter = GeminiHarnessAdapter(
        run_id="gemini-local-fixture-smoke",
        run_dir=run_dir,
        executable=str(executable),
        conformance_evidence_path=conformance,
        model="deterministic-local-fixture",
        base_environment={
            "PATH": os.environ.get("PATH", os.defpath),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            # Non-secret sentinels prove that credential-shaped parent keys are stripped.
            "GEMINI_API_KEY": "fixture-must-not-propagate",
            "GOOGLE_APPLICATION_CREDENTIALS": "fixture-must-not-propagate",
        },
    )
    materialized = adapter.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=run_dir,
    )
    manifest = load_materialization_manifest(materialized)
    stage = manifest["stages"][0]
    prompt = Path(stage["prompt_path"]).read_text(encoding="utf-8")
    identity = adapter.detect_identity()
    probe = adapter.probe_capabilities(binding["required_capabilities"])
    if probe.status != "SUPPORTED":
        raise GeminiRuntimeSmokeError(
            f"deterministic fixture capabilities did not validate: {probe.status}"
        )
    binding_gate_blocked = False
    try:
        adapter.build_launch_spec(
            materialized=materialized,
            prompt=prompt,
            timeout_seconds=20,
        )
    except GeminiPreflightError:
        binding_gate_blocked = True
    if not binding_gate_blocked:
        raise GeminiRuntimeSmokeError("unvalidated formal binding gate unexpectedly opened")

    spec = build_gemini_launch_spec(
        identity=identity,
        materialized=materialized,
        manifest=manifest,
        stage_index=0,
        prompt=prompt,
        timeout_seconds=20,
        base_environment=adapter.base_environment,
        model="deterministic-local-fixture",
    )
    forbidden_keys = {
        "GEMINI_API_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "OPENAI_API_KEY",
    }
    if forbidden_keys & set(spec.env):
        raise GeminiRuntimeSmokeError("launcher propagated credential-shaped parent state")
    with spec.trace_path.open("w", encoding="utf-8") as stdout_handle:
        result = subprocess.run(
            spec.argv,
            cwd=spec.cwd,
            env=dict(spec.env),
            stdout=stdout_handle,
            stderr=subprocess.PIPE,
            text=True,
            timeout=spec.timeout_seconds,
            check=False,
        )
    if result.returncode != 0:
        raise GeminiRuntimeSmokeError(
            f"deterministic Gemini fixture exited {result.returncode}: {result.stderr}"
        )
    events = list(
        normalize_gemini_trace(
            identity=identity,
            materialized=materialized,
            manifest=manifest,
            binding_document=binding,
            raw_trace_path=spec.trace_path,
            stage_index=0,
        )
    )
    if not events or "file.read" not in {event["event_type"] for event in events}:
        raise GeminiRuntimeSmokeError("deterministic trace did not produce required Event IR")
    event_path = result_root / "event_ir.jsonl"
    event_path.write_text(
        "".join(
            json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n"
            for event in events
        ),
        encoding="utf-8",
    )
    adapter.cleanup(materialized=materialized)
    cleanup_path = run_dir / "evidence/cleanup-gemini-gemini-local-fixture-smoke.json"
    canonical_after = hashlib.sha256((case_dir / "case_meta.json").read_bytes()).hexdigest()
    if canonical_before != canonical_after:
        raise GeminiRuntimeSmokeError("canonical case hash changed during local smoke")
    hook_path = Path(stage["hook_trace_path"])
    report: dict[str, Any] = {
        "schema_name": "safety_bench_gemini_deterministic_runtime_smoke",
        "schema_version": 1,
        "harness_id": "gemini",
        "runtime_identity": "checked_in_fixture_not_real_gemini_cli",
        "fixture_version": identity.version,
        "fixture_binary_sha256": executable_sha256,
        "case_id": SMOKE_CASE_ID,
        "capability_status": probe.status,
        "formal_binding_gate": "BLOCKED_UNVALIDATED",
        "process_exit_code": result.returncode,
        "network_scope": "none",
        "external_credentials_used": False,
        "external_model_runs": 0,
        "raw_trace": {
            "stream_path": str(spec.trace_path.relative_to(result_root)),
            "stream_sha256": sha256_file(spec.trace_path),
            "hook_path": str(hook_path.relative_to(result_root)),
            "hook_sha256": sha256_file(hook_path),
        },
        "event_ir": {
            "path": str(event_path.relative_to(result_root)),
            "sha256": sha256_file(event_path),
            "event_count": len(events),
            "event_types": [event["event_type"] for event in events],
        },
        "cleanup_evidence": str(cleanup_path.relative_to(result_root)),
        "canonical_case_hash_unchanged": True,
        "execution_outcome": "NOT_RUN",
        "scoring_status": "NOT_PRODUCED",
    }
    report["report_payload_sha256"] = hashlib.sha256(
        json.dumps(
            report, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-root", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    report = run_runtime_smoke(args.result_root)
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
