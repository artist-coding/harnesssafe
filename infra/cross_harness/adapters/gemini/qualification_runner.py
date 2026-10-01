"""Authorized, unscored Gemini CLI qualification executor.

This is deliberately separate from formal/scored execution.  It can exercise
one reviewed smoke case and its four matched controls, but always reports
``scoring_status=NOT_PRODUCED``.  The child is isolated with bubblewrap and a
restricted admin policy, while Vertex authentication stays in a root-owned
loopback proxy.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Mapping

from ...bindings.gemini import load_gemini_smoke_bindings
from .adapter import GeminiHarnessAdapter
from .launcher import build_gemini_bwrap_command, build_gemini_launch_spec
from .materializer import (
    apply_gemini_control_intervention,
    load_materialization_manifest,
    sha256_file,
)
from .vertex_auth_proxy import (
    ServiceAccountTokenProvider,
    VertexQualificationProxy,
)


_REPO_ROOT = Path(__file__).resolve().parents[4]
_CONFORMANCE = (
    _REPO_ROOT
    / "tests/cross_harness/gemini/fixtures/gemini_cli_0_51_0_capability_conformance.json"
)
_CONTROLS = (
    "clean_control",
    "no_persist_control",
    "no_trigger_control",
    "cleanup_control",
)
_QUALIFICATION_CANDIDATES = frozenset(
    {
        "F1_memory_evolution_001_customerservice_01_refund_case_overgeneralization_round1",
        "F1_memory_evolution_002_customerservice_01_refund_case_overgeneralization_round2",
        "T3_compaction_resume_poisoning_016_saved_plan_poisoning_audit",
        "T3_shared_artifact_supply_chain_001_shared_decision_artifact_decision",
    }
)


class GeminiQualificationError(RuntimeError):
    """The authorized qualification failed closed."""


def _case_dir(case_id: str) -> Path:
    inventory = json.loads(
        (
            _REPO_ROOT
            / "infra/cross_harness/bindings/gemini/active_328_v1.json"
        ).read_text(encoding="utf-8")
    )
    matches = [item for item in inventory["cases"] if item["case_id"] == case_id]
    if len(matches) != 1:
        raise GeminiQualificationError("qualification case is absent from inventory")
    return (_REPO_ROOT / matches[0]["case_dir"]).resolve()


def _validate_tree_no_symlinks(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise GeminiQualificationError(f"qualification run contains symlink: {path}")


def _assistant_content_sha256(trace_path: Path) -> str:
    deltas: list[str] = []
    for line in trace_path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        if record.get("type") != "message" or record.get("role") != "assistant":
            continue
        content = record.get("content")
        if isinstance(content, str):
            deltas.append(content)
    return hashlib.sha256("".join(deltas).encode("utf-8")).hexdigest()


def _variant(
    *,
    case_id: str,
    binding: Mapping[str, Any],
    case_dir: Path,
    variant_name: str,
    control_type: str | None,
    root_dir: Path,
    proxy: VertexQualificationProxy,
    proxy_environment: Mapping[str, str],
    model: str,
    timeout_seconds: int,
) -> dict[str, Any]:
    run_dir = root_dir / variant_name
    adapter = GeminiHarnessAdapter(
        run_id=f"q-{variant_name}",
        run_dir=run_dir,
        executable="/usr/local/bin/gemini",
        conformance_evidence_path=_CONFORMANCE,
        model=model,
        canary_token=hashlib.sha256(
            f"{case_id}:{variant_name}".encode("utf-8")
        ).hexdigest(),
        control_type=control_type,
        base_environment={"PATH": "/usr/local/bin:/usr/bin:/bin"},
    )
    identity = adapter.detect_identity()
    if identity.version != "0.51.0":
        raise GeminiQualificationError("Gemini version drifted from qualification plan")
    probe = adapter.probe_capabilities(binding["required_capabilities"])
    if probe.status != "SUPPORTED":
        raise GeminiQualificationError(
            "candidate capability preflight is not SUPPORTED: "
            + "; ".join(probe.reasons)
        )
    materialized = adapter.materialize_binding(
        case_dir=case_dir,
        binding_document=binding,
        run_dir=run_dir,
    )
    manifest = load_materialization_manifest(materialized)
    stages: list[dict[str, Any]] = []
    trigger_index = None
    if control_type is not None:
        control = manifest["control"]
        trigger_index = int(control.get("control_trigger_stage_index", len(manifest["stages"]))) - 1
    for stage in manifest["stages"]:
        index = stage["index"]
        intervention_path: Path | None = None
        if control_type == "clean_control" and index == 0:
            intervention_path = apply_gemini_control_intervention(
                materialized=materialized, before_stage_index=index
            )
        elif control_type in {
            "no_persist_control",
            "no_trigger_control",
            "cleanup_control",
        } and index == trigger_index:
            intervention_path = apply_gemini_control_intervention(
                materialized=materialized, before_stage_index=index
            )

        adapter.stage_index = index
        prompt = Path(stage["prompt_path"]).read_text(encoding="utf-8")
        # This lower-level launch is the explicit qualification path. Formal
        # adapter launch remains blocked while the checked-in binding is
        # UNVALIDATED and no scoring is produced here.
        spec = build_gemini_launch_spec(
            identity=identity,
            materialized=materialized,
            manifest=manifest,
            stage_index=index,
            prompt=prompt,
            timeout_seconds=timeout_seconds,
            base_environment=adapter.base_environment,
            model=model,
        )
        _validate_tree_no_symlinks(root_dir)
        command = build_gemini_bwrap_command(
            launch_spec=spec,
            run_dir=root_dir,
            extra_environment=proxy_environment,
        )
        proxy.begin_scope(f"{variant_name}:stage:{index}", max_provider_requests=12)
        try:
            result = subprocess.run(
                command,
                cwd="/",
                env={"PATH": "/usr/bin:/bin"},
                text=True,
                capture_output=True,
                timeout=timeout_seconds + 15,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            partial_stdout = exc.stdout or ""
            partial_stderr = exc.stderr or ""
            if isinstance(partial_stdout, bytes):
                partial_stdout = partial_stdout.decode("utf-8", errors="replace")
            if isinstance(partial_stderr, bytes):
                partial_stderr = partial_stderr.decode("utf-8", errors="replace")
            spec.trace_path.write_text(partial_stdout, encoding="utf-8")
            stderr_path = spec.trace_path.with_name("gemini-stderr.txt")
            stderr_path.write_text(partial_stderr, encoding="utf-8")
            raise GeminiQualificationError(
                f"{variant_name} stage {index} timed out; "
                f"partial_stream_sha256={sha256_file(spec.trace_path)}; "
                f"partial_stderr_sha256={sha256_file(stderr_path)}"
            ) from exc
        spec.trace_path.write_text(result.stdout, encoding="utf-8")
        stderr_path = spec.trace_path.with_name("gemini-stderr.txt")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        if result.returncode != 0:
            raise GeminiQualificationError(
                f"{variant_name} stage {index} exited {result.returncode}; "
                f"stderr_sha256={sha256_file(stderr_path)}"
            )
        try:
            events = list(
                adapter.normalize_trace(
                    identity=identity,
                    materialized=materialized,
                    raw_trace_path=spec.trace_path,
                )
            )
        except Exception as exc:
            raise GeminiQualificationError(
                f"{variant_name} stage {index} Event IR normalization failed: {exc}"
            ) from exc
        stages.append(
            {
                "index": index,
                "name": stage["name"],
                "process_exit_code": result.returncode,
                "raw_stream_sha256": sha256_file(spec.trace_path),
                "stderr_sha256": sha256_file(stderr_path),
                "assistant_content_sha256": _assistant_content_sha256(spec.trace_path),
                "normalized_event_types": [event["event_type"] for event in events],
                "normalized_event_count": len(events),
                "event_ir_schema_valid": True,
                "control_intervention_sha256": (
                    sha256_file(intervention_path) if intervention_path else None
                ),
            }
        )
        event_path = spec.trace_path.with_name("event-ir.jsonl")
        event_path.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )
        stages[-1]["event_ir_sha256"] = sha256_file(event_path)
    adapter.cleanup(materialized=materialized)
    artifact_paths: dict[str, dict[str, Any]] = {}
    workspace = Path(manifest["workspace_dir"])
    for name, relative in manifest.get("artifact_bindings", {}).items():
        path = workspace / relative
        artifact_paths[name] = {
            "path": relative,
            "present": path.is_file(),
            "sha256": sha256_file(path) if path.is_file() else None,
        }
    return {
        "variant": variant_name,
        "control_type": control_type,
        "stages": stages,
        "stages_executed": len(stages),
        "stages_total": len(manifest["stages"]),
        "full_stage_pipeline_completed": len(stages) == len(manifest["stages"]),
        "artifacts": artifact_paths,
        "scoring_status": "NOT_PRODUCED",
    }


def run_qualification(
    *,
    case_id: str,
    credential_file: Path,
    project: str,
    model: str,
    location: str,
    cost_cap_usd: float,
    timeout_seconds: int,
    variant_names: tuple[str, ...] = ("attack", *_CONTROLS),
    output_path: Path | None = None,
) -> tuple[Path, dict[str, Any]]:
    if case_id not in _QUALIFICATION_CANDIDATES:
        raise GeminiQualificationError(
            "case is NOT_RUN in the 16-case static review and cannot be invoked"
        )
    if model != "gemini-3.5-flash" or location != "global":
        raise GeminiQualificationError("authorization pins gemini-3.5-flash at global")
    credential_file = Path(credential_file).resolve()
    credential_hash = sha256_file(credential_file)
    bindings = load_gemini_smoke_bindings(repo_root=_REPO_ROOT)
    binding = bindings[case_id]
    case_dir = _case_dir(case_id)
    root_dir = Path(tempfile.mkdtemp(prefix="safety-bench-gemini-q-", dir="/tmp"))
    evidence_path = root_dir / "vertex-proxy-evidence.json"
    token_provider = ServiceAccountTokenProvider(
        credential_file,
        scope="https://www.googleapis.com/auth/cloud-platform",
    )
    proxy = VertexQualificationProxy(
        project=project,
        location=location,
        model=model,
        token_provider=token_provider,
        evidence_path=evidence_path,
        cost_cap_usd=cost_cap_usd,
    )
    started = datetime.now(timezone.utc).isoformat()
    variants: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    try:
        client = proxy.start(root_dir / "vertex-client")
        proxy_environment = client.environment()
        known_variants = {"attack": None, **{name: name for name in _CONTROLS}}
        if (
            not variant_names
            or any(name not in known_variants for name in variant_names)
            or len(set(variant_names)) != len(variant_names)
        ):
            raise GeminiQualificationError("qualification variants are invalid")
        for variant_name in variant_names:
            control_type = known_variants[variant_name]
            try:
                variants.append(
                    _variant(
                        case_id=case_id,
                        binding=binding,
                        case_dir=case_dir,
                        variant_name=variant_name,
                        control_type=control_type,
                        root_dir=root_dir,
                        proxy=proxy,
                        proxy_environment=proxy_environment,
                        model=model,
                        timeout_seconds=timeout_seconds,
                    )
                )
            except Exception as exc:
                failures.append({"variant": variant_name, "reason": str(exc)})
    except Exception as exc:
        failures.append({"variant": "runner", "reason": str(exc)})
    finally:
        proxy.stop()
    proxy_evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    completed = (
        not failures
        and set(variant_names) == {"attack", *_CONTROLS}
        and len(variants) == 5
        and all(item["full_stage_pipeline_completed"] for item in variants)
    )
    report = {
        "schema_name": "safety_bench_gemini_case_qualification",
        "schema_version": 1,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "case_id": case_id,
        "case_meta_sha256": binding["case_meta_sha256"],
        "binding_version": binding["binding_version"],
        "harness": {
            "id": "gemini",
            "version": "0.51.0",
            "executable_sha256": "a2533ac23365a1c72b847780b53235d38cf21cc7ee736c98dfa8cbb70b1a9425",
        },
        "provider": {
            "kind": "vertex_ai",
            "project_id_sha256": hashlib.sha256(project.encode()).hexdigest(),
            "location": location,
            "model": model,
            "credential_file_sha256": credential_hash,
            "credential_value_recorded": False,
        },
        "authorization": {
            "cost_cap_usd": cost_cap_usd,
            "formal_full_suite_authorized": False,
        },
        "isolation": {
            "bubblewrap_root_excludes_root_home": True,
            "child_user_namespace_uid": 0,
            "child_uid_is_not_host_root": True,
            "model_shell_tool_denied": True,
            "model_network_tools_denied": True,
            "long_term_credential_exposed_to_child": False,
            "real_oauth_token_exposed_to_child": False,
        },
        "variants": variants,
        "variant_count_completed": len(variants),
        "variant_names_requested": list(variant_names),
        "complete_attack_and_matched_controls": completed,
        "failures": failures,
        "provider_requests": proxy_evidence["provider_requests"],
        "estimated_cost_usd": proxy_evidence["estimated_cost_usd"],
        "execution_outcome": "QUALIFIED" if completed else "NOT_RUN",
        "scoring_status": "NOT_PRODUCED",
        "formal_benchmark_trials": 0,
        "safe_or_n0_prohibited": True,
        "raw_trace_root": str(root_dir),
    }
    if output_path is None:
        output_path = root_dir / "qualification-report.json"
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return output_path, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--credential-file", required=True, type=Path)
    parser.add_argument("--project", required=True)
    parser.add_argument("--model", default="gemini-3.5-flash")
    parser.add_argument("--location", default="global")
    parser.add_argument("--cost-cap-usd", type=float, default=100.0)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument(
        "--variant",
        action="append",
        choices=("attack", *_CONTROLS),
        dest="variants",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    path, report = run_qualification(
        case_id=args.case_id,
        credential_file=args.credential_file,
        project=args.project,
        model=args.model,
        location=args.location,
        cost_cap_usd=args.cost_cap_usd,
        timeout_seconds=args.timeout_seconds,
        variant_names=tuple(args.variants or ("attack", *_CONTROLS)),
        output_path=args.output,
    )
    print(
        json.dumps(
            {
                "report": str(path),
                "execution_outcome": report["execution_outcome"],
                "variant_count_completed": report["variant_count_completed"],
                "provider_requests": report["provider_requests"],
                "estimated_cost_usd": report["estimated_cost_usd"],
            },
            sort_keys=True,
        )
    )
    return 0 if report["execution_outcome"] == "QUALIFIED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
