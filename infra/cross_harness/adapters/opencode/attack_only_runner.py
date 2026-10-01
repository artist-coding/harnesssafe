"""Resumable OpenCode Contract v1 smoke attack-only runner.

The runner never scores a case.  ``ATTACK_COMPLETED`` means only that every
declared attack stage exited successfully and its raw evidence normalized.
Expected Event IR types describe observable attack paths; their absence is a
model outcome for the scoring layer, not an execution failure.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Mapping, Sequence

from ...adapter import HarnessIdentity
from ...bindings.opencode import load_opencode_smoke_bindings
from .adapter import (
    OpenCodeExecutableNotFound,
    OpenCodeHarnessAdapter,
    OpenCodeProbeError,
)
from .capabilities import aggregate_required_capabilities, capability_matrix
from .launcher import build_opencode_bwrap_command
from .materializer import (
    binding_document_sha256,
    load_materialization_manifest,
    sha256_file,
    translate_runtime_project_instruction,
)
from .provider import (
    OpenCodeProviderProfile,
    load_provider_profile,
    preflight_provider,
)
from .qualification import (
    OpenCodeQualificationError,
    case_qualification_status,
    load_case_qualification,
)


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_INVENTORY = REPO_ROOT / "docs/codex_conformance_smoke_v1.json"
DEFAULT_WORK_ROOT = Path("/tmp/safety-bench-opencode-smoke-v1")
PROTOCOL_SCHEMA_VERSION = 1


class OpenCodeAttackOnlyError(RuntimeError):
    """The attack-only protocol or execution invariant failed."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenCodeAttackOnlyError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise OpenCodeAttackOnlyError(f"expected JSON object: {path}")
    return value


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


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _safe_case_dir_name(index: int, case_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", case_id)[:96].strip("._-")
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:12]
    return f"{index:03d}-{slug}-{digest}"


def _case_run_id(index: int, case_id: str) -> str:
    digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:16]
    return f"oc16-{index:03d}-{digest}"


def _detect_identity(
    *,
    executable: str,
    work_root: Path,
    profile: OpenCodeProviderProfile | None,
    conformance_path: Path | None,
    environ: Mapping[str, str],
) -> tuple[HarnessIdentity | None, OpenCodeHarnessAdapter]:
    model = profile.model if profile is not None else "unconfigured/unconfigured"
    adapter = OpenCodeHarnessAdapter(
        run_id="opencode-smoke-preflight",
        run_dir=work_root / "preflight",
        model=model,
        executable=executable,
        conformance_evidence_path=conformance_path,
        provider_config=profile.provider_config() if profile is not None else {},
        credential_environment_names=(
            (profile.credential_env,) if profile is not None else ()
        ),
        base_environment=environ,
    )
    try:
        return adapter.detect_identity(), adapter
    except (OpenCodeExecutableNotFound, OpenCodeProbeError):
        return None, adapter


def attack_only_protocol(
    *,
    identity: HarnessIdentity | None,
    profile: OpenCodeProviderProfile | None,
    inventory_path: Path = DEFAULT_INVENTORY,
    conformance_path: Path | None = None,
    qualification_path: Path | None = None,
) -> dict[str, Any]:
    inventory = _read_json(inventory_path)
    protocol = {
        "schema_name": "safety_bench_opencode_attack_only_protocol",
        "schema_version": PROTOCOL_SCHEMA_VERSION,
        "harness_id": "opencode",
        "harness_version": identity.version if identity is not None else None,
        "executable_sha256": (
            identity.feature_flags.get("binary_sha256")
            if identity is not None
            else None
        ),
        "provider_profile": profile.profile_id if profile is not None else None,
        "model": profile.model if profile is not None else None,
        "case_scope": "contract_v1_smoke_16",
        "case_count": 16,
        "trial_policy": {
            "attack_trials_per_case": 1,
            "controls_required": False,
            "matched_controls_generated": False,
        },
        "completion_gate": {
            "ATTACK_COMPLETED": (
                "all attack stages exit 0 and the union of stage Event IR "
                "contains every binding-declared expected event type"
            ),
            "NOT_RUN": (
                "binding, capability, executable, provider, or credential "
                "preflight did not pass"
            ),
            "FAILED": (
                "a ready case was invoked but materialization, launch, process, "
                "or trace validation failed"
            ),
        },
        "scoring": {
            "status_during_execution": "NOT_PRODUCED",
            "only_attack_completed_enters_shared_analyzer": True,
            "failed_or_not_run_never_maps_to_SAFE_or_N0": True,
        },
        "inventory_path": str(Path(inventory_path).resolve()),
        "inventory_sha256": sha256_file(Path(inventory_path)),
        "inventory_id": inventory["inventory_id"],
        "conformance_path": (
            str(Path(conformance_path).resolve())
            if conformance_path is not None
            else None
        ),
        "conformance_sha256": (
            sha256_file(Path(conformance_path))
            if conformance_path is not None and Path(conformance_path).is_file()
            else None
        ),
        "qualification_path": (
            str(Path(qualification_path).resolve())
            if qualification_path is not None
            else None
        ),
        "qualification_sha256": (
            sha256_file(Path(qualification_path))
            if qualification_path is not None and Path(qualification_path).is_file()
            else None
        ),
    }
    protocol["protocol_sha256"] = _canonical_sha256(protocol)
    return protocol


def build_attack_readiness(
    *,
    repo_root: Path,
    executable: str,
    work_root: Path,
    profile: OpenCodeProviderProfile | None,
    profile_path: Path | None,
    conformance_path: Path | None,
    environ: Mapping[str, str],
    qualification_path: Path | None = None,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    inventory_path = root / "docs/codex_conformance_smoke_v1.json"
    inventory = _read_json(inventory_path)
    bindings = load_opencode_smoke_bindings(repo_root=root)
    identity, _ = _detect_identity(
        executable=executable,
        work_root=work_root,
        profile=profile,
        conformance_path=conformance_path,
        environ=environ,
    )
    matrix = capability_matrix(
        identity=identity,
        conformance_path=conformance_path,
    )
    if profile is None:
        provider_ready = False
        provider_evidence: tuple[str, ...] = ()
        provider_reasons = ("OpenCode provider profile is not configured",)
    else:
        provider = preflight_provider(
            profile,
            environ=environ,
            profile_path=profile_path,
        )
        provider_ready = provider.ready
        provider_evidence = provider.evidence
        provider_reasons = provider.reasons
    protocol = attack_only_protocol(
        identity=identity,
        profile=profile,
        inventory_path=inventory_path,
        conformance_path=conformance_path,
        qualification_path=qualification_path,
    )
    qualification: Mapping[str, Any] | None = None
    qualification_error: str | None = None
    if qualification_path is not None:
        try:
            qualification = load_case_qualification(
                qualification_path,
                harness_version=identity.version if identity is not None else None,
                executable_sha256=(
                    identity.feature_flags.get("binary_sha256")
                    if identity is not None
                    else None
                ),
                conformance_sha256=protocol["conformance_sha256"],
            )
        except OpenCodeQualificationError as exc:
            qualification_error = str(exc)

    rows: list[dict[str, Any]] = []
    for index, source in enumerate(inventory["cases"], start=1):
        case_id = source["case_id"]
        binding = bindings[case_id]
        support = binding["supported_harnesses"]["opencode"]
        native = binding["harness_native_binding"].get("opencode")
        aggregate, evidence, capability_reasons = (
            aggregate_required_capabilities(
                binding["required_capabilities"], matrix
            )
        )
        blocking: list[str] = []
        qualification_ready = False
        qualification_evidence: list[str] = []
        qualification_reasons: list[str] = []
        if isinstance(native, Mapping):
            qualification_ready, qualification_evidence, qualification_reasons = (
                case_qualification_status(
                    qualification=qualification,
                    case_id=case_id,
                    binding_sha256=binding_document_sha256(binding),
                    case_meta_sha256=str(source["case_meta_sha256"]),
                    expected_event_types=native["expected_event_types"],
                )
            )
        if qualification_error is not None:
            qualification_reasons = [
                f"OpenCode qualification evidence is invalid: {qualification_error}"
            ]
        if support["status"] == "unsupported":
            blocking.append(support["rationale"])
        elif support["status"] == "unvalidated" and not qualification_ready:
            blocking.append(
                "OpenCode binding status is unvalidated and no matching "
                "case qualification evidence is available"
            )
            blocking.extend(qualification_reasons)
        elif support["status"] not in {"supported", "conditional", "unvalidated"}:
            blocking.append(
                f"OpenCode binding status is {support['status']}; supported, "
                "conditional, or qualified unvalidated is required"
            )
        if not isinstance(native, Mapping):
            if support["status"] != "unsupported":
                blocking.append("OpenCode native binding is absent")
        else:
            config = native.get("config")
            if (
                not isinstance(config, Mapping)
                or config.get("disposition") != "READY"
            ) and not qualification_ready:
                blocking.append("OpenCode binding disposition is not READY")
        if aggregate != "SUPPORTED":
            blocking.extend(capability_reasons)
        if identity is None:
            blocking.append("OpenCode executable identity could not be verified")
        if not provider_ready:
            blocking.extend(provider_reasons)
        attack_status = "ATTACK_READY" if not blocking else "NOT_RUN"
        rows.append(
            {
                "manifest_index": index,
                "case_id": case_id,
                "case_dir": source["case_dir"],
                "case_meta_sha256": source["case_meta_sha256"],
                "binding_version": binding["binding_version"],
                "binding_status": support["status"],
                "required_capabilities": binding["required_capabilities"],
                "required_capability_status": {
                    capability: matrix[capability].status
                    for capability in binding["required_capabilities"]
                },
                "capability_aggregate_status": aggregate,
                "capability_evidence": list(evidence),
                "provider_evidence": list(provider_evidence),
                "qualification_status": (
                    "QUALIFIED" if qualification_ready else "NOT_QUALIFIED"
                ),
                "qualification_evidence": qualification_evidence,
                "stage_count": (
                    len(native["config"]["stages"])
                    if isinstance(native, Mapping)
                    else 0
                ),
                "attack_status": attack_status,
                "blocking_reasons": list(dict.fromkeys(blocking)),
                "execution_outcome": "NOT_RUN",
                "scoring_status": "NOT_PRODUCED",
            }
        )
    summary = {
        "case_count": len(rows),
        "attack_status_counts": dict(
            Counter(row["attack_status"] for row in rows)
        ),
        "binding_status_counts": dict(
            Counter(row["binding_status"] for row in rows)
        ),
        "capability_status_counts": dict(
            Counter(row["capability_aggregate_status"] for row in rows)
        ),
        "provider_ready": provider_ready,
        "qualification_status_counts": dict(
            Counter(row["qualification_status"] for row in rows)
        ),
        "scoring_status": "NOT_PRODUCED",
    }
    readiness = {
        "schema_name": "safety_bench_opencode_attack_only_readiness",
        "schema_version": 1,
        "generated_at": _now(),
        "protocol": protocol,
        "summary": summary,
        "cases": rows,
    }
    readiness["readiness_sha256"] = _canonical_sha256(readiness)
    return readiness


def _session_id_from_trace(path: Path) -> str:
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OpenCodeAttackOnlyError(
                f"{path}:{line_number} is not valid JSON: {exc}"
            ) from exc
        if isinstance(row, Mapping):
            value = row.get("sessionID")
            if isinstance(value, str) and value:
                return value
            part = row.get("part")
            if isinstance(part, Mapping):
                value = part.get("sessionID")
                if isinstance(value, str) and value:
                    return value
    raise OpenCodeAttackOnlyError(f"OpenCode trace has no sessionID: {path}")


def _artifact_status(manifest: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    workspace = Path(str(manifest["workspace_dir"]))
    result: dict[str, dict[str, Any]] = {}
    for name, relative in dict(manifest.get("artifact_bindings", {})).items():
        path = workspace / str(relative)
        result[str(name)] = {
            "path": str(relative),
            "present": path.is_file(),
            "sha256": sha256_file(path) if path.is_file() else None,
        }
    return result


def _handoff_artifact_snapshot(
    manifest: Mapping[str, Any],
) -> dict[str, str | None]:
    workspace = Path(str(manifest["workspace_dir"]))
    result: dict[str, str | None] = {}
    for relative in manifest.get("handoff_paths", []):
        if not isinstance(relative, str):
            continue
        path = workspace / relative
        result[relative] = sha256_file(path) if path.is_file() else None
    return result


def _tool_error_diagnostics(path: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not isinstance(row, Mapping) or row.get("type") != "tool_use":
            continue
        part = row.get("part")
        if not isinstance(part, Mapping):
            continue
        state = part.get("state")
        if not isinstance(state, Mapping) or state.get("status") != "error":
            continue
        error = str(state.get("error", ""))
        category = (
            "permission_denied"
            if "prevents you from using this specific tool call" in error
            else "tool_runtime_error"
        )
        result.append(
            {
                "line": line_number,
                "tool": str(part.get("tool", "unknown")),
                "category": category,
                "error_sha256": hashlib.sha256(
                    error.encode("utf-8")
                ).hexdigest(),
            }
        )
    return result


def _instruction_snapshot(
    manifest: Mapping[str, Any],
) -> dict[str, str] | None:
    workspace = Path(str(manifest["workspace_dir"]))
    path = workspace / "AGENTS.md"
    if not path.is_file():
        return None
    return {
        "path": "AGENTS.md",
        "sha256": sha256_file(path),
    }


def _record_instruction_attestation(
    *,
    manifest: Mapping[str, Any],
    session_id: str,
    stage_index: int,
    snapshot: Mapping[str, str] | None,
) -> None:
    if snapshot is None:
        return
    hook_path = Path(str(manifest["hook_log_path"]))
    hook_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "kind": "instruction.loaded",
        "sessionID": session_id,
        "stageIndex": stage_index,
        "timestamp": _now(),
        "path": snapshot["path"],
        "sha256": snapshot["sha256"],
        "evidence": "version_pinned_launch_attestation",
    }
    with hook_path.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
        )


def _case_outcome_path(
    work_root: Path, case_row: Mapping[str, Any]
) -> Path:
    return (
        work_root
        / "cases"
        / _safe_case_dir_name(
            int(case_row["manifest_index"]), str(case_row["case_id"])
        )
        / "attack-outcome.json"
    )


def _existing_completed(
    path: Path, *, protocol_sha256: str, case_meta_sha256: str
) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        document = _read_json(path)
    except OpenCodeAttackOnlyError:
        return None
    if (
        document.get("attack_status") == "ATTACK_COMPLETED"
        and document.get("protocol_sha256") == protocol_sha256
        and document.get("case_meta_sha256") == case_meta_sha256
    ):
        result = dict(document)
        result["idempotent_reuse"] = True
        return result
    return None


def execute_attack_case(
    *,
    case_row: Mapping[str, Any],
    binding: Mapping[str, Any],
    case_dir: Path,
    work_root: Path,
    protocol: Mapping[str, Any],
    profile: OpenCodeProviderProfile,
    executable: str,
    conformance_path: Path,
    environ: Mapping[str, str],
    timeout_seconds: int,
    skip_completed: bool = True,
) -> dict[str, Any]:
    case_run_dir = _case_outcome_path(work_root, case_row).parent
    outcome_path = case_run_dir / "attack-outcome.json"
    if skip_completed:
        existing = _existing_completed(
            outcome_path,
            protocol_sha256=str(protocol["protocol_sha256"]),
            case_meta_sha256=str(case_row["case_meta_sha256"]),
        )
        if existing is not None:
            return existing
    if case_row["attack_status"] != "ATTACK_READY":
        outcome = {
            "schema_name": "safety_bench_opencode_attack_only_case_outcome",
            "schema_version": 1,
            "case_id": case_row["case_id"],
            "case_meta_sha256": case_row["case_meta_sha256"],
            "attack_status": "NOT_RUN",
            "execution_outcome": "NOT_RUN",
            "failure_type": "pre_execution_gate",
            "blocking_reasons": list(case_row.get("blocking_reasons", [])),
            "stage_count_completed": 0,
            "stage_count_total": case_row["stage_count"],
            "stages": [],
            "controls_run": 0,
            "scoring_status": "NOT_PRODUCED",
            "safe_or_n0_prohibited": True,
            "protocol_sha256": protocol["protocol_sha256"],
            "started_at": None,
            "finished_at": _now(),
        }
        _write_json(outcome_path, outcome)
        return outcome
    if case_run_dir.exists():
        expected_parent = (work_root / "cases").resolve()
        if case_run_dir.parent.resolve() != expected_parent:
            raise OpenCodeAttackOnlyError(
                f"refusing to clean unexpected case directory: {case_run_dir}"
            )
        shutil.rmtree(case_run_dir)

    started_at = _now()
    stages: list[dict[str, Any]] = []
    adapter = OpenCodeHarnessAdapter(
        run_id=_case_run_id(
            int(case_row["manifest_index"]), str(case_row["case_id"])
        ),
        run_dir=case_run_dir,
        model=profile.model,
        executable=executable,
        conformance_evidence_path=conformance_path,
        provider_config=profile.provider_config(),
        credential_environment_names=(profile.credential_env,),
        base_environment=environ,
    )
    try:
        identity = adapter.detect_identity()
        probe = adapter.probe_capabilities(case_row["required_capabilities"])
        if probe.status != "SUPPORTED":
            raise OpenCodeAttackOnlyError(
                "case capability preflight changed after readiness generation"
            )
        materialized = adapter.materialize_binding(
            case_dir=case_dir,
            binding_document=binding,
            run_dir=case_run_dir,
        )
        manifest = load_materialization_manifest(materialized)
        session_id: str | None = None
        observed_event_types: set[str] = set()
        for stage in manifest["stages"]:
            index = int(stage["index"])
            adapter.stage_index = index
            adapter.session_id = session_id
            if index > 0:
                translation = translate_runtime_project_instruction(
                    Path(str(manifest["workspace_dir"]))
                )
                if translation is not None:
                    _write_json(
                        case_run_dir
                        / "raw"
                        / f"stage-{index:02d}-instruction-translation.json",
                        translation,
                    )
            instruction_snapshot = _instruction_snapshot(manifest)
            artifact_snapshot_before = _handoff_artifact_snapshot(manifest)
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
            stage_started = _now()
            try:
                result = subprocess.run(
                    command,
                    cwd="/",
                    env={"PATH": "/usr/bin:/bin"},
                    text=True,
                    capture_output=True,
                    timeout=timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout or ""
                stderr = exc.stderr or ""
                if isinstance(stdout, bytes):
                    stdout = stdout.decode("utf-8", errors="replace")
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", errors="replace")
                spec.trace_path.parent.mkdir(parents=True, exist_ok=True)
                spec.trace_path.write_text(stdout, encoding="utf-8")
                (case_run_dir / "raw" / f"stage-{index:02d}-stderr.txt").write_text(
                    stderr, encoding="utf-8"
                )
                raise OpenCodeAttackOnlyError(
                    f"stage {index} timed out after {timeout_seconds}s"
                ) from exc
            spec.trace_path.parent.mkdir(parents=True, exist_ok=True)
            spec.trace_path.write_text(result.stdout, encoding="utf-8")
            stderr_path = case_run_dir / "raw" / f"stage-{index:02d}-stderr.txt"
            stderr_path.write_text(result.stderr, encoding="utf-8")
            if result.returncode != 0:
                raise OpenCodeAttackOnlyError(
                    f"stage {index} exited {result.returncode}"
                )
            observed_session = _session_id_from_trace(spec.trace_path)
            if stage.get("session_action") in {"resume", "continue"}:
                if session_id is None or observed_session != session_id:
                    raise OpenCodeAttackOnlyError(
                        f"stage {index} did not resume the exact session"
                    )
            else:
                session_id = observed_session
            _record_instruction_attestation(
                manifest=manifest,
                session_id=observed_session,
                stage_index=index,
                snapshot=instruction_snapshot,
            )
            events = list(
                adapter.normalize_trace(
                    identity=identity,
                    materialized=materialized,
                    raw_trace_path=spec.trace_path,
                    artifact_snapshot_before=artifact_snapshot_before,
                )
            )
            tool_errors = _tool_error_diagnostics(spec.trace_path)
            permission_errors = [
                error
                for error in tool_errors
                if error["category"] == "permission_denied"
            ]
            if permission_errors:
                raise OpenCodeAttackOnlyError(
                    "OpenCode permission policy blocked "
                    f"{len(permission_errors)} run-local tool call(s) "
                    f"during stage {index}"
                )
            event_path = (
                case_run_dir / "normalized" / f"stage-{index:02d}-events.jsonl"
            )
            _write_jsonl(event_path, events)
            observed_event_types.update(
                str(event["event_type"]) for event in events
            )
            stages.append(
                {
                    "index": index,
                    "name": stage["name"],
                    "session_id": observed_session,
                    "exit_code": result.returncode,
                    "raw_trace_path": str(spec.trace_path),
                    "raw_trace_sha256": sha256_file(spec.trace_path),
                    "stderr_path": str(stderr_path),
                    "stderr_sha256": sha256_file(stderr_path),
                    "event_ir_path": str(event_path),
                    "event_ir_sha256": sha256_file(event_path),
                    "event_count": len(events),
                    "event_types": sorted(
                        {str(event["event_type"]) for event in events}
                    ),
                    "tool_error_count": len(tool_errors),
                    "tool_errors": tool_errors,
                    "started_at": stage_started,
                    "finished_at": _now(),
                }
            )
        expected = set(
            binding["harness_native_binding"]["opencode"][
                "expected_event_types"
            ]
        )
        missing = sorted(expected - observed_event_types)
        outcome = {
            "schema_name": "safety_bench_opencode_attack_only_case_outcome",
            "schema_version": 1,
            "case_id": case_row["case_id"],
            "case_meta_sha256": case_row["case_meta_sha256"],
            "attack_status": "ATTACK_COMPLETED",
            "execution_outcome": "ATTACK_COMPLETED",
            "failure_type": None,
            "blocking_reasons": [],
            "stage_count_completed": len(stages),
            "stage_count_total": case_row["stage_count"],
            "stages": stages,
            "observed_event_types": sorted(observed_event_types),
            "expected_event_types": sorted(expected),
            "missing_expected_event_types": missing,
            # Retained for compatibility with the initial v1 report reader.
            # These are observational expectations, not execution gates.
            "required_event_types": sorted(expected),
            "artifacts": _artifact_status(manifest),
            "controls_run": 0,
            "scoring_status": "NOT_PRODUCED",
            "safe_or_n0_prohibited": True,
            "protocol_sha256": protocol["protocol_sha256"],
            "started_at": started_at,
            "finished_at": _now(),
        }
    except Exception as exc:
        outcome = {
            "schema_name": "safety_bench_opencode_attack_only_case_outcome",
            "schema_version": 1,
            "case_id": case_row["case_id"],
            "case_meta_sha256": case_row["case_meta_sha256"],
            "attack_status": "FAILED",
            "execution_outcome": "FAILED",
            "failure_type": type(exc).__name__,
            "blocking_reasons": [str(exc)],
            "stage_count_completed": len(stages),
            "stage_count_total": case_row["stage_count"],
            "stages": stages,
            "controls_run": 0,
            "scoring_status": "NOT_PRODUCED",
            "safe_or_n0_prohibited": True,
            "protocol_sha256": protocol["protocol_sha256"],
            "started_at": started_at,
            "finished_at": _now(),
        }
    _write_json(outcome_path, outcome)
    return outcome


def _load_case_ids(path: Path) -> list[str]:
    text = Path(path).read_text(encoding="utf-8").strip()
    if not text:
        return []
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        values: Any = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    else:
        if isinstance(value, list):
            values = value
        elif isinstance(value, Mapping) and isinstance(value.get("case_ids"), list):
            values = value["case_ids"]
        else:
            raise OpenCodeAttackOnlyError(
                "case-id file must be a newline list, JSON list, or "
                "object with case_ids"
            )
    if not all(isinstance(item, str) and item.strip() for item in values):
        raise OpenCodeAttackOnlyError("case-id file contains an invalid case_id")
    return list(dict.fromkeys(item.strip() for item in values))


def run_batch(
    *,
    readiness: Mapping[str, Any],
    repo_root: Path,
    work_root: Path,
    profile: OpenCodeProviderProfile,
    executable: str,
    conformance_path: Path,
    environ: Mapping[str, str],
    timeout_seconds: int,
    case_ids: Sequence[str] = (),
    pending_only: bool = False,
) -> dict[str, Any]:
    bindings = load_opencode_smoke_bindings(repo_root=repo_root)
    known = {row["case_id"] for row in readiness["cases"]}
    unknown = sorted(set(case_ids) - known)
    if unknown:
        raise OpenCodeAttackOnlyError(f"unknown case IDs: {unknown}")
    selected = [
        row
        for row in readiness["cases"]
        if not case_ids or row["case_id"] in set(case_ids)
    ]
    if pending_only:
        selected = [
            row
            for row in selected
            if _existing_completed(
                _case_outcome_path(work_root, row),
                protocol_sha256=readiness["protocol"]["protocol_sha256"],
                case_meta_sha256=row["case_meta_sha256"],
            )
            is None
        ]
    outcomes: list[dict[str, Any]] = []
    for row in selected:
        outcomes.append(
            execute_attack_case(
                case_row=row,
                binding=bindings[row["case_id"]],
                case_dir=Path(repo_root) / row["case_dir"],
                work_root=work_root,
                protocol=readiness["protocol"],
                profile=profile,
                executable=executable,
                conformance_path=conformance_path,
                environ=environ,
                timeout_seconds=timeout_seconds,
            )
        )
    report = {
        "schema_name": "safety_bench_opencode_attack_only_batch_report",
        "schema_version": 1,
        "generated_at": _now(),
        "protocol_sha256": readiness["protocol"]["protocol_sha256"],
        "selected_case_count": len(selected),
        "outcome_counts": dict(
            Counter(outcome["attack_status"] for outcome in outcomes)
        ),
        "scoring_status": "NOT_PRODUCED",
        "outcomes": outcomes,
    }
    _write_json(work_root / "attack-only-batch-report.json", report)
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="OpenCode Contract v1 smoke attack-only runner"
    )
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT)
    parser.add_argument("--executable", default="opencode")
    parser.add_argument("--provider-profile", type=Path)
    parser.add_argument("--conformance", type=Path)
    parser.add_argument("--qualification", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=360)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--pending-only", action="store_true")
    parser.add_argument("--case-id", action="append", default=[])
    parser.add_argument("--case-id-file", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    work_root = args.work_root.resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    profile = (
        load_provider_profile(args.provider_profile)
        if args.provider_profile is not None
        else None
    )
    conformance = (
        args.conformance.resolve() if args.conformance is not None else None
    )
    qualification = (
        args.qualification.resolve() if args.qualification is not None else None
    )
    readiness = build_attack_readiness(
        repo_root=args.repo_root,
        executable=args.executable,
        work_root=work_root,
        profile=profile,
        profile_path=args.provider_profile,
        conformance_path=conformance,
        qualification_path=qualification,
        environ=os.environ,
    )
    _write_json(work_root / "attack-only-readiness.json", readiness)
    if not args.execute:
        print(json.dumps(readiness["summary"], sort_keys=True))
        return 0
    if profile is None:
        raise OpenCodeAttackOnlyError(
            "--execute requires --provider-profile"
        )
    if conformance is None or not conformance.is_file():
        raise OpenCodeAttackOnlyError(
            "--execute requires version-pinned --conformance evidence"
        )
    try:
        work_root.relative_to(Path("/tmp"))
    except ValueError as exc:
        raise OpenCodeAttackOnlyError(
            "--execute work-root must be under /tmp for bubblewrap isolation"
        ) from exc
    case_ids = list(args.case_id)
    if args.case_id_file is not None:
        case_ids.extend(_load_case_ids(args.case_id_file))
    report = run_batch(
        readiness=readiness,
        repo_root=args.repo_root.resolve(),
        work_root=work_root,
        profile=profile,
        executable=args.executable,
        conformance_path=conformance,
        environ=os.environ,
        timeout_seconds=args.timeout_seconds,
        case_ids=list(dict.fromkeys(case_ids)),
        pending_only=args.pending_only,
    )
    print(json.dumps(report["outcome_counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OpenCodeAttackOnlyError",
    "attack_only_protocol",
    "build_attack_readiness",
    "execute_attack_case",
    "run_batch",
]
