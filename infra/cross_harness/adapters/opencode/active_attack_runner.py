"""OpenCode active-328 attack-only batch launcher.

The runner consumes active readiness rows and executes only
``experiment_status=EXPERIMENT_READY`` cases by default.  It never scores cases;
``ATTACK_COMPLETED`` only means the declared attack stages ran and their raw
evidence normalized. Missing expected attack events remain observable model
outcomes for the scoring layer.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...contract import TARGET_HARNESSES
from .active_readiness import build_active_readiness
from .attack_only_runner import (
    OpenCodeAttackOnlyError,
    _load_case_ids,
    _safe_case_dir_name,
    _write_json,
    execute_attack_case,
)
from .bench_inventory import build_inventory
from .materializer import binding_document_sha256
from .provider import load_provider_profile


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_WORK_ROOT = Path("/tmp/safety-bench-opencode-active-328-attack")
DEFAULT_TIMEOUT_SECONDS = 360


class OpenCodeActiveAttackError(RuntimeError):
    """The active-328 attack runner failed a protocol invariant."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenCodeActiveAttackError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise OpenCodeActiveAttackError(f"expected JSON object: {path}")
    return value


def _clean_artifact_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.startswith("workspace/"):
        text = text.removeprefix("workspace/")
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return path.as_posix()


def _raw_meta_stages(meta: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    stages = meta.get("stages")
    if isinstance(stages, list) and stages:
        return [stage for stage in stages if isinstance(stage, Mapping)]
    return [
        {
            "name": "single_stage",
            "user_prompt": meta.get("user_prompt"),
            "mcp_configs": meta.get("mcp_configs", []),
        }
    ]


def _stage_configs(
    *, inventory_row: Mapping[str, Any], meta: Mapping[str, Any]
) -> list[dict[str, Any]]:
    raw_stages = _raw_meta_stages(meta)
    inventory_stages = inventory_row.get("stages", [])
    configured: list[dict[str, Any]] = []
    plugin_skills = [
        str(skill)
        for skill in meta.get("plugin_skills", [])
        if isinstance(skill, str) and skill.strip()
    ]
    for index, raw in enumerate(raw_stages):
        inventory_stage = (
            inventory_stages[index]
            if isinstance(inventory_stages, list)
            and index < len(inventory_stages)
            and isinstance(inventory_stages[index], Mapping)
            else {}
        )
        name = raw.get("name", inventory_stage.get("name", f"stage_{index}"))
        stage: dict[str, Any] = {"index": index, "name": str(name)}
        action = raw.get("session_action") or inventory_stage.get("session_action")
        if action in {"fresh", "resume", "continue", "new"}:
            stage["session_action"] = action
        mcp_configs = raw.get("mcp_configs")
        if isinstance(mcp_configs, list) and mcp_configs:
            first = mcp_configs[0]
            if isinstance(first, str) and first.strip():
                stage["mcp_config"] = first
        if plugin_skills:
            stage["skills"] = [f"plugin/skills/{skill}" for skill in plugin_skills]
        configured.append(stage)
    return configured


def _agent_configs(meta: Mapping[str, Any]) -> list[dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for stage in _raw_meta_stages(meta):
        agents = stage.get("claude_agents")
        if not isinstance(agents, Mapping):
            continue
        for name, raw in agents.items():
            if not isinstance(name, str) or not isinstance(raw, Mapping):
                continue
            description = raw.get("description")
            prompt = raw.get("prompt")
            if isinstance(description, str) and isinstance(prompt, str):
                result[name] = {
                    "name": name,
                    "description": description,
                    "prompt": prompt,
                }
    return list(result.values())


def _handoff_paths(meta: Mapping[str, Any]) -> list[str]:
    paths: set[str] = set()
    for key in (
        "workspace_artifact",
        "artifact_or_cache",
        "handoff_path",
        "output_path",
        "shared_artifact_path",
        "carrier_path",
    ):
        path = _clean_artifact_path(meta.get(key))
        if path:
            paths.add(path)
    lifecycle = meta.get("lifecycle")
    if isinstance(lifecycle, Mapping):
        for key in ("producer_artifact", "transduced_artifact"):
            path = _clean_artifact_path(lifecycle.get(key))
            if path:
                paths.add(path)
    for stage in _raw_meta_stages(meta):
        for key in ("required_artifacts", "consume_artifacts"):
            raw_values = stage.get(key, [])
            if not isinstance(raw_values, list):
                continue
            for raw in raw_values:
                path = (
                    _clean_artifact_path(raw.get("path"))
                    if isinstance(raw, Mapping)
                    else _clean_artifact_path(raw)
                )
                if path:
                    paths.add(path)
    return sorted(paths)


def _mcp_permission_patterns(case_dir: Path, stages: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    permissions: dict[str, str] = {}
    for stage in stages:
        config = stage.get("mcp_config")
        if not isinstance(config, str) or not config.strip():
            continue
        path = case_dir / config
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        raw_servers = value.get("mcpServers", value.get("mcp"))
        if not isinstance(raw_servers, Mapping):
            continue
        for server in raw_servers:
            if isinstance(server, str) and server.strip():
                permissions[f"{server}_*"] = "allow"
    return permissions


def _artifact_bindings(paths: Sequence[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for index, path in enumerate(paths):
        label = Path(path).name.replace(".", "_").replace("-", "_") or f"artifact_{index}"
        while label in result:
            label = f"{label}_{index}"
        result[label] = path
    return result


def active_binding_document(
    *, inventory_row: Mapping[str, Any], case_dir: Path
) -> dict[str, Any]:
    meta = _read_json(case_dir / "case_meta.json")
    stages = _stage_configs(inventory_row=inventory_row, meta=meta)
    handoff_paths = _handoff_paths(meta)
    permissions = {
        "read": "allow",
        "edit": "allow",
        "bash": "allow",
        "skill": "allow",
        "task": "allow",
        # bubblewrap already limits the process to the run-local case tree and
        # read-only runtime. OpenCode's workspace-relative policy must allow
        # case fixtures and adapter state that intentionally live beside the
        # workspace inside that isolated tree.
        "external_directory": "allow",
    }
    permissions.update(_mcp_permission_patterns(case_dir, stages))
    config: dict[str, Any] = {
        "binding_class": inventory_row["binding_class"],
        "disposition": "READY",
        "blocking_reasons": [],
        "stages": stages,
        "permissions": permissions,
    }
    agents = _agent_configs(meta)
    if agents:
        config["agents"] = agents
    if handoff_paths:
        config["handoff_paths"] = handoff_paths
    variant_kind = (
        "neutral" if inventory_row.get("binding_kind") == "neutral" else "native"
    )
    support = {
        harness: {
            "status": "unvalidated",
            "rationale": "active-328 generated OpenCode binding for attack-only execution",
        }
        for harness in sorted(TARGET_HARNESSES)
    }
    support["opencode"]["conformance_profile"] = "opencode.contract_v1"
    return {
        "schema_name": "safety_bench_cross_harness_binding",
        "schema_version": 1,
        "case_id": inventory_row["case_id"],
        "case_meta_sha256": inventory_row["case_meta_sha256"],
        "semantic_surface": inventory_row["semantic_surface"],
        "surface_class": inventory_row["surface_class"],
        "required_capabilities": inventory_row["required_capabilities"],
        "supported_harnesses": support,
        "comparison_group": inventory_row["comparison_group"],
        "binding_version": inventory_row["binding_version"],
        "harness_native_binding": {
            "opencode": {
                "adapter": "opencode.adapter_v1",
                "variant_kind": variant_kind,
                "config": config,
                "expected_event_types": inventory_row["expected_normalized_events"],
                "artifact_bindings": _artifact_bindings(handoff_paths),
            }
        },
        "notes": (
            "Generated from active-328 manifest/readiness for one attack-only "
            "OpenCode execution attempt; scoring remains outside this runner."
        ),
    }


def _case_outcome_path(work_root: Path, case_row: Mapping[str, Any]) -> Path:
    return (
        work_root
        / "cases"
        / _safe_case_dir_name(int(case_row["manifest_index"]), str(case_row["case_id"]))
        / "attack-outcome.json"
    )


def _completed(path: Path, *, protocol_sha256: str, case_meta_sha256: str) -> bool:
    if not path.is_file():
        return False
    try:
        document = _read_json(path)
    except OpenCodeActiveAttackError:
        return False
    return (
        document.get("attack_status") == "ATTACK_COMPLETED"
        and document.get("protocol_sha256") == protocol_sha256
        and document.get("case_meta_sha256") == case_meta_sha256
    )


def _select_rows(
    *,
    readiness: Mapping[str, Any],
    case_ids: Sequence[str],
    pending_only: bool,
    work_root: Path,
    offset: int,
    limit: int | None,
) -> tuple[list[Mapping[str, Any]], int]:
    rows_by_id = {row["case_id"]: row for row in readiness["cases"]}
    if case_ids:
        unknown = sorted(set(case_ids) - set(rows_by_id))
        if unknown:
            raise OpenCodeActiveAttackError(f"unknown case_id(s): {unknown}")
        selected = [rows_by_id[case_id] for case_id in case_ids]
    else:
        selected = [
            row
            for row in readiness["cases"]
            if row.get("experiment_status") == "EXPERIMENT_READY"
        ]
    selected_before_pending = len(selected)
    if pending_only:
        protocol_sha256 = str(readiness["protocol"]["protocol_sha256"])
        selected = [
            row
            for row in selected
            if not _completed(
                _case_outcome_path(work_root, row),
                protocol_sha256=protocol_sha256,
                case_meta_sha256=str(row["case_meta_sha256"]),
            )
        ]
    if offset < 0:
        raise OpenCodeActiveAttackError("offset must be non-negative")
    if offset:
        selected = selected[offset:]
    if limit is not None:
        if limit < 1:
            raise OpenCodeActiveAttackError("limit must be positive")
        selected = selected[:limit]
    return selected, selected_before_pending


def _not_invoked_outcome(
    *,
    status: str,
    case_row: Mapping[str, Any],
    protocol: Mapping[str, Any],
    reasons: Sequence[str],
) -> dict[str, Any]:
    return {
        "schema_name": "safety_bench_opencode_attack_only_case_outcome",
        "schema_version": 1,
        "case_id": case_row["case_id"],
        "case_meta_sha256": case_row["case_meta_sha256"],
        "attack_status": status,
        "execution_outcome": status,
        "failure_type": "pre_execution_gate",
        "blocking_reasons": list(reasons),
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


def _batch_report(
    *,
    started: str,
    work_root: Path,
    readiness: Mapping[str, Any],
    selected: Sequence[Mapping[str, Any]],
    outcomes: Sequence[Mapping[str, Any]],
    dry_run: bool,
    selection_metadata: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_name": "safety_bench_opencode_active_328_attack_only_batch_report",
        "schema_version": 1,
        "started_at": started,
        "finished_at": _now(),
        "dry_run": dry_run,
        "protocol": readiness["protocol"],
        "work_root": str(work_root),
        "selection": {
            "case_count": len(selected),
            "case_ids": [row["case_id"] for row in selected],
            **dict(selection_metadata),
        },
        "readiness_summary": readiness["summary"],
        "outcome_counts": dict(Counter(outcome["attack_status"] for outcome in outcomes)),
        "stage_counts": {
            "completed": sum(int(outcome.get("stage_count_completed", 0)) for outcome in outcomes),
            "planned": sum(int(outcome.get("stage_count_total", 0)) for outcome in outcomes),
        },
        "scoring_status": "NOT_PRODUCED",
        "safe_or_n0_prohibited": True,
    }


def execute_active_batch(
    *,
    repo_root: Path,
    work_root: Path,
    executable: str,
    provider_profile_path: Path,
    conformance_path: Path,
    environ: Mapping[str, str],
    case_ids: Sequence[str] = (),
    pending_only: bool = False,
    offset: int = 0,
    limit: int | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    dry_run: bool = False,
) -> tuple[Path, dict[str, Any]]:
    root = Path(repo_root).resolve()
    work = Path(work_root).resolve()
    try:
        work.relative_to(Path("/tmp"))
    except ValueError as exc:
        raise OpenCodeActiveAttackError(
            "active-328 attack execution requires work-root under /tmp"
        ) from exc
    work.mkdir(parents=True, exist_ok=True)
    profile = load_provider_profile(provider_profile_path)
    readiness = build_active_readiness(
        repo_root=root,
        executable=executable,
        work_root=work,
        profile=profile,
        profile_path=provider_profile_path,
        conformance_path=conformance_path,
        environ=environ,
    )
    selected, selected_before_pending = _select_rows(
        readiness=readiness,
        case_ids=case_ids,
        pending_only=pending_only,
        work_root=work,
        offset=offset,
        limit=limit,
    )
    _write_json(work / "active-328-attack-readiness.json", readiness)
    inventory = build_inventory(root)
    inventory_rows = {row["case_id"]: row for row in inventory["cases"]}
    started = _now()
    outcomes: list[dict[str, Any]] = []
    protocol = readiness["protocol"]
    if dry_run:
        for row in selected:
            outcomes.append(
                _not_invoked_outcome(
                    status="NOT_RUN",
                    case_row=row,
                    protocol=protocol,
                    reasons=["dry_run"],
                )
            )
    else:
        if profile.credential_env not in environ or not environ.get(profile.credential_env):
            raise OpenCodeActiveAttackError(
                f"{profile.credential_env} is required for active-328 execution"
            )
        for row in selected:
            inventory_row = inventory_rows[str(row["case_id"])]
            binding = active_binding_document(
                inventory_row=inventory_row,
                case_dir=root / str(row["case_dir"]),
            )
            outcome = execute_attack_case(
                case_row=row,
                binding=binding,
                case_dir=root / str(row["case_dir"]),
                work_root=work,
                protocol=protocol,
                profile=profile,
                executable=executable,
                conformance_path=conformance_path,
                environ=environ,
                timeout_seconds=timeout_seconds,
            )
            outcome["binding_sha256"] = binding_document_sha256(binding)
            outcomes.append(outcome)
    report = _batch_report(
        started=started,
        work_root=work,
        readiness=readiness,
        selected=selected,
        outcomes=outcomes,
        dry_run=dry_run,
        selection_metadata={
            "case_set": "experiment_ready",
            "requested_case_count": len(case_ids),
            "selected_before_pending_count": selected_before_pending,
            "pending_only": pending_only,
            "offset": offset,
            "limit": limit,
        },
    )
    path = work / (
        "active-328-attack-only-dry-run-report.json"
        if dry_run
        else "active-328-attack-only-batch-report.json"
    )
    _write_json(path, report)
    return path, report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT)
    parser.add_argument("--executable", default="opencode")
    parser.add_argument("--provider-profile", type=Path, required=True)
    parser.add_argument("--conformance", type=Path, required=True)
    parser.add_argument("--case-id", action="append", dest="case_ids", default=[])
    parser.add_argument("--case-id-file", type=Path)
    parser.add_argument("--pending-only", action="store_true")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    case_ids = list(args.case_ids)
    if args.case_id_file is not None:
        case_ids.extend(_load_case_ids(args.case_id_file))
    path, report = execute_active_batch(
        repo_root=args.repo_root,
        work_root=args.work_root,
        executable=args.executable,
        provider_profile_path=args.provider_profile,
        conformance_path=args.conformance,
        environ=os.environ,
        case_ids=list(dict.fromkeys(case_ids)),
        pending_only=args.pending_only,
        offset=args.offset,
        limit=args.limit,
        timeout_seconds=args.timeout_seconds,
        dry_run=args.dry_run,
    )
    print(
        json.dumps(
            {
                "report": str(path),
                "selection": report["selection"],
                "outcome_counts": report["outcome_counts"],
                "scoring_status": report["scoring_status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OpenCodeActiveAttackError",
    "active_binding_document",
    "execute_active_batch",
]
