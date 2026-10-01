"""OpenCode 328-case active readiness planner.

The planner uses the canonical active manifest plus version-pinned OpenCode
capability conformance to decide which cases are ``ATTACK_READY``.  It does not
execute model calls and never emits benchmark scores.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...adapter import HarnessIdentity
from .adapter import (
    OpenCodeExecutableNotFound,
    OpenCodeHarnessAdapter,
    OpenCodeProbeError,
)
from .bench_inventory import build_inventory
from .capabilities import aggregate_required_capabilities, capability_matrix
from .materializer import canonical_sha256, sha256_file
from .provider import (
    OpenCodeProviderProfile,
    load_provider_profile,
    preflight_provider,
)


REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_WORK_ROOT = Path("/tmp/safety-bench-opencode-active-328")
SCHEMA_NAME = "safety_bench_opencode_active_328_readiness"
SCHEMA_VERSION = 1
_DURABLE_MEMORY_CAPABILITIES = frozenset(
    {"durable_memory_write", "durable_memory_retrieval"}
)
_SESSION_COMPACTION_CAPABILITIES = frozenset({"session_compaction"})


class OpenCodeActiveReadinessError(RuntimeError):
    """The active readiness planner failed a protocol invariant."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write_json(path: Path, document: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


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
        run_id="opencode-active-328-preflight",
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


def _protocol(
    *,
    identity: HarnessIdentity | None,
    profile: OpenCodeProviderProfile | None,
    inventory: Mapping[str, Any],
    conformance_path: Path | None,
) -> dict[str, Any]:
    protocol = {
        "schema_name": "safety_bench_opencode_active_328_attack_only_protocol",
        "schema_version": 1,
        "harness_id": "opencode",
        "harness_version": identity.version if identity is not None else None,
        "executable_sha256": (
            identity.feature_flags.get("binary_sha256")
            if identity is not None
            else None
        ),
        "provider_profile": profile.profile_id if profile is not None else None,
        "model": profile.model if profile is not None else None,
        "case_scope": "active_328_v1",
        "case_count": 328,
        "trial_policy": {
            "attack_trials_per_case": 1,
            "controls_required": False,
            "matched_controls_generated": False,
        },
        "completion_gate": {
            "ATTACK_READY": (
                "case-required capabilities are SUPPORTED by version-pinned "
                "OpenCode conformance, executable identity is verified, and "
                "provider credential preflight is present"
            ),
            "NOT_RUN": (
                "one or more required capabilities, executable identity, or "
                "provider preflight did not pass"
            ),
        },
        "scoring": {
            "status_during_execution": "NOT_PRODUCED",
            "only_attack_completed_enters_shared_analyzer": True,
            "failed_or_not_run_never_maps_to_SAFE_or_N0": True,
        },
        "inventory_sha256": inventory["inventory_content_sha256"],
        "manifest_sha256": inventory["source_contract"]["manifest_sha256"],
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
    }
    protocol["protocol_sha256"] = canonical_sha256(protocol)
    return protocol


def _experiment_marking(
    *,
    attack_status: str,
    missing_capabilities: Sequence[str],
    identity_ready: bool,
    provider_ready: bool,
) -> dict[str, Any]:
    if attack_status == "ATTACK_READY":
        return {
            "experiment_status": "EXPERIMENT_READY",
            "experiment_blocker_class": None,
            "experiment_blocker_capabilities": [],
        }
    missing = frozenset(missing_capabilities)
    if missing and missing <= _DURABLE_MEMORY_CAPABILITIES:
        return {
            "experiment_status": "NOT_EXPERIMENTABLE",
            "experiment_blocker_class": "opencode_missing_durable_memory_surface",
            "experiment_blocker_capabilities": sorted(missing),
        }
    if missing and missing <= _SESSION_COMPACTION_CAPABILITIES:
        return {
            "experiment_status": "NOT_EXPERIMENTABLE",
            "experiment_blocker_class": "opencode_missing_session_compaction_evidence",
            "experiment_blocker_capabilities": sorted(missing),
        }
    if missing and missing <= (
        _DURABLE_MEMORY_CAPABILITIES | _SESSION_COMPACTION_CAPABILITIES
    ):
        return {
            "experiment_status": "NOT_EXPERIMENTABLE",
            "experiment_blocker_class": (
                "opencode_missing_durable_memory_surface_and_session_compaction_evidence"
            ),
            "experiment_blocker_capabilities": sorted(missing),
        }
    if not identity_ready or not provider_ready:
        return {
            "experiment_status": "ENVIRONMENT_BLOCKED",
            "experiment_blocker_class": "preflight_not_ready",
            "experiment_blocker_capabilities": sorted(missing),
        }
    return {
        "experiment_status": "CAPABILITY_UNVALIDATED",
        "experiment_blocker_class": "opencode_capability_unvalidated",
        "experiment_blocker_capabilities": sorted(missing),
    }


def build_active_readiness(
    *,
    repo_root: Path,
    executable: str,
    work_root: Path,
    profile: OpenCodeProviderProfile | None,
    profile_path: Path | None,
    conformance_path: Path | None,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    inventory = build_inventory(root)
    identity, _ = _detect_identity(
        executable=executable,
        work_root=work_root,
        profile=profile,
        conformance_path=conformance_path,
        environ=environ,
    )
    matrix = capability_matrix(identity=identity, conformance_path=conformance_path)
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
    protocol = _protocol(
        identity=identity,
        profile=profile,
        inventory=inventory,
        conformance_path=conformance_path,
    )

    rows: list[dict[str, Any]] = []
    for row in inventory["cases"]:
        aggregate, evidence, capability_reasons = aggregate_required_capabilities(
            row["required_capabilities"], matrix
        )
        capability_status = {
            capability: matrix[capability].status
            for capability in row["required_capabilities"]
        }
        blocking: list[str] = []
        if aggregate != "SUPPORTED":
            blocking.extend(row["blocking_reasons"])
            blocking.extend(capability_reasons)
        if identity is None:
            blocking.append("OpenCode executable identity could not be verified")
        if not provider_ready:
            blocking.extend(provider_reasons)
        attack_status = "ATTACK_READY" if not blocking else "NOT_RUN"
        missing_capabilities = [
            capability
            for capability, status in capability_status.items()
            if status != "SUPPORTED"
        ]
        experiment = _experiment_marking(
            attack_status=attack_status,
            missing_capabilities=missing_capabilities,
            identity_ready=identity is not None,
            provider_ready=provider_ready,
        )
        rows.append(
            {
                "manifest_index": row["manifest_index"],
                "suite": row["suite"],
                "case_id": row["case_id"],
                "case_dir": row["case_dir"],
                "stage_count": row["stage_count"],
                "case_meta_sha256": row["case_meta_sha256"],
                "binding_version": row["binding_version"],
                "binding_class": row["binding_class"],
                "binding_kind": row["binding_kind"],
                "binding_disposition": row["disposition"],
                "comparison_group": row["comparison_group"],
                "semantic_surface": row["semantic_surface"],
                "required_capabilities": row["required_capabilities"],
                "required_capability_status": capability_status,
                "capability_aggregate_status": aggregate,
                "capability_evidence": list(evidence),
                "provider_evidence": list(provider_evidence),
                "attack_status": attack_status,
                **experiment,
                "blocking_reasons": list(dict.fromkeys(blocking)),
                "execution_outcome": "NOT_RUN",
                "scoring_status": "NOT_PRODUCED",
            }
        )

    def blocker_key(case_row: Mapping[str, Any]) -> str:
        blockers = [
            capability
            for capability, status in case_row["required_capability_status"].items()
            if status != "SUPPORTED"
        ]
        return " + ".join(blockers) if blockers else "non_capability_preflight"

    summary = {
        "case_count": len(rows),
        "stage_count": sum(row["stage_count"] for row in rows),
        "attack_status_counts": dict(Counter(row["attack_status"] for row in rows)),
        "attack_ready_stage_count": sum(
            row["stage_count"] for row in rows if row["attack_status"] == "ATTACK_READY"
        ),
        "attack_ready_by_suite": dict(
            Counter(
                row["suite"]
                for row in rows
                if row["attack_status"] == "ATTACK_READY"
            )
        ),
        "not_run_by_suite": dict(
            Counter(
                row["suite"]
                for row in rows
                if row["attack_status"] == "NOT_RUN"
            )
        ),
        "not_run_blocker_group_counts": dict(
            Counter(
                blocker_key(row)
                for row in rows
                if row["attack_status"] == "NOT_RUN"
            )
        ),
        "experiment_status_counts": dict(
            Counter(row["experiment_status"] for row in rows)
        ),
        "not_experimentable_blocker_class_counts": dict(
            Counter(
                row["experiment_blocker_class"]
                for row in rows
                if row["experiment_status"] == "NOT_EXPERIMENTABLE"
            )
        ),
        "provider_ready": provider_ready,
        "identity_ready": identity is not None,
        "scoring_status": "NOT_PRODUCED",
    }
    document = {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "generated_at": _now(),
        "protocol": protocol,
        "inventory_summary": inventory["summary"],
        "summary": summary,
        "cases": rows,
    }
    document["readiness_sha256"] = canonical_sha256(document)
    return document


def write_case_lists(
    *,
    readiness: Mapping[str, Any],
    ready_out: Path | None,
    not_run_out: Path | None,
    not_experimentable_out: Path | None = None,
) -> None:
    if ready_out is not None:
        ready_out.parent.mkdir(parents=True, exist_ok=True)
        ready_out.write_text(
            "\n".join(
                row["case_id"]
                for row in readiness["cases"]
                if row["attack_status"] == "ATTACK_READY"
            )
            + "\n",
            encoding="utf-8",
        )
    if not_run_out is not None:
        not_run_out.parent.mkdir(parents=True, exist_ok=True)
        not_run_out.write_text(
            "\n".join(
                row["case_id"]
                for row in readiness["cases"]
                if row["attack_status"] == "NOT_RUN"
            )
            + "\n",
            encoding="utf-8",
        )
    if not_experimentable_out is not None:
        not_experimentable_out.parent.mkdir(parents=True, exist_ok=True)
        not_experimentable_out.write_text(
            "\n".join(
                row["case_id"]
                for row in readiness["cases"]
                if row.get("experiment_status") == "NOT_EXPERIMENTABLE"
            )
            + "\n",
            encoding="utf-8",
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--work-root", type=Path, default=DEFAULT_WORK_ROOT)
    parser.add_argument("--executable", default="opencode")
    parser.add_argument("--provider-profile", type=Path)
    parser.add_argument("--conformance", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ready-case-ids-out", type=Path)
    parser.add_argument("--not-run-case-ids-out", type=Path)
    parser.add_argument("--not-experimentable-case-ids-out", type=Path)
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
    readiness = build_active_readiness(
        repo_root=args.repo_root,
        executable=args.executable,
        work_root=work_root,
        profile=profile,
        profile_path=args.provider_profile,
        conformance_path=conformance,
        environ=os.environ,
    )
    output = args.output or (work_root / "active-328-readiness.json")
    _write_json(output, readiness)
    write_case_lists(
        readiness=readiness,
        ready_out=args.ready_case_ids_out or (work_root / "attack-ready-case-ids.txt"),
        not_run_out=args.not_run_case_ids_out or (work_root / "not-run-case-ids.txt"),
        not_experimentable_out=(
            args.not_experimentable_case_ids_out
            or (work_root / "not-experimentable-case-ids.txt")
        ),
    )
    print(json.dumps(readiness["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OpenCodeActiveReadinessError",
    "build_active_readiness",
    "write_case_lists",
]
