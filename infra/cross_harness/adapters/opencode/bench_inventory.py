"""OpenCode projection inventory for all 328 active Safety Bench cases.

This module is a static planning/readiness layer.  It reads the canonical
``runs/manifest.json`` active suite, derives the case-required cross-harness
capabilities, and keeps execution/scoring fail-closed.  It never edits
``runs/active`` or produces N0--N5b scores.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from infra.check_paper_suite_lock import (
    canonical_case_content_record,
    canonical_json_sha256,
    is_reparse_point,
)

from ...contract import CAPABILITIES, TARGET_HARNESSES


SCHEMA_NAME = "safety_bench_opencode_active_adaptation_inventory"
SCHEMA_VERSION = 1
EXPECTED_CASE_COUNT = 328
EXPECTED_STAGE_COUNT = 690
EXPECTED_SUITE_COUNTS = {
    "v2_skill_runtime": 84,
    "v2_tool_mcp_runtime": 70,
    "F1_memory_runtime": 72,
    "T2_memory_to_skill": 36,
    "T3_subagent_poisoning": 30,
    "T3_compaction_resume_poisoning": 30,
    "T3_shared_artifact_supply_chain": 6,
}
EXPECTED_SURFACE_COUNTS = {"common": 242, "native": 86}
EXPECTED_BINDING_CLASS_COUNTS = {"D": 231, "M": 97, "N/A": 0}
EXPECTED_BINDING_KIND_COUNTS = {"native": 170, "hybrid": 70, "neutral": 88}
EXPECTED_DISPOSITION_COUNTS = {"READY": 0, "NOT_RUN": 328, "BLOCKED": 0}

CAPABILITY_ORDER = (
    "headless_execution",
    "structured_trace",
    "workspace_isolation",
    "instruction_loading",
    "skill_discovery",
    "skill_activation_trace",
    "mcp_configuration",
    "mcp_health_trace",
    "mcp_tool_trace",
    "fresh_process",
    "durable_memory_write",
    "durable_memory_retrieval",
    "session_resume",
    "session_compaction",
    "subagent_delegation",
    "artifact_hash_provenance",
    "control_isolation",
)
EVENT_ORDER = (
    "instruction.loaded",
    "skill.discovered",
    "skill.activated",
    "mcp.server_initialized",
    "mcp.tool_requested",
    "mcp.tool_result",
    "file.write",
    "artifact.handoff",
    "file.read",
    "memory.written",
    "memory.retrieved",
    "session.started",
    "session.compacted",
    "session.resumed",
    "agent.spawned",
    "agent.completed",
)
_BASE_CAPABILITIES = {
    "headless_execution",
    "structured_trace",
    "workspace_isolation",
}


class OpenCodeBenchInventoryError(ValueError):
    """The canonical suite or OpenCode static projection failed an invariant."""


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _ordered(values: Iterable[str], order: tuple[str, ...], label: str) -> list[str]:
    observed = set(values)
    unknown = sorted(observed - set(order))
    if unknown:
        raise OpenCodeBenchInventoryError(f"unknown {label}: {unknown}")
    return [value for value in order if value in observed]


def _plain_descendant(root: Path, relative_value: str) -> Path:
    if not isinstance(relative_value, str) or not relative_value.strip():
        raise OpenCodeBenchInventoryError("manifest case_dir must be non-empty")
    relative = PurePosixPath(relative_value)
    if (
        relative.is_absolute()
        or relative.as_posix() != relative_value
        or not relative.parts
        or relative.parts[0] != "active"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise OpenCodeBenchInventoryError(
            f"unsafe or non-canonical manifest case_dir: {relative_value!r}"
        )
    runs_root = root / "runs"
    active_root = runs_root / "active"
    cursor = runs_root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink() or is_reparse_point(cursor):
            raise OpenCodeBenchInventoryError(
                f"canonical case path traverses a linked component: {cursor}"
            )
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(active_root.resolve(strict=True))
    except (OSError, ValueError, RuntimeError) as exc:
        raise OpenCodeBenchInventoryError(
            f"manifest case path is unavailable or escapes runs/active: {relative_value}"
        ) from exc
    if not resolved.is_dir():
        raise OpenCodeBenchInventoryError(f"manifest case path is not a directory: {resolved}")
    return resolved


def _stages(meta: Mapping[str, Any], case_id: str) -> list[dict[str, Any]]:
    raw_stages = meta.get("stages")
    if raw_stages is None:
        raw_stages = [{"name": "single_stage", "user_prompt": meta.get("user_prompt")}]
        source = "case_meta_root"
    else:
        source = "case_meta.stages"
    if not isinstance(raw_stages, list) or not raw_stages:
        raise OpenCodeBenchInventoryError(f"{case_id}: stages must be non-empty")
    records: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw in enumerate(raw_stages):
        if not isinstance(raw, Mapping):
            raise OpenCodeBenchInventoryError(f"{case_id}: stage {index} is not an object")
        name = raw.get("name")
        prompt = raw.get("user_prompt")
        if not isinstance(name, str) or not name.strip() or name in names:
            raise OpenCodeBenchInventoryError(f"{case_id}: invalid/duplicate stage name")
        if not isinstance(prompt, str) or not prompt.strip():
            raise OpenCodeBenchInventoryError(f"{case_id}: stage {name} has no prompt")
        names.add(name)
        records.append(
            {
                "index": index,
                "name": name,
                "source": source,
                "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "stage_canonical_sha256": canonical_json_sha256(raw),
                "session_action": str(raw.get("session_action") or ""),
                "runtime_mode": str(raw.get("runtime_mode") or ""),
            }
        )
    return records


def _family_segment(case_dir: str) -> str:
    parts = PurePosixPath(case_dir).parts
    return next((part for part in parts if "." in part), "")


def _classification(
    suite: str,
    case_dir: str,
    meta: Mapping[str, Any],
    stage_count: int,
) -> dict[str, Any]:
    capabilities = set(_BASE_CAPABILITIES)
    events: set[str] = set()
    family = _family_segment(case_dir)
    case_id = str(meta.get("case_id") or "")
    disposition = "NOT_RUN"
    blockers = [
        "OpenCode active-328 binding is generated from the canonical active "
        "manifest; execution eligibility remains capability-evidence bound."
    ]

    if suite == "F1_memory_runtime":
        semantic_surface = "workspace.memory_snapshot_reconsumption"
        surface_class, binding_class, binding_kind = "common", "D", "neutral"
        comparison_group = "common_memory_surface"
        capabilities.update({"fresh_process", "artifact_hash_provenance"})
        events.add("file.read")
    elif suite == "v2_skill_runtime":
        semantic_surface = "skill.package_discovery_activation"
        surface_class, binding_kind = "common", "native"
        needs_variant = (
            (family.startswith("F2.04_") and "case_401_" not in case_id)
            or (family.startswith("F2.06_") and "case_601_" not in case_id)
            or (
                family.startswith("F2.13_")
                and ("case_702_" in case_id or "case_703_" in case_id)
            )
        )
        binding_class = "M" if needs_variant else "D"
        comparison_group = "common_skill_surface"
        capabilities.update({"skill_discovery", "skill_activation_trace"})
        events.update({"skill.discovered", "skill.activated"})
        if stage_count > 1:
            capabilities.update({"fresh_process", "artifact_hash_provenance"})
            events.update({"file.write", "file.read"})
        if "case_702_" in case_id or "case_703_" in case_id:
            capabilities.add("instruction_loading")
            events.add("instruction.loaded")
            blockers.append(
                "OpenCode v1 keeps instruction_loading fail-closed without "
                "native hermetic JSON evidence for project-instruction loading."
            )
    elif suite == "v2_tool_mcp_runtime":
        semantic_surface = "mcp.tool_persistent_carrier"
        surface_class, binding_class, binding_kind = "common", "D", "hybrid"
        comparison_group = "common_mcp_tool_surface"
        capabilities.update(
            {
                "mcp_configuration",
                "mcp_health_trace",
                "mcp_tool_trace",
                "fresh_process",
                "artifact_hash_provenance",
            }
        )
        events.update(
            {
                "mcp.server_initialized",
                "mcp.tool_requested",
                "mcp.tool_result",
                "file.write",
                "file.read",
            }
        )
        if str(meta.get("carrier") or "") == "memory":
            capabilities.update({"durable_memory_write", "durable_memory_retrieval"})
            events.update({"memory.written", "memory.retrieved"})
            blockers.append(
                "OpenCode v1 has no documented native durable project auto-memory "
                "store matching this case carrier."
            )
    elif suite == "T2_memory_to_skill":
        semantic_surface = "native.memory_to_generated_skill"
        surface_class, binding_class, binding_kind = "native", "M", "native"
        comparison_group = "native_namespace_memory_to_skill"
        capabilities.update(
            {
                "durable_memory_write",
                "durable_memory_retrieval",
                "skill_discovery",
                "skill_activation_trace",
                "fresh_process",
                "artifact_hash_provenance",
            }
        )
        events.update(
            {
                "memory.written",
                "memory.retrieved",
                "file.write",
                "skill.discovered",
                "skill.activated",
            }
        )
        blockers.append(
            "OpenCode v1 has no documented native durable auto-memory lifecycle "
            "that can prove memory-to-generated-skill lineage."
        )
        if family.startswith("M2S.08_"):
            comparison_group = "native_compaction_memory_to_skill"
            capabilities.update({"session_compaction", "session_resume"})
            events.update({"session.compacted", "session.resumed"})
            blockers.append(
                "This case also requires measurable compaction provenance, which "
                "OpenCode v1 keeps fail-closed."
            )
    elif suite == "T3_subagent_poisoning":
        semantic_surface = "native.subagent_artifact_handoff"
        surface_class, binding_class, binding_kind = "native", "M", "native"
        comparison_group = "native_subagent"
        capabilities.update({"subagent_delegation", "artifact_hash_provenance"})
        events.update(
            {
                "agent.spawned",
                "file.write",
                "artifact.handoff",
                "agent.completed",
                "file.read",
            }
        )
    elif suite == "T3_compaction_resume_poisoning":
        if family.startswith(("CR.04_", "CR.05_")):
            semantic_surface = "workspace.saved_state_fresh_process_reuse"
            surface_class, binding_class, binding_kind = "common", "D", "neutral"
            comparison_group = "common_saved_state_reuse"
            capabilities.update({"fresh_process", "artifact_hash_provenance"})
            events.update({"file.write", "file.read"})
        elif family.startswith("CR.02_"):
            semantic_surface = "native.session_resume_lineage"
            surface_class, binding_class, binding_kind = "native", "M", "native"
            comparison_group = "native_session_resume"
            capabilities.add("session_resume")
            events.update({"session.started", "session.resumed"})
        else:
            semantic_surface = "native.session_compaction_resume_lineage"
            surface_class, binding_class, binding_kind = "native", "M", "native"
            comparison_group = "native_session_compaction"
            capabilities.update({"session_compaction", "session_resume"})
            events.update({"session.started", "session.compacted", "session.resumed"})
            blockers.append(
                "OpenCode v1 does not expose enough native compaction evidence "
                "for Contract v1 summary identity/token-reduction provenance."
            )
    elif suite == "T3_shared_artifact_supply_chain":
        semantic_surface = "workspace.shared_artifact_handoff"
        surface_class, binding_class, binding_kind = "common", "D", "neutral"
        comparison_group = "common_shared_artifact"
        capabilities.update({"fresh_process", "artifact_hash_provenance"})
        events.update({"file.write", "artifact.handoff", "file.read"})
    else:
        raise OpenCodeBenchInventoryError(f"unknown active suite: {suite}")

    return {
        "semantic_surface": semantic_surface,
        "surface_class": surface_class,
        "binding_class": binding_class,
        "binding_kind": binding_kind,
        "comparison_group": comparison_group,
        "required_capabilities": _ordered(capabilities, CAPABILITY_ORDER, "capabilities"),
        "expected_normalized_events": _ordered(events, EVENT_ORDER, "events"),
        "disposition": disposition,
        "blocking_reasons": blockers,
    }


def _support_map() -> dict[str, dict[str, str]]:
    support = {
        harness: {
            "status": "unvalidated",
            "rationale": "This OpenCode-owned active inventory makes no support claim for other harnesses.",
        }
        for harness in sorted(TARGET_HARNESSES)
    }
    support["opencode"] = {
        "status": "unvalidated",
        "rationale": (
            "OpenCode active-328 execution eligibility is derived only from "
            "version-pinned capability/readiness evidence."
        ),
    }
    return support


def build_inventory(repo_root: Path | None = None) -> dict[str, Any]:
    root = (repo_root or default_repo_root()).resolve()
    manifest_path = root / "runs/manifest.json"
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8-sig"))
    if manifest.get("version") != 7:
        raise OpenCodeBenchInventoryError("runs/manifest.json version drifted from 7")

    rows: list[dict[str, Any]] = []
    suite_counts: Counter[str] = Counter()
    manifest_index = 0
    for suite_name, suite in manifest.get("suites", {}).items():
        if suite.get("status") != "active":
            continue
        for entry in suite.get("cases", []):
            relative = entry.get("case_dir")
            case_path = _plain_descendant(root, relative)
            meta_path = case_path / "case_meta.json"
            meta_raw = meta_path.read_bytes()
            meta = json.loads(meta_raw.decode("utf-8-sig"))
            case_id = entry.get("case_id") or meta.get("case_id")
            if not isinstance(case_id, str) or not case_id.strip():
                raise OpenCodeBenchInventoryError(f"case without stable ID: {relative}")
            if meta.get("case_id") != case_id:
                raise OpenCodeBenchInventoryError(f"manifest/meta case ID mismatch: {case_id}")
            stages = _stages(meta, case_id)
            classification = _classification(suite_name, relative, meta, len(stages))
            content = canonical_case_content_record(case_path)
            rows.append(
                {
                    "manifest_index": manifest_index,
                    "suite": suite_name,
                    "case_id": case_id,
                    "case_dir": f"runs/{relative}",
                    "case_meta_sha256": hashlib.sha256(meta_raw).hexdigest(),
                    "case_meta_canonical_sha256": content[
                        "case_meta_canonical_sha256"
                    ],
                    "case_content_sha256": content["case_content_sha256"],
                    "stage_count": len(stages),
                    "stages": stages,
                    **classification,
                    "supported_harnesses": _support_map(),
                    "harness_native_binding": {
                        "opencode": {
                            "adapter": "opencode.adapter_v1",
                            "binding_kind": classification["binding_kind"],
                            "materialization_profile": "active_328_generated_v1",
                        }
                    },
                    "binding_version": 1,
                    "execution_outcome": "NOT_RUN",
                    "scoring_status": "NOT_PRODUCED",
                }
            )
            suite_counts[suite_name] += 1
            manifest_index += 1

    if len(rows) != EXPECTED_CASE_COUNT or dict(suite_counts) != EXPECTED_SUITE_COUNTS:
        raise OpenCodeBenchInventoryError("active manifest membership/counts drifted")
    stage_count = sum(row["stage_count"] for row in rows)
    if stage_count != EXPECTED_STAGE_COUNT:
        raise OpenCodeBenchInventoryError(
            f"active stage count drifted: {stage_count} != {EXPECTED_STAGE_COUNT}"
        )

    binding_class_counts = dict(Counter(row["binding_class"] for row in rows))
    binding_class_counts.setdefault("N/A", 0)
    disposition_counts = dict(Counter(row["disposition"] for row in rows))
    disposition_counts.setdefault("READY", 0)
    disposition_counts.setdefault("BLOCKED", 0)
    summary = {
        "case_count": len(rows),
        "stage_count": stage_count,
        "suite_counts": dict(suite_counts),
        "surface_class_counts": dict(Counter(row["surface_class"] for row in rows)),
        "binding_class_counts": binding_class_counts,
        "binding_kind_counts": dict(Counter(row["binding_kind"] for row in rows)),
        "disposition_counts": disposition_counts,
        "execution_outcome_counts": {"NOT_RUN": len(rows)},
        "scoring_status": "NOT_PRODUCED",
        "formal_external_model_runs": 0,
    }
    document: dict[str, Any] = {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "harness_id": "opencode",
        "generated_at": "live",
        "source_contract": {
            "construction_authority": "runs/manifest.json",
            "manifest_path": "runs/manifest.json",
            "manifest_version": manifest["version"],
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "classification_note": (
                "Static D/M/N/A projection is not execution evidence; "
                "active readiness is computed separately from version-pinned "
                "OpenCode capability conformance."
            ),
        },
        "summary": summary,
        "cases": rows,
    }
    document["inventory_content_sha256"] = canonical_json_sha256(document)
    validate_inventory(document, repo_root=root, verify_live=False)
    return document


def _expect_counts(summary: Mapping[str, Any]) -> None:
    expected = {
        "surface_class_counts": EXPECTED_SURFACE_COUNTS,
        "binding_class_counts": EXPECTED_BINDING_CLASS_COUNTS,
        "binding_kind_counts": EXPECTED_BINDING_KIND_COUNTS,
        "disposition_counts": EXPECTED_DISPOSITION_COUNTS,
    }
    for key, value in expected.items():
        observed = dict(summary.get(key, {}))
        if key == "binding_class_counts" and "N/A" not in observed:
            observed["N/A"] = 0
        if key == "disposition_counts":
            observed.setdefault("READY", 0)
            observed.setdefault("BLOCKED", 0)
        if observed != value:
            raise OpenCodeBenchInventoryError(f"{key} drifted: {observed} != {value}")


def validate_inventory(
    document: Mapping[str, Any],
    *,
    repo_root: Path | None = None,
    verify_live: bool = True,
) -> None:
    if document.get("schema_name") != SCHEMA_NAME or document.get("schema_version") != 1:
        raise OpenCodeBenchInventoryError("invalid OpenCode inventory schema identity")
    if document.get("harness_id") != "opencode":
        raise OpenCodeBenchInventoryError("OpenCode inventory harness_id drifted")
    rows = document.get("cases")
    if not isinstance(rows, list) or len(rows) != EXPECTED_CASE_COUNT:
        raise OpenCodeBenchInventoryError("OpenCode inventory must contain 328 rows")
    if len({row.get("case_id") for row in rows if isinstance(row, Mapping)}) != len(rows):
        raise OpenCodeBenchInventoryError("OpenCode inventory case IDs must be unique")
    summary = document.get("summary")
    if not isinstance(summary, Mapping):
        raise OpenCodeBenchInventoryError("OpenCode inventory summary is absent")
    if summary.get("case_count") != EXPECTED_CASE_COUNT:
        raise OpenCodeBenchInventoryError("OpenCode summary case_count drifted")
    if summary.get("stage_count") != EXPECTED_STAGE_COUNT:
        raise OpenCodeBenchInventoryError("OpenCode summary stage_count drifted")
    if dict(summary.get("suite_counts", {})) != EXPECTED_SUITE_COUNTS:
        raise OpenCodeBenchInventoryError("OpenCode suite counts drifted")
    _expect_counts(summary)
    if summary.get("scoring_status") != "NOT_PRODUCED":
        raise OpenCodeBenchInventoryError("static inventory may not produce scoring")
    if summary.get("formal_external_model_runs") != 0:
        raise OpenCodeBenchInventoryError("static inventory may not claim external runs")
    for row in rows:
        if not isinstance(row, Mapping):
            raise OpenCodeBenchInventoryError("inventory rows must be objects")
        required = {
            "semantic_surface",
            "surface_class",
            "required_capabilities",
            "supported_harnesses",
            "harness_native_binding",
            "comparison_group",
            "binding_version",
            "case_meta_sha256",
            "expected_normalized_events",
            "disposition",
            "blocking_reasons",
        }
        missing = sorted(required - set(row))
        if missing:
            raise OpenCodeBenchInventoryError(
                f"{row.get('case_id')}: missing required inventory fields {missing}"
            )
        if set(row["required_capabilities"]) - CAPABILITIES:
            raise OpenCodeBenchInventoryError(f"{row['case_id']}: unknown capability")
        if row["disposition"] != "READY" and not row["blocking_reasons"]:
            raise OpenCodeBenchInventoryError(f"{row['case_id']}: NOT_RUN lacks evidence")
        if row.get("execution_outcome") != "NOT_RUN":
            raise OpenCodeBenchInventoryError(f"{row['case_id']}: execution must be NOT_RUN")
        serialized = json.dumps(row, sort_keys=True)
        if "SAFE" in serialized or '"N0"' in serialized:
            raise OpenCodeBenchInventoryError(
                f"{row['case_id']}: static/unvalidated row contains a safety score"
            )
    supplied_digest = document.get("inventory_content_sha256")
    without_digest = dict(document)
    without_digest.pop("inventory_content_sha256", None)
    if supplied_digest != canonical_json_sha256(without_digest):
        raise OpenCodeBenchInventoryError("OpenCode inventory content digest mismatch")
    if verify_live:
        rebuilt = build_inventory(repo_root=repo_root)
        if rebuilt != document:
            raise OpenCodeBenchInventoryError(
                "OpenCode inventory differs from live canonical inputs"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "validate", "summary"))
    parser.add_argument("--repo-root", type=Path, default=default_repo_root())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    if args.action == "generate":
        document = build_inventory(root)
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(document, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    elif args.output is not None:
        document = json.loads(args.output.read_text(encoding="utf-8"))
        validate_inventory(document, repo_root=root, verify_live=True)
    else:
        document = build_inventory(root)
    if args.action in {"generate", "summary"}:
        print(json.dumps(document["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "OpenCodeBenchInventoryError",
    "build_inventory",
    "default_repo_root",
    "validate_inventory",
]
