"""Hash-frozen Gemini adaptation inventory for all 328 active cases.

The inventory is a static planning artifact.  It never launches Gemini and it
never upgrades an unvalidated capability into execution eligibility.
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
from ...bindings.gemini import load_gemini_smoke_bindings


SCHEMA_NAME = "safety_bench_gemini_active_adaptation_inventory"
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
FIXED_BASE_COMMIT = "opencode-as-run"

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


class GeminiBenchInventoryError(ValueError):
    """The canonical suite or Gemini inventory failed a static invariant."""


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def default_inventory_path(repo_root: Path | None = None) -> Path:
    root = repo_root.resolve() if repo_root is not None else default_repo_root()
    return root / "infra/cross_harness/bindings/gemini/active_328_v1.json"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ordered(values: Iterable[str], order: tuple[str, ...], label: str) -> list[str]:
    observed = set(values)
    unknown = sorted(observed - set(order))
    if unknown:
        raise GeminiBenchInventoryError(f"unknown {label}: {unknown}")
    return [value for value in order if value in observed]


def _plain_descendant(root: Path, relative_value: str) -> Path:
    if not isinstance(relative_value, str) or not relative_value.strip():
        raise GeminiBenchInventoryError("manifest case_dir must be non-empty")
    relative = PurePosixPath(relative_value)
    if (
        relative.is_absolute()
        or relative.as_posix() != relative_value
        or not relative.parts
        or relative.parts[0] != "active"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise GeminiBenchInventoryError(
            f"unsafe or non-canonical manifest case_dir: {relative_value!r}"
        )
    runs_root = root / "runs"
    active_root = runs_root / "active"
    cursor = runs_root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink() or is_reparse_point(cursor):
            raise GeminiBenchInventoryError(
                f"canonical case path traverses a linked component: {cursor}"
            )
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(active_root.resolve(strict=True))
    except (OSError, ValueError, RuntimeError) as exc:
        raise GeminiBenchInventoryError(
            f"manifest case path is unavailable or escapes runs/active: {relative_value}"
        ) from exc
    if not resolved.is_dir():
        raise GeminiBenchInventoryError(f"manifest case path is not a directory: {resolved}")
    return resolved


def _stages(meta: Mapping[str, Any], case_id: str) -> list[dict[str, Any]]:
    raw_stages = meta.get("stages")
    if raw_stages is None:
        raw_stages = [{"name": "single_stage", "user_prompt": meta.get("user_prompt")}]
        source = "case_meta_root"
    else:
        source = "case_meta.stages"
    if not isinstance(raw_stages, list) or not raw_stages:
        raise GeminiBenchInventoryError(f"{case_id}: stages must be non-empty")
    records: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw in enumerate(raw_stages):
        if not isinstance(raw, Mapping):
            raise GeminiBenchInventoryError(f"{case_id}: stage {index} is not an object")
        name = raw.get("name")
        prompt = raw.get("user_prompt")
        if not isinstance(name, str) or not name.strip() or name in names:
            raise GeminiBenchInventoryError(f"{case_id}: invalid/duplicate stage name")
        if not isinstance(prompt, str) or not prompt.strip():
            raise GeminiBenchInventoryError(f"{case_id}: stage {name} has no prompt")
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
        "Gemini CLI 0.51.0 now pins gemini-2.5-flash with a run-local dynamic "
        "model-resolution override and provider usage confirms that exact ID, but "
        "the no-tool verification ended with terminal result status error; "
        "case-required runtime capabilities remain NOT_RUN."
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
        if family.startswith("M2S.08_"):
            comparison_group = "native_compaction_memory_to_skill"
            capabilities.update({"session_compaction", "session_resume"})
            events.update({"session.compacted", "session.resumed"})
            blockers.append(
                "Gemini binding now maps the compacted-summary carrier to an "
                "adapter-scoped session lifecycle and Gemini memory path, but native "
                "session compaction/resume plus Auto Memory to generated-skill lineage "
                "conformance has not been executed."
            )
        else:
            blockers.append(
                "Gemini Auto Memory is experimental and no review/apply plus generated-skill "
                "lineage conformance has been executed."
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
        blockers.append(
            "No Gemini-native parent/child identity and artifact-lineage runtime evidence exists."
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
            blockers.append("Exact Gemini session resume lineage has not been exercised.")
        else:
            semantic_surface = "native.session_compaction_resume_lineage"
            surface_class, binding_class, binding_kind = "native", "M", "native"
            comparison_group = "native_session_compaction"
            capabilities.update({"session_compaction", "session_resume"})
            events.update({"session.started", "session.compacted", "session.resumed"})
            blockers.append(
                "PreCompress alone cannot prove summary identity or token reduction; native "
                "compaction/resume evidence is absent."
            )
    elif suite == "T3_shared_artifact_supply_chain":
        semantic_surface = "workspace.shared_artifact_handoff"
        surface_class, binding_class, binding_kind = "common", "D", "neutral"
        comparison_group = "common_shared_artifact"
        capabilities.update({"fresh_process", "artifact_hash_provenance"})
        events.update({"file.write", "artifact.handoff", "file.read"})
    else:
        raise GeminiBenchInventoryError(f"unknown active suite: {suite}")

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
            "rationale": "This Gemini-owned inventory makes no support claim for other harnesses.",
        }
        for harness in sorted(TARGET_HARNESSES)
    }
    support["gemini"] = {
        "status": "unvalidated",
        "rationale": (
            "Gemini 0.51.0 exact 2.5 model routing is evidence-bound, but the latest "
            "terminal result failed and case-required capabilities remain fail-closed."
        ),
    }
    return support


def build_inventory(repo_root: Path | None = None) -> dict[str, Any]:
    root = (repo_root or default_repo_root()).resolve()
    manifest_path = root / "runs/manifest.json"
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8-sig"))
    if manifest.get("version") != 7:
        raise GeminiBenchInventoryError("runs/manifest.json version drifted from 7")
    smoke_ids = set(load_gemini_smoke_bindings(repo_root=root))
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
                raise GeminiBenchInventoryError(f"case without stable ID: {relative}")
            if meta.get("case_id") != case_id:
                raise GeminiBenchInventoryError(f"manifest/meta case ID mismatch: {case_id}")
            stages = _stages(meta, case_id)
            classification = _classification(
                suite_name, relative, meta, len(stages)
            )
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
                        "gemini": {
                            "adapter": "gemini.adapter_v1",
                            "binding_kind": classification["binding_kind"],
                            "materialization_profile": (
                                "reviewed_smoke_v1"
                                if case_id in smoke_ids
                                else "generated_materializer_v1"
                            ),
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
        raise GeminiBenchInventoryError("active manifest membership/counts drifted")
    stage_count = sum(row["stage_count"] for row in rows)
    if stage_count != EXPECTED_STAGE_COUNT:
        raise GeminiBenchInventoryError(
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
        "smoke_binding_count": sum(
            row["harness_native_binding"]["gemini"]["materialization_profile"]
            == "reviewed_smoke_v1"
            for row in rows
        ),
        "expanded_binding_count": EXPECTED_CASE_COUNT - len(smoke_ids),
        "materializable_binding_count": EXPECTED_CASE_COUNT,
        "scoring_status": "NOT_PRODUCED",
        "formal_external_model_runs": 0,
        "external_runtime_smoke_attempts": 10,
        "external_runtime_successful_provider_responses": 3,
    }
    document: dict[str, Any] = {
        "schema_name": SCHEMA_NAME,
        "schema_version": SCHEMA_VERSION,
        "harness_id": "gemini",
        "generated_on": "2026-07-21",
        "source_contract": {
            "fixed_base_commit": FIXED_BASE_COMMIT,
            "manifest_path": "runs/manifest.json",
            "manifest_version": manifest["version"],
            "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "classification_basis": (
                "docs/cross_harness_expansion_workload.md static Gemini projection"
            ),
            "classification_note": (
                "D/M/N/A is pre-conformance adaptation work; disposition/execution are "
                "separate and fail closed."
            ),
            "runtime_evidence_fixture": (
                "tests/cross_harness/gemini/fixtures/"
                "gemini_cli_0_51_0_vertex_global_smoke.json"
            ),
            "runtime_identity": {
                "version": "0.51.0",
                "executable_sha256": (
                    "a2533ac23365a1c72b847780b53235d38cf21cc7ee736c98dfa8cbb70b1a9425"
                ),
            },
            "model_routing_disposition": (
                "EXACT_ROUTE_VERIFIED_TERMINAL_ERROR_NOT_RUN"
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
        # Counter omits zero-count keys; normalize projected zero categories.
        if key == "binding_class_counts" and "N/A" not in observed:
            observed["N/A"] = 0
        if key == "disposition_counts" and "READY" not in observed:
            observed["READY"] = 0
        if key == "disposition_counts" and "BLOCKED" not in observed:
            observed["BLOCKED"] = 0
        if observed != value:
            raise GeminiBenchInventoryError(f"{key} drifted: {observed} != {value}")


def validate_inventory(
    document: Mapping[str, Any],
    *,
    repo_root: Path | None = None,
    verify_live: bool = True,
) -> None:
    if document.get("schema_name") != SCHEMA_NAME or document.get("schema_version") != 1:
        raise GeminiBenchInventoryError("invalid Gemini inventory schema identity")
    if document.get("harness_id") != "gemini":
        raise GeminiBenchInventoryError("Gemini inventory harness_id drifted")
    rows = document.get("cases")
    if not isinstance(rows, list) or len(rows) != EXPECTED_CASE_COUNT:
        raise GeminiBenchInventoryError("Gemini inventory must contain 328 rows")
    if len({row.get("case_id") for row in rows if isinstance(row, Mapping)}) != len(rows):
        raise GeminiBenchInventoryError("Gemini inventory case IDs must be unique")
    summary = document.get("summary")
    if not isinstance(summary, Mapping):
        raise GeminiBenchInventoryError("Gemini inventory summary is absent")
    if summary.get("case_count") != EXPECTED_CASE_COUNT:
        raise GeminiBenchInventoryError("Gemini summary case_count drifted")
    if summary.get("stage_count") != EXPECTED_STAGE_COUNT:
        raise GeminiBenchInventoryError("Gemini summary stage_count drifted")
    if dict(summary.get("suite_counts", {})) != EXPECTED_SUITE_COUNTS:
        raise GeminiBenchInventoryError("Gemini suite counts drifted")
    _expect_counts(summary)
    if summary.get("scoring_status") != "NOT_PRODUCED":
        raise GeminiBenchInventoryError("static inventory may not produce scoring")
    if summary.get("formal_external_model_runs") != 0:
        raise GeminiBenchInventoryError("static inventory may not claim external runs")
    for row in rows:
        if not isinstance(row, Mapping):
            raise GeminiBenchInventoryError("inventory rows must be objects")
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
            raise GeminiBenchInventoryError(
                f"{row.get('case_id')}: missing required binding fields {missing}"
            )
        if set(row["required_capabilities"]) - CAPABILITIES:
            raise GeminiBenchInventoryError(f"{row['case_id']}: unknown capability")
        if row["disposition"] != "READY" and not row["blocking_reasons"]:
            raise GeminiBenchInventoryError(f"{row['case_id']}: NOT_RUN lacks evidence")
        if row.get("execution_outcome") != "NOT_RUN":
            raise GeminiBenchInventoryError(f"{row['case_id']}: execution must be NOT_RUN")
        serialized = json.dumps(row, sort_keys=True)
        if "SAFE" in serialized or '"N0"' in serialized:
            raise GeminiBenchInventoryError(
                f"{row['case_id']}: static/unvalidated row contains a safety score"
            )
    supplied_digest = document.get("inventory_content_sha256")
    without_digest = dict(document)
    without_digest.pop("inventory_content_sha256", None)
    if supplied_digest != canonical_json_sha256(without_digest):
        raise GeminiBenchInventoryError("Gemini inventory content digest mismatch")
    if verify_live:
        rebuilt = build_inventory(repo_root=repo_root)
        if rebuilt != document:
            raise GeminiBenchInventoryError(
                "checked-in Gemini inventory differs from live canonical inputs"
            )


def load_inventory(
    path: Path | None = None,
    *,
    repo_root: Path | None = None,
    verify_live: bool = True,
) -> dict[str, Any]:
    root = (repo_root or default_repo_root()).resolve()
    inventory_path = (path or default_inventory_path(root)).resolve()
    document = json.loads(inventory_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise GeminiBenchInventoryError("Gemini inventory root must be an object")
    validate_inventory(document, repo_root=root, verify_live=verify_live)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "validate", "summary"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    root = default_repo_root()
    path = (args.output or default_inventory_path(root)).resolve()
    if args.action == "generate":
        document = build_inventory(root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    else:
        document = load_inventory(path, repo_root=root, verify_live=True)
    if args.action in {"generate", "summary"}:
        print(json.dumps(document["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
