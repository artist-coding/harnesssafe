"""Hash-frozen Kimi inventory for the 328 active Safety Bench cases.

This module is intentionally Kimi-owned.  It reads the canonical active-case
manifest and case trees but never writes to them.  The checked-in snapshot is
both a coverage assertion and a drift gate for Kimi planning/execution:
formal Kimi work must stop when the live canonical inputs do not exactly match
the frozen inventory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from infra.check_paper_suite_lock import (
    canonical_case_content_record,
    canonical_json_sha256,
    is_reparse_point,
)
from infra.cross_harness.contract import CAPABILITIES, TARGET_HARNESSES


INVENTORY_SCHEMA_NAME = "safety_bench_kimi_active_inventory"
INVENTORY_SCHEMA_VERSION = 1
MANIFEST_VERSION = 7
EXPECTED_CASE_COUNT = 328
EXPECTED_STAGE_COUNT = 690
EXPECTED_SUITE_COUNTS: dict[str, int] = {
    "v2_skill_runtime": 84,
    "v2_tool_mcp_runtime": 70,
    "F1_memory_runtime": 72,
    "T2_memory_to_skill": 36,
    "T3_subagent_poisoning": 30,
    "T3_compaction_resume_poisoning": 30,
    "T3_shared_artifact_supply_chain": 6,
}

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

_BASE_CAPABILITIES = {
    "headless_execution",
    "structured_trace",
    "workspace_isolation",
    # Matched-control comparisons are currently scoped to Claude Code.  Kimi
    # attack rows still require strict per-trial isolation, but do not require
    # evidence for the separate attack/control equivalence capability.
}
_SKILL_CAPABILITIES = {"skill_discovery", "skill_activation_trace"}
_MCP_CAPABILITIES = {
    "mcp_configuration",
    "mcp_health_trace",
    "mcp_tool_trace",
}
_MEMORY_CAPABILITIES = {
    "durable_memory_write",
    "durable_memory_retrieval",
}
_FRAME_FIELDS = ("entry", "carrier", "boundary", "trigger", "violation", "recovery")


class KimiBenchInventoryError(ValueError):
    """Raised when the canonical Kimi benchmark inventory fails closed."""


class KimiBenchInventoryDriftError(KimiBenchInventoryError):
    """Raised when live canonical inputs differ from the frozen snapshot."""


def default_repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def default_snapshot_path(repo_root: Path | str | None = None) -> Path:
    root = Path(repo_root).resolve() if repo_root is not None else default_repo_root()
    return root / "infra" / "cross_harness" / "bindings" / "kimi" / "active_328_v1.json"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise KimiBenchInventoryError(f"JSON object contains duplicate key: {key!r}")
        result[key] = value
    return result


def _load_json_object(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise KimiBenchInventoryError(f"cannot read JSON file {path}: {exc}") from exc
    try:
        value = json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise KimiBenchInventoryError(f"invalid JSON file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise KimiBenchInventoryError(f"JSON root must be an object: {path}")
    return value, raw


def _plain_path(path: Path, *, label: str) -> None:
    if path.is_symlink() or is_reparse_point(path):
        raise KimiBenchInventoryError(f"{label} must not be a symlink or reparse point: {path}")


def resolve_manifest_case_dir(repo_root: Path | str, case_dir: str) -> Path:
    """Resolve one manifest path while rejecting traversal and linked paths."""

    root = Path(repo_root).resolve()
    if not isinstance(case_dir, str) or not case_dir or case_dir != case_dir.strip():
        raise KimiBenchInventoryError("manifest case_dir must be a non-empty trimmed string")
    if "\\" in case_dir:
        raise KimiBenchInventoryError(f"manifest case_dir must use POSIX separators: {case_dir!r}")
    relative = PurePosixPath(case_dir)
    if relative.is_absolute() or relative.as_posix() != case_dir:
        raise KimiBenchInventoryError(f"manifest case_dir is not normalized: {case_dir!r}")
    if len(relative.parts) < 2 or relative.parts[0] != "active":
        raise KimiBenchInventoryError(
            f"manifest case_dir must be below runs/active: {case_dir!r}"
        )
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise KimiBenchInventoryError(f"manifest case_dir contains traversal: {case_dir!r}")

    runs_root = root / "runs"
    active_root = runs_root / "active"
    for label, path in (("runs root", runs_root), ("active root", active_root)):
        if not path.is_dir():
            raise KimiBenchInventoryError(f"{label} is missing: {path}")
        _plain_path(path, label=label)

    cursor = runs_root
    for part in relative.parts:
        cursor = cursor / part
        if not cursor.exists():
            raise KimiBenchInventoryError(f"manifest case path is missing: {cursor}")
        _plain_path(cursor, label="manifest case path component")

    resolved = cursor.resolve(strict=True)
    active_resolved = active_root.resolve(strict=True)
    try:
        resolved.relative_to(active_resolved)
    except ValueError as exc:
        raise KimiBenchInventoryError(
            f"manifest case path escapes runs/active: {case_dir!r}"
        ) from exc
    if not resolved.is_dir():
        raise KimiBenchInventoryError(f"manifest case path is not a directory: {resolved}")
    return resolved


def _string_list(value: Any, *, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item.strip() for item in value
    ):
        raise KimiBenchInventoryError(f"{label} must be an array of non-empty strings")
    if len(value) != len(set(value)):
        raise KimiBenchInventoryError(f"{label} must not contain duplicates")
    return list(value)


def _stage_records(meta: Mapping[str, Any], *, case_id: str) -> list[dict[str, Any]]:
    raw_stages = meta.get("stages")
    if raw_stages is None:
        raw_stages = [
            {
                "name": "single_stage",
                "user_prompt": meta.get("user_prompt"),
                "plugin_dirs": meta.get("plugin_dirs") or [],
                "mcp_configs": meta.get("mcp_configs") or [],
                "declared_oracles": meta.get("oracles") or [],
            }
        ]
        stage_source = "case_meta_root"
    else:
        if not isinstance(raw_stages, list) or not raw_stages:
            raise KimiBenchInventoryError(f"{case_id}: stages must be a non-empty array")
        stage_source = "case_meta.stages"

    records: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw_stage in enumerate(raw_stages):
        if not isinstance(raw_stage, dict):
            raise KimiBenchInventoryError(f"{case_id}: stage {index} must be an object")
        name = raw_stage.get("name")
        if not isinstance(name, str) or not name.strip():
            raise KimiBenchInventoryError(f"{case_id}: stage {index} has no name")
        if name in names:
            raise KimiBenchInventoryError(f"{case_id}: duplicate stage name {name!r}")
        names.add(name)
        prompt = raw_stage.get("user_prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise KimiBenchInventoryError(
                f"{case_id}: stage {index} has no non-empty user_prompt"
            )
        session_action = raw_stage.get("session_action") or ""
        runtime_mode = raw_stage.get("runtime_mode") or ""
        if not isinstance(session_action, str) or not isinstance(runtime_mode, str):
            raise KimiBenchInventoryError(
                f"{case_id}: stage {index} session/runtime fields must be strings"
            )
        supported = _string_list(
            raw_stage.get("supported_harnesses"),
            label=f"{case_id}.stages[{index}].supported_harnesses",
        )
        unknown_harnesses = sorted(set(supported) - TARGET_HARNESSES)
        if unknown_harnesses:
            raise KimiBenchInventoryError(
                f"{case_id}: stage {index} names unknown harnesses: {unknown_harnesses}"
            )
        records.append(
            {
                "index": index,
                "name": name,
                "source": stage_source,
                "user_prompt_sha256": _sha256_text(prompt),
                "stage_canonical_sha256": canonical_json_sha256(raw_stage),
                "runtime_mode": runtime_mode,
                "session_action": session_action,
                "supported_harnesses": supported,
                "plugin_dirs": _string_list(
                    raw_stage.get("plugin_dirs"),
                    label=f"{case_id}.stages[{index}].plugin_dirs",
                ),
                "mcp_configs": _string_list(
                    raw_stage.get("mcp_configs"),
                    label=f"{case_id}.stages[{index}].mcp_configs",
                ),
                "declared_oracles": _string_list(
                    raw_stage.get("declared_oracles"),
                    label=f"{case_id}.stages[{index}].declared_oracles",
                ),
            }
        )
    return records


def _contains_string_fragment(value: Any, fragment: str) -> bool:
    if isinstance(value, str):
        return fragment.casefold() in value.casefold()
    if isinstance(value, Mapping):
        return any(_contains_string_fragment(item, fragment) for item in value.values())
    if isinstance(value, list):
        return any(_contains_string_fragment(item, fragment) for item in value)
    return False


def _ordered_capabilities(values: Iterable[str]) -> list[str]:
    capabilities = set(values)
    unknown = sorted(capabilities - CAPABILITIES)
    if unknown:
        raise KimiBenchInventoryError(f"internal classifier emitted unknown capabilities: {unknown}")
    return [item for item in CAPABILITY_ORDER if item in capabilities]


def _execution_classification(
    suite_name: str,
    meta: Mapping[str, Any],
    stages: Sequence[Mapping[str, Any]],
    *,
    case_id: str,
) -> dict[str, Any]:
    stage_count = len(stages)
    capabilities = set(_BASE_CAPABILITIES)
    execution_class = ""
    binding_kind = ""
    semantic_binding: dict[str, Any] | None = None

    if suite_name == "v2_skill_runtime":
        capabilities.update(_SKILL_CAPABILITIES)
        binding_kind = "native"
        if stage_count == 1:
            execution_class = "requires_kimi_native_skill_direct"
        elif stage_count == 2:
            execution_class = "requires_kimi_native_skill_persistence"
            capabilities.add("fresh_process")
        else:
            raise KimiBenchInventoryError(
                f"{case_id}: skill-runtime case must have one or two stages"
            )
        if _contains_string_fragment(meta, "CLAUDE.md"):
            capabilities.add("instruction_loading")

    elif suite_name == "v2_tool_mcp_runtime":
        if stage_count != 2:
            raise KimiBenchInventoryError(f"{case_id}: F3 case must have two stages")
        mcp_configs = _string_list(
            meta.get("mcp_configs"), label=f"{case_id}.mcp_configs"
        )
        if not mcp_configs:
            raise KimiBenchInventoryError(f"{case_id}: F3 case has no MCP config")
        capabilities.update(_MCP_CAPABILITIES | {"fresh_process"})
        carrier = meta.get("carrier")
        if carrier == "memory":
            if meta.get("boundary") != "cross_session":
                raise KimiBenchInventoryError(
                    f"{case_id}: F3 memory carrier must cross a session boundary"
                )
            execution_class = "requires_kimi_native_mcp_memory"
            binding_kind = "native"
            capabilities.update(_MEMORY_CAPABILITIES)
        elif carrier in {"workspace_file", "registry_cache", "tool_schema_cache"}:
            execution_class = "requires_kimi_native_mcp_workspace_carrier"
            binding_kind = "hybrid"
            capabilities.add("artifact_hash_provenance")
        else:
            raise KimiBenchInventoryError(
                f"{case_id}: unsupported F3 carrier for Kimi planning: {carrier!r}"
            )

    elif suite_name == "F1_memory_runtime":
        if stage_count != 2 or meta.get("entry") != "preseeded_memory_snapshot":
            raise KimiBenchInventoryError(
                f"{case_id}: F1 neutral snapshot case has unexpected shape"
            )
        snapshot_path = meta.get("input_memory_snapshot_relpath")
        if not isinstance(snapshot_path, str) or not snapshot_path.strip():
            raise KimiBenchInventoryError(f"{case_id}: F1 snapshot path is missing")
        execution_class = "neutral_workspace_memory_snapshot"
        binding_kind = "neutral"
        capabilities.add("fresh_process")

    elif suite_name == "T2_memory_to_skill":
        if stage_count != 3:
            raise KimiBenchInventoryError(f"{case_id}: T2 case must have three stages")
        boundary = meta.get("boundary")
        capabilities.update(
            _SKILL_CAPABILITIES
            | _MEMORY_CAPABILITIES
            | {"fresh_process", "artifact_hash_provenance"}
        )
        if boundary == "mcp_result_to_generated_skill":
            execution_class = "requires_kimi_native_mcp_memory_to_skill"
            binding_kind = "hybrid"
            capabilities.update(_MCP_CAPABILITIES)
        elif boundary in {
            "memory_to_generated_skill",
            "summary_to_generated_skill",
            "memory_to_existing_skill_update",
        }:
            execution_class = "requires_kimi_native_memory_to_skill"
            binding_kind = "native"
        else:
            raise KimiBenchInventoryError(
                f"{case_id}: unsupported T2 boundary for Kimi planning: {boundary!r}"
            )

    elif suite_name == "T3_subagent_poisoning":
        mechanism = (meta.get("boundary_runtime_contract") or {}).get("mechanism")
        if stage_count != 2 or mechanism != "real_claude_subagent_to_exact_artifact":
            raise KimiBenchInventoryError(
                f"{case_id}: subagent case has unexpected canonical runtime contract"
            )
        execution_class = "requires_kimi_native_subagent"
        binding_kind = "native"
        capabilities.update(
            {"subagent_delegation", "fresh_process", "artifact_hash_provenance"}
        )
        attack_family_id = meta.get("attack_family_id")
        if attack_family_id == "SA.03":
            if not stages[1].get("mcp_configs"):
                raise KimiBenchInventoryError(
                    f"{case_id}: SA.03 consumer must freeze an MCP configuration"
                )
            capabilities.update(_MCP_CAPABILITIES)
        elif any(stage.get("mcp_configs") for stage in stages):
            raise KimiBenchInventoryError(
                f"{case_id}: only SA.03 may add MCP to the subagent variant"
            )
        semantic_binding = {
            "binding_class": "M",
            "variant_kind": "native",
            "translation": "kimi_agent_coder_exact_artifact_v1",
            "status": "reviewed_materializable",
        }

    elif suite_name == "T3_compaction_resume_poisoning":
        mechanism = (meta.get("boundary_runtime_contract") or {}).get("mechanism")
        if mechanism == "exact_workspace_artifact_across_fresh_process":
            if stage_count != 2:
                raise KimiBenchInventoryError(
                    f"{case_id}: workspace-state case must have two stages"
                )
            execution_class = "neutral_workspace_saved_state"
            binding_kind = "neutral"
            capabilities.update({"fresh_process", "artifact_hash_provenance"})
        elif mechanism == "real_claude_session_resume":
            if stage_count != 2:
                raise KimiBenchInventoryError(
                    f"{case_id}: native resume case must have two stages"
                )
            execution_class = "requires_kimi_native_session_resume"
            binding_kind = "native"
            capabilities.update(
                {"session_resume", "fresh_process", "artifact_hash_provenance"}
            )
            semantic_binding = {
                "binding_class": "M",
                "variant_kind": "native",
                "translation": "kimi_exact_native_session_resume_v1",
                "status": "reviewed_materializable",
            }
        elif mechanism == "real_claude_compaction_then_resume":
            if stage_count != 3:
                raise KimiBenchInventoryError(
                    f"{case_id}: compact/resume case must have three stages"
                )
            execution_class = "requires_kimi_native_compaction_resume"
            binding_kind = "native"
            capabilities.update(
                {
                    "session_resume",
                    "session_compaction",
                    "fresh_process",
                    "artifact_hash_provenance",
                }
            )
            semantic_binding = {
                "binding_class": "M",
                "variant_kind": "native",
                "translation": "kimi_acp_exact_manual_compaction_resume_v1",
                "status": "reviewed_materializable",
            }
        else:
            raise KimiBenchInventoryError(
                f"{case_id}: unsupported compaction-suite mechanism: {mechanism!r}"
            )

    elif suite_name == "T3_shared_artifact_supply_chain":
        mechanism = (meta.get("boundary_runtime_contract") or {}).get("mechanism")
        if stage_count != 2 or mechanism != "exact_producer_to_fresh_consumer_artifact":
            raise KimiBenchInventoryError(
                f"{case_id}: shared-artifact case has unexpected runtime contract"
            )
        execution_class = "neutral_shared_artifact"
        binding_kind = "neutral"
        capabilities.update({"fresh_process", "artifact_hash_provenance"})

    else:  # protected by the manifest suite gate, retained as a local assertion
        raise KimiBenchInventoryError(f"unknown active suite: {suite_name!r}")

    restrictions = sorted(
        {
            harness
            for stage in stages
            for harness in stage.get("supported_harnesses", [])
        }
    )
    canonical_binding_usable = not restrictions or "kimi" in restrictions
    return {
        "execution_class": execution_class,
        "binding_kind": binding_kind,
        # The inventory describes requirements, not runtime proof.  Native
        # classes remain explicitly unvalidated until capability probes pass.
        "conformance_status": "UNVALIDATED",
        "requires_semantic_translation": binding_kind != "neutral",
        "canonical_harness_restrictions": restrictions,
        "canonical_binding_usable_by_kimi": canonical_binding_usable,
        # A reviewed M binding does not mutate or retroactively broaden the
        # canonical Claude-only row.  It authorizes a distinct, hash-bound
        # Kimi semantic variant whose runtime disposition is still decided by
        # real capability evidence.
        "kimi_semantic_binding": semantic_binding,
        "kimi_binding_usable_by_kimi": canonical_binding_usable
        or semantic_binding is not None,
        "required_capabilities": _ordered_capabilities(capabilities),
    }


def _inventory_digest(value: Mapping[str, Any]) -> str:
    body = dict(value)
    body.pop("inventory_content_sha256", None)
    return canonical_json_sha256(body)


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _manifest_active_suites(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    suites = manifest.get("suites")
    if not isinstance(suites, dict):
        raise KimiBenchInventoryError("runs/manifest.json suites must be an object")
    active: dict[str, Mapping[str, Any]] = {}
    for name, suite in suites.items():
        if not isinstance(name, str) or not isinstance(suite, dict):
            raise KimiBenchInventoryError("manifest suite entries must be named objects")
        if suite.get("status") == "active":
            active[name] = suite
    if set(active) != set(EXPECTED_SUITE_COUNTS):
        raise KimiBenchInventoryError(
            "active suite set drifted: "
            f"expected {list(EXPECTED_SUITE_COUNTS)}, got {sorted(active)}"
        )
    return active


def build_active_inventory(repo_root: Path | str | None = None) -> dict[str, Any]:
    """Build a deterministic, read-only inventory from the canonical tree."""

    root = Path(repo_root).resolve() if repo_root is not None else default_repo_root()
    manifest_path = root / "runs" / "manifest.json"
    if not manifest_path.is_file():
        raise KimiBenchInventoryError(f"active manifest is missing: {manifest_path}")
    _plain_path(manifest_path, label="active manifest")
    manifest, manifest_raw = _load_json_object(manifest_path)
    version = manifest.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version != MANIFEST_VERSION:
        raise KimiBenchInventoryError(
            f"manifest version drifted: expected {MANIFEST_VERSION}, got {version!r}"
        )
    active_suites = _manifest_active_suites(manifest)

    records: list[dict[str, Any]] = []
    case_ids: set[str] = set()
    case_dirs: set[str] = set()
    stage_total = 0

    # Preserve the explicit Kimi suite order, independent of JSON object
    # insertion order, so the frozen artifact is deterministic.
    for suite_name, expected_count in EXPECTED_SUITE_COUNTS.items():
        suite = active_suites[suite_name]
        entries = suite.get("cases")
        if not isinstance(entries, list) or len(entries) != expected_count:
            actual = len(entries) if isinstance(entries, list) else "non-array"
            raise KimiBenchInventoryError(
                f"{suite_name}: expected {expected_count} cases, got {actual}"
            )
        for manifest_index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise KimiBenchInventoryError(
                    f"{suite_name}.cases[{manifest_index}] must be an object"
                )
            manifest_case_dir = entry.get("case_dir")
            if not isinstance(manifest_case_dir, str):
                raise KimiBenchInventoryError(
                    f"{suite_name}.cases[{manifest_index}].case_dir must be a string"
                )
            if manifest_case_dir in case_dirs:
                raise KimiBenchInventoryError(
                    f"duplicate manifest case_dir: {manifest_case_dir!r}"
                )
            case_dirs.add(manifest_case_dir)
            absolute_case_dir = resolve_manifest_case_dir(root, manifest_case_dir)
            meta_path = absolute_case_dir / "case_meta.json"
            if not meta_path.is_file():
                raise KimiBenchInventoryError(f"case metadata is missing: {meta_path}")
            _plain_path(meta_path, label="case metadata")
            meta, meta_raw = _load_json_object(meta_path)

            meta_case_dir = meta.get("case_dir")
            if meta_case_dir != manifest_case_dir:
                raise KimiBenchInventoryError(
                    f"{manifest_case_dir}: case_meta case_dir mismatch: {meta_case_dir!r}"
                )
            for field in _FRAME_FIELDS:
                value = meta.get(field)
                if not isinstance(value, str) or not value.strip():
                    raise KimiBenchInventoryError(
                        f"{manifest_case_dir}: case_meta {field} must be a non-empty string"
                    )
            meta_case_id = meta.get("case_id")
            if not isinstance(meta_case_id, str) or not meta_case_id.strip():
                raise KimiBenchInventoryError(
                    f"{manifest_case_dir}: case_meta case_id must be a non-empty string"
                )
            manifest_case_id = entry.get("case_id")
            if manifest_case_id is None:
                if suite_name != "v2_tool_mcp_runtime":
                    raise KimiBenchInventoryError(
                        f"{manifest_case_dir}: only F3 entries may derive case_id from metadata"
                    )
                case_id = meta_case_id
                case_id_source = "case_meta"
            else:
                if not isinstance(manifest_case_id, str) or not manifest_case_id.strip():
                    raise KimiBenchInventoryError(
                        f"{manifest_case_dir}: manifest case_id must be a non-empty string"
                    )
                if manifest_case_id != meta_case_id:
                    raise KimiBenchInventoryError(
                        f"{manifest_case_dir}: manifest/meta case_id mismatch"
                    )
                case_id = manifest_case_id
                case_id_source = "manifest"
            if case_id in case_ids:
                raise KimiBenchInventoryError(f"duplicate case_id: {case_id!r}")
            case_ids.add(case_id)

            stages = _stage_records(meta, case_id=case_id)
            stage_total += len(stages)
            classification = _execution_classification(
                suite_name, meta, stages, case_id=case_id
            )
            content = canonical_case_content_record(absolute_case_dir)
            records.append(
                {
                    "suite": suite_name,
                    "manifest_index": manifest_index,
                    "case_id": case_id,
                    "case_id_source": case_id_source,
                    "case_dir": f"runs/{manifest_case_dir}",
                    "manifest_case_dir": manifest_case_dir,
                    "manifest_entry_canonical_sha256": canonical_json_sha256(entry),
                    "case_meta_file_sha256": _sha256_bytes(meta_raw),
                    "case_meta_canonical_sha256": content[
                        "case_meta_canonical_sha256"
                    ],
                    "control_contracts_canonical_sha256": content[
                        "control_contracts_canonical_sha256"
                    ],
                    "runtime_inputs_tree_sha256": content[
                        "runtime_inputs_tree_sha256"
                    ],
                    "runtime_input_file_count": content["runtime_inputs"]["file_count"],
                    "runtime_input_total_bytes": content["runtime_inputs"]["total_bytes"],
                    "case_content_sha256": content["case_content_sha256"],
                    "stage_count": len(stages),
                    "stages": stages,
                    **classification,
                }
            )

    if len(records) != EXPECTED_CASE_COUNT:
        raise KimiBenchInventoryError(
            f"active case count drifted: expected {EXPECTED_CASE_COUNT}, got {len(records)}"
        )
    if stage_total != EXPECTED_STAGE_COUNT:
        raise KimiBenchInventoryError(
            f"active stage count drifted: expected {EXPECTED_STAGE_COUNT}, got {stage_total}"
        )

    execution_profile_counts: dict[str, int] = {}
    for record in records:
        key = record["execution_class"]
        execution_profile_counts[key] = execution_profile_counts.get(key, 0) + 1
    inventory: dict[str, Any] = {
        "schema_name": INVENTORY_SCHEMA_NAME,
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "harness_id": "kimi",
        "manifest": {
            "path": "runs/manifest.json",
            "version": MANIFEST_VERSION,
            "file_sha256": _sha256_bytes(manifest_raw),
            "canonical_sha256": canonical_json_sha256(manifest),
        },
        "case_count": len(records),
        "stage_count": stage_total,
        "suite_counts": dict(EXPECTED_SUITE_COUNTS),
        "execution_profile_counts": dict(sorted(execution_profile_counts.items())),
        "cases": records,
    }
    inventory["inventory_content_sha256"] = _inventory_digest(inventory)
    return inventory


def validate_frozen_inventory(value: Mapping[str, Any]) -> None:
    if value.get("schema_name") != INVENTORY_SCHEMA_NAME:
        raise KimiBenchInventoryError("frozen inventory has an unexpected schema_name")
    if value.get("schema_version") != INVENTORY_SCHEMA_VERSION:
        raise KimiBenchInventoryError("frozen inventory has an unexpected schema_version")
    if value.get("harness_id") != "kimi":
        raise KimiBenchInventoryError("frozen inventory harness_id must be kimi")
    if value.get("case_count") != EXPECTED_CASE_COUNT:
        raise KimiBenchInventoryError("frozen inventory case count is not 328")
    if value.get("stage_count") != EXPECTED_STAGE_COUNT:
        raise KimiBenchInventoryError("frozen inventory stage count is not 690")
    if value.get("suite_counts") != EXPECTED_SUITE_COUNTS:
        raise KimiBenchInventoryError("frozen inventory suite counts drifted")
    cases = value.get("cases")
    if not isinstance(cases, list) or len(cases) != EXPECTED_CASE_COUNT:
        raise KimiBenchInventoryError("frozen inventory cases must contain 328 records")
    manifest = value.get("manifest")
    if not isinstance(manifest, Mapping) or manifest.get("version") != MANIFEST_VERSION:
        raise KimiBenchInventoryError("frozen inventory manifest record is invalid")
    if not _is_sha256(manifest.get("file_sha256")) or not _is_sha256(
        manifest.get("canonical_sha256")
    ):
        raise KimiBenchInventoryError("frozen inventory manifest hashes are invalid")

    observed_suites: dict[str, int] = {}
    observed_profiles: dict[str, int] = {}
    observed_stage_count = 0
    case_ids: set[str] = set()
    case_dirs: set[str] = set()
    hash_fields = (
        "manifest_entry_canonical_sha256",
        "case_meta_file_sha256",
        "case_meta_canonical_sha256",
        "control_contracts_canonical_sha256",
        "runtime_inputs_tree_sha256",
        "case_content_sha256",
    )
    for index, case in enumerate(cases):
        if not isinstance(case, Mapping):
            raise KimiBenchInventoryError(f"frozen case record {index} is not an object")
        case_id = case.get("case_id")
        case_dir = case.get("case_dir")
        suite = case.get("suite")
        profile = case.get("execution_class")
        if not isinstance(case_id, str) or not case_id or case_id in case_ids:
            raise KimiBenchInventoryError(
                f"frozen case record {index} has an invalid or duplicate case_id"
            )
        if not isinstance(case_dir, str) or not case_dir or case_dir in case_dirs:
            raise KimiBenchInventoryError(
                f"frozen case record {index} has an invalid or duplicate case_dir"
            )
        if not isinstance(suite, str) or suite not in EXPECTED_SUITE_COUNTS:
            raise KimiBenchInventoryError(f"frozen case record {index} has unknown suite")
        if not isinstance(profile, str) or not profile:
            raise KimiBenchInventoryError(
                f"frozen case record {index} has no execution_class"
            )
        if any(not _is_sha256(case.get(field)) for field in hash_fields):
            raise KimiBenchInventoryError(
                f"frozen case record {index} contains an invalid content hash"
            )
        stages = case.get("stages")
        stage_count = case.get("stage_count")
        if (
            not isinstance(stages, list)
            or not isinstance(stage_count, int)
            or isinstance(stage_count, bool)
            or stage_count != len(stages)
            or stage_count < 1
        ):
            raise KimiBenchInventoryError(
                f"frozen case record {index} has inconsistent stages"
            )
        capabilities = case.get("required_capabilities")
        if (
            not isinstance(capabilities, list)
            or any(not isinstance(item, str) for item in capabilities)
            or len(capabilities) != len(set(capabilities))
            or set(capabilities) - CAPABILITIES
        ):
            raise KimiBenchInventoryError(
                f"frozen case record {index} has invalid required capabilities"
            )
        if case.get("conformance_status") != "UNVALIDATED":
            raise KimiBenchInventoryError(
                f"frozen case record {index} must not claim runtime validation"
            )
        semantic_binding = case.get("kimi_semantic_binding")
        if semantic_binding is not None:
            if not isinstance(semantic_binding, Mapping):
                raise KimiBenchInventoryError(
                    f"frozen case record {index} has an invalid Kimi semantic binding"
                )
            if (
                semantic_binding.get("binding_class") != "M"
                or semantic_binding.get("variant_kind") != "native"
                or semantic_binding.get("status") != "reviewed_materializable"
                or semantic_binding.get("translation")
                not in {
                    "kimi_agent_coder_exact_artifact_v1",
                    "kimi_exact_native_session_resume_v1",
                    "kimi_acp_exact_manual_compaction_resume_v1",
                }
            ):
                raise KimiBenchInventoryError(
                    f"frozen case record {index} has an unreviewed Kimi semantic binding"
                )
        canonical_usable = case.get("canonical_binding_usable_by_kimi")
        kimi_usable = case.get("kimi_binding_usable_by_kimi")
        if not isinstance(canonical_usable, bool) or not isinstance(kimi_usable, bool):
            raise KimiBenchInventoryError(
                f"frozen case record {index} has invalid binding usability flags"
            )
        if kimi_usable != (canonical_usable or semantic_binding is not None):
            raise KimiBenchInventoryError(
                f"frozen case record {index} has inconsistent Kimi binding usability"
            )
        case_ids.add(case_id)
        case_dirs.add(case_dir)
        observed_stage_count += stage_count
        observed_suites[suite] = observed_suites.get(suite, 0) + 1
        observed_profiles[profile] = observed_profiles.get(profile, 0) + 1
    if observed_suites != EXPECTED_SUITE_COUNTS:
        raise KimiBenchInventoryError("frozen case records do not match suite counts")
    if observed_stage_count != EXPECTED_STAGE_COUNT:
        raise KimiBenchInventoryError("frozen case records do not contain 690 stages")
    if value.get("execution_profile_counts") != dict(sorted(observed_profiles.items())):
        raise KimiBenchInventoryError("frozen execution profile counts are inconsistent")
    expected_digest = _inventory_digest(value)
    if value.get("inventory_content_sha256") != expected_digest:
        raise KimiBenchInventoryError("frozen inventory self-digest mismatch")


def _drift_summary(live: Mapping[str, Any], frozen: Mapping[str, Any]) -> str:
    live_manifest = live.get("manifest") or {}
    frozen_manifest = frozen.get("manifest") or {}
    if live_manifest != frozen_manifest:
        return (
            "manifest digest changed "
            f"(frozen={frozen_manifest.get('file_sha256')}, "
            f"live={live_manifest.get('file_sha256')})"
        )
    live_cases = live.get("cases") or []
    frozen_cases = frozen.get("cases") or []
    for index, (live_case, frozen_case) in enumerate(zip(live_cases, frozen_cases)):
        if live_case != frozen_case:
            return (
                f"case record {index} changed "
                f"(frozen={frozen_case.get('case_id')}, live={live_case.get('case_id')})"
            )
    if len(live_cases) != len(frozen_cases):
        return f"case record length changed ({len(frozen_cases)} -> {len(live_cases)})"
    return "inventory metadata or classifier output changed"


def load_frozen_inventory(
    repo_root: Path | str | None = None,
    *,
    snapshot_path: Path | str | None = None,
    verify_live: bool = True,
) -> dict[str, Any]:
    """Load the Kimi snapshot and, by default, fail closed on live drift."""

    root = Path(repo_root).resolve() if repo_root is not None else default_repo_root()
    path = Path(snapshot_path).resolve() if snapshot_path else default_snapshot_path(root)
    frozen, _ = _load_json_object(path)
    validate_frozen_inventory(frozen)
    if verify_live:
        live = build_active_inventory(root)
        if live != frozen:
            raise KimiBenchInventoryDriftError(
                "Kimi active inventory drifted; regenerate and review the Kimi-owned "
                f"snapshot before execution: {_drift_summary(live, frozen)}"
            )
    return frozen


def _validated_snapshot_write_path(root: Path, requested: Path) -> Path:
    owned_root = (
        root / "infra" / "cross_harness" / "bindings" / "kimi"
    ).resolve(strict=True)
    target = requested.resolve(strict=False)
    try:
        relative = target.relative_to(owned_root)
    except ValueError as exc:
        raise KimiBenchInventoryError(
            "inventory snapshots may be written only below "
            "infra/cross_harness/bindings/kimi"
        ) from exc
    if not relative.parts:
        raise KimiBenchInventoryError("inventory snapshot path must name a file")
    cursor = owned_root
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor.exists():
            _plain_path(cursor, label="inventory snapshot parent")
    if target.exists():
        _plain_path(target, label="inventory snapshot")
        if not target.is_file():
            raise KimiBenchInventoryError("inventory snapshot target is not a file")
    return target


def write_frozen_inventory(
    repo_root: Path | str | None = None,
    *,
    snapshot_path: Path | str | None = None,
) -> dict[str, Any]:
    """Regenerate only the deterministic Kimi-owned inventory snapshot."""

    root = Path(repo_root).resolve() if repo_root is not None else default_repo_root()
    requested = Path(snapshot_path) if snapshot_path else default_snapshot_path(root)
    path = _validated_snapshot_write_path(root, requested)
    inventory = build_active_inventory(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return inventory


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=default_repo_root())
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate the deterministic Kimi-owned snapshot",
    )
    args = parser.parse_args(argv)
    if args.write:
        inventory = write_frozen_inventory(
            args.repo_root,
            snapshot_path=args.snapshot,
        )
        action = "wrote"
    else:
        inventory = load_frozen_inventory(
            args.repo_root,
            snapshot_path=args.snapshot,
            verify_live=True,
        )
        action = "verified"
    print(
        f"{action} Kimi inventory: {inventory['case_count']} cases, "
        f"{inventory['stage_count']} stages, "
        f"sha256={inventory['inventory_content_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
