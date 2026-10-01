"""Versioned Gemini CLI bindings for smoke and the complete active suite."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from ...contract import ContractValidationError, validate_binding_document


COMMON_BINDING_DIR = Path(__file__).with_name("common_surface_v1")
NATIVE_BINDING_DIR = Path(__file__).with_name("native_surface_v1")
FULL_SUITE_BINDING_DIR = Path(__file__).with_name("active_328_v1")
BINDING_DIRS = (COMMON_BINDING_DIR, NATIVE_BINDING_DIR)
# Compatibility alias for callers that only enumerate the common cohort.
BINDING_DIR = COMMON_BINDING_DIR
EXPECTED_COMMON_BINDING_COUNT = 11
EXPECTED_NATIVE_BINDING_COUNT = 5
EXPECTED_SMOKE_BINDING_COUNT = 16
EXPECTED_FULL_SUITE_BINDING_COUNT = 328
EXPECTED_EXPANDED_BINDING_COUNT = 312


def _safe_relative(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ContractValidationError(f"{label} must be a non-empty path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ContractValidationError(f"{label} must be repository-relative and safe")


def validate_gemini_binding(document: Mapping[str, Any]) -> None:
    """Apply Gemini-private invariants without changing the shared schema."""

    validate_binding_document(document)
    support = document["supported_harnesses"]["gemini"]
    if support["status"] != "unvalidated":
        raise ContractValidationError(
            "Gemini support must remain unvalidated until version-pinned runtime "
            "conformance evidence is committed"
        )
    native = document["harness_native_binding"].get("gemini")
    if not isinstance(native, Mapping):
        raise ContractValidationError("every smoke case needs a Gemini candidate binding")
    if native.get("adapter") != "gemini.adapter_v1":
        raise ContractValidationError("Gemini adapter must be gemini.adapter_v1")
    config = native.get("config")
    if not isinstance(config, Mapping):
        raise ContractValidationError("Gemini config must be an object")
    if config.get("binding_class") not in {"D", "M", "N/A"}:
        raise ContractValidationError("Gemini binding_class must be D, M, or N/A")
    if config.get("binding_kind") not in {"native", "hybrid", "neutral"}:
        raise ContractValidationError(
            "Gemini binding_kind must be native, hybrid, or neutral"
        )
    if config.get("disposition") not in {"READY", "NOT_RUN", "BLOCKED"}:
        raise ContractValidationError(
            "Gemini disposition must be READY, NOT_RUN, or BLOCKED"
        )
    blocking_reasons = config.get("blocking_reasons")
    if (
        not isinstance(blocking_reasons, list)
        or any(not isinstance(item, str) or not item.strip() for item in blocking_reasons)
        or (config["disposition"] != "READY" and not blocking_reasons)
    ):
        raise ContractValidationError(
            "non-READY Gemini bindings need non-empty blocking_reasons"
        )
    expected_normalized = config.get("expected_normalized_events")
    if expected_normalized != native.get("expected_event_types"):
        raise ContractValidationError(
            "expected_normalized_events must equal Contract expected_event_types"
        )
    stages = config.get("stages")
    if not isinstance(stages, list) or not stages:
        raise ContractValidationError("Gemini config.stages must be non-empty")
    seen: set[int] = set()
    for position, stage in enumerate(stages):
        if not isinstance(stage, Mapping):
            raise ContractValidationError(f"Gemini stage {position} must be an object")
        index = stage.get("index")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
            or index in seen
        ):
            raise ContractValidationError(
                f"Gemini stage {position} index must be unique and non-negative"
            )
        seen.add(index)
        if not isinstance(stage.get("name"), str) or not stage["name"].strip():
            raise ContractValidationError(f"Gemini stage {position} name must be non-empty")
        for skill in stage.get("skills", []):
            _safe_relative(skill, f"Gemini stage {position} skill")
        if stage.get("mcp_config") is not None:
            _safe_relative(stage["mcp_config"], f"Gemini stage {position} MCP config")
        replacements = stage.get("prompt_replacements", [])
        if not isinstance(replacements, list):
            raise ContractValidationError(
                f"Gemini stage {position} prompt_replacements must be an array"
            )
        for replacement_index, replacement in enumerate(replacements):
            if (
                not isinstance(replacement, Mapping)
                or set(replacement) != {"source", "target"}
                or not isinstance(replacement["source"], str)
                or not replacement["source"]
                or not isinstance(replacement["target"], str)
            ):
                raise ContractValidationError(
                    f"Gemini stage {position} prompt replacement "
                    f"{replacement_index} is invalid"
                )
    for position, instruction in enumerate(config.get("instructions", [])):
        if not isinstance(instruction, Mapping):
            raise ContractValidationError(
                f"Gemini instruction {position} must be an object"
            )
        _safe_relative(instruction.get("source"), f"Gemini instruction {position} source")
        _safe_relative(instruction.get("target"), f"Gemini instruction {position} target")
        if instruction.get("translation") != "gemini_project_instruction_v1":
            raise ContractValidationError(
                f"Gemini instruction {position} uses an unreviewed translation"
            )
    for position, instruction in enumerate(config.get("generated_instructions", [])):
        if not isinstance(instruction, Mapping):
            raise ContractValidationError(
                f"Gemini generated instruction {position} must be an object"
            )
        _safe_relative(
            instruction.get("path"),
            f"Gemini generated instruction {position} path",
        )
        producer_stage = instruction.get("producer_stage_index")
        if (
            not isinstance(producer_stage, int)
            or isinstance(producer_stage, bool)
            or producer_stage < 0
        ):
            raise ContractValidationError(
                f"Gemini generated instruction {position} producer_stage_index "
                "must be non-negative"
            )
    for position, relocation in enumerate(config.get("workspace_relocations", [])):
        if not isinstance(relocation, Mapping):
            raise ContractValidationError(
                f"Gemini relocation {position} must be an object"
            )
        _safe_relative(relocation.get("source"), f"Gemini relocation {position} source")
        _safe_relative(relocation.get("target"), f"Gemini relocation {position} target")
        frontmatter = relocation.get("ensure_skill_frontmatter")
        if frontmatter is not None and (
            not isinstance(frontmatter, Mapping)
            or not isinstance(frontmatter.get("name"), str)
            or not frontmatter["name"].strip()
            or not isinstance(frontmatter.get("description"), str)
            or not frontmatter["description"].strip()
        ):
            raise ContractValidationError(
                f"Gemini relocation {position} skill frontmatter is invalid"
            )
    for position, memory in enumerate(config.get("memory_bindings", [])):
        if not isinstance(memory, Mapping):
            raise ContractValidationError(f"Gemini memory binding {position} must be an object")
        _safe_relative(memory.get("path"), f"Gemini memory binding {position} path")
        for key in ("store", "scope", "entry_id"):
            if not isinstance(memory.get(key), str) or not memory[key].strip():
                raise ContractValidationError(
                    f"Gemini memory binding {position} {key} must be non-empty"
                )
    for position, agent in enumerate(config.get("agents", [])):
        if not isinstance(agent, Mapping):
            raise ContractValidationError(f"Gemini agent {position} must be an object")
        for key in ("name", "description", "prompt"):
            if not isinstance(agent.get(key), str) or not agent[key].strip():
                raise ContractValidationError(
                    f"Gemini agent {position} {key} must be non-empty"
                )
        _safe_relative(agent.get("target"), f"Gemini agent {position} target")


def _load_binding_dirs(
    binding_dirs: tuple[Path, ...], *, expected_count: int
) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for binding_dir in binding_dirs:
        for path in sorted(binding_dir.glob("*.json")):
            document = json.loads(path.read_text(encoding="utf-8"))
            validate_gemini_binding(document)
            case_id = document["case_id"]
            if case_id in documents:
                raise ContractValidationError(f"duplicate Gemini case_id: {case_id}")
            documents[case_id] = document
    if len(documents) != expected_count:
        raise ContractValidationError(
            f"Gemini binding set must contain {expected_count} cases, "
            f"found {len(documents)}"
        )
    return documents


def _verify_inventory(
    documents: Mapping[str, Mapping[str, Any]],
    *, repo_root: Path,
    expected_surface: str | None,
) -> None:
    inventory_path = repo_root / "docs" / "codex_conformance_smoke_v1.json"
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    selected = {
        entry["case_id"]: entry
        for entry in inventory["cases"]
        if expected_surface is None or entry["surface_class"] == expected_surface
    }
    if set(documents) != set(selected):
        label = expected_surface or "complete"
        raise ContractValidationError(
            f"Gemini bindings must match the frozen {label} smoke inventory"
        )
    for case_id, document in documents.items():
        source = selected[case_id]
        if document["case_meta_sha256"] != source["case_meta_sha256"]:
            raise ContractValidationError(f"Gemini binding hash drift for {case_id}")
        meta_path = repo_root / source["case_dir"] / "case_meta.json"
        observed = hashlib.sha256(meta_path.read_bytes()).hexdigest()
        if observed != document["case_meta_sha256"]:
            raise ContractValidationError(f"canonical case hash drift for {case_id}")


def load_gemini_common_bindings(
    *, repo_root: Path | None = None
) -> dict[str, dict[str, Any]]:
    """Load the 11 common candidates and verify their frozen source hashes."""

    documents = _load_binding_dirs(
        (COMMON_BINDING_DIR,), expected_count=EXPECTED_COMMON_BINDING_COUNT
    )
    if repo_root is not None:
        _verify_inventory(
            documents, repo_root=repo_root, expected_surface="common"
        )
    return documents


def load_gemini_smoke_bindings(
    *, repo_root: Path | None = None
) -> dict[str, dict[str, Any]]:
    """Load all 16 common/native smoke candidates and verify source hashes."""

    documents = _load_binding_dirs(
        BINDING_DIRS, expected_count=EXPECTED_SMOKE_BINDING_COUNT
    )
    if repo_root is not None:
        _verify_inventory(documents, repo_root=repo_root, expected_surface=None)
    return documents


def load_gemini_all_bindings(
    *, repo_root: Path | None = None
) -> dict[str, dict[str, Any]]:
    """Load one validated Gemini binding for every active canonical case."""

    smoke = _load_binding_dirs(
        BINDING_DIRS, expected_count=EXPECTED_SMOKE_BINDING_COUNT
    )
    expanded = _load_binding_dirs(
        (FULL_SUITE_BINDING_DIR,), expected_count=EXPECTED_EXPANDED_BINDING_COUNT
    )
    overlap = sorted(set(smoke) & set(expanded))
    if overlap:
        raise ContractValidationError(
            f"expanded Gemini binding set duplicates smoke cases: {overlap}"
        )
    documents = {**smoke, **expanded}
    if len(documents) != EXPECTED_FULL_SUITE_BINDING_COUNT:
        raise ContractValidationError(
            "complete Gemini binding set must contain exactly 328 cases"
        )
    if repo_root is not None:
        inventory = json.loads(
            (repo_root / "infra/cross_harness/bindings/gemini/active_328_v1.json")
            .read_text(encoding="utf-8")
        )
        selected = {entry["case_id"]: entry for entry in inventory["cases"]}
        if set(documents) != set(selected):
            raise ContractValidationError(
                "complete Gemini bindings must match the active 328 inventory"
            )
        for case_id, document in documents.items():
            source = selected[case_id]
            if document["case_meta_sha256"] != source["case_meta_sha256"]:
                raise ContractValidationError(
                    f"Gemini full-suite binding hash drift for {case_id}"
                )
            meta_path = repo_root / source["case_dir"] / "case_meta.json"
            observed = hashlib.sha256(meta_path.read_bytes()).hexdigest()
            if observed != document["case_meta_sha256"]:
                raise ContractValidationError(
                    f"canonical active case hash drift for {case_id}"
                )
    return documents


__all__ = [
    "BINDING_DIR",
    "BINDING_DIRS",
    "COMMON_BINDING_DIR",
    "FULL_SUITE_BINDING_DIR",
    "NATIVE_BINDING_DIR",
    "EXPECTED_COMMON_BINDING_COUNT",
    "EXPECTED_NATIVE_BINDING_COUNT",
    "EXPECTED_SMOKE_BINDING_COUNT",
    "EXPECTED_FULL_SUITE_BINDING_COUNT",
    "EXPECTED_EXPANDED_BINDING_COUNT",
    "load_gemini_all_bindings",
    "load_gemini_common_bindings",
    "load_gemini_smoke_bindings",
    "validate_gemini_binding",
]
