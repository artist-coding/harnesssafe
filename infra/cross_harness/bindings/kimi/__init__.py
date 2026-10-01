"""Versioned Kimi bindings derived from the common-case selection only."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from ...contract import ContractValidationError, validate_binding_document


BINDING_DIR = Path(__file__).with_name("common_surface_v1")
NO_NATIVE_BINDING_CASES = frozenset(
    {"F3_mcp_result_instruction_same_session_001"}
)


def _safe_relative(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ContractValidationError(f"{label} must be a non-empty path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ContractValidationError(f"{label} must be repository-relative and safe")


def validate_kimi_binding(document: Mapping[str, Any]) -> None:
    """Apply Kimi-private invariants without changing the shared schema."""

    validate_binding_document(document)
    kimi = document["harness_native_binding"].get("kimi")
    if kimi is None:
        if (
            document["case_id"] not in NO_NATIVE_BINDING_CASES
            or document["supported_harnesses"]["kimi"]["status"] != "unvalidated"
        ):
            raise ContractValidationError(
                "a missing Kimi binding is allowed only for the reviewed N/A case"
            )
        return
    if not isinstance(kimi, Mapping):
        raise ContractValidationError("Kimi binding must be an object")
    if kimi.get("adapter") != "kimi.adapter_v1":
        raise ContractValidationError("Kimi adapter must be kimi.adapter_v1")
    config = kimi.get("config")
    if not isinstance(config, Mapping):
        raise ContractValidationError("Kimi config must be an object")
    if config.get("binding_class") not in {"D", "M", "N/A"}:
        raise ContractValidationError("Kimi config.binding_class must be D, M, or N/A")
    stages = config.get("stages")
    if not isinstance(stages, list) or not stages:
        raise ContractValidationError("Kimi config.stages must be non-empty")
    seen_stage_indexes: set[int] = set()
    for index, stage in enumerate(stages):
        if not isinstance(stage, Mapping):
            raise ContractValidationError(f"Kimi stage {index} must be an object")
        stage_index = stage.get("index")
        if (
            not isinstance(stage_index, int)
            or isinstance(stage_index, bool)
            or stage_index < 0
            or stage_index in seen_stage_indexes
        ):
            raise ContractValidationError(
                f"Kimi stage {index} index must be unique and non-negative"
            )
        seen_stage_indexes.add(stage_index)
        if not isinstance(stage.get("name"), str) or not stage["name"].strip():
            raise ContractValidationError(f"Kimi stage {index} name must be non-empty")
        for skill in stage.get("skills", []):
            _safe_relative(skill, f"Kimi stage {index} skill")
        if stage.get("mcp_config") is not None:
            _safe_relative(stage["mcp_config"], f"Kimi stage {index} MCP config")
    for index, instruction in enumerate(config.get("instructions", [])):
        if not isinstance(instruction, Mapping):
            raise ContractValidationError(f"Kimi instruction {index} must be an object")
        _safe_relative(instruction.get("source"), f"Kimi instruction {index} source")
        _safe_relative(instruction.get("target"), f"Kimi instruction {index} target")
    for index, artifact in enumerate(config.get("callback_artifacts", [])):
        _safe_relative(artifact, f"Kimi callback artifact {index}")


def load_kimi_common_bindings(
    *, repo_root: Path | None = None
) -> dict[str, dict[str, Any]]:
    """Load all 11 candidates and optionally verify the Codex source inventory.

    The Codex inventory is used only to freeze case selection, paths, and
    canonical hashes. Kimi support states live exclusively in these documents.
    """

    documents: dict[str, dict[str, Any]] = {}
    for path in sorted(BINDING_DIR.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        validate_kimi_binding(document)
        case_id = document["case_id"]
        if case_id in documents:
            raise ContractValidationError(f"duplicate Kimi case_id: {case_id}")
        documents[case_id] = document
    if len(documents) != 11:
        raise ContractValidationError(
            f"Kimi common binding set must contain 11 cases, found {len(documents)}"
        )

    if repo_root is not None:
        inventory_path = repo_root / "docs" / "codex_conformance_smoke_v1.json"
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        common = {
            entry["case_id"]: entry
            for entry in inventory["cases"]
            if entry["surface_class"] == "common"
        }
        if set(documents) != set(common):
            raise ContractValidationError(
                "Kimi bindings must match the 11 common case IDs selected by the "
                "Codex inventory"
            )
        for case_id, document in documents.items():
            source = common[case_id]
            if document["case_meta_sha256"] != source["case_meta_sha256"]:
                raise ContractValidationError(f"Kimi binding hash drift for {case_id}")
            meta_path = repo_root / source["case_dir"] / "case_meta.json"
            observed = hashlib.sha256(meta_path.read_bytes()).hexdigest()
            if observed != document["case_meta_sha256"]:
                raise ContractValidationError(f"canonical case hash drift for {case_id}")
            if document["supported_harnesses"]["kimi"]["status"] != "unvalidated":
                raise ContractValidationError(
                    "Kimi support must remain unvalidated until runtime conformance"
                )
    return documents


__all__ = [
    "BINDING_DIR",
    "NO_NATIVE_BINDING_CASES",
    "load_kimi_common_bindings",
    "validate_kimi_binding",
]
