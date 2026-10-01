"""Versioned OpenCode Contract v1 smoke bindings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from ...contract import ContractValidationError, validate_binding_document


BINDING_DIR = Path(__file__).with_name("smoke_v1")
EXPECTED_BINDING_COUNT = 16


def validate_opencode_binding(document: Mapping[str, Any]) -> None:
    validate_binding_document(document)
    support = document["supported_harnesses"]["opencode"]
    native = document["harness_native_binding"].get("opencode")
    if support["status"] == "unsupported":
        if native is not None:
            raise ContractValidationError(
                "unsupported OpenCode smoke surfaces must not have a runnable binding"
            )
        return
    if support["status"] != "unvalidated":
        raise ContractValidationError(
            "OpenCode smoke candidates remain unvalidated until exact-binary "
            "runtime conformance evidence is committed"
        )
    if not isinstance(native, Mapping):
        raise ContractValidationError(
            "an unvalidated OpenCode candidate needs a native binding"
        )
    if native.get("adapter") != "opencode.adapter_v1":
        raise ContractValidationError(
            "OpenCode adapter must be opencode.adapter_v1"
        )
    config = native.get("config")
    if not isinstance(config, Mapping):
        raise ContractValidationError("OpenCode config must be an object")
    if config.get("disposition") != "NOT_RUN":
        raise ContractValidationError(
            "pre-conformance OpenCode smoke candidates must remain NOT_RUN"
        )
    stages = config.get("stages")
    if not isinstance(stages, list) or not stages:
        raise ContractValidationError("OpenCode config.stages must be non-empty")
    seen: set[int] = set()
    for position, stage in enumerate(stages):
        if not isinstance(stage, Mapping):
            raise ContractValidationError(
                f"OpenCode stage {position} must be an object"
            )
        index = stage.get("index")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
            or index in seen
        ):
            raise ContractValidationError(
                f"OpenCode stage {position} index must be unique and non-negative"
            )
        seen.add(index)
        if not isinstance(stage.get("name"), str) or not stage["name"].strip():
            raise ContractValidationError(
                f"OpenCode stage {position} name must be non-empty"
            )


def load_opencode_smoke_bindings(
    *, repo_root: Path | None = None
) -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for path in sorted(BINDING_DIR.glob("*.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        validate_opencode_binding(document)
        case_id = document["case_id"]
        if case_id in documents:
            raise ContractValidationError(
                f"duplicate OpenCode case_id: {case_id}"
            )
        documents[case_id] = document
    if len(documents) != EXPECTED_BINDING_COUNT:
        raise ContractValidationError(
            f"OpenCode smoke bindings must contain {EXPECTED_BINDING_COUNT} "
            f"cases, found {len(documents)}"
        )
    if repo_root is not None:
        root = Path(repo_root).resolve()
        inventory = json.loads(
            (root / "docs/codex_conformance_smoke_v1.json").read_text(
                encoding="utf-8"
            )
        )
        frozen = {row["case_id"]: row for row in inventory["cases"]}
        if set(documents) != set(frozen):
            raise ContractValidationError(
                "OpenCode bindings drifted from the frozen smoke inventory"
            )
        for case_id, document in documents.items():
            row = frozen[case_id]
            case_meta = root / row["case_dir"] / "case_meta.json"
            observed = hashlib.sha256(case_meta.read_bytes()).hexdigest()
            if (
                document["case_meta_sha256"] != row["case_meta_sha256"]
                or observed != row["case_meta_sha256"]
            ):
                raise ContractValidationError(
                    f"OpenCode canonical hash drift for {case_id}"
                )
    return documents


__all__ = [
    "BINDING_DIR",
    "EXPECTED_BINDING_COUNT",
    "load_opencode_smoke_bindings",
    "validate_opencode_binding",
]
