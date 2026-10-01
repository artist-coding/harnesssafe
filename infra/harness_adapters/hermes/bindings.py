from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from .model import BindingDisposition, HermesBinding


_REQUIRED_FIELDS = {
    "case_dir",
    "case_meta_sha256",
    "semantic_surface",
    "required_capabilities",
    "stage_runtime_modes",
    "expected_normalized_events",
    "disposition",
    "blocking_reasons",
}


def case_contract_sha256(case_meta_path: Path) -> str:
    return hashlib.sha256(case_meta_path.read_bytes()).hexdigest()


def _active_manifest_paths(repo_root: Path) -> set[str]:
    manifest = json.loads(
        (repo_root / "runs/manifest.json").read_text(encoding="utf-8-sig")
    )
    return {
        str(entry["case_dir"])
        for suite in manifest["suites"].values()
        if suite.get("status") == "active"
        for entry in suite.get("cases", [])
    }


def _validate_case_dir(value: object) -> str:
    case_dir = str(value)
    path = PurePosixPath(case_dir)
    if (
        path.is_absolute()
        or len(path.parts) < 2
        or path.parts[:1] != ("active",)
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"binding case_dir must remain under runs/active: {case_dir}")
    return path.as_posix()


def _string_tuple(value: object, field: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"binding field {field} must be a list of strings")
    result = tuple(value)
    if not allow_empty and not result:
        raise ValueError(f"binding field {field} must not be empty")
    return result


def _parse_binding(record: object, inventory_version: str) -> HermesBinding:
    if not isinstance(record, dict):
        raise ValueError("each Hermes binding must be a JSON object")
    missing = sorted(_REQUIRED_FIELDS - set(record))
    if missing:
        raise ValueError(f"Hermes binding is missing fields: {', '.join(missing)}")
    case_dir = _validate_case_dir(record["case_dir"])
    digest = str(record["case_meta_sha256"])
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError(f"invalid case metadata SHA-256 for {case_dir}")
    try:
        disposition = BindingDisposition(str(record["disposition"]))
    except ValueError as exc:
        raise ValueError(f"unknown Hermes binding disposition for {case_dir}") from exc
    return HermesBinding(
        case_dir=case_dir,
        case_meta_sha256=digest,
        semantic_surface=str(record["semantic_surface"]),
        required_capabilities=_string_tuple(
            record["required_capabilities"], "required_capabilities", allow_empty=False
        ),
        stage_runtime_modes=_string_tuple(
            record["stage_runtime_modes"], "stage_runtime_modes", allow_empty=False
        ),
        expected_normalized_events=_string_tuple(
            record["expected_normalized_events"], "expected_normalized_events"
        ),
        disposition=disposition,
        blocking_reasons=_string_tuple(record["blocking_reasons"], "blocking_reasons"),
        binding_version=inventory_version,
    )


def load_inventory(
    inventory_path: Path,
    *,
    repo_root: Path,
    require_manifest_match: bool = True,
) -> dict[str, HermesBinding]:
    payload = json.loads(inventory_path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict) or not isinstance(payload.get("bindings"), list):
        raise ValueError("Hermes inventory must contain a bindings list")
    version = str(payload.get("binding_version", ""))
    if version != "hermes-binding-v1":
        raise ValueError(f"unsupported Hermes binding version: {version}")

    bindings: dict[str, HermesBinding] = {}
    for record in payload["bindings"]:
        binding = _parse_binding(record, version)
        if binding.case_dir in bindings:
            raise ValueError(f"duplicate Hermes binding: {binding.case_dir}")
        bindings[binding.case_dir] = binding

    if require_manifest_match:
        manifest_paths = _active_manifest_paths(repo_root)
        inventory_paths = set(bindings)
        if inventory_paths != manifest_paths:
            missing = sorted(manifest_paths - inventory_paths)
            extra = sorted(inventory_paths - manifest_paths)
            raise ValueError(
                "Hermes inventory does not exactly match active manifest: "
                f"missing={missing[:3]} extra={extra[:3]}"
            )
    return bindings


def resolve_binding(binding: HermesBinding, case_dir: Path) -> HermesBinding:
    actual = case_contract_sha256(case_dir / "case_meta.json")
    if actual != binding.case_meta_sha256:
        raise ValueError(
            f"Hermes binding hash mismatch for {binding.case_dir}: "
            f"expected={binding.case_meta_sha256} actual={actual}"
        )
    return binding


def write_selected_binding(
    binding: HermesBinding,
    materialized_case_dir: Path,
    *,
    canonical_case_dir: Path | None = None,
) -> Path:
    resolve_binding(binding, canonical_case_dir or materialized_case_dir)
    target = materialized_case_dir / "harness_binding.json"
    payload = {"harness": "hermes", **binding.to_dict()}
    target.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return target
