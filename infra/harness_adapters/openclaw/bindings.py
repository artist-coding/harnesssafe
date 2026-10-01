from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath

from .model import BindingDisposition, OpenClawBinding


_FIELDS = {
    "binding_version", "case_dir", "case_meta_sha256", "semantic_surface",
    "comparison_group", "required_capabilities", "stage_runtime_modes",
    "expected_normalized_events", "disposition", "blocking_reasons",
}


def case_contract_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_paths(repo_root: Path) -> set[str]:
    manifest = json.loads((repo_root / "runs/manifest.json").read_text(encoding="utf-8-sig"))
    return {
        str(entry["case_dir"])
        for suite in manifest["suites"].values()
        if suite.get("status") == "active"
        for entry in suite.get("cases", [])
    }


def _strings(value: object, field: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    if nonempty and not value:
        raise ValueError(f"{field} must not be empty")
    return tuple(value)


def _parse(record: object, version: str) -> OpenClawBinding:
    if not isinstance(record, dict):
        raise ValueError("each OpenClaw binding must be an object")
    unknown = set(record) - _FIELDS
    missing = _FIELDS - set(record)
    if unknown:
        raise ValueError(f"unknown OpenClaw binding fields: {sorted(unknown)}")
    if missing:
        raise ValueError(f"missing OpenClaw binding fields: {sorted(missing)}")
    path = PurePosixPath(str(record["case_dir"]))
    if path.is_absolute() or path.parts[:1] != ("active",) or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise ValueError(f"binding case_dir must remain under runs/active: {path}")
    digest = str(record["case_meta_sha256"])
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError(f"invalid case metadata SHA-256 for {path}")
    try:
        disposition = BindingDisposition(str(record["disposition"]))
    except ValueError as exc:
        raise ValueError(f"unknown OpenClaw disposition for {path}") from exc
    return OpenClawBinding(
        case_dir=path.as_posix(),
        case_meta_sha256=digest,
        semantic_surface=str(record["semantic_surface"]),
        comparison_group=str(record["comparison_group"]),
        required_capabilities=_strings(record["required_capabilities"], "required_capabilities", nonempty=True),
        stage_runtime_modes=_strings(record["stage_runtime_modes"], "stage_runtime_modes", nonempty=True),
        expected_normalized_events=_strings(record["expected_normalized_events"], "expected_normalized_events"),
        disposition=disposition,
        blocking_reasons=_strings(record["blocking_reasons"], "blocking_reasons"),
        binding_version=version,
    )


def load_inventory(path: Path, *, repo_root: Path, require_manifest_match: bool = True) -> dict[str, OpenClawBinding]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict) or not isinstance(payload.get("bindings"), list):
        raise ValueError("OpenClaw inventory must contain a bindings list")
    version = str(payload.get("binding_version", ""))
    if version != "openclaw-binding-v1":
        raise ValueError(f"unsupported OpenClaw binding version: {version}")
    result: dict[str, OpenClawBinding] = {}
    for record in payload["bindings"]:
        binding = _parse(record, version)
        if binding.case_dir in result:
            raise ValueError(f"duplicate OpenClaw binding: {binding.case_dir}")
        result[binding.case_dir] = binding
    if require_manifest_match and set(result) != _manifest_paths(repo_root):
        raise ValueError("OpenClaw inventory does not exactly match active manifest")
    return result


def resolve_binding(binding: OpenClawBinding, case_dir: Path) -> OpenClawBinding:
    actual = case_contract_sha256(case_dir / "case_meta.json")
    if actual != binding.case_meta_sha256:
        raise ValueError(f"OpenClaw binding hash mismatch: expected={binding.case_meta_sha256} actual={actual}")
    return binding


def write_selected_binding(binding: OpenClawBinding, materialized_case_dir: Path, *, canonical_case_dir: Path | None = None) -> Path:
    resolve_binding(binding, canonical_case_dir or materialized_case_dir)
    target = materialized_case_dir / "harness_binding.json"
    target.write_text(json.dumps({"harness": "openclaw", **binding.to_dict()}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return target
