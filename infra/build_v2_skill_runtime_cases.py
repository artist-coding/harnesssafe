"""Generate v2 skill runtime cases under runs/active/F2_skill_runtime/.

This script imports the existing V3 skill builders and re-emits the 84 cases
into an F2-grouped layout (mirroring the F3 MCP layout).

Run from repo root:
    python infra/build_v2_skill_runtime_cases.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

BENCH_ROOT = Path(__file__).resolve().parent.parent
V2_SKILL_ROOT = BENCH_ROOT / "runs" / "active" / "F2_skill_runtime"
MANIFEST_PATH = BENCH_ROOT / "runs" / "manifest.json"

# Import existing builder modules by file path so we don't need infra/__init__.py.
BUILDER_MODULE_NAMES = [
    "build_v3_sk_e_cases",
    "build_v3_sk_e2_cases",
    "build_v3_sk_e3_cases",
    "build_v3_sk_i_cases",
    "build_v3_sk_i2_cases",
    "build_v3_sk_i3_cases",
]

# F2 grouping for the 18 SkillSafetyBench.md sub-categories.
ATTACK_F2_MAP = {
    "SK-I-1": "F2.01_perm_claim_spoofing",
    "SK-I-2": "F2.02_scope_overflow",
    "SK-I-3": "F2.03_manifest_output_ipi",
    "SK-I-4": "F2.04_metadata_tampering",
    "SK-I-5": "F2.05_rule_example_poisoning",
    "SK-I-6": "F2.06_static_auth_spoofing",
    "SK-E-1": "F2.07_sandbox_escape",
    "SK-E-2": "F2.08_runtime_toolchain_hijack",
    "SK-E-3": "F2.09_serialization_loader_abuse",
    "SK-E-4": "F2.10_execution_output_ipi",
    "SK-E-5": "F2.11_credential_exfiltration",
    "SK-E-6": "F2.12_network_boundary_violation",
    "SK-E-7": "F2.13_local_memory_state_attack",
    "SK-E-8": "F2.14_output_artifact_integrity",
    "SK-E-9": "F2.15_path_traversal_sensitive_file",
    "SK-E-10": "F2.16_interpreter_query_injection",
    "SK-E-11": "F2.17_protocol_identity_spoofing",
    "SK-E-12": "F2.18_resource_exhaustion",
}


def _load_module(name: str) -> Any:
    path = BENCH_ROOT / "infra" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load builder module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _remove_tree(path: Path) -> None:
    def _onerror(func: Any, p: str, exc_info: Any) -> None:
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            print(f"warning: could not remove {p}")

    if path.exists():
        shutil.rmtree(path, onerror=_onerror)


def _reset_v2_skill_root() -> None:
    _remove_tree(V2_SKILL_ROOT)
    V2_SKILL_ROOT.mkdir(parents=True, exist_ok=True)


def _is_reparse_point(path: Path) -> bool:
    """Return True for Windows junctions/reparse points not detected by islink."""
    try:
        return bool(os.lstat(path).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, AttributeError):
        return False


def _strip_unc_prefix(path_str: str) -> str:
    """Remove Windows extended-length path prefix so pathlib can compare paths."""
    if path_str.startswith("\\\\?\\"):
        return path_str[4:]
    if path_str.startswith("\\\\?\\UNC\\"):
        return "\\\\" + path_str[8:]
    return path_str


def _create_windows_junction(link: Path, target: Path) -> None:
    """Create a Windows directory junction (does not require admin)."""
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
    )


def _rewrite_symlinks(old_root: Path, new_root: Path) -> None:
    """Rewrite symlinks/junctions under new_root to valid targets.

    V3 builders may create directory junctions on Windows with absolute targets.
    After moving the case from old_root to new_root, absolute targets that point
    into old_root become stale. We remap such targets to new_root and recreate
    the link so the case can be materialized without errors.
    """
    old_root_abs = old_root.resolve()
    new_root_abs = new_root.resolve()

    for dirpath, dirnames, filenames in os.walk(new_root, followlinks=False):
        for name in filenames + dirnames:
            path = Path(dirpath) / name
            if not (os.path.islink(path) or _is_reparse_point(path)):
                continue
            target = _strip_unc_prefix(os.path.normpath(os.readlink(path)))
            target_path = Path(target)
            if not target_path.is_absolute():
                continue  # already relative, leave alone

            # If the absolute target was inside the old case root, remap it.
            try:
                relative_in_case = target_path.resolve().relative_to(old_root_abs)
                target_path = new_root_abs / relative_in_case
            except (ValueError, OSError):
                pass  # target is outside old_root or cannot resolve; keep as-is

            if not target_path.exists():
                print(f"warning: symlink {path} points to missing target {target_path}")
                continue

            path.unlink()
            if os.name == "nt" and target_path.is_dir():
                # Directory junctions work without admin on Windows.
                _create_windows_junction(path, target_path)
                print(f"rewrote junction {path} -> {target_path}")
            else:
                # Try a relative symlink first for portability.
                try:
                    rel_target = os.path.relpath(
                        str(target_path.resolve()), start=str(path.parent.resolve())
                    )
                    path.symlink_to(Path(rel_target), target_is_directory=target_path.is_dir())
                    print(f"rewrote symlink {path} -> {rel_target}")
                except OSError:
                    # Fallback to absolute symlink if the OS forbids relative ones.
                    path.symlink_to(target_path, target_is_directory=target_path.is_dir())
                    print(f"rewrote symlink {path} -> {target_path}")


def _build_cases() -> list[dict[str, Any]]:
    manifest_entries: list[dict[str, Any]] = []

    for module_name in BUILDER_MODULE_NAMES:
        module = _load_module(module_name)
        builders = getattr(module, "BUILDERS")
        for case_id, builder in builders.items():
            # Generate payload files first so we know the real attack_id.
            case_root = V2_SKILL_ROOT / "_tmp" / case_id
            if case_root.exists():
                shutil.rmtree(case_root)
            case_root.mkdir(parents=True, exist_ok=True)
            meta = builder(case_root)

            attack_id = meta["attack_id"]
            group = ATTACK_F2_MAP[attack_id]
            final_root = V2_SKILL_ROOT / group / case_id
            final_root.parent.mkdir(parents=True, exist_ok=True)
            _remove_tree(final_root)
            case_root.rename(final_root)
            _rewrite_symlinks(case_root, final_root)

            # Rewrite location metadata for the new layout.
            new_case_dir = f"active/F2_skill_runtime/{group}/{case_id}"
            meta["case_dir"] = new_case_dir
            meta["canonical_suite"] = "skill_runtime"

            _write_json(final_root / "case_meta.json", meta)

            manifest_entries.append(
                {
                    "case_dir": new_case_dir,
                    "attack_id": attack_id,
                    "variant": meta["variant"],
                }
            )
            print(f"built {new_case_dir} ({attack_id} - {meta['variant']})")

    # Clean up the temporary staging directory.
    tmp_root = V2_SKILL_ROOT / "_tmp"
    if tmp_root.exists():
        shutil.rmtree(tmp_root)

    return manifest_entries


def _update_manifest(manifest_entries: list[dict[str, Any]]) -> dict[str, Any]:
    manifest = _load_json(MANIFEST_PATH)

    # Mark old V3 skill suites inactive.
    for suite_name in (
        "v3_sk_e",
        "v3_sk_e2",
        "v3_sk_e3",
        "v3_sk_i",
        "v3_sk_i2",
        "v3_sk_i3",
    ):
        if suite_name in manifest["suites"]:
            manifest["suites"][suite_name]["status"] = "inactive"

    # Add/replace the unified v2 skill runtime suite.
    manifest["suites"]["v2_skill_runtime"] = {
        "framework": "idea_v2",
        "family": "F2_skill_risk",
        "note": "All 84 V3 skill cases reorganized by F2 attack type. Built by infra/build_v2_skill_runtime_cases.py; normalized by infra/normalize_task_metadata.py.",
        "cases": manifest_entries,
        "status": "active",
        "canonical_suite": "skill_runtime",
    }

    _write_json(MANIFEST_PATH, manifest)
    return manifest


def _normalize_cases(manifest: dict[str, Any]) -> None:
    # Import here so the script can still generate payloads even if normalize
    # utilities change independently.
    spec = importlib.util.spec_from_file_location(
        "normalize_task_metadata", BENCH_ROOT / "infra" / "normalize_task_metadata.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load normalize_task_metadata.py")
    norm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(norm)

    suite = manifest["suites"]["v2_skill_runtime"]
    for entry in suite["cases"]:
        meta_path = BENCH_ROOT / "runs" / entry["case_dir"] / "case_meta.json"
        meta = _load_json(meta_path)
        norm.normalize_v3_skill_case(meta, suite)
        _write_json(meta_path, meta)
        if meta.get("case_id"):
            entry["case_id"] = meta["case_id"]
        if meta.get("canonical_suite"):
            entry["canonical_suite"] = meta["canonical_suite"]
    _write_json(MANIFEST_PATH, manifest)


def main() -> int:
    _reset_v2_skill_root()
    manifest_entries = _build_cases()
    manifest = _update_manifest(manifest_entries)
    _normalize_cases(manifest)

    print(f"\nDone. {len(manifest_entries)} cases under {V2_SKILL_ROOT}")
    print(f"Manifest updated: {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
