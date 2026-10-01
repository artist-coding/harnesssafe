"""Generate the upgraded active F2 skill runtime cases.

This script imports the existing V3 skill builders (for unchanged baseline/core
cases) and the new wrapper builders (for cases upgraded to two-stage persistence
per Plan(4)). It emits all 84 cases into an F2-grouped layout and updates the
manifest.

Run from repo root:
    python infra/build_v2_skill_runtime_new_cases.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

BENCH_ROOT = Path(__file__).resolve().parent.parent
V2_SKILL_NEW_ROOT = BENCH_ROOT / "runs" / "active" / "F2_skill_runtime"
MANIFEST_PATH = BENCH_ROOT / "runs" / "manifest.json"

# Wrapper builders import original builders by name; make infra importable.
sys.path.insert(0, str(BENCH_ROOT / "infra"))

# Original V3 builder modules. These generate the 22 unchanged cases.
ORIGINAL_BUILDER_MODULES = [
    "build_v3_sk_e_cases",
    "build_v3_sk_e2_cases",
    "build_v3_sk_e3_cases",
    "build_v3_sk_i_cases",
    "build_v3_sk_i2_cases",
    "build_v3_sk_i3_cases",
]

# New wrapper builder modules. These generate the 62 upgraded cases.
WRAPPER_BUILDER_MODULES = [
    "build_v2_new_sk_e_cases",
    "build_v2_new_sk_e2_cases",
    "build_v2_new_sk_e3_cases",
    "build_v2_new_sk_i_cases",
    "build_v2_new_sk_i2_cases",
    "build_v2_new_sk_i3_cases",
]

# F2 grouping for the 18 SkillSafetyBench sub-categories.
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

# Cases that keep their original baseline/core form in the new suite.
UNCHANGED_CASE_IDS = {
    # Baselines
    "sk_i_case_101",
    "sk_i_case_201",
    "sk_i_case_301",
    "sk_i_case_401",
    "sk_i_case_501",
    "sk_i_case_601",
    "sk_e_case_101",
    "sk_e_case_201",
    "sk_e_case_301",
    "sk_e_case_401",
    "sk_e_case_501",
    "sk_e_case_601",
    "sk_e_case_701",
    "sk_e_case_801",
    "sk_e_case_901",
    "sk_e_case_1001",
    "sk_e_case_1101",
    "sk_e_case_1201",
    # Existing core cases
    "sk_e_case_702",
    "sk_e_case_703",
    "sk_e_case_704",
    "sk_e_case_705",
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


def _reset_v2_skill_new_root() -> None:
    _remove_tree(V2_SKILL_NEW_ROOT)
    V2_SKILL_NEW_ROOT.mkdir(parents=True, exist_ok=True)


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


def _collect_builders() -> dict[str, Any]:
    """Return a merged dict of {case_id: builder_func} for the new suite."""
    builders: dict[str, Any] = {}

    # Pre-load the shared helper and original builders so wrapper imports resolve.
    sys.modules["build_v2_skill_runtime_new_shared"] = _load_module("build_v2_skill_runtime_new_shared")
    for _orig_name in ORIGINAL_BUILDER_MODULES:
        sys.modules[_orig_name] = _load_module(_orig_name)

    # Load original builders for unchanged cases.
    for module_name in ORIGINAL_BUILDER_MODULES:
        module = _load_module(module_name)
        for case_id, builder in getattr(module, "BUILDERS").items():
            if case_id in UNCHANGED_CASE_IDS:
                builders[case_id] = builder

    # Load wrapper builders for upgraded cases.
    for module_name in WRAPPER_BUILDER_MODULES:
        module = _load_module(module_name)
        for case_id, builder in getattr(module, "BUILDERS").items():
            if case_id not in UNCHANGED_CASE_IDS:
                builders[case_id] = builder

    return builders


def _build_cases(builders: dict[str, Any]) -> list[dict[str, Any]]:
    manifest_entries: list[dict[str, Any]] = []

    overrides = _load_module("build_v2_skill_runtime_new_overrides").SKILL_MD_OVERRIDES

    for case_id in sorted(builders):
        builder = builders[case_id]
        # Generate payload files first so we know the real attack_id.
        case_root = V2_SKILL_NEW_ROOT / "_tmp" / case_id
        if case_root.exists():
            shutil.rmtree(case_root)
        case_root.mkdir(parents=True, exist_ok=True)
        meta = builder(case_root)

        attack_id = meta["attack_id"]
        group = ATTACK_F2_MAP[attack_id]
        final_root = V2_SKILL_NEW_ROOT / group / case_id
        final_root.parent.mkdir(parents=True, exist_ok=True)
        _remove_tree(final_root)
        case_root.rename(final_root)
        _rewrite_symlinks(case_root, final_root)

        # Rewrite location metadata for the new layout.
        new_case_dir = f"active/F2_skill_runtime/{group}/{case_id}"
        meta["case_dir"] = new_case_dir
        meta["canonical_suite"] = "skill_runtime"

        # Apply a hand-authored SKILL.md override if one is registered for this
        # case (faithful two-stage rewrites the generic templates could not
        # produce). Written to the primary skill's SKILL.md.
        if case_id in overrides and meta.get("plugin_skills"):
            skill_md_path = final_root / "plugin" / "skills" / meta["plugin_skills"][0] / "SKILL.md"
            if skill_md_path.parent.exists():
                skill_md_path.write_text(overrides[case_id], encoding="utf-8", newline="\n")
            else:
                raise RuntimeError(f"override skill path missing: {skill_md_path}")

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
    tmp_root = V2_SKILL_NEW_ROOT / "_tmp"
    if tmp_root.exists():
        shutil.rmtree(tmp_root)

    return manifest_entries


def _update_manifest(manifest_entries: list[dict[str, Any]]) -> dict[str, Any]:
    manifest = _load_json(MANIFEST_PATH)

    # Add/replace the active F2 skill runtime suite.
    manifest["suites"]["v2_skill_runtime"] = {
        "framework": "idea_v2",
        "family": "F2_skill_risk",
        "note": "Active F2 skill runtime suite: 84 cases, using the v2_skill_runtime_new two-stage upgrade. Composition is 18 direct baseline cases plus 66 indirect/multi-stage persistence cases. The previous direct suite is preserved under runs/reference/v2_skill_runtime_direct/.",
        "cases": manifest_entries,
        "status": "active",
        "canonical_suite": "skill_runtime",
        "layer1_suite": "F2_skill_runtime",
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


def _refresh_manifest_entries(manifest: dict[str, Any]) -> None:
    suite = manifest["suites"]["v2_skill_runtime"]
    for entry in suite["cases"]:
        meta_path = BENCH_ROOT / "runs" / entry["case_dir"] / "case_meta.json"
        meta = _load_json(meta_path)
        if meta.get("case_id"):
            entry["case_id"] = meta["case_id"]
        if meta.get("canonical_suite"):
            entry["canonical_suite"] = meta["canonical_suite"]
    _write_json(MANIFEST_PATH, manifest)


def _annotate_cases() -> None:
    spec = importlib.util.spec_from_file_location(
        "annotate_benchmark_reporting_metadata",
        BENCH_ROOT / "infra" / "annotate_benchmark_reporting_metadata.py",
    )
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load annotate_benchmark_reporting_metadata.py")
    annotate_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(annotate_mod)
    annotate_mod.annotate()


def main() -> int:
    builders = _collect_builders()
    expected = 84
    if len(builders) != expected:
        missing = sorted(
            {f"sk_{family}_case_{n:04d}" for family in ("e", "i") for n in range(1, 100)}
            - set(builders)
        )
        raise RuntimeError(
            f"Expected {expected} builders, got {len(builders)}. Missing: {missing}"
        )

    _reset_v2_skill_new_root()
    manifest_entries = _build_cases(builders)
    manifest = _update_manifest(manifest_entries)
    _normalize_cases(manifest)
    _refresh_manifest_entries(manifest)
    _annotate_cases()

    print(f"\nDone. {len(manifest_entries)} cases under {V2_SKILL_NEW_ROOT}")
    print(f"Manifest updated: {MANIFEST_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
