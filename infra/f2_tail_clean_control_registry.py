"""Pinned refresh registry for repaired F2.13--F2.18 clean controls.

The registry covers only the eighteen independently reviewed tail cases.  It
pins every reviewed clean skill source and the complete clean-workspace tree,
then delegates generated plugin contracts and entry-source bundle hashes to
the repository's existing control repair primitives.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from infra.clean_plugin_sanitizer import (
    PluginSanitizationError,
    file_tree_snapshot,
    sha256_bytes,
    validate_sanitized_plugin_tree,
)
from infra.repair_active_control_contracts import (
    create_f2_clean_plugins,
    repair_controls,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class TailCaseSpec:
    relative: str
    clean_sources: dict[str, str]
    clean_workspace_sha256: str | None


SPECS: dict[str, TailCaseSpec] = {
    "sk_e_case_102": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.15_path_traversal_sensitive_file/sk_e_case_102",
        {"controls/clean_sources/plugin/skills/env-profiler/SKILL.md": "64fbd4ac203104d9b388e97fde292b07c264156768f55a7c1eb4dc27bec65201"},
        "ad149f7345ee62ce672cbb8c8779395cef7a96d1a839c6fab96fa420969e0b3a",
    ),
    "sk_e_case_103": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.15_path_traversal_sensitive_file/sk_e_case_103",
        {"controls/clean_sources/plugin/skills/resource-monitor/SKILL.md": "b8ddba0b295b8097936f8af89599c85b199b6cce7161ff70ebe96ed2027499f6"},
        None,
    ),
    "sk_e_case_704": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.13_local_memory_state_attack/sk_e_case_704",
        {"controls/clean_sources/plugin/skills/session-initializer/SKILL.md": "94edf8d6808c26c3ad168adced2bb4677af83b0e7833d3c27aa252a449a36587"},
        "b7c10f6f6bf1990b8e331d6c886e05f13aed1350fa5d18393ed75fc0e343863b",
    ),
    "sk_e_case_801": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.14_output_artifact_integrity/sk_e_case_801",
        {"controls/clean_sources/plugin/skills/html-exporter/SKILL.md": "f68171534e0fd7b384035240fd9625be98096ae0993ac02b54f98236b73004dd"},
        None,
    ),
    "sk_e_case_802": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.14_output_artifact_integrity/sk_e_case_802",
        {"controls/clean_sources/plugin/skills/report-exporter/SKILL.md": "2f262e51f7ec6058b6bc4dbad94737a276269989c01f19941fcd75aad67c91d8"},
        None,
    ),
    "sk_e_case_803": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.14_output_artifact_integrity/sk_e_case_803",
        {"controls/clean_sources/plugin/skills/pdf-generator/SKILL.md": "9c101b9dde6e8d918745caaf9bcc8ad0772fd5e2f8d060bfad3efde89e5b1179"},
        "7596bf0bc4a512ad35d3f059957cf5a5ce091f192a50a9e74cb002d4a08f9601",
    ),
    "sk_e_case_804": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.14_output_artifact_integrity/sk_e_case_804",
        {"controls/clean_sources/plugin/skills/svg-exporter/SKILL.md": "0d617d36a6c45d232bd3865cbaeef059d1635777f57a4b07e469b2ed13485c69"},
        "0cfd86c47854ddabf8be0c5077376b8974ecabb0dee730e15e0a7ed550dc368e",
    ),
    "sk_e_case_805": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.14_output_artifact_integrity/sk_e_case_805",
        {"controls/clean_sources/plugin/skills/email-template-generator/SKILL.md": "cd91f43f24e20778e32ef39163f31bf1c0ffd6ef94c4b0d19a3c127d8f350fc7"},
        "cccde13c7ed7ed7b1862474157fb650d2d2807e966b0fa65e8b97255aad9591d",
    ),
    "sk_e_case_901": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.15_path_traversal_sensitive_file/sk_e_case_901",
        {"controls/clean_sources/plugin/skills/file-browser/SKILL.md": "f1065626a962f55e64f643375dad9e7c8f5c12526a5acffb4125f06cecdb22c1"},
        None,
    ),
    "sk_e_case_902": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.15_path_traversal_sensitive_file/sk_e_case_902",
        {"controls/clean_sources/plugin/skills/workspace-scanner/SKILL.md": "2e4496a2c167a5007680039b64450ac81d71c5b0173de57a22e6ec061a55ba46"},
        "f4041aae03bd44a22e1d394437a89ebdec055b4079275a2af5c52ecd986698cc",
    ),
    "sk_e_case_904": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.15_path_traversal_sensitive_file/sk_e_case_904",
        {"controls/clean_sources/plugin/skills/log-rotator/SKILL.md": "8817d39d16ebcb1f87cba7a13d68812e830ded6a86e7dd799f805ff64e5566d5"},
        "9142b7fb476c86b3bf086eca60c686d4186fee581bb7ea0919b24338d36289be",
    ),
    "sk_e_case_1101": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.17_protocol_identity_spoofing/sk_e_case_1101",
        {"controls/clean_sources/plugin/skills/license-validator/SKILL.md": "d9aa71f8aa6af035e69c5bf0b26eb5f026ad19063569155fcbcab894d4082e01"},
        "1bd4c6d364c514dec3624e1a4b8a80a23104c6ac6ec2d22a2326f684b70176de",
    ),
    "sk_e_case_1102": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.17_protocol_identity_spoofing/sk_e_case_1102",
        {"controls/clean_sources/plugin/skills/api-tester/SKILL.md": "992d67b9b3070707180358c47ab16006c8cfa3152ee503f2c466c565f248963e"},
        "ef94967e7c879b626be5d0945f66e181a44d867e621bb15b60daab42e69a36f9",
    ),
    "sk_e_case_1105": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.17_protocol_identity_spoofing/sk_e_case_1105",
        {"controls/clean_sources/plugin/skills/oauth-flow-tester/SKILL.md": "1d62dfec1b510f26590bd464f981de6b328e164fae309934527907beb1e9edb5"},
        "e9f3a41504323416493649a30e97a90a114a27bd3c9cf9f6c4879b68556b0680",
    ),
    "sk_e_case_1201": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.18_resource_exhaustion/sk_e_case_1201",
        {"controls/clean_sources/plugin/skills/site-crawler/SKILL.md": "836c18f97820fe51e85e2c43b9d568e3a59a43267157bf2e15aa1f8319b2659c"},
        "3fc3a91a6246b006daf8e18697526f881ec73c42d74ffd2e048662523f2dbc1f",
    ),
    "sk_e_case_1202": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.18_resource_exhaustion/sk_e_case_1202",
        {"controls/clean_sources/plugin/skills/data-decompressor/SKILL.md": "fefba05bd2eda1859c9bd23127eb332f9be12c5bb3b5721c8d87b9a9e2a04e3a"},
        "ede029e4998ef65be14508ab1df6dc35b17e1bba8b9e885264f5d8c32205f00c",
    ),
    "sk_e_case_1203": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.18_resource_exhaustion/sk_e_case_1203",
        {"controls/clean_sources/plugin/skills/config-resolver/SKILL.md": "81edae726a11cd1d0847a599f02f489f166e97724424d9a9182e36f135d53325"},
        "af5c8d0c25840d225e322f357d81313e31fbfefb2a0aefe8c407b2cbead83986",
    ),
    "sk_e_case_1204": TailCaseSpec(
        "runs/active/F2_skill_runtime/F2.18_resource_exhaustion/sk_e_case_1204",
        {"controls/clean_sources/plugin/skills/image-processor/SKILL.md": "4cbd042abec2d4e80d28d0bdd46d6b994e2943836eb0e8d6aba093930c6567b4"},
        "f89042d2fc1d82f8c2dbd14846b7021f526a678ea12b7229d4e191c7fff4cfa2",
    ),
}


def _clean_control(meta: dict[str, Any]) -> dict[str, Any]:
    rows = [row for row in meta.get("control_suite", []) if row.get("control_type") == "clean_control"]
    if len(rows) != 1:
        raise PluginSanitizationError("expected exactly one clean_control row")
    return rows[0]


def _validate_pinned_inputs(case_root: Path, spec: TailCaseSpec) -> None:
    for relative, expected in spec.clean_sources.items():
        path = case_root / relative
        if not path.is_file() or sha256_bytes(path.read_bytes()) != expected:
            raise PluginSanitizationError(f"reviewed clean source drifted: {path}")
    workspace = case_root / "controls" / "clean_workspace"
    if spec.clean_workspace_sha256 is None:
        if workspace.exists():
            raise PluginSanitizationError(f"unexpected clean workspace tree: {workspace}")
    elif not workspace.is_dir() or file_tree_snapshot(workspace)["sha256"] != spec.clean_workspace_sha256:
        raise PluginSanitizationError(f"reviewed clean workspace drifted: {workspace}")


def _set_reviewed_hashes(meta: dict[str, Any], spec: TailCaseSpec) -> None:
    observed: set[str] = set()
    plugins = (meta.get("clean_plugin_sanitization") or {}).get("plugins") or {}
    for plugin_plan in plugins.values():
        for file_plan in (plugin_plan.get("files") or {}).values():
            clean_source = file_plan.get("clean_source") or {}
            relative = str(clean_source.get("path") or "")
            if not relative:
                continue
            if relative not in spec.clean_sources:
                raise PluginSanitizationError(f"unregistered clean source in metadata: {relative}")
            clean_source["sha256"] = spec.clean_sources[relative]
            observed.add(relative)
    if observed != set(spec.clean_sources):
        raise PluginSanitizationError(
            f"clean-source plan mismatch; planned={sorted(observed)} registered={sorted(spec.clean_sources)}"
        )


def _prepare_case_specific_inputs(case_root: Path, meta: dict[str, Any]) -> None:
    clean = _clean_control(meta)
    if case_root.name == "sk_e_case_1101":
        mocks = meta.get("mock_servers") or []
        if len(mocks) != 1:
            raise PluginSanitizationError("1101 must declare one mock server")
        mocks[0]["cwd"] = "workspace"
        clean["control_workspace_overrides"] = [
            {"source": "controls/clean_workspace/mock_server.py", "target": "mock_server.py"},
        ]
    elif case_root.name == "sk_e_case_1201":
        clean_docs = case_root / "controls" / "clean_workspace" / "docs"
        attack_docs = case_root / "workspace" / "docs"
        clean_files = sorted(path.relative_to(clean_docs).as_posix() for path in clean_docs.rglob("*") if path.is_file())
        attack_files = sorted(path.relative_to(attack_docs).as_posix() for path in attack_docs.rglob("*") if path.is_file())
        if clean_files != attack_files:
            raise PluginSanitizationError("1201 clean documentation tree must replace every attack graph file")
        clean["control_workspace_overrides"] = [
            {"source": "controls/clean_workspace/indexing_task.md", "target": "indexing_task.md"},
            *[
                {"source": f"controls/clean_workspace/docs/{relative}", "target": f"docs/{relative}"}
                for relative in clean_files
            ],
        ]


def refresh_registered_case(case_root: Path | str, *, write_meta: bool = True) -> dict[str, Any]:
    case_root = Path(case_root)
    spec = SPECS.get(case_root.name)
    if spec is None or case_root.resolve() != (ROOT / spec.relative).resolve():
        raise PluginSanitizationError(f"case is outside the tail registry: {case_root}")
    _validate_pinned_inputs(case_root, spec)
    meta = json.loads((case_root / "case_meta.json").read_text(encoding="utf-8-sig"))
    _set_reviewed_hashes(meta, spec)
    _prepare_case_specific_inputs(case_root, meta)
    clean_plugins, contracts = create_f2_clean_plugins(case_root, meta)
    repair_controls(
        "v2_skill_runtime",
        case_root,
        meta,
        clean_plugins,
        contracts,
        None,
        None,
    )
    if write_meta:
        write_json(case_root / "case_meta.json", meta)
    return {
        "case_id": case_root.name,
        "clean_plugin_count": len(clean_plugins),
        "workspace_target_count": len(_clean_control(meta).get("control_workspace_overrides") or []),
        "bundle_target_count": len((_clean_control(meta).get("control_clean_entry_source_bundle") or {}).get("targets") or []),
    }


def validate_registered_case(case_root: Path | str) -> dict[str, Any]:
    case_root = Path(case_root)
    spec = SPECS[case_root.name]
    _validate_pinned_inputs(case_root, spec)
    meta = json.loads((case_root / "case_meta.json").read_text(encoding="utf-8-sig"))
    _prepare_case_specific_inputs(case_root, meta)
    clean = _clean_control(meta)
    attack_dirs = list(meta.get("plugin_dirs") or [])
    clean_dirs = list(clean.get("control_plugin_dirs") or [])
    contracts = list(clean.get("control_plugin_interface_contracts") or [])
    if not (len(attack_dirs) == len(clean_dirs) == len(contracts)):
        raise PluginSanitizationError("plugin and contract counts differ")
    for attack, destination, contract in zip(attack_dirs, clean_dirs, contracts):
        validate_sanitized_plugin_tree(case_root / attack, case_root / destination, meta, contract)
    return {
        "case_id": case_root.name,
        "valid": True,
        "workspace_target_count": len(clean.get("control_workspace_overrides") or []),
    }


def refresh_registered_scope(repo_root: Path | str = ROOT) -> dict[str, Any]:
    repo_root = Path(repo_root).resolve()
    rows = []
    for case_id, spec in sorted(SPECS.items()):
        case_root = repo_root / spec.relative
        if case_root.name != case_id or not case_root.is_dir():
            raise PluginSanitizationError(f"registered case is missing: {case_root}")
        rows.append(refresh_registered_case(case_root))
    return {"schema_version": SCHEMA_VERSION, "refreshed_case_count": len(rows), "cases": rows}


def validate_registered_scope(repo_root: Path | str = ROOT) -> dict[str, Any]:
    repo_root = Path(repo_root).resolve()
    rows = [validate_registered_case(repo_root / spec.relative) for _, spec in sorted(SPECS.items())]
    return {"schema_version": SCHEMA_VERSION, "validated_case_count": len(rows), "cases": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate without refreshing generated contracts")
    args = parser.parse_args()
    report = validate_registered_scope() if args.check else refresh_registered_scope()
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SPECS", "refresh_registered_case", "refresh_registered_scope", "validate_registered_case", "validate_registered_scope"]
