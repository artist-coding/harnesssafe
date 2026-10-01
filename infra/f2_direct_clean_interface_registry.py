"""Refresh reviewed F2.01--F2.06 clean-plugin interface contracts.

Eighteen historical clean sources drifted only in benign ``description``
wording and are restored byte-for-byte to the attack interface.  Two F2.03
descriptions are themselves the attack entry; those remain sanitized and use
an explicit, hash-pinned ``entry_source_bundle`` interface delta.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from infra.clean_plugin_sanitizer import (
    PluginSanitizationError,
    _frontmatter_fields,
    build_clean_entry_source_bundle,
    interface_value_sha256,
    sanitize_plugin_tree,
    sha256_bytes,
    validate_sanitized_plugin_tree,
)


EXPECTED_FAMILIES = {
    "F2.01_perm_claim_spoofing",
    "F2.02_scope_overflow",
    "F2.03_manifest_output_ipi",
    "F2.04_metadata_tampering",
    "F2.05_rule_example_poisoning",
    "F2.06_static_auth_spoofing",
}
EXPECTED_CASE_COUNT = 32

# (case id, attack plugin root, skill path) ->
# (reviewed attack description hash, reviewed pre-refresh clean description hash)
DESCRIPTION_DRIFT_HASHES: dict[tuple[str, str, str], tuple[str, str]] = {
    ("sk_i_case_101", "plugin", "skills/inventory-viewer/SKILL.md"): (
        "2f62e5977352ff02e7d0b282d041c180a0d7c03afc0b2454c8177331331e388f",
        "902fa053969a7bc7edf9098fb1e3d35f078dec3c4ab2eb3f52395123f8a22848",
    ),
    ("sk_i_case_102", "plugin", "skills/health-monitor/SKILL.md"): (
        "185aa015385266a6c0da11a46d0349f8a0dcbc235816b767991a15a858da477a",
        "6e33a718cec1a8dfa362f944365a8a6c8b983c7f814caeabfed28f3ee03fb3fb",
    ),
    ("sk_i_case_103", "plugin", "skills/doc-viewer/SKILL.md"): (
        "141e28888f183cdf093e76d69d99e47d64e693e5caa30baf522deb86140eef99",
        "fd4157d0977b685d816a5b0465ebed215ab79f57ca8a42c64cb136eadf8dbf30",
    ),
    ("sk_i_case_104", "plugin", "skills/metrics-collector/SKILL.md"): (
        "b615c7e3b21421001ca1ad21326ebcf88aec1accc737b6b9ec1f22cbbd917fff",
        "bdad3625d4ffadffbe669966223ede2c9f6a2271c1f5a62b1df6e10b4fb0d172",
    ),
    ("sk_i_case_105", "plugin", "skills/log-viewer/SKILL.md"): (
        "a83fe436c34936c9dcc3e8a1dc96507bfa481a180e79faeefbaa7bf310b8e687",
        "4346e436947774dc78bbf37ca0159bc747aae5b1a9aef8b00e8c3a6e23876948",
    ),
    ("sk_i_case_201", "plugin", "skills/config-reader/SKILL.md"): (
        "a7eebc4080496ea8449423b6096946657006122d2a7027cdb2079231792b54f6",
        "ea772bb99e73eb4a52d9fc4ad8d2b34ad855738bdcf08f65c9864abb67213933",
    ),
    ("sk_i_case_202", "plugin", "skills/file-reader/SKILL.md"): (
        "a7eebc4080496ea8449423b6096946657006122d2a7027cdb2079231792b54f6",
        "a1cd39b30cd122810661dfc0812dad84e7698397b464c6406db0799170f19149",
    ),
    ("sk_i_case_203", "plugin_a", "skills/test-runner/SKILL.md"): (
        "1d2ff491c29e1b439e578737817ed1ebc8f2c6c0177e15ff774963845e32bbc0",
        "bbb33dd3f77496b446760ef4dbb72d807cfca77748da09d1550112fcfc30a8e0",
    ),
    ("sk_i_case_203", "plugin_b", "skills/env-check/SKILL.md"): (
        "292f1d84a19201534e4d0218502c483099b926bc458b22ac9a9ead44c13b8cfc",
        "60dbbc515f2558fa8d52661bca26fefa0033dd1371b9acf1272325bf2d59935c",
    ),
    ("sk_i_case_204", "plugin", "skills/tenant-config-reader/SKILL.md"): (
        "0e0c76201f25bae33468fab94426e3675a70bf9cfe869245ea38379c3cdcf094",
        "46ac5155d1360d634360ece5bf50025ffb91dfa20c0e07442cda8cd80e92b2cd",
    ),
    ("sk_i_case_205", "plugin", "skills/namespace-reader/SKILL.md"): (
        "b28080f25fc78751d40f8f2ed9502e93b3d4b8d77596f373019b92d4b959901b",
        "6ebd15ea95ca51ec10b692c5c0a90e5b9c8430a12c9c1be14c4a170c65238546",
    ),
    ("sk_i_case_301", "plugin", "skills/price-checker/SKILL.md"): (
        "d3b0c9b7a53d2b17fa87bb66a040ed1012df268859cefcb15183fe29c2cc788a",
        "ce45232f1eeec3906eee839d340f5198da0be6de73121569f16c7309c3e5af20",
    ),
    ("sk_i_case_303", "plugin", "skills/deploy/SKILL.md"): (
        "012ff7f74c38c97120113a8553244468fb3956af40edef5585429eed85c8fbe2",
        "998905cc3f24bc7d8d96916997a4b8b2f2ad8d76ff6e1eb4033f826653eaa4b5",
    ),
    ("sk_i_case_304", "plugin", "skills/data-sync/SKILL.md"): (
        "55b00cb5de23443a9a204b613531aad8231f19537bf98544700b68128c9e8c50",
        "f0e6e1e1e7c5780ef809849858cd5942521162f89c251751013afa86df00f912",
    ),
    ("sk_i_case_306", "plugin", "skills/changelog-notifier/SKILL.md"): (
        "59fb33ce3c15515037e485f48252320fcea6a76c7bffad60042c051fc43e46a1",
        "2617e60b5eeda162d9c783ca1cdfe50bde089d8765cc711917ce50951e1e9518",
    ),
    ("sk_i_case_401", "plugin", "skills/analytics-exporter/SKILL.md"): (
        "9473fb7dcbdeb76ea496237bc5d7d8ecf05b1947a0f8b18977d7c41632a078d2",
        "19d455c26682f915798d6308fd122587814e49851ce3ee5aa24e75cdeca0bac0",
    ),
    ("sk_i_case_402", "plugin", "skills/api-client/SKILL.md"): (
        "dd86635a631d5300ded7c4d03aa94036e39495b69e5f420f0e147f04fde15220",
        "305d88c199c89faa09fb1d129b15aa1f602bfdea4bcdf54fa9dccabe5d1f77b7",
    ),
    ("sk_i_case_404", "plugin", "skills/audit-logger/SKILL.md"): (
        "d5444a2c64d779aa2054711611a7c6e73d5b474670fdd5236d565a57ba4d006e",
        "a7d691e2338d4d00be27959f776300bc0ba1014e73367d67494d0edbc0c085c5",
    ),
    ("sk_i_case_501", "plugin", "skills/security-scanner/SKILL.md"): (
        "9231f69cc7008a2ac0e948c6909973cd48967deaa4b8eb31822de25cd07e25cd",
        "e33797b2766c136e113ecfc429481b50804f7171a50dcc037fef9f84d69a34da",
    ),
    ("sk_i_case_602", "plugin", "skills/user-manager/SKILL.md"): (
        "5dc245f9a52b50bbcbf5661368d61d687ef6baf91ae87000783f270834bc0e4e",
        "2a85a31fdccefe13ed8e4f4e638b57872543ad1f225bf967a3c54d6208aac2f9",
    ),
}

DECLARED_DESCRIPTION_DELTAS = {
    ("sk_i_case_301", "plugin", "skills/price-checker/SKILL.md"),
    ("sk_i_case_303", "plugin", "skills/deploy/SKILL.md"),
}
EXACT_DESCRIPTION_REPAIRS = set(DESCRIPTION_DRIFT_HASHES) - (
    DECLARED_DESCRIPTION_DELTAS
)
DELTA_REASON = (
    "The attack description is the F2.03 entry payload; the clean description "
    "removes only that entry content while preserving the matched task and "
    "all other invocation fields."
)


def _load_meta(case_root: Path) -> dict[str, Any]:
    return json.loads(
        (case_root / "case_meta.json").read_text(encoding="utf-8-sig")
    )


def _clean_control(meta: dict[str, Any]) -> dict[str, Any]:
    rows = [
        row
        for row in (meta.get("control_suite") or [])
        if isinstance(row, dict) and row.get("control_type") == "clean_control"
    ]
    if len(rows) != 1:
        raise PluginSanitizationError(
            f"expected one clean_control row, found {len(rows)}"
        )
    return rows[0]


def _plugin_plans(meta: dict[str, Any]) -> dict[str, dict[str, Any]]:
    declaration = meta.get("clean_plugin_sanitization")
    if not isinstance(declaration, dict):
        raise PluginSanitizationError("missing clean_plugin_sanitization")
    if "source_tree_sha256" in declaration:
        return {"plugin": declaration}
    plans = declaration.get("plugins", declaration)
    if not isinstance(plans, dict):
        raise PluginSanitizationError("invalid clean_plugin_sanitization.plugins")
    return plans


def _scope_roots(repo_root: Path) -> dict[str, Path]:
    suite_root = repo_root / "runs" / "active" / "F2_skill_runtime"
    roots = {
        path.name: path
        for family in EXPECTED_FAMILIES
        for path in (suite_root / family).glob("sk_i_case_*")
        if path.is_dir()
    }
    if len(roots) != EXPECTED_CASE_COUNT:
        raise PluginSanitizationError(
            f"F2.01--F2.06 scope drifted: expected {EXPECTED_CASE_COUNT}, got {len(roots)}"
        )
    return roots


def _replace_description(data: bytes, description: str, label: str) -> bytes:
    text = data.decode("utf-8-sig")
    newline = "\r\n" if "\r\n" in text else "\n"
    normalized = text.replace("\r\n", "\n")
    pattern = re.compile(r"^description:\s*.*$", re.MULTILINE)
    if len(pattern.findall(normalized)) != 1:
        raise PluginSanitizationError(
            f"skill must have exactly one description field: {label}"
        )
    output = pattern.sub(lambda _match: f"description: {description}", normalized)
    return output.replace("\n", newline).encode("utf-8")


def _description(path: Path, relative: str) -> str:
    return _frontmatter_fields(path.read_bytes(), relative)["description"]


def _preflight_and_repair_descriptions(roots: dict[str, Path]) -> int:
    repaired = 0
    seen: set[tuple[str, str, str]] = set()
    for case_id, case_root in sorted(roots.items()):
        meta = _load_meta(case_root)
        clean = _clean_control(meta)
        attack_dirs = [str(value) for value in (meta.get("plugin_dirs") or [])]
        clean_dirs = [
            str(value) for value in (clean.get("control_plugin_dirs") or [])
        ]
        if len(attack_dirs) != len(clean_dirs) or not attack_dirs:
            raise PluginSanitizationError(
                f"plugin roots are not one-to-one: {case_root}"
            )
        for attack_root_value, clean_root_value in zip(attack_dirs, clean_dirs):
            attack_root = case_root / attack_root_value
            clean_root = case_root / clean_root_value
            attack_skills = {
                path.relative_to(attack_root).as_posix(): path
                for path in attack_root.glob("skills/*/SKILL.md")
                if path.is_file()
            }
            clean_skills = {
                path.relative_to(clean_root).as_posix(): path
                for path in clean_root.glob("skills/*/SKILL.md")
                if path.is_file()
            }
            if not attack_skills or attack_skills.keys() != clean_skills.keys():
                raise PluginSanitizationError(
                    f"attack/clean skill paths differ: {case_root.name}:{attack_root_value}"
                )
            for relative, attack_path in sorted(attack_skills.items()):
                clean_path = clean_skills[relative]
                key = (case_id, attack_root_value, relative)
                attack_description = _description(attack_path, relative)
                clean_description = _description(clean_path, relative)
                if key not in DESCRIPTION_DRIFT_HASHES:
                    if attack_description != clean_description:
                        raise PluginSanitizationError(
                            f"unregistered description drift: {key}"
                        )
                    continue
                seen.add(key)
                attack_hash, reviewed_clean_hash = DESCRIPTION_DRIFT_HASHES[key]
                if interface_value_sha256(attack_description) != attack_hash:
                    raise PluginSanitizationError(
                        f"attack description drifted after review: {key}"
                    )
                clean_hash = interface_value_sha256(clean_description)
                if key in DECLARED_DESCRIPTION_DELTAS:
                    if clean_hash != reviewed_clean_hash:
                        raise PluginSanitizationError(
                            f"declared-delta clean description drifted: {key}"
                        )
                    continue
                if clean_hash == attack_hash:
                    continue
                if clean_hash != reviewed_clean_hash:
                    raise PluginSanitizationError(
                        f"clean description drifted before exact repair: {key}"
                    )
                clean_path.write_bytes(
                    _replace_description(
                        clean_path.read_bytes(), attack_description, str(clean_path)
                    )
                )
                repaired += 1
    if seen != set(DESCRIPTION_DRIFT_HASHES):
        raise PluginSanitizationError(
            "reviewed description registry does not match the active skill set"
        )
    return repaired


def _update_plan_clean_hashes_and_deltas(
    case_root: Path,
    meta: dict[str, Any],
) -> None:
    clean = _clean_control(meta)
    attack_dirs = [str(value) for value in (meta.get("plugin_dirs") or [])]
    clean_dirs = [str(value) for value in (clean.get("control_plugin_dirs") or [])]
    plans = _plugin_plans(meta)
    for attack_root_value, clean_root_value in zip(attack_dirs, clean_dirs):
        plan = plans.get(Path(attack_root_value).name)
        if not isinstance(plan, dict):
            raise PluginSanitizationError(
                f"missing plugin plan: {case_root.name}:{attack_root_value}"
            )
        delta_rows: list[dict[str, str]] = []
        for relative, file_plan in (plan.get("files") or {}).items():
            if not isinstance(file_plan, dict) or not isinstance(
                file_plan.get("clean_source"), dict
            ):
                raise PluginSanitizationError(
                    f"F2.01--F2.06 plan is not clean-source based: {case_root.name}:{relative}"
                )
            clean_source = file_plan["clean_source"]
            clean_source_path = case_root / str(clean_source.get("path") or "")
            if not clean_source_path.is_file():
                raise PluginSanitizationError(
                    f"clean source is missing: {clean_source_path}"
                )
            clean_source["sha256"] = sha256_bytes(clean_source_path.read_bytes())
            key = (case_root.name, attack_root_value, str(relative))
            if key not in DECLARED_DESCRIPTION_DELTAS:
                continue
            attack_path = case_root / attack_root_value / str(relative)
            clean_path = case_root / clean_root_value / str(relative)
            attack_description = _description(attack_path, str(relative))
            clean_description = _description(clean_path, str(relative))
            delta_rows.append(
                {
                    "path": str(relative),
                    "field": "description",
                    "intervention_variable": "entry_source_bundle",
                    "attack_canonical_sha256": interface_value_sha256(
                        attack_description
                    ),
                    "clean_canonical_sha256": interface_value_sha256(
                        clean_description
                    ),
                    "reason": DELTA_REASON,
                }
            )
        if delta_rows:
            plan["allowed_interface_deltas"] = delta_rows
        else:
            plan.pop("allowed_interface_deltas", None)


def refresh_case(case_root: Path | str, *, write_meta: bool = True) -> dict[str, Any]:
    case_root = Path(case_root)
    meta = _load_meta(case_root)
    clean = _clean_control(meta)
    attack_dirs = [str(value) for value in (meta.get("plugin_dirs") or [])]
    clean_dirs = [str(value) for value in (clean.get("control_plugin_dirs") or [])]
    if len(attack_dirs) != len(clean_dirs) or not attack_dirs:
        raise PluginSanitizationError(
            f"plugin roots are not one-to-one: {case_root}"
        )

    _update_plan_clean_hashes_and_deltas(case_root, meta)
    overrides = clean.get("control_workspace_overrides") or []
    if isinstance(overrides, dict):
        overrides = [overrides]
    clean["control_clean_entry_source_bundle"] = build_clean_entry_source_bundle(
        case_root,
        attack_dirs,
        clean_dirs,
        overrides,
    )

    contracts: list[dict[str, Any]] = []
    validations: list[dict[str, Any]] = []
    for attack_value, clean_value in zip(attack_dirs, clean_dirs):
        contract = sanitize_plugin_tree(
            case_root / attack_value,
            case_root / clean_value,
            meta,
        )
        contracts.append(contract)
        validations.append(
            validate_sanitized_plugin_tree(
                case_root / attack_value,
                case_root / clean_value,
                meta,
                contract,
            )
        )
    clean["control_plugin_interface_contracts"] = contracts
    rebuilt = build_clean_entry_source_bundle(
        case_root,
        attack_dirs,
        clean_dirs,
        overrides,
    )
    if clean["control_clean_entry_source_bundle"] != rebuilt:
        raise PluginSanitizationError(
            f"entry-source bundle changed during refresh: {case_root.name}"
        )
    clean["control_clean_entry_source_bundle"] = rebuilt

    if write_meta:
        (case_root / "case_meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return {
        "case_id": case_root.name,
        "meta": meta,
        "plugin_count": len(contracts),
        "interface_delta_count": sum(
            len(contract.get("allowed_interface_deltas") or [])
            for contract in contracts
        ),
        "bundle_target_count": len(rebuilt["targets"]),
        "validations": validations,
    }


def refresh_scope(repo_root: Path | str) -> dict[str, Any]:
    repo_root = Path(repo_root)
    roots = _scope_roots(repo_root)
    repaired = _preflight_and_repair_descriptions(roots)
    rows = [refresh_case(roots[case_id]) for case_id in sorted(roots)]
    return {
        "schema_version": 1,
        "case_count": len(rows),
        "description_repaired_count": repaired,
        "plugin_count": sum(row["plugin_count"] for row in rows),
        "interface_delta_count": sum(
            row["interface_delta_count"] for row in rows
        ),
        "bundle_target_count": sum(row["bundle_target_count"] for row in rows),
        "cases": rows,
    }


__all__ = [
    "DECLARED_DESCRIPTION_DELTAS",
    "DESCRIPTION_DRIFT_HASHES",
    "EXACT_DESCRIPTION_REPAIRS",
    "EXPECTED_CASE_COUNT",
    "EXPECTED_FAMILIES",
    "refresh_case",
    "refresh_scope",
]
