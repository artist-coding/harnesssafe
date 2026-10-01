"""Check whether the repository cleanup plan is ready for tag/release."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from infra import check_release_metadata
except ModuleNotFoundError:  # direct `python infra/check_repo_release_cleanliness.py`
    import check_release_metadata  # type: ignore


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INVENTORY = "docs/generated_artifacts/repo_change_inventory.json"

REQUIRED_VALIDATION_COMMANDS = [
    "python -m pytest -q",
    "python infra\\check_public_artifact_safety.py --bundle-dir runs\\_artifacts\\repro_bundles\\paper_core_20260625",
    "python infra\\check_repo_release_cleanliness.py --require-clean --require-release-metadata",
    ".\\infra\\run_paper_preflight.ps1 -Profile submission",
]


def issue(
    severity: str,
    scope: str,
    message: str,
    action: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "scope": scope,
        "message": message,
        "action": action,
        "detail": detail or {},
    }


def load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError:
        return {}


def _count_value(*values: Any) -> int:
    for value in values:
        if isinstance(value, int):
            return value
    return 0


def _missing_validation_commands(commands: list[Any]) -> list[str]:
    command_text = [str(command) for command in commands]
    return [
        required
        for required in REQUIRED_VALIDATION_COMMANDS
        if required not in command_text
    ]


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _path_exists(root: Path, path_text: str) -> bool:
    path = Path(path_text)
    if not path.is_absolute():
        path = root / path
    return path.is_file()


def _release_metadata_issue(report: dict[str, Any]) -> dict[str, Any]:
    summary = report.get("summary", {})
    next_actions = [
        str(item.get("id"))
        for item in report.get("next_actions", [])
        if isinstance(item, dict) and item.get("id")
    ]
    return issue(
        "error",
        "release_metadata",
        "release metadata is not ready for public tag/release",
        "Finalize docs/release_metadata_final.json, apply it, add the final root license, then rerun this check.",
        {
            "ok": report.get("ok"),
            "public_release_ready": summary.get("public_release_ready"),
            "license_present": summary.get("license_present"),
            "citation_placeholder_author": summary.get("citation_placeholder_author"),
            "citation_preprint": summary.get("citation_preprint"),
            "citation_has_public_link": summary.get("citation_has_public_link"),
            "next_action_ids": next_actions,
        },
    )


def build_report(
    root: Path = ROOT,
    *,
    inventory_path: str | Path = DEFAULT_INVENTORY,
    require_clean: bool = False,
    require_release_metadata: bool = False,
) -> dict[str, Any]:
    inventory_file = Path(inventory_path)
    if not inventory_file.is_absolute():
        inventory_file = root / inventory_file
    inventory = load_json(inventory_file)
    issues: list[dict[str, Any]] = []

    if not inventory:
        issues.append(
            issue(
                "error",
                "inventory",
                "missing or unreadable repo change inventory",
                "Run python infra\\generate_repo_change_inventory.py before checking release cleanliness.",
                {"path": str(inventory_file)},
            )
        )

    summary = inventory.get("summary", {}) if isinstance(inventory, dict) else {}
    staging = inventory.get("release_staging_plan", {}) if isinstance(inventory, dict) else {}
    logical_commits = summary.get("logical_commits", {}) if isinstance(summary, dict) else {}
    ordered_commits = staging.get("ordered_logical_commits", []) if isinstance(staging, dict) else []
    stage_groups = _as_list(staging.get("stage_groups", []) if isinstance(staging, dict) else [])
    validation_commands = staging.get("validation_commands", []) if isinstance(staging, dict) else []
    changed_entries = _count_value(summary.get("changed_entries") if isinstance(summary, dict) else None)
    manual_review_entries = _count_value(
        staging.get("manual_review_entries") if isinstance(staging, dict) else None,
        summary.get("manual_review_entries") if isinstance(summary, dict) else None,
    )
    do_not_commit_entries = _count_value(
        staging.get("do_not_commit_entries") if isinstance(staging, dict) else None,
        summary.get("do_not_commit_entries") if isinstance(summary, dict) else None,
    )

    if inventory and not staging:
        issues.append(
            issue(
                "error",
                "staging_plan",
                "repo change inventory does not include a release staging plan",
                "Regenerate docs/generated_artifacts/repo_change_inventory.json with infra/generate_repo_change_inventory.py.",
            )
        )
    if changed_entries and not ordered_commits:
        issues.append(
            issue(
                "error",
                "staging_plan",
                "dirty worktree entries are not grouped into logical release commits",
                "Regenerate the repo change inventory and review any manual-review bucket.",
                {"changed_entries": changed_entries},
            )
        )
    if ordered_commits and not stage_groups:
        issues.append(
            issue(
                "error",
                "staging_plan",
                "release staging plan is missing pathspec staging groups",
                "Regenerate docs/generated_artifacts/repo_change_inventory.json with infra/generate_repo_change_inventory.py.",
            )
        )
    for group in stage_groups:
        if not isinstance(group, dict):
            continue
        logical_commit = str(group.get("logical_commit") or "")
        paths = [str(path) for path in _as_list(group.get("paths", []))]
        pathspec_file = str(group.get("pathspec_file") or "")
        if not pathspec_file:
            issues.append(
                issue(
                    "error",
                    "staging_plan",
                    "pathspec staging group is missing a pathspec file",
                    "Regenerate the repo change inventory before staging release commits.",
                    {"logical_commit": logical_commit},
                )
            )
        elif not _path_exists(root, pathspec_file):
            issues.append(
                issue(
                    "error",
                    "staging_plan",
                    "pathspec staging file is missing",
                    "Regenerate the repo change inventory before staging release commits.",
                    {"logical_commit": logical_commit, "pathspec_file": pathspec_file},
                )
            )
        forbidden_paths = [
            path
            for path in paths
            if path.startswith("bench_state/")
            or "/agent_home/" in path
            or "/materialized_case/" in path
            or path.endswith("/trace.jsonl")
            or path.endswith("/honeypot.jsonl")
            or path.endswith("/oracle.json")
        ]
        if logical_commit in {"do-not-commit", "manual-review"} or forbidden_paths:
            issues.append(
                issue(
                    "error",
                    "staging_plan",
                    "pathspec staging group includes non-release paths",
                    "Remove local-state or manual-review paths from release staging groups.",
                    {"logical_commit": logical_commit, "forbidden_paths": forbidden_paths},
                )
            )
    missing_commands = _missing_validation_commands(validation_commands)
    if missing_commands:
        issues.append(
            issue(
                "error",
                "validation_commands",
                "release staging plan is missing required final validation commands",
                "Regenerate docs/generated_artifacts/repo_change_inventory.json after updating infra/generate_repo_change_inventory.py.",
                {"missing_commands": missing_commands},
            )
        )
    if manual_review_entries:
        issues.append(
            issue(
                "error",
                "manual_review",
                "manual-review entries remain in the release inventory",
                "Classify or remove manual-review paths before staging release commits.",
                {"manual_review_entries": manual_review_entries},
            )
        )
    if do_not_commit_entries:
        severity = "error" if require_clean else "warning"
        issues.append(
            issue(
                severity,
                "local_state",
                "do-not-commit local state remains in the worktree inventory",
                "Remove, ignore, or explicitly keep local-only state out of release commits before tagging.",
                {"do_not_commit_entries": do_not_commit_entries},
            )
        )

    release_metadata_report: dict[str, Any] | None = None
    if require_release_metadata:
        release_metadata_report = check_release_metadata.build_release_metadata_report(
            root,
            require_license=True,
        )
        summary_ok = release_metadata_report.get("summary", {}).get("public_release_ready")
        if not release_metadata_report.get("ok") or not summary_ok:
            issues.append(_release_metadata_issue(release_metadata_report))

    errors = [item for item in issues if item["severity"] == "error"]
    warnings = [item for item in issues if item["severity"] == "warning"]
    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "inventory_path": str(inventory_file),
        "require_clean": require_clean,
        "require_release_metadata": require_release_metadata,
        "ok": not errors,
        "summary": {
            "changed_entries": changed_entries,
            "logical_commit_count": len(logical_commits) if isinstance(logical_commits, dict) else 0,
            "ordered_logical_commit_count": len(ordered_commits) if isinstance(ordered_commits, list) else 0,
            "stage_group_count": len(stage_groups),
            "manual_review_entries": manual_review_entries,
            "do_not_commit_entries": do_not_commit_entries,
            "validation_command_count": len(validation_commands) if isinstance(validation_commands, list) else 0,
            "missing_validation_command_count": len(missing_commands),
            "release_metadata_checked": require_release_metadata,
            "release_metadata_public_ready": (
                release_metadata_report.get("summary", {}).get("public_release_ready")
                if release_metadata_report
                else None
            ),
            "tag_release_ready": not errors and require_clean and require_release_metadata,
            "error_count": len(errors),
            "warning_count": len(warnings),
        },
        "release_staging_plan": staging,
        "issues": issues,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# Repo Release Cleanliness Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- inventory_path: `{report['inventory_path']}`",
        f"- require_clean: `{str(report['require_clean']).lower()}`",
        f"- require_release_metadata: `{str(report['require_release_metadata']).lower()}`",
        f"- ok: `{str(report['ok']).lower()}`",
        "",
        "## Summary",
        "",
        f"- changed_entries: `{summary.get('changed_entries', 0)}`",
        f"- ordered_logical_commit_count: `{summary.get('ordered_logical_commit_count', 0)}`",
        f"- stage_group_count: `{summary.get('stage_group_count', 0)}`",
        f"- manual_review_entries: `{summary.get('manual_review_entries', 0)}`",
        f"- do_not_commit_entries: `{summary.get('do_not_commit_entries', 0)}`",
        f"- validation_command_count: `{summary.get('validation_command_count', 0)}`",
        f"- missing_validation_command_count: `{summary.get('missing_validation_command_count', 0)}`",
        f"- release_metadata_checked: `{str(summary.get('release_metadata_checked', False)).lower()}`",
        f"- release_metadata_public_ready: `{str(summary.get('release_metadata_public_ready')).lower()}`",
        f"- tag_release_ready: `{str(summary.get('tag_release_ready', False)).lower()}`",
        "",
        "## Final Validation Commands",
        "",
    ]
    commands = report.get("release_staging_plan", {}).get("validation_commands", [])
    if commands:
        for command in commands:
            lines.append(f"- `{command}`")
    else:
        lines.append("- none")

    lines.extend(["", "## Issues", ""])
    if report.get("issues"):
        lines.extend(["| Severity | Scope | Message | Action |", "| --- | --- | --- | --- |"])
        for item in report["issues"]:
            lines.append(
                f"| {item['severity']} | {item['scope']} | {item['message']} | {item['action']} |"
            )
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check repository release-cleanliness state.")
    parser.add_argument("--inventory", default=DEFAULT_INVENTORY)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--require-release-metadata", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    report = build_report(
        ROOT,
        inventory_path=args.inventory,
        require_clean=args.require_clean,
        require_release_metadata=args.require_release_metadata,
    )
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n" if args.json else render_markdown(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
