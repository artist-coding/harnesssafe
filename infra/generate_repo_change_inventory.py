"""Generate a logical commit inventory from the current git worktree."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/repo_change_inventory.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/repo_change_inventory.md")
DEFAULT_STAGE_DIR = Path("docs/generated_artifacts/repo_release_stage_pathspecs")

LOGICAL_COMMIT_ORDER = [
    "benchmark-core-support",
    "active-case-control-fixtures",
    "paper-infra-and-gates",
    "paper-docs-and-evidence",
    "paper-entrypoint-docs",
    "paper-generated-reports",
    "release-metadata-handoff",
    "repo-cleanup-plan",
]

LOGICAL_COMMIT_MESSAGES = {
    "benchmark-core-support": "benchmark-core-support: update runner and oracle infrastructure",
    "active-case-control-fixtures": "active-case-control-fixtures: add active case controls and metadata",
    "paper-infra-and-gates": "paper-infra-and-gates: add paper validation and reporting gates",
    "paper-docs-and-evidence": "paper-docs-and-evidence: add paper evidence and manuscript artifacts",
    "paper-entrypoint-docs": "paper-entrypoint-docs: update reviewer entry points",
    "paper-generated-reports": "paper-generated-reports: include generated public bundle artifacts",
    "release-metadata-handoff": "release-metadata-handoff: add release metadata decision scaffolding",
    "repo-cleanup-plan": "repo-cleanup-plan: add release staging inventory",
}

FINAL_VALIDATION_COMMANDS = [
    "python -m pytest -q",
    "python infra\\check_public_artifact_safety.py --bundle-dir runs\\_artifacts\\repro_bundles\\paper_core_20260625",
    "python infra\\check_repo_release_cleanliness.py --require-clean --require-release-metadata",
    ".\\infra\\run_paper_preflight.ps1 -Profile submission",
]


CATEGORY_DEFINITIONS: dict[str, dict[str, str]] = {
    "entrypoint_docs": {
        "title": "Entry Point Documentation",
        "commit": "paper-entrypoint-docs",
        "policy": "include",
    },
    "release_metadata": {
        "title": "Release Metadata Handoff",
        "commit": "release-metadata-handoff",
        "policy": "include_after_author_decision",
    },
    "paper_artifacts": {
        "title": "Paper Documents And Generated Evidence",
        "commit": "paper-docs-and-evidence",
        "policy": "include",
    },
    "paper_infra": {
        "title": "Paper Validation And Reporting Infrastructure",
        "commit": "paper-infra-and-gates",
        "policy": "include",
    },
    "paper_tests": {
        "title": "Paper Validation Tests",
        "commit": "paper-infra-and-gates",
        "policy": "include",
    },
    "benchmark_infra": {
        "title": "Benchmark Runner And Oracle Infrastructure",
        "commit": "benchmark-core-support",
        "policy": "include",
    },
    "benchmark_tests": {
        "title": "Benchmark Runner And Oracle Tests",
        "commit": "benchmark-core-support",
        "policy": "include",
    },
    "active_cases": {
        "title": "Active Case Metadata And Controls",
        "commit": "active-case-control-fixtures",
        "policy": "include",
    },
    "paper_reports": {
        "title": "Paper Report Outputs",
        "commit": "paper-generated-reports",
        "policy": "publish_or_include_with_artifact_release",
    },
    "paper_release_bundle": {
        "title": "Public Repro Bundle",
        "commit": "paper-generated-reports",
        "policy": "publish_or_include_with_artifact_release",
    },
    "repo_cleanup": {
        "title": "Repo Cleanup Inventory",
        "commit": "repo-cleanup-plan",
        "policy": "include",
    },
    "local_state_exclude": {
        "title": "Local State To Exclude",
        "commit": "do-not-commit",
        "policy": "do_not_commit",
    },
    "misc_review": {
        "title": "Miscellaneous Review Needed",
        "commit": "manual-review",
        "policy": "review",
    },
}


PAPER_INFRA_PREFIXES = (
    "infra/audit_paper_",
    "infra/apply_release_metadata_decisions.py",
    "infra/build_repro_bundle.py",
    "infra/check_paper_",
    "infra/check_public_artifact_safety.py",
    "infra/check_release_metadata.py",
    "infra/check_repo_release_cleanliness.py",
    "infra/estimate_paper_run_budget.py",
    "infra/export_case_study_evidence.py",
    "infra/export_paper_",
    "infra/generate_benchmark_card.py",
    "infra/generate_claim_evidence_map.py",
    "infra/generate_control_integrity_report.py",
    "infra/generate_full_suite_eligibility_appendix.py",
    "infra/generate_oracle_coverage_report.py",
    "infra/generate_paper_",
    "infra/generate_statistical_analysis.py",
    "infra/generate_submission_package_manifest.py",
    "infra/generate_threat_model_card.py",
    "infra/paper_queue_job.py",
    "infra/plan_external_validity_calibration.py",
    "infra/plan_paper_experiment_matrix.py",
    "infra/report_paper_submission_gaps.py",
    "infra/run_paper_",
)


PAPER_TEST_PREFIXES = (
    "tests/test_audit_paper_",
    "tests/test_apply_release_metadata_decisions.py",
    "tests/test_build_repro_bundle.py",
    "tests/test_check_paper_",
    "tests/test_check_repo_release_cleanliness.py",
    "tests/test_estimate_paper_run_budget.py",
    "tests/test_export_case_study_evidence.py",
    "tests/test_export_paper_",
    "tests/test_generate_benchmark_card.py",
    "tests/test_generate_claim_evidence_map.py",
    "tests/test_generate_control_integrity_report.py",
    "tests/test_generate_full_suite_eligibility_appendix.py",
    "tests/test_generate_oracle_coverage_report.py",
    "tests/test_generate_paper_",
    "tests/test_generate_statistical_analysis.py",
    "tests/test_generate_submission_package_manifest.py",
    "tests/test_generate_threat_model_card.py",
    "tests/test_paper_",
    "tests/test_plan_external_validity_calibration.py",
    "tests/test_plan_paper_experiment_matrix.py",
    "tests/test_public_artifact_safety.py",
    "tests/test_release_metadata.py",
    "tests/test_report_paper_submission_gaps.py",
    "tests/test_run_paper_queue.py",
)


def norm_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def run_git_status(root: Path = ROOT) -> list[str]:
    proc = subprocess.run(
        ["git", "status", "--short"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git status failed")
    return [line for line in proc.stdout.splitlines() if line.strip()]


def parse_status_lines(lines: list[str]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for line in lines:
        if len(line) < 4:
            continue
        status = line[:2]
        raw_path = line[3:].strip()
        if " -> " in raw_path:
            raw_path = raw_path.split(" -> ", 1)[1].strip()
        path = norm_path(raw_path)
        entries.append(
            {
                "status": status,
                "status_text": status_to_text(status),
                "path": path,
            }
        )
    return entries


def status_to_text(status: str) -> str:
    if status == "??":
        return "untracked"
    if status == "!!":
        return "ignored"
    index, worktree = status[0], status[1]
    labels: list[str] = []
    if index.strip():
        labels.append(f"index:{index}")
    if worktree.strip():
        labels.append(f"worktree:{worktree}")
    return ", ".join(labels) if labels else "unknown"


def starts_any(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path.startswith(prefix) for prefix in prefixes)


def classify_path(path: str) -> str:
    path = norm_path(path)
    if (
        path.startswith("bench_state/")
        or "/agent_home/" in path
        or "/materialized_case/" in path
        or path.endswith("/trace.jsonl")
        or path.endswith("/honeypot.jsonl")
        or path.endswith("/oracle.json")
    ):
        return "local_state_exclude"
    if path in {
        "CITATION.cff",
        "LICENSE",
        "LICENSE.md",
        "COPYING",
        "COPYING.md",
        "LICENSES.md",
        "NOTICE",
        "docs/release_metadata_final.json",
    }:
        return "release_metadata"
    if path in {".gitignore", "README.md", "RUNBOOK.md", "docs/README.md"}:
        return "entrypoint_docs"
    if path.startswith("docs/generated_artifacts/repo_change_inventory."):
        return "repo_cleanup"
    if path.startswith("docs/generated_artifacts/repo_release_stage_pathspecs/"):
        return "repo_cleanup"
    if (
        path.startswith("docs/paper_")
        or path.startswith("docs/figures/")
        or path.startswith("docs/generated_artifacts/")
    ):
        return "paper_artifacts"
    if starts_any(path, PAPER_INFRA_PREFIXES):
        return "paper_infra"
    if starts_any(path, PAPER_TEST_PREFIXES):
        return "paper_tests"
    if path.startswith("runs/active/"):
        return "active_cases"
    if path.startswith("runs/_reports/"):
        return "paper_reports"
    if path.startswith("runs/_artifacts/"):
        return "paper_release_bundle"
    if path.startswith("infra/"):
        return "benchmark_infra"
    if path.startswith("tests/"):
        return "benchmark_tests"
    return "misc_review"


def build_inventory(
    status_lines: list[str],
    root: Path = ROOT,
    stage_dir: Path = DEFAULT_STAGE_DIR,
) -> dict[str, Any]:
    entries = parse_status_lines(status_lines)
    for entry in entries:
        category = classify_path(entry["path"])
        definition = CATEGORY_DEFINITIONS[category]
        entry["category"] = category
        entry["category_title"] = definition["title"]
        entry["logical_commit"] = definition["commit"]
        entry["include_policy"] = definition["policy"]

    by_category = Counter(entry["category"] for entry in entries)
    by_status = Counter(entry["status"] for entry in entries)
    by_commit = Counter(entry["logical_commit"] for entry in entries)
    release_staging_plan = build_release_staging_plan(entries, by_commit, stage_dir)
    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "summary": {
            "changed_entries": len(entries),
            "categories": dict(sorted(by_category.items())),
            "statuses": dict(sorted(by_status.items())),
            "logical_commits": dict(sorted(by_commit.items())),
            "do_not_commit_entries": by_category.get("local_state_exclude", 0),
            "manual_review_entries": by_commit.get("manual-review", 0),
        },
        "release_staging_plan": release_staging_plan,
        "categories": CATEGORY_DEFINITIONS,
        "entries": entries,
    }


def build_release_staging_plan(
    entries: list[dict[str, str]],
    by_commit: Counter[str],
    stage_dir: Path = DEFAULT_STAGE_DIR,
) -> dict[str, Any]:
    entries_by_commit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for entry in entries:
        entries_by_commit[entry["logical_commit"]].append(entry)
    ordered_commits: list[dict[str, Any]] = []
    seen: set[str] = set()
    for commit in LOGICAL_COMMIT_ORDER:
        commit_entries = entries_by_commit.get(commit, [])
        if not commit_entries:
            continue
        seen.add(commit)
        categories = sorted({entry["category"] for entry in commit_entries})
        policies = sorted({entry["include_policy"] for entry in commit_entries})
        ordered_commits.append(
            {
                "logical_commit": commit,
                "entries": len(commit_entries),
                "categories": categories,
                "policies": policies,
            }
        )
    for commit in sorted(set(by_commit) - seen - {"do-not-commit", "manual-review"}):
        commit_entries = entries_by_commit.get(commit, [])
        categories = sorted({entry["category"] for entry in commit_entries})
        policies = sorted({entry["include_policy"] for entry in commit_entries})
        ordered_commits.append(
            {
                "logical_commit": commit,
                "entries": len(commit_entries),
                "categories": categories,
                "policies": policies,
            }
        )
    stage_groups = build_stage_groups(ordered_commits, entries_by_commit, stage_dir)
    do_not_commit_entries = by_commit.get("do-not-commit", 0)
    manual_review_entries = by_commit.get("manual-review", 0)
    return {
        "ordered_logical_commits": ordered_commits,
        "pathspec_dir": str(stage_dir).replace("\\", "/"),
        "stage_groups": stage_groups,
        "do_not_commit_entries": do_not_commit_entries,
        "manual_review_entries": manual_review_entries,
        "validation_commands": FINAL_VALIDATION_COMMANDS,
        "release_blockers": build_release_blockers(
            do_not_commit_entries=do_not_commit_entries,
            manual_review_entries=manual_review_entries,
        ),
    }


def build_release_blockers(*, do_not_commit_entries: int, manual_review_entries: int) -> list[str]:
    blockers = [
        "final root LICENSE and CITATION metadata",
        "public repository, artifact URL, or DOI",
    ]
    if do_not_commit_entries:
        blockers.append("clean handling of do-not-commit local state")
    if manual_review_entries:
        blockers.append("manual review bucket resolved")
    blockers.append("passing submission preflight")
    return blockers


def build_stage_groups(
    ordered_commits: list[dict[str, Any]],
    entries_by_commit: dict[str, list[dict[str, str]]],
    stage_dir: Path,
) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    stage_dir_text = str(stage_dir).replace("\\", "/")
    for commit in ordered_commits:
        logical_commit = str(commit["logical_commit"])
        if logical_commit in {"do-not-commit", "manual-review"}:
            continue
        paths = sorted({entry["path"] for entry in entries_by_commit.get(logical_commit, [])})
        if not paths:
            continue
        pathspec_file = f"{stage_dir_text}/{logical_commit}.txt"
        groups.append(
            {
                "logical_commit": logical_commit,
                "entries": len(paths),
                "pathspec_file": pathspec_file,
                "stage_command": f"git add --pathspec-from-file {pathspec_file}",
                "commit_command": f"git commit -m \"{LOGICAL_COMMIT_MESSAGES.get(logical_commit, logical_commit)}\"",
                "paths": paths,
            }
        )
    return groups


def render_markdown(inventory: dict[str, Any], *, preview_limit: int = 30) -> str:
    summary = inventory["summary"]
    entries = inventory["entries"]
    staging = inventory.get("release_staging_plan", {})
    by_category: dict[str, list[dict[str, str]]] = defaultdict(list)
    by_commit: dict[str, list[dict[str, str]]] = defaultdict(list)
    for entry in entries:
        by_category[entry["category"]].append(entry)
        by_commit[entry["logical_commit"]].append(entry)

    lines = [
        "# Repo Change Inventory",
        "",
        f"- generated_at: `{inventory['generated_at']}`",
        f"- changed_entries: `{summary['changed_entries']}`",
        f"- do_not_commit_entries: `{summary['do_not_commit_entries']}`",
        "",
        "## Purpose",
        "",
        "This report groups the current dirty worktree into logical commit buckets for the final paper-artifact cleanup. It is an inventory, not an instruction to stage every path. Paths marked `do_not_commit` should stay local or be removed from the release candidate.",
        "",
        "## Recommended Logical Commits",
        "",
        "| Logical commit | Entries | Suggested scope |",
        "| --- | ---: | --- |",
    ]
    for commit, commit_entries in sorted(by_commit.items()):
        categories = sorted({entry["category"] for entry in commit_entries})
        scope = ", ".join(categories)
        lines.append(f"| `{commit}` | {len(commit_entries)} | {scope} |")

    lines.extend(
        [
            "",
            "## Category Summary",
            "",
            "| Category | Policy | Entries | Logical commit |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for category, definition in CATEGORY_DEFINITIONS.items():
        count = len(by_category.get(category, []))
        lines.append(
            f"| `{category}` | `{definition['policy']}` | {count} | `{definition['commit']}` |"
        )

    lines.extend(
        [
            "",
            "## Release Staging Procedure",
            "",
            "Use this as a non-destructive staging checklist after release metadata is final. Stage paths by logical commit from the JSON inventory; do not stage entries in the `do-not-commit` bucket.",
            "",
            "| Order | Logical commit | Entries | Categories | Policy notes |",
            "| ---: | --- | ---: | --- | --- |",
        ]
    )
    for index, commit in enumerate(staging.get("ordered_logical_commits", []), start=1):
        categories = ", ".join(commit.get("categories", []))
        policies = ", ".join(commit.get("policies", []))
        lines.append(
            f"| {index} | `{commit['logical_commit']}` | {commit['entries']} | {categories} | {policies} |"
        )
    lines.extend(
        [
            "",
            "Pathspec staging commands after release metadata is final:",
            "",
            "| Order | Logical commit | Paths | Stage command | Suggested commit |",
            "| ---: | --- | ---: | --- | --- |",
        ]
    )
    for index, group in enumerate(staging.get("stage_groups", []), start=1):
        lines.append(
            f"| {index} | `{group['logical_commit']}` | {group['entries']} | "
            f"`{group['stage_command']}` | `{group['commit_command']}` |"
        )
    lines.extend(
        [
            "",
            "Validation commands before tag/release/DOI:",
            "",
        ]
    )
    for command in staging.get("validation_commands", FINAL_VALIDATION_COMMANDS):
        lines.append(f"- `{command}`")
    lines.extend(
        [
            "",
            "Release blockers that must be resolved before tagging:",
            "",
        ]
    )
    for blocker in staging.get("release_blockers", []):
        lines.append(f"- {blocker}")

    lines.extend(["", "## Do Not Commit Review", ""])
    excluded = by_category.get("local_state_exclude", [])
    if not excluded:
        lines.append("- none")
    else:
        lines.extend(
            [
                "These paths look like local state, raw run material, or secrets-adjacent workspace data and should not be included in a public release commit:",
                "",
            ]
        )
        for entry in excluded[:preview_limit]:
            lines.append(f"- `{entry['status'].strip() or entry['status']}` `{entry['path']}`")
        if len(excluded) > preview_limit:
            lines.append(f"- ... {len(excluded) - preview_limit} more entries in JSON")

    lines.extend(["", "## Category Details", ""])
    for category, definition in CATEGORY_DEFINITIONS.items():
        category_entries = by_category.get(category, [])
        lines.extend(
            [
                f"### {definition['title']}",
                "",
                f"- category: `{category}`",
                f"- policy: `{definition['policy']}`",
                f"- logical_commit: `{definition['commit']}`",
                f"- entries: `{len(category_entries)}`",
                "",
            ]
        )
        if not category_entries:
            lines.append("- none")
        else:
            for entry in category_entries[:preview_limit]:
                lines.append(f"- `{entry['status']}` `{entry['path']}`")
            if len(category_entries) > preview_limit:
                lines.append(f"- ... {len(category_entries) - preview_limit} more entries in JSON")
        lines.append("")

    lines.extend(
        [
            "## Final Cleanup Gate",
            "",
            "Before tagging or publishing, fill release metadata, remove or intentionally ignore local-state entries, rerun the validation commands above, then tag the release and mint the public artifact DOI/URL.",
            "",
        ]
    )
    return "\n".join(lines)


def write_stage_pathspecs(inventory: dict[str, Any], stage_dir: Path) -> None:
    if not stage_dir.is_absolute():
        stage_dir = ROOT / stage_dir
    stage_dir.mkdir(parents=True, exist_ok=True)
    expected_names: set[str] = set()
    for group in inventory.get("release_staging_plan", {}).get("stage_groups", []):
        pathspec_file = Path(group["pathspec_file"])
        if not pathspec_file.is_absolute():
            pathspec_file = ROOT / pathspec_file
        expected_names.add(pathspec_file.name)
        paths = [str(path).replace("\\", "/") for path in group.get("paths", [])]
        pathspec_file.write_text("\n".join(paths) + "\n", encoding="utf-8")
    for stale in stage_dir.glob("*.txt"):
        if stale.name not in expected_names:
            stale.unlink()


def write_outputs(inventory: dict[str, Any], out_json: Path, out_md: Path, stage_dir: Path = DEFAULT_STAGE_DIR) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    write_stage_pathspecs(inventory, stage_dir)
    out_json.write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(inventory), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a logical commit inventory for the dirty worktree.")
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    parser.add_argument("--stage-dir", default=str(DEFAULT_STAGE_DIR))
    args = parser.parse_args()

    stage_dir = Path(args.stage_dir)
    inventory = build_inventory(run_git_status(), stage_dir=stage_dir)
    write_outputs(inventory, Path(args.out_json), Path(args.out_md), stage_dir)
    print(args.out_json)
    print(args.out_md)
    print(args.stage_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
