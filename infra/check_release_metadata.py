"""Validate repository-level release metadata for paper artifacts."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

CITATION_FILE = "CITATION.cff"
FINAL_DECISION_FILE = "docs/release_metadata_final.json"
APPLY_TOOL_FILE = "infra/apply_release_metadata_decisions.py"
APPLY_DRY_RUN_COMMAND = (
    "python infra\\apply_release_metadata_decisions.py --decision "
    "docs\\release_metadata_final.json --require-license"
)
APPLY_WRITE_COMMAND = APPLY_DRY_RUN_COMMAND + " --write"
CHECK_COMMAND = "python infra\\check_release_metadata.py --require-license"
LICENSE_FILES = ["LICENSE", "LICENSE.md", "COPYING", "COPYING.md"]
SPLIT_LICENSE_MAPPING_FILES = ["LICENSES.md", "NOTICE"]
README_ENTRY_POINTS = ["README.md", "docs/README.md"]
RELEASE_TEXT_FILES = [
    *LICENSE_FILES,
    *SPLIT_LICENSE_MAPPING_FILES,
    "README.md",
    "RUNBOOK.md",
    "docs/README.md",
    "docs/paper_artifact_evaluation_readme.md",
    "docs/paper_bibliography.bib",
    "docs/paper_current_status.md",
    "docs/paper_draft.md",
    "docs/paper_experiment_protocol.md",
]
MOJIBAKE_FRAGMENTS = [
    "\u951b",
    "\u9428",
    "\u93c4",
    "\u4e64",
    "\u4e67",
    "\u4e7c",
    "\u7ecb",
    "\ufffd",
    "鏂",
    "褰",
    "妫",
    "鐨",
    "乣",
    "乺",
    "沘",
    "璁烘",
    "瀹為獙",
]
SUSPICIOUS_ROOT_NAMES = {
    "%SystemDrive%",
    "%USERPROFILE%",
    "%APPDATA%",
    "%LOCALAPPDATA%",
    "%TEMP%",
    "%TMP%",
}

REQUIRED_CITATION_SNIPPETS = [
    "cff-version:",
    "message:",
    "title:",
    "authors:",
    "version:",
    "date-released:",
]

CITATION_LINK_FIELDS = [
    "doi",
    "url",
    "repository",
    "repository-code",
    "repository-artifact",
]

PLACEHOLDER_AUTHOR_FRAGMENTS = [
    "Safety Bench Authors",
    "Anonymous",
    "TBD",
    "TODO",
    "REPLACE",
]


def has_issue(issues: list[dict[str, Any]], scope: str, *needles: str) -> bool:
    wanted = [needle.lower() for needle in needles]
    for item in issues:
        if item.get("scope") != scope:
            continue
        message = str(item.get("message", "")).lower()
        if all(needle in message for needle in wanted):
            return True
    return False


def next_action(
    action_id: str,
    action: str,
    *,
    required_before_public_release: bool = True,
    blocks_current_check: bool = False,
) -> dict[str, Any]:
    return {
        "id": action_id,
        "action": action,
        "required_before_public_release": required_before_public_release,
        "blocks_current_check": blocks_current_check,
    }


def issue(severity: str, scope: str, message: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "severity": severity,
        "scope": scope,
        "message": message,
        "detail": detail or {},
    }


def read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return ""


def has_reference(text: str, reference: str) -> bool:
    return reference in text or reference.replace("/", "\\") in text


def check_text_files(root: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for rel in RELEASE_TEXT_FILES:
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError as exc:
            issues.append(
                issue(
                    "error",
                    "text_encoding",
                    "release-facing text file is not UTF-8 readable",
                    {"path": rel, "error": str(exc)},
                )
            )
            continue
        for fragment in MOJIBAKE_FRAGMENTS:
            if fragment in text:
                issues.append(
                    issue(
                        "error",
                        "text_encoding",
                        "release-facing text file contains likely mojibake",
                        {"path": rel, "fragment": fragment},
                    )
                )
                break
    return issues


def check_workspace_hygiene(root: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for name in sorted(SUSPICIOUS_ROOT_NAMES):
        path = root / name
        if path.exists():
            issues.append(
                issue(
                    "error",
                    "workspace_hygiene",
                    "repository root contains a likely unexpanded environment-variable path",
                    {"path": name},
                )
            )
    return issues


def license_path(root: Path) -> Path | None:
    for rel in LICENSE_FILES:
        path = root / rel
        if path.is_file():
            return path
    return None


def split_license_mapping_path(root: Path) -> Path | None:
    for rel in SPLIT_LICENSE_MAPPING_FILES:
        path = root / rel
        if path.is_file():
            return path
    return None


def cff_has_field(text: str, field: str) -> bool:
    return bool(re.search(rf"(?m)^\s*{re.escape(field)}\s*:", text))


def check_citation(root: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    path = root / CITATION_FILE
    if not path.is_file():
        return [issue("error", "citation", "missing CITATION.cff", {"path": CITATION_FILE})]
    text = read_text(path)
    for snippet in REQUIRED_CITATION_SNIPPETS:
        if snippet not in text:
            issues.append(
                issue(
                    "error",
                    "citation",
                    "CITATION.cff is missing a required field",
                    {"field": snippet.rstrip(":")},
                )
            )
    if "Safety Bench" not in text:
        issues.append(issue("error", "citation", "CITATION.cff does not identify Safety Bench"))
    if "REPLACE" in text or "TODO" in text:
        issues.append(issue("warning", "citation", "CITATION.cff contains placeholder text"))
    for fragment in PLACEHOLDER_AUTHOR_FRAGMENTS:
        if fragment in text:
            issues.append(
                issue(
                    "warning",
                    "citation",
                    "CITATION.cff uses placeholder author metadata",
                    {"fragment": fragment},
                )
            )
            break
    if "0.1.0-preprint" in text:
        issues.append(issue("warning", "citation", "CITATION.cff is still marked as preprint"))
    if not any(cff_has_field(text, field) for field in CITATION_LINK_FIELDS):
        issues.append(
            issue(
                "warning",
                "citation",
                "CITATION.cff does not include repository URL or DOI",
                {"accepted_fields": CITATION_LINK_FIELDS},
            )
        )
    return issues


def check_release_docs(root: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    required_refs = [
        FINAL_DECISION_FILE,
        APPLY_TOOL_FILE,
        "check_release_metadata.py",
    ]
    for rel in README_ENTRY_POINTS:
        entry = root / rel
        text = read_text(entry) if entry.is_file() else ""
        for required in required_refs:
            if not has_reference(text, required):
                issues.append(
                    issue(
                        "error",
                        "release_docs",
                        "README entry point is missing required release metadata reference",
                        {"entry": rel, "reference": required},
                    )
                )
    artifact_readme = root / "docs/paper_artifact_evaluation_readme.md"
    artifact_text = read_text(artifact_readme) if artifact_readme.is_file() else ""
    for required in [FINAL_DECISION_FILE, APPLY_TOOL_FILE, CHECK_COMMAND]:
        if not has_reference(artifact_text, required):
            issues.append(
                issue(
                    "error",
                    "release_docs",
                    "artifact evaluation README is missing required release metadata reference",
                    {"path": str(artifact_readme.relative_to(root)), "reference": required},
                )
            )
    final_path = root / FINAL_DECISION_FILE
    if not final_path.is_file():
        issues.append(
            issue(
                "warning",
                "release_docs",
                "missing final release metadata decision file",
                {"path": FINAL_DECISION_FILE},
            )
        )
    return issues


def check_license(root: Path, require_license: bool) -> list[dict[str, Any]]:
    found = license_path(root)
    if found is None:
        severity = "error" if require_license else "warning"
        return [
            issue(
                severity,
                "license",
                "no finalized root license file found",
                {"accepted_names": LICENSE_FILES},
            )
        ]
    text = read_text(found)
    if any(token in text.lower() for token in ["pending", "to be selected", "draft"]):
        severity = "error" if require_license else "warning"
        return [issue(severity, "license", "root license appears to be draft or pending", {"path": found.name})]
    return []


def build_summary(
    root: Path,
    issues: list[dict[str, Any]],
    *,
    require_license: bool,
    found_license: Path | None,
    found_split_license_mapping: Path | None,
) -> dict[str, Any]:
    citation_text = read_text(root / CITATION_FILE)
    return {
        "error_count": sum(1 for item in issues if item["severity"] == "error"),
        "warning_count": sum(1 for item in issues if item["severity"] == "warning"),
        "license_required": require_license,
        "license_present": found_license is not None,
        "license_file": found_license.name if found_license else "",
        "split_license_mapping_present": found_split_license_mapping is not None,
        "split_license_mapping_file": found_split_license_mapping.name if found_split_license_mapping else "",
        "accepted_split_license_mapping_files": SPLIT_LICENSE_MAPPING_FILES,
        "license_draft_or_pending": has_issue(issues, "license", "draft")
        or has_issue(issues, "license", "pending"),
        "citation_file_present": (root / CITATION_FILE).is_file(),
        "citation_placeholder_author": any(fragment in citation_text for fragment in PLACEHOLDER_AUTHOR_FRAGMENTS),
        "citation_preprint": "0.1.0-preprint" in citation_text,
        "citation_has_public_link": any(cff_has_field(citation_text, field) for field in CITATION_LINK_FIELDS),
        "public_release_ready": len(issues) == 0,
    }


def build_next_actions(summary: dict[str, Any], issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []

    if not summary["citation_file_present"]:
        actions.append(
            next_action(
                "add_citation_file",
                (
                    "Create docs/release_metadata_final.json with title, authors, version, "
                    "date, and public repository or DOI metadata, then apply it with "
                    "infra/apply_release_metadata_decisions.py."
                ),
                blocks_current_check=True,
            )
        )
    elif has_issue(issues, "citation", "missing", "required field"):
        actions.append(
            next_action(
                "complete_required_citation_fields",
                (
                    "Fill the citation object in docs/release_metadata_final.json with "
                    "cff-version-compatible title, authors, version, and date-released metadata, "
                    "then apply it with infra/apply_release_metadata_decisions.py."
                ),
                blocks_current_check=True,
            )
        )

    if summary["citation_placeholder_author"]:
        actions.append(
            next_action(
                "finalize_citation_authors",
                (
                    "Set the final author list and order in docs/release_metadata_final.json, "
                    "then dry-run/apply with infra/apply_release_metadata_decisions.py."
                ),
            )
        )
    if summary["citation_preprint"]:
        actions.append(
            next_action(
                "finalize_version_date",
                (
                    "Set a final non-preprint version and release date in "
                    "docs/release_metadata_final.json, then dry-run/apply the decision file."
                ),
            )
        )
    if not summary["citation_has_public_link"]:
        actions.append(
            next_action(
                "add_public_url_or_doi",
                (
                    "Add a public repository URL, artifact URL, DOI, or artifact DOI to "
                    "docs/release_metadata_final.json, then dry-run/apply the decision file."
                ),
            )
        )

    if not summary["license_present"] or summary["license_draft_or_pending"]:
        actions.append(
            next_action(
                "add_final_license",
                (
                    "Put final root license text in docs/release_metadata_final.json, dry-run "
                    "infra/apply_release_metadata_decisions.py, rerun with --write, then rerun "
                    "check_release_metadata.py --require-license."
                ),
                blocks_current_check=summary["license_required"],
            )
        )

    if any(item.get("scope") == "release_docs" for item in issues):
        actions.append(
            next_action(
                "fix_release_docs",
                "Create docs/release_metadata_final.json and keep README.md/docs/README.md release commands current.",
                blocks_current_check=True,
            )
        )
    if any(item.get("scope") == "text_encoding" for item in issues):
        actions.append(
            next_action(
                "fix_release_text_encoding",
                "Fix non-UTF-8 or mojibake content in release-facing text files before public release.",
                blocks_current_check=True,
            )
        )
    if any(item.get("scope") == "workspace_hygiene" for item in issues):
        actions.append(
            next_action(
                "fix_workspace_hygiene",
                "Remove unexpanded environment-variable paths from the repository root before release.",
                blocks_current_check=True,
            )
        )
    return actions


def build_release_metadata_report(root: Path = ROOT, require_license: bool = False) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    issues.extend(check_workspace_hygiene(root))
    issues.extend(check_text_files(root))
    issues.extend(check_citation(root))
    issues.extend(check_release_docs(root))
    issues.extend(check_license(root, require_license=require_license))
    found_license = license_path(root)
    found_split_license_mapping = split_license_mapping_path(root)
    summary = build_summary(
        root,
        issues,
        require_license=require_license,
        found_license=found_license,
        found_split_license_mapping=found_split_license_mapping,
    )
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "require_license": require_license,
        "citation_file": CITATION_FILE,
        "final_decision_file": FINAL_DECISION_FILE,
        "license_file": found_license.name if found_license else "",
        "split_license_mapping_file": found_split_license_mapping.name if found_split_license_mapping else "",
        "summary": summary,
        "next_actions": build_next_actions(summary, issues),
        "issues": issues,
        "ok": not any(item["severity"] == "error" for item in issues),
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# Release Metadata Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- require_license: `{str(report['require_license']).lower()}`",
        f"- citation_file: `{report['citation_file']}`",
        f"- final_decision_file: `{report['final_decision_file']}`",
        f"- license_file: `{report['license_file'] or 'n/a'}`",
        f"- split_license_mapping_file: `{report.get('split_license_mapping_file') or 'n/a'}`",
        f"- ok: `{str(report['ok']).lower()}`",
        "",
        "## Summary",
        "",
        f"- errors: `{summary.get('error_count', 0)}`",
        f"- warnings: `{summary.get('warning_count', 0)}`",
        f"- public_release_ready: `{str(summary.get('public_release_ready', False)).lower()}`",
        f"- citation_placeholder_author: `{str(summary.get('citation_placeholder_author', False)).lower()}`",
        f"- citation_preprint: `{str(summary.get('citation_preprint', False)).lower()}`",
        f"- citation_has_public_link: `{str(summary.get('citation_has_public_link', False)).lower()}`",
        f"- license_present: `{str(summary.get('license_present', False)).lower()}`",
        f"- split_license_mapping_present: `{str(summary.get('split_license_mapping_present', False)).lower()}`",
        "",
        "## Next Actions",
        "",
    ]
    next_actions = report.get("next_actions", [])
    if next_actions:
        lines += ["| ID | Blocks Current Check | Required Before Public Release | Action |", "| --- | --- | --- | --- |"]
        for item in next_actions:
            lines.append(
                f"| {item['id']} | {str(item['blocks_current_check']).lower()} | "
                f"{str(item['required_before_public_release']).lower()} | {item['action']} |"
            )
        lines += [
            "",
            "## Finalization Commands",
            "",
            "```powershell",
            APPLY_DRY_RUN_COMMAND,
            APPLY_WRITE_COMMAND,
            CHECK_COMMAND,
            "```",
        ]
    else:
        lines.append("- none")
    lines += [
        "",
        "## Issues",
        "",
    ]
    if report["issues"]:
        lines += ["| Severity | Scope | Message |", "| --- | --- | --- |"]
        for item in report["issues"]:
            lines.append(f"| {item['severity']} | {item['scope']} | {item['message']} |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check repository release metadata.")
    parser.add_argument("--require-license", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    report = build_release_metadata_report(ROOT, require_license=args.require_license)
    text = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
