"""Apply finalized release metadata decisions to citation and license files."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CITATION_PATH = Path("CITATION.cff")
ACCEPTED_LICENSE_PATHS = {"LICENSE", "LICENSE.md", "COPYING", "COPYING.md"}
ACCEPTED_MAPPING_PATHS = {"LICENSES.md", "NOTICE"}
ACCEPTED_PUBLIC_LINK_FIELDS = {
    "doi",
    "url",
    "repository",
    "repository-code",
    "repository-artifact",
}
PLACEHOLDER_FRAGMENTS = [
    "Safety Bench Authors",
    "Anonymous",
    "TBD",
    "TODO",
    "REPLACE",
    "0.1.0-preprint",
]
DEFAULT_MESSAGE = (
    "If you use Safety Bench or its experiment artifacts, please cite the "
    "accompanying paper or this repository."
)
DEFAULT_ABSTRACT = (
    "Safety Bench evaluates persistent poisoning risks in agent harnesses across "
    "memory, skill, tool/MCP, and cross-boundary carriers using observable trace, "
    "honeypot, workspace, and tool-argument evidence."
)
DEFAULT_KEYWORDS = [
    "agent harness security",
    "prompt injection",
    "persistent poisoning",
    "benchmark",
    "tool security",
    "model context protocol",
]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def relpath(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def issue(severity: str, scope: str, message: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"severity": severity, "scope": scope, "message": message, "detail": detail or {}}


def quote_yaml(value: Any) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def normalized_rel_path(value: str, *, allowed: set[str], label: str) -> tuple[str, list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    text = str(value or "").replace("\\", "/").strip()
    if not text:
        issues.append(issue("error", label, f"{label} path is empty"))
        return "", issues
    path = Path(text)
    if path.is_absolute() or ".." in path.parts or "/" in text:
        issues.append(issue("error", label, f"{label} path must be a repository-root filename", {"path": text}))
        return text, issues
    if text not in allowed:
        issues.append(
            issue(
                "error",
                label,
                f"{label} path is not accepted by the release metadata checker",
                {"path": text, "accepted": sorted(allowed)},
            )
        )
    return text, issues


def has_placeholder(value: Any) -> bool:
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value or "")
    lower = text.lower()
    return any(fragment.lower() in lower for fragment in PLACEHOLDER_FRAGMENTS)


def validate_authors(authors: Any) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not isinstance(authors, list) or not authors:
        return [issue("error", "citation", "citation.authors must be a non-empty list")]
    for index, author in enumerate(authors):
        if not isinstance(author, dict):
            issues.append(issue("error", "citation", "citation author must be an object", {"index": index}))
            continue
        has_name = bool(str(author.get("name") or "").strip())
        has_split_name = bool(str(author.get("family-names") or "").strip()) and bool(str(author.get("given-names") or "").strip())
        if not has_name and not has_split_name:
            issues.append(
                issue(
                    "error",
                    "citation",
                    "citation author must include name or family-names plus given-names",
                    {"index": index},
                )
            )
        if has_placeholder(author):
            issues.append(issue("error", "citation", "citation author still contains placeholder text", {"index": index}))
    return issues


def validate_citation(citation: Any) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not isinstance(citation, dict):
        return [issue("error", "citation", "decision file must include a citation object")]
    required = ["title", "authors", "version", "date-released"]
    for field in required:
        if not citation.get(field):
            issues.append(issue("error", "citation", "citation field is required", {"field": field}))
    if citation.get("version") == "0.1.0-preprint" or "preprint" in str(citation.get("version") or "").lower():
        issues.append(issue("error", "citation", "citation version must be finalized and non-preprint"))
    date_value = str(citation.get("date-released") or "")
    if date_value and not re.match(r"^\d{4}-\d{2}-\d{2}$", date_value):
        issues.append(issue("error", "citation", "date-released must use YYYY-MM-DD", {"date-released": date_value}))
    if has_placeholder({key: citation.get(key) for key in ["title", "version", "date-released"]}):
        issues.append(issue("error", "citation", "citation metadata still contains placeholder text"))
    issues.extend(validate_authors(citation.get("authors")))
    if not any(str(citation.get(field) or "").strip() for field in ACCEPTED_PUBLIC_LINK_FIELDS):
        issues.append(
            issue(
                "error",
                "citation",
                "citation must include at least one public repository, artifact URL, or DOI field",
                {"accepted_fields": sorted(ACCEPTED_PUBLIC_LINK_FIELDS)},
            )
        )
    return issues


def validate_license(license_spec: Any, *, require_license: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if license_spec is None:
        if require_license:
            issues.append(issue("error", "license", "license object is required when --require-license is used"))
        return {}, issues
    if not isinstance(license_spec, dict):
        return {}, [issue("error", "license", "license must be an object")]
    path, path_issues = normalized_rel_path(str(license_spec.get("path") or "LICENSE"), allowed=ACCEPTED_LICENSE_PATHS, label="license")
    issues.extend(path_issues)
    text = str(license_spec.get("text") or "")
    if not text.strip():
        issues.append(issue("error", "license", "license.text must be non-empty"))
    if any(token in text.lower() for token in ["pending", "to be selected", "draft"]):
        issues.append(issue("error", "license", "license.text still appears to be draft or pending"))
    return {"path": path, "text": text}, issues


def validate_mapping(mapping_spec: Any) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if mapping_spec is None:
        return {}, []
    if not isinstance(mapping_spec, dict):
        return {}, [issue("error", "split_license_mapping", "split_license_mapping must be an object")]
    issues: list[dict[str, Any]] = []
    path, path_issues = normalized_rel_path(
        str(mapping_spec.get("path") or "LICENSES.md"),
        allowed=ACCEPTED_MAPPING_PATHS,
        label="split_license_mapping",
    )
    issues.extend(path_issues)
    text = str(mapping_spec.get("text") or "")
    if not text.strip():
        issues.append(issue("error", "split_license_mapping", "split_license_mapping.text must be non-empty"))
    return {"path": path, "text": text}, issues


def render_authors(authors: list[dict[str, Any]]) -> list[str]:
    lines = ["authors:"]
    for author in authors:
        keys = ["family-names", "given-names", "name", "orcid", "affiliation"]
        emitted = False
        for key in keys:
            value = author.get(key)
            if value:
                prefix = "  -" if not emitted else "   "
                lines.append(f"{prefix} {key}: {quote_yaml(value)}")
                emitted = True
    return lines


def render_citation(citation: dict[str, Any]) -> str:
    lines = [
        "cff-version: 1.2.0",
        f"message: {quote_yaml(citation.get('message') or DEFAULT_MESSAGE)}",
        f"title: {quote_yaml(citation['title'])}",
        f"type: {quote_yaml(citation.get('type') or 'software')}",
        *render_authors(citation["authors"]),
        f"version: {quote_yaml(citation['version'])}",
        f"date-released: {quote_yaml(citation['date-released'])}",
    ]
    for field in ["doi", "url", "repository", "repository-code", "repository-artifact"]:
        value = citation.get(field)
        if value:
            lines.append(f"{field}: {quote_yaml(value)}")
    abstract = citation.get("abstract") or DEFAULT_ABSTRACT
    if abstract:
        lines.append(f"abstract: {quote_yaml(abstract)}")
    keywords = citation.get("keywords", DEFAULT_KEYWORDS)
    if keywords:
        lines.append("keywords:")
        for keyword in keywords:
            lines.append(f"  - {quote_yaml(keyword)}")
    return "\n".join(lines) + "\n"


def build_changes(decision: dict[str, Any], *, require_license: bool = False) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if decision.get("example_only") is True:
        issues.append(
            issue(
                "error",
                "inputs",
                "decision file is marked example_only; copy it to docs/release_metadata_final.json and replace all placeholder values before applying",
            )
        )
    citation = decision.get("citation")
    issues.extend(validate_citation(citation))
    license_spec, license_issues = validate_license(decision.get("license"), require_license=require_license)
    issues.extend(license_issues)
    mapping_spec, mapping_issues = validate_mapping(decision.get("split_license_mapping"))
    issues.extend(mapping_issues)
    if issues:
        return [], issues

    changes = [
        {
            "path": str(DEFAULT_CITATION_PATH),
            "role": "citation",
            "content": render_citation(citation),
        }
    ]
    if license_spec:
        changes.append({"path": license_spec["path"], "role": "license", "content": license_spec["text"].rstrip() + "\n"})
    if mapping_spec:
        changes.append(
            {
                "path": mapping_spec["path"],
                "role": "split_license_mapping",
                "content": mapping_spec["text"].rstrip() + "\n",
            }
        )
    return changes, []


def write_changes(root: Path, changes: list[dict[str, Any]]) -> None:
    root_resolved = root.resolve()
    for change in changes:
        target = (root / change["path"]).resolve()
        try:
            target.relative_to(root_resolved)
        except ValueError as exc:  # pragma: no cover - validation should prevent this
            raise ValueError(f"refusing to write outside repository root: {target}") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(change["content"], encoding="utf-8")


def build_report(
    root: Path = ROOT,
    decision_path: Path | None = None,
    *,
    write: bool = False,
    require_license: bool = False,
) -> dict[str, Any]:
    if decision_path is None:
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "ok": False,
            "written": False,
            "issues": [issue("error", "inputs", "decision path is required")],
            "changes": [],
        }
    path = decision_path if decision_path.is_absolute() else root / decision_path
    if not path.is_file():
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "ok": False,
            "written": False,
            "issues": [issue("error", "inputs", "decision file is missing", {"path": str(decision_path)})],
            "changes": [],
        }
    try:
        decision = load_json(path)
    except Exception as exc:
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "ok": False,
            "written": False,
            "issues": [issue("error", "inputs", "could not parse decision JSON", {"error": str(exc)})],
            "changes": [],
        }
    changes, issues = build_changes(decision, require_license=require_license)
    if write and not issues:
        write_changes(root, changes)
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "decision_path": str(decision_path).replace("\\", "/"),
        "ok": not issues,
        "written": bool(write and not issues),
        "require_license": require_license,
        "issues": issues,
        "changes": [
            {
                "path": change["path"],
                "role": change["role"],
                "bytes": len(change["content"].encode("utf-8")),
            }
            for change in changes
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Apply Release Metadata Decisions",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- ok: `{str(report.get('ok')).lower()}`",
        f"- written: `{str(report.get('written')).lower()}`",
        f"- require_license: `{str(report.get('require_license', False)).lower()}`",
        f"- decision_path: `{report.get('decision_path', 'n/a')}`",
        "",
        "## Changes",
        "",
    ]
    if report.get("changes"):
        lines += ["| Role | Path | Bytes |", "| --- | --- | ---: |"]
        for change in report["changes"]:
            lines.append(f"| {change['role']} | `{change['path']}` | {change['bytes']} |")
    else:
        lines.append("- none")
    lines += ["", "## Issues", ""]
    if report.get("issues"):
        lines += ["| Severity | Scope | Message |", "| --- | --- | --- |"]
        for item in report["issues"]:
            lines.append(f"| {item['severity']} | {item['scope']} | {item['message']} |")
    else:
        lines.append("- none")
    if report.get("ok"):
        lines += [
            "",
            "## Next Validation",
            "",
            "```powershell",
            "python infra\\check_release_metadata.py --require-license",
            ".\\infra\\run_paper_preflight.ps1 -Profile submission",
            "```",
        ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply finalized release metadata decisions.")
    parser.add_argument("--decision", required=True, help="Path to finalized release metadata decision JSON.")
    parser.add_argument("--write", action="store_true", help="Write CITATION/license files. Without this, dry-run only.")
    parser.add_argument("--require-license", action="store_true", help="Require a final license object in the decision JSON.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    report = build_report(ROOT, Path(args.decision), write=args.write, require_license=args.require_license)
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n" if args.json else render_markdown(report)
    if args.out:
        out_path = ROOT / args.out
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
