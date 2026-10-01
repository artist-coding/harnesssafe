"""Check the paper manuscript draft for required submission-support sections."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DRAFT = "docs/paper_draft.md"

REQUIRED_SECTIONS = [
    "# Safety Bench:",
    "## Abstract",
    "## 1. Introduction",
    "## 2. Threat Model",
    "## 3. Benchmark Design",
    "## 4. Scoring And Oracles",
    "## 5. Experimental Protocol",
    "## 6. 328-Case Attack Results",
    "## 7. Controls And Ablations",
    "## 8. Case Studies",
    "## 9. Related Work",
    "## 10. Responsible Release And Artifact Safety",
    "## 11. Limitations",
    "## 12. Reproducibility",
    "## 13. Conclusion",
]

REQUIRED_PHRASES = [
    "Claude Code + Kimi K2.6",
    "Claude Code + MiniMax M2.5",
    "328 cases",
    "328 active hard-oracle cases",
    "one attack trial",
    "Evaluation Record v3",
    "Source run-validity schema",
    "Clean control",
    "No-persist control",
    "No-trigger control",
    "Cleanup control",
    "N0-N5b",
    "protocol noncompletion",
    "execution-invalid",
    "conditional ASR",
    "end-to-end attack rate",
    "Entry -> Carrier -> Boundary -> Trigger -> Violation",
    "This pattern is easy to miss in single-turn evaluations",
    "53.37%",
    "53.97%",
    "handoff/proced_context.md",
    "Sixty-nine current cases use `O_local_marker`",
    "docs/paper_artifact_evaluation_readme.md",
]

FORBIDDEN_PHRASES = [
    "[CITE]",
    "TODO",
    "TBD",
    "Manuscript status:",
    "analysis draft",
    "working manuscript",
    "draft narrative",
    "working selections",
    "final venue-specific polish is still needed",
    "Kimi K2.6 remains pending",
    "preliminary Claude",
    "RESULTS_PENDING_FORMAL_MATRIX",
    "2,296",
    "three attack trials",
    "formal queue has not started",
    "paper_core_20260625",
    "paper_controls_core_20260625",
    "23/171",
    "7/171",
    "130 eligible extended candidates",
]


def issue(severity: str, scope: str, message: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "severity": severity,
        "scope": scope,
        "message": message,
        "detail": detail or {},
    }


def first_match_location(text: str, phrase: str) -> dict[str, Any]:
    index = text.lower().find(phrase.lower())
    if index < 0:
        return {}
    line = text.count("\n", 0, index) + 1
    lines = text.splitlines()
    preview = lines[line - 1].strip() if line <= len(lines) else ""
    return {"line": line, "preview": preview[:240]}


def section_order(text: str, headings: list[str]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    last_index = -1
    for heading in headings:
        index = text.find(heading)
        if index < 0:
            issues.append(issue("error", "sections", "required manuscript section is missing", {"section": heading}))
            continue
        if index < last_index:
            issues.append(
                issue(
                    "error",
                    "sections",
                    "required manuscript section is out of order",
                    {"section": heading},
                )
            )
        last_index = index
    return issues


def markdown_table_count(text: str) -> int:
    return len(re.findall(r"(?m)^\| .+ \|$", text))


def contains_phrase(text: str, phrase: str) -> bool:
    compact_text = re.sub(r"\s+", " ", text)
    compact_phrase = re.sub(r"\s+", " ", phrase)
    return compact_phrase in compact_text


def build_manuscript_report(root: Path = ROOT, draft: Path | None = None) -> dict[str, Any]:
    draft_path = draft or root / DEFAULT_DRAFT
    issues: list[dict[str, Any]] = []
    if not draft_path.is_file():
        issues.append(issue("error", "inputs", "paper manuscript draft is missing", {"path": str(draft_path)}))
        text = ""
    else:
        text = draft_path.read_text(encoding="utf-8-sig")
        issues.extend(section_order(text, REQUIRED_SECTIONS))
        for phrase in REQUIRED_PHRASES:
            if not contains_phrase(text, phrase):
                issues.append(
                    issue(
                        "error",
                        "required_content",
                        "required manuscript support phrase is missing",
                        {"phrase": phrase},
                    )
                )
        lower_text = text.lower()
        for phrase in FORBIDDEN_PHRASES:
            if phrase.lower() in lower_text:
                detail = {"phrase": phrase}
                detail.update(first_match_location(text, phrase))
                issues.append(
                    issue(
                        "error",
                        "forbidden_content",
                        "manuscript contains unresolved or obsolete language",
                        detail,
                    )
                )
        if markdown_table_count(text) < 5:
            issues.append(
                issue(
                    "error",
                    "structure",
                    "manuscript should include enough summary tables for benchmark, scoring, results, controls, and evidence",
                    {"table_rows_detected": markdown_table_count(text), "minimum": 5},
                )
            )
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "draft": str(draft_path),
        "required_sections": len(REQUIRED_SECTIONS),
        "required_phrases": len(REQUIRED_PHRASES),
        "forbidden_phrases": len(FORBIDDEN_PHRASES),
        "markdown_table_rows": markdown_table_count(text),
        "issues": issues,
        "ok": not any(item.get("severity") == "error" for item in issues),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Paper Manuscript Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- ok: `{str(report['ok']).lower()}`",
        f"- draft: `{report['draft']}`",
        f"- required_sections: `{report['required_sections']}`",
        f"- required_phrases: `{report['required_phrases']}`",
        f"- forbidden_phrases: `{report['forbidden_phrases']}`",
        f"- markdown_table_rows: `{report['markdown_table_rows']}`",
        "",
        "## Issues",
        "",
    ]
    if report["issues"]:
        lines += ["| Severity | Scope | Message | Detail |", "| --- | --- | --- | --- |"]
        for item in report["issues"]:
            detail = json.dumps(item.get("detail", {}), ensure_ascii=False, sort_keys=True)
            lines.append(f"| {item.get('severity')} | {item.get('scope')} | {item.get('message')} | `{detail}` |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check paper manuscript draft completeness.")
    parser.add_argument("--draft", default=DEFAULT_DRAFT)
    parser.add_argument("--out", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = build_manuscript_report(ROOT, draft=Path(args.draft))
    text = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
