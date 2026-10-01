"""Check paper claim boundaries against the current experiment state."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

CURRENT_REQUIRED_PHRASES = {
    "docs/paper_draft.md": [
        "328 active hard-oracle cases",
        "one attack trial per case",
        "Evaluation Record v3",
        "protocol noncompletion",
        "conditional ASR",
        "end-to-end attack rate",
    ],
    "docs/paper_artifact_evaluation_readme.md": [
        "328 active hard-oracle cases",
        "CaseSet=all",
        "one attack trial per case",
        "Evaluation Record v3",
        "protocol-noncompletion",
        "execution-invalid",
    ],
    "docs/paper_current_status.md": [
        "one attack trial per case",
        "Evaluation Record v3",
        "attempted all 328 cases",
        "protocol-noncompletion",
        "execution invalid",
    ],
}

CURRENT_FORBIDDEN_PHRASES = {
    "docs/paper_draft.md": [
        "| core cases | 57 |",
        "| planned rows | 399 |",
        "130 eligible extended candidates",
        "23/171",
        "7/171",
        "paper_core_20260625",
        "paper_controls_core_20260625",
        "RESULTS_PENDING_FORMAL_MATRIX",
        "The formal queue has not started",
        "Formal quantitative results will be reported only after",
    ],
    "docs/paper_artifact_evaluation_readme.md": [
        "formal result matrix has not yet been executed",
        "The normative plan contains 984 attack rows",
    ],
    "docs/paper_current_status.md": [
        "Formal 2,296-row matrix | not started",
        "Formal quantitative results | unavailable",
    ],
}
SUBMISSION_FORBIDDEN_PHRASES = {
    "docs/paper_draft.md": [
        "RESULTS_PENDING_FORMAL_MATRIX",
        "The formal queue has not started",
        "will be populated only when",
        "Formal quantitative results will be reported only after",
    ],
    "docs/paper_artifact_evaluation_readme.md": [
        "formal result matrix has not yet been executed",
        "intentionally absent before the matrix is complete",
    ],
    "docs/paper_current_status.md": [
        "Formal 2,296-row matrix | not started",
        "Formal quantitative results | unavailable",
    ],
}

SUBMISSION_REQUIRED_PHRASES = {
    "docs/paper_draft.md": [
        "328 active hard-oracle cases",
        "one attack trial per case",
        "Evaluation Record v3",
        "protocol noncompletion",
        "conditional ASR",
        "end-to-end attack rate",
        "328-Case Attack Results",
    ],
    "docs/paper_artifact_evaluation_readme.md": [
        "328 active hard-oracle cases",
        "one attack trial per case",
        "Evaluation Record v3",
        "protocol-noncompletion",
        "execution-invalid",
    ],
}

NO_CITE_PLACEHOLDER_DOCS = [
    "docs/paper_draft.md",
]

CURRENT_ACTIVE_CASE_COUNT = 328
CROSS_HARNESS_EXCLUDED_CASES = 30
STALE_SCOPE_COUNT = CURRENT_ACTIVE_CASE_COUNT + CROSS_HARNESS_EXCLUDED_CASES
STALE_SCOPE_PROVENANCE_DOCS: set[str] = set()
ROOT_SCOPE_DOCS = (
    "README.md",
    "CLAUDE.md",
    "RUNBOOK.md",
    "runs/README.md",
)
HISTORICAL_LINE_MARKERS = (
    "historical",
    "provenance",
    "superseded",
    "pre-freeze",
    "former",
    "amendment",
    "原 ",
    "从原",
)

PREFREEZE_OPERATIONAL_DOCS = (
    "runs/manifest.json",
    "docs/paper_current_status.md",
)
PREMATURE_FREEZE_PATTERNS = (
    re.compile(r"\bfrozen-scope\b", re.IGNORECASE),
    re.compile(r"\b328-case benchmark design is frozen\b", re.IGNORECASE),
    re.compile(r"\bthe formal 328-case experiment matrix is complete\b", re.IGNORECASE),
    re.compile(r"冻结的\s*328-case\s*正式矩阵", re.IGNORECASE),
)
NEGATED_OR_CONDITIONAL_FREEZE_MARKERS = (
    "cannot declare",
    "cannot claim",
    "not frozen",
    "not yet",
    "only after",
    "pre-freeze",
    "future",
    "不能声明",
    "不得声明",
    "尚未",
    "拟冻结",
    "才可以",
    "才能",
)

FORMAL_SERIAL_FORBIDDEN_SWITCHES = (
    "--batch",
    "--harness",
    "--include-post-run",
    "--skip-readiness-check",
)


def issue(severity: str, path: str, message: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "severity": severity,
        "path": path,
        "message": message,
        "detail": detail or {},
    }


def read_doc(root: Path, rel: str) -> str:
    path = root / rel
    return path.read_text(encoding="utf-8-sig") if path.is_file() else ""


def first_match_location(text: str, phrase: str) -> dict[str, Any]:
    index = text.lower().find(phrase.lower())
    if index < 0:
        return {}
    line = text.count("\n", 0, index) + 1
    lines = text.splitlines()
    preview = lines[line - 1].strip() if line <= len(lines) else ""
    return {"line": line, "preview": preview[:240]}


def contains_phrase(text: str, phrase: str) -> bool:
    compact_text = " ".join(text.split()).lower()
    compact_phrase = " ".join(phrase.split()).lower()
    return compact_phrase in compact_text


def require_phrases(root: Path, requirements: dict[str, list[str]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for rel, phrases in requirements.items():
        text = read_doc(root, rel)
        if not text:
            issues.append(issue("error", rel, "required paper claim document is missing"))
            continue
        for phrase in phrases:
            if not contains_phrase(text, phrase):
                issues.append(
                    issue(
                        "error",
                        rel,
                        "required claim-boundary phrase is missing",
                        {"phrase": phrase},
                    )
                )
    return issues


def forbid_phrases(root: Path, forbidden: dict[str, list[str]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for rel, phrases in forbidden.items():
        text = read_doc(root, rel)
        if not text:
            issues.append(issue("error", rel, "required paper claim document is missing"))
            continue
        lower_text = text.lower()
        for phrase in phrases:
            if phrase.lower() in lower_text:
                detail = {"phrase": phrase}
                detail.update(first_match_location(text, phrase))
                issues.append(
                    issue(
                        "error",
                        rel,
                        "submission profile still contains current/preliminary claim language",
                        detail,
                    )
                )
    return issues


def check_cite_placeholders(root: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for rel in NO_CITE_PLACEHOLDER_DOCS:
        text = read_doc(root, rel)
        if "[CITE]" in text:
            issues.append(
                issue(
                    "error",
                    rel,
                    "paper document still contains [CITE] placeholder",
                    first_match_location(text, "[CITE]"),
                )
            )
    return issues


def check_stale_scope_references(root: Path) -> list[dict[str, Any]]:
    """Reject former formal-scope counts except in explicitly labeled provenance."""

    issues: list[dict[str, Any]] = []
    # Treat the former denominator as a standalone numeric token.  Looking
    # around for only decimal digits produced false positives whenever a
    # SHA-256 digest happened to contain the hexadecimal substring ``358``.
    pattern = re.compile(rf"(?<![A-Za-z0-9]){STALE_SCOPE_COUNT}(?![A-Za-z0-9])")
    docs_root = root / "docs"
    paths = [
        path
        for path in (sorted(docs_root.rglob("*")) if docs_root.is_dir() else [])
        if path.is_file() and path.suffix.lower() in {".md", ".json"}
    ]
    paths.extend(
        path
        for rel in ROOT_SCOPE_DOCS
        if (path := root / rel).is_file() and path not in paths
    )
    for path in paths:
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        if rel in STALE_SCOPE_PROVENANCE_DOCS:
            prefix = text[:800].lower()
            if not any(
                marker in prefix
                for marker in (
                    "superseded",
                    "historical",
                    "provenance",
                    "pre-amendment",
                    "amendment",
                )
            ):
                issues.append(
                    issue(
                        "error",
                        rel,
                        "former-scope provenance document lacks an explicit historical marker",
                    )
                )
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not pattern.search(line):
                continue
            lower = line.lower()
            if any(marker in lower for marker in HISTORICAL_LINE_MARKERS):
                continue
            issues.append(
                issue(
                    "error",
                    rel,
                    "stale former formal-scope reference is not labeled as provenance",
                    {"line": line_number, "preview": line.strip()[:240]},
                )
            )
    return issues


def check_premature_freeze_claims(root: Path) -> list[dict[str, Any]]:
    """Reject positive freeze/completion claims in the pre-freeze profile.

    The target declarations are intentionally allowed when the same line is
    explicitly negated or conditional (for example, "cannot declare ...").
    This keeps the status document useful while preventing an operational
    manifest or current contract from silently claiming a gate that has not
    yet been met.
    """

    issues: list[dict[str, Any]] = []
    for rel in PREFREEZE_OPERATIONAL_DOCS:
        text = read_doc(root, rel)
        if not text:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            lower = line.lower()
            if any(marker in lower for marker in NEGATED_OR_CONDITIONAL_FREEZE_MARKERS):
                continue
            for pattern in PREMATURE_FREEZE_PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                issues.append(
                    issue(
                        "error",
                        rel,
                        "pre-freeze operational document makes a premature freeze/completion claim",
                        {
                            "line": line_number,
                            "phrase": match.group(0),
                            "preview": line.strip()[:240],
                        },
                    )
                )
                break
    return issues


def check_formal_serial_execution_commands(root: Path) -> list[dict[str, Any]]:
    """Reject documented formal commands that the serial consumer fails closed.

    Formal execution consumes the single preregistered 2,296-row order.  Batch
    or harness filters, inline post-processing, and readiness bypasses are
    intentionally forbidden by ``run_paper_queue.py``.  Reviewer-facing docs
    must not advertise a command that looks executable but is guaranteed to be
    rejected at the freeze boundary.
    """

    paths: list[Path] = []
    for rel in ("README.md", "RUNBOOK.md"):
        path = root / rel
        if path.is_file():
            paths.append(path)
    docs_root = root / "docs"
    if docs_root.is_dir():
        paths.extend(
            path
            for path in sorted(docs_root.rglob("*.md"))
            if "generated_artifacts" not in path.relative_to(root).parts
        )

    issues: list[dict[str, Any]] = []
    serial_re = re.compile(r"--queue-mode\s+serial\b", re.IGNORECASE)
    for path in paths:
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            lower = line.lower()
            if (
                "run_paper_queue.py" not in lower
                or "--execute" not in lower
                or not serial_re.search(line)
            ):
                continue
            forbidden = [
                switch for switch in FORMAL_SERIAL_FORBIDDEN_SWITCHES if switch in lower
            ]
            if not forbidden:
                continue
            issues.append(
                issue(
                    "error",
                    rel,
                    "formal serial execute command contains a forbidden filter or readiness bypass",
                    {
                        "line": line_number,
                        "switches": forbidden,
                        "preview": line.strip()[:240],
                    },
                )
            )
    return issues


def build_claim_report(root: Path = ROOT, profile: str = "current_claude") -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    if profile == "current_claude":
        issues.extend(require_phrases(root, CURRENT_REQUIRED_PHRASES))
        issues.extend(forbid_phrases(root, CURRENT_FORBIDDEN_PHRASES))
    elif profile == "submission":
        issues.extend(require_phrases(root, SUBMISSION_REQUIRED_PHRASES))
        issues.extend(forbid_phrases(root, SUBMISSION_FORBIDDEN_PHRASES))
    else:
        raise ValueError(f"unknown profile: {profile}")
    issues.extend(check_cite_placeholders(root))
    issues.extend(check_stale_scope_references(root))
    issues.extend(check_formal_serial_execution_commands(root))
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "profile": profile,
        "root": str(root),
        "issues": issues,
        "ok": not any(item["severity"] == "error" for item in issues),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Paper Claim Boundary Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- profile: `{report['profile']}`",
        f"- ok: `{str(report['ok']).lower()}`",
        "",
        "## Issues",
        "",
    ]
    if report["issues"]:
        lines += ["| Severity | Path | Message |", "| --- | --- | --- |"]
        for item in report["issues"]:
            lines.append(f"| {item['severity']} | `{item['path']}` | {item['message']} |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check paper claim-boundary language.")
    parser.add_argument("--profile", choices=["current_claude", "submission"], default="current_claude")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    report = build_claim_report(ROOT, profile=args.profile)
    text = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
