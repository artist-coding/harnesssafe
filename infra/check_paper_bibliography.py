"""Check paper bibliography and citation-key coverage."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

BIBLIOGRAPHY_FILE = "docs/paper_bibliography.bib"
SOURCE_DOCS = [
    "docs/paper_draft.md",
]

REQUIRED_BIB_KEYS = [
    "greshake2023indirect",
    "liu2024formalizing",
    "zhan2024injecagent",
    "debenedetti2024agentdojo",
    "ruan2024toolemu",
    "yao2024taubench",
    "dash2026memorypoisoning",
    "modelcontextprotocol2025spec",
    "nsa2026mcpsecurity",
    "owasp2025llm01",
    "ncsc2025promptinjection",
    "spracklen2025packagehallucinations",
    "zhang2024asb",
    "chen2024agentpoison",
    "dong2025minja",
    "xie2026memevobench",
    "pulipaka2026hiddenmemory",
    "karamchandani2026farma",
    "louck2026memoryauthority",
    "dai2026statefulbackdoor",
    "li2026plantpersisttrigger",
    "schmotz2026skillinject",
    "qu2026skillsupplychain",
    "xie2026scrbench",
    "jamshidi2025mcpsemantic",
    "huang2026mcptoolpoisoning",
    "liu2026sharelock",
    "lee2024promptinfection",
    "deng2026openclaw",
]

FORBIDDEN_PLACEHOLDERS = [
    "[CITE]",
    "TODO",
    "TBD",
]

BIB_ENTRY_RE = re.compile(r"@\w+\{([^,\s]+),")
CITATION_KEY_RE = re.compile(r"`([a-z][a-z0-9]*\d{4}[a-z0-9]*)`")


def issue(severity: str, scope: str, message: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "severity": severity,
        "scope": scope,
        "message": message,
        "detail": detail or {},
    }


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def extract_bib_keys(text: str) -> set[str]:
    return set(BIB_ENTRY_RE.findall(text))


def extract_citation_keys(text: str) -> set[str]:
    return set(CITATION_KEY_RE.findall(text))


def first_match_location(text: str, phrase: str) -> dict[str, Any]:
    index = text.lower().find(phrase.lower())
    if index < 0:
        return {}
    line = text.count("\n", 0, index) + 1
    lines = text.splitlines()
    preview = lines[line - 1].strip() if line <= len(lines) else ""
    return {"line": line, "preview": preview[:240]}


def build_bibliography_report(
    root: Path = ROOT,
    bibliography_file: str = BIBLIOGRAPHY_FILE,
    source_docs: list[str] | None = None,
) -> dict[str, Any]:
    source_docs = source_docs or list(SOURCE_DOCS)
    issues: list[dict[str, Any]] = []
    bib_path = root / bibliography_file
    bib_text = ""
    if not bib_path.is_file():
        issues.append(issue("error", "bibliography", "missing bibliography file", {"path": bibliography_file}))
    else:
        bib_text = read_text(bib_path)

    bib_keys = extract_bib_keys(bib_text)
    doc_records: list[dict[str, Any]] = []
    cited_by_doc: dict[str, list[str]] = {}
    all_cited_keys: set[str] = set()
    manuscript_text = ""

    for rel in source_docs:
        path = root / rel
        if not path.is_file():
            issues.append(issue("error", "bibliography", "missing citation source document", {"path": rel}))
            doc_records.append({"path": rel, "exists": False, "citation_keys": []})
            continue
        text = read_text(path)
        if rel == "docs/paper_draft.md":
            manuscript_text = text
        keys = extract_citation_keys(text)
        all_cited_keys.update(keys)
        cited_by_doc[rel] = sorted(keys)
        doc_records.append({"path": rel, "exists": True, "citation_keys": sorted(keys)})
        lower_text = text.lower()
        for phrase in FORBIDDEN_PLACEHOLDERS:
            if phrase.lower() in lower_text:
                detail = {"path": rel, "phrase": phrase}
                detail.update(first_match_location(text, phrase))
                issues.append(
                    issue(
                        "error",
                        "bibliography",
                        "citation source contains unresolved placeholder",
                        detail,
                    )
                )

    for key in REQUIRED_BIB_KEYS:
        if key not in bib_keys:
            issues.append(issue("error", "bibliography", "required BibTeX key is missing", {"key": key}))
        if key not in manuscript_text:
            issues.append(
                issue(
                    "error",
                    "bibliography",
                    "required citation key is missing from the canonical manuscript",
                    {"key": key},
                )
            )

    unknown_cited_keys = sorted(key for key in all_cited_keys if key not in bib_keys)
    for key in unknown_cited_keys:
        issues.append(issue("error", "bibliography", "cited key is missing from BibTeX bibliography", {"key": key}))

    unused_required_keys = sorted(key for key in REQUIRED_BIB_KEYS if key in bib_keys and key not in all_cited_keys)
    for key in unused_required_keys:
        issues.append(issue("warning", "bibliography", "required BibTeX key is not cited in scanned source docs", {"key": key}))

    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "bibliography_file": bibliography_file,
        "source_docs": doc_records,
        "required_keys": REQUIRED_BIB_KEYS,
        "bib_keys": sorted(bib_keys),
        "cited_keys": sorted(all_cited_keys),
        "cited_by_doc": cited_by_doc,
        "missing_required_bib_keys": sorted(key for key in REQUIRED_BIB_KEYS if key not in bib_keys),
        "missing_related_work_keys": sorted(key for key in REQUIRED_BIB_KEYS if key not in manuscript_text),
        "unknown_cited_keys": unknown_cited_keys,
        "unused_required_keys": unused_required_keys,
        "issues": issues,
        "ok": not any(item.get("severity") == "error" for item in issues),
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Paper Bibliography Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- ok: `{str(report['ok']).lower()}`",
        f"- bibliography_file: `{report['bibliography_file']}`",
        f"- required_keys: `{len(report['required_keys'])}`",
        f"- bib_keys: `{len(report['bib_keys'])}`",
        f"- cited_keys: `{len(report['cited_keys'])}`",
        f"- missing_required_bib_keys: `{len(report['missing_required_bib_keys'])}`",
        f"- missing_related_work_keys: `{len(report['missing_related_work_keys'])}`",
        f"- unknown_cited_keys: `{len(report['unknown_cited_keys'])}`",
        f"- unused_required_keys: `{len(report['unused_required_keys'])}`",
        "",
        "## Source Documents",
        "",
        "| Path | Exists | Citation keys |",
        "| --- | --- | ---: |",
    ]
    for item in report.get("source_docs", []):
        lines.append(
            f"| {item.get('path')} | `{str(item.get('exists')).lower()}` | {len(item.get('citation_keys', []))} |"
        )
    lines += ["", "## Issues", ""]
    if report.get("issues"):
        lines += ["| Severity | Scope | Message | Detail |", "| --- | --- | --- | --- |"]
        for item in report["issues"]:
            detail = json.dumps(item.get("detail", {}), ensure_ascii=False, sort_keys=True)
            lines.append(f"| {item.get('severity')} | {item.get('scope')} | {item.get('message')} | `{detail}` |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check paper bibliography citation coverage.")
    parser.add_argument("--bibliography", default=BIBLIOGRAPHY_FILE)
    parser.add_argument("--source-doc", action="append", default=[])
    parser.add_argument("--out-json", default="")
    parser.add_argument("--out-md", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = build_bibliography_report(
        root=ROOT,
        bibliography_file=args.bibliography,
        source_docs=args.source_doc or None,
    )
    if args.out_json:
        Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out_json).write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.out_md:
        Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out_md).write_text(render_markdown(report), encoding="utf-8")
    if not args.out_json and not args.out_md:
        if args.json:
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(render_markdown(report), end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
