"""Check that a public repro bundle does not copy raw run evidence or secrets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent

ALLOWED_COPIED_ROLE_PREFIXES = (
    "attack_report:",
    "control_report",
    "tables:",
    "case_study_evidence:",
    "benchmark_card:",
    "supplementary_appendix:",
    "oracle_coverage:",
    "threat_model_card:",
    "statistical_analysis:",
    "claim_evidence_map:",
    "control_integrity:",
    "paper_figures:",
    "bibliography_check:",
    "manuscript:",
    "full_suite_eligibility:",
    "external_validity_plan:",
    "suite_lock:",
    "experiment_plan:",
    "matrix_progress:",
    "run_queue:",
    "run_execution:",
    "run_budget:",
    "submission_gap:",
    "submission_objective:",
    "submission_package:",
    "live_status:",
    "release_metadata:",
)

FORBIDDEN_BASENAMES = {
    "trace.jsonl": "raw harness trace",
    "trace.err": "raw harness stderr",
    "honeypot.jsonl": "raw honeypot capture",
    "oracle.json": "raw oracle payload",
    "oracle.md": "raw oracle report",
    "case.json": "materialized case payload",
    "callback_resolution.json": "callback runtime metadata",
    "deployment.id": "deployment canary metadata",
}

FORBIDDEN_PATH_FRAGMENTS = {
    "/materialized_case/": "materialized case directory",
    "/agent_home/": "run-scoped agent home",
    "/global_config_guard/": "global config guard snapshot",
    "/bench_state/secrets/": "local benchmark secret directory",
    "/.claude/": "local Claude config directory",
    "/.codex/": "local Codex config directory",
    "/.hermes/": "local Hermes config directory",
}

CANARY_RE = re.compile(r"\bdpl-[A-Za-z0-9][A-Za-z0-9_-]{10,}\b")
SECRET_VALUE_RE = re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{18,}\b")
ENV_ASSIGN_RE = re.compile(
    r"\b(?P<name>ANTHROPIC_AUTH_TOKEN|ANTHROPIC_API_KEY|DASHSCOPE_CODING_API_KEY|DASHSCOPE_API_KEY|OPENAI_API_KEY)\b"
    r"\s*[:=]\s*(?P<value>[^\r\n#]+)",
    flags=re.IGNORECASE,
)


def artifact_issue(
    severity: str,
    scope: str,
    message: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "severity": severity,
        "scope": scope,
        "message": message,
        "detail": detail or {},
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def norm_slashes(value: str) -> str:
    return value.replace("\\", "/")


def relpath(path: Path, base: Path) -> str:
    try:
        return norm_slashes(str(path.resolve().relative_to(base.resolve())))
    except ValueError:
        return norm_slashes(str(path))


def manifest_copied_path(raw: str, bundle_dir: Path) -> str:
    text = norm_slashes(str(raw or "")).lstrip("./")
    if not text:
        return ""
    if text.startswith("files/"):
        return text
    marker = "/files/"
    if marker in text:
        return "files/" + text.split(marker, 1)[1]
    try:
        return relpath(Path(raw), bundle_dir)
    except (OSError, ValueError):
        return text


def load_manifest(bundle_dir: Path) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    manifest_path = bundle_dir / "repro_manifest.json"
    if not manifest_path.is_file():
        return None, [artifact_issue("error", "manifest", "missing repro_manifest.json")]
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8-sig")), []
    except Exception as exc:  # pragma: no cover - defensive parsing guard
        return None, [
            artifact_issue(
                "error",
                "manifest",
                "could not parse repro_manifest.json",
                {"error": str(exc)},
            )
        ]


def copied_artifact_index(manifest: dict[str, Any], bundle_dir: Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for item in manifest.get("copied_artifacts", []) or []:
        copied = manifest_copied_path(str(item.get("copied_to") or ""), bundle_dir)
        if copied:
            out[copied] = item
    return out


def check_copied_scope(bundle_dir: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    files_dir = bundle_dir / "files"
    copied_index = copied_artifact_index(manifest, bundle_dir)
    copied_files = [
        relpath(path, bundle_dir)
        for path in files_dir.rglob("*")
        if path.is_file()
    ] if files_dir.is_dir() else []

    if copied_files and not copied_index:
        return [
            artifact_issue(
                "error",
                "copy_scope",
                "bundle files are not recorded in copied_artifacts",
                {"file_count": len(copied_files)},
            )
        ]

    for copied in copied_files:
        if copied not in copied_index:
            issues.append(
                artifact_issue(
                    "error",
                    "copy_scope",
                    "bundle contains an unmanifested copied file",
                    {"path": copied},
                )
            )

    for copied, item in copied_index.items():
        role = str(item.get("role") or "")
        if not role.startswith(ALLOWED_COPIED_ROLE_PREFIXES):
            issues.append(
                artifact_issue(
                    "error",
                    "copy_scope",
                    "copied artifact role is not public-bundle allowlisted",
                    {"role": role, "path": copied},
                )
            )
        path = bundle_dir / copied
        if not path.is_file():
            issues.append(
                artifact_issue(
                    "error",
                    "copy_scope",
                    "copied artifact is missing from bundle files",
                    {"path": copied},
                )
            )
            continue
        expected_hash = str(item.get("copied_sha256") or "")
        if expected_hash and sha256(path) != expected_hash:
            issues.append(
                artifact_issue(
                    "error",
                    "copy_scope",
                    "copied artifact hash does not match repro manifest",
                    {"path": copied},
                )
            )
    return issues


def check_forbidden_paths(bundle_dir: Path) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for path in bundle_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = relpath(path, bundle_dir)
        normalized = "/" + rel.lower().replace("\\", "/")
        basename = path.name.lower()
        if basename in FORBIDDEN_BASENAMES:
            issues.append(
                artifact_issue(
                    "error",
                    "path",
                    "bundle copies a forbidden raw run file",
                    {
                        "path": rel,
                        "kind": FORBIDDEN_BASENAMES[basename],
                    },
                )
            )
        for fragment, description in FORBIDDEN_PATH_FRAGMENTS.items():
            if fragment in normalized:
                issues.append(
                    artifact_issue(
                        "error",
                        "path",
                        "bundle copies a forbidden runtime directory",
                        {"path": rel, "kind": description},
                    )
                )
    return issues


def is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            sample = f.read(4096)
    except OSError:
        return True
    return b"\0" in sample


def is_placeholder_secret(value: str) -> bool:
    token = value.strip().strip("\"'`").strip()
    lower = token.lower()
    if not token:
        return True
    if token.startswith("<") and token.endswith(">"):
        return True
    if token.startswith("$"):
        return True
    if lower in {"true", "false", "null", "none", "n/a"}:
        return True
    return any(marker in lower for marker in ["your-key", "dashscope-key", "placeholder", "redacted", "example"])


def line_detail(path: Path, bundle_dir: Path, line_number: int, kind: str) -> dict[str, Any]:
    return {
        "path": relpath(path, bundle_dir),
        "line": line_number,
        "kind": kind,
    }


def check_text_file(path: Path, bundle_dir: Path) -> tuple[list[dict[str, Any]], bool]:
    if is_binary(path):
        return [], False
    issues: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                if CANARY_RE.search(line):
                    issues.append(
                        artifact_issue(
                            "error",
                            "content",
                            "bundle text contains a deployment canary token",
                            line_detail(path, bundle_dir, line_number, "dpl-canary"),
                        )
                    )
                if SECRET_VALUE_RE.search(line):
                    issues.append(
                        artifact_issue(
                            "error",
                            "content",
                            "bundle text contains a provider-style secret value",
                            line_detail(path, bundle_dir, line_number, "secret-value"),
                        )
                    )
                for match in ENV_ASSIGN_RE.finditer(line):
                    if not is_placeholder_secret(match.group("value")):
                        issues.append(
                            artifact_issue(
                                "error",
                                "content",
                                "bundle text assigns a provider credential value",
                                {
                                    **line_detail(path, bundle_dir, line_number, "credential-assignment"),
                                    "name": match.group("name"),
                                },
                            )
                        )
    except OSError as exc:
        issues.append(
            artifact_issue(
                "error",
                "content",
                "could not scan bundle text file",
                {"path": relpath(path, bundle_dir), "error": str(exc)},
            )
        )
    return issues, True


def check_text_content(bundle_dir: Path) -> tuple[list[dict[str, Any]], dict[str, int]]:
    issues: list[dict[str, Any]] = []
    scanned = 0
    skipped_binary = 0
    for path in bundle_dir.rglob("*"):
        if not path.is_file():
            continue
        file_issues, did_scan = check_text_file(path, bundle_dir)
        issues.extend(file_issues)
        if did_scan:
            scanned += 1
        else:
            skipped_binary += 1
    return issues, {"scanned_text_files": scanned, "skipped_binary_files": skipped_binary}


def build_safety_report(bundle_dir: Path) -> dict[str, Any]:
    issues: list[dict[str, Any]] = []
    if not bundle_dir.is_dir():
        issues.append(
            artifact_issue(
                "error",
                "bundle",
                "bundle directory does not exist",
                {"path": str(bundle_dir)},
            )
        )
        return {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "bundle_dir": str(bundle_dir),
            "summary": {"file_count": 0, "scanned_text_files": 0, "skipped_binary_files": 0},
            "issues": issues,
            "ok": False,
        }

    manifest, manifest_issues = load_manifest(bundle_dir)
    issues.extend(manifest_issues)
    if manifest is not None:
        issues.extend(check_copied_scope(bundle_dir, manifest))
    issues.extend(check_forbidden_paths(bundle_dir))
    content_issues, scan_summary = check_text_content(bundle_dir)
    issues.extend(content_issues)

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "bundle_dir": str(bundle_dir),
        "summary": {
            "file_count": sum(1 for path in bundle_dir.rglob("*") if path.is_file()),
            **scan_summary,
        },
        "issues": issues,
        "ok": not any(item.get("severity") == "error" for item in issues),
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# Public Artifact Safety Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- bundle_dir: `{report['bundle_dir']}`",
        f"- ok: `{str(report['ok']).lower()}`",
        f"- file_count: `{summary.get('file_count', 0)}`",
        f"- scanned_text_files: `{summary.get('scanned_text_files', 0)}`",
        f"- skipped_binary_files: `{summary.get('skipped_binary_files', 0)}`",
        "",
        "## Issues",
        "",
    ]
    if report.get("issues"):
        lines += ["| Severity | Scope | Message |", "| --- | --- | --- |"]
        for item in report["issues"]:
            lines.append(f"| {item['severity']} | {item['scope']} | {item['message']} |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check a repro bundle for public artifact safety.")
    parser.add_argument("--bundle-dir", required=True, help="Directory produced by build_repro_bundle.py.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    report = build_safety_report(Path(args.bundle_dir))
    text = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
