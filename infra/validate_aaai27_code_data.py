"""Validate the anonymous AAAI-27 Safety Bench Code and Data artifact.

This validator is intentionally self contained so it can run from the
extracted supplementary ZIP without access to the development worktrees.
It performs structural, accounting, checksum, and basic anonymity checks;
it never launches a benchmark harness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


EXPECTED_CASES = 328
EXPECTED_HARNESSES = {
    "claude",
    "codex",
    "hermes",
    "openclaw",
    "gemini",
    "opencode",
    "kimi_code",
}
EXPECTED_CONFIGURATIONS = {
    "claude-code_gpt-5.6-sol",
    "claude-code_haiku-4.5",
    "claude-code_kimi-k2.6",
    "claude-code_minimax-m2.5",
    "claude-code_opus-4.7",
    "claude-code_sonnet-4.6",
    "codex-cli_gpt-5.6-sol",
    "gemini-cli_gemini-3.5-flash",
    "hermes_kimi-k3",
    "kimi-code_kimi-k3",
    "openclaw_gpt-5.6-sol",
    "opencode_qwen-3.7-plus",
}

PROGRESS_NODES = ("N0", "N1", "N2", "N3", "N4", "N5a", "N5b")
CODEX_CORRECTED_NODES = {
    "N0": 45,
    "N1": 48,
    "N2": 168,
    "N3": 38,
    "N4": 16,
    "N5a": 8,
    "N5b": 5,
}
CODEX_T3S_CORRECTED_NODES = {
    "N0": 0,
    "N1": 5,
    "N2": 1,
    "N3": 22,
    "N4": 0,
    "N5a": 2,
    "N5b": 0,
}

PERSONAL_PATH_PATTERNS = (
    re.compile(
        r"\b[A-Za-z]:[\\/]+Users[\\/]+(?!anonymous(?:[\\/]|$))[^\\/\s\"']+",
        re.IGNORECASE,
    ),
    re.compile(
        r"/Users/(?!anonymous(?:/|$))[A-Za-z0-9._-]+/",
        re.IGNORECASE,
    ),
    re.compile(r"<TEMP_ROOT>\\safety-bench", re.IGNORECASE),
    re.compile(r"<TEMP_ROOT>\\aaai-code-data", re.IGNORECASE),
    re.compile(
        r"/home/(?!runner(?:/|$)|user(?:/|$)|sandbox(?:/|$)|\.)[A-Za-z0-9._-]+/",
        re.IGNORECASE,
    ),
)

EMAIL_PATTERN = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RAW_GIT_OBJECT_PATTERN = re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE)
PRIVATE_FREEZE_PATH_PATTERN = re.compile(r"safety-bench-freeze-[0-9a-f]{7,40}", re.IGNORECASE)
VCS_CONTEXT_PATTERN = re.compile(
    r"\b(?:commit|merge[-_ ]?base|(?:git[-_ ]?)?(?:head|tip)|freeze)\b"
    r"[^\r\n]{0,48}\b(?=[0-9a-f]{7,40}\b)(?=[0-9a-f]*[a-f])"
    r"[0-9a-f]{7,40}\b",
    re.IGNORECASE,
)
ALLOWED_SYNTHETIC_EMAILS = {"git@github.com"}
ALLOWED_SYNTHETIC_EMAIL_DOMAINS = {"company.com", "external.com", "example.invalid"}
FORBIDDEN_VCS_NAMES = {
    ".git",
    "repository.bundle",
    "git-branch.txt",
    "git-head.txt",
    "git-log.txt",
    "git-status.txt",
    "merge-base-with-freeze.txt",
    "staged.patch",
    "unstaged.patch",
    "historical_patches",
}
TEXT_SUFFIXES = {
    ".cfg",
    ".cff",
    ".csv",
    ".ini",
    ".json",
    ".jsonl",
    ".md",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".tsv",
    ".txt",
    ".yaml",
    ".yml",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: row is not an object")
            rows.append(row)
    return rows


def active_case_count(manifest: dict[str, Any]) -> int:
    suites = manifest.get("suites", {})
    if not isinstance(suites, dict):
        return 0
    return sum(
        len(suite.get("cases", []))
        for suite in suites.values()
        if isinstance(suite, dict) and suite.get("status") == "active"
    )


def check_structure(root: Path) -> list[str]:
    errors: list[str] = []
    required = [
        "README.md",
        "LICENSE",
        "LICENSES.md",
        "requirements.txt",
        "requirements-dev.txt",
        "runs/manifest.json",
        "runs/active",
        "infra/analyze_trace.py",
        "infra/evaluation_scoring.py",
        "infra/case_materializer.py",
        "infra/run_harness_case.ps1",
        "provenance/experiment_snapshots.json",
        "provenance/environment_versions.json",
        "provenance/file_hashes.json",
        "results/README.md",
        "results/paper_primary/README.md",
        "results/paper_primary/main_table.json",
        "results/paper_primary/main_table.csv",
        "results/paper_primary/reconciliation.json",
        "results/paper_primary/codex_t3s_correction_ledger.jsonl",
        "results/paper_primary/codex_t3s_correction_summary.json",
        "provenance/paper_source.json",
    ]
    for relative in required:
        if not (root / relative).exists():
            errors.append(f"missing required path: {relative}")

    manifest_path = root / "runs/manifest.json"
    if manifest_path.is_file():
        count = active_case_count(read_json(manifest_path))
        if count != EXPECTED_CASES:
            errors.append(f"active case count is {count}, expected {EXPECTED_CASES}")

    adapter_root = root / "infra/adapters"
    found_harnesses: set[str] = set()
    if adapter_root.is_dir():
        for path in adapter_root.glob("*/adapter_manifest.json"):
            try:
                payload = read_json(path)
                harness = str(payload.get("harness_id") or "")
                found_harnesses.add(harness)
                for implementation in payload.get("implementation_paths", []):
                    if not (root / str(implementation)).exists():
                        errors.append(
                            f"{path.relative_to(root)} references missing implementation: {implementation}"
                        )
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                errors.append(f"invalid adapter manifest {path.relative_to(root)}: {exc}")
    if found_harnesses != EXPECTED_HARNESSES:
        errors.append(
            "adapter harness set mismatch: "
            f"found={sorted(found_harnesses)} expected={sorted(EXPECTED_HARNESSES)}"
        )

    canonical_root = root / "results/canonical"
    found_configs = {path.name for path in canonical_root.iterdir() if path.is_dir()} if canonical_root.is_dir() else set()
    if found_configs != EXPECTED_CONFIGURATIONS:
        errors.append(
            "result configuration set mismatch: "
            f"found={sorted(found_configs)} expected={sorted(EXPECTED_CONFIGURATIONS)}"
        )
    for config in sorted(found_configs):
        config_dir = canonical_root / config
        jsonl_path = config_dir / "results.jsonl"
        summary_path = config_dir / "summary.json"
        config_path = config_dir / "configuration.json"
        for path in (jsonl_path, summary_path, config_path, config_dir / "results.csv"):
            if not path.is_file():
                errors.append(f"missing result artifact: {path.relative_to(root)}")
        if jsonl_path.is_file():
            try:
                rows = load_jsonl(jsonl_path)
                if len(rows) != EXPECTED_CASES:
                    errors.append(f"{config}: {len(rows)} rows, expected {EXPECTED_CASES}")
            except (OSError, ValueError) as exc:
                errors.append(str(exc))

    minimax_summary = canonical_root / "claude-code_minimax-m2.5/summary.json"
    if minimax_summary.is_file():
        payload = read_json(minimax_summary)
        expected = {
            "inventory_cases": 328,
            "evaluation_eligible_rows": 317,
            "protocol_noncompletion_rows": 11,
            "attack_success_count": 172,
            "confirmed_compromise_count": 96,
        }
        for key, value in expected.items():
            if payload.get(key) != value:
                errors.append(
                    f"MiniMax final ledger {key}={payload.get(key)!r}, expected {value!r}"
                )
        nodes = payload.get("progress_nodes_on_evaluation_eligible_rows", {})
        if nodes.get("N5a") != 76 or nodes.get("N5b") != 96:
            errors.append(f"MiniMax replacement node counts are inconsistent: {nodes}")


    summaries: dict[str, dict[str, Any]] = {}
    for config in found_configs:
        summary_path = canonical_root / config / "summary.json"
        if summary_path.is_file():
            try:
                summaries[config] = read_json(summary_path)
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                errors.append(f"invalid summary {config}: {exc}")

    codex_summary = summaries.get("codex-cli_gpt-5.6-sol")
    if codex_summary is not None:
        expected = {
            "inventory_cases": 328,
            "evaluation_eligible_rows": 328,
            "attack_success_count": 13,
            "confirmed_compromise_count": 5,
            "correction_rows": 30,
        }
        for key, value in expected.items():
            if codex_summary.get(key) != value:
                errors.append(f"Codex corrected ledger {key}={codex_summary.get(key)!r}, expected {value!r}")
        nodes = codex_summary.get("progress_nodes_on_evaluation_eligible_rows", {})
        if nodes != CODEX_CORRECTED_NODES:
            errors.append(f"Codex corrected node distribution is inconsistent: {nodes}")
        formal_asr = codex_summary.get("formal_asr")
        if formal_asr is None or abs(float(formal_asr) - 13 / 328) > 1e-12:
            errors.append(f"Codex corrected formal ASR is inconsistent: {formal_asr!r}")

    kimi_summary = summaries.get("kimi-code_kimi-k3")
    if kimi_summary is not None:
        if kimi_summary.get("evaluation_eligible_rows") != 0 or kimi_summary.get("formal_asr") is not None:
            errors.append("Kimi Code formal ASR must be N/A with zero evaluation-eligible rows")
        available_nodes = kimi_summary.get("progress_nodes_on_available_rows", {})
        available_count = sum(int(available_nodes.get(node, 0)) for node in PROGRESS_NODES)
        diagnostic_successes = int(available_nodes.get("N5a", 0)) + int(available_nodes.get("N5b", 0))
        if (diagnostic_successes, available_count) != (18, 202):
            errors.append(
                f"Kimi Code diagnostic scope is inconsistent: {diagnostic_successes}/{available_count}, expected 18/202"
            )

    paper_table_path = root / "results/paper_primary/main_table.json"
    if paper_table_path.is_file():
        try:
            paper_payload = read_json(paper_table_path)
            paper_rows = paper_payload.get("rows", [])
            if not isinstance(paper_rows, list) or len(paper_rows) != 13:
                errors.append(f"paper-primary main table has {len(paper_rows) if isinstance(paper_rows, list) else 'invalid'} rows, expected 13")
                paper_rows = []
            paper_by_key = {
                (str(row.get("experiment")), str(row.get("configuration_id"))): row
                for row in paper_rows
                if isinstance(row, dict)
            }
            codex_paper = paper_by_key.get(("Exp1", "codex-cli_gpt-5.6-sol"))
            codex_expected = {
                "css": 62.3,
                "asr_percent": 3.96,
                "asr_numerator": 13,
                "asr_denominator": 328,
                "asr_metric_status": "formal",
                "canonical_formal_eligible": 328,
                "canonical_formal_attack_successes": 13,
            }
            if codex_paper is None:
                errors.append("paper-primary Codex Exp1 row is missing")
            else:
                for key, value in codex_expected.items():
                    if codex_paper.get(key) != value:
                        errors.append(f"paper-primary Codex {key}={codex_paper.get(key)!r}, expected {value!r}")
            kimi_paper = paper_by_key.get(("Exp1", "kimi-code_kimi-k3"))
            kimi_expected = {
                "css": 43.3,
                "asr_percent": 8.91,
                "asr_numerator": 18,
                "asr_denominator": 202,
                "asr_metric_status": "diagnostic_not_formal",
                "canonical_formal_eligible": 0,
                "canonical_formal_attack_successes": 0,
                "canonical_formal_asr_percent": None,
            }
            if kimi_paper is None:
                errors.append("paper-primary Kimi Code Exp1 row is missing")
            else:
                for key, value in kimi_expected.items():
                    if kimi_paper.get(key) != value:
                        errors.append(f"paper-primary Kimi Code {key}={kimi_paper.get(key)!r}, expected {value!r}")
            for row in paper_rows:
                if not isinstance(row, dict):
                    continue
                config = str(row.get("configuration_id") or "")
                summary = summaries.get(config)
                if summary is None:
                    errors.append(f"paper-primary row has no canonical summary: {config}")
                    continue
                if config == "kimi-code_kimi-k3":
                    continue
                expected_pair = (summary.get("attack_success_count"), summary.get("evaluation_eligible_rows"))
                actual_pair = (row.get("asr_numerator"), row.get("asr_denominator"))
                if actual_pair != expected_pair:
                    errors.append(f"paper/canonical ASR mismatch for {row.get('experiment')}/{config}: {actual_pair} vs {expected_pair}")
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            errors.append(f"invalid paper-primary main table: {exc}")

    correction_path = root / "results/paper_primary/codex_t3s_correction_ledger.jsonl"
    if correction_path.is_file():
        try:
            correction_rows = load_jsonl(correction_path)
            if len(correction_rows) != 30:
                errors.append(f"Codex T3-S correction ledger has {len(correction_rows)} rows, expected 30")
            correction_nodes = Counter(str(row.get("corrected_progress_node") or "") for row in correction_rows)
            actual_nodes = {node: correction_nodes.get(node, 0) for node in PROGRESS_NODES}
            if actual_nodes != CODEX_T3S_CORRECTED_NODES:
                errors.append(f"Codex T3-S correction distribution is inconsistent: {actual_nodes}")
            if sum(bool(row.get("attack_success")) for row in correction_rows) != 2:
                errors.append("Codex T3-S correction ledger must contain two attack-success rows")
        except (OSError, ValueError) as exc:
            errors.append(f"invalid Codex T3-S correction ledger: {exc}")
    return errors


def check_forbidden_payloads(root: Path) -> list[str]:
    errors: list[str] = []
    forbidden_names = {"agent_home", "bench_state", *FORBIDDEN_VCS_NAMES}
    citation_path = root / "CITATION.cff"
    if citation_path.is_file():
        citation = citation_path.read_text(encoding="utf-8-sig", errors="replace")
        if "family-names: Anonymous" not in citation:
            errors.append("CITATION.cff must use the anonymous review identity")
        if re.search(r"\b(orcid|given-names|email):", citation, re.IGNORECASE):
            errors.append("CITATION.cff contains non-anonymous identity fields")

    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if path.name in forbidden_names:
            errors.append(f"forbidden development/runtime payload: {relative}")
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            errors.append(f"cannot scan {relative}: {exc}")
            continue
        for pattern in PERSONAL_PATH_PATTERNS:
            match = pattern.search(text)
            if match:
                errors.append(
                    f"personal/source path remains in {relative}: {match.group(0)!r}"
                )
                break

        for email_match in EMAIL_PATTERN.finditer(text):
            email = email_match.group(0).lower()
            domain = email.rsplit("@", 1)[1]
            if email not in ALLOWED_SYNTHETIC_EMAILS and domain not in ALLOWED_SYNTHETIC_EMAIL_DOMAINS:
                errors.append(f"non-synthetic email remains in {relative}: {email!r}")
                break

        private_freeze_match = PRIVATE_FREEZE_PATH_PATTERN.search(text)
        if private_freeze_match:
            errors.append(
                f"private freeze VCS prefix remains in {relative}: "
                f"{private_freeze_match.group(0)!r}"
            )

        strict_vcs_scope = (
            (relative.parts and relative.parts[0] in {"provenance", "docs"})
            or relative.name in {"configuration.json", "adapter_manifest.json"}
            or len(relative.parts) == 1
        )
        if strict_vcs_scope:
            match = RAW_GIT_OBJECT_PATTERN.search(text)
            if match:
                errors.append(
                    f"raw 40-hex VCS/SHA-1 identifier remains in {relative}: {match.group(0)!r}"
                )
            context_match = VCS_CONTEXT_PATTERN.search(text)
            if context_match:
                errors.append(
                    f"contextual raw VCS identifier remains in {relative}: "
                    f"{context_match.group(0)!r}"
                )
    return errors

def verify_hashes(root: Path) -> list[str]:
    errors: list[str] = []
    manifest_path = root / "provenance/file_hashes.json"
    if not manifest_path.is_file():
        return ["missing provenance/file_hashes.json"]
    payload = read_json(manifest_path)
    records = payload.get("files", [])
    expected_paths: set[str] = set()
    for record in records:
        relative = str(record.get("path") or "")
        expected = str(record.get("sha256") or "")
        expected_paths.add(relative)
        path = root / relative
        if not path.is_file():
            errors.append(f"hash manifest path missing: {relative}")
            continue
        actual = sha256(path)
        if actual != expected:
            errors.append(f"checksum mismatch: {relative}")
    ignored = {"provenance/file_hashes.json", "SHA256SUMS"}
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).as_posix() not in ignored
    }
    missing_records = actual_paths - expected_paths
    stale_records = expected_paths - actual_paths
    if missing_records:
        errors.append(f"files absent from hash manifest: {sorted(missing_records)[:10]}")
    if stale_records:
        errors.append(f"stale hash manifest records: {sorted(stale_records)[:10]}")
    return errors


def validate(root: Path, *, include_hashes: bool) -> dict[str, Any]:
    root = root.resolve()
    errors = check_structure(root)
    errors.extend(check_forbidden_payloads(root))
    if include_hashes:
        errors.extend(verify_hashes(root))
    return {
        "artifact_root": str(root),
        "valid": not errors,
        "error_count": len(errors),
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", default=".")
    parser.add_argument("--verify-hashes", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = validate(Path(args.artifact_root), include_hashes=args.verify_hashes)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("PASS" if result["valid"] else "FAIL")
        for error in result["errors"]:
            print(f"- {error}")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
