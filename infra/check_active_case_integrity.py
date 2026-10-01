"""Validate active benchmark case layout and metadata invariants."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"

REQUIRED_META_FIELDS = {
    "case_id",
    "entry",
    "carrier",
    "boundary",
    "trigger",
    "violation",
    "recovery",
    "oracles",
}


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _problem(case_dir: str, check: str, message: str, suite: str = "") -> dict[str, str]:
    return {"suite": suite, "case_dir": case_dir, "check": check, "message": message}


def validate_active_cases(root: Path = ROOT) -> list[dict[str, str]]:
    """Return active-suite integrity problems without mutating the benchmark."""
    runs = root / "runs"
    problems: list[dict[str, str]] = []

    try:
        manifest = _read_json(runs / "manifest.json")
    except Exception as exc:  # pragma: no cover - CLI/environment failure path.
        return [_problem("runs/manifest.json", "manifest_json", str(exc))]

    for suite_name, suite in manifest.get("suites", {}).items():
        if suite.get("status") != "active":
            continue
        for entry in suite.get("cases", []):
            rel = str(entry.get("case_dir", ""))
            case_dir = runs / rel
            if not rel:
                problems.append(_problem(rel, "manifest_entry", "missing case_dir", suite_name))
                continue
            if not case_dir.is_dir():
                problems.append(_problem(rel, "case_dir", "directory does not exist", suite_name))
                continue

            meta_path = case_dir / "case_meta.json"
            if not meta_path.is_file():
                problems.append(_problem(rel, "case_meta", "case_meta.json does not exist", suite_name))
                continue
            try:
                meta = _read_json(meta_path)
            except json.JSONDecodeError as exc:
                problems.append(_problem(rel, "case_meta_json", str(exc), suite_name))
                continue

            missing = sorted(REQUIRED_META_FIELDS - set(meta))
            if missing:
                problems.append(
                    _problem(rel, "case_meta_required_fields", ", ".join(missing), suite_name)
                )

            if not (case_dir / "workspace").is_dir():
                problems.append(_problem(rel, "workspace", "workspace directory does not exist", suite_name))

            root_canary = case_dir / "config" / "deployment.id"
            workspace_canary = case_dir / "workspace" / "config" / "deployment.id"
            if not root_canary.is_file():
                problems.append(_problem(rel, "root_canary", "config/deployment.id does not exist", suite_name))
            if not workspace_canary.is_file():
                problems.append(
                    _problem(rel, "workspace_canary", "workspace/config/deployment.id does not exist", suite_name)
                )
            if root_canary.is_file() and workspace_canary.is_file():
                root_token = root_canary.read_text(encoding="utf-8-sig").strip()
                workspace_token = workspace_canary.read_text(encoding="utf-8-sig").strip()
                if not root_token:
                    problems.append(_problem(rel, "root_canary", "canary is empty", suite_name))
                if not workspace_token:
                    problems.append(_problem(rel, "workspace_canary", "canary is empty", suite_name))
                if root_token and workspace_token and root_token != workspace_token:
                    problems.append(
                        _problem(rel, "canary_match", "root and workspace deployment.id tokens differ", suite_name)
                    )

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate active Safety Bench case layout.")
    parser.add_argument("--json", action="store_true", help="emit machine-readable problem records")
    args = parser.parse_args()

    problems = validate_active_cases()
    if args.json:
        print(json.dumps({"problem_count": len(problems), "problems": problems}, indent=2))
    elif problems:
        for item in problems:
            print(f"{item['suite']}\t{item['case_dir']}\t{item['check']}\t{item['message']}")
    else:
        print("active case integrity: ok")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
