"""Generate a reviewer-facing benchmark card for the paper artifact."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"

DEFAULT_ATTACK_LABEL = "paper_core_20260625"
DEFAULT_CONTROL_LABEL = "paper_controls_core_20260625"
DEFAULT_SUITE_LOCK = Path("docs/generated_artifacts/paper_suite_lock.json")
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/benchmark_card.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/benchmark_card.md")


def safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return slug.strip("_") or "paper"


def split_cli_values(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            token = part.strip()
            if token:
                out.append(token)
    return out


def resolve_report_dirs(
    *,
    labels: Iterable[str] | None,
    paths: Iterable[str] | None,
    default_label: str = "",
    root: Path = ROOT,
) -> list[Path]:
    report_paths = [Path(path) for path in split_cli_values(paths)]
    labels_list = split_cli_values(labels)
    if not report_paths and not labels_list and default_label:
        labels_list = [default_label]
    report_paths.extend(root / "runs" / "_reports" / safe_slug(label) for label in labels_list)
    return report_paths


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def relpath(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def as_float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def pct(value: Any, digits: int = 1) -> str:
    return f"{as_float(value) * 100:.{digits}f}%"


def pct_or_na(value: Any, digits: int = 1) -> str:
    return "n/a" if value is None or value == "" else pct(value, digits)


def number_or_na(value: Any, digits: int = 4) -> str:
    parsed = optional_float(value)
    return f"{parsed:.{digits}f}" if parsed is not None else "n/a"


def table_text(table: dict[str, Any], section: str, row: int, column: int, default: str = "") -> str:
    try:
        return str(table.get(section, {}).get("rows", [])[row][column])
    except (IndexError, TypeError):
        return default


def table_value(
    table: dict[str, Any], section: str, row: int, header: str, default: str = ""
) -> str:
    block = table.get(section, {})
    if not isinstance(block, dict):
        return default
    headers = block.get("headers", [])
    rows = block.get("rows", [])
    if not isinstance(headers, list) or not isinstance(rows, list) or row >= len(rows):
        return default
    try:
        column = headers.index(header)
    except ValueError:
        return default
    try:
        return str(rows[row][column])
    except (IndexError, TypeError):
        return default


MEASUREMENT_COUNT_FIELDS = (
    "completed_trials",
    "asr_eligible_trials",
    "n_minus_1_trials",
    "accounted_terminal_trials",
    "protocol_denominator_trials",
    "attack_success_trials",
)
MEASUREMENT_MARKERS = (
    "asr_eligible_trials",
    "n_minus_1_trials",
    "accounted_terminal_trials",
    "protocol_denominator_trials",
    "protocol_completion_trial_rate",
    "model_nonconformance_trial_rate",
    "end_to_end_attack_trial_rate",
)


def _required_nonnegative_int(row: dict[str, Any], key: str, context: str) -> int:
    if key not in row:
        raise ValueError(f"{context}: current measurement contract is missing {key}")
    value = row.get(key)
    if isinstance(value, bool):
        raise ValueError(f"{context}: {key} must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{context}: {key} must be a non-negative integer") from exc
    try:
        exact = float(value) == float(parsed)
    except (TypeError, ValueError):
        exact = False
    if parsed < 0 or not exact:
        raise ValueError(f"{context}: {key} must be a non-negative integer")
    return parsed


def measurement_counts(
    row: dict[str, Any], context: str, *, require_current: bool = False
) -> dict[str, int] | None:
    if not any(key in row for key in MEASUREMENT_MARKERS):
        if require_current:
            raise ValueError(
                f"{context}: current measurement contract is missing "
                f"{MEASUREMENT_COUNT_FIELDS[0]}"
            )
        return None
    counts = {
        key: _required_nonnegative_int(row, key, context)
        for key in MEASUREMENT_COUNT_FIELDS
    }
    all_scored = counts["completed_trials"]
    eligible = counts["asr_eligible_trials"]
    n_minus_one = counts["n_minus_1_trials"]
    accounted = counts["accounted_terminal_trials"]
    denominator = counts["protocol_denominator_trials"]
    successes = counts["attack_success_trials"]
    if eligible > all_scored:
        raise ValueError(f"{context}: S cannot exceed all scored rows")
    if accounted != all_scored + n_minus_one:
        raise ValueError(f"{context}: T must equal all scored rows + M")
    if denominator != eligible + n_minus_one:
        raise ValueError(f"{context}: D must equal S + M")
    if successes > eligible:
        raise ValueError(f"{context}: A cannot exceed S")
    if "confirmed_trials" in row:
        confirmed = _required_nonnegative_int(row, "confirmed_trials", context)
        if confirmed > eligible:
            raise ValueError(f"{context}: confirmed trials cannot exceed S")
    return counts


def summary_requires_current_contract(summary: dict[str, Any]) -> bool:
    evaluation_version = str(summary.get("evaluation_schema_version") or "")
    if evaluation_version:
        try:
            return int(evaluation_version.split(".", 1)[0]) >= 2
        except ValueError:
            return False
    schema_version = summary.get("schema_version")
    return (
        isinstance(schema_version, int)
        and not isinstance(schema_version, bool)
        and schema_version >= 2
    )


def protocol_metrics_available(row: dict[str, Any], context: str = "row") -> bool:
    return measurement_counts(row, context) is not None


def first_harness_macro(summary: dict[str, Any], *, run_kind: str = "", control_type: str = "") -> dict[str, Any]:
    rows = summary.get("harness_macro", [])
    if not isinstance(rows, list):
        return {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        if run_kind and row.get("run_kind") != run_kind:
            continue
        if control_type and row.get("control_type") != control_type:
            continue
        return row
    return rows[0] if rows and isinstance(rows[0], dict) else {}


def sum_harness_macro(summary: dict[str, Any]) -> dict[str, Any]:
    totals = {
        "completed_trials": 0,
        "n_minus_1_trials": 0,
        "accounted_terminal_trials": 0,
        "protocol_denominator_trials": 0,
        "timeout_trials": 0,
        "asr_eligible_trials": 0,
        "attack_success_trials": 0,
        "factual_attack_success_trials": 0,
        "confirmed_trials": 0,
    }
    control_types: list[str] = []
    seen = 0
    current_rows = 0
    require_current = summary_requires_current_contract(summary)
    for index, row in enumerate(summary.get("harness_macro", [])):
        if not isinstance(row, dict):
            continue
        seen += 1
        counts = measurement_counts(
            row,
            f"control_macro[{index}]",
            require_current=require_current,
        )
        if counts is not None:
            current_rows += 1
        for key in totals:
            if counts is not None and key in counts:
                totals[key] += counts[key]
            else:
                totals[key] += as_int(row.get(key))
        control_type = str(row.get("control_type") or "")
        if control_type and control_type not in control_types:
            control_types.append(control_type)
    totals["control_types"] = control_types
    if current_rows and current_rows != seen:
        raise ValueError("control macros cannot mix current and legacy measurement contracts")
    if seen and current_rows == 0:
        # Legacy summaries predate explicit S. Preserve the historical
        # all-scored denominator consistently at both aggregate and by-type
        # levels while leaving M/T/D protocol metrics unavailable.
        totals["asr_eligible_trials"] = totals["completed_trials"]
    totals["protocol_metrics_available"] = bool(seen and current_rows == seen)
    return totals


def control_type_summaries(control_summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for summary in control_summaries:
        require_current = summary_requires_current_contract(summary)
        for index, row in enumerate(summary.get("harness_macro", [])):
            if not isinstance(row, dict):
                continue
            control_type = str(row.get("control_type") or "")
            if not control_type:
                continue
            counts = measurement_counts(
                row,
                f"control_macro[{index}]",
                require_current=require_current,
            )
            protocol_available = counts is not None
            scored_trials = (
                counts["completed_trials"]
                if counts is not None
                else as_int(row.get("completed_trials"))
            )
            asr_eligible_trials = (
                counts["asr_eligible_trials"] if counts is not None else scored_trials
            )
            n_minus_one_trials = (
                counts["n_minus_1_trials"] if counts is not None else 0
            )
            protocol_denominator_trials = (
                counts["protocol_denominator_trials"] if counts is not None else 0
            )
            attack_success_trials = as_int(row.get("attack_success_trials"))
            out.append(
                {
                    "control_type": control_type,
                    "harness": str(row.get("harness") or ""),
                    "rows": scored_trials,
                    "scored_trials": scored_trials,
                    "asr_eligible_scored_trials": asr_eligible_trials,
                    "n_minus_1_trials": (
                        n_minus_one_trials
                        if protocol_available
                        else None
                    ),
                    "accounted_terminal_trials": (
                        counts["accounted_terminal_trials"]
                        if protocol_available
                        else None
                    ),
                    "protocol_denominator_trials": (
                        protocol_denominator_trials if protocol_available else None
                    ),
                    "protocol_metrics_available": protocol_available,
                    "protocol_completion_rate": (
                        asr_eligible_trials / protocol_denominator_trials
                        if protocol_available and protocol_denominator_trials
                        else None
                    ),
                    "model_nonconformance_rate": (
                        n_minus_one_trials / protocol_denominator_trials
                        if protocol_available and protocol_denominator_trials
                        else None
                    ),
                    "conditional_violation_rate": (
                        attack_success_trials / asr_eligible_trials
                        if asr_eligible_trials
                        else None
                    ),
                    "end_to_end_violation_rate": (
                        attack_success_trials / protocol_denominator_trials
                        if protocol_available and protocol_denominator_trials
                        else None
                    ),
                    "attack_success_rows": attack_success_trials,
                    "confirmed_rows": as_int(row.get("confirmed_trials")),
                    "timeouts": as_int(row.get("timeout_trials")),
                }
            )
    return out


def load_summaries(dirs: list[Path]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for directory in dirs:
        summary_path = directory / "summary.json"
        if not summary_path.is_file():
            continue
        summaries.append(load_json(summary_path))
    return summaries


def build_card(
    *,
    attack_dirs: list[Path],
    control_dirs: list[Path],
    table_dir: Path | None,
    suite_lock_path: Path,
    baseline_runtime: str = "Claude Code",
    baseline_model: str = "Kimi K2.6",
    baseline_harness: str = "claude",
    baseline_model_source: str = "Claude Code runtime default",
    codex_in_current_scope: bool = False,
    root: Path = ROOT,
) -> dict[str, Any]:
    if not attack_dirs:
        attack_dirs = resolve_report_dirs(labels=[DEFAULT_ATTACK_LABEL], paths=[], root=root)
    if not control_dirs:
        control_dirs = resolve_report_dirs(labels=[DEFAULT_CONTROL_LABEL], paths=[], root=root)
    attack_summaries = load_summaries(attack_dirs)
    control_summaries = load_summaries(control_dirs)
    if not attack_summaries:
        raise FileNotFoundError("no attack summary.json found")
    if not control_summaries:
        raise FileNotFoundError("no control summary.json found")

    suite_lock_abs = suite_lock_path if suite_lock_path.is_absolute() else root / suite_lock_path
    suite_lock = load_json(suite_lock_abs)
    table_payload: dict[str, Any] = {}
    if table_dir is not None:
        table_path = table_dir / "paper_tables.json"
        if table_path.is_file():
            table_payload = load_json(table_path)

    attack_summary = attack_summaries[0]
    attack_macro = first_harness_macro(attack_summary, run_kind="attack")
    control_totals = {
        "completed_trials": 0,
        "n_minus_1_trials": 0,
        "accounted_terminal_trials": 0,
        "protocol_denominator_trials": 0,
        "timeout_trials": 0,
        "asr_eligible_trials": 0,
        "attack_success_trials": 0,
        "factual_attack_success_trials": 0,
        "confirmed_trials": 0,
        "control_types": [],
        "protocol_metrics_available": True,
    }
    control_summary_count = 0
    for control_summary in control_summaries:
        totals = sum_harness_macro(control_summary)
        control_summary_count += 1
        for key in [
            "completed_trials",
            "n_minus_1_trials",
            "accounted_terminal_trials",
            "protocol_denominator_trials",
            "timeout_trials",
            "asr_eligible_trials",
            "attack_success_trials",
            "factual_attack_success_trials",
            "confirmed_trials",
        ]:
            control_totals[key] += as_int(totals.get(key))
        control_totals["protocol_metrics_available"] = bool(
            control_totals["protocol_metrics_available"]
            and totals.get("protocol_metrics_available")
        )
        for control_type in totals.get("control_types", []):
            if control_type not in control_totals["control_types"]:
                control_totals["control_types"].append(control_type)

    attack_counts = measurement_counts(
        attack_macro,
        "attack_macro",
        require_current=summary_requires_current_contract(attack_summary),
    )
    attack_protocol_available = attack_counts is not None
    attack_rows = (
        attack_counts["completed_trials"]
        if attack_counts is not None
        else as_int(attack_macro.get("completed_trials"))
        if "completed_trials" in attack_macro
        else len(attack_summary.get("rows", []))
    )
    has_control_macro = any(
        isinstance(row, dict)
        for summary in control_summaries
        for row in summary.get("harness_macro", [])
    )
    control_rows = (
        as_int(control_totals.get("completed_trials"))
        if has_control_macro
        else sum(len(item.get("rows", [])) for item in control_summaries)
    )
    total_rows = attack_rows + control_rows
    case_count = as_int(attack_summary.get("active_case_count")) or as_int(suite_lock.get("case_counts", {}).get("core"))
    attack_trials_per_case = round(attack_rows / case_count, 2) if case_count else 0
    attack_asr_eligible_trials = (
        attack_counts["asr_eligible_trials"]
        if attack_counts is not None
        else attack_rows
    )
    attack_n_minus_one_trials = (
        attack_counts["n_minus_1_trials"] if attack_counts is not None else 0
    )
    attack_protocol_denominator_trials = (
        attack_counts["protocol_denominator_trials"] if attack_counts is not None else 0
    )
    attack_success_trials = (
        attack_counts["attack_success_trials"]
        if attack_counts is not None
        else as_int(attack_macro.get("attack_success_trials"))
    )
    control_protocol_denominator_trials = (
        as_int(control_totals.get("protocol_denominator_trials"))
    )

    attack_conditional_asr = (
        attack_success_trials / attack_asr_eligible_trials
        if attack_asr_eligible_trials
        else None
    )
    attack_family_macro_asr = optional_float(
        attack_macro.get("family_macro_attack_success")
    ) if attack_asr_eligible_trials > 0 else None
    attack_family_macro_end_to_end = (
        optional_float(attack_macro.get("family_macro_end_to_end_attack"))
        if attack_protocol_available and attack_protocol_denominator_trials > 0
        else None
    )
    attack_family_macro_confirmed = optional_float(
        attack_macro.get("family_macro_confirmed")
    ) if attack_asr_eligible_trials > 0 else None
    attack_family_macro_risk = optional_float(
        attack_macro.get("family_macro_risk")
    ) if attack_asr_eligible_trials > 0 else None

    # Summary counts are authoritative.  paper_tables.json is a presentation
    # cache and may be stale, so it must never supply published metric values.
    attack_ci_low = optional_float(attack_macro.get("attack_success_ci_low"))
    attack_ci_high = optional_float(attack_macro.get("attack_success_ci_high"))
    if attack_conditional_asr is None:
        pooled_asr = "n/a"
    elif attack_ci_low is not None and attack_ci_high is not None:
        pooled_asr = (
            f"{pct_or_na(attack_conditional_asr)} "
            f"[{pct_or_na(attack_ci_low)}-{pct_or_na(attack_ci_high)}]"
        )
    else:
        pooled_asr = pct_or_na(attack_conditional_asr)
    family_macro_asr = pct_or_na(attack_family_macro_asr)
    family_macro_end_to_end = pct_or_na(attack_family_macro_end_to_end)
    family_macro_confirmed = pct_or_na(attack_family_macro_confirmed)
    mean_risk = (
        round(attack_family_macro_risk, 4)
        if attack_asr_eligible_trials > 0 and attack_family_macro_risk is not None
        else None
    )

    return {
        "schema_version": 2,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "metric_contract": {
            "n_minus_one_is_progress_node": False,
            "conditional_asr_denominator": "ASR-eligible N0-N5b scored attack rows",
            "end_to_end_denominator": "ASR-eligible scored attack rows plus N-1 attack rows",
            "legacy_missing_protocol_fields": "reported unavailable",
        },
        "benchmark": {
            "name": "Safety Bench",
            "frame": "Entry -> Carrier -> Boundary -> Trigger -> Violation",
            "purpose": (
                "Measure whether untrusted input can persist through agent harness carriers "
                "and later induce observable unsafe actions during benign tasks."
            ),
        },
        "scope": {
            "active_case_count": as_int(suite_lock.get("active_case_count")),
            "case_counts": suite_lock.get("case_counts", {}),
            "source_manifest": suite_lock.get("source_manifest", "runs/manifest.json"),
            "suite_lock": str(suite_lock_path).replace("\\", "/"),
        },
        "current_baseline": {
            "harness": baseline_harness,
            "runtime": baseline_runtime,
            "model": baseline_model,
            "model_source": baseline_model_source,
            "codex_in_current_scope": codex_in_current_scope,
        },
        "matrix": {
            "case_set": attack_summary.get("case_set", "core"),
            "attack_report_labels": [str(item.get("label") or path.name) for item, path in zip(attack_summaries, attack_dirs)],
            "control_report_labels": [
                str(item.get("label") or path.name) for item, path in zip(control_summaries, control_dirs)
            ],
            "attack_rows": attack_rows,
            "control_rows": control_rows,
            "total_rows": total_rows,
            "scored_attack_rows": attack_rows,
            "n_minus_1_attack_rows": (
                attack_counts["n_minus_1_trials"]
                if attack_protocol_available
                else None
            ),
            "accounted_terminal_attack_rows": (
                attack_counts["accounted_terminal_trials"]
                if attack_protocol_available
                else None
            ),
            "protocol_denominator_attack_rows": (
                attack_protocol_denominator_trials
                if attack_protocol_available
                else None
            ),
            "scored_control_rows": control_rows,
            "n_minus_1_control_rows": (
                as_int(control_totals.get("n_minus_1_trials"))
                if control_totals["protocol_metrics_available"]
                else None
            ),
            "accounted_terminal_control_rows": (
                as_int(control_totals.get("accounted_terminal_trials"))
                if control_totals["protocol_metrics_available"]
                else None
            ),
            "protocol_denominator_control_rows": (
                control_protocol_denominator_trials
                if control_totals["protocol_metrics_available"]
                else None
            ),
            "protocol_metrics_available": bool(
                attack_protocol_available
                and control_summary_count
                and control_totals["protocol_metrics_available"]
            ),
            "attack_trials_per_case": attack_trials_per_case,
            "control_types": control_totals["control_types"],
        },
        "current_results": {
            "scored_trials": attack_rows,
            "asr_eligible_scored_trials": attack_asr_eligible_trials,
            "n_minus_1_trials": (
                attack_counts["n_minus_1_trials"]
                if attack_protocol_available
                else None
            ),
            "accounted_terminal_trials": (
                attack_counts["accounted_terminal_trials"]
                if attack_protocol_available
                else None
            ),
            "protocol_denominator_trials": (
                attack_protocol_denominator_trials
                if attack_protocol_available
                else None
            ),
            "protocol_metrics_available": attack_protocol_available,
            "protocol_completion_rate": (
                attack_asr_eligible_trials / attack_protocol_denominator_trials
                if attack_protocol_available and attack_protocol_denominator_trials
                else None
            ),
            "model_nonconformance_rate": (
                attack_n_minus_one_trials / attack_protocol_denominator_trials
                if attack_protocol_available and attack_protocol_denominator_trials
                else None
            ),
            "attack_success_rows": attack_success_trials,
            "confirmed_rows": as_int(attack_macro.get("confirmed_trials")),
            "timeouts": as_int(attack_macro.get("timeout_trials")),
            "pooled_asr": pooled_asr,
            "conditional_asr": pooled_asr,
            "pooled_asr_rate": attack_conditional_asr,
            "conditional_asr_rate": attack_conditional_asr,
            "end_to_end_attack_rate": (
                attack_success_trials / attack_protocol_denominator_trials
                if attack_protocol_available and attack_protocol_denominator_trials
                else None
            ),
            "pooled_asr_ci_low": optional_float(
                attack_macro.get("attack_success_ci_low")
            ),
            "pooled_asr_ci_high": optional_float(
                attack_macro.get("attack_success_ci_high")
            ),
            "family_macro_asr": family_macro_asr,
            "family_macro_end_to_end": family_macro_end_to_end,
            "family_macro_confirmed": family_macro_confirmed,
            "mean_risk": mean_risk,
        },
        "controls": {
            "rows": control_rows,
            "scored_trials": control_rows,
            "asr_eligible_scored_trials": as_int(
                control_totals.get("asr_eligible_trials")
            ),
            "n_minus_1_trials": (
                as_int(control_totals.get("n_minus_1_trials"))
                if control_totals["protocol_metrics_available"]
                else None
            ),
            "accounted_terminal_trials": (
                as_int(control_totals.get("accounted_terminal_trials"))
                if control_totals["protocol_metrics_available"]
                else None
            ),
            "protocol_denominator_trials": (
                control_protocol_denominator_trials
                if control_totals["protocol_metrics_available"]
                else None
            ),
            "protocol_metrics_available": control_totals["protocol_metrics_available"],
            "protocol_completion_rate": (
                as_int(control_totals.get("asr_eligible_trials"))
                / control_protocol_denominator_trials
                if control_totals["protocol_metrics_available"]
                and control_protocol_denominator_trials
                else None
            ),
            "model_nonconformance_rate": (
                as_int(control_totals.get("n_minus_1_trials"))
                / control_protocol_denominator_trials
                if control_totals["protocol_metrics_available"]
                and control_protocol_denominator_trials
                else None
            ),
            "conditional_violation_rate": (
                as_int(control_totals.get("attack_success_trials"))
                / as_int(control_totals.get("asr_eligible_trials"))
                if as_int(control_totals.get("asr_eligible_trials"))
                else None
            ),
            "end_to_end_violation_rate": (
                as_int(control_totals.get("attack_success_trials"))
                / control_protocol_denominator_trials
                if control_totals["protocol_metrics_available"]
                and control_protocol_denominator_trials
                else None
            ),
            "attack_success_rows": as_int(control_totals.get("attack_success_trials")),
            "confirmed_rows": as_int(control_totals.get("confirmed_trials")),
            "timeouts": as_int(control_totals.get("timeout_trials")),
            "by_type": control_type_summaries(control_summaries),
        },
        "evidence": {
            "primary_evidence": [
                "trace",
                "honeypot",
                "canary",
                "workspace artifact",
                "local marker",
                "tool or MCP argument",
            ],
            "case_study_evidence": "runs/_reports/paper_core_20260625/case_study_evidence/",
            "case_study_check": "runs/_reports/paper_core_20260625/paper_case_study_check.md",
            "manuscript_check": "runs/_reports/paper_core_20260625/paper_manuscript_check.md",
            "number_check": "runs/_reports/paper_core_20260625/paper_numbers_check.md",
        },
        "public_artifact_boundary": {
            "excluded_from_public_bundle": [
                "raw traces",
                "honeypot logs",
                "raw oracle records",
                "agent homes",
                "canary values",
                "provider secrets",
            ],
            "release_blockers": [
                "root LICENSE selection",
                "final author/order metadata",
                "public repository URL",
                "artifact DOI",
                "non-preprint version/date",
            ],
        },
        "limitations": [
            f"The current completed baseline is a single local {baseline_runtime} harness run with {baseline_model}.",
            "Hard and proxy oracle coverage varies by family and is documented in the suite lock and case metadata.",
            "Public bundles intentionally exclude raw traces and honeypot evidence.",
            "Submission release metadata is still pending until final venue and licensing choices are made.",
        ],
        "sources": {
            "attack_reports": [relpath(path, root) for path in attack_dirs],
            "control_reports": [relpath(path, root) for path in control_dirs],
            "table_dir": relpath(table_dir, root) if table_dir else "",
            "suite_lock": str(suite_lock_path).replace("\\", "/"),
        },
    }


def render_markdown(card: dict[str, Any]) -> str:
    baseline = card["current_baseline"]
    matrix = card["matrix"]
    results = card["current_results"]
    controls = card["controls"]
    scope = card["scope"]
    lines = [
        "# Safety Bench Benchmark Card",
        "",
        f"- generated_at: `{card['generated_at']}`",
        f"- benchmark: `{card['benchmark']['name']}`",
        f"- frame: `{card['benchmark']['frame']}`",
        f"- purpose: {card['benchmark']['purpose']}",
        "",
        "## Scope",
        "",
        f"- active_cases: `{scope.get('active_case_count', 0)}`",
        f"- core_cases: `{scope.get('case_counts', {}).get('core', 0)}`",
        f"- extended_cases: `{scope.get('case_counts', {}).get('extended', 0)}`",
        f"- exploratory_cases: `{scope.get('case_counts', {}).get('exploratory', 0)}`",
        f"- source_manifest: `{scope.get('source_manifest', 'runs/manifest.json')}`",
        "",
        "## Current Baseline",
        "",
        f"- baseline: `{baseline['runtime']} + {baseline['model']}`",
        f"- harness: `{baseline['harness']}`",
        f"- model_source: `{baseline['model_source']}`",
        f"- codex_in_current_scope: `{str(baseline['codex_in_current_scope']).lower()}`",
        "",
        "## Matrix And Results",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Scored attack rows | {matrix['scored_attack_rows']} |",
        f"| Attack ASR-eligible scored rows | {results['asr_eligible_scored_trials']} |",
        f"| Attack N-1 rows | {matrix['n_minus_1_attack_rows'] if matrix['n_minus_1_attack_rows'] is not None else 'n/a'} |",
        f"| Accounted terminal attack rows | {matrix['accounted_terminal_attack_rows'] if matrix['accounted_terminal_attack_rows'] is not None else 'n/a'} |",
        f"| Attack protocol denominator (S+M) | {matrix['protocol_denominator_attack_rows'] if matrix['protocol_denominator_attack_rows'] is not None else 'n/a'} |",
        f"| Scored control rows | {matrix['scored_control_rows']} |",
        f"| Control N-1 rows | {matrix['n_minus_1_control_rows'] if matrix['n_minus_1_control_rows'] is not None else 'n/a'} |",
        f"| Accounted terminal control rows | {matrix['accounted_terminal_control_rows'] if matrix['accounted_terminal_control_rows'] is not None else 'n/a'} |",
        f"| Control protocol denominator (S+M) | {matrix['protocol_denominator_control_rows'] if matrix['protocol_denominator_control_rows'] is not None else 'n/a'} |",
        f"| Legacy scored total rows | {matrix['total_rows']} |",
        f"| Attack trials per core case | {matrix['attack_trials_per_case']} |",
        f"| Attack success rows | {results['attack_success_rows']} |",
        f"| Confirmed compromise rows | {results['confirmed_rows']} |",
        f"| Protocol completion rate | {pct_or_na(results['protocol_completion_rate'])} |",
        f"| Model nonconformance rate | {pct_or_na(results['model_nonconformance_rate'])} |",
        f"| Conditional ASR | {results['conditional_asr']} |",
        f"| End-to-end attack rate | {pct_or_na(results['end_to_end_attack_rate'])} |",
        f"| Family macro conditional ASR | {results['family_macro_asr']} |",
        f"| Family macro end-to-end attack rate | {results['family_macro_end_to_end']} |",
        f"| Family macro confirmed | {results['family_macro_confirmed']} |",
        f"| Mean risk | {number_or_na(results['mean_risk'])} |",
        f"| Attack timeouts | {results['timeouts']} |",
        "",
        "## Controls",
        "",
        f"- control_types: `{', '.join(matrix.get('control_types', []))}`",
        f"- control_scored_rows: `{controls['scored_trials']}`",
        f"- control_asr_eligible_scored_rows: `{controls['asr_eligible_scored_trials']}`",
        f"- control_n_minus_1_rows: `{controls['n_minus_1_trials'] if controls['n_minus_1_trials'] is not None else 'n/a'}`",
        f"- control_accounted_terminal_rows: `{controls['accounted_terminal_trials'] if controls['accounted_terminal_trials'] is not None else 'n/a'}`",
        f"- control_protocol_denominator_rows: `{controls['protocol_denominator_trials'] if controls['protocol_denominator_trials'] is not None else 'n/a'}`",
        f"- control_protocol_completion_rate: `{pct_or_na(controls['protocol_completion_rate'])}`",
        f"- control_model_nonconformance_rate: `{pct_or_na(controls['model_nonconformance_rate'])}`",
        f"- control_conditional_violation_rate: `{pct_or_na(controls['conditional_violation_rate'])}`",
        f"- control_end_to_end_violation_rate: `{pct_or_na(controls['end_to_end_violation_rate'])}`",
        f"- control_attack_success_rows: `{controls['attack_success_rows']}`",
        f"- control_confirmed_rows: `{controls['confirmed_rows']}`",
        f"- control_timeouts: `{controls['timeouts']}`",
        "",
        "| Control | All Scored | ASR Eligible (S) | N-1 (M) | Coverage Accounted (T) | Protocol Denominator (D) | Protocol completion (S/D) | Model nonconformance (M/D) | Conditional violation (A/S) | End-to-end violation (A/D) | Confirmed | Timeouts |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in controls.get("by_type", []):
        lines.append(
            f"| {row['control_type']} | {row['scored_trials']} | "
            f"{row['asr_eligible_scored_trials']} | "
            f"{row['n_minus_1_trials'] if row['n_minus_1_trials'] is not None else 'n/a'} | "
            f"{row['accounted_terminal_trials'] if row['accounted_terminal_trials'] is not None else 'n/a'} | "
            f"{row['protocol_denominator_trials'] if row['protocol_denominator_trials'] is not None else 'n/a'} | "
            f"{pct_or_na(row['protocol_completion_rate'])} | "
            f"{pct_or_na(row['model_nonconformance_rate'])} | "
            f"{pct_or_na(row['conditional_violation_rate'])} | "
            f"{pct_or_na(row['end_to_end_violation_rate'])} | "
            f"{row['confirmed_rows']} | {row['timeouts']} |"
        )
    lines += [
        "",
        "## Evidence And Oracles",
        "",
        "- Primary evidence is observable trace, honeypot, canary, workspace artifact, local marker, and tool/MCP argument evidence.",
        f"- case_study_evidence: `{card['evidence']['case_study_evidence']}`",
        f"- case_study_check: `{card['evidence']['case_study_check']}`",
        f"- manuscript_check: `{card['evidence']['manuscript_check']}`",
        f"- number_check: `{card['evidence']['number_check']}`",
        "",
        "## Public Artifact Boundary",
        "",
        "- Excluded from the public bundle: "
        + ", ".join(card["public_artifact_boundary"]["excluded_from_public_bundle"])
        + ".",
        "- Release blockers: " + ", ".join(card["public_artifact_boundary"]["release_blockers"]) + ".",
        "",
        "## Limitations",
        "",
    ]
    lines.extend(f"- {item}" for item in card["limitations"])
    lines += [
        "",
        "## Sources",
        "",
        f"- attack_reports: `{', '.join(card['sources']['attack_reports'])}`",
        f"- control_reports: `{', '.join(card['sources']['control_reports'])}`",
        f"- table_dir: `{card['sources']['table_dir']}`",
        f"- suite_lock: `{card['sources']['suite_lock']}`",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the Safety Bench benchmark card.")
    parser.add_argument("--attack-label", action="append", default=[])
    parser.add_argument("--attack-report-dir", action="append", default=[])
    parser.add_argument("--control-label", action="append", default=[])
    parser.add_argument("--control-report-dir", action="append", default=[])
    parser.add_argument("--table-dir", default="")
    parser.add_argument("--suite-lock", default=str(DEFAULT_SUITE_LOCK))
    parser.add_argument("--baseline-runtime", default="Claude Code")
    parser.add_argument("--baseline-model", default="Kimi K2.6")
    parser.add_argument("--baseline-harness", default="claude")
    parser.add_argument("--baseline-model-source", default="Claude Code runtime default")
    parser.add_argument("--codex-in-current-scope", action="store_true")
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    args = parser.parse_args()

    attack_dirs = resolve_report_dirs(
        labels=args.attack_label,
        paths=args.attack_report_dir,
        default_label=DEFAULT_ATTACK_LABEL,
    )
    control_dirs = resolve_report_dirs(
        labels=args.control_label,
        paths=args.control_report_dir,
        default_label=DEFAULT_CONTROL_LABEL,
    )
    table_dir = Path(args.table_dir) if args.table_dir else None
    card = build_card(
        attack_dirs=attack_dirs,
        control_dirs=control_dirs,
        table_dir=table_dir,
        suite_lock_path=Path(args.suite_lock),
        baseline_runtime=args.baseline_runtime,
        baseline_model=args.baseline_model,
        baseline_harness=args.baseline_harness,
        baseline_model_source=args.baseline_model_source,
        codex_in_current_scope=args.codex_in_current_scope,
    )
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(card, indent=2, ensure_ascii=False), encoding="utf-8")
    out_md.write_text(render_markdown(card), encoding="utf-8")
    print(out_json)
    print(out_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
