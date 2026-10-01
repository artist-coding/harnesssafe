"""Generate reviewer-facing statistical analysis artifacts for the paper."""

from __future__ import annotations

import argparse
import json
import math
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ATTACK_LABEL = "paper_core_20260625"
DEFAULT_CONTROL_LABEL = "paper_controls_core_20260625"
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/paper_statistical_analysis.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/paper_statistical_analysis.md")
Z_95 = 1.959963984540054


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
    dirs = [Path(path) for path in split_cli_values(paths)]
    labels_list = split_cli_values(labels)
    if not dirs and not labels_list and default_label:
        labels_list = [default_label]
    dirs.extend(root / "runs" / "_reports" / safe_slug(label) for label in labels_list)
    return dirs


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def load_summaries(dirs: list[Path]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for directory in dirs:
        path = directory / "summary.json"
        if path.is_file():
            summaries.append(load_json(path))
    return summaries


def relpath(path: Path | None, root: Path = ROOT) -> str:
    if path is None:
        return ""
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
        return float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0


def optional_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def rate(successes: int, trials: int) -> float | None:
    return successes / trials if trials > 0 else None


def rounded_rate(successes: int, trials: int, digits: int = 6) -> float | None:
    value = rate(successes, trials)
    return round(value, digits) if value is not None else None


def rounded_optional_float(value: Any, digits: int = 6) -> float | None:
    parsed = optional_float(value)
    return round(parsed, digits) if parsed is not None else None


def rate_difference(left: Any, right: Any, digits: int = 6) -> float | None:
    left_rate = optional_float(left)
    right_rate = optional_float(right)
    if left_rate is None or right_rate is None:
        return None
    return round(left_rate - right_rate, digits)


def pct(value: float, digits: int = 1) -> str:
    return f"{value * 100:.{digits}f}%"


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> list[float]:
    if trials <= 0:
        return []
    p_hat = successes / trials
    denominator = 1.0 + (z * z / trials)
    center = p_hat + (z * z / (2.0 * trials))
    margin = z * math.sqrt((p_hat * (1.0 - p_hat) / trials) + (z * z / (4.0 * trials * trials)))
    low = max(0.0, (center - margin) / denominator)
    high = min(1.0, (center + margin) / denominator)
    return [round(low, 6), round(high, 6)]


def one_sided_zero_success_upper(trials: int, alpha: float = 0.05) -> float | None:
    if trials <= 0:
        return None
    return round(1.0 - math.pow(alpha, 1.0 / trials), 6)


def metric_block(successes: int, trials: int) -> dict[str, Any]:
    if successes < 0 or trials < 0 or successes > trials:
        raise ValueError("metric counts must satisfy 0 <= successes <= trials")
    return {
        "available": True,
        "successes": successes,
        "trials": trials,
        "rate": rounded_rate(successes, trials),
        "wilson95": wilson_interval(successes, trials),
    }


def unavailable_metric_block() -> dict[str, Any]:
    return {
        "available": False,
        "successes": None,
        "trials": None,
        "rate": None,
        "wilson95": [],
    }


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
    """Validate and return the canonical T/S/M/D/A counts for a current row.

    Rows without any measurement marker are treated as legacy artifacts.  Once
    a row advertises any current-contract field, the complete contract is
    mandatory and is validated fail-closed.
    """

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


def protocol_counts_available(row: dict[str, Any], context: str = "row") -> bool:
    return measurement_counts(row, context) is not None


def adjusted_odds_ratio(
    attack_successes: int,
    attack_trials: int,
    control_successes: int,
    control_trials: int,
) -> dict[str, Any]:
    if attack_trials <= 0 or control_trials <= 0:
        return {
            "available": False,
            "estimate": None,
            "ci95": [],
            "method": "haldane_anscombe",
        }
    a = attack_successes + 0.5
    b = max(attack_trials - attack_successes, 0) + 0.5
    c = control_successes + 0.5
    d = max(control_trials - control_successes, 0) + 0.5
    estimate = (a * d) / (b * c)
    se = math.sqrt((1.0 / a) + (1.0 / b) + (1.0 / c) + (1.0 / d))
    low = math.exp(math.log(estimate) - Z_95 * se)
    high = math.exp(math.log(estimate) + Z_95 * se)
    return {
        "available": True,
        "estimate": round(estimate, 6),
        "ci95": [round(low, 6), round(high, 6)],
        "method": "haldane_anscombe",
    }


def summary_rows(summaries: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    return [
        row
        for summary in summaries
        for row in summary.get(key, [])
        if isinstance(row, dict)
    ]


def attack_macro(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    for row in summary_rows(summaries, "harness_macro"):
        if str(row.get("run_kind") or "") == "attack":
            return row
    rows = summary_rows(summaries, "harness_macro")
    return rows[0] if rows else {}


def control_macros(summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in summary_rows(summaries, "harness_macro")
        if not row.get("run_kind") or str(row.get("run_kind") or "") == "control"
    ]


def sum_field(rows: list[dict[str, Any]], field: str) -> int:
    return sum(as_int(row.get(field)) for row in rows)


def timeout_sensitivity(successes: int, trials: int, timeouts: int) -> dict[str, Any]:
    if timeouts < 0:
        raise ValueError("timeout count must be non-negative")
    # S already excludes execution-invalid timeout rows. Counterfactual timeout
    # scenarios therefore add those rows to S; subtracting them from S would
    # double-exclude and can create impossible A > trials blocks.
    expanded_trials = trials + timeouts
    return {
        "trials": trials,
        "timeouts": timeouts,
        "observed_status_quo": metric_block(successes, trials),
        "timeouts_as_failures": metric_block(successes, expanded_trials),
        "timeouts_as_successes": metric_block(
            successes + timeouts, expanded_trials
        ),
        "timeouts_excluded": metric_block(successes, trials),
        "interpretation": "timeout rows are outside S and are added only in counterfactual scenarios",
    }


def current_measurement_rows(
    rows: list[dict[str, Any]], context: str
) -> list[tuple[dict[str, Any], dict[str, int]]]:
    current: list[tuple[dict[str, Any], dict[str, int]]] = []
    for index, row in enumerate(rows):
        if str(row.get("run_kind") or "") not in {"", "attack"}:
            continue
        counts = measurement_counts(row, f"{context}[{index}]")
        # Protocol summaries use D, so D-only rows remain visible. Safety,
        # progress, and risk fields are nulled separately whenever S == 0.
        if counts is not None and counts["protocol_denominator_trials"] > 0:
            current.append((row, counts))
    return current


def family_heterogeneity(rows: list[dict[str, Any]]) -> dict[str, Any]:
    families = current_measurement_rows(rows, "family_macro")
    top = sorted(
        families,
        key=lambda item: (
            item[1]["attack_success_trials"] / item[1]["asr_eligible_trials"]
            if item[1]["asr_eligible_trials"]
            else -1.0,
            as_int(item[0].get("confirmed_trials"))
            / item[1]["asr_eligible_trials"]
            if item[1]["asr_eligible_trials"]
            else -1.0,
            (optional_float(item[0].get("avg_risk_case_mean")) or 0.0)
            if item[1]["asr_eligible_trials"]
            else -1.0,
        ),
        reverse=True,
    )[:10]
    rates = [
        counts["attack_success_trials"] / counts["asr_eligible_trials"]
        for _row, counts in families
        if counts["asr_eligible_trials"] > 0
    ]
    confirmed_rates = [
        as_int(row.get("confirmed_trials")) / counts["asr_eligible_trials"]
        for row, counts in families
        if counts["asr_eligible_trials"] > 0
    ]
    return {
        "families": len(families),
        "families_with_attack_success": sum(
            1 for _row, counts in families if counts["attack_success_trials"] > 0
        ),
        "families_with_confirmed": sum(
            1 for row, _counts in families if as_int(row.get("confirmed_trials")) > 0
        ),
        "min_attack_success_rate": round(min(rates), 6) if rates else None,
        "max_attack_success_rate": round(max(rates), 6) if rates else None,
        "min_confirmed_rate": round(min(confirmed_rates), 6) if confirmed_rates else None,
        "max_confirmed_rate": round(max(confirmed_rates), 6) if confirmed_rates else None,
        "top_families": [
            {
                "suite": str(row.get("suite") or ""),
                "paper_family": str(row.get("paper_family") or ""),
                "cases": as_int(row.get("cases")),
                "completed_trials": counts["completed_trials"],
                "asr_eligible_trials": counts["asr_eligible_trials"],
                "n_minus_1_trials": counts["n_minus_1_trials"],
                "accounted_terminal_trials": counts["accounted_terminal_trials"],
                "protocol_denominator_trials": counts["protocol_denominator_trials"],
                "attack_success_trials": counts["attack_success_trials"],
                "confirmed_trials": as_int(row.get("confirmed_trials")),
                "attack_success_trial_rate": rounded_rate(
                    counts["attack_success_trials"], counts["asr_eligible_trials"]
                ),
                "protocol_completion_trial_rate": rounded_rate(
                    counts["asr_eligible_trials"], counts["protocol_denominator_trials"]
                ),
                "model_nonconformance_trial_rate": rounded_rate(
                    counts["n_minus_1_trials"], counts["protocol_denominator_trials"]
                ),
                "end_to_end_attack_trial_rate": rounded_rate(
                    counts["attack_success_trials"], counts["protocol_denominator_trials"]
                ),
                "confirmed_trial_rate": rounded_rate(
                    as_int(row.get("confirmed_trials")), counts["asr_eligible_trials"]
                ),
                "avg_risk_case_mean": (
                    rounded_optional_float(row.get("avg_risk_case_mean"), 4)
                    if counts["asr_eligible_trials"] > 0
                    else None
                ),
            }
            for row, counts in top
        ],
    }


def case_heterogeneity(rows: list[dict[str, Any]]) -> dict[str, Any]:
    cases = current_measurement_rows(rows, "case_summary")
    top = sorted(
        cases,
        key=lambda item: (
            item[1]["attack_success_trials"] / item[1]["asr_eligible_trials"]
            if item[1]["asr_eligible_trials"]
            else -1.0,
            as_int(item[0].get("confirmed_trials"))
            / item[1]["asr_eligible_trials"]
            if item[1]["asr_eligible_trials"]
            else -1.0,
            (optional_float(item[0].get("avg_risk")) or 0.0)
            if item[1]["asr_eligible_trials"]
            else -1.0,
        ),
        reverse=True,
    )[:10]
    return {
        "cases": len(cases),
        "cases_with_attack_success": sum(
            1 for _row, counts in cases if counts["attack_success_trials"] > 0
        ),
        "cases_with_confirmed": sum(
            1 for row, _counts in cases if as_int(row.get("confirmed_trials")) > 0
        ),
        "top_cases": [
            {
                "suite": str(row.get("suite") or ""),
                "paper_family": str(row.get("paper_family") or ""),
                "case_dir": str(row.get("case_dir") or ""),
                "completed_trials": counts["completed_trials"],
                "asr_eligible_trials": counts["asr_eligible_trials"],
                "n_minus_1_trials": counts["n_minus_1_trials"],
                "accounted_terminal_trials": counts["accounted_terminal_trials"],
                "protocol_denominator_trials": counts["protocol_denominator_trials"],
                "attack_success_trials": counts["attack_success_trials"],
                "confirmed_trials": as_int(row.get("confirmed_trials")),
                "attack_success_rate": rounded_rate(
                    counts["attack_success_trials"], counts["asr_eligible_trials"]
                ),
                "protocol_completion_rate": rounded_rate(
                    counts["asr_eligible_trials"], counts["protocol_denominator_trials"]
                ),
                "model_nonconformance_rate": rounded_rate(
                    counts["n_minus_1_trials"], counts["protocol_denominator_trials"]
                ),
                "end_to_end_attack_rate": rounded_rate(
                    counts["attack_success_trials"], counts["protocol_denominator_trials"]
                ),
                "confirmed_rate": rounded_rate(
                    as_int(row.get("confirmed_trials")), counts["asr_eligible_trials"]
                ),
                "max_progress_node": (
                    str(row.get("max_progress_node"))
                    if counts["asr_eligible_trials"] > 0
                    and row.get("max_progress_node") not in {None, ""}
                    else None
                ),
                "avg_risk": (
                    rounded_optional_float(row.get("avg_risk"), 4)
                    if counts["asr_eligible_trials"] > 0
                    else None
                ),
            }
            for row, counts in top
        ],
    }


def control_type_rows(macros: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for index, row in enumerate(
        sorted(macros, key=lambda item: str(item.get("control_type") or ""))
    ):
        counts = measurement_counts(row, f"control_macro[{index}]")
        protocol_available = counts is not None
        trials = counts["completed_trials"] if counts is not None else as_int(
            row.get("completed_trials")
        )
        n_minus_one = counts["n_minus_1_trials"] if counts is not None else 0
        accounted = counts["accounted_terminal_trials"] if counts is not None else 0
        asr_trials = counts["asr_eligible_trials"] if counts is not None else trials
        protocol_denominator = (
            counts["protocol_denominator_trials"] if counts is not None else 0
        )
        successes = as_int(row.get("attack_success_trials"))
        confirmed = as_int(row.get("confirmed_trials"))
        rows.append(
            {
                "control_type": str(row.get("control_type") or "control"),
                "completed_trials": trials,
                "scored_trials": trials,
                "asr_eligible_scored_trials": asr_trials,
                "n_minus_1_trials": n_minus_one if protocol_available else None,
                "accounted_terminal_trials": accounted if protocol_available else None,
                "protocol_denominator_trials": (
                    protocol_denominator if protocol_available else None
                ),
                "protocol_metrics_available": protocol_available,
                "timeout_trials": as_int(row.get("timeout_trials")),
                "attack_success_trials": successes,
                "confirmed_trials": confirmed,
                "protocol_completion_rate": (
                    rounded_rate(asr_trials, protocol_denominator)
                    if protocol_available
                    else None
                ),
                "model_nonconformance_rate": (
                    rounded_rate(n_minus_one, protocol_denominator)
                    if protocol_available
                    else None
                ),
                "attack_success_rate": rounded_rate(successes, asr_trials),
                "attack_success_wilson95": wilson_interval(successes, asr_trials),
                "end_to_end_violation_rate": (
                    rounded_rate(successes, protocol_denominator)
                    if protocol_available
                    else None
                ),
                "confirmed_rate": rounded_rate(confirmed, asr_trials),
                "confirmed_wilson95": wilson_interval(confirmed, asr_trials),
            }
        )
    return rows


def build_analysis(
    *,
    attack_dirs: list[Path],
    control_dirs: list[Path],
    baseline_runtime: str = "Claude Code",
    baseline_model: str = "Kimi K2.6",
    baseline_harness: str = "",
    root: Path = ROOT,
) -> dict[str, Any]:
    attack_summaries = load_summaries(attack_dirs)
    control_summaries = load_summaries(control_dirs)
    attack = attack_macro(attack_summaries)
    controls = control_macros(control_summaries)

    attack_requires_current = any(
        summary_requires_current_contract(summary) for summary in attack_summaries
    )
    control_requires_current = any(
        summary_requires_current_contract(summary) for summary in control_summaries
    )
    for summary_index, summary in enumerate(attack_summaries):
        if not summary_requires_current_contract(summary):
            continue
        for collection in ("family_macro", "case_summary"):
            for row_index, row in enumerate(summary.get(collection, [])):
                if isinstance(row, dict):
                    measurement_counts(
                        row,
                        f"attack_summary[{summary_index}].{collection}[{row_index}]",
                        require_current=True,
                    )
    attack_counts = measurement_counts(
        attack, "attack_macro", require_current=attack_requires_current
    )
    control_count_rows = [
        measurement_counts(
            row,
            f"control_macro[{index}]",
            require_current=control_requires_current,
        )
        for index, row in enumerate(controls)
    ]
    if any(counts is not None for counts in control_count_rows) and not all(
        counts is not None for counts in control_count_rows
    ):
        raise ValueError("control macros cannot mix current and legacy measurement contracts")
    attack_protocol_available = attack_counts is not None
    control_protocol_available = bool(controls) and all(
        counts is not None for counts in control_count_rows
    )
    attack_trials = (
        attack_counts["completed_trials"]
        if attack_counts is not None
        else as_int(attack.get("completed_trials"))
    )
    attack_n_minus_one = (
        attack_counts["n_minus_1_trials"] if attack_counts is not None else 0
    )
    attack_accounted = (
        attack_counts["accounted_terminal_trials"] if attack_counts is not None else 0
    )
    attack_asr_trials = (
        attack_counts["asr_eligible_trials"]
        if attack_counts is not None
        else attack_trials
    )
    attack_timeouts = as_int(attack.get("timeout_trials"))
    attack_successes = as_int(attack.get("attack_success_trials"))
    attack_confirmed = as_int(attack.get("confirmed_trials"))
    control_trials = (
        sum(counts["completed_trials"] for counts in control_count_rows if counts)
        if control_protocol_available
        else sum_field(controls, "completed_trials")
    )
    control_n_minus_one = (
        sum(counts["n_minus_1_trials"] for counts in control_count_rows if counts)
        if control_protocol_available
        else 0
    )
    control_accounted = (
        sum(counts["accounted_terminal_trials"] for counts in control_count_rows if counts)
        if control_protocol_available
        else 0
    )
    control_asr_trials = (
        sum(counts["asr_eligible_trials"] for counts in control_count_rows if counts)
        if control_protocol_available
        else control_trials
    )
    control_timeouts = sum_field(controls, "timeout_trials")
    control_successes = sum_field(controls, "attack_success_trials")
    control_confirmed = sum_field(controls, "confirmed_trials")
    attack_protocol_denominator = (
        attack_counts["protocol_denominator_trials"] if attack_counts is not None else 0
    )
    control_protocol_denominator = (
        sum(
            counts["protocol_denominator_trials"]
            for counts in control_count_rows
            if counts
        )
        if control_protocol_available
        else 0
    )

    attack_success = metric_block(attack_successes, attack_asr_trials)
    confirmed = metric_block(attack_confirmed, attack_asr_trials)
    control_success = metric_block(control_successes, control_asr_trials)
    control_confirmed_block = metric_block(control_confirmed, control_asr_trials)
    attack_protocol_completion = (
        metric_block(attack_asr_trials, attack_protocol_denominator)
        if attack_protocol_available
        else unavailable_metric_block()
    )
    attack_model_nonconformance = (
        metric_block(attack_n_minus_one, attack_protocol_denominator)
        if attack_protocol_available
        else unavailable_metric_block()
    )
    attack_end_to_end = (
        metric_block(attack_successes, attack_protocol_denominator)
        if attack_protocol_available
        else unavailable_metric_block()
    )
    control_protocol_completion = (
        metric_block(control_asr_trials, control_protocol_denominator)
        if control_protocol_available
        else unavailable_metric_block()
    )
    control_model_nonconformance = (
        metric_block(control_n_minus_one, control_protocol_denominator)
        if control_protocol_available
        else unavailable_metric_block()
    )
    control_end_to_end = (
        metric_block(control_successes, control_protocol_denominator)
        if control_protocol_available
        else unavailable_metric_block()
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
        "baseline": {
            "runtime": baseline_runtime,
            "model": baseline_model,
            "harness": baseline_harness or str(attack.get("harness") or "claude"),
            "label": str(attack_summaries[0].get("label") or "") if attack_summaries else "",
        },
        "sources": {
            "attack_report_dirs": [relpath(path, root) for path in attack_dirs],
            "control_report_dirs": [relpath(path, root) for path in control_dirs],
            "public_artifact_boundary": (
                "Derived only from sanitized summary artifacts; raw traces, honeypots, "
                "materialized cases, secrets, and run-local agent homes are excluded."
            ),
        },
        "matrix": {
            "attack_rows": attack_trials,
            "attack_scored_rows": attack_trials,
            "attack_asr_eligible_scored_rows": attack_asr_trials,
            "attack_n_minus_1_rows": attack_n_minus_one if attack_protocol_available else None,
            "attack_accounted_terminal_rows": attack_accounted if attack_protocol_available else None,
            "attack_protocol_denominator_rows": (
                attack_protocol_denominator if attack_protocol_available else None
            ),
            "attack_timeouts": attack_timeouts,
            "control_rows": control_trials,
            "control_scored_rows": control_trials,
            "control_asr_eligible_scored_rows": control_asr_trials,
            "control_n_minus_1_rows": control_n_minus_one if control_protocol_available else None,
            "control_accounted_terminal_rows": control_accounted if control_protocol_available else None,
            "control_protocol_denominator_rows": (
                control_protocol_denominator if control_protocol_available else None
            ),
            "control_timeouts": control_timeouts,
            "protocol_metrics_available": bool(
                attack_protocol_available and control_protocol_available
            ),
            "control_types": [row["control_type"] for row in control_type_rows(controls)],
        },
        "primary_effects": {
            "attack_success": attack_success,
            "conditional_attack_success": attack_success,
            "protocol_completion": attack_protocol_completion,
            "model_nonconformance": attack_model_nonconformance,
            "end_to_end_attack": attack_end_to_end,
            "confirmed_compromise": confirmed,
            "control_attack_success": control_success,
            "control_conditional_violation": control_success,
            "control_protocol_completion": control_protocol_completion,
            "control_model_nonconformance": control_model_nonconformance,
            "control_end_to_end_violation": control_end_to_end,
            "control_confirmed_compromise": control_confirmed_block,
            "risk_difference_attack_success_vs_control": rate_difference(
                attack_success["rate"], control_success["rate"]
            ),
            "risk_difference_confirmed_vs_control": rate_difference(
                confirmed["rate"], control_confirmed_block["rate"]
            ),
            "descriptive_odds_ratio_attack_success_vs_control": adjusted_odds_ratio(
                attack_successes,
                attack_asr_trials,
                control_successes,
                control_asr_trials,
            ),
            "descriptive_odds_ratio_confirmed_vs_control": adjusted_odds_ratio(
                attack_confirmed,
                attack_asr_trials,
                control_confirmed,
                control_asr_trials,
            ),
        },
        "control_zero_success_bound": {
            "successes": control_successes,
            "trials": control_asr_trials,
            "one_sided_95_upper": one_sided_zero_success_upper(control_asr_trials)
            if control_successes == 0
            else None,
            "wilson95": control_success["wilson95"],
        },
        "timeout_sensitivity": {
            "attack_success": timeout_sensitivity(attack_successes, attack_asr_trials, attack_timeouts),
            "confirmed_compromise": timeout_sensitivity(attack_confirmed, attack_asr_trials, attack_timeouts),
            "control_attack_success": timeout_sensitivity(control_successes, control_asr_trials, control_timeouts),
            "control_confirmed_compromise": timeout_sensitivity(control_confirmed, control_asr_trials, control_timeouts),
        },
        "control_by_type": control_type_rows(controls),
        "family_heterogeneity": family_heterogeneity(summary_rows(attack_summaries, "family_macro")),
        "case_heterogeneity": case_heterogeneity(summary_rows(attack_summaries, "case_summary")),
    }


def interval_text(values: list[float]) -> str:
    if len(values) != 2:
        return "n/a"
    low = values[0]
    high = values[1]
    return f"[{pct(low)}, {pct(high)}]"


def pct_or_na(value: Any, digits: int = 1) -> str:
    parsed = optional_float(value)
    return pct(parsed, digits) if parsed is not None else "n/a"


def number_or_na(value: Any, digits: int = 1) -> str:
    parsed = optional_float(value)
    return f"{parsed:.{digits}f}" if parsed is not None else "n/a"


def metric_text(block: dict[str, Any]) -> str:
    if block.get("available") is False:
        return "n/a (legacy artifact lacks N-1 accounting fields)"
    return (
        f"{block.get('successes', 0)}/{block.get('trials', 0)} "
        f"({pct_or_na(block.get('rate'))}), Wilson 95% "
        f"{interval_text(block.get('wilson95', []))}"
    )


def render_markdown(analysis: dict[str, Any]) -> str:
    baseline = analysis.get("baseline", {})
    matrix = analysis.get("matrix", {})
    effects = analysis.get("primary_effects", {})
    zero = analysis.get("control_zero_success_bound", {})
    timeout = analysis.get("timeout_sensitivity", {})
    family = analysis.get("family_heterogeneity", {})
    cases = analysis.get("case_heterogeneity", {})
    lines = [
        "# Safety Bench Statistical Analysis",
        "",
        f"- generated_at: `{analysis.get('generated_at')}`",
        f"- baseline: `{baseline.get('runtime', 'Claude Code')} + {baseline.get('model', 'Kimi K2.6')}`",
        f"- harness: `{baseline.get('harness')}`",
        f"- attack_scored_rows: `{matrix.get('attack_scored_rows', 0)}`",
        f"- attack_asr_eligible_scored_rows: `{matrix.get('attack_asr_eligible_scored_rows', 0)}`",
        f"- attack_n_minus_1_rows: `{matrix.get('attack_n_minus_1_rows') if matrix.get('attack_n_minus_1_rows') is not None else 'n/a'}`",
        f"- attack_accounted_terminal_rows: `{matrix.get('attack_accounted_terminal_rows') if matrix.get('attack_accounted_terminal_rows') is not None else 'n/a'}`",
        f"- attack_protocol_denominator_rows: `{matrix.get('attack_protocol_denominator_rows') if matrix.get('attack_protocol_denominator_rows') is not None else 'n/a'}`",
        f"- control_scored_rows: `{matrix.get('control_scored_rows', 0)}`",
        f"- control_asr_eligible_scored_rows: `{matrix.get('control_asr_eligible_scored_rows', 0)}`",
        f"- control_n_minus_1_rows: `{matrix.get('control_n_minus_1_rows') if matrix.get('control_n_minus_1_rows') is not None else 'n/a'}`",
        f"- control_accounted_terminal_rows: `{matrix.get('control_accounted_terminal_rows') if matrix.get('control_accounted_terminal_rows') is not None else 'n/a'}`",
        f"- control_protocol_denominator_rows: `{matrix.get('control_protocol_denominator_rows') if matrix.get('control_protocol_denominator_rows') is not None else 'n/a'}`",
        f"- attack_timeouts: `{matrix.get('attack_timeouts', 0)}`",
        f"- control_timeouts: `{matrix.get('control_timeouts', 0)}`",
        "",
        "## Primary Effects",
        "",
        "| Metric | Result |",
        "| --- | --- |",
        f"| Conditional attack success (ASR-eligible scored denominator) | {metric_text(effects.get('conditional_attack_success', {}))} |",
        f"| Protocol completion (S+M denominator) | {metric_text(effects.get('protocol_completion', {}))} |",
        f"| Model nonconformance / N-1 (S+M denominator) | {metric_text(effects.get('model_nonconformance', {}))} |",
        f"| End-to-end attack (S+M denominator) | {metric_text(effects.get('end_to_end_attack', {}))} |",
        f"| Confirmed compromise | {metric_text(effects.get('confirmed_compromise', {}))} |",
        f"| Control conditional violation (ASR-eligible scored denominator) | {metric_text(effects.get('control_conditional_violation', {}))} |",
        f"| Control protocol completion (S+M denominator) | {metric_text(effects.get('control_protocol_completion', {}))} |",
        f"| Control model nonconformance / N-1 (S+M denominator) | {metric_text(effects.get('control_model_nonconformance', {}))} |",
        f"| Control end-to-end violation (S+M denominator) | {metric_text(effects.get('control_end_to_end_violation', {}))} |",
        f"| Control confirmed compromise | {metric_text(effects.get('control_confirmed_compromise', {}))} |",
        (
            f"| Attack-success risk difference vs pooled controls | "
            f"{pct_or_na(effects.get('risk_difference_attack_success_vs_control'))} |"
        ),
        (
            f"| Confirmed risk difference vs pooled controls | "
            f"{pct_or_na(effects.get('risk_difference_confirmed_vs_control'))} |"
        ),
        "",
        "## Control Zero-Success Bound",
        "",
        (
            f"The pooled control attack-success count is {zero.get('successes', 0)}/{zero.get('trials', 0)}. "
            f"The one-sided 95% zero-success upper bound is {pct_or_na(zero.get('one_sided_95_upper'))}; "
            f"the two-sided Wilson 95% interval is {interval_text(zero.get('wilson95', []))}."
        ),
        "",
        "## Timeout Sensitivity",
        "",
        "| Metric | Status quo | Timeouts as successes | Timeouts excluded |",
        "| --- | --- | --- | --- |",
    ]
    for name, label in [
        ("attack_success", "Attack success"),
        ("confirmed_compromise", "Confirmed compromise"),
        ("control_attack_success", "Control attack success"),
        ("control_confirmed_compromise", "Control confirmed compromise"),
    ]:
        row = timeout.get(name, {}) if isinstance(timeout.get(name), dict) else {}
        lines.append(
            f"| {label} | "
            f"{metric_text(row.get('observed_status_quo', {}))} | "
            f"{metric_text(row.get('timeouts_as_successes', {}))} | "
            f"{metric_text(row.get('timeouts_excluded', {}))} |"
        )
    lines += [
        "",
        "Timeout sensitivity is diagnostic: timeout rows are outside S and are added only in the counterfactual columns.",
    ]
    lines += [
        "",
        "## Family Heterogeneity",
        "",
        f"- families: `{family.get('families', 0)}`",
        f"- families_with_attack_success: `{family.get('families_with_attack_success', 0)}`",
        f"- families_with_confirmed: `{family.get('families_with_confirmed', 0)}`",
        (
            f"- attack_success_rate_range: "
            f"`{pct_or_na(family.get('min_attack_success_rate'))}-{pct_or_na(family.get('max_attack_success_rate'))}`"
        ),
        "",
        "| Suite | Family | All Scored | S | M | T | D | Protocol completion (S/D) | Model nonconformance (M/D) | Conditional ASR (A/S) | End-to-end attack (A/D) | Confirmed | Risk |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in family.get("top_families", []):
        lines.append(
            f"| {row.get('suite')} | {row.get('paper_family')} | {row.get('completed_trials')} | "
            f"{row.get('asr_eligible_trials')} | "
            f"{row.get('n_minus_1_trials') if row.get('n_minus_1_trials') is not None else 'n/a'} | "
            f"{row.get('accounted_terminal_trials') if row.get('accounted_terminal_trials') is not None else 'n/a'} | "
            f"{row.get('protocol_denominator_trials') if row.get('protocol_denominator_trials') is not None else 'n/a'} | "
            f"{pct(row.get('protocol_completion_trial_rate')) if row.get('protocol_completion_trial_rate') is not None else 'n/a'} | "
            f"{pct(row.get('model_nonconformance_trial_rate')) if row.get('model_nonconformance_trial_rate') is not None else 'n/a'} | "
            f"{row.get('attack_success_trials')} ({pct_or_na(row.get('attack_success_trial_rate'))}) | "
            f"{pct(row.get('end_to_end_attack_trial_rate')) if row.get('end_to_end_attack_trial_rate') is not None else 'n/a'} | "
            f"{row.get('confirmed_trials')} ({pct_or_na(row.get('confirmed_trial_rate'))}) | "
            f"{number_or_na(row.get('avg_risk_case_mean'))} |"
        )
    lines += [
        "",
        "## Case Heterogeneity",
        "",
        f"- cases: `{cases.get('cases', 0)}`",
        f"- cases_with_attack_success: `{cases.get('cases_with_attack_success', 0)}`",
        f"- cases_with_confirmed: `{cases.get('cases_with_confirmed', 0)}`",
        "",
        "| Suite | Family | Case | All Scored | S | M | T | D | Protocol completion (S/D) | Model nonconformance (M/D) | Conditional ASR (A/S) | End-to-end attack (A/D) | Confirmed | Max node | Risk |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |",
    ]
    for row in cases.get("top_cases", []):
        lines.append(
            f"| {row.get('suite')} | {row.get('paper_family')} | `{row.get('case_dir')}` | "
            f"{row.get('completed_trials')} | "
            f"{row.get('asr_eligible_trials')} | "
            f"{row.get('n_minus_1_trials') if row.get('n_minus_1_trials') is not None else 'n/a'} | "
            f"{row.get('accounted_terminal_trials') if row.get('accounted_terminal_trials') is not None else 'n/a'} | "
            f"{row.get('protocol_denominator_trials') if row.get('protocol_denominator_trials') is not None else 'n/a'} | "
            f"{pct(row.get('protocol_completion_rate')) if row.get('protocol_completion_rate') is not None else 'n/a'} | "
            f"{pct(row.get('model_nonconformance_rate')) if row.get('model_nonconformance_rate') is not None else 'n/a'} | "
            f"{row.get('attack_success_trials')}/{row.get('asr_eligible_trials')} | "
            f"{pct(row.get('end_to_end_attack_rate')) if row.get('end_to_end_attack_rate') is not None else 'n/a'} | "
            f"{row.get('confirmed_trials')}/{row.get('asr_eligible_trials')} | "
            f"{row.get('max_progress_node') or 'n/a'} | {number_or_na(row.get('avg_risk'))} |"
        )
    lines += [
        "",
        "## Control By Type",
        "",
        "| Control type | All Scored | S | M | T | D | Protocol completion (S/D) | Model nonconformance (M/D) | Conditional violation (A/S) | End-to-end violation (A/D) | Confirmed | Timeouts |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in analysis.get("control_by_type", []):
        lines.append(
            f"| {row.get('control_type')} | {row.get('scored_trials')} | "
            f"{row.get('asr_eligible_scored_trials')} | "
            f"{row.get('n_minus_1_trials') if row.get('n_minus_1_trials') is not None else 'n/a'} | "
            f"{row.get('accounted_terminal_trials') if row.get('accounted_terminal_trials') is not None else 'n/a'} | "
            f"{row.get('protocol_denominator_trials') if row.get('protocol_denominator_trials') is not None else 'n/a'} | "
            f"{pct(row.get('protocol_completion_rate')) if row.get('protocol_completion_rate') is not None else 'n/a'} | "
            f"{pct(row.get('model_nonconformance_rate')) if row.get('model_nonconformance_rate') is not None else 'n/a'} | "
            f"{row.get('attack_success_trials')} ({pct_or_na(row.get('attack_success_rate'))}) | "
            f"{pct(row.get('end_to_end_violation_rate')) if row.get('end_to_end_violation_rate') is not None else 'n/a'} | "
            f"{row.get('confirmed_trials')} ({pct_or_na(row.get('confirmed_rate'))}) | "
            f"{row.get('timeout_trials')} |"
        )
    lines += [
        "",
        "## Public Artifact Boundary",
        "",
        analysis.get("sources", {}).get("public_artifact_boundary", ""),
        "",
        "## Sources",
        "",
    ]
    for path in analysis.get("sources", {}).get("attack_report_dirs", []):
        lines.append(f"- attack_report_dir: `{path}`")
    for path in analysis.get("sources", {}).get("control_report_dirs", []):
        lines.append(f"- control_report_dir: `{path}`")
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attack-label", action="append", default=[], help="Attack report label under runs/_reports.")
    parser.add_argument("--control-label", action="append", default=[], help="Control report label under runs/_reports.")
    parser.add_argument("--attack-report-dir", action="append", default=[], help="Explicit attack report directory.")
    parser.add_argument("--control-report-dir", action="append", default=[], help="Explicit control report directory.")
    parser.add_argument("--baseline-runtime", default="Claude Code")
    parser.add_argument("--baseline-model", default="Kimi K2.6")
    parser.add_argument("--baseline-harness", default="")
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
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
    analysis = build_analysis(
        attack_dirs=attack_dirs,
        control_dirs=control_dirs,
        baseline_runtime=args.baseline_runtime,
        baseline_model=args.baseline_model,
        baseline_harness=args.baseline_harness,
    )
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(analysis, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(analysis), encoding="utf-8")
    print(f"wrote {out_json}")
    print(f"wrote {out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
