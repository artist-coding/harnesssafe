"""Generate paper supplementary appendix artifacts from checked reports."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    from infra.check_paper_results import is_scored_row, is_terminal_model_protocol_row
except ModuleNotFoundError:  # direct `python infra/generate_paper_appendix.py`
    from check_paper_results import (  # type: ignore
        is_scored_row,
        is_terminal_model_protocol_row,
    )


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ATTACK_LABEL = "paper_core_20260625"
DEFAULT_CONTROL_LABEL = "paper_controls_core_20260625"
DEFAULT_BENCHMARK_CARD = Path("docs/generated_artifacts/benchmark_card.json")
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/paper_supplementary_appendix.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/paper_supplementary_appendix.md")
DEFAULT_OUT_TEX = Path("docs/generated_artifacts/paper_supplementary_appendix.tex")


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


def one_decimal_or_na(value: Any) -> str:
    parsed = optional_float(value)
    return "n/a" if parsed is None else f"{parsed:.1f}"


def ratio_or_none(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def count_fraction_or_na(numerator: Any, denominator: Any) -> str:
    if denominator in (None, "") or as_int(denominator) == 0:
        return "n/a"
    return f"{as_int(numerator)}/{as_int(denominator)}"


def row_is_n_minus_one(row: dict[str, Any]) -> bool:
    return is_terminal_model_protocol_row(row)


def protocol_metrics_available(row: dict[str, Any]) -> bool:
    return all(
        key in row and row.get(key) not in (None, "")
        for key in (
            "asr_eligible_trials",
            "n_minus_1_trials",
            "accounted_terminal_trials",
            "protocol_denominator_trials",
        )
    )


def normalize_protocol_macro(row: dict[str, Any], *, context: str) -> dict[str, Any]:
    """Return a macro row whose published rates are derived from S/M/T/D.

    Legacy rows without the four auditable protocol counts remain renderable,
    but every protocol-dependent rate is unavailable.  New-contract rows fail
    closed when coverage accounting (T) or the measurement denominator (D)
    disagrees with its definition.
    """

    out = dict(row)
    all_scored = as_int(row.get("completed_trials"))
    successes = as_int(row.get("attack_success_trials"))
    if not protocol_metrics_available(row):
        out.update(
            {
                "asr_eligible_scored_trials": None,
                "n_minus_1_trials": None,
                "accounted_terminal_trials": None,
                "protocol_denominator_trials": None,
                "protocol_completion_trial_rate": None,
                "model_nonconformance_trial_rate": None,
                "attack_success_trial_rate": None,
                "end_to_end_attack_trial_rate": None,
            }
        )
        return out

    asr_eligible = as_int(row.get("asr_eligible_trials"))
    n_minus_one = as_int(row.get("n_minus_1_trials"))
    accounted_terminal = as_int(row.get("accounted_terminal_trials"))
    protocol_denominator = as_int(row.get("protocol_denominator_trials"))
    counts = (all_scored, asr_eligible, n_minus_one, accounted_terminal, protocol_denominator, successes)
    if any(count < 0 for count in counts):
        raise ValueError(f"{context}: protocol counts must be non-negative")
    if asr_eligible > all_scored:
        raise ValueError(f"{context}: S cannot exceed all scored rows")
    if accounted_terminal != all_scored + n_minus_one:
        raise ValueError(f"{context}: T must equal all scored rows plus M")
    if protocol_denominator != asr_eligible + n_minus_one:
        raise ValueError(f"{context}: D must equal S plus M")
    if successes > asr_eligible:
        raise ValueError(f"{context}: A cannot exceed S")

    out.update(
        {
            "asr_eligible_scored_trials": asr_eligible,
            "n_minus_1_trials": n_minus_one,
            "accounted_terminal_trials": accounted_terminal,
            "protocol_denominator_trials": protocol_denominator,
            "protocol_completion_trial_rate": ratio_or_none(asr_eligible, protocol_denominator),
            "model_nonconformance_trial_rate": ratio_or_none(n_minus_one, protocol_denominator),
            "attack_success_trial_rate": ratio_or_none(successes, asr_eligible),
            "end_to_end_attack_trial_rate": ratio_or_none(successes, protocol_denominator),
        }
    )
    return out


def tex_escape(value: Any) -> str:
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in text)


def first_harness_macro(summary: dict[str, Any], *, run_kind: str = "", control_type: str = "") -> dict[str, Any]:
    for row in summary.get("harness_macro", []):
        if not isinstance(row, dict):
            continue
        if run_kind and row.get("run_kind") != run_kind:
            continue
        if control_type and row.get("control_type") != control_type:
            continue
        return row
    rows = summary.get("harness_macro", [])
    return rows[0] if rows and isinstance(rows[0], dict) else {}


def progress_distribution(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {node: 0 for node in ["N0", "N1", "N2", "N3", "N4", "N5a", "N5b"]}
    for row in rows:
        # N-1 keeps diagnostic progress separately; it is not an eighth ladder
        # node and must not be folded into N0-N5b paper counts.
        if row_is_n_minus_one(row) or not is_scored_row(row):
            continue
        has_current_eligibility_contract = any(
            key in row
            for key in (
                "result_class",
                "asr_eligible",
                "attack_success_metric_excluded",
            )
        )
        if has_current_eligibility_contract and (
            not row.get("asr_eligible")
            or row.get("attack_success_metric_excluded")
        ):
            # ASR-ineligible scored rows remain visible in coverage T only.
            continue
        node = str(row.get("progress_node") or row.get("max_progress_node") or "")
        if node == "N5":  # pre-2.1 compatibility
            node = "N5b"
        if node in counts:
            counts[node] += 1
    return counts


def control_type_rows(control_summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for summary in control_summaries:
        for macro in summary.get("harness_macro", []):
            if not isinstance(macro, dict) or not macro.get("control_type"):
                continue
            control_type = str(macro.get("control_type"))
            macro = normalize_protocol_macro(
                macro,
                context=f"control macro {control_type}",
            )
            matching = [
                row
                for row in summary.get("rows", [])
                if isinstance(row, dict) and str(row.get("control_type") or "") == control_type
            ]
            progress = progress_distribution(matching)
            protocol_available = protocol_metrics_available(macro)
            rows.append(
                {
                    "control_type": control_type,
                    "rows": as_int(macro.get("completed_trials")),
                    "scored_trials": as_int(macro.get("completed_trials")),
                    "asr_eligible_scored_trials": (
                        as_int(macro.get("asr_eligible_scored_trials"))
                        if protocol_available
                        else None
                    ),
                    "n_minus_1_trials": (
                        as_int(macro.get("n_minus_1_trials"))
                        if protocol_available
                        else None
                    ),
                    "accounted_terminal_trials": (
                        as_int(macro.get("accounted_terminal_trials"))
                        if protocol_available
                        else None
                    ),
                    "protocol_denominator_trials": (
                        as_int(macro.get("protocol_denominator_trials"))
                        if protocol_available
                        else None
                    ),
                    "protocol_completion_rate": (
                        optional_float(macro.get("protocol_completion_trial_rate"))
                        if protocol_available
                        else None
                    ),
                    "model_nonconformance_rate": (
                        optional_float(macro.get("model_nonconformance_trial_rate"))
                        if protocol_available
                        else None
                    ),
                    "conditional_violation_rate": optional_float(
                        macro.get("attack_success_trial_rate")
                    ),
                    "end_to_end_violation_rate": (
                        optional_float(macro.get("end_to_end_attack_trial_rate"))
                        if protocol_available
                        else None
                    ),
                    "attack_success": as_int(macro.get("attack_success_trials")),
                    "confirmed": as_int(macro.get("confirmed_trials")),
                    "timeouts": as_int(macro.get("timeout_trials")),
                    "n0": progress["N0"],
                    "n1": progress["N1"],
                    "n2": progress["N2"],
                    "n3": progress["N3"],
                    "n4": progress["N4"],
                    "n5a": progress["N5a"],
                    "n5b": progress["N5b"],
                }
            )
    return rows


def successful_cases(attack_summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        {
            **row,
            "asr_eligible_scored_trials": (
                as_int(row.get("asr_eligible_trials"))
                if row.get("asr_eligible_trials") not in (None, "")
                else None
            ),
        }
        for row in attack_summary.get("case_summary", [])
        if isinstance(row, dict)
        and (as_int(row.get("attack_success_trials")) > 0 or as_int(row.get("confirmed_trials")) > 0)
    ]
    for row in rows:
        denominator = row.get("asr_eligible_scored_trials")
        if denominator is not None and (
            as_int(row.get("attack_success_trials")) > as_int(denominator)
            or as_int(row.get("confirmed_trials")) > as_int(denominator)
        ):
            raise ValueError(f"case summary {row.get('case_dir', '')}: success counts cannot exceed S")
    return sorted(
        rows,
        key=lambda row: (
            -as_int(row.get("confirmed_trials")),
            -as_int(row.get("attack_success_trials")),
            str(row.get("suite") or ""),
            str(row.get("paper_family") or ""),
            str(row.get("case_dir") or ""),
        ),
    )


def case_study_route_by_case(case_evidence: dict[str, Any]) -> dict[str, str]:
    routes: dict[str, str] = {}
    for item in case_evidence.get("cases", []):
        if not isinstance(item, dict):
            continue
        case_dir = str(item.get("case_dir") or "")
        if not case_dir:
            continue
        routes[case_dir] = "main_paper" if item.get("recommended_main_paper") else "appendix"
    return routes


def annotate_case_routes(rows: list[dict[str, Any]], case_evidence: dict[str, Any]) -> list[dict[str, Any]]:
    routes = case_study_route_by_case(case_evidence)
    annotated: list[dict[str, Any]] = []
    for row in rows:
        case_dir = str(row.get("case_dir") or "")
        route = routes.get(case_dir, "appendix")
        annotated.append({**row, "case_study_route": route, "recommended_main_paper": route == "main_paper"})
    return annotated


def family_rows(attack_summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        normalize_protocol_macro(
            row,
            context=(
                f"family macro {row.get('suite', '')}/{row.get('paper_family', '')}"
            ),
        )
        for row in attack_summary.get("family_macro", [])
        if isinstance(row, dict)
    ]
    return sorted(rows, key=lambda row: (str(row.get("suite") or ""), str(row.get("paper_family") or "")))


def load_control_summaries(dirs: list[Path]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for directory in dirs:
        path = directory / "summary.json"
        if path.is_file():
            summaries.append(load_json(path))
    return summaries


def load_case_evidence(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    payload_path = path / "case_study_evidence.json"
    if payload_path.is_file():
        return load_json(payload_path)
    return {}


def build_appendix(
    *,
    attack_dirs: list[Path],
    control_dirs: list[Path],
    case_evidence_dir: Path | None,
    benchmark_card_path: Path,
    root: Path = ROOT,
) -> dict[str, Any]:
    if not attack_dirs:
        attack_dirs = resolve_report_dirs(labels=[DEFAULT_ATTACK_LABEL], paths=[], root=root)
    if not control_dirs:
        control_dirs = resolve_report_dirs(labels=[DEFAULT_CONTROL_LABEL], paths=[], root=root)
    attack_summary_path = attack_dirs[0] / "summary.json"
    if not attack_summary_path.is_file():
        raise FileNotFoundError(f"missing attack summary: {attack_summary_path}")
    attack_summary = load_json(attack_summary_path)
    control_summaries = load_control_summaries(control_dirs)
    if not control_summaries:
        raise FileNotFoundError("no control summary.json found")

    benchmark_path = benchmark_card_path if benchmark_card_path.is_absolute() else root / benchmark_card_path
    benchmark_card = load_json(benchmark_path) if benchmark_path.is_file() else {}
    case_evidence = load_case_evidence(case_evidence_dir)
    attack_macro = normalize_protocol_macro(
        first_harness_macro(attack_summary, run_kind="attack"),
        context="attack harness macro",
    )
    all_control_rows = control_type_rows(control_summaries)
    attack_protocol_available = protocol_metrics_available(attack_macro)
    attack_rows = (
        as_int(attack_macro.get("completed_trials"))
        if "completed_trials" in attack_macro
        else len(attack_summary.get("rows", []))
    )
    control_rows = sum(row["rows"] for row in all_control_rows)
    control_protocol_available = bool(all_control_rows) and all(
        row.get("protocol_denominator_trials") is not None
        for row in all_control_rows
    )
    control_asr_eligible = (
        sum(as_int(row.get("asr_eligible_scored_trials")) for row in all_control_rows)
        if control_protocol_available
        else None
    )
    control_n_minus_one = (
        sum(as_int(row.get("n_minus_1_trials")) for row in all_control_rows)
        if control_protocol_available
        else None
    )
    control_accounted = (
        sum(as_int(row.get("accounted_terminal_trials")) for row in all_control_rows)
        if control_protocol_available
        else None
    )
    control_protocol_denominator = (
        sum(as_int(row.get("protocol_denominator_trials")) for row in all_control_rows)
        if control_protocol_available
        else None
    )
    successful = annotate_case_routes(successful_cases(attack_summary), case_evidence)
    families = family_rows(attack_summary)
    main_paper_successful = sum(1 for row in successful if row.get("recommended_main_paper"))
    attack_progress = progress_distribution(
        [row for row in attack_summary.get("rows", []) if isinstance(row, dict)]
    )
    if attack_protocol_available and sum(attack_progress.values()) != as_int(
        attack_macro.get("asr_eligible_scored_trials")
    ):
        raise ValueError(
            "attack progress distribution must contain exactly the ASR-eligible scored rows S"
        )

    return {
        "schema_version": 2,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "metric_contract": {
            "n_minus_one_is_progress_node": False,
            "S": "ASR-eligible N0-N5b scored rows",
            "M": "strict terminal N-1 model-protocol deviations",
            "T": "all N0-N5b scored rows plus M (coverage accounting)",
            "D": "S plus M (protocol measurement denominator)",
            "conditional_asr_denominator": "ASR-eligible N0-N5b scored attack rows",
            "protocol_completion_rate": "S/D",
            "model_nonconformance_rate": "M/D",
            "conditional_asr": "A/S",
            "end_to_end_attack_rate": "A/D",
            "end_to_end_denominator": "ASR-eligible scored attack rows plus N-1 attack rows",
        },
        "sources": {
            "attack_reports": [relpath(path, root) for path in attack_dirs],
            "control_reports": [relpath(path, root) for path in control_dirs],
            "case_evidence_dir": relpath(case_evidence_dir, root) if case_evidence_dir else "",
            "benchmark_card": relpath(benchmark_path, root),
        },
        "baseline": benchmark_card.get(
            "current_baseline",
            {"runtime": "Claude Code", "model": "Kimi K2.6", "harness": "claude"},
        ),
        "matrix": {
            "case_set": attack_summary.get("case_set", "core"),
            "attack_rows": attack_rows,
            "attack_scored_rows": attack_rows,
            "attack_asr_eligible_scored_rows": (
                as_int(attack_macro.get("asr_eligible_scored_trials"))
                if attack_protocol_available
                else None
            ),
            "attack_n_minus_1_rows": (
                as_int(attack_macro.get("n_minus_1_trials"))
                if attack_protocol_available
                else None
            ),
            "attack_accounted_terminal_rows": (
                as_int(attack_macro.get("accounted_terminal_trials"))
                if attack_protocol_available
                else None
            ),
            "attack_protocol_denominator_rows": (
                as_int(attack_macro.get("protocol_denominator_trials"))
                if attack_protocol_available
                else None
            ),
            "control_rows": control_rows,
            "control_scored_rows": control_rows,
            "control_asr_eligible_scored_rows": control_asr_eligible,
            "control_n_minus_1_rows": control_n_minus_one,
            "control_accounted_terminal_rows": control_accounted,
            "control_protocol_denominator_rows": control_protocol_denominator,
            "total_rows": attack_rows + control_rows,
            "attack_success_rows": as_int(attack_macro.get("attack_success_trials")),
            "confirmed_rows": as_int(attack_macro.get("confirmed_trials")),
            "attack_timeouts": as_int(attack_macro.get("timeout_trials")),
            "protocol_completion_rate": (
                optional_float(attack_macro.get("protocol_completion_trial_rate"))
                if attack_protocol_available
                else None
            ),
            "model_nonconformance_rate": (
                optional_float(attack_macro.get("model_nonconformance_trial_rate"))
                if attack_protocol_available
                else None
            ),
            "pooled_asr": optional_float(attack_macro.get("attack_success_trial_rate")),
            "conditional_asr": optional_float(attack_macro.get("attack_success_trial_rate")),
            "end_to_end_attack_rate": (
                optional_float(attack_macro.get("end_to_end_attack_trial_rate"))
                if attack_protocol_available
                else None
            ),
            "family_macro_asr": optional_float(
                attack_macro.get("family_macro_attack_success")
            ),
            "family_macro_end_to_end": (
                optional_float(attack_macro.get("family_macro_end_to_end_attack"))
                if attack_protocol_available
                else None
            ),
            "family_macro_confirmed": optional_float(
                attack_macro.get("family_macro_confirmed")
            ),
            # Risk is a safety metric over S.  An empty eligible set has no
            # numeric mean; keep JSON null and render it as n/a.
            "mean_risk": optional_float(attack_macro.get("family_macro_risk")),
        },
        "attack_progress": attack_progress,
        "controls": all_control_rows,
        "families": families,
        "successful_cases": successful,
        "case_evidence": {
            "case_count": as_int(case_evidence.get("case_count")),
            "attack_row_count": as_int(case_evidence.get("attack_row_count")),
            "recommended_main_paper_count": as_int(case_evidence.get("recommended_main_paper_count")),
            "appendix_only_case_count": max(len(successful) - main_paper_successful, 0),
        },
    }


def render_markdown(appendix: dict[str, Any]) -> str:
    baseline = appendix["baseline"]
    matrix = appendix["matrix"]
    lines = [
        "# Safety Bench Supplementary Appendix",
        "",
        f"- generated_at: `{appendix['generated_at']}`",
        f"- baseline: `{baseline.get('runtime', 'Claude Code')} + {baseline.get('model', 'Kimi K2.6')}`",
        f"- harness: `{baseline.get('harness', 'claude')}`",
        f"- case_set: `{matrix['case_set']}`",
        "",
        "Measurement contract: `S` = ASR-eligible N0-N5b scored rows; `M` = strict terminal N-1 rows; "
        "`T` = all N0-N5b scored rows + M (coverage); `D` = S + M (protocol metrics). "
        "Rates are S/D, M/D, A/S, and A/D.",
        "",
        "## Matrix Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| All scored attack rows | {matrix['attack_scored_rows']} |",
        f"| Attack ASR-eligible scored rows (S) | {matrix['attack_asr_eligible_scored_rows'] if matrix['attack_asr_eligible_scored_rows'] is not None else 'n/a'} |",
        f"| Attack N-1 rows | {matrix['attack_n_minus_1_rows'] if matrix['attack_n_minus_1_rows'] is not None else 'n/a'} |",
        f"| Attack coverage-accounted rows (T) | {matrix['attack_accounted_terminal_rows'] if matrix['attack_accounted_terminal_rows'] is not None else 'n/a'} |",
        f"| Attack protocol denominator (D=S+M) | {matrix['attack_protocol_denominator_rows'] if matrix['attack_protocol_denominator_rows'] is not None else 'n/a'} |",
        f"| All scored control rows | {matrix['control_scored_rows']} |",
        f"| Control ASR-eligible scored rows (S) | {matrix['control_asr_eligible_scored_rows'] if matrix['control_asr_eligible_scored_rows'] is not None else 'n/a'} |",
        f"| Control N-1 rows | {matrix['control_n_minus_1_rows'] if matrix['control_n_minus_1_rows'] is not None else 'n/a'} |",
        f"| Control coverage-accounted rows (T) | {matrix['control_accounted_terminal_rows'] if matrix['control_accounted_terminal_rows'] is not None else 'n/a'} |",
        f"| Control protocol denominator (D=S+M) | {matrix['control_protocol_denominator_rows'] if matrix['control_protocol_denominator_rows'] is not None else 'n/a'} |",
        f"| All scored total rows | {matrix['total_rows']} |",
        f"| Attack success rows | {matrix['attack_success_rows']} |",
        f"| Confirmed rows | {matrix['confirmed_rows']} |",
        f"| Attack timeouts | {matrix['attack_timeouts']} |",
        f"| Protocol completion rate | {pct_or_na(matrix['protocol_completion_rate'])} |",
        f"| Model nonconformance rate | {pct_or_na(matrix['model_nonconformance_rate'])} |",
        f"| Conditional ASR | {pct_or_na(matrix['conditional_asr'])} |",
        f"| End-to-end attack rate | {pct_or_na(matrix['end_to_end_attack_rate'])} |",
        f"| Family macro conditional ASR | {pct_or_na(matrix['family_macro_asr'])} |",
        f"| Family macro end-to-end attack rate | {pct_or_na(matrix['family_macro_end_to_end'])} |",
        f"| Family macro confirmed | {pct_or_na(matrix['family_macro_confirmed'])} |",
        f"| Mean risk | {one_decimal_or_na(matrix['mean_risk'])} |",
        "",
        "## Attack Progress Distribution",
        "",
        "| Node | Rows |",
        "| --- | ---: |",
    ]
    for node, count in appendix["attack_progress"].items():
        lines.append(f"| {node} | {count} |")
    lines += [
        "",
        "## Control Summary",
        "",
        "| Control | All Scored | S | M | T | D | Protocol completion (S/D) | Model nonconformance (M/D) | Conditional violation (A/S) | End-to-end violation (A/D) | Confirmed | Timeouts | N0 | N1 | N2 | N3 | N4 | N5a | N5b |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in appendix["controls"]:
        lines.append(
            f"| {row['control_type']} | {row['scored_trials']} | "
            f"{row['asr_eligible_scored_trials'] if row['asr_eligible_scored_trials'] is not None else 'n/a'} | "
            f"{row['n_minus_1_trials'] if row['n_minus_1_trials'] is not None else 'n/a'} | "
            f"{row['accounted_terminal_trials'] if row['accounted_terminal_trials'] is not None else 'n/a'} | "
            f"{row['protocol_denominator_trials'] if row['protocol_denominator_trials'] is not None else 'n/a'} | "
            f"{pct_or_na(row['protocol_completion_rate'])} | "
            f"{pct_or_na(row['model_nonconformance_rate'])} | "
            f"{pct_or_na(row['conditional_violation_rate'])} | "
            f"{pct_or_na(row['end_to_end_violation_rate'])} | {row['confirmed']} | "
            f"{row['timeouts']} | {row['n0']} | {row['n1']} | {row['n2']} | {row['n3']} | {row['n4']} | {row['n5a']} | {row['n5b']} |"
        )
    lines += [
        "",
        "## Family-Level Results",
        "",
        "| Suite | Family | Scored Cases | All Scored | S | M | T | D | Protocol completion (S/D) | Model nonconformance (M/D) | Conditional ASR (A/S) | End-to-end attack (A/D) | Case Mean Conditional ASR | Case Mean End-to-End | Case Mean Confirmed | Risk |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in appendix["families"]:
        lines.append(
            f"| {row.get('suite', '')} | {row.get('paper_family', '')} | "
            f"{as_int(row.get('complete_cases'))}/{as_int(row.get('cases'))} | "
            f"{as_int(row.get('completed_trials'))} | "
            f"{as_int(row.get('asr_eligible_scored_trials')) if row.get('asr_eligible_scored_trials') is not None else 'n/a'} | "
            f"{as_int(row.get('n_minus_1_trials')) if row.get('n_minus_1_trials') is not None else 'n/a'} | "
            f"{as_int(row.get('accounted_terminal_trials')) if row.get('accounted_terminal_trials') is not None else 'n/a'} | "
            f"{as_int(row.get('protocol_denominator_trials')) if row.get('protocol_denominator_trials') is not None else 'n/a'} | "
            f"{pct_or_na(row.get('protocol_completion_trial_rate'))} | "
            f"{pct_or_na(row.get('model_nonconformance_trial_rate'))} | "
            f"{pct_or_na(row.get('attack_success_trial_rate'))} | "
            f"{pct_or_na(row.get('end_to_end_attack_trial_rate'))} | "
            f"{pct_or_na(row.get('attack_success_case_mean'))} | "
            f"{pct_or_na(row.get('end_to_end_attack_case_mean'))} | "
            f"{pct_or_na(row.get('confirmed_case_mean'))} | "
            f"{one_decimal_or_na(row.get('avg_risk_case_mean'))} |"
        )
    lines += [
        "",
        "## Successful Or Confirmed Cases",
        "",
        "| Suite | Family | Case | Main Paper | Success (A/S) | Confirmed (C/S) | Max Node | Risk |",
        "| --- | --- | --- | --- | ---: | ---: | --- | ---: |",
    ]
    for row in appendix["successful_cases"]:
        main_paper = "yes" if row.get("recommended_main_paper") else "appendix"
        lines.append(
            f"| {row.get('suite', '')} | {row.get('paper_family', '')} | `{row.get('case_dir', '')}` | "
            f"{main_paper} | "
            f"{count_fraction_or_na(row.get('attack_success_trials'), row.get('asr_eligible_scored_trials'))} | "
            f"{count_fraction_or_na(row.get('confirmed_trials'), row.get('asr_eligible_scored_trials'))} | "
            f"{row.get('max_progress_node', '')} | {one_decimal_or_na(row.get('avg_risk'))} |"
        )
    evidence = appendix["case_evidence"]
    lines += [
        "",
        "## Case-Study Evidence Pack",
        "",
        f"- cases: `{evidence['case_count']}`",
        f"- attack_rows: `{evidence['attack_row_count']}`",
        f"- recommended_main_paper_cases: `{evidence['recommended_main_paper_count']}`",
        f"- appendix_only_successful_cases: `{evidence['appendix_only_case_count']}`",
        "",
        "## Public Artifact Boundary",
        "",
        "- The public bundle includes sanitized reports, tables, benchmark card, appendix, hashes, and reproduction commands.",
        "- It excludes raw traces, honeypots, oracle payloads, agent homes, deployment canaries, and provider secrets.",
        "",
        "## Sources",
        "",
        f"- attack_reports: `{', '.join(appendix['sources']['attack_reports'])}`",
        f"- control_reports: `{', '.join(appendix['sources']['control_reports'])}`",
        f"- case_evidence_dir: `{appendix['sources']['case_evidence_dir']}`",
        f"- benchmark_card: `{appendix['sources']['benchmark_card']}`",
    ]
    return "\n".join(lines) + "\n"


def render_tex(appendix: dict[str, Any]) -> str:
    matrix = appendix["matrix"]
    lines = [
        r"\section{Safety Bench Supplementary Appendix}",
        "",
        (
            r"\paragraph{Measurement contract.} $S$ is the ASR-eligible N0--N5b scored set, "
            r"$M$ is strict terminal N-1, $T$ is all scored rows plus $M$ for coverage, "
            r"and $D=S+M$. The four rates are $S/D$, $M/D$, $A/S$, and $A/D$."
        ),
        "",
        r"\subsection{Matrix Summary}",
        r"\begin{tabular}{lr}",
        r"\toprule",
        r"Metric & Value \\",
        r"\midrule",
    ]
    for label, value in [
        ("All scored attack rows", matrix["attack_scored_rows"]),
        ("Attack ASR-eligible scored rows (S)", matrix["attack_asr_eligible_scored_rows"] if matrix["attack_asr_eligible_scored_rows"] is not None else "n/a"),
        ("Attack N-1 rows", matrix["attack_n_minus_1_rows"] if matrix["attack_n_minus_1_rows"] is not None else "n/a"),
        ("Attack coverage-accounted rows (T)", matrix["attack_accounted_terminal_rows"] if matrix["attack_accounted_terminal_rows"] is not None else "n/a"),
        ("Attack protocol denominator (D)", matrix["attack_protocol_denominator_rows"] if matrix["attack_protocol_denominator_rows"] is not None else "n/a"),
        ("All scored control rows", matrix["control_scored_rows"]),
        ("Control ASR-eligible scored rows (S)", matrix["control_asr_eligible_scored_rows"] if matrix["control_asr_eligible_scored_rows"] is not None else "n/a"),
        ("Control N-1 rows", matrix["control_n_minus_1_rows"] if matrix["control_n_minus_1_rows"] is not None else "n/a"),
        ("Control coverage-accounted rows (T)", matrix["control_accounted_terminal_rows"] if matrix["control_accounted_terminal_rows"] is not None else "n/a"),
        ("Control protocol denominator (D)", matrix["control_protocol_denominator_rows"] if matrix["control_protocol_denominator_rows"] is not None else "n/a"),
        ("Attack success rows", matrix["attack_success_rows"]),
        ("Confirmed rows", matrix["confirmed_rows"]),
        ("Protocol completion", pct_or_na(matrix["protocol_completion_rate"])),
        ("Model nonconformance", pct_or_na(matrix["model_nonconformance_rate"])),
        ("Conditional ASR", pct_or_na(matrix["conditional_asr"])),
        ("End-to-end attack", pct_or_na(matrix["end_to_end_attack_rate"])),
        ("Family macro conditional ASR", pct_or_na(matrix["family_macro_asr"])),
        ("Family macro end-to-end", pct_or_na(matrix["family_macro_end_to_end"])),
        ("Mean risk", one_decimal_or_na(matrix["mean_risk"])),
    ]:
        lines.append(f"{tex_escape(label)} & {tex_escape(value)}" + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", "", r"\subsection{Control Summary}"]
    lines += [
        r"\begin{tabular}{lrrrrrrrrrrr}",
        r"\toprule",
        r"Control & All & S & M & T & D & S/D & M/D & A/S & A/D & Confirmed & Timeout \\",
        r"\midrule",
    ]
    for row in appendix["controls"]:
        lines.append(
            f"{tex_escape(row['control_type'])} & {row['scored_trials']} & "
            f"{tex_escape(row['asr_eligible_scored_trials'] if row['asr_eligible_scored_trials'] is not None else 'n/a')} & "
            f"{tex_escape(row['n_minus_1_trials'] if row['n_minus_1_trials'] is not None else 'n/a')} & "
            f"{tex_escape(row['accounted_terminal_trials'] if row['accounted_terminal_trials'] is not None else 'n/a')} & "
            f"{tex_escape(row['protocol_denominator_trials'] if row['protocol_denominator_trials'] is not None else 'n/a')} & "
            f"{tex_escape(pct_or_na(row['protocol_completion_rate']))} & "
            f"{tex_escape(pct_or_na(row['model_nonconformance_rate']))} & "
            f"{tex_escape(pct_or_na(row['conditional_violation_rate']))} & "
            f"{tex_escape(pct_or_na(row['end_to_end_violation_rate']))} & "
            f"{row['confirmed']} & {row['timeouts']} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}", "", r"\subsection{Family-Level Results}"]
    lines += [
        r"\begin{tabular}{lllrrrrrrrrrrrrr}",
        r"\toprule",
        r"Suite & Family & Cases & All & S & M & T & D & S/D & M/D & A/S & A/D & Case ASR & Case E2E & Confirmed & Risk \\",
        r"\midrule",
    ]
    for row in appendix["families"]:
        lines.append(
            f"{tex_escape(row.get('suite', ''))} & {tex_escape(row.get('paper_family', ''))} & "
            f"{as_int(row.get('complete_cases'))}/{as_int(row.get('cases'))} & "
            f"{as_int(row.get('completed_trials'))} & "
            f"{tex_escape(as_int(row.get('asr_eligible_scored_trials')) if row.get('asr_eligible_scored_trials') is not None else 'n/a')} & "
            f"{tex_escape(as_int(row.get('n_minus_1_trials')) if row.get('n_minus_1_trials') is not None else 'n/a')} & "
            f"{tex_escape(as_int(row.get('accounted_terminal_trials')) if row.get('accounted_terminal_trials') is not None else 'n/a')} & "
            f"{tex_escape(as_int(row.get('protocol_denominator_trials')) if row.get('protocol_denominator_trials') is not None else 'n/a')} & "
            f"{tex_escape(pct_or_na(row.get('protocol_completion_trial_rate')))} & "
            f"{tex_escape(pct_or_na(row.get('model_nonconformance_trial_rate')))} & "
            f"{tex_escape(pct_or_na(row.get('attack_success_trial_rate')))} & "
            f"{tex_escape(pct_or_na(row.get('end_to_end_attack_trial_rate')))} & "
            f"{tex_escape(pct_or_na(row.get('attack_success_case_mean')))} & "
            f"{tex_escape(pct_or_na(row.get('end_to_end_attack_case_mean')))} & "
            f"{tex_escape(pct_or_na(row.get('confirmed_case_mean')))} & "
            f"{one_decimal_or_na(row.get('avg_risk_case_mean'))} \\\\"
        )
    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        "",
        r"\subsection{Successful Or Confirmed Cases}",
        r"\begin{tabular}{lllllrr}",
        r"\toprule",
        r"Suite & Family & Case & Main & Success (A/S) & Confirmed (C/S) & Risk \\",
        r"\midrule",
    ]
    for row in appendix["successful_cases"]:
        main_paper = "yes" if row.get("recommended_main_paper") else "appendix"
        lines.append(
            f"{tex_escape(row.get('suite', ''))} & {tex_escape(row.get('paper_family', ''))} & "
            f"{tex_escape(row.get('case_dir', ''))} & {tex_escape(main_paper)} & "
            f"{tex_escape(count_fraction_or_na(row.get('attack_success_trials'), row.get('asr_eligible_scored_trials')))} & "
            f"{tex_escape(count_fraction_or_na(row.get('confirmed_trials'), row.get('asr_eligible_scored_trials')))} & "
            f"{one_decimal_or_na(row.get('avg_risk'))} \\\\"
        )
    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        "",
        r"\subsection{Public Artifact Boundary}",
        (
            "The public bundle includes sanitized reports, tables, benchmark card, appendix, hashes, "
            "and reproduction commands. It excludes raw traces, honeypots, oracle payloads, "
            "agent homes, deployment canaries, and provider secrets."
        ),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Safety Bench supplementary appendix artifacts.")
    parser.add_argument("--attack-label", action="append", default=[])
    parser.add_argument("--attack-report-dir", action="append", default=[])
    parser.add_argument("--control-label", action="append", default=[])
    parser.add_argument("--control-report-dir", action="append", default=[])
    parser.add_argument("--case-evidence-dir", default="")
    parser.add_argument("--benchmark-card", default=str(DEFAULT_BENCHMARK_CARD))
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    parser.add_argument("--out-tex", default=str(DEFAULT_OUT_TEX))
    args = parser.parse_args()

    appendix = build_appendix(
        attack_dirs=resolve_report_dirs(
            labels=args.attack_label,
            paths=args.attack_report_dir,
            default_label=DEFAULT_ATTACK_LABEL,
        ),
        control_dirs=resolve_report_dirs(
            labels=args.control_label,
            paths=args.control_report_dir,
            default_label=DEFAULT_CONTROL_LABEL,
        ),
        case_evidence_dir=Path(args.case_evidence_dir) if args.case_evidence_dir else None,
        benchmark_card_path=Path(args.benchmark_card),
    )
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_tex = Path(args.out_tex)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_tex.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(appendix, indent=2, ensure_ascii=False), encoding="utf-8")
    out_md.write_text(render_markdown(appendix), encoding="utf-8")
    out_tex.write_text(render_tex(appendix), encoding="utf-8")
    print(out_json)
    print(out_md)
    print(out_tex)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
