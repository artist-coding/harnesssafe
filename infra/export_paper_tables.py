"""Export paper-ready tables from Safety Bench report artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"

PROTOCOL_METRIC_FIELDS = (
    "asr_eligible_trials",
    "n_minus_1_trials",
    "accounted_terminal_trials",
    "protocol_denominator_trials",
    "attack_success_trials",
)


def safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return slug.strip("._") or "paper_tables"


def report_dir_from(label: str = "", path: str = "") -> Path:
    if path:
        return Path(path)
    if not label:
        raise SystemExit("provide --attack-label/--control-label or an explicit report dir")
    return RUNS / "_reports" / safe_slug(label)


def split_cli_values(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            token = part.strip()
            if token:
                out.append(token)
    return out


def report_dirs_from(labels: Iterable[str] | None = None, paths: Iterable[str] | None = None) -> list[Path]:
    dirs = [Path(path) for path in split_cli_values(paths)]
    dirs.extend(RUNS / "_reports" / safe_slug(label) for label in split_cli_values(labels))
    return dirs


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def pct(value: str | float | None) -> str:
    if value in (None, ""):
        return "n/a"
    try:
        return f"{100 * float(value):.1f}%"
    except (TypeError, ValueError):
        return "n/a"


def ci(row: dict[str, str], prefix: str) -> str:
    low = pct(row.get(f"{prefix}_ci_low"))
    high = pct(row.get(f"{prefix}_ci_high"))
    if low == "n/a" or high == "n/a":
        return "n/a"
    return f"{low}-{high}"


def value(row: dict[str, str], key: str, default: str = "0") -> str:
    raw = row.get(key)
    return default if raw in (None, "") else str(raw)


def has_protocol_metrics(row: dict[str, str]) -> bool:
    """Return whether a macro row was produced under the N-1-aware contract.

    Legacy report CSVs do not contain enough information to prove that the
    absence of an N-1 row means zero model nonconformance.  Treat those fields
    as unavailable instead of silently reporting a perfect completion rate.
    """

    return all(field in row and row.get(field) not in (None, "") for field in PROTOCOL_METRIC_FIELDS)


def _count(row: dict[str, str], key: str, *, context: str) -> int:
    try:
        result = int(row.get(key) or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{context}: {key} must be an integer") from exc
    if result < 0:
        raise ValueError(f"{context}: {key} must be non-negative")
    return result


def protocol_measurement(row: dict[str, str], *, context: str) -> dict[str, str]:
    """Derive all published protocol rates from auditable S/M/T/D/A counts."""

    if not has_protocol_metrics(row):
        return {
            "S": "n/a",
            "M": "n/a",
            "T": "n/a",
            "D": "n/a",
            "A": "n/a",
            "protocol_completion": "n/a",
            "model_nonconformance": "n/a",
            "conditional": "n/a",
            "end_to_end": "n/a",
        }

    all_scored = _count(row, "completed_trials", context=context)
    asr_eligible = _count(row, "asr_eligible_trials", context=context)
    n_minus_one = _count(row, "n_minus_1_trials", context=context)
    accounted = _count(row, "accounted_terminal_trials", context=context)
    denominator = _count(row, "protocol_denominator_trials", context=context)
    successes = _count(row, "attack_success_trials", context=context)
    if asr_eligible > all_scored:
        raise ValueError(f"{context}: S cannot exceed all scored rows")
    if accounted != all_scored + n_minus_one:
        raise ValueError(f"{context}: T must equal all scored rows plus M")
    if denominator != asr_eligible + n_minus_one:
        raise ValueError(f"{context}: D must equal S plus M")
    if successes > asr_eligible:
        raise ValueError(f"{context}: A cannot exceed S")

    def rate(numerator: int, denominator_value: int) -> str:
        return pct(numerator / denominator_value) if denominator_value else "n/a"

    return {
        "S": str(asr_eligible),
        "M": str(n_minus_one),
        "T": str(accounted),
        "D": str(denominator),
        "A": str(successes),
        "protocol_completion": rate(asr_eligible, denominator),
        "model_nonconformance": rate(n_minus_one, denominator),
        "conditional": rate(successes, asr_eligible),
        "end_to_end": rate(successes, denominator),
    }


def unique_nonempty(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        token = str(value or "")
        if token and token not in out:
            out.append(token)
    return out


def latex_escape(text: str) -> str:
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
    return "".join(replacements.get(ch, ch) for ch in str(text))


def markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def latex_table(headers: list[str], rows: list[list[str]], caption: str, label: str) -> str:
    colspec = "l" * len(headers)
    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\small",
        rf"\begin{{tabular}}{{{colspec}}}",
        r"\toprule",
        " & ".join(latex_escape(header) for header in headers) + r" \\",
        r"\midrule",
    ]
    for row in rows:
        lines.append(" & ".join(latex_escape(cell) for cell in row) + r" \\")
    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        rf"\caption{{{latex_escape(caption)}}}",
        rf"\label{{{latex_escape(label)}}}",
        r"\end{table}",
        "",
    ]
    return "\n".join(lines)


def main_results_rows(harness_macro: list[dict[str, str]]) -> list[list[str]]:
    rows: list[list[str]] = []
    attack_rows = [
        row for row in harness_macro if (row.get("run_kind") or "attack") == "attack"
    ]
    for row in sorted(attack_rows, key=lambda r: value(r, "harness", "")):
        metrics = protocol_measurement(
            row,
            context=f"attack harness macro {value(row, 'harness', '')}",
        )
        pooled = (
            f"{metrics['conditional']} [{ci(row, 'attack_success')}]"
            if metrics["conditional"] != "n/a"
            else "n/a"
        )
        rows.append(
            [
                value(row, "harness", ""),
                f"{value(row, 'complete_families')}/{value(row, 'families')}",
                value(row, "completed_trials"),
                metrics["S"],
                metrics["M"],
                metrics["T"],
                metrics["D"],
                metrics["A"],
                metrics["protocol_completion"],
                metrics["model_nonconformance"],
                pooled,
                metrics["end_to_end"],
                pct(row.get("family_macro_attack_success")),
                pct(row.get("family_macro_end_to_end_attack")) if has_protocol_metrics(row) else "n/a",
                pct(row.get("family_macro_confirmed")),
                value(row, "family_macro_risk", "n/a"),
                value(row, "timeout_trials"),
            ]
        )
    return rows


def family_results_rows(family_macro: list[dict[str, str]], limit: int = 80) -> list[list[str]]:
    rows: list[list[str]] = []
    attack_rows = [
        row
        for row in family_macro
        if (row.get("run_kind") or "attack") == "attack"
        and (
            int(row.get("accounted_terminal_trials") or 0) > 0
            if has_protocol_metrics(row)
            else int(row.get("complete_cases") or 0) > 0
        )
    ]
    for row in sorted(
        attack_rows,
        key=lambda r: (
            value(r, "harness", ""),
            value(r, "suite", ""),
            value(r, "paper_family", ""),
        ),
    )[:limit]:
        metrics = protocol_measurement(
            row,
            context=(
                f"family macro {value(row, 'harness', '')}/"
                f"{value(row, 'suite', '')}/{value(row, 'paper_family', '')}"
            ),
        )
        conditional = (
            f"{metrics['conditional']} [{ci(row, 'attack_success')}]"
            if metrics["conditional"] != "n/a"
            else "n/a"
        )
        rows.append(
            [
                value(row, "harness", ""),
                value(row, "suite", ""),
                value(row, "paper_family", ""),
                f"{value(row, 'complete_cases')}/{value(row, 'cases')}",
                value(row, "completed_trials"),
                metrics["S"],
                metrics["M"],
                metrics["T"],
                metrics["D"],
                metrics["A"],
                metrics["protocol_completion"],
                metrics["model_nonconformance"],
                conditional,
                metrics["end_to_end"],
                pct(row.get("attack_success_case_mean")) if has_protocol_metrics(row) else "n/a",
                pct(row.get("end_to_end_attack_case_mean")) if has_protocol_metrics(row) else "n/a",
                pct(row.get("confirmed_case_mean")),
                value(row, "avg_risk_case_mean", "n/a"),
            ]
        )
    return rows


def control_results_rows(harness_macro: list[dict[str, str]]) -> list[list[str]]:
    rows: list[list[str]] = []
    control_rows = [row for row in harness_macro if row.get("run_kind") == "control"]
    for row in sorted(
        control_rows,
        key=lambda r: (value(r, "control_type", ""), value(r, "harness", "")),
    ):
        metrics = protocol_measurement(
            row,
            context=(
                f"control harness macro {value(row, 'control_type', '')}/"
                f"{value(row, 'harness', '')}"
            ),
        )
        rows.append(
            [
                value(row, "control_type", ""),
                value(row, "harness", ""),
                f"{value(row, 'complete_families')}/{value(row, 'families')}",
                value(row, "completed_trials"),
                metrics["S"],
                metrics["M"],
                metrics["T"],
                metrics["D"],
                metrics["A"],
                metrics["protocol_completion"],
                metrics["model_nonconformance"],
                metrics["conditional"],
                metrics["end_to_end"],
                pct(row.get("confirmed_trial_rate")),
                value(row, "timeout_trials"),
            ]
        )
    return rows


def normalize_report_dirs(value: Path | list[Path] | tuple[Path, ...] | None) -> list[Path]:
    if value is None:
        return []
    if isinstance(value, Path):
        return [value]
    return [Path(item) for item in value]


def build_tables(
    attack_report_dir: Path,
    control_report_dir: Path | list[Path] | tuple[Path, ...] | None = None,
    family_limit: int = 80,
) -> dict[str, Any]:
    attack_summary = read_json(attack_report_dir / "summary.json")
    attack_harness = read_csv(attack_report_dir / "harness_macro.csv")
    attack_family = read_csv(attack_report_dir / "family_macro.csv")
    control_report_dirs = normalize_report_dirs(control_report_dir)
    control_harness: list[dict[str, str]] = []
    control_summaries: list[dict[str, Any]] = []
    for report_dir in control_report_dirs:
        control_harness.extend(read_csv(report_dir / "harness_macro.csv"))
        control_summaries.append(read_json(report_dir / "summary.json"))
    control_labels = unique_nonempty(str(summary.get("label") or "") for summary in control_summaries if summary)

    main_headers = [
        "Harness",
        "Scored Families",
        "All Scored",
        "ASR Eligible (S)",
        "N-1 (M)",
        "Coverage Accounted (T)",
        "Protocol Denominator (D)",
        "Attack Success (A)",
        "Protocol Completion (S/D)",
        "Model Nonconformance (M/D)",
        "Conditional ASR (A/S) [95% CI]",
        "End-to-End Attack Rate (A/D)",
        "Family Macro Conditional ASR",
        "Family Macro End-to-End",
        "Family Macro Confirmed",
        "Risk",
        "Timeouts",
    ]
    family_headers = [
        "Harness",
        "Suite",
        "Family",
        "Scored Cases",
        "All Scored",
        "ASR Eligible (S)",
        "N-1 (M)",
        "Coverage Accounted (T)",
        "Protocol Denominator (D)",
        "Attack Success (A)",
        "Protocol Completion (S/D)",
        "Model Nonconformance (M/D)",
        "Conditional ASR (A/S) [95% CI]",
        "End-to-End Attack Rate (A/D)",
        "Case Mean Conditional ASR",
        "Case Mean End-to-End",
        "Case Mean Confirmed",
        "Risk",
    ]
    control_headers = [
        "Control",
        "Harness",
        "Scored Families",
        "All Scored",
        "ASR Eligible (S)",
        "N-1 (M)",
        "Coverage Accounted (T)",
        "Protocol Denominator (D)",
        "Violation (A)",
        "Protocol Completion (S/D)",
        "Model Nonconformance (M/D)",
        "Conditional Violation Rate (A/S)",
        "End-to-End Violation Rate (A/D)",
        "Confirmed Rate",
        "Timeouts",
    ]

    main_rows = main_results_rows(attack_harness)
    family_rows = family_results_rows(attack_family, family_limit)
    control_rows = control_results_rows(control_harness)

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
            "legacy_missing_protocol_fields": "rendered as n/a",
        },
        "sources": {
            "attack_report_dir": str(attack_report_dir),
            "control_report_dir": str(control_report_dirs[0]) if control_report_dirs else "",
            "control_report_dirs": [str(path) for path in control_report_dirs],
        },
        "attack_label": attack_summary.get("label", ""),
        "control_label": ", ".join(label for label in control_labels if label),
        "control_labels": control_labels,
        "main": {"headers": main_headers, "rows": main_rows},
        "family": {"headers": family_headers, "rows": family_rows},
        "control": {"headers": control_headers, "rows": control_rows},
    }


def render_markdown(tables: dict[str, Any]) -> str:
    lines = [
        "# Paper Tables",
        "",
        f"- generated_at: `{tables['generated_at']}`",
        f"- attack_label: `{tables.get('attack_label') or 'n/a'}`",
        f"- control_label: `{tables.get('control_label') or 'n/a'}`",
        "",
        "Measurement contract: `S` = ASR-eligible N0-N5b scored rows; `M` = strict terminal N-1 rows; "
        "`T` = all N0-N5b scored rows + M (coverage); `D` = S + M. "
        "Rates are S/D, M/D, A/S, and A/D.",
        "",
        "## Main Results",
        "",
        markdown_table(tables["main"]["headers"], tables["main"]["rows"]),
        "",
        "## Family Results",
        "",
        markdown_table(tables["family"]["headers"], tables["family"]["rows"]),
    ]
    if tables["control"]["rows"]:
        lines += [
            "",
            "## Control Results",
            "",
            markdown_table(tables["control"]["headers"], tables["control"]["rows"]),
        ]
    return "\n".join(lines) + "\n"


def write_tables(tables: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "markdown": out_dir / "paper_tables.md",
        "json": out_dir / "paper_tables.json",
        "main_latex": out_dir / "main_results_table.tex",
        "family_latex": out_dir / "family_results_table.tex",
        "control_latex": out_dir / "control_results_table.tex",
    }
    paths["markdown"].write_text(render_markdown(tables), encoding="utf-8")
    paths["json"].write_text(json.dumps(tables, indent=2, ensure_ascii=False), encoding="utf-8")
    paths["main_latex"].write_text(
        latex_table(
            tables["main"]["headers"],
            tables["main"]["rows"],
            "Safety Bench main benchmark results.",
            "tab:safety-bench-main",
        ),
        encoding="utf-8",
    )
    paths["family_latex"].write_text(
        latex_table(
            tables["family"]["headers"],
            tables["family"]["rows"],
            "Family-level Safety Bench results.",
            "tab:safety-bench-family",
        ),
        encoding="utf-8",
    )
    if tables["control"]["rows"]:
        paths["control_latex"].write_text(
            latex_table(
                tables["control"]["headers"],
                tables["control"]["rows"],
                "Safety Bench control experiment results.",
                "tab:safety-bench-controls",
            ),
            encoding="utf-8",
        )
    else:
        paths["control_latex"].write_text(
            "% No control report was provided.\n",
            encoding="utf-8",
        )
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Export paper-ready tables from report artifacts.")
    parser.add_argument("--attack-label", default="", help="Attack report label under runs/_reports.")
    parser.add_argument("--attack-report-dir", default="", help="Explicit attack report directory.")
    parser.add_argument("--control-label", action="append", default=[], help="Control report label under runs/_reports. Repeat or comma-separate for multiple control reports.")
    parser.add_argument("--control-report-dir", action="append", default=[], help="Explicit control report directory. Repeat or comma-separate for multiple control reports.")
    parser.add_argument("--out-dir", default="", help="Output directory. Defaults to <attack-report-dir>/paper_tables.")
    parser.add_argument("--family-limit", type=int, default=80, help="Maximum family rows in exported family table.")
    args = parser.parse_args()

    attack_report_dir = report_dir_from(args.attack_label, args.attack_report_dir)
    control_report_dirs = report_dirs_from(args.control_label, args.control_report_dir)
    out_dir = Path(args.out_dir) if args.out_dir else attack_report_dir / "paper_tables"
    tables = build_tables(attack_report_dir, control_report_dirs, args.family_limit)
    paths = write_tables(tables, out_dir)
    for path in paths.values():
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
