"""Check paper numeric claims against generated result artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    from infra.export_paper_tables import safe_slug
    from infra.check_paper_results import is_scored_row, is_terminal_model_protocol_row
except ModuleNotFoundError:  # direct `python infra/check_paper_numbers.py`
    from export_paper_tables import safe_slug  # type: ignore
    from check_paper_results import (  # type: ignore
        is_scored_row,
        is_terminal_model_protocol_row,
    )


ROOT = Path(__file__).resolve().parent.parent

PAPER_DOCS = [
    "docs/paper_draft.md",
    "docs/paper_artifact_evaluation_readme.md",
]

NODES = ["N0", "N1", "N2", "N3", "N4", "N5a", "N5b"]


def split_cli_values(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        for part in str(value).split(","):
            token = part.strip()
            if token:
                out.append(token)
    return out


def resolve_path(root: Path, value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def report_dirs(labels: Iterable[str] | None, paths: Iterable[str] | None, root: Path) -> list[Path]:
    dirs = [resolve_path(root, path) for path in split_cli_values(paths)]
    dirs.extend(root / "runs" / "_reports" / safe_slug(label) for label in split_cli_values(labels))
    return dirs


def issue(
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
    if value is None or value == "" or str(value).strip().lower() == "n/a":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "__yes__"}


def load_json(path: Path) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), []
    except FileNotFoundError:
        return None, [issue("error", "inputs", "required JSON file is missing", {"path": str(path)})]
    except json.JSONDecodeError as exc:
        return None, [issue("error", "inputs", "could not parse JSON file", {"path": str(path), "error": str(exc)})]


def load_summary_rows(path: Path, scope: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    payload, issues = load_json(path / "summary.json")
    if payload is None:
        return {}, issues
    rows = payload.get("rows")
    if not isinstance(rows, list):
        issues.append(issue("error", scope, "summary.json rows must be a list", {"path": str(path / "summary.json")}))
        payload["rows"] = []
    return payload, issues


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip())


def contains_phrase(text: str, phrase: str) -> bool:
    return normalize_text(phrase).lower() in normalize_text(text).lower()


def first_match_location(text: str, phrase: str) -> dict[str, Any]:
    compact = normalize_text(text).lower()
    compact_phrase = normalize_text(phrase).lower()
    index = compact.find(compact_phrase)
    if index < 0:
        return {}
    raw_index = text.lower().find(phrase.lower())
    if raw_index < 0:
        return {"preview": compact[index : index + 200]}
    line = text.count("\n", 0, raw_index) + 1
    lines = text.splitlines()
    preview = lines[line - 1].strip() if line <= len(lines) else ""
    return {"line": line, "preview": preview[:240]}


def percentage(numerator: int, denominator: int) -> str:
    if denominator <= 0:
        return "n/a"
    value = 100.0 * numerator / denominator
    return f"{value:.1f}%"


def display_optional(value: Any) -> Any:
    return "n/a" if value is None else value


def rounded_one(value: float) -> str:
    return f"{value:.1f}"


def rounded_one_or_na(value: Any) -> str:
    parsed = optional_float(value)
    return "n/a" if parsed is None else rounded_one(parsed)


def row_timed_out(row: dict[str, Any]) -> bool:
    return boolish(row.get("timed_out")) or as_int(row.get("stage_timeouts")) > 0


def row_is_n_minus_one(row: dict[str, Any]) -> bool:
    """Recognize the sanitized report form of a terminal N-1 result."""

    return is_terminal_model_protocol_row(row)


def protocol_contract_available(rows: list[dict[str, Any]]) -> bool:
    return bool(rows) and all("result_class" in row and "run_valid" in row for row in rows)


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    protocol_available = protocol_contract_available(rows)
    if protocol_available:
        n_minus_one_rows = [row for row in rows if row_is_n_minus_one(row)]
        scored_rows = [row for row in rows if is_scored_row(row)]
        invalid_rows = [
            row for row in rows if row not in scored_rows and row not in n_minus_one_rows
        ]
    else:
        # Legacy summaries predate result_class.  Their rows remain usable for
        # conditional ASR, but protocol completion/nonconformance is unknown.
        scored_rows = list(rows)
        n_minus_one_rows = []
        invalid_rows = []
    accounted_terminal = scored_rows + n_minus_one_rows
    asr_eligible_rows = [
        row
        for row in scored_rows
        if boolish(row.get("asr_eligible"))
        and not boolish(row.get("attack_success_metric_excluded"))
    ]
    if not protocol_available and not asr_eligible_rows:
        asr_eligible_rows = scored_rows
    protocol_denominator = asr_eligible_rows + n_minus_one_rows
    nodes = Counter(
        "N5b" if str(row.get("progress_node") or "") == "N5" else str(row.get("progress_node") or "")
        for row in asr_eligible_rows
    )
    factual_nodes = Counter(
        "N5b" if str(row.get("progress_node") or "") == "N5" else str(row.get("progress_node") or "")
        for row in scored_rows
    )
    risk_values = [
        as_float(row.get("risk_score"))
        for row in asr_eligible_rows
        if row.get("risk_score") not in (None, "")
    ]
    factual_risk_values = [
        as_float(row.get("risk_score"))
        for row in scored_rows
        if row.get("risk_score") not in (None, "")
    ]
    attack_success = sum(
        1 for row in asr_eligible_rows if boolish(row.get("attack_success"))
    )
    factual_attack_success = sum(
        1 for row in scored_rows if boolish(row.get("attack_success"))
    )
    return {
        "rows": len(rows),
        "scored_rows": len(scored_rows),
        "n_minus_1_rows": len(n_minus_one_rows) if protocol_available else None,
        "accounted_terminal_rows": len(accounted_terminal) if protocol_available else None,
        "protocol_denominator_rows": (
            len(protocol_denominator) if protocol_available else None
        ),
        "invalid_rows": len(invalid_rows) if protocol_available else None,
        "protocol_metrics_available": protocol_available,
        "asr_eligible_rows": len(asr_eligible_rows),
        "attack_success": attack_success,
        "factual_attack_success": factual_attack_success,
        "confirmed_compromise": sum(
            1
            for row in asr_eligible_rows
            if boolish(row.get("confirmed_compromise"))
        ),
        "timeouts": sum(1 for row in rows if row_timed_out(row)),
        "node_counts": {node: nodes.get(node, 0) for node in NODES},
        "factual_node_counts": {
            node: factual_nodes.get(node, 0) for node in NODES
        },
        "mean_risk": (sum(risk_values) / len(risk_values)) if risk_values else None,
        "factual_mean_risk": (
            sum(factual_risk_values) / len(factual_risk_values)
            if factual_risk_values
            else None
        ),
        "families": len({str(row.get("paper_family") or row.get("family") or "") for row in rows if row.get("paper_family") or row.get("family")}),
        "scored_families": len(
            {
                str(row.get("paper_family") or row.get("family") or "")
                for row in scored_rows
                if row.get("paper_family") or row.get("family")
            }
        ),
        "cases": len({str(row.get("case_dir") or "") for row in rows if row.get("case_dir")}),
        "conditional_asr": (
            attack_success / len(asr_eligible_rows) if asr_eligible_rows else None
        ),
        "protocol_completion_rate": (
            len(asr_eligible_rows) / len(protocol_denominator)
            if protocol_available and protocol_denominator
            else None
        ),
        "model_nonconformance_rate": (
            len(n_minus_one_rows) / len(protocol_denominator)
            if protocol_available and protocol_denominator
            else None
        ),
        "end_to_end_attack_rate": (
            attack_success / len(protocol_denominator)
            if protocol_available and protocol_denominator
            else None
        ),
    }


def load_table_main(table_dir: Path | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if table_dir is None:
        return {}, [issue("error", "tables", "no paper table directory provided")]
    payload, issues = load_json(table_dir / "paper_tables.json")
    if payload is None:
        return {}, issues
    main = payload.get("main", {})
    rows = main.get("rows", []) if isinstance(main, dict) else []
    headers = main.get("headers", []) if isinstance(main, dict) else []
    if not rows or not isinstance(rows[0], list):
        issues.append(issue("error", "tables", "paper_tables.json does not contain a main result row"))
        return {}, issues
    row = rows[0]
    values = {str(header): row[index] if index < len(row) else "" for index, header in enumerate(headers)}
    return values, issues


def parse_pooled_asr(value: str) -> dict[str, str]:
    text = str(value or "")
    match = re.search(r"(?P<asr>\d+(?:\.\d+)?)%\s*\[(?P<low>\d+(?:\.\d+)?)%-(?P<high>\d+(?:\.\d+)?)%\]", text)
    if not match:
        return {"pooled": text, "ci_prose": text}
    return {
        "pooled": f"{match.group('asr')}%",
        "ci_prose": f"[{match.group('low')}%, {match.group('high')}%]",
    }


def check_table_consistency(
    *,
    table: dict[str, Any],
    attack: dict[str, Any],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    current_protocol_table = "All Scored" in table or "Protocol Denominator (D)" in table
    n1_table = current_protocol_table or "Scored Trials" in table or "Accounted Terminal" in table
    if current_protocol_table:
        expected_values = {
            "Scored Families": f"{attack['scored_families']}/{attack['families']}",
            "All Scored": str(attack["scored_rows"]),
            "ASR Eligible (S)": str(attack["asr_eligible_rows"]),
            "N-1 (M)": str(attack["n_minus_1_rows"]),
            "Coverage Accounted (T)": str(attack["accounted_terminal_rows"]),
            "Protocol Denominator (D)": str(attack["protocol_denominator_rows"]),
            "Attack Success (A)": str(attack["attack_success"]),
            "Protocol Completion (S/D)": percentage(
                attack["asr_eligible_rows"], attack["protocol_denominator_rows"]
            ),
            "Model Nonconformance (M/D)": percentage(
                attack["n_minus_1_rows"], attack["protocol_denominator_rows"]
            ),
            "End-to-End Attack Rate (A/D)": percentage(
                attack["attack_success"], attack["protocol_denominator_rows"]
            ),
            "Timeouts": str(attack["timeouts"]),
        }
    elif n1_table:
        expected_values = {
            "Scored Families": f"{attack['scored_families']}/{attack['families']}",
            "Scored Trials": str(attack["scored_rows"]),
            "Timeouts": str(attack["timeouts"]),
        }
        if attack.get("protocol_metrics_available"):
            expected_values.update(
                {
                    "N-1": str(attack["n_minus_1_rows"]),
                    "Accounted Terminal": str(attack["accounted_terminal_rows"]),
                    "ASR Eligible": str(attack["asr_eligible_rows"]),
                    "Protocol Denominator": str(
                        attack["protocol_denominator_rows"]
                    ),
                    "Protocol Completion": percentage(
                        attack["asr_eligible_rows"],
                        attack["protocol_denominator_rows"],
                    ),
                    "Model Nonconformance": percentage(
                        attack["n_minus_1_rows"],
                        attack["protocol_denominator_rows"],
                    ),
                    "End-to-End Attack Rate": percentage(
                        attack["attack_success"],
                        attack["protocol_denominator_rows"],
                    ),
                }
            )
    else:
        expected_values = {
            "Families": f"{attack['families']}/{attack['families']}",
            "Trials": str(attack["rows"]),
            "Timeouts": str(attack["timeouts"]),
        }
    for key, expected in expected_values.items():
        actual = str(table.get(key, ""))
        if actual != expected:
            issues.append(
                issue(
                    "error",
                    "tables",
                    "paper main table numeric value does not match summaries",
                    {"column": key, "expected": expected, "actual": actual},
                )
            )
    pooled_key = (
        "Conditional ASR (A/S) [95% CI]"
        if current_protocol_table
        else "Conditional ASR [95% CI]"
        if n1_table
        else "Pooled ASR [95% CI]"
    )
    pooled = str(table.get(pooled_key, ""))
    expected_pooled_prefix = percentage(
        attack["attack_success"], attack["asr_eligible_rows"]
    )
    if pooled and not pooled.startswith(expected_pooled_prefix):
        issues.append(
            issue(
                "error",
                "tables",
                "paper main table conditional ASR does not match scored ASR-eligible rows",
                {
                    "column": pooled_key,
                    "expected_prefix": expected_pooled_prefix,
                    "actual": pooled,
                },
            )
        )
    table_risk = optional_float(table.get("Risk"))
    macro_risk = attack.get("macro_risk")
    if current_protocol_table and as_int(attack.get("asr_eligible_rows")) == 0:
        if str(table.get("Risk", "")).strip().lower() != "n/a":
            issues.append(
                issue(
                    "error",
                    "tables",
                    "paper main table risk must be n/a when S is zero",
                    {"expected": "n/a", "actual": table.get("Risk")},
                )
            )
    elif macro_risk is not None and table_risk is not None and not math.isclose(
        table_risk, as_float(macro_risk), rel_tol=0.0, abs_tol=0.05
    ):
        issues.append(
            issue(
                "error",
                "tables",
                "paper main table mean risk does not match attack rows",
                {"expected": rounded_one(as_float(macro_risk)), "actual": table.get("Risk")},
            )
        )
    return issues


def load_macro_risk(report_dir: Path) -> float | None:
    path = report_dir / "harness_macro.csv"
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                if str(row.get("run_kind") or "attack") == "attack":
                    return optional_float(row.get("family_macro_risk"))
    except OSError:
        return None
    return None


def expected_doc_phrases(
    *,
    attack: dict[str, Any],
    control: dict[str, Any],
    table: dict[str, Any],
    case_evidence: dict[str, Any],
) -> dict[str, list[str]]:
    current_protocol_table = "All Scored" in table or "Protocol Denominator (D)" in table
    n1_table = current_protocol_table or "Scored Trials" in table or "Accounted Terminal" in table
    pooled_key = (
        "Conditional ASR (A/S) [95% CI]"
        if current_protocol_table
        else "Conditional ASR [95% CI]"
        if n1_table
        else "Pooled ASR [95% CI]"
    )
    macro_key = (
        "Family Macro Conditional ASR" if n1_table else "Family Macro ASR"
    )
    default_pooled = percentage(
        attack["attack_success"], attack["asr_eligible_rows"]
    )
    pooled = parse_pooled_asr(str(table.get(pooled_key, default_pooled)))
    macro_asr = str(table.get(macro_key, ""))
    macro_confirmed = str(table.get("Family Macro Confirmed", ""))
    table_risk = optional_float(table.get("Risk"))
    risk = rounded_one_or_na(
        table_risk if table_risk is not None else attack.get("mean_risk")
    )

    attack_rows = int(
        attack.get("accounted_terminal_rows")
        if attack.get("protocol_metrics_available")
        else attack["rows"]
    )
    control_rows = int(
        control.get("accounted_terminal_rows")
        if control.get("protocol_metrics_available")
        else control["rows"]
    )
    attack_scored = int(attack["scored_rows"])
    attack_asr_trials = int(attack["asr_eligible_rows"])
    attack_protocol_trials = int(
        attack.get("protocol_denominator_rows")
        if attack.get("protocol_metrics_available")
        else attack["rows"]
    )
    control_protocol_trials = int(
        control.get("protocol_denominator_rows")
        if control.get("protocol_metrics_available")
        else control["rows"]
    )
    attack_success = int(attack["attack_success"])
    confirmed = int(attack["confirmed_compromise"])
    control_success = int(control["attack_success"])
    control_confirmed = int(control["confirmed_compromise"])

    draft = [
        f"{attack_rows} attack rows",
        f"{control_rows} matched control rows",
        f"{attack_success}/{attack_asr_trials} attack successes",
        f"{confirmed}/{attack_asr_trials} confirmed",
        f"pooled ASR of {pooled['pooled']}",
        pooled["ci_prose"],
        f"family macro ASR {macro_asr}",
        f"family macro confirmed {macro_confirmed}",
        f"mean risk {risk}",
        f"{control['asr_eligible_rows']}/{control_protocol_trials} rows",
        "zero attack success and zero confirmed compromise",
    ]
    if n1_table and attack.get("protocol_metrics_available"):
        draft.extend(
            [
                f"{attack_scored} scored attack rows",
                f"{attack_asr_trials} ASR-eligible scored attack rows",
                f"{attack['n_minus_1_rows']} N-1 rows",
                f"{attack_rows} accounted terminal attack rows",
                f"{attack_protocol_trials} protocol-denominator attack rows",
                f"conditional ASR of {pooled['pooled']}",
                f"end-to-end attack rate of {percentage(attack_success, attack_protocol_trials)}",
            ]
        )
    if as_int(case_evidence.get("case_count")) > 0 and as_int(case_evidence.get("attack_row_count")) > 0:
        draft.append(
            f"{as_int(case_evidence.get('case_count'))} unique successful cases represented by "
            f"{as_int(case_evidence.get('attack_row_count'))} attack"
        )

    results = [
        f"Attack rows | {attack_rows}",
        f"Attack timeouts | {attack['timeouts']}",
        f"Attack success rows | {attack_success}",
        f"Confirmed compromise rows | {confirmed}",
        f"Pooled ASR | {table.get(pooled_key, pooled['pooled'])}",
        f"Family macro ASR | {macro_asr}",
        f"Family macro confirmed | {macro_confirmed}",
        f"Mean risk | {risk}",
        f"Control rows | {control_rows}",
        f"Control attack success | {control_success}",
        f"Control confirmed compromise | {control_confirmed}",
        f"Control timeouts | {control['timeouts']}",
    ]
    current_status = [
        f"Attack rows | {attack_rows}",
        f"Attack timeouts | {attack['timeouts']}",
        f"Attack success rows | {attack_success}",
        f"Confirmed compromise rows | {confirmed}",
        f"Pooled ASR | {table.get(pooled_key, pooled['pooled'])}",
        f"Family macro ASR | {macro_asr}",
        f"Family macro confirmed | {macro_confirmed}",
        f"Mean risk | {risk}",
        f"Control rows | {control_rows}",
        f"Control attack-success rows | {control_success}",
        f"Control confirmed rows | {control_confirmed}",
        f"Control timeouts | {control['timeouts']}",
    ]
    for node in NODES:
        results.append(f"| {node} | {attack['node_counts'].get(node, 0)} |")
        current_status.append(f"| {node} | {attack['node_counts'].get(node, 0)} |")
    for node in NODES:
        current_status.append(f"| {node} | {control['node_counts'].get(node, 0)} |")

    artifact_readme = [
        f"{attack_rows}/{attack_rows} attack",
        f"{control_rows}/{control_rows} control",
        "zero `attack_success` and zero",
    ]
    if n1_table and attack.get("protocol_metrics_available"):
        artifact_readme.extend(
            [
                f"{attack_scored} scored attack rows",
                f"{attack_asr_trials} ASR-eligible scored attack rows",
                f"{attack['n_minus_1_rows']} N-1 rows",
                f"{attack_rows} accounted terminal attack rows",
                f"{attack_protocol_trials} protocol-denominator attack rows",
            ]
        )

    return {
        "docs/paper_draft.md": draft,
        "docs/paper_artifact_evaluation_readme.md": artifact_readme,
    }


def check_docs(root: Path, requirements: dict[str, list[str]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for rel, phrases in requirements.items():
        path = root / rel
        if not path.is_file():
            issues.append(issue("error", "docs", "required paper numeric document is missing", {"path": rel}))
            continue
        text = path.read_text(encoding="utf-8-sig")
        for phrase in phrases:
            if phrase and not contains_phrase(text, phrase):
                issues.append(
                    issue(
                        "error",
                        "docs",
                        "paper document is missing current numeric claim",
                        {"path": rel, "phrase": phrase, **first_match_location(text, phrase)},
                    )
                )
    return issues


def build_number_report(
    *,
    root: Path = ROOT,
    attack_dirs: list[Path] | None = None,
    control_dirs: list[Path] | None = None,
    table_dir: Path | None = None,
    case_evidence_dir: Path | None = None,
) -> dict[str, Any]:
    attack_dirs = attack_dirs or []
    control_dirs = control_dirs or []
    issues: list[dict[str, Any]] = []

    if not attack_dirs:
        issues.append(issue("error", "inputs", "no attack report directory provided"))
        attack_summary: dict[str, Any] = {"rows": []}
    else:
        attack_summary, loaded_issues = load_summary_rows(attack_dirs[0], "attack")
        issues.extend(loaded_issues)

    control_rows: list[dict[str, Any]] = []
    if not control_dirs:
        issues.append(issue("error", "inputs", "no control report directory provided"))
    for directory in control_dirs:
        control_summary, loaded_issues = load_summary_rows(directory, "control")
        issues.extend(loaded_issues)
        control_rows.extend(control_summary.get("rows", []) if isinstance(control_summary.get("rows"), list) else [])

    attack_rows = attack_summary.get("rows", []) if isinstance(attack_summary.get("rows"), list) else []
    attack_numbers = summarize_rows(attack_rows)
    if attack_dirs:
        macro_risk = load_macro_risk(attack_dirs[0])
        if macro_risk is not None:
            attack_numbers["macro_risk"] = macro_risk
    control_numbers = summarize_rows(control_rows)
    table_main, table_issues = load_table_main(table_dir)
    issues.extend(table_issues)
    if table_main:
        issues.extend(check_table_consistency(table=table_main, attack=attack_numbers))

    case_evidence: dict[str, Any] = {}
    if case_evidence_dir is not None:
        payload, case_issues = load_json(case_evidence_dir / "case_study_evidence.json")
        issues.extend(case_issues)
        if payload:
            case_evidence = payload

    if table_main:
        requirements = expected_doc_phrases(
            attack=attack_numbers,
            control=control_numbers,
            table=table_main,
            case_evidence=case_evidence,
        )
        issues.extend(check_docs(root, requirements))

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "root": str(root),
        "sources": {
            "attack_report_dirs": [str(path) for path in attack_dirs],
            "control_report_dirs": [str(path) for path in control_dirs],
            "table_dir": str(table_dir) if table_dir else "",
            "case_evidence_dir": str(case_evidence_dir) if case_evidence_dir else "",
        },
        "numbers": {
            "attack": attack_numbers,
            "control": control_numbers,
            "main_table": table_main,
            "case_evidence": {
                "case_count": as_int(case_evidence.get("case_count")),
                "attack_row_count": as_int(case_evidence.get("attack_row_count")),
                "recommended_main_paper_count": as_int(case_evidence.get("recommended_main_paper_count")),
            },
        },
        "checked_docs": PAPER_DOCS,
        "issues": issues,
        "ok": not any(item.get("severity") == "error" for item in issues),
    }


def render_markdown(report: dict[str, Any]) -> str:
    attack = report.get("numbers", {}).get("attack", {})
    control = report.get("numbers", {}).get("control", {})
    case_evidence = report.get("numbers", {}).get("case_evidence", {})
    lines = [
        "# Paper Number Check",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- ok: `{str(report['ok']).lower()}`",
        "",
        "## Summary",
        "",
        f"- attack result rows: `{attack.get('rows', 0)}`",
        f"- attack scored rows: `{attack.get('scored_rows', 0)}`",
        f"- attack ASR-eligible scored rows (S): `{display_optional(attack.get('asr_eligible_rows'))}`",
        f"- attack N-1 rows (M): `{display_optional(attack.get('n_minus_1_rows'))}`",
        f"- attack coverage-accounted terminal rows: `{display_optional(attack.get('accounted_terminal_rows'))}`",
        f"- attack protocol denominator rows (S+M): `{display_optional(attack.get('protocol_denominator_rows'))}`",
        f"- attack successes: `{attack.get('attack_success', 0)}`",
        f"- confirmed compromises: `{attack.get('confirmed_compromise', 0)}`",
        f"- conditional ASR: `{display_optional(attack.get('conditional_asr'))}`",
        f"- protocol completion rate: `{display_optional(attack.get('protocol_completion_rate'))}`",
        f"- model nonconformance rate: `{display_optional(attack.get('model_nonconformance_rate'))}`",
        f"- end-to-end attack rate: `{display_optional(attack.get('end_to_end_attack_rate'))}`",
        f"- control result rows: `{control.get('rows', 0)}`",
        f"- control scored rows: `{control.get('scored_rows', 0)}`",
        f"- control ASR-eligible scored rows (S): `{display_optional(control.get('asr_eligible_rows'))}`",
        f"- control N-1 rows (M): `{display_optional(control.get('n_minus_1_rows'))}`",
        f"- control coverage-accounted terminal rows: `{display_optional(control.get('accounted_terminal_rows'))}`",
        f"- control protocol denominator rows (S+M): `{display_optional(control.get('protocol_denominator_rows'))}`",
        f"- control attack successes: `{control.get('attack_success', 0)}`",
        f"- control confirmed compromises: `{control.get('confirmed_compromise', 0)}`",
        f"- case-study cases: `{case_evidence.get('case_count', 0)}`",
        f"- case-study attack rows: `{case_evidence.get('attack_row_count', 0)}`",
        "",
        "## Issues",
        "",
    ]
    if report["issues"]:
        lines += ["| Severity | Scope | Message | Detail |", "| --- | --- | --- | --- |"]
        for item in report["issues"]:
            detail = json.dumps(item.get("detail", {}), ensure_ascii=False)
            lines.append(f"| {item['severity']} | {item['scope']} | {item['message']} | `{detail}` |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Check paper numeric claims against generated artifacts.")
    parser.add_argument("--attack-label", action="append", default=[])
    parser.add_argument("--attack-report-dir", action="append", default=[])
    parser.add_argument("--control-label", action="append", default=[])
    parser.add_argument("--control-report-dir", action="append", default=[])
    parser.add_argument("--table-dir", default="")
    parser.add_argument("--case-evidence-dir", default="")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    attack_dirs = report_dirs(args.attack_label, args.attack_report_dir, ROOT)
    control_dirs = report_dirs(args.control_label, args.control_report_dir, ROOT)
    table_dir = resolve_path(ROOT, args.table_dir) if args.table_dir else None
    case_evidence_dir = resolve_path(ROOT, args.case_evidence_dir) if args.case_evidence_dir else None
    report = build_number_report(
        root=ROOT,
        attack_dirs=attack_dirs,
        control_dirs=control_dirs,
        table_dir=table_dir,
        case_evidence_dir=case_evidence_dir,
    )
    text = json.dumps(report, indent=2, ensure_ascii=False) if args.json else render_markdown(report)
    if args.out:
        output = resolve_path(ROOT, args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
