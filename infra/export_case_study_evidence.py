"""Export paper case-study evidence packs from existing report artifacts."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    from infra.export_paper_tables import safe_slug, split_cli_values
    from infra.check_paper_results import (
        is_scored_row as _is_scored_normalized_row,
        is_terminal_model_protocol_row,
    )
except ModuleNotFoundError:  # direct `python infra/export_case_study_evidence.py`
    from export_paper_tables import safe_slug, split_cli_values
    from check_paper_results import (  # type: ignore
        is_scored_row as _is_scored_normalized_row,
        is_terminal_model_protocol_row,
    )


ROOT = Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"

CONTROL_TYPES = ["clean_control", "no_persist_control", "no_trigger_control", "cleanup_control"]
RECOMMENDED_CURRENT_CLAUDE_CASES = [
    "active/F2_skill_runtime/F2.04_metadata_tampering/sk_i_case_401",
    "active/F3_tool_mcp_runtime/f304_hpae/case_002",
]

SUMMARY_FIELDS = [
    "suite",
    "paper_family",
    "case_dir",
    "variant",
    "harness",
    "run_id",
    "run_dir",
    "has_run",
    "has_oracle",
    "run_valid",
    "run_validity_source",
    "run_validity_schema_version",
    "result_class",
    "display_node",
    "model_protocol_status",
    "model_protocol_failure_kind",
    "model_protocol_failure_stage",
    "model_protocol_evidence",
    "terminal_outcome",
    "retry_eligible",
    "asr_eligible",
    "formal_asr_eligible",
    "attack_success_metric_excluded",
    "diagnostic_progress_node",
    "progress_node",
    "verdict",
    "progress_score",
    "risk_score",
    "attack_success",
    "confirmed_compromise",
    "global_config_touched",
    "timed_out",
    "stage_timeouts",
    "O_callback_probe_ok",
]

FRAME_FIELDS = ["entry", "carrier", "boundary", "trigger", "violation", "recovery"]


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def is_scored_report_row(row: dict[str, Any]) -> bool:
    """Classify current rows strictly, but keep legacy synthetic rows usable."""

    if "run_valid" not in row:
        return boolish(row.get("has_oracle", True))
    return _is_scored_normalized_row(row)


def is_accounted_terminal_row(row: dict[str, Any]) -> bool:
    return is_scored_report_row(row) or is_terminal_model_protocol_row(row)


def is_asr_eligible_scored_row(row: dict[str, Any]) -> bool:
    """Return whether a scored row belongs to the published ASR denominator.

    Current report rows carry the explicit eligibility contract. Legacy
    synthetic rows without either field remain usable for historical fixtures,
    but an explicit exclusion always wins.
    """

    if not is_scored_report_row(row):
        return False
    if "asr_eligible" not in row and "attack_success_metric_excluded" not in row:
        return True
    return bool(
        boolish(row.get("asr_eligible"))
        and not boolish(row.get("attack_success_metric_excluded"))
    )


def rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def format_rate(value: Any) -> str:
    try:
        return f"{float(value) * 100:.1f}%" if value is not None else "n/a"
    except (TypeError, ValueError):
        return "n/a"


def split_csv_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    text = str(value or "")
    return [part.strip() for part in text.split(",") if part.strip()]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def report_dir(label: str = "", path: str = "") -> Path:
    if path:
        return Path(path)
    if label:
        return RUNS / "_reports" / safe_slug(label)
    raise ValueError("report label or explicit report directory is required")


def report_dirs(labels: Iterable[str] | None, paths: Iterable[str] | None) -> list[Path]:
    dirs = [Path(path) for path in split_cli_values(paths or [])]
    dirs.extend(RUNS / "_reports" / safe_slug(label) for label in split_cli_values(labels or []))
    return dirs


def relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve())).replace("\\", "/")
    except ValueError:
        return str(path)


def compact_row(row: dict[str, Any]) -> dict[str, Any]:
    out = {field: row.get(field) for field in SUMMARY_FIELDS if field in row}
    scored = is_scored_report_row(row)
    model_protocol_terminal = is_terminal_model_protocol_row(row)
    out["scored"] = scored
    out["asr_eligible_scored"] = is_asr_eligible_scored_row(row)
    out["model_protocol_terminal"] = model_protocol_terminal
    out["accounted_terminal"] = scored or model_protocol_terminal
    out["outcome_node"] = (
        "N-1"
        if model_protocol_terminal
        else str(row.get("display_node") or row.get("progress_node") or "")
    )
    if model_protocol_terminal:
        # Preserve diagnostic fields explicitly, but never let them masquerade
        # as formal attack/control outcomes in a case-study artifact.
        out["diagnostic_attack_success"] = boolish(row.get("attack_success"))
        out["diagnostic_confirmed_compromise"] = boolish(
            row.get("confirmed_compromise")
        )
        out["attack_success"] = False
        out["confirmed_compromise"] = False
    out["observed_oracles"] = sorted(
        key for key, value in row.items() if key.startswith("O_") and boolish(value)
    )
    out["evidence_oracles"] = split_csv_values(row.get("evidence_oracles"))
    oracle_path = ROOT / str(row.get("run_dir", "")) / "oracle.json"
    oracle_md_path = ROOT / str(row.get("run_dir", "")) / "oracle.md"
    out["oracle_json"] = relpath(oracle_path) if oracle_path.is_file() else ""
    out["oracle_md"] = relpath(oracle_md_path) if oracle_md_path.is_file() else ""
    return out


def select_attack_rows(rows: list[dict[str, Any]], explicit_cases: list[str]) -> list[dict[str, Any]]:
    eligible_rows = [row for row in rows if is_asr_eligible_scored_row(row)]
    if explicit_cases:
        wanted = set(explicit_cases)
        return [
            row for row in eligible_rows if str(row.get("case_dir", "")) in wanted
        ]
    return [
        row
        for row in eligible_rows
        if boolish(row.get("attack_success")) or boolish(row.get("confirmed_compromise"))
    ]


def attack_sort_key(row: dict[str, Any]) -> tuple[int, int, int, str]:
    return (
        int(boolish(row.get("confirmed_compromise"))),
        int(boolish(row.get("attack_success"))),
        int(row.get("risk_score") or 0),
        str(row.get("run_id") or ""),
    )


def group_attack_rows(rows: list[dict[str, Any]]) -> list[tuple[str, list[dict[str, Any]]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for row in rows:
        case_dir = str(row.get("case_dir", ""))
        if not case_dir:
            continue
        if case_dir not in grouped:
            grouped[case_dir] = []
            order.append(case_dir)
        grouped[case_dir].append(row)
    return [(case_dir, grouped[case_dir]) for case_dir in order]


def load_control_rows(control_dirs: list[Path]) -> dict[str, dict[str, dict[str, Any]]]:
    controls: dict[str, dict[str, dict[str, Any]]] = {}
    for directory in control_dirs:
        summary_path = directory / "summary.json"
        if not summary_path.is_file():
            continue
        for row in load_json(summary_path).get("rows", []):
            case_dir = str(row.get("case_dir", ""))
            control_type = str(row.get("control_type", ""))
            if not case_dir or not control_type or not is_accounted_terminal_row(row):
                continue
            existing = controls.setdefault(case_dir, {}).get(control_type)
            # Prefer a scorable safety contrast over an N-1 coverage row.  The
            # formal duplicate-accounted gate remains authoritative elsewhere.
            if existing is None or (
                is_asr_eligible_scored_row(row)
                and not is_asr_eligible_scored_row(existing)
            ) or (
                is_scored_report_row(row)
                and not is_scored_report_row(existing)
                and not is_asr_eligible_scored_row(existing)
            ):
                controls[case_dir][control_type] = row
    return controls


def load_case_meta(case_dir: str) -> dict[str, Any]:
    path = RUNS / case_dir / "case_meta.json"
    return load_json(path) if path.is_file() else {}


def case_frame(meta: dict[str, Any]) -> dict[str, Any]:
    return {field: meta.get(field, "") for field in FRAME_FIELDS}


def build_case_record(
    case_dir: str,
    attack_rows: list[dict[str, Any]],
    controls_by_case: dict[str, dict[str, dict[str, Any]]],
) -> dict[str, Any]:
    row = max(attack_rows, key=attack_sort_key)
    meta = load_case_meta(case_dir)
    attacks = [compact_row(attack_row) for attack_row in attack_rows]
    raw_controls = controls_by_case.get(case_dir, {})
    controls = {
        control_type: compact_row(raw_controls.get(control_type, {}))
        for control_type in CONTROL_TYPES
        if control_type in raw_controls
    }
    missing_controls = [control_type for control_type in CONTROL_TYPES if control_type not in controls]
    control_violations = [
        control_type
        for control_type, control in raw_controls.items()
        if is_asr_eligible_scored_row(control)
        and (
            boolish(control.get("attack_success"))
            or boolish(control.get("confirmed_compromise"))
        )
    ]
    control_model_protocol_deviations = [
        control_type
        for control_type, control in raw_controls.items()
        if is_terminal_model_protocol_row(control)
    ]
    control_asr_ineligible_scored = [
        control_type
        for control_type, control in raw_controls.items()
        if is_scored_report_row(control)
        and not is_asr_eligible_scored_row(control)
    ]
    scored_control_count = sum(
        1 for control in raw_controls.values() if is_scored_report_row(control)
    )
    eligible_control_count = sum(
        1 for control in raw_controls.values() if is_asr_eligible_scored_row(control)
    )
    protocol_control_count = sum(
        1
        for control in raw_controls.values()
        if is_terminal_model_protocol_row(control)
    )
    accounted_control_count = scored_control_count + protocol_control_count
    protocol_control_denominator = eligible_control_count + protocol_control_count
    return {
        "case_dir": case_dir,
        "case_id": meta.get("case_id", ""),
        "paper_family": row.get("paper_family", ""),
        "suite": row.get("suite", ""),
        "variant": row.get("variant", ""),
        "recommended_main_paper": case_dir in RECOMMENDED_CURRENT_CLAUDE_CASES,
        "frame": case_frame(meta),
        "oracle_strength": meta.get("oracle_strength", row.get("oracle_strength", "")),
        "attack": compact_row(row),
        "attacks": attacks,
        "attack_row_count": len(attacks),
        "controls": controls,
        "missing_controls": missing_controls,
        "control_violations": control_violations,
        "control_model_protocol_deviations": control_model_protocol_deviations,
        "control_asr_ineligible_scored": control_asr_ineligible_scored,
        "control_accounted_terminal_count": accounted_control_count,
        "control_scored_count": scored_control_count,
        "control_asr_eligible_scored_count": eligible_control_count,
        "control_asr_ineligible_scored_count": (
            scored_control_count - eligible_control_count
        ),
        "control_model_protocol_terminal_count": protocol_control_count,
        "control_protocol_denominator_count": protocol_control_denominator,
        "control_protocol_completion_rate": rate(
            eligible_control_count, protocol_control_denominator
        ),
        "control_model_nonconformance_rate": rate(
            protocol_control_count, protocol_control_denominator
        ),
        "source_case_meta": relpath(RUNS / case_dir / "case_meta.json"),
    }


def build_evidence_pack(
    *,
    attack_dir: Path,
    control_dirs: list[Path],
    case_dirs: list[str] | None = None,
) -> dict[str, Any]:
    attack_summary_path = attack_dir / "summary.json"
    if not attack_summary_path.is_file():
        raise FileNotFoundError(f"missing attack summary: {attack_summary_path}")
    attack_summary = load_json(attack_summary_path)
    observed_attack_rows = [
        row for row in attack_summary.get("rows", []) if isinstance(row, dict)
    ]
    scored_attack_rows = [
        row for row in observed_attack_rows if is_scored_report_row(row)
    ]
    eligible_scored_attack_rows = [
        row for row in observed_attack_rows if is_asr_eligible_scored_row(row)
    ]
    protocol_attack_rows = [
        row for row in observed_attack_rows if is_terminal_model_protocol_row(row)
    ]
    accounted_attack_rows = [
        row for row in observed_attack_rows if is_accounted_terminal_row(row)
    ]
    protocol_denominator_attack_rows = eligible_scored_attack_rows + protocol_attack_rows
    successful_eligible_attack_rows = [
        row
        for row in eligible_scored_attack_rows
        if boolish(row.get("attack_success"))
    ]
    selected_rows = select_attack_rows(observed_attack_rows, case_dirs or [])
    controls_by_case = load_control_rows(control_dirs)
    cases = [
        build_case_record(case_dir, attack_rows, controls_by_case)
        for case_dir, attack_rows in group_attack_rows(selected_rows)
    ]
    issues: list[dict[str, Any]] = []
    for case in cases:
        if case["missing_controls"]:
            issues.append(
                {
                    "severity": "error",
                    "case_dir": case["case_dir"],
                    "message": "missing control rows",
                    "controls": case["missing_controls"],
                }
            )
        if case["control_violations"]:
            issues.append(
                {
                    "severity": "error",
                    "case_dir": case["case_dir"],
                    "message": "control rows contain unsafe success",
                    "controls": case["control_violations"],
                }
            )
        if case["control_model_protocol_deviations"]:
            issues.append(
                {
                    "severity": "error",
                    "case_dir": case["case_dir"],
                    "message": (
                        "control rows are accounted terminal N-1 outcomes; "
                        "the safety contrast is not scorable"
                    ),
                    "controls": case["control_model_protocol_deviations"],
                }
            )
        if case["control_asr_ineligible_scored"]:
            issues.append(
                {
                    "severity": "error",
                    "case_dir": case["case_dir"],
                    "message": (
                        "control rows are scored but ASR-ineligible; "
                        "the main-paper safety contrast is not metric-eligible"
                    ),
                    "controls": case["control_asr_ineligible_scored"],
                }
            )
    matched_control_accounted = sum(
        int(case["control_accounted_terminal_count"]) for case in cases
    )
    matched_control_scored = sum(int(case["control_scored_count"]) for case in cases)
    matched_control_eligible = sum(
        int(case["control_asr_eligible_scored_count"]) for case in cases
    )
    matched_control_protocol = sum(
        int(case["control_model_protocol_terminal_count"]) for case in cases
    )
    matched_control_denominator = matched_control_eligible + matched_control_protocol
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "attack_report": relpath(attack_dir),
        "control_reports": [relpath(path) for path in control_dirs],
        "selection": (
            "explicit_asr_eligible_scored_only"
            if case_dirs
            else "attack_success_or_confirmed_asr_eligible_scored_only"
        ),
        "observed_attack_rows": len(observed_attack_rows),
        "accounted_terminal_attack_rows": len(accounted_attack_rows),
        "scored_attack_rows": len(scored_attack_rows),
        "asr_eligible_scored_attack_rows": len(eligible_scored_attack_rows),
        "asr_ineligible_scored_attack_rows": (
            len(scored_attack_rows) - len(eligible_scored_attack_rows)
        ),
        "model_protocol_terminal_attack_rows": len(protocol_attack_rows),
        "excluded_model_protocol_attack_rows": len(protocol_attack_rows),
        "protocol_denominator_attack_rows": len(protocol_denominator_attack_rows),
        "attack_success_rows": len(successful_eligible_attack_rows),
        "attack_protocol_completion_rate": rate(
            len(eligible_scored_attack_rows), len(protocol_denominator_attack_rows)
        ),
        "attack_model_nonconformance_rate": rate(
            len(protocol_attack_rows), len(protocol_denominator_attack_rows)
        ),
        "conditional_attack_success_rate": rate(
            len(successful_eligible_attack_rows), len(eligible_scored_attack_rows)
        ),
        "end_to_end_attack_rate": rate(
            len(successful_eligible_attack_rows), len(protocol_denominator_attack_rows)
        ),
        "matched_control_accounted_terminal_rows": matched_control_accounted,
        "matched_control_scored_rows": matched_control_scored,
        "matched_control_asr_eligible_scored_rows": matched_control_eligible,
        "matched_control_asr_ineligible_scored_rows": (
            matched_control_scored - matched_control_eligible
        ),
        "matched_control_model_protocol_terminal_rows": matched_control_protocol,
        "matched_control_protocol_denominator_rows": matched_control_denominator,
        "control_protocol_completion_rate": rate(
            matched_control_eligible, matched_control_denominator
        ),
        "control_model_nonconformance_rate": rate(
            matched_control_protocol, matched_control_denominator
        ),
        "case_count": len(cases),
        "attack_row_count": len(selected_rows),
        "recommended_main_paper_count": sum(1 for case in cases if case["recommended_main_paper"]),
        "cases": cases,
        "issues": issues,
        "ok": not any(item["severity"] == "error" for item in issues),
    }


def render_markdown(pack: dict[str, Any]) -> str:
    lines = [
        "# Case Study Evidence Pack",
        "",
        f"- generated_at: `{pack['generated_at']}`",
        f"- attack_report: `{pack['attack_report']}`",
        f"- case_count: `{pack['case_count']}`",
        f"- attack_row_count: `{pack.get('attack_row_count', pack['case_count'])}`",
        f"- observed_attack_rows: `{pack.get('observed_attack_rows', pack.get('attack_row_count', 0))}`",
        f"- accounted_terminal_attack_rows: `{pack.get('accounted_terminal_attack_rows', pack.get('attack_row_count', 0))}`",
        f"- scored_attack_rows: `{pack.get('scored_attack_rows', pack.get('attack_row_count', 0))}`",
        f"- asr_eligible_scored_attack_rows (S): `{pack.get('asr_eligible_scored_attack_rows', 0)}`",
        f"- model_protocol_terminal_attack_rows (N-1): `{pack.get('model_protocol_terminal_attack_rows', 0)}`",
        f"- protocol_denominator_attack_rows (D=S+M): `{pack.get('protocol_denominator_attack_rows', 0)}`",
        f"- attack_success_rows (A): `{pack.get('attack_success_rows', 0)}`",
        f"- attack_protocol_completion_rate: `{format_rate(pack.get('attack_protocol_completion_rate'))}`",
        f"- attack_model_nonconformance_rate: `{format_rate(pack.get('attack_model_nonconformance_rate'))}`",
        f"- conditional_attack_success_rate: `{format_rate(pack.get('conditional_attack_success_rate'))}`",
        f"- end_to_end_attack_rate: `{format_rate(pack.get('end_to_end_attack_rate'))}`",
        f"- matched_control_model_protocol_terminal_rows (N-1): `{pack.get('matched_control_model_protocol_terminal_rows', 0)}`",
        f"- control_protocol_completion_rate: `{format_rate(pack.get('control_protocol_completion_rate'))}`",
        f"- control_model_nonconformance_rate: `{format_rate(pack.get('control_model_nonconformance_rate'))}`",
        f"- recommended_main_paper_count: `{pack['recommended_main_paper_count']}`",
        f"- ok: `{str(pack['ok']).lower()}`",
        "",
        "## Cases",
        "",
    ]
    for case in pack["cases"]:
        attack = case["attack"]
        controls = case["controls"]
        lines += [
            f"### {case['paper_family']} {case['case_dir']}",
            "",
            f"- recommended_main_paper: `{str(case['recommended_main_paper']).lower()}`",
            f"- progress: `{attack.get('outcome_node', attack.get('progress_node'))}` `{attack.get('verdict')}`",
            f"- attack_success: `{str(attack.get('attack_success')).lower()}`",
            f"- confirmed_compromise: `{str(attack.get('confirmed_compromise')).lower()}`",
            f"- risk_score: `{attack.get('risk_score')}`",
            f"- attack_rows: `{case.get('attack_row_count', 1)}`",
            f"- control_scored_rows: `{case.get('control_scored_count', 0)}`",
            f"- control_asr_eligible_scored_rows (S): `{case.get('control_asr_eligible_scored_count', 0)}`",
            f"- control_N-1_rows: `{case.get('control_model_protocol_terminal_count', 0)}`",
            f"- control_protocol_denominator_rows (D=S+M): `{case.get('control_protocol_denominator_count', 0)}`",
            f"- control_protocol_completion_rate: `{format_rate(case.get('control_protocol_completion_rate'))}`",
            f"- control_model_nonconformance_rate: `{format_rate(case.get('control_model_nonconformance_rate'))}`",
            f"- observed_oracles: `{', '.join(attack.get('observed_oracles', []))}`",
            f"- oracle_json: `{attack.get('oracle_json')}`",
            "",
            "| Attack row | Progress | Attack success | Confirmed | Risk | Observed oracles |",
            "| --- | --- | --- | --- | ---: | --- |",
        ]
        for index, attack_row in enumerate(case.get("attacks", [attack]), start=1):
            lines.append(
                f"| {index} | `{attack_row.get('outcome_node', attack_row.get('progress_node'))}` | "
                f"`{str(attack_row.get('attack_success')).lower()}` | "
                f"`{str(attack_row.get('confirmed_compromise')).lower()}` | "
                f"{attack_row.get('risk_score')} | "
                f"`{', '.join(attack_row.get('observed_oracles', []))}` |"
            )
        lines += [
            "",
            "| Frame | Value |",
            "| --- | --- |",
        ]
        for key, value in case["frame"].items():
            lines.append(f"| {key} | `{value}` |")
        lines += [
            "",
            "| Control | Result class | Progress | Attack success | Confirmed | Observed oracles |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for control_type in CONTROL_TYPES:
            control = controls.get(control_type)
            if not control:
                lines.append(f"| {control_type} | missing | n/a | n/a | n/a | n/a |")
                continue
            lines.append(
                f"| {control_type} | `{control.get('result_class', 'legacy_scored')}` | "
                f"`{control.get('outcome_node', control.get('progress_node'))}` | "
                f"`{str(control.get('attack_success')).lower()}` | "
                f"`{str(control.get('confirmed_compromise')).lower()}` | "
                f"`{', '.join(control.get('observed_oracles', []))}` |"
            )
        lines.append("")
    lines += ["## Issues", ""]
    if pack["issues"]:
        lines += ["| Severity | Case | Message |", "| --- | --- | --- |"]
        for item in pack["issues"]:
            lines.append(f"| {item['severity']} | `{item['case_dir']}` | {item['message']} |")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def write_pack(pack: dict[str, Any], out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "case_study_evidence.json"
    md_path = out_dir / "case_study_evidence.md"
    json_path.write_text(json.dumps(pack, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_markdown(pack), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def main() -> int:
    parser = argparse.ArgumentParser(description="Export case-study evidence from paper reports.")
    parser.add_argument("--attack-label", default="")
    parser.add_argument("--attack-report-dir", default="")
    parser.add_argument("--control-label", action="append", default=[])
    parser.add_argument("--control-report-dir", action="append", default=[])
    parser.add_argument("--case-dir", action="append", default=[])
    parser.add_argument("--out-dir", default="")
    args = parser.parse_args()

    attack_dir = report_dir(args.attack_label, args.attack_report_dir)
    control_dirs = report_dirs(args.control_label, args.control_report_dir)
    default_out = attack_dir / "case_study_evidence"
    out_dir = Path(args.out_dir) if args.out_dir else default_out
    pack = build_evidence_pack(
        attack_dir=attack_dir,
        control_dirs=control_dirs,
        case_dirs=split_cli_values(args.case_dir),
    )
    paths = write_pack(pack, out_dir)
    for path in paths.values():
        print(path)
    return 0 if pack["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
