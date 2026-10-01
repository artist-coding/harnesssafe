"""Generate the full-suite eligibility appendix for the paper artifact."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUITE_LOCK = Path("docs/generated_artifacts/paper_suite_lock.json")
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/paper_full_suite_eligibility.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/paper_full_suite_eligibility.md")
CASE_SETS = ["core", "extended", "exploratory", "all"]
ORACLE_STRENGTHS = ["hard_trace_oracle", "soft_semantic_oracle", "propagation_only"]
ATTACK_ROWS_PER_CASE = 3
CONTROL_ROWS_PER_CASE = 4
ROWS_PER_CASE = ATTACK_ROWS_PER_CASE + CONTROL_ROWS_PER_CASE


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def pct(numerator: int, denominator: int) -> str | None:
    if denominator <= 0:
        return None
    return f"{(numerator / denominator) * 100:.1f}%"


def display_rate(value: Any) -> str:
    return "n/a" if value is None else str(value)


def md_escape(value: Any) -> str:
    text = str(value or "")
    return text.replace("|", "\\|").replace("\n", " ")


def first_case_set(case: dict[str, Any]) -> str:
    # ``core`` and ``all`` are formal-scope aliases. Prefer the legacy
    # reporting stratum for secondary tables when one is present.
    case_sets = [
        str(item)
        for item in case.get("case_sets", [])
        if str(item) not in {"all", "core"}
    ]
    return case_sets[0] if case_sets else "core"


def is_main_asr_case(case: dict[str, Any]) -> bool:
    runtime_contract = case.get("boundary_runtime_contract")
    runtime_metric_eligible = not (
        isinstance(runtime_contract, dict)
        and runtime_contract.get("metric_eligible") is False
    )
    return (
        bool(case.get("main_table_eligible"))
        and case.get("oracle_strength") == "hard_trace_oracle"
        and not bool(case.get("attack_success_metric_excluded"))
        and runtime_metric_eligible
    )


def normalized_counter(values: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(str(value or "not_declared") for value in values).items()))


def reason_for_case(case: dict[str, Any]) -> str:
    case_set = first_case_set(case)
    oracle_strength = str(case.get("oracle_strength") or "")
    violation_status = str(case.get("violation_oracle_status") or "")
    reporting_track = str(case.get("reporting_track") or "")
    runtime_contract = case.get("boundary_runtime_contract")
    if is_main_asr_case(case):
        return (
            "Included in the formal metric-eligible subset: hard-oracle case "
            "with no ASR-exclusion flag. Reporting track is a secondary stratum only."
        )
    if (
        bool(case.get("attack_success_metric_excluded"))
        and isinstance(runtime_contract, dict)
        and runtime_contract.get("metric_eligible") is False
    ):
        reason = str(runtime_contract.get("metric_exclusion_reason") or "").strip()
        suffix = f" Reason: {reason}" if reason else ""
        return (
            "Runnable boundary-runtime diagnostic excluded from formal ASR until "
            "hard session provenance is available."
            + suffix
        )
    if bool(case.get("attack_success_metric_excluded")) and violation_status == "missing_analyzer":
        return (
            "Extended diagnostic case excluded from main ASR because the desired "
            "resource/limit raw analyzer signal is not implemented in the current evaluator."
        )
    if bool(case.get("attack_success_metric_excluded")) and oracle_strength == "propagation_only":
        return (
            "Extended diagnostic case excluded from main ASR because it checks "
            "carrier propagation/persistence rather than a case-specific unsafe-action oracle."
        )
    if oracle_strength == "soft_semantic_oracle":
        return (
            "Extended coverage case kept out of main ASR because its primary "
            "oracle is semantic/judgment-based rather than a hard trace or tool artifact."
        )
    if case_set == "exploratory" or reporting_track == "exploratory_case_study":
        suffix = " It is selected as a representative case-study seed." if case.get("case_study_representative") else ""
        return (
            "Exploratory reporting stratum retained for secondary analysis. A case in "
            "this stratum still enters formal ASR when it is hard-oracle and eligible."
            + suffix
        )
    if case_set == "extended" or reporting_track == "extended_benchmark":
        return (
            "Extended reporting stratum retained for secondary analysis. A case in "
            "this stratum still enters the planned metric-eligible case scope."
        )
    return "Not selected for formal ASR because it is not an eligible hard-oracle case."


def policy_for_case_set(case_set: str, *, coverage_cases: int, formal_cases: int) -> str:
    if case_set == "core":
        return (
            f"Compatibility alias for all: selects the same {coverage_cases} active "
            f"hard-oracle cases; {formal_cases} are currently metric-eligible."
        )
    if case_set == "extended":
        return (
            "Secondary reporting stratum only; it does not independently change formal eligibility."
        )
    if case_set == "exploratory":
        return (
            "Secondary T3/cross-boundary stratum; eligible hard-oracle cases remain in formal ASR."
        )
    return (
        f"Canonical runnable coverage: all {coverage_cases} active hard-oracle cases; "
        f"formal metrics use the {formal_cases} eligible cases."
    )


def count_in_cases(cases: list[dict[str, Any]], predicate) -> int:
    return sum(1 for case in cases if predicate(case))


def case_set_counts(cases: list[dict[str, Any]]) -> dict[str, int]:
    return {case_set: count_in_cases(cases, lambda case, case_set=case_set: case_set in case.get("case_sets", [])) for case_set in CASE_SETS}


def aggregate_case_set(case_set: str, cases: list[dict[str, Any]]) -> dict[str, Any]:
    selected = [case for case in cases if case_set in case.get("case_sets", [])]
    hard = count_in_cases(selected, lambda case: case.get("oracle_strength") == "hard_trace_oracle")
    soft = count_in_cases(selected, lambda case: case.get("oracle_strength") == "soft_semantic_oracle")
    propagation = count_in_cases(selected, lambda case: case.get("oracle_strength") == "propagation_only")
    main = count_in_cases(selected, is_main_asr_case)
    excluded = count_in_cases(selected, lambda case: bool(case.get("attack_success_metric_excluded")))
    return {
        "case_set": case_set,
        "cases": len(selected),
        "main_asr_cases": main,
        "main_asr_fraction": pct(main, len(selected)),
        "hard_trace_oracle": hard,
        "soft_semantic_oracle": soft,
        "propagation_only": propagation,
        "attack_success_metric_excluded": excluded,
        "case_study_representatives": count_in_cases(selected, lambda case: bool(case.get("case_study_representative"))),
        "policy": policy_for_case_set(
            case_set,
            coverage_cases=len(cases),
            formal_cases=count_in_cases(cases, is_main_asr_case),
        ),
    }


def aggregate_group(cases: list[dict[str, Any]], group_keys: list[str]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        key_values: list[str] = []
        for key in group_keys:
            if key == "case_set":
                key_values.append(first_case_set(case))
            else:
                key_values.append(str(case.get(key) or "not_declared"))
        groups[tuple(key_values)].append(case)
    rows: list[dict[str, Any]] = []
    for key_tuple, selected in sorted(groups.items()):
        row = {key: key_tuple[index] for index, key in enumerate(group_keys)}
        row.update(
            {
                "cases": len(selected),
                "main_asr_cases": count_in_cases(selected, is_main_asr_case),
                "hard_trace_oracle": count_in_cases(selected, lambda case: case.get("oracle_strength") == "hard_trace_oracle"),
                "soft_semantic_oracle": count_in_cases(selected, lambda case: case.get("oracle_strength") == "soft_semantic_oracle"),
                "propagation_only": count_in_cases(selected, lambda case: case.get("oracle_strength") == "propagation_only"),
                "attack_success_metric_excluded": count_in_cases(selected, lambda case: bool(case.get("attack_success_metric_excluded"))),
                "case_study_representatives": count_in_cases(selected, lambda case: bool(case.get("case_study_representative"))),
            }
        )
        rows.append(row)
    return rows


def family_rationale(row: dict[str, Any]) -> str:
    case_set = row.get("case_set", "")
    if row.get("main_asr_cases", 0):
        return "Contributes at least one hard-oracle case to the main ASR subset."
    if row.get("soft_semantic_oracle", 0) and row.get("cases") == row.get("soft_semantic_oracle"):
        return "Soft-semantic coverage only; appendix/secondary analysis, not main ASR."
    if row.get("propagation_only", 0):
        return "Propagation-only diagnostic coverage; excluded from ASR."
    if row.get("attack_success_metric_excluded", 0):
        return "Diagnostic coverage with analyzer-gap exclusion from ASR."
    if case_set == "exploratory":
        return "Exploratory T3/cross-boundary coverage; appendix/case-study use."
    return "Hard-oracle coverage included in the planned metric-eligible case scope."


def case_rows(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for case in sorted(cases, key=lambda item: item.get("case_dir", "")):
        case_set = first_case_set(case)
        rows.append(
            {
                "case_dir": case.get("case_dir", ""),
                "suite": case.get("suite", ""),
                "paper_family": case.get("paper_family", ""),
                "case_set": case_set,
                "reporting_track": case.get("reporting_track", ""),
                "oracle_strength": case.get("oracle_strength", ""),
                "violation_oracle_status": case.get("violation_oracle_status", ""),
                "paper_priority": case.get("paper_priority", ""),
                "main_asr": is_main_asr_case(case),
                "attack_success_metric_excluded": bool(case.get("attack_success_metric_excluded")),
                "case_study_representative": bool(case.get("case_study_representative")),
                "eligibility_reason": reason_for_case(case),
            }
        )
    return rows


def build_report(root: Path = ROOT, suite_lock: Path = DEFAULT_SUITE_LOCK) -> dict[str, Any]:
    lock_path = suite_lock if suite_lock.is_absolute() else root / suite_lock
    lock = load_json(lock_path)
    cases = lock.get("cases", [])
    per_case = case_rows(cases)
    family_rows = aggregate_group(cases, ["suite", "paper_family", "case_set"])
    for row in family_rows:
        row["eligibility_rationale"] = family_rationale(row)
    active_cases = len(cases)
    main_asr_cases = count_in_cases(cases, is_main_asr_case)
    diagnostic_cases = active_cases - main_asr_cases
    summary = {
        "active_cases": active_cases,
        "core_cases": case_set_counts(cases).get("core", 0),
        "extended_cases": case_set_counts(cases).get("extended", 0),
        "exploratory_cases": case_set_counts(cases).get("exploratory", 0),
        "main_asr_cases": main_asr_cases,
        "diagnostic_cases": diagnostic_cases,
        "runnable_matrix_rows": active_cases * ROWS_PER_CASE,
        "formal_main_table_rows": main_asr_cases * ROWS_PER_CASE,
        "diagnostic_matrix_rows": diagnostic_cases * ROWS_PER_CASE,
        "hard_trace_oracle_cases": count_in_cases(cases, lambda case: case.get("oracle_strength") == "hard_trace_oracle"),
        "soft_semantic_oracle_cases": count_in_cases(cases, lambda case: case.get("oracle_strength") == "soft_semantic_oracle"),
        "propagation_only_cases": count_in_cases(cases, lambda case: case.get("oracle_strength") == "propagation_only"),
        "attack_success_metric_excluded_cases": count_in_cases(cases, lambda case: bool(case.get("attack_success_metric_excluded"))),
        "case_study_representatives": count_in_cases(cases, lambda case: bool(case.get("case_study_representative"))),
        "claim_boundary": (
            f"All {active_cases} active hard-oracle cases define runnable benchmark coverage. "
            f"The planned/design-time case scope contains {main_asr_cases} metric-eligible cases; "
            f"the remaining {diagnostic_cases} "
            "cases are reported separately. Realized conditional ASR uses only ASR-eligible "
            "N0-N5b scored attack rows and excludes N-1. The core "
            "selector is a compatibility alias for all; reporting tracks are secondary strata only."
        ),
    }
    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "suite_lock": str(suite_lock).replace("\\", "/"),
        # Bind derived eligibility artifacts to the complete runtime-input
        # lock. ``case_set_sha256`` remains only as a v1 compatibility
        # fallback for historical lock files.
        "suite_lock_digest": lock.get("suite_content_sha256")
        or lock.get("case_set_sha256", ""),
        "suite_lock_attestation_sha256": lock.get("attestation_sha256", ""),
        "suite_lock_schema_version": lock.get("schema_version"),
        "suite_lock_git_commit_sha": lock.get("git_commit_sha", ""),
        "suite_lock_git_worktree_dirty": lock.get("git_worktree_dirty"),
        "summary": summary,
        "case_sets": [aggregate_case_set(case_set, cases) for case_set in CASE_SETS],
        "by_suite": aggregate_group(cases, ["suite"]),
        "by_oracle_strength": aggregate_group(cases, ["oracle_strength"]),
        "by_reporting_track": aggregate_group(cases, ["reporting_track"]),
        "by_family": family_rows,
        "cases": per_case,
    }


def render_case_set_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Case set | Cases | Main ASR | Main ASR fraction | Hard | Soft | Propagation | ASR-excluded | Case-study reps | Policy |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {row['case_set']} | {row['cases']} | {row['main_asr_cases']} | "
            f"{display_rate(row.get('main_asr_fraction'))} | "
            f"{row['hard_trace_oracle']} | {row['soft_semantic_oracle']} | "
            f"{row['propagation_only']} | {row['attack_success_metric_excluded']} | "
            f"{row['case_study_representatives']} | {md_escape(row['policy'])} |"
        )
    return lines


def render_group_table(rows: list[dict[str, Any]], group_cols: list[str]) -> list[str]:
    headers = [col.replace("_", " ").title() for col in group_cols]
    lines = [
        "| " + " | ".join([*headers, "Cases", "Main ASR", "Hard", "Soft", "Propagation", "ASR-excluded", "Case-study reps"]) + " |",
        "| " + " | ".join(["---" for _ in group_cols] + ["---:", "---:", "---:", "---:", "---:", "---:", "---:"]) + " |",
    ]
    for row in rows:
        prefix = [md_escape(row.get(col, "")) for col in group_cols]
        values = [
            str(row.get("cases", 0)),
            str(row.get("main_asr_cases", 0)),
            str(row.get("hard_trace_oracle", 0)),
            str(row.get("soft_semantic_oracle", 0)),
            str(row.get("propagation_only", 0)),
            str(row.get("attack_success_metric_excluded", 0)),
            str(row.get("case_study_representatives", 0)),
        ]
        lines.append("| " + " | ".join([*prefix, *values]) + " |")
    return lines


def render_family_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Suite | Family | Case set | Cases | Main ASR | Hard | Soft | Propagation | ASR-excluded | Rationale |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in rows:
        lines.append(
            f"| {md_escape(row['suite'])} | {md_escape(row['paper_family'])} | {row['case_set']} | "
            f"{row['cases']} | {row['main_asr_cases']} | {row['hard_trace_oracle']} | "
            f"{row['soft_semantic_oracle']} | {row['propagation_only']} | "
            f"{row['attack_success_metric_excluded']} | {md_escape(row['eligibility_rationale'])} |"
        )
    return lines


def render_case_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Case | Suite | Family | Set | Oracle | Main ASR | ASR-excluded | Reason |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| `{md_escape(row['case_dir'])}` | {md_escape(row['suite'])} | "
            f"{md_escape(row['paper_family'])} | {row['case_set']} | "
            f"{md_escape(row['oracle_strength'])} | `{str(row['main_asr']).lower()}` | "
            f"`{str(row['attack_success_metric_excluded']).lower()}` | "
            f"{md_escape(row['eligibility_reason'])} |"
        )
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Full-Suite Eligibility Appendix",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- suite_lock: `{report['suite_lock']}`",
        f"- suite_lock_digest: `{str(report.get('suite_lock_digest') or '')[:16]}`",
        f"- suite_lock_attestation: `{str(report.get('suite_lock_attestation_sha256') or '')[:16]}`",
        f"- suite_lock_git_commit: `{str(report.get('suite_lock_git_commit_sha') or '')}`",
        f"- suite_lock_git_worktree_dirty: `{str(report.get('suite_lock_git_worktree_dirty')).lower()}`",
        f"- active_cases: `{summary['active_cases']}`",
        f"- benchmark_coverage_cases: `{summary['active_cases']}`",
        f"- main_quantitative_asr_cases: `{summary['main_asr_cases']}`",
        f"- diagnostic_cases: `{summary['diagnostic_cases']}`",
        f"- runnable_matrix_rows: `{summary['runnable_matrix_rows']}`",
        f"- formal_main_table_rows: `{summary['formal_main_table_rows']}`",
        f"- diagnostic_matrix_rows: `{summary['diagnostic_matrix_rows']}`",
        f"- core_cases: `{summary['core_cases']}`",
        f"- extended_cases: `{summary['extended_cases']}`",
        f"- exploratory_cases: `{summary['exploratory_cases']}`",
        f"- hard_trace_oracle_cases: `{summary['hard_trace_oracle_cases']}`",
        f"- soft_semantic_oracle_cases: `{summary['soft_semantic_oracle_cases']}`",
        f"- propagation_only_cases: `{summary['propagation_only_cases']}`",
        f"- attack_success_metric_excluded_cases: `{summary['attack_success_metric_excluded_cases']}`",
        "",
        "## Claim Boundary",
        "",
        summary["claim_boundary"],
        "",
        "This appendix is an eligibility map, not an ASR result. It distinguishes full runnable "
        f"coverage ({summary['active_cases']} cases; {summary['runnable_matrix_rows']} rows) from "
        f"the formal main table ({summary['main_asr_cases']} cases; "
        f"{summary['formal_main_table_rows']} rows) and diagnostics "
        f"({summary['diagnostic_cases']} cases; {summary['diagnostic_matrix_rows']} rows). "
        "Eligibility is derived only from the active manifest and runtime contract; result snapshots do not define it.",
        "",
        "## Case-Set Policy",
        "",
        *render_case_set_table(report["case_sets"]),
        "",
        "## Suite Eligibility Summary",
        "",
        *render_group_table(report["by_suite"], ["suite"]),
        "",
        "## Oracle-Strength Eligibility Summary",
        "",
        *render_group_table(report["by_oracle_strength"], ["oracle_strength"]),
        "",
        "## Reporting Track Summary",
        "",
        *render_group_table(report["by_reporting_track"], ["reporting_track"]),
        "",
        "## Family Eligibility Table",
        "",
        *render_family_table(report["by_family"]),
        "",
        "## Per-Case Eligibility Table",
        "",
        *render_case_table(report["cases"]),
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the full-suite eligibility appendix.")
    parser.add_argument("--suite-lock", default=str(DEFAULT_SUITE_LOCK))
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    args = parser.parse_args()

    report = build_report(ROOT, Path(args.suite_lock))
    json_path = ROOT / args.out_json
    md_path = ROOT / args.out_md
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    print(str(json_path.relative_to(ROOT)).replace("\\", "/"))
    print(str(md_path.relative_to(ROOT)).replace("\\", "/"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
