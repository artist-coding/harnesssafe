"""Generate a static external-validity calibration plan for appendix runs."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SUITE_LOCK = Path("docs/generated_artifacts/paper_suite_lock.json")
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/paper_external_validity_plan.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/paper_external_validity_plan.md")
DEFAULT_RUN_LABEL = "paper_external_validity_ext_hard"
DEFAULT_HARNESS = "claude"
DEFAULT_KIMI_MODEL = "kimi-k2.6"
DEFAULT_TIMEOUT_SEC = 300
DEFAULT_TRIALS = 1
DEFAULT_PER_SUITE = 6
CONTROL_TYPES = [
    "clean_control",
    "no_persist_control",
    "no_trigger_control",
    "cleanup_control",
]
ATTACK_ROWS_PER_CASE = 3
CONTROL_ROWS_PER_CASE = len(CONTROL_TYPES)
ROWS_PER_CASE = ATTACK_ROWS_PER_CASE + CONTROL_ROWS_PER_CASE


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def md_escape(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def case_sort_key(case: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(case.get("suite") or ""),
        str(case.get("paper_family") or ""),
        str(case.get("case_id") or ""),
        str(case.get("case_dir") or ""),
    )


def is_extended_hard_candidate(case: dict[str, Any]) -> bool:
    runtime_contract = case.get("boundary_runtime_contract")
    runtime_metric_eligible = not (
        isinstance(runtime_contract, dict)
        and runtime_contract.get("metric_eligible") is False
    )
    return (
        "extended" in case.get("case_sets", [])
        and str(case.get("oracle_strength") or "") == "hard_trace_oracle"
        and bool(case.get("main_table_eligible"))
        and not bool(case.get("attack_success_metric_excluded"))
        and runtime_metric_eligible
    )


def is_formal_case(case: dict[str, Any]) -> bool:
    runtime_contract = case.get("boundary_runtime_contract")
    return (
        str(case.get("oracle_strength") or "") == "hard_trace_oracle"
        and bool(case.get("main_table_eligible"))
        and not bool(case.get("attack_success_metric_excluded"))
        and not (
            isinstance(runtime_contract, dict)
            and runtime_contract.get("metric_eligible") is False
        )
    )


def control_types_for(case: dict[str, Any]) -> list[str]:
    declared = [
        str(item.get("control_type") or "")
        for item in case.get("control_suite", [])
        if isinstance(item, dict) and item.get("control_type")
    ]
    ordered = [control for control in CONTROL_TYPES if control in declared]
    ordered.extend(sorted(set(declared) - set(ordered)))
    return ordered


def select_round_robin_by_family(candidates: list[dict[str, Any]], per_suite: int) -> list[dict[str, Any]]:
    by_suite: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in sorted(candidates, key=case_sort_key):
        by_suite[str(case.get("suite") or "not_declared")].append(case)

    selected: list[dict[str, Any]] = []
    for suite in sorted(by_suite):
        family_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for case in by_suite[suite]:
            family_buckets[str(case.get("paper_family") or "not_declared")].append(case)
        for family in family_buckets:
            family_buckets[family].sort(key=case_sort_key)

        suite_selected: list[dict[str, Any]] = []
        family_order = sorted(family_buckets)
        while len(suite_selected) < per_suite and any(family_buckets.values()):
            for family in family_order:
                if len(suite_selected) >= per_suite:
                    break
                if family_buckets[family]:
                    suite_selected.append(family_buckets[family].pop(0))
        selected.extend(suite_selected)
    return selected


def summarize_counts(cases: list[dict[str, Any]], key: str) -> dict[str, int]:
    return dict(sorted(Counter(str(case.get(key) or "not_declared") for case in cases).items()))


def selected_case_row(case: dict[str, Any], rank: int) -> dict[str, Any]:
    frame = case.get("frame") if isinstance(case.get("frame"), dict) else {}
    return {
        "selection_rank": rank,
        "case_dir": str(case.get("case_dir") or ""),
        "suite": str(case.get("suite") or ""),
        "paper_family": str(case.get("paper_family") or ""),
        "case_id": str(case.get("case_id") or ""),
        "variant": str(case.get("variant") or ""),
        "reporting_track": str(case.get("reporting_track") or ""),
        "oracle_strength": str(case.get("oracle_strength") or ""),
        "violation_oracle_status": str(case.get("violation_oracle_status") or ""),
        "hard_violation_oracles": [str(item) for item in case.get("hard_violation_oracles", [])],
        "control_types": control_types_for(case),
        "frame": {
            "entry": str(frame.get("entry") or ""),
            "carrier": str(frame.get("carrier") or ""),
            "boundary": str(frame.get("boundary") or ""),
            "trigger": str(frame.get("trigger") or ""),
            "violation": str(frame.get("violation") or ""),
        },
        "selection_rationale": (
            "Extended hard-trace candidate selected by deterministic per-suite, "
            "per-family round-robin for appendix calibration only."
        ),
    }


def powershell_array(name: str, values: list[str]) -> str:
    lines = [f"${name} = @("]
    for value in values:
        escaped = value.replace("`", "``").replace('"', '`"')
        lines.append(f'  "{escaped}"')
    lines.append(")")
    return "\n".join(lines)


def build_run_commands(
    *,
    selected_case_dirs: list[str],
    run_label: str,
    control_label: str,
    harness: str,
    trials: int,
    timeout_sec: int,
    permission_profile: str,
    isolation_mode: str,
    kimi_model: str,
    model: str,
) -> dict[str, Any]:
    model_arg = f" -Model {model}" if model else ""
    attack_block = "\n".join(
        [
            powershell_array("externalCases", selected_case_dirs),
            "foreach ($case in $externalCases) {",
            (
                f"  .\\infra\\run_harness_case.ps1 -Harness {harness} "
                f'-CaseDir ".\\runs\\$case" '
                f"-PermissionProfile {permission_profile} "
                f"-IsolationMode {isolation_mode} "
                f"-RunLabel {run_label} "
                f"-TimeoutSec {timeout_sec}{model_arg}"
            ),
            "}",
        ]
    )
    control_block = "\n".join(
        [
            powershell_array("externalCases", selected_case_dirs),
            (
                f".\\infra\\run_paper_control_matrix.ps1 -RunLabel {control_label} "
                f"-CaseSet extended -Trials 1 -Harnesses {harness} "
                f"-KimiModel {kimi_model} "
                f"-TimeoutSec {timeout_sec} -SkipCompleted "
                "-CaseDirFilter $externalCases"
            ),
        ]
    )
    attack_report = (
        f"python infra\\report_active_run.py --label {run_label} --case-set extended "
        f"--all-matching-runs --run-kind attack --harness {harness}"
    )
    control_report = (
        f"python infra\\report_active_run.py --label {control_label} --case-set extended "
        f"--all-matching-runs --run-kind control --control-type all --harness {harness}"
    )
    quality_gate = (
        f"python infra\\check_paper_results.py --attack-label {run_label} "
        f"--control-label {control_label} --case-set extended "
        f"--min-attack-trials {trials} --min-control-trials 1 --control-type all "
        f"--expected-harness {harness} "
        f"--out runs\\_reports\\{run_label}\\paper_external_validity_quality_gate.md"
    )
    return {
        "note": "These commands are generated for explicit future execution; this planner does not run benchmark cases.",
        "case_list_powershell": powershell_array("externalCases", selected_case_dirs),
        "attack_commands_powershell": attack_block,
        "control_commands_powershell": control_block,
        "report_commands": [attack_report, control_report, quality_gate],
    }


def build_analysis_protocol(
    *,
    run_label: str,
    control_label: str,
    trials: int,
    coverage_cases: int,
    formal_cases: int,
) -> dict[str, str]:
    return {
        "runner_policy": (
            "Use run_harness_case.ps1 for all attack rows, matching run_harness_batch "
            "and the paper queue. The unified runner expands F3 multi-stage metadata "
            "into phase1_inject and phase2_trigger stages when present."
        ),
        "control_policy": (
            "Run run_paper_control_matrix.ps1 with the same CaseDirFilter and the "
            "declared matched controls. Keep these rows under the separate control "
            f"label {control_label}."
        ),
        "denominator_policy": (
            "Report these repeated calibration rows as a selected sensitivity slice. "
            f"They do not change membership of the {formal_cases}-case planned metric-eligible scope "
            f"within the {coverage_cases}-case runnable coverage, and must not replace the "
            "complete formal matrix."
        ),
        "completion_gate": (
            f"Require at least {trials} attack trial(s), at least one matched-control "
            "trial for each declared control type, and a passing check_paper_results.py "
            "quality gate before discussing calibration results."
        ),
        "interpretation_policy": (
            "Use the calibration to check whether extended hard-oracle behavior is "
            "directionally consistent by suite and family. Treat disagreement as "
            "heterogeneity evidence, not as a post-hoc change to the main claim."
        ),
        "artifact_policy": (
            f"Write reports under runs/_reports/{run_label}/ and keep public release "
            "gates separate from unpublished raw traces."
        ),
    }


def build_report(
    root: Path = ROOT,
    suite_lock: Path = DEFAULT_SUITE_LOCK,
    *,
    per_suite: int = DEFAULT_PER_SUITE,
    harness: str = DEFAULT_HARNESS,
    run_label: str = DEFAULT_RUN_LABEL,
    control_label: str = "",
    trials: int = DEFAULT_TRIALS,
    timeout_sec: int = DEFAULT_TIMEOUT_SEC,
    permission_profile: str = "max_permission",
    isolation_mode: str = "isolated_home",
    kimi_model: str = DEFAULT_KIMI_MODEL,
    model: str = "",
) -> dict[str, Any]:
    lock_path = suite_lock if suite_lock.is_absolute() else root / suite_lock
    lock = load_json(lock_path)
    cases = lock.get("cases", [])
    candidates = [case for case in cases if is_extended_hard_candidate(case)]
    selected = select_round_robin_by_family(candidates, per_suite=max(0, per_suite))
    selected_rows = [selected_case_row(case, index + 1) for index, case in enumerate(selected)]
    selected_case_dirs = [row["case_dir"] for row in selected_rows]
    effective_control_label = control_label or f"{run_label}_controls"
    candidate_by_suite = summarize_counts(candidates, "suite")
    selected_by_suite = dict(Counter(row["suite"] for row in selected_rows))
    selected_by_family = dict(Counter(row["paper_family"] for row in selected_rows))
    active_cases = as_int(lock.get("active_case_count")) or len(cases)
    formal_cases = sum(1 for case in cases if is_formal_case(case))
    diagnostic_cases = active_cases - formal_cases
    if formal_cases == active_cases:
        main_asr_boundary = (
            "The selected cases are an optional appendix calibration plan. "
            f"They are already members of the {formal_cases}-case metric-eligible set, "
            "which is identical to the runnable hard-oracle coverage; extra calibration "
            "trials are reported separately as sensitivity analysis."
        )
    else:
        main_asr_boundary = (
            "The selected cases are an optional appendix calibration plan. "
            f"They are already members of the {formal_cases}-case metric-eligible subset "
            f"within the {active_cases}-case runnable hard-oracle coverage; extra calibration "
            "trials are reported separately as sensitivity analysis."
        )

    return {
        "schema_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "suite_lock": str(suite_lock).replace("\\", "/"),
        "suite_lock_digest": lock.get("case_set_sha256", ""),
        "summary": {
            "active_cases": active_cases,
            "formal_cases": formal_cases,
            "diagnostic_cases": diagnostic_cases,
            "runnable_matrix_rows": active_cases * ROWS_PER_CASE,
            "formal_main_table_rows": formal_cases * ROWS_PER_CASE,
            "diagnostic_matrix_rows": diagnostic_cases * ROWS_PER_CASE,
            "candidate_cases": len(candidates),
            "selected_cases": len(selected_rows),
            "per_suite_target": per_suite,
            "candidate_by_suite": candidate_by_suite,
            "selected_by_suite": dict(sorted(selected_by_suite.items())),
            "selected_by_family": dict(sorted(selected_by_family.items())),
            "main_asr_boundary": main_asr_boundary,
        },
        "selection_policy": {
            "candidate_filter": (
                "case_sets contains extended; oracle_strength == hard_trace_oracle; "
                "main_table_eligible is true; attack_success_metric_excluded is false; "
                "boundary_runtime_contract.metric_eligible is not false"
            ),
            "selection_method": (
                "Within each suite, cases are sorted and selected by deterministic "
                "round-robin over paper_family until per_suite_target is reached."
            ),
            "execution_policy": (
                "Static planning only. Generating this file does not run benchmark cases, "
                "does not launch harnesses, does not read raw traces, and does not modify "
                "benchmark results."
            ),
            "claim_policy": (
                "Appendix calibration only; report repeated subset trials separately "
                f"from the complete {active_cases}-case runnable matrix and the "
                f"{formal_cases}-case formal main table."
            ),
        },
        "run_config": {
            "harness": harness,
            "run_label": run_label,
            "control_label": effective_control_label,
            "trials": trials,
            "timeout_sec": timeout_sec,
            "permission_profile": permission_profile,
            "isolation_mode": isolation_mode,
            "kimi_model": kimi_model,
            "model": model,
        },
        "analysis_protocol": build_analysis_protocol(
            run_label=run_label,
            control_label=effective_control_label,
            trials=trials,
            coverage_cases=active_cases,
            formal_cases=formal_cases,
        ),
        "selected_cases": selected_rows,
        "commands": build_run_commands(
            selected_case_dirs=selected_case_dirs,
            run_label=run_label,
            control_label=effective_control_label,
            harness=harness,
            trials=trials,
            timeout_sec=timeout_sec,
            permission_profile=permission_profile,
            isolation_mode=isolation_mode,
            kimi_model=kimi_model,
            model=model,
        ),
    }


def render_summary_table(report: dict[str, Any]) -> list[str]:
    summary = report["summary"]
    lines = [
        "| Field | Value |",
        "| --- | ---: |",
        f"| active_cases | {summary['active_cases']} |",
        f"| formal_cases | {summary['formal_cases']} |",
        f"| diagnostic_cases | {summary['diagnostic_cases']} |",
        f"| runnable_matrix_rows | {summary['runnable_matrix_rows']} |",
        f"| formal_main_table_rows | {summary['formal_main_table_rows']} |",
        f"| diagnostic_matrix_rows | {summary['diagnostic_matrix_rows']} |",
        f"| candidate_cases | {summary['candidate_cases']} |",
        f"| selected_cases | {summary['selected_cases']} |",
        f"| per_suite_target | {summary['per_suite_target']} |",
    ]
    return lines


def render_suite_table(counts: dict[str, int], selected_counts: dict[str, int]) -> list[str]:
    lines = [
        "| Suite | Candidate cases | Selected cases |",
        "| --- | ---: | ---: |",
    ]
    for suite in sorted(set(counts) | set(selected_counts)):
        lines.append(f"| {md_escape(suite)} | {counts.get(suite, 0)} | {selected_counts.get(suite, 0)} |")
    return lines


def render_case_table(rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Rank | Case | Suite | Family | Controls | Rationale |",
        "| ---: | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        controls = ", ".join(row.get("control_types", []))
        lines.append(
            f"| {row['selection_rank']} | `{md_escape(row['case_dir'])}` | "
            f"{md_escape(row['suite'])} | {md_escape(row['paper_family'])} | "
            f"{md_escape(controls)} | {md_escape(row['selection_rationale'])} |"
        )
    return lines


def render_protocol_table(protocol: dict[str, str]) -> list[str]:
    labels = {
        "runner_policy": "Runner",
        "control_policy": "Controls",
        "denominator_policy": "Denominator",
        "completion_gate": "Completion gate",
        "interpretation_policy": "Interpretation",
        "artifact_policy": "Artifacts",
    }
    lines = [
        "| Rule | Policy |",
        "| --- | --- |",
    ]
    for key, label in labels.items():
        lines.append(f"| {label} | {md_escape(protocol.get(key, ''))} |")
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    commands = report["commands"]
    run_config = report["run_config"]
    protocol = report["analysis_protocol"]
    lines = [
        "# External-Validity Calibration Plan",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- suite_lock: `{report['suite_lock']}`",
        f"- suite_lock_digest: `{str(report.get('suite_lock_digest') or '')[:16]}`",
        f"- run_label: `{run_config['run_label']}`",
        f"- control_label: `{run_config['control_label']}`",
        "",
        "## Claim Boundary",
        "",
        summary["main_asr_boundary"],
        "",
        "This is a static appendix plan. It does not run benchmark cases, does not "
        f"change the {summary['formal_cases']}-case formal membership within the "
        f"{summary['active_cases']}-case runnable coverage, and does not replace the "
        "complete main matrix.",
        "",
        "## Selection Summary",
        "",
        *render_summary_table(report),
        "",
        "## Candidate Pool By Suite",
        "",
        *render_suite_table(summary["candidate_by_suite"], summary["selected_by_suite"]),
        "",
        "## Selected Cases",
        "",
        *render_case_table(report["selected_cases"]),
        "",
        "## Appendix Analysis Protocol",
        "",
        *render_protocol_table(protocol),
        "",
        "## Future Execution Commands",
        "",
        "Run these only when intentionally starting the optional appendix calibration.",
        "",
        "Attack rows:",
        "",
        "```powershell",
        commands["attack_commands_powershell"],
        "```",
        "",
        "Matched controls:",
        "",
        "```powershell",
        commands["control_commands_powershell"],
        "```",
        "",
        "Reports after execution:",
        "",
        "```powershell",
        *commands["report_commands"],
        "```",
    ]
    return "\n".join(lines) + "\n"


def write_outputs(report: dict[str, Any], out_json: Path, out_md: Path) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an optional external-validity calibration plan.")
    parser.add_argument("--suite-lock", default=str(DEFAULT_SUITE_LOCK))
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    parser.add_argument("--per-suite", type=int, default=DEFAULT_PER_SUITE)
    parser.add_argument("--harness", choices=["claude", "codex", "hermes"], default=DEFAULT_HARNESS)
    parser.add_argument("--run-label", default=DEFAULT_RUN_LABEL)
    parser.add_argument("--control-label", default="")
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS)
    parser.add_argument("--timeout-sec", type=int, default=DEFAULT_TIMEOUT_SEC)
    parser.add_argument("--permission-profile", choices=["max_permission", "default_permission"], default="max_permission")
    parser.add_argument("--isolation-mode", choices=["isolated_home"], default="isolated_home")
    parser.add_argument("--kimi-model", default=DEFAULT_KIMI_MODEL)
    parser.add_argument("--model", default="")
    args = parser.parse_args()

    report = build_report(
        root=ROOT,
        suite_lock=Path(args.suite_lock),
        per_suite=args.per_suite,
        harness=args.harness,
        run_label=args.run_label,
        control_label=args.control_label,
        trials=args.trials,
        timeout_sec=args.timeout_sec,
        permission_profile=args.permission_profile,
        isolation_mode=args.isolation_mode,
        kimi_model=args.kimi_model,
        model=args.model,
    )
    json_path = ROOT / args.out_json
    md_path = ROOT / args.out_md
    write_outputs(report, json_path, md_path)
    print(str(json_path.relative_to(ROOT)).replace("\\", "/"))
    print(str(md_path.relative_to(ROOT)).replace("\\", "/"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
