"""Generate reviewer-facing oracle coverage artifacts for the paper."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    from infra.check_paper_results import (
        is_scored_row as _is_scored_normalized_row,
        is_terminal_model_protocol_row,
    )
except ModuleNotFoundError:  # direct `python infra/generate_oracle_coverage_report.py`
    from check_paper_results import (  # type: ignore
        is_scored_row as _is_scored_normalized_row,
        is_terminal_model_protocol_row,
    )


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ATTACK_LABEL = "paper_core_20260625"
DEFAULT_CONTROL_LABEL = "paper_controls_core_20260625"
DEFAULT_SUITE_LOCK = Path("docs/generated_artifacts/paper_suite_lock.json")
DEFAULT_OUT_JSON = Path("docs/generated_artifacts/paper_oracle_coverage.json")
DEFAULT_OUT_MD = Path("docs/generated_artifacts/paper_oracle_coverage.md")


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


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return bool(value)


def rate(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def rate_pct(value: Any) -> str:
    if value is None:
        return "n/a"
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "n/a"


def is_scored_report_row(row: dict[str, Any]) -> bool:
    """Classify current rows strictly while retaining old synthetic fixtures.

    Historical hand-written report fixtures predate ``run_valid`` and often
    omit ``has_oracle``.  Current normalized rows always carry ``run_valid``
    and are delegated to the paper-result classifier without relaxation.
    """

    if "run_valid" not in row:
        legacy = dict(row)
        legacy.setdefault("has_oracle", True)
        return _is_scored_normalized_row(legacy)
    return _is_scored_normalized_row(row)


def is_accounted_terminal_row(row: dict[str, Any]) -> bool:
    return is_scored_report_row(row) or is_terminal_model_protocol_row(row)


def is_asr_eligible_scored_row(row: dict[str, Any]) -> bool:
    if not is_scored_report_row(row):
        return False
    if "asr_eligible" not in row and "attack_success_metric_excluded" not in row:
        return True
    return boolish(row.get("asr_eligible")) and not boolish(
        row.get("attack_success_metric_excluded")
    )


def normalize_oracles(value: Any) -> list[str]:
    if isinstance(value, list):
        tokens = [str(item).strip() for item in value]
    elif isinstance(value, str):
        tokens = [part.strip() for part in re.split(r"[,;\s]+", value)]
    else:
        tokens = []
    return sorted({token for token in tokens if token.startswith("O_")})


def case_in_set(case: dict[str, Any], case_set: str) -> bool:
    if case_set == "all":
        return True
    case_sets = case.get("case_sets")
    if isinstance(case_sets, list):
        return case_set in {str(item) for item in case_sets}
    if case_set == "core":
        return bool(case.get("main_table_eligible"))
    if case_set == "extended":
        return case.get("reporting_track") == "extended_benchmark"
    if case_set == "exploratory":
        return case.get("reporting_track") == "exploratory_case_study"
    raise ValueError(f"unknown case_set: {case_set}")


def load_summaries(dirs: list[Path]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for directory in dirs:
        path = directory / "summary.json"
        if path.is_file():
            summaries.append(load_json(path))
    return summaries


def oracle_columns(row: dict[str, Any]) -> list[str]:
    return sorted(
        key for key, value in row.items() if key.startswith("O_") and boolish(value)
    )


def unique_sorted(values: Iterable[str]) -> list[str]:
    return sorted({str(value) for value in values if str(value)})


def counter_rows(counter: Counter[str]) -> list[dict[str, Any]]:
    return [{"oracle": key, "count": value} for key, value in sorted(counter.items())]


def top_counter_rows(counter: Counter[str], limit: int = 20) -> list[dict[str, Any]]:
    return [{"oracle": key, "count": value} for key, value in counter.most_common(limit)]


def aggregate_design_cases(cases: list[dict[str, Any]]) -> dict[str, Any]:
    strength_counts: Counter[str] = Counter()
    declared_counts: Counter[str] = Counter()
    hard_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    by_suite: dict[str, dict[str, Any]] = {}
    by_family: dict[tuple[str, str], dict[str, Any]] = {}

    for case in cases:
        suite = str(case.get("suite") or case.get("canonical_suite") or "")
        family = str(case.get("paper_family") or "")
        strength = str(case.get("oracle_strength") or "unspecified")
        declared = normalize_oracles(case.get("oracles"))
        hard = normalize_oracles(case.get("hard_violation_oracles"))
        status = str(case.get("violation_oracle_status") or "declared")

        strength_counts[strength] += 1
        status_counts[status] += 1
        declared_counts.update(declared)
        hard_counts.update(hard)

        suite_row = by_suite.setdefault(
            suite,
            {
                "suite": suite,
                "cases": 0,
                "oracle_strength_counts": Counter(),
                "cases_with_declared_oracles": 0,
                "cases_with_hard_violation_oracles": 0,
                "declared_oracles": set(),
                "hard_violation_oracles": set(),
            },
        )
        family_row = by_family.setdefault(
            (suite, family),
            {
                "suite": suite,
                "paper_family": family,
                "cases": 0,
                "oracle_strength_counts": Counter(),
                "cases_with_declared_oracles": 0,
                "cases_with_hard_violation_oracles": 0,
                "declared_oracles": set(),
                "hard_violation_oracles": set(),
            },
        )
        for row in [suite_row, family_row]:
            row["cases"] += 1
            row["oracle_strength_counts"][strength] += 1
            if declared:
                row["cases_with_declared_oracles"] += 1
            if hard:
                row["cases_with_hard_violation_oracles"] += 1
            row["declared_oracles"].update(declared)
            row["hard_violation_oracles"].update(hard)

    def freeze_row(row: dict[str, Any]) -> dict[str, Any]:
        strengths = row["oracle_strength_counts"]
        return {
            **{key: value for key, value in row.items() if key != "oracle_strength_counts"},
            "hard_trace_oracle": as_int(strengths.get("hard_trace_oracle")),
            "propagation_only": as_int(strengths.get("propagation_only")),
            "soft_semantic_oracle": as_int(strengths.get("soft_semantic_oracle")),
            "other_oracle_strength": sum(
                value
                for key, value in strengths.items()
                if key not in {"hard_trace_oracle", "propagation_only", "soft_semantic_oracle"}
            ),
            "declared_oracles": sorted(row["declared_oracles"]),
            "hard_violation_oracles": sorted(row["hard_violation_oracles"]),
        }

    return {
        "case_count": len(cases),
        "oracle_strength_counts": dict(sorted(strength_counts.items())),
        "oracle_status_counts": dict(sorted(status_counts.items())),
        "cases_with_declared_oracles": sum(1 for case in cases if normalize_oracles(case.get("oracles"))),
        "cases_with_hard_violation_oracles": sum(
            1 for case in cases if normalize_oracles(case.get("hard_violation_oracles"))
        ),
        "declared_oracle_counts": counter_rows(declared_counts),
        "hard_violation_oracle_counts": counter_rows(hard_counts),
        "by_suite": sorted((freeze_row(row) for row in by_suite.values()), key=lambda row: row["suite"]),
        "by_family": sorted(
            (freeze_row(row) for row in by_family.values()),
            key=lambda row: (row["suite"], row["paper_family"]),
        ),
    }


def aggregate_observed_rows(
    *,
    summaries: list[dict[str, Any]],
    design_by_case_dir: dict[str, dict[str, Any]],
    run_kind: str,
) -> dict[str, Any]:
    rows = [
        row
        for summary in summaries
        for row in summary.get("rows", [])
        if isinstance(row, dict) and (not run_kind or str(row.get("run_kind") or "") == run_kind)
    ]
    scored_rows = [row for row in rows if is_scored_report_row(row)]
    protocol_rows = [row for row in rows if is_terminal_model_protocol_row(row)]
    accounted_rows = [row for row in rows if is_accounted_terminal_row(row)]
    unaccounted_rows = [row for row in rows if not is_accounted_terminal_row(row)]
    asr_eligible_rows = [row for row in scored_rows if is_asr_eligible_scored_row(row)]

    oracle_counts: Counter[str] = Counter()
    factual_scored_oracle_counts: Counter[str] = Counter()
    declared_hits: Counter[str] = Counter()
    hard_hits: Counter[str] = Counter()
    diagnostic_oracle_counts: Counter[str] = Counter()
    protocol_diagnostic_oracle_counts: Counter[str] = Counter()
    by_suite: dict[tuple[str, str], dict[str, Any]] = {}
    rows_with_any_oracle = 0
    diagnostic_rows_with_any_oracle = 0
    protocol_rows_with_any_oracle = 0
    attack_success_rows = sum(
        1 for row in asr_eligible_rows if boolish(row.get("attack_success"))
    )
    factual_attack_success_rows = sum(
        1 for row in scored_rows if boolish(row.get("attack_success"))
    )
    asr_attack_success_rows = attack_success_rows
    confirmed_rows = sum(
        1
        for row in asr_eligible_rows
        if boolish(row.get("confirmed_compromise"))
    )
    factual_confirmed_rows = sum(
        1 for row in scored_rows if boolish(row.get("confirmed_compromise"))
    )
    success_with_declared_hit = 0
    success_with_hard_hit = 0

    for row in rows:
        observed = oracle_columns(row)
        scored = is_scored_report_row(row)
        protocol = is_terminal_model_protocol_row(row)
        accounted = scored or protocol
        asr_eligible = is_asr_eligible_scored_row(row)
        if scored:
            factual_scored_oracle_counts.update(observed)
        if asr_eligible:
            oracle_counts.update(observed)
            if observed:
                rows_with_any_oracle += 1
        elif not scored:
            diagnostic_oracle_counts.update(observed)
            if observed:
                diagnostic_rows_with_any_oracle += 1
            if protocol:
                protocol_diagnostic_oracle_counts.update(observed)
                protocol_rows_with_any_oracle += int(bool(observed))

        case_dir = str(row.get("case_dir") or "")
        design = design_by_case_dir.get(case_dir, {})
        declared = set(normalize_oracles(design.get("oracles")))
        hard = set(normalize_oracles(design.get("hard_violation_oracles")))
        observed_set = set(observed)
        declared_overlap = observed_set & declared
        hard_overlap = observed_set & hard
        if asr_eligible:
            declared_hits.update(declared_overlap)
            hard_hits.update(hard_overlap)
            if boolish(row.get("attack_success")) and declared_overlap:
                success_with_declared_hit += 1
            if boolish(row.get("attack_success")) and hard_overlap:
                success_with_hard_hit += 1

        suite = str(row.get("suite") or design.get("suite") or design.get("canonical_suite") or "")
        family = str(row.get("paper_family") or design.get("paper_family") or "")
        bucket = by_suite.setdefault(
            (suite, family),
            {
                "suite": suite,
                "paper_family": family,
                "rows": 0,
                "scored_rows": 0,
                "model_protocol_terminal_rows": 0,
                "accounted_terminal_rows": 0,
                "unaccounted_rows": 0,
                "asr_eligible_scored_rows": 0,
                "attack_success_rows": 0,
                "factual_attack_success_rows": 0,
                "asr_attack_success_rows": 0,
                "confirmed_rows": 0,
                "factual_confirmed_rows": 0,
                "rows_with_any_oracle": 0,
                "factual_rows_with_any_oracle": 0,
                "diagnostic_rows_with_any_oracle": 0,
                "observed_oracles": set(),
                "factual_observed_oracles": set(),
                "observed_declared_oracles": set(),
                "observed_hard_violation_oracles": set(),
                "diagnostic_oracles": set(),
            },
        )
        bucket["rows"] += 1
        if scored:
            bucket["scored_rows"] += 1
            bucket["factual_attack_success_rows"] += int(
                boolish(row.get("attack_success"))
            )
            bucket["factual_confirmed_rows"] += int(
                boolish(row.get("confirmed_compromise"))
            )
            bucket["factual_rows_with_any_oracle"] += int(bool(observed))
            bucket["factual_observed_oracles"].update(observed)
            if asr_eligible:
                bucket["asr_eligible_scored_rows"] += 1
                bucket["attack_success_rows"] += int(
                    boolish(row.get("attack_success"))
                )
                bucket["asr_attack_success_rows"] += int(
                    boolish(row.get("attack_success"))
                )
                bucket["confirmed_rows"] += int(
                    boolish(row.get("confirmed_compromise"))
                )
                bucket["rows_with_any_oracle"] += int(bool(observed))
                bucket["observed_oracles"].update(observed)
                bucket["observed_declared_oracles"].update(declared_overlap)
                bucket["observed_hard_violation_oracles"].update(hard_overlap)
        else:
            bucket["diagnostic_rows_with_any_oracle"] += int(bool(observed))
            bucket["diagnostic_oracles"].update(observed)
        if protocol:
            bucket["model_protocol_terminal_rows"] += 1
        if accounted:
            bucket["accounted_terminal_rows"] += 1
        else:
            bucket["unaccounted_rows"] += 1

    family_rows = []
    for bucket in by_suite.values():
        scored_count = as_int(bucket["scored_rows"])
        protocol_count = as_int(bucket["model_protocol_terminal_rows"])
        accounted_count = as_int(bucket["accounted_terminal_rows"])
        asr_eligible_count = as_int(bucket["asr_eligible_scored_rows"])
        protocol_denominator_count = asr_eligible_count + protocol_count
        family_rows.append(
            {
                **{key: value for key, value in bucket.items() if not isinstance(value, set)},
                "n_minus_1_rows": protocol_count,
                "protocol_denominator_rows": protocol_denominator_count,
                "protocol_completion_rate": rate(
                    asr_eligible_count, protocol_denominator_count
                ),
                "model_nonconformance_rate": rate(
                    protocol_count, protocol_denominator_count
                ),
                "conditional_asr": rate(
                    as_int(bucket["asr_attack_success_rows"]), asr_eligible_count
                ),
                "end_to_end_attack_rate": rate(
                    as_int(bucket["asr_attack_success_rows"]),
                    protocol_denominator_count,
                ),
                "observed_oracles": sorted(bucket["observed_oracles"]),
                "factual_observed_oracles": sorted(
                    bucket["factual_observed_oracles"]
                ),
                "observed_declared_oracles": sorted(bucket["observed_declared_oracles"]),
                "observed_hard_violation_oracles": sorted(bucket["observed_hard_violation_oracles"]),
                "diagnostic_oracles": sorted(bucket["diagnostic_oracles"]),
            }
        )

    accounted_count = len(accounted_rows)
    protocol_denominator_count = len(asr_eligible_rows) + len(protocol_rows)
    return {
        "row_count": len(rows),
        "observed_rows": len(rows),
        "scored_rows": len(scored_rows),
        "model_protocol_terminal_rows": len(protocol_rows),
        "n_minus_1_rows": len(protocol_rows),
        "accounted_terminal_rows": accounted_count,
        "protocol_denominator_rows": protocol_denominator_count,
        "unaccounted_rows": len(unaccounted_rows),
        "asr_eligible_scored_rows": len(asr_eligible_rows),
        "rows_with_any_oracle": rows_with_any_oracle,
        "diagnostic_rows_with_any_oracle": diagnostic_rows_with_any_oracle,
        "model_protocol_rows_with_any_oracle": protocol_rows_with_any_oracle,
        "attack_success_rows": attack_success_rows,
        "factual_attack_success_rows": factual_attack_success_rows,
        "asr_attack_success_rows": asr_attack_success_rows,
        "confirmed_rows": confirmed_rows,
        "factual_confirmed_rows": factual_confirmed_rows,
        "protocol_completion_rate": rate(
            len(asr_eligible_rows), protocol_denominator_count
        ),
        "model_nonconformance_rate": rate(
            len(protocol_rows), protocol_denominator_count
        ),
        "conditional_asr": rate(asr_attack_success_rows, len(asr_eligible_rows)),
        "end_to_end_attack_rate": rate(
            asr_attack_success_rows, protocol_denominator_count
        ),
        "success_rows_with_declared_oracle_hit": success_with_declared_hit,
        "success_rows_with_hard_violation_oracle_hit": success_with_hard_hit,
        "observed_oracle_counts": counter_rows(oracle_counts),
        "top_observed_oracles": top_counter_rows(oracle_counts),
        "factual_scored_oracle_counts": counter_rows(
            factual_scored_oracle_counts
        ),
        "observed_declared_oracle_counts": counter_rows(declared_hits),
        "observed_hard_violation_oracle_counts": counter_rows(hard_hits),
        "diagnostic_oracle_counts": counter_rows(diagnostic_oracle_counts),
        "model_protocol_diagnostic_oracle_counts": counter_rows(
            protocol_diagnostic_oracle_counts
        ),
        "by_family": sorted(family_rows, key=lambda item: (item["suite"], item["paper_family"])),
    }


def build_coverage(
    *,
    suite_lock_path: Path,
    attack_dirs: list[Path],
    control_dirs: list[Path],
    case_set: str = "core",
    root: Path = ROOT,
) -> dict[str, Any]:
    suite_lock_abs = suite_lock_path if suite_lock_path.is_absolute() else root / suite_lock_path
    suite_lock = load_json(suite_lock_abs)
    cases = [
        case
        for case in suite_lock.get("cases", [])
        if isinstance(case, dict) and case_in_set(case, case_set)
    ]
    design_by_case_dir = {str(case.get("case_dir") or ""): case for case in cases}
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

    design = aggregate_design_cases(cases)
    attack = aggregate_observed_rows(
        summaries=attack_summaries,
        design_by_case_dir=design_by_case_dir,
        run_kind="attack",
    )
    control = aggregate_observed_rows(
        summaries=control_summaries,
        design_by_case_dir=design_by_case_dir,
        run_kind="control",
    )
    attack_scope_rows = [
        row
        for summary in attack_summaries
        for row in summary.get("rows", [])
        if isinstance(row, dict)
        and str(row.get("run_kind") or "") == "attack"
        and str(row.get("case_dir") or "") in design_by_case_dir
    ]
    accounted_observed_case_dirs = unique_sorted(
        row.get("case_dir", "")
        for row in attack_scope_rows
        if is_accounted_terminal_row(row)
    )
    unaccounted_observed_case_dirs = unique_sorted(
        row.get("case_dir", "")
        for row in attack_scope_rows
        if not is_accounted_terminal_row(row)
    )
    raw_observed_case_dirs = unique_sorted(
        row.get("case_dir", "") for row in attack_scope_rows
    )
    design_case_dirs = set(design_by_case_dir)
    missing_observed_cases = sorted(
        design_case_dirs - set(accounted_observed_case_dirs)
    )

    return {
        "schema_version": 2,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "case_set": case_set,
        "scope": {
            "suite_lock": relpath(suite_lock_abs, root),
            "source_manifest": suite_lock.get("source_manifest", "runs/manifest.json"),
            "active_case_count": as_int(suite_lock.get("active_case_count")),
            "case_counts": suite_lock.get("case_counts", {}),
            "case_set_cases": len(cases),
            # Backward-compatible name, now deliberately restricted to case
            # dirs with at least one accounted terminal result.
            "observed_attack_cases": len(accounted_observed_case_dirs),
            "accounted_observed_attack_cases": len(accounted_observed_case_dirs),
            "accounted_observed_attack_case_dirs": accounted_observed_case_dirs,
            "unaccounted_observed_attack_cases": len(unaccounted_observed_case_dirs),
            "unaccounted_observed_attack_case_dirs": unaccounted_observed_case_dirs,
            "raw_observed_attack_cases": len(raw_observed_case_dirs),
            "raw_observed_attack_case_dirs": raw_observed_case_dirs,
            "missing_observed_cases": missing_observed_cases,
        },
        "design_time": design,
        "observed_baseline": {
            "attack": attack,
            "control": control,
        },
        "interpretation": [
            "Design-time coverage is computed from docs/generated_artifacts/paper_suite_lock.json and case metadata.",
            "Observed baseline coverage is computed from sanitized report_active_run summary rows.",
            "Formal oracle hits and attack outcomes are aggregated only from ASR-eligible scored rows S.",
            "N-1 is an accounted terminal model-protocol outcome, not a progress node or scorable oracle outcome.",
            "O_* values on N-1 or unaccounted rows are retained only as separate diagnostic evidence.",
            "Scope-level observed attack cases require at least one scored or strict N-1 result; invalid-only cases remain missing and are listed separately as unaccounted observations.",
            "Protocol completion and model nonconformance use ASR-eligible scored + N-1 (S+M) as their denominator; ASR-ineligible scored rows remain coverage-accounted but enter neither rate.",
            "Hard/proxy/soft coverage varies by family; pooled ASR must be read with these coverage strata.",
        ],
        "public_artifact_boundary": {
            "included": [
                "suite-level oracle strength counts",
                "declared oracle frequency counts",
                "observed O_* boolean count summaries",
                "separate non-scorable diagnostic O_* count summaries",
                "all-scored, ASR-eligible S, N-1, accounted, and unaccounted row counts",
                "protocol completion, model nonconformance, conditional ASR, and end-to-end attack rates",
                "family-level coverage summaries",
            ],
            "excluded": [
                "raw traces",
                "honeypot logs",
                "canary values",
                "raw oracle payloads",
                "agent homes",
                "provider secrets",
            ],
        },
        "sources": {
            "attack_reports": [relpath(path, root) for path in attack_dirs],
            "control_reports": [relpath(path, root) for path in control_dirs],
            "suite_lock": relpath(suite_lock_abs, root),
        },
    }


def render_oracle_list(rows: list[dict[str, Any]], *, limit: int | None = None) -> list[str]:
    items = rows if limit is None else rows[:limit]
    if not items:
        return ["| none | 0 |"]
    return [f"| `{row['oracle']}` | {row['count']} |" for row in items]


def render_markdown(report: dict[str, Any]) -> str:
    scope = report["scope"]
    design = report["design_time"]
    attack = report["observed_baseline"]["attack"]
    control = report["observed_baseline"]["control"]
    strengths = design["oracle_strength_counts"]
    lines = [
        "# Safety Bench Oracle Coverage Report",
        "",
        f"- generated_at: `{report['generated_at']}`",
        f"- case_set: `{report['case_set']}`",
        f"- suite_lock: `{scope['suite_lock']}`",
        f"- case_set_cases: `{scope['case_set_cases']}`",
        f"- observed_attack_cases (accounted terminal): `{scope['observed_attack_cases']}`",
        f"- raw_observed_attack_cases: `{scope.get('raw_observed_attack_cases', scope['observed_attack_cases'])}`",
        f"- unaccounted_observed_attack_cases: `{scope.get('unaccounted_observed_attack_cases', 0)}`",
        f"- missing_accounted_attack_cases: `{len(scope.get('missing_observed_cases', []))}`",
        "",
        "## Design-Time Oracle Coverage",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Cases | {design['case_count']} |",
        f"| Hard trace oracle cases | {as_int(strengths.get('hard_trace_oracle'))} |",
        f"| Propagation-only cases | {as_int(strengths.get('propagation_only'))} |",
        f"| Soft semantic oracle cases | {as_int(strengths.get('soft_semantic_oracle'))} |",
        f"| Cases with declared oracles | {design['cases_with_declared_oracles']} |",
        f"| Cases with hard violation oracles | {design['cases_with_hard_violation_oracles']} |",
        "",
        "## Oracle Strength By Suite",
        "",
        "| Suite | Cases | Hard | Propagation | Soft | Declared | Hard Violation |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in design["by_suite"]:
        lines.append(
            f"| {row['suite']} | {row['cases']} | {row['hard_trace_oracle']} | "
            f"{row['propagation_only']} | {row['soft_semantic_oracle']} | "
            f"{row['cases_with_declared_oracles']} | {row['cases_with_hard_violation_oracles']} |"
        )
    lines += [
        "",
        "## Declared Oracle Frequencies",
        "",
        "| Oracle | Cases |",
        "| --- | ---: |",
    ]
    lines.extend(render_oracle_list(design["declared_oracle_counts"]))
    lines += [
        "",
        "## Hard Violation Oracle Frequencies",
        "",
        "| Oracle | Cases |",
        "| --- | ---: |",
    ]
    lines.extend(render_oracle_list(design["hard_violation_oracle_counts"]))
    lines += [
        "",
        "## Observed Baseline Oracle Coverage",
        "",
        "Formal O_* and outcome aggregates below include ASR-eligible N0-N5b scored rows S only. "
        "N-1 and unresolved rows retain separate diagnostic counts.",
        "",
        "| Run Kind | Observed | All Scored | N-1 | Coverage Accounted (T) | Protocol Denominator (D=S+M) | Unaccounted | ASR Eligible Scored (S) | S With Oracle | Diagnostic With Oracle |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| attack | {attack['row_count']} | {attack['scored_rows']} | "
            f"{attack['n_minus_1_rows']} | {attack['accounted_terminal_rows']} | "
            f"{attack['protocol_denominator_rows']} | {attack['unaccounted_rows']} | "
            f"{attack['asr_eligible_scored_rows']} | {attack['rows_with_any_oracle']} | "
            f"{attack['diagnostic_rows_with_any_oracle']} |"
        ),
        (
            f"| control | {control['row_count']} | {control['scored_rows']} | "
            f"{control['n_minus_1_rows']} | {control['accounted_terminal_rows']} | "
            f"{control['protocol_denominator_rows']} | {control['unaccounted_rows']} | "
            f"{control['asr_eligible_scored_rows']} | {control['rows_with_any_oracle']} | "
            f"{control['diagnostic_rows_with_any_oracle']} |"
        ),
        "",
        "| Run Kind | Attack Success | Confirmed | Conditional ASR/Violation | Protocol Completion | Model Nonconformance | End-to-End Attack/Violation | Success With Declared Hit | Success With Hard Hit |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        (
            f"| attack | {attack['attack_success_rows']} | {attack['confirmed_rows']} | "
            f"{rate_pct(attack['conditional_asr'])} | "
            f"{rate_pct(attack['protocol_completion_rate'])} | "
            f"{rate_pct(attack['model_nonconformance_rate'])} | "
            f"{rate_pct(attack['end_to_end_attack_rate'])} | "
            f"{attack['success_rows_with_declared_oracle_hit']} | "
            f"{attack['success_rows_with_hard_violation_oracle_hit']} |"
        ),
        (
            f"| control | {control['attack_success_rows']} | {control['confirmed_rows']} | "
            f"{rate_pct(control['conditional_asr'])} | "
            f"{rate_pct(control['protocol_completion_rate'])} | "
            f"{rate_pct(control['model_nonconformance_rate'])} | "
            f"{rate_pct(control['end_to_end_attack_rate'])} | "
            f"{control['success_rows_with_declared_oracle_hit']} | "
            f"{control['success_rows_with_hard_violation_oracle_hit']} |"
        ),
        "",
        "## Top ASR-Eligible Attack Oracles (S)",
        "",
        "| Oracle | Rows |",
        "| --- | ---: |",
    ]
    lines.extend(render_oracle_list(attack["top_observed_oracles"], limit=20))
    lines += [
        "",
        "## Non-Scorable Diagnostic Attack Oracles",
        "",
        "These counts are diagnostic only and do not contribute to attack-success, confirmation, or formal oracle aggregates.",
        "",
        "| Oracle | Rows |",
        "| --- | ---: |",
    ]
    lines.extend(render_oracle_list(attack["diagnostic_oracle_counts"], limit=20))
    lines += [
        "",
        "## Observed Family Coverage",
        "",
        "| Suite | Family | Observed | All Scored | N-1 | Coverage Accounted (T) | Protocol Denominator (D=S+M) | Unaccounted | Success (A) | Confirmed | S With Oracle | Protocol Completion | Model Nonconformance | Conditional ASR | End-to-End |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in attack["by_family"]:
        lines.append(
            f"| {row['suite']} | {row['paper_family']} | {row['rows']} | "
            f"{row['scored_rows']} | {row['n_minus_1_rows']} | "
            f"{row['accounted_terminal_rows']} | {row['protocol_denominator_rows']} | {row['unaccounted_rows']} | "
            f"{row['attack_success_rows']} | {row['confirmed_rows']} | "
            f"{row['rows_with_any_oracle']} | "
            f"{rate_pct(row['protocol_completion_rate'])} | "
            f"{rate_pct(row['model_nonconformance_rate'])} | "
            f"{rate_pct(row['conditional_asr'])} | "
            f"{rate_pct(row['end_to_end_attack_rate'])} |"
        )
    lines += [
        "",
        "## Public Artifact Boundary",
        "",
        "- Included: "
        + ", ".join(report["public_artifact_boundary"]["included"])
        + ".",
        "- Excluded: "
        + ", ".join(report["public_artifact_boundary"]["excluded"])
        + ".",
        "",
        "## Sources",
        "",
        f"- attack_reports: `{', '.join(report['sources']['attack_reports'])}`",
        f"- control_reports: `{', '.join(report['sources']['control_reports'])}`",
        f"- suite_lock: `{report['sources']['suite_lock']}`",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Safety Bench oracle coverage artifacts.")
    parser.add_argument("--attack-label", action="append", default=[])
    parser.add_argument("--attack-report-dir", action="append", default=[])
    parser.add_argument("--control-label", action="append", default=[])
    parser.add_argument("--control-report-dir", action="append", default=[])
    parser.add_argument("--suite-lock", default=str(DEFAULT_SUITE_LOCK))
    parser.add_argument("--case-set", default="core", choices=["core", "extended", "exploratory", "all"])
    parser.add_argument("--out-json", default=str(DEFAULT_OUT_JSON))
    parser.add_argument("--out-md", default=str(DEFAULT_OUT_MD))
    args = parser.parse_args()

    report = build_coverage(
        suite_lock_path=Path(args.suite_lock),
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
        case_set=args.case_set,
    )
    out_json = Path(args.out_json)
    out_md = Path(args.out_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")
    print(out_json)
    print(out_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
