"""Standalone aggregation of strict schema-v2 results across a suite.

This remains an independent, ad-hoc aggregator rather than the formal paper
report pipeline.  It nevertheless follows the same measurement contract:

* all N0--N5b scored rows contribute to coverage accounting ``T``;
* only ASR-eligible scored rows contribute to ``S`` and to attack successes
  ``A``;
* strict N-1 terminal rows contribute to model nonconformance ``M``;
* the protocol denominator is ``D = S + M``.

Execution-invalid rows enter none of those sets.  N-1 is never folded into
N0--N5b/conditional ASR, and an ASR-ineligible scored success cannot enter
``A``.  Attack success uses canonical ``evaluation.attack_success``, not a
loose union of oracles.

Usage:
  python infra/aggregate_results.py --suite v2_persist
  python infra/aggregate_results.py --suite v2_skill --bootstrap 5000
  python infra/aggregate_results.py --root runs/active/F1_memory_runtime --bootstrap 5000

For each case_dir we walk `results/*` and produce, per case:
  - n_runs (strict scored schema-v2 runs)
  - n_minus_1_runs and invalid_runs
  - per-oracle diagnostic hit counts
  - coverage ``T``, eligible scored rows ``S``, N-1 rows ``M``, and ``D=S+M``
  - protocol completion ``S/D`` and model nonconformance ``M/D``
  - conditional ASR ``A/S`` and end-to-end attack rate ``A/D``
  - 95% percentile bootstrap CI for conditional ASR

A plain stdout table is printed. JSON of the same data is written to
runs/_aggregates/<suite>_<ts>.json (or --out).
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from infra.result_classification import (
        is_scored_run_validity,
        is_terminal_model_protocol_deviation,
    )
except ModuleNotFoundError:  # direct `python infra/aggregate_results.py`
    from result_classification import (  # type: ignore
        is_scored_run_validity,
        is_terminal_model_protocol_deviation,
    )

BENCH_ROOT = Path(__file__).resolve().parent.parent
RUNS_ROOT = BENCH_ROOT / "runs"
MANIFEST = RUNS_ROOT / "manifest.json"

UNSAFE_ORACLES = (
    "O_net",
    "O_canary",
    "O_outside_read",
    "O_bash_net",
    "O_persist_write",
    "O_unsafe_recommendation",
)
INFO_ORACLES = ("O_skill_invoked", "O_command_invoked")


def _load_json(p: Path) -> dict[str, Any] | None:
    try:
        return json.loads(p.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def _bootstrap_ci(values: list[int], n_boot: int, seed: int = 0) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    rng = random.Random(seed)
    n = len(values)
    means: list[float] = []
    for _ in range(n_boot):
        s = sum(values[rng.randrange(n)] for _ in range(n))
        means.append(s / n)
    means.sort()
    lo = means[int(0.025 * n_boot)]
    hi = means[min(int(0.975 * n_boot), n_boot - 1)]
    return (lo, hi)


def _case_rows(
    case_dir: Path,
) -> tuple[list[dict[str, Any]], list[str], dict[str, int]]:
    results_dir = case_dir / "results"
    rows: list[dict[str, Any]] = []
    disposition_counts = {
        "observed_runs": 0,
        "scored_runs": 0,
        "n_minus_1_runs": 0,
        "invalid_runs": 0,
    }
    if not results_dir.is_dir():
        return rows, [], disposition_counts
    skill_pool: set[str] = set()
    for run in sorted(results_dir.iterdir()):
        if not run.is_dir():
            continue
        op = run / "oracle.json"
        vp = run / "run_validity.json"
        if not op.exists() and not vp.exists():
            continue
        disposition_counts["observed_runs"] += 1
        validity = _load_json(vp) if vp.is_file() else None
        verdict = _load_json(op) if op.is_file() else None
        if not validity or not verdict:
            disposition_counts["invalid_runs"] += 1
            continue
        if is_terminal_model_protocol_deviation(validity):
            disposition_counts["n_minus_1_runs"] += 1
            continue
        schema_version = validity.get("schema_version")
        current_schema = bool(
            isinstance(schema_version, int)
            and not isinstance(schema_version, bool)
            and schema_version >= 2
        )
        evaluation = verdict.get("evaluation")
        eligibility_fields_valid = bool(
            isinstance(evaluation, dict)
            and all(
                key in evaluation and isinstance(evaluation.get(key), bool)
                for key in ("asr_eligible", "attack_success_metric_excluded")
            )
        )
        if (
            not current_schema
            or not is_scored_run_validity(validity)
            or not isinstance(evaluation, dict)
            or not isinstance(evaluation.get("attack_success"), bool)
            or not eligibility_fields_valid
        ):
            disposition_counts["invalid_runs"] += 1
            continue
        disposition_counts["scored_runs"] += 1
        asr_eligible = bool(
            evaluation["asr_eligible"]
            and not evaluation["attack_success_metric_excluded"]
        )
        oracles = verdict.get("oracles") or {}
        rows.append(
            {
                "run_id": run.name,
                "permission_mode": verdict.get("permission_mode"),
                "run_label": verdict.get("run_label"),
                "result_class": "scored",
                "attack_success": evaluation["attack_success"],
                "asr_eligible": asr_eligible,
                "attack_success_metric_excluded": bool(
                    evaluation.get("attack_success_metric_excluded", False)
                ),
                **{k: bool(oracles.get(k, False)) for k in UNSAFE_ORACLES + INFO_ORACLES},
                "tool_use_count": verdict.get("tool_use_count"),
            }
        )
        for s in verdict.get("plugin_skills") or []:
            skill_pool.add(s)
    return rows, sorted(skill_pool), disposition_counts


def aggregate(case_dirs: list[Path], n_boot: int) -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    overall_eligible_attack_indicators: list[int] = []

    for case_dir in case_dirs:
        rows, plugin_skills, dispositions = _case_rows(case_dir)
        eligible_rows = [row for row in rows if row["asr_eligible"]]
        per_oracle = {
            k: sum(1 for r in eligible_rows if r[k])
            for k in UNSAFE_ORACLES + INFO_ORACLES
        }
        raw_per_oracle = {
            k: sum(1 for r in rows if r[k])
            for k in UNSAFE_ORACLES + INFO_ORACLES
        }
        eligible_attack_flags = [
            1 if row["attack_success"] else 0 for row in eligible_rows
        ]
        scored = len(rows)
        eligible_scored = len(eligible_rows)
        n_minus_one = dispositions["n_minus_1_runs"]
        accounted_terminal = scored + n_minus_one
        protocol_denominator = eligible_scored + n_minus_one
        attack_successes = sum(eligible_attack_flags)
        raw_attack_successes = sum(1 for row in rows if row["attack_success"])
        conditional_asr = (
            attack_successes / eligible_scored if eligible_scored else None
        )
        ci95 = (
            list(_bootstrap_ci(eligible_attack_flags, n_boot=n_boot))
            if eligible_attack_flags
            else None
        )
        overall_eligible_attack_indicators.extend(eligible_attack_flags)

        cases.append(
            {
                "case_dir": str(case_dir.relative_to(RUNS_ROOT)).replace("\\", "/"),
                # Compatibility: n_runs remains the count of all scored rows.
                "n_runs": scored,
                **dispositions,
                "asr_eligible_scored_runs": eligible_scored,
                "accounted_terminal_runs": accounted_terminal,
                "protocol_denominator_runs": protocol_denominator,
                "attack_successes": attack_successes,
                "raw_attack_successes": raw_attack_successes,
                "protocol_completion_rate": (
                    eligible_scored / protocol_denominator
                    if protocol_denominator
                    else None
                ),
                "model_nonconformance_rate": (
                    n_minus_one / protocol_denominator
                    if protocol_denominator
                    else None
                ),
                "conditional_asr": conditional_asr,
                # Compatibility alias: asr is the conditional A/S metric.
                "asr": conditional_asr,
                "end_to_end_attack_rate": (
                    attack_successes / protocol_denominator
                    if protocol_denominator
                    else None
                ),
                "ci95": ci95,
                "per_oracle": {k: per_oracle[k] for k in UNSAFE_ORACLES},
                "info_oracles": {k: per_oracle[k] for k in INFO_ORACLES},
                "raw_per_oracle": {
                    k: raw_per_oracle[k] for k in UNSAFE_ORACLES
                },
                "raw_info_oracles": {
                    k: raw_per_oracle[k] for k in INFO_ORACLES
                },
                "plugin_skills": plugin_skills,
                "runs": rows,
            }
        )

    overall_scored = sum(case["scored_runs"] for case in cases)
    overall_eligible_scored = sum(
        case["asr_eligible_scored_runs"] for case in cases
    )
    overall_n_minus_1 = sum(case["n_minus_1_runs"] for case in cases)
    overall_invalid = sum(case["invalid_runs"] for case in cases)
    overall_observed = sum(case["observed_runs"] for case in cases)
    overall_accounted = overall_scored + overall_n_minus_1
    overall_protocol_denominator = overall_eligible_scored + overall_n_minus_1
    overall_attack_successes = sum(overall_eligible_attack_indicators)
    overall = {
        "n_runs": overall_scored,
        "observed_runs": overall_observed,
        "scored_runs": overall_scored,
        "n_minus_1_runs": overall_n_minus_1,
        "invalid_runs": overall_invalid,
        "asr_eligible_scored_runs": overall_eligible_scored,
        "accounted_terminal_runs": overall_accounted,
        "protocol_denominator_runs": overall_protocol_denominator,
        "protocol_completion_rate": (
            overall_eligible_scored / overall_protocol_denominator
            if overall_protocol_denominator
            else None
        ),
        "model_nonconformance_rate": (
            overall_n_minus_1 / overall_protocol_denominator
            if overall_protocol_denominator
            else None
        ),
        "hits": overall_attack_successes,
        "attack_successes": overall_attack_successes,
        "raw_attack_successes": sum(
            case["raw_attack_successes"] for case in cases
        ),
        "conditional_asr": (
            overall_attack_successes / overall_eligible_scored
            if overall_eligible_scored
            else None
        ),
        "asr": (
            overall_attack_successes / overall_eligible_scored
            if overall_eligible_scored
            else None
        ),
        "end_to_end_attack_rate": (
            overall_attack_successes / overall_protocol_denominator
            if overall_protocol_denominator
            else None
        ),
        "ci95": _bootstrap_ci(overall_eligible_attack_indicators, n_boot=n_boot)
        if overall_eligible_attack_indicators
        else None,
    }
    return {"cases": cases, "overall": overall}


def render_text(report: dict[str, Any]) -> str:
    lines: list[str] = []
    header = "case_dir".ljust(48) + " T  S  M  D  inv A   S/D    M/D    A/S    A/D    CI95             per-oracle (net/can/oR/bN/pW) info (sk/cmd)"
    lines.append(header)
    lines.append("-" * len(header))
    for c in report["cases"]:
        cd = c["case_dir"]
        po = c["per_oracle"]
        io = c["info_oracles"]
        asr = c["asr"]
        completion = c["protocol_completion_rate"]
        nonconformance = c["model_nonconformance_rate"]
        end_to_end = c["end_to_end_attack_rate"]
        ci = c["ci95"]
        per = f"{po['O_net']}/{po['O_canary']}/{po['O_outside_read']}/{po['O_bash_net']}/{po['O_persist_write']}"
        inf = f"{io['O_skill_invoked']}/{io['O_command_invoked']}"
        asr_text = f"{asr:.3f}" if asr is not None else "n/a"
        completion_text = (
            f"{completion:.3f}" if completion is not None else "n/a"
        )
        nonconformance_text = (
            f"{nonconformance:.3f}" if nonconformance is not None else "n/a"
        )
        end_text = f"{end_to_end:.3f}" if end_to_end is not None else "n/a"
        ci_text = (
            f"[{ci[0]:.3f},{ci[1]:.3f}]" if ci is not None else "n/a"
        )
        lines.append(
            f"{cd:<48} {c['accounted_terminal_runs']:<2} "
            f"{c['asr_eligible_scored_runs']:<2} {c['n_minus_1_runs']:<2} "
            f"{c['protocol_denominator_runs']:<2} {c['invalid_runs']:<3} "
            f"{c['attack_successes']:<3} {completion_text:<6} "
            f"{nonconformance_text:<6} {asr_text:<6} {end_text:<6} "
            f"{ci_text:<16} {per:<25} {inf}"
        )
    ov = report["overall"]
    lines.append("-" * len(header))
    asr_text = f"{ov['asr']:.3f}" if ov["asr"] is not None else "n/a"
    completion_text = (
        f"{ov['protocol_completion_rate']:.3f}"
        if ov["protocol_completion_rate"] is not None
        else "n/a"
    )
    nonconformance_text = (
        f"{ov['model_nonconformance_rate']:.3f}"
        if ov["model_nonconformance_rate"] is not None
        else "n/a"
    )
    end_text = (
        f"{ov['end_to_end_attack_rate']:.3f}"
        if ov["end_to_end_attack_rate"] is not None
        else "n/a"
    )
    ci_text = (
        f"[{ov['ci95'][0]:.3f},{ov['ci95'][1]:.3f}]"
        if ov["ci95"] is not None
        else "n/a"
    )
    lines.append(
        f"overall scored={ov['scored_runs']} S={ov['asr_eligible_scored_runs']} "
        f"M={ov['n_minus_1_runs']} T={ov['accounted_terminal_runs']} "
        f"D={ov['protocol_denominator_runs']} invalid={ov['invalid_runs']} "
        f"A={ov['attack_successes']} S/D={completion_text} "
        f"M/D={nonconformance_text} A/S={asr_text} A/D={end_text} CI95={ci_text}"
    )
    return "\n".join(lines) + "\n"


def _case_dirs_from_suite(suite: str) -> list[Path]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    suite_obj = manifest["suites"].get(suite)
    if not suite_obj:
        raise SystemExit(f"suite '{suite}' not found in {MANIFEST}")
    if "cases" in suite_obj:
        return [RUNS_ROOT / c["case_dir"] for c in suite_obj["cases"]]
    if "case_glob" in suite_obj:
        return sorted(RUNS_ROOT.glob(suite_obj["case_glob"]))
    raise SystemExit(f"suite '{suite}' has neither cases nor case_glob")


def _case_dirs_from_root(root: Path) -> list[Path]:
    return sorted(
        p for p in root.iterdir() if p.is_dir() and (p / "results").is_dir()
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--suite", help="suite key under runs/manifest.json")
    g.add_argument("--root", help="alternative: directory containing case dirs")
    ap.add_argument("--bootstrap", type=int, default=5000)
    ap.add_argument("--out", default="", help="optional JSON output path")
    args = ap.parse_args()

    if args.suite:
        case_dirs = _case_dirs_from_suite(args.suite)
        tag = args.suite
    else:
        case_dirs = _case_dirs_from_root(Path(args.root))
        tag = Path(args.root).name

    report = aggregate(case_dirs, n_boot=args.bootstrap)
    text = render_text(report)
    print(text)

    out_path = Path(args.out) if args.out else (
        RUNS_ROOT
        / "_aggregates"
        / f"{tag}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[aggregate] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
